//! Per-app network destination policy (#221 stage E).
//!
//! The kernel attests which app a network client belongs to: [`TrustedCaller::domain`] is the
//! manifest row the caller was launched for (a fork inherits its parent's), [`APP_SELF_TEST`]
//! for a self-test kernel's own clients, and [`APP_UNATTRIBUTED`] otherwise. The network
//! service looks the app up in [`NETWORK_POLICIES`] and lets it resolve names and reach only the
//! destinations its entry names. An app without an entry may not open, resolve or connect at
//! all, so a row that gains `Grant::NetworkClient` or `Grant::NativeNetworkClient` without a
//! policy gets nothing.
//!
//! Policies are compiled in beside the manifest; the manifest tests require every row that
//! holds either grant to have exactly one entry, and every entry to name such a row.

use clean_slate_capability::{NetDestination, NetTransport};
use clean_slate_network::addr::{Ipv4Addr, SocketAddrV4};
use clean_slate_network::error::DenialReason;
use clean_slate_network::protocol::TrustedCaller;

use crate::network_service::{NetworkAuthorizer, NetworkOp, NetworkTarget};
use crate::{SYSTEM_SHELL_SERVICE_ID, TERMINAL_SHELL_SERVICE_ID};

/// The app of a caller the kernel could not attribute to a manifest row. It has no policy.
pub const APP_UNATTRIBUTED: u64 = 0;

/// The app of the clients a self-test kernel (one that does not launch init) runs itself: the
/// M7 and M9 probes and fixtures. Only such a kernel attributes a caller to it; a kernel that
/// launches init never does.
pub const APP_SELF_TEST: u64 = u64::MAX;

/// Which peers a [`DestinationRule`] covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Peer {
    /// Any IPv4 address.
    Any,
    /// The resolver the launch configuration names, on its port; nothing when it names none.
    SystemResolver,
    /// Addresses in `addr/prefix`.
    Subnet { addr: Ipv4Addr, prefix: u8 },
}

impl Peer {
    fn covers(self, dest: SocketAddrV4, resolver: Option<SocketAddrV4>) -> bool {
        match self {
            Self::Any => true,
            Self::SystemResolver => resolver == Some(dest),
            Self::Subnet { addr, prefix } => {
                let prefix = u32::from(prefix.min(32));
                let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
                let want = u32::from_be_bytes(addr.octets()) & mask;
                u32::from_be_bytes(dest.addr.octets()) & mask == want
            }
        }
    }
}

/// One kind of destination an app may reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DestinationRule {
    /// [`NetTransport::Tcp`] or [`NetTransport::Udp`]; a `Resolve` rule matches nothing.
    pub transport: NetTransport,
    pub peer: Peer,
    /// Inclusive port range. A [`Peer::SystemResolver`] rule checks the resolver's own port.
    pub ports: (u16, u16),
}

impl DestinationRule {
    pub const ANY_PORT: (u16, u16) = (1, u16::MAX);

    fn covers(
        &self,
        transport: NetTransport,
        dest: SocketAddrV4,
        resolver: Option<SocketAddrV4>,
    ) -> bool {
        transport != NetTransport::Resolve
            && self.transport == transport
            && (self.peer == Peer::SystemResolver
                || (self.ports.0..=self.ports.1).contains(&dest.port))
            && self.peer.covers(dest, resolver)
    }
}

/// What one app may do on the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppNetworkPolicy {
    /// The manifest row (`ServiceId`) this policy is for, or [`APP_SELF_TEST`].
    pub app: u64,
    /// Whether the app may ask the service to resolve names.
    pub resolve: bool,
    pub destinations: &'static [DestinationRule],
}

/// The shells (#218, #311): TCP anywhere, and DNS only through the system resolver, so no
/// other datagram leaves for an arbitrary peer.
const SHELL_DESTINATIONS: &[DestinationRule] = &[
    DestinationRule {
        transport: NetTransport::Tcp,
        peer: Peer::Any,
        ports: DestinationRule::ANY_PORT,
    },
    DestinationRule {
        transport: NetTransport::Udp,
        peer: Peer::SystemResolver,
        ports: DestinationRule::ANY_PORT,
    },
];

/// A self-test kernel's own clients probe the lab network as they please.
const SELF_TEST_DESTINATIONS: &[DestinationRule] = &[
    DestinationRule {
        transport: NetTransport::Tcp,
        peer: Peer::Any,
        ports: (0, u16::MAX),
    },
    DestinationRule {
        transport: NetTransport::Udp,
        peer: Peer::Any,
        ports: (0, u16::MAX),
    },
];

/// Every app's network policy. An app missing here may not use the network.
pub const NETWORK_POLICIES: &[AppNetworkPolicy] = &[
    AppNetworkPolicy {
        app: SYSTEM_SHELL_SERVICE_ID.0 as u64,
        resolve: true,
        destinations: SHELL_DESTINATIONS,
    },
    AppNetworkPolicy {
        app: TERMINAL_SHELL_SERVICE_ID.0 as u64,
        resolve: true,
        destinations: SHELL_DESTINATIONS,
    },
    AppNetworkPolicy {
        app: APP_SELF_TEST,
        resolve: true,
        destinations: SELF_TEST_DESTINATIONS,
    },
];

/// The policy for `app` in `policies`, if it has one. [`APP_UNATTRIBUTED`] never has one.
pub fn policy_for(
    policies: &'static [AppNetworkPolicy],
    app: u64,
) -> Option<&'static AppNetworkPolicy> {
    if app == APP_UNATTRIBUTED {
        return None;
    }
    policies.iter().find(|policy| policy.app == app)
}

/// The production authorizer: each caller's app policy, against the launch resolver.
#[derive(Clone, Copy, Debug)]
pub struct AppPolicyAuthorizer {
    policies: &'static [AppNetworkPolicy],
    resolver: Option<SocketAddrV4>,
}

impl AppPolicyAuthorizer {
    pub const fn new(
        policies: &'static [AppNetworkPolicy],
        resolver: Option<SocketAddrV4>,
    ) -> Self {
        Self { policies, resolver }
    }

    fn policy(&self, caller: &TrustedCaller) -> Option<&'static AppNetworkPolicy> {
        policy_for(self.policies, caller.domain)
    }
}

impl NetworkAuthorizer for AppPolicyAuthorizer {
    /// An app without a policy may not start anything; work on sessions it already holds
    /// (none, then) and `Close` stay with the session checks.
    fn authorize(&self, caller: &TrustedCaller, op: NetworkOp) -> Result<(), DenialReason> {
        match op {
            NetworkOp::Resolve | NetworkOp::Open | NetworkOp::Connect => self
                .policy(caller)
                .map(|_| ())
                .ok_or(DenialReason::Destination),
            NetworkOp::RawDevice => Err(DenialReason::NoCapability),
            NetworkOp::Send | NetworkOp::Receive | NetworkOp::Close => Ok(()),
        }
    }

    fn authorize_target(
        &self,
        caller: &TrustedCaller,
        target: NetworkTarget,
    ) -> Result<(), DenialReason> {
        let policy = self.policy(caller).ok_or(DenialReason::Destination)?;
        let allowed = match target {
            NetworkTarget::Resolve => policy.resolve,
            NetworkTarget::Destination { transport, dest } => policy
                .destinations
                .iter()
                .any(|rule| rule.covers(transport, dest, self.resolver)),
        };
        if allowed {
            Ok(())
        } else {
            Err(DenialReason::Destination)
        }
    }
}

/// The audit encoding of `target`.
pub fn audit_destination(target: NetworkTarget) -> NetDestination {
    match target {
        NetworkTarget::Resolve => NetDestination::RESOLVE,
        NetworkTarget::Destination { transport, dest } => NetDestination {
            transport,
            addr: dest.addr.octets(),
            port: dest.port,
        },
    }
}

/// How many distinct recent refusals [`RefusalReports`] remembers.
pub const REFUSAL_REPORT_SLOTS: usize = 8;

/// Keeps a caller that retries a refused destination from writing a record per try. The
/// audit store keeps every refusal, so each record costs a disk write: a refusal is reported
/// once, and again only after `interval` ticks without being reported. The ring's per-holder
/// budget bounds what is left (the record is charged to the refused caller).
pub struct RefusalReports {
    recent: [Option<(TrustedCaller, u64, u64)>; REFUSAL_REPORT_SLOTS],
    interval: u64,
}

impl RefusalReports {
    pub const fn new(interval: u64) -> Self {
        Self {
            recent: [None; REFUSAL_REPORT_SLOTS],
            interval,
        }
    }

    /// Whether to report `caller`'s refusal for `destination` (a [`NetDestination`]
    /// encoding) at tick `now`; when it says yes it remembers the report.
    pub fn should_report(&mut self, caller: TrustedCaller, destination: u64, now: u64) -> bool {
        let same = |entry: &(TrustedCaller, u64, u64)| entry.0 == caller && entry.1 == destination;
        if let Some(entry) = self.recent.iter_mut().flatten().find(|entry| same(entry)) {
            if now.saturating_sub(entry.2) < self.interval {
                return false;
            }
            entry.2 = now;
            return true;
        }
        let slot = match self.recent.iter().position(Option::is_none) {
            Some(free) => free,
            None => self
                .recent
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.map_or(0, |entry| entry.2))
                .map_or(0, |(index, _)| index),
        };
        self.recent[slot] = Some((caller, destination, now));
        true
    }

    /// Forgets `caller`'s refusals (it exited).
    pub fn forget(&mut self, caller: TrustedCaller) {
        for slot in &mut self.recent {
            if slot.is_some_and(|entry| entry.0 == caller) {
                *slot = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        ServiceSpec, SYSTEM_DESKTOP_MANIFEST, SYSTEM_MANIFEST, SYSTEM_TERMINAL_DESKTOP_MANIFEST,
    };

    const MANIFESTS: [&[ServiceSpec]; 3] = [
        SYSTEM_MANIFEST,
        SYSTEM_DESKTOP_MANIFEST,
        SYSTEM_TERMINAL_DESKTOP_MANIFEST,
    ];

    const RESOLVER: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new([10, 77, 0, 1]), 53);

    fn caller(app: u64) -> TrustedCaller {
        TrustedCaller::new(40, app, 1)
    }

    fn dest(octets: [u8; 4], port: u16, transport: NetTransport) -> NetworkTarget {
        NetworkTarget::Destination {
            transport,
            dest: SocketAddrV4::new(Ipv4Addr::new(octets), port),
        }
    }

    fn authorizer() -> AppPolicyAuthorizer {
        AppPolicyAuthorizer::new(NETWORK_POLICIES, Some(RESOLVER))
    }

    #[test]
    fn a_shell_reaches_tcp_anywhere_and_udp_only_at_the_system_resolver() {
        let auth = authorizer();
        for app in [SYSTEM_SHELL_SERVICE_ID.0, TERMINAL_SHELL_SERVICE_ID.0] {
            let shell = caller(u64::from(app));
            assert_eq!(auth.authorize(&shell, NetworkOp::Open), Ok(()));
            assert_eq!(
                auth.authorize_target(&shell, NetworkTarget::Resolve),
                Ok(())
            );
            let tcp = dest([10, 77, 0, 50], 4001, NetTransport::Tcp);
            assert_eq!(auth.authorize_target(&shell, tcp), Ok(()));
            let dns = dest([10, 77, 0, 1], 53, NetTransport::Udp);
            assert_eq!(auth.authorize_target(&shell, dns), Ok(()));
            for refused in [
                dest([10, 77, 0, 50], 53, NetTransport::Udp),
                dest([10, 77, 0, 1], 5353, NetTransport::Udp),
                dest([8, 8, 8, 8], 53, NetTransport::Udp),
            ] {
                assert_eq!(
                    auth.authorize_target(&shell, refused),
                    Err(DenialReason::Destination),
                    "{refused:?}"
                );
            }
        }
    }

    #[test]
    fn without_a_launch_resolver_a_shell_sends_no_datagram() {
        let auth = AppPolicyAuthorizer::new(NETWORK_POLICIES, None);
        let shell = caller(u64::from(SYSTEM_SHELL_SERVICE_ID.0));
        let dns = dest([10, 77, 0, 1], 53, NetTransport::Udp);
        assert_eq!(
            auth.authorize_target(&shell, dns),
            Err(DenialReason::Destination)
        );
    }

    #[test]
    fn an_app_without_a_policy_starts_nothing_but_may_close() {
        let auth = authorizer();
        for app in [APP_UNATTRIBUTED, 0x5302, 0x5200] {
            let nobody = caller(app);
            for op in [NetworkOp::Resolve, NetworkOp::Open, NetworkOp::Connect] {
                assert_eq!(auth.authorize(&nobody, op), Err(DenialReason::Destination));
            }
            assert_eq!(auth.authorize(&nobody, NetworkOp::Close), Ok(()));
            assert_eq!(
                auth.authorize_target(&nobody, NetworkTarget::Resolve),
                Err(DenialReason::Destination)
            );
            let tcp = dest([10, 77, 0, 50], 4001, NetTransport::Tcp);
            assert_eq!(
                auth.authorize_target(&nobody, tcp),
                Err(DenialReason::Destination)
            );
        }
    }

    #[test]
    fn self_test_clients_reach_anything() {
        let auth = authorizer();
        let probe = caller(APP_SELF_TEST);
        for target in [
            dest([10, 77, 0, 50], 9, NetTransport::Udp),
            dest([10, 77, 0, 50], 4433, NetTransport::Tcp),
            NetworkTarget::Resolve,
        ] {
            assert_eq!(auth.authorize_target(&probe, target), Ok(()));
        }
    }

    #[test]
    fn subnet_and_port_range_rules_match_only_inside_them() {
        let rule = DestinationRule {
            transport: NetTransport::Tcp,
            peer: Peer::Subnet {
                addr: Ipv4Addr::new([192, 168, 4, 0]),
                prefix: 22,
            },
            ports: (80, 443),
        };
        let at = |octets, port| SocketAddrV4::new(Ipv4Addr::new(octets), port);
        assert!(rule.covers(NetTransport::Tcp, at([192, 168, 7, 255], 80), None));
        assert!(rule.covers(NetTransport::Tcp, at([192, 168, 4, 1], 443), None));
        assert!(!rule.covers(NetTransport::Tcp, at([192, 168, 8, 1], 80), None));
        assert!(!rule.covers(NetTransport::Tcp, at([192, 168, 4, 1], 444), None));
        assert!(!rule.covers(NetTransport::Udp, at([192, 168, 4, 1], 80), None));
        let everything = DestinationRule {
            peer: Peer::Subnet {
                addr: Ipv4Addr::new([1, 2, 3, 4]),
                prefix: 0,
            },
            ..rule
        };
        assert!(everything.covers(NetTransport::Tcp, at([9, 9, 9, 9], 80), None));
    }

    #[test]
    fn every_network_client_row_has_one_policy_and_every_policy_names_one() {
        let rows = || MANIFESTS.into_iter().flatten();
        for spec in rows() {
            let app = u64::from(spec.id.0);
            let entries = NETWORK_POLICIES.iter().filter(|p| p.app == app).count();
            let expected = usize::from(spec.is_network_client());
            assert_eq!(entries, expected, "row {:#x}", spec.id.0);
        }
        for policy in NETWORK_POLICIES {
            if policy.app == APP_SELF_TEST {
                continue;
            }
            assert!(
                rows().any(|spec| u64::from(spec.id.0) == policy.app && spec.is_network_client()),
                "policy {:#x} names no NetworkClient row",
                policy.app
            );
        }
        assert!(policy_for(NETWORK_POLICIES, APP_UNATTRIBUTED).is_none());
    }

    #[test]
    fn a_retried_refusal_is_reported_once_per_interval() {
        let mut reports = RefusalReports::new(100);
        let shell = caller(u64::from(SYSTEM_SHELL_SERVICE_ID.0));
        assert!(reports.should_report(shell, 7, 0));
        assert!(!reports.should_report(shell, 7, 1));
        assert!(!reports.should_report(shell, 7, 99));
        assert!(reports.should_report(shell, 8, 99), "another destination");
        let other = TrustedCaller::new(41, shell.domain, 1);
        assert!(reports.should_report(other, 7, 99), "another caller");
        assert!(reports.should_report(shell, 7, 100));
        assert!(!reports.should_report(shell, 7, 150));
        reports.forget(shell);
        assert!(reports.should_report(shell, 7, 150));
    }

    #[test]
    fn a_full_table_forgets_the_oldest_report() {
        let mut reports = RefusalReports::new(1_000);
        let shell = caller(u64::from(SYSTEM_SHELL_SERVICE_ID.0));
        for destination in 0..REFUSAL_REPORT_SLOTS as u64 {
            assert!(reports.should_report(shell, destination, destination));
        }
        assert!(reports.should_report(shell, 99, 50));
        assert!(
            reports.should_report(shell, 0, 51),
            "the oldest was forgotten"
        );
        assert!(!reports.should_report(shell, 2, 52));
    }

    #[test]
    fn audit_destinations_round_trip() {
        let target = dest([10, 77, 0, 50], 53, NetTransport::Udp);
        let encoded = audit_destination(target).encode();
        assert_eq!(
            NetDestination::decode(encoded),
            Some(NetDestination {
                transport: NetTransport::Udp,
                addr: [10, 77, 0, 50],
                port: 53
            })
        );
        assert_eq!(
            NetDestination::decode(audit_destination(NetworkTarget::Resolve).encode()),
            Some(NetDestination::RESOLVE)
        );
    }
}
