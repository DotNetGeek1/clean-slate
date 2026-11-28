//! #353 native network probe: the manifest row of the `m10-net-client-self-test` kernel, the
//! row's network policy, and the lane checks the probe (`clean-slate-net-probe-userspace`)
//! reports through.
//!
//! The probe is a native row whose only grant is `Grant::NativeNetworkClient`: no Linux
//! personality, no console. Against the M7 fixture peer it resolves [`NET_PROBE_HOSTNAME`],
//! fetches a page over a TCP stream, makes a TLS exchange and a UDP round trip, all through the
//! network service, then connects to [`NET_PROBE_DENIED`], which its policy does not name: the
//! service refuses it and records the refusal in the audit log, which the kernel checks. Last
//! (#378) it reads the service's per-app counters, which its row's `Grant::NetworkStats` lets it,
//! and checks its own row matches what it did ([`NET_PROBE_EXPECTED_STATS`]).
//!
//! The same probe runs the #359 listen lane (`m10-net-listen-self-test`) when the kernel's
//! [`NET_PROBE_CHECK_MODE`] answers [`NET_PROBE_MODE_LISTEN`]: it listens on
//! [`NET_PROBE_LISTEN_PORT`], is refused [`NET_PROBE_LISTEN_DENIED_PORT`] (audited), and echoes
//! what the host sends through QEMU's `hostfwd` on the first connection that carries
//! [`NET_PROBE_ECHO`].

use clean_slate_capability::NetTransport;
use clean_slate_network::addr::Ipv4Addr;
use clean_slate_service_lifecycle::ServiceId;

use crate::manifest::{
    Grant, Liveness, RestartSpec, ServiceImage, ServiceSpec, Start, NETWORK_SERVICE_SPEC,
};
use crate::network_policy::{AppNetworkPolicy, DestinationRule, Peer};
use crate::NETWORK_SERVICE_ID;

pub const NET_PROBE_SERVICE_ID: ServiceId = ServiceId(0x0000_5700);

/// The probe's row. It depends on the network row, so the service is running and the client
/// capability is issued at launch.
pub const NET_PROBE_SPEC: ServiceSpec = ServiceSpec {
    id: NET_PROBE_SERVICE_ID,
    image: ServiceImage::NetProbe,
    mode: 0,
    grants: &[Grant::NativeNetworkClient, Grant::NetworkStats],
    restart: RestartSpec::Never,
    depends_on: &[NETWORK_SERVICE_ID],
    slot_allowance: None,
    memory_pages: 0,
    launch_name: None,
    start: Start::AtBoot,
    liveness: Liveness::Off,
};

/// The system network row without its storage dependency: the lane runs no storage service.
pub const NET_PROBE_NETWORK_SPEC: ServiceSpec = ServiceSpec {
    depends_on: &[],
    ..NETWORK_SERVICE_SPEC
};

/// The lane's rows: the network service and the probe.
pub const NET_PROBE_MANIFEST: &[ServiceSpec] = &[NET_PROBE_NETWORK_SPEC, NET_PROBE_SPEC];

const _: () = assert!(crate::manifest::validate_manifest(NET_PROBE_MANIFEST).is_ok());

/// The probe's bootstrap page, 1 MiB above the service code address. It holds the probe's
/// pid (`u64`) and nothing else: the probe's only authority is its network client capability,
/// which the kernel looks up for it.
pub const NET_PROBE_BOOTSTRAP_ADDRESS: u64 = 0x0000_4000_0010_0000;

/// The fixture peer (`clean_slate_network::fixture::PEER_IPV4`).
pub const NET_PROBE_PEER: [u8; 4] = [10, 77, 0, 1];
/// The name the probe resolves; the fixture answers it with [`NET_PROBE_PEER`].
pub const NET_PROBE_HOSTNAME: &str = "m7.fixture.test";
/// The fixture's TCP service: it answers [`NET_PROBE_REQUEST`] with [`NET_PROBE_PAGE`].
pub const NET_PROBE_TCP_PORT: u16 = 4001;
/// The fixture's TLS service, same request and answer.
pub const NET_PROBE_TLS_PORT: u16 = 4443;
/// The fixture's UDP echo.
pub const NET_PROBE_UDP_PORT: u16 = 4000;
/// A peer port the policy does not name.
pub const NET_PROBE_DENIED_PORT: u16 = 4002;
pub const NET_PROBE_DENIED: ([u8; 4], u16) = (NET_PROBE_PEER, NET_PROBE_DENIED_PORT);

pub const NET_PROBE_REQUEST: &[u8] = b"clean-slate-m7-fixture-request";
pub const NET_PROBE_PAGE: &[u8] = b"clean-slate-m7-fixture-response";
pub const NET_PROBE_DATAGRAM: &[u8] = b"clean-slate-native-datagram";

/// The port the listen lane's probe listens on; its policy names only this one.
pub const NET_PROBE_LISTEN_PORT: u16 = 7000;
/// A port the probe's policy does not let it listen on.
pub const NET_PROBE_LISTEN_DENIED_PORT: u16 = 7001;
/// What the host sends in through `hostfwd` and expects back.
pub const NET_PROBE_ECHO: &[u8] = b"clean-slate-native-listen-echo";

const fn peer_port(transport: NetTransport, port: u16) -> DestinationRule {
    DestinationRule {
        transport,
        peer: Peer::Subnet {
            addr: Ipv4Addr::new(NET_PROBE_PEER),
            prefix: 32,
        },
        ports: (port, port),
    }
}

/// The probe may resolve names and reach exactly the fixture's three services.
pub const NET_PROBE_POLICY: AppNetworkPolicy = AppNetworkPolicy {
    app: NET_PROBE_SERVICE_ID.0 as u64,
    resolve: true,
    destinations: &[
        peer_port(NetTransport::Tcp, NET_PROBE_TCP_PORT),
        peer_port(NetTransport::Tcp, NET_PROBE_TLS_PORT),
        peer_port(NetTransport::Udp, NET_PROBE_UDP_PORT),
    ],
    listen_ports: &[(NET_PROBE_LISTEN_PORT, NET_PROBE_LISTEN_PORT)],
};

/// `SYSCALL_NR_CAP_GRANT` harness sub-operation of the M6 fixtures, which the lane serves for
/// the probe (`rsi` = check, `rdx` = argument).
pub const NET_PROBE_SUBOP_LANE_CHECK: u64 = 0x104;

/// Lane check: a step starts; the argument is its [`NetProbeStep`] code.
pub const NET_PROBE_CHECK_STEP: u64 = 1;
/// Lane check: the denied connect was refused; the kernel checks the audit log holds the
/// refusal. The argument is 0.
pub const NET_PROBE_CHECK_REFUSED: u64 = 2;
/// Lane check: every step passed. The kernel ends the boot there, with a pass.
pub const NET_PROBE_CHECK_DONE: u64 = 3;
/// Lane check: a step failed; the argument is [`NetProbeFailure::encode`]. The kernel ends the
/// boot there, with a failure.
pub const NET_PROBE_CHECK_FAILED: u64 = 4;
/// Lane check: which steps to run. The kernel answers [`NET_PROBE_MODE_LISTEN`] in the listen
/// lane; any other answer (the client lane's kernel, or one that does not know the check)
/// means the client steps.
pub const NET_PROBE_CHECK_MODE: u64 = 5;
/// Lane check: the probe listens; the argument is the port. The host may connect from now.
pub const NET_PROBE_CHECK_LISTENING: u64 = 6;
/// Lane check: the listen on [`NET_PROBE_LISTEN_DENIED_PORT`] was refused; the kernel checks the
/// audit log holds the refusal. The argument is the port.
pub const NET_PROBE_CHECK_LISTEN_REFUSED: u64 = 7;

/// Lane check: the probe's own counters (#378); the argument is [`NetProbeStats::encode`]. The
/// kernel logs them.
pub const NET_PROBE_CHECK_STATS: u64 = 8;

/// The probe's row in the network service's counters, narrowed to what the lane checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetProbeStats {
    pub bytes_sent: u16,
    pub bytes_received: u16,
    pub connections: u8,
    pub listeners: u8,
    pub refusals: u8,
    pub dns_lookups: u8,
}

impl NetProbeStats {
    /// Each field in its own bits, low to high, in declaration order. A count past a field's
    /// width saturates.
    pub const fn encode(self) -> u64 {
        (self.bytes_sent as u64)
            | (self.bytes_received as u64) << 16
            | (self.connections as u64) << 32
            | (self.listeners as u64) << 40
            | (self.refusals as u64) << 48
            | (self.dns_lookups as u64) << 56
    }

    pub const fn decode(raw: u64) -> Self {
        Self {
            bytes_sent: raw as u16,
            bytes_received: (raw >> 16) as u16,
            connections: (raw >> 32) as u8,
            listeners: (raw >> 40) as u8,
            refusals: (raw >> 48) as u8,
            dns_lookups: (raw >> 56) as u8,
        }
    }
}

/// What the client lane's probe has done when it reads its counters: the TCP and TLS requests
/// and the datagram out, the two pages and the datagram back, three connects (stream, TLS
/// exchange, datagram), the refused connect, and one lookup that went to the resolver.
pub const NET_PROBE_EXPECTED_STATS: NetProbeStats = NetProbeStats {
    bytes_sent: (2 * NET_PROBE_REQUEST.len() + NET_PROBE_DATAGRAM.len()) as u16,
    bytes_received: (2 * NET_PROBE_PAGE.len() + NET_PROBE_DATAGRAM.len()) as u16,
    connections: 3,
    listeners: 0,
    refusals: 1,
    dns_lookups: 1,
};

/// [`NET_PROBE_CHECK_MODE`]'s answer for the listen lane.
pub const NET_PROBE_MODE_LISTEN: u64 = 1;

/// A step of the probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum NetProbeStep {
    Resolve = 1,
    Connect = 2,
    Fetch = 3,
    Tls = 4,
    Udp = 5,
    Denied = 6,
    /// Listen lane (#359): listen on the policy's port.
    Listen = 7,
    /// Listen lane: listen on a port the policy does not name; must be refused.
    ListenDenied = 8,
    /// Listen lane: accept the host's connection.
    Accept = 9,
    /// Listen lane: read the host's bytes and send them back.
    Echo = 10,
    /// Client lane (#378): read the per-app counters and check the probe's own row.
    Stats = 11,
}

impl NetProbeStep {
    pub const ALL: [Self; 11] = [
        Self::Resolve,
        Self::Connect,
        Self::Fetch,
        Self::Tls,
        Self::Udp,
        Self::Denied,
        Self::Listen,
        Self::ListenDenied,
        Self::Accept,
        Self::Echo,
        Self::Stats,
    ];

    pub const fn code(self) -> u64 {
        self as u64
    }

    pub const fn from_code(code: u64) -> Option<Self> {
        let mut index = 0;
        while index < Self::ALL.len() {
            if Self::ALL[index] as u64 == code {
                return Some(Self::ALL[index]);
            }
            index += 1;
        }
        None
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::Connect => "connect",
            Self::Fetch => "fetch",
            Self::Tls => "tls",
            Self::Udp => "udp",
            Self::Denied => "denied",
            Self::Listen => "listen",
            Self::ListenDenied => "listen-denied",
            Self::Accept => "accept",
            Self::Echo => "echo",
            Self::Stats => "stats",
        }
    }
}

/// Why a step failed: a native status, or a wrong answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetProbeFailure {
    pub step: NetProbeStep,
    /// A native status (`u64::MAX - n`), or [`NET_PROBE_WRONG_ANSWER`].
    pub status: u64,
}

/// The step completed with an answer other than the one the fixture gives.
pub const NET_PROBE_WRONG_ANSWER: u64 = 1;

impl NetProbeFailure {
    /// The step in the top byte, the distance of the status below `u64::MAX` (or the wrong
    /// answer marker) below it.
    pub const fn encode(self) -> u64 {
        let detail = if self.status == NET_PROBE_WRONG_ANSWER {
            0x00ff_ffff_ffff_ffff
        } else {
            let below = u64::MAX - self.status;
            if below < 0x00ff_ffff_ffff_ffff {
                below
            } else {
                0x00ff_ffff_ffff_fffe
            }
        };
        (self.step.code() << 56) | detail
    }

    pub const fn decode(raw: u64) -> Option<Self> {
        let Some(step) = NetProbeStep::from_code(raw >> 56) else {
            return None;
        };
        let detail = raw & 0x00ff_ffff_ffff_ffff;
        let status = if detail == 0x00ff_ffff_ffff_ffff {
            NET_PROBE_WRONG_ANSWER
        } else {
            u64::MAX - detail
        };
        Some(Self { step, status })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_ETIMEDOUT};

    #[test]
    fn failures_round_trip() {
        for step in NetProbeStep::ALL {
            for status in [STATUS_EACCES, STATUS_ETIMEDOUT, NET_PROBE_WRONG_ANSWER] {
                let failure = NetProbeFailure { step, status };
                assert_eq!(NetProbeFailure::decode(failure.encode()), Some(failure));
            }
        }
        assert_eq!(NetProbeFailure::decode(0), None);
    }

    #[test]
    fn probe_stats_round_trip() {
        let stats = NetProbeStats {
            bytes_sent: u16::MAX,
            bytes_received: 89,
            connections: 3,
            listeners: 255,
            refusals: 1,
            dns_lookups: 2,
        };
        assert_eq!(NetProbeStats::decode(stats.encode()), stats);
        assert_eq!(
            NET_PROBE_EXPECTED_STATS.bytes_sent as usize,
            2 * NET_PROBE_REQUEST.len() + NET_PROBE_DATAGRAM.len()
        );
    }

    #[test]
    fn the_probe_row_is_a_native_network_client_with_nothing_else() {
        assert!(!NET_PROBE_SPEC.image.is_linux());
        assert_eq!(
            NET_PROBE_SPEC.grants,
            [Grant::NativeNetworkClient, Grant::NetworkStats]
        );
        assert!(NET_PROBE_SPEC.is_network_client());
    }

    #[test]
    fn the_policy_names_the_fixture_services_and_not_the_denied_port() {
        use crate::network_policy::{AppPolicyAuthorizer, NETWORK_POLICIES};
        use crate::network_service::{NetworkAuthorizer, NetworkTarget};
        use clean_slate_network::addr::SocketAddrV4;
        use clean_slate_network::protocol::TrustedCaller;

        let authorizer = AppPolicyAuthorizer::new(NETWORK_POLICIES, None);
        let probe = TrustedCaller::new(9, u64::from(NET_PROBE_SERVICE_ID.0), 1);
        let reach = |transport, port| {
            let dest = SocketAddrV4::new(Ipv4Addr::new(NET_PROBE_PEER), port);
            authorizer
                .authorize_target(&probe, NetworkTarget::Destination { transport, dest })
                .is_ok()
        };
        assert!(reach(NetTransport::Tcp, NET_PROBE_TCP_PORT));
        assert!(reach(NetTransport::Tcp, NET_PROBE_TLS_PORT));
        assert!(reach(NetTransport::Udp, NET_PROBE_UDP_PORT));
        assert!(!reach(NetTransport::Tcp, NET_PROBE_DENIED_PORT));
        assert!(!reach(NetTransport::Udp, NET_PROBE_TCP_PORT));
        assert!(authorizer
            .authorize_target(&probe, NetworkTarget::Resolve)
            .is_ok());
        let listen = |port| {
            authorizer
                .authorize_target(&probe, NetworkTarget::Listen { port })
                .is_ok()
        };
        assert!(listen(NET_PROBE_LISTEN_PORT));
        assert!(!listen(NET_PROBE_LISTEN_DENIED_PORT));
        assert!(!listen(NET_PROBE_TCP_PORT));
        assert_eq!(NET_PROBE_DENIED, (NET_PROBE_PEER, NET_PROBE_DENIED_PORT));
        assert_eq!(
            NET_PROBE_PEER,
            clean_slate_network::fixture::PEER_IPV4.octets()
        );
        assert_eq!(
            NET_PROBE_HOSTNAME,
            clean_slate_network::fixture::FIXTURE_HOSTNAME
        );
        assert_eq!(
            NET_PROBE_TCP_PORT,
            clean_slate_network::fixture::TCP_ECHO_PORT
        );
        assert_eq!(NET_PROBE_TLS_PORT, clean_slate_network::fixture::TLS_PORT);
        assert_eq!(
            NET_PROBE_UDP_PORT,
            clean_slate_network::fixture::UDP_ECHO_PORT
        );
        assert_eq!(
            NET_PROBE_REQUEST,
            clean_slate_network::fixture::APP_REQUEST_BYTES
        );
        assert_eq!(
            NET_PROBE_PAGE,
            clean_slate_network::fixture::APP_RESPONSE_BYTES
        );
    }
}
