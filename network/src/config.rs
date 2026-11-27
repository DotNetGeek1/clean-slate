//! Launch-time network configuration and trust anchors (#221 stage D).
//!
//! The network service has no compiled-in addresses, peer, resolver or certificate authority.
//! Whoever launches it (the kernel) writes a [`NetworkConfig`] and a [`TrustAnchors`] store into
//! its bootstrap page, and the service checks both with [`NetworkConfig::parse`] and
//! [`TrustAnchors::set`] before it brings its stacks up. Both are plain `#[repr(C)]` data so they
//! cross the user/kernel boundary as bytes.
//!
//! Zero means "absent" throughout: an all-zero [`NetworkConfig`] is an unconfigured network (no
//! address, so every send is unreachable), an all-zero gateway is an on-link-only network, an
//! all-zero gateway MAC means the next hop is resolved with ARP, an all-zero resolver means no
//! DNS, and an empty [`TrustAnchors`] trusts nothing (every TLS handshake fails closed).

use crate::addr::{BoundedHostname, Ipv4Addr, MacAddr, SocketAddrV4};
use crate::limits::MAX_REQUEST_HOSTNAME_LEN;

/// [`NetworkConfig::version`] of a configured network. `0` is unconfigured.
pub const NETWORK_CONFIG_VERSION: u32 = 1;

/// Most anchors one [`TrustAnchors`] store holds.
pub const MAX_TRUST_ANCHORS: usize = 4;
/// DER bytes one [`TrustAnchors`] store holds, all anchors together. Sized so the store fits the
/// network service's one-page bootstrap beside the rest of it.
pub const TRUST_ANCHOR_STORE_BYTES: usize = 2_560;

/// The local address, its on-link prefix and the default gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Route {
    pub local: Ipv4Addr,
    pub prefix_len: u8,
    /// Next hop for every destination off the local prefix; `None` makes them unreachable.
    pub gateway: Option<Ipv4Addr>,
}

impl Ipv4Route {
    /// No address and no route: every destination is unreachable.
    pub const UNCONFIGURED: Self = Self {
        local: Ipv4Addr::new([0; 4]),
        prefix_len: 0,
        gateway: None,
    };

    /// `local` on a /24 with no gateway (the shape of the hermetic M7 lab network).
    pub const fn on_link_24(local: Ipv4Addr) -> Self {
        Self {
            local,
            prefix_len: 24,
            gateway: None,
        }
    }

    pub fn is_configured(&self) -> bool {
        self.local != Ipv4Addr::new([0; 4])
    }

    /// Whether `dst` is on the local prefix.
    pub fn on_link(&self, dst: Ipv4Addr) -> bool {
        self.is_configured() && prefix_matches(self.local, dst, self.prefix_len)
    }

    /// The neighbour a datagram to `dst` is handed to: `dst` itself when it is on-link, else
    /// the gateway; `None` when there is no route (or no address).
    pub fn next_hop(&self, dst: Ipv4Addr) -> Option<Ipv4Addr> {
        if !self.is_configured() || dst == self.local || !unicast(dst) {
            return None;
        }
        if self.on_link(dst) {
            Some(dst)
        } else {
            self.gateway
        }
    }
}

fn prefix_mask(prefix_len: u8) -> u32 {
    match prefix_len {
        0 => 0,
        len if len >= 32 => u32::MAX,
        len => u32::MAX << (32 - u32::from(len)),
    }
}

fn prefix_matches(a: Ipv4Addr, b: Ipv4Addr, prefix_len: u8) -> bool {
    let mask = prefix_mask(prefix_len);
    u32::from_be_bytes(a.octets()) & mask == u32::from_be_bytes(b.octets()) & mask
}

/// Launch-time network configuration, as the launcher writes it (see the module docs).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkConfig {
    /// [`NETWORK_CONFIG_VERSION`], or `0` for an unconfigured network.
    pub version: u32,
    pub local_ipv4: [u8; 4],
    pub gateway_ipv4: [u8; 4],
    pub dns_ipv4: [u8; 4],
    pub dns_port: u16,
    /// Static next-hop MAC for the gateway (or, with no gateway, for every on-link peer the
    /// service reaches). All zero: resolve with ARP.
    pub gateway_mac: [u8; 6],
    pub prefix_len: u8,
    /// Length of [`Self::tls_peer_name`]; `0` refuses the native TLS session.
    pub tls_peer_name_len: u8,
    /// The name the native TLS session verifies the server certificate against, until the
    /// connect request carries one per connection.
    pub tls_peer_name: [u8; MAX_REQUEST_HOSTNAME_LEN],
    /// [`CONFIG_FLAG_DHCP`]; other bits are reserved (zero).
    pub flags: u8,
    pub _reserved: [u8; 6],
}

/// [`NetworkConfig::flags`]: lease the address, prefix, gateway and (unless the config names
/// one) the resolver with DHCP ([`crate::dhcp`]) instead of configuring them statically.
pub const CONFIG_FLAG_DHCP: u8 = 1 << 0;

// No padding: the struct crosses the user/kernel boundary as bytes.
const _: () = assert!(core::mem::size_of::<NetworkConfig>() == 88);

/// Why a [`NetworkConfig`] or [`TrustAnchors`] was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    UnsupportedVersion,
    /// Prefix length over 32, or a /0 network.
    BadPrefix,
    /// The local address is zero, broadcast, multicast or the network/broadcast address of a
    /// prefix shorter than /31.
    BadLocalAddress,
    /// The gateway is the local address, or not on the local prefix.
    BadGateway,
    /// A resolver address without a port, or a port without an address.
    BadResolver,
    BadTlsPeerName,
    /// A static MAC that is multicast or broadcast.
    BadGatewayMac,
    /// A DHCP configuration that also names a static address, prefix, gateway or gateway MAC.
    DhcpWithStaticAddress,
    /// The anchor count or lengths do not fit the store.
    BadTrustAnchors,
    /// Reserved bytes are not zero.
    Reserved,
}

/// A checked [`NetworkConfig`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceNetwork {
    pub route: Ipv4Route,
    /// Pinned MAC of the next hop a configured gateway (or, on an on-link-only network, every
    /// peer) answers for. `None`: ARP.
    pub gateway_mac: Option<MacAddr>,
    pub resolver: Option<SocketAddrV4>,
    pub tls_peer_name: Option<BoundedHostname>,
    /// The route is still to be leased with DHCP: until [`Self::with_lease`] it is
    /// unconfigured.
    pub dhcp: bool,
}

impl ServiceNetwork {
    /// The unconfigured network: no address, no resolver, no TLS peer.
    pub const UNCONFIGURED: Self = Self {
        route: Ipv4Route::UNCONFIGURED,
        gateway_mac: None,
        resolver: None,
        tls_peer_name: None,
        dhcp: false,
    };

    /// This DHCP network with `lease` applied: the leased route, and the leased resolver
    /// (port 53) unless the configuration named one. The result is checked like a static
    /// configuration, so a lease that would not pass as one is refused.
    pub fn with_lease(&self, lease: &crate::dhcp::DhcpLease) -> Result<Self, ConfigError> {
        let resolver = self
            .resolver
            .or_else(|| lease.dns.map(|dns| SocketAddrV4::new(dns, 53)));
        let name = match &self.tls_peer_name {
            Some(name) => name.as_str().map_err(|_| ConfigError::BadTlsPeerName)?,
            None => "",
        };
        let route = Ipv4Route {
            local: lease.address,
            prefix_len: lease.prefix_len,
            gateway: lease.router,
        };
        NetworkConfig::new_static(route, None, resolver, name).parse()
    }

    /// The MAC to pin for `dst`'s next hop, when the configuration names one: the gateway's
    /// MAC for a routed destination, or for an on-link peer on a network without a gateway.
    pub fn pinned_neighbour(&self, dst: Ipv4Addr) -> Option<(Ipv4Addr, MacAddr)> {
        let mac = self.gateway_mac?;
        let hop = self.route.next_hop(dst)?;
        match self.route.gateway {
            Some(gateway) if hop == gateway => Some((hop, mac)),
            Some(_) => None,
            None => Some((hop, mac)),
        }
    }
}

impl NetworkConfig {
    /// All zero: no network.
    pub const UNCONFIGURED: Self = Self {
        version: 0,
        local_ipv4: [0; 4],
        gateway_ipv4: [0; 4],
        dns_ipv4: [0; 4],
        dns_port: 0,
        gateway_mac: [0; 6],
        prefix_len: 0,
        tls_peer_name_len: 0,
        tls_peer_name: [0; MAX_REQUEST_HOSTNAME_LEN],
        flags: 0,
        _reserved: [0; 6],
    };

    /// A DHCP configuration: the route is leased at launch. `resolver`, when given, is used
    /// instead of the leased one. `tls_peer_name` as in [`Self::new_static`].
    pub const fn new_dhcp(resolver: Option<SocketAddrV4>, tls_peer_name: &str) -> Self {
        let mut config = Self::new_static(Ipv4Route::UNCONFIGURED, None, resolver, tls_peer_name);
        config.flags = CONFIG_FLAG_DHCP;
        config
    }

    /// A static configuration. `tls_peer_name` longer than
    /// [`MAX_REQUEST_HOSTNAME_LEN`] is truncated, which [`Self::parse`] then refuses only if
    /// the truncation leaves an invalid name.
    pub const fn new_static(
        route: Ipv4Route,
        gateway_mac: Option<MacAddr>,
        resolver: Option<SocketAddrV4>,
        tls_peer_name: &str,
    ) -> Self {
        let mut config = Self::UNCONFIGURED;
        config.version = NETWORK_CONFIG_VERSION;
        config.local_ipv4 = route.local.octets();
        config.prefix_len = route.prefix_len;
        if let Some(gateway) = route.gateway {
            config.gateway_ipv4 = gateway.octets();
        }
        if let Some(mac) = gateway_mac {
            config.gateway_mac = mac.octets();
        }
        if let Some(resolver) = resolver {
            config.dns_ipv4 = resolver.addr.octets();
            config.dns_port = resolver.port;
        }
        let name = tls_peer_name.as_bytes();
        let mut i = 0;
        while i < name.len() && i < MAX_REQUEST_HOSTNAME_LEN {
            config.tls_peer_name[i] = name[i];
            i += 1;
        }
        config.tls_peer_name_len = i as u8;
        config
    }

    /// Checks the configuration. An unconfigured one gives [`ServiceNetwork::UNCONFIGURED`].
    pub fn parse(&self) -> Result<ServiceNetwork, ConfigError> {
        if self._reserved != [0; 6] || self.flags & !CONFIG_FLAG_DHCP != 0 {
            return Err(ConfigError::Reserved);
        }
        if self.version == 0 && *self == Self::UNCONFIGURED {
            return Ok(ServiceNetwork::UNCONFIGURED);
        }
        if self.version != NETWORK_CONFIG_VERSION {
            return Err(ConfigError::UnsupportedVersion);
        }
        if self.flags & CONFIG_FLAG_DHCP != 0 {
            return self.parse_dhcp();
        }
        if self.prefix_len == 0 || self.prefix_len > 32 {
            return Err(ConfigError::BadPrefix);
        }
        let local = Ipv4Addr::new(self.local_ipv4);
        if !usable_host(local, self.prefix_len) {
            return Err(ConfigError::BadLocalAddress);
        }
        let route_on_link = Ipv4Route {
            local,
            prefix_len: self.prefix_len,
            gateway: None,
        };
        let gateway = match self.gateway_ipv4 {
            [0, 0, 0, 0] => None,
            raw => {
                let gateway = Ipv4Addr::new(raw);
                if gateway == local || !route_on_link.on_link(gateway) || !unicast(gateway) {
                    return Err(ConfigError::BadGateway);
                }
                Some(gateway)
            }
        };
        let gateway_mac = match self.gateway_mac {
            [0, 0, 0, 0, 0, 0] => None,
            raw if raw[0] & 1 != 0 => return Err(ConfigError::BadGatewayMac),
            raw => Some(MacAddr::new(raw)),
        };
        let resolver = match (self.dns_ipv4, self.dns_port) {
            ([0, 0, 0, 0], 0) => None,
            ([0, 0, 0, 0], _) | (_, 0) => return Err(ConfigError::BadResolver),
            (raw, port) => {
                let addr = Ipv4Addr::new(raw);
                if !unicast(addr) || addr == local {
                    return Err(ConfigError::BadResolver);
                }
                Some(SocketAddrV4::new(addr, port))
            }
        };
        let tls_peer_name = self.parse_tls_peer_name()?;
        Ok(ServiceNetwork {
            route: Ipv4Route {
                gateway,
                ..route_on_link
            },
            gateway_mac,
            resolver,
            tls_peer_name,
            dhcp: false,
        })
    }
}

impl NetworkConfig {
    fn parse_dhcp(&self) -> Result<ServiceNetwork, ConfigError> {
        if self.local_ipv4 != [0; 4]
            || self.gateway_ipv4 != [0; 4]
            || self.gateway_mac != [0; 6]
            || self.prefix_len != 0
        {
            return Err(ConfigError::DhcpWithStaticAddress);
        }
        let resolver = match (self.dns_ipv4, self.dns_port) {
            ([0, 0, 0, 0], 0) => None,
            ([0, 0, 0, 0], _) | (_, 0) => return Err(ConfigError::BadResolver),
            (raw, port) => {
                let addr = Ipv4Addr::new(raw);
                if !unicast(addr) {
                    return Err(ConfigError::BadResolver);
                }
                Some(SocketAddrV4::new(addr, port))
            }
        };
        Ok(ServiceNetwork {
            route: Ipv4Route::UNCONFIGURED,
            gateway_mac: None,
            resolver,
            tls_peer_name: self.parse_tls_peer_name()?,
            dhcp: true,
        })
    }

    fn parse_tls_peer_name(&self) -> Result<Option<BoundedHostname>, ConfigError> {
        match self.tls_peer_name_len {
            0 if self.tls_peer_name == [0; MAX_REQUEST_HOSTNAME_LEN] => Ok(None),
            0 => Err(ConfigError::BadTlsPeerName),
            len => {
                let len = usize::from(len);
                if len > MAX_REQUEST_HOSTNAME_LEN
                    || self.tls_peer_name[len..].iter().any(|&b| b != 0)
                {
                    return Err(ConfigError::BadTlsPeerName);
                }
                let name = &self.tls_peer_name[..len];
                if !is_dns_name(name) {
                    return Err(ConfigError::BadTlsPeerName);
                }
                let name = core::str::from_utf8(name).map_err(|_| ConfigError::BadTlsPeerName)?;
                Ok(Some(
                    BoundedHostname::try_from_str(name).map_err(|_| ConfigError::BadTlsPeerName)?,
                ))
            }
        }
    }
}

/// Letters, digits, hyphens and dots, with no empty label and no label starting or ending
/// in a hyphen.
fn is_dns_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name.split(|&b| b == b'.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.first() != Some(&b'-')
                && label.last() != Some(&b'-')
                && label
                    .iter()
                    .all(|&b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn unicast(addr: Ipv4Addr) -> bool {
    let o = addr.octets();
    o != [0; 4] && o != [255; 4] && !(224..=239).contains(&o[0])
}

fn usable_host(addr: Ipv4Addr, prefix_len: u8) -> bool {
    if !unicast(addr) {
        return false;
    }
    if prefix_len >= 31 {
        return true;
    }
    let host = u32::from_be_bytes(addr.octets()) & !prefix_mask(prefix_len);
    host != 0 && host != !prefix_mask(prefix_len)
}

/// Trust anchors (DER X.509 certificates), packed back to back. The launcher picks them: test
/// kernels hand the network service the M7 test CA, production kernels the bundled root set.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustAnchors {
    pub count: u16,
    pub lens: [u16; MAX_TRUST_ANCHORS],
    pub _reserved: [u8; 6],
    pub der: [u8; TRUST_ANCHOR_STORE_BYTES],
}

const _: () = assert!(
    core::mem::size_of::<TrustAnchors>() == 16 + TRUST_ANCHOR_STORE_BYTES,
    "TrustAnchors layout is part of the bootstrap ABI"
);

/// A checked view of a [`TrustAnchors`] store.
#[derive(Clone, Copy, Debug)]
pub struct TrustAnchorSet<'a> {
    ders: [&'a [u8]; MAX_TRUST_ANCHORS],
    len: usize,
}

impl<'a> TrustAnchorSet<'a> {
    pub const EMPTY: TrustAnchorSet<'static> = TrustAnchorSet {
        ders: [&[]; MAX_TRUST_ANCHORS],
        len: 0,
    };

    /// Up to [`MAX_TRUST_ANCHORS`] anchors; any more are refused.
    pub fn from_ders(ders: &[&'a [u8]]) -> Result<Self, ConfigError> {
        if ders.len() > MAX_TRUST_ANCHORS || ders.iter().any(|der| der.is_empty()) {
            return Err(ConfigError::BadTrustAnchors);
        }
        let mut set = Self {
            ders: [&[]; MAX_TRUST_ANCHORS],
            len: ders.len(),
        };
        set.ders[..ders.len()].copy_from_slice(ders);
        Ok(set)
    }

    pub fn as_slice(&self) -> &[&'a [u8]] {
        &self.ders[..self.len]
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl TrustAnchors {
    pub const EMPTY: Self = Self {
        count: 0,
        lens: [0; MAX_TRUST_ANCHORS],
        _reserved: [0; 6],
        der: [0; TRUST_ANCHOR_STORE_BYTES],
    };

    /// Packs `ders`; refuses more than [`MAX_TRUST_ANCHORS`], an empty anchor, or more than
    /// [`TRUST_ANCHOR_STORE_BYTES`] in all.
    pub fn from_ders(ders: &[&[u8]]) -> Result<Self, ConfigError> {
        let mut store = Self::EMPTY;
        store.fill(ders)?;
        Ok(store)
    }

    /// [`Self::from_ders`] in place (the store is 2.5 KiB; launchers fill it where it lives).
    /// On error the store is left empty.
    pub fn fill(&mut self, ders: &[&[u8]]) -> Result<(), ConfigError> {
        *self = Self::EMPTY;
        if ders.len() > MAX_TRUST_ANCHORS {
            return Err(ConfigError::BadTrustAnchors);
        }
        let mut at = 0usize;
        for (i, der) in ders.iter().enumerate() {
            let Some(end) = at
                .checked_add(der.len())
                .filter(|&end| end <= TRUST_ANCHOR_STORE_BYTES && !der.is_empty())
            else {
                *self = Self::EMPTY;
                return Err(ConfigError::BadTrustAnchors);
            };
            self.der[at..end].copy_from_slice(der);
            self.lens[i] = der.len() as u16;
            at = end;
        }
        self.count = ders.len() as u16;
        Ok(())
    }

    /// The anchors, after checking the count, the lengths and that unused bytes are zero.
    pub fn set(&self) -> Result<TrustAnchorSet<'_>, ConfigError> {
        if self._reserved != [0; 6] {
            return Err(ConfigError::Reserved);
        }
        let count = usize::from(self.count);
        if count > MAX_TRUST_ANCHORS || self.lens[count..].iter().any(|&len| len != 0) {
            return Err(ConfigError::BadTrustAnchors);
        }
        let mut set = TrustAnchorSet {
            ders: [&[]; MAX_TRUST_ANCHORS],
            len: count,
        };
        let mut at = 0usize;
        for i in 0..count {
            let len = usize::from(self.lens[i]);
            let end = at
                .checked_add(len)
                .filter(|&end| end <= TRUST_ANCHOR_STORE_BYTES && len != 0)
                .ok_or(ConfigError::BadTrustAnchors)?;
            set.ders[i] = &self.der[at..end];
            at = end;
        }
        if self.der[at..].iter().any(|&b| b != 0) {
            return Err(ConfigError::BadTrustAnchors);
        }
        Ok(set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: Ipv4Addr = Ipv4Addr::new([10, 0, 2, 15]);
    const GATEWAY: Ipv4Addr = Ipv4Addr::new([10, 0, 2, 2]);
    const DNS: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new([10, 0, 2, 3]), 53);
    const MAC: MacAddr = MacAddr::new([0x52, 0x55, 0x0a, 0x00, 0x02, 0x02]);

    fn route() -> Ipv4Route {
        Ipv4Route {
            local: LOCAL,
            prefix_len: 24,
            gateway: Some(GATEWAY),
        }
    }

    #[test]
    fn unconfigured_parses_to_no_network() {
        let network = NetworkConfig::UNCONFIGURED.parse().unwrap();
        assert_eq!(network, ServiceNetwork::UNCONFIGURED);
        assert_eq!(network.route.next_hop(GATEWAY), None);
    }

    #[test]
    fn static_config_round_trips() {
        let config = NetworkConfig::new_static(route(), Some(MAC), Some(DNS), "example.test");
        let network = config.parse().unwrap();
        assert_eq!(network.route, route());
        assert_eq!(network.gateway_mac, Some(MAC));
        assert_eq!(network.resolver, Some(DNS));
        assert_eq!(
            network.tls_peer_name.unwrap().as_str().unwrap(),
            "example.test"
        );
    }

    #[test]
    fn next_hop_is_the_destination_on_link_and_the_gateway_off_it() {
        let route = route();
        assert_eq!(route.next_hop(DNS.addr), Some(DNS.addr));
        let remote = Ipv4Addr::new([192, 0, 2, 7]);
        assert_eq!(route.next_hop(remote), Some(GATEWAY));
        assert_eq!(route.next_hop(LOCAL), None);
        let no_gateway = Ipv4Route {
            gateway: None,
            ..route
        };
        assert_eq!(no_gateway.next_hop(remote), None);
    }

    #[test]
    fn prefixes_other_than_24_route() {
        let route = Ipv4Route {
            local: Ipv4Addr::new([172, 16, 5, 9]),
            prefix_len: 20,
            gateway: Some(Ipv4Addr::new([172, 16, 0, 1])),
        };
        assert!(route.on_link(Ipv4Addr::new([172, 16, 15, 200])));
        assert!(!route.on_link(Ipv4Addr::new([172, 16, 16, 1])));
        let host_route = Ipv4Route {
            local: LOCAL,
            prefix_len: 32,
            gateway: None,
        };
        assert_eq!(host_route.next_hop(GATEWAY), None);
    }

    #[test]
    fn pinned_neighbour_covers_only_the_gateway_hop() {
        let network = NetworkConfig::new_static(route(), Some(MAC), Some(DNS), "")
            .parse()
            .unwrap();
        let remote = Ipv4Addr::new([192, 0, 2, 7]);
        assert_eq!(network.pinned_neighbour(remote), Some((GATEWAY, MAC)));
        assert_eq!(network.pinned_neighbour(GATEWAY), Some((GATEWAY, MAC)));
        // An on-link host that is not the gateway is resolved with ARP.
        assert_eq!(network.pinned_neighbour(DNS.addr), None);
        let lab = NetworkConfig::new_static(Ipv4Route::on_link_24(LOCAL), Some(MAC), None, "")
            .parse()
            .unwrap();
        assert_eq!(lab.pinned_neighbour(DNS.addr), Some((DNS.addr, MAC)));
        assert_eq!(lab.pinned_neighbour(Ipv4Addr::new([192, 0, 2, 7])), None);
    }

    #[test]
    fn bad_configs_are_refused() {
        let good = NetworkConfig::new_static(route(), None, Some(DNS), "");
        type Mutation = fn(&mut NetworkConfig);
        let cases: [(Mutation, ConfigError); 9] = [
            (|c| c.version = 9, ConfigError::UnsupportedVersion),
            (|c| c.prefix_len = 33, ConfigError::BadPrefix),
            (|c| c.prefix_len = 0, ConfigError::BadPrefix),
            (
                |c| c.local_ipv4 = [10, 0, 2, 0],
                ConfigError::BadLocalAddress,
            ),
            (
                |c| c.local_ipv4 = [224, 0, 0, 1],
                ConfigError::BadLocalAddress,
            ),
            (|c| c.gateway_ipv4 = [10, 0, 3, 1], ConfigError::BadGateway),
            (|c| c.dns_port = 0, ConfigError::BadResolver),
            (
                |c| c.gateway_mac = [1, 0, 0, 0, 0, 0],
                ConfigError::BadGatewayMac,
            ),
            (|c| c._reserved[0] = 1, ConfigError::Reserved),
        ];
        for (mutate, expected) in cases {
            let mut config = good;
            mutate(&mut config);
            assert_eq!(config.parse(), Err(expected));
        }
        let mut bad_name = good;
        bad_name.tls_peer_name_len = 3;
        bad_name.tls_peer_name[..3].copy_from_slice(b"a b");
        assert_eq!(bad_name.parse(), Err(ConfigError::BadTlsPeerName));
    }

    #[test]
    fn dhcp_config_takes_its_route_from_the_lease() {
        let config = NetworkConfig::new_dhcp(None, "example.test");
        let network = config.parse().unwrap();
        assert!(network.dhcp);
        assert_eq!(network.route, Ipv4Route::UNCONFIGURED);
        let lease = crate::dhcp::DhcpLease {
            address: LOCAL,
            prefix_len: 24,
            router: Some(GATEWAY),
            dns: Some(DNS.addr),
            server: GATEWAY,
            lease_secs: 3_600,
        };
        let leased = network.with_lease(&lease).unwrap();
        assert!(!leased.dhcp);
        assert_eq!(leased.route, route());
        assert_eq!(leased.resolver, Some(DNS));
        assert_eq!(leased.gateway_mac, None);
        assert_eq!(
            leased.tls_peer_name.unwrap().as_str().unwrap(),
            "example.test"
        );
        // A configured resolver wins over the leased one.
        let own = SocketAddrV4::new(Ipv4Addr::new([192, 0, 2, 53]), 5353);
        let pinned = NetworkConfig::new_dhcp(Some(own), "").parse().unwrap();
        assert_eq!(pinned.with_lease(&lease).unwrap().resolver, Some(own));
        // A lease that would not pass as a static configuration is refused.
        let broadcast = crate::dhcp::DhcpLease {
            address: Ipv4Addr::new([10, 0, 2, 255]),
            ..lease
        };
        assert_eq!(
            network.with_lease(&broadcast),
            Err(ConfigError::BadLocalAddress)
        );
    }

    #[test]
    fn dhcp_config_refuses_static_fields_and_unknown_flags() {
        let mut with_address = NetworkConfig::new_dhcp(None, "");
        with_address.local_ipv4 = LOCAL.octets();
        assert_eq!(
            with_address.parse(),
            Err(ConfigError::DhcpWithStaticAddress)
        );
        let mut with_mac = NetworkConfig::new_dhcp(None, "");
        with_mac.gateway_mac = MAC.octets();
        assert_eq!(with_mac.parse(), Err(ConfigError::DhcpWithStaticAddress));
        let mut unknown = NetworkConfig::new_dhcp(None, "");
        unknown.flags |= 1 << 3;
        assert_eq!(unknown.parse(), Err(ConfigError::Reserved));
    }

    #[test]
    fn trust_anchors_pack_and_unpack() {
        let a = [1u8; 300];
        let b = [2u8; 500];
        let store = TrustAnchors::from_ders(&[&a, &b]).unwrap();
        let set = store.set().unwrap();
        assert_eq!(set.as_slice(), &[&a[..], &b[..]]);
        assert!(TrustAnchors::EMPTY.set().unwrap().is_empty());
    }

    #[test]
    fn trust_anchor_store_refuses_what_does_not_fit() {
        let big = [1u8; TRUST_ANCHOR_STORE_BYTES];
        assert_eq!(
            TrustAnchors::from_ders(&[&big, &[1]]),
            Err(ConfigError::BadTrustAnchors)
        );
        let one = [1u8];
        assert_eq!(
            TrustAnchors::from_ders(&[&one[..]; MAX_TRUST_ANCHORS + 1]),
            Err(ConfigError::BadTrustAnchors)
        );
        let mut forged = TrustAnchors::from_ders(&[&one]).unwrap();
        forged.lens[0] = 0;
        assert_eq!(forged.set().unwrap_err(), ConfigError::BadTrustAnchors);
        let mut trailing = TrustAnchors::from_ders(&[&one]).unwrap();
        trailing.der[10] = 9;
        assert_eq!(trailing.set().unwrap_err(), ConfigError::BadTrustAnchors);
    }
}
