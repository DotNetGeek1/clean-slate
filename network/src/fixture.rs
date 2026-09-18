//! Hermetic M7 acceptance fixture contract (host-side peer is out of crate scope).
//!
//! **Assumptions:** no public Internet, no public DNS resolvers, no external PKI,
//! and no dependence on the host LAN. QEMU/host peers must implement only the
//! behaviour described for [`FixturePeer`].

use crate::addr::{Ipv4Addr, MacAddr, SocketAddrV4};

pub const FIXTURE_HOSTNAME: &str = "m7.fixture.test";

pub const GUEST_MAC: MacAddr = MacAddr::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
pub const PEER_MAC: MacAddr = MacAddr::new([0x52, 0x54, 0x00, 0xab, 0xcd, 0xef]);

pub const GUEST_IPV4: Ipv4Addr = Ipv4Addr::new([10, 77, 0, 2]);
pub const PEER_IPV4: Ipv4Addr = Ipv4Addr::new([10, 77, 0, 1]);
pub const GATEWAY_IPV4: Ipv4Addr = Ipv4Addr::new([10, 77, 0, 1]);
pub const SUBNET_PREFIX_LEN: u8 = 24;

pub const FIXTURE_A_RECORD: Ipv4Addr = PEER_IPV4;
pub const FIXTURE_A_TTL_SECS: u32 = 300;

pub const DNS_SERVER_PORT: u16 = 53;
pub const DNS_SERVER_ADDR: SocketAddrV4 = SocketAddrV4::new(PEER_IPV4, DNS_SERVER_PORT);

pub const UDP_ECHO_PORT: u16 = 4000;
pub const TCP_ECHO_PORT: u16 = 4001;
pub const TLS_PORT: u16 = 4443;

pub const TLS_SERVER_NAME: &str = FIXTURE_HOSTNAME;

pub const APP_REQUEST_BYTES: &[u8] = b"clean-slate-m7-fixture-request";
pub const APP_RESPONSE_BYTES: &[u8] = b"clean-slate-m7-fixture-response";

/// Repository-relative paths for the hermetic TLS material (created by later lanes).
pub const FIXTURE_CERT_PATH: &str = "xtask/fixtures/m7/server.crt";
pub const FIXTURE_KEY_PATH: &str = "xtask/fixtures/m7/server.key";
pub const FIXTURE_TRUST_ANCHOR_PATH: &str = "xtask/fixtures/m7/ca.crt";

/// Description of the host/QEMU-side peer required by M7 acceptance tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixturePeer {
    pub mac: MacAddr,
    pub ipv4: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub dns: SocketAddrV4,
    pub udp_echo_port: u16,
    pub tcp_echo_port: u16,
    pub tls_port: u16,
    pub tls_server_name: &'static str,
}

impl FixturePeer {
    pub const fn host_peer() -> Self {
        Self {
            mac: PEER_MAC,
            ipv4: PEER_IPV4,
            gateway: GATEWAY_IPV4,
            dns: SocketAddrV4::new(PEER_IPV4, DNS_SERVER_PORT),
            udp_echo_port: UDP_ECHO_PORT,
            tcp_echo_port: TCP_ECHO_PORT,
            tls_port: TLS_PORT,
            tls_server_name: TLS_SERVER_NAME,
        }
    }
}

/// Behavioural contract for the hermetic peer (implementation lives in xtask/QEMU fixtures):
///
/// - Reply to ARP who-has for [`PEER_IPV4`] with [`PEER_MAC`].
/// - Reply to ICMP echo requests toward [`PEER_IPV4`].
/// - UDP echo: datagrams to [`UDP_ECHO_PORT`] return the same payload.
/// - DNS: [`FIXTURE_HOSTNAME`] returns [`FIXTURE_A_RECORD`] with [`FIXTURE_A_TTL_SECS`]; all
///   other names return NXDOMAIN.
/// - TCP echo on [`TCP_ECHO_PORT`]: send [`APP_REQUEST_BYTES`], receive [`APP_RESPONSE_BYTES`].
/// - TLS on [`TLS_PORT`] with server name [`TLS_SERVER_NAME`], certificate from
///   [`FIXTURE_CERT_PATH`], same application byte contract as TCP echo after handshake.
pub const FIXTURE_PEER: FixturePeer = FixturePeer::host_peer();

pub const GUEST_SOCKET: SocketAddrV4 = SocketAddrV4::new(GUEST_IPV4, 0);
