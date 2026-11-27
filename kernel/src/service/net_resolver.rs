//! The resolver Linux programs read from `/etc/resolv.conf` (#354).
//!
//! The launch configuration's resolver when it names one; otherwise the one the live network
//! service published (`NET_SUBOP_PUBLISH_RESOLVER`), which is its DHCP lease's. A publication
//! counts only while the instance that sent it is live, so a stopped or restarted service
//! leaves no stale address behind. With neither, the file is empty.

use core::sync::atomic::{AtomicU64, Ordering};

use clean_slate_network::addr::SocketAddrV4;
#[cfg(clean_slate_linux_rootfs)]
use clean_slate_network::config::{resolv_conf, RESOLV_CONF_MAX_BYTES};

/// Pid of the service instance that published [`PUBLISHED_RESOLVER`]; 0 = none.
static PUBLISHER_PID: AtomicU64 = AtomicU64::new(0);
/// [`encode`]d resolver; 0 = none.
static PUBLISHED_RESOLVER: AtomicU64 = AtomicU64::new(0);

const PRESENT: u64 = 1 << 48;

fn encode(resolver: Option<SocketAddrV4>) -> u64 {
    resolver.map_or(0, |resolver| {
        PRESENT
            | u64::from(u32::from_be_bytes(resolver.addr.octets())) << 16
            | u64::from(resolver.port)
    })
}

#[cfg(any(clean_slate_linux_rootfs, test))]
fn decode(raw: u64) -> Option<SocketAddrV4> {
    (raw & PRESENT != 0).then(|| {
        SocketAddrV4::new(
            clean_slate_network::addr::Ipv4Addr::new(((raw >> 16) as u32).to_be_bytes()),
            raw as u16,
        )
    })
}

/// Records what service instance `pid` resolves through.
pub(crate) fn publish(pid: u64, resolver: Option<SocketAddrV4>) {
    PUBLISHER_PID.store(0, Ordering::Release);
    PUBLISHED_RESOLVER.store(encode(resolver), Ordering::Release);
    PUBLISHER_PID.store(pid, Ordering::Release);
}

#[cfg(clean_slate_linux_rootfs)]
fn launch_resolver() -> Option<SocketAddrV4> {
    crate::service::net_launch::network_config()
        .parse()
        .ok()
        .and_then(|network| network.resolver)
}

#[cfg(any(clean_slate_linux_rootfs, test))]
fn published_resolver(live_service_pid: Option<u64>) -> Option<SocketAddrV4> {
    let pid = PUBLISHER_PID.load(Ordering::Acquire);
    if pid == 0 || live_service_pid != Some(pid) {
        return None;
    }
    decode(PUBLISHED_RESOLVER.load(Ordering::Acquire))
}

/// The resolver Linux programs use now.
#[cfg(clean_slate_linux_rootfs)]
pub(crate) fn current_resolver() -> Option<SocketAddrV4> {
    launch_resolver()
        .or_else(|| published_resolver(crate::service::net_syscall::live_network_service_pid()))
}

/// The bytes of `/etc/resolv.conf` now.
#[cfg(clean_slate_linux_rootfs)]
pub(crate) struct ResolvConf {
    bytes: [u8; RESOLV_CONF_MAX_BYTES],
    len: usize,
}

#[cfg(clean_slate_linux_rootfs)]
impl ResolvConf {
    pub(crate) fn now() -> Self {
        Self::for_resolver(current_resolver())
    }

    fn for_resolver(resolver: Option<SocketAddrV4>) -> Self {
        let mut bytes = [0u8; RESOLV_CONF_MAX_BYTES];
        let len = resolv_conf(resolver, &mut bytes);
        Self { bytes, len }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_network::addr::Ipv4Addr;

    #[test]
    fn encoding_round_trips() {
        for resolver in [
            None,
            Some(SocketAddrV4::new(Ipv4Addr::new([0, 0, 0, 0]), 0)),
            Some(SocketAddrV4::new(Ipv4Addr::new([10, 0, 2, 3]), 53)),
            Some(SocketAddrV4::new(Ipv4Addr::new([255; 4]), u16::MAX)),
        ] {
            assert_eq!(decode(encode(resolver)), resolver);
        }
    }

    #[test]
    fn a_publication_counts_only_while_its_service_is_live() {
        let leased = SocketAddrV4::new(Ipv4Addr::new([10, 0, 2, 3]), 53);
        publish(41, Some(leased));
        assert_eq!(published_resolver(Some(41)), Some(leased));
        assert_eq!(published_resolver(Some(42)), None);
        assert_eq!(published_resolver(None), None);
        publish(42, None);
        assert_eq!(published_resolver(Some(42)), None);
    }

    #[cfg(clean_slate_linux_rootfs)]
    #[test]
    fn resolv_conf_is_one_nameserver_line_or_empty() {
        let leased = SocketAddrV4::new(Ipv4Addr::new([10, 0, 2, 3]), 53);
        assert_eq!(
            ResolvConf::for_resolver(Some(leased)).as_bytes(),
            b"nameserver 10.0.2.3\n"
        );
        assert_eq!(ResolvConf::for_resolver(None).as_bytes(), b"");
    }
}
