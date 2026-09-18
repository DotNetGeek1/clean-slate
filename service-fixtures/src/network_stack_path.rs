//! L3/DNS/TCP path for M7.8 (shared stack: DNS resolver then TCP transport).

use clean_slate_network::addr::SocketAddrV4;
use clean_slate_network::device::NetworkLink;
use clean_slate_network::dns::{DnsError, DnsResolver, ResolveOutcome};
use clean_slate_network::error::NetworkError;
use clean_slate_network::fixture::{DNS_SERVER_ADDR, GUEST_IPV4};
use clean_slate_network::protocol::TrustedCaller;
use clean_slate_network::session::{SessionGeneration, SessionId};
use clean_slate_network::stack::L3Stack;
use clean_slate_network::tcp::TcpState;
use clean_slate_network::tcp::TcpTransport;

use crate::network_service::{NetworkResolveConnect, PacketPath};

const ARP_TTL_TICKS: u64 = 50_000;
const POLL_BURST: u64 = 256;
const CONNECT_POLL_LIMIT: u64 = 50_000;

enum Backend<L: NetworkLink> {
    None,
    Resolver(DnsResolver<L>),
    Tcp(TcpTransport<L>),
}

/// Drives DNS then TCP on one virtio-backed link (no VirtIO types here).
pub struct NetworkStackPath<L: NetworkLink> {
    backend: Backend<L>,
    generation: SessionGeneration,
    tick: u64,
}

impl<L: NetworkLink> NetworkStackPath<L> {
    pub fn new(generation: SessionGeneration) -> Self {
        Self {
            backend: Backend::None,
            generation,
            tick: 0,
        }
    }

    pub fn attach(&mut self, link: L) {
        let mac = link.link().mac;
        let stack = L3Stack::new(link, mac, GUEST_IPV4, ARP_TTL_TICKS);
        let resolver = DnsResolver::new(
            clean_slate_network::udp::UdpTransport::new(stack, self.generation),
            DNS_SERVER_ADDR,
        );
        self.backend = Backend::Resolver(resolver);
    }

    pub fn poll(&mut self) {
        self.tick = self.tick.saturating_add(1);
        let now = self.tick;
        match &mut self.backend {
            Backend::Resolver(resolver) => {
                let _ = resolver.poll(now);
            }
            Backend::Tcp(tcp) => {
                let _ = tcp.poll(now);
            }
            Backend::None => {}
        }
    }

    pub fn malformed_drop_count(&self) -> u64 {
        match &self.backend {
            Backend::Resolver(resolver) => resolver.stats().dropped_malformed,
            Backend::Tcp(tcp) => {
                let stats = tcp.stats();
                stats.dropped_bad_checksum
            }
            Backend::None => 0,
        }
    }

    pub fn tcp_connections_in_use(&self) -> usize {
        match &self.backend {
            Backend::Tcp(tcp) => tcp.connections_in_use(),
            _ => 0,
        }
    }

    pub fn resolve(
        &mut self,
        caller: TrustedCaller,
        name: &str,
    ) -> Result<(clean_slate_network::addr::Ipv4Addr, u32), NetworkError> {
        let resolver = match &mut self.backend {
            Backend::Resolver(resolver) => resolver,
            _ => return Err(NetworkError::Transport(clean_slate_network::device::NetworkDeviceError::NotReady)),
        };
        let now = self.tick;
        let outcome = resolver.resolve(now, caller, name).map_err(map_dns)?;
        match outcome {
            ResolveOutcome::Cached { addr, ttl } => Ok((addr, ttl)),
            ResolveOutcome::Pending { query_id } => {
                for _ in 0..CONNECT_POLL_LIMIT {
                    self.tick = self.tick.saturating_add(1);
                    let now = self.tick;
                    let _ = resolver.poll(now);
                    if let Some(result) = resolver.take_result(query_id, caller) {
                        return result.map_err(map_dns);
                    }
                }
                Err(NetworkError::Timeout)
            }
        }
    }

    fn transition_to_tcp(&mut self) -> Result<(), NetworkError> {
        let taken = core::mem::replace(&mut self.backend, Backend::None);
        match taken {
            Backend::Resolver(resolver) => {
                self.backend = Backend::Tcp(resolver.into_tcp_transport(self.generation));
                Ok(())
            }
            Backend::Tcp(tcp) => {
                self.backend = Backend::Tcp(tcp);
                Ok(())
            }
            Backend::None => {
                self.backend = Backend::None;
                Err(NetworkError::Transport(
                    clean_slate_network::device::NetworkDeviceError::NotReady,
                ))
            }
        }
    }

    fn tcp_mut(&mut self) -> Result<&mut TcpTransport<L>, NetworkError> {
        self.transition_to_tcp()?;
        match &mut self.backend {
            Backend::Tcp(tcp) => Ok(tcp),
            _ => Err(NetworkError::Transport(
                clean_slate_network::device::NetworkDeviceError::NotReady,
            )),
        }
    }

    pub fn connect_tcp(
        &mut self,
        caller: TrustedCaller,
        session: SessionId,
        dest: SocketAddrV4,
    ) -> Result<(), NetworkError> {
        self.transition_to_tcp()?;
        let now = self.tick;
        let id = self
            .tcp_mut()?
            .connect_at_index(now, caller, dest, session.index())?;
        if id != session {
            return Err(NetworkError::Protocol);
        }
        for _ in 0..CONNECT_POLL_LIMIT {
            self.tick = self.tick.saturating_add(1);
            let now = self.tick;
            let tcp = self.tcp_mut()?;
            let _ = tcp.poll(now);
            if tcp.state(session, caller)? == TcpState::Established {
                return Ok(());
            }
        }
        Err(NetworkError::Timeout)
    }

    pub fn reset_backend(&mut self, link: L) {
        self.attach(link);
    }
}

impl<L: NetworkLink> NetworkResolveConnect for NetworkStackPath<L> {
    fn resolve_name(
        &mut self,
        caller: TrustedCaller,
        name: &str,
    ) -> Result<(clean_slate_network::addr::Ipv4Addr, u32), NetworkError> {
        self.resolve(caller, name)
    }

    fn connect_session(
        &mut self,
        caller: TrustedCaller,
        session: SessionId,
        dest: SocketAddrV4,
    ) -> Result<(), NetworkError> {
        self.connect_tcp(caller, session, dest)
    }

    fn poll_idle(&mut self) {
        self.poll();
    }
}

impl<L: NetworkLink> PacketPath for NetworkStackPath<L> {
    fn on_send(
        &mut self,
        caller: TrustedCaller,
        session: SessionId,
        payload: &[u8],
        _link: &mut dyn NetworkLink,
    ) -> Result<u32, NetworkError> {
        self.transition_to_tcp()?;
        let now = self.tick;
        for _ in 0..POLL_BURST {
            self.tick = self.tick.saturating_add(1);
            let tick = self.tick;
            let _ = self.tcp_mut()?.poll(tick);
        }
        let n = self.tcp_mut()?.send(now, session, caller, payload)?;
        Ok(n as u32)
    }

    fn on_receive(
        &mut self,
        caller: TrustedCaller,
        session: SessionId,
        max_len: u32,
        _link: &mut dyn NetworkLink,
        out: &mut [u8],
    ) -> Result<u32, NetworkError> {
        self.transition_to_tcp()?;
        for _ in 0..CONNECT_POLL_LIMIT {
            self.tick = self.tick.saturating_add(1);
            let now = self.tick;
            let _ = self.tcp_mut()?.poll(now);
            let n = self.tcp_mut()?.receive(session, caller, out)?;
            if n > 0 {
                return Ok(n.min(max_len as usize) as u32);
            }
        }
        Ok(0)
    }
}

fn map_dns(err: DnsError) -> NetworkError {
    NetworkError::from(err)
}
