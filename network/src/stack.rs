//! Host-testable Ethernet / ARP / IPv4 / ICMP composition over [`NetworkLink`].

use crate::addr::{EtherType, IpProtocol, Ipv4Addr, MacAddr};
use crate::arp::{ArpCache, ArpPacket};
use crate::buffer::FrameBuf;
use crate::config::Ipv4Route;
use crate::device::NetworkLink;
use crate::error::NetworkError;
use crate::ethernet::{EthernetFrame, EthernetHeader, ParseError};
use crate::icmp::{build_echo_reply, build_echo_request, IcmpMessage};
use crate::ipv4::{Ipv4Header, IPV4_MIN_HEADER_LEN};
use crate::limits::{MAX_ETHERNET_FRAME_BYTES, MAX_L3_PAYLOAD_BYTES};

/// On-wire Ethernet header length (no VLAN).
pub const ETHERNET_HEADER_LEN: usize = EthernetHeader::LEN;

/// Minimum Ethernet frame size on the wire (excluding FCS).
pub const MIN_ETHERNET_FRAME_BYTES: usize = 60;

/// IPv4 header length for datagrams this stack generates (20 bytes, no options).
pub const STANDARD_IPV4_HEADER_LEN: usize = IPV4_MIN_HEADER_LEN;

/// Byte offset in a [`FrameBuf`] where L4 (UDP/TCP/ICMP) payload begins after
/// Ethernet + standard IPv4 headers written by this stack.
pub const fn l3_payload_offset() -> usize {
    ETHERNET_HEADER_LEN + STANDARD_IPV4_HEADER_LEN
}

/// IPv4 datagram delivered to upper layers with validated payload bounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv4Inbound {
    pub header: Ipv4Header,
    pub frame: FrameBuf,
    pub payload_offset: usize,
    pub payload_len: usize,
}

impl Ipv4Inbound {
    /// L4 payload slice (UDP/TCP/ICMP bytes), already bounded to the IPv4 `total_len`.
    pub fn payload(&self) -> &[u8] {
        let end = self
            .payload_offset
            .checked_add(self.payload_len)
            .unwrap_or(self.payload_offset);
        self.frame
            .as_slice()
            .get(self.payload_offset..end)
            .unwrap_or(&[])
    }
}

/// One inbound datagram for upper layers or echo clients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inbound {
    /// UDP/TCP payload for #124 / #125.
    Ipv4(Ipv4Inbound),
    /// ICMP echo reply delivered to a local ping client.
    IcmpEchoReply {
        id: u16,
        seq: u16,
        payload: FrameBuf,
    },
}

/// Non-fatal stack counters (malformed frames are dropped, not propagated).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StackStats {
    pub dropped_malformed: u64,
    pub dropped_fragmented: u64,
    pub arp_replies_sent: u64,
    pub icmp_replies_sent: u64,
    pub arp_requests_sent: u64,
    pub ipv4_forwarded: u64,
}

/// Bounded L2/L3 stack for one NIC / one IPv4 address, with one on-link prefix and an
/// optional default gateway ([`Ipv4Route`]).
pub struct L3Stack<L: NetworkLink> {
    link: L,
    our_mac: MacAddr,
    our_ip: Ipv4Addr,
    route: Ipv4Route,
    arp: ArpCache,
    stats: StackStats,
    next_identification: u16,
}

impl<L: NetworkLink> L3Stack<L> {
    /// Creates a stack bound to `our_mac` / `our_ip` on an on-link /24 with no gateway, with
    /// the given ARP cache TTL.
    pub fn new(link: L, our_mac: MacAddr, our_ip: Ipv4Addr, arp_ttl_ticks: u64) -> Self {
        Self::with_route(link, our_mac, Ipv4Route::on_link_24(our_ip), arp_ttl_ticks)
    }

    /// Creates a stack bound to `our_mac` and `route` (address, prefix, gateway).
    pub fn with_route(link: L, our_mac: MacAddr, route: Ipv4Route, arp_ttl_ticks: u64) -> Self {
        Self {
            link,
            our_mac,
            our_ip: route.local,
            route,
            arp: ArpCache::new(arp_ttl_ticks),
            stats: StackStats::default(),
            next_identification: 1,
        }
    }

    pub fn link(&self) -> &L {
        &self.link
    }

    pub fn link_mut(&mut self) -> &mut L {
        &mut self.link
    }

    pub fn our_mac(&self) -> MacAddr {
        self.our_mac
    }

    pub fn our_ip(&self) -> Ipv4Addr {
        self.our_ip
    }

    pub fn route(&self) -> Ipv4Route {
        self.route
    }

    pub fn stats(&self) -> StackStats {
        self.stats
    }

    pub fn arp_cache(&self) -> &ArpCache {
        &self.arp
    }

    pub fn arp_cache_mut(&mut self) -> &mut ArpCache {
        &mut self.arp
    }

    /// Clears ARP state and statistics, then resets the underlying link.
    pub fn reset(&mut self) -> Result<(), NetworkError> {
        self.arp.clear();
        self.stats = StackStats::default();
        self.next_identification = 1;
        self.link.reset().map_err(NetworkError::from)
    }

    /// Receives and dispatches at most one frame (`now` is a monotonic tick counter).
    pub fn poll(&mut self, now: u64) -> Result<Option<Inbound>, NetworkError> {
        self.arp.expire(now);
        let Some(frame) = self.link.receive()? else {
            return Ok(None);
        };
        self.dispatch_frame(frame, now)
    }

    /// Sends an IPv4 datagram to `dst_ip` through its next hop: `dst_ip` itself on the local
    /// prefix, else the gateway.
    ///
    /// Returns [`NetworkError::Unreachable`] when there is no route, or when the next hop's
    /// MAC is not cached and an ARP request was emitted (bounded); callers should `poll` and
    /// retry.
    pub fn send_ipv4<W>(
        &mut self,
        now: u64,
        dst_ip: Ipv4Addr,
        protocol: IpProtocol,
        payload_len: usize,
        write_payload: W,
    ) -> Result<(), NetworkError>
    where
        W: FnOnce(&mut [u8]) -> Result<(), NetworkError>,
    {
        let Some(next_hop) = self.route.next_hop(dst_ip) else {
            return Err(NetworkError::Unreachable);
        };
        if let Some(mac) = self.arp.lookup(next_hop, now) {
            return self.transmit_ipv4(
                mac,
                self.our_ip,
                dst_ip,
                protocol,
                payload_len,
                write_payload,
            );
        }
        if self.arp.track_pending(next_hop) {
            let req = ArpPacket::request(self.our_mac, self.our_ip, next_hop);
            let _ = self.transmit_arp(req, MacAddr::new([0xFF; 6]));
            self.stats.arp_requests_sent += 1;
        }
        Err(NetworkError::Unreachable)
    }

    /// Sends an ICMP echo request to `dst`.
    pub fn send_icmp_echo(
        &mut self,
        now: u64,
        dst: Ipv4Addr,
        id: u16,
        seq: u16,
        payload: &[u8],
    ) -> Result<(), NetworkError> {
        let icmp_len = 8usize
            .checked_add(payload.len())
            .ok_or(NetworkError::Protocol)?;
        self.send_ipv4(now, dst, IpProtocol::ICMP, icmp_len, |buf| {
            build_echo_request(id, seq, payload, buf).map_err(NetworkError::from)?;
            Ok(())
        })
    }

    fn dispatch_frame(
        &mut self,
        frame: FrameBuf,
        now: u64,
    ) -> Result<Option<Inbound>, NetworkError> {
        // Without an address the stack answers nothing and delivers nothing.
        if !self.route.is_configured() {
            return Ok(None);
        }
        let data = frame.as_slice();
        let (eth, l3) = match EthernetFrame::parse_frame(data) {
            Ok(v) => v,
            Err(_) => {
                self.stats.dropped_malformed += 1;
                return Ok(None);
            }
        };
        if eth.ethertype == EtherType::ARP {
            self.handle_arp(eth, l3, now)?;
            return Ok(None);
        }
        let (ipv4, payload) = match Ipv4Header::parse(l3) {
            Ok(v) => v,
            Err(ParseError::Fragmented) => {
                self.stats.dropped_fragmented += 1;
                return Ok(None);
            }
            Err(_) => {
                self.stats.dropped_malformed += 1;
                return Ok(None);
            }
        };
        if ipv4.dst != self.our_ip {
            return Ok(None);
        }
        if ipv4.protocol == IpProtocol::ICMP {
            match IcmpMessage::parse(payload) {
                Ok(IcmpMessage::EchoRequest {
                    id,
                    seq,
                    payload: echo_pl,
                }) => {
                    self.send_icmp_echo_reply(eth, ipv4, id, seq, echo_pl)?;
                }
                Ok(IcmpMessage::EchoReply {
                    id,
                    seq,
                    payload: echo_pl,
                }) => {
                    let payload_buf =
                        FrameBuf::from_slice(echo_pl).map_err(|_| NetworkError::Protocol)?;
                    return Ok(Some(Inbound::IcmpEchoReply {
                        id,
                        seq,
                        payload: payload_buf,
                    }));
                }
                Ok(_) | Err(_) => self.stats.dropped_malformed += 1,
            }
            return Ok(None);
        }
        if ipv4.protocol == IpProtocol::UDP || ipv4.protocol == IpProtocol::TCP {
            let payload_offset = ETHERNET_HEADER_LEN + ipv4.header_len;
            let payload_len = payload.len();
            let inbound = Ipv4Inbound {
                header: ipv4,
                frame,
                payload_offset,
                payload_len,
            };
            self.stats.ipv4_forwarded += 1;
            return Ok(Some(Inbound::Ipv4(inbound)));
        }
        self.stats.dropped_malformed += 1;
        Ok(None)
    }

    /// A reply is accepted only when it answers a request we still have outstanding:
    /// it names the IP we asked for, it is addressed to us, and it is not gratuitous.
    fn arp_reply_answers_pending(&self, arp: ArpPacket) -> bool {
        arp.sender_ip != arp.target_ip
            && arp.target_ip == self.our_ip
            && self.arp.is_pending(arp.sender_ip)
    }

    fn handle_arp(
        &mut self,
        eth: EthernetHeader,
        data: &[u8],
        now: u64,
    ) -> Result<(), NetworkError> {
        let arp = match ArpPacket::parse(data) {
            Ok(v) => v,
            Err(_) => {
                self.stats.dropped_malformed += 1;
                return Ok(());
            }
        };
        match arp.op {
            crate::arp::ArpOp::Request if arp.target_ip == self.our_ip => {
                let reply = ArpPacket::reply_to(arp, self.our_mac, self.our_ip);
                self.transmit_arp(reply, eth.src)?;
                self.stats.arp_replies_sent += 1;
            }
            crate::arp::ArpOp::Reply if self.arp_reply_answers_pending(arp) => {
                self.arp.insert(arp.sender_ip, arp.sender_mac, now);
            }
            _ => {}
        }
        Ok(())
    }

    fn send_icmp_echo_reply(
        &mut self,
        eth: EthernetHeader,
        ipv4: Ipv4Header,
        id: u16,
        seq: u16,
        payload: &[u8],
    ) -> Result<(), NetworkError> {
        let icmp_len = 8usize
            .checked_add(payload.len())
            .ok_or(NetworkError::Protocol)?;
        self.transmit_ipv4(
            eth.src,
            self.our_ip,
            ipv4.src,
            IpProtocol::ICMP,
            icmp_len,
            |buf| {
                build_echo_reply(IcmpMessage::EchoRequest { id, seq, payload }, buf)
                    .map_err(NetworkError::from)?;
                Ok(())
            },
        )?;
        self.stats.icmp_replies_sent += 1;
        Ok(())
    }

    fn transmit_arp(&mut self, arp: ArpPacket, dst_mac: MacAddr) -> Result<(), NetworkError> {
        let mut arp_bytes = [0u8; crate::arp::ARP_PACKET_LEN];
        arp.write(&mut arp_bytes).map_err(NetworkError::from)?;
        let eth = EthernetHeader {
            dst: dst_mac,
            src: self.our_mac,
            ethertype: EtherType::ARP,
        };
        let frame = EthernetFrame::build(eth, &arp_bytes).map_err(NetworkError::from)?;
        self.transmit_frame(frame)
    }

    fn transmit_ipv4<W>(
        &mut self,
        dst_mac: MacAddr,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        protocol: IpProtocol,
        payload_len: usize,
        write_payload: W,
    ) -> Result<(), NetworkError>
    where
        W: FnOnce(&mut [u8]) -> Result<(), NetworkError>,
    {
        if payload_len > MAX_L3_PAYLOAD_BYTES.saturating_sub(STANDARD_IPV4_HEADER_LEN) {
            return Err(NetworkError::Protocol);
        }
        let total = l3_payload_offset()
            .checked_add(payload_len)
            .ok_or(NetworkError::Protocol)?;
        if total > MAX_ETHERNET_FRAME_BYTES {
            return Err(NetworkError::Protocol);
        }

        let mut frame = FrameBuf::empty();
        reserve_zero_bytes(&mut frame, ETHERNET_HEADER_LEN).map_err(|_| NetworkError::Protocol)?;
        reserve_zero_bytes(&mut frame, STANDARD_IPV4_HEADER_LEN)
            .map_err(|_| NetworkError::Protocol)?;
        reserve_zero_bytes(&mut frame, payload_len).map_err(|_| NetworkError::Protocol)?;

        let slice = frame.as_mut_slice();
        let eth = EthernetHeader {
            dst: dst_mac,
            src: self.our_mac,
            ethertype: EtherType::IPV4,
        };
        eth.write(&mut slice[..ETHERNET_HEADER_LEN])
            .map_err(NetworkError::from)?;

        let mut ipv4 = Ipv4Header::new_template(src_ip, dst_ip, protocol);
        ipv4.identification = self.bump_identification();
        ipv4.write(
            &mut slice[ETHERNET_HEADER_LEN..l3_payload_offset()],
            payload_len,
        )
        .map_err(NetworkError::from)?;

        write_payload(&mut slice[l3_payload_offset()..l3_payload_offset() + payload_len])?;

        self.transmit_frame(frame)
    }

    fn bump_identification(&mut self) -> u16 {
        let id = self.next_identification;
        self.next_identification = self.next_identification.wrapping_add(1);
        id
    }

    fn transmit_frame(&mut self, frame: FrameBuf) -> Result<(), NetworkError> {
        let mut frame = frame;
        while frame.len() < MIN_ETHERNET_FRAME_BYTES {
            frame.push_bytes(&[0]).map_err(|_| NetworkError::Protocol)?;
        }
        match self.link.transmit(frame) {
            Ok(()) => Ok(()),
            Err((err, _frame)) => Err(NetworkError::Transport(err)),
        }
    }
}

fn reserve_zero_bytes(
    frame: &mut FrameBuf,
    mut len: usize,
) -> Result<(), crate::buffer::FrameBufError> {
    const CHUNK: [u8; 32] = [0; 32];
    while len > 0 {
        let n = len.min(CHUNK.len());
        frame.push_bytes(&CHUNK[..n])?;
        len -= n;
    }
    Ok(())
}

/// Whether `a` and `b` share the first `prefix_len` bits (`prefix_len` 0..=32).
pub fn same_subnet(a: Ipv4Addr, b: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len > 32 {
        return false;
    }
    Ipv4Route {
        local: a,
        prefix_len,
        gateway: None,
    }
    .on_link(b)
}

impl From<crate::device::NetworkDeviceError> for NetworkError {
    fn from(err: crate::device::NetworkDeviceError) -> Self {
        Self::Transport(err)
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::arp::ArpOp;
    use crate::fake::FakeLink;
    use crate::fixture::{GUEST_IPV4, PEER_IPV4};

    #[test]
    fn icmp_echo_over_fake_link() {
        let (link_a, link_b) = FakeLink::pair();
        let mac_a = link_a.link().mac;
        let mac_b = link_b.link().mac;
        let ip_a = GUEST_IPV4;
        let ip_b = PEER_IPV4;

        let mut a = L3Stack::new(link_a, mac_a, ip_a, 1000);
        let mut b = L3Stack::new(link_b, mac_b, ip_b, 1000);

        let payload = b"clean-slate-echo";
        let mut reply = None;
        for tick in 0..128 {
            let _ = b.poll(tick);
            let _ = a.poll(tick);
            let _ = a.send_icmp_echo(tick, ip_b, 42, 1, payload);
            let _ = b.poll(tick);
            if let Ok(Some(Inbound::IcmpEchoReply {
                id,
                seq,
                payload: pl,
            })) = a.poll(tick)
            {
                assert_eq!(id, 42);
                assert_eq!(seq, 1);
                assert_eq!(pl.as_slice(), payload);
                reply = Some(());
                break;
            }
        }
        assert!(reply.is_some());
        assert!(b.stats().icmp_replies_sent >= 1);
    }

    #[test]
    fn off_link_destinations_go_through_the_gateway() {
        let local = Ipv4Addr::new([10, 0, 2, 15]);
        let gateway = Ipv4Addr::new([10, 0, 2, 2]);
        let gateway_mac = MacAddr::new([0x52, 0x55, 0x0a, 0x00, 0x02, 0x02]);
        let remote = Ipv4Addr::new([192, 0, 2, 7]);
        let mac = MacAddr::new([0x02; 6]);
        let route = Ipv4Route {
            local,
            prefix_len: 24,
            gateway: Some(gateway),
        };
        let mut stack = L3Stack::with_route(FakeLink::new(mac, true), mac, route, 1000);
        let err = stack
            .send_ipv4(0, remote, IpProtocol::UDP, 0, |_| Ok(()))
            .unwrap_err();
        assert!(matches!(err, NetworkError::Unreachable));
        // The stack asked for the gateway, not the remote host.
        assert!(stack.arp_cache().is_pending(gateway));
        assert!(!stack.arp_cache().is_pending(remote));

        stack.arp_cache_mut().insert(gateway, gateway_mac, 0);
        stack.link().drained_tx();
        stack
            .send_ipv4(1, remote, IpProtocol::UDP, 0, |_| Ok(()))
            .unwrap();
        let sent = stack.link().drained_tx();
        assert_eq!(sent.len(), 1);
        let (eth, l3) = EthernetFrame::parse_frame(sent[0].as_slice()).unwrap();
        assert_eq!(eth.dst, gateway_mac);
        let (ipv4, _) = Ipv4Header::parse(l3).unwrap();
        assert_eq!(ipv4.dst, remote);
        assert_eq!(ipv4.src, local);
    }

    #[test]
    fn without_a_gateway_off_link_is_unreachable_and_sends_nothing() {
        let mac = MacAddr::new([0x02; 6]);
        let mut stack = L3Stack::new(FakeLink::new(mac, true), mac, GUEST_IPV4, 1000);
        let err = stack
            .send_ipv4(0, Ipv4Addr::new([192, 0, 2, 7]), IpProtocol::UDP, 0, |_| {
                Ok(())
            })
            .unwrap_err();
        assert!(matches!(err, NetworkError::Unreachable));
        assert_eq!(stack.link().tx_depth(), 0);
    }

    #[test]
    fn an_unconfigured_stack_sends_and_answers_nothing() {
        let mac = MacAddr::new([0x02; 6]);
        let mut stack =
            L3Stack::with_route(FakeLink::new(mac, true), mac, Ipv4Route::UNCONFIGURED, 1000);
        assert!(stack
            .send_ipv4(0, PEER_IPV4, IpProtocol::UDP, 0, |_| Ok(()))
            .is_err());
        let probe = ArpPacket::request(MacAddr::new([0x04; 6]), PEER_IPV4, Ipv4Addr::new([0; 4]));
        stack
            .link()
            .inject_rx(arp_frame(
                MacAddr::new([0xff; 6]),
                MacAddr::new([0x04; 6]),
                probe,
            ))
            .unwrap();
        assert!(stack.poll(0).unwrap().is_none());
        assert_eq!(stack.link().tx_depth(), 0);
    }

    #[test]
    fn malformed_inject_counted() {
        let link = FakeLink::new(MacAddr::new([0x02; 6]), true);
        link.inject_rx(FrameBuf::from_slice(b"garbage").unwrap())
            .unwrap();
        let mut stack = L3Stack::new(link, MacAddr::new([0x02; 6]), GUEST_IPV4, 10);
        assert!(stack.poll(0).unwrap().is_none());
        assert!(stack.stats().dropped_malformed >= 1);
    }

    #[test]
    fn reset_clears_cache() {
        let link = FakeLink::new(MacAddr::new([0; 6]), true);
        let mut stack = L3Stack::new(link, MacAddr::new([1; 6]), GUEST_IPV4, 10);
        stack
            .arp_cache_mut()
            .insert(PEER_IPV4, MacAddr::new([2; 6]), 0);
        assert!(stack.arp_cache().lookup(PEER_IPV4, 0).is_some());
        stack.reset().unwrap();
        assert!(stack.arp_cache().lookup(PEER_IPV4, 0).is_none());
        assert_eq!(stack.stats().dropped_malformed, 0);
    }

    fn arp_frame(dst: MacAddr, src: MacAddr, packet: ArpPacket) -> FrameBuf {
        let mut body = [0u8; crate::arp::ARP_PACKET_LEN];
        packet.write(&mut body).unwrap();
        let header = EthernetHeader {
            dst,
            src,
            ethertype: EtherType::ARP,
        };
        EthernetFrame::build(header, &body).unwrap()
    }

    fn solicit(stack: &mut L3Stack<FakeLink>, mac: MacAddr) {
        let err = stack
            .send_ipv4(0, PEER_IPV4, IpProtocol::ICMP, 0, |_| Ok(()))
            .unwrap_err();
        assert!(matches!(err, NetworkError::Unreachable));
        assert!(stack.arp_cache().is_pending(PEER_IPV4));
        let reply = ArpPacket {
            op: ArpOp::Reply,
            sender_mac: MacAddr::new([0x52, 0x54, 0x00, 0xab, 0xcd, 0xef]),
            sender_ip: PEER_IPV4,
            target_mac: mac,
            target_ip: GUEST_IPV4,
        };
        stack
            .link()
            .inject_rx(arp_frame(mac, reply.sender_mac, reply))
            .unwrap();
        assert!(stack.poll(1).unwrap().is_none());
    }

    #[test]
    fn unsolicited_arp_reply_is_ignored() {
        let mac = MacAddr::new([0x02, 0, 0, 0, 0, 2]);
        let link = FakeLink::new(mac, true);
        let mut stack = L3Stack::new(link, mac, GUEST_IPV4, 1000);
        let reply = ArpPacket {
            op: ArpOp::Reply,
            sender_mac: MacAddr::new([0x02, 0x21, 0, 0, 0, 0x66]),
            sender_ip: PEER_IPV4,
            target_mac: mac,
            target_ip: GUEST_IPV4,
        };
        stack
            .link()
            .inject_rx(arp_frame(mac, reply.sender_mac, reply))
            .unwrap();
        assert!(stack.poll(0).unwrap().is_none());
        assert!(stack.arp_cache().lookup(PEER_IPV4, 0).is_none());
    }

    #[test]
    fn arp_reply_for_a_different_ip_is_ignored() {
        let mac = MacAddr::new([0x02, 0, 0, 0, 0, 2]);
        let link = FakeLink::new(mac, true);
        let mut stack = L3Stack::new(link, mac, GUEST_IPV4, 1000);
        let err = stack
            .send_ipv4(0, PEER_IPV4, IpProtocol::ICMP, 0, |_| Ok(()))
            .unwrap_err();
        assert!(matches!(err, NetworkError::Unreachable));
        let other = Ipv4Addr::new([10, 77, 0, 9]);
        let reply = ArpPacket {
            op: ArpOp::Reply,
            sender_mac: MacAddr::new([0x02, 0x21, 0, 0, 0, 0x66]),
            sender_ip: other,
            target_mac: mac,
            target_ip: GUEST_IPV4,
        };
        stack
            .link()
            .inject_rx(arp_frame(mac, reply.sender_mac, reply))
            .unwrap();
        assert!(stack.poll(1).unwrap().is_none());
        assert!(stack.arp_cache().lookup(PEER_IPV4, 1).is_none());
        assert!(stack.arp_cache().lookup(other, 1).is_none());
        assert!(stack.arp_cache().is_pending(PEER_IPV4));
    }

    #[test]
    fn gratuitous_arp_does_not_overwrite_an_entry() {
        let mac = MacAddr::new([0x02, 0, 0, 0, 0, 2]);
        let real = MacAddr::new([0x52, 0x54, 0x00, 0xab, 0xcd, 0xef]);
        let link = FakeLink::new(mac, true);
        let mut stack = L3Stack::new(link, mac, GUEST_IPV4, 1000);
        solicit(&mut stack, mac);
        assert_eq!(stack.arp_cache().lookup(PEER_IPV4, 1), Some(real));
        let poison = MacAddr::new([0x02, 0x21, 0, 0, 0, 0x66]);
        let gratuitous = ArpPacket {
            op: ArpOp::Reply,
            sender_mac: poison,
            sender_ip: PEER_IPV4,
            target_mac: poison,
            target_ip: PEER_IPV4,
        };
        stack
            .link()
            .inject_rx(arp_frame(mac, poison, gratuitous))
            .unwrap();
        assert!(stack.poll(2).unwrap().is_none());
        assert_eq!(stack.arp_cache().lookup(PEER_IPV4, 2), Some(real));
    }

    #[test]
    fn ipv4_packets_do_not_create_or_overwrite_arp_entries() {
        let mac = MacAddr::new([0x02, 0, 0, 0, 0, 2]);
        let real = MacAddr::new([0x52, 0x54, 0x00, 0xab, 0xcd, 0xef]);
        let poison = MacAddr::new([0x02, 0x21, 0, 0, 0, 0x66]);
        let link = FakeLink::new(mac, true);
        let mut stack = L3Stack::new(link, mac, GUEST_IPV4, 1000);
        stack.link().inject_rx(ipv4_frame(poison, mac)).unwrap();
        assert!(stack.poll(0).unwrap().is_none());
        assert!(stack.arp_cache().lookup(PEER_IPV4, 0).is_none());
        solicit(&mut stack, mac);
        stack.link().inject_rx(ipv4_frame(poison, mac)).unwrap();
        assert!(stack.poll(2).unwrap().is_none());
        assert_eq!(stack.arp_cache().lookup(PEER_IPV4, 2), Some(real));
    }

    fn ipv4_frame(src_mac: MacAddr, dst_mac: MacAddr) -> FrameBuf {
        let mut payload = [0u8; 20];
        Ipv4Header::new_template(PEER_IPV4, GUEST_IPV4, IpProtocol::ICMP)
            .write(&mut payload, 0)
            .unwrap();
        let header = EthernetHeader {
            dst: dst_mac,
            src: src_mac,
            ethertype: EtherType::IPV4,
        };
        EthernetFrame::build(header, &payload).unwrap()
    }
}
