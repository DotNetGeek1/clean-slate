//! DHCPv4 client (RFC 2131, options from RFC 2132): one lease at service start.
//!
//! [`DhcpClient`] is sans-IO: it builds whole Ethernet frames for the caller to transmit and
//! reads whole received frames, so it runs before any IPv4 stack exists (the client has no
//! address yet; it sends from `0.0.0.0` to the limited broadcast address). The caller owns the
//! clock and the retransmission schedule ([`DhcpClient::retransmit_delay_ms`]).
//!
//! The exchange is DISCOVER, OFFER, REQUEST, ACK. The client takes the first acceptable
//! OFFER; a NAK, or an ACK for a different address, starts over from DISCOVER. Replies are
//! accepted only when they carry this client's transaction id and hardware address, come from
//! UDP port 67 to port 68, and (after an OFFER was taken) name the server that made it.
//!
//! Not here yet: renewing (T1/T2) or releasing the lease, and ARP-probing the offered address
//! before using it (RFC 2131 §2.2 "SHOULD").

use crate::addr::{EtherType, IpProtocol, Ipv4Addr, MacAddr};
use crate::buffer::FrameBuf;
use crate::checksum::Checksum;
use crate::ethernet::{EthernetFrame, EthernetHeader};
use crate::ipv4::{pseudo_header_checksum, Ipv4Header, IPV4_MIN_HEADER_LEN};
use crate::udp::UDP_HEADER_LEN;

pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;

const OP_BOOTREQUEST: u8 = 1;
const OP_BOOTREPLY: u8 = 2;
const HTYPE_ETHERNET: u8 = 1;
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
/// Fixed BOOTP header up to and including the magic cookie.
const BOOTP_FIXED_LEN: usize = 240;
/// Minimum BOOTP message a client sends (RFC 1542 §2.1: some relays drop shorter ones).
const BOOTP_MIN_LEN: usize = 300;
/// BOOTP `flags` broadcast bit: asks the server to broadcast its replies.
const FLAG_BROADCAST: u16 = 0x8000;

const OPT_PAD: u8 = 0;
const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MESSAGE_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAMETER_LIST: u8 = 55;
const OPT_MAX_MESSAGE_SIZE: u8 = 57;
const OPT_CLIENT_ID: u8 = 61;
const OPT_END: u8 = 255;

const MSG_DISCOVER: u8 = 1;
const MSG_OFFER: u8 = 2;
const MSG_REQUEST: u8 = 3;
const MSG_ACK: u8 = 5;
const MSG_NAK: u8 = 6;

/// First retransmission delay; it doubles per attempt up to [`MAX_RETRANSMIT_MS`] (RFC 2131
/// §4.1 asks for 4 s doubling to 64 s with jitter; a service waiting to start uses less).
const FIRST_RETRANSMIT_MS: u64 = 1_000;
const MAX_RETRANSMIT_MS: u64 = 8_000;

/// The address configuration a server granted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DhcpLease {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    /// First router the server named, if it is on the leased prefix.
    pub router: Option<Ipv4Addr>,
    /// First DNS server the server named.
    pub dns: Option<Ipv4Addr>,
    pub server: Ipv4Addr,
    /// Lease length in seconds; `u32::MAX` is infinite.
    pub lease_secs: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Sending DISCOVER, waiting for an OFFER.
    Selecting,
    /// Sending REQUEST for `offer`, waiting for its ACK.
    Requesting {
        offer: DhcpLease,
    },
    Bound {
        lease: DhcpLease,
    },
}

/// What a received frame did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhcpEvent {
    /// Not a reply for this client, or nothing changed.
    Ignored,
    /// An OFFER was taken: send [`DhcpClient::frame`] (now a REQUEST) at once.
    Offered,
    /// The server NAKed (or ACKed something else): send [`DhcpClient::frame`] (a DISCOVER
    /// again) at once.
    Restarted,
    /// The lease is granted.
    Bound(DhcpLease),
}

/// A DHCPv4 client for one interface (see the module docs).
#[derive(Clone, Debug)]
pub struct DhcpClient {
    mac: MacAddr,
    xid: u32,
    state: State,
    /// Frames sent in the current state, for the backoff.
    attempts: u32,
}

impl DhcpClient {
    /// A client for the interface with hardware address `mac`; `xid` should be random.
    pub fn new(mac: MacAddr, xid: u32) -> Self {
        Self {
            mac,
            xid,
            state: State::Selecting,
            attempts: 0,
        }
    }

    pub fn lease(&self) -> Option<DhcpLease> {
        match self.state {
            State::Bound { lease } => Some(lease),
            _ => None,
        }
    }

    /// The frame to send now: DISCOVER while selecting, REQUEST while requesting, and
    /// `None` once bound. Each call counts as one transmission for the backoff.
    pub fn frame(&mut self) -> Option<FrameBuf> {
        let (message_type, offer) = match self.state {
            State::Selecting => (MSG_DISCOVER, None),
            State::Requesting { offer } => (MSG_REQUEST, Some(offer)),
            State::Bound { .. } => return None,
        };
        self.attempts = self.attempts.saturating_add(1);
        let mut message = [0u8; BOOTP_MIN_LEN];
        message[0] = OP_BOOTREQUEST;
        message[1] = HTYPE_ETHERNET;
        message[2] = 6;
        message[4..8].copy_from_slice(&self.xid.to_be_bytes());
        message[10..12].copy_from_slice(&FLAG_BROADCAST.to_be_bytes());
        message[28..34].copy_from_slice(&self.mac.octets());
        message[236..240].copy_from_slice(&MAGIC_COOKIE);
        let mut options = Options {
            out: &mut message[BOOTP_FIXED_LEN..],
            at: 0,
        };
        options.put(OPT_MESSAGE_TYPE, &[message_type]);
        let mut client_id = [HTYPE_ETHERNET, 0, 0, 0, 0, 0, 0];
        client_id[1..].copy_from_slice(&self.mac.octets());
        options.put(OPT_CLIENT_ID, &client_id);
        if let Some(offer) = offer {
            options.put(OPT_REQUESTED_IP, &offer.address.octets());
            options.put(OPT_SERVER_ID, &offer.server.octets());
        }
        options.put(
            OPT_PARAMETER_LIST,
            &[
                OPT_SUBNET_MASK,
                OPT_ROUTER,
                OPT_DNS,
                OPT_LEASE_TIME,
                OPT_SERVER_ID,
            ],
        );
        options.put(OPT_MAX_MESSAGE_SIZE, &1_500u16.to_be_bytes());
        options.end();
        build_frame(self.mac, &message).ok()
    }

    /// How long to wait for a reply to the frame just sent before sending it again.
    pub fn retransmit_delay_ms(&self) -> u64 {
        let shift = self.attempts.saturating_sub(1).min(8);
        (FIRST_RETRANSMIT_MS << shift).min(MAX_RETRANSMIT_MS)
    }

    /// Frames sent in the current state.
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Reads one received Ethernet frame.
    pub fn handle_frame(&mut self, frame: &[u8]) -> DhcpEvent {
        let Some(reply) = parse_reply(frame, self.mac, self.xid) else {
            return DhcpEvent::Ignored;
        };
        match (self.state, reply.message_type) {
            (State::Selecting, MSG_OFFER) => match reply.lease() {
                Some(offer) => {
                    self.state = State::Requesting { offer };
                    self.attempts = 0;
                    DhcpEvent::Offered
                }
                None => DhcpEvent::Ignored,
            },
            (State::Requesting { offer }, MSG_ACK | MSG_NAK)
                if reply.server_id != Some(offer.server) =>
            {
                DhcpEvent::Ignored
            }
            (State::Requesting { offer }, MSG_ACK) => match reply.lease() {
                Some(lease) if lease.address == offer.address => {
                    self.state = State::Bound { lease };
                    DhcpEvent::Bound(lease)
                }
                _ => self.restart(),
            },
            (State::Requesting { .. }, MSG_NAK) => self.restart(),
            _ => DhcpEvent::Ignored,
        }
    }

    fn restart(&mut self) -> DhcpEvent {
        self.state = State::Selecting;
        self.attempts = 0;
        DhcpEvent::Restarted
    }
}

struct Options<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl Options<'_> {
    /// Every option the client writes fits the 60 bytes after the cookie.
    fn put(&mut self, code: u8, value: &[u8]) {
        let end = self.at + 2 + value.len();
        self.out[self.at] = code;
        self.out[self.at + 1] = value.len() as u8;
        self.out[self.at + 2..end].copy_from_slice(value);
        self.at = end;
    }

    fn end(&mut self) {
        self.out[self.at] = OPT_END;
    }
}

/// A broadcast Ethernet + IPv4 (`0.0.0.0` to `255.255.255.255`) + UDP (68 to 67) frame.
fn build_frame(mac: MacAddr, message: &[u8]) -> Result<FrameBuf, crate::ethernet::ParseError> {
    let src = Ipv4Addr::new([0; 4]);
    let dst = Ipv4Addr::new([255; 4]);
    let udp_len = UDP_HEADER_LEN + message.len();
    let mut packet = [0u8; IPV4_MIN_HEADER_LEN + UDP_HEADER_LEN + BOOTP_MIN_LEN];
    let mut header = Ipv4Header::new_template(src, dst, IpProtocol::UDP);
    header.ttl = 64;
    header.write(&mut packet, udp_len)?;
    let udp = &mut packet[IPV4_MIN_HEADER_LEN..];
    udp[0..2].copy_from_slice(&DHCP_CLIENT_PORT.to_be_bytes());
    udp[2..4].copy_from_slice(&DHCP_SERVER_PORT.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[UDP_HEADER_LEN..udp_len].copy_from_slice(message);
    let sum = pseudo_header_checksum(src, dst, IpProtocol::UDP, udp_len as u16)
        .add_bytes(&udp[..udp_len])
        .finish();
    let sum = if sum == 0 { 0xffff } else { sum };
    udp[6..8].copy_from_slice(&sum.to_be_bytes());
    EthernetFrame::build(
        EthernetHeader {
            dst: MacAddr::new([0xff; 6]),
            src: mac,
            ethertype: EtherType::IPV4,
        },
        &packet[..IPV4_MIN_HEADER_LEN + udp_len],
    )
}

/// The parts of a server reply the client uses.
#[derive(Clone, Copy, Debug, Default)]
struct Reply {
    message_type: u8,
    yiaddr: [u8; 4],
    server_id: Option<Ipv4Addr>,
    mask: Option<[u8; 4]>,
    router: Option<Ipv4Addr>,
    dns: Option<Ipv4Addr>,
    lease_secs: Option<u32>,
}

impl Reply {
    /// The lease this OFFER or ACK describes, if it is usable: a unicast address, a server
    /// id, and a contiguous mask (or the address's classful default when none is given). A
    /// router off the leased prefix, or equal to the address, is dropped.
    fn lease(&self) -> Option<DhcpLease> {
        let address = Ipv4Addr::new(self.yiaddr);
        let server = self.server_id?;
        if !unicast(self.yiaddr) {
            return None;
        }
        let prefix_len = match self.mask {
            Some(mask) => mask_prefix(mask)?,
            None => classful_prefix(self.yiaddr)?,
        };
        if prefix_len == 0 || prefix_len > 32 {
            return None;
        }
        let router = self.router.filter(|&router| {
            router != address
                && unicast(router.octets())
                && same_prefix(router, address, prefix_len)
        });
        Some(DhcpLease {
            address,
            prefix_len,
            router,
            dns: self.dns.filter(|dns| unicast(dns.octets())),
            server,
            lease_secs: self.lease_secs.unwrap_or(0),
        })
    }
}

fn unicast(o: [u8; 4]) -> bool {
    o != [0; 4] && o != [255; 4] && !(224..=255).contains(&o[0]) && o[0] != 127
}

fn mask_prefix(mask: [u8; 4]) -> Option<u8> {
    let mask = u32::from_be_bytes(mask);
    let prefix = mask.leading_ones();
    (mask.checked_shl(prefix).unwrap_or(0) == 0).then_some(prefix as u8)
}

fn classful_prefix(addr: [u8; 4]) -> Option<u8> {
    match addr[0] {
        0..=127 => Some(8),
        128..=191 => Some(16),
        192..=223 => Some(24),
        _ => None,
    }
}

fn same_prefix(a: Ipv4Addr, b: Ipv4Addr, prefix_len: u8) -> bool {
    let mask = u32::MAX
        .checked_shl(32 - u32::from(prefix_len))
        .unwrap_or(0);
    u32::from_be_bytes(a.octets()) & mask == u32::from_be_bytes(b.octets()) & mask
}

/// A BOOTREPLY for `mac` with transaction id `xid`, from UDP port 67 to port 68, or `None`.
fn parse_reply(frame: &[u8], mac: MacAddr, xid: u32) -> Option<Reply> {
    let (eth, l3) = EthernetFrame::parse_frame(frame).ok()?;
    if eth.ethertype != EtherType::IPV4 {
        return None;
    }
    let (ip, l4) = Ipv4Header::parse(l3).ok()?;
    if ip.protocol != IpProtocol::UDP || l4.len() < UDP_HEADER_LEN {
        return None;
    }
    let src_port = u16::from_be_bytes([l4[0], l4[1]]);
    let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
    let udp_len = usize::from(u16::from_be_bytes([l4[4], l4[5]]));
    let wire_sum = u16::from_be_bytes([l4[6], l4[7]]);
    if src_port != DHCP_SERVER_PORT || dst_port != DHCP_CLIENT_PORT {
        return None;
    }
    if udp_len < UDP_HEADER_LEN || udp_len > l4.len() {
        return None;
    }
    let datagram = &l4[..udp_len];
    // A zero UDP checksum means "not computed" over IPv4 (RFC 768); some servers send it.
    if wire_sum != 0 {
        let sum: Checksum = pseudo_header_checksum(ip.src, ip.dst, IpProtocol::UDP, udp_len as u16)
            .add_bytes(datagram);
        if sum.finish() != 0 {
            return None;
        }
    }
    let message = &datagram[UDP_HEADER_LEN..];
    if message.len() < BOOTP_FIXED_LEN
        || message[0] != OP_BOOTREPLY
        || message[1] != HTYPE_ETHERNET
        || message[2] != 6
        || message[4..8] != xid.to_be_bytes()
        || message[28..34] != mac.octets()
        || message[236..240] != MAGIC_COOKIE
    {
        return None;
    }
    let mut reply = Reply {
        yiaddr: message[16..20].try_into().ok()?,
        ..Reply::default()
    };
    let mut options = &message[BOOTP_FIXED_LEN..];
    loop {
        let (&code, rest) = options.split_first()?;
        match code {
            OPT_PAD => {
                options = rest;
                continue;
            }
            OPT_END => break,
            _ => {}
        }
        let (&len, rest) = rest.split_first()?;
        let len = usize::from(len);
        if rest.len() < len {
            return None;
        }
        let (value, rest) = rest.split_at(len);
        options = rest;
        let first_addr = || {
            value
                .get(..4)
                .map(|v| Ipv4Addr::new([v[0], v[1], v[2], v[3]]))
        };
        match code {
            OPT_MESSAGE_TYPE if len == 1 => reply.message_type = value[0],
            OPT_SERVER_ID if len == 4 => reply.server_id = first_addr(),
            OPT_SUBNET_MASK if len == 4 => reply.mask = value.try_into().ok(),
            OPT_ROUTER if len >= 4 && len % 4 == 0 => reply.router = first_addr(),
            OPT_DNS if len >= 4 && len % 4 == 0 => reply.dns = first_addr(),
            OPT_LEASE_TIME if len == 4 => {
                reply.lease_secs = Some(u32::from_be_bytes(value.try_into().ok()?))
            }
            _ => {}
        }
    }
    (reply.message_type != 0).then_some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: MacAddr = MacAddr::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    const SERVER_MAC: MacAddr = MacAddr::new([0x52, 0x55, 0x0a, 0x00, 0x02, 0x02]);
    const SERVER: [u8; 4] = [10, 0, 2, 2];
    const XID: u32 = 0x1234_5678;

    /// The pieces of a client frame the test server reads.
    struct Request {
        message_type: u8,
        requested: Option<[u8; 4]>,
        server_id: Option<[u8; 4]>,
        broadcast: bool,
    }

    fn read_request(frame: &FrameBuf) -> Request {
        let (eth, l3) = EthernetFrame::parse_frame(frame.as_slice()).unwrap();
        assert_eq!(eth.dst, MacAddr::new([0xff; 6]));
        assert_eq!(eth.src, MAC);
        let (ip, l4) = Ipv4Header::parse(l3).unwrap();
        assert_eq!(ip.src, Ipv4Addr::new([0; 4]));
        assert_eq!(ip.dst, Ipv4Addr::new([255; 4]));
        let (udp, message) = crate::udp::UdpHeader::parse(ip.src, ip.dst, l4).unwrap();
        assert_eq!((udp.src_port, udp.dst_port), (68, 67));
        assert!(message.len() >= BOOTP_MIN_LEN);
        assert_eq!(message[0], OP_BOOTREQUEST);
        assert_eq!(message[4..8], XID.to_be_bytes());
        assert_eq!(message[28..34], MAC.octets());
        assert_eq!(message[236..240], MAGIC_COOKIE);
        let mut request = Request {
            message_type: 0,
            requested: None,
            server_id: None,
            broadcast: u16::from_be_bytes([message[10], message[11]]) & FLAG_BROADCAST != 0,
        };
        let mut options = &message[BOOTP_FIXED_LEN..];
        while let Some((&code, rest)) = options.split_first() {
            if code == OPT_END {
                break;
            }
            let len = usize::from(rest[0]);
            let value = &rest[1..1 + len];
            match code {
                OPT_MESSAGE_TYPE => request.message_type = value[0],
                OPT_REQUESTED_IP => request.requested = Some(value.try_into().unwrap()),
                OPT_SERVER_ID => request.server_id = Some(value.try_into().unwrap()),
                _ => {}
            }
            options = &rest[1 + len..];
        }
        request
    }

    /// A server reply; `options` are raw (code, value) pairs after the message type.
    fn reply(
        message_type: u8,
        xid: u32,
        yiaddr: [u8; 4],
        options: &[(u8, &[u8])],
        zero_udp_checksum: bool,
    ) -> FrameBuf {
        let mut message = [0u8; 548];
        message[0] = OP_BOOTREPLY;
        message[1] = HTYPE_ETHERNET;
        message[2] = 6;
        message[4..8].copy_from_slice(&xid.to_be_bytes());
        message[16..20].copy_from_slice(&yiaddr);
        message[28..34].copy_from_slice(&MAC.octets());
        message[236..240].copy_from_slice(&MAGIC_COOKIE);
        let mut at = BOOTP_FIXED_LEN;
        let mut put = |code: u8, value: &[u8]| {
            message[at] = code;
            message[at + 1] = value.len() as u8;
            message[at + 2..at + 2 + value.len()].copy_from_slice(value);
            at += 2 + value.len();
        };
        put(OPT_MESSAGE_TYPE, &[message_type]);
        for (code, value) in options {
            put(*code, value);
        }
        message[at] = OPT_PAD;
        message[at + 1] = OPT_END;
        let src = Ipv4Addr::new(SERVER);
        let dst = Ipv4Addr::new([255; 4]);
        let mut l4 = [0u8; 600];
        let n = crate::udp::UdpHeader::write(src, dst, 67, 68, &message, &mut l4).unwrap();
        if zero_udp_checksum {
            l4[6] = 0;
            l4[7] = 0;
        }
        let mut packet = [0u8; 700];
        Ipv4Header::new_template(src, dst, IpProtocol::UDP)
            .write(&mut packet, n)
            .unwrap();
        packet[20..20 + n].copy_from_slice(&l4[..n]);
        EthernetFrame::build(
            EthernetHeader {
                dst: MacAddr::new([0xff; 6]),
                src: SERVER_MAC,
                ethertype: EtherType::IPV4,
            },
            &packet[..20 + n],
        )
        .unwrap()
    }

    fn slirp_options() -> [(u8, &'static [u8]); 5] {
        [
            (OPT_SERVER_ID, &[10, 0, 2, 2]),
            (OPT_SUBNET_MASK, &[255, 255, 255, 0]),
            (OPT_ROUTER, &[10, 0, 2, 2]),
            (OPT_DNS, &[10, 0, 2, 3]),
            (OPT_LEASE_TIME, &[0, 1, 0x51, 0x80]),
        ]
    }

    const OFFERED: [u8; 4] = [10, 0, 2, 15];

    fn expected_lease() -> DhcpLease {
        DhcpLease {
            address: Ipv4Addr::new(OFFERED),
            prefix_len: 24,
            router: Some(Ipv4Addr::new([10, 0, 2, 2])),
            dns: Some(Ipv4Addr::new([10, 0, 2, 3])),
            server: Ipv4Addr::new(SERVER),
            lease_secs: 86_400,
        }
    }

    #[test]
    fn discover_offer_request_ack_binds_the_lease() {
        let mut client = DhcpClient::new(MAC, XID);
        let discover = read_request(&client.frame().unwrap());
        assert_eq!(discover.message_type, MSG_DISCOVER);
        assert!(discover.broadcast);
        assert_eq!(discover.requested, None);

        let offer = reply(MSG_OFFER, XID, OFFERED, &slirp_options(), false);
        assert_eq!(client.handle_frame(offer.as_slice()), DhcpEvent::Offered);
        let request = read_request(&client.frame().unwrap());
        assert_eq!(request.message_type, MSG_REQUEST);
        assert_eq!(request.requested, Some(OFFERED));
        assert_eq!(request.server_id, Some(SERVER));
        // A second OFFER (another server) while requesting changes nothing.
        assert_eq!(client.handle_frame(offer.as_slice()), DhcpEvent::Ignored);

        let ack = reply(MSG_ACK, XID, OFFERED, &slirp_options(), true);
        assert_eq!(
            client.handle_frame(ack.as_slice()),
            DhcpEvent::Bound(expected_lease())
        );
        assert_eq!(client.lease(), Some(expected_lease()));
        assert!(client.frame().is_none());
    }

    #[test]
    fn replies_for_someone_else_are_ignored() {
        let mut client = DhcpClient::new(MAC, XID);
        client.frame();
        let other_xid = reply(MSG_OFFER, XID + 1, OFFERED, &slirp_options(), false);
        assert_eq!(
            client.handle_frame(other_xid.as_slice()),
            DhcpEvent::Ignored
        );
        let mut bad_sum = reply(MSG_OFFER, XID, OFFERED, &slirp_options(), false);
        let last = bad_sum.as_slice().len() - 20;
        let mut bytes = bad_sum.as_slice().to_vec();
        bytes[last] ^= 0x55;
        bad_sum = FrameBuf::from_slice(&bytes).unwrap();
        assert_eq!(client.handle_frame(bad_sum.as_slice()), DhcpEvent::Ignored);
        // An ACK before any OFFER was taken is not a lease.
        let ack = reply(MSG_ACK, XID, OFFERED, &slirp_options(), false);
        assert_eq!(client.handle_frame(ack.as_slice()), DhcpEvent::Ignored);
        assert_eq!(client.handle_frame(&[0u8; 20]), DhcpEvent::Ignored);
    }

    #[test]
    fn offers_without_a_usable_address_or_server_are_ignored() {
        let mut client = DhcpClient::new(MAC, XID);
        let no_server = [(OPT_SUBNET_MASK, &[255u8, 255, 255, 0][..])];
        let cases = [
            reply(MSG_OFFER, XID, OFFERED, &no_server, false),
            reply(MSG_OFFER, XID, [0, 0, 0, 0], &slirp_options(), false),
            reply(MSG_OFFER, XID, [224, 0, 0, 1], &slirp_options(), false),
            reply(
                MSG_OFFER,
                XID,
                OFFERED,
                &[
                    (OPT_SERVER_ID, &SERVER[..]),
                    (OPT_SUBNET_MASK, &[255, 0, 255, 0][..]),
                ],
                false,
            ),
        ];
        for offer in cases {
            assert_eq!(client.handle_frame(offer.as_slice()), DhcpEvent::Ignored);
        }
    }

    #[test]
    fn a_router_off_the_prefix_is_dropped_and_a_missing_mask_is_classful() {
        let mut client = DhcpClient::new(MAC, XID);
        let options = [
            (OPT_SERVER_ID, &SERVER[..]),
            (OPT_ROUTER, &[192, 168, 1, 1][..]),
        ];
        let offer = reply(MSG_OFFER, XID, OFFERED, &options, false);
        assert_eq!(client.handle_frame(offer.as_slice()), DhcpEvent::Offered);
        let ack = reply(MSG_ACK, XID, OFFERED, &options, false);
        let DhcpEvent::Bound(lease) = client.handle_frame(ack.as_slice()) else {
            panic!("not bound");
        };
        assert_eq!(lease.prefix_len, 8);
        assert_eq!(lease.router, None);
        assert_eq!(lease.dns, None);
    }

    #[test]
    fn nak_or_a_different_address_starts_over() {
        let mut client = DhcpClient::new(MAC, XID);
        client.frame();
        let offer = reply(MSG_OFFER, XID, OFFERED, &slirp_options(), false);
        client.handle_frame(offer.as_slice());
        client.frame();
        // A NAK from a server other than the one that offered is ignored.
        let foreign_nak = reply(
            MSG_NAK,
            XID,
            [0; 4],
            &[(OPT_SERVER_ID, &[10, 0, 2, 9])],
            false,
        );
        assert_eq!(
            client.handle_frame(foreign_nak.as_slice()),
            DhcpEvent::Ignored
        );
        let nak = reply(MSG_NAK, XID, [0; 4], &[(OPT_SERVER_ID, &SERVER)], false);
        assert_eq!(client.handle_frame(nak.as_slice()), DhcpEvent::Restarted);
        assert_eq!(
            read_request(&client.frame().unwrap()).message_type,
            MSG_DISCOVER
        );

        client.handle_frame(offer.as_slice());
        let wrong = reply(MSG_ACK, XID, [10, 0, 2, 16], &slirp_options(), false);
        assert_eq!(client.handle_frame(wrong.as_slice()), DhcpEvent::Restarted);
        assert_eq!(client.lease(), None);
    }

    #[test]
    fn retransmissions_back_off_to_a_cap() {
        let mut client = DhcpClient::new(MAC, XID);
        let mut delays = [0u64; 6];
        for delay in &mut delays {
            client.frame();
            *delay = client.retransmit_delay_ms();
        }
        assert_eq!(delays, [1_000, 2_000, 4_000, 8_000, 8_000, 8_000]);
        let offer = reply(MSG_OFFER, XID, OFFERED, &slirp_options(), false);
        client.handle_frame(offer.as_slice());
        client.frame();
        assert_eq!(
            client.retransmit_delay_ms(),
            1_000,
            "a new state restarts the backoff"
        );
    }

    #[test]
    fn truncated_frames_never_panic() {
        let mut client = DhcpClient::new(MAC, XID);
        let offer = reply(MSG_OFFER, XID, OFFERED, &slirp_options(), false);
        for len in 0..offer.as_slice().len() {
            let _ = client.handle_frame(&offer.as_slice()[..len]);
        }
    }

    #[test]
    fn masks() {
        assert_eq!(mask_prefix([255, 255, 255, 0]), Some(24));
        assert_eq!(mask_prefix([255, 255, 240, 0]), Some(20));
        assert_eq!(mask_prefix([255, 255, 255, 255]), Some(32));
        assert_eq!(mask_prefix([0, 0, 0, 0]), Some(0));
        assert_eq!(mask_prefix([255, 0, 255, 0]), None);
    }
}
