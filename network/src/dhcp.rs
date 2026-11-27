//! DHCPv4 client (RFC 2131, options from RFC 2132): takes a lease and keeps it.
//!
//! [`DhcpClient`] is sans-IO: it builds whole Ethernet frames for the caller to transmit and
//! reads whole received frames, so it runs before any IPv4 stack exists (the client has no
//! address yet; it sends from `0.0.0.0` to the limited broadcast address). The caller owns
//! the clock: every call that can change state takes `now_ms`, a monotonic millisecond count,
//! and [`DhcpClient::next_deadline_ms`] says when to call [`DhcpClient::poll`] and
//! [`DhcpClient::transmit`] again even if no frame arrives.
//!
//! The first exchange is DISCOVER, OFFER, REQUEST, ACK. The client takes the first acceptable
//! OFFER; a NAK, an ACK for a different address, or four unanswered REQUESTs start over from
//! DISCOVER. Replies are accepted only when they carry this client's transaction id and
//! hardware address, come from UDP port 67 to port 68, and (after an OFFER was taken, or
//! while renewing) name the server that granted the lease.
//!
//! Once bound (RFC 2131 §4.4.5), the client renews at T1 by unicasting a REQUEST to that
//! server, rebinds at T2 by broadcasting it to any server, and drops the lease when it ends,
//! reporting [`DhcpEvent::Expired`] and starting over. T1 and T2 come from options 58 and 59,
//! or default to 1/2 and 7/8 of the lease. An ACK while renewing or rebinding is
//! [`DhcpEvent::Renewed`], with whatever the server now says (router, DNS); a NAK, or an ACK
//! for another address, ends the lease at once. A lease with no lease time is taken as
//! infinite, as is `u32::MAX`, and is never renewed. [`DhcpClient::with_max_lease_secs`]
//! shortens every lease to a cap (a short-lease test, or a site that wants faster DNS
//! changes).
//!
//! The renewing REQUEST goes to the Ethernet address the ACK came from: the server itself,
//! or the relay that forwarded it, so no ARP is needed. Each new exchange (DISCOVER, renewal)
//! takes a new transaction id.
//!
//! Not here: ARP-probing the offered address before using it (RFC 2131 §2.2 "SHOULD"), and
//! the `secs` field (always 0). [`DhcpClient::release`] builds a DHCPRELEASE for a clean
//! shutdown.

use crate::addr::{EtherType, IpProtocol, Ipv4Addr, MacAddr};
use crate::buffer::FrameBuf;
use crate::checksum::Checksum;
use crate::ethernet::{EthernetFrame, EthernetHeader};
use crate::ipv4::{pseudo_header_checksum, Ipv4Header, IPV4_MIN_HEADER_LEN};
use crate::udp::UDP_HEADER_LEN;

pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;

/// [`DhcpLease::lease_secs`] (and the T1/T2 fields) for a lease that never ends.
pub const INFINITE_LEASE: u32 = u32::MAX;

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
const OPT_RENEWAL_TIME: u8 = 58;
const OPT_REBINDING_TIME: u8 = 59;
const OPT_CLIENT_ID: u8 = 61;
const OPT_END: u8 = 255;

const MSG_DISCOVER: u8 = 1;
const MSG_OFFER: u8 = 2;
const MSG_REQUEST: u8 = 3;
const MSG_ACK: u8 = 5;
const MSG_NAK: u8 = 6;
const MSG_RELEASE: u8 = 7;

/// First retransmission delay while selecting or requesting; it doubles per attempt up to
/// [`MAX_RETRANSMIT_MS`] (RFC 2131 §4.1 asks for 4 s doubling to 64 s with jitter; a service
/// waiting to start begins sooner).
const FIRST_RETRANSMIT_MS: u64 = 1_000;
const MAX_RETRANSMIT_MS: u64 = 64_000;
/// REQUESTs sent for one OFFER before the client starts over from DISCOVER.
const MAX_REQUEST_ATTEMPTS: u32 = 4;
/// Shortest wait between renewing (or rebinding) REQUESTs. RFC 2131 §4.4.5 waits half the
/// time left to T2 (or to the lease's end), down to 60 s; this floor is lower so that short
/// leases still get a few tries.
const MIN_LEASE_RETRY_MS: u64 = 4_000;

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
    /// Lease length in seconds; [`INFINITE_LEASE`] never ends.
    pub lease_secs: u32,
    /// T1: seconds after the lease starts at which the client renews.
    pub renew_secs: u32,
    /// T2: seconds after the lease starts at which the client rebinds.
    pub rebind_secs: u32,
}

/// Where the client is in RFC 2131's state machine (§4.4, figure 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhcpPhase {
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
    /// Released; the client sends nothing more.
    Stopped,
}

/// A lease in use, with its timers as absolute milliseconds (`u64::MAX`: never).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Held {
    lease: DhcpLease,
    /// Ethernet source of the ACK: the next hop for renewing REQUESTs.
    server_mac: MacAddr,
    renew_at: u64,
    rebind_at: u64,
    expire_at: u64,
}

impl Held {
    fn new(lease: DhcpLease, server_mac: MacAddr, start_ms: u64) -> Self {
        let at = |secs: u32| {
            if secs == INFINITE_LEASE {
                u64::MAX
            } else {
                start_ms.saturating_add(u64::from(secs) * 1_000)
            }
        };
        Self {
            lease,
            server_mac,
            renew_at: at(lease.renew_secs),
            rebind_at: at(lease.rebind_secs),
            expire_at: at(lease.lease_secs),
        }
    }
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
        held: Held,
    },
    /// Past T1: unicasting REQUEST to the lease's server.
    Renewing {
        held: Held,
    },
    /// Past T2: broadcasting REQUEST to any server.
    Rebinding {
        held: Held,
    },
    Stopped,
}

/// What a received frame, or the passing of time, did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhcpEvent {
    /// Not a reply for this client, or nothing changed.
    Ignored,
    /// An OFFER was taken: [`DhcpClient::transmit`] now gives a REQUEST.
    Offered,
    /// The server NAKed (or ACKed something else) before a lease was held: the client is
    /// selecting again.
    Restarted,
    /// A lease is granted, where none was held.
    Bound(DhcpLease),
    /// The held lease was extended (renewing or rebinding). Its router or DNS may differ
    /// from before; its address does not.
    Renewed(DhcpLease),
    /// The held lease (given) ended, ran out or was refused: stop using its address. The
    /// client is selecting again.
    Expired(DhcpLease),
}

/// A DHCPv4 client for one interface (see the module docs).
#[derive(Clone, Debug)]
pub struct DhcpClient {
    mac: MacAddr,
    xid: u32,
    state: State,
    /// Frames sent in the current state, for the backoff.
    attempts: u32,
    /// When [`Self::transmit`] next sends a frame (in a state that sends).
    next_send_ms: u64,
    /// When the last frame was sent: a lease counts from the REQUEST that won it.
    last_sent_ms: u64,
    max_lease_secs: Option<u32>,
}

impl DhcpClient {
    /// A client for the interface with hardware address `mac`; `xid` should be random. Its
    /// first DISCOVER is due at once.
    pub fn new(mac: MacAddr, xid: u32) -> Self {
        Self {
            mac,
            xid,
            state: State::Selecting,
            attempts: 0,
            next_send_ms: 0,
            last_sent_ms: 0,
            max_lease_secs: None,
        }
    }

    /// Caps every lease (and so its T1 and T2) at `max_lease_secs` seconds (at least 4).
    pub fn with_max_lease_secs(mut self, max_lease_secs: Option<u32>) -> Self {
        self.max_lease_secs = max_lease_secs.map(|secs| secs.max(4));
        self
    }

    /// The lease in use: bound, renewing or rebinding.
    pub fn lease(&self) -> Option<DhcpLease> {
        self.held().map(|held| held.lease)
    }

    fn held(&self) -> Option<Held> {
        match self.state {
            State::Bound { held } | State::Renewing { held } | State::Rebinding { held } => {
                Some(held)
            }
            _ => None,
        }
    }

    pub fn phase(&self) -> DhcpPhase {
        match self.state {
            State::Selecting => DhcpPhase::Selecting,
            State::Requesting { .. } => DhcpPhase::Requesting,
            State::Bound { .. } => DhcpPhase::Bound,
            State::Renewing { .. } => DhcpPhase::Renewing,
            State::Rebinding { .. } => DhcpPhase::Rebinding,
            State::Stopped => DhcpPhase::Stopped,
        }
    }

    /// Frames sent in the current state.
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// The earliest time [`Self::poll`] or [`Self::transmit`] has something to do; `None`
    /// while bound to an infinite lease, or stopped.
    pub fn next_deadline_ms(&self) -> Option<u64> {
        let deadline = match self.state {
            State::Selecting | State::Requesting { .. } => self.next_send_ms,
            State::Bound { held } => held.renew_at,
            State::Renewing { held } => self.next_send_ms.min(held.rebind_at).min(held.expire_at),
            State::Rebinding { held } => self.next_send_ms.min(held.expire_at),
            State::Stopped => return None,
        };
        (deadline != u64::MAX).then_some(deadline)
    }

    /// Runs the lease timers: renewing at T1, rebinding at T2, and [`DhcpEvent::Expired`] at
    /// the lease's end. Otherwise [`DhcpEvent::Ignored`].
    pub fn poll(&mut self, now_ms: u64) -> DhcpEvent {
        let Some(held) = self.held() else {
            return DhcpEvent::Ignored;
        };
        if now_ms >= held.expire_at {
            self.restart(now_ms);
            return DhcpEvent::Expired(held.lease);
        }
        match self.state {
            State::Bound { .. } | State::Renewing { .. } if now_ms >= held.rebind_at => {
                self.enter(State::Rebinding { held }, now_ms);
            }
            State::Bound { .. } if now_ms >= held.renew_at => {
                self.new_xid();
                self.enter(State::Renewing { held }, now_ms);
            }
            _ => {}
        }
        DhcpEvent::Ignored
    }

    /// The frame to send now, if one is due: DISCOVER while selecting, REQUEST while
    /// requesting, renewing or rebinding. Each frame returned counts as one transmission and
    /// schedules the next. Call [`Self::poll`] first so the timers are current.
    pub fn transmit(&mut self, now_ms: u64) -> Option<FrameBuf> {
        if now_ms < self.next_send_ms {
            return None;
        }
        if matches!(self.state, State::Requesting { .. }) && self.attempts >= MAX_REQUEST_ATTEMPTS {
            self.restart(now_ms);
        }
        let broadcast = MacAddr::new([0xff; 6]);
        let any = Ipv4Addr::new([255; 4]);
        let (message_type, ciaddr, requested, dst_mac, dst_ip, wait_ms) = match self.state {
            State::Selecting => (MSG_DISCOVER, None, None, broadcast, any, self.backoff_ms()),
            State::Requesting { offer } => (
                MSG_REQUEST,
                None,
                Some(offer),
                broadcast,
                any,
                self.backoff_ms(),
            ),
            State::Renewing { held } => (
                MSG_REQUEST,
                Some(held.lease.address),
                None,
                held.server_mac,
                held.lease.server,
                half_of_remaining(now_ms, held.rebind_at),
            ),
            State::Rebinding { held } => (
                MSG_REQUEST,
                Some(held.lease.address),
                None,
                broadcast,
                any,
                half_of_remaining(now_ms, held.expire_at),
            ),
            State::Bound { .. } | State::Stopped => return None,
        };
        let mut message = [0u8; BOOTP_MIN_LEN];
        let mut options = self.message(&mut message, message_type, ciaddr);
        if let Some(offer) = requested {
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
                OPT_RENEWAL_TIME,
                OPT_REBINDING_TIME,
            ],
        );
        options.put(OPT_MAX_MESSAGE_SIZE, &1_500u16.to_be_bytes());
        options.end();
        let src_ip = ciaddr.unwrap_or(Ipv4Addr::new([0; 4]));
        let frame = build_frame(self.mac, src_ip, dst_mac, dst_ip, &message).ok()?;
        self.attempts = self.attempts.saturating_add(1);
        self.last_sent_ms = now_ms;
        self.next_send_ms = now_ms.saturating_add(wait_ms);
        Some(frame)
    }

    /// Gives the held lease back: a DHCPRELEASE to the server that granted it, for a clean
    /// shutdown. The client then sends nothing more. `None` when no lease is held.
    pub fn release(&mut self) -> Option<FrameBuf> {
        let held = self.held()?;
        self.state = State::Stopped;
        let mut message = [0u8; BOOTP_MIN_LEN];
        let mut options = self.message(&mut message, MSG_RELEASE, Some(held.lease.address));
        options.put(OPT_SERVER_ID, &held.lease.server.octets());
        options.end();
        build_frame(
            self.mac,
            held.lease.address,
            held.server_mac,
            held.lease.server,
            &message,
        )
        .ok()
    }

    /// Fills the BOOTP header of `message` and its first options (message type, client id).
    fn message<'a>(
        &self,
        message: &'a mut [u8; BOOTP_MIN_LEN],
        message_type: u8,
        ciaddr: Option<Ipv4Addr>,
    ) -> Options<'a> {
        message[0] = OP_BOOTREQUEST;
        message[1] = HTYPE_ETHERNET;
        message[2] = 6;
        message[4..8].copy_from_slice(&self.xid.to_be_bytes());
        match ciaddr {
            // With an address the client can take unicast replies (RFC 2131 §4.4.5).
            Some(ciaddr) => message[12..16].copy_from_slice(&ciaddr.octets()),
            None => message[10..12].copy_from_slice(&FLAG_BROADCAST.to_be_bytes()),
        }
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
        options
    }

    /// Selecting/requesting retransmission delay after the frame about to be sent.
    fn backoff_ms(&self) -> u64 {
        let shift = self.attempts.min(8);
        (FIRST_RETRANSMIT_MS << shift).min(MAX_RETRANSMIT_MS)
    }

    /// Reads one received Ethernet frame at `now_ms`.
    pub fn handle_frame(&mut self, frame: &[u8], now_ms: u64) -> DhcpEvent {
        let Some((reply, from_mac)) = parse_reply(frame, self.mac, self.xid) else {
            return DhcpEvent::Ignored;
        };
        let cap = self.max_lease_secs;
        match (self.state, reply.message_type) {
            (State::Selecting, MSG_OFFER) => match reply.lease(cap) {
                Some(offer) => {
                    self.enter(State::Requesting { offer }, now_ms);
                    DhcpEvent::Offered
                }
                None => DhcpEvent::Ignored,
            },
            (State::Requesting { offer }, MSG_ACK | MSG_NAK)
                if reply.server_id != Some(offer.server) =>
            {
                DhcpEvent::Ignored
            }
            (State::Requesting { offer }, MSG_ACK) => match reply.lease(cap) {
                Some(lease) if lease.address == offer.address => {
                    let held = Held::new(lease, from_mac, self.last_sent_ms);
                    self.enter(State::Bound { held }, now_ms);
                    DhcpEvent::Bound(lease)
                }
                _ => self.restart(now_ms),
            },
            (State::Requesting { .. }, MSG_NAK) => self.restart(now_ms),
            // Renewing talks to the lease's server only; rebinding takes any server.
            (State::Renewing { held }, MSG_ACK | MSG_NAK)
                if reply.server_id != Some(held.lease.server) =>
            {
                DhcpEvent::Ignored
            }
            (State::Renewing { held } | State::Rebinding { held }, MSG_ACK) => {
                match reply.lease(cap) {
                    Some(lease) if lease.address == held.lease.address => {
                        let held = Held::new(lease, from_mac, self.last_sent_ms);
                        self.enter(State::Bound { held }, now_ms);
                        DhcpEvent::Renewed(lease)
                    }
                    // An ACK without a usable lease is not an answer; keep trying.
                    None => DhcpEvent::Ignored,
                    Some(_) => {
                        self.restart(now_ms);
                        DhcpEvent::Expired(held.lease)
                    }
                }
            }
            (State::Renewing { held } | State::Rebinding { held }, MSG_NAK) => {
                self.restart(now_ms);
                DhcpEvent::Expired(held.lease)
            }
            _ => DhcpEvent::Ignored,
        }
    }

    fn enter(&mut self, state: State, now_ms: u64) {
        self.state = state;
        self.attempts = 0;
        self.next_send_ms = now_ms;
    }

    fn restart(&mut self, now_ms: u64) -> DhcpEvent {
        self.new_xid();
        self.enter(State::Selecting, now_ms);
        DhcpEvent::Restarted
    }

    /// The next exchange's transaction id (xorshift32 of the last, so it stays non-zero),
    /// so a late reply to an earlier exchange is not taken for this one.
    fn new_xid(&mut self) {
        let mut x = self.xid.max(1);
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.xid = x;
    }
}

/// Half the time from `now_ms` to `until_ms`, but at least [`MIN_LEASE_RETRY_MS`].
fn half_of_remaining(now_ms: u64, until_ms: u64) -> u64 {
    (until_ms.saturating_sub(now_ms) / 2).max(MIN_LEASE_RETRY_MS)
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

/// An Ethernet + IPv4 + UDP (68 to 67) frame from `src_ip` to `dst_ip` at `dst_mac`.
fn build_frame(
    mac: MacAddr,
    src: Ipv4Addr,
    dst_mac: MacAddr,
    dst: Ipv4Addr,
    message: &[u8],
) -> Result<FrameBuf, crate::ethernet::ParseError> {
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
            dst: dst_mac,
            src: mac,
            ethertype: EtherType::IPV4,
        },
        &packet[..IPV4_MIN_HEADER_LEN + udp_len],
    )
}

/// Whether `frame` is a UDP datagram from the DHCP server port to the client port: what the
/// caller hands to [`DhcpClient::handle_frame`] rather than to its UDP stack.
pub fn is_dhcp_reply(frame: &[u8]) -> bool {
    let Ok((eth, l3)) = EthernetFrame::parse_frame(frame) else {
        return false;
    };
    let Ok((ip, l4)) = Ipv4Header::parse(l3) else {
        return false;
    };
    eth.ethertype == EtherType::IPV4
        && ip.protocol == IpProtocol::UDP
        && l4.len() >= 4
        && l4[0..2] == DHCP_SERVER_PORT.to_be_bytes()
        && l4[2..4] == DHCP_CLIENT_PORT.to_be_bytes()
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
    renew_secs: Option<u32>,
    rebind_secs: Option<u32>,
}

impl Reply {
    /// The lease this OFFER or ACK describes, if it is usable: a unicast address, a server
    /// id, a non-zero lease time, and a contiguous mask (or the address's classful default
    /// when none is given). A router off the leased prefix, or equal to the address, is
    /// dropped. The lease is cut to `max_lease_secs`; T1 and T2 are the server's when they
    /// fit (`0 < T1 < T2 < lease`), else the RFC 2131 §4.4.5 defaults.
    fn lease(&self, max_lease_secs: Option<u32>) -> Option<DhcpLease> {
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
        let granted = self.lease_secs.unwrap_or(INFINITE_LEASE);
        if granted == 0 {
            return None;
        }
        let lease_secs = match max_lease_secs {
            Some(cap) if cap < granted => cap,
            _ => granted,
        };
        let (renew_secs, rebind_secs) = if lease_secs == INFINITE_LEASE {
            (INFINITE_LEASE, INFINITE_LEASE)
        } else {
            let lease = u64::from(lease_secs);
            let rebind = self
                .rebind_secs
                .filter(|&t2| t2 > 0 && t2 < lease_secs)
                .unwrap_or((lease * 7 / 8) as u32);
            let renew = self
                .renew_secs
                .filter(|&t1| t1 > 0 && t1 < rebind)
                .unwrap_or_else(|| {
                    let half = (lease / 2) as u32;
                    if half < rebind {
                        half
                    } else {
                        rebind / 2
                    }
                });
            (renew.min(rebind), rebind)
        };
        Some(DhcpLease {
            address,
            prefix_len,
            router,
            dns: self.dns.filter(|dns| unicast(dns.octets())),
            server,
            lease_secs,
            renew_secs,
            rebind_secs,
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

/// A BOOTREPLY for `mac` with transaction id `xid`, from UDP port 67 to port 68, with the
/// Ethernet source it came from; or `None`.
fn parse_reply(frame: &[u8], mac: MacAddr, xid: u32) -> Option<(Reply, MacAddr)> {
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
        let secs = || value.try_into().ok().map(u32::from_be_bytes);
        match code {
            OPT_MESSAGE_TYPE if len == 1 => reply.message_type = value[0],
            OPT_SERVER_ID if len == 4 => reply.server_id = first_addr(),
            OPT_SUBNET_MASK if len == 4 => reply.mask = value.try_into().ok(),
            OPT_ROUTER if len >= 4 && len % 4 == 0 => reply.router = first_addr(),
            OPT_DNS if len >= 4 && len % 4 == 0 => reply.dns = first_addr(),
            OPT_LEASE_TIME if len == 4 => reply.lease_secs = secs(),
            OPT_RENEWAL_TIME if len == 4 => reply.renew_secs = secs(),
            OPT_REBINDING_TIME if len == 4 => reply.rebind_secs = secs(),
            _ => {}
        }
    }
    (reply.message_type != 0).then_some((reply, eth.src))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: MacAddr = MacAddr::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    const SERVER_MAC: MacAddr = MacAddr::new([0x52, 0x55, 0x0a, 0x00, 0x02, 0x02]);
    const SERVER: [u8; 4] = [10, 0, 2, 2];
    const XID: u32 = 0x1234_5678;
    const BROADCAST_MAC: MacAddr = MacAddr::new([0xff; 6]);

    /// The pieces of a client frame the test server reads.
    struct Request {
        message_type: u8,
        xid: u32,
        requested: Option<[u8; 4]>,
        server_id: Option<[u8; 4]>,
        broadcast: bool,
        ciaddr: [u8; 4],
        eth_dst: MacAddr,
        ip_src: [u8; 4],
        ip_dst: [u8; 4],
    }

    fn read_request(frame: &FrameBuf) -> Request {
        let (eth, l3) = EthernetFrame::parse_frame(frame.as_slice()).unwrap();
        assert_eq!(eth.src, MAC);
        let (ip, l4) = Ipv4Header::parse(l3).unwrap();
        let (udp, message) = crate::udp::UdpHeader::parse(ip.src, ip.dst, l4).unwrap();
        assert_eq!((udp.src_port, udp.dst_port), (68, 67));
        assert!(message.len() >= BOOTP_MIN_LEN);
        assert_eq!(message[0], OP_BOOTREQUEST);
        assert_eq!(message[28..34], MAC.octets());
        assert_eq!(message[236..240], MAGIC_COOKIE);
        let mut request = Request {
            message_type: 0,
            xid: u32::from_be_bytes(message[4..8].try_into().unwrap()),
            requested: None,
            server_id: None,
            broadcast: u16::from_be_bytes([message[10], message[11]]) & FLAG_BROADCAST != 0,
            ciaddr: message[12..16].try_into().unwrap(),
            eth_dst: eth.dst,
            ip_src: ip.src.octets(),
            ip_dst: ip.dst.octets(),
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
                dst: BROADCAST_MAC,
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

    /// A one-hour lease (T1 30 min, T2 52.5 min by default), with `dns` as the DNS server.
    fn hour_options(dns: &'static [u8]) -> [(u8, &'static [u8]); 5] {
        [
            (OPT_SERVER_ID, &[10, 0, 2, 2]),
            (OPT_SUBNET_MASK, &[255, 255, 255, 0]),
            (OPT_ROUTER, &[10, 0, 2, 2]),
            (OPT_DNS, dns),
            (OPT_LEASE_TIME, &[0, 0, 0x0e, 0x10]),
        ]
    }

    const OFFERED: [u8; 4] = [10, 0, 2, 15];
    const HOUR_MS: u64 = 3_600_000;

    fn expected_lease() -> DhcpLease {
        DhcpLease {
            address: Ipv4Addr::new(OFFERED),
            prefix_len: 24,
            router: Some(Ipv4Addr::new([10, 0, 2, 2])),
            dns: Some(Ipv4Addr::new([10, 0, 2, 3])),
            server: Ipv4Addr::new(SERVER),
            lease_secs: 86_400,
            renew_secs: 43_200,
            rebind_secs: 75_600,
        }
    }

    /// A client bound at `start_ms` (its REQUEST sent then) to a one-hour lease.
    fn bound_client(start_ms: u64) -> DhcpClient {
        let mut client = DhcpClient::new(MAC, XID);
        client.transmit(start_ms).unwrap();
        let options = hour_options(&[10, 0, 2, 3]);
        let offer = reply(MSG_OFFER, XID, OFFERED, &options, false);
        assert_eq!(
            client.handle_frame(offer.as_slice(), start_ms),
            DhcpEvent::Offered
        );
        client.transmit(start_ms).unwrap();
        let ack = reply(MSG_ACK, XID, OFFERED, &options, false);
        assert!(matches!(
            client.handle_frame(ack.as_slice(), start_ms),
            DhcpEvent::Bound(_)
        ));
        client
    }

    /// Frames a client sent, with the time each went out.
    type Sent = std::vec::Vec<(u64, Request)>;

    /// Runs `client` from `from_ms` to `until_ms` with no server answering, returning the
    /// frames it sent (with their times) and the first non-`Ignored` timer event.
    fn run_silent(
        client: &mut DhcpClient,
        from_ms: u64,
        until_ms: u64,
    ) -> (Sent, Option<(u64, DhcpEvent)>) {
        let mut sent = std::vec::Vec::new();
        let mut now = from_ms;
        while now <= until_ms {
            let event = client.poll(now);
            if event != DhcpEvent::Ignored {
                return (sent, Some((now, event)));
            }
            if let Some(frame) = client.transmit(now) {
                sent.push((now, read_request(&frame)));
            }
            match client.next_deadline_ms() {
                Some(deadline) => now = deadline.max(now + 1),
                None => break,
            }
        }
        (sent, None)
    }

    #[test]
    fn discover_offer_request_ack_binds_the_lease() {
        let mut client = DhcpClient::new(MAC, XID);
        let discover = read_request(&client.transmit(0).unwrap());
        assert_eq!(discover.message_type, MSG_DISCOVER);
        assert!(discover.broadcast);
        assert_eq!(discover.requested, None);
        assert_eq!(discover.eth_dst, BROADCAST_MAC);
        assert_eq!((discover.ip_src, discover.ip_dst), ([0; 4], [255; 4]));

        let offer = reply(MSG_OFFER, XID, OFFERED, &slirp_options(), false);
        assert_eq!(client.handle_frame(offer.as_slice(), 5), DhcpEvent::Offered);
        assert_eq!(
            client.next_deadline_ms(),
            Some(5),
            "the REQUEST is due at once"
        );
        let request = read_request(&client.transmit(5).unwrap());
        assert_eq!(request.message_type, MSG_REQUEST);
        assert_eq!(request.requested, Some(OFFERED));
        assert_eq!(request.server_id, Some(SERVER));
        assert_eq!(request.ciaddr, [0; 4]);
        // A second OFFER (another server) while requesting changes nothing.
        assert_eq!(client.handle_frame(offer.as_slice(), 6), DhcpEvent::Ignored);

        let ack = reply(MSG_ACK, XID, OFFERED, &slirp_options(), true);
        assert_eq!(
            client.handle_frame(ack.as_slice(), 9),
            DhcpEvent::Bound(expected_lease())
        );
        assert_eq!(client.lease(), Some(expected_lease()));
        assert_eq!(client.phase(), DhcpPhase::Bound);
        assert!(client.transmit(9).is_none());
        // T1 counts from the REQUEST that won the lease (sent at 5 ms).
        assert_eq!(client.next_deadline_ms(), Some(5 + 43_200_000));
    }

    #[test]
    fn replies_for_someone_else_are_ignored() {
        let mut client = DhcpClient::new(MAC, XID);
        client.transmit(0);
        let other_xid = reply(MSG_OFFER, XID + 1, OFFERED, &slirp_options(), false);
        assert_eq!(
            client.handle_frame(other_xid.as_slice(), 0),
            DhcpEvent::Ignored
        );
        let mut bad_sum = reply(MSG_OFFER, XID, OFFERED, &slirp_options(), false);
        let last = bad_sum.as_slice().len() - 20;
        let mut bytes = bad_sum.as_slice().to_vec();
        bytes[last] ^= 0x55;
        bad_sum = FrameBuf::from_slice(&bytes).unwrap();
        assert_eq!(
            client.handle_frame(bad_sum.as_slice(), 0),
            DhcpEvent::Ignored
        );
        // An ACK before any OFFER was taken is not a lease.
        let ack = reply(MSG_ACK, XID, OFFERED, &slirp_options(), false);
        assert_eq!(client.handle_frame(ack.as_slice(), 0), DhcpEvent::Ignored);
        assert_eq!(client.handle_frame(&[0u8; 20], 0), DhcpEvent::Ignored);
    }

    #[test]
    fn offers_without_a_usable_address_server_or_lease_are_ignored() {
        let mut client = DhcpClient::new(MAC, XID);
        let no_server = [(OPT_SUBNET_MASK, &[255u8, 255, 255, 0][..])];
        let mut zero_lease = slirp_options();
        zero_lease[4] = (OPT_LEASE_TIME, &[0, 0, 0, 0]);
        let cases = [
            reply(MSG_OFFER, XID, OFFERED, &no_server, false),
            reply(MSG_OFFER, XID, [0, 0, 0, 0], &slirp_options(), false),
            reply(MSG_OFFER, XID, [224, 0, 0, 1], &slirp_options(), false),
            reply(MSG_OFFER, XID, OFFERED, &zero_lease, false),
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
            assert_eq!(client.handle_frame(offer.as_slice(), 0), DhcpEvent::Ignored);
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
        assert_eq!(client.handle_frame(offer.as_slice(), 0), DhcpEvent::Offered);
        let ack = reply(MSG_ACK, XID, OFFERED, &options, false);
        let DhcpEvent::Bound(lease) = client.handle_frame(ack.as_slice(), 0) else {
            panic!("not bound");
        };
        assert_eq!(lease.prefix_len, 8);
        assert_eq!(lease.router, None);
        assert_eq!(lease.dns, None);
        // No lease time: infinite, never renewed.
        assert_eq!(lease.lease_secs, INFINITE_LEASE);
        assert_eq!(client.next_deadline_ms(), None);
        assert_eq!(client.poll(u64::MAX - 1), DhcpEvent::Ignored);
        assert!(client.transmit(u64::MAX - 1).is_none());
    }

    #[test]
    fn nak_or_a_different_address_starts_over() {
        let mut client = DhcpClient::new(MAC, XID);
        client.transmit(0);
        let offer = reply(MSG_OFFER, XID, OFFERED, &slirp_options(), false);
        client.handle_frame(offer.as_slice(), 0);
        client.transmit(0);
        // A NAK from a server other than the one that offered is ignored.
        let foreign_nak = reply(
            MSG_NAK,
            XID,
            [0; 4],
            &[(OPT_SERVER_ID, &[10, 0, 2, 9])],
            false,
        );
        assert_eq!(
            client.handle_frame(foreign_nak.as_slice(), 0),
            DhcpEvent::Ignored
        );
        let nak = reply(MSG_NAK, XID, [0; 4], &[(OPT_SERVER_ID, &SERVER)], false);
        assert_eq!(client.handle_frame(nak.as_slice(), 0), DhcpEvent::Restarted);
        let discover = read_request(&client.transmit(0).unwrap());
        assert_eq!(discover.message_type, MSG_DISCOVER);
        assert_ne!(discover.xid, XID, "a new exchange takes a new xid");

        let xid = discover.xid;
        let offer = reply(MSG_OFFER, xid, OFFERED, &slirp_options(), false);
        client.handle_frame(offer.as_slice(), 0);
        let wrong = reply(MSG_ACK, xid, [10, 0, 2, 16], &slirp_options(), false);
        assert_eq!(
            client.handle_frame(wrong.as_slice(), 0),
            DhcpEvent::Restarted
        );
        assert_eq!(client.lease(), None);
    }

    #[test]
    fn retransmissions_back_off_to_a_cap() {
        let mut client = DhcpClient::new(MAC, XID);
        let (sent, event) = run_silent(&mut client, 0, 300_000);
        assert_eq!(event, None);
        let times: std::vec::Vec<u64> = sent.iter().map(|(at, _)| *at).collect();
        assert_eq!(
            times[..9],
            [0, 1_000, 3_000, 7_000, 15_000, 31_000, 63_000, 127_000, 191_000]
        );
        assert!(sent.iter().all(|(_, r)| r.message_type == MSG_DISCOVER));

        let offer = reply(MSG_OFFER, XID, OFFERED, &slirp_options(), false);
        client.handle_frame(offer.as_slice(), 300_000);
        client.transmit(300_000).unwrap();
        assert_eq!(
            client.next_deadline_ms(),
            Some(301_000),
            "a new state restarts the backoff"
        );
    }

    #[test]
    fn unanswered_requests_fall_back_to_discover() {
        let mut client = DhcpClient::new(MAC, XID);
        client.transmit(0);
        let offer = reply(MSG_OFFER, XID, OFFERED, &slirp_options(), false);
        client.handle_frame(offer.as_slice(), 0);
        let (sent, _) = run_silent(&mut client, 0, 20_000);
        let kinds: std::vec::Vec<u8> = sent.iter().map(|(_, r)| r.message_type).collect();
        assert_eq!(
            kinds[..5],
            [
                MSG_REQUEST,
                MSG_REQUEST,
                MSG_REQUEST,
                MSG_REQUEST,
                MSG_DISCOVER
            ]
        );
        assert_eq!(client.phase(), DhcpPhase::Selecting);
    }

    #[test]
    fn renews_at_t1_by_unicast_and_a_renewal_ack_extends_the_lease() {
        let mut client = bound_client(1_000);
        let t1 = 1_000 + HOUR_MS / 2;
        assert_eq!(client.next_deadline_ms(), Some(t1));
        assert_eq!(client.poll(t1 - 1), DhcpEvent::Ignored);
        assert!(client.transmit(t1 - 1).is_none());

        assert_eq!(client.poll(t1), DhcpEvent::Ignored);
        assert_eq!(client.phase(), DhcpPhase::Renewing);
        let renew = read_request(&client.transmit(t1).unwrap());
        assert_eq!(renew.message_type, MSG_REQUEST);
        assert_eq!(renew.ciaddr, OFFERED);
        assert!(!renew.broadcast);
        assert_eq!(renew.requested, None, "renewing names no requested address");
        assert_eq!(renew.server_id, None, "or server id");
        assert_eq!(
            renew.eth_dst, SERVER_MAC,
            "unicast to where the ACK came from"
        );
        assert_eq!((renew.ip_src, renew.ip_dst), (OFFERED, SERVER));
        assert_ne!(renew.xid, XID);

        // An ACK from another server while renewing is not taken.
        let mut foreign = hour_options(&[10, 0, 2, 3]);
        foreign[0] = (OPT_SERVER_ID, &[10, 0, 2, 9]);
        let foreign = reply(MSG_ACK, renew.xid, OFFERED, &foreign, false);
        assert_eq!(
            client.handle_frame(foreign.as_slice(), t1 + 10),
            DhcpEvent::Ignored
        );

        let ack = reply(
            MSG_ACK,
            renew.xid,
            OFFERED,
            &hour_options(&[10, 0, 2, 3]),
            false,
        );
        let DhcpEvent::Renewed(lease) = client.handle_frame(ack.as_slice(), t1 + 20) else {
            panic!("not renewed");
        };
        assert_eq!(lease.address, Ipv4Addr::new(OFFERED));
        assert_eq!(client.phase(), DhcpPhase::Bound);
        // The new lease counts from the renewing REQUEST.
        assert_eq!(client.next_deadline_ms(), Some(t1 + HOUR_MS / 2));
    }

    #[test]
    fn unanswered_renewals_rebind_at_t2_by_broadcast_then_expire() {
        let mut client = bound_client(0);
        let t1 = HOUR_MS / 2;
        let t2 = HOUR_MS * 7 / 8;
        let (sent, event) = run_silent(&mut client, t1, HOUR_MS + 1);
        assert_eq!(
            event,
            Some((HOUR_MS, DhcpEvent::Expired(hour_lease([10, 0, 2, 3]))))
        );
        let renewing: std::vec::Vec<&(u64, Request)> =
            sent.iter().filter(|(at, _)| *at < t2).collect();
        let rebinding: std::vec::Vec<&(u64, Request)> =
            sent.iter().filter(|(at, _)| *at >= t2).collect();
        // Renewing: half the time left to T2 each time, down to the floor.
        assert_eq!(renewing[0].0, t1);
        assert_eq!(renewing[1].0, t1 + (t2 - t1) / 2);
        assert!(renewing
            .iter()
            .all(|(_, r)| r.eth_dst == SERVER_MAC && r.ip_dst == SERVER));
        assert!(renewing.len() < 16, "the floor bounds the retries");
        // Rebinding: broadcast, from the leased address, starting at T2.
        assert_eq!(rebinding[0].0, t2);
        assert!(rebinding.iter().all(|(_, r)| {
            r.message_type == MSG_REQUEST
                && r.eth_dst == BROADCAST_MAC
                && r.ip_dst == [255; 4]
                && r.ip_src == OFFERED
                && r.ciaddr == OFFERED
        }));
        assert_eq!(client.lease(), None);
        assert_eq!(client.phase(), DhcpPhase::Selecting);
        let discover = read_request(&client.transmit(HOUR_MS).unwrap());
        assert_eq!(discover.message_type, MSG_DISCOVER);
        assert_eq!(discover.ip_src, [0; 4]);
    }

    fn hour_lease(dns: [u8; 4]) -> DhcpLease {
        DhcpLease {
            address: Ipv4Addr::new(OFFERED),
            prefix_len: 24,
            router: Some(Ipv4Addr::new([10, 0, 2, 2])),
            dns: Some(Ipv4Addr::new(dns)),
            server: Ipv4Addr::new(SERVER),
            lease_secs: 3_600,
            renew_secs: 1_800,
            rebind_secs: 3_150,
        }
    }

    #[test]
    fn a_rebinding_ack_from_any_server_carries_a_dns_change() {
        let mut client = bound_client(0);
        let t2 = HOUR_MS * 7 / 8;
        assert_eq!(client.poll(HOUR_MS / 2), DhcpEvent::Ignored);
        assert_eq!(client.poll(t2), DhcpEvent::Ignored);
        assert_eq!(client.phase(), DhcpPhase::Rebinding);
        let rebind = read_request(&client.transmit(t2).unwrap());
        // Another server answers, naming another DNS server.
        let options = [
            (OPT_SERVER_ID, &[10, 0, 2, 4][..]),
            (OPT_SUBNET_MASK, &[255, 255, 255, 0][..]),
            (OPT_ROUTER, &[10, 0, 2, 2][..]),
            (OPT_DNS, &[10, 0, 2, 53][..]),
            (OPT_LEASE_TIME, &[0, 0, 0x0e, 0x10][..]),
        ];
        let ack = reply(MSG_ACK, rebind.xid, OFFERED, &options, false);
        let event = client.handle_frame(ack.as_slice(), t2 + 5);
        assert_eq!(
            event,
            DhcpEvent::Renewed(DhcpLease {
                server: Ipv4Addr::new([10, 0, 2, 4]),
                ..hour_lease([10, 0, 2, 53])
            })
        );
        // Later renewals go to the server that now holds the lease.
        client.poll(t2 + HOUR_MS / 2);
        let renew = read_request(&client.transmit(t2 + HOUR_MS / 2).unwrap());
        assert_eq!(renew.ip_dst, [10, 0, 2, 4]);
    }

    #[test]
    fn a_nak_or_another_address_while_renewing_ends_the_lease() {
        let mut client = bound_client(0);
        client.poll(HOUR_MS / 2);
        let renew = read_request(&client.transmit(HOUR_MS / 2).unwrap());
        let nak = reply(
            MSG_NAK,
            renew.xid,
            [0; 4],
            &[(OPT_SERVER_ID, &SERVER)],
            false,
        );
        assert_eq!(
            client.handle_frame(nak.as_slice(), HOUR_MS / 2 + 1),
            DhcpEvent::Expired(hour_lease([10, 0, 2, 3]))
        );
        assert_eq!(client.phase(), DhcpPhase::Selecting);

        let mut client = bound_client(0);
        client.poll(HOUR_MS / 2);
        let renew = read_request(&client.transmit(HOUR_MS / 2).unwrap());
        let moved = reply(
            MSG_ACK,
            renew.xid,
            [10, 0, 2, 16],
            &hour_options(&[10, 0, 2, 3]),
            false,
        );
        assert!(matches!(
            client.handle_frame(moved.as_slice(), HOUR_MS / 2 + 1),
            DhcpEvent::Expired(_)
        ));
        // A late reply to the old exchange's xid is not taken for the new one.
        let late = reply(MSG_OFFER, renew.xid, OFFERED, &slirp_options(), false);
        assert_eq!(
            client.handle_frame(late.as_slice(), HOUR_MS / 2 + 2),
            DhcpEvent::Ignored
        );
    }

    #[test]
    fn server_t1_t2_are_used_when_they_fit_and_a_cap_shortens_the_lease() {
        let mut options = [(0u8, &[][..]); 7];
        options[..5].copy_from_slice(&hour_options(&[10, 0, 2, 3]));
        options[5] = (OPT_RENEWAL_TIME, &[0, 0, 0x02, 0x58]); // 600 s
        options[6] = (OPT_REBINDING_TIME, &[0, 0, 0x04, 0xb0]); // 1200 s
        let offer = reply(MSG_OFFER, XID, OFFERED, &options, false);
        let ack = reply(MSG_ACK, XID, OFFERED, &options, false);

        let mut client = DhcpClient::new(MAC, XID);
        client.handle_frame(offer.as_slice(), 0);
        client.transmit(0);
        let DhcpEvent::Bound(lease) = client.handle_frame(ack.as_slice(), 0) else {
            panic!("not bound");
        };
        assert_eq!(
            (lease.lease_secs, lease.renew_secs, lease.rebind_secs),
            (3_600, 600, 1_200)
        );

        // Capped at 20 s: the server's T1/T2 no longer fit, so the defaults apply.
        let mut client = DhcpClient::new(MAC, XID).with_max_lease_secs(Some(20));
        client.handle_frame(offer.as_slice(), 0);
        client.transmit(0);
        let DhcpEvent::Bound(lease) = client.handle_frame(ack.as_slice(), 0) else {
            panic!("not bound");
        };
        assert_eq!(
            (lease.lease_secs, lease.renew_secs, lease.rebind_secs),
            (20, 10, 17)
        );
        assert_eq!(client.next_deadline_ms(), Some(10_000));

        // T1 past T2 is not taken.
        let mut bad = options;
        bad[5] = (OPT_RENEWAL_TIME, &[0, 0, 0x0e, 0x00]);
        let offer = reply(MSG_OFFER, XID, OFFERED, &bad, false);
        let ack = reply(MSG_ACK, XID, OFFERED, &bad, false);
        let mut client = DhcpClient::new(MAC, XID);
        client.handle_frame(offer.as_slice(), 0);
        client.transmit(0);
        let DhcpEvent::Bound(lease) = client.handle_frame(ack.as_slice(), 0) else {
            panic!("not bound");
        };
        assert_eq!((lease.renew_secs, lease.rebind_secs), (600, 1_200));
    }

    #[test]
    fn release_unicasts_to_the_server_and_stops() {
        let mut client = DhcpClient::new(MAC, XID);
        assert!(client.release().is_none(), "no lease, nothing to release");
        let mut client = bound_client(0);
        let release = read_request(&client.release().unwrap());
        assert_eq!(release.message_type, MSG_RELEASE);
        assert_eq!(release.ciaddr, OFFERED);
        assert_eq!(release.server_id, Some(SERVER));
        assert_eq!(release.eth_dst, SERVER_MAC);
        assert_eq!((release.ip_src, release.ip_dst), (OFFERED, SERVER));
        assert_eq!(client.phase(), DhcpPhase::Stopped);
        assert_eq!(client.next_deadline_ms(), None);
        assert!(client.transmit(u64::MAX - 1).is_none());
    }

    #[test]
    fn dhcp_replies_are_told_apart() {
        let offer = reply(MSG_OFFER, XID, OFFERED, &slirp_options(), false);
        assert!(is_dhcp_reply(offer.as_slice()));
        let mut client = DhcpClient::new(MAC, XID);
        let discover = client.transmit(0).unwrap();
        assert!(!is_dhcp_reply(discover.as_slice()), "68 -> 67 is a request");
        assert!(!is_dhcp_reply(&[0u8; 60]));
    }

    #[test]
    fn truncated_frames_never_panic() {
        let mut client = DhcpClient::new(MAC, XID);
        let offer = reply(MSG_OFFER, XID, OFFERED, &slirp_options(), false);
        for len in 0..offer.as_slice().len() {
            let _ = client.handle_frame(&offer.as_slice()[..len], 0);
            let _ = is_dhcp_reply(&offer.as_slice()[..len]);
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
