//! #221 stage F: receive window, retransmission backoff, out-of-order reassembly and
//! listen/accept, driven from a scripted raw peer that writes and reads every segment.

use crate::addr::{IpProtocol, SocketAddrV4};
use crate::error::{DenialReason, NetworkError};
use crate::fake::FakeLink;
use crate::fixture::{GUEST_IPV4, GUEST_MAC, PEER_IPV4, PEER_MAC};
use crate::protocol::TrustedCaller;
use crate::rng::{NetRng, SEED_BYTES};
use crate::session::{SessionGeneration, SessionId};
use crate::stack::{Inbound, L3Stack};
use crate::tcp::conn::write_tcp_to_buf;
use crate::tcp::segment::{parse as parse_tcp, TcpFlags, TcpSegment};
use crate::tcp::{
    TcpState, TcpTimers, TcpTransport, TCP_LISTEN_BACKLOG, TCP_MAX_RETRIES, TCP_RECV_BUFFER_BYTES,
    TCP_SYN_ACK_RETRIES,
};

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

const OWNER: TrustedCaller = TrustedCaller::new(1, 1, 1);
const OTHER: TrustedCaller = TrustedCaller::new(2, 1, 1);
/// ARP entries never expire inside these tests.
const ARP_TTL: u64 = u64::MAX / 4;
const PEER_PORT: u16 = 7000;
const PEER_ISS: u32 = 90_000;
const PEER_MSS: u16 = 1000;

type Guest = Box<TcpTransport<FakeLink>>;

/// One segment the guest put on the wire.
struct Wire {
    seg: TcpSegment,
    data: Vec<u8>,
}

/// A peer whose every segment the test writes by hand.
struct RawPeer {
    stack: L3Stack<FakeLink>,
    port: u16,
    guest_port: u16,
    snd_nxt: u32,
    rcv_nxt: u32,
    window: u16,
}

impl RawPeer {
    fn seg(&self, seq: u32, flags: TcpFlags) -> TcpSegment {
        TcpSegment {
            src_port: self.port,
            dst_port: self.guest_port,
            seq,
            ack: self.rcv_nxt,
            data_offset: 5,
            flags,
            window: self.window,
            checksum: 0,
            urgent: 0,
            mss_option: None,
        }
    }

    fn send_seg(&mut self, now: u64, seg: &TcpSegment, payload: &[u8]) {
        let len = seg.header_len() + payload.len();
        self.stack
            .send_ipv4(now, GUEST_IPV4, IpProtocol::TCP, len, |buf| {
                write_tcp_to_buf(PEER_IPV4, GUEST_IPV4, seg, payload, buf)?;
                Ok(())
            })
            .expect("peer transmit");
    }

    /// Data (and flags) at an explicit sequence number, acknowledging `rcv_nxt`.
    fn send_at(&mut self, now: u64, seq: u32, flags: TcpFlags, payload: &[u8]) {
        let seg = self.seg(seq, TcpFlags::ACK.union(flags));
        self.send_seg(now, &seg, payload);
    }

    fn ack(&mut self, now: u64, ack: u32) {
        let mut seg = self.seg(self.snd_nxt, TcpFlags::ACK);
        seg.ack = ack;
        self.send_seg(now, &seg, &[]);
    }

    fn recv(&mut self, now: u64) -> Vec<Wire> {
        // The fake link also keeps a copy of every frame sent; long tests drop them.
        self.stack.link().drained_tx();
        let mut out = Vec::new();
        while let Some(inbound) = self.stack.poll(now).expect("peer poll") {
            let Inbound::Ipv4(ip) = inbound else {
                continue;
            };
            if ip.header.protocol != IpProtocol::TCP {
                continue;
            }
            let (seg, data) = parse_tcp(ip.header.src, ip.header.dst, ip.payload()).unwrap();
            out.push(Wire {
                seg,
                data: data.to_vec(),
            });
        }
        out
    }
}

fn pair() -> (Guest, RawPeer) {
    let (guest_link, peer_link) = FakeLink::pair();
    let mut guest_stack = L3Stack::new(guest_link, GUEST_MAC, GUEST_IPV4, ARP_TTL);
    guest_stack.arp_cache_mut().insert(PEER_IPV4, PEER_MAC, 0);
    let mut peer_stack = L3Stack::new(peer_link, PEER_MAC, PEER_IPV4, ARP_TTL);
    peer_stack.arp_cache_mut().insert(GUEST_IPV4, GUEST_MAC, 0);
    let guest = TcpTransport::alloc_boxed(
        guest_stack,
        SessionGeneration::new(1),
        NetRng::from_seed([0x33; SEED_BYTES]),
    );
    let peer = RawPeer {
        stack: peer_stack,
        port: PEER_PORT,
        guest_port: 0,
        snd_nxt: PEER_ISS,
        rcv_nxt: 0,
        window: 8192,
    };
    (guest, peer)
}

/// Active open from the guest, completed by hand. Returns the guest's session.
fn established(guest: &mut Guest, peer: &mut RawPeer) -> SessionId {
    let remote = SocketAddrV4::new(PEER_IPV4, PEER_PORT);
    let id = guest.connect(0, OWNER, remote).unwrap();
    let syn = peer.recv(0).pop().expect("guest SYN");
    assert!(syn.seg.flags.contains(TcpFlags::SYN));
    peer.guest_port = syn.seg.src_port;
    peer.rcv_nxt = syn.seg.seq.wrapping_add(1);
    let mut syn_ack = peer.seg(PEER_ISS, TcpFlags::SYN.union(TcpFlags::ACK));
    syn_ack.data_offset = 6;
    syn_ack.mss_option = Some(PEER_MSS);
    peer.send_seg(0, &syn_ack, &[]);
    peer.snd_nxt = PEER_ISS + 1;
    guest.poll(0).unwrap();
    assert_eq!(guest.state(id, OWNER).unwrap(), TcpState::Established);
    let ack = peer.recv(0).pop().expect("handshake ACK");
    assert_eq!(ack.seg.ack, PEER_ISS + 1);
    id
}

/// `poll`, dropping the fake link's copy of what was sent so long runs stay bounded.
fn tick(guest: &mut Guest, now: u64) {
    guest.poll(now).unwrap();
    guest.stack().link().drained_tx();
}

fn read_all(guest: &mut Guest, id: SessionId) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    while let Ok(n) = guest.receive(id, OWNER, &mut buf) {
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    out
}

fn last_ack(wire: &[Wire]) -> (u32, u16) {
    let seg = &wire.last().expect("guest answered").seg;
    (seg.ack, seg.window)
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

// ---- Out-of-order reassembly -------------------------------------------------------

#[test]
fn out_of_order_segments_are_reassembled() {
    let (mut guest, mut peer) = pair();
    let id = established(&mut guest, &mut peer);
    let data = pattern(30);
    let base = PEER_ISS + 1;

    // Third and second chunks first: held, each answered by a duplicate ACK of `base`.
    peer.send_at(1, base + 20, TcpFlags::PSH, &data[20..]);
    peer.send_at(1, base + 10, TcpFlags::default(), &data[10..20]);
    guest.poll(1).unwrap();
    let wire = peer.recv(1);
    assert_eq!(wire.len(), 2);
    assert!(wire.iter().all(|w| w.seg.ack == base));
    assert!(read_all(&mut guest, id).is_empty());
    assert_eq!(guest.stats().out_of_order_queued, 2);
    let conn = guest.table().get(id, OWNER).unwrap();
    assert_eq!(conn.out_of_order_bytes(), 20);
    assert_eq!(conn.advertised_window() as usize, TCP_RECV_BUFFER_BYTES);

    // The gap fills: everything is delivered in order and acknowledged at once.
    peer.send_at(2, base, TcpFlags::default(), &data[..10]);
    guest.poll(2).unwrap();
    assert_eq!(last_ack(&peer.recv(2)).0, base + 30);
    assert_eq!(read_all(&mut guest, id), data);
    assert_eq!(
        guest.table().get(id, OWNER).unwrap().out_of_order_bytes(),
        0
    );
}

#[test]
fn overlapping_and_duplicate_segments_are_trimmed() {
    let (mut guest, mut peer) = pair();
    let id = established(&mut guest, &mut peer);
    let data = pattern(40);
    let base = PEER_ISS + 1;

    peer.send_at(1, base, TcpFlags::default(), &data[..15]);
    // Overlaps the delivered bytes on the left.
    peer.send_at(1, base + 10, TcpFlags::default(), &data[10..25]);
    // Out of order, then a segment overlapping both the held range and the gap.
    peer.send_at(1, base + 30, TcpFlags::default(), &data[30..40]);
    peer.send_at(1, base + 20, TcpFlags::default(), &data[20..35]);
    // A pure duplicate of the first segment.
    peer.send_at(1, base, TcpFlags::default(), &data[..15]);
    guest.poll(1).unwrap();
    let wire = peer.recv(1);
    assert_eq!(last_ack(&wire).0, base + 40);
    assert_eq!(read_all(&mut guest, id), data);
    assert_eq!(
        guest.stats().dropped_out_of_order,
        1,
        "only the pure duplicate"
    );
}

#[test]
fn out_of_order_fin_closes_once_the_gap_fills() {
    let (mut guest, mut peer) = pair();
    let id = established(&mut guest, &mut peer);
    let base = PEER_ISS + 1;
    peer.send_at(1, base + 5, TcpFlags::FIN, b"world");
    guest.poll(1).unwrap();
    assert_eq!(guest.state(id, OWNER).unwrap(), TcpState::Established);
    peer.send_at(2, base, TcpFlags::default(), b"hello");
    guest.poll(2).unwrap();
    assert_eq!(guest.state(id, OWNER).unwrap(), TcpState::CloseWait);
    assert_eq!(
        last_ack(&peer.recv(2)).0,
        base + 11,
        "data and FIN acknowledged"
    );
    assert_eq!(read_all(&mut guest, id), b"helloworld");
    let mut buf = [0u8; 4];
    assert_eq!(
        guest.receive(id, OWNER, &mut buf).unwrap_err(),
        NetworkError::Closed
    );
}

#[test]
fn reassembly_ranges_are_bounded() {
    let (mut guest, mut peer) = pair();
    let id = established(&mut guest, &mut peer);
    let base = PEER_ISS + 1;
    // Five disjoint holes: the fifth range does not fit and is dropped.
    for k in 1..=5u32 {
        peer.send_at(1, base + k * 100, TcpFlags::default(), b"x");
    }
    guest.poll(1).unwrap();
    assert_eq!(guest.stats().out_of_order_queued, 4);
    assert_eq!(guest.stats().dropped_out_of_order, 1);
    assert_eq!(
        guest.table().get(id, OWNER).unwrap().out_of_order_bytes(),
        4
    );
}

// ---- Receive window -----------------------------------------------------------------

#[test]
fn receive_window_closes_and_reopens_with_a_window_update() {
    let (mut guest, mut peer) = pair();
    let id = established(&mut guest, &mut peer);
    let base = PEER_ISS + 1;
    let data = pattern(TCP_RECV_BUFFER_BYTES);
    for (i, chunk) in data.chunks(1000).enumerate() {
        peer.send_at(1, base + (i * 1000) as u32, TcpFlags::default(), chunk);
    }
    guest.poll(1).unwrap();
    let wire = peer.recv(1);
    assert_eq!(last_ack(&wire), (base + TCP_RECV_BUFFER_BYTES as u32, 0));

    // Beyond a zero window: dropped, answered with the same ACK and window 0.
    let right = base + TCP_RECV_BUFFER_BYTES as u32;
    peer.send_at(2, right, TcpFlags::default(), b"more");
    guest.poll(2).unwrap();
    assert_eq!(last_ack(&peer.recv(2)), (right, 0));
    assert_eq!(guest.stats().dropped_out_of_order, 1);

    // A small read does not reopen the window (silly window avoidance)...
    let mut small = [0u8; 100];
    assert_eq!(guest.receive(id, OWNER, &mut small).unwrap(), 100);
    guest.poll(3).unwrap();
    assert!(peer.recv(3).is_empty());
    // ...a large one does, with an unprompted window update.
    let mut big = [0u8; 2000];
    assert_eq!(guest.receive(id, OWNER, &mut big).unwrap(), 2000);
    assert_eq!(guest.next_timer_deadline(), Some(0), "update is due now");
    guest.poll(4).unwrap();
    assert_eq!(last_ack(&peer.recv(4)), (right, 2100));
    assert_eq!(guest.next_timer_deadline(), None);
}

#[test]
fn data_is_trimmed_to_the_receive_window() {
    let (mut guest, mut peer) = pair();
    let id = established(&mut guest, &mut peer);
    let base = PEER_ISS + 1;
    let first = pattern(TCP_RECV_BUFFER_BYTES - 10);
    for (i, chunk) in first.chunks(1000).enumerate() {
        peer.send_at(1, base + (i * 1000) as u32, TcpFlags::default(), chunk);
    }
    // 30 bytes into a 10-byte window: only 10 are taken, and the FIN with them is not.
    peer.send_at(1, base + first.len() as u32, TcpFlags::FIN, &[7u8; 30]);
    guest.poll(1).unwrap();
    assert_eq!(
        last_ack(&peer.recv(1)),
        (base + TCP_RECV_BUFFER_BYTES as u32, 0)
    );
    assert_eq!(guest.state(id, OWNER).unwrap(), TcpState::Established);
    assert_eq!(read_all(&mut guest, id).len(), TCP_RECV_BUFFER_BYTES);
}

// ---- Sending: windows, retransmission, backoff ----------------------------------------

/// Data segments (non-empty payload) in `wire`.
fn data_segments(wire: &[Wire]) -> Vec<&Wire> {
    wire.iter().filter(|w| !w.data.is_empty()).collect()
}

#[test]
fn send_window_allows_several_segments_in_flight() {
    let (mut guest, mut peer) = pair();
    let id = established(&mut guest, &mut peer);
    let data = pattern(3000);
    guest.send(1, id, OWNER, &data).unwrap();
    let wire = peer.recv(1);
    let segs = data_segments(&wire);
    // Peer MSS 1000; the initial congestion window (4380 bytes) covers all three.
    assert_eq!(segs.len(), 3);
    assert!(segs.iter().all(|w| w.data.len() == 1000));
    let first = segs[0].seg.seq;
    assert_eq!(segs[2].seg.seq, first + 2000);
    let sent: Vec<u8> = segs.iter().flat_map(|w| w.data.clone()).collect();
    assert_eq!(sent, data);
    peer.ack(2, first + 3000);
    guest.poll(2).unwrap();
    assert_eq!(guest.next_timer_deadline(), None, "all acknowledged");
}

#[test]
fn send_respects_the_peer_window() {
    let (mut guest, mut peer) = pair();
    let id = established(&mut guest, &mut peer);
    peer.window = 1500;
    peer.ack(1, peer.rcv_nxt);
    guest.poll(1).unwrap();
    guest.send(2, id, OWNER, &pattern(3000)).unwrap();
    let wire = peer.recv(2);
    let lens: Vec<usize> = data_segments(&wire).iter().map(|w| w.data.len()).collect();
    assert_eq!(lens, [1000, 500]);
    // The ACK slides the window: the rest goes.
    let una = peer.rcv_nxt;
    peer.ack(3, una + 1500);
    guest.poll(3).unwrap();
    let lens: Vec<usize> = data_segments(&peer.recv(3))
        .iter()
        .map(|w| w.data.len())
        .collect();
    assert_eq!(lens, [1000, 500]);
}

#[test]
fn retransmission_timeouts_back_off_exponentially_then_fail() {
    let (mut guest, mut peer) = pair();
    let id = established(&mut guest, &mut peer);
    guest.send(10, id, OWNER, b"lost").unwrap();
    assert_eq!(data_segments(&peer.recv(10)).len(), 1);
    let timers = TcpTimers::DEFAULT;
    // The handshake's near-zero RTT sample put the RTO at its floor.
    let rto = guest.table().get(id, OWNER).unwrap().rto;
    assert_eq!(rto, timers.rto_min);

    let mut sends = Vec::new();
    let mut now = 10;
    while guest.connections_in_use() == 1 && now < 100_000 {
        now = guest.next_timer_deadline().expect("RTO armed");
        guest.poll(now).unwrap();
        if !data_segments(&peer.recv(now)).is_empty() {
            sends.push(now);
        }
    }
    assert_eq!(sends.len(), TCP_MAX_RETRIES as usize);
    assert_eq!(guest.stats().timeouts, 1);
    let gaps: Vec<u64> = core::iter::once(10)
        .chain(sends.iter().copied())
        .collect::<Vec<_>>()
        .windows(2)
        .map(|w| w[1] - w[0])
        .collect();
    let mut expected = rto;
    for gap in &gaps {
        assert_eq!(*gap, expected, "gaps {gaps:?}");
        expected = (expected * 2).min(timers.rto_max);
    }
}

#[test]
fn rtt_samples_set_the_retransmission_timeout() {
    let (mut guest, mut peer) = pair();
    let id = established(&mut guest, &mut peer);
    for round in 0..40u64 {
        let t = 100 + round * 1_000;
        guest.send(t, id, OWNER, b"ping").unwrap();
        let seg = data_segments(&peer.recv(t))[0].seg;
        peer.ack(t + 120, seg.seq + 4);
        guest.poll(t + 120).unwrap();
    }
    let conn = guest.table().get(id, OWNER).unwrap();
    let srtt = conn.srtt().expect("sampled");
    assert!((115..=125).contains(&srtt), "srtt {srtt}");
    assert!(conn.rto >= 120 && conn.rto < 400, "rto {}", conn.rto);
}

#[test]
fn karn_rule_skips_samples_from_retransmitted_segments() {
    let (mut guest, mut peer) = pair();
    let id = established(&mut guest, &mut peer);
    let before = guest.table().get(id, OWNER).unwrap().srtt();
    let rto_before = guest.table().get(id, OWNER).unwrap().rto;
    guest.send(0, id, OWNER, b"x").unwrap();
    let seq = data_segments(&peer.recv(0))[0].seg.seq;
    let rto = guest.next_timer_deadline().unwrap();
    guest.poll(rto).unwrap();
    assert_eq!(data_segments(&peer.recv(rto)).len(), 1, "retransmitted");
    peer.ack(rto + 1, seq + 1);
    guest.poll(rto + 1).unwrap();
    let conn = guest.table().get(id, OWNER).unwrap();
    assert_eq!(conn.srtt(), before, "ambiguous ACK is not an RTT sample");
    assert_eq!(conn.rto, rto_before * 2, "backoff kept");
}

#[test]
fn three_duplicate_acks_fast_retransmit_the_lost_segment() {
    let (mut guest, mut peer) = pair();
    let id = established(&mut guest, &mut peer);
    guest.send(1, id, OWNER, &pattern(3000)).unwrap();
    let wire = peer.recv(1);
    let first = data_segments(&wire)[0].seg.seq;
    let first_data = data_segments(&wire)[0].data.clone();
    // Segment one was lost; segments two and three each draw a duplicate ACK.
    for _ in 0..3 {
        peer.ack(2, first);
    }
    guest.poll(2).unwrap();
    let wire = peer.recv(2);
    let segs = data_segments(&wire);
    assert_eq!(segs.len(), 1, "one fast retransmit");
    assert_eq!(segs[0].seg.seq, first);
    assert_eq!(segs[0].data, first_data);
    assert_eq!(guest.stats().fast_retransmits, 1);
    assert_eq!(guest.stats().retransmits, 0, "no timeout needed");
    peer.ack(3, first + 3000);
    guest.poll(3).unwrap();
    assert_eq!(guest.next_timer_deadline(), None);
}

#[test]
fn timeout_resends_from_the_first_unacknowledged_byte() {
    let (mut guest, mut peer) = pair();
    let id = established(&mut guest, &mut peer);
    let data = pattern(3000);
    guest.send(1, id, OWNER, &data).unwrap();
    let first = data_segments(&peer.recv(1))[0].seg.seq;
    // The peer got only the first segment.
    peer.ack(2, first + 1000);
    guest.poll(2).unwrap();
    let rto = guest.next_timer_deadline().unwrap();
    guest.poll(rto).unwrap();
    let wire = peer.recv(rto);
    let segs = data_segments(&wire);
    assert_eq!(segs.len(), 1, "congestion window collapses to one segment");
    assert_eq!(segs[0].seg.seq, first + 1000);
    assert_eq!(segs[0].data, data[1000..2000]);
    // Its ACK lets the remaining (already sent once) segment go again.
    peer.ack(rto + 1, first + 2000);
    guest.poll(rto + 1).unwrap();
    let wire = peer.recv(rto + 1);
    let segs = data_segments(&wire);
    assert_eq!(segs.len(), 1);
    assert_eq!(segs[0].seg.seq, first + 2000);
    peer.ack(rto + 2, first + 3000);
    guest.poll(rto + 2).unwrap();
    assert_eq!(guest.next_timer_deadline(), None);
}

#[test]
fn zero_window_is_probed_without_timing_out() {
    let (mut guest, mut peer) = pair();
    let id = established(&mut guest, &mut peer);
    peer.window = 0;
    peer.ack(1, peer.rcv_nxt);
    guest.poll(1).unwrap();
    guest.send(2, id, OWNER, b"blocked").unwrap();
    assert!(data_segments(&peer.recv(2)).is_empty(), "window is closed");
    let una = peer.rcv_nxt;

    // Probes keep going, backing off, for far longer than the retry budget would allow,
    // because the peer answers each one.
    let mut probes = Vec::new();
    let mut now = 2;
    while now < 60_000 {
        now = guest.next_timer_deadline().expect("persist armed");
        tick(&mut guest, now);
        for w in peer.recv(now) {
            assert!(w.data.is_empty());
            assert_eq!(w.seg.seq, una.wrapping_sub(1), "probe below snd_una");
            probes.push(now);
            peer.ack(now, una);
        }
        tick(&mut guest, now);
    }
    assert!(
        probes.len() > TCP_MAX_RETRIES as usize,
        "{} probes",
        probes.len()
    );
    let gaps: Vec<u64> = probes.windows(2).map(|w| w[1] - w[0]).collect();
    assert!(
        gaps.windows(2).all(|g| g[1] >= g[0]),
        "probes back off: {gaps:?}"
    );
    assert_eq!(*gaps.last().unwrap(), TcpTimers::DEFAULT.rto_max);
    assert_eq!(guest.stats().window_probes, probes.len() as u64);
    assert_eq!(guest.stats().timeouts, 0);
    assert_eq!(guest.state(id, OWNER).unwrap(), TcpState::Established);

    // The window opens: everything goes out.
    peer.window = 4096;
    peer.ack(now + 1, una);
    guest.poll(now + 1).unwrap();
    let wire = peer.recv(now + 1);
    let sent: Vec<u8> = data_segments(&wire)
        .iter()
        .flat_map(|w| w.data.clone())
        .collect();
    assert_eq!(sent, b"blocked");
}

#[test]
fn unanswered_zero_window_probes_time_out() {
    let (mut guest, mut peer) = pair();
    let id = established(&mut guest, &mut peer);
    peer.window = 0;
    peer.ack(1, peer.rcv_nxt);
    guest.poll(1).unwrap();
    guest.send(2, id, OWNER, b"blocked").unwrap();
    let mut now;
    while guest.connections_in_use() == 1 {
        now = guest.next_timer_deadline().expect("persist armed");
        tick(&mut guest, now);
    }
    assert_eq!(guest.stats().window_probes, u64::from(TCP_MAX_RETRIES));
    assert_eq!(guest.stats().timeouts, 1);
}

#[test]
fn close_sends_fin_after_queued_data() {
    let (mut guest, mut peer) = pair();
    let id = established(&mut guest, &mut peer);
    peer.window = 1000;
    peer.ack(1, peer.rcv_nxt);
    guest.poll(1).unwrap();
    guest.send(2, id, OWNER, &pattern(1500)).unwrap();
    guest.close(2, id, OWNER).unwrap();
    let wire = peer.recv(2);
    assert_eq!(wire.len(), 1);
    assert!(
        !wire[0].seg.flags.contains(TcpFlags::FIN),
        "data still queued"
    );
    let first = wire[0].seg.seq;
    peer.ack(3, first + 1000);
    guest.poll(3).unwrap();
    let wire = peer.recv(3);
    assert_eq!(wire.len(), 1);
    assert_eq!(wire[0].data.len(), 500);
    assert!(
        wire[0].seg.flags.contains(TcpFlags::FIN),
        "FIN rides the last byte"
    );
    peer.ack(4, first + 1501);
    guest.poll(4).unwrap();
    assert_eq!(guest.state(id, OWNER).unwrap(), TcpState::FinWait2);
}

#[test]
fn far_out_of_range_ack_is_challenged() {
    let (mut guest, mut peer) = pair();
    let id = established(&mut guest, &mut peer);
    guest.send(1, id, OWNER, b"data").unwrap();
    let seq = data_segments(&peer.recv(1))[0].seg.seq;
    peer.ack(2, seq + 100);
    guest.poll(2).unwrap();
    assert_eq!(guest.stats().dropped_bad_ack, 1);
    assert_eq!(last_ack(&peer.recv(2)).0, PEER_ISS + 1, "challenge ACK");
    assert!(
        guest.next_timer_deadline().is_some(),
        "data still unacknowledged"
    );
}

#[test]
fn timers_follow_the_tick_period() {
    let ten_ms = TcpTimers::from_tick_period_ns(10_000_000);
    assert_eq!(ten_ms.rto_initial, TcpTimers::DEFAULT.rto_initial / 10);
    assert_eq!(ten_ms.connect_timeout, 50);
    let coarse = TcpTimers::from_tick_period_ns(1_000_000_000);
    assert_eq!(coarse.rto_min, 1, "never zero ticks");
}

// ---- Listen / accept ------------------------------------------------------------------

const LISTEN_PORT: u16 = 8080;

/// The peer opens toward the guest's listener from `src_port`. Returns the SYN-ACK.
fn peer_syn(guest: &mut Guest, peer: &mut RawPeer, now: u64, src_port: u16) -> Option<Wire> {
    peer.port = src_port;
    peer.guest_port = LISTEN_PORT;
    peer.snd_nxt = PEER_ISS;
    peer.rcv_nxt = 0;
    let mut syn = peer.seg(PEER_ISS, TcpFlags::SYN);
    syn.ack = 0;
    syn.data_offset = 6;
    syn.mss_option = Some(PEER_MSS);
    peer.send_seg(now, &syn, &[]);
    guest.poll(now).unwrap();
    peer.recv(now).pop()
}

fn passive_established(guest: &mut Guest, peer: &mut RawPeer) -> SessionId {
    let listener = guest.listen(OWNER, LISTEN_PORT).unwrap();
    let syn_ack = peer_syn(guest, peer, 0, PEER_PORT).expect("SYN-ACK");
    peer.snd_nxt = PEER_ISS + 1;
    peer.rcv_nxt = syn_ack.seg.seq + 1;
    peer.ack(1, peer.rcv_nxt);
    guest.poll(1).unwrap();
    guest.accept(listener, OWNER).unwrap().expect("accepted")
}

#[test]
fn listen_accept_and_exchange_data() {
    let (mut guest, mut peer) = pair();
    let listener = guest.listen(OWNER, LISTEN_PORT).unwrap();
    assert_eq!(guest.accept(listener, OWNER).unwrap(), None);

    let syn_ack = peer_syn(&mut guest, &mut peer, 0, PEER_PORT).expect("SYN-ACK");
    assert!(syn_ack
        .seg
        .flags
        .contains(TcpFlags::SYN.union(TcpFlags::ACK)));
    assert_eq!(syn_ack.seg.ack, PEER_ISS + 1);
    assert!(syn_ack.seg.mss_option.is_some());
    assert_eq!(guest.stats().passive_opens, 1);
    // Half-open: not acceptable yet.
    assert_eq!(guest.accept(listener, OWNER).unwrap(), None);

    // The handshake ACK carries the first request bytes.
    peer.snd_nxt = PEER_ISS + 1;
    peer.rcv_nxt = syn_ack.seg.seq + 1;
    peer.send_at(1, PEER_ISS + 1, TcpFlags::PSH, b"GET /");
    guest.poll(1).unwrap();
    assert_eq!(last_ack(&peer.recv(1)).0, PEER_ISS + 6);
    assert_eq!(guest.pending_accepts(listener, OWNER).unwrap(), 1);
    let id = guest.accept(listener, OWNER).unwrap().expect("accepted");
    assert_eq!(guest.accept(listener, OWNER).unwrap(), None);
    assert_eq!(guest.state(id, OWNER).unwrap(), TcpState::Established);
    assert_eq!(read_all(&mut guest, id), b"GET /");

    guest.send(2, id, OWNER, b"200 OK").unwrap();
    let wire = peer.recv(2);
    let segs = data_segments(&wire);
    assert_eq!(segs[0].data, b"200 OK");
    assert_eq!(segs[0].seg.src_port, LISTEN_PORT);
    assert_eq!(segs[0].seg.dst_port, PEER_PORT);
}

#[test]
fn passive_close_from_the_server_side() {
    let (mut guest, mut peer) = pair();
    let id = passive_established(&mut guest, &mut peer);
    guest.close(2, id, OWNER).unwrap();
    let fin = peer.recv(2).pop().unwrap();
    assert!(fin.seg.flags.contains(TcpFlags::FIN));
    peer.rcv_nxt = fin.seg.seq + 1;
    peer.send_at(3, peer.snd_nxt, TcpFlags::FIN, &[]);
    guest.poll(3).unwrap();
    assert_eq!(guest.state(id, OWNER).unwrap(), TcpState::TimeWait);
    for t in 4..1_000 {
        guest.poll(t).unwrap();
    }
    assert_eq!(guest.connections_in_use(), 0);
}

#[test]
fn lost_syn_ack_is_retransmitted_then_abandoned() {
    let (mut guest, mut peer) = pair();
    let _listener = guest.listen(OWNER, LISTEN_PORT).unwrap();
    let first = peer_syn(&mut guest, &mut peer, 0, PEER_PORT).expect("SYN-ACK");
    // The peer retransmits its SYN: the same SYN-ACK comes back.
    let again = peer_syn(&mut guest, &mut peer, 5, PEER_PORT).expect("SYN-ACK again");
    assert_eq!(again.seg.seq, first.seg.seq);
    assert_eq!(guest.connections_in_use(), 1);

    let mut resent = 0;
    while guest.connections_in_use() == 1 {
        let now = guest.next_timer_deadline().expect("SYN-ACK RTO");
        guest.poll(now).unwrap();
        resent += peer.recv(now).len();
    }
    assert_eq!(resent, TCP_SYN_ACK_RETRIES as usize);
}

#[test]
fn peer_rst_drops_a_half_open_connection_quietly() {
    let (mut guest, mut peer) = pair();
    let listener = guest.listen(OWNER, LISTEN_PORT).unwrap();
    let syn_ack = peer_syn(&mut guest, &mut peer, 0, PEER_PORT).unwrap();
    let _ = syn_ack;
    let rst = peer.seg(PEER_ISS + 1, TcpFlags::RST);
    peer.send_seg(1, &rst, &[]);
    guest.poll(1).unwrap();
    assert_eq!(guest.connections_in_use(), 0);
    assert_eq!(guest.accept(listener, OWNER).unwrap(), None);
    // The listener still works.
    assert!(peer_syn(&mut guest, &mut peer, 2, PEER_PORT + 1).is_some());
}

#[test]
fn listen_backlog_bounds_half_open_connections() {
    let (mut guest, mut peer) = pair();
    let listener = guest.listen(OWNER, LISTEN_PORT).unwrap();
    for i in 0..TCP_LISTEN_BACKLOG as u16 {
        assert!(peer_syn(&mut guest, &mut peer, 0, 7100 + i).is_some());
    }
    assert!(
        peer_syn(&mut guest, &mut peer, 0, 7200).is_none(),
        "backlog full"
    );
    assert_eq!(guest.stats().dropped_syn_backlog, 1);
    assert_eq!(guest.connections_in_use(), TCP_LISTEN_BACKLOG);

    // Closing the listener resets the connections nobody accepted.
    guest.close_listener(1, listener, OWNER).unwrap();
    assert_eq!(guest.connections_in_use(), 0);
    let resets = peer.recv(1);
    assert_eq!(resets.len(), TCP_LISTEN_BACKLOG);
    assert!(resets.iter().all(|w| w.seg.flags.contains(TcpFlags::RST)));
    assert!(
        peer_syn(&mut guest, &mut peer, 2, 7300).is_none(),
        "no listener"
    );
    assert!(guest.stats().dropped_no_conn >= 1);
}

#[test]
fn accept_hands_out_connections_in_arrival_order() {
    let (mut guest, mut peer) = pair();
    let listener = guest.listen(OWNER, LISTEN_PORT).unwrap();
    let mut isss = Vec::new();
    for port in [7101u16, 7102] {
        isss.push((
            port,
            peer_syn(&mut guest, &mut peer, 0, port).unwrap().seg.seq,
        ));
    }
    // The second completes its handshake first.
    for &(port, iss) in isss.iter().rev() {
        peer.port = port;
        peer.snd_nxt = PEER_ISS + 1;
        peer.rcv_nxt = iss + 1;
        peer.ack(1, iss + 1);
        guest.poll(1).unwrap();
    }
    let a = guest.accept(listener, OWNER).unwrap().unwrap();
    let b = guest.accept(listener, OWNER).unwrap().unwrap();
    assert_eq!(guest.table().get(a, OWNER).unwrap().remote.port, 7102);
    assert_eq!(guest.table().get(b, OWNER).unwrap().remote.port, 7101);
}

#[test]
fn listener_ids_are_owned_and_ports_exclusive() {
    let (mut guest, _peer) = pair();
    let listener = guest.listen(OWNER, LISTEN_PORT).unwrap();
    assert_eq!(
        guest.listen(OTHER, LISTEN_PORT).unwrap_err(),
        NetworkError::InvalidRequest
    );
    assert_eq!(
        guest.listen(OWNER, 0).unwrap_err(),
        NetworkError::InvalidRequest
    );
    assert_eq!(
        guest.accept(listener, OTHER).unwrap_err(),
        NetworkError::Denied(DenialReason::NoCapability)
    );
    assert_eq!(
        guest.close_listener(0, listener, OTHER).unwrap_err(),
        NetworkError::Denied(DenialReason::NoCapability)
    );
    guest.on_holder_exit(0, OWNER).unwrap();
    assert_eq!(guest.table().listeners_in_use(), 0);
    assert!(guest.listen(OTHER, LISTEN_PORT).is_ok());
}

#[test]
fn unaccepted_connection_ids_are_not_usable() {
    let (mut guest, mut peer) = pair();
    let listener = guest.listen(OWNER, LISTEN_PORT).unwrap();
    let syn_ack = peer_syn(&mut guest, &mut peer, 0, PEER_PORT).unwrap();
    peer.snd_nxt = PEER_ISS + 1;
    peer.rcv_nxt = syn_ack.seg.seq + 1;
    peer.ack(1, peer.rcv_nxt);
    guest.poll(1).unwrap();
    // Guess the slot id before accept: refused.
    let guessed = (0..32)
        .map(|i| SessionId::new(SessionGeneration::new(1), i))
        .find(|&id| guest.table().slots[id.index() as usize].is_some())
        .unwrap();
    assert_eq!(
        guest.state(guessed, OWNER).unwrap_err(),
        NetworkError::NotFound
    );
    assert_eq!(guest.accept(listener, OWNER).unwrap(), Some(guessed));
    assert!(guest.state(guessed, OWNER).is_ok());
}

// ---- End to end over a lossy, reordering link -------------------------------------------

/// Forwards frames between two transports, dropping and reordering some (deterministic).
struct LossyRelay {
    to_server: FakeLink,
    to_client: FakeLink,
    rng: u64,
    held: [Option<crate::buffer::FrameBuf>; 2],
    drop_percent: u64,
    reorder_percent: u64,
    dropped: u64,
    reordered: u64,
    /// Faults start once the handshake is done (the connect timeout is not under test).
    armed: bool,
}

impl LossyRelay {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        self.rng.wrapping_mul(0x2545_f491_4f6c_dd1d) % 100
    }

    fn pump(&mut self) {
        use crate::device::NetworkLink;
        for dir in 0..2 {
            loop {
                let from = if dir == 0 {
                    &mut self.to_client
                } else {
                    &mut self.to_server
                };
                let Some(frame) = from.receive().unwrap() else {
                    break;
                };
                let roll = if self.armed { self.next() } else { 100 };
                if roll < self.drop_percent {
                    self.dropped += 1;
                    continue;
                }
                if roll < self.drop_percent + self.reorder_percent && self.held[dir].is_none() {
                    // Hold this frame back until the next one in this direction has passed.
                    self.held[dir] = Some(frame);
                    self.reordered += 1;
                    continue;
                }
                let held = self.held[dir].take();
                let to = if dir == 0 {
                    &mut self.to_server
                } else {
                    &mut self.to_client
                };
                let _ = to.transmit(frame);
                if let Some(held) = held {
                    let _ = to.transmit(held);
                }
                to.drained_tx();
            }
        }
    }

    /// Releases held frames (a reordered frame never waits forever).
    fn flush(&mut self) {
        use crate::device::NetworkLink;
        if let Some(f) = self.held[0].take() {
            let _ = self.to_server.transmit(f);
        }
        if let Some(f) = self.held[1].take() {
            let _ = self.to_client.transmit(f);
        }
        self.to_server.drained_tx();
        self.to_client.drained_tx();
    }
}

fn lossy_transfer(seed: u64, drop_percent: u64, reorder_percent: u64) {
    lossy_transfer_checked(seed, drop_percent, reorder_percent, true);
}

/// `check_stats`: also require that loss and reordering were seen and recovered from
/// (a run whose only losses were pure ACKs needs no retransmission).
fn lossy_transfer_checked(seed: u64, drop_percent: u64, reorder_percent: u64, check_stats: bool) {
    let (client_link, relay_a) = FakeLink::pair();
    let (relay_b, server_link) = FakeLink::pair();
    let mut client_stack = L3Stack::new(client_link, GUEST_MAC, GUEST_IPV4, ARP_TTL);
    client_stack.arp_cache_mut().insert(PEER_IPV4, PEER_MAC, 0);
    let mut server_stack = L3Stack::new(server_link, PEER_MAC, PEER_IPV4, ARP_TTL);
    server_stack
        .arp_cache_mut()
        .insert(GUEST_IPV4, GUEST_MAC, 0);
    let mut client = TcpTransport::alloc_boxed(
        client_stack,
        SessionGeneration::new(1),
        NetRng::from_seed([1; SEED_BYTES]),
    );
    let mut server = TcpTransport::alloc_boxed(
        server_stack,
        SessionGeneration::new(1),
        NetRng::from_seed([2; SEED_BYTES]),
    );
    let mut relay = LossyRelay {
        to_server: relay_b,
        to_client: relay_a,
        rng: seed | 1,
        held: [None, None],
        drop_percent,
        reorder_percent,
        dropped: 0,
        reordered: 0,
        armed: false,
    };

    let upload = pattern(64 * 1024);
    let download: Vec<u8> = pattern(48 * 1024).iter().map(|b| b ^ 0x5a).collect();
    let listener = server.listen(OTHER, LISTEN_PORT).unwrap();
    let c = client
        .connect(0, OWNER, SocketAddrV4::new(PEER_IPV4, LISTEN_PORT))
        .unwrap();
    let mut s: Option<SessionId> = None;
    let (mut up_sent, mut down_sent) = (0usize, 0usize);
    let (mut got_up, mut got_down) = (Vec::new(), Vec::new());
    let (mut client_closed, mut server_closed) = (false, false);
    let mut buf = [0u8; 1024];

    let mut now = 0u64;
    while now < 600_000 {
        now += 1;
        client.poll(now).unwrap();
        client.stack().link().drained_tx();
        relay.pump();
        server.poll(now).unwrap();
        server.stack().link().drained_tx();
        relay.pump();
        if now % 37 == 0 {
            relay.flush();
        }

        if s.is_none() {
            s = server.accept(listener, OTHER).unwrap();
            relay.armed = s.is_some();
        }
        let established = client.state(c, OWNER).ok() == Some(TcpState::Established)
            || client.state(c, OWNER).ok() == Some(TcpState::CloseWait);
        if established && up_sent < upload.len() {
            if let Ok(n) = client.send(now, c, OWNER, &upload[up_sent..]) {
                up_sent += n;
            }
        }
        if up_sent == upload.len() && !client_closed && established {
            client.close(now, c, OWNER).unwrap();
            client_closed = true;
        }
        if let Some(sid) = s {
            loop {
                match server.receive(sid, OTHER, &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got_up.extend_from_slice(&buf[..n]),
                }
            }
            if down_sent < download.len() {
                if let Ok(n) = server.send(now, sid, OTHER, &download[down_sent..]) {
                    down_sent += n;
                }
            } else if !server_closed && got_up.len() == upload.len() {
                server.close(now, sid, OTHER).unwrap();
                server_closed = true;
            }
        }
        loop {
            match client.receive(c, OWNER, &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => got_down.extend_from_slice(&buf[..n]),
            }
        }
        if client.connections_in_use() == 0 && server.connections_in_use() == 0 {
            break;
        }
    }
    assert_eq!(
        got_up.len(),
        upload.len(),
        "upload incomplete at tick {now}"
    );
    assert!(got_up == upload, "upload corrupted");
    assert_eq!(
        got_down.len(),
        download.len(),
        "download incomplete at tick {now}"
    );
    assert!(got_down == download, "download corrupted");
    assert_eq!(client.connections_in_use(), 0, "client slot freed");
    assert_eq!(server.connections_in_use(), 0, "server slot freed");
    if check_stats && drop_percent > 0 {
        assert!(relay.dropped > 0);
        let retransmits = client.stats().retransmits
            + client.stats().fast_retransmits
            + server.stats().retransmits
            + server.stats().fast_retransmits;
        assert!(retransmits > 0);
    }
    if check_stats && reorder_percent > 0 {
        assert!(relay.reordered > 0);
        assert!(client.stats().out_of_order_queued + server.stats().out_of_order_queued > 0);
    }
}

#[test]
fn clean_link_transfer_both_ways() {
    lossy_transfer(7, 0, 0);
}

#[test]
fn transfer_survives_reordering() {
    lossy_transfer(11, 0, 15);
}

#[test]
fn transfer_survives_loss_and_reordering() {
    for seed in [3, 5, 9, 21] {
        lossy_transfer(seed, 10, 10);
    }
}

#[test]
#[ignore = "soak: cargo test -p clean-slate-network --features alloc -- --ignored soak"]
fn soak_many_seeds() {
    for seed in 1..1000 {
        lossy_transfer_checked(seed, seed % 25, (seed / 3) % 20, false);
    }
}

#[test]
fn transfer_survives_heavy_loss() {
    lossy_transfer(42, 25, 5);
}
