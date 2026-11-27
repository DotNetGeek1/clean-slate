//! Per-connection TCP state machine and bounded buffers.
//!
//! The send ring holds every byte from `snd_una` on: bytes in flight stay there until the
//! peer acknowledges them, so a retransmission re-reads them from the ring (go-back-N from
//! `snd_una` after a timeout, one segment after three duplicate ACKs). The receive ring
//! holds in-order bytes for `receive`; out-of-order bytes inside the advertised window are
//! written straight into the ring's free space at their sequence offset and tracked as a
//! few ranges, so reassembly needs no extra storage.

use crate::addr::{Ipv4Addr, SocketAddrV4};
use crate::error::NetworkError;
use crate::protocol::TrustedCaller;
use crate::tcp::segment::{
    write as write_segment, TcpFlags, TcpSegment, MAX_TCP_PAYLOAD, OUR_TCP_MSS,
};
use crate::tcp::state::TcpState;
use crate::tcp::stats::TcpStats;

/// Send buffer capacity: bytes queued by the application and bytes in flight, not yet ACKed.
pub const TCP_SEND_BUFFER_BYTES: usize = 4096;

/// Receive buffer capacity: in-order data waiting for `receive`, and the advertised window.
pub const TCP_RECV_BUFFER_BYTES: usize = 4096;

/// Retransmission timeouts in a row (no new ACK in between) before `NetworkError::Timeout`.
pub const TCP_MAX_RETRIES: u32 = 8;

/// SYN-ACK retransmissions for a passive open before the embryonic connection is dropped.
pub const TCP_SYN_ACK_RETRIES: u32 = 4;

/// Retransmission timeout before the first RTT sample (RFC 6298 §2.1, shortened for the lab).
pub const TCP_RTO_INITIAL_MS: u64 = 100;

/// Lower bound on the computed retransmission timeout.
pub const TCP_RTO_MIN_MS: u64 = 50;

/// Upper bound on the retransmission timeout, including exponential backoff.
pub const TCP_RTO_MAX_MS: u64 = 4_000;

/// TIME-WAIT duration before a closed connection slot is reusable.
pub const TCP_TIME_WAIT_MS: u64 = 200;

/// Backstop active-open timeout while waiting for SYN-ACK. Callers own the real connect
/// deadline (the network service's is 500 ms) and must always reach it first: a connection
/// the transport times out is freed, so the caller would see it vanish instead of time out.
pub const TCP_CONNECT_TIMEOUT_MS: u64 = 10_000;

/// Disjoint out-of-order ranges held per connection; a segment that would need a fifth is dropped.
pub const TCP_MAX_OOO_RANGES: usize = 4;

/// Duplicate ACKs that trigger a fast retransmit (RFC 5681 §3.2).
pub const TCP_DUP_ACK_THRESHOLD: u32 = 3;

/// MSS assumed when the peer's SYN carries no MSS option (RFC 1122 §4.2.2.6).
pub const TCP_DEFAULT_PEER_MSS: u16 = 536;

/// TCP timer lengths in transport ticks, derived from the tick period.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpTimers {
    pub rto_initial: u64,
    pub rto_min: u64,
    pub rto_max: u64,
    pub time_wait: u64,
    pub connect_timeout: u64,
}

impl TcpTimers {
    /// Timers for a 1 ms tick.
    pub const DEFAULT: Self = Self::from_tick_period_ns(1_000_000);

    pub const fn from_tick_period_ns(tick_period_ns: u64) -> Self {
        Self {
            rto_initial: ms_to_ticks(TCP_RTO_INITIAL_MS, tick_period_ns),
            rto_min: ms_to_ticks(TCP_RTO_MIN_MS, tick_period_ns),
            rto_max: ms_to_ticks(TCP_RTO_MAX_MS, tick_period_ns),
            time_wait: ms_to_ticks(TCP_TIME_WAIT_MS, tick_period_ns),
            connect_timeout: ms_to_ticks(TCP_CONNECT_TIMEOUT_MS, tick_period_ns),
        }
    }
}

const fn ms_to_ticks(ms: u64, tick_period_ns: u64) -> u64 {
    let period = if tick_period_ns == 0 {
        1_000_000
    } else {
        tick_period_ns
    };
    let ticks = ms.saturating_mul(1_000_000).div_ceil(period);
    if ticks == 0 {
        1
    } else {
        ticks
    }
}

/// Fixed-capacity byte ring.
#[derive(Clone, Debug)]
pub(crate) struct RingBuf<const N: usize> {
    data: [u8; N],
    head: usize,
    len: usize,
}

impl<const N: usize> RingBuf<N> {
    pub const fn new() -> Self {
        Self {
            data: [0; N],
            head: 0,
            len: 0,
        }
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn filled(&self) -> usize {
        self.len
    }

    pub fn free_space(&self) -> usize {
        N - self.len
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    pub fn push(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.free_space());
        self.write_beyond(0, &data[..n]);
        self.len += n;
        n
    }

    pub fn pop(&mut self, out: &mut [u8]) -> usize {
        let n = self.peek_at(0, out);
        self.discard(n)
    }

    /// Copies filled bytes starting `offset` bytes after the head, without consuming them.
    pub fn peek_at(&self, offset: usize, out: &mut [u8]) -> usize {
        let n = out.len().min(self.len.saturating_sub(offset));
        for (i, byte) in out.iter_mut().enumerate().take(n) {
            *byte = self.data[(self.head + offset + i) % N];
        }
        n
    }

    /// Drops up to `n` bytes from the head.
    pub fn discard(&mut self, n: usize) -> usize {
        let n = n.min(self.len);
        self.head = (self.head + n) % N;
        // `head` must not snap back to 0 when the ring empties: out-of-order bytes may be
        // parked past the filled end, at positions relative to `head + len`.
        self.len -= n;
        n
    }

    /// Writes into free space `offset` bytes past the filled end without marking it filled.
    pub fn write_beyond(&mut self, offset: usize, data: &[u8]) -> usize {
        let n = data.len().min(self.free_space().saturating_sub(offset));
        for (i, &b) in data.iter().take(n).enumerate() {
            self.data[(self.head + self.len + offset + i) % N] = b;
        }
        n
    }

    /// Marks `n` bytes already written by [`Self::write_beyond`] as filled.
    pub fn commit(&mut self, n: usize) {
        self.len += n.min(self.free_space());
    }
}

type SendRing = RingBuf<TCP_SEND_BUFFER_BYTES>;
type RecvRing = RingBuf<TCP_RECV_BUFFER_BYTES>;

/// Out-of-order bytes `[start, end)` already written into the receive ring.
#[derive(Clone, Copy, Debug, Default)]
struct SeqRange {
    start: u32,
    end: u32,
}

/// One TCP connection (active or passive open).
pub struct TcpConnection {
    pub owner: TrustedCaller,
    pub local: SocketAddrV4,
    pub remote: SocketAddrV4,
    pub state: TcpState,
    pub snd_una: u32,
    pub snd_nxt: u32,
    /// Highest sequence number sent (`snd_nxt` rewinds to `snd_una` on a timeout).
    pub snd_max: u32,
    pub iss: u32,
    pub rcv_nxt: u32,
    pub irs: u32,
    pub peer_window: u16,
    pub peer_mss: u16,
    /// Segment sequence and acknowledgment numbers of the last window update (RFC 793).
    snd_wl1: u32,
    snd_wl2: u32,
    send_buf: SendRing,
    recv_buf: RecvRing,
    ooo: [SeqRange; TCP_MAX_OOO_RANGES],
    ooo_len: usize,
    /// Sequence number of a FIN that arrived ahead of `rcv_nxt`.
    ooo_fin: Option<u32>,
    timers: TcpTimers,
    /// Current retransmission timeout in ticks, backed off on each expiry.
    pub rto: u64,
    /// Smoothed RTT ×8 and RTT variance ×4, in ticks (RFC 6298, BSD scaling).
    srtt8: u64,
    rttvar4: u64,
    have_rtt: bool,
    /// The segment being timed for an RTT sample: (sequence number it ends at, tick sent).
    rtt_probe: Option<(u32, u64)>,
    rto_deadline: Option<u64>,
    rto_retries: u32,
    persist_deadline: Option<u64>,
    /// Zero-window probes sent since the peer last acknowledged anything.
    probes_unanswered: u32,
    /// Probes sent while the window stayed closed (the persist backoff exponent).
    probes_sent: u32,
    /// Send one segment on the next pass even if the peer's window is closed (RTO, probe).
    force_send: bool,
    pub cwnd: u32,
    pub ssthresh: u32,
    dup_acks: u32,
    /// Right edge of the receive window (`rcv_nxt + window`) last advertised to the peer.
    adv_right_edge: u32,
    time_wait_deadline: Option<u64>,
    connect_deadline: Option<u64>,
    pending_syn: bool,
    peer_fin_seen: bool,
    /// Sequence number of our FIN, fixed when the application closes.
    fin_seq: Option<u32>,
    /// Listener slot for a passive open; `accepted` once handed to the application.
    pub(crate) listener: Option<u8>,
    pub(crate) accepted: bool,
    /// Order in which passive connections reached ESTABLISHED, for FIFO `accept`.
    pub(crate) established_order: u64,
    failed: Option<NetworkError>,
}

impl TcpConnection {
    /// Active open: SYN-SENT, SYN not yet transmitted.
    pub fn new(owner: TrustedCaller, local: SocketAddrV4, remote: SocketAddrV4, iss: u32) -> Self {
        Self::with_timers(owner, local, remote, iss, TcpTimers::DEFAULT)
    }

    pub fn with_timers(
        owner: TrustedCaller,
        local: SocketAddrV4,
        remote: SocketAddrV4,
        iss: u32,
        timers: TcpTimers,
    ) -> Self {
        let mss = u32::from(OUR_TCP_MSS);
        Self {
            owner,
            local,
            remote,
            state: TcpState::SynSent,
            snd_una: iss,
            snd_nxt: iss,
            snd_max: iss,
            iss,
            rcv_nxt: 0,
            irs: 0,
            peer_window: 0,
            peer_mss: TCP_DEFAULT_PEER_MSS,
            snd_wl1: 0,
            snd_wl2: 0,
            send_buf: SendRing::new(),
            recv_buf: RecvRing::new(),
            ooo: [SeqRange::default(); TCP_MAX_OOO_RANGES],
            ooo_len: 0,
            ooo_fin: None,
            timers,
            rto: timers.rto_initial,
            srtt8: 0,
            rttvar4: 0,
            have_rtt: false,
            rtt_probe: None,
            rto_deadline: None,
            rto_retries: 0,
            persist_deadline: None,
            probes_unanswered: 0,
            probes_sent: 0,
            force_send: false,
            cwnd: initial_cwnd(mss),
            ssthresh: u32::MAX,
            dup_acks: 0,
            adv_right_edge: 0,
            time_wait_deadline: None,
            connect_deadline: None,
            pending_syn: true,
            peer_fin_seen: false,
            fin_seq: None,
            listener: None,
            accepted: false,
            established_order: 0,
            failed: None,
        }
    }

    /// Passive open: SYN-RECEIVED from the peer's `syn`, SYN-ACK not yet transmitted.
    pub fn new_passive(
        owner: TrustedCaller,
        local: SocketAddrV4,
        remote: SocketAddrV4,
        iss: u32,
        syn: &TcpSegment,
        listener: u8,
        timers: TcpTimers,
    ) -> Self {
        let mut conn = Self::with_timers(owner, local, remote, iss, timers);
        conn.state = TcpState::SynReceived;
        conn.pending_syn = false;
        conn.irs = syn.seq;
        conn.rcv_nxt = syn.seq.wrapping_add(1);
        conn.peer_window = syn.window;
        conn.snd_wl1 = syn.seq;
        conn.set_peer_mss(syn.mss_option);
        conn.listener = Some(listener);
        conn
    }

    fn set_peer_mss(&mut self, option: Option<u16>) {
        self.peer_mss = option.unwrap_or(TCP_DEFAULT_PEER_MSS).clamp(1, OUR_TCP_MSS);
        self.cwnd = initial_cwnd(self.send_mss() as u32);
    }

    /// Largest payload we put in one segment toward this peer.
    pub fn send_mss(&self) -> usize {
        (self.peer_mss as usize).min(MAX_TCP_PAYLOAD)
    }

    pub fn advertised_window(&self) -> u16 {
        self.recv_buf.free_space().min(u16::MAX as usize) as u16
    }

    pub fn timers(&self) -> TcpTimers {
        self.timers
    }

    pub fn release_buffers(&mut self) {
        self.send_buf.clear();
        self.recv_buf.clear();
        self.ooo_len = 0;
        self.ooo_fin = None;
        self.rto_deadline = None;
        self.persist_deadline = None;
    }

    pub fn take_failure(&mut self) -> Option<NetworkError> {
        self.failed.take()
    }

    pub fn on_connect_start(&mut self, now: u64) {
        self.touch_connect_deadline(now);
        self.pending_syn = true;
    }

    pub fn touch_connect_deadline(&mut self, now: u64) {
        self.connect_deadline = Some(now + self.timers.connect_timeout);
    }

    fn bytes_in_flight(&self) -> u32 {
        self.snd_max.wrapping_sub(self.snd_una)
    }

    fn fin_acked(&self) -> bool {
        self.fin_seq.is_some_and(|fin| seq_lt(fin, self.snd_una))
    }

    fn fail(&mut self, err: NetworkError) -> NetworkError {
        self.state = TcpState::Reset;
        self.release_buffers();
        self.failed = Some(err);
        err
    }

    pub fn tick_timers(&mut self, now: u64, stats: &mut TcpStats) -> TimerAction {
        if let Some(err) = self.failed {
            return TimerAction::Failed(err);
        }
        if self.state == TcpState::TimeWait {
            // Every path into TIME-WAIT must eventually free the slot. Some transitions
            // happen inside `on_segment` before the transport stamps the deadline, so arm
            // it here on first observation if it is still unset.
            let deadline = *self
                .time_wait_deadline
                .get_or_insert(now + self.timers.time_wait);
            if now >= deadline {
                self.state = TcpState::Closed;
                self.release_buffers();
                return TimerAction::Closed;
            }
            return TimerAction::None;
        }
        if self.state == TcpState::SynSent {
            if let Some(dl) = self.connect_deadline {
                if now >= dl {
                    stats.timeouts += 1;
                    return TimerAction::Failed(self.fail(NetworkError::Timeout));
                }
            }
        }
        if let Some(dl) = self.rto_deadline {
            if now >= dl {
                return self.on_rto_expired(now, stats);
            }
        }
        if let Some(dl) = self.persist_deadline {
            if now >= dl {
                // Zero-window probe (RFC 1122 §4.2.2.17). The probe is an ACK carrying
                // `snd_una - 1`, which the peer must answer with its current window, so no
                // probe byte is left in flight when the window reopens. Probing continues,
                // backed off, for as long as the peer answers.
                if self.probes_unanswered >= TCP_MAX_RETRIES {
                    stats.timeouts += 1;
                    return TimerAction::Failed(self.fail(NetworkError::Timeout));
                }
                self.probes_unanswered += 1;
                self.probes_sent += 1;
                let backoff = self
                    .rto
                    .saturating_mul(1u64 << self.probes_sent.min(16))
                    .min(self.timers.rto_max);
                self.persist_deadline = Some(now + backoff);
                stats.window_probes += 1;
                return TimerAction::Probe;
            }
        }
        TimerAction::None
    }

    fn on_rto_expired(&mut self, now: u64, stats: &mut TcpStats) -> TimerAction {
        match self.state {
            TcpState::SynSent => {}
            TcpState::SynReceived => {
                if self.rto_retries >= TCP_SYN_ACK_RETRIES {
                    self.state = TcpState::Closed;
                    self.release_buffers();
                    return TimerAction::Closed;
                }
            }
            _ => {
                if self.rto_retries >= TCP_MAX_RETRIES {
                    stats.timeouts += 1;
                    return TimerAction::Failed(self.fail(NetworkError::Timeout));
                }
            }
        }
        self.rto_retries += 1;
        // RFC 6298 §5.5-5.6: back off, restart the timer, and stop timing (Karn).
        self.rto = self.rto.saturating_mul(2).min(self.timers.rto_max);
        self.rto_deadline = Some(now + self.rto);
        self.rtt_probe = None;
        stats.retransmits += 1;
        if self.state.is_synchronized() {
            // RFC 5681 §3.1: collapse to one segment and resend from `snd_una`.
            let mss = self.send_mss() as u32;
            self.ssthresh = (self.bytes_in_flight() / 2).max(2 * mss);
            self.cwnd = mss;
            self.dup_acks = 0;
            self.snd_nxt = self.snd_una;
            self.force_send = true;
        }
        TimerAction::Retransmit
    }

    /// Earliest tick at which [`Self::tick_timers`] or a window update has work, or `None`.
    ///
    /// An unarmed TIME-WAIT or a due window update reports `Some(0)` (due now).
    pub fn next_timer_deadline(&self) -> Option<u64> {
        if self.failed.is_some() {
            return None;
        }
        if self.window_update_due() {
            return Some(0);
        }
        let mut next: Option<u64> = None;
        let mut consider = |dl: u64| next = Some(next.map_or(dl, |n| n.min(dl)));
        if self.state == TcpState::TimeWait {
            consider(self.time_wait_deadline.unwrap_or(0));
            return next;
        }
        if self.state == TcpState::SynSent {
            if let Some(dl) = self.connect_deadline {
                consider(dl);
            }
        }
        if let Some(dl) = self.rto_deadline {
            consider(dl);
        }
        if let Some(dl) = self.persist_deadline {
            consider(dl);
        }
        next
    }

    pub fn on_unreachable(&mut self) {
        if self.state == TcpState::SynSent {
            self.pending_syn = true;
        }
    }

    pub fn needs_syn_retry(&self) -> bool {
        self.pending_syn && self.state == TcpState::SynSent
    }

    pub fn clear_pending_syn(&mut self) {
        self.pending_syn = false;
    }

    pub fn has_active_retransmit(&self) -> bool {
        self.rto_deadline.is_some()
    }

    pub fn on_segment(
        &mut self,
        seg: &TcpSegment,
        payload: &[u8],
        now: u64,
        stats: &mut TcpStats,
    ) -> SegmentAction {
        if let Some(err) = self.failed {
            return SegmentAction::Failed(err);
        }

        if seg.flags.contains(TcpFlags::RST) {
            return self.on_rst(seg, stats);
        }

        match self.state {
            TcpState::SynSent => self.on_syn_sent(seg, payload, now, stats),
            TcpState::SynReceived => self.on_syn_received(seg, payload, now, stats),
            TcpState::Closed | TcpState::Reset => SegmentAction::None,
            _ => self.on_synchronized(seg, payload, now, stats),
        }
    }

    fn on_rst(&mut self, seg: &TcpSegment, stats: &mut TcpStats) -> SegmentAction {
        // RFC 793 §3.4: in SYN-SENT a RST is acceptable only if it ACKs our SYN; in every
        // other state it must carry the exact next expected sequence number (RFC 5961
        // §3.2). Anything else is a blind RST and is dropped, so an off-path peer cannot
        // tear down sessions.
        let acceptable = if self.state == TcpState::SynSent {
            seg.flags.contains(TcpFlags::ACK) && seg.ack == self.iss.wrapping_add(1)
        } else {
            seg.seq == self.rcv_nxt
        };
        if !acceptable {
            stats.dropped_out_of_order += 1;
            return SegmentAction::None;
        }
        stats.resets_received += 1;
        if self.state == TcpState::SynReceived {
            // A passive open the peer abandoned: drop it quietly; the listener stays.
            self.state = TcpState::Closed;
            self.release_buffers();
            return SegmentAction::Closed;
        }
        SegmentAction::Failed(self.fail(NetworkError::Reset))
    }

    fn on_syn_sent(
        &mut self,
        seg: &TcpSegment,
        payload: &[u8],
        now: u64,
        stats: &mut TcpStats,
    ) -> SegmentAction {
        // RFC 793 §3.9 SYN-SENT: a segment without SYN (and not RST) is dropped.
        if !seg.flags.contains(TcpFlags::SYN) || !seg.flags.contains(TcpFlags::ACK) {
            return SegmentAction::None;
        }
        if seg.ack != self.iss.wrapping_add(1) {
            stats.dropped_bad_ack += 1;
            return SegmentAction::None;
        }
        self.pending_syn = false;
        self.irs = seg.seq;
        self.rcv_nxt = seg.seq.wrapping_add(1);
        self.set_peer_mss(seg.mss_option);
        self.connect_deadline = None;
        self.on_handshake_acked(seg, now);
        // Data piggybacked on the SYN-ACK starts at IRS+1 == rcv_nxt (RFC 793 §3.9).
        if !payload.is_empty() || seg.flags.contains(TcpFlags::FIN) {
            self.accept_data(
                seg.seq.wrapping_add(1),
                payload,
                seg.flags.contains(TcpFlags::FIN),
                stats,
            );
        }
        SegmentAction::SendAck
    }

    fn on_syn_received(
        &mut self,
        seg: &TcpSegment,
        payload: &[u8],
        now: u64,
        stats: &mut TcpStats,
    ) -> SegmentAction {
        if seg.flags.contains(TcpFlags::SYN) && !seg.flags.contains(TcpFlags::ACK) {
            // The peer retransmitted its SYN: our SYN-ACK was lost.
            if seg.seq == self.irs {
                return SegmentAction::SendSynAck;
            }
            stats.dropped_out_of_order += 1;
            return SegmentAction::None;
        }
        if !seg.flags.contains(TcpFlags::ACK) {
            return SegmentAction::None;
        }
        if seg.ack != self.iss.wrapping_add(1) {
            stats.dropped_bad_ack += 1;
            return SegmentAction::None;
        }
        let seg_len = segment_len(seg, payload);
        if !self.acceptable(seg.seq, seg_len) {
            stats.dropped_out_of_order += 1;
            return SegmentAction::SendAck;
        }
        self.on_handshake_acked(seg, now);
        // The handshake ACK may carry data or a FIN.
        match self.on_synchronized(seg, payload, now, stats) {
            SegmentAction::None => SegmentAction::MaybeSendData,
            other => other,
        }
    }

    /// Our SYN (or SYN-ACK) was acknowledged: the connection is ESTABLISHED.
    fn on_handshake_acked(&mut self, seg: &TcpSegment, now: u64) {
        if self.rto_retries == 0 {
            if let Some((_, sent)) = self.rtt_probe {
                self.rtt_sample(now.saturating_sub(sent));
            }
        }
        self.rtt_probe = None;
        self.rto_deadline = None;
        self.rto_retries = 0;
        self.snd_una = self.iss.wrapping_add(1);
        self.snd_nxt = self.snd_una;
        self.snd_max = self.snd_una;
        self.peer_window = seg.window;
        self.snd_wl1 = seg.seq;
        self.snd_wl2 = seg.ack;
        self.state = TcpState::Established;
    }

    /// Every state after the handshake (RFC 793 §3.9 "Otherwise").
    fn on_synchronized(
        &mut self,
        seg: &TcpSegment,
        payload: &[u8],
        now: u64,
        stats: &mut TcpStats,
    ) -> SegmentAction {
        let seg_len = segment_len(seg, payload);
        if !self.acceptable(seg.seq, seg_len) {
            // Unacceptable: dropped, and answered with an ACK so a peer whose earlier ACK
            // was lost stops retransmitting.
            stats.dropped_out_of_order += 1;
            return SegmentAction::SendAck;
        }
        if seg.flags.contains(TcpFlags::SYN) {
            // RFC 5961 §4.2: an in-window SYN gets a challenge ACK, never a reset.
            stats.dropped_out_of_order += 1;
            return SegmentAction::SendAck;
        }
        if !seg.flags.contains(TcpFlags::ACK) {
            return SegmentAction::None;
        }

        let mut action = SegmentAction::None;
        // RFC 5961 §5.2: an ACK is acceptable only in [snd_una - MAX.SND.WND, snd_max].
        // One that acknowledges something never sent, or is too old to be a duplicate,
        // is dropped with a challenge ACK.
        if seq_lt(self.snd_max, seg.ack)
            || seq_lt(seg.ack, self.snd_una.wrapping_sub(u32::from(u16::MAX)))
        {
            stats.dropped_bad_ack += 1;
            return SegmentAction::SendAck;
        }
        if seq_le(self.snd_una, seg.ack) {
            let advanced = seg.ack != self.snd_una;
            let window_changed = self.update_send_window(seg);
            if advanced {
                self.on_new_ack(seg.ack, now);
                action = SegmentAction::MaybeSendData;
            } else if payload.is_empty()
                && !seg.flags.contains(TcpFlags::FIN)
                && !window_changed
                && self.bytes_in_flight() != 0
                && self.peer_window != 0
            {
                self.dup_acks += 1;
                if self.dup_acks == TCP_DUP_ACK_THRESHOLD {
                    // RFC 5681 §3.2 fast retransmit of the segment at `snd_una`.
                    let mss = self.send_mss() as u32;
                    self.ssthresh = (self.bytes_in_flight() / 2).max(2 * mss);
                    self.cwnd = self.ssthresh;
                    self.rtt_probe = None;
                    stats.fast_retransmits += 1;
                    action = SegmentAction::Retransmit;
                }
            }
            if window_changed && matches!(action, SegmentAction::None) {
                action = SegmentAction::MaybeSendData;
            }
            // Any acceptable ACK answers outstanding zero-window probes.
            self.probes_unanswered = 0;
        }

        if self.fin_acked() {
            match self.state {
                TcpState::FinWait1 => self.state = TcpState::FinWait2,
                TcpState::Closing => self.state = TcpState::TimeWait,
                TcpState::LastAck => {
                    self.state = TcpState::Closed;
                    self.release_buffers();
                    return SegmentAction::Closed;
                }
                _ => {}
            }
        }

        let fin = seg.flags.contains(TcpFlags::FIN);
        if (!payload.is_empty() || fin)
            && matches!(
                self.state,
                TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
            )
        {
            self.accept_data(seg.seq, payload, fin, stats);
            action = SegmentAction::SendAck;
        } else if seg_len == 0 && seq_lt(seg.seq, self.rcv_nxt) {
            // Below `rcv_nxt`: a zero-window probe (or a stale ACK). Answer with our
            // window. The answer carries `snd_max`, which is never below the peer's
            // `rcv_nxt`, so it cannot draw a reply in turn.
            action = SegmentAction::SendAck;
        }
        action
    }

    /// RFC 793 §3.9 window update rule (SND.WL1 / SND.WL2). Returns whether it changed.
    fn update_send_window(&mut self, seg: &TcpSegment) -> bool {
        if seq_lt(self.snd_wl1, seg.seq)
            || (self.snd_wl1 == seg.seq && seq_le(self.snd_wl2, seg.ack))
        {
            let changed = self.peer_window != seg.window;
            self.peer_window = seg.window;
            self.snd_wl1 = seg.seq;
            self.snd_wl2 = seg.ack;
            if seg.window != 0 {
                self.persist_deadline = None;
                self.probes_unanswered = 0;
                self.probes_sent = 0;
            }
            return changed;
        }
        false
    }

    fn on_new_ack(&mut self, ack: u32, now: u64) {
        let acked = ack.wrapping_sub(self.snd_una);
        self.send_buf.discard(acked as usize);
        self.snd_una = ack;
        if seq_lt(self.snd_nxt, self.snd_una) {
            self.snd_nxt = self.snd_una;
        }
        if let Some((end, sent)) = self.rtt_probe {
            if seq_le(end, ack) {
                self.rtt_sample(now.saturating_sub(sent));
                self.rtt_probe = None;
            }
        }
        self.rto_retries = 0;
        self.dup_acks = 0;
        let mss = self.send_mss() as u32;
        if self.cwnd < self.ssthresh {
            self.cwnd = self.cwnd.saturating_add(acked.min(mss));
        } else {
            self.cwnd = self
                .cwnd
                .saturating_add((mss.saturating_mul(mss) / self.cwnd.max(1)).max(1));
        }
        self.cwnd = self.cwnd.min(4 * TCP_SEND_BUFFER_BYTES as u32);
        self.rto_deadline = if self.snd_una == self.snd_max {
            None
        } else {
            Some(now + self.rto)
        };
    }

    /// RFC 6298 §2.2-2.3.
    fn rtt_sample(&mut self, rtt: u64) {
        let rtt = rtt.max(1);
        if self.have_rtt {
            let srtt = self.srtt8 / 8;
            let delta = srtt.abs_diff(rtt);
            self.rttvar4 = (3 * self.rttvar4 + 4 * delta) / 4;
            self.srtt8 = (7 * self.srtt8 + 8 * rtt) / 8;
        } else {
            self.srtt8 = 8 * rtt;
            self.rttvar4 = 2 * rtt;
            self.have_rtt = true;
        }
        let rto = self.srtt8 / 8 + self.rttvar4.max(1);
        self.rto = rto.clamp(self.timers.rto_min, self.timers.rto_max);
    }

    /// Smoothed round-trip time in ticks, once a sample exists.
    pub fn srtt(&self) -> Option<u64> {
        self.have_rtt.then_some(self.srtt8 / 8)
    }

    /// RFC 793 §3.9 segment acceptability against the receive window.
    ///
    /// A segment that occupies no sequence space only carries an ACK and a window, so it
    /// is accepted from up to one maximum window below `rcv_nxt` to the window's right
    /// edge (RFC 793's "special allowance" for ACKs). A peer that rewound `snd_nxt` to
    /// retransmit, or whose window we closed, still gets its ACKs through; the ACK field
    /// itself is checked against `snd_una`/`snd_max` (RFC 5961 §5.2).
    fn acceptable(&self, seq: u32, seg_len: u32) -> bool {
        let wnd = self.recv_buf.free_space() as u32;
        let right = self.rcv_nxt.wrapping_add(wnd);
        if seg_len == 0 {
            return seq_le(self.rcv_nxt.wrapping_sub(u32::from(u16::MAX)), seq)
                && seq_le(seq, right);
        }
        let in_window = |x: u32| seq_le(self.rcv_nxt, x) && seq_lt(x, right);
        wnd != 0 && (in_window(seq) || in_window(seq.wrapping_add(seg_len - 1)))
    }

    /// Takes the acceptable part of a segment's data (and FIN): in-order bytes go to the
    /// application, later bytes inside the window wait in the ring for the gap to fill.
    fn accept_data(&mut self, seq: u32, payload: &[u8], fin: bool, stats: &mut TcpStats) {
        let mut seq = seq;
        let mut data = payload;
        if seq_lt(seq, self.rcv_nxt) {
            let skip = (self.rcv_nxt.wrapping_sub(seq) as usize).min(data.len());
            data = &data[skip..];
            seq = seq.wrapping_add(skip as u32);
        }
        let offset = seq.wrapping_sub(self.rcv_nxt) as usize;
        let room = self.recv_buf.free_space().saturating_sub(offset);
        let mut fin = fin;
        if data.len() > room {
            data = &data[..room];
            fin = false;
        }

        if offset == 0 {
            let n = self.recv_buf.push(data);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(n as u32);
            self.drain_ooo();
            if fin || self.ooo_fin == Some(self.rcv_nxt) {
                self.consume_fin();
            }
            return;
        }

        if !data.is_empty() {
            let end = seq.wrapping_add(data.len() as u32);
            if !self.insert_ooo(seq, end) {
                stats.dropped_out_of_order += 1;
                return;
            }
            self.recv_buf.write_beyond(offset, data);
            stats.out_of_order_queued += 1;
        }
        if fin {
            self.ooo_fin = Some(seq.wrapping_add(data.len() as u32));
        }
    }

    /// Adds `[start, end)` to the out-of-order ranges, merging overlaps. `false` when full.
    fn insert_ooo(&mut self, start: u32, end: u32) -> bool {
        let touches = |r: &SeqRange| seq_le(r.start, end) && seq_le(start, r.end);
        let ranges = &self.ooo[..self.ooo_len];
        if !ranges.iter().any(touches) && self.ooo_len == TCP_MAX_OOO_RANGES {
            return false;
        }
        let (mut start, mut end) = (start, end);
        let mut i = 0;
        while i < self.ooo_len {
            let r = self.ooo[i];
            if seq_le(r.start, end) && seq_le(start, r.end) {
                if seq_lt(r.start, start) {
                    start = r.start;
                }
                if seq_lt(end, r.end) {
                    end = r.end;
                }
                self.ooo_len -= 1;
                self.ooo[i] = self.ooo[self.ooo_len];
            } else {
                i += 1;
            }
        }
        self.ooo[self.ooo_len] = SeqRange { start, end };
        self.ooo_len += 1;
        true
    }

    /// Moves out-of-order ranges that now touch `rcv_nxt` into the in-order data.
    fn drain_ooo(&mut self) {
        let mut i = 0;
        while i < self.ooo_len {
            let r = self.ooo[i];
            if seq_le(r.start, self.rcv_nxt) {
                if seq_lt(self.rcv_nxt, r.end) {
                    let n = r.end.wrapping_sub(self.rcv_nxt);
                    self.recv_buf.commit(n as usize);
                    self.rcv_nxt = r.end;
                }
                self.ooo_len -= 1;
                self.ooo[i] = self.ooo[self.ooo_len];
                i = 0;
            } else {
                i += 1;
            }
        }
    }

    fn consume_fin(&mut self) {
        self.peer_fin_seen = true;
        self.ooo_fin = None;
        self.ooo_len = 0;
        self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
        self.state = match self.state {
            TcpState::Established => TcpState::CloseWait,
            TcpState::FinWait1 if self.fin_acked() => TcpState::TimeWait,
            TcpState::FinWait1 => TcpState::Closing,
            TcpState::FinWait2 => TcpState::TimeWait,
            other => other,
        };
    }

    /// Bytes held out of order, waiting for a gap before them to fill.
    pub fn out_of_order_bytes(&self) -> usize {
        self.ooo[..self.ooo_len]
            .iter()
            .map(|r| r.end.wrapping_sub(r.start) as usize)
            .sum()
    }

    /// The application freed enough receive space that the peer should hear about it
    /// (RFC 1122 §4.2.3.3 receiver-side silly window avoidance).
    pub fn window_update_due(&self) -> bool {
        if !matches!(
            self.state,
            TcpState::Established | TcpState::FinWait1 | TcpState::FinWait2
        ) {
            return false;
        }
        let right = self.rcv_nxt.wrapping_add(self.recv_buf.free_space() as u32);
        let grown = right.wrapping_sub(self.adv_right_edge);
        if !seq_lt(self.adv_right_edge, right) {
            return false;
        }
        let threshold = (OUR_TCP_MSS as usize).min(TCP_RECV_BUFFER_BYTES / 2) as u32;
        grown >= threshold
    }

    pub fn queue_send(&mut self, data: &[u8]) -> Result<usize, NetworkError> {
        if !matches!(self.state, TcpState::Established | TcpState::CloseWait) {
            return Err(NetworkError::Closed);
        }
        let n = self.send_buf.push(data);
        if n == 0 && !data.is_empty() {
            return Err(NetworkError::QueueFull);
        }
        Ok(n)
    }

    pub fn has_buffered_recv(&self) -> bool {
        !self.recv_buf.is_empty()
    }

    pub fn recv_buffered_len(&self) -> usize {
        self.recv_buf.filled()
    }

    pub fn receive(&mut self, out: &mut [u8]) -> Result<usize, NetworkError> {
        let n = self.recv_buf.pop(out);
        if n > 0 {
            return Ok(n);
        }
        if self.state == TcpState::Reset {
            return Err(NetworkError::Reset);
        }
        if self.peer_fin_seen {
            return Err(NetworkError::Closed);
        }
        Ok(0)
    }

    /// The application closed: our FIN goes out after every queued byte.
    pub fn start_close(&mut self) -> bool {
        let next = match self.state {
            TcpState::Established => TcpState::FinWait1,
            TcpState::CloseWait => TcpState::LastAck,
            _ => return false,
        };
        self.state = next;
        self.fin_seq = Some(self.snd_una.wrapping_add(self.send_buf.filled() as u32));
        true
    }

    pub fn enter_time_wait(&mut self, now: u64) {
        self.state = TcpState::TimeWait;
        self.time_wait_deadline = Some(now + self.timers.time_wait);
    }

    pub fn build_segment(
        &mut self,
        flags: TcpFlags,
        seq: u32,
        ack: u32,
        syn: bool,
        fin: bool,
    ) -> TcpSegment {
        let mut f = flags;
        if syn {
            f = f.union(TcpFlags::SYN);
        }
        if fin {
            f = f.union(TcpFlags::FIN);
        }
        let window = self.advertised_window();
        if f.contains(TcpFlags::ACK) {
            self.adv_right_edge = self.rcv_nxt.wrapping_add(u32::from(window));
        }
        TcpSegment {
            src_port: self.local.port,
            dst_port: self.remote.port,
            seq,
            ack,
            data_offset: if syn { 6 } else { 5 },
            flags: f,
            window,
            checksum: 0,
            urgent: 0,
            mss_option: if syn { Some(OUR_TCP_MSS) } else { None },
        }
    }

    /// Our SYN (active open) or SYN-ACK (passive open), sequence number ISS.
    pub fn syn_segment(&mut self) -> TcpSegment {
        if self.state == TcpState::SynReceived {
            self.build_segment(TcpFlags::ACK, self.iss, self.rcv_nxt, true, false)
        } else {
            self.build_segment(TcpFlags::default(), self.iss, 0, true, false)
        }
    }

    /// Records that the SYN or SYN-ACK went out: it occupies ISS and arms the RTO.
    pub fn on_syn_transmitted(&mut self, now: u64) {
        self.snd_nxt = self.iss.wrapping_add(1);
        self.snd_max = self.snd_nxt;
        if self.rto_retries == 0 && self.rtt_probe.is_none() {
            self.rtt_probe = Some((self.snd_nxt, now));
        }
        self.rto_deadline.get_or_insert(now + self.rto);
    }

    /// A zero-window probe: an ACK one below `snd_una`, outside the peer's window.
    pub fn probe_segment(&mut self) -> TcpSegment {
        let seq = self.snd_una.wrapping_sub(1);
        self.build_segment(TcpFlags::ACK, seq, self.rcv_nxt, false, false)
    }

    /// The pure ACK the transport sends for [`SegmentAction::SendAck`] and window updates.
    ///
    /// It carries `snd_max`, not a `snd_nxt` rewound for retransmission, so it never sits
    /// below data the peer already holds.
    pub fn ack_segment(&mut self) -> TcpSegment {
        self.build_segment(TcpFlags::ACK, self.snd_max, self.rcv_nxt, false, false)
    }

    pub fn send_buf_has_data(&self) -> bool {
        !self.send_buf.is_empty()
    }

    /// States in which our data or FIN may still go out (or need resending).
    fn may_send(&self) -> bool {
        matches!(
            self.state,
            TcpState::Established
                | TcpState::CloseWait
                | TcpState::FinWait1
                | TcpState::LastAck
                | TcpState::Closing
        )
    }

    /// The next data and/or FIN segment the windows allow, its payload copied to `out`.
    ///
    /// Advances `snd_nxt` and arms the RTO; `None` when nothing may be sent now. A closed
    /// peer window with nothing in flight arms the persist timer instead.
    pub fn next_segment(
        &mut self,
        now: u64,
        out: &mut [u8; MAX_TCP_PAYLOAD],
    ) -> Option<(TcpSegment, usize)> {
        if !self.may_send() {
            return None;
        }
        let in_flight = self.snd_nxt.wrapping_sub(self.snd_una);
        let sent = (in_flight as usize).min(self.send_buf.filled());
        let unsent = self.send_buf.filled() - sent;
        let fin_pending = self.fin_seq.is_some_and(|fin| !seq_lt(fin, self.snd_nxt));
        if unsent == 0 && !fin_pending {
            return None;
        }
        let window = u32::from(self.peer_window).min(self.cwnd);
        let mut usable = window.saturating_sub(in_flight) as usize;
        if self.force_send {
            usable = usable.max(1);
        }
        let n = unsent.min(self.send_mss()).min(usable);
        if n == 0 && unsent > 0 {
            if self.peer_window == 0
                && self.snd_max == self.snd_una
                && self.persist_deadline.is_none()
            {
                self.persist_deadline = Some(now + self.rto);
            }
            return None;
        }
        let fin = fin_pending && n == unsent;
        self.force_send = false;
        let n = self.send_buf.peek_at(sent, &mut out[..n]);
        let seq = self.snd_nxt;
        let mut flags = TcpFlags::ACK;
        if n > 0 && n == unsent {
            flags = flags.union(TcpFlags::PSH);
        }
        let seg = self.build_segment(flags, seq, self.rcv_nxt, false, fin);
        self.snd_nxt = seq.wrapping_add(n as u32 + u32::from(fin));
        let new_data = seq_le(self.snd_max, seq);
        if seq_lt(self.snd_max, self.snd_nxt) {
            self.snd_max = self.snd_nxt;
        }
        if new_data && self.rtt_probe.is_none() {
            self.rtt_probe = Some((self.snd_nxt, now));
        }
        self.rto_deadline.get_or_insert(now + self.rto);
        self.persist_deadline = None;
        Some((seg, n))
    }

    /// The first unacknowledged segment again, for a fast retransmit. `snd_nxt` stays put.
    pub fn head_segment(&mut self, out: &mut [u8; MAX_TCP_PAYLOAD]) -> Option<(TcpSegment, usize)> {
        if !self.may_send() || self.snd_max == self.snd_una {
            return None;
        }
        let in_flight = self.snd_max.wrapping_sub(self.snd_una) as usize;
        let data_in_flight = in_flight.min(self.send_buf.filled());
        let n = data_in_flight.min(self.send_mss());
        let n = self.send_buf.peek_at(0, &mut out[..n]);
        let fin = self.fin_seq.is_some_and(|fin| {
            fin == self.snd_una.wrapping_add(n as u32) && seq_lt(fin, self.snd_max)
        });
        if n == 0 && !fin {
            return None;
        }
        let seg = self.build_segment(TcpFlags::ACK, self.snd_una, self.rcv_nxt, false, fin);
        Some((seg, n))
    }

    pub fn abort(&mut self) {
        self.state = TcpState::Reset;
        self.release_buffers();
    }
}

const fn initial_cwnd(mss: u32) -> u32 {
    // RFC 5681 §3.1: IW = min(4*SMSS, max(2*SMSS, 4380)).
    let floor = if 2 * mss > 4380 { 2 * mss } else { 4380 };
    if 4 * mss < floor {
        4 * mss
    } else {
        floor
    }
}

pub enum TimerAction {
    None,
    /// The RTO fired: resend (SYN, SYN-ACK, or data from `snd_una`).
    Retransmit,
    /// The persist timer fired: send [`TcpConnection::probe_segment`].
    Probe,
    Closed,
    Failed(NetworkError),
}

pub enum SegmentAction {
    None,
    SendAck,
    /// Resend our SYN-ACK (the peer retransmitted its SYN).
    SendSynAck,
    MaybeSendData,
    /// Fast retransmit of the segment at `snd_una`.
    Retransmit,
    Closed,
    Failed(NetworkError),
}

pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

pub fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

fn segment_len(seg: &TcpSegment, payload: &[u8]) -> u32 {
    payload.len() as u32
        + u32::from(seg.flags.contains(TcpFlags::SYN))
        + u32::from(seg.flags.contains(TcpFlags::FIN))
}

pub fn write_tcp_to_buf(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    seg: &TcpSegment,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, NetworkError> {
    write_segment(src_ip, dst_ip, seg, payload, out).map_err(|_| NetworkError::Protocol)
}

#[cfg(test)]
mod close_state_tests {
    use super::*;

    const ISS: u32 = 1_000;
    const IRS: u32 = 5_000;

    fn established() -> TcpConnection {
        let local = SocketAddrV4::new(Ipv4Addr::new([10, 0, 2, 15]), 50_000);
        let remote = SocketAddrV4::new(Ipv4Addr::new([10, 0, 2, 2]), 4001);
        let mut conn = TcpConnection::new(TrustedCaller::new(1, 1, 1), local, remote, ISS);
        let mut stats = TcpStats::default();
        let syn_ack = peer_segment(IRS, ISS + 1, TcpFlags::SYN.union(TcpFlags::ACK));
        assert!(matches!(
            conn.on_segment(&syn_ack, &[], 0, &mut stats),
            SegmentAction::SendAck
        ));
        assert_eq!(conn.state, TcpState::Established);
        conn
    }

    /// Mirrors `TcpTransport::close`: our FIN consumes one sequence number and stays in
    /// flight (retransmit armed) until the peer acknowledges it.
    fn send_our_fin(conn: &mut TcpConnection) {
        assert!(conn.start_close());
        let mut buf = [0u8; MAX_TCP_PAYLOAD];
        let (seg, n) = conn.next_segment(0, &mut buf).expect("FIN goes out");
        assert!(seg.flags.contains(TcpFlags::FIN));
        assert_eq!(n, 0);
    }

    fn peer_segment(seq: u32, ack: u32, flags: TcpFlags) -> TcpSegment {
        TcpSegment {
            src_port: 4001,
            dst_port: 50_000,
            seq,
            ack,
            data_offset: 5,
            flags,
            window: 4096,
            checksum: 0,
            urgent: 0,
            mss_option: None,
        }
    }

    fn fin_ack(seq: u32, ack: u32) -> TcpSegment {
        peer_segment(seq, ack, TcpFlags::FIN.union(TcpFlags::ACK))
    }

    #[test]
    fn simultaneous_close_goes_through_closing_to_time_wait() {
        let mut conn = established();
        let mut stats = TcpStats::default();
        send_our_fin(&mut conn);
        assert_eq!(conn.state, TcpState::FinWait1);

        // Peer FIN crosses ours: it does not yet acknowledge our FIN.
        let action = conn.on_segment(&fin_ack(IRS + 1, ISS + 1), &[], 0, &mut stats);
        assert!(matches!(action, SegmentAction::SendAck));
        assert_eq!(conn.state, TcpState::Closing);
        assert_eq!(conn.rcv_nxt, IRS + 2);

        let ack = peer_segment(IRS + 2, ISS + 2, TcpFlags::ACK);
        conn.on_segment(&ack, &[], 0, &mut stats);
        assert_eq!(conn.state, TcpState::TimeWait);
    }

    #[test]
    fn fin_acking_our_fin_in_fin_wait1_enters_time_wait() {
        let mut conn = established();
        let mut stats = TcpStats::default();
        send_our_fin(&mut conn);

        let action = conn.on_segment(&fin_ack(IRS + 1, ISS + 2), &[], 0, &mut stats);
        assert!(matches!(action, SegmentAction::SendAck));
        assert_eq!(conn.state, TcpState::TimeWait);
    }

    #[test]
    fn ack_of_our_fin_in_fin_wait1_enters_fin_wait2() {
        let mut conn = established();
        let mut stats = TcpStats::default();
        send_our_fin(&mut conn);

        let ack = peer_segment(IRS + 1, ISS + 2, TcpFlags::ACK);
        conn.on_segment(&ack, &[], 0, &mut stats);
        assert_eq!(conn.state, TcpState::FinWait2);
    }

    #[test]
    fn out_of_sequence_fin_in_fin_wait2_is_acknowledged_and_held() {
        let mut conn = established();
        let mut stats = TcpStats::default();
        send_our_fin(&mut conn);
        conn.on_segment(
            &peer_segment(IRS + 1, ISS + 2, TcpFlags::ACK),
            &[],
            0,
            &mut stats,
        );
        assert_eq!(conn.state, TcpState::FinWait2);

        let action = conn.on_segment(&fin_ack(IRS + 9, ISS + 2), &[], 0, &mut stats);
        assert!(matches!(action, SegmentAction::SendAck));
        assert_eq!(conn.state, TcpState::FinWait2);
        assert_eq!(conn.rcv_nxt, IRS + 1);

        let action = conn.on_segment(&fin_ack(IRS + 1, ISS + 2), &[], 0, &mut stats);
        assert!(matches!(action, SegmentAction::SendAck));
        assert_eq!(conn.state, TcpState::TimeWait);
    }

    #[test]
    fn retransmitted_fin_is_reacknowledged_in_closing() {
        let mut conn = established();
        let mut stats = TcpStats::default();
        send_our_fin(&mut conn);
        conn.on_segment(&fin_ack(IRS + 1, ISS + 1), &[], 0, &mut stats);
        assert_eq!(conn.state, TcpState::Closing);

        let action = conn.on_segment(&fin_ack(IRS + 1, ISS + 1), &[], 0, &mut stats);
        assert!(matches!(action, SegmentAction::SendAck));
        assert_eq!(conn.state, TcpState::Closing);
        assert_eq!(conn.rcv_nxt, IRS + 2);
    }

    #[test]
    fn retransmitted_fin_is_reacknowledged_in_time_wait() {
        let mut conn = established();
        let mut stats = TcpStats::default();
        send_our_fin(&mut conn);
        conn.on_segment(&fin_ack(IRS + 1, ISS + 2), &[], 0, &mut stats);
        assert_eq!(conn.state, TcpState::TimeWait);

        let action = conn.on_segment(&fin_ack(IRS + 1, ISS + 2), &[], 0, &mut stats);
        assert!(matches!(action, SegmentAction::SendAck));
        assert_eq!(conn.state, TcpState::TimeWait);
        assert_eq!(conn.rcv_nxt, IRS + 2);
    }

    #[test]
    fn retransmitted_fin_is_reacknowledged_in_last_ack() {
        let mut conn = established();
        let mut stats = TcpStats::default();
        conn.on_segment(&fin_ack(IRS + 1, ISS + 1), &[], 0, &mut stats);
        assert_eq!(conn.state, TcpState::CloseWait);
        send_our_fin(&mut conn);
        assert_eq!(conn.state, TcpState::LastAck);

        let action = conn.on_segment(&fin_ack(IRS + 1, ISS + 1), &[], 0, &mut stats);
        assert!(matches!(action, SegmentAction::SendAck));
        assert_eq!(conn.state, TcpState::LastAck);

        let ack = peer_segment(IRS + 2, ISS + 2, TcpFlags::ACK);
        assert!(matches!(
            conn.on_segment(&ack, &[], 0, &mut stats),
            SegmentAction::Closed
        ));
    }
}
