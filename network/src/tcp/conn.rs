//! Per-connection client state machine and bounded buffers.

use crate::addr::{Ipv4Addr, SocketAddrV4};
use crate::error::NetworkError;
use crate::protocol::TrustedCaller;
use crate::session::SessionGeneration;
use crate::tcp::segment::{
    write as write_segment, TcpFlags, TcpSegment, MAX_TCP_PAYLOAD, OUR_TCP_MSS,
};
use crate::tcp::state::TcpState;
use crate::tcp::stats::TcpStats;

/// Send buffer capacity (bytes queued by the application, not yet ACKed by peer).
pub const TCP_SEND_BUFFER_BYTES: usize = 4096;

/// Receive buffer capacity (in-order data waiting for `receive`.
pub const TCP_RECV_BUFFER_BYTES: usize = 4096;

/// Retransmission attempts before `NetworkError::Timeout`.
pub const TCP_MAX_RETRIES: u32 = 5;

/// Retransmission timeout (~50 ms at 1 ms LAPIC tick).
pub const TCP_RTO_TICKS: u64 = 50;

/// TIME-WAIT duration before a closed connection slot is reusable (~200 ms).
pub const TCP_TIME_WAIT_TICKS: u64 = 200;

/// Active-open timeout while waiting for SYN-ACK (~500 ms).
pub const TCP_CONNECT_TIMEOUT_TICKS: u64 = 500;

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
        let cap = self.free_space();
        let n = data.len().min(cap);
        for (i, &b) in data.iter().take(n).enumerate() {
            let idx = (self.head + self.len + i) % N;
            self.data[idx] = b;
        }
        self.len += n;
        n
    }

    pub fn pop(&mut self, out: &mut [u8]) -> usize {
        let n = out.len().min(self.len);
        for (i, byte) in out.iter_mut().enumerate().take(n) {
            *byte = self.data[(self.head + i) % N];
        }
        self.head = (self.head + n) % N;
        self.len -= n;
        n
    }
}

type SendRing = RingBuf<TCP_SEND_BUFFER_BYTES>;
type RecvRing = RingBuf<TCP_RECV_BUFFER_BYTES>;

#[derive(Clone, Debug)]
struct Unacked {
    active: bool,
    seq: u32,
    data_len: usize,
    syn: bool,
    fin: bool,
    data: [u8; MAX_TCP_PAYLOAD],
}

impl Unacked {
    const fn empty() -> Self {
        Self {
            active: false,
            seq: 0,
            data_len: 0,
            syn: false,
            fin: false,
            data: [0; MAX_TCP_PAYLOAD],
        }
    }
}

/// One client TCP connection.
pub struct TcpConnection {
    pub owner: TrustedCaller,
    pub local: SocketAddrV4,
    pub remote: SocketAddrV4,
    pub state: TcpState,
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub iss: u32,
    pub rcv_nxt: u32,
    pub irs: u32,
    pub peer_window: u16,
    pub peer_mss: u16,
    send_buf: SendRing,
    recv_buf: RecvRing,
    retransmit: Unacked,
    rto_deadline: Option<u64>,
    rto_retries: u32,
    time_wait_deadline: Option<u64>,
    connect_deadline: Option<u64>,
    pending_syn: bool,
    peer_fin_seen: bool,
    our_fin_sent: bool,
    failed: Option<NetworkError>,
}

impl TcpConnection {
    pub fn new(owner: TrustedCaller, local: SocketAddrV4, remote: SocketAddrV4, iss: u32) -> Self {
        Self {
            owner,
            local,
            remote,
            state: TcpState::SynSent,
            snd_una: iss,
            snd_nxt: iss,
            iss,
            rcv_nxt: 0,
            irs: 0,
            peer_window: OUR_TCP_MSS,
            peer_mss: OUR_TCP_MSS,
            send_buf: SendRing::new(),
            recv_buf: RecvRing::new(),
            retransmit: Unacked::empty(),
            rto_deadline: None,
            rto_retries: 0,
            time_wait_deadline: None,
            connect_deadline: None,
            pending_syn: true,
            peer_fin_seen: false,
            our_fin_sent: false,
            failed: None,
        }
    }

    pub fn advertised_window(&self) -> u16 {
        self.recv_buf.free_space().min(u16::MAX as usize) as u16
    }

    pub fn release_buffers(&mut self) {
        self.send_buf.clear();
        self.recv_buf.clear();
        self.retransmit = Unacked::empty();
        self.rto_deadline = None;
    }

    pub fn take_failure(&mut self) -> Option<NetworkError> {
        self.failed.take()
    }

    pub fn on_connect_start(&mut self, now: u64) {
        self.touch_connect_deadline(now);
        self.pending_syn = true;
    }

    pub fn touch_connect_deadline(&mut self, now: u64) {
        self.connect_deadline = Some(now + TCP_CONNECT_TIMEOUT_TICKS);
    }

    pub fn tick_timers(&mut self, now: u64, stats: &mut TcpStats) -> TimerAction {
        if let Some(err) = self.failed {
            return TimerAction::Failed(err);
        }
        if self.state == TcpState::TimeWait {
            // Every path into TIME-WAIT must eventually free the slot. Some
            // transitions (e.g. CLOSING -> TIME-WAIT, or the ACK of our FIN in
            // FIN-WAIT-1) happen inside `on_segment` without a timestamp, so arm
            // the deadline here on first observation if it is still unset.
            let deadline = *self
                .time_wait_deadline
                .get_or_insert(now + TCP_TIME_WAIT_TICKS);
            if now >= deadline {
                self.state = TcpState::Closed;
                self.release_buffers();
                return TimerAction::Closed;
            }
        }
        if self.state == TcpState::SynSent {
            if let Some(dl) = self.connect_deadline {
                if now >= dl {
                    self.state = TcpState::Reset;
                    self.release_buffers();
                    stats.timeouts += 1;
                    self.failed = Some(NetworkError::Timeout);
                    return TimerAction::Failed(NetworkError::Timeout);
                }
            }
        }
        if self.retransmit.active {
            if let Some(dl) = self.rto_deadline {
                if now >= dl {
                    if self.state != TcpState::SynSent && self.rto_retries >= TCP_MAX_RETRIES {
                        self.state = TcpState::Reset;
                        self.release_buffers();
                        stats.timeouts += 1;
                        self.failed = Some(NetworkError::Timeout);
                        return TimerAction::Failed(NetworkError::Timeout);
                    }
                    if self.state != TcpState::SynSent {
                        self.rto_retries += 1;
                    }
                    stats.retransmits += 1;
                    self.rto_deadline = Some(now + TCP_RTO_TICKS);
                    return TimerAction::Retransmit;
                }
            }
        }
        TimerAction::None
    }

    /// Earliest tick at which [`Self::tick_timers`] has work, or `None` when no timer is armed.
    ///
    /// An unarmed TIME-WAIT reports `Some(0)` (due now) so the next poll arms it.
    pub fn next_timer_deadline(&self) -> Option<u64> {
        if self.failed.is_some() {
            return None;
        }
        let mut next: Option<u64> = None;
        let mut consider = |dl: u64| next = Some(next.map_or(dl, |n| n.min(dl)));
        if self.state == TcpState::TimeWait {
            consider(self.time_wait_deadline.unwrap_or(0));
        }
        if self.state == TcpState::SynSent {
            if let Some(dl) = self.connect_deadline {
                consider(dl);
            }
        }
        if self.retransmit.active {
            if let Some(dl) = self.rto_deadline {
                consider(dl);
            }
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
        self.retransmit.active
    }

    pub fn on_segment(
        &mut self,
        seg: &TcpSegment,
        payload: &[u8],
        stats: &mut TcpStats,
    ) -> SegmentAction {
        if let Some(err) = self.failed {
            return SegmentAction::Failed(err);
        }

        if seg.flags.contains(TcpFlags::RST) {
            // RFC 793 §3.4: in SYN-SENT a RST is acceptable only if it ACKs our
            // SYN; in every other synchronized state it must carry the exact
            // next expected sequence number. Anything else is a blind RST and
            // is dropped, so an off-path peer cannot tear down sessions.
            let acceptable = if self.state == TcpState::SynSent {
                seg.flags.contains(TcpFlags::ACK) && seg.ack == self.iss.wrapping_add(1)
            } else {
                seq_acceptable(seg.seq, self.rcv_nxt)
            };
            if acceptable {
                stats.resets_received += 1;
                self.state = TcpState::Reset;
                self.release_buffers();
                self.failed = Some(NetworkError::Reset);
                return SegmentAction::Failed(NetworkError::Reset);
            }
            stats.dropped_out_of_order += 1;
            return SegmentAction::None;
        }

        match self.state {
            TcpState::SynSent => self.on_syn_sent(seg, payload, stats),
            TcpState::Established => self.on_established(seg, payload, stats),
            TcpState::FinWait1 => self.on_fin_wait1(seg, payload, stats),
            TcpState::FinWait2 => self.on_fin_wait2(seg, payload, stats),
            TcpState::Closing => self.on_closing(seg, payload, stats),
            TcpState::LastAck => self.on_last_ack(seg, payload, stats),
            TcpState::TimeWait => self.on_time_wait(seg, payload, stats),
            TcpState::CloseWait => self.on_close_wait(seg, payload, stats),
            _ => SegmentAction::None,
        }
    }

    fn on_syn_sent(
        &mut self,
        seg: &TcpSegment,
        payload: &[u8],
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
        self.retransmit.active = false;
        self.rto_deadline = None;
        self.rto_retries = 0;
        self.irs = seg.seq;
        self.rcv_nxt = seg.seq.wrapping_add(1);
        if let Some(mss) = seg.mss_option {
            self.peer_mss = mss.min(OUR_TCP_MSS);
        }
        self.peer_window = seg.window;
        self.snd_una = self.iss.wrapping_add(1);
        self.snd_nxt = self.iss.wrapping_add(1);
        self.state = TcpState::Established;
        self.connect_deadline = None;
        // Data piggybacked on the SYN-ACK starts at IRS+1 == rcv_nxt (RFC 793 §3.9).
        let take = payload.len().min(self.recv_buf.free_space());
        self.recv_buf.push(payload.get(..take).unwrap_or(&[]));
        self.rcv_nxt = self.rcv_nxt.wrapping_add(take as u32);
        SegmentAction::SendAck
    }

    fn on_established(
        &mut self,
        seg: &TcpSegment,
        payload: &[u8],
        stats: &mut TcpStats,
    ) -> SegmentAction {
        let mut action = SegmentAction::None;
        if seg.flags.contains(TcpFlags::ACK) {
            if !ack_valid(seg.ack, self.snd_una, self.snd_nxt) {
                stats.dropped_bad_ack += 1;
            } else {
                self.apply_ack(seg.ack);
            }
        }
        self.peer_window = seg.window;

        if self.is_unacceptable(seg, payload, stats) {
            action = SegmentAction::SendAck;
        } else if occupies_sequence_space(seg, payload) {
            let mut consume = payload.len();
            if seg.flags.contains(TcpFlags::SYN) {
                consume += 1;
            }
            let room = self.recv_buf.free_space();
            let accept = consume.min(room);
            if accept > payload.len() {
                // SYN bit consumes sequence space without payload bytes here.
            }
            let data_take = accept.min(payload.len());
            self.recv_buf.push(payload.get(..data_take).unwrap_or(&[]));
            self.rcv_nxt = self.rcv_nxt.wrapping_add(data_take as u32);
            if seg.flags.contains(TcpFlags::SYN) {
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            }
            if seg.flags.contains(TcpFlags::FIN) {
                self.peer_fin_seen = true;
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                self.state = TcpState::CloseWait;
            }
            action = SegmentAction::SendAck;
        } else if seg.flags.contains(TcpFlags::ACK)
            && ack_valid(seg.ack, self.snd_una, self.snd_nxt)
        {
            action = SegmentAction::MaybeSendData;
        }
        // Accepted or unacceptable sequence space must be acknowledged even while our
        // own data is in flight; queued data is sent by the transport's per-poll pass.
        action
    }

    fn on_fin_wait1(
        &mut self,
        seg: &TcpSegment,
        payload: &[u8],
        stats: &mut TcpStats,
    ) -> SegmentAction {
        // `on_established` applies the ACK, accepts data, and consumes an in-order FIN
        // (leaving CLOSE-WAIT behind); the FIN-WAIT-1 successor state is decided here
        // from what has now been exchanged (RFC 793 §3.9).
        let action = self.on_established(seg, payload, stats);
        let our_fin_acked = self.our_fin_sent && self.snd_una == self.snd_nxt;
        self.state = match (self.peer_fin_seen, our_fin_acked) {
            (true, true) => TcpState::TimeWait,
            (true, false) => TcpState::Closing,
            (false, true) => TcpState::FinWait2,
            (false, false) => TcpState::FinWait1,
        };
        action
    }

    fn on_fin_wait2(
        &mut self,
        seg: &TcpSegment,
        payload: &[u8],
        stats: &mut TcpStats,
    ) -> SegmentAction {
        if seg.flags.contains(TcpFlags::ACK) && ack_valid(seg.ack, self.snd_una, self.snd_nxt) {
            self.apply_ack(seg.ack);
        }
        if self.is_unacceptable(seg, payload, stats) {
            return SegmentAction::SendAck;
        }
        if !payload.is_empty() {
            let take = payload.len().min(self.recv_buf.free_space());
            self.recv_buf.push(payload.get(..take).unwrap_or(&[]));
            self.rcv_nxt = self.rcv_nxt.wrapping_add(take as u32);
            return SegmentAction::SendAck;
        }
        if seg.flags.contains(TcpFlags::FIN) {
            self.peer_fin_seen = true;
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            self.state = TcpState::TimeWait;
            return SegmentAction::SendAck;
        }
        SegmentAction::None
    }

    fn on_closing(
        &mut self,
        seg: &TcpSegment,
        payload: &[u8],
        stats: &mut TcpStats,
    ) -> SegmentAction {
        if seg.flags.contains(TcpFlags::ACK) && ack_valid(seg.ack, self.snd_una, self.snd_nxt) {
            self.apply_ack(seg.ack);
            if self.snd_una == self.snd_nxt {
                self.state = TcpState::TimeWait;
            }
        }
        if self.is_unacceptable(seg, payload, stats) {
            return SegmentAction::SendAck;
        }
        SegmentAction::None
    }

    fn on_time_wait(
        &mut self,
        seg: &TcpSegment,
        payload: &[u8],
        stats: &mut TcpStats,
    ) -> SegmentAction {
        // Everything the peer may send here was already consumed, so any segment that
        // occupies sequence space is unacceptable. The transport restarts the 2MSL timer
        // when TIME-WAIT answers with an ACK.
        if self.is_unacceptable(seg, payload, stats) {
            return SegmentAction::SendAck;
        }
        SegmentAction::None
    }

    /// RFC 793 §3.9: a segment occupying sequence space that does not start at `rcv_nxt`
    /// is unacceptable. It is dropped (and counted) and must be answered with an ACK so a
    /// peer whose earlier ACK was lost stops retransmitting, in every synchronized state.
    fn is_unacceptable(&self, seg: &TcpSegment, payload: &[u8], stats: &mut TcpStats) -> bool {
        if occupies_sequence_space(seg, payload) && seg.seq != self.rcv_nxt {
            stats.dropped_out_of_order += 1;
            return true;
        }
        false
    }

    fn on_last_ack(
        &mut self,
        seg: &TcpSegment,
        payload: &[u8],
        stats: &mut TcpStats,
    ) -> SegmentAction {
        if seg.flags.contains(TcpFlags::ACK) && seg.ack == self.snd_nxt {
            self.state = TcpState::Closed;
            self.release_buffers();
            return SegmentAction::Closed;
        }
        if self.is_unacceptable(seg, payload, stats) {
            return SegmentAction::SendAck;
        }
        if seg.flags.contains(TcpFlags::ACK) {
            stats.dropped_bad_ack += 1;
        }
        SegmentAction::None
    }

    fn on_close_wait(
        &mut self,
        seg: &TcpSegment,
        payload: &[u8],
        stats: &mut TcpStats,
    ) -> SegmentAction {
        if seg.flags.contains(TcpFlags::ACK) && ack_valid(seg.ack, self.snd_una, self.snd_nxt) {
            self.apply_ack(seg.ack);
        }
        if self.is_unacceptable(seg, payload, stats) {
            return SegmentAction::SendAck;
        }
        if !payload.is_empty() {
            let take = payload.len().min(self.recv_buf.free_space());
            self.recv_buf.push(payload.get(..take).unwrap_or(&[]));
            self.rcv_nxt = self.rcv_nxt.wrapping_add(take as u32);
            return SegmentAction::SendAck;
        }
        SegmentAction::MaybeSendData
    }

    fn apply_ack(&mut self, ack: u32) {
        if seq_le(self.snd_una, ack) && seq_le(ack, self.snd_nxt) {
            self.snd_una = ack;
            if self.snd_una == self.snd_nxt {
                self.retransmit.active = false;
                self.rto_deadline = None;
                self.rto_retries = 0;
            }
        }
    }

    pub fn queue_send(&mut self, data: &[u8]) -> Result<usize, NetworkError> {
        if self.state.is_terminal() || self.state == TcpState::Reset {
            return Err(NetworkError::Closed);
        }
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
        if n == 0 && self.peer_fin_seen && self.recv_buf.is_empty() {
            return Err(NetworkError::Closed);
        }
        Ok(n)
    }

    pub fn start_close(&mut self) -> bool {
        if self.state == TcpState::Established {
            self.state = TcpState::FinWait1;
            self.our_fin_sent = true;
            return true;
        }
        if self.state == TcpState::CloseWait {
            self.state = TcpState::LastAck;
            self.our_fin_sent = true;
            return true;
        }
        false
    }

    pub fn enter_time_wait(&mut self, now: u64) {
        self.state = TcpState::TimeWait;
        self.time_wait_deadline = Some(now + TCP_TIME_WAIT_TICKS);
    }

    pub fn build_segment(
        &self,
        flags: TcpFlags,
        seq: u32,
        ack: u32,
        _payload: &[u8],
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
        TcpSegment {
            src_port: self.local.port,
            dst_port: self.remote.port,
            seq,
            ack,
            data_offset: if syn { 6 } else { 5 },
            flags: f,
            window: self.advertised_window(),
            checksum: 0,
            urgent: 0,
            mss_option: if syn { Some(OUR_TCP_MSS) } else { None },
        }
    }

    pub fn record_unacked(&mut self, seq: u32, payload: &[u8], syn: bool, fin: bool, now: u64) {
        self.retransmit.active = true;
        self.retransmit.seq = seq;
        self.retransmit.data_len = payload.len();
        self.retransmit.syn = syn;
        self.retransmit.fin = fin;
        self.retransmit.data[..payload.len()].copy_from_slice(payload);
        self.rto_deadline = Some(now + TCP_RTO_TICKS);
    }

    pub fn unacked_for_retransmit(&self) -> Option<(TcpSegment, &[u8])> {
        if !self.retransmit.active {
            return None;
        }
        let flags = if self.retransmit.syn {
            TcpFlags::SYN
        } else {
            TcpFlags::ACK.union(if self.retransmit.fin {
                TcpFlags::FIN
            } else {
                TcpFlags::default()
            })
        };
        let seg = self.build_segment(
            flags,
            self.retransmit.seq,
            self.rcv_nxt,
            &self.retransmit.data[..self.retransmit.data_len],
            self.retransmit.syn,
            self.retransmit.fin,
        );
        Some((seg, &self.retransmit.data[..self.retransmit.data_len]))
    }

    pub fn send_buf_has_data(&self) -> bool {
        !self.send_buf.is_empty()
    }

    pub fn pop_send_chunk(&mut self, max_len: usize) -> (usize, [u8; MAX_TCP_PAYLOAD]) {
        let mut tmp = [0u8; MAX_TCP_PAYLOAD];
        let mut out = [0u8; MAX_TCP_PAYLOAD];
        let n = self.send_buf.pop(&mut tmp[..max_len.min(MAX_TCP_PAYLOAD)]);
        out[..n].copy_from_slice(&tmp[..n]);
        (n, out)
    }

    pub fn abort(&mut self) {
        self.state = TcpState::Reset;
        self.release_buffers();
    }
}

pub enum TimerAction {
    None,
    Retransmit,
    Closed,
    Failed(NetworkError),
}

pub enum SegmentAction {
    None,
    SendAck,
    MaybeSendData,
    Closed,
    Failed(NetworkError),
}

/// Deterministic initial sequence number from service generation, slot index, and a counter.
pub fn deterministic_iss(generation: SessionGeneration, index: u32, counter: u64) -> u32 {
    let g = generation.get() as u32;
    let c = counter as u32;
    g ^ (index.wrapping_mul(0x9E37_79B9)) ^ c.wrapping_mul(0x85EB_CA6B)
}

pub fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

pub fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

fn ack_valid(ack: u32, snd_una: u32, snd_nxt: u32) -> bool {
    seq_le(snd_una, ack) && seq_le(ack, snd_nxt)
}

fn occupies_sequence_space(seg: &TcpSegment, payload: &[u8]) -> bool {
    !payload.is_empty() || seg.flags.contains(TcpFlags::SYN) || seg.flags.contains(TcpFlags::FIN)
}

fn seq_acceptable(seq: u32, rcv_nxt: u32) -> bool {
    seq == rcv_nxt
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
            conn.on_segment(&syn_ack, &[], &mut stats),
            SegmentAction::SendAck
        ));
        assert_eq!(conn.state, TcpState::Established);
        conn
    }

    /// Mirrors `TcpTransport::send_fin_at`: our FIN consumes one sequence number and
    /// stays in flight (retransmit armed) until the peer acknowledges it.
    fn send_our_fin(conn: &mut TcpConnection) {
        assert!(conn.start_close());
        let seq = conn.snd_nxt;
        conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
        conn.record_unacked(seq, &[], false, true, 0);
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
        let action = conn.on_segment(&fin_ack(IRS + 1, ISS + 1), &[], &mut stats);
        assert!(matches!(action, SegmentAction::SendAck));
        assert_eq!(conn.state, TcpState::Closing);
        assert_eq!(conn.rcv_nxt, IRS + 2);

        let ack = peer_segment(IRS + 2, ISS + 2, TcpFlags::ACK);
        conn.on_segment(&ack, &[], &mut stats);
        assert_eq!(conn.state, TcpState::TimeWait);
    }

    #[test]
    fn fin_acking_our_fin_in_fin_wait1_enters_time_wait() {
        let mut conn = established();
        let mut stats = TcpStats::default();
        send_our_fin(&mut conn);

        let action = conn.on_segment(&fin_ack(IRS + 1, ISS + 2), &[], &mut stats);
        assert!(matches!(action, SegmentAction::SendAck));
        assert_eq!(conn.state, TcpState::TimeWait);
    }

    #[test]
    fn ack_of_our_fin_in_fin_wait1_enters_fin_wait2() {
        let mut conn = established();
        let mut stats = TcpStats::default();
        send_our_fin(&mut conn);

        let ack = peer_segment(IRS + 1, ISS + 2, TcpFlags::ACK);
        conn.on_segment(&ack, &[], &mut stats);
        assert_eq!(conn.state, TcpState::FinWait2);
    }

    #[test]
    fn out_of_sequence_fin_in_fin_wait2_is_acknowledged_not_consumed() {
        let mut conn = established();
        let mut stats = TcpStats::default();
        send_our_fin(&mut conn);
        conn.on_segment(
            &peer_segment(IRS + 1, ISS + 2, TcpFlags::ACK),
            &[],
            &mut stats,
        );
        assert_eq!(conn.state, TcpState::FinWait2);

        let action = conn.on_segment(&fin_ack(IRS + 9, ISS + 2), &[], &mut stats);
        assert!(matches!(action, SegmentAction::SendAck));
        assert_eq!(conn.state, TcpState::FinWait2);
        assert_eq!(conn.rcv_nxt, IRS + 1);
        assert_eq!(stats.dropped_out_of_order, 1);

        let action = conn.on_segment(&fin_ack(IRS + 1, ISS + 2), &[], &mut stats);
        assert!(matches!(action, SegmentAction::SendAck));
        assert_eq!(conn.state, TcpState::TimeWait);
    }

    #[test]
    fn retransmitted_fin_is_reacknowledged_in_closing() {
        let mut conn = established();
        let mut stats = TcpStats::default();
        send_our_fin(&mut conn);
        conn.on_segment(&fin_ack(IRS + 1, ISS + 1), &[], &mut stats);
        assert_eq!(conn.state, TcpState::Closing);

        let action = conn.on_segment(&fin_ack(IRS + 1, ISS + 1), &[], &mut stats);
        assert!(matches!(action, SegmentAction::SendAck));
        assert_eq!(conn.state, TcpState::Closing);
        assert_eq!(conn.rcv_nxt, IRS + 2);
    }

    #[test]
    fn retransmitted_fin_is_reacknowledged_in_time_wait() {
        let mut conn = established();
        let mut stats = TcpStats::default();
        send_our_fin(&mut conn);
        conn.on_segment(&fin_ack(IRS + 1, ISS + 2), &[], &mut stats);
        assert_eq!(conn.state, TcpState::TimeWait);

        let action = conn.on_segment(&fin_ack(IRS + 1, ISS + 2), &[], &mut stats);
        assert!(matches!(action, SegmentAction::SendAck));
        assert_eq!(conn.state, TcpState::TimeWait);
        assert_eq!(conn.rcv_nxt, IRS + 2);
    }

    #[test]
    fn retransmitted_fin_is_reacknowledged_in_last_ack() {
        let mut conn = established();
        let mut stats = TcpStats::default();
        conn.on_segment(&fin_ack(IRS + 1, ISS + 1), &[], &mut stats);
        assert_eq!(conn.state, TcpState::CloseWait);
        send_our_fin(&mut conn);
        assert_eq!(conn.state, TcpState::LastAck);

        let action = conn.on_segment(&fin_ack(IRS + 1, ISS + 1), &[], &mut stats);
        assert!(matches!(action, SegmentAction::SendAck));
        assert_eq!(conn.state, TcpState::LastAck);

        let ack = peer_segment(IRS + 2, ISS + 2, TcpFlags::ACK);
        assert!(matches!(
            conn.on_segment(&ack, &[], &mut stats),
            SegmentAction::Closed
        ));
    }
}
