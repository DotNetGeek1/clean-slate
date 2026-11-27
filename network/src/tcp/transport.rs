//! Connection table and [`TcpTransport`] over [`L3Stack`].

#[cfg(feature = "alloc")]
extern crate alloc;

use crate::addr::{IpProtocol, Ipv4Addr, SocketAddrV4};
use crate::device::NetworkLink;
use crate::error::{DenialReason, NetworkError};
use crate::limits::MAX_TCP_CONNECTIONS;
use crate::protocol::TrustedCaller;
use crate::rng::{IssKey, NetRng};
use crate::session::{SessionGeneration, SessionId};
use crate::stack::{self, L3Stack};
use crate::tcp::conn::{write_tcp_to_buf, SegmentAction, TcpConnection, TcpTimers, TimerAction};
use crate::tcp::segment::{parse as parse_tcp, TcpFlags, TcpSegment, MAX_TCP_PAYLOAD};
use crate::tcp::state::TcpState;
use crate::tcp::stats::TcpStats;

/// Max inbound frames one [`TcpTransport::poll`] processes (one device RX queue's worth).
pub const TCP_POLL_RX_BUDGET: usize = crate::limits::MAX_DEVICE_RX_QUEUE_DEPTH as usize;

/// Listening ports per transport.
pub const MAX_TCP_LISTENERS: usize = 4;

/// Connections a listener holds that the application has not accepted yet (half-open
/// SYN-RECEIVED ones included), so a SYN flood cannot take the whole table.
pub const TCP_LISTEN_BACKLOG: usize = 4;

/// Most segments one send pass puts on the wire for a connection.
const TCP_SEND_BURST: usize = 8;

/// A listening port, from [`TcpTransport::listen`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenerId(SessionId);

impl ListenerId {
    pub const fn from_raw(raw: u64) -> Self {
        Self(SessionId::from_raw(raw))
    }

    pub const fn raw(self) -> u64 {
        self.0.raw()
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Listener {
    owner: TrustedCaller,
    port: u16,
}

/// Fixed-size connection table keyed by [`SessionId`] index.
pub struct TcpTable {
    generation: SessionGeneration,
    pub(crate) slots: [Option<TcpConnection>; MAX_TCP_CONNECTIONS as usize],
    listeners: [Option<Listener>; MAX_TCP_LISTENERS],
    timers: TcpTimers,
    established_counter: u64,
    /// Ephemeral ports.
    rng: NetRng,
    /// RFC 6528 initial sequence numbers.
    iss_key: IssKey,
}

impl TcpTable {
    /// Initializes a zeroed [`TcpTable`] (static or heap-backed storage).
    pub fn init_in_place(&mut self, generation: SessionGeneration, mut rng: NetRng) {
        self.generation = generation;
        self.iss_key = IssKey::new(&mut rng);
        self.rng = rng;
        self.timers = TcpTimers::DEFAULT;
        self.established_counter = 0;
        for slot in self.slots.iter_mut() {
            *slot = None;
        }
        self.listeners = [None; MAX_TCP_LISTENERS];
    }

    pub fn new(generation: SessionGeneration, mut rng: NetRng) -> Self {
        Self {
            generation,
            slots: [const { None }; MAX_TCP_CONNECTIONS as usize],
            listeners: [None; MAX_TCP_LISTENERS],
            timers: TcpTimers::DEFAULT,
            established_counter: 0,
            iss_key: IssKey::new(&mut rng),
            rng,
        }
    }

    pub fn generation(&self) -> SessionGeneration {
        self.generation
    }

    pub fn connections_in_use(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    fn alloc_slot(
        &mut self,
        now: u64,
        owner: TrustedCaller,
        remote: SocketAddrV4,
        our_ip: Ipv4Addr,
    ) -> Result<usize, NetworkError> {
        let index = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(NetworkError::SessionExhausted)?;
        let slots = &self.slots;
        let listeners = &self.listeners;
        let port = self
            .rng
            .ephemeral_port(|port| {
                slots.iter().flatten().any(|c| c.local.port == port)
                    || listeners.iter().flatten().any(|l| l.port == port)
            })
            .ok_or(NetworkError::SessionExhausted)?;
        let local = SocketAddrV4::new(our_ip, port);
        let iss = self.iss_key.iss(local, remote, now);
        self.slots[index] = Some(TcpConnection::with_timers(
            owner,
            local,
            remote,
            iss,
            self.timers,
        ));
        Ok(index)
    }

    /// A SYN reached listener `listener`: a SYN-RECEIVED slot, if the backlog has room.
    fn alloc_passive_slot(
        &mut self,
        now: u64,
        listener: usize,
        local: SocketAddrV4,
        remote: SocketAddrV4,
        syn: &TcpSegment,
    ) -> Option<usize> {
        let owner = self.listeners.get(listener)?.as_ref()?.owner;
        let waiting = self
            .slots
            .iter()
            .flatten()
            .filter(|c| c.listener == Some(listener as u8) && !c.accepted)
            .count();
        if waiting >= TCP_LISTEN_BACKLOG {
            return None;
        }
        let index = self.slots.iter().position(Option::is_none)?;
        let iss = self.iss_key.iss(local, remote, now);
        self.slots[index] = Some(TcpConnection::new_passive(
            owner,
            local,
            remote,
            iss,
            syn,
            listener as u8,
            self.timers,
        ));
        Some(index)
    }

    fn listener_for_port(&self, port: u16) -> Option<usize> {
        self.listeners
            .iter()
            .position(|l| l.is_some_and(|l| l.port == port))
    }

    fn check_listener(&self, id: ListenerId, owner: TrustedCaller) -> Result<usize, NetworkError> {
        if !id.0.matches_generation(self.generation) {
            return Err(NetworkError::Denied(DenialReason::StaleGeneration));
        }
        let index = id.0.index() as usize;
        let listener = self
            .listeners
            .get(index)
            .and_then(|l| l.as_ref())
            .ok_or(NetworkError::NotFound)?;
        if listener.owner != owner {
            return Err(NetworkError::Denied(DenialReason::NoCapability));
        }
        Ok(index)
    }

    fn check_id(&self, id: SessionId, owner: TrustedCaller) -> Result<usize, NetworkError> {
        if !id.matches_generation(self.generation) {
            return Err(NetworkError::Denied(DenialReason::StaleGeneration));
        }
        let index = id.index() as usize;
        if index >= self.slots.len() {
            return Err(NetworkError::NotFound);
        }
        let slot = self.slots[index].as_ref().ok_or(NetworkError::NotFound)?;
        if slot.listener.is_some() && !slot.accepted {
            // Not handed out by `accept` yet: nobody holds this id.
            return Err(NetworkError::NotFound);
        }
        if slot.owner != owner {
            return Err(NetworkError::Denied(DenialReason::NoCapability));
        }
        Ok(index)
    }

    pub fn get_mut(
        &mut self,
        id: SessionId,
        owner: TrustedCaller,
    ) -> Result<&mut TcpConnection, NetworkError> {
        let index = self.check_id(id, owner)?;
        self.slots[index].as_mut().ok_or(NetworkError::NotFound)
    }

    pub fn get(&self, id: SessionId, owner: TrustedCaller) -> Result<&TcpConnection, NetworkError> {
        let index = self.check_id(id, owner)?;
        self.slots[index].as_ref().ok_or(NetworkError::NotFound)
    }

    pub fn free_slot(&mut self, index: usize) {
        if index < self.slots.len() {
            self.slots[index] = None;
        }
    }

    pub fn find_by_quad(&mut self, local_port: u16, remote: SocketAddrV4) -> Option<usize> {
        for (i, slot) in self.slots.iter().enumerate() {
            if let Some(c) = slot {
                if c.local.port == local_port && c.remote == remote {
                    return Some(i);
                }
            }
        }
        None
    }

    pub fn abort_all_owned_by(&mut self, owner: TrustedCaller) -> usize {
        let mut n = 0;
        for slot in self.slots.iter_mut() {
            if let Some(conn) = slot {
                if conn.owner == owner {
                    conn.abort();
                    *slot = None;
                    n += 1;
                }
            }
        }
        n
    }

    pub fn clear_all(&mut self) {
        for slot in self.slots.iter_mut() {
            *slot = None;
        }
        self.listeners = [None; MAX_TCP_LISTENERS];
    }

    pub fn listeners_in_use(&self) -> usize {
        self.listeners.iter().filter(|l| l.is_some()).count()
    }
}

/// Client TCP transport: bounded table + L3 transmit/receive.
///
/// The table holds up to [`MAX_TCP_CONNECTIONS`] connections (~9.7 KiB each in `no_std`).
/// Do not construct this type on small boot stacks; use zeroed static storage and
/// [`TcpTransport::init_in_place`].
pub struct TcpTransport<L: NetworkLink> {
    stack: L3Stack<L>,
    table: TcpTable,
    stats: TcpStats,
}

impl<L: NetworkLink> TcpTransport<L> {
    /// # Safety
    ///
    /// `slot` must point to valid, aligned storage (typically `MaybeUninit::zeroed()` static).
    /// No other references to `*slot` may exist until initialization completes.
    pub unsafe fn init_in_place(
        slot: *mut Self,
        stack: L3Stack<L>,
        generation: SessionGeneration,
        rng: NetRng,
    ) {
        unsafe {
            (*slot).stack = stack;
            (*slot).table.init_in_place(generation, rng);
            (*slot).stats = TcpStats::default();
        }
    }

    pub fn new(stack: L3Stack<L>, generation: SessionGeneration, rng: NetRng) -> Self {
        Self {
            stack,
            table: TcpTable::new(generation, rng),
            stats: TcpStats::default(),
        }
    }

    /// Heap-backed transport for host tests (avoids multi-hundred-KiB stack frames).
    #[cfg(feature = "alloc")]
    pub fn alloc_boxed(
        stack: L3Stack<L>,
        generation: SessionGeneration,
        rng: NetRng,
    ) -> alloc::boxed::Box<Self> {
        let layout = core::alloc::Layout::new::<Self>();
        let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) as *mut Self };
        if ptr.is_null() {
            alloc::alloc::handle_alloc_error(layout);
        }
        unsafe {
            core::ptr::write(&mut (*ptr).stack, stack);
            (*ptr).table.init_in_place(generation, rng);
            (*ptr).stats = TcpStats::default();
            alloc::boxed::Box::from_raw(ptr)
        }
    }

    /// An independent generator keyed from this transport's, for the TLS transaction that
    /// rides on it.
    pub fn fork_rng(&mut self) -> NetRng {
        self.table.rng.fork()
    }

    /// The length of one `now` tick, for the ISS clock (see [`IssKey::set_tick_period_ns`]).
    /// Also sets the TCP timers (RTO bounds, TIME-WAIT, connect timeout) for new connections.
    pub fn set_tick_period_ns(&mut self, tick_period_ns: u64) {
        self.table.iss_key.set_tick_period_ns(tick_period_ns);
        self.table.timers = TcpTimers::from_tick_period_ns(tick_period_ns);
    }

    pub fn stack(&self) -> &L3Stack<L> {
        &self.stack
    }

    pub fn stack_mut(&mut self) -> &mut L3Stack<L> {
        &mut self.stack
    }

    pub fn table(&self) -> &TcpTable {
        &self.table
    }

    pub fn table_mut(&mut self) -> &mut TcpTable {
        &mut self.table
    }

    pub fn stats(&self) -> TcpStats {
        self.stats
    }

    pub fn connections_in_use(&self) -> usize {
        self.table.connections_in_use()
    }

    pub fn into_parts(self) -> (L3Stack<L>, TcpTable, TcpStats) {
        (self.stack, self.table, self.stats)
    }

    pub fn reset(&mut self, now: u64) -> Result<(), NetworkError> {
        for i in 0..self.table.slots.len() {
            let terminal = self.table.slots[i]
                .as_ref()
                .map(|c| c.state.is_terminal())
                .unwrap_or(true);
            if !terminal {
                self.send_rst_at(now, i)?;
                self.stats.resets_sent += 1;
            }
        }
        self.table.clear_all();
        self.stats = TcpStats::default();
        self.stack.reset()?;
        Ok(())
    }

    /// Active open: allocates a slot and sends SYN (or defers on ARP miss).
    pub fn connect(
        &mut self,
        now: u64,
        owner: TrustedCaller,
        remote: SocketAddrV4,
    ) -> Result<SessionId, NetworkError> {
        let our_ip = self.stack.our_ip();
        let index = self.table.alloc_slot(now, owner, remote, our_ip)?;
        let id = SessionId::new(self.table.generation, index as u32);
        self.table.slots[index]
            .as_mut()
            .unwrap()
            .on_connect_start(now);
        if let Err(NetworkError::Unreachable) = self.send_syn_at(now, index) {
            self.table.slots[index].as_mut().unwrap().on_unreachable();
        } else {
            self.table.slots[index]
                .as_mut()
                .unwrap()
                .clear_pending_syn();
        }
        Ok(id)
    }

    pub fn state(&self, id: SessionId, owner: TrustedCaller) -> Result<TcpState, NetworkError> {
        Ok(self.table.get(id, owner)?.state)
    }

    pub fn send(
        &mut self,
        now: u64,
        id: SessionId,
        owner: TrustedCaller,
        data: &[u8],
    ) -> Result<usize, NetworkError> {
        let index = self.table.check_id(id, owner)?;
        let conn = self.table.slots[index]
            .as_mut()
            .ok_or(NetworkError::NotFound)?;
        if conn.state == TcpState::Reset {
            return Err(NetworkError::Reset);
        }
        if conn.state.is_terminal() {
            return Err(NetworkError::Closed);
        }
        let written = conn.queue_send(data)?;
        self.try_send_data_at(now, index)?;
        Ok(written)
    }

    pub fn receive(
        &mut self,
        id: SessionId,
        owner: TrustedCaller,
        out: &mut [u8],
    ) -> Result<usize, NetworkError> {
        let conn = self.table.get_mut(id, owner)?;
        conn.receive(out)
    }

    pub fn close(
        &mut self,
        now: u64,
        id: SessionId,
        owner: TrustedCaller,
    ) -> Result<(), NetworkError> {
        let index = self.table.check_id(id, owner)?;
        let start = self.table.slots[index].as_mut().unwrap().start_close();
        if start {
            // The FIN follows any queued data, as the windows allow.
            self.try_send_data_at(now, index)?;
        }
        Ok(())
    }

    pub fn abort(&mut self, id: SessionId, owner: TrustedCaller) -> Result<(), NetworkError> {
        let index = self.table.check_id(id, owner)?;
        if let Some(conn) = self.table.slots[index].as_mut() {
            conn.abort();
            self.table.free_slot(index);
        }
        Ok(())
    }

    /// Passive open: SYNs to `port` on our address start connections for `owner` to
    /// [`Self::accept`].
    pub fn listen(&mut self, owner: TrustedCaller, port: u16) -> Result<ListenerId, NetworkError> {
        if port == 0 {
            return Err(NetworkError::InvalidRequest);
        }
        let in_use = self.table.listener_for_port(port).is_some()
            || self
                .table
                .slots
                .iter()
                .flatten()
                .any(|c| c.local.port == port);
        if in_use {
            return Err(NetworkError::InvalidRequest);
        }
        let index = self
            .table
            .listeners
            .iter()
            .position(Option::is_none)
            .ok_or(NetworkError::SessionExhausted)?;
        self.table.listeners[index] = Some(Listener { owner, port });
        Ok(ListenerId(SessionId::new(
            self.table.generation,
            index as u32,
        )))
    }

    /// The oldest established connection on `listener` not yet accepted, now the caller's.
    pub fn accept(
        &mut self,
        listener: ListenerId,
        owner: TrustedCaller,
    ) -> Result<Option<SessionId>, NetworkError> {
        let index = self.table.check_listener(listener, owner)?;
        let ready = self
            .table
            .slots
            .iter()
            .enumerate()
            .filter_map(|(i, slot)| slot.as_ref().map(|c| (i, c)))
            .filter(|(_, c)| {
                c.listener == Some(index as u8) && !c.accepted && c.state != TcpState::SynReceived
            })
            .min_by_key(|(_, c)| c.established_order)
            .map(|(i, _)| i);
        let Some(slot) = ready else {
            return Ok(None);
        };
        self.table.slots[slot].as_mut().unwrap().accepted = true;
        Ok(Some(SessionId::new(self.table.generation, slot as u32)))
    }

    /// Connections on `listener` that [`Self::accept`] would hand out now.
    pub fn pending_accepts(
        &self,
        listener: ListenerId,
        owner: TrustedCaller,
    ) -> Result<usize, NetworkError> {
        let index = self.table.check_listener(listener, owner)?;
        Ok(self
            .table
            .slots
            .iter()
            .flatten()
            .filter(|c| {
                c.listener == Some(index as u8) && !c.accepted && c.state != TcpState::SynReceived
            })
            .count())
    }

    /// Stops listening; connections not yet accepted are reset, accepted ones are kept.
    pub fn close_listener(
        &mut self,
        now: u64,
        listener: ListenerId,
        owner: TrustedCaller,
    ) -> Result<(), NetworkError> {
        let index = self.table.check_listener(listener, owner)?;
        self.drop_listener(now, index);
        Ok(())
    }

    fn drop_listener(&mut self, now: u64, index: usize) {
        self.table.listeners[index] = None;
        for i in 0..self.table.slots.len() {
            let orphan = self.table.slots[i]
                .as_ref()
                .is_some_and(|c| c.listener == Some(index as u8) && !c.accepted);
            if orphan {
                let _ = self.send_rst_at(now, i);
                self.stats.resets_sent += 1;
                self.table.slots[i].as_mut().unwrap().abort();
                self.table.free_slot(i);
            }
        }
    }

    pub fn on_holder_exit(
        &mut self,
        now: u64,
        owner: TrustedCaller,
    ) -> Result<usize, NetworkError> {
        let mut count = 0;
        for l in 0..MAX_TCP_LISTENERS {
            if self.table.listeners[l].is_some_and(|l| l.owner == owner) {
                self.drop_listener(now, l);
            }
        }
        for i in 0..self.table.slots.len() {
            let should_abort = self.table.slots[i]
                .as_ref()
                .map(|c| c.owner == owner && !c.state.is_terminal())
                .unwrap_or(false);
            if should_abort {
                self.send_rst_at(now, i)?;
                self.stats.resets_sent += 1;
                self.table.slots[i].as_mut().unwrap().abort();
                self.table.free_slot(i);
                count += 1;
            }
        }
        Ok(count)
    }

    /// Earliest tick at which [`Self::poll`] has timer work (retransmit, persist probe,
    /// connect timeout, TIME-WAIT expiry, window update) across all connections, or `None`.
    pub fn next_timer_deadline(&self) -> Option<u64> {
        self.table
            .slots
            .iter()
            .flatten()
            .filter_map(|conn| conn.next_timer_deadline())
            .min()
    }

    /// Drives RX, timers, SYN retry, data and window updates.
    ///
    /// At most [`TCP_POLL_RX_BUDGET`] inbound frames are processed per call so a
    /// peer flood cannot keep the caller from observing connection state.
    pub fn poll(&mut self, now: u64) -> Result<(), NetworkError> {
        for _ in 0..TCP_POLL_RX_BUDGET {
            let Some(inbound) = self.stack.poll(now)? else {
                break;
            };
            let stack::Inbound::Ipv4(ip) = inbound else {
                continue;
            };
            if ip.header.protocol != IpProtocol::TCP {
                continue;
            }
            let payload = ip.payload();
            let src = ip.header.src;
            let dst = ip.header.dst;
            match parse_tcp(src, dst, payload) {
                Ok((seg, data)) => {
                    self.stats.segments_received += 1;
                    let local_port = seg.dst_port;
                    let remote = SocketAddrV4::new(src, seg.src_port);
                    if let Some(index) = self.table.find_by_quad(local_port, remote) {
                        self.dispatch(now, index, &seg, data)?;
                    } else {
                        self.on_unmatched(now, SocketAddrV4::new(dst, local_port), remote, &seg);
                    }
                }
                Err(_) => {
                    self.stats.dropped_bad_checksum += 1;
                }
            }
        }

        for i in 0..self.table.slots.len() {
            if let Some(conn) = self.table.slots[i].as_mut() {
                match conn.tick_timers(now, &mut self.stats) {
                    TimerAction::Retransmit => {
                        self.retransmit_at(now, i)?;
                    }
                    TimerAction::Probe => {
                        let (seg, dst) = (conn.probe_segment(), conn.remote.addr);
                        self.transmit_tcp_at(now, i, dst, &seg, &[])?;
                    }
                    TimerAction::Closed => {
                        self.table.free_slot(i);
                    }
                    TimerAction::Failed(_) => {
                        self.on_failed(i);
                    }
                    TimerAction::None => {}
                }
            }
        }

        for i in 0..self.table.slots.len() {
            let Some(conn) = self.table.slots[i].as_ref() else {
                continue;
            };
            if conn.needs_syn_retry() {
                if self.send_syn_at(now, i).is_ok() {
                    self.table.slots[i].as_mut().unwrap().clear_pending_syn();
                }
                continue;
            }
            if conn.state.is_synchronized() {
                let _ = self.try_send_data_at(now, i);
            }
            if self.table.slots[i]
                .as_ref()
                .is_some_and(|c| c.window_update_due())
            {
                self.send_ack_at(now, i)?;
            }
        }
        Ok(())
    }

    fn dispatch(
        &mut self,
        now: u64,
        index: usize,
        seg: &TcpSegment,
        data: &[u8],
    ) -> Result<(), NetworkError> {
        let conn = self.table.slots[index].as_mut().unwrap();
        let was_handshaking = conn.state == TcpState::SynReceived;
        let action = conn.on_segment(seg, data, now, &mut self.stats);
        if was_handshaking && conn.state.is_synchronized() {
            self.table.established_counter += 1;
            conn.established_order = self.table.established_counter;
        }
        match action {
            SegmentAction::SendAck => {
                self.send_ack_at(now, index)?;
                if self.table.slots[index].as_ref().unwrap().state == TcpState::TimeWait {
                    self.table.slots[index]
                        .as_mut()
                        .unwrap()
                        .enter_time_wait(now);
                }
            }
            SegmentAction::SendSynAck => {
                let _ = self.send_syn_at(now, index);
            }
            SegmentAction::MaybeSendData => {
                let _ = self.try_send_data_at(now, index);
            }
            SegmentAction::Retransmit => {
                self.fast_retransmit_at(now, index)?;
            }
            SegmentAction::Closed => {
                self.table.free_slot(index);
            }
            SegmentAction::Failed(_) => self.on_failed(index),
            SegmentAction::None => {}
        }
        Ok(())
    }

    fn on_failed(&mut self, index: usize) {
        let conn = self.table.slots[index].as_mut().unwrap();
        // A passive connection nobody accepted has no reader: free it now.
        let unread = conn.has_buffered_recv() && (conn.listener.is_none() || conn.accepted);
        if !unread {
            conn.abort();
            self.table.free_slot(index);
        }
        // Otherwise `receive` drains in-order data before the slot is freed.
    }

    /// A segment for no connection: a SYN to a listener starts a passive open; anything
    /// else is dropped (no RST, so closed ports stay quiet).
    fn on_unmatched(
        &mut self,
        now: u64,
        local: SocketAddrV4,
        remote: SocketAddrV4,
        seg: &TcpSegment,
    ) {
        let is_syn = seg.flags.contains(TcpFlags::SYN)
            && !seg.flags.contains(TcpFlags::ACK)
            && !seg.flags.contains(TcpFlags::RST);
        let listener = self.table.listener_for_port(local.port);
        let (true, Some(listener)) = (is_syn, listener) else {
            self.stats.dropped_no_conn += 1;
            return;
        };
        if local.addr != self.stack.our_ip() {
            self.stats.dropped_no_conn += 1;
            return;
        }
        let Some(index) = self
            .table
            .alloc_passive_slot(now, listener, local, remote, seg)
        else {
            self.stats.dropped_syn_backlog += 1;
            return;
        };
        self.stats.passive_opens += 1;
        let _ = self.send_syn_at(now, index);
    }

    /// Our SYN (active) or SYN-ACK (passive).
    fn send_syn_at(&mut self, now: u64, index: usize) -> Result<(), NetworkError> {
        let (seg, dst) = {
            let conn = self.table.slots[index].as_mut().unwrap();
            (conn.syn_segment(), conn.remote.addr)
        };
        let result = self.transmit_raw(now, dst, &seg, &[]);
        let conn = self.table.slots[index].as_mut().unwrap();
        match result {
            Err(NetworkError::Unreachable) => {
                conn.on_unreachable();
                // A passive open still waits on its RTO for the SYN-ACK retry.
                if conn.state == TcpState::SynReceived {
                    conn.on_syn_transmitted(now);
                }
                Err(NetworkError::Unreachable)
            }
            Ok(()) => {
                conn.on_syn_transmitted(now);
                Ok(())
            }
            other => other,
        }
    }

    fn send_ack_at(&mut self, now: u64, index: usize) -> Result<(), NetworkError> {
        let (seg, dst) = {
            let conn = self.table.slots[index].as_mut().unwrap();
            (conn.ack_segment(), conn.remote.addr)
        };
        self.transmit_tcp_at(now, index, dst, &seg, &[])
    }

    fn send_rst_at(&mut self, now: u64, index: usize) -> Result<(), NetworkError> {
        let (seg, dst) = {
            let conn = self.table.slots[index].as_mut().unwrap();
            let seg = conn.build_segment(
                TcpFlags::RST.union(TcpFlags::ACK),
                conn.snd_nxt,
                conn.rcv_nxt,
                false,
                false,
            );
            (seg, conn.remote.addr)
        };
        let _ = self.transmit_raw(now, dst, &seg, &[]);
        Ok(())
    }

    /// The RTO fired: SYN or SYN-ACK again, or data from `snd_una` (already rewound).
    fn retransmit_at(&mut self, now: u64, index: usize) -> Result<(), NetworkError> {
        let state = self.table.slots[index].as_ref().unwrap().state;
        if matches!(state, TcpState::SynSent | TcpState::SynReceived) {
            let _ = self.send_syn_at(now, index);
            return Ok(());
        }
        self.try_send_data_at(now, index)
    }

    fn fast_retransmit_at(&mut self, now: u64, index: usize) -> Result<(), NetworkError> {
        let mut buf = [0u8; MAX_TCP_PAYLOAD];
        let Some((seg, n, dst)) = ({
            let conn = self.table.slots[index].as_mut().unwrap();
            conn.head_segment(&mut buf)
                .map(|(seg, n)| (seg, n, conn.remote.addr))
        }) else {
            return Ok(());
        };
        self.transmit_tcp_at(now, index, dst, &seg, &buf[..n])
    }

    fn try_send_data_at(&mut self, now: u64, index: usize) -> Result<(), NetworkError> {
        let mut buf = [0u8; MAX_TCP_PAYLOAD];
        for _ in 0..TCP_SEND_BURST {
            let Some((seg, n, dst)) = ({
                let conn = self.table.slots[index].as_mut().unwrap();
                conn.next_segment(now, &mut buf)
                    .map(|(seg, n)| (seg, n, conn.remote.addr))
            }) else {
                return Ok(());
            };
            self.transmit_tcp_at(now, index, dst, &seg, &buf[..n])?;
        }
        Ok(())
    }

    /// Like [`Self::transmit_raw`], but ARP miss defers to a later poll instead of failing the driver.
    fn transmit_tcp_at(
        &mut self,
        now: u64,
        index: usize,
        dst: Ipv4Addr,
        seg: &TcpSegment,
        payload: &[u8],
    ) -> Result<(), NetworkError> {
        match self.transmit_raw(now, dst, seg, payload) {
            Err(NetworkError::Unreachable) => {
                self.table.slots[index].as_mut().unwrap().on_unreachable();
                Ok(())
            }
            other => other,
        }
    }

    fn transmit_raw(
        &mut self,
        now: u64,
        dst: Ipv4Addr,
        seg: &TcpSegment,
        payload: &[u8],
    ) -> Result<(), NetworkError> {
        let src = self.stack.our_ip();
        let total_len = seg.header_len() + payload.len();
        match self
            .stack
            .send_ipv4(now, dst, IpProtocol::TCP, total_len, |buf| {
                let written = write_tcp_to_buf(src, dst, seg, payload, buf)?;
                if written != total_len {
                    return Err(NetworkError::Protocol);
                }
                Ok(())
            }) {
            Ok(()) => {
                self.stats.segments_sent += 1;
                Ok(())
            }
            Err(NetworkError::Unreachable) => Err(NetworkError::Unreachable),
            Err(e) => Err(e),
        }
    }
}
