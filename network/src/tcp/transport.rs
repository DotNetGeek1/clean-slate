//! Connection table and [`TcpTransport`] over [`L3Stack`].

#[cfg(any(test, feature = "alloc"))]
extern crate alloc;
#[cfg(any(test, feature = "alloc"))]
use alloc::boxed::Box;

use crate::addr::{IpProtocol, Ipv4Addr, SocketAddrV4};
use crate::device::NetworkLink;
use crate::error::{DenialReason, NetworkError};
use crate::limits::MAX_TCP_CONNECTIONS;
use crate::protocol::TrustedCaller;
use crate::session::{SessionGeneration, SessionId};
use crate::stack::{self, L3Stack};
use crate::tcp::conn::{
    deterministic_iss, write_tcp_to_buf, SegmentAction, TcpConnection, TimerAction,
};
use crate::tcp::segment::{parse as parse_tcp, syn_segment, TcpFlags, MAX_TCP_PAYLOAD};
use crate::tcp::state::TcpState;
use crate::tcp::stats::TcpStats;

const EPHEMERAL_PORT_BASE: u16 = 50_000;

fn new_slot_storage() -> SlotStorage {
    #[cfg(any(test, feature = "alloc"))]
    {
        Box::new([const { None }; MAX_TCP_CONNECTIONS as usize])
    }
    #[cfg(not(any(test, feature = "alloc")))]
    {
        [const { None }; MAX_TCP_CONNECTIONS as usize]
    }
}

#[cfg(any(test, feature = "alloc"))]
type SlotStorage = Box<[Option<TcpConnection>; MAX_TCP_CONNECTIONS as usize]>;
#[cfg(not(any(test, feature = "alloc")))]
type SlotStorage = [Option<TcpConnection>; MAX_TCP_CONNECTIONS as usize];

/// Fixed-size connection table keyed by [`SessionId`] index.
pub struct TcpTable {
    generation: SessionGeneration,
    pub(crate) slots: SlotStorage,
    iss_counter: u64,
}

impl TcpTable {
    /// Initializes a zeroed [`TcpTable`] (static or heap-backed storage).
    pub fn init_in_place(&mut self, generation: SessionGeneration) {
        self.generation = generation;
        self.iss_counter = 0;
        #[cfg(any(test, feature = "alloc"))]
        {
            self.slots = new_slot_storage();
        }
        #[cfg(not(any(test, feature = "alloc")))]
        {
            for slot in self.slots.iter_mut() {
                *slot = None;
            }
        }
    }

    pub fn new(generation: SessionGeneration) -> Self {
        Self {
            generation,
            slots: new_slot_storage(),
            iss_counter: 0,
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
        owner: TrustedCaller,
        remote: SocketAddrV4,
        our_ip: Ipv4Addr,
    ) -> Result<usize, NetworkError> {
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_none() {
                let port = EPHEMERAL_PORT_BASE + index as u16;
                let local = SocketAddrV4::new(our_ip, port);
                let iss = deterministic_iss(self.generation, index as u32, self.iss_counter);
                self.iss_counter += 1;
                let conn = TcpConnection::new(owner, local, remote, iss);
                *slot = Some(conn);
                return Ok(index);
            }
        }
        Err(NetworkError::SessionExhausted)
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
    ) {
        unsafe {
            (*slot).stack = stack;
            (*slot).table.init_in_place(generation);
            (*slot).stats = TcpStats::default();
        }
    }

    pub fn new(stack: L3Stack<L>, generation: SessionGeneration) -> Self {
        Self {
            stack,
            table: TcpTable::new(generation),
            stats: TcpStats::default(),
        }
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
        let index = self.table.alloc_slot(owner, remote, our_ip)?;
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
            self.send_fin_at(now, index)?;
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

    pub fn on_holder_exit(
        &mut self,
        now: u64,
        owner: TrustedCaller,
    ) -> Result<usize, NetworkError> {
        let mut count = 0;
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

    /// Drives RX, timers, SYN retry, and retransmits.
    pub fn poll(&mut self, now: u64) -> Result<(), NetworkError> {
        while let Some(inbound) = self.stack.poll(now)? {
            if let stack::Inbound::Ipv4(ip) = inbound {
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
                            let action = self.table.slots[index].as_mut().unwrap().on_segment(
                                &seg,
                                data,
                                &mut self.stats,
                            );
                            match action {
                                SegmentAction::SendAck => {
                                    self.send_ack_at(now, index)?;
                                    if self.table.slots[index].as_ref().unwrap().state
                                        == TcpState::TimeWait
                                    {
                                        self.table.slots[index]
                                            .as_mut()
                                            .unwrap()
                                            .enter_time_wait(now);
                                    }
                                }
                                SegmentAction::MaybeSendData => {
                                    let _ = self.try_send_data_at(now, index);
                                }
                                SegmentAction::Closed => {
                                    self.table.free_slot(index);
                                }
                                SegmentAction::Failed(_) => {
                                    self.table.slots[index].as_mut().unwrap().abort();
                                    self.table.free_slot(index);
                                }
                                SegmentAction::None => {}
                            }
                        } else {
                            self.stats.dropped_no_conn += 1;
                        }
                    }
                    Err(_) => {
                        self.stats.dropped_bad_checksum += 1;
                    }
                }
            }
        }

        for i in 0..self.table.slots.len() {
            if let Some(conn) = self.table.slots[i].as_mut() {
                match conn.tick_timers(now, &mut self.stats) {
                    TimerAction::Retransmit => {
                        self.retransmit_at(now, i)?;
                    }
                    TimerAction::Closed => {
                        self.table.free_slot(i);
                    }
                    TimerAction::Failed(_) => {
                        conn.abort();
                        self.table.free_slot(i);
                    }
                    TimerAction::None => {}
                }
            }
        }

        for i in 0..self.table.slots.len() {
            let retry = self.table.slots[i]
                .as_ref()
                .map(|c| c.needs_syn_retry())
                .unwrap_or(false);
            if retry {
                if self.send_syn_at(now, i).is_ok() {
                    self.table.slots[i].as_mut().unwrap().clear_pending_syn();
                }
            } else if self.table.slots[i]
                .as_ref()
                .map(|c| matches!(c.state, TcpState::Established | TcpState::CloseWait))
                .unwrap_or(false)
            {
                let _ = self.try_send_data_at(now, i);
            }
        }
        Ok(())
    }

    fn send_syn_at(&mut self, now: u64, index: usize) -> Result<(), NetworkError> {
        let (seg, dst) = {
            let conn = self.table.slots[index].as_mut().unwrap();
            let seg = syn_segment(conn.local.port, conn.remote.port, conn.iss);
            conn.record_unacked(conn.iss, &[], true, false, now);
            conn.touch_connect_deadline(now);
            (seg, conn.remote.addr)
        };
        match self.transmit_raw(now, dst, &seg, &[]) {
            Err(NetworkError::Unreachable) => {
                self.table.slots[index].as_mut().unwrap().on_unreachable();
                Err(NetworkError::Unreachable)
            }
            Ok(()) => {
                let conn = self.table.slots[index].as_mut().unwrap();
                conn.snd_nxt = conn.iss.wrapping_add(1);
                Ok(())
            }
            other => other,
        }
    }

    fn send_ack_at(&mut self, now: u64, index: usize) -> Result<(), NetworkError> {
        let (seg, dst) = {
            let conn = self.table.slots[index].as_mut().unwrap();
            let seg =
                conn.build_segment(TcpFlags::ACK, conn.snd_nxt, conn.rcv_nxt, &[], false, false);
            (seg, conn.remote.addr)
        };
        self.transmit_raw(now, dst, &seg, &[])?;
        Ok(())
    }

    fn send_fin_at(&mut self, now: u64, index: usize) -> Result<(), NetworkError> {
        let (seg, dst) = {
            let conn = self.table.slots[index].as_mut().unwrap();
            let seq = conn.snd_nxt;
            let seg = conn.build_segment(TcpFlags::ACK, seq, conn.rcv_nxt, &[], false, true);
            conn.snd_nxt = conn.snd_nxt.wrapping_add(1);
            conn.record_unacked(seq, &[], false, true, now);
            (seg, conn.remote.addr)
        };
        self.transmit_raw(now, dst, &seg, &[])?;
        Ok(())
    }

    fn send_rst_at(&mut self, now: u64, index: usize) -> Result<(), NetworkError> {
        let (seg, dst) = {
            let conn = self.table.slots[index].as_mut().unwrap();
            let seg = conn.build_segment(
                TcpFlags::RST.union(TcpFlags::ACK),
                conn.snd_nxt,
                conn.rcv_nxt,
                &[],
                false,
                false,
            );
            (seg, conn.remote.addr)
        };
        let _ = self.transmit_raw(now, dst, &seg, &[]);
        Ok(())
    }

    fn retransmit_at(&mut self, now: u64, index: usize) -> Result<(), NetworkError> {
        let mut buf = [0u8; MAX_TCP_PAYLOAD];
        let (seg, n, dst) = {
            let conn = self.table.slots[index].as_mut().unwrap();
            let (seg, payload) = conn
                .unacked_for_retransmit()
                .ok_or(NetworkError::Protocol)?;
            let n = payload.len();
            buf[..n].copy_from_slice(payload);
            (seg, n, conn.remote.addr)
        };
        self.transmit_raw(now, dst, &seg, &buf[..n])?;
        if self.table.slots[index].as_ref().unwrap().state == TcpState::SynSent {
            self.table.slots[index]
                .as_mut()
                .unwrap()
                .touch_connect_deadline(now);
        }
        Ok(())
    }

    fn try_send_data_at(&mut self, now: u64, index: usize) -> Result<(), NetworkError> {
        let mut buf = [0u8; MAX_TCP_PAYLOAD];
        let (seg, n, dst) = {
            let conn = self.table.slots[index].as_mut().unwrap();
            if conn.has_active_retransmit() || !conn.send_buf_has_data() {
                return Ok(());
            }
            if !matches!(conn.state, TcpState::Established | TcpState::CloseWait) {
                return Ok(());
            }
            let max = conn
                .peer_mss
                .min(conn.peer_window)
                .min(MAX_TCP_PAYLOAD as u16) as usize;
            let (n, chunk) = conn.pop_send_chunk(max);
            if n == 0 {
                return Ok(());
            }
            buf[..n].copy_from_slice(&chunk[..n]);
            let seq = conn.snd_nxt;
            let seg = conn.build_segment(
                TcpFlags::ACK.union(TcpFlags::PSH),
                seq,
                conn.rcv_nxt,
                &buf[..n],
                false,
                false,
            );
            conn.snd_nxt = conn.snd_nxt.wrapping_add(n as u32);
            conn.record_unacked(seq, &buf[..n], false, false, now);
            (seg, n, conn.remote.addr)
        };
        self.transmit_raw(now, dst, &seg, &buf[..n])?;
        Ok(())
    }

    fn transmit_raw(
        &mut self,
        now: u64,
        dst: Ipv4Addr,
        seg: &crate::tcp::segment::TcpSegment,
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
