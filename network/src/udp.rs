//! Bounded UDP codec, endpoint table, and transport over [`L3Stack`](crate::stack::L3Stack).
//!
//! M7 requires mandatory UDP checksums on the wire: a checksum field of zero is rejected
//! (IPv4 "no checksum" is not supported). A computed checksum of zero is written as `0xFFFF`.

use crate::addr::{IpProtocol, Ipv4Addr, SocketAddrV4};
use crate::device::NetworkLink;
use crate::error::{DenialReason, NetworkError};
use crate::ethernet::ParseError;
use crate::limits::{
    MAX_APPLICATION_PAYLOAD_BYTES, MAX_L3_PAYLOAD_BYTES, MAX_PENDING_REQUESTS_PER_SESSION,
    MAX_UDP_ENDPOINTS,
};
use crate::protocol::TrustedCaller;
use crate::session::{SessionGeneration, SessionId, SessionState};
use crate::stack::{Inbound, L3Stack};

/// UDP header length on the wire (RFC 768).
pub const UDP_HEADER_LEN: usize = 8;

/// Maximum UDP datagram payload (L3 payload minus standard IPv4 and UDP headers).
pub const MAX_UDP_PAYLOAD: usize = MAX_L3_PAYLOAD_BYTES
    .saturating_sub(crate::ipv4::IPV4_MIN_HEADER_LEN)
    .saturating_sub(UDP_HEADER_LEN);

/// First ephemeral local port for deterministic auto-bind ([`UdpTable::open`] with `None`).
pub const EPHEMERAL_PORT_BASE: u16 = 49_152;

/// Session handle for a UDP endpoint (same packing as [`SessionId`]).
pub type UdpEndpointId = SessionId;

const RX_QUEUE_CAP: usize = MAX_PENDING_REQUESTS_PER_SESSION as usize;
const ENDPOINT_SLOTS: usize = MAX_UDP_ENDPOINTS as usize;

/// Parsed UDP header (checksum validated separately in [`UdpHeader::parse`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    /// Parses and validates a UDP datagram in `payload` (typically IPv4 L4 bytes).
    ///
    /// `length` must be at least [`UDP_HEADER_LEN`] and must not exceed `payload.len()`; bytes
    /// beyond `length` are ignored. Checksum zero on the wire is rejected for M7.
    pub fn parse(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        payload: &[u8],
    ) -> Result<(Self, &[u8]), ParseError> {
        if payload.len() < UDP_HEADER_LEN {
            return Err(ParseError::Truncated);
        }
        let src_port = u16::from_be_bytes([payload[0], payload[1]]);
        let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
        let length = u16::from_be_bytes([payload[4], payload[5]]);
        let checksum = u16::from_be_bytes([payload[6], payload[7]]);
        let length_usize = length as usize;
        if length_usize < UDP_HEADER_LEN {
            return Err(ParseError::BadTotalLength);
        }
        if length_usize > payload.len() {
            return Err(ParseError::BadTotalLength);
        }
        if checksum == 0 {
            return Err(ParseError::BadChecksum);
        }
        if !verify_udp_datagram(
            src_ip,
            dst_ip,
            payload.get(0..length_usize).ok_or(ParseError::Truncated)?,
        ) {
            return Err(ParseError::BadChecksum);
        }
        let data = payload
            .get(UDP_HEADER_LEN..length_usize)
            .ok_or(ParseError::Truncated)?;
        Ok((
            Self {
                src_port,
                dst_port,
                length,
                checksum,
            },
            data,
        ))
    }

    /// Writes UDP header + `data` into `out` and returns total bytes written.
    pub fn write(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, ParseError> {
        if data.len() > MAX_UDP_PAYLOAD {
            return Err(ParseError::PayloadTooLarge);
        }
        let total = UDP_HEADER_LEN
            .checked_add(data.len())
            .ok_or(ParseError::BadTotalLength)?;
        if total > u16::MAX as usize {
            return Err(ParseError::BadTotalLength);
        }
        if out.len() < total {
            return Err(ParseError::BufferTooSmall);
        }
        out[0..2].copy_from_slice(&src_port.to_be_bytes());
        out[2..4].copy_from_slice(&dst_port.to_be_bytes());
        out[4..6].copy_from_slice(&(total as u16).to_be_bytes());
        out[6] = 0;
        out[7] = 0;
        out[UDP_HEADER_LEN..total].copy_from_slice(data);
        let csum = compute_udp_checksum(
            src_ip,
            dst_ip,
            out.get(0..total).ok_or(ParseError::Truncated)?,
        );
        let wire = if csum == 0 { 0xFFFF } else { csum };
        out[6..8].copy_from_slice(&wire.to_be_bytes());
        Ok(total)
    }
}

fn compute_udp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, datagram: &[u8]) -> u16 {
    use crate::checksum::Checksum;
    let len_u16 = u16::try_from(datagram.len()).unwrap_or(0);
    let mut sum = Checksum::new();
    sum = sum.add_bytes(&src_ip.octets());
    sum = sum.add_bytes(&dst_ip.octets());
    sum = sum.add_bytes(&[0, IpProtocol::UDP.get()]);
    sum = sum.add_bytes(&len_u16.to_be_bytes());
    if datagram.len() >= UDP_HEADER_LEN {
        let mut hdr = [0u8; UDP_HEADER_LEN];
        if let Some(prefix) = datagram.get(0..UDP_HEADER_LEN) {
            hdr.copy_from_slice(prefix);
        }
        hdr[6] = 0;
        hdr[7] = 0;
        sum = sum.add_bytes(&hdr);
        if datagram.len() > UDP_HEADER_LEN {
            sum = sum.add_bytes(datagram.get(UDP_HEADER_LEN..).unwrap_or(&[]));
        }
    } else {
        sum = sum.add_bytes(datagram);
    }
    sum.finish()
}

fn verify_udp_datagram(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, datagram: &[u8]) -> bool {
    use crate::checksum::Checksum;
    let len_u16 = u16::try_from(datagram.len()).unwrap_or(0);
    let mut sum = Checksum::new();
    sum = sum.add_bytes(&src_ip.octets());
    sum = sum.add_bytes(&dst_ip.octets());
    sum = sum.add_bytes(&[0, IpProtocol::UDP.get()]);
    sum = sum.add_bytes(&len_u16.to_be_bytes());
    sum = sum.add_bytes(datagram);
    sum.finish() == 0
}

/// One received datagram waiting in an endpoint RX queue.
#[derive(Clone, Copy)]
struct QueuedDatagram {
    from: SocketAddrV4,
    len: u16,
    data: [u8; MAX_APPLICATION_PAYLOAD_BYTES],
}

impl QueuedDatagram {
    const STORAGE_BYTES: usize = 6 + 2 + MAX_APPLICATION_PAYLOAD_BYTES;

    fn store(from: SocketAddrV4, payload: &[u8]) -> Self {
        let len = payload.len().min(MAX_APPLICATION_PAYLOAD_BYTES);
        let mut data = [0u8; MAX_APPLICATION_PAYLOAD_BYTES];
        if let Some(slice) = data.get_mut(0..len) {
            slice.copy_from_slice(payload.get(0..len).unwrap_or(&[]));
        }
        Self {
            from,
            len: len as u16,
            data,
        }
    }
}

/// Fixed-capacity RX ring per endpoint.
struct RxQueue {
    entries: [QueuedDatagram; RX_QUEUE_CAP],
    head: u8,
    len: u8,
}

impl RxQueue {
    const fn empty() -> Self {
        Self {
            entries: [QueuedDatagram {
                from: SocketAddrV4::new(Ipv4Addr::new([0, 0, 0, 0]), 0),
                len: 0,
                data: [0; MAX_APPLICATION_PAYLOAD_BYTES],
            }; RX_QUEUE_CAP],
            head: 0,
            len: 0,
        }
    }

    fn is_full(&self) -> bool {
        self.len as usize >= RX_QUEUE_CAP
    }

    fn push(&mut self, from: SocketAddrV4, payload: &[u8]) -> bool {
        if self.is_full() {
            return false;
        }
        let tail = (self.head as usize + self.len as usize) % RX_QUEUE_CAP;
        self.entries[tail] = QueuedDatagram::store(from, payload);
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<QueuedDatagram> {
        if self.len == 0 {
            return None;
        }
        let entry = self.entries[self.head as usize];
        self.head = ((self.head as usize + 1) % RX_QUEUE_CAP) as u8;
        self.len -= 1;
        Some(entry)
    }

    fn queued_count(&self) -> usize {
        self.len as usize
    }
}

/// One bound UDP endpoint (logical view of a live table slot).
pub struct UdpEndpoint {
    pub owner: TrustedCaller,
    pub local_port: u16,
    pub connected_peer: Option<SocketAddrV4>,
    pub state: SessionState,
}

impl UdpEndpoint {
    /// Fixed memory per endpoint RX storage (documented contract bound).
    pub const RX_QUEUE_MEMORY_BYTES: usize = RX_QUEUE_CAP * QueuedDatagram::STORAGE_BYTES;
}

#[derive(Clone, Copy)]
struct SlotMeta {
    owner: TrustedCaller,
    local_port: u16,
    connected_peer: Option<SocketAddrV4>,
    state: SessionState,
    live: bool,
}

impl SlotMeta {
    const fn vacant() -> Self {
        Self {
            owner: TrustedCaller::new(0, 0, 0),
            local_port: 0,
            connected_peer: None,
            state: SessionState::Closed,
            live: false,
        }
    }
}

/// Bounded UDP endpoint table for one network-service generation.
///
/// The table is ~1 MiB (`UDP_TABLE_MAX_RX_BYTES` plus slot metadata). Do not place it on
/// small thread stacks; the network service should hold it in static storage or a heap box.
pub struct UdpTable {
    generation: SessionGeneration,
    meta: [SlotMeta; ENDPOINT_SLOTS],
    rx: [RxQueue; ENDPOINT_SLOTS],
    queued_total: usize,
}

impl UdpTable {
    /// Initializes a zeroed [`UdpTable`] (for static or heap-backed storage).
    pub fn init_in_place(&mut self, generation: SessionGeneration) {
        self.generation = generation;
        self.queued_total = 0;
        for i in 0..ENDPOINT_SLOTS {
            self.meta[i] = SlotMeta::vacant();
        }
    }

    /// Creates an empty table tagged with `generation` (stale ids from prior tables fail checks).
    ///
    /// The table is ~1 MiB; prefer zeroed static storage plus [`init_in_place`] in the network service.
    pub fn new(generation: SessionGeneration) -> Self {
        let mut table = unsafe { core::mem::MaybeUninit::<Self>::zeroed().assume_init() };
        table.init_in_place(generation);
        table
    }

    pub fn generation(&self) -> SessionGeneration {
        self.generation
    }

    /// Number of live endpoints.
    pub fn endpoints_in_use(&self) -> usize {
        self.meta.iter().filter(|m| m.live).count()
    }

    /// Total datagrams queued across all endpoints.
    pub fn queued_datagrams(&self) -> usize {
        self.queued_total
    }

    /// Returns the bound local port for a live endpoint (tests and service diagnostics).
    pub fn local_port(&self, id: SessionId, owner: TrustedCaller) -> Result<u16, NetworkError> {
        let index = self.resolve_index(id, owner)?;
        Ok(self.meta[index].local_port)
    }

    /// Opens a UDP endpoint; `local_port == None` picks the lowest free ephemeral port.
    pub fn open(
        &mut self,
        owner: TrustedCaller,
        local_port: Option<u16>,
    ) -> Result<SessionId, NetworkError> {
        let port = match local_port {
            Some(p) => {
                if self.port_in_use(p) {
                    return Err(NetworkError::InvalidRequest);
                }
                p
            }
            None => self.allocate_ephemeral_port()?,
        };
        let index = self
            .find_free_slot()
            .ok_or(NetworkError::SessionExhausted)?;
        self.meta[index] = SlotMeta {
            owner,
            local_port: port,
            connected_peer: None,
            state: SessionState::Open,
            live: true,
        };
        self.rx[index] = RxQueue::empty();
        Ok(SessionId::new(self.generation, index as u32))
    }

    /// Sets the default peer for sends when `dest` is omitted.
    pub fn connect(
        &mut self,
        id: SessionId,
        owner: TrustedCaller,
        peer: SocketAddrV4,
    ) -> Result<(), NetworkError> {
        let index = self.resolve_index(id, owner)?;
        self.meta[index].connected_peer = Some(peer);
        Ok(())
    }

    /// Closes an endpoint and drops its RX queue.
    pub fn close(&mut self, id: SessionId, owner: TrustedCaller) -> Result<(), NetworkError> {
        let index = self.resolve_index(id, owner)?;
        let queued = self.rx[index].queued_count();
        self.meta[index] = SlotMeta::vacant();
        self.rx[index] = RxQueue::empty();
        self.queued_total = self.queued_total.saturating_sub(queued);
        Ok(())
    }

    /// Reclaims every endpoint owned by `owner` (holder exit).
    pub fn on_holder_exit(&mut self, owner: TrustedCaller) -> usize {
        let mut closed = 0usize;
        for index in 0..ENDPOINT_SLOTS {
            if self.meta[index].live && self.meta[index].owner == owner {
                self.queued_total = self
                    .queued_total
                    .saturating_sub(self.rx[index].queued_count());
                self.meta[index] = SlotMeta::vacant();
                self.rx[index] = RxQueue::empty();
                closed += 1;
            }
        }
        closed
    }

    /// Drops all endpoints and queued datagrams (service restart).
    pub fn clear(&mut self) {
        for index in 0..ENDPOINT_SLOTS {
            self.meta[index] = SlotMeta::vacant();
            self.rx[index] = RxQueue::empty();
        }
        self.queued_total = 0;
    }

    fn port_in_use(&self, port: u16) -> bool {
        self.meta.iter().any(|m| m.live && m.local_port == port)
    }

    fn allocate_ephemeral_port(&self) -> Result<u16, NetworkError> {
        for i in 0..ENDPOINT_SLOTS {
            let port = EPHEMERAL_PORT_BASE + i as u16;
            if !self.port_in_use(port) {
                return Ok(port);
            }
        }
        Err(NetworkError::SessionExhausted)
    }

    fn find_free_slot(&self) -> Option<usize> {
        self.meta.iter().position(|m| !m.live)
    }

    fn resolve_index(&self, id: SessionId, owner: TrustedCaller) -> Result<usize, NetworkError> {
        if !id.matches_generation(self.generation) {
            return Err(NetworkError::Denied(DenialReason::StaleGeneration));
        }
        let index = id.index() as usize;
        if index >= ENDPOINT_SLOTS {
            return Err(NetworkError::NotFound);
        }
        let ep = &self.meta[index];
        if !ep.live {
            return Err(NetworkError::NotFound);
        }
        if ep.owner != owner {
            return Err(NetworkError::Denied(DenialReason::NoCapability));
        }
        Ok(index)
    }

    fn slot_index_for_port(&self, port: u16) -> Option<usize> {
        self.meta
            .iter()
            .position(|m| m.live && m.local_port == port && m.state == SessionState::Open)
    }

    fn enqueue(&mut self, port: u16, from: SocketAddrV4, payload: &[u8]) -> Result<(), RxDrop> {
        let index = self.slot_index_for_port(port).ok_or(RxDrop::Unbound)?;
        if let Some(peer) = self.meta[index].connected_peer {
            if from != peer {
                return Err(RxDrop::Foreign);
            }
        }
        if !self.rx[index].push(from, payload) {
            return Err(RxDrop::QueueFull);
        }
        self.queued_total += 1;
        Ok(())
    }

    fn dequeue(
        &mut self,
        id: SessionId,
        owner: TrustedCaller,
    ) -> Result<Option<QueuedDatagram>, NetworkError> {
        let index = self.resolve_index(id, owner)?;
        if let Some(dg) = self.rx[index].pop() {
            self.queued_total = self.queued_total.saturating_sub(1);
            Ok(Some(dg))
        } else {
            Ok(None)
        }
    }
}

/// Worst-case table memory (32 endpoints × 8 queued datagrams × ~4104 B each), excluding slot metadata.
pub const UDP_TABLE_MAX_RX_BYTES: usize = ENDPOINT_SLOTS * UdpEndpoint::RX_QUEUE_MEMORY_BYTES;

#[derive(Debug)]
enum RxDrop {
    Unbound,
    Foreign,
    QueueFull,
}

/// Non-fatal UDP transport counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UdpStats {
    pub dropped_unbound: u64,
    pub dropped_foreign: u64,
    pub dropped_queue_full: u64,
    pub dropped_malformed: u64,
    pub sent: u64,
    pub received: u64,
}

/// UDP over IPv4 on a bounded endpoint table and [`L3Stack`].
pub struct UdpTransport<L: NetworkLink> {
    stack: L3Stack<L>,
    table: UdpTable,
    stats: UdpStats,
}

impl<L: NetworkLink> UdpTransport<L> {
    /// Creates transport with a fresh endpoint table for `generation`.
    pub fn new(stack: L3Stack<L>, generation: SessionGeneration) -> Self {
        Self {
            stack,
            table: UdpTable::new(generation),
            stats: UdpStats::default(),
        }
    }

    pub fn stack(&self) -> &L3Stack<L> {
        &self.stack
    }

    pub fn stack_mut(&mut self) -> &mut L3Stack<L> {
        &mut self.stack
    }

    pub fn table(&self) -> &UdpTable {
        &self.table
    }

    pub fn table_mut(&mut self) -> &mut UdpTable {
        &mut self.table
    }

    pub fn stats(&self) -> UdpStats {
        self.stats
    }

    /// Sends one datagram; `dest` required unless the endpoint is connected.
    ///
    /// Returns bytes sent on success. [`NetworkError::Unreachable`] means an ARP request was
    /// emitted and the caller should `poll` and retry with the same tick or a later `now`.
    pub fn send(
        &mut self,
        now: u64,
        id: SessionId,
        owner: TrustedCaller,
        dest: Option<SocketAddrV4>,
        data: &[u8],
    ) -> Result<usize, NetworkError> {
        if data.len() > MAX_APPLICATION_PAYLOAD_BYTES {
            return Err(NetworkError::InvalidRequest);
        }
        let index = self.table.resolve_index(id, owner)?;
        let meta = &self.table.meta[index];
        let peer = match dest {
            Some(d) => d,
            None => meta.connected_peer.ok_or(NetworkError::InvalidRequest)?,
        };
        let src_port = meta.local_port;
        let src_ip = self.stack.our_ip();
        let dst_ip = peer.addr;
        let dst_port = peer.port;
        let udp_len = UDP_HEADER_LEN
            .checked_add(data.len())
            .ok_or(NetworkError::Protocol)?;
        self.stack
            .send_ipv4(now, dst_ip, IpProtocol::UDP, udp_len, |buf| {
                if buf.len() < udp_len {
                    return Err(NetworkError::Protocol);
                }
                UdpHeader::write(src_ip, dst_ip, src_port, dst_port, data, buf)
                    .map_err(|_| NetworkError::Protocol)?;
                Ok(())
            })?;
        self.stats.sent += 1;
        Ok(data.len())
    }

    /// Receives at most one link frame and dispatches UDP datagrams to endpoint queues.
    ///
    /// Non-UDP [`Inbound`] values are ignored (TCP and future #88 multiplexing read the same
    /// stack poll path separately).
    pub fn poll(&mut self, now: u64) -> Result<(), NetworkError> {
        let inbound = self.stack.poll(now)?;
        if let Some(Inbound::Ipv4(ipv4)) = inbound {
            if ipv4.header.protocol != IpProtocol::UDP {
                return Ok(());
            }
            let l4 = ipv4.payload();
            match UdpHeader::parse(ipv4.header.src, ipv4.header.dst, l4) {
                Ok((hdr, data)) => {
                    let from = SocketAddrV4::new(ipv4.header.src, hdr.src_port);
                    match self.table.enqueue(hdr.dst_port, from, data) {
                        Ok(()) => self.stats.received += 1,
                        Err(RxDrop::Unbound) => self.stats.dropped_unbound += 1,
                        Err(RxDrop::Foreign) => self.stats.dropped_foreign += 1,
                        Err(RxDrop::QueueFull) => self.stats.dropped_queue_full += 1,
                    }
                }
                Err(_) => self.stats.dropped_malformed += 1,
            }
        }
        Ok(())
    }

    /// Non-blocking receive: copies up to `out.len()` bytes and returns `(from, full_datagram_len)`.
    ///
    /// `full_datagram_len` is the stored payload size before truncation; if it exceeds `out.len()`,
    /// only `out.len()` bytes are copied (truncation is silent except via the length difference).
    pub fn receive(
        &mut self,
        id: SessionId,
        owner: TrustedCaller,
        out: &mut [u8],
    ) -> Result<Option<(SocketAddrV4, usize)>, NetworkError> {
        let dg = self.table.dequeue(id, owner)?;
        if let Some(dg) = dg {
            let full = dg.len as usize;
            let copy_len = full.min(out.len());
            if let Some(dst) = out.get_mut(0..copy_len) {
                dst.copy_from_slice(dg.data.get(0..copy_len).unwrap_or(&[]));
            }
            Ok(Some((dg.from, full)))
        } else {
            Ok(None)
        }
    }

    /// Polls until `deadline_tick` (inclusive) and returns the first datagram or [`NetworkError::Timeout`].
    pub fn receive_with_deadline(
        &mut self,
        mut now: u64,
        deadline_tick: u64,
        id: SessionId,
        owner: TrustedCaller,
        out: &mut [u8],
    ) -> Result<(SocketAddrV4, usize), NetworkError> {
        while now <= deadline_tick {
            self.poll(now)?;
            if let Some(pair) = self.receive(id, owner, out)? {
                return Ok(pair);
            }
            now = now.saturating_add(1);
        }
        Err(NetworkError::Timeout)
    }

    /// Clears endpoints and resets the underlying stack (new table generation is a separate `new`).
    pub fn reset(&mut self) -> Result<(), NetworkError> {
        self.table.clear();
        self.stats = UdpStats::default();
        self.stack.reset()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeLink;
    use crate::fixture::{GUEST_IPV4, GUEST_MAC, PEER_IPV4, UDP_ECHO_PORT};

    const OWNER_A: TrustedCaller = TrustedCaller::new(1, 0, 0);
    const OWNER_B: TrustedCaller = TrustedCaller::new(2, 0, 0);
    const GEN: SessionGeneration = SessionGeneration::new(7);

    fn heap_table(generation: SessionGeneration) -> std::boxed::Box<UdpTable> {
        let layout = core::alloc::Layout::new::<UdpTable>();
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) as *mut UdpTable };
        assert!(!ptr.is_null(), "UdpTable heap allocation failed");
        unsafe {
            (*ptr).init_in_place(generation);
            std::boxed::Box::from_raw(ptr)
        }
    }

    fn heap_transport(
        stack: L3Stack<FakeLink>,
        generation: SessionGeneration,
    ) -> std::boxed::Box<UdpTransport<FakeLink>> {
        let layout = core::alloc::Layout::new::<UdpTransport<FakeLink>>();
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) as *mut UdpTransport<FakeLink> };
        assert!(!ptr.is_null(), "UdpTransport heap allocation failed");
        unsafe {
            core::ptr::write(&mut (*ptr).stack, stack);
            (*ptr).table.init_in_place(generation);
            (*ptr).stats = UdpStats::default();
            std::boxed::Box::from_raw(ptr)
        }
    }

    #[test]
    fn codec_roundtrip() {
        let src = Ipv4Addr::new([10, 77, 0, 2]);
        let dst = Ipv4Addr::new([10, 77, 0, 1]);
        let data = b"hello-udp";
        let mut buf = [0u8; 64];
        let n = UdpHeader::write(src, dst, 4000, 53, data, &mut buf).unwrap();
        let (hdr, pl) = UdpHeader::parse(src, dst, &buf[..n]).unwrap();
        assert_eq!(hdr.src_port, 4000);
        assert_eq!(hdr.dst_port, 53);
        assert_eq!(pl, data);
    }

    #[test]
    fn codec_truncated_lengths() {
        let src = Ipv4Addr::new([1, 2, 3, 4]);
        let dst = Ipv4Addr::new([5, 6, 7, 8]);
        let mut full = [0u8; 16];
        UdpHeader::write(src, dst, 1, 2, b"x", &mut full).unwrap();
        for len in 0..UDP_HEADER_LEN {
            assert_eq!(
                UdpHeader::parse(src, dst, &full[..len]),
                Err(ParseError::Truncated)
            );
        }
    }

    #[test]
    fn codec_bad_length_field() {
        let src = Ipv4Addr::new([1, 1, 1, 1]);
        let dst = Ipv4Addr::new([2, 2, 2, 2]);
        let mut buf = [0u8; 32];
        UdpHeader::write(src, dst, 10, 20, b"ab", &mut buf).unwrap();
        buf[4] = 0;
        buf[5] = 4;
        assert_eq!(
            UdpHeader::parse(src, dst, &buf),
            Err(ParseError::BadTotalLength)
        );
        buf[4] = 0xFF;
        buf[5] = 0xFF;
        assert_eq!(
            UdpHeader::parse(src, dst, &buf),
            Err(ParseError::BadTotalLength)
        );
    }

    #[test]
    fn codec_bad_checksum_and_zero_rejected() {
        let src = Ipv4Addr::new([10, 0, 0, 1]);
        let dst = Ipv4Addr::new([10, 0, 0, 2]);
        let mut buf = [0u8; 32];
        UdpHeader::write(src, dst, 1, 2, b"data", &mut buf).unwrap();
        buf[7] ^= 0x01;
        assert_eq!(
            UdpHeader::parse(src, dst, &buf),
            Err(ParseError::BadChecksum)
        );
        UdpHeader::write(src, dst, 1, 2, b"data", &mut buf).unwrap();
        buf[6] = 0;
        buf[7] = 0;
        assert_eq!(
            UdpHeader::parse(src, dst, &buf),
            Err(ParseError::BadChecksum)
        );
    }

    #[test]
    fn codec_zero_checksum_encoded_as_ffff() {
        let src = Ipv4Addr::new([192, 0, 2, 1]);
        let dst = Ipv4Addr::new([192, 0, 2, 2]);
        let mut buf = [0u8; UDP_HEADER_LEN + 4];
        let mut state = 0x00C0_FFEE_u32;
        for _ in 0..500_000 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let src_port = (state >> 16) as u16;
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let dst_port = (state >> 16) as u16;
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let len = (state as usize) % 5;
            let payload = [0xA5u8; 4];
            let n =
                UdpHeader::write(src, dst, src_port, dst_port, &payload[..len], &mut buf).unwrap();
            buf[6] = 0;
            buf[7] = 0;
            if compute_udp_checksum(src, dst, &buf[..n]) != 0 {
                continue;
            }
            let mut wire = [0u8; UDP_HEADER_LEN + 4];
            UdpHeader::write(src, dst, src_port, dst_port, &payload[..len], &mut wire).unwrap();
            assert_eq!(u16::from_be_bytes([wire[6], wire[7]]), 0xFFFF);
            buf[6] = 0xFF;
            buf[7] = 0xFF;
            assert!(UdpHeader::parse(src, dst, &buf[..n]).is_ok());
            return;
        }
        panic!("no UDP payload produced a zero checksum in search space");
    }

    #[test]
    fn codec_write_rejects_oversized() {
        let src = Ipv4Addr::new([1, 2, 3, 4]);
        let dst = Ipv4Addr::new([4, 3, 2, 1]);
        let big = vec![0u8; MAX_UDP_PAYLOAD + 1];
        let mut out = [0u8; 8];
        assert_eq!(
            UdpHeader::write(src, dst, 1, 1, &big, &mut out),
            Err(ParseError::PayloadTooLarge)
        );
    }

    #[test]
    fn codec_lcg_no_panic() {
        let src = Ipv4Addr::new([10, 77, 0, 2]);
        let dst = Ipv4Addr::new([10, 77, 0, 1]);
        let mut state = 0x1234_5678_u32;
        for _ in 0..512 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let len = (state as usize) % 1501;
            let mut buf = [0u8; 1500];
            for byte in buf.iter_mut().take(len) {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = (state >> 16) as u8;
            }
            let _ = UdpHeader::parse(src, dst, &buf[..len]);
        }
    }

    #[test]
    fn table_open_close_and_ephemeral() {
        let mut t = heap_table(GEN);
        let id1 = t.open(OWNER_A, None).unwrap();
        let id2 = t.open(OWNER_A, None).unwrap();
        assert_eq!(t.endpoints_in_use(), 2);
        let p1 = t.local_port(id1, OWNER_A).unwrap();
        let p2 = t.local_port(id2, OWNER_A).unwrap();
        assert_eq!(p1, EPHEMERAL_PORT_BASE);
        assert_eq!(p2, EPHEMERAL_PORT_BASE + 1);
        t.close(id1, OWNER_A).unwrap();
        let id3 = t.open(OWNER_A, None).unwrap();
        let p3 = t.local_port(id3, OWNER_A).unwrap();
        assert_eq!(p3, EPHEMERAL_PORT_BASE);
        assert_eq!(t.endpoints_in_use(), 2);
    }

    #[test]
    fn table_explicit_port_collision() {
        let mut t = heap_table(GEN);
        t.open(OWNER_A, Some(UDP_ECHO_PORT)).unwrap();
        assert_eq!(
            t.open(OWNER_B, Some(UDP_ECHO_PORT)),
            Err(NetworkError::InvalidRequest)
        );
    }

    #[test]
    fn table_exhaustion() {
        let mut t = heap_table(GEN);
        let mut ids = Vec::new();
        for _ in 0..ENDPOINT_SLOTS {
            ids.push(t.open(OWNER_A, None).unwrap());
        }
        assert_eq!(t.open(OWNER_A, None), Err(NetworkError::SessionExhausted));
        for id in ids {
            t.close(id, OWNER_A).unwrap();
        }
    }

    #[test]
    fn table_wrong_owner_and_stale_generation() {
        let mut t = heap_table(GEN);
        let id = t.open(OWNER_A, None).unwrap();
        assert_eq!(
            t.close(id, OWNER_B),
            Err(NetworkError::Denied(DenialReason::NoCapability))
        );
        let mut t2 = heap_table(SessionGeneration::new(GEN.get() + 1));
        assert_eq!(
            t2.close(id, OWNER_A),
            Err(NetworkError::Denied(DenialReason::StaleGeneration))
        );
    }

    #[test]
    fn table_holder_exit_and_reuse() {
        let mut t = heap_table(GEN);
        let _ = t.open(OWNER_A, None).unwrap();
        let _ = t.open(OWNER_A, None).unwrap();
        let _ = t.open(OWNER_B, None).unwrap();
        assert_eq!(t.on_holder_exit(OWNER_A), 2);
        assert_eq!(t.endpoints_in_use(), 1);
        for _ in 0..(ENDPOINT_SLOTS * 4) {
            let id = t.open(OWNER_A, None).unwrap();
            t.close(id, OWNER_A).unwrap();
        }
        assert!(t.endpoints_in_use() <= ENDPOINT_SLOTS);
    }

    fn make_stack(mac: crate::addr::MacAddr, ip: Ipv4Addr, link: FakeLink) -> L3Stack<FakeLink> {
        L3Stack::new(link, mac, ip, 1000)
    }

    fn peer_udp_echo(
        peer: &mut UdpTransport<FakeLink>,
        peer_id: SessionId,
        peer_owner: TrustedCaller,
        now: u64,
    ) {
        peer.poll(now).unwrap();
        let mut buf = [0u8; MAX_APPLICATION_PAYLOAD_BYTES];
        if let Ok(Some((from, len))) = peer.receive(peer_id, peer_owner, &mut buf) {
            let payload = buf.get(0..len.min(buf.len())).unwrap_or(&[]);
            let _ = peer.send(now, peer_id, peer_owner, Some(from), payload);
        }
    }

    #[test]
    fn transport_echo_roundtrip_with_arp_retry() {
        let (guest_link, peer_link) = FakeLink::pair();
        let guest_mac = guest_link.link().mac;
        let peer_mac = peer_link.link().mac;
        let mut guest = heap_transport(make_stack(guest_mac, GUEST_IPV4, guest_link), GEN);
        let mut peer = heap_transport(
            make_stack(peer_mac, PEER_IPV4, peer_link),
            SessionGeneration::new(8),
        );
        let peer_owner = TrustedCaller::new(99, 0, 0);
        let peer_id = peer
            .table_mut()
            .open(peer_owner, Some(UDP_ECHO_PORT))
            .unwrap();
        let guest_id = guest.table_mut().open(OWNER_A, None).unwrap();
        let dest = SocketAddrV4::new(PEER_IPV4, UDP_ECHO_PORT);
        let payload = b"echo-me";
        for now in 0u64..128 {
            peer.poll(now).unwrap();
            guest.poll(now).unwrap();
            let _ = guest.send(now, guest_id, OWNER_A, Some(dest), payload);
            peer.poll(now).unwrap();
            guest.poll(now).unwrap();
            peer_udp_echo(&mut peer, peer_id, peer_owner, now);
            guest.poll(now).unwrap();
            let mut buf = [0u8; 64];
            if let Ok(Some((from, len))) = guest.receive(guest_id, OWNER_A, &mut buf) {
                assert_eq!(from.addr, PEER_IPV4);
                assert_eq!(len, payload.len());
                assert_eq!(&buf[..len], payload);
                return;
            }
        }
        panic!("echo round trip timed out");
    }

    #[test]
    fn transport_queue_full_drops() {
        let mut t = heap_table(GEN);
        let id = t.open(OWNER_A, Some(5000)).unwrap();
        let from = SocketAddrV4::new(PEER_IPV4, 1234);
        let payload = [0u8; 4];
        for _ in 0..RX_QUEUE_CAP {
            t.enqueue(5000, from, &payload).unwrap();
        }
        assert_eq!(t.queued_datagrams(), RX_QUEUE_CAP);
        assert!(matches!(
            t.enqueue(5000, from, &payload),
            Err(RxDrop::QueueFull)
        ));
        assert_eq!(t.queued_datagrams(), RX_QUEUE_CAP);
        t.close(id, OWNER_A).unwrap();
        assert_eq!(t.queued_datagrams(), 0);
    }

    #[test]
    fn transport_connected_drops_foreign() {
        let mut transport = heap_transport(
            make_stack(GUEST_MAC, GUEST_IPV4, FakeLink::new(GUEST_MAC, true)),
            GEN,
        );
        let id = transport.table_mut().open(OWNER_A, Some(6000)).unwrap();
        let peer = SocketAddrV4::new(PEER_IPV4, 4000);
        transport.table_mut().connect(id, OWNER_A, peer).unwrap();
        let foreign = SocketAddrV4::new(Ipv4Addr::new([10, 77, 0, 9]), 4000);
        assert!(matches!(
            transport.table_mut().enqueue(6000, foreign, b"x"),
            Err(RxDrop::Foreign)
        ));
        transport.table_mut().enqueue(6000, peer, b"ok").unwrap();
        assert_eq!(transport.table().queued_datagrams(), 1);
    }

    #[test]
    fn transport_unbound_port_drops() {
        let mut transport = heap_transport(
            make_stack(GUEST_MAC, GUEST_IPV4, FakeLink::new(GUEST_MAC, true)),
            GEN,
        );
        assert!(matches!(
            transport
                .table_mut()
                .enqueue(9999, SocketAddrV4::new(PEER_IPV4, 1), b"a"),
            Err(RxDrop::Unbound)
        ));
    }

    #[test]
    fn transport_reset_and_holder_exit() {
        let mut transport = heap_transport(
            make_stack(GUEST_MAC, GUEST_IPV4, FakeLink::new(GUEST_MAC, true)),
            GEN,
        );
        let id = transport.table_mut().open(OWNER_A, Some(7000)).unwrap();
        transport
            .table_mut()
            .enqueue(7000, SocketAddrV4::new(PEER_IPV4, 1), b"q")
            .unwrap();
        transport.reset().unwrap();
        assert_eq!(transport.table().queued_datagrams(), 0);
        let mut t2 = heap_table(SessionGeneration::new(GEN.get() + 1));
        assert_eq!(
            t2.close(id, OWNER_A),
            Err(NetworkError::Denied(DenialReason::StaleGeneration))
        );
        let mut t3 = heap_table(GEN);
        let id2 = t3.open(OWNER_A, Some(7001)).unwrap();
        t3.enqueue(7001, SocketAddrV4::new(PEER_IPV4, 2), b"z")
            .unwrap();
        assert_eq!(t3.on_holder_exit(OWNER_A), 1);
        assert_eq!(t3.queued_datagrams(), 0);
        t3.close(id2, OWNER_A).ok();
    }

    #[test]
    fn transport_rx_queue_full_drops_with_stats() {
        let (guest_link, peer_link) = FakeLink::pair();
        let mut guest = heap_transport(
            make_stack(guest_link.link().mac, GUEST_IPV4, guest_link),
            GEN,
        );
        let mut peer = heap_transport(
            make_stack(peer_link.link().mac, PEER_IPV4, peer_link),
            SessionGeneration::new(2),
        );
        let guest_port = 8200u16;
        let guest_id = guest.table_mut().open(OWNER_A, Some(guest_port)).unwrap();
        let peer_id = peer.table_mut().open(OWNER_B, None).unwrap();
        let dest = SocketAddrV4::new(GUEST_IPV4, guest_port);
        let payload = b"p";
        for now in 0u64..(RX_QUEUE_CAP as u64 + 4) {
            for _ in 0..8 {
                guest.poll(now).unwrap();
                peer.poll(now).unwrap();
                if peer
                    .send(now, peer_id, OWNER_B, Some(dest), payload)
                    .is_ok()
                {
                    break;
                }
            }
            guest.poll(now).unwrap();
            peer.poll(now).unwrap();
        }
        assert_eq!(guest.stats().received, RX_QUEUE_CAP as u64);
        assert!(guest.stats().dropped_queue_full >= 1);
        assert_eq!(guest.table().queued_datagrams(), RX_QUEUE_CAP);
        let mut buf = [0u8; 8];
        for _ in 0..RX_QUEUE_CAP {
            assert!(guest
                .receive(guest_id, OWNER_A, &mut buf)
                .unwrap()
                .is_some());
        }
        assert_eq!(guest.table().queued_datagrams(), 0);
    }
}
