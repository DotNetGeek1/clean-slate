//! Bounded DNS codec (RFC 1035 subset), cache, and resolver over [`UdpTransport`].
//!
//! Supported subset: A/IN queries over UDP with RD=1, single question, first A answer.
//! CNAME chasing, DNS-over-TCP, and DNSSEC are deferred.
//!
//! Capability checks (`NET_RESOLVE`) are performed by the network service **above** this
//! layer; [`DnsResolver::resolve`] assumes the caller is already authorized.

use crate::addr::{Ipv4Addr, SocketAddrV4};
use crate::device::NetworkLink;
use crate::error::NetworkError;
use crate::limits::{MAX_DNS_LABEL_LEN, MAX_DNS_NAME_LEN, MAX_IN_FLIGHT_RESOLVER_QUERIES};
use crate::protocol::TrustedCaller;
use crate::session::{SessionGeneration, SessionId};
use crate::udp::{UdpTransport, MAX_UDP_PAYLOAD};

/// Maximum A records accepted in a response answer section.
pub const MAX_DNS_ANSWERS: usize = 8;

/// Fixed DNS cache entry count.
pub const DNS_CACHE_CAPACITY: usize = 16;

/// Minimum TTL stored in the cache (seconds).
pub const DNS_MIN_TTL_SECS: u32 = 1;

/// Maximum TTL stored in the cache (seconds).
pub const DNS_MAX_TTL_SECS: u32 = 86_400;

/// Resolver query timeout in monotonic ticks.
pub const DNS_QUERY_TIMEOUT_TICKS: u64 = 500;

/// Compression pointer follow hop limit.
pub const DNS_COMPRESSION_HOP_LIMIT: usize = 16;

const DNS_HEADER_LEN: usize = 12;
const QTYPE_A: u16 = 1;
const QCLASS_IN: u16 = 1;
const RR_TYPE_A: u16 = 1;
const RR_CLASS_IN: u16 = 1;

const FLAG_QR: u16 = 0x8000;
const FLAG_OPCODE_MASK: u16 = 0x7800;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RCODE_MASK: u16 = 0x000F;

const RCODE_NXDOMAIN: u8 = 3;

const PENDING_SLOTS: usize = MAX_IN_FLIGHT_RESOLVER_QUERIES as usize;

/// DNS wire parse/encode failures and resolver outcomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsError {
    InvalidName,
    Truncated,
    Malformed,
    IdMismatch,
    NotAResponse,
    CompressionLoop,
    PointerForward,
    TooManyRecords,
    UnsupportedType,
    NameNotFound,
    ServerFailure(u8),
    NoAddress,
    Timeout,
    QueueFull,
    Transport(NetworkError),
}

impl From<DnsError> for NetworkError {
    fn from(err: DnsError) -> Self {
        match err {
            DnsError::NameNotFound => NetworkError::NotFound,
            DnsError::Timeout => NetworkError::Timeout,
            DnsError::QueueFull => NetworkError::QueueFull,
            DnsError::Transport(e) => e,
            _ => NetworkError::Protocol,
        }
    }
}

/// Parsed DNS header (12 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self, DnsError> {
        if bytes.len() < DNS_HEADER_LEN {
            return Err(DnsError::Truncated);
        }
        Ok(Self {
            id: u16::from_be_bytes([bytes[0], bytes[1]]),
            flags: u16::from_be_bytes([bytes[2], bytes[3]]),
            qdcount: u16::from_be_bytes([bytes[4], bytes[5]]),
            ancount: u16::from_be_bytes([bytes[6], bytes[7]]),
            nscount: u16::from_be_bytes([bytes[8], bytes[9]]),
            arcount: u16::from_be_bytes([bytes[10], bytes[11]]),
        })
    }

    pub fn write(&self, out: &mut [u8]) -> Result<(), DnsError> {
        if out.len() < DNS_HEADER_LEN {
            return Err(DnsError::Truncated);
        }
        out[0..2].copy_from_slice(&self.id.to_be_bytes());
        out[2..4].copy_from_slice(&self.flags.to_be_bytes());
        out[4..6].copy_from_slice(&self.qdcount.to_be_bytes());
        out[6..8].copy_from_slice(&self.ancount.to_be_bytes());
        out[8..10].copy_from_slice(&self.nscount.to_be_bytes());
        out[10..12].copy_from_slice(&self.arcount.to_be_bytes());
        Ok(())
    }
}

/// First A record from a successful response parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DnsAnswer {
    pub ttl: u32,
    pub addr: Ipv4Addr,
}

/// Outcome of [`DnsResolver::resolve`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveOutcome {
    Cached { addr: Ipv4Addr, ttl: u32 },
    Pending { query_id: u32 },
}

/// Validates a host name for DNS encoding (labels 1..=63, total <= 253).
pub fn validate_dns_name(name: &str) -> Result<(), DnsError> {
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    if trimmed.is_empty() {
        return Err(DnsError::InvalidName);
    }
    if trimmed.len() > MAX_DNS_NAME_LEN {
        return Err(DnsError::InvalidName);
    }
    let mut total = 0usize;
    for label in trimmed.split('.') {
        if label.is_empty() {
            return Err(DnsError::InvalidName);
        }
        if label.len() > MAX_DNS_LABEL_LEN {
            return Err(DnsError::InvalidName);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(DnsError::InvalidName);
        }
        for ch in label.bytes() {
            let ok = ch.is_ascii_lowercase()
                || ch.is_ascii_uppercase()
                || ch.is_ascii_digit()
                || ch == b'-';
            if !ok {
                return Err(DnsError::InvalidName);
            }
        }
        total = total
            .checked_add(label.len())
            .and_then(|n| n.checked_add(1))
            .ok_or(DnsError::InvalidName)?;
    }
    if total > 0 {
        total = total.saturating_sub(1);
    }
    if total > MAX_DNS_NAME_LEN {
        return Err(DnsError::InvalidName);
    }
    Ok(())
}

fn encode_qname(name: &str, out: &mut [u8]) -> Result<usize, DnsError> {
    validate_dns_name(name)?;
    let trimmed = name.strip_suffix('.').unwrap_or(name);
    let mut offset = 0usize;
    for label in trimmed.split('.') {
        let len = label.len();
        if offset + 1 + len > out.len() {
            return Err(DnsError::Truncated);
        }
        out[offset] = len as u8;
        offset += 1;
        let dst = out
            .get_mut(offset..offset + len)
            .ok_or(DnsError::Truncated)?;
        dst.copy_from_slice(label.as_bytes());
        offset += len;
    }
    if offset >= out.len() {
        return Err(DnsError::Truncated);
    }
    out[offset] = 0;
    Ok(offset + 1)
}

/// Encodes a standard query (QTYPE A, QCLASS IN, RD=1) into `out`.
pub fn encode_query(id: u16, name: &str, out: &mut [u8]) -> Result<usize, DnsError> {
    if out.len() < DNS_HEADER_LEN + 5 {
        return Err(DnsError::Truncated);
    }
    let hdr = DnsHeader {
        id,
        flags: FLAG_RD,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };
    hdr.write(out)?;
    let name_off = DNS_HEADER_LEN;
    let name_len = encode_qname(name, out.get_mut(name_off..).ok_or(DnsError::Truncated)?)?;
    let qtype_off = name_off + name_len;
    if qtype_off + 4 > out.len() {
        return Err(DnsError::Truncated);
    }
    out[qtype_off..qtype_off + 2].copy_from_slice(&QTYPE_A.to_be_bytes());
    out[qtype_off + 2..qtype_off + 4].copy_from_slice(&QCLASS_IN.to_be_bytes());
    Ok(qtype_off + 4)
}

fn read_name_at_no_alloc(
    msg: &[u8],
    mut offset: usize,
    current_pos: usize,
    hops: &mut usize,
    out: &mut [u8],
) -> Result<(usize, usize), DnsError> {
    let mut out_len = 0usize;
    let mut first = true;
    let start = offset;
    let mut end_offset = offset;
    let mut followed_pointer = false;
    loop {
        if offset >= msg.len() {
            return Err(DnsError::Truncated);
        }
        let byte = msg[offset];
        if byte == 0 {
            if !followed_pointer {
                end_offset = offset + 1;
            }
            break;
        }
        if byte & 0xC0 == 0xC0 {
            if offset + 1 >= msg.len() {
                return Err(DnsError::Truncated);
            }
            let ptr = u16::from_be_bytes([byte, msg[offset + 1]]) & 0x3FFF;
            let ptr_usize = ptr as usize;
            if ptr_usize >= current_pos {
                return Err(DnsError::PointerForward);
            }
            if !followed_pointer {
                end_offset = offset + 2;
                followed_pointer = true;
            }
            *hops = hops.saturating_add(1);
            if *hops > DNS_COMPRESSION_HOP_LIMIT {
                return Err(DnsError::CompressionLoop);
            }
            offset = ptr_usize;
            continue;
        }
        if byte & 0xC0 != 0 {
            return Err(DnsError::Malformed);
        }
        let len = byte as usize;
        offset += 1;
        if offset + len > msg.len() {
            return Err(DnsError::Truncated);
        }
        if !first {
            if out_len >= out.len() {
                return Err(DnsError::Malformed);
            }
            out[out_len] = b'.';
            out_len += 1;
        }
        first = false;
        let label = msg.get(offset..offset + len).ok_or(DnsError::Truncated)?;
        if out_len + len > out.len() {
            return Err(DnsError::Malformed);
        }
        out[out_len..out_len + len].copy_from_slice(label);
        out_len += len;
        offset += len;
    }
    let _ = start;
    Ok((out_len, end_offset))
}

fn skip_name(msg: &[u8], offset: usize, current_pos: usize) -> Result<usize, DnsError> {
    let mut hops = 0usize;
    let mut scratch = [0u8; MAX_DNS_NAME_LEN];
    let (_, end) = read_name_at_no_alloc(msg, offset, current_pos, &mut hops, &mut scratch)?;
    Ok(end)
}

fn skip_rr(msg: &[u8], offset: usize, current_pos: usize) -> Result<(usize, u16, u16), DnsError> {
    let name_end = skip_name(msg, offset, current_pos)?;
    if name_end + 10 > msg.len() {
        return Err(DnsError::Truncated);
    }
    let rtype = u16::from_be_bytes([msg[name_end], msg[name_end + 1]]);
    let rclass = u16::from_be_bytes([msg[name_end + 2], msg[name_end + 3]]);
    let _ttl = u32::from_be_bytes([
        msg[name_end + 4],
        msg[name_end + 5],
        msg[name_end + 6],
        msg[name_end + 7],
    ]);
    let rdlen = u16::from_be_bytes([msg[name_end + 8], msg[name_end + 9]]) as usize;
    let data_end = name_end
        .checked_add(10)
        .and_then(|n| n.checked_add(rdlen))
        .ok_or(DnsError::Malformed)?;
    if data_end > msg.len() {
        return Err(DnsError::Truncated);
    }
    Ok((data_end, rtype, rclass))
}

/// Parses a DNS response and returns the first A record for `expected_name`.
pub fn parse_response(
    bytes: &[u8],
    expected_id: u16,
    expected_name: &str,
) -> Result<DnsAnswer, DnsError> {
    let hdr = DnsHeader::parse(bytes)?;
    if hdr.id != expected_id {
        return Err(DnsError::IdMismatch);
    }
    if hdr.flags & FLAG_QR == 0 {
        return Err(DnsError::NotAResponse);
    }
    if hdr.flags & FLAG_TC != 0 {
        return Err(DnsError::Truncated);
    }
    if (hdr.flags & FLAG_OPCODE_MASK) >> 11 != 0 {
        return Err(DnsError::Malformed);
    }
    let rcode = (hdr.flags & FLAG_RCODE_MASK) as u8;
    if rcode == RCODE_NXDOMAIN {
        return Err(DnsError::NameNotFound);
    }
    if rcode != 0 {
        return Err(DnsError::ServerFailure(rcode));
    }
    if hdr.qdcount > 1 {
        return Err(DnsError::Malformed);
    }
    if hdr.ancount as usize > MAX_DNS_ANSWERS {
        return Err(DnsError::TooManyRecords);
    }

    let mut offset = DNS_HEADER_LEN;
    let mut hops = 0usize;
    let mut qname_buf = [0u8; MAX_DNS_NAME_LEN];
    let (qname_len, qend) =
        read_name_at_no_alloc(bytes, offset, offset, &mut hops, &mut qname_buf)?;
    offset = qend;
    if offset + 4 > bytes.len() {
        return Err(DnsError::Truncated);
    }
    offset += 4;

    let expected = expected_name.strip_suffix('.').unwrap_or(expected_name);
    if qname_len != expected.len() {
        return Err(DnsError::Malformed);
    }
    if !qname_buf
        .get(0..qname_len)
        .ok_or(DnsError::Malformed)?
        .eq_ignore_ascii_case(expected.as_bytes())
    {
        return Err(DnsError::Malformed);
    }

    let mut found: Option<DnsAnswer> = None;
    for _ in 0..hdr.ancount {
        let (rr_end, rtype, rclass) = skip_rr(bytes, offset, offset)?;
        if rtype == RR_TYPE_A && rclass == RR_CLASS_IN {
            let name_end = skip_name(bytes, offset, offset)?;
            let ttl = u32::from_be_bytes([
                bytes[name_end + 4],
                bytes[name_end + 5],
                bytes[name_end + 6],
                bytes[name_end + 7],
            ]);
            let rdlen = u16::from_be_bytes([bytes[name_end + 8], bytes[name_end + 9]]) as usize;
            if rdlen != 4 {
                return Err(DnsError::Malformed);
            }
            let data_start = name_end + 10;
            let octets = bytes
                .get(data_start..data_start + 4)
                .ok_or(DnsError::Truncated)?;
            let addr = Ipv4Addr::new([octets[0], octets[1], octets[2], octets[3]]);
            if found.is_none() {
                found = Some(DnsAnswer { ttl, addr });
            }
        }
        offset = rr_end;
    }

    for _ in 0..hdr.nscount {
        let (end, _, _) = skip_rr(bytes, offset, offset)?;
        offset = end;
    }
    for _ in 0..hdr.arcount {
        let (end, _, _) = skip_rr(bytes, offset, offset)?;
        offset = end;
    }

    found.ok_or(DnsError::NoAddress)
}

#[derive(Clone, Copy)]
struct CacheEntry {
    name_len: u8,
    name: [u8; MAX_DNS_NAME_LEN],
    addr: Ipv4Addr,
    expires_at: u64,
}

impl CacheEntry {
    const fn empty() -> Self {
        Self {
            name_len: 0,
            name: [0; MAX_DNS_NAME_LEN],
            addr: Ipv4Addr::new([0, 0, 0, 0]),
            expires_at: 0,
        }
    }

    fn name_str(&self) -> &str {
        core::str::from_utf8(self.name.get(0..self.name_len as usize).unwrap_or(&[])).unwrap_or("")
    }
}

/// Fixed-capacity DNS answer cache with TTL clamping and soonest-expiry eviction.
pub struct DnsCache {
    entries: [CacheEntry; DNS_CACHE_CAPACITY],
    len: u8,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsCache {
    pub const fn new() -> Self {
        Self {
            entries: [CacheEntry::empty(); DNS_CACHE_CAPACITY],
            len: 0,
        }
    }

    pub fn clear(&mut self) {
        self.len = 0;
        for e in &mut self.entries {
            *e = CacheEntry::empty();
        }
    }

    fn clamp_ttl(ttl_secs: u32) -> u32 {
        ttl_secs.clamp(DNS_MIN_TTL_SECS, DNS_MAX_TTL_SECS)
    }

    pub fn insert(
        &mut self,
        name: &str,
        addr: Ipv4Addr,
        ttl_secs: u32,
        now_tick: u64,
        ticks_per_sec: u64,
    ) -> Result<(), DnsError> {
        validate_dns_name(name)?;
        let ttl = Self::clamp_ttl(ttl_secs);
        let tps = ticks_per_sec.max(1);
        let ttl_ticks = (ttl as u64).saturating_mul(tps);
        let expires = now_tick.saturating_add(ttl_ticks);

        let name_bytes = name.as_bytes();
        if name_bytes.len() > MAX_DNS_NAME_LEN {
            return Err(DnsError::InvalidName);
        }

        for i in 0..self.len as usize {
            if self.entries[i].name_str().eq_ignore_ascii_case(name) {
                self.entries[i].addr = addr;
                self.entries[i].expires_at = expires;
                return Ok(());
            }
        }

        let slot = if (self.len as usize) < DNS_CACHE_CAPACITY {
            let idx = self.len as usize;
            self.len += 1;
            idx
        } else {
            let mut victim = 0usize;
            let mut min_exp = self.entries[0].expires_at;
            for i in 1..DNS_CACHE_CAPACITY {
                if self.entries[i].expires_at < min_exp {
                    min_exp = self.entries[i].expires_at;
                    victim = i;
                }
            }
            victim
        };

        let entry = &mut self.entries[slot];
        entry.name_len = name_bytes.len() as u8;
        entry.name = [0; MAX_DNS_NAME_LEN];
        entry
            .name
            .get_mut(0..name_bytes.len())
            .ok_or(DnsError::Malformed)?
            .copy_from_slice(name_bytes);
        entry.addr = addr;
        entry.expires_at = expires;
        Ok(())
    }

    pub fn lookup(&self, name: &str, now_tick: u64) -> Option<(Ipv4Addr, u32)> {
        let tps = 1u64;
        for i in 0..self.len as usize {
            let e = &self.entries[i];
            if e.name_str().eq_ignore_ascii_case(name) {
                if now_tick >= e.expires_at {
                    return None;
                }
                let remaining_ticks = e.expires_at - now_tick;
                let remaining_secs = (remaining_ticks / tps.max(1)) as u32;
                return Some((e.addr, remaining_secs.max(1)));
            }
        }
        None
    }

    pub fn lookup_with_tps(
        &self,
        name: &str,
        now_tick: u64,
        ticks_per_sec: u64,
    ) -> Option<(Ipv4Addr, u32)> {
        let tps = ticks_per_sec.max(1);
        for i in 0..self.len as usize {
            let e = &self.entries[i];
            if e.name_str().eq_ignore_ascii_case(name) {
                if now_tick >= e.expires_at {
                    return None;
                }
                let remaining_ticks = e.expires_at - now_tick;
                let remaining_secs = (remaining_ticks / tps) as u32;
                return Some((e.addr, remaining_secs.max(1)));
            }
        }
        None
    }
}

#[derive(Clone, Copy)]
enum PendingState {
    InFlight,
    DoneOk { addr: Ipv4Addr, ttl: u32 },
    DoneErr(DnsError),
}

#[derive(Clone, Copy)]
struct PendingQuery {
    live: bool,
    query_id: u32,
    dns_id: u16,
    owner: TrustedCaller,
    name_len: u8,
    name: [u8; MAX_DNS_NAME_LEN],
    endpoint: SessionId,
    deadline: u64,
    query_sent: bool,
    state: PendingState,
}

impl PendingQuery {
    const fn vacant() -> Self {
        Self {
            live: false,
            query_id: 0,
            dns_id: 0,
            owner: TrustedCaller::new(0, 0, 0),
            name_len: 0,
            name: [0; MAX_DNS_NAME_LEN],
            endpoint: SessionId::new(SessionGeneration::new(0), 0),
            deadline: 0,
            query_sent: false,
            state: PendingState::InFlight,
        }
    }
}

/// Resolver statistics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DnsResolverStats {
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub queries_sent: u64,
    pub responses_ok: u64,
    pub dropped_mismatch: u64,
    pub dropped_foreign_source: u64,
    pub dropped_malformed: u64,
    pub timeouts: u64,
}

/// DNS resolver over UDP with bounded in-flight queries and a fixed cache.
pub struct DnsResolver<L: NetworkLink> {
    udp: UdpTransport<L>,
    cache: DnsCache,
    server: SocketAddrV4,
    pending: [PendingQuery; PENDING_SLOTS],
    next_query_id: u32,
    dns_id_counter: u16,
    generation: SessionGeneration,
    ticks_per_sec: u64,
    stats: DnsResolverStats,
}

impl<L: NetworkLink> DnsResolver<L> {
    /// Default monotonic ticks per second for cache expiry (host tests / service tick rate).
    pub const DEFAULT_TICKS_PER_SEC: u64 = 1000;

    pub fn new(udp: UdpTransport<L>, server: SocketAddrV4) -> Self {
        Self::with_ticks(udp, server, Self::DEFAULT_TICKS_PER_SEC)
    }

    pub fn with_ticks(udp: UdpTransport<L>, server: SocketAddrV4, ticks_per_sec: u64) -> Self {
        let generation = udp.table().generation();
        Self {
            udp,
            cache: DnsCache::new(),
            server,
            pending: [PendingQuery::vacant(); PENDING_SLOTS],
            next_query_id: 1,
            dns_id_counter: 1,
            generation,
            ticks_per_sec: ticks_per_sec.max(1),
            stats: DnsResolverStats::default(),
        }
    }

    /// Initializes a resolver at `slot` without constructing a multi-megabyte `Self` on the stack.
    ///
    /// # Safety
    ///
    /// `slot` must point to valid uninitialized storage large enough for [`DnsResolver`], and
    /// callers must not alias `slot` until initialization completes.
    pub unsafe fn init_in_place(
        slot: *mut Self,
        stack: crate::stack::L3Stack<L>,
        generation: SessionGeneration,
        server: SocketAddrV4,
        ticks_per_sec: u64,
    ) {
        unsafe {
            UdpTransport::init_in_place(core::ptr::addr_of_mut!((*slot).udp), stack, generation);
            (*slot).cache = DnsCache::new();
            (*slot).server = server;
            (*slot).pending = [PendingQuery::vacant(); PENDING_SLOTS];
            (*slot).next_query_id = 1;
            (*slot).dns_id_counter = 1;
            (*slot).generation = generation;
            (*slot).ticks_per_sec = ticks_per_sec.max(1);
            (*slot).stats = DnsResolverStats::default();
        }
    }

    /// Heap-backed resolver for environments that cannot place large protocol state on thread stacks.
    #[cfg(feature = "alloc")]
    pub fn alloc_boxed(
        stack: crate::stack::L3Stack<L>,
        generation: SessionGeneration,
        server: SocketAddrV4,
        ticks_per_sec: u64,
    ) -> alloc::boxed::Box<Self> {
        let layout = core::alloc::Layout::new::<Self>();
        let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) as *mut Self };
        if ptr.is_null() {
            alloc::alloc::handle_alloc_error(layout);
        }
        unsafe {
            Self::init_in_place(ptr, stack, generation, server, ticks_per_sec);
            alloc::boxed::Box::from_raw(ptr)
        }
    }

    pub fn stats(&self) -> DnsResolverStats {
        self.stats
    }

    pub fn cache(&self) -> &DnsCache {
        &self.cache
    }

    pub fn udp_mut(&mut self) -> &mut UdpTransport<L> {
        &mut self.udp
    }

    fn alloc_dns_id(&mut self) -> u16 {
        let gen = self.generation.get() as u16;
        let id = self.dns_id_counter;
        self.dns_id_counter = self.dns_id_counter.wrapping_add(1);
        id ^ gen
    }

    fn alloc_query_id(&mut self) -> u32 {
        let id = self.next_query_id;
        self.next_query_id = self.next_query_id.wrapping_add(1);
        id
    }

    fn find_pending_slot(&self) -> Option<usize> {
        self.pending.iter().position(|p| !p.live)
    }

    fn store_name(name: &str) -> Result<([u8; MAX_DNS_NAME_LEN], u8), DnsError> {
        validate_dns_name(name)?;
        let bytes = name.as_bytes();
        if bytes.len() > MAX_DNS_NAME_LEN {
            return Err(DnsError::InvalidName);
        }
        let mut buf = [0u8; MAX_DNS_NAME_LEN];
        buf.get_mut(0..bytes.len())
            .ok_or(DnsError::Malformed)?
            .copy_from_slice(bytes);
        Ok((buf, bytes.len() as u8))
    }

    /// Starts or completes a resolution. Caller must already hold `NET_RESOLVE` authorization.
    pub fn resolve(
        &mut self,
        now: u64,
        owner: TrustedCaller,
        name: &str,
    ) -> Result<ResolveOutcome, DnsError> {
        if let Some((addr, ttl)) = self.cache.lookup_with_tps(name, now, self.ticks_per_sec) {
            self.stats.cache_hits += 1;
            return Ok(ResolveOutcome::Cached { addr, ttl });
        }
        self.stats.cache_misses += 1;
        validate_dns_name(name)?;

        let slot = self.find_pending_slot().ok_or(DnsError::QueueFull)?;
        let endpoint = self
            .udp
            .table_mut()
            .open(owner, None)
            .map_err(DnsError::Transport)?;
        self.udp
            .table_mut()
            .connect(endpoint, owner, self.server)
            .map_err(DnsError::Transport)?;

        let dns_id = self.alloc_dns_id();
        let query_id = self.alloc_query_id();
        let (name_buf, name_len) = Self::store_name(name)?;

        let deadline = now.saturating_add(DNS_QUERY_TIMEOUT_TICKS);
        let mut query_sent = false;
        let mut payload = [0u8; 512];
        let plen = encode_query(dns_id, name, &mut payload)?;
        match self
            .udp
            .send(now, endpoint, owner, Some(self.server), &payload[..plen])
        {
            Ok(_) => {
                self.stats.queries_sent += 1;
                query_sent = true;
            }
            Err(NetworkError::Unreachable) => {}
            Err(e) => {
                let _ = self.udp.table_mut().close(endpoint, owner);
                return Err(DnsError::Transport(e));
            }
        }

        self.pending[slot] = PendingQuery {
            live: true,
            query_id,
            dns_id,
            owner,
            name_len,
            name: name_buf,
            endpoint,
            deadline,
            query_sent,
            state: PendingState::InFlight,
        };
        Ok(ResolveOutcome::Pending { query_id })
    }

    fn pending_name(p: &PendingQuery) -> &str {
        core::str::from_utf8(p.name.get(0..p.name_len as usize).unwrap_or(&[])).unwrap_or("")
    }

    fn finish_pending(&mut self, index: usize, result: PendingState) {
        if matches!(self.pending[index].state, PendingState::InFlight) {
            let owner = self.pending[index].owner;
            let endpoint = self.pending[index].endpoint;
            let _ = self.udp.table_mut().close(endpoint, owner);
        }
        self.pending[index].state = result;
    }

    pub fn poll(&mut self, now: u64) -> Result<(), DnsError> {
        for i in 0..PENDING_SLOTS {
            if self.pending[i].live
                && matches!(self.pending[i].state, PendingState::InFlight)
                && now > self.pending[i].deadline
            {
                self.stats.timeouts += 1;
                self.finish_pending(i, PendingState::DoneErr(DnsError::Timeout));
            }
        }

        self.udp.poll(now).map_err(DnsError::Transport)?;

        let mut buf = [0u8; MAX_UDP_PAYLOAD];
        for i in 0..PENDING_SLOTS {
            if !self.pending[i].live || !matches!(self.pending[i].state, PendingState::InFlight) {
                continue;
            }
            if !self.pending[i].query_sent {
                let owner = self.pending[i].owner;
                let endpoint = self.pending[i].endpoint;
                let dns_id = self.pending[i].dns_id;
                let name = Self::pending_name(&self.pending[i]);
                let mut payload = [0u8; 512];
                if let Ok(plen) = encode_query(dns_id, name, &mut payload) {
                    if self
                        .udp
                        .send(now, endpoint, owner, Some(self.server), &payload[..plen])
                        .is_ok()
                    {
                        self.stats.queries_sent += 1;
                        self.pending[i].query_sent = true;
                    }
                }
            }
            let owner = self.pending[i].owner;
            let endpoint = self.pending[i].endpoint;
            let dns_id = self.pending[i].dns_id;
            let name = Self::pending_name(&self.pending[i]);
            while let Some((from, len)) = self
                .udp
                .receive(endpoint, owner, &mut buf)
                .map_err(DnsError::Transport)?
            {
                if from.addr != self.server.addr || from.port != self.server.port {
                    self.stats.dropped_foreign_source += 1;
                    continue;
                }
                let slice = buf.get(0..len).unwrap_or(&[]);
                match parse_response(slice, dns_id, name) {
                    Ok(answer) => {
                        let _ = self.cache.insert(
                            name,
                            answer.addr,
                            answer.ttl,
                            now,
                            self.ticks_per_sec,
                        );
                        self.stats.responses_ok += 1;
                        self.finish_pending(
                            i,
                            PendingState::DoneOk {
                                addr: answer.addr,
                                ttl: answer.ttl,
                            },
                        );
                        break;
                    }
                    Err(DnsError::IdMismatch) | Err(DnsError::Malformed) => {
                        self.stats.dropped_mismatch += 1;
                    }
                    Err(
                        e @ (DnsError::NameNotFound
                        | DnsError::ServerFailure(_)
                        | DnsError::NoAddress),
                    ) => {
                        self.finish_pending(i, PendingState::DoneErr(e));
                        break;
                    }
                    Err(_) => {
                        self.stats.dropped_malformed += 1;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn take_result(
        &mut self,
        query_id: u32,
        owner: TrustedCaller,
    ) -> Option<Result<(Ipv4Addr, u32), DnsError>> {
        for i in 0..PENDING_SLOTS {
            if self.pending[i].live
                && self.pending[i].query_id == query_id
                && self.pending[i].owner == owner
            {
                let state = self.pending[i].state;
                if matches!(state, PendingState::InFlight) {
                    return None;
                }
                self.pending[i].live = false;
                return Some(match state {
                    PendingState::DoneOk { addr, ttl } => Ok((addr, ttl)),
                    PendingState::DoneErr(e) => Err(e),
                    PendingState::InFlight => None?,
                });
            }
        }
        None
    }

    pub fn on_holder_exit(&mut self, owner: TrustedCaller) {
        for i in 0..PENDING_SLOTS {
            if self.pending[i].live && self.pending[i].owner == owner {
                let endpoint = self.pending[i].endpoint;
                let _ = self.udp.table_mut().close(endpoint, owner);
                self.pending[i] = PendingQuery::vacant();
            }
        }
        self.udp.table_mut().on_holder_exit(owner);
    }

    pub fn reset(&mut self) -> Result<(), DnsError> {
        for i in 0..PENDING_SLOTS {
            if self.pending[i].live {
                let owner = self.pending[i].owner;
                let endpoint = self.pending[i].endpoint;
                let _ = self.udp.table_mut().close(endpoint, owner);
            }
            self.pending[i] = PendingQuery::vacant();
        }
        self.cache.clear();
        self.stats = DnsResolverStats::default();
        self.dns_id_counter = 1;
        self.udp.reset().map_err(DnsError::Transport)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{FIXTURE_A_RECORD, FIXTURE_A_TTL_SECS, FIXTURE_HOSTNAME};

    fn build_valid_response(id: u16, name: &str, addr: Ipv4Addr, ttl: u32) -> Vec<u8> {
        let mut msg = Vec::new();
        let hdr = DnsHeader {
            id,
            flags: 0x8480,
            qdcount: 1,
            ancount: 1,
            nscount: 0,
            arcount: 0,
        };
        let mut head = [0u8; 12];
        hdr.write(&mut head).unwrap();
        msg.extend_from_slice(&head);
        let mut q = [0u8; 64];
        let qlen = encode_qname(name, &mut q).unwrap();
        msg.extend_from_slice(&q[..qlen]);
        msg.extend_from_slice(&QTYPE_A.to_be_bytes());
        msg.extend_from_slice(&QCLASS_IN.to_be_bytes());
        let qname_start = 12usize;
        msg.push(0xC0 | ((qname_start >> 8) as u8));
        msg.push((qname_start & 0xFF) as u8);
        msg.extend_from_slice(&RR_TYPE_A.to_be_bytes());
        msg.extend_from_slice(&RR_CLASS_IN.to_be_bytes());
        msg.extend_from_slice(&ttl.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&addr.octets());
        msg
    }

    #[test]
    fn encode_query_valid() {
        let mut buf = [0u8; 128];
        let n = encode_query(0x1234, FIXTURE_HOSTNAME, &mut buf).unwrap();
        assert!(n > DNS_HEADER_LEN);
        let hdr = DnsHeader::parse(&buf).unwrap();
        assert_eq!(hdr.id, 0x1234);
        assert_ne!(hdr.flags & FLAG_RD, 0);
    }

    #[test]
    fn name_validation_cases() {
        assert!(validate_dns_name("").is_err());
        assert!(validate_dns_name("a..b").is_err());
        assert!(validate_dns_name(&"a".repeat(64)).is_err());
        assert!(validate_dns_name(&format!("{}.x", "a".repeat(250))).is_err());
        assert!(validate_dns_name("bad_underscore").is_err());
        assert!(validate_dns_name("-bad.com").is_err());
        assert!(validate_dns_name("bad-.com").is_err());
        assert!(validate_dns_name("ok.example.com").is_ok());
        assert!(validate_dns_name("ok.example.com.").is_ok());
    }

    #[test]
    fn question_section_bounds() {
        let id = 42;
        let resp = build_valid_response(id, FIXTURE_HOSTNAME, FIXTURE_A_RECORD, FIXTURE_A_TTL_SECS);
        let mut hops = 0usize;
        let mut buf = [0u8; MAX_DNS_NAME_LEN];
        let (qlen, qend) =
            read_name_at_no_alloc(&resp, DNS_HEADER_LEN, DNS_HEADER_LEN, &mut hops, &mut buf)
                .unwrap();
        assert_eq!(qlen, FIXTURE_HOSTNAME.len());
        assert_eq!(qend, 33 - 4);
        let rr = skip_rr(&resp, qend + 4, qend + 4).unwrap();
        assert_eq!(rr, (resp.len(), RR_TYPE_A, RR_CLASS_IN));
    }

    #[test]
    fn parse_response_valid_a() {
        let id = 42;
        let resp = build_valid_response(id, FIXTURE_HOSTNAME, FIXTURE_A_RECORD, FIXTURE_A_TTL_SECS);
        let ans = parse_response(&resp, id, FIXTURE_HOSTNAME).unwrap();
        assert_eq!(ans.addr, FIXTURE_A_RECORD);
        assert_eq!(ans.ttl, FIXTURE_A_TTL_SECS);
    }

    #[test]
    fn parse_nxdomain_and_servfail() {
        let id = 7;
        let mut resp = build_valid_response(id, "x.test", FIXTURE_A_RECORD, 60);
        resp[3] = RCODE_NXDOMAIN;
        assert_eq!(
            parse_response(&resp, id, "x.test"),
            Err(DnsError::NameNotFound)
        );
        resp[3] = 2;
        assert_eq!(
            parse_response(&resp, id, "x.test"),
            Err(DnsError::ServerFailure(2))
        );
    }

    #[test]
    fn parse_truncated_tc_id_qr() {
        let id = 1;
        let resp = build_valid_response(id, FIXTURE_HOSTNAME, FIXTURE_A_RECORD, 60);
        assert_eq!(
            parse_response(&resp, id + 1, FIXTURE_HOSTNAME),
            Err(DnsError::IdMismatch)
        );
        let mut qr0 = resp.clone();
        qr0[2] &= 0x7F;
        assert_eq!(
            parse_response(&qr0, id, FIXTURE_HOSTNAME),
            Err(DnsError::NotAResponse)
        );
        let mut tc = resp.clone();
        tc[2] |= 0x02;
        assert_eq!(
            parse_response(&tc, id, FIXTURE_HOSTNAME),
            Err(DnsError::Truncated)
        );
    }

    #[test]
    fn parse_truncated_slices_no_panic() {
        let id = 9;
        let resp = build_valid_response(id, FIXTURE_HOSTNAME, FIXTURE_A_RECORD, 60);
        for len in 0..resp.len() {
            let _ = parse_response(&resp[..len], id, FIXTURE_HOSTNAME);
        }
    }

    #[test]
    fn parse_random_lcg_no_panic() {
        let mut state = 0xCAFE_BABE_u32;
        let mut buf = [0u8; 512];
        for _ in 0..256 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let len = (state as usize) % (buf.len() + 1);
            for byte in buf.iter_mut().take(len) {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = (state >> 16) as u8;
            }
            let _ = parse_response(&buf[..len], 1, FIXTURE_HOSTNAME);
        }
    }

    #[test]
    fn cache_insert_lookup_expiry() {
        let mut cache = DnsCache::new();
        let addr = FIXTURE_A_RECORD;
        cache.insert(FIXTURE_HOSTNAME, addr, 10, 0, 1).unwrap();
        assert_eq!(
            cache.lookup_with_tps(FIXTURE_HOSTNAME, 5, 1),
            Some((addr, 5))
        );
        assert!(cache.lookup_with_tps(FIXTURE_HOSTNAME, 10, 1).is_none());
        cache.insert(FIXTURE_HOSTNAME, addr, 0, 0, 1).unwrap();
        let (_, ttl) = cache.lookup_with_tps(FIXTURE_HOSTNAME, 0, 1).unwrap();
        assert_eq!(ttl, DNS_MIN_TTL_SECS);
        cache.clear();
        assert!(cache.lookup_with_tps(FIXTURE_HOSTNAME, 0, 1).is_none());
    }

    #[cfg(feature = "alloc")]
    mod resolver_tests {
        use super::*;
        use crate::addr::SocketAddrV4;
        use crate::fake::FakeLink;
        use crate::fixture::{
            DNS_SERVER_ADDR, FIXTURE_A_RECORD, FIXTURE_A_TTL_SECS, FIXTURE_HOSTNAME, GUEST_IPV4,
            GUEST_MAC, PEER_IPV4, PEER_MAC,
        };
        use crate::session::SessionGeneration;
        use crate::stack::L3Stack;
        use crate::udp::UdpTransport;

        const OWNER: TrustedCaller = TrustedCaller::new(1, 0, 0);
        const OTHER: TrustedCaller = TrustedCaller::new(2, 0, 0);
        const GEN: SessionGeneration = SessionGeneration::new(3);
        const TPS: u64 = 1000;

        fn run_on_large_stack<F: FnOnce() + Send + 'static>(f: F) {
            std::thread::Builder::new()
                .stack_size(8 * 1024 * 1024)
                .spawn(f)
                .expect("spawn large-stack test thread")
                .join()
                .expect("large-stack test thread");
        }

        struct TestDnsServer {
            transport: std::boxed::Box<UdpTransport<FakeLink>>,
            owner: TrustedCaller,
            listen: Option<SessionId>,
        }

        impl TestDnsServer {
            fn new(link: FakeLink) -> Self {
                let stack = L3Stack::new(link, PEER_MAC, PEER_IPV4, 1000);
                let mut transport = UdpTransport::alloc_boxed(stack, GEN);
                transport
                    .stack_mut()
                    .arp_cache_mut()
                    .insert(GUEST_IPV4, GUEST_MAC, 0);
                let owner = TrustedCaller::new(99, 0, 0);
                Self {
                    transport,
                    owner,
                    listen: None,
                }
            }

            fn ensure_bind53(&mut self) -> SessionId {
                if let Some(id) = self.listen {
                    return id;
                }
                let id = self
                    .transport
                    .table_mut()
                    .open(self.owner, Some(53))
                    .unwrap();
                self.listen = Some(id);
                id
            }

            fn poll_handle(&mut self, now: u64) {
                self.transport.poll(now).unwrap();
                let id = self.ensure_bind53();
                let mut buf = [0u8; MAX_UDP_PAYLOAD];
                if let Ok(Some((from, len))) = self.transport.receive(id, self.owner, &mut buf) {
                    let slice = &buf[..len];
                    let hdr = DnsHeader::parse(slice).unwrap();
                    let mut hops = 0;
                    let mut qbuf = [0u8; MAX_DNS_NAME_LEN];
                    let (qlen, qend) = read_name_at_no_alloc(
                        slice,
                        DNS_HEADER_LEN,
                        DNS_HEADER_LEN,
                        &mut hops,
                        &mut qbuf,
                    )
                    .unwrap();
                    let qname = core::str::from_utf8(&qbuf[..qlen]).unwrap_or("");
                    let qtype = u16::from_be_bytes([slice[qend], slice[qend + 1]]);
                    let mut out = [0u8; 512];
                    let response =
                        if qtype == QTYPE_A && qname.eq_ignore_ascii_case(FIXTURE_HOSTNAME) {
                            build_valid_response(
                                hdr.id,
                                FIXTURE_HOSTNAME,
                                FIXTURE_A_RECORD,
                                FIXTURE_A_TTL_SECS,
                            )
                        } else {
                            let mut r = build_valid_response(hdr.id, qname, FIXTURE_A_RECORD, 60);
                            r[3] = RCODE_NXDOMAIN;
                            r
                        };
                    let n = response.len().min(out.len());
                    out[..n].copy_from_slice(&response[..n]);
                    let _ = self
                        .transport
                        .send(now, id, self.owner, Some(from), &out[..n]);
                }
            }
        }

        fn make_resolver(link: FakeLink) -> DnsResolver<FakeLink> {
            let stack = L3Stack::new(link, GUEST_MAC, GUEST_IPV4, 1000);
            let mut udp = UdpTransport::new(stack, GEN);
            udp.stack_mut()
                .arp_cache_mut()
                .insert(PEER_IPV4, PEER_MAC, 0);
            DnsResolver::with_ticks(udp, DNS_SERVER_ADDR, TPS)
        }

        fn pump_both(
            resolver: &mut DnsResolver<FakeLink>,
            server: &mut TestDnsServer,
            now: u64,
            rounds: u64,
        ) {
            for t in now..now + rounds {
                server.poll_handle(t);
                let _ = resolver.poll(t);
            }
        }

        #[test]
        fn resolver_happy_path_and_cache() {
            run_on_large_stack(|| {
                let (a, b) = FakeLink::pair();
                let mut server = TestDnsServer::new(b);
                server.ensure_bind53();
                let mut resolver = make_resolver(a);
                let out = resolver.resolve(0, OWNER, FIXTURE_HOSTNAME).unwrap();
                let qid = match out {
                    ResolveOutcome::Pending { query_id } => query_id,
                    _ => panic!("expected pending"),
                };
                pump_both(&mut resolver, &mut server, 0, 200);
                let (addr, ttl) = resolver.take_result(qid, OWNER).unwrap().unwrap();
                assert_eq!(addr, FIXTURE_A_RECORD);
                assert_eq!(ttl, FIXTURE_A_TTL_SECS);
                let cached = resolver.resolve(100, OWNER, FIXTURE_HOSTNAME).unwrap();
                assert!(matches!(cached, ResolveOutcome::Cached { .. }));
            });
        }

        #[test]
        fn resolver_nxdomain() {
            run_on_large_stack(|| {
                let (a, b) = FakeLink::pair();
                let mut server = TestDnsServer::new(b);
                server.ensure_bind53();
                let mut resolver = make_resolver(a);
                let out = resolver.resolve(0, OWNER, "nope.test").unwrap();
                let qid = match out {
                    ResolveOutcome::Pending { query_id } => query_id,
                    _ => panic!("expected pending"),
                };
                pump_both(&mut resolver, &mut server, 0, 200);
                assert_eq!(
                    resolver.take_result(qid, OWNER).unwrap(),
                    Err(DnsError::NameNotFound)
                );
            });
        }

        #[test]
        fn resolver_timeout_and_foreign_drop() {
            run_on_large_stack(|| {
                let (a, _b) = FakeLink::pair();
                let mut resolver = make_resolver(a);
                let out = resolver.resolve(0, OWNER, FIXTURE_HOSTNAME).unwrap();
                let qid = match out {
                    ResolveOutcome::Pending { query_id } => query_id,
                    _ => panic!("expected pending"),
                };
                for t in 0..DNS_QUERY_TIMEOUT_TICKS + 10 {
                    let _ = resolver.poll(t);
                }
                assert_eq!(
                    resolver.take_result(qid, OWNER).unwrap(),
                    Err(DnsError::Timeout)
                );
                let baseline = resolver.udp_mut().table().endpoints_in_use();
                assert_eq!(baseline, 0);

                let (a2, b2) = FakeLink::pair();
                let mut server = TestDnsServer::new(b2);
                server.ensure_bind53();
                let mut resolver2 = make_resolver(a2);
                let out2 = resolver2.resolve(0, OWNER, FIXTURE_HOSTNAME).unwrap();
                let qid2 = match out2 {
                    ResolveOutcome::Pending { query_id } => query_id,
                    _ => panic!("expected pending"),
                };
                let foreign = SocketAddrV4::new(Ipv4Addr::new([9, 9, 9, 9]), 53);
                let bogus = build_valid_response(1, FIXTURE_HOSTNAME, FIXTURE_A_RECORD, 60);
                let ep = resolver2.udp_mut().table().endpoints_in_use();
                assert_eq!(ep, 1);
                pump_both(&mut resolver2, &mut server, 0, 5);
                let _ = foreign;
                let _ = bogus;
                pump_both(&mut resolver2, &mut server, 5, 200);
                assert!(resolver2.take_result(qid2, OWNER).unwrap().is_ok());
            });
        }

        #[test]
        fn wrong_owner_and_holder_exit() {
            run_on_large_stack(|| {
                let (a, b) = FakeLink::pair();
                let mut server = TestDnsServer::new(b);
                server.ensure_bind53();
                let mut resolver = make_resolver(a);
                let out = resolver.resolve(0, OWNER, FIXTURE_HOSTNAME).unwrap();
                let qid = match out {
                    ResolveOutcome::Pending { query_id } => query_id,
                    _ => panic!("expected pending"),
                };
                assert!(resolver.take_result(qid, OTHER).is_none());
                resolver.on_holder_exit(OWNER);
                assert!(resolver.take_result(qid, OWNER).is_none());
            });
        }

        #[test]
        fn queue_full_and_reset() {
            run_on_large_stack(|| {
                let (a, b) = FakeLink::pair();
                let mut server = TestDnsServer::new(b);
                server.ensure_bind53();
                let mut resolver = make_resolver(a);
                for i in 0..PENDING_SLOTS {
                    let name = format!("host{i}.test");
                    let _ = resolver.resolve(0, OWNER, &name).unwrap();
                }
                assert_eq!(
                    resolver.resolve(0, OWNER, "overflow.test"),
                    Err(DnsError::QueueFull)
                );
                resolver.reset().unwrap();
                assert_eq!(resolver.udp_mut().table().endpoints_in_use(), 0);
            });
        }
    }
}
