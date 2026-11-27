//! Bounded DNS codec (RFC 1035 subset), cache, and resolver over [`UdpTransport`], or over TCP
//! (RFC 7766 framing) when the resolver is [`DnsResolver::set_over_tcp`]: the resolver then only
//! hands out framed queries ([`DnsResolver::start_tcp_query`]) and takes back the replies; the
//! caller owns the TCP connection.
//!
//! Supported subset: A/IN queries with RD=1, single question. An A record counts
//! only when its owner is the queried name, or the name reached by following CNAMEs from
//! that question in the same reply (at most [`MAX_CNAME_CHAIN`] names, question included).
//! TCP fallback on truncated UDP replies and DNSSEC are deferred.
//!
//! Capability checks (`NET_RESOLVE`) are performed by the network service **above** this
//! layer; [`DnsResolver::resolve`] assumes the caller is already authorized.

use crate::addr::{Ipv4Addr, SocketAddrV4};
use crate::device::NetworkLink;
use crate::error::NetworkError;
use crate::limits::{MAX_DNS_LABEL_LEN, MAX_DNS_NAME_LEN, MAX_IN_FLIGHT_RESOLVER_QUERIES};
use crate::protocol::TrustedCaller;
use crate::rng::NetRng;
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

/// Resolver query timeout wall time (ms); derive IRQ ticks via kernel tick period.
pub const DNS_QUERY_TIMEOUT_MS: u64 = 500;
/// Resolver query timeout at 1 ms/tick production (`DNS_QUERY_TIMEOUT_MS`).
pub const DNS_QUERY_TIMEOUT_TICKS: u64 = DNS_QUERY_TIMEOUT_MS;

/// Query timeout (ms, = ticks at 1 ms/tick) over TCP: the connection's handshake and close are
/// part of it.
pub const DNS_TCP_QUERY_TIMEOUT_TICKS: u64 = 3_000;

/// Largest DNS-over-TCP message the resolver sends or accepts, with its two-byte length prefix
/// (RFC 7766 section 8). Replies are held to the classic 512-byte UDP limit.
pub const DNS_TCP_MAX_MESSAGE: usize = 2 + 512;

/// Interval (ms, = ticks at 1 ms/tick) after which an unanswered query is sent again with the
/// same ID, until [`DNS_QUERY_TIMEOUT_TICKS`] expires: four sends within the deadline.
pub const DNS_RETRANSMIT_TICKS: u64 = DNS_QUERY_TIMEOUT_TICKS / 4;

/// Compression pointer follow hop limit.
pub const DNS_COMPRESSION_HOP_LIMIT: usize = 16;

const DNS_HEADER_LEN: usize = 12;
const QTYPE_A: u16 = 1;
const QCLASS_IN: u16 = 1;
const RR_TYPE_A: u16 = 1;
const RR_TYPE_CNAME: u16 = 5;
const RR_CLASS_IN: u16 = 1;

/// Names allowed in one CNAME chain, counting the queried name. One more CNAME is rejected.
pub const MAX_CNAME_CHAIN: usize = 8;

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

/// Encodes a standard query as a DNS-over-TCP message: the two-byte length, then the query.
pub fn encode_tcp_query(id: u16, name: &str, out: &mut [u8]) -> Result<usize, DnsError> {
    let body = out.get_mut(2..).ok_or(DnsError::Truncated)?;
    let len = encode_query(id, name, body)?;
    out[..2].copy_from_slice(&(len as u16).to_be_bytes());
    Ok(len + 2)
}

/// The full length (prefix included) of the DNS-over-TCP message whose first bytes are `head`,
/// once two bytes are in; `None` before that.
pub fn tcp_message_len(head: &[u8]) -> Option<usize> {
    let prefix: [u8; 2] = head.get(..2)?.try_into().ok()?;
    Some(usize::from(u16::from_be_bytes(prefix)) + 2)
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

/// Parses a DNS response and returns the A record for `expected_name`.
///
/// The owner of that record must be `expected_name`, or the name at the end of a CNAME
/// chain followed from it inside this reply. A loop, a chain of more than
/// [`MAX_CNAME_CHAIN`] names, or an A record for any other name does not resolve.
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

    let answer_at = offset;
    let mut current = [0u8; MAX_DNS_NAME_LEN];
    current[..qname_len].copy_from_slice(qname_buf.get(..qname_len).ok_or(DnsError::Malformed)?);
    let (current_len, followed) =
        follow_cnames(bytes, answer_at, hdr.ancount, &mut current, qname_len)?;
    let (found, foreign_address) = find_address(
        bytes,
        answer_at,
        hdr.ancount,
        current.get(..current_len).ok_or(DnsError::Malformed)?,
    )?;

    offset = skip_records(bytes, answer_at, hdr.ancount)?;
    offset = skip_records(bytes, offset, hdr.nscount)?;
    let _end = skip_records(bytes, offset, hdr.arcount)?;

    match found {
        Some(answer) => Ok(answer),
        // An A record for some other name is not an answer; the query keeps waiting.
        None if foreign_address && followed == 0 => Err(DnsError::Malformed),
        None => Err(DnsError::NoAddress),
    }
}

fn dns_name_eq(left: &[u8], right: &[u8]) -> bool {
    left.eq_ignore_ascii_case(right)
}

struct AnswerRr {
    owner_len: usize,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    data_start: usize,
    data_end: usize,
    next: usize,
}

fn read_answer_rr(msg: &[u8], offset: usize, owner: &mut [u8]) -> Result<AnswerRr, DnsError> {
    let mut hops = 0usize;
    let (owner_len, name_end) = read_name_at_no_alloc(msg, offset, offset, &mut hops, owner)?;
    if name_end + 10 > msg.len() {
        return Err(DnsError::Truncated);
    }
    let rtype = u16::from_be_bytes([msg[name_end], msg[name_end + 1]]);
    let rclass = u16::from_be_bytes([msg[name_end + 2], msg[name_end + 3]]);
    let ttl = u32::from_be_bytes([
        msg[name_end + 4],
        msg[name_end + 5],
        msg[name_end + 6],
        msg[name_end + 7],
    ]);
    let rdlen = u16::from_be_bytes([msg[name_end + 8], msg[name_end + 9]]) as usize;
    let data_start = name_end + 10;
    let data_end = data_start.checked_add(rdlen).ok_or(DnsError::Malformed)?;
    if data_end > msg.len() {
        return Err(DnsError::Truncated);
    }
    Ok(AnswerRr {
        owner_len,
        rtype,
        rclass,
        ttl,
        data_start,
        data_end,
        next: data_end,
    })
}

/// Decodes the name stored as the whole of `start..end`.
fn rdata_name(msg: &[u8], start: usize, end: usize, out: &mut [u8]) -> Result<usize, DnsError> {
    let mut hops = 0usize;
    let (len, name_end) = read_name_at_no_alloc(msg, start, start, &mut hops, out)?;
    if name_end != end {
        return Err(DnsError::Malformed);
    }
    Ok(len)
}

fn skip_records(msg: &[u8], mut offset: usize, count: u16) -> Result<usize, DnsError> {
    for _ in 0..count {
        let (end, _, _) = skip_rr(msg, offset, offset)?;
        offset = end;
    }
    Ok(offset)
}

/// Follows CNAMEs from the name already in `current` (length `current_len`).
/// Returns the final name's length and how many CNAMEs were followed.
fn follow_cnames(
    msg: &[u8],
    answer_at: usize,
    ancount: u16,
    current: &mut [u8],
    mut current_len: usize,
) -> Result<(usize, usize), DnsError> {
    let mut origin = [0u8; MAX_DNS_NAME_LEN];
    origin
        .get_mut(..current_len)
        .ok_or(DnsError::Malformed)?
        .copy_from_slice(current.get(..current_len).ok_or(DnsError::Malformed)?);
    let origin_len = current_len;
    let mut prev_rdata = [(0usize, 0usize); MAX_CNAME_CHAIN];
    let mut followed = 0usize;
    loop {
        let mut target = [0u8; MAX_DNS_NAME_LEN];
        let Some(CnameTarget {
            len: target_len,
            rdata,
        }) = find_cname(
            msg,
            answer_at,
            ancount,
            current.get(..current_len).ok_or(DnsError::Malformed)?,
            &mut target,
        )?
        else {
            break;
        };
        if followed + 1 >= MAX_CNAME_CHAIN {
            return Err(DnsError::Malformed);
        }
        let target_bytes = target.get(..target_len).ok_or(DnsError::Malformed)?;
        if dns_name_eq(
            target_bytes,
            current.get(..current_len).ok_or(DnsError::Malformed)?,
        ) || dns_name_eq(
            target_bytes,
            origin.get(..origin_len).ok_or(DnsError::Malformed)?,
        ) || previous_name_is(msg, &prev_rdata[..followed], target_bytes)?
        {
            return Err(DnsError::Malformed);
        }
        prev_rdata[followed] = rdata;
        followed += 1;
        current
            .get_mut(..target_len)
            .ok_or(DnsError::Malformed)?
            .copy_from_slice(target_bytes);
        current_len = target_len;
    }
    Ok((current_len, followed))
}

fn previous_name_is(msg: &[u8], prev: &[(usize, usize)], target: &[u8]) -> Result<bool, DnsError> {
    let mut scratch = [0u8; MAX_DNS_NAME_LEN];
    for &(start, end) in prev {
        let len = rdata_name(msg, start, end, &mut scratch)?;
        if dns_name_eq(scratch.get(..len).ok_or(DnsError::Malformed)?, target) {
            return Ok(true);
        }
    }
    Ok(false)
}

struct CnameTarget {
    len: usize,
    rdata: (usize, usize),
}

/// The first IN CNAME for `owner`.
fn find_cname(
    msg: &[u8],
    mut offset: usize,
    ancount: u16,
    owner_want: &[u8],
    target: &mut [u8],
) -> Result<Option<CnameTarget>, DnsError> {
    let mut owner = [0u8; MAX_DNS_NAME_LEN];
    for _ in 0..ancount {
        let rr = read_answer_rr(msg, offset, &mut owner)?;
        if rr.rtype == RR_TYPE_CNAME
            && rr.rclass == RR_CLASS_IN
            && dns_name_eq(
                owner.get(..rr.owner_len).ok_or(DnsError::Malformed)?,
                owner_want,
            )
        {
            let len = rdata_name(msg, rr.data_start, rr.data_end, target)?;
            return Ok(Some(CnameTarget {
                len,
                rdata: (rr.data_start, rr.data_end),
            }));
        }
        offset = rr.next;
    }
    Ok(None)
}

/// The first IN A record for `owner`, and whether some other IN A record is present.
fn find_address(
    msg: &[u8],
    mut offset: usize,
    ancount: u16,
    owner_want: &[u8],
) -> Result<(Option<DnsAnswer>, bool), DnsError> {
    let mut owner = [0u8; MAX_DNS_NAME_LEN];
    let mut found = None;
    let mut foreign_address = false;
    for _ in 0..ancount {
        let rr = read_answer_rr(msg, offset, &mut owner)?;
        if rr.rtype == RR_TYPE_A && rr.rclass == RR_CLASS_IN {
            if rr.data_end - rr.data_start != 4 {
                return Err(DnsError::Malformed);
            }
            let matches = dns_name_eq(
                owner.get(..rr.owner_len).ok_or(DnsError::Malformed)?,
                owner_want,
            );
            if matches && found.is_none() {
                let octets = msg
                    .get(rr.data_start..rr.data_end)
                    .ok_or(DnsError::Truncated)?;
                found = Some(DnsAnswer {
                    ttl: rr.ttl,
                    addr: Ipv4Addr::new([octets[0], octets[1], octets[2], octets[3]]),
                });
            } else if !matches {
                foreign_address = true;
            }
        }
        offset = rr.next;
    }
    Ok((found, foreign_address))
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
    /// Tick at which the query is (re)sent: the resolve tick until a send succeeds, then
    /// [`DNS_RETRANSMIT_TICKS`] after each successful send.
    next_send: u64,
    sends: u8,
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
            next_send: 0,
            sends: 0,
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
    /// Sends of a query after its first, because no acceptable reply arrived in time.
    pub retransmits: u64,
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
    generation: SessionGeneration,
    ticks_per_sec: u64,
    stats: DnsResolverStats,
    /// Queries go over TCP, through the caller (see the module docs).
    over_tcp: bool,
}

/// A DNS-over-TCP query [`DnsResolver::start_tcp_query`] hands out: send `message()` to the
/// resolver's server on a new TCP connection and pass the reply to
/// [`DnsResolver::complete_tcp_query`].
#[derive(Clone, Copy)]
pub struct DnsTcpQuery {
    pub query_id: u32,
    pub server: SocketAddrV4,
    message: [u8; DNS_TCP_MAX_MESSAGE],
    len: usize,
}

impl DnsTcpQuery {
    pub fn message(&self) -> &[u8] {
        &self.message[..self.len]
    }
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
            generation,
            ticks_per_sec: ticks_per_sec.max(1),
            stats: DnsResolverStats::default(),
            over_tcp: false,
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
        rng: NetRng,
    ) {
        unsafe {
            UdpTransport::init_in_place(
                core::ptr::addr_of_mut!((*slot).udp),
                stack,
                generation,
                rng,
            );
            (*slot).cache = DnsCache::new();
            (*slot).server = server;
            (*slot).pending = [PendingQuery::vacant(); PENDING_SLOTS];
            (*slot).next_query_id = 1;
            (*slot).generation = generation;
            (*slot).ticks_per_sec = ticks_per_sec.max(1);
            (*slot).stats = DnsResolverStats::default();
            (*slot).over_tcp = false;
        }
    }

    /// Heap-backed resolver for environments that cannot place large protocol state on thread stacks.
    #[cfg(feature = "alloc")]
    pub fn alloc_boxed(
        stack: crate::stack::L3Stack<L>,
        generation: SessionGeneration,
        server: SocketAddrV4,
        ticks_per_sec: u64,
        rng: NetRng,
    ) -> alloc::boxed::Box<Self> {
        let layout = core::alloc::Layout::new::<Self>();
        let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) as *mut Self };
        if ptr.is_null() {
            alloc::alloc::handle_alloc_error(layout);
        }
        unsafe {
            Self::init_in_place(ptr, stack, generation, server, ticks_per_sec, rng);
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

    /// Sends queries over TCP from now on (set before the first resolve).
    pub fn set_over_tcp(&mut self, over_tcp: bool) {
        self.over_tcp = over_tcp;
    }

    pub fn over_tcp(&self) -> bool {
        self.over_tcp
    }

    /// A random query ID that no live query is using.
    fn alloc_dns_id(&mut self) -> u16 {
        loop {
            let id = self.udp.table_mut().rng_mut().next_u32() as u16;
            if !self.pending.iter().any(|p| p.live && p.dns_id == id) {
                return id;
            }
        }
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
        if self.over_tcp {
            let (name_buf, name_len) = Self::store_name(name)?;
            let dns_id = self.alloc_dns_id();
            let query_id = self.alloc_query_id();
            // Not sent yet: `start_tcp_query` hands it out.
            self.pending[slot] = PendingQuery {
                live: true,
                query_id,
                dns_id,
                owner,
                name_len,
                name: name_buf,
                endpoint: SessionId::new(SessionGeneration::new(0), 0),
                deadline: now.saturating_add(DNS_TCP_QUERY_TIMEOUT_TICKS),
                next_send: now,
                sends: 0,
                state: PendingState::InFlight,
            };
            return Ok(ResolveOutcome::Pending { query_id });
        }
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
        let mut next_send = now;
        let mut sends = 0;
        let mut payload = [0u8; 512];
        let plen = encode_query(dns_id, name, &mut payload)?;
        match self
            .udp
            .send(now, endpoint, owner, Some(self.server), &payload[..plen])
        {
            Ok(_) => {
                self.stats.queries_sent += 1;
                next_send = now.saturating_add(DNS_RETRANSMIT_TICKS);
                sends = 1;
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
            next_send,
            sends,
            state: PendingState::InFlight,
        };
        Ok(ResolveOutcome::Pending { query_id })
    }

    fn pending_name(p: &PendingQuery) -> &str {
        core::str::from_utf8(p.name.get(0..p.name_len as usize).unwrap_or(&[])).unwrap_or("")
    }

    fn finish_pending(&mut self, index: usize, result: PendingState) {
        if !self.over_tcp && matches!(self.pending[index].state, PendingState::InFlight) {
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
        if self.over_tcp {
            return Ok(());
        }

        let mut buf = [0u8; MAX_UDP_PAYLOAD];
        for i in 0..PENDING_SLOTS {
            if !self.pending[i].live || !matches!(self.pending[i].state, PendingState::InFlight) {
                continue;
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
            let pending = &self.pending[i];
            if !matches!(pending.state, PendingState::InFlight) || now < pending.next_send {
                continue;
            }
            let mut payload = [0u8; 512];
            let Ok(plen) = encode_query(dns_id, Self::pending_name(pending), &mut payload) else {
                continue;
            };
            if self
                .udp
                .send(now, endpoint, owner, Some(self.server), &payload[..plen])
                .is_ok()
            {
                self.stats.queries_sent += 1;
                if self.pending[i].sends > 0 {
                    self.stats.retransmits += 1;
                }
                self.pending[i].sends = self.pending[i].sends.saturating_add(1);
                self.pending[i].next_send = now.saturating_add(DNS_RETRANSMIT_TICKS);
            }
        }
        Ok(())
    }

    /// The oldest query not yet sent, marked sent, as a DNS-over-TCP message. Over TCP only.
    pub fn start_tcp_query(&mut self) -> Option<DnsTcpQuery> {
        if !self.over_tcp {
            return None;
        }
        let index = self
            .pending
            .iter()
            .enumerate()
            .filter(|(_, p)| p.live && p.sends == 0 && matches!(p.state, PendingState::InFlight))
            .min_by_key(|(_, p)| p.query_id)?
            .0;
        let mut message = [0u8; DNS_TCP_MAX_MESSAGE];
        let pending = &self.pending[index];
        let Ok(len) = encode_tcp_query(pending.dns_id, Self::pending_name(pending), &mut message)
        else {
            self.finish_pending(index, PendingState::DoneErr(DnsError::InvalidName));
            return None;
        };
        self.pending[index].sends = 1;
        self.stats.queries_sent += 1;
        Some(DnsTcpQuery {
            query_id: self.pending[index].query_id,
            server: self.server,
            message,
            len,
        })
    }

    /// Whether `query_id` is still waiting for its reply (not answered, timed out or dropped
    /// with its holder).
    pub fn tcp_query_waiting(&self, query_id: u32) -> bool {
        self.pending
            .iter()
            .any(|p| p.live && p.query_id == query_id && matches!(p.state, PendingState::InFlight))
    }

    /// Finishes `query_id` with the DNS-over-TCP `message` its connection returned (length
    /// prefix included), or with `Err` when the connection failed. There is no retry over TCP:
    /// a reply that does not check out fails the query.
    pub fn complete_tcp_query(
        &mut self,
        query_id: u32,
        message: Result<&[u8], DnsError>,
        now: u64,
    ) {
        let Some(index) = self.pending.iter().position(|p| {
            p.live && p.query_id == query_id && matches!(p.state, PendingState::InFlight)
        }) else {
            return;
        };
        let result = message.and_then(|message| {
            let body = message.get(2..).ok_or(DnsError::Truncated)?;
            let name = Self::pending_name(&self.pending[index]);
            let answer = parse_response(body, self.pending[index].dns_id, name)?;
            let _ = self
                .cache
                .insert(name, answer.addr, answer.ttl, now, self.ticks_per_sec);
            Ok(answer)
        });
        let state = match result {
            Ok(answer) => {
                self.stats.responses_ok += 1;
                PendingState::DoneOk {
                    addr: answer.addr,
                    ttl: answer.ttl,
                }
            }
            Err(err) => {
                if matches!(err, DnsError::IdMismatch | DnsError::Malformed) {
                    self.stats.dropped_mismatch += 1;
                }
                PendingState::DoneErr(err)
            }
        };
        self.finish_pending(index, state);
    }

    /// Earliest tick at which [`Self::poll`] retransmits or times out an in-flight query (`poll`
    /// expires a query once `now` passes its deadline), or `None` with nothing in flight.
    ///
    /// A query whose first send has not succeeded yet (ARP miss) is retried on the next poll
    /// that ingress triggers, so it contributes only its timeout here.
    pub fn next_deadline(&self) -> Option<u64> {
        self.pending
            .iter()
            .filter(|p| p.live && matches!(p.state, PendingState::InFlight))
            .map(|p| {
                let expiry = p.deadline.saturating_add(1);
                // Over TCP nothing is resent: the caller's connection carries the query.
                if p.sends > 0 && !self.over_tcp {
                    expiry.min(p.next_send)
                } else {
                    expiry
                }
            })
            .min()
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

    /// Queries still holding a pending slot (in flight or awaiting `take_result`).
    pub fn pending_queries(&self) -> usize {
        self.pending.iter().filter(|query| query.live).count()
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

    fn push_name(msg: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
    }

    fn push_rr(msg: &mut Vec<u8>, owner: &str, rtype: u16, rdata: &[u8]) {
        push_name(msg, owner);
        msg.extend_from_slice(&rtype.to_be_bytes());
        msg.extend_from_slice(&RR_CLASS_IN.to_be_bytes());
        msg.extend_from_slice(&300u32.to_be_bytes());
        msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        msg.extend_from_slice(rdata);
    }

    fn message(id: u16, qname: &str, ancount: u16, records: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
        let hdr = DnsHeader {
            id,
            flags: 0x8480,
            qdcount: 1,
            ancount,
            nscount: 0,
            arcount: 0,
        };
        let mut msg = vec![0u8; DNS_HEADER_LEN];
        hdr.write(&mut msg).unwrap();
        push_name(&mut msg, qname);
        msg.extend_from_slice(&QTYPE_A.to_be_bytes());
        msg.extend_from_slice(&QCLASS_IN.to_be_bytes());
        records(&mut msg);
        msg
    }

    #[test]
    fn mismatched_owner_name_is_rejected() {
        let id = 42;
        let decoy = Ipv4Addr::new([10, 77, 0, 66]);
        let msg = message(id, FIXTURE_HOSTNAME, 1, |msg| {
            push_rr(msg, "forged.fixture.test", RR_TYPE_A, &decoy.octets());
        });
        assert_eq!(
            parse_response(&msg, id, FIXTURE_HOSTNAME),
            Err(DnsError::Malformed)
        );
        let different_case = message(id, FIXTURE_HOSTNAME, 1, |msg| {
            push_rr(
                msg,
                "M7.FIXTURE.TEST",
                RR_TYPE_A,
                &FIXTURE_A_RECORD.octets(),
            );
        });
        let ans = parse_response(&different_case, id, FIXTURE_HOSTNAME).unwrap();
        assert_eq!(ans.addr, FIXTURE_A_RECORD);
    }

    #[test]
    fn cname_chain_is_followed_past_a_decoy_address() {
        let id = 7;
        let qname = "www.example";
        let decoy = Ipv4Addr::new([10, 77, 0, 66]);
        let msg = message(id, qname, 4, |msg| {
            push_rr(msg, "forged.example", RR_TYPE_A, &decoy.octets());
            let mut cname_a = Vec::new();
            push_name(&mut cname_a, "a.example");
            push_rr(msg, qname, RR_TYPE_CNAME, &cname_a);
            let mut cname_b = Vec::new();
            push_name(&mut cname_b, "b.example");
            push_rr(msg, "a.example", RR_TYPE_CNAME, &cname_b);
            push_rr(msg, "b.example", RR_TYPE_A, &FIXTURE_A_RECORD.octets());
        });
        let ans = parse_response(&msg, id, qname).unwrap();
        assert_eq!(ans.addr, FIXTURE_A_RECORD);
    }

    #[test]
    fn cname_loop_or_too_long_chain_is_rejected() {
        let id = 9;
        let qname = "www.example";
        let decoy = Ipv4Addr::new([10, 77, 0, 66]);
        let looped = message(id, qname, 3, |msg| {
            push_rr(msg, "forged.example", RR_TYPE_A, &decoy.octets());
            let mut to_a = Vec::new();
            push_name(&mut to_a, "a.example");
            push_rr(msg, qname, RR_TYPE_CNAME, &to_a);
            let mut back = Vec::new();
            push_name(&mut back, qname);
            push_rr(msg, "a.example", RR_TYPE_CNAME, &back);
        });
        assert_eq!(parse_response(&looped, id, qname), Err(DnsError::Malformed));

        // Eight names (the question plus seven CNAMEs) is the maximum that still resolves.
        let mut names = vec![qname.to_owned()];
        for hop in 1..MAX_CNAME_CHAIN {
            names.push(format!("n{hop}.example"));
        }
        let at_bound = message(id, qname, MAX_CNAME_CHAIN as u16, |msg| {
            for hop in 0..MAX_CNAME_CHAIN - 1 {
                let mut next = Vec::new();
                push_name(&mut next, &names[hop + 1]);
                push_rr(msg, &names[hop], RR_TYPE_CNAME, &next);
            }
            push_rr(
                msg,
                names.last().expect("chain"),
                RR_TYPE_A,
                &FIXTURE_A_RECORD.octets(),
            );
        });
        assert_eq!(
            parse_response(&at_bound, id, qname).unwrap().addr,
            FIXTURE_A_RECORD
        );

        // One more CNAME does not fit in the answer-section cap, so the too-long chain is
        // eight CNAME hops with no terminal address: the chain itself is malformed.
        let mut long_names = vec!["q.example".to_owned()];
        for hop in 1..=MAX_CNAME_CHAIN {
            long_names.push(format!("n{hop}.example"));
        }
        let too_long = message(id, "q.example", MAX_CNAME_CHAIN as u16, |msg| {
            for hop in 0..MAX_CNAME_CHAIN {
                let mut next = Vec::new();
                push_name(&mut next, &long_names[hop + 1]);
                push_rr(msg, &long_names[hop], RR_TYPE_CNAME, &next);
            }
        });
        assert_eq!(
            parse_response(&too_long, id, "q.example"),
            Err(DnsError::Malformed)
        );
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
            /// Queries still to be received and dropped unanswered.
            ignore_queries: u32,
            ignored_ids: Vec<u16>,
            answered_ids: Vec<u16>,
        }

        impl TestDnsServer {
            fn new(link: FakeLink) -> Self {
                let stack = L3Stack::new(link, PEER_MAC, PEER_IPV4, 1000);
                let mut transport =
                    UdpTransport::alloc_boxed(stack, GEN, NetRng::from_seed([0x53; 32]));
                transport
                    .stack_mut()
                    .arp_cache_mut()
                    .insert(GUEST_IPV4, GUEST_MAC, 0);
                let owner = TrustedCaller::new(99, 0, 0);
                Self {
                    transport,
                    owner,
                    listen: None,
                    ignore_queries: 0,
                    ignored_ids: Vec::new(),
                    answered_ids: Vec::new(),
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
                    if self.ignore_queries > 0 {
                        self.ignore_queries -= 1;
                        self.ignored_ids.push(hdr.id);
                        return;
                    }
                    self.answered_ids.push(hdr.id);
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
            make_resolver_seeded(link, 0x52)
        }

        fn make_resolver_seeded(link: FakeLink, seed: u8) -> DnsResolver<FakeLink> {
            let stack = L3Stack::new(link, GUEST_MAC, GUEST_IPV4, 1000);
            let mut udp = UdpTransport::new(stack, GEN, NetRng::from_seed([seed; 32]));
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

        /// Six concurrent queries carry six distinct IDs, and a resolver seeded differently
        /// sends different IDs from different source ports.
        #[test]
        fn query_ids_and_ports_are_random_and_unique_among_live_queries() {
            run_on_large_stack(|| {
                let sent = |seed: u8| {
                    let (a, b) = FakeLink::pair();
                    let mut server = TestDnsServer::new(b);
                    server.ensure_bind53();
                    server.ignore_queries = u32::MAX;
                    let mut resolver = make_resolver_seeded(a, seed);
                    let mut ports = Vec::new();
                    for name in ["a.test", "b.test", "c.test", "d.test", "e.test", "f.test"] {
                        resolver.resolve(0, OWNER, name).unwrap();
                    }
                    for query in resolver.pending.iter().filter(|p| p.live) {
                        let table = resolver.udp.table();
                        ports.push(table.local_port(query.endpoint, OWNER).unwrap());
                    }
                    pump_both(&mut resolver, &mut server, 0, 20);
                    (server.ignored_ids.clone(), ports)
                };
                let (ids, ports) = sent(1);
                assert_eq!(ids.len(), 6);
                let distinct: std::collections::HashSet<u16> = ids.iter().copied().collect();
                assert_eq!(distinct.len(), ids.len(), "IDs {ids:?} repeat");
                let (other_ids, other_ports) = sent(2);
                assert_ne!(ids, other_ids);
                assert_ne!(ports, other_ports);
            });
        }

        #[test]
        fn next_deadline_is_the_first_tick_poll_times_out() {
            run_on_large_stack(|| {
                let (a, _b) = FakeLink::pair();
                let mut resolver = make_resolver(a);
                assert_eq!(resolver.next_deadline(), None);
                let qid = match resolver.resolve(5, OWNER, FIXTURE_HOSTNAME).unwrap() {
                    ResolveOutcome::Pending { query_id } => query_id,
                    _ => panic!("expected pending"),
                };
                let expiry = 5 + DNS_QUERY_TIMEOUT_TICKS + 1;
                let mut retransmit_at = 5 + DNS_RETRANSMIT_TICKS;
                while retransmit_at < expiry {
                    assert_eq!(resolver.next_deadline(), Some(retransmit_at));
                    resolver.poll(retransmit_at - 1).unwrap();
                    let before = resolver.stats().retransmits;
                    resolver.poll(retransmit_at).unwrap();
                    assert_eq!(resolver.stats().retransmits, before + 1);
                    retransmit_at += DNS_RETRANSMIT_TICKS;
                }
                assert_eq!(resolver.next_deadline(), Some(expiry));
                resolver.poll(expiry - 1).unwrap();
                assert_eq!(resolver.take_result(qid, OWNER), None);
                resolver.poll(expiry).unwrap();
                assert_eq!(
                    resolver.take_result(qid, OWNER).unwrap(),
                    Err(DnsError::Timeout)
                );
                assert_eq!(resolver.next_deadline(), None);
                assert_eq!(
                    resolver.stats().retransmits,
                    DNS_QUERY_TIMEOUT_TICKS / DNS_RETRANSMIT_TICKS
                );
            });
        }

        #[test]
        fn a_lost_query_is_sent_again_with_the_same_id() {
            run_on_large_stack(|| {
                let (a, b) = FakeLink::pair();
                let mut server = TestDnsServer::new(b);
                server.ensure_bind53();
                server.ignore_queries = 1;
                let mut resolver = make_resolver(a);
                let qid = match resolver.resolve(0, OWNER, FIXTURE_HOSTNAME).unwrap() {
                    ResolveOutcome::Pending { query_id } => query_id,
                    _ => panic!("expected pending"),
                };
                pump_both(&mut resolver, &mut server, 0, DNS_RETRANSMIT_TICKS - 1);
                assert_eq!(resolver.take_result(qid, OWNER), None);
                assert_eq!(server.ignored_ids.len(), 1);
                pump_both(
                    &mut resolver,
                    &mut server,
                    DNS_RETRANSMIT_TICKS - 1,
                    DNS_RETRANSMIT_TICKS,
                );
                let (addr, _) = resolver.take_result(qid, OWNER).unwrap().unwrap();
                assert_eq!(addr, FIXTURE_A_RECORD);
                assert_eq!(server.answered_ids, server.ignored_ids);
                assert_eq!(resolver.stats().retransmits, 1);
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

        /// The reply to `message` (a DNS-over-TCP query) as a DNS-over-TCP message.
        fn tcp_reply(message: &[u8], addr: Ipv4Addr, ttl: u32) -> Vec<u8> {
            assert_eq!(tcp_message_len(message), Some(message.len()));
            let id = u16::from_be_bytes([message[2], message[3]]);
            let body = build_valid_response(id, FIXTURE_HOSTNAME, addr, ttl);
            let mut out = (body.len() as u16).to_be_bytes().to_vec();
            out.extend_from_slice(&body);
            out
        }

        #[test]
        fn over_tcp_the_caller_carries_the_query_and_the_answer_is_cached() {
            run_on_large_stack(|| {
                let (a, _b) = FakeLink::pair();
                let mut resolver = make_resolver(a);
                assert!(resolver.start_tcp_query().is_none(), "UDP resolver");
                resolver.set_over_tcp(true);
                let ResolveOutcome::Pending { query_id } =
                    resolver.resolve(0, OWNER, FIXTURE_HOSTNAME).unwrap()
                else {
                    panic!("expected pending");
                };
                // Nothing goes out over UDP.
                assert_eq!(resolver.udp_mut().table().endpoints_in_use(), 0);
                let query = resolver.start_tcp_query().expect("a query to carry");
                assert_eq!(query.query_id, query_id);
                assert_eq!(query.server, DNS_SERVER_ADDR);
                assert!(resolver.start_tcp_query().is_none(), "handed out once");
                assert!(resolver.tcp_query_waiting(query_id));
                assert!(resolver.take_result(query_id, OWNER).is_none());

                let reply = tcp_reply(query.message(), FIXTURE_A_RECORD, FIXTURE_A_TTL_SECS);
                resolver.complete_tcp_query(query_id, Ok(&reply), 5);
                assert!(!resolver.tcp_query_waiting(query_id));
                assert_eq!(
                    resolver.take_result(query_id, OWNER),
                    Some(Ok((FIXTURE_A_RECORD, FIXTURE_A_TTL_SECS)))
                );
                assert!(matches!(
                    resolver.resolve(10, OWNER, FIXTURE_HOSTNAME).unwrap(),
                    ResolveOutcome::Cached { .. }
                ));
            });
        }

        #[test]
        fn over_tcp_a_bad_reply_a_failed_connection_or_the_deadline_fail_the_query() {
            run_on_large_stack(|| {
                let (a, _b) = FakeLink::pair();
                let mut resolver = make_resolver(a);
                resolver.set_over_tcp(true);
                let pending = |resolver: &mut DnsResolver<FakeLink>, name: &str| match resolver
                    .resolve(0, OWNER, name)
                    .unwrap()
                {
                    ResolveOutcome::Pending { query_id } => query_id,
                    _ => panic!("expected pending"),
                };

                let wrong_id = pending(&mut resolver, FIXTURE_HOSTNAME);
                let query = resolver.start_tcp_query().unwrap();
                let mut reply = tcp_reply(query.message(), FIXTURE_A_RECORD, 60);
                reply[2] ^= 0xff;
                resolver.complete_tcp_query(wrong_id, Ok(&reply), 1);
                assert_eq!(
                    resolver.take_result(wrong_id, OWNER),
                    Some(Err(DnsError::IdMismatch))
                );

                let reset = pending(&mut resolver, FIXTURE_HOSTNAME);
                resolver.start_tcp_query().unwrap();
                resolver.complete_tcp_query(
                    reset,
                    Err(DnsError::Transport(NetworkError::Reset)),
                    1,
                );
                assert_eq!(
                    resolver.take_result(reset, OWNER),
                    Some(Err(DnsError::Transport(NetworkError::Reset)))
                );

                let slow = pending(&mut resolver, FIXTURE_HOSTNAME);
                resolver.start_tcp_query().unwrap();
                assert_eq!(
                    resolver.next_deadline(),
                    Some(DNS_TCP_QUERY_TIMEOUT_TICKS + 1)
                );
                resolver.poll(DNS_TCP_QUERY_TIMEOUT_TICKS + 1).unwrap();
                assert!(!resolver.tcp_query_waiting(slow));
                assert_eq!(
                    resolver.take_result(slow, OWNER),
                    Some(Err(DnsError::Timeout))
                );
            });
        }

        #[test]
        fn tcp_framing_prefixes_the_length() {
            let mut out = [0u8; DNS_TCP_MAX_MESSAGE];
            let len = encode_tcp_query(0x1234, FIXTURE_HOSTNAME, &mut out).unwrap();
            assert_eq!(tcp_message_len(&out[..len]), Some(len));
            assert_eq!(&out[2..4], &[0x12, 0x34]);
            assert_eq!(tcp_message_len(&out[..1]), None);
        }
    }
}
