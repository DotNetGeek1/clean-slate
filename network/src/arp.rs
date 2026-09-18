//! IPv4-over-Ethernet ARP (RFC 826 subset).

use crate::addr::{Ipv4Addr, MacAddr};
use crate::ethernet::ParseError;

/// ARP hardware type: Ethernet.
pub const ARP_HTYPE_ETHERNET: u16 = 1;
/// ARP protocol type: IPv4.
pub const ARP_PTYPE_IPV4: u16 = 0x0800;
pub const ARP_HLEN: u8 = 6;
pub const ARP_PLEN: u8 = 4;
pub const ARP_PACKET_LEN: usize = 28;

/// ARP opcodes supported by M7 wave-0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArpOp {
    Request = 1,
    Reply = 2,
}

impl ArpOp {
    fn from_wire(op: u16) -> Result<Self, ParseError> {
        match op {
            1 => Ok(Self::Request),
            2 => Ok(Self::Reply),
            _ => Err(ParseError::BadOpcode),
        }
    }

    const fn to_wire(self) -> u16 {
        match self {
            Self::Request => 1,
            Self::Reply => 2,
        }
    }
}

/// Parsed ARP packet (Ethernet + IPv4 only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpPacket {
    pub op: ArpOp,
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

impl ArpPacket {
    /// Parses a 28-byte IPv4/Ethernet ARP message.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < ARP_PACKET_LEN {
            return Err(ParseError::Truncated);
        }
        let htype = u16::from_be_bytes([data[0], data[1]]);
        if htype != ARP_HTYPE_ETHERNET {
            return Err(ParseError::BadHardwareType);
        }
        let ptype = u16::from_be_bytes([data[2], data[3]]);
        if ptype != ARP_PTYPE_IPV4 {
            return Err(ParseError::UnsupportedProtocol);
        }
        let hlen = data[4];
        let plen = data[5];
        if hlen != ARP_HLEN || plen != ARP_PLEN {
            return Err(ParseError::BadAddressLength);
        }
        let op = ArpOp::from_wire(u16::from_be_bytes([data[6], data[7]]))?;
        let sender_mac = MacAddr::from_bytes(data.get(8..14).ok_or(ParseError::Truncated)?)
            .map_err(|_| ParseError::Truncated)?;
        let sender_ip = Ipv4Addr::from_bytes(data.get(14..18).ok_or(ParseError::Truncated)?)
            .map_err(|_| ParseError::Truncated)?;
        let target_mac = MacAddr::from_bytes(data.get(18..24).ok_or(ParseError::Truncated)?)
            .map_err(|_| ParseError::Truncated)?;
        let target_ip = Ipv4Addr::from_bytes(data.get(24..28).ok_or(ParseError::Truncated)?)
            .map_err(|_| ParseError::Truncated)?;
        Ok(Self {
            op,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        })
    }

    /// Serializes the packet into `out` (requires at least [`ARP_PACKET_LEN`] bytes).
    pub fn write(self, out: &mut [u8]) -> Result<usize, ParseError> {
        if out.len() < ARP_PACKET_LEN {
            return Err(ParseError::BufferTooSmall);
        }
        out[0..2].copy_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
        out[2..4].copy_from_slice(&ARP_PTYPE_IPV4.to_be_bytes());
        out[4] = ARP_HLEN;
        out[5] = ARP_PLEN;
        out[6..8].copy_from_slice(&self.op.to_wire().to_be_bytes());
        out[8..14].copy_from_slice(&self.sender_mac.octets());
        out[14..18].copy_from_slice(&self.sender_ip.octets());
        out[18..24].copy_from_slice(&self.target_mac.octets());
        out[24..28].copy_from_slice(&self.target_ip.octets());
        Ok(ARP_PACKET_LEN)
    }

    /// Builds an ARP request for `target_ip` from `sender_mac` / `sender_ip`.
    pub fn request(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Self {
        Self {
            op: ArpOp::Request,
            sender_mac,
            sender_ip,
            target_mac: MacAddr::new([0; 6]),
            target_ip,
        }
    }

    /// Builds an ARP reply mirroring a request's target fields.
    pub fn reply_to(request: Self, our_mac: MacAddr, our_ip: Ipv4Addr) -> Self {
        Self {
            op: ArpOp::Reply,
            sender_mac: our_mac,
            sender_ip: our_ip,
            target_mac: request.sender_mac,
            target_ip: request.sender_ip,
        }
    }
}

/// Maximum ARP cache entries (oldest-inserted evicted when full).
pub const ARP_CACHE_CAPACITY: usize = 16;

/// Maximum distinct unresolved IPs with outstanding ARP requests.
pub const MAX_PENDING_ARP_REQUESTS: usize = 4;

#[derive(Clone, Copy, Debug)]
struct ArpEntry {
    ip: Ipv4Addr,
    mac: MacAddr,
    inserted_at: u64,
    expires_at: u64,
    valid: bool,
}

impl ArpEntry {
    const fn empty() -> Self {
        Self {
            ip: Ipv4Addr::new([0; 4]),
            mac: MacAddr::new([0; 6]),
            inserted_at: 0,
            expires_at: 0,
            valid: false,
        }
    }
}

/// Bounded ARP cache with tick-based expiry.
///
/// When full, the entry with the smallest `inserted_at` is evicted before insert.
#[derive(Clone, Debug)]
pub struct ArpCache {
    ttl_ticks: u64,
    entries: [ArpEntry; ARP_CACHE_CAPACITY],
    pending: [Option<Ipv4Addr>; MAX_PENDING_ARP_REQUESTS],
}

impl ArpCache {
    /// Creates a cache whose entries expire `ttl_ticks` after insertion.
    pub const fn new(ttl_ticks: u64) -> Self {
        Self {
            ttl_ticks,
            entries: [ArpEntry::empty(); ARP_CACHE_CAPACITY],
            pending: [None; MAX_PENDING_ARP_REQUESTS],
        }
    }

    /// Inserts or refreshes `ip` -> `mac`, valid until `now + ttl_ticks`.
    pub fn insert(&mut self, ip: Ipv4Addr, mac: MacAddr, now: u64) {
        if let Some(idx) = self.find_slot(ip) {
            self.entries[idx].mac = mac;
            self.entries[idx].inserted_at = now;
            self.entries[idx].expires_at = now.saturating_add(self.ttl_ticks);
            self.entries[idx].valid = true;
            self.clear_pending(ip);
            return;
        }
        let idx = self.evict_oldest_or_free();
        self.entries[idx] = ArpEntry {
            ip,
            mac,
            inserted_at: now,
            expires_at: now.saturating_add(self.ttl_ticks),
            valid: true,
        };
        self.clear_pending(ip);
    }

    /// Returns the MAC for `ip` when a non-expired entry exists.
    pub fn lookup(&self, ip: Ipv4Addr, now: u64) -> Option<MacAddr> {
        self.entries.iter().find_map(|e| {
            if e.valid && e.ip == ip && e.expires_at > now {
                Some(e.mac)
            } else {
                None
            }
        })
    }

    /// Removes expired entries.
    pub fn expire(&mut self, now: u64) {
        for e in &mut self.entries {
            if e.valid && e.expires_at <= now {
                e.valid = false;
            }
        }
    }

    /// Clears all entries and pending ARP state.
    pub fn clear(&mut self) {
        for e in &mut self.entries {
            *e = ArpEntry::empty();
        }
        self.pending = [None; MAX_PENDING_ARP_REQUESTS];
    }

    /// Records an outstanding ARP request for `ip` if capacity allows.
    ///
    /// Returns `false` when the pending tracker is full and `ip` is not already tracked.
    pub fn track_pending(&mut self, ip: Ipv4Addr) -> bool {
        if self.pending.contains(&Some(ip)) {
            return true;
        }
        for slot in &mut self.pending {
            if slot.is_none() {
                *slot = Some(ip);
                return true;
            }
        }
        false
    }

    pub fn clear_pending(&mut self, ip: Ipv4Addr) {
        for slot in &mut self.pending {
            if *slot == Some(ip) {
                *slot = None;
            }
        }
    }

    pub fn pending_count(&self) -> usize {
        self.pending.iter().filter(|p| p.is_some()).count()
    }

    fn find_slot(&self, ip: Ipv4Addr) -> Option<usize> {
        self.entries
            .iter()
            .enumerate()
            .find_map(|(i, e)| (e.valid && e.ip == ip).then_some(i))
    }

    fn evict_oldest_or_free(&mut self) -> usize {
        let mut oldest_idx = 0usize;
        let mut oldest_time = u64::MAX;
        let mut free_idx = None;
        for (i, e) in self.entries.iter().enumerate() {
            if !e.valid {
                free_idx = Some(i);
                break;
            }
            if e.inserted_at < oldest_time {
                oldest_time = e.inserted_at;
                oldest_idx = i;
            }
        }
        free_idx.unwrap_or(oldest_idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arp_roundtrip() {
        let pkt = ArpPacket {
            op: ArpOp::Request,
            sender_mac: MacAddr::new([1; 6]),
            sender_ip: Ipv4Addr::new([10, 0, 0, 1]),
            target_mac: MacAddr::new([0; 6]),
            target_ip: Ipv4Addr::new([10, 0, 0, 2]),
        };
        let mut buf = [0u8; ARP_PACKET_LEN];
        assert_eq!(pkt.write(&mut buf).unwrap(), ARP_PACKET_LEN);
        assert_eq!(ArpPacket::parse(&buf).unwrap(), pkt);
    }

    #[test]
    fn arp_truncated_loop() {
        let mut buf = [0u8; ARP_PACKET_LEN];
        ArpPacket::request(
            MacAddr::new([0; 6]),
            Ipv4Addr::new([1, 2, 3, 4]),
            Ipv4Addr::new([5, 6, 7, 8]),
        )
        .write(&mut buf)
        .unwrap();
        for len in 0..ARP_PACKET_LEN {
            assert_eq!(ArpPacket::parse(&buf[..len]), Err(ParseError::Truncated));
        }
    }

    #[test]
    fn arp_bad_hardware() {
        let mut buf = [0u8; ARP_PACKET_LEN];
        buf[0] = 0x00;
        buf[1] = 0x02;
        assert_eq!(ArpPacket::parse(&buf), Err(ParseError::BadHardwareType));
    }

    #[test]
    fn cache_capacity_and_eviction() {
        let mut cache = ArpCache::new(100);
        for i in 0..=ARP_CACHE_CAPACITY {
            let ip = Ipv4Addr::new([10, 0, 0, i as u8]);
            cache.insert(ip, MacAddr::new([i as u8; 6]), i as u64);
        }
        assert!(cache.lookup(Ipv4Addr::new([10, 0, 0, 0]), 50).is_none());
        assert!(cache
            .lookup(Ipv4Addr::new([10, 0, 0, ARP_CACHE_CAPACITY as u8]), 50)
            .is_some());
    }

    #[test]
    fn cache_expiry_and_clear() {
        let mut cache = ArpCache::new(10);
        let ip = Ipv4Addr::new([1, 2, 3, 4]);
        cache.insert(ip, MacAddr::new([9; 6]), 0);
        assert!(cache.lookup(ip, 5).is_some());
        assert!(cache.lookup(ip, 10).is_none());
        cache.insert(ip, MacAddr::new([9; 6]), 0);
        cache.clear();
        assert!(cache.lookup(ip, 0).is_none());
        assert_eq!(cache.pending_count(), 0);
    }

    #[test]
    fn pending_bounded() {
        let mut cache = ArpCache::new(1);
        for i in 0..MAX_PENDING_ARP_REQUESTS {
            assert!(cache.track_pending(Ipv4Addr::new([i as u8; 4])));
        }
        assert!(!cache.track_pending(Ipv4Addr::new([99; 4])));
    }
}
