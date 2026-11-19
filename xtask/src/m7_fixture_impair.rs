//! #221 stage A: a deterministic adversarial wire between QEMU and the M7 fixture.
//!
//! Every impairment is a one-shot per DNS query ID or per TCP connection, so a lane can require
//! exact counts of what the fixture did to the guest (#223): an impairment that silently did
//! not fire fails the lane, and so does a guest that did not recover from one.

use std::collections::{HashMap, HashSet};

use clean_slate_network::addr::{EtherType, IpProtocol, Ipv4Addr};
use clean_slate_network::ethernet::EthernetHeader;
use clean_slate_network::fixture::PEER_IPV4;
use clean_slate_network::ipv4::Ipv4Header;
use clean_slate_network::tcp::{parse_tcp_segment, write_tcp_segment, TcpFlags, TcpSegment};

/// The address every forged DNS answer carries; a guest that prints it accepted a forgery.
pub const DNS_DECOY_ADDR: [u8; 4] = [10, 77, 0, 66];

/// Source port of the forged DNS reply that tests the guest's server-port check.
pub const DNS_FORGERY_PORT: u16 = 5353;

/// What the impaired wire did, one counter per kind of impairment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImpairCounts {
    /// First copy of each DNS query ID, dropped unanswered.
    pub dns_queries_dropped: u32,
    /// Forged DNS replies sent ahead of a real one.
    pub dns_forged_replies: u32,
    /// First SYN of each guest connection, dropped.
    pub tcp_syns_dropped: u32,
    /// First guest data segment of each connection, dropped.
    pub tcp_guest_data_dropped: u32,
    /// Blind RSTs (sequence number off by one) injected ahead of the fixture's first data.
    pub tcp_blind_rsts: u32,
    /// Fixture data segments delivered split in two, second half first.
    pub tcp_reordered: u32,
    /// Stale duplicates of already-delivered fixture data.
    pub tcp_stale_duplicates: u32,
}

impl ImpairCounts {
    pub const ZERO: Self = Self {
        dns_queries_dropped: 0,
        dns_forged_replies: 0,
        tcp_syns_dropped: 0,
        tcp_guest_data_dropped: 0,
        tcp_blind_rsts: 0,
        tcp_reordered: 0,
        tcp_stale_duplicates: 0,
    };
}

/// DNS impairments: which query IDs have been dropped once already.
#[derive(Default)]
pub struct DnsImpairer {
    dropped_ids: HashSet<u16>,
}

impl DnsImpairer {
    /// True when this is the first copy of `query`'s ID, which the fixture drops.
    pub fn drop_first_copy(&mut self, query: &[u8]) -> bool {
        query.len() >= 2
            && self
                .dropped_ids
                .insert(u16::from_be_bytes([query[0], query[1]]))
    }
}

/// Forged replies to `query`, each carrying [`DNS_DECOY_ADDR`], that the guest must ignore.
/// `from_port_53` are sent from the DNS server's own socket, `from_other_port` from
/// [`DNS_FORGERY_PORT`]. Returns `None` for anything that is not a single-question query.
pub fn forged_dns_replies(query: &[u8]) -> Option<ForgedDnsReplies> {
    let answer = decoy_a_answer(query)?;
    let mut wrong_id = answer.clone();
    wrong_id[0] ^= 0x80;
    let mut truncated_flag = answer.clone();
    truncated_flag[2] |= 0x02;
    let mut cut_short = answer.clone();
    cut_short.truncate(answer.len() - 2);
    Some(ForgedDnsReplies {
        from_port_53: vec![wrong_id, truncated_flag, cut_short],
        from_other_port: answer,
    })
}

pub struct ForgedDnsReplies {
    pub from_port_53: Vec<Vec<u8>>,
    pub from_other_port: Vec<u8>,
}

/// A well-formed answer to `query`'s question with the query's ID and one A record for the
/// decoy address.
fn decoy_a_answer(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 || u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }
    let mut offset = 12;
    loop {
        let len = *query.get(offset)? as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        offset += len;
    }
    let question = query.get(12..offset + 4)?;
    let mut answer = Vec::with_capacity(question.len() + 28);
    answer.extend_from_slice(&query[..2]);
    answer.extend_from_slice(&0x8180u16.to_be_bytes());
    answer.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
    answer.extend_from_slice(question);
    answer.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
    answer.extend_from_slice(&300u32.to_be_bytes());
    answer.extend_from_slice(&4u16.to_be_bytes());
    answer.extend_from_slice(&DNS_DECOY_ADDR);
    Some(answer)
}

/// Per-connection TCP impairment state, keyed by (guest port, fixture port).
#[derive(Clone, Copy)]
struct ConnScript {
    guest_iss: u32,
    syn_dropped: bool,
    guest_data_dropped: bool,
    fixture_data_scripted: bool,
}

/// Outcome of one impaired TCP decision, for the fixture's log and counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpImpairment {
    SynDropped,
    GuestDataDropped,
    /// The fixture's first data segment was replaced by: blind RST, second half, first half,
    /// second half again, stale copy of the first half.
    FixtureDataScripted,
}

#[derive(Default)]
pub struct TcpImpairer {
    conns: HashMap<(u16, u16), ConnScript>,
}

impl TcpImpairer {
    /// Decides whether a guest → fixture frame is dropped.
    pub fn guest_frame(&mut self, frame: &[u8]) -> Option<TcpImpairment> {
        let tcp = ParsedTcp::parse(frame)?;
        if tcp.ip.dst != PEER_IPV4 {
            return None;
        }
        let key = (tcp.seg.src_port, tcp.seg.dst_port);
        if tcp.seg.flags.contains(TcpFlags::SYN) && !tcp.seg.flags.contains(TcpFlags::ACK) {
            let conn = self.conns.entry(key).or_insert(ConnScript {
                guest_iss: tcp.seg.seq,
                syn_dropped: false,
                guest_data_dropped: false,
                fixture_data_scripted: false,
            });
            if conn.guest_iss != tcp.seg.seq {
                *conn = ConnScript {
                    guest_iss: tcp.seg.seq,
                    syn_dropped: false,
                    guest_data_dropped: false,
                    fixture_data_scripted: false,
                };
            }
            if !conn.syn_dropped {
                conn.syn_dropped = true;
                return Some(TcpImpairment::SynDropped);
            }
            return None;
        }
        if tcp.payload.is_empty() {
            return None;
        }
        let conn = self.conns.get_mut(&key)?;
        if conn.guest_data_dropped {
            return None;
        }
        conn.guest_data_dropped = true;
        Some(TcpImpairment::GuestDataDropped)
    }

    /// The frames to put on the wire in place of a fixture → guest frame.
    pub fn fixture_frame(&mut self, frame: &[u8]) -> (Vec<Vec<u8>>, Option<TcpImpairment>) {
        let unchanged = || (vec![frame.to_vec()], None);
        let Some(tcp) = ParsedTcp::parse(frame) else {
            return unchanged();
        };
        let flags = tcp.seg.flags;
        if tcp.ip.src != PEER_IPV4
            || tcp.payload.len() < 2
            || flags.contains(TcpFlags::SYN)
            || flags.contains(TcpFlags::RST)
        {
            return unchanged();
        }
        let Some(conn) = self.conns.get_mut(&(tcp.seg.dst_port, tcp.seg.src_port)) else {
            return unchanged();
        };
        if conn.fixture_data_scripted {
            return unchanged();
        }
        conn.fixture_data_scripted = true;

        let mid = tcp.payload.len() / 2;
        let (first, second) = tcp.payload.split_at(mid);
        let without_fin = TcpFlags(flags.0 & !TcpFlags::FIN.0);
        let blind_rst = TcpSegment {
            seq: tcp.seg.seq.wrapping_add(1),
            ack: 0,
            flags: TcpFlags::RST,
            window: 0,
            ..tcp.plain_segment()
        };
        let first_half = TcpSegment {
            flags: without_fin,
            ..tcp.plain_segment()
        };
        let second_half = TcpSegment {
            seq: tcp.seg.seq.wrapping_add(mid as u32),
            ..tcp.plain_segment()
        };
        let frames = [
            tcp.rebuild(&blind_rst, &[]),
            tcp.rebuild(&second_half, second),
            tcp.rebuild(&first_half, first),
            tcp.rebuild(&second_half, second),
            tcp.rebuild(&first_half, first),
        ];
        if frames.iter().any(Option::is_none) {
            return unchanged();
        }
        (
            frames.into_iter().flatten().collect(),
            Some(TcpImpairment::FixtureDataScripted),
        )
    }
}

struct ParsedTcp<'a> {
    eth: EthernetHeader,
    ip: Ipv4Header,
    seg: TcpSegment,
    payload: &'a [u8],
}

impl<'a> ParsedTcp<'a> {
    fn parse(frame: &'a [u8]) -> Option<Self> {
        let (eth, l3) = EthernetHeader::parse(frame).ok()?;
        if eth.ethertype != EtherType::IPV4 {
            return None;
        }
        let (ip, ip_payload) = Ipv4Header::parse(l3).ok()?;
        if ip.protocol != IpProtocol::TCP {
            return None;
        }
        let (seg, payload) = parse_tcp_segment(ip.src, ip.dst, ip_payload).ok()?;
        Some(Self {
            eth,
            ip,
            seg,
            payload,
        })
    }

    /// The segment's ports, numbers, flags and window, without options.
    fn plain_segment(&self) -> TcpSegment {
        TcpSegment {
            data_offset: 5,
            checksum: 0,
            urgent: 0,
            mss_option: None,
            ..self.seg
        }
    }

    /// A frame with this frame's Ethernet and IPv4 headers around `seg` and `payload`.
    fn rebuild(&self, seg: &TcpSegment, payload: &[u8]) -> Option<Vec<u8>> {
        tcp_frame(self.eth, self.ip.src, self.ip.dst, seg, payload)
    }
}

/// An Ethernet + 20-byte IPv4 + TCP frame with valid checksums.
pub fn tcp_frame(
    eth: EthernetHeader,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    seg: &TcpSegment,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let mut frame = vec![0u8; 14 + 20 + 60 + payload.len()];
    let ip_off = eth.write(&mut frame).ok()?;
    let tcp_off = ip_off + 20;
    let tcp_len = write_tcp_segment(src, dst, seg, payload, &mut frame[tcp_off..]).ok()?;
    let ip = Ipv4Header {
        src,
        dst,
        protocol: IpProtocol::TCP,
        ttl: 64,
        identification: 0,
        flags: 0,
        fragment_offset: 0,
        header_len: 20,
        total_len: 0,
        dscp: 0,
        ecn: 0,
    };
    ip.write(&mut frame[ip_off..], tcp_len).ok()?;
    frame.truncate(tcp_off + tcp_len);
    Some(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_network::addr::MacAddr;
    use clean_slate_network::fixture::{GUEST_IPV4, GUEST_MAC, PEER_MAC};

    fn frame(from_guest: bool, seg: TcpSegment, payload: &[u8]) -> Vec<u8> {
        let (src_mac, dst_mac, src, dst): (MacAddr, MacAddr, _, _) = if from_guest {
            (GUEST_MAC, PEER_MAC, GUEST_IPV4, PEER_IPV4)
        } else {
            (PEER_MAC, GUEST_MAC, PEER_IPV4, GUEST_IPV4)
        };
        let eth = EthernetHeader {
            dst: dst_mac,
            src: src_mac,
            ethertype: EtherType::IPV4,
        };
        tcp_frame(eth, src, dst, &seg, payload).unwrap()
    }

    fn seg(src_port: u16, dst_port: u16, seq: u32, flags: TcpFlags) -> TcpSegment {
        TcpSegment {
            src_port,
            dst_port,
            seq,
            ack: 0,
            data_offset: 5,
            flags,
            window: 4096,
            checksum: 0,
            urgent: 0,
            mss_option: None,
        }
    }

    fn decoded(frame: &[u8]) -> (TcpSegment, Vec<u8>) {
        let tcp = ParsedTcp::parse(frame).unwrap();
        (tcp.seg, tcp.payload.to_vec())
    }

    #[test]
    fn each_connection_loses_its_first_syn_and_first_data_segment_once() {
        let mut wire = TcpImpairer::default();
        let syn = frame(true, seg(50000, 4001, 7, TcpFlags::SYN), &[]);
        assert_eq!(wire.guest_frame(&syn), Some(TcpImpairment::SynDropped));
        assert_eq!(wire.guest_frame(&syn), None, "the retransmitted SYN passes");
        let data = frame(true, seg(50000, 4001, 8, TcpFlags::ACK), b"request");
        assert_eq!(
            wire.guest_frame(&data),
            Some(TcpImpairment::GuestDataDropped)
        );
        assert_eq!(wire.guest_frame(&data), None);
        // A new connection on the same ports (new ISS) is impaired again.
        let syn = frame(true, seg(50000, 4001, 9000, TcpFlags::SYN), &[]);
        assert_eq!(wire.guest_frame(&syn), Some(TcpImpairment::SynDropped));
    }

    #[test]
    fn the_first_fixture_data_segment_arrives_split_reordered_and_duplicated() {
        let mut wire = TcpImpairer::default();
        wire.guest_frame(&frame(true, seg(50001, 4443, 1, TcpFlags::SYN), &[]));
        let reply = frame(
            false,
            seg(4443, 50001, 100, TcpFlags::ACK.union(TcpFlags::FIN)),
            b"abcdef",
        );
        let (frames, what) = wire.fixture_frame(&reply);
        assert_eq!(what, Some(TcpImpairment::FixtureDataScripted));
        let got: Vec<_> = frames.iter().map(|f| decoded(f)).collect();
        assert_eq!(got.len(), 5);
        assert!(got[0].0.flags.contains(TcpFlags::RST));
        assert_eq!(
            got[0].0.seq, 101,
            "blind RST is one off the expected sequence"
        );
        assert_eq!((got[1].0.seq, got[1].1.as_slice()), (103, &b"def"[..]));
        assert!(got[1].0.flags.contains(TcpFlags::FIN));
        assert_eq!((got[2].0.seq, got[2].1.as_slice()), (100, &b"abc"[..]));
        assert!(!got[2].0.flags.contains(TcpFlags::FIN));
        assert_eq!(got[3], got[1]);
        assert_eq!(got[4], got[2]);
        let (again, what) = wire.fixture_frame(&reply);
        assert_eq!((again, what), (vec![reply], None));
    }

    #[test]
    fn unknown_connections_and_empty_segments_pass_untouched() {
        let mut wire = TcpImpairer::default();
        let ack = frame(false, seg(4443, 50002, 5, TcpFlags::ACK), &[]);
        assert_eq!(wire.fixture_frame(&ack), (vec![ack.clone()], None));
        let data = frame(false, seg(4443, 50002, 5, TcpFlags::ACK), b"xy");
        assert_eq!(wire.fixture_frame(&data), (vec![data.clone()], None));
    }

    #[test]
    fn dns_queries_lose_their_first_copy_and_forgeries_carry_the_decoy() {
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(b"\x02m7\x07fixture\x04test\x00\x00\x01\x00\x01");
        let mut dns = DnsImpairer::default();
        assert!(dns.drop_first_copy(&query));
        assert!(!dns.drop_first_copy(&query));
        let forged = forged_dns_replies(&query).unwrap();
        let [wrong_id, tc, cut] = forged.from_port_53.as_slice() else {
            panic!("three forgeries from port 53");
        };
        assert_ne!(wrong_id[..2], query[..2]);
        assert_eq!(tc[..2], query[..2]);
        assert_ne!(tc[2] & 0x02, 0);
        assert_eq!(cut.len(), forged.from_other_port.len() - 2);
        assert!(forged.from_other_port.ends_with(&DNS_DECOY_ADDR));
    }
}
