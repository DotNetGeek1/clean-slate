//! #221: the values an off-path attacker would have to guess to spoof the guest's TCP and DNS
//! traffic (TCP initial sequence numbers, source ports, DNS query IDs), as the fixture saw them
//! on the wire. Lanes require that they change from boot to boot and that none of them is the
//! value the old deterministic allocators produced.

use std::collections::HashSet;

use clean_slate_network::addr::{EtherType, IpProtocol};
use clean_slate_network::ethernet::EthernetHeader;
use clean_slate_network::fixture::{DNS_SERVER_PORT, PEER_IPV4};
use clean_slate_network::ipv4::Ipv4Header;
use clean_slate_network::tcp::{parse_tcp_segment, TcpFlags};

const UDP_HEADER_BYTES: usize = 8;
const DNS_HEADER_BYTES: usize = 12;

/// What the guest put on the wire, in order. Retransmissions repeat a SYN or a query exactly,
/// so each distinct value is recorded once.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GuestValues {
    /// Frames of any kind the guest sent.
    pub frames: u32,
    /// `(source port, initial sequence number)` of each distinct SYN the guest sent.
    pub tcp_syns: Vec<(u16, u32)>,
    /// `(source port, query ID)` of each distinct DNS query the guest sent to the fixture.
    pub dns_queries: Vec<(u16, u16)>,
}

impl GuestValues {
    /// Records one frame from the guest, before the impaired wire drops or forwards it.
    pub fn observe(&mut self, frame: &[u8]) {
        self.frames += 1;
        let Ok((eth, l3)) = EthernetHeader::parse(frame) else {
            return;
        };
        if eth.ethertype != EtherType::IPV4 {
            return;
        }
        let Ok((ip, ip_payload)) = Ipv4Header::parse(l3) else {
            return;
        };
        if ip.protocol == IpProtocol::TCP {
            let Ok((seg, _)) = parse_tcp_segment(ip.src, ip.dst, ip_payload) else {
                return;
            };
            if seg.flags.contains(TcpFlags::SYN) && !seg.flags.contains(TcpFlags::ACK) {
                push_distinct(&mut self.tcp_syns, (seg.src_port, seg.seq));
            }
        } else if ip.protocol == IpProtocol::UDP && ip.dst == PEER_IPV4 {
            if ip_payload.len() < UDP_HEADER_BYTES + DNS_HEADER_BYTES {
                return;
            }
            let src_port = u16::from_be_bytes([ip_payload[0], ip_payload[1]]);
            let dst_port = u16::from_be_bytes([ip_payload[2], ip_payload[3]]);
            if dst_port != DNS_SERVER_PORT {
                return;
            }
            let dns = &ip_payload[UDP_HEADER_BYTES..];
            push_distinct(
                &mut self.dns_queries,
                (src_port, u16::from_be_bytes([dns[0], dns[1]])),
            );
        }
    }

    fn tcp_ports(&self) -> Vec<u16> {
        self.tcp_syns.iter().map(|&(port, _)| port).collect()
    }

    fn dns_ids(&self) -> Vec<u16> {
        self.dns_queries.iter().map(|&(_, id)| id).collect()
    }
}

/// Boots that send at least this many DNS queries must also change their query IDs alone from
/// one boot to the next; with fewer, a chance repeat of the ID list (1 in 65536 for one query)
/// would fail a sound guest, so only (port, ID) pairs are compared.
const DNS_IDS_COMPARED_ALONE_FROM: usize = 2;

fn push_distinct<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}

/// How many SYNs and DNS queries each boot of a lane sends, so the checks below cannot pass on
/// a boot that sent nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestExchanges {
    pub tcp_syns: usize,
    pub dns_queries: usize,
}

/// What the old allocators put on the wire for a lane's boot: ports from a fixed base plus the
/// slot, ISS from the service generation, slot and a counter, DNS IDs counting up from the
/// generation. Recorded from that lane on `main` before #221 stage C.
#[derive(Clone, Copy, Debug)]
pub struct LegacyValues {
    pub tcp_syns: &'static [(u16, u32)],
    pub dns_queries: &'static [(u16, u16)],
}

/// Every boot sent exactly `expected`; no boot repeats the legacy ports or DNS IDs; consecutive
/// boots differ in their TCP source ports and in their DNS (port, ID) pairs, and also in their
/// DNS IDs alone when a boot sends [`DNS_IDS_COMPARED_ALONE_FROM`] queries or more; no ISS
/// repeats anywhere in the lane. Lists are compared whole, so a chance repeat of one 16-bit
/// value cannot fail a lane.
pub fn require_unpredictable(
    lane: &str,
    boots: &[GuestValues],
    expected: GuestExchanges,
    legacy: LegacyValues,
) -> Result<(), String> {
    let legacy_ports: Vec<u16> = legacy.tcp_syns.iter().map(|&(port, _)| port).collect();
    let legacy_iss: HashSet<u32> = legacy.tcp_syns.iter().map(|&(_, iss)| iss).collect();
    let legacy_dns_ids: Vec<u16> = legacy.dns_queries.iter().map(|&(_, id)| id).collect();
    let mut seen_iss = HashSet::new();
    for (index, boot) in boots.iter().enumerate() {
        let name = format!("{lane} boot {}", index + 1);
        if boot.tcp_syns.len() != expected.tcp_syns
            || boot.dns_queries.len() != expected.dns_queries
        {
            return Err(format!(
                "{name}: the fixture saw {} SYN(s) and {} DNS query(ies), expected {} and {}",
                boot.tcp_syns.len(),
                boot.dns_queries.len(),
                expected.tcp_syns,
                expected.dns_queries
            ));
        }
        if !legacy_ports.is_empty() && boot.tcp_ports() == legacy_ports {
            return Err(format!(
                "{name}: TCP source ports {:?} are the old fixed-base ports",
                boot.tcp_ports()
            ));
        }
        if !legacy_dns_ids.is_empty() && boot.dns_ids() == legacy_dns_ids {
            return Err(format!(
                "{name}: DNS query IDs {:?} are the old counter values",
                boot.dns_ids()
            ));
        }
        for &(port, iss) in &boot.tcp_syns {
            if legacy_iss.contains(&iss) {
                return Err(format!(
                    "{name}: ISS {iss:#010x} (port {port}) is an old deterministic ISS"
                ));
            }
            if !seen_iss.insert(iss) {
                return Err(format!(
                    "{name}: ISS {iss:#010x} (port {port}) repeats an ISS seen earlier in the lane"
                ));
            }
        }
    }
    for (index, pair) in boots.windows(2).enumerate() {
        let (before, after) = (&pair[0], &pair[1]);
        let name = format!("{lane} boot {}", index + 2);
        if expected.tcp_syns > 0 && after.tcp_ports() == before.tcp_ports() {
            return Err(format!(
                "{name}: TCP source ports {:?} repeat the previous boot's",
                after.tcp_ports()
            ));
        }
        if expected.dns_queries > 0 && after.dns_queries == before.dns_queries {
            return Err(format!(
                "{name}: DNS (port, ID) pairs {:?} repeat the previous boot's",
                after.dns_queries
            ));
        }
        if expected.dns_queries >= DNS_IDS_COMPARED_ALONE_FROM
            && after.dns_ids() == before.dns_ids()
        {
            return Err(format!(
                "{name}: DNS query IDs {:?} repeat the previous boot's",
                after.dns_ids()
            ));
        }
    }
    Ok(())
}

/// Prints what a lane's boots chose, so a passing run records its evidence.
pub fn report(lane: &str, boots: &[GuestValues]) {
    for (index, boot) in boots.iter().enumerate() {
        println!(
            "[FIX ] {lane} boot {} guest values tcp(port,iss)={:?} dns(port,id)={:?} frames={}",
            index + 1,
            boot.tcp_syns
                .iter()
                .map(|&(port, iss)| format!("({port},{iss:#010x})"))
                .collect::<Vec<_>>(),
            boot.dns_queries
                .iter()
                .map(|&(port, id)| format!("({port},{id:#06x})"))
                .collect::<Vec<_>>(),
            boot.frames
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m7_fixture_impair::tcp_frame;
    use clean_slate_network::fixture::{GUEST_IPV4, GUEST_MAC, PEER_MAC};
    use clean_slate_network::tcp::TcpSegment;

    const ETH: EthernetHeader = EthernetHeader {
        dst: PEER_MAC,
        src: GUEST_MAC,
        ethertype: EtherType::IPV4,
    };

    fn syn(port: u16, iss: u32) -> Vec<u8> {
        let seg = TcpSegment {
            src_port: port,
            dst_port: 4443,
            seq: iss,
            ack: 0,
            data_offset: 5,
            flags: TcpFlags::SYN,
            window: 4096,
            checksum: 0,
            urgent: 0,
            mss_option: None,
        };
        tcp_frame(ETH, GUEST_IPV4, PEER_IPV4, &seg, &[]).unwrap()
    }

    fn dns_query(port: u16, id: u16) -> Vec<u8> {
        let mut udp = Vec::new();
        udp.extend(port.to_be_bytes());
        udp.extend(DNS_SERVER_PORT.to_be_bytes());
        udp.extend(((UDP_HEADER_BYTES + DNS_HEADER_BYTES) as u16).to_be_bytes());
        udp.extend([0, 0]);
        udp.extend(id.to_be_bytes());
        udp.extend([0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        let mut frame = vec![0u8; EthernetHeader::LEN + 20 + udp.len()];
        let ip_off = ETH.write(&mut frame).unwrap();
        let ip = Ipv4Header {
            src: GUEST_IPV4,
            dst: PEER_IPV4,
            protocol: IpProtocol::UDP,
            ttl: 64,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            header_len: 20,
            total_len: 0,
            dscp: 0,
            ecn: 0,
        };
        ip.write(&mut frame[ip_off..], udp.len()).unwrap();
        frame[ip_off + 20..].copy_from_slice(&udp);
        frame
    }

    fn boot(tcp_syns: &[(u16, u32)], dns_queries: &[(u16, u16)]) -> GuestValues {
        GuestValues {
            frames: (tcp_syns.len() + dns_queries.len()) as u32,
            tcp_syns: tcp_syns.to_vec(),
            dns_queries: dns_queries.to_vec(),
        }
    }

    use crate::{
        M7_DNS_EXCHANGES as DNS, M7_DNS_LEGACY as DNS_LEGACY, M7_NETWORK_EXCHANGES as NETWORK,
        M7_NETWORK_LEGACY as NETWORK_LEGACY, M7_TLS_EXCHANGES as TLS, M7_TLS_LEGACY as TLS_LEGACY,
    };

    fn network_boots() -> [GuestValues; 2] {
        [
            boot(
                &[(51_234, 0x1111_1111), (62_001, 0x2222_2222)],
                &[(58_000, 0x9a3c)],
            ),
            boot(
                &[(49_700, 0x3333_3333), (55_555, 0x4444_4444)],
                &[(60_123, 0x17e2)],
            ),
        ]
    }

    fn dns_boots() -> [GuestValues; 2] {
        [
            boot(&[], &[(53_001, 0x4d21), (61_002, 0xb7c0)]),
            boot(&[], &[(50_404, 0x0e9f), (57_777, 0x6a15)]),
        ]
    }

    fn assert_fails(result: Result<(), String>, needle: &str) {
        let error = result.expect_err("the gate accepted the boots");
        assert!(
            error.contains(needle),
            "{error:?} does not mention {needle:?}"
        );
    }

    #[test]
    fn valid_boots_pass_every_lane() {
        let tls = [
            boot(&[(51_000, 0x0101_0101), (60_000, 0x0202_0202)], &[]),
            boot(&[(52_000, 0x0303_0303), (61_000, 0x0404_0404)], &[]),
        ];
        assert_eq!(require_unpredictable("tls", &tls, TLS, TLS_LEGACY), Ok(()));
        assert_eq!(
            require_unpredictable("dns", &dns_boots(), DNS, DNS_LEGACY),
            Ok(())
        );
        assert_eq!(
            require_unpredictable("net", &network_boots(), NETWORK, NETWORK_LEGACY),
            Ok(())
        );
    }

    #[test]
    fn a_wrong_count_fails() {
        let mut boots = network_boots();
        boots[1].tcp_syns.pop();
        assert_fails(
            require_unpredictable("net", &boots, NETWORK, NETWORK_LEGACY),
            "boot 2: the fixture saw 1 SYN(s)",
        );
        let mut boots = dns_boots();
        boots[0].dns_queries.push((65_000, 0x1234));
        assert_fails(
            require_unpredictable("dns", &boots, DNS, DNS_LEGACY),
            "boot 1: the fixture saw 0 SYN(s) and 3 DNS",
        );
    }

    #[test]
    fn an_empty_boot_fails() {
        let mut boots = network_boots();
        boots[0] = GuestValues::default();
        assert_fails(
            require_unpredictable("net", &boots, NETWORK, NETWORK_LEGACY),
            "boot 1: the fixture saw 0 SYN(s) and 0 DNS",
        );
    }

    #[test]
    fn identical_port_lists_fail() {
        let mut boots = network_boots();
        boots[1].tcp_syns = vec![(51_234, 0x5555_5555), (62_001, 0x6666_6666)];
        assert_fails(
            require_unpredictable("net", &boots, NETWORK, NETWORK_LEGACY),
            "boot 2: TCP source ports [51234, 62001] repeat",
        );
    }

    #[test]
    fn legacy_ports_and_iss_fail() {
        let mut boots = network_boots();
        boots[0].tcp_syns = vec![(50_000, 0x7777_7777), (50_001, 0x8888_8888)];
        assert_fails(
            require_unpredictable("net", &boots, NETWORK, NETWORK_LEGACY),
            "old fixed-base ports",
        );
        let mut boots = network_boots();
        boots[1].tcp_syns[0].1 = 0x0000_0001;
        assert_fails(
            require_unpredictable("net", &boots, NETWORK, NETWORK_LEGACY),
            "is an old deterministic ISS",
        );
    }

    #[test]
    fn legacy_dns_ids_fail_whatever_the_ports() {
        let mut boots = dns_boots();
        boots[1].dns_queries = vec![(52_000, 0x0000), (63_000, 0x0003)];
        assert_fails(
            require_unpredictable("dns", &boots, DNS, DNS_LEGACY),
            "boot 2: DNS query IDs [0, 3] are the old counter values",
        );
        let mut boots = network_boots();
        boots[0].dns_queries = vec![(58_000, 0x0000)];
        assert_fails(
            require_unpredictable("net", &boots, NETWORK, NETWORK_LEGACY),
            "boot 1: DNS query IDs [0] are the old counter values",
        );
    }

    #[test]
    fn a_repeated_iss_fails_even_across_boots() {
        let mut boots = network_boots();
        boots[1].tcp_syns[1].1 = boots[0].tcp_syns[0].1;
        assert_fails(
            require_unpredictable("net", &boots, NETWORK, NETWORK_LEGACY),
            "repeats an ISS seen earlier in the lane",
        );
    }

    #[test]
    fn identical_dns_pairs_fail() {
        let mut boots = network_boots();
        boots[1].dns_queries = boots[0].dns_queries.clone();
        assert_fails(
            require_unpredictable("net", &boots, NETWORK, NETWORK_LEGACY),
            "DNS (port, ID) pairs",
        );
    }

    #[test]
    fn identical_dns_id_lists_fail_on_the_dns_lane_even_with_fresh_ports() {
        let mut boots = dns_boots();
        boots[1].dns_queries = vec![(50_404, 0x4d21), (57_777, 0xb7c0)];
        assert_fails(
            require_unpredictable("dns", &boots, DNS, DNS_LEGACY),
            "boot 2: DNS query IDs [19745, 47040] repeat the previous boot's",
        );
    }

    #[test]
    fn one_query_lanes_compare_pairs_not_ids_alone() {
        let mut boots = network_boots();
        boots[1].dns_queries = vec![(60_123, boots[0].dns_queries[0].1)];
        assert_eq!(
            require_unpredictable("net", &boots, NETWORK, NETWORK_LEGACY),
            Ok(())
        );
    }

    #[test]
    fn observe_records_syns_and_queries_once_each() {
        let mut values = GuestValues::default();
        for frame in [
            syn(51_000, 0xabcd_0001),
            dns_query(53_000, 0x1234),
            syn(51_000, 0xabcd_0001),
            dns_query(53_000, 0x1234),
            syn(52_000, 0xabcd_0002),
            dns_query(54_000, 0x5678),
        ] {
            values.observe(&frame);
        }
        assert_eq!(values.frames, 6);
        assert_eq!(
            values.tcp_syns,
            [(51_000, 0xabcd_0001), (52_000, 0xabcd_0002)]
        );
        assert_eq!(values.dns_queries, [(53_000, 0x1234), (54_000, 0x5678)]);
    }

    #[test]
    fn observe_ignores_frames_that_are_not_guest_syns_or_queries() {
        let mut values = GuestValues::default();
        let syn_ack = TcpSegment {
            src_port: 51_000,
            dst_port: 4443,
            seq: 2,
            ack: 9,
            data_offset: 5,
            flags: TcpFlags::SYN.union(TcpFlags::ACK),
            window: 4096,
            checksum: 0,
            urgent: 0,
            mss_option: None,
        };
        let mut runt = syn(51_000, 1);
        runt.truncate(10);
        for frame in [
            tcp_frame(ETH, GUEST_IPV4, PEER_IPV4, &syn_ack, &[]).unwrap(),
            runt,
        ] {
            values.observe(&frame);
        }
        assert_eq!(values.frames, 2);
        assert!(values.tcp_syns.is_empty());
        assert!(values.dns_queries.is_empty());
    }
}
