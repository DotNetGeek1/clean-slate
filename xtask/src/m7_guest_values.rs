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
}

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

/// Every boot sent exactly `expected`; no boot repeats the legacy values; consecutive boots
/// differ in their TCP source ports and in their DNS (port, ID) pairs; no ISS repeats anywhere
/// in the lane. Lists are compared whole, so a chance repeat of one 16-bit value cannot fail
/// a lane.
pub fn require_unpredictable(
    lane: &str,
    boots: &[GuestValues],
    expected: GuestExchanges,
    legacy: LegacyValues,
) -> Result<(), String> {
    let legacy_ports: Vec<u16> = legacy.tcp_syns.iter().map(|&(port, _)| port).collect();
    let legacy_iss: HashSet<u32> = legacy.tcp_syns.iter().map(|&(_, iss)| iss).collect();
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
        if !legacy.dns_queries.is_empty() && boot.dns_queries == legacy.dns_queries {
            return Err(format!(
                "{name}: DNS (port, ID) pairs {:?} are the old counter values",
                boot.dns_queries
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
