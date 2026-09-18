//! TCP segment parse/serialize (MSS-only options on SYN).

use crate::addr::{IpProtocol, Ipv4Addr};
use crate::checksum::Checksum;
use crate::ethernet::ParseError;
use crate::ipv4::pseudo_header_checksum;
use crate::limits::MAX_L3_PAYLOAD_BYTES;

/// Minimum TCP header length on the wire (no options).
pub const TCP_MIN_HEADER_LEN: usize = 20;

/// Maximum TCP payload per segment when IPv4 uses a 20-byte header and the TCP header has no options.
pub const MAX_TCP_PAYLOAD: usize = MAX_L3_PAYLOAD_BYTES - TCP_MIN_HEADER_LEN - TCP_MIN_HEADER_LEN;

/// Our advertised MSS (fits one Ethernet MTU with fixed L3/L4 headers).
pub const OUR_TCP_MSS: u16 = MAX_TCP_PAYLOAD as u16;

const MSS_OPTION_KIND: u8 = 2;
const MSS_OPTION_LEN: u8 = 4;
const NOP_OPTION: u8 = 1;
const EOL_OPTION: u8 = 0;

/// TCP control flags (byte 13 of the header).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: Self = Self(0x01);
    pub const SYN: Self = Self(0x02);
    pub const RST: Self = Self(0x04);
    pub const PSH: Self = Self(0x08);
    pub const ACK: Self = Self(0x10);
    pub const URG: Self = Self(0x20);

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Parsed TCP header and options relevant to this milestone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpSegment {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent: u16,
    pub mss_option: Option<u16>,
}

impl TcpSegment {
    pub fn header_len(self) -> usize {
        usize::from(self.data_offset) * 4
    }
}

/// Parses `bytes` as a TCP segment destined for `dst_ip` from `src_ip`.
pub fn parse(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    bytes: &[u8],
) -> Result<(TcpSegment, &[u8]), ParseError> {
    if bytes.len() < TCP_MIN_HEADER_LEN {
        return Err(ParseError::Truncated);
    }
    let src_port = u16::from_be_bytes([bytes[0], bytes[1]]);
    let dst_port = u16::from_be_bytes([bytes[2], bytes[3]]);
    let seq = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let ack = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let data_offset = bytes[12] >> 4;
    if !(5..=15).contains(&data_offset) {
        return Err(ParseError::BadHeaderLength);
    }
    let header_len = usize::from(data_offset) * 4;
    if header_len > bytes.len() {
        return Err(ParseError::Truncated);
    }
    let flags = TcpFlags(bytes[13]);
    let window = u16::from_be_bytes([bytes[14], bytes[15]]);
    let checksum = u16::from_be_bytes([bytes[16], bytes[17]]);
    let urgent = u16::from_be_bytes([bytes[18], bytes[19]]);

    let mut zeroed = [0u8; 60];
    let hdr = bytes.get(0..header_len).ok_or(ParseError::Truncated)?;
    zeroed[..header_len].copy_from_slice(hdr);
    zeroed[16] = 0;
    zeroed[17] = 0;
    let pseudo = pseudo_header_checksum(src_ip, dst_ip, IpProtocol::TCP, bytes.len() as u16);
    let mut sum = Checksum::new().add_bytes(&pseudo.to_be_bytes());
    sum = sum.add_bytes(&zeroed[..header_len]);
    let payload = bytes.get(header_len..).ok_or(ParseError::Truncated)?;
    sum = sum.add_bytes(payload);
    if sum.finish() != checksum {
        return Err(ParseError::BadChecksum);
    }

    let mss_option = parse_options(bytes.get(20..header_len).ok_or(ParseError::Truncated)?)?;

    Ok((
        TcpSegment {
            src_port,
            dst_port,
            seq,
            ack,
            data_offset,
            flags,
            window,
            checksum,
            urgent,
            mss_option,
        },
        payload,
    ))
}

fn parse_options(options: &[u8]) -> Result<Option<u16>, ParseError> {
    let mut i = 0;
    let mut mss = None;
    while i < options.len() {
        let kind = options[i];
        match kind {
            EOL_OPTION => break,
            NOP_OPTION => {
                i += 1;
            }
            MSS_OPTION_KIND => {
                if i + 1 >= options.len() {
                    return Err(ParseError::BadHeaderLength);
                }
                let len = options[i + 1];
                if len != MSS_OPTION_LEN {
                    return Err(ParseError::BadHeaderLength);
                }
                if i + usize::from(len) > options.len() {
                    return Err(ParseError::BadHeaderLength);
                }
                let val = u16::from_be_bytes([options[i + 2], options[i + 3]]);
                mss = Some(val);
                i += usize::from(len);
            }
            _ => {
                if i + 1 >= options.len() {
                    return Err(ParseError::BadHeaderLength);
                }
                let len = options[i + 1];
                if len < 2 {
                    return Err(ParseError::UnsupportedProtocol);
                }
                let advance = usize::from(len);
                if i + advance > options.len() {
                    return Err(ParseError::BadHeaderLength);
                }
                i += advance;
            }
        }
    }
    Ok(mss)
}

/// Writes `segment` and `payload` into `out`, returning total bytes written.
pub fn write(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    segment: &TcpSegment,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, ParseError> {
    let header_len = segment.header_len();
    let total = header_len
        .checked_add(payload.len())
        .ok_or(ParseError::PayloadTooLarge)?;
    if total > out.len() {
        return Err(ParseError::BufferTooSmall);
    }
    if payload.len() > MAX_TCP_PAYLOAD {
        return Err(ParseError::PayloadTooLarge);
    }

    out[0..2].copy_from_slice(&segment.src_port.to_be_bytes());
    out[2..4].copy_from_slice(&segment.dst_port.to_be_bytes());
    out[4..8].copy_from_slice(&segment.seq.to_be_bytes());
    out[8..12].copy_from_slice(&segment.ack.to_be_bytes());
    out[12] = (segment.data_offset << 4) & 0xF0;
    out[13] = segment.flags.get();
    out[14..16].copy_from_slice(&segment.window.to_be_bytes());
    out[16] = 0;
    out[17] = 0;
    out[18..20].copy_from_slice(&segment.urgent.to_be_bytes());

    if header_len > TCP_MIN_HEADER_LEN {
        write_options(
            segment,
            out.get_mut(20..header_len)
                .ok_or(ParseError::BufferTooSmall)?,
        )?;
    }

    out.get_mut(header_len..total)
        .ok_or(ParseError::BufferTooSmall)?
        .copy_from_slice(payload);

    let pseudo = pseudo_header_checksum(src_ip, dst_ip, IpProtocol::TCP, total as u16);
    let mut sum = Checksum::new().add_bytes(&pseudo.to_be_bytes());
    sum = sum.add_bytes(out.get(0..total).ok_or(ParseError::BufferTooSmall)?);
    let csum = sum.finish();
    out[16..18].copy_from_slice(&csum.to_be_bytes());

    Ok(total)
}

fn write_options(segment: &TcpSegment, out: &mut [u8]) -> Result<(), ParseError> {
    if segment.flags.contains(TcpFlags::SYN) && segment.mss_option.is_some() {
        if out.len() < 4 {
            return Err(ParseError::BufferTooSmall);
        }
        out[0] = MSS_OPTION_KIND;
        out[1] = MSS_OPTION_LEN;
        let mss = segment.mss_option.unwrap_or(OUR_TCP_MSS);
        out[2..4].copy_from_slice(&mss.to_be_bytes());
    }
    Ok(())
}

/// Builds a segment template for SYN with our MSS option (24-byte header).
pub fn syn_segment(src_port: u16, dst_port: u16, seq: u32) -> TcpSegment {
    TcpSegment {
        src_port,
        dst_port,
        seq,
        ack: 0,
        data_offset: 6,
        flags: TcpFlags::SYN,
        window: 4096,
        checksum: 0,
        urgent: 0,
        mss_option: Some(OUR_TCP_MSS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_without_mss() {
        let src = Ipv4Addr::new([10, 77, 0, 2]);
        let dst = Ipv4Addr::new([10, 77, 0, 1]);
        let seg = TcpSegment {
            src_port: 50000,
            dst_port: 4001,
            seq: 100,
            ack: 200,
            data_offset: 5,
            flags: TcpFlags::ACK,
            window: 4096,
            checksum: 0,
            urgent: 0,
            mss_option: None,
        };
        let payload = b"hello";
        let mut buf = [0u8; 64];
        let n = write(src, dst, &seg, payload, &mut buf).unwrap();
        let (parsed, pl) = parse(dst, src, &buf[..n]).unwrap();
        assert_eq!(pl, payload);
        assert_eq!(parsed.src_port, seg.src_port);
        assert_eq!(parsed.dst_port, seg.dst_port);
        assert_eq!(parsed.seq, seg.seq);
        assert_eq!(parsed.ack, seg.ack);
        assert_eq!(parsed.flags, seg.flags);
        assert_eq!(parsed.mss_option, None);
    }

    #[test]
    fn roundtrip_syn_with_mss() {
        let src = Ipv4Addr::new([10, 77, 0, 2]);
        let dst = Ipv4Addr::new([10, 77, 0, 1]);
        let seg = syn_segment(50000, 4001, 42);
        let mut buf = [0u8; 64];
        let n = write(src, dst, &seg, &[], &mut buf).unwrap();
        assert_eq!(n, 24);
        let (parsed, pl) = parse(dst, src, &buf[..n]).unwrap();
        assert!(pl.is_empty());
        assert_eq!(parsed.mss_option, Some(OUR_TCP_MSS));
        assert!(parsed.flags.contains(TcpFlags::SYN));
    }

    #[test]
    fn truncated_and_bad_offset() {
        let src = Ipv4Addr::new([1, 2, 3, 4]);
        let dst = Ipv4Addr::new([5, 6, 7, 8]);
        for len in 0..TCP_MIN_HEADER_LEN {
            assert_eq!(
                parse(src, dst, &[0u8; 20][..len]),
                Err(ParseError::Truncated)
            );
        }
        let mut buf = [0u8; 40];
        buf[12] = 0x40; // data offset 4
        assert_eq!(
            parse(src, dst, &buf[..20]),
            Err(ParseError::BadHeaderLength)
        );
        buf[12] = 0xF0; // data offset 15 but truncated
        assert_eq!(parse(src, dst, &buf[..20]), Err(ParseError::Truncated));
    }

    #[test]
    fn bad_checksum_rejected() {
        let src = Ipv4Addr::new([10, 0, 0, 1]);
        let dst = Ipv4Addr::new([10, 0, 0, 2]);
        let seg = TcpSegment {
            src_port: 1,
            dst_port: 2,
            seq: 0,
            ack: 0,
            data_offset: 5,
            flags: TcpFlags::ACK,
            window: 0,
            checksum: 0,
            urgent: 0,
            mss_option: None,
        };
        let mut buf = [0u8; 40];
        write(src, dst, &seg, &[], &mut buf).unwrap();
        buf[16] ^= 0xFF;
        assert_eq!(parse(dst, src, &buf[..20]), Err(ParseError::BadChecksum));
    }

    #[test]
    fn malformed_options() {
        let src = Ipv4Addr::new([10, 0, 0, 1]);
        let dst = Ipv4Addr::new([10, 0, 0, 2]);
        let mut buf = [0u8; 64];
        let seg = TcpSegment {
            src_port: 1,
            dst_port: 2,
            seq: 0,
            ack: 0,
            data_offset: 6,
            flags: TcpFlags::SYN,
            window: 100,
            checksum: 0,
            urgent: 0,
            mss_option: Some(1460),
        };
        write(src, dst, &seg, &[], &mut buf).unwrap();
        // len 0 on unknown option
        buf[20] = 99;
        buf[21] = 0;
        fix_checksum(&mut buf, 24, src, dst);
        assert_eq!(
            parse(dst, src, &buf[..24]),
            Err(ParseError::UnsupportedProtocol)
        );
        // len 1
        buf[21] = 1;
        fix_checksum(&mut buf, 24, src, dst);
        assert_eq!(
            parse(dst, src, &buf[..24]),
            Err(ParseError::UnsupportedProtocol)
        );
        // overrun
        buf[20] = 99;
        buf[21] = 8;
        fix_checksum(&mut buf, 24, src, dst);
        assert_eq!(
            parse(dst, src, &buf[..24]),
            Err(ParseError::BadHeaderLength)
        );
    }

    fn fix_checksum(buf: &mut [u8], total: usize, src: Ipv4Addr, dst: Ipv4Addr) {
        buf[16] = 0;
        buf[17] = 0;
        let pseudo = pseudo_header_checksum(src, dst, IpProtocol::TCP, total as u16);
        let mut sum = Checksum::new().add_bytes(&pseudo.to_be_bytes());
        sum = sum.add_bytes(&buf[..total]);
        let csum = sum.finish();
        buf[16..18].copy_from_slice(&csum.to_be_bytes());
    }

    #[test]
    fn parser_never_panics_random_lengths() {
        let src = Ipv4Addr::new([10, 77, 0, 2]);
        let dst = Ipv4Addr::new([10, 77, 0, 1]);
        let mut state = 0xCAFE_BABE_u32;
        for _ in 0..512 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let len = (state as usize) % 1501;
            let mut buf = [0u8; 1500];
            for byte in buf.iter_mut().take(len) {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *byte = (state >> 16) as u8;
            }
            let _ = parse(src, dst, &buf[..len]);
        }
    }

    #[test]
    fn max_tcp_payload_constant() {
        assert_eq!(MAX_TCP_PAYLOAD, 1460);
    }
}
