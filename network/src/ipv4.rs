//! IPv4 header parsing and serialization (no fragmentation reassembly).

use crate::addr::{IpProtocol, Ipv4Addr};
use crate::checksum::{checksum, Checksum};
use crate::ethernet::ParseError;
use crate::limits::MAX_L3_PAYLOAD_BYTES;

pub const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV4_VERSION: u8 = 4;

/// Parsed IPv4 header (options skipped, not interpreted).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Header {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: IpProtocol,
    pub ttl: u8,
    pub identification: u16,
    pub flags: u16,
    pub fragment_offset: u16,
    pub header_len: usize,
    pub total_len: u16,
    pub dscp: u8,
    pub ecn: u8,
}

impl Ipv4Header {
    /// Parses an IPv4 header from `data`, returning the header and L4 payload slice.
    ///
    /// Rejects fragmented datagrams (MF set or non-zero fragment offset). Trailing
    /// Ethernet padding beyond `total_len` is ignored; the payload is truncated to
    /// `total_len - header_len`.
    pub fn parse(data: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        if data.len() < IPV4_MIN_HEADER_LEN {
            return Err(ParseError::Truncated);
        }
        let version_ihl = *data.first().ok_or(ParseError::Truncated)?;
        let version = version_ihl >> 4;
        if version != IPV4_VERSION {
            return Err(ParseError::BadVersion);
        }
        let ihl = (version_ihl & 0x0F) as usize;
        if !(5..=15).contains(&ihl) {
            return Err(ParseError::BadHeaderLength);
        }
        let header_len = ihl.checked_mul(4).ok_or(ParseError::BadHeaderLength)?;
        if header_len > data.len() {
            return Err(ParseError::Truncated);
        }
        let header = data.get(0..header_len).ok_or(ParseError::Truncated)?;
        let checksum_wire = u16::from_be_bytes([header[10], header[11]]);
        let mut zeroed = [0u8; 60];
        zeroed[..header_len].copy_from_slice(header);
        zeroed[10] = 0;
        zeroed[11] = 0;
        if checksum(&zeroed[..header_len]) != checksum_wire {
            return Err(ParseError::BadChecksum);
        }
        let total_len = u16::from_be_bytes([header[2], header[3]]) as usize;
        if total_len < header_len {
            return Err(ParseError::BadTotalLength);
        }
        if total_len > data.len() {
            return Err(ParseError::BadTotalLength);
        }
        let flags_frag = u16::from_be_bytes([header[6], header[7]]);
        let fragment_offset = flags_frag & 0x1FFF;
        let mf = (flags_frag & 0x2000) != 0;
        if mf || fragment_offset != 0 {
            return Err(ParseError::Fragmented);
        }
        let dscp_ecn = header[1];
        let src = Ipv4Addr::from_bytes(header.get(12..16).ok_or(ParseError::Truncated)?)
            .map_err(|_| ParseError::Truncated)?;
        let dst = Ipv4Addr::from_bytes(header.get(16..20).ok_or(ParseError::Truncated)?)
            .map_err(|_| ParseError::Truncated)?;
        let payload = data
            .get(header_len..total_len)
            .ok_or(ParseError::Truncated)?;
        Ok((
            Self {
                src,
                dst,
                protocol: IpProtocol::new(header[9]),
                ttl: header[8],
                identification: u16::from_be_bytes([header[4], header[5]]),
                flags: flags_frag & !0x1FFF,
                fragment_offset,
                header_len,
                total_len: total_len as u16,
                dscp: dscp_ecn >> 2,
                ecn: dscp_ecn & 0x03,
            },
            payload,
        ))
    }

    /// Writes a 20-byte IPv4 header (no options) with DF set and checksum.
    pub fn write(&self, out: &mut [u8], payload_len: usize) -> Result<usize, ParseError> {
        if payload_len > MAX_L3_PAYLOAD_BYTES.saturating_sub(IPV4_MIN_HEADER_LEN) {
            return Err(ParseError::PayloadTooLarge);
        }
        if out.len() < IPV4_MIN_HEADER_LEN {
            return Err(ParseError::BufferTooSmall);
        }
        let total_len = IPV4_MIN_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(ParseError::BadTotalLength)?;
        if total_len > u16::MAX as usize {
            return Err(ParseError::BadTotalLength);
        }
        out[0] = (IPV4_VERSION << 4) | 5;
        out[1] = (self.dscp << 2) | (self.ecn & 0x03);
        out[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        out[4..6].copy_from_slice(&self.identification.to_be_bytes());
        let flags = self.flags | 0x4000;
        out[6..8].copy_from_slice(&flags.to_be_bytes());
        out[8] = self.ttl;
        out[9] = self.protocol.get();
        out[10] = 0;
        out[11] = 0;
        out[12..16].copy_from_slice(&self.src.octets());
        out[16..20].copy_from_slice(&self.dst.octets());
        let csum = checksum(&out[..IPV4_MIN_HEADER_LEN]);
        out[10..12].copy_from_slice(&csum.to_be_bytes());
        Ok(IPV4_MIN_HEADER_LEN)
    }

    /// Default header template for locally generated traffic (`ttl` 64, DF via write).
    pub fn new_template(src: Ipv4Addr, dst: Ipv4Addr, protocol: IpProtocol) -> Self {
        Self {
            src,
            dst,
            protocol,
            ttl: 64,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            header_len: IPV4_MIN_HEADER_LEN,
            total_len: 0,
            dscp: 0,
            ecn: 0,
        }
    }
}

/// IPv4 pseudo-header checksum used by TCP and UDP (RFC 793 / 768).
pub fn pseudo_header_checksum(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: IpProtocol,
    payload_len: u16,
) -> u16 {
    let mut sum = Checksum::new();
    sum = sum.add_bytes(&src.octets());
    sum = sum.add_bytes(&dst.octets());
    sum = sum.add_bytes(&[0, protocol.get()]);
    sum = sum.add_bytes(&payload_len.to_be_bytes());
    sum.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::checksum;
    use crate::checksum::Checksum;

    fn build_valid_packet(payload: &[u8]) -> Vec<u8> {
        let hdr = Ipv4Header::new_template(
            Ipv4Addr::new([10, 0, 0, 1]),
            Ipv4Addr::new([10, 0, 0, 2]),
            IpProtocol::ICMP,
        );
        let mut buf = vec![0u8; IPV4_MIN_HEADER_LEN + payload.len()];
        hdr.write(&mut buf, payload.len()).unwrap();
        buf[IPV4_MIN_HEADER_LEN..].copy_from_slice(payload);
        buf
    }

    #[test]
    fn roundtrip_parse_write() {
        let payload = b"hello";
        let data = build_valid_packet(payload);
        let (hdr, pl) = Ipv4Header::parse(&data).unwrap();
        assert_eq!(pl, payload);
        let mut out = [0u8; 40];
        hdr.write(&mut out, pl.len()).unwrap();
        assert_eq!(&out[..IPV4_MIN_HEADER_LEN], &data[..IPV4_MIN_HEADER_LEN]);
    }

    #[test]
    fn truncated_loop() {
        let data = build_valid_packet(b"x");
        for len in 0..IPV4_MIN_HEADER_LEN {
            assert_eq!(Ipv4Header::parse(&data[..len]), Err(ParseError::Truncated));
        }
    }

    #[test]
    fn bad_version_and_ihl() {
        let mut data = build_valid_packet(b"");
        data[0] = 0x60;
        assert_eq!(Ipv4Header::parse(&data), Err(ParseError::BadVersion));
        data[0] = 0x44;
        assert_eq!(Ipv4Header::parse(&data), Err(ParseError::BadHeaderLength));
    }

    #[test]
    fn bad_checksum() {
        let mut data = build_valid_packet(b"");
        data[10] ^= 0xFF;
        assert_eq!(Ipv4Header::parse(&data), Err(ParseError::BadChecksum));
    }

    fn fix_ipv4_checksum(data: &mut [u8]) {
        data[10] = 0;
        data[11] = 0;
        let csum = checksum(&data[..IPV4_MIN_HEADER_LEN]);
        data[10..12].copy_from_slice(&csum.to_be_bytes());
    }

    #[test]
    fn fragmented_rejected() {
        let mut data = build_valid_packet(b"");
        data[6] |= 0x20;
        fix_ipv4_checksum(&mut data);
        assert_eq!(Ipv4Header::parse(&data), Err(ParseError::Fragmented));
        let mut data2 = build_valid_packet(b"");
        data2[7] = 0x02;
        fix_ipv4_checksum(&mut data2);
        assert_eq!(Ipv4Header::parse(&data2), Err(ParseError::Fragmented));
    }

    #[test]
    fn pseudo_header_known() {
        let c = pseudo_header_checksum(
            Ipv4Addr::new([192, 0, 2, 1]),
            Ipv4Addr::new([192, 0, 2, 2]),
            IpProtocol::UDP,
            8,
        );
        let manual = Checksum::new()
            .add_bytes(&[192, 0, 2, 1])
            .add_bytes(&[192, 0, 2, 2])
            .add_bytes(&[0, 17])
            .add_bytes(&8u16.to_be_bytes())
            .finish();
        assert_eq!(c, manual);
    }
}
