//! IEEE 802.3 Ethernet II framing (no VLAN).

use crate::addr::{EtherType, MacAddr};
use crate::buffer::FrameBuf;
use crate::error::NetworkError;
use crate::limits::{MAX_ETHERNET_FRAME_BYTES, MTU};

/// Errors parsing or serializing untrusted on-wire bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    FrameTooShort,
    FrameTooLarge,
    PayloadTooLarge,
    BadEtherType,
    BadVersion,
    BadHeaderLength,
    BadChecksum,
    BadTotalLength,
    Fragmented,
    UnsupportedProtocol,
    BadOpcode,
    BadHardwareType,
    BadAddressLength,
    BufferTooSmall,
}

impl From<ParseError> for NetworkError {
    fn from(_: ParseError) -> Self {
        Self::Protocol
    }
}

/// Parsed Ethernet II header (14 bytes, no VLAN).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthernetHeader {
    pub dst: MacAddr,
    pub src: MacAddr,
    pub ethertype: EtherType,
}

impl EthernetHeader {
    pub const LEN: usize = 14;

    /// Parses `data` and returns the header plus the L3 payload slice.
    pub fn parse(data: &[u8]) -> Result<(Self, &[u8]), ParseError> {
        if data.len() < Self::LEN {
            return Err(ParseError::Truncated);
        }
        let dst = MacAddr::from_bytes(data.get(0..6).ok_or(ParseError::Truncated)?)
            .map_err(|_| ParseError::Truncated)?;
        let src = MacAddr::from_bytes(data.get(6..12).ok_or(ParseError::Truncated)?)
            .map_err(|_| ParseError::Truncated)?;
        let ethertype_raw = u16::from_be_bytes([
            *data.get(12).ok_or(ParseError::Truncated)?,
            *data.get(13).ok_or(ParseError::Truncated)?,
        ]);
        let ethertype = EtherType::new(ethertype_raw);
        if ethertype != EtherType::IPV4 && ethertype != EtherType::ARP {
            return Err(ParseError::BadEtherType);
        }
        let payload = data.get(Self::LEN..).ok_or(ParseError::Truncated)?;
        Ok((
            Self {
                dst,
                src,
                ethertype,
            },
            payload,
        ))
    }

    /// Writes the header into `out` and returns bytes written (always [`Self::LEN`]).
    pub fn write(self, out: &mut [u8]) -> Result<usize, ParseError> {
        if out.len() < Self::LEN {
            return Err(ParseError::BufferTooSmall);
        }
        out[0..6].copy_from_slice(&self.dst.octets());
        out[6..12].copy_from_slice(&self.src.octets());
        out[12..14].copy_from_slice(&self.ethertype.get().to_be_bytes());
        Ok(Self::LEN)
    }
}

/// Builds a bounded Ethernet frame in a [`FrameBuf`].
pub struct EthernetFrame;

impl EthernetFrame {
    /// Validates length bounds and writes header + payload into a new [`FrameBuf`].
    pub fn build(header: EthernetHeader, payload: &[u8]) -> Result<FrameBuf, ParseError> {
        if payload.len() > MTU as usize {
            return Err(ParseError::PayloadTooLarge);
        }
        let total = EthernetHeader::LEN
            .checked_add(payload.len())
            .ok_or(ParseError::FrameTooLarge)?;
        if total < EthernetHeader::LEN {
            return Err(ParseError::FrameTooShort);
        }
        if total > MAX_ETHERNET_FRAME_BYTES {
            return Err(ParseError::FrameTooLarge);
        }
        let mut buf = FrameBuf::empty();
        let mut hdr_bytes = [0u8; EthernetHeader::LEN];
        header.write(&mut hdr_bytes)?;
        buf.push_bytes(&hdr_bytes)
            .map_err(|_| ParseError::FrameTooLarge)?;
        buf.push_bytes(payload)
            .map_err(|_| ParseError::FrameTooLarge)?;
        Ok(buf)
    }

    /// Parses a full on-wire frame with Ethernet length checks.
    pub fn parse_frame(data: &[u8]) -> Result<(EthernetHeader, &[u8]), ParseError> {
        if data.len() < EthernetHeader::LEN {
            return Err(ParseError::FrameTooShort);
        }
        if data.len() > MAX_ETHERNET_FRAME_BYTES {
            return Err(ParseError::FrameTooLarge);
        }
        EthernetHeader::parse(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::EtherType;

    fn sample_header() -> EthernetHeader {
        EthernetHeader {
            dst: MacAddr::new([0x52, 0x54, 0, 0, 0, 1]),
            src: MacAddr::new([0x52, 0x54, 0, 0, 0, 2]),
            ethertype: EtherType::IPV4,
        }
    }

    #[test]
    fn roundtrip_header() {
        let hdr = sample_header();
        let mut buf = [0u8; EthernetHeader::LEN];
        assert_eq!(hdr.write(&mut buf).unwrap(), EthernetHeader::LEN);
        let (parsed, payload) = EthernetHeader::parse(&buf).unwrap();
        assert_eq!(parsed, hdr);
        assert!(payload.is_empty());
    }

    #[test]
    fn truncated_header_loop() {
        for len in 0..EthernetHeader::LEN {
            assert_eq!(
                EthernetHeader::parse(&[0u8; 14][..len]),
                Err(ParseError::Truncated)
            );
        }
    }

    #[test]
    fn build_rejects_oversized_payload() {
        let hdr = sample_header();
        let big = [0u8; 1501];
        assert_eq!(
            EthernetFrame::build(hdr, &big),
            Err(ParseError::PayloadTooLarge)
        );
    }

    #[test]
    fn bad_ethertype() {
        let mut buf = [0u8; 14];
        buf[12..14].copy_from_slice(&0x88CCu16.to_be_bytes());
        assert_eq!(EthernetHeader::parse(&buf), Err(ParseError::BadEtherType));
    }
}
