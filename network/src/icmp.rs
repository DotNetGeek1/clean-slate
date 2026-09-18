//! ICMPv4 subset (echo and error shells).

use crate::checksum::{checksum, verify};
use crate::ethernet::ParseError;

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_DEST_UNREACH: u8 = 3;
pub const ICMP_TIME_EXCEEDED: u8 = 11;
pub const ICMP_ECHO_REQUEST: u8 = 8;

const ICMP_HEADER_LEN: usize = 4;

/// Parsed ICMP message borrowing from the input buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcmpMessage<'a> {
    EchoRequest {
        id: u16,
        seq: u16,
        payload: &'a [u8],
    },
    EchoReply {
        id: u16,
        seq: u16,
        payload: &'a [u8],
    },
    DestinationUnreachable {
        code: u8,
        original_header_bytes: &'a [u8],
    },
    TimeExceeded {
        code: u8,
        original_header_bytes: &'a [u8],
    },
    Other {
        ty: u8,
        code: u8,
    },
}

impl<'a> IcmpMessage<'a> {
    /// Parses and checksum-validates an ICMP message.
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < ICMP_HEADER_LEN {
            return Err(ParseError::Truncated);
        }
        let ty = data[0];
        let code = data[1];
        let checksum_wire = u16::from_be_bytes([data[2], data[3]]);
        if !verify(data, checksum_wire) {
            return Err(ParseError::BadChecksum);
        }
        match ty {
            ICMP_ECHO_REQUEST | ICMP_ECHO_REPLY => {
                if data.len() < 8 {
                    return Err(ParseError::Truncated);
                }
                let id = u16::from_be_bytes([data[4], data[5]]);
                let seq = u16::from_be_bytes([data[6], data[7]]);
                let payload = data.get(8..).ok_or(ParseError::Truncated)?;
                if ty == ICMP_ECHO_REQUEST {
                    Ok(Self::EchoRequest { id, seq, payload })
                } else {
                    Ok(Self::EchoReply { id, seq, payload })
                }
            }
            ICMP_DEST_UNREACH | ICMP_TIME_EXCEEDED => {
                let original = data.get(8..).ok_or(ParseError::Truncated)?;
                if ty == ICMP_DEST_UNREACH {
                    Ok(Self::DestinationUnreachable {
                        code,
                        original_header_bytes: original,
                    })
                } else {
                    Ok(Self::TimeExceeded {
                        code,
                        original_header_bytes: original,
                    })
                }
            }
            _ => Ok(Self::Other { ty, code }),
        }
    }
}

/// Builds an ICMP echo request message into `out`.
pub fn build_echo_request(
    id: u16,
    seq: u16,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, ParseError> {
    write_echo(ICMP_ECHO_REQUEST, id, seq, payload, out)
}

/// Builds an ICMP echo reply matching a request's id, sequence, and payload bytes.
pub fn build_echo_reply(request: IcmpMessage<'_>, out: &mut [u8]) -> Result<usize, ParseError> {
    match request {
        IcmpMessage::EchoRequest { id, seq, payload } => {
            write_echo(ICMP_ECHO_REPLY, id, seq, payload, out)
        }
        _ => Err(ParseError::UnsupportedProtocol),
    }
}

fn write_echo(
    ty: u8,
    id: u16,
    seq: u16,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, ParseError> {
    let total = 8usize
        .checked_add(payload.len())
        .ok_or(ParseError::PayloadTooLarge)?;
    if out.len() < total {
        return Err(ParseError::BufferTooSmall);
    }
    out[0] = ty;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    out[4..6].copy_from_slice(&id.to_be_bytes());
    out[6..8].copy_from_slice(&seq.to_be_bytes());
    if !payload.is_empty() {
        out[8..total].copy_from_slice(payload);
    }
    let csum = checksum(&out[..total]);
    out[2..4].copy_from_slice(&csum.to_be_bytes());
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_roundtrip() {
        let mut buf = [0u8; 64];
        let len = build_echo_request(1, 2, b"ping", &mut buf).unwrap();
        let msg = IcmpMessage::parse(&buf[..len]).unwrap();
        match msg {
            IcmpMessage::EchoRequest { id, seq, payload } => {
                assert_eq!(id, 1);
                assert_eq!(seq, 2);
                assert_eq!(payload, b"ping");
            }
            _ => panic!("expected echo request"),
        }
        let mut reply = [0u8; 64];
        let rlen = build_echo_reply(msg, &mut reply).unwrap();
        let rep = IcmpMessage::parse(&reply[..rlen]).unwrap();
        assert!(matches!(rep, IcmpMessage::EchoReply { .. }));
    }

    #[test]
    fn truncated_and_bad_checksum() {
        for len in 0..ICMP_HEADER_LEN {
            assert_eq!(
                IcmpMessage::parse(&[0u8; 8][..len]),
                Err(ParseError::Truncated)
            );
        }
        let mut buf = [0u8; 8];
        build_echo_request(0, 0, &[], &mut buf).unwrap();
        buf[2] ^= 0xFF;
        assert_eq!(IcmpMessage::parse(&buf), Err(ParseError::BadChecksum));
    }
}
