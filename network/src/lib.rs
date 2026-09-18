//! Shared M7 network contract and socket model.
//!
//! Layering (each layer depends only on the layers below it):
//!
//! ```text
//! NetworkLink device contract  (#82 VirtIO, #83 service bridge)
//!        |
//! userspace network service + TrustedCaller / NetworkRequest IPC
//!        |
//! protocol stack (#84 Ethernet/ARP/IPv4/ICMP, #124 UDP, #125 TCP)
//!        |
//! DNS (#85) and TLS (#86)
//! ```
//!
//! Linux socket ABI compatibility is explicitly out of scope until M9. This
//! crate must not embed Linux-specific socket option semantics.

#![cfg_attr(not(test), no_std)]

#[cfg(any(test, feature = "alloc"))]
extern crate alloc;

pub mod addr;
pub mod buffer;
pub mod device;
pub mod error;
pub mod fixture;
pub mod limits;
pub mod protocol;
pub mod session;

#[cfg(any(test, feature = "alloc"))]
pub mod fake;

#[cfg(test)]
mod tests {
    use super::addr::{BoundedHostname, Ipv4Addr, MacAddr, SocketAddrV4};
    use super::buffer::{FrameBuf, FrameBufError};
    use super::error::{DenialReason, NetworkError};
    use super::fixture::{
        APP_REQUEST_BYTES, APP_RESPONSE_BYTES, FIXTURE_A_RECORD, FIXTURE_HOSTNAME, GUEST_IPV4,
        PEER_IPV4, TLS_SERVER_NAME,
    };
    use super::limits::MAX_APPLICATION_PAYLOAD_BYTES;
    use super::protocol::{NetworkRequest, NetworkResponse};
    use super::session::{SessionGeneration, SessionId, SocketKind};

    #[test]
    fn addr_parsing_bounds() {
        assert!(MacAddr::from_bytes(&[0; 5]).is_err());
        assert!(Ipv4Addr::from_bytes(&[0; 3]).is_err());
        let addr = SocketAddrV4::new(Ipv4Addr::new([1, 2, 3, 4]), 8080);
        let encoded = addr.encode();
        assert_eq!(SocketAddrV4::decode(&encoded).unwrap(), addr);
        assert!(BoundedHostname::try_from_str("").is_err());
        assert!(BoundedHostname::try_from_str(&"a".repeat(254)).is_err());
        let name = BoundedHostname::try_from_str(FIXTURE_HOSTNAME).unwrap();
        assert_eq!(name.as_str().unwrap(), FIXTURE_HOSTNAME);
    }

    #[test]
    fn frame_buf_push_and_truncate_bounds() {
        let mut buf = FrameBuf::empty();
        buf.push_bytes(&[1, 2, 3]).unwrap();
        assert_eq!(buf.len(), 3);
        buf.truncate(2).unwrap();
        assert_eq!(buf.as_slice(), &[1, 2]);
        assert_eq!(buf.truncate(5), Err(FrameBufError::TruncateOutOfBounds));
        let mut big = FrameBuf::empty();
        let chunk = [0u8; 500];
        for _ in 0..3 {
            assert!(big.push_bytes(&chunk).is_ok());
        }
        assert_eq!(big.push_bytes(&chunk), Err(FrameBufError::WouldOverflow));
    }

    #[test]
    fn request_response_roundtrip() {
        let name = BoundedHostname::try_from_str(FIXTURE_HOSTNAME).unwrap();
        let requests = [
            NetworkRequest::Resolve { name },
            NetworkRequest::Open {
                kind: SocketKind::Tcp,
            },
            NetworkRequest::Connect {
                session: SessionId::new(SessionGeneration::new(9), 1),
                dest: SocketAddrV4::new(FIXTURE_A_RECORD, 443),
            },
            NetworkRequest::Send {
                session: SessionId::new(SessionGeneration::new(9), 1),
                payload_len: APP_REQUEST_BYTES.len() as u32,
            },
            NetworkRequest::Receive {
                session: SessionId::new(SessionGeneration::new(9), 1),
                max_len: 64,
            },
            NetworkRequest::Close {
                session: SessionId::new(SessionGeneration::new(9), 1),
            },
        ];
        for request in requests {
            let encoded = request.encode();
            let decoded = NetworkRequest::decode(&encoded).unwrap();
            assert_eq!(decoded, request);
        }

        let responses = [
            NetworkResponse::Resolve {
                addr: PEER_IPV4,
                ttl: 120,
            },
            NetworkResponse::Open {
                session: SessionId::new(SessionGeneration::new(3), 7),
            },
            NetworkResponse::Connect,
            NetworkResponse::Send {
                bytes_sent: APP_REQUEST_BYTES.len() as u32,
            },
            NetworkResponse::Receive {
                payload_len: APP_RESPONSE_BYTES.len() as u32,
            },
            NetworkResponse::Close,
            NetworkResponse::Error {
                code: NetworkError::Protocol.code(),
            },
        ];
        for response in responses {
            let encoded = response.encode();
            let decoded = NetworkResponse::decode(&encoded).unwrap();
            assert_eq!(decoded, response);
        }
    }

    #[test]
    fn wire_rejects_truncated_and_oversized() {
        let encoded = NetworkRequest::Send {
            session: SessionId::new(SessionGeneration::new(1), 0),
            payload_len: 64,
        }
        .encode();
        assert!(NetworkRequest::decode(&encoded[..8]).is_err());
        let mut bad = encoded;
        bad[16..20].copy_from_slice(&(MAX_APPLICATION_PAYLOAD_BYTES as u32 + 1).to_le_bytes());
        assert!(NetworkRequest::decode(&bad).is_err());
    }

    #[test]
    fn session_generation_mismatch() {
        let session = SessionId::new(SessionGeneration::new(4), 2);
        assert!(session.matches_generation(SessionGeneration::new(4)));
        assert!(!session.matches_generation(SessionGeneration::new(5)));
    }

    #[test]
    fn error_codes_stable_and_unique() {
        let codes = [
            NetworkError::InvalidRequest.code(),
            NetworkError::Denied(DenialReason::NoCapability).code(),
            NetworkError::Denied(DenialReason::MissingRight).code(),
            NetworkError::Denied(DenialReason::StaleGeneration).code(),
            NetworkError::Denied(DenialReason::Revoked).code(),
            NetworkError::Unreachable.code(),
            NetworkError::Timeout.code(),
            NetworkError::Reset.code(),
            NetworkError::Protocol.code(),
            NetworkError::Transport(super::device::NetworkDeviceError::QueueFull).code(),
            NetworkError::QueueFull.code(),
            NetworkError::SessionExhausted.code(),
            NetworkError::NotFound.code(),
            NetworkError::Closed.code(),
        ];
        for (i, a) in codes.iter().enumerate() {
            for (j, b) in codes.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn fixture_constants_self_consistent() {
        assert_eq!(TLS_SERVER_NAME, FIXTURE_HOSTNAME);
        assert_eq!(GUEST_IPV4, super::fixture::GUEST_SOCKET.addr);
    }
}
