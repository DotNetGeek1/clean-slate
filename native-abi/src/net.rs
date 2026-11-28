//! The native network client (#353): syscalls 14 `NETWORK_CAPABILITY` and 15 `NETWORK_REQUEST`,
//! the request and response frames a client exchanges with the network service through them,
//! and what the service's error codes mean as native statuses.
//!
//! # Authority
//!
//! A row holding `Grant::NativeNetworkClient` is given the network client entitlement at launch,
//! and from it a client capability bound to the live network-service instance, re-issued each
//! time an instance registers (`NET_RESOLVE | NET_CONNECT | NET_SEND | NET_RECEIVE`, never raw NIC
//! authority). The kernel also attributes the process to its manifest row, which the service
//! reads as the caller's app, so the per-app destination policy decides what it may reach and
//! which ports it may listen on. `LISTEN` needs `NET_CONNECT` and `ACCEPT` `NET_RECEIVE`.
//! Identity is the kernel's: nothing in a frame names the caller.
//!
//! `NETWORK_CAPABILITY` (`rdi` = [`NETWORK_CLIENT_DEVICE_ID`], `rsi` =
//! [`NETWORK_CAPABILITY_VERSION`]) returns the client capability's handle, or `EACCES` when the
//! caller holds none (no grant, or no instance live). After a network-service restart the old
//! handle is revoked; ask again.
//!
//! # Requests
//!
//! `NETWORK_REQUEST` takes a sub-operation in `rdi` and the client handle in `rsi`:
//!
//! | Sub-op | `rdx` | `r10` | `r8` | `r9` | Result |
//! |--------|-------|-------|------|------|--------|
//! | [`NET_SUBOP_SUBMIT`] | request frame | payload | payload length | 0 | request id |
//! | [`NET_SUBOP_WAIT`] | request id | absolute deadline, monotonic ns (0 = none) | 0 | 0 | 0 once the request has completed, `ETIMEDOUT` |
//! | [`NET_SUBOP_POLL`] | request id | response frame (out) | payload buffer (out) | its length | 0; blocks until the request completes |
//! | [`NET_SUBOP_DISCARD`] | request id | 0 | 0 | 0 | 0; the response, now or when it completes, is dropped |
//!
//! A request id is the caller's own: another process's ids are refused. `POLL` consumes the
//! completed request and needs a payload buffer at least as long as the response payload (a
//! `Receive`'s `max_len` is always enough); `WAIT` never consumes, so a client that gave up
//! waiting can wait or poll again later. A deadline is on the clock syscall 24 `MONOTONIC`
//! reads.
//!
//! Frames are [`NET_FRAME_BYTES`] long, little-endian:
//!
//! ```text
//! [0..4]  NET_FRAME_MAGIC
//! [4..6]  NET_FRAME_VERSION
//! [6]     kind (NET_KIND_*)
//! [7]     status, responses only: NET_RESPONSE_OK or NET_RESPONSE_ERROR
//! [8..]   body
//! ```
//!
//! | Kind | Request body | Response body |
//! |------|--------------|---------------|
//! | `RESOLVE` | `[8]` name length 1..=[`NET_MAX_HOSTNAME_BYTES`], `[9..]` ASCII name | `[8..12]` IPv4 address, `[12..16]` TTL s |
//! | `OPEN` | `[8]` socket kind (`NET_SOCKET_*`) | `[8..16]` session |
//! | `CONNECT` | `[8..16]` session, `[16..20]` IPv4 address, `[20..22]` port | — |
//! | `SEND` | `[8..16]` session, `[16..20]` payload length | `[8..12]` bytes accepted |
//! | `RECEIVE` | `[8..16]` session, `[16..20]` most bytes wanted | `[8..12]` payload length |
//! | `CLOSE` | `[8..16]` session | — |
//! | `LISTEN` | `[8..16]` session, `[16..18]` local port | — |
//! | `ACCEPT` | `[8..16]` listening session | `[8..16]` new session, `[16..20]` peer IPv4 address, `[20..22]` peer port |
//!
//! An error response has status [`NET_RESPONSE_ERROR`] and `[8..10]` a service error code
//! ([`net_error_status`] turns it into a status).
//!
//! # Socket kinds
//!
//! - [`NET_SOCKET_STREAM`]: a TCP stream. `CONNECT` completes once the handshake has; `SEND`
//!   may accept fewer bytes than offered; `RECEIVE` completes when bytes arrive, with length 0 at
//!   the end of the stream. `CLOSE` cancels an outstanding `RECEIVE` (it completes with a reset).
//!   Instead of `CONNECT`, a stream may `LISTEN` on a local port (#359): SYNs to that port on
//!   the service's address then start connections the listener holds, up to a small backlog
//!   (past it a SYN is answered with a reset). `ACCEPT` completes with the oldest established
//!   one as a new stream session of the caller's, already connected, and its peer; it waits
//!   while none is ready. `CLOSE` on a listener stops listening, resets the connections not yet
//!   accepted and cancels an outstanding `ACCEPT`; sessions already accepted stay open. The
//!   ports an app may listen on are its row's policy: another port is refused (`EACCES`) and
//!   the refusal audited, and a port already in use is `EADDRINUSE`.
//! - [`NET_SOCKET_DATAGRAM`]: a UDP socket, connected to one peer by `CONNECT` before `SEND`;
//!   `RECEIVE` completes with one datagram.
//! - [`NET_SOCKET_TLS_EXCHANGE`]: one TLS request and response. `CONNECT` only records the
//!   peer; `SEND` connects, verifies the peer against the service's trust anchors and its
//!   configured server name, sends the payload and reads the peer's answer until it closes, and
//!   completes once that is done; `RECEIVE` then returns the answer.
//!
//! These are the service's `LinuxTcp`, `LinuxUdp` and `Tcp` kinds: the plain stream and
//! datagram kinds the Linux socket layer also uses, and the M7 TLS kind.

use crate::status::{
    STATUS_EACCES, STATUS_EADDRINUSE, STATUS_ECONNRESET, STATUS_EHOSTUNREACH, STATUS_EINVAL,
    STATUS_EIO, STATUS_ENOBUFS, STATUS_ENOENT, STATUS_EPIPE, STATUS_EPROTO, STATUS_ESTALE,
    STATUS_ETIMEDOUT,
};

pub use clean_slate_capability::syscall_abi::{
    SYSCALL_NR_NETWORK_CAPABILITY, SYSCALL_NR_NETWORK_REQUEST,
};

/// `NETWORK_CAPABILITY`'s `rsi`.
pub const NETWORK_CAPABILITY_VERSION: u16 = 1;
/// Raw NIC authority: the network service's only.
pub const NETWORK_DEVICE_ID: u64 = 1;
/// Application network access (submit, wait, poll, discard).
pub const NETWORK_CLIENT_DEVICE_ID: u64 = 2;

pub const NET_SUBOP_SUBMIT: u64 = 1;
pub const NET_SUBOP_POLL: u64 = 2;
/// Waits for a request to complete without consuming it (#353).
pub const NET_SUBOP_WAIT: u64 = 15;
/// Drops interest in a request's response (#353).
pub const NET_SUBOP_DISCARD: u64 = 16;

pub const NET_FRAME_BYTES: usize = 64;
pub const NET_FRAME_MAGIC: u32 = 0x4E45_5431; // "NET1"
pub const NET_FRAME_VERSION: u16 = 1;
/// The most payload bytes one `SEND` carries or one `RECEIVE` returns.
pub const NET_MAX_PAYLOAD_BYTES: usize = 4096;
/// The longest name one `RESOLVE` carries.
pub const NET_MAX_HOSTNAME_BYTES: usize = 55;

pub const NET_KIND_RESOLVE: u8 = 1;
pub const NET_KIND_OPEN: u8 = 2;
pub const NET_KIND_CONNECT: u8 = 3;
pub const NET_KIND_SEND: u8 = 4;
pub const NET_KIND_RECEIVE: u8 = 5;
pub const NET_KIND_CLOSE: u8 = 6;
pub const NET_KIND_LISTEN: u8 = 7;
pub const NET_KIND_ACCEPT: u8 = 8;

pub const NET_RESPONSE_OK: u8 = 0;
pub const NET_RESPONSE_ERROR: u8 = 1;

pub const NET_SOCKET_TLS_EXCHANGE: u8 = 2;
pub const NET_SOCKET_DATAGRAM: u8 = 3;
pub const NET_SOCKET_STREAM: u8 = 4;

const RESOLVE_NAME_OFFSET: usize = 9;
const _: () = assert!(RESOLVE_NAME_OFFSET + NET_MAX_HOSTNAME_BYTES <= NET_FRAME_BYTES);

/// An IPv4 address and port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NetAddr {
    pub ip: [u8; 4],
    pub port: u16,
}

impl NetAddr {
    pub const fn new(ip: [u8; 4], port: u16) -> Self {
        Self { ip, port }
    }
}

/// Why a name cannot be resolved by the service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameError {
    Empty,
    TooLong,
    NotAscii,
}

/// A request frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetRequest<'a> {
    Resolve { name: &'a [u8] },
    Open { kind: u8 },
    Connect { session: u64, peer: NetAddr },
    Send { session: u64, len: u32 },
    Receive { session: u64, max_len: u32 },
    Close { session: u64 },
    Listen { session: u64, port: u16 },
    Accept { session: u64 },
}

/// Checks a name `RESOLVE` can carry.
pub const fn validate_hostname(name: &[u8]) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name.len() > NET_MAX_HOSTNAME_BYTES {
        return Err(NameError::TooLong);
    }
    if !name.is_ascii() {
        return Err(NameError::NotAscii);
    }
    Ok(())
}

impl NetRequest<'_> {
    /// The frame, or the name's fault for a `Resolve` the service would refuse.
    pub fn encode(&self) -> Result<[u8; NET_FRAME_BYTES], NameError> {
        let mut out = header();
        let session_and = |out: &mut [u8; NET_FRAME_BYTES], kind: u8, session: u64| {
            out[6] = kind;
            out[8..16].copy_from_slice(&session.to_le_bytes());
        };
        match *self {
            Self::Resolve { name } => {
                validate_hostname(name)?;
                out[6] = NET_KIND_RESOLVE;
                out[8] = name.len() as u8;
                out[RESOLVE_NAME_OFFSET..RESOLVE_NAME_OFFSET + name.len()].copy_from_slice(name);
            }
            Self::Open { kind } => {
                out[6] = NET_KIND_OPEN;
                out[8] = kind;
            }
            Self::Connect { session, peer } => {
                session_and(&mut out, NET_KIND_CONNECT, session);
                out[16..20].copy_from_slice(&peer.ip);
                out[20..22].copy_from_slice(&peer.port.to_le_bytes());
            }
            Self::Send { session, len } => {
                session_and(&mut out, NET_KIND_SEND, session);
                out[16..20].copy_from_slice(&len.to_le_bytes());
            }
            Self::Receive { session, max_len } => {
                session_and(&mut out, NET_KIND_RECEIVE, session);
                out[16..20].copy_from_slice(&max_len.to_le_bytes());
            }
            Self::Close { session } => session_and(&mut out, NET_KIND_CLOSE, session),
            Self::Listen { session, port } => {
                session_and(&mut out, NET_KIND_LISTEN, session);
                out[16..18].copy_from_slice(&port.to_le_bytes());
            }
            Self::Accept { session } => session_and(&mut out, NET_KIND_ACCEPT, session),
        }
        Ok(out)
    }
}

fn header() -> [u8; NET_FRAME_BYTES] {
    let mut out = [0u8; NET_FRAME_BYTES];
    out[0..4].copy_from_slice(&NET_FRAME_MAGIC.to_le_bytes());
    out[4..6].copy_from_slice(&NET_FRAME_VERSION.to_le_bytes());
    out
}

/// A response frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetResponse {
    Resolve {
        ip: [u8; 4],
        ttl: u32,
    },
    Open {
        session: u64,
    },
    Connect,
    Send {
        accepted: u32,
    },
    Receive {
        len: u32,
    },
    Close,
    Listen,
    /// The accepted connection's own stream session, and its peer.
    Accept {
        session: u64,
        peer: NetAddr,
    },
    /// A service error code; see [`net_error_status`].
    Error {
        code: u16,
    },
}

/// A frame that is not a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadFrame;

impl NetResponse {
    pub fn decode(frame: &[u8; NET_FRAME_BYTES]) -> Result<Self, BadFrame> {
        if u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) != NET_FRAME_MAGIC
            || u16::from_le_bytes([frame[4], frame[5]]) != NET_FRAME_VERSION
        {
            return Err(BadFrame);
        }
        let word = |at: usize| {
            u32::from_le_bytes([frame[at], frame[at + 1], frame[at + 2], frame[at + 3]])
        };
        if frame[7] == NET_RESPONSE_ERROR {
            return Ok(Self::Error {
                code: u16::from_le_bytes([frame[8], frame[9]]),
            });
        }
        if frame[7] != NET_RESPONSE_OK {
            return Err(BadFrame);
        }
        Ok(match frame[6] {
            NET_KIND_RESOLVE => Self::Resolve {
                ip: [frame[8], frame[9], frame[10], frame[11]],
                ttl: word(12),
            },
            NET_KIND_OPEN => Self::Open {
                session: session_at(frame),
            },
            NET_KIND_CONNECT => Self::Connect,
            NET_KIND_SEND => Self::Send { accepted: word(8) },
            NET_KIND_RECEIVE => Self::Receive { len: word(8) },
            NET_KIND_CLOSE => Self::Close,
            NET_KIND_LISTEN => Self::Listen,
            NET_KIND_ACCEPT => Self::Accept {
                session: session_at(frame),
                peer: NetAddr::new(
                    [frame[16], frame[17], frame[18], frame[19]],
                    u16::from_le_bytes([frame[20], frame[21]]),
                ),
            },
            _ => return Err(BadFrame),
        })
    }

    /// The frame (the service side, and fakes).
    pub fn encode(&self) -> [u8; NET_FRAME_BYTES] {
        let mut out = header();
        out[7] = NET_RESPONSE_OK;
        match *self {
            Self::Resolve { ip, ttl } => {
                out[6] = NET_KIND_RESOLVE;
                out[8..12].copy_from_slice(&ip);
                out[12..16].copy_from_slice(&ttl.to_le_bytes());
            }
            Self::Open { session } => {
                out[6] = NET_KIND_OPEN;
                out[8..16].copy_from_slice(&session.to_le_bytes());
            }
            Self::Connect => out[6] = NET_KIND_CONNECT,
            Self::Send { accepted } => {
                out[6] = NET_KIND_SEND;
                out[8..12].copy_from_slice(&accepted.to_le_bytes());
            }
            Self::Receive { len } => {
                out[6] = NET_KIND_RECEIVE;
                out[8..12].copy_from_slice(&len.to_le_bytes());
            }
            Self::Close => out[6] = NET_KIND_CLOSE,
            Self::Listen => out[6] = NET_KIND_LISTEN,
            Self::Accept { session, peer } => {
                out[6] = NET_KIND_ACCEPT;
                out[8..16].copy_from_slice(&session.to_le_bytes());
                out[16..20].copy_from_slice(&peer.ip);
                out[20..22].copy_from_slice(&peer.port.to_le_bytes());
            }
            Self::Error { code } => {
                out[7] = NET_RESPONSE_ERROR;
                out[8..10].copy_from_slice(&code.to_le_bytes());
            }
        }
        out
    }
}

fn session_at(frame: &[u8; NET_FRAME_BYTES]) -> u64 {
    let mut session = [0u8; 8];
    session.copy_from_slice(&frame[8..16]);
    u64::from_le_bytes(session)
}

/// Service error codes (`clean_slate_network::error::NetworkError::code`).
pub const NET_ERROR_INVALID_REQUEST: u16 = 1;
pub const NET_ERROR_NO_CAPABILITY: u16 = 2;
pub const NET_ERROR_MISSING_RIGHT: u16 = 3;
pub const NET_ERROR_STALE_GENERATION: u16 = 4;
pub const NET_ERROR_REVOKED: u16 = 5;
pub const NET_ERROR_UNREACHABLE: u16 = 6;
pub const NET_ERROR_TIMEOUT: u16 = 7;
pub const NET_ERROR_RESET: u16 = 8;
pub const NET_ERROR_PROTOCOL: u16 = 9;
pub const NET_ERROR_TRANSPORT: u16 = 10;
pub const NET_ERROR_QUEUE_FULL: u16 = 11;
pub const NET_ERROR_SESSION_EXHAUSTED: u16 = 12;
pub const NET_ERROR_NOT_FOUND: u16 = 13;
pub const NET_ERROR_CLOSED: u16 = 14;
/// The caller's app may not reach the destination, or resolve names (#221 stage E).
pub const NET_ERROR_DESTINATION_DENIED: u16 = 15;
/// A `LISTEN` on a port already listened on or in use (#359).
pub const NET_ERROR_ADDRESS_IN_USE: u16 = 16;

/// The native status a service error code means. A TLS exchange that fails for any reason
/// (handshake, peer identity, timeout) answers [`NET_ERROR_TIMEOUT`], so it reads `ETIMEDOUT`.
pub const fn net_error_status(code: u16) -> u64 {
    match code {
        NET_ERROR_NO_CAPABILITY
        | NET_ERROR_MISSING_RIGHT
        | NET_ERROR_REVOKED
        | NET_ERROR_DESTINATION_DENIED => STATUS_EACCES,
        NET_ERROR_STALE_GENERATION => STATUS_ESTALE,
        NET_ERROR_UNREACHABLE => STATUS_EHOSTUNREACH,
        NET_ERROR_TIMEOUT => STATUS_ETIMEDOUT,
        NET_ERROR_RESET => STATUS_ECONNRESET,
        NET_ERROR_PROTOCOL => STATUS_EPROTO,
        NET_ERROR_TRANSPORT => STATUS_EIO,
        NET_ERROR_QUEUE_FULL | NET_ERROR_SESSION_EXHAUSTED => STATUS_ENOBUFS,
        NET_ERROR_NOT_FOUND => STATUS_ENOENT,
        NET_ERROR_CLOSED => STATUS_EPIPE,
        NET_ERROR_ADDRESS_IN_USE => STATUS_EADDRINUSE,
        _ => STATUS_EINVAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_resolve_carries_its_name_after_its_length() {
        let frame = NetRequest::Resolve {
            name: b"example.test",
        }
        .encode()
        .unwrap();
        assert_eq!(frame[6], NET_KIND_RESOLVE);
        assert_eq!(frame[8], 12);
        assert_eq!(&frame[9..21], b"example.test");
        assert_eq!(
            NetRequest::Resolve { name: b"" }.encode(),
            Err(NameError::Empty)
        );
        assert_eq!(
            NetRequest::Resolve { name: &[b'a'; 56] }.encode(),
            Err(NameError::TooLong)
        );
        assert_eq!(
            NetRequest::Resolve {
                name: "é".as_bytes()
            }
            .encode(),
            Err(NameError::NotAscii)
        );
    }

    #[test]
    fn responses_round_trip() {
        for response in [
            NetResponse::Resolve {
                ip: [10, 77, 0, 1],
                ttl: 300,
            },
            NetResponse::Open {
                session: 0x1_0000_0007,
            },
            NetResponse::Connect,
            NetResponse::Send { accepted: 17 },
            NetResponse::Receive { len: 4096 },
            NetResponse::Close,
            NetResponse::Listen,
            NetResponse::Accept {
                session: 0x1_0000_0009,
                peer: NetAddr::new([10, 0, 2, 2], 51_000),
            },
            NetResponse::Error { code: 15 },
        ] {
            assert_eq!(NetResponse::decode(&response.encode()), Ok(response));
        }
        let mut frame = NetResponse::Close.encode();
        frame[0] ^= 1;
        assert_eq!(NetResponse::decode(&frame), Err(BadFrame));
    }

    #[test]
    fn a_refused_destination_reads_as_eacces() {
        assert_eq!(
            net_error_status(NET_ERROR_DESTINATION_DENIED),
            STATUS_EACCES
        );
        assert_eq!(net_error_status(NET_ERROR_STALE_GENERATION), STATUS_ESTALE);
        assert_eq!(net_error_status(NET_ERROR_CLOSED), STATUS_EPIPE);
        assert_eq!(
            net_error_status(NET_ERROR_ADDRESS_IN_USE),
            STATUS_EADDRINUSE
        );
        assert_eq!(net_error_status(999), STATUS_EINVAL);
    }
}
