//! Bounded client ↔ network-service request/response wire shapes.
//!
//! Every request and response is exactly one fixed-size frame that fits a
//! single kernel IPC message. Application payload bytes for `Send` / `Receive`
//! are **not** carried in the frame: the frame carries only the byte count, and
//! the bytes travel through the bounded payload region owned by the network
//! service transport (lane #83), sized by
//! [`crate::limits::MAX_APPLICATION_PAYLOAD_BYTES`].
//!
//! Frame layout (little-endian):
//!
//! ```text
//! [0..4]  NETWORK_PROTOCOL_MAGIC
//! [4..6]  NETWORK_PROTOCOL_VERSION
//! [6]     NetworkRequestKind
//! [7]     NetworkResponseStatus (responses only; 0 in requests)
//! [8..]   kind-specific body
//! ```

use crate::addr::{BoundedHostname, SocketAddrV4};
use crate::limits::{MAX_APPLICATION_PAYLOAD_BYTES, MAX_REQUEST_HOSTNAME_LEN};
use crate::session::{SessionId, SocketKind};

pub const NETWORK_PROTOCOL_MAGIC: u32 = 0x4E45_5431; // "NET1"
pub const NETWORK_PROTOCOL_VERSION: u16 = 1;
pub const NETWORK_REQUEST_BYTES: usize = 64;
pub const NETWORK_RESPONSE_BYTES: usize = 64;

/// Byte offset of the hostname bytes inside a `Resolve` request frame
/// (after the header and the one-byte name length at offset 8).
const RESOLVE_NAME_OFFSET: usize = 9;

const _: () = assert!(
    RESOLVE_NAME_OFFSET + MAX_REQUEST_HOSTNAME_LEN <= NETWORK_REQUEST_BYTES,
    "Resolve hostname must fit inside one request frame"
);

/// Caller identity attached by the trusted network service, never by the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct TrustedCaller {
    pub pid: u64,
    pub domain: u64,
    pub instance_generation: u64,
}

impl TrustedCaller {
    pub const fn new(pid: u64, domain: u64, instance_generation: u64) -> Self {
        Self {
            pid,
            domain,
            instance_generation,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NetworkRequestKind {
    Resolve = 1,
    Open = 2,
    Connect = 3,
    Send = 4,
    Receive = 5,
    Close = 6,
    /// Makes a stream session a listener on a local port (#359).
    Listen = 7,
    /// Takes the next connection a listener's backlog holds (#359).
    Accept = 8,
    /// Reads the per-app network counters (#378); needs `NET_STATS`.
    Stats = 9,
}

impl NetworkRequestKind {
    pub const fn from_repr(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Resolve),
            2 => Some(Self::Open),
            3 => Some(Self::Connect),
            4 => Some(Self::Send),
            5 => Some(Self::Receive),
            6 => Some(Self::Close),
            7 => Some(Self::Listen),
            8 => Some(Self::Accept),
            9 => Some(Self::Stats),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkRequest {
    Resolve {
        name: BoundedHostname,
    },
    Open {
        kind: SocketKind,
    },
    Connect {
        session: SessionId,
        dest: SocketAddrV4,
    },
    /// Transmit `payload_len` bytes supplied out-of-band via the service payload region.
    Send {
        session: SessionId,
        payload_len: u32,
    },
    /// Receive up to `max_len` bytes into the service payload region.
    Receive {
        session: SessionId,
        max_len: u32,
    },
    Close {
        session: SessionId,
    },
    /// Listen on our address, `port`, with a stream session that is not connected (#359).
    /// `Close` on the session stops listening.
    Listen {
        session: SessionId,
        port: u16,
    },
    /// The oldest established connection on listening `session`, as a new stream session.
    Accept {
        session: SessionId,
    },
    /// The per-app counters (#378), as many rows as fit `max_len` bytes of the service payload
    /// region. Rows are `clean_slate_native_abi::net::NetAppStats` encodings.
    Stats {
        max_len: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkRequestDecodeError {
    BadMagic,
    UnsupportedVersion(u16),
    InvalidKind(u8),
    Truncated,
    OversizedField,
    InvalidHostname,
    InvalidSocketKind(u8),
}

impl NetworkRequest {
    pub fn encode(&self) -> [u8; NETWORK_REQUEST_BYTES] {
        let mut out = [0u8; NETWORK_REQUEST_BYTES];
        out[0..4].copy_from_slice(&NETWORK_PROTOCOL_MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&NETWORK_PROTOCOL_VERSION.to_le_bytes());
        match self {
            Self::Resolve { name } => {
                out[6] = NetworkRequestKind::Resolve as u8;
                let len = name.len();
                out[8] = len as u8;
                out[RESOLVE_NAME_OFFSET..RESOLVE_NAME_OFFSET + len]
                    .copy_from_slice(name.as_bytes());
            }
            Self::Open { kind } => {
                out[6] = NetworkRequestKind::Open as u8;
                out[8] = *kind as u8;
            }
            Self::Connect { session, dest } => {
                out[6] = NetworkRequestKind::Connect as u8;
                out[8..16].copy_from_slice(&session.raw().to_le_bytes());
                out[16..22].copy_from_slice(&dest.encode());
            }
            Self::Send {
                session,
                payload_len,
            } => {
                out[6] = NetworkRequestKind::Send as u8;
                out[8..16].copy_from_slice(&session.raw().to_le_bytes());
                out[16..20].copy_from_slice(&payload_len.to_le_bytes());
            }
            Self::Receive { session, max_len } => {
                out[6] = NetworkRequestKind::Receive as u8;
                out[8..16].copy_from_slice(&session.raw().to_le_bytes());
                out[16..20].copy_from_slice(&max_len.to_le_bytes());
            }
            Self::Close { session } => {
                out[6] = NetworkRequestKind::Close as u8;
                out[8..16].copy_from_slice(&session.raw().to_le_bytes());
            }
            Self::Listen { session, port } => {
                out[6] = NetworkRequestKind::Listen as u8;
                out[8..16].copy_from_slice(&session.raw().to_le_bytes());
                out[16..18].copy_from_slice(&port.to_le_bytes());
            }
            Self::Accept { session } => {
                out[6] = NetworkRequestKind::Accept as u8;
                out[8..16].copy_from_slice(&session.raw().to_le_bytes());
            }
            Self::Stats { max_len } => {
                out[6] = NetworkRequestKind::Stats as u8;
                out[8..12].copy_from_slice(&max_len.to_le_bytes());
            }
        }
        out
    }

    /// The session a request acts on; `None` for `Resolve`, `Open` and `Stats`.
    pub const fn session(&self) -> Option<SessionId> {
        match *self {
            Self::Resolve { .. } | Self::Open { .. } | Self::Stats { .. } => None,
            Self::Connect { session, .. }
            | Self::Send { session, .. }
            | Self::Receive { session, .. }
            | Self::Close { session }
            | Self::Listen { session, .. }
            | Self::Accept { session } => Some(session),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, NetworkRequestDecodeError> {
        if bytes.len() < NETWORK_REQUEST_BYTES {
            return Err(NetworkRequestDecodeError::Truncated);
        }
        let magic = u32::from_le_bytes(bytes[0..4].try_into().expect("slice"));
        if magic != NETWORK_PROTOCOL_MAGIC {
            return Err(NetworkRequestDecodeError::BadMagic);
        }
        let version = u16::from_le_bytes(bytes[4..6].try_into().expect("slice"));
        if version != NETWORK_PROTOCOL_VERSION {
            return Err(NetworkRequestDecodeError::UnsupportedVersion(version));
        }
        let kind = NetworkRequestKind::from_repr(bytes[6])
            .ok_or(NetworkRequestDecodeError::InvalidKind(bytes[6]))?;
        match kind {
            NetworkRequestKind::Resolve => {
                let len = bytes[8];
                let name = BoundedHostname::from_encoded(len, &bytes[RESOLVE_NAME_OFFSET..])
                    .map_err(|_| NetworkRequestDecodeError::InvalidHostname)?;
                Ok(Self::Resolve { name })
            }
            NetworkRequestKind::Open => {
                let kind = SocketKind::from_repr(bytes[8])
                    .ok_or(NetworkRequestDecodeError::InvalidSocketKind(bytes[8]))?;
                Ok(Self::Open { kind })
            }
            NetworkRequestKind::Connect => {
                let session = SessionId::from_raw(u64::from_le_bytes(
                    bytes[8..16].try_into().expect("slice"),
                ));
                let dest = SocketAddrV4::decode(
                    bytes[16..22]
                        .try_into()
                        .map_err(|_| NetworkRequestDecodeError::Truncated)?,
                )
                .map_err(|_| NetworkRequestDecodeError::OversizedField)?;
                Ok(Self::Connect { session, dest })
            }
            NetworkRequestKind::Send => {
                let session = SessionId::from_raw(u64::from_le_bytes(
                    bytes[8..16].try_into().expect("slice"),
                ));
                let payload_len = u32::from_le_bytes(bytes[16..20].try_into().expect("slice"));
                if payload_len as usize > MAX_APPLICATION_PAYLOAD_BYTES {
                    return Err(NetworkRequestDecodeError::OversizedField);
                }
                Ok(Self::Send {
                    session,
                    payload_len,
                })
            }
            NetworkRequestKind::Receive => {
                let session = SessionId::from_raw(u64::from_le_bytes(
                    bytes[8..16].try_into().expect("slice"),
                ));
                let max_len = u32::from_le_bytes(bytes[16..20].try_into().expect("slice"));
                if max_len as usize > MAX_APPLICATION_PAYLOAD_BYTES {
                    return Err(NetworkRequestDecodeError::OversizedField);
                }
                Ok(Self::Receive { session, max_len })
            }
            NetworkRequestKind::Close => {
                let session = SessionId::from_raw(u64::from_le_bytes(
                    bytes[8..16].try_into().expect("slice"),
                ));
                Ok(Self::Close { session })
            }
            NetworkRequestKind::Listen => {
                let session = SessionId::from_raw(u64::from_le_bytes(
                    bytes[8..16].try_into().expect("slice"),
                ));
                let port = u16::from_le_bytes(bytes[16..18].try_into().expect("slice"));
                Ok(Self::Listen { session, port })
            }
            NetworkRequestKind::Accept => {
                let session = SessionId::from_raw(u64::from_le_bytes(
                    bytes[8..16].try_into().expect("slice"),
                ));
                Ok(Self::Accept { session })
            }
            NetworkRequestKind::Stats => {
                let max_len = u32::from_le_bytes(bytes[8..12].try_into().expect("slice"));
                if max_len as usize > MAX_APPLICATION_PAYLOAD_BYTES {
                    return Err(NetworkRequestDecodeError::OversizedField);
                }
                Ok(Self::Stats { max_len })
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NetworkResponseStatus {
    Ok = 0,
    Error = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkResponse {
    Resolve {
        addr: crate::addr::Ipv4Addr,
        ttl: u32,
    },
    Open {
        session: SessionId,
    },
    Connect,
    Send {
        bytes_sent: u32,
    },
    Receive {
        payload_len: u32,
    },
    Close,
    Listen,
    /// The accepted connection's new stream session and its peer.
    Accept {
        session: SessionId,
        peer: SocketAddrV4,
    },
    /// `rows` counter rows are in the payload; the table held `apps` rows (more than `rows`
    /// when `max_len` was too short), and `untracked` counts requests from apps the full table
    /// had no row for.
    Stats {
        rows: u16,
        apps: u16,
        untracked: u32,
    },
    Error {
        code: u16,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkResponseDecodeError {
    BadMagic,
    UnsupportedVersion(u16),
    InvalidStatus(u8),
    InvalidKind(u8),
    Truncated,
}

impl NetworkResponse {
    pub fn encode(&self) -> [u8; NETWORK_RESPONSE_BYTES] {
        let mut out = [0u8; NETWORK_RESPONSE_BYTES];
        out[0..4].copy_from_slice(&NETWORK_PROTOCOL_MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&NETWORK_PROTOCOL_VERSION.to_le_bytes());
        match self {
            Self::Resolve { addr, ttl } => {
                out[6] = NetworkRequestKind::Resolve as u8;
                out[7] = NetworkResponseStatus::Ok as u8;
                out[8..12].copy_from_slice(&addr.octets());
                out[12..16].copy_from_slice(&ttl.to_le_bytes());
            }
            Self::Open { session } => {
                out[6] = NetworkRequestKind::Open as u8;
                out[7] = NetworkResponseStatus::Ok as u8;
                out[8..16].copy_from_slice(&session.raw().to_le_bytes());
            }
            Self::Connect => {
                out[6] = NetworkRequestKind::Connect as u8;
                out[7] = NetworkResponseStatus::Ok as u8;
            }
            Self::Send { bytes_sent } => {
                out[6] = NetworkRequestKind::Send as u8;
                out[7] = NetworkResponseStatus::Ok as u8;
                out[8..12].copy_from_slice(&bytes_sent.to_le_bytes());
            }
            Self::Receive { payload_len } => {
                out[6] = NetworkRequestKind::Receive as u8;
                out[7] = NetworkResponseStatus::Ok as u8;
                out[8..12].copy_from_slice(&payload_len.to_le_bytes());
            }
            Self::Close => {
                out[6] = NetworkRequestKind::Close as u8;
                out[7] = NetworkResponseStatus::Ok as u8;
            }
            Self::Listen => {
                out[6] = NetworkRequestKind::Listen as u8;
                out[7] = NetworkResponseStatus::Ok as u8;
            }
            Self::Accept { session, peer } => {
                out[6] = NetworkRequestKind::Accept as u8;
                out[7] = NetworkResponseStatus::Ok as u8;
                out[8..16].copy_from_slice(&session.raw().to_le_bytes());
                out[16..22].copy_from_slice(&peer.encode());
            }
            Self::Stats {
                rows,
                apps,
                untracked,
            } => {
                out[6] = NetworkRequestKind::Stats as u8;
                out[7] = NetworkResponseStatus::Ok as u8;
                out[8..10].copy_from_slice(&rows.to_le_bytes());
                out[10..12].copy_from_slice(&apps.to_le_bytes());
                out[12..16].copy_from_slice(&untracked.to_le_bytes());
            }
            Self::Error { code } => {
                out[7] = NetworkResponseStatus::Error as u8;
                out[8..10].copy_from_slice(&code.to_le_bytes());
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, NetworkResponseDecodeError> {
        if bytes.len() < NETWORK_RESPONSE_BYTES {
            return Err(NetworkResponseDecodeError::Truncated);
        }
        let magic = u32::from_le_bytes(bytes[0..4].try_into().expect("slice"));
        if magic != NETWORK_PROTOCOL_MAGIC {
            return Err(NetworkResponseDecodeError::BadMagic);
        }
        let version = u16::from_le_bytes(bytes[4..6].try_into().expect("slice"));
        if version != NETWORK_PROTOCOL_VERSION {
            return Err(NetworkResponseDecodeError::UnsupportedVersion(version));
        }
        match bytes[7] {
            x if x == NetworkResponseStatus::Error as u8 => {
                let code = u16::from_le_bytes(bytes[8..10].try_into().expect("slice"));
                Ok(Self::Error { code })
            }
            x if x == NetworkResponseStatus::Ok as u8 => {
                let kind = NetworkRequestKind::from_repr(bytes[6])
                    .ok_or(NetworkResponseDecodeError::InvalidKind(bytes[6]))?;
                match kind {
                    NetworkRequestKind::Resolve => {
                        let mut octets = [0u8; 4];
                        octets.copy_from_slice(&bytes[8..12]);
                        let ttl = u32::from_le_bytes(bytes[12..16].try_into().expect("slice"));
                        Ok(Self::Resolve {
                            addr: crate::addr::Ipv4Addr(octets),
                            ttl,
                        })
                    }
                    NetworkRequestKind::Open => {
                        let session = SessionId::from_raw(u64::from_le_bytes(
                            bytes[8..16].try_into().expect("slice"),
                        ));
                        Ok(Self::Open { session })
                    }
                    NetworkRequestKind::Connect => Ok(Self::Connect),
                    NetworkRequestKind::Send => {
                        let bytes_sent =
                            u32::from_le_bytes(bytes[8..12].try_into().expect("slice"));
                        Ok(Self::Send { bytes_sent })
                    }
                    NetworkRequestKind::Receive => {
                        let payload_len =
                            u32::from_le_bytes(bytes[8..12].try_into().expect("slice"));
                        Ok(Self::Receive { payload_len })
                    }
                    NetworkRequestKind::Close => Ok(Self::Close),
                    NetworkRequestKind::Listen => Ok(Self::Listen),
                    NetworkRequestKind::Accept => {
                        let session = SessionId::from_raw(u64::from_le_bytes(
                            bytes[8..16].try_into().expect("slice"),
                        ));
                        let peer = SocketAddrV4::decode(bytes[16..22].try_into().expect("slice"))
                            .map_err(|_| NetworkResponseDecodeError::Truncated)?;
                        Ok(Self::Accept { session, peer })
                    }
                    NetworkRequestKind::Stats => Ok(Self::Stats {
                        rows: u16::from_le_bytes(bytes[8..10].try_into().expect("slice")),
                        apps: u16::from_le_bytes(bytes[10..12].try_into().expect("slice")),
                        untracked: u32::from_le_bytes(bytes[12..16].try_into().expect("slice")),
                    }),
                }
            }
            other => Err(NetworkResponseDecodeError::InvalidStatus(other)),
        }
    }
}
