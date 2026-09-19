//! TLS adapter errors (no secret material in [`Debug`] output).

use crate::error::NetworkError;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TlsError {
    Tcp(NetworkError),
    Handshake,
    PeerIdentity,
    Protocol,
    TruncatedRecord,
    Timeout,
    Closed,
    BufferTooSmall,
    Rng,
}

impl core::fmt::Debug for TlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Tcp(inner) => f.debug_tuple("Tcp").field(inner).finish(),
            Self::Handshake => f.write_str("Handshake"),
            Self::PeerIdentity => f.write_str("PeerIdentity"),
            Self::Protocol => f.write_str("Protocol"),
            Self::TruncatedRecord => f.write_str("TruncatedRecord"),
            Self::Timeout => f.write_str("Timeout"),
            Self::Closed => f.write_str("Closed"),
            Self::BufferTooSmall => f.write_str("BufferTooSmall"),
            Self::Rng => f.write_str("Rng"),
        }
    }
}

impl From<NetworkError> for TlsError {
    fn from(value: NetworkError) -> Self {
        Self::Tcp(value)
    }
}

impl From<TlsError> for NetworkError {
    fn from(value: TlsError) -> Self {
        match value {
            TlsError::Tcp(inner) => inner,
            TlsError::Handshake
            | TlsError::PeerIdentity
            | TlsError::Protocol
            | TlsError::TruncatedRecord => NetworkError::Protocol,
            TlsError::Timeout => NetworkError::Timeout,
            TlsError::Closed => NetworkError::Closed,
            TlsError::BufferTooSmall | TlsError::Rng => NetworkError::Protocol,
        }
    }
}

#[cfg(feature = "tls")]
pub(crate) fn map_embedded_tls_error(error: embedded_tls::TlsError) -> TlsError {
    match error {
        embedded_tls::TlsError::InvalidCertificate => TlsError::PeerIdentity,
        embedded_tls::TlsError::ConnectionClosed => TlsError::Closed,
        embedded_tls::TlsError::InvalidRecord
        | embedded_tls::TlsError::ParseError(_)
        | embedded_tls::TlsError::DecodeError => TlsError::TruncatedRecord,
        embedded_tls::TlsError::HandshakeAborted(_, _)
        | embedded_tls::TlsError::AbortHandshake(_, _)
        | embedded_tls::TlsError::MissingHandshake
        | embedded_tls::TlsError::InvalidHandshake => TlsError::Handshake,
        embedded_tls::TlsError::Io(embedded_io::ErrorKind::TimedOut) => TlsError::Timeout,
        embedded_tls::TlsError::Io(_) => TlsError::Protocol,
        _ => TlsError::Protocol,
    }
}
