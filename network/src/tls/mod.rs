//! Bounded TLS 1.3 client over [`crate::tcp::TcpTransport`] (#86).

#[cfg(feature = "tls")]
mod error;
#[cfg(feature = "tls")]
mod io;
#[cfg(feature = "tls")]
mod session;
#[cfg(feature = "tls")]
mod verify;

#[cfg(feature = "tls")]
pub use error::TlsError;
#[cfg(feature = "tls")]
pub use session::{TlsConfig, TlsSession};
#[cfg(feature = "tls")]
pub use verify::{TlsRng, VALIDATION_TIME_UNIX};

/// Maximum TLS ciphertext record size (RFC 8446); safe read buffer size for `embedded-tls`.
pub const TLS_RECORD_BUFFER_BYTES: usize = 16_640;

#[cfg(feature = "tls")]
#[cfg(test)]
mod tests;
