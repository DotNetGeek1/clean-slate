//! Bounded TLS 1.3 client over [`crate::tcp::TcpTransport`] (#86).

#[cfg(feature = "tls")]
mod error;
#[cfg(feature = "tls")]
mod io;
#[cfg(feature = "tls")]
mod session;
#[cfg(feature = "tls")]
mod trace;
#[cfg(feature = "tls")]
mod transaction;
#[cfg(feature = "tls")]
mod verify;

#[cfg(feature = "tls")]
pub use error::TlsError;
#[cfg(feature = "tls")]
pub use session::TlsConfig;
#[cfg(feature = "m7-handshake-trace")]
pub use trace::HANDSHAKE_MARKER;
#[cfg(feature = "tls")]
pub use transaction::{tls_transaction, TlsTransactionBudget, TlsTransactionClock};
#[cfg(feature = "tls")]
pub use verify::TlsRng;

/// Pages of scratch heap one TLS transaction may use (the network service's runs
/// `clean_slate_runtime`'s size-class heap over this many pages and resets it after each
/// transaction). `embedded-tls`'s certificate parser and RSA verification (`rsa`'s big
/// integers) are what allocate; the host tests check the fixture chains fit in half of it.
pub const TLS_SCRATCH_PAGES: usize = 48;

/// Maximum TLS ciphertext record size (RFC 8446); safe read buffer size for `embedded-tls`.
pub const TLS_RECORD_BUFFER_BYTES: usize = 16_640;

#[cfg(all(test, feature = "alloc", feature = "tls"))]
mod tests;
