//! I/O error type of the TLS transaction's TCP adapter.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsIoError;

impl core::fmt::Display for TlsIoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("tls io error")
    }
}

impl core::error::Error for TlsIoError {}

impl embedded_io::Error for TlsIoError {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::TimedOut
    }
}
