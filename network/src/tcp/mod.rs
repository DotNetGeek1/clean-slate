//! Bounded client-only TCP (#125) over [`crate::stack::L3Stack`].
//!
//! In-order delivery, stop-and-go (one outstanding data segment), fixed RTO,
//! MSS-only options on SYN. Server/listen states are out of scope.

mod conn;
mod segment;
mod state;
mod stats;
mod transport;

#[cfg(any(test, feature = "alloc"))]
mod test_peer;

#[cfg(any(test, feature = "host-tls-peer"))]
mod tls_test_peer;

pub use conn::{
    TCP_CONNECT_TIMEOUT_TICKS, TCP_MAX_RETRIES, TCP_RECV_BUFFER_BYTES, TCP_RTO_TICKS,
    TCP_SEND_BUFFER_BYTES, TCP_TIME_WAIT_TICKS,
};
pub use segment::{TcpFlags, TcpSegment, MAX_TCP_PAYLOAD, TCP_MIN_HEADER_LEN};
pub use state::TcpState;
pub use stats::TcpStats;
pub use transport::{TcpTable, TcpTransport};

#[cfg(any(test, feature = "alloc"))]
pub use test_peer::TestPeer;

#[cfg(any(test, feature = "host-tls-peer"))]
pub use tls_test_peer::{
    load_fixture_server_config, server_config_from_der, TlsPeerCert, TlsPeerFault, TlsTestPeer,
};

#[cfg(test)]
mod tests;
