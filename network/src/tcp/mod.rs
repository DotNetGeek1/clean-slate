//! Bounded TCP (#125, #221 stage F) over [`crate::stack::L3Stack`].
//!
//! Active and passive open (`listen`/`accept`), a sliding send window bounded by the
//! peer's window and a congestion window (RFC 5681 slow start, fast retransmit), RFC 6298
//! retransmission timeouts with exponential backoff and Karn's rule, zero-window probes,
//! and receive-side reassembly of out-of-order segments inside the advertised window.
//! Options: MSS only, on SYN.

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
    TcpTimers, TCP_CONNECT_TIMEOUT_MS, TCP_DEFAULT_PEER_MSS, TCP_DUP_ACK_THRESHOLD,
    TCP_MAX_OOO_RANGES, TCP_MAX_RETRIES, TCP_RECV_BUFFER_BYTES, TCP_RTO_INITIAL_MS, TCP_RTO_MAX_MS,
    TCP_RTO_MIN_MS, TCP_SEND_BUFFER_BYTES, TCP_SYN_ACK_RETRIES, TCP_TIME_WAIT_MS,
};
pub use segment::{
    parse as parse_tcp_segment, write as write_tcp_segment, TcpFlags, TcpSegment, MAX_TCP_PAYLOAD,
    TCP_MIN_HEADER_LEN,
};
pub use state::TcpState;
pub use stats::TcpStats;
pub use transport::{ListenerId, TcpTable, TcpTransport, MAX_TCP_LISTENERS, TCP_LISTEN_BACKLOG};

#[cfg(any(test, feature = "alloc"))]
pub use test_peer::TestPeer;

#[cfg(any(test, feature = "host-tls-peer"))]
pub use tls_test_peer::{
    load_fixture_server_config, server_config_from_chain, server_config_from_der, TlsPeerCert,
    TlsPeerFault, TlsTestPeer,
};

#[cfg(all(test, feature = "alloc"))]
mod tests;

#[cfg(all(test, feature = "alloc"))]
mod reliability_tests;
