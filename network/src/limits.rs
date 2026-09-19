//! Explicit upper bounds for the first M7 implementation.
//!
//! These limits are part of the public contract: later lanes must not silently
//! exceed them without a coordinated version bump.

/// Maximum Ethernet frame size accepted by the device contract (1514 bytes).
///
/// VLAN tags and jumbo frames are out of scope for M7 wave-0.
pub const MAX_ETHERNET_FRAME_BYTES: usize = 1514;

/// Standard IPv4 MTU (1500-byte L3 payload on Ethernet).
pub const MTU: u16 = 1500;

/// Maximum L3 payload bytes the stack contract accepts for a single datagram
/// (matches [`MTU`] for IPv4-on-Ethernet).
pub const MAX_L3_PAYLOAD_BYTES: usize = MTU as usize;

/// Maximum simultaneous socket sessions per network-service instance.
pub const MAX_SESSIONS: u32 = 32;

/// Maximum outstanding client requests queued per session.
pub const MAX_PENDING_REQUESTS_PER_SESSION: u32 = 8;

/// Maximum RX frames queued on a [`crate::device::NetworkLink`] implementation.
pub const MAX_DEVICE_RX_QUEUE_DEPTH: u32 = 64;

/// Maximum TX frames queued on a [`crate::device::NetworkLink`] implementation.
pub const MAX_DEVICE_TX_QUEUE_DEPTH: u32 = 64;

/// Maximum DNS host name length (253 octets per RFC 1035).
pub const MAX_DNS_NAME_LEN: usize = 253;

/// Maximum length of a single DNS label (63 octets).
pub const MAX_DNS_LABEL_LEN: usize = 63;

/// Maximum host name length a client may place in one `Resolve` request.
///
/// The client<->service request frame is a single kernel IPC message
/// (64 bytes, see `kernel::ipc::IPC_MAX_MESSAGE_BYTES`); after the header and
/// length byte, 55 bytes remain for the name. This is deliberately smaller than
/// [`MAX_DNS_NAME_LEN`], which bounds names parsed from DNS wire messages.
pub const MAX_REQUEST_HOSTNAME_LEN: usize = 55;

/// Maximum in-flight resolver queries per client holder.
pub const MAX_IN_FLIGHT_RESOLVER_QUERIES: u32 = 8;

/// Maximum concurrent TCP connections tracked by the network service.
pub const MAX_TCP_CONNECTIONS: u32 = MAX_SESSIONS;

/// Maximum concurrent UDP endpoints tracked by the network service.
pub const MAX_UDP_ENDPOINTS: u32 = MAX_SESSIONS;

/// Maximum application payload bytes in one `Send` request.
pub const MAX_APPLICATION_PAYLOAD_BYTES: usize = 4096;

/// Maximum bytes returned by one `Receive` response payload slice.
pub const MAX_RECEIVE_BYTES: usize = MAX_APPLICATION_PAYLOAD_BYTES;
