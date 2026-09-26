//! Bounded network-service IPC subops and bootstrap metadata (M7.3).

use clean_slate_network::protocol::{
    NetworkRequest, NetworkResponse, NETWORK_REQUEST_BYTES, NETWORK_RESPONSE_BYTES,
};

pub const NETWORK_UNAUTHORIZED_PROBE_SERVICE_ID_VALUE: u32 = 0x0000_5201;
pub const NETWORK_DEVICE_ID: u64 = 1;
/// Application network access (submit/poll); distinct from raw NIC authority.
pub const NETWORK_CLIENT_DEVICE_ID: u64 = 2;

pub const NETWORK_STATUS_PENDING: u64 = 0xFFFF_FFFF_FFFF_FFF0;

pub const NETWORK_SERVICE_BOOTSTRAP_ADDRESS: u64 = 0x0000_4000_0020_0000;

pub const NETWORK_CAPABILITY_VERSION: u16 = 1;

pub const NETWORK_SERVICE_MODE_ACCEPTANCE: u64 = 1;
pub const NETWORK_SERVICE_MODE_UNAUTHORIZED_PROBE: u64 = 2;
pub const NETWORK_SERVICE_MODE_CLIENT: u64 = 3;
pub const NETWORK_SERVICE_MODE_INFLIGHT_ARM: u64 = 4;
pub const NETWORK_SERVICE_MODE_STALE_CLOSE: u64 = 5;
pub const NETWORK_SERVICE_MODE_CAPACITY_LOOP: u64 = 6;
pub const NETWORK_SERVICE_MODE_CONVERGED_CLIENT: u64 = 7;

pub const NETWORK_SERVICE_RESULT_PENDING: u64 = 0;
pub const NETWORK_SERVICE_RESULT_OK: u64 = 1;
pub const NETWORK_SERVICE_RESULT_ERROR: u64 = 2;

pub const NET_SUBOP_SUBMIT: u64 = 1;
pub const NET_SUBOP_POLL: u64 = 2;
pub const NET_SUBOP_SERVICE_NEXT: u64 = 3;
pub const NET_SUBOP_SERVICE_COMPLETE: u64 = 4;
pub const NET_SUBOP_RAW_GEOMETRY: u64 = 5;
pub const NET_SUBOP_RAW_TRANSMIT: u64 = 6;
pub const NET_SUBOP_RAW_RECEIVE: u64 = 7;
pub const NET_SUBOP_POP_HOLDER_EXIT: u64 = 8;
pub const NET_SUBOP_ACK_HOLDER_EXIT: u64 = 9;
pub const NET_SUBOP_MONOTONIC_TICKS: u64 = 10;
/// Returns LAPIC IRQ period in nanoseconds (0 if uncalibrated).
pub const NET_SUBOP_TICK_PERIOD_NS: u64 = 11;
/// Net-service idle block (#167): `rsi` = raw-device handle, `rdx` = non-empty subset of
/// [`NET_WAIT_WORK_MASK`], `r10` = relative timeout in ns (0 = no timeout, requires a
/// calibrated TSC otherwise). Returns 0 when a selected source is already ready, else the
/// #145 native wait outcome after blocking (woken / timed out / cancelled); callers re-check
/// state either way. Errors: `EINVAL` (bad mask, TSC uncalibrated), `EACCES`, `ESTALE`.
pub const NET_SUBOP_WAIT_WORK: u64 = 12;
/// Wake for a queued client request or a pending holder-exit notification.
pub const NET_WAIT_WORK_REQUESTS: u64 = 1 << 0;
/// Wake when `NET_SUBOP_RAW_RECEIVE` would return a frame.
pub const NET_WAIT_WORK_RX: u64 = 1 << 1;
pub const NET_WAIT_WORK_MASK: u64 = NET_WAIT_WORK_REQUESTS | NET_WAIT_WORK_RX;

pub const NET_SERVICE_ROLE_ID: u64 = 1;

pub const NETWORK_MAX_PAYLOAD_BYTES: usize =
    clean_slate_network::limits::MAX_APPLICATION_PAYLOAD_BYTES;
pub const NETWORK_SERVICE_NEXT_METADATA_BYTES: usize = 28;
pub const NETWORK_SERVICE_NEXT_WIRE_BYTES: usize =
    NETWORK_SERVICE_NEXT_METADATA_BYTES + NETWORK_MAX_PAYLOAD_BYTES;

pub const NETWORK_REQUEST_SLOTS: usize = 64;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkServiceBootstrap {
    pub mode: u64,
    pub service_generation: u64,
    pub result_code: u64,
    pub aux_status: u64,
    pub net_role_handle: u64,
    pub session_id_raw: u64,
    pub echo_len: u64,
    pub reclaimed_sessions: u64,
    pub reclaimed_pending: u64,
    pub inflight_failed: u64,
    pub tls_transactions: u64,
    pub tls_heap_checkpoint: u64,
    pub tls_heap_after_last: u64,
}

impl NetworkServiceBootstrap {
    pub const fn new(mode: u64, service_generation: u64) -> Self {
        Self {
            mode,
            service_generation,
            result_code: NETWORK_SERVICE_RESULT_PENDING,
            aux_status: 0,
            net_role_handle: 0,
            session_id_raw: 0,
            echo_len: 0,
            reclaimed_sessions: 0,
            reclaimed_pending: 0,
            inflight_failed: 0,
            tls_transactions: 0,
            tls_heap_checkpoint: 0,
            tls_heap_after_last: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkServiceWorkItem {
    pub request_id: u64,
    pub request: NetworkRequest,
    pub payload_len: u32,
    pub payload: [u8; NETWORK_MAX_PAYLOAD_BYTES],
}

impl NetworkServiceWorkItem {
    pub const fn empty() -> Self {
        Self {
            request_id: 0,
            request: NetworkRequest::Close {
                session: clean_slate_network::session::SessionId::from_raw(0),
            },
            payload_len: 0,
            payload: [0; NETWORK_MAX_PAYLOAD_BYTES],
        }
    }
}

pub fn encode_request(request: &NetworkRequest) -> [u8; NETWORK_REQUEST_BYTES] {
    request.encode()
}

pub fn encode_response(response: &NetworkResponse) -> [u8; NETWORK_RESPONSE_BYTES] {
    response.encode()
}
