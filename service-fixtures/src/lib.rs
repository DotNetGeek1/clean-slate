//! M4.7 supervised crash-service and unrelated-workload fixtures.
//!
//! Host-testable launch metadata and deterministic diagnostics for QEMU
//! self-tests, future supervisor launch (#36), and recovery acceptance (#42).

#![cfg_attr(not(test), no_std)]

mod block_transport;
mod config;
mod crash_service;
mod diagnostics;
/// M6 scripted CPL3 fixture protocol (shared test harness).
pub mod m6_fixture;
mod network_service;
mod network_transport;
/// M6.3 object-capability protocol (lane-owned).
pub mod object_capability;
mod storage_service;
mod unrelated_workload;

pub use block_transport::{
    handle_block_request, BlockTransportDecodeError, BlockTransportOp, BlockTransportRequest,
    BlockTransportResponse, BlockTransportStatus, BLOCK_TRANSPORT_MAGIC,
    BLOCK_TRANSPORT_MAX_PAYLOAD_BYTES, BLOCK_TRANSPORT_REQUEST_BYTES,
    BLOCK_TRANSPORT_RESPONSE_BYTES, BLOCK_TRANSPORT_VERSION, STORAGE_BLOCK_DEVICE_ID,
};
pub use config::{
    ConfigDecodeError, ConfigEncodeError, CrashServiceLaunchConfig, CrashServiceMode,
    UnrelatedWorkloadLaunchConfig, CRASH_SERVICE_LAUNCH_MAGIC, CRASH_SERVICE_LAUNCH_VERSION,
    UNRELATED_WORKLOAD_LAUNCH_MAGIC, UNRELATED_WORKLOAD_LAUNCH_VERSION,
};
pub use crash_service::{CrashServiceFixtureHarness, CrashServiceFixtureRole};
pub use diagnostics::{
    format_crash_service_injecting_line, format_crash_service_replacement_healthy_line,
    format_crash_service_started_line, format_unrelated_workload_progress_line,
};
pub use network_service::{
    AllowAllAuthorizer, DenyAllAuthorizer, NetworkAuthorizer, NetworkOp, NetworkService,
};
pub use network_transport::{
    encode_request, encode_response, NetworkServiceBootstrap, NetworkServiceWorkItem,
    NetworkServiceWorkItem as NetWorkItem, NETWORK_CAPABILITY_VERSION, NETWORK_CLIENT_DEVICE_ID,
    NETWORK_DEVICE_ID, NETWORK_MAX_PAYLOAD_BYTES, NETWORK_REQUEST_SLOTS,
    NETWORK_SERVICE_BOOTSTRAP_ADDRESS, NETWORK_SERVICE_MODE_ACCEPTANCE,
    NETWORK_SERVICE_MODE_CAPACITY_LOOP, NETWORK_SERVICE_MODE_CLIENT,
    NETWORK_SERVICE_MODE_CONVERGED_CLIENT, NETWORK_SERVICE_MODE_INFLIGHT_ARM,
    NETWORK_SERVICE_MODE_STALE_CLOSE, NETWORK_SERVICE_MODE_UNAUTHORIZED_PROBE,
    NETWORK_SERVICE_NEXT_METADATA_BYTES, NETWORK_SERVICE_NEXT_WIRE_BYTES,
    NETWORK_SERVICE_RESULT_ERROR, NETWORK_SERVICE_RESULT_OK, NETWORK_SERVICE_RESULT_PENDING,
    NETWORK_STATUS_PENDING, NETWORK_UNAUTHORIZED_PROBE_SERVICE_ID_VALUE, NET_SERVICE_ROLE_ID,
    NET_SUBOP_ACK_HOLDER_EXIT, NET_SUBOP_MONOTONIC_TICKS, NET_SUBOP_POLL,
    NET_SUBOP_POP_HOLDER_EXIT, NET_SUBOP_RAW_GEOMETRY, NET_SUBOP_RAW_RECEIVE,
    NET_SUBOP_RAW_TRANSMIT, NET_SUBOP_SERVICE_COMPLETE, NET_SUBOP_SERVICE_NEXT,
    NET_SUBOP_SERVICE_REQUEUE, NET_SUBOP_SUBMIT,
    NET_SUBOP_TICK_PERIOD_NS,
};
pub use object_capability::{
    ObjectServiceDecodeError, ObjectServiceRequest, OBJECT_MAX_PAYLOAD_BYTES, OBJECT_OP_READ,
    OBJECT_OP_WRITE, OBJECT_REQUEST_SLOTS, OBJECT_SERVICE_REQUEST_BYTES, OBJECT_SERVICE_ROLE_ID,
    OBJECT_STATUS_NOT_FOUND, OBJECT_STATUS_OK, OBJECT_STATUS_PENDING, OBJECT_STATUS_STORE_ERROR,
    OBJECT_STATUS_TOO_LARGE, OBJECT_SUBOP_CLAIM_BOOTSTRAP_GRANT, OBJECT_SUBOP_POLL,
    OBJECT_SUBOP_SERVICE_COMPLETE, OBJECT_SUBOP_SERVICE_NEXT, OBJECT_SUBOP_SUBMIT,
};
pub use storage_service::{
    StorageServiceBootstrap, STORAGE_SERVICE_BOOTSTRAP_ADDRESS,
    STORAGE_SERVICE_MODE_CRASH_ARM_EARLY, STORAGE_SERVICE_MODE_CRASH_ARM_LATE,
    STORAGE_SERVICE_MODE_CRASH_RECOVERY, STORAGE_SERVICE_MODE_INTEGRATION_INITIAL,
    STORAGE_SERVICE_MODE_INTEGRATION_RESTART, STORAGE_SERVICE_MODE_OBJECT_SERVICE,
    STORAGE_SERVICE_MODE_PERSISTENCE, STORAGE_SERVICE_MODE_UNAUTHORIZED_PROBE,
    STORAGE_SERVICE_RESULT_ERROR, STORAGE_SERVICE_RESULT_OK, STORAGE_SERVICE_RESULT_PENDING,
    STORAGE_SERVICE_RESULT_UNAUTHORIZED_DENIED,
};
pub use unrelated_workload::{UnrelatedWorkloadFixture, UNRELATED_WORKLOAD_SERVICE_ID};

pub use clean_slate_service_lifecycle::ServiceId;

/// Stable logical identity for the supervised crash-service fixture.
pub const CRASH_SERVICE_ID: ServiceId = ServiceId(0x0000_4100);
/// Stable logical identity for the M5 userspace storage service.
pub const STORAGE_SERVICE_ID: ServiceId = ServiceId(0x0000_5100);
/// Stable logical identity for an unrelated userspace process used by M5 denial tests.
pub const STORAGE_UNAUTHORIZED_SERVICE_ID: ServiceId = ServiceId(0x0000_5101);
/// Stable logical identity for the M7 userspace network service.
pub const NETWORK_SERVICE_ID: ServiceId = ServiceId(0x0000_5200);
/// Unrelated process used by M7 denial tests.
pub const NETWORK_UNAUTHORIZED_SERVICE_ID: ServiceId = ServiceId(0x0000_5201);
