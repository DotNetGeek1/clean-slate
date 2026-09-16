//! M4.7 supervised crash-service and unrelated-workload fixtures.
//!
//! Host-testable launch metadata and deterministic diagnostics for QEMU
//! self-tests, future supervisor launch (#36), and recovery acceptance (#42).

#![cfg_attr(not(test), no_std)]

mod block_transport;
mod config;
mod crash_service;
mod diagnostics;
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
pub use unrelated_workload::{UnrelatedWorkloadFixture, UNRELATED_WORKLOAD_SERVICE_ID};

pub use clean_slate_service_lifecycle::ServiceId;

/// Stable logical identity for the supervised crash-service fixture.
pub const CRASH_SERVICE_ID: ServiceId = ServiceId(0x0000_4100);
/// Stable logical identity for the M5 userspace storage service.
pub const STORAGE_SERVICE_ID: ServiceId = ServiceId(0x0000_5100);
