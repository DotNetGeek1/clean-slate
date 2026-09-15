//! M4.1 service lifecycle protocol and state model.
//!
//! Shared, host-testable contract for the userspace supervisor, kernel lifecycle
//! control path, and supervised services. Restart backoff stays out of this layer.
//! M4.4 health timeout evaluation lives in `health_tracker` without restart policy.
//! M4.5 dependency evaluation is host-testable in `dependency_graph`.

#![cfg_attr(not(test), no_std)]

mod control;
mod dependency;
mod dependency_graph;
mod diagnostics;
mod health;
mod health_tracker;
mod identity;
mod state;
mod time;
mod tracker;
mod wire;

pub use control::{ControlRequest, ControlRequestKind};
pub use dependency::{DependencyEdge, DependencyMetadata, MAX_INLINE_DEPENDENCIES};
pub use dependency_graph::{
    lifecycle_state_satisfies, single_dependency, DependencyGraph, DependencyGraphError,
    DependencyHealthSnapshot, StartBlockReason, StartReadiness, DEFAULT_REQUIRED_DEPENDENCY_STATE,
};
pub use diagnostics::{
    format_declared_line, format_dependency_blocked_line, format_dependency_ready_line,
    format_health_healthy_line, format_health_unhealthy_line, format_instance_line,
};
pub use health::{HealthReport, HealthStatus};
pub use health_tracker::{
    HealthFailureEvent, HealthFailureReason, HealthReportOutcome, HealthTrackerError,
    LifecycleFailureOutcome, ServiceHealthRecord, ServiceHealthTracker,
};
pub use identity::{DomainId, InstanceGeneration, ProcessId, ServiceId, ServiceInstanceId};
pub use state::{
    apply_transition, LifecycleEvent, LifecycleEventKind, ServiceLifecycleState, TransitionError,
    TransitionInput,
};
pub use time::{ticks_add, ticks_reached, LivenessConfig, MonotonicTicks};
pub use tracker::{ServiceLifecycleRecord, ServiceLifecycleTracker, TrackerError};
pub use wire::{
    DecodeError, LifecycleMessage, LifecycleMessageKind, LIFECYCLE_PROTOCOL_VERSION,
    LIFECYCLE_WIRE_MAX_BYTES,
};
