//! M4.1 service lifecycle protocol and state model.
//!
//! Shared, host-testable contract for the userspace supervisor, kernel lifecycle
//! control path, and supervised services. Policy (restart backoff, dependency
//! evaluation, health timeouts) stays out of this layer.

#![cfg_attr(not(test), no_std)]

mod control;
mod dependency;
mod diagnostics;
mod health;
mod identity;
mod state;
mod tracker;
mod wire;

pub use control::{ControlRequest, ControlRequestKind};
pub use dependency::{DependencyEdge, DependencyMetadata, MAX_INLINE_DEPENDENCIES};
pub use diagnostics::{format_declared_line, format_instance_line};
pub use health::{HealthReport, HealthStatus};
pub use identity::{DomainId, InstanceGeneration, ProcessId, ServiceId, ServiceInstanceId};
pub use state::{LifecycleEvent, LifecycleEventKind, ServiceLifecycleState, TransitionError};
pub use tracker::{ServiceLifecycleRecord, ServiceLifecycleTracker};
pub use wire::{
    DecodeError, LifecycleMessage, LifecycleMessageKind, LIFECYCLE_PROTOCOL_VERSION,
    LIFECYCLE_WIRE_MAX_BYTES,
};
