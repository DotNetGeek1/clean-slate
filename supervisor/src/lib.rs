//! M4.3 userspace supervisor runtime and bounded service registry.
//!
//! Policy (health timeouts, dependency graphs, restart backoff) stays out of the
//! registry core where noted; Wave 2 convergence (`ConvergedSupervisor`) composes
//! health (#38), dependencies (#39), and restart policy (#40) in userspace.

#![cfg_attr(not(test), no_std)]

mod control;
mod convergence;
mod diagnostics;
mod registry;
mod restart_policy;
mod runtime;

pub use control::{FakeLifecycleControl, LifecycleControl, LifecycleControlError};
pub use convergence::{ConvergedSupervisor, ConvergedSupervisorError, ServiceConvergenceConfig};
pub use diagnostics::{
    format_failure_line, format_registered_line, format_restart_line,
    format_restart_suppressed_line, format_restarted_line, format_service_state_line,
    format_started_line,
};
pub use registry::{ServiceQueryEntry, ServiceRegistry, ServiceRegistryError};
pub use restart_policy::{
    BoundedRestart, RecoveryRuntime, RestartDecision, RestartPolicy, RestartSuppressedReason,
};
pub use runtime::{DiagnosticSink, Supervisor, SupervisorError};

pub const DEFAULT_REGISTRY_CAPACITY: usize = 8;
