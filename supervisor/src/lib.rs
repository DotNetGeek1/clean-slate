//! M4.3 userspace supervisor runtime and bounded service registry.
//!
//! Policy (health timeouts, dependency graphs, restart backoff) stays out of this
//! crate; lifecycle control is delegated to a narrow, mockable backend (#36).

#![cfg_attr(not(test), no_std)]

mod control;
mod diagnostics;
mod registry;
mod runtime;

pub use control::{FakeLifecycleControl, LifecycleControl, LifecycleControlError};
pub use diagnostics::{format_registered_line, format_service_state_line, format_started_line};
pub use registry::{ServiceQueryEntry, ServiceRegistry, ServiceRegistryError};
pub use runtime::{DiagnosticSink, Supervisor, SupervisorError};

pub const DEFAULT_REGISTRY_CAPACITY: usize = 8;
