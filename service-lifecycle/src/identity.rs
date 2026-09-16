//! Logical service identity vs process-instance identity.

use core::fmt;

/// Stable logical identity for a supervised service (independent of PID/generation).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServiceId(pub u32);

/// Monotonic replacement counter for a logical service's live instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InstanceGeneration(pub u32);

/// Process identifier for a running instance (kernel-owned, not stable across restarts).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProcessId(pub u64);

/// Resource-domain identifier bound to a process instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DomainId(pub u64);

/// A specific process/domain incarnation of a logical service.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ServiceInstanceId {
    pub service: ServiceId,
    pub generation: InstanceGeneration,
    pub pid: ProcessId,
    pub domain: DomainId,
}

impl ServiceInstanceId {
    pub const fn new(
        service: ServiceId,
        generation: InstanceGeneration,
        pid: ProcessId,
        domain: DomainId,
    ) -> Self {
        Self {
            service,
            generation,
            pid,
            domain,
        }
    }

    /// Logical service only — never conflated with a PID.
    pub const fn logical_service(self) -> ServiceId {
        self.service
    }
}

impl fmt::Display for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
