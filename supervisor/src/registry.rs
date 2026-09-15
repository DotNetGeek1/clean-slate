//! Bounded userspace service registry keyed by stable logical `ServiceId`.

use clean_slate_service_lifecycle::{
    ControlRequest, LifecycleEvent, ServiceId, ServiceLifecycleRecord, ServiceLifecycleState,
    ServiceLifecycleTracker, TrackerError, TransitionError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceQueryEntry {
    pub service: ServiceId,
    pub state: ServiceLifecycleState,
    pub generation: u32,
    pub active_pid: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceRegistryError {
    Registry(TrackerError),
    Transition(TransitionError),
}

/// Fixed-capacity registry; logical service ID is never derived from PID.
pub struct ServiceRegistry<const N: usize> {
    tracker: ServiceLifecycleTracker<N>,
}

impl<const N: usize> Default for ServiceRegistry<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ServiceRegistry<N> {
    pub const fn new() -> Self {
        Self {
            tracker: ServiceLifecycleTracker::new(),
        }
    }

    pub fn declare(&mut self, service: ServiceId) -> Result<(), ServiceRegistryError> {
        self.tracker
            .declare(service)
            .map_err(ServiceRegistryError::Registry)
    }

    pub fn apply_control(&mut self, request: ControlRequest) -> Result<(), ServiceRegistryError> {
        self.tracker
            .record_mut(request.service)
            .map_err(ServiceRegistryError::Registry)?
            .apply_control(request)
            .map_err(ServiceRegistryError::Transition)
    }

    pub fn apply_event(&mut self, event: LifecycleEvent) -> Result<(), ServiceRegistryError> {
        self.tracker
            .record_mut(event.instance.service)
            .map_err(ServiceRegistryError::Registry)?
            .apply_event(event)
            .map_err(ServiceRegistryError::Transition)
    }

    pub fn query(&self, service: ServiceId) -> Option<ServiceQueryEntry> {
        self.tracker.record(service).ok().map(snapshot_from_record)
    }

    pub fn entries(&self) -> [Option<ServiceQueryEntry>; N] {
        let mut out = [None; N];
        for (index, slot) in self.tracker.entries().iter().enumerate() {
            out[index] = slot.as_ref().map(snapshot_from_record);
        }
        out
    }
}

fn snapshot_from_record(record: &ServiceLifecycleRecord) -> ServiceQueryEntry {
    ServiceQueryEntry {
        service: record.service,
        state: record.state,
        generation: record.authoritative_generation.0,
        active_pid: record.active_instance.map(|instance| instance.pid.0),
    }
}
