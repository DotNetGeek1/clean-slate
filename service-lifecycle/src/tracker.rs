//! Per-service lifecycle record used by supervisor/kernel adapters.

use crate::control::{ControlRequest, ControlRequestKind};
use crate::identity::{InstanceGeneration, ServiceId, ServiceInstanceId};
use crate::state::{
    apply_transition, LifecycleEvent, LifecycleEventKind, ServiceLifecycleState, TransitionError,
    TransitionInput,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceLifecycleRecord {
    pub service: ServiceId,
    pub state: ServiceLifecycleState,
    pub authoritative_generation: InstanceGeneration,
    pub active_instance: Option<ServiceInstanceId>,
}

impl ServiceLifecycleRecord {
    pub const fn declared(service: ServiceId) -> Self {
        Self {
            service,
            state: ServiceLifecycleState::Declared,
            authoritative_generation: InstanceGeneration(0),
            active_instance: None,
        }
    }

    pub fn apply_control(&mut self, request: ControlRequest) -> Result<(), TransitionError> {
        if request.service != self.service {
            return Err(TransitionError::InstanceMismatch);
        }
        let (next, generation) = apply_transition(
            self.state,
            self.authoritative_generation,
            TransitionInput::Control(request.kind),
            None,
        )?;
        self.state = next;
        self.authoritative_generation = generation;
        if matches!(
            request.kind,
            ControlRequestKind::Start | ControlRequestKind::Restart
        ) {
            self.active_instance = None;
        }
        Ok(())
    }

    pub fn apply_event(&mut self, event: LifecycleEvent) -> Result<(), TransitionError> {
        if event.instance.service != self.service {
            return Err(TransitionError::InstanceMismatch);
        }
        let (next, generation) = apply_transition(
            self.state,
            self.authoritative_generation,
            TransitionInput::Event(event.kind),
            Some(event.instance),
        )?;
        self.state = next;
        self.authoritative_generation = generation;
        if matches!(event.kind, LifecycleEventKind::InstanceSpawned) {
            self.active_instance = Some(event.instance);
        }
        if matches!(
            event.kind,
            LifecycleEventKind::Exited | LifecycleEventKind::Faulted
        ) {
            self.active_instance = None;
        }
        Ok(())
    }
}

/// Fixed-capacity registry for parallel M4 lanes (supervisor host tests).
pub struct ServiceLifecycleTracker<const N: usize> {
    records: [Option<ServiceLifecycleRecord>; N],
}

impl<const N: usize> Default for ServiceLifecycleTracker<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ServiceLifecycleTracker<N> {
    pub const fn new() -> Self {
        Self { records: [None; N] }
    }

    pub fn declare(&mut self, service: ServiceId) -> Result<(), TrackerError> {
        if self.find(service).is_some() {
            return Err(TrackerError::DuplicateService);
        }
        let slot = self
            .records
            .iter()
            .position(|entry| entry.is_none())
            .ok_or(TrackerError::CapacityExceeded)?;
        self.records[slot] = Some(ServiceLifecycleRecord::declared(service));
        Ok(())
    }

    pub fn record_mut(
        &mut self,
        service: ServiceId,
    ) -> Result<&mut ServiceLifecycleRecord, TrackerError> {
        let index = self.find(service).ok_or(TrackerError::UnknownService)?;
        self.records[index]
            .as_mut()
            .ok_or(TrackerError::UnknownService)
    }

    fn find(&self, service: ServiceId) -> Option<usize> {
        self.records
            .iter()
            .position(|entry| matches!(entry, Some(record) if record.service == service))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrackerError {
    DuplicateService,
    UnknownService,
    CapacityExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{DomainId, ProcessId};

    fn instance(service: u32, gen: u32, pid: u64) -> ServiceInstanceId {
        ServiceInstanceId::new(
            ServiceId(service),
            InstanceGeneration(gen),
            ProcessId(pid),
            DomainId(pid),
        )
    }

    #[test]
    fn stale_instance_cannot_update_replacement_state() {
        let mut tracker = ServiceLifecycleTracker::<4>::new();
        let service = ServiceId(10);
        tracker.declare(service).expect("declare");
        let record = tracker.record_mut(service).expect("record");
        record
            .apply_control(ControlRequest::new(service, ControlRequestKind::Start))
            .expect("start");
        record
            .apply_event(LifecycleEvent::new(
                instance(10, 1, 100),
                LifecycleEventKind::Ready,
            ))
            .expect("ready");
        assert_eq!(record.state, ServiceLifecycleState::Running);
        assert_eq!(record.authoritative_generation, InstanceGeneration(1));

        record
            .apply_control(ControlRequest::new(service, ControlRequestKind::Restart))
            .expect("restart request");
        record
            .apply_control(ControlRequest::new(service, ControlRequestKind::Start))
            .expect("start replacement");
        assert_eq!(record.authoritative_generation, InstanceGeneration(2));

        let stale_exit = LifecycleEvent::new(instance(10, 1, 100), LifecycleEventKind::Exited);
        let err = tracker
            .record_mut(service)
            .expect("record")
            .apply_event(stale_exit)
            .unwrap_err();
        assert!(matches!(err, TransitionError::StaleInstance { .. }));
        assert_eq!(
            tracker.record_mut(service).expect("record").state,
            ServiceLifecycleState::Starting
        );
    }

    #[test]
    fn logical_service_id_differs_from_pid_in_active_instance() {
        let mut record = ServiceLifecycleRecord::declared(ServiceId(42));
        record
            .apply_control(ControlRequest::new(
                ServiceId(42),
                ControlRequestKind::Start,
            ))
            .expect("start");
        let pid = ProcessId(9001);
        let inst = ServiceInstanceId::new(ServiceId(42), InstanceGeneration(1), pid, DomainId(77));
        record
            .apply_event(LifecycleEvent::new(
                inst,
                LifecycleEventKind::InstanceSpawned,
            ))
            .expect("spawned");
        let active = record.active_instance.expect("active");
        assert_eq!(active.logical_service(), ServiceId(42));
        assert_eq!(active.pid, pid);
        assert_ne!(active.pid.0, active.logical_service().0 as u64);
    }
}
