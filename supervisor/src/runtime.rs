//! Supervisor runtime: registry ownership, event validation, control issuance.

use core::fmt::Write;

use clean_slate_service_lifecycle::{
    ControlRequest, ControlRequestKind, LifecycleEvent, ProcessId, ServiceId,
};

use crate::control::{LifecycleControl, LifecycleControlError};
use crate::diagnostics::{format_registered_line, format_service_state_line, format_started_line};
use crate::registry::{ServiceRegistry, ServiceRegistryError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupervisorError {
    Registry(ServiceRegistryError),
    Control(LifecycleControlError),
    UnknownService,
}

pub trait DiagnosticSink {
    fn emit_line(&mut self, line: &str) -> Result<(), SupervisorError>;
}

pub struct Supervisor<C, D, const N: usize> {
    self_pid: ProcessId,
    registry: ServiceRegistry<N>,
    control: C,
    diagnostics: D,
}

impl<C, D, const N: usize> Supervisor<C, D, N>
where
    C: LifecycleControl,
    D: DiagnosticSink,
{
    pub fn new(self_pid: ProcessId, control: C, diagnostics: D) -> Self {
        Self {
            self_pid,
            registry: ServiceRegistry::new(),
            control,
            diagnostics,
        }
    }

    pub fn registry(&self) -> &ServiceRegistry<N> {
        &self.registry
    }

    pub fn start(&mut self) -> Result<(), SupervisorError> {
        let mut buffer = LineBuffer::new();
        format_started_line(&mut buffer, self.self_pid)
            .map_err(|_| SupervisorError::Control(LifecycleControlError::TransportFailed))?;
        self.diagnostics.emit_line(buffer.as_str())?;
        Ok(())
    }

    pub fn register_service(&mut self, service: ServiceId) -> Result<(), SupervisorError> {
        self.registry
            .declare(service)
            .map_err(SupervisorError::Registry)?;
        let mut buffer = LineBuffer::new();
        format_registered_line(&mut buffer, service)
            .map_err(|_| SupervisorError::Control(LifecycleControlError::TransportFailed))?;
        self.diagnostics.emit_line(buffer.as_str())?;
        self.log_service_state(service)?;
        Ok(())
    }

    pub fn request_start(&mut self, service: ServiceId) -> Result<(), SupervisorError> {
        let request = ControlRequest::new(service, ControlRequestKind::Start);
        self.control
            .issue_control(request)
            .map_err(SupervisorError::Control)?;
        self.registry
            .apply_control(request)
            .map_err(SupervisorError::Registry)?;
        self.drain_events_for(service)?;
        self.log_service_state(service)?;
        Ok(())
    }

    pub fn apply_control(&mut self, request: ControlRequest) -> Result<(), SupervisorError> {
        self.registry
            .apply_control(request)
            .map_err(SupervisorError::Registry)
    }

    pub fn handle_lifecycle_event(&mut self, event: LifecycleEvent) -> Result<(), SupervisorError> {
        self.registry
            .apply_event(event)
            .map_err(SupervisorError::Registry)?;
        self.log_service_state(event.instance.service)?;
        Ok(())
    }

    pub fn request_restart(&mut self, service: ServiceId) -> Result<(), SupervisorError> {
        let restart = ControlRequest::new(service, ControlRequestKind::Restart);
        self.control
            .issue_control(restart)
            .map_err(SupervisorError::Control)?;
        self.registry
            .apply_control(restart)
            .map_err(SupervisorError::Registry)?;

        let start = ControlRequest::new(service, ControlRequestKind::Start);
        self.control
            .issue_control(start)
            .map_err(SupervisorError::Control)?;
        self.registry
            .apply_control(start)
            .map_err(SupervisorError::Registry)?;
        self.drain_events_for(service)?;
        self.log_service_state(service)?;
        Ok(())
    }

    fn drain_events_for(&mut self, service: ServiceId) -> Result<(), SupervisorError> {
        for _ in 0..8 {
            match self.control.poll_event(service) {
                Ok(Some(event)) => {
                    self.handle_lifecycle_event(event)?;
                }
                Ok(None) => break,
                Err(error) => return Err(SupervisorError::Control(error)),
            }
        }
        Ok(())
    }

    fn log_service_state(&mut self, service: ServiceId) -> Result<(), SupervisorError> {
        let snapshot = self
            .registry
            .query(service)
            .ok_or(SupervisorError::UnknownService)?;
        let mut buffer = LineBuffer::new();
        format_service_state_line(
            &mut buffer,
            snapshot.service,
            snapshot.state,
            snapshot.active_pid,
            snapshot.generation,
        )
        .map_err(|_| SupervisorError::Control(LifecycleControlError::TransportFailed))?;
        self.diagnostics.emit_line(buffer.as_str())?;
        Ok(())
    }
}

struct LineBuffer {
    bytes: [u8; 96],
    len: usize,
}

impl LineBuffer {
    const fn new() -> Self {
        Self {
            bytes: [0; 96],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }
}

impl Write for LineBuffer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let next = self.len + s.len();
        if next > self.bytes.len() {
            return Err(core::fmt::Error);
        }
        self.bytes[self.len..next].copy_from_slice(s.as_bytes());
        self.len = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::FakeLifecycleControl;
    use clean_slate_service_lifecycle::{
        DomainId, InstanceGeneration, LifecycleEventKind, ServiceInstanceId, TransitionError,
    };

    struct VecSink(Vec<String>);

    impl DiagnosticSink for VecSink {
        fn emit_line(&mut self, line: &str) -> Result<(), SupervisorError> {
            self.0.push(line.to_string());
            Ok(())
        }
    }

    fn instance(service: u32, gen: u32, pid: u64) -> ServiceInstanceId {
        ServiceInstanceId::new(
            ServiceId(service),
            InstanceGeneration(gen),
            ProcessId(pid),
            DomainId(pid),
        )
    }

    #[test]
    fn declare_start_running_flow() {
        let service = ServiceId(1);
        let mut control = FakeLifecycleControl::<8>::new();
        control
            .push_pending(LifecycleEvent::new(
                instance(1, 1, 200),
                LifecycleEventKind::InstanceSpawned,
            ))
            .expect("spawned");
        control
            .push_pending(LifecycleEvent::new(
                instance(1, 1, 200),
                LifecycleEventKind::Ready,
            ))
            .expect("ready");

        let mut supervisor =
            Supervisor::<_, _, 8>::new(ProcessId(10), control, VecSink(Vec::new()));
        supervisor.start().expect("start");
        supervisor.register_service(service).expect("register");
        supervisor.request_start(service).expect("start service");

        let snapshot = supervisor.registry().query(service).expect("snapshot");
        assert_eq!(
            snapshot.state,
            clean_slate_service_lifecycle::ServiceLifecycleState::Running
        );
        assert_eq!(snapshot.active_pid, Some(200));
        assert_ne!(snapshot.active_pid, Some(service.0 as u64));
    }

    #[test]
    fn stale_instance_does_not_mutate_replacement() {
        let service = ServiceId(5);
        let control = FakeLifecycleControl::<8>::new();
        let mut supervisor = Supervisor::<_, _, 8>::new(ProcessId(1), control, VecSink(Vec::new()));
        supervisor.register_service(service).expect("register");

        supervisor
            .registry_mut()
            .apply_control(ControlRequest::new(service, ControlRequestKind::Start))
            .expect("control");
        supervisor
            .handle_lifecycle_event(LifecycleEvent::new(
                instance(5, 1, 50),
                LifecycleEventKind::InstanceSpawned,
            ))
            .expect("spawn");
        supervisor
            .handle_lifecycle_event(LifecycleEvent::new(
                instance(5, 1, 50),
                LifecycleEventKind::Ready,
            ))
            .expect("ready");

        supervisor
            .registry_mut()
            .apply_control(ControlRequest::new(service, ControlRequestKind::Restart))
            .expect("restart");
        supervisor
            .registry_mut()
            .apply_control(ControlRequest::new(service, ControlRequestKind::Start))
            .expect("start replacement");

        let err = supervisor
            .handle_lifecycle_event(LifecycleEvent::new(
                instance(5, 1, 50),
                LifecycleEventKind::Exited,
            ))
            .unwrap_err();
        assert!(matches!(
            err,
            SupervisorError::Registry(ServiceRegistryError::Transition(
                TransitionError::StaleInstance { .. }
            ))
        ));
        let snapshot = supervisor.registry().query(service).expect("snapshot");
        assert_eq!(
            snapshot.state,
            clean_slate_service_lifecycle::ServiceLifecycleState::Starting
        );
    }
}

// Test-only accessor to avoid widening the public API surface.
#[cfg(test)]
impl<C, D, const N: usize> Supervisor<C, D, N> {
    fn registry_mut(&mut self) -> &mut ServiceRegistry<N> {
        &mut self.registry
    }
}
