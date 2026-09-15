//! Host coverage for declare → start → running → exit/fault → replacement flows.

use clean_slate_service_lifecycle::{
    ControlRequest, ControlRequestKind, DomainId, InstanceGeneration, LifecycleEvent,
    LifecycleEventKind, ProcessId, ServiceId, ServiceInstanceId, ServiceLifecycleState,
};
use clean_slate_supervisor::{DiagnosticSink, FakeLifecycleControl, Supervisor, SupervisorError};

struct NullSink;

impl DiagnosticSink for NullSink {
    fn emit_line(&mut self, _line: &str) -> Result<(), SupervisorError> {
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
fn replacement_instance_after_fault() {
    let service = ServiceId(3);
    let mut control = FakeLifecycleControl::<16>::new();
    control
        .push_pending(LifecycleEvent::new(
            instance(3, 1, 80),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("spawn");
    control
        .push_pending(LifecycleEvent::new(
            instance(3, 1, 80),
            LifecycleEventKind::Ready,
        ))
        .expect("ready");

    let mut supervisor = Supervisor::<_, _, 4>::new(ProcessId(9), control, NullSink);
    supervisor.register_service(service).expect("declare");
    supervisor.request_start(service).expect("start");
    assert_eq!(
        supervisor.registry().query(service).expect("query").state,
        ServiceLifecycleState::Running
    );

    supervisor
        .handle_lifecycle_event(LifecycleEvent::new(
            instance(3, 1, 80),
            LifecycleEventKind::Faulted,
        ))
        .expect("fault");

    supervisor
        .apply_control(ControlRequest::new(service, ControlRequestKind::Start))
        .expect("start replacement from faulted");

    supervisor
        .handle_lifecycle_event(LifecycleEvent::new(
            instance(3, 2, 81),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("spawn replacement");
    supervisor
        .handle_lifecycle_event(LifecycleEvent::new(
            instance(3, 2, 81),
            LifecycleEventKind::Ready,
        ))
        .expect("ready replacement");

    let snapshot = supervisor.registry().query(service).expect("query");
    assert_eq!(snapshot.state, ServiceLifecycleState::Running);
    assert_eq!(snapshot.generation, 2);
    assert_eq!(snapshot.active_pid, Some(81));
    assert_ne!(snapshot.active_pid, Some(service.0 as u64));
}
