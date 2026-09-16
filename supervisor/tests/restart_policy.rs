//! Host coverage for M4.6 restart policy and Wave 2 convergence.

use std::cell::RefCell;
use std::rc::Rc;

use clean_slate_service_lifecycle::{
    single_dependency, DomainId, HealthReport, HealthStatus, InstanceGeneration, LifecycleEvent,
    LifecycleEventKind, LivenessConfig, ProcessId, ServiceId, ServiceInstanceId,
    ServiceLifecycleState,
};
use clean_slate_supervisor::{
    BoundedRestart, ConvergedSupervisor, ConvergedSupervisorError, DiagnosticSink,
    FakeLifecycleControl, RestartPolicy, ServiceConvergenceConfig, SupervisorError,
};

#[derive(Clone, Default)]
struct LineCapture(Rc<RefCell<Vec<String>>>);

impl DiagnosticSink for LineCapture {
    fn emit_line(&mut self, line: &str) -> Result<(), SupervisorError> {
        self.0.borrow_mut().push(line.to_string());
        Ok(())
    }
}

fn lines(capture: &LineCapture) -> Vec<String> {
    capture.0.borrow().clone()
}

fn instance(service: u32, gen: u32, pid: u64) -> ServiceInstanceId {
    ServiceInstanceId::new(
        ServiceId(service),
        InstanceGeneration(gen),
        ProcessId(pid),
        DomainId(pid),
    )
}

fn on_failure_config() -> ServiceConvergenceConfig {
    ServiceConvergenceConfig::new(
        RestartPolicy::OnFailure(BoundedRestart::new(3, 5)),
        LivenessConfig::new(100),
    )
}

fn on_failure_no_backoff_config() -> ServiceConvergenceConfig {
    ServiceConvergenceConfig::new(
        RestartPolicy::OnFailure(BoundedRestart::new(3, 0)),
        LivenessConfig::new(100),
    )
}

#[test]
fn successful_restart_after_fault_emits_recovery_markers() {
    let service = ServiceId(1);
    let mut control = FakeLifecycleControl::<16>::new();
    control
        .push_pending(LifecycleEvent::new(
            instance(1, 1, 50),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("spawn");
    control
        .push_pending(LifecycleEvent::new(
            instance(1, 1, 50),
            LifecycleEventKind::Ready,
        ))
        .expect("ready");
    control
        .push_pending(LifecycleEvent::new(
            instance(1, 2, 60),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("spawn2");
    control
        .push_pending(LifecycleEvent::new(
            instance(1, 2, 60),
            LifecycleEventKind::Ready,
        ))
        .expect("ready2");

    let capture = LineCapture::default();
    let mut sup = ConvergedSupervisor::<_, _, 4>::new(
        ProcessId(9),
        control,
        capture.clone(),
        LivenessConfig::new(100),
    );
    sup.set_virtual_ticks(0);
    sup.register_service(service, on_failure_config())
        .expect("register");
    sup.request_start(service).expect("start");
    sup.handle_lifecycle_event(LifecycleEvent::new(
        instance(1, 1, 50),
        LifecycleEventKind::Faulted,
    ))
    .expect("fault");

    let output = lines(&capture);
    assert!(output
        .iter()
        .any(|line| line.contains("[SUP ] failure service=1 pid=50")));
    assert!(output
        .iter()
        .any(|line| line.contains("[SUP ] restart service=1 attempt=1")));
    assert!(output
        .iter()
        .any(|line| line.contains("[SUP ] restarted service=1 old-pid=50 new-pid=60")));
    assert_eq!(
        sup.registry().query(service).expect("query").state,
        ServiceLifecycleState::Running
    );
    assert_eq!(sup.registry().query(service).expect("query").generation, 2);
}

#[test]
fn never_policy_suppresses_restart() {
    let service = ServiceId(2);
    let mut control = FakeLifecycleControl::<8>::new();
    control
        .push_pending(LifecycleEvent::new(
            instance(2, 1, 70),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("spawn");
    control
        .push_pending(LifecycleEvent::new(
            instance(2, 1, 70),
            LifecycleEventKind::Ready,
        ))
        .expect("ready");

    let capture = LineCapture::default();
    let mut sup = ConvergedSupervisor::<_, _, 4>::new(
        ProcessId(1),
        control,
        capture.clone(),
        LivenessConfig::new(50),
    );
    let config = ServiceConvergenceConfig::new(RestartPolicy::Never, LivenessConfig::new(50));
    sup.register_service(service, config).expect("register");
    sup.request_start(service).expect("start");
    sup.handle_lifecycle_event(LifecycleEvent::new(
        instance(2, 1, 70),
        LifecycleEventKind::Faulted,
    ))
    .expect("fault");

    let output = lines(&capture);
    assert!(output
        .iter()
        .any(|line| line.contains("[SUP ] restart suppressed service=2 reason=never")));
}

#[test]
fn stale_exit_after_restart_is_ignored() {
    let service = ServiceId(4);
    let mut control = FakeLifecycleControl::<16>::new();
    control
        .push_pending(LifecycleEvent::new(
            instance(4, 1, 10),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("spawn");
    control
        .push_pending(LifecycleEvent::new(
            instance(4, 1, 10),
            LifecycleEventKind::Ready,
        ))
        .expect("ready");
    control
        .push_pending(LifecycleEvent::new(
            instance(4, 2, 11),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("spawn2");
    control
        .push_pending(LifecycleEvent::new(
            instance(4, 2, 11),
            LifecycleEventKind::Ready,
        ))
        .expect("ready2");

    let capture = LineCapture::default();
    let mut sup = ConvergedSupervisor::<_, _, 4>::new(
        ProcessId(1),
        control,
        capture.clone(),
        LivenessConfig::new(50),
    );
    sup.set_virtual_ticks(0);
    sup.register_service(service, on_failure_config())
        .expect("register");
    sup.request_start(service).expect("start");
    sup.handle_lifecycle_event(LifecycleEvent::new(
        instance(4, 1, 10),
        LifecycleEventKind::Faulted,
    ))
    .expect("fault");
    sup.handle_lifecycle_event(LifecycleEvent::new(
        instance(4, 1, 10),
        LifecycleEventKind::Exited,
    ))
    .expect("stale exit");

    assert_eq!(sup.registry().query(service).expect("query").generation, 2);
}

#[test]
fn dependency_blocks_start_until_upstream_running() {
    let upstream = ServiceId(10);
    let downstream = ServiceId(11);
    let mut control = FakeLifecycleControl::<16>::new();
    control
        .push_pending(LifecycleEvent::new(
            instance(10, 1, 300),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("up spawn");
    control
        .push_pending(LifecycleEvent::new(
            instance(10, 1, 300),
            LifecycleEventKind::Ready,
        ))
        .expect("up ready");
    control
        .push_pending(LifecycleEvent::new(
            instance(11, 1, 200),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("down spawn");
    control
        .push_pending(LifecycleEvent::new(
            instance(11, 1, 200),
            LifecycleEventKind::Ready,
        ))
        .expect("down ready");

    let capture = LineCapture::default();
    let mut sup = ConvergedSupervisor::<_, _, 8>::new(
        ProcessId(1),
        control,
        capture.clone(),
        LivenessConfig::new(50),
    );
    sup.register_service(upstream, on_failure_config())
        .expect("up");
    sup.register_service(downstream, on_failure_config())
        .expect("down");
    sup.set_dependencies(single_dependency(
        downstream,
        upstream,
        ServiceLifecycleState::Running,
    ))
    .expect("deps");

    assert!(matches!(
        sup.request_start(downstream),
        Err(ConvergedSupervisorError::StartBlocked(_))
    ));
    let blocked = lines(&capture);
    assert!(blocked
        .iter()
        .any(|line| line.contains("[DEP ] service=11 blocked-by=10")));

    sup.request_start(upstream).expect("start up");
    sup.request_start(downstream).expect("start down");
}

#[test]
fn explicit_healthy_report_resets_retry_state() {
    let service = ServiceId(6);
    let mut control = FakeLifecycleControl::<16>::new();
    control
        .push_pending(LifecycleEvent::new(
            instance(6, 1, 80),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("spawn");
    control
        .push_pending(LifecycleEvent::new(
            instance(6, 1, 80),
            LifecycleEventKind::Ready,
        ))
        .expect("ready");
    control
        .push_pending(LifecycleEvent::new(
            instance(6, 2, 81),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("spawn2");
    control
        .push_pending(LifecycleEvent::new(
            instance(6, 2, 81),
            LifecycleEventKind::Ready,
        ))
        .expect("ready2");
    control
        .push_pending(LifecycleEvent::new(
            instance(6, 3, 82),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("spawn3");
    control
        .push_pending(LifecycleEvent::new(
            instance(6, 3, 82),
            LifecycleEventKind::Ready,
        ))
        .expect("ready3");
    control
        .push_pending(LifecycleEvent::new(
            instance(6, 4, 83),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("spawn4");
    control
        .push_pending(LifecycleEvent::new(
            instance(6, 4, 83),
            LifecycleEventKind::Ready,
        ))
        .expect("ready4");

    let capture = LineCapture::default();
    let mut sup = ConvergedSupervisor::<_, _, 4>::new(
        ProcessId(1),
        control,
        capture.clone(),
        LivenessConfig::new(50),
    );
    sup.set_virtual_ticks(0);
    sup.register_service(service, on_failure_no_backoff_config())
        .expect("register");
    sup.request_start(service).expect("start");
    sup.handle_lifecycle_event(LifecycleEvent::new(
        instance(6, 1, 80),
        LifecycleEventKind::Faulted,
    ))
    .expect("fault1");
    sup.handle_lifecycle_event(LifecycleEvent::new(
        instance(6, 2, 81),
        LifecycleEventKind::Faulted,
    ))
    .expect("fault2 without reset");
    sup.apply_health_report(HealthReport::new(
        service,
        InstanceGeneration(3),
        HealthStatus::Ok,
    ))
    .expect("first healthy report");
    sup.apply_health_report(HealthReport::new(
        service,
        InstanceGeneration(3),
        HealthStatus::Ok,
    ))
    .expect("second healthy report resets crash history");
    sup.handle_lifecycle_event(LifecycleEvent::new(
        instance(6, 3, 82),
        LifecycleEventKind::Faulted,
    ))
    .expect("fault3 after healthy report reset");

    let output = lines(&capture);
    assert_eq!(
        output
            .iter()
            .filter(|line| line.contains("[SUP ] restart service=6 attempt=1"))
            .count(),
        2
    );
}

#[test]
fn ready_then_immediate_fault_loop_exhausts_retry_budget() {
    let service = ServiceId(7);
    let mut control = FakeLifecycleControl::<32>::new();
    control
        .push_pending(LifecycleEvent::new(
            instance(7, 1, 101),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("spawn1");
    control
        .push_pending(LifecycleEvent::new(
            instance(7, 1, 101),
            LifecycleEventKind::Ready,
        ))
        .expect("ready1");
    control
        .push_pending(LifecycleEvent::new(
            instance(7, 2, 102),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("spawn2");
    control
        .push_pending(LifecycleEvent::new(
            instance(7, 2, 102),
            LifecycleEventKind::Ready,
        ))
        .expect("ready2");
    control
        .push_pending(LifecycleEvent::new(
            instance(7, 3, 103),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("spawn3");
    control
        .push_pending(LifecycleEvent::new(
            instance(7, 3, 103),
            LifecycleEventKind::Ready,
        ))
        .expect("ready3");
    control
        .push_pending(LifecycleEvent::new(
            instance(7, 4, 104),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("spawn4");
    control
        .push_pending(LifecycleEvent::new(
            instance(7, 4, 104),
            LifecycleEventKind::Ready,
        ))
        .expect("ready4");

    let capture = LineCapture::default();
    let mut sup = ConvergedSupervisor::<_, _, 4>::new(
        ProcessId(1),
        control,
        capture.clone(),
        LivenessConfig::new(50),
    );
    sup.set_virtual_ticks(0);
    sup.register_service(service, on_failure_no_backoff_config())
        .expect("register");
    sup.request_start(service).expect("start");
    sup.handle_lifecycle_event(LifecycleEvent::new(
        instance(7, 1, 101),
        LifecycleEventKind::Faulted,
    ))
    .expect("fault1");
    sup.handle_lifecycle_event(LifecycleEvent::new(
        instance(7, 2, 102),
        LifecycleEventKind::Faulted,
    ))
    .expect("fault2");
    sup.handle_lifecycle_event(LifecycleEvent::new(
        instance(7, 3, 103),
        LifecycleEventKind::Faulted,
    ))
    .expect("fault3");
    sup.handle_lifecycle_event(LifecycleEvent::new(
        instance(7, 4, 104),
        LifecycleEventKind::Faulted,
    ))
    .expect("fault4");

    let output = lines(&capture);
    assert!(output
        .iter()
        .any(|line| line.contains("[SUP ] restart service=7 attempt=1")));
    assert!(output
        .iter()
        .any(|line| line.contains("[SUP ] restart service=7 attempt=2")));
    assert!(output
        .iter()
        .any(|line| line.contains("[SUP ] restart service=7 attempt=3")));
    assert!(output
        .iter()
        .any(|line| line.contains("[SUP ] restart suppressed service=7 reason=exhausted")));
}

#[test]
fn immediate_single_health_report_then_fault_still_exhausts() {
    let service = ServiceId(8);
    let mut control = FakeLifecycleControl::<32>::new();
    control
        .push_pending(LifecycleEvent::new(
            instance(8, 1, 201),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("spawn1");
    control
        .push_pending(LifecycleEvent::new(
            instance(8, 1, 201),
            LifecycleEventKind::Ready,
        ))
        .expect("ready1");
    control
        .push_pending(LifecycleEvent::new(
            instance(8, 2, 202),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("spawn2");
    control
        .push_pending(LifecycleEvent::new(
            instance(8, 2, 202),
            LifecycleEventKind::Ready,
        ))
        .expect("ready2");
    control
        .push_pending(LifecycleEvent::new(
            instance(8, 3, 203),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("spawn3");
    control
        .push_pending(LifecycleEvent::new(
            instance(8, 3, 203),
            LifecycleEventKind::Ready,
        ))
        .expect("ready3");
    control
        .push_pending(LifecycleEvent::new(
            instance(8, 4, 204),
            LifecycleEventKind::InstanceSpawned,
        ))
        .expect("spawn4");
    control
        .push_pending(LifecycleEvent::new(
            instance(8, 4, 204),
            LifecycleEventKind::Ready,
        ))
        .expect("ready4");

    let capture = LineCapture::default();
    let mut sup = ConvergedSupervisor::<_, _, 4>::new(
        ProcessId(1),
        control,
        capture.clone(),
        LivenessConfig::new(50),
    );
    sup.set_virtual_ticks(0);
    sup.register_service(service, on_failure_no_backoff_config())
        .expect("register");
    sup.request_start(service).expect("start");
    sup.apply_health_report(HealthReport::new(
        service,
        InstanceGeneration(1),
        HealthStatus::Ok,
    ))
    .expect("single report g1");
    sup.handle_lifecycle_event(LifecycleEvent::new(
        instance(8, 1, 201),
        LifecycleEventKind::Faulted,
    ))
    .expect("fault1");
    sup.apply_health_report(HealthReport::new(
        service,
        InstanceGeneration(2),
        HealthStatus::Ok,
    ))
    .expect("single report g2");
    sup.handle_lifecycle_event(LifecycleEvent::new(
        instance(8, 2, 202),
        LifecycleEventKind::Faulted,
    ))
    .expect("fault2");
    sup.apply_health_report(HealthReport::new(
        service,
        InstanceGeneration(3),
        HealthStatus::Ok,
    ))
    .expect("single report g3");
    sup.handle_lifecycle_event(LifecycleEvent::new(
        instance(8, 3, 203),
        LifecycleEventKind::Faulted,
    ))
    .expect("fault3");
    sup.apply_health_report(HealthReport::new(
        service,
        InstanceGeneration(4),
        HealthStatus::Ok,
    ))
    .expect("single report g4");
    sup.handle_lifecycle_event(LifecycleEvent::new(
        instance(8, 4, 204),
        LifecycleEventKind::Faulted,
    ))
    .expect("fault4");

    let output = lines(&capture);
    assert!(output
        .iter()
        .any(|line| line.contains("[SUP ] restart service=8 attempt=1")));
    assert!(output
        .iter()
        .any(|line| line.contains("[SUP ] restart service=8 attempt=2")));
    assert!(output
        .iter()
        .any(|line| line.contains("[SUP ] restart service=8 attempt=3")));
    assert!(output
        .iter()
        .any(|line| line.contains("[SUP ] restart suppressed service=8 reason=exhausted")));
}
