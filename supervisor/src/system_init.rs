//! #218 S3b userspace init: starts the system manifest's services in row order, each only after
//! every service it depends on has reported ready, and applies each row's restart policy.
//!
//! Host-testable. `bin/init.rs` drives it with `LIFECYCLE_WAIT` (21) and `WORK_SET` op `NOW`:
//! it blocks until a lifecycle message is pending or [`SystemInit::next_deadline`] passes, then
//! calls [`SystemInit::on_wake`]. Once every service is running or given up and no retry is
//! due, the deadline is `None`, so init blocks until the kernel has a message for it.
//!
//! Ticks are monotonic nanoseconds throughout.

use core::fmt::{self, Write};

use clean_slate_service_fixtures::manifest::{RestartSpec, ServiceSpec};
use clean_slate_service_lifecycle::{
    ticks_add, ticks_reached, DependencyEdge, DependencyMetadata, LivenessConfig, MonotonicTicks,
    ProcessId, ServiceId, ServiceLifecycleState,
};

use crate::control::LifecycleControl;
use crate::convergence::{
    ConvergedSupervisor, ConvergedSupervisorError, LineBuffer, ServiceConvergenceConfig,
};
use crate::restart_policy::{BoundedRestart, RestartPolicy};
use crate::runtime::DiagnosticSink;

/// How long a started instance may stay starting before init stops it and applies its restart
/// policy (provisional, #218 S3b open question).
pub const INIT_READY_TIMEOUT_NS: u64 = 10_000_000_000;

/// No service reports health yet, so liveness is off: with a finite period every instance would
/// be declared unhealthy, and restarted, once the period passed without a report. `ticks_add`
/// saturates, so this deadline is never reached.
const LIVENESS_OFF: LivenessConfig = LivenessConfig::new(u64::MAX);

/// Messages handled per wake at most, so one wake cannot turn into a loop.
const MAX_EVENTS_PER_WAKE: usize = 16;

/// The supervisor policy for a manifest row's restart spec.
pub const fn restart_policy(spec: RestartSpec) -> RestartPolicy {
    match spec {
        RestartSpec::Never => RestartPolicy::Never,
        RestartSpec::OnFailure {
            max_attempts,
            backoff_base_ticks,
            initial_delay_ticks,
        } => RestartPolicy::OnFailure(
            BoundedRestart::new(max_attempts, backoff_base_ticks)
                .with_initial_delay(initial_delay_ticks),
        ),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Progress {
    NotStarted,
    Started,
    /// No retry left (or none allowed); init leaves the service down.
    GaveUp,
    /// A dependency gave up, so init never starts this service.
    Blocked,
}

#[derive(Clone, Copy, Debug)]
struct ServiceSlot {
    spec: &'static ServiceSpec,
    progress: Progress,
    /// Generation whose ready deadline is armed, and that deadline.
    ready_deadline: Option<(u32, MonotonicTicks)>,
    announced_ready_generation: u32,
}

pub struct SystemInit<C, D, const N: usize> {
    supervisor: ConvergedSupervisor<C, D, N>,
    slots: [Option<ServiceSlot>; N],
    ready_timeout_ns: u64,
    settled_announced: bool,
}

impl<C, D, const N: usize> SystemInit<C, D, N>
where
    C: LifecycleControl,
    D: DiagnosticSink,
{
    /// Registers every row of `manifest` with its restart policy and dependencies. Starts
    /// nothing until [`Self::boot`].
    pub fn new(
        self_pid: u64,
        control: C,
        diagnostics: D,
        manifest: &'static [ServiceSpec],
        ready_timeout_ns: u64,
    ) -> Result<Self, ConvergedSupervisorError> {
        if manifest.len() > N {
            return Err(ConvergedSupervisorError::UnknownService);
        }
        let mut supervisor =
            ConvergedSupervisor::new(ProcessId(self_pid), control, diagnostics, LIVENESS_OFF);
        supervisor.start()?;
        let mut init = Self {
            supervisor,
            slots: [None; N],
            ready_timeout_ns,
            settled_announced: false,
        };
        init.emit(format_args!(
            "[INIT] started pid={self_pid} services={}",
            manifest.len()
        ))?;
        for (index, spec) in manifest.iter().enumerate() {
            init.supervisor.register_service(
                spec.id,
                ServiceConvergenceConfig::new(restart_policy(spec.restart), LIVENESS_OFF),
            )?;
            let mut metadata = DependencyMetadata::empty(spec.id);
            for dependency in spec.depends_on {
                let pushed = metadata.push_edge(DependencyEdge {
                    depends_on: *dependency,
                    required_state: ServiceLifecycleState::Running,
                });
                if !pushed {
                    return Err(ConvergedSupervisorError::UnknownService);
                }
            }
            init.supervisor.set_dependencies(metadata)?;
            init.slots[index] = Some(ServiceSlot {
                spec,
                progress: Progress::NotStarted,
                ready_deadline: None,
                announced_ready_generation: 0,
            });
        }
        Ok(init)
    }

    pub fn supervisor(&self) -> &ConvergedSupervisor<C, D, N> {
        &self.supervisor
    }

    /// Starts every row whose dependencies are already met (at boot: those with none).
    pub fn boot(&mut self, now: MonotonicTicks) {
        self.on_wake(now, None);
    }

    /// One wake: `pending` is the service `LIFECYCLE_WAIT` reported, or `None` after a timeout.
    /// Handles that service's messages, runs retries that are due, enforces ready deadlines and
    /// starts rows whose dependencies became ready.
    pub fn on_wake(&mut self, now: MonotonicTicks, pending: Option<ServiceId>) {
        if self.supervisor.advance_ticks(now).is_err() {
            self.give_up_on_due_retries(now);
        }
        if let Some(service) = pending {
            self.handle_messages(service, now);
        }
        self.reconcile(now);
        self.start_eligible(now);
        self.announce_settled();
    }

    /// When init must wake without a message: the earliest ready deadline or due retry. `None`
    /// once every service is running or given up.
    pub fn next_deadline(&self) -> Option<MonotonicTicks> {
        let mut earliest: Option<MonotonicTicks> = None;
        let mut consider = |deadline: MonotonicTicks| {
            earliest = Some(earliest.map_or(deadline, |current| current.min(deadline)));
        };
        for slot in self.slots.iter().flatten() {
            if slot.progress != Progress::Started {
                continue;
            }
            if let Some((_, deadline)) = slot.ready_deadline {
                consider(deadline);
            }
            let Some(runtime) = self.supervisor.recovery_runtime(slot.spec.id) else {
                continue;
            };
            // A retry still waiting on a dependency runs when that dependency's next message
            // wakes init, not on a timer that has already expired.
            if runtime.pending() && self.dependencies_running(slot.spec) {
                consider(runtime.not_before());
            }
        }
        earliest
    }

    fn handle_messages(&mut self, service: ServiceId, now: MonotonicTicks) {
        let known = self.slot_index(service).is_some();
        for _ in 0..MAX_EVENTS_PER_WAKE {
            let event = match self.supervisor.poll_lifecycle_event(service) {
                Ok(Some(event)) => event,
                Ok(None) => return,
                Err(_) => {
                    self.give_up(service, "poll failed");
                    return;
                }
            };
            // A message for a service init does not run is consumed so it cannot wake init
            // again; there is nothing to apply it to.
            if known && self.supervisor.handle_lifecycle_event(event).is_err() {
                self.give_up(service, "bad lifecycle message");
                self.give_up_on_due_retries(now);
                return;
            }
        }
    }

    fn reconcile(&mut self, now: MonotonicTicks) {
        for index in 0..N {
            let Some(slot) = self.slots[index] else {
                continue;
            };
            if slot.progress != Progress::Started {
                continue;
            }
            let service = slot.spec.id;
            let Some(snapshot) = self.supervisor.registry().query(service) else {
                continue;
            };
            match snapshot.state {
                ServiceLifecycleState::Starting => {
                    let armed = slot
                        .ready_deadline
                        .filter(|(generation, _)| *generation == snapshot.generation);
                    let Some((_, deadline)) = armed else {
                        self.set_ready_deadline(
                            index,
                            Some((snapshot.generation, ticks_add(now, self.ready_timeout_ns))),
                        );
                        continue;
                    };
                    if ticks_reached(now, deadline) {
                        self.set_ready_deadline(index, None);
                        let timeout_ms = self.ready_timeout_ns / 1_000_000;
                        let _ = self.emit(format_args!(
                            "[INIT] service={} not ready in {timeout_ms} ms; stopping it",
                            service.0
                        ));
                        if self.supervisor.terminate(service).is_err() {
                            self.give_up(service, "terminate failed");
                        }
                    }
                }
                ServiceLifecycleState::Running => {
                    self.set_ready_deadline(index, None);
                    if snapshot.generation != slot.announced_ready_generation {
                        if let Some(slot) = self.slots[index].as_mut() {
                            slot.announced_ready_generation = snapshot.generation;
                        }
                        let _ = self.emit(format_args!(
                            "[INIT] service={} ready gen={}",
                            service.0, snapshot.generation
                        ));
                    }
                }
                ServiceLifecycleState::Faulted | ServiceLifecycleState::Exited => {
                    self.set_ready_deadline(index, None);
                    self.give_up_if_exhausted(index);
                }
                _ => {}
            }
        }
        // Re-check after a terminate above turned an instance into a failure.
        for index in 0..N {
            if self.slots[index].is_some_and(|slot| slot.progress == Progress::Started) {
                let failed = self.slots[index]
                    .and_then(|slot| self.supervisor.registry().query(slot.spec.id))
                    .is_some_and(|snapshot| {
                        matches!(
                            snapshot.state,
                            ServiceLifecycleState::Faulted | ServiceLifecycleState::Exited
                        )
                    });
                if failed {
                    self.give_up_if_exhausted(index);
                }
            }
        }
    }

    fn give_up_if_exhausted(&mut self, index: usize) {
        let Some(slot) = self.slots[index] else {
            return;
        };
        let Some(runtime) = self.supervisor.recovery_runtime(slot.spec.id) else {
            return;
        };
        if runtime.pending() {
            if let Some(dependency) = slot
                .spec
                .depends_on
                .iter()
                .copied()
                .find(|dependency| self.has_given_up(*dependency))
            {
                let _ = self.emit(format_args!(
                    "[INIT] gave up service={}: service={} is down",
                    slot.spec.id.0, dependency.0
                ));
                if let Some(slot) = self.slots[index].as_mut() {
                    slot.progress = Progress::GaveUp;
                }
            }
            return;
        }
        let exhausted = match runtime.policy() {
            RestartPolicy::Never => true,
            RestartPolicy::OnFailure(limits) => runtime.attempts() >= limits.max_attempts,
        };
        if !exhausted {
            return;
        }
        if let Some(slot) = self.slots[index].as_mut() {
            slot.progress = Progress::GaveUp;
        }
        let _ = self.emit(format_args!(
            "[INIT] gave up service={} restarts={}; init carries on",
            slot.spec.id.0,
            runtime.attempts()
        ));
    }

    fn start_eligible(&mut self, now: MonotonicTicks) {
        for index in 0..N {
            let Some(slot) = self.slots[index] else {
                continue;
            };
            if slot.progress != Progress::NotStarted {
                continue;
            }
            if let Some(dependency) = slot
                .spec
                .depends_on
                .iter()
                .copied()
                .find(|dependency| self.has_given_up(*dependency))
            {
                if let Some(slot) = self.slots[index].as_mut() {
                    slot.progress = Progress::Blocked;
                }
                let _ = self.emit(format_args!(
                    "[INIT] not starting service={}: service={} is down",
                    slot.spec.id.0, dependency.0
                ));
                continue;
            }
            if !self.dependencies_running(slot.spec) {
                continue;
            }
            let _ = self.emit_start_line(slot.spec);
            match self.supervisor.request_start(slot.spec.id) {
                Ok(()) => {
                    if let Some(slot) = self.slots[index].as_mut() {
                        slot.progress = Progress::Started;
                    }
                    let generation = self
                        .supervisor
                        .registry()
                        .query(slot.spec.id)
                        .map_or(0, |snapshot| snapshot.generation);
                    self.set_ready_deadline(
                        index,
                        Some((generation, ticks_add(now, self.ready_timeout_ns))),
                    );
                }
                Err(_) => self.give_up(slot.spec.id, "start request failed"),
            }
        }
    }

    fn announce_settled(&mut self) {
        let mut running = 0;
        let mut down = 0;
        for slot in self.slots.iter().flatten() {
            match slot.progress {
                Progress::GaveUp | Progress::Blocked => down += 1,
                Progress::Started
                    if self
                        .supervisor
                        .registry()
                        .query(slot.spec.id)
                        .is_some_and(|snapshot| {
                            snapshot.state == ServiceLifecycleState::Running
                        }) =>
                {
                    running += 1
                }
                _ => {}
            }
        }
        let total = self.slots.iter().flatten().count();
        let settled = running + down == total && self.next_deadline().is_none();
        if settled && !self.settled_announced {
            let _ = self.emit(format_args!(
                "[INIT] boot settled running={running} down={down}; waiting, no deadline"
            ));
        }
        self.settled_announced = settled;
    }

    fn emit_start_line(&mut self, spec: &ServiceSpec) -> Result<(), ConvergedSupervisorError> {
        let mut line = LineBuffer::new();
        let mut result = write!(line, "[INIT] ");
        for (index, dependency) in spec.depends_on.iter().enumerate() {
            let separator = if index == 0 { "" } else { ", " };
            result = result.and(write!(line, "{separator}service={} ready", dependency.0));
        }
        let separator = if spec.depends_on.is_empty() { "" } else { "; " };
        result = result.and(writeln!(line, "{separator}starting service={}", spec.id.0));
        result.map_err(|_| ConvergedSupervisorError::UnknownService)?;
        self.supervisor.emit_diagnostic(line.as_str())
    }

    fn give_up(&mut self, service: ServiceId, reason: &str) {
        let Some(index) = self.slot_index(service) else {
            return;
        };
        if let Some(slot) = self.slots[index].as_mut() {
            slot.progress = Progress::GaveUp;
            slot.ready_deadline = None;
        }
        let _ = self.emit(format_args!(
            "[INIT] gave up service={}: {reason}",
            service.0
        ));
    }

    /// A supervisor call that drives due retries failed; each service with a retry due is the
    /// one that may have failed, and is left down rather than retried in a loop.
    fn give_up_on_due_retries(&mut self, now: MonotonicTicks) {
        for index in 0..N {
            let Some(slot) = self.slots[index] else {
                continue;
            };
            let due = self
                .supervisor
                .recovery_runtime(slot.spec.id)
                .is_some_and(|runtime| {
                    runtime.pending() && ticks_reached(now, runtime.not_before())
                });
            if slot.progress == Progress::Started && due {
                self.give_up(slot.spec.id, "restart failed");
            }
        }
    }

    fn set_ready_deadline(&mut self, index: usize, deadline: Option<(u32, MonotonicTicks)>) {
        if let Some(slot) = self.slots[index].as_mut() {
            slot.ready_deadline = deadline;
        }
    }

    fn dependencies_running(&self, spec: &ServiceSpec) -> bool {
        spec.depends_on.iter().all(|dependency| {
            self.supervisor
                .registry()
                .query(*dependency)
                .is_some_and(|snapshot| snapshot.state == ServiceLifecycleState::Running)
        })
    }

    fn has_given_up(&self, service: ServiceId) -> bool {
        self.slot_index(service)
            .and_then(|index| self.slots[index])
            .is_some_and(|slot| matches!(slot.progress, Progress::GaveUp | Progress::Blocked))
    }

    fn slot_index(&self, service: ServiceId) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.is_some_and(|slot| slot.spec.id == service))
    }

    fn emit(&mut self, args: fmt::Arguments<'_>) -> Result<(), ConvergedSupervisorError> {
        let mut line = LineBuffer::new();
        writeln!(line, "{args}").map_err(|_| ConvergedSupervisorError::UnknownService)?;
        self.supervisor.emit_diagnostic(line.as_str())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::cell::RefCell;
    use std::rc::Rc;
    use std::string::{String, ToString};
    use std::vec::Vec;

    use clean_slate_service_fixtures::manifest::SYSTEM_MANIFEST;
    use clean_slate_service_fixtures::{NETWORK_SERVICE_ID, STORAGE_SERVICE_ID};
    use clean_slate_service_lifecycle::{
        ControlRequest, ControlRequestKind, DomainId, InstanceGeneration, LifecycleEvent,
        LifecycleEventKind, ServiceInstanceId,
    };

    use super::*;
    use crate::control::{FakeLifecycleControl, LifecycleControlError};
    use crate::runtime::SupervisorError;

    const SECOND: u64 = 1_000_000_000;
    const INIT_PID: u64 = 3;

    /// Answers control requests the way the kernel does: Start spawns a new instance,
    /// Terminate reports it exited. Requests are recorded by the wrapped fake.
    #[derive(Default)]
    struct KernelModel {
        fake: FakeLifecycleControl<64>,
        next_pid: u64,
        live: Vec<(ServiceId, ServiceInstanceId)>,
        generations: Vec<(ServiceId, u32)>,
        polls: usize,
    }

    impl KernelModel {
        fn instance(&self, service: ServiceId) -> ServiceInstanceId {
            self.live
                .iter()
                .find(|(id, _)| *id == service)
                .map(|(_, instance)| *instance)
                .expect("service has a live instance")
        }

        fn report(&mut self, service: ServiceId, kind: LifecycleEventKind) {
            let event = LifecycleEvent::new(self.instance(service), kind);
            self.fake.push_pending(event).expect("queue event");
        }
    }

    #[derive(Clone, Default)]
    struct SharedKernel(Rc<RefCell<KernelModel>>);

    impl LifecycleControl for SharedKernel {
        fn issue_control(&mut self, request: ControlRequest) -> Result<(), LifecycleControlError> {
            let mut model = self.0.borrow_mut();
            model.fake.issue_control(request)?;
            match request.kind {
                ControlRequestKind::Start => {
                    let generation = match model
                        .generations
                        .iter_mut()
                        .find(|(id, _)| *id == request.service)
                    {
                        Some((_, generation)) => {
                            *generation += 1;
                            *generation
                        }
                        None => {
                            model.generations.push((request.service, 1));
                            1
                        }
                    };
                    model.next_pid += 1;
                    let instance = ServiceInstanceId::new(
                        request.service,
                        InstanceGeneration(generation),
                        ProcessId(100 + model.next_pid),
                        DomainId(100 + model.next_pid),
                    );
                    model.live.retain(|(id, _)| *id != request.service);
                    model.live.push((request.service, instance));
                    model
                        .fake
                        .push_pending(LifecycleEvent::new(
                            instance,
                            LifecycleEventKind::InstanceSpawned,
                        ))
                        .expect("queue spawn");
                }
                ControlRequestKind::Terminate => {
                    model.report(request.service, LifecycleEventKind::Exited);
                }
                _ => {}
            }
            Ok(())
        }

        fn poll_event(
            &mut self,
            service: ServiceId,
        ) -> Result<Option<LifecycleEvent>, LifecycleControlError> {
            let mut model = self.0.borrow_mut();
            model.polls += 1;
            model.fake.poll_event(service)
        }
    }

    #[derive(Clone, Default)]
    struct SharedLog(Rc<RefCell<Vec<String>>>);

    impl DiagnosticSink for SharedLog {
        fn emit_line(&mut self, line: &str) -> Result<(), SupervisorError> {
            self.0.borrow_mut().push(line.trim_end().to_string());
            Ok(())
        }
    }

    struct Harness {
        init: SystemInit<SharedKernel, SharedLog, 4>,
        kernel: SharedKernel,
        log: SharedLog,
    }

    impl Harness {
        fn boot() -> Self {
            let kernel = SharedKernel::default();
            let log = SharedLog::default();
            let mut init = SystemInit::new(
                INIT_PID,
                kernel.clone(),
                log.clone(),
                SYSTEM_MANIFEST,
                INIT_READY_TIMEOUT_NS,
            )
            .expect("init registers the manifest");
            init.boot(0);
            Self { init, kernel, log }
        }

        fn report(&mut self, now: u64, service: ServiceId, kind: LifecycleEventKind) {
            self.kernel.0.borrow_mut().report(service, kind);
            self.init.on_wake(now, Some(service));
        }

        fn requests(&self) -> Vec<(ServiceId, ControlRequestKind)> {
            self.kernel
                .0
                .borrow()
                .fake
                .issued_requests()
                .map(|request| (request.service, request.kind))
                .collect()
        }

        fn starts_of(&self, service: ServiceId) -> usize {
            self.requests()
                .iter()
                .filter(|request| **request == (service, ControlRequestKind::Start))
                .count()
        }

        fn lines_with(&self, needle: &str) -> Vec<String> {
            self.log
                .0
                .borrow()
                .iter()
                .filter(|line| line.contains(needle))
                .cloned()
                .collect()
        }

        fn position_of(&self, needle: &str) -> usize {
            self.log
                .0
                .borrow()
                .iter()
                .position(|line| line.contains(needle))
                .unwrap_or_else(|| panic!("no line contains {needle:?}: {:#?}", self.log.0))
        }

        fn state(&self, service: ServiceId) -> ServiceLifecycleState {
            self.init
                .supervisor()
                .registry()
                .query(service)
                .expect("registered")
                .state
        }

        /// Fails the current storage instance at `now` and wakes init at each due deadline
        /// until the next storage instance is launched.
        fn fail_storage_and_run_retry(&mut self, now: u64) -> u64 {
            let starts = self.starts_of(STORAGE_SERVICE_ID);
            self.report(now, STORAGE_SERVICE_ID, LifecycleEventKind::Faulted);
            let deadline = self.init.next_deadline().expect("a retry is scheduled");
            self.init.on_wake(deadline - 1, None);
            assert_eq!(
                self.starts_of(STORAGE_SERVICE_ID),
                starts,
                "retry ran early"
            );
            self.init.on_wake(deadline, None);
            assert_eq!(self.starts_of(STORAGE_SERVICE_ID), starts + 1);
            deadline
        }
    }

    #[test]
    fn boot_starts_storage_only_and_announces_itself() {
        let harness = Harness::boot();
        assert_eq!(
            harness.requests(),
            [(STORAGE_SERVICE_ID, ControlRequestKind::Start)]
        );
        assert_eq!(
            harness.lines_with("[INIT] started pid=3 services=2").len(),
            1
        );
        assert_eq!(harness.lines_with("[INIT] starting service=20736").len(), 1);
        assert_eq!(
            harness.state(STORAGE_SERVICE_ID),
            ServiceLifecycleState::Starting
        );
        assert_eq!(
            harness.state(NETWORK_SERVICE_ID),
            ServiceLifecycleState::Declared
        );
    }

    #[test]
    fn network_starts_only_after_storage_reports_ready() {
        let mut harness = Harness::boot();
        harness.init.on_wake(SECOND, None);
        assert_eq!(harness.starts_of(NETWORK_SERVICE_ID), 0);

        harness.report(2 * SECOND, STORAGE_SERVICE_ID, LifecycleEventKind::Ready);
        assert_eq!(
            harness.requests(),
            [
                (STORAGE_SERVICE_ID, ControlRequestKind::Start),
                (NETWORK_SERVICE_ID, ControlRequestKind::Start),
            ]
        );
        let storage_ready = harness.position_of("[INIT] service=20736 ready gen=1");
        let network_start =
            harness.position_of("[INIT] service=20736 ready; starting service=20992");
        assert!(storage_ready < network_start);
    }

    #[test]
    fn once_both_services_are_ready_init_waits_with_no_deadline_and_does_no_work() {
        let mut harness = Harness::boot();
        harness.report(SECOND, STORAGE_SERVICE_ID, LifecycleEventKind::Ready);
        assert!(
            harness.init.next_deadline().is_some(),
            "network ready deadline"
        );
        harness.report(2 * SECOND, NETWORK_SERVICE_ID, LifecycleEventKind::Ready);

        assert_eq!(harness.init.next_deadline(), None);
        assert_eq!(
            harness.lines_with("[INIT] boot settled running=2 down=0; waiting, no deadline"),
            ["[INIT] boot settled running=2 down=0; waiting, no deadline"]
        );

        let requests = harness.requests().len();
        let polls = harness.kernel.0.borrow().polls;
        let lines = harness.log.0.borrow().len();
        harness.init.on_wake(1_000 * SECOND, None);
        assert_eq!(harness.requests().len(), requests, "no control request");
        assert_eq!(harness.kernel.0.borrow().polls, polls, "no lifecycle poll");
        assert_eq!(
            harness.log.0.borrow().len(),
            lines,
            "settled line printed once"
        );
        assert_eq!(harness.init.next_deadline(), None);
    }

    #[test]
    fn failed_storage_is_retried_three_times_with_growing_delay_then_given_up() {
        let mut harness = Harness::boot();
        let mut now = SECOND;
        let mut retry_delays = Vec::new();
        for _ in 0..3 {
            let launched = harness.fail_storage_and_run_retry(now);
            retry_delays.push(launched - now);
            now = launched + SECOND;
        }
        assert_eq!(retry_delays, [2 * SECOND, 4 * SECOND, 6 * SECOND]);
        assert_eq!(harness.starts_of(STORAGE_SERVICE_ID), 4);

        harness.report(now, STORAGE_SERVICE_ID, LifecycleEventKind::Faulted);
        assert_eq!(harness.starts_of(STORAGE_SERVICE_ID), 4, "no fifth launch");
        assert_eq!(
            harness.lines_with("[INIT] gave up service=20736"),
            ["[INIT] gave up service=20736 restarts=3; init carries on"]
        );
        assert_eq!(
            harness.lines_with("[INIT] not starting service=20992"),
            ["[INIT] not starting service=20992: service=20736 is down"]
        );
        assert_eq!(harness.starts_of(NETWORK_SERVICE_ID), 0);
        assert_eq!(
            harness.init.next_deadline(),
            None,
            "init blocks instead of looping"
        );
        assert_eq!(
            harness.lines_with("[INIT] boot settled"),
            ["[INIT] boot settled running=0 down=2; waiting, no deadline"]
        );

        let requests = harness.requests().len();
        harness.init.on_wake(now + 3_600 * SECOND, None);
        assert_eq!(harness.requests().len(), requests);
    }

    #[test]
    fn a_retry_waits_for_its_delay_even_when_init_is_woken_early() {
        let mut harness = Harness::boot();
        harness.report(SECOND, STORAGE_SERVICE_ID, LifecycleEventKind::Faulted);
        assert_eq!(harness.init.next_deadline(), Some(3 * SECOND));
        for now in [SECOND + 1, 2 * SECOND, 3 * SECOND - 1] {
            harness.init.on_wake(now, None);
        }
        assert_eq!(harness.starts_of(STORAGE_SERVICE_ID), 1);
        harness.init.on_wake(3 * SECOND, None);
        assert_eq!(
            harness.requests()[1..],
            [
                (STORAGE_SERVICE_ID, ControlRequestKind::Restart),
                (STORAGE_SERVICE_ID, ControlRequestKind::Start),
            ]
        );
    }

    #[test]
    fn storage_that_never_reports_ready_is_stopped_at_the_deadline_and_retried() {
        let mut harness = Harness::boot();
        assert_eq!(harness.init.next_deadline(), Some(INIT_READY_TIMEOUT_NS));
        harness.init.on_wake(INIT_READY_TIMEOUT_NS - 1, None);
        assert!(!harness
            .requests()
            .contains(&(STORAGE_SERVICE_ID, ControlRequestKind::Terminate)));

        harness.init.on_wake(INIT_READY_TIMEOUT_NS, None);
        assert!(harness
            .requests()
            .contains(&(STORAGE_SERVICE_ID, ControlRequestKind::Terminate)));
        assert_eq!(
            harness.lines_with("not ready in"),
            ["[INIT] service=20736 not ready in 10000 ms; stopping it"]
        );
        assert_eq!(harness.starts_of(NETWORK_SERVICE_ID), 0);
        assert_eq!(
            harness.init.next_deadline(),
            Some(INIT_READY_TIMEOUT_NS + 2 * SECOND)
        );
        harness
            .init
            .on_wake(INIT_READY_TIMEOUT_NS + 2 * SECOND, None);
        assert_eq!(harness.starts_of(STORAGE_SERVICE_ID), 2);

        harness.report(
            INIT_READY_TIMEOUT_NS + 3 * SECOND,
            STORAGE_SERVICE_ID,
            LifecycleEventKind::Ready,
        );
        assert_eq!(
            harness.lines_with("[INIT] service=20736 ready gen=2").len(),
            1
        );
        assert_eq!(harness.starts_of(NETWORK_SERVICE_ID), 1);
    }

    #[test]
    fn a_running_service_that_faults_is_restarted_and_announced_ready_again() {
        let mut harness = Harness::boot();
        harness.report(SECOND, STORAGE_SERVICE_ID, LifecycleEventKind::Ready);
        harness.report(2 * SECOND, NETWORK_SERVICE_ID, LifecycleEventKind::Ready);

        harness.report(10 * SECOND, NETWORK_SERVICE_ID, LifecycleEventKind::Faulted);
        assert_eq!(harness.init.next_deadline(), Some(12 * SECOND));
        harness.init.on_wake(12 * SECOND, None);
        assert_eq!(harness.starts_of(NETWORK_SERVICE_ID), 2);
        harness.report(13 * SECOND, NETWORK_SERVICE_ID, LifecycleEventKind::Ready);
        assert_eq!(
            harness.lines_with("[INIT] service=20992 ready gen=2").len(),
            1
        );
        assert_eq!(harness.init.next_deadline(), None);
        assert_eq!(harness.lines_with("[INIT] boot settled").len(), 2);
        assert_eq!(
            harness.starts_of(STORAGE_SERVICE_ID),
            1,
            "storage untouched"
        );
    }

    #[test]
    fn a_network_retry_waits_while_storage_is_down_and_no_timer_spins_for_it() {
        let mut harness = Harness::boot();
        harness.report(SECOND, STORAGE_SERVICE_ID, LifecycleEventKind::Ready);
        harness.report(2 * SECOND, NETWORK_SERVICE_ID, LifecycleEventKind::Ready);
        harness.report(10 * SECOND, STORAGE_SERVICE_ID, LifecycleEventKind::Faulted);
        harness.report(10 * SECOND, NETWORK_SERVICE_ID, LifecycleEventKind::Faulted);

        harness.init.on_wake(12 * SECOND, None);
        assert_eq!(harness.starts_of(STORAGE_SERVICE_ID), 2);
        assert_eq!(
            harness.starts_of(NETWORK_SERVICE_ID),
            1,
            "storage not ready yet"
        );
        assert_eq!(
            harness.init.next_deadline(),
            Some(12 * SECOND + INIT_READY_TIMEOUT_NS),
            "only storage's ready deadline is armed"
        );

        harness.report(13 * SECOND, STORAGE_SERVICE_ID, LifecycleEventKind::Ready);
        assert_eq!(harness.starts_of(NETWORK_SERVICE_ID), 2);
    }

    #[test]
    fn a_message_for_a_service_init_does_not_run_is_consumed() {
        let mut harness = Harness::boot();
        let stray = ServiceInstanceId::new(
            ServiceId(0x9999),
            InstanceGeneration(1),
            ProcessId(77),
            DomainId(77),
        );
        harness
            .kernel
            .0
            .borrow_mut()
            .fake
            .push_pending(LifecycleEvent::new(stray, LifecycleEventKind::Faulted))
            .unwrap();
        harness.init.on_wake(SECOND, Some(ServiceId(0x9999)));
        assert_eq!(
            harness
                .kernel
                .0
                .borrow_mut()
                .fake
                .poll_event(ServiceId(0x9999)),
            Ok(None)
        );
        assert_eq!(
            harness.state(STORAGE_SERVICE_ID),
            ServiceLifecycleState::Starting
        );
    }

    /// The kernel console takes at most 64 bytes per IPC message; a longer line would be split
    /// across several console lines.
    #[test]
    fn every_init_line_fits_one_console_message() {
        let mut harness = Harness::boot();
        harness.init.on_wake(INIT_READY_TIMEOUT_NS, None);
        let mut now = INIT_READY_TIMEOUT_NS;
        for _ in 0..3 {
            now = harness.fail_storage_and_run_retry(now + SECOND) + SECOND;
        }
        harness.report(now, STORAGE_SERVICE_ID, LifecycleEventKind::Faulted);

        let mut ready = Harness::boot();
        ready.report(SECOND, STORAGE_SERVICE_ID, LifecycleEventKind::Ready);
        ready.report(2 * SECOND, NETWORK_SERVICE_ID, LifecycleEventKind::Ready);

        let lines: Vec<String> = [harness, ready]
            .iter()
            .flat_map(|harness| harness.log.0.borrow().clone())
            .filter(|line| line.starts_with("[INIT]"))
            .collect();
        for needle in [
            "not ready in",
            "gave up",
            "not starting",
            "boot settled",
            "ready;",
        ] {
            assert!(
                lines.iter().any(|line| line.contains(needle)),
                "{needle:?} not exercised"
            );
        }
        for line in lines {
            assert!(line.len() < 64, "{line:?} is {} bytes", line.len());
        }
    }

    #[test]
    fn manifest_restart_specs_map_to_bounded_restart_with_initial_delay() {
        assert_eq!(restart_policy(RestartSpec::Never), RestartPolicy::Never);
        assert_eq!(
            restart_policy(RestartSpec::OnFailure {
                max_attempts: 3,
                backoff_base_ticks: 2 * SECOND,
                initial_delay_ticks: 2 * SECOND,
            }),
            RestartPolicy::OnFailure(
                BoundedRestart::new(3, 2 * SECOND).with_initial_delay(2 * SECOND)
            )
        );
    }
}
