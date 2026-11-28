//! #218 S3b userspace init: starts the system manifest's services in row order, each only after
//! every service it depends on has reported ready, and applies each row's restart policy.
//!
//! Host-testable. `bin/init.rs` drives it with `LIFECYCLE_WAIT` (21) and `WORK_SET` op `NOW`:
//! it blocks until a lifecycle message is pending or [`SystemInit::next_deadline`] passes, then
//! calls [`SystemInit::on_wake`]. Once every service is running or given up and no retry is
//! due, the deadline is `None`, so init blocks until the kernel has a message for it.
//!
//! Ticks are monotonic nanoseconds throughout.
//!
//! #373 system stop: [`SystemInit::request_system_stop`] (a launcher client holding
//! `LAUNCH_POWER` asks for it) turns restart policies off for good and stops the running rows
//! one at a time in reverse manifest order. Every row comes after the rows it depends on, so
//! each service stops before anything it needs. Init sends `Stop`, which gives the instance a
//! stop notice and [`SERVICE_STOP_GRACE_NS`]; it waits for the instance's end and logs
//! `[INIT] stop <name> ok|timeout|fault service=<id>`: `ok` when it exited by itself,
//! `timeout` when the kernel (or, as a fallback, init) terminated it at the deadline, `fault`
//! when it crashed. A crash of any service during the stop is not restarted. After the last row
//! init logs `[INIT] system stopped` and waits with no deadline; powering off is #372's.

use core::fmt::{self, Write};

use clean_slate_native_abi::launcher::{AppEntry, AppName, AppState, StartResult, StopResult};
use clean_slate_native_abi::service_stop::{SERVICE_STOP_GRACE_NS, STOP_EXIT_STATUS_DEADLINE};
use clean_slate_service_fixtures::manifest::{RestartSpec, ServiceSpec, Start};
use clean_slate_service_lifecycle::{
    ticks_add, ticks_reached, DependencyEdge, DependencyMetadata, LifecycleEventKind,
    LivenessConfig, MonotonicTicks, ProcessId, ServiceId, ServiceLifecycleState,
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

/// How long after the kernel's stop deadline init terminates a stopping instance itself. The
/// kernel ends it at its deadline on init's next `LIFECYCLE_WAIT`, so this only matters if
/// that did not happen.
pub const INIT_STOP_SLACK_NS: u64 = 250_000_000;

/// Messages handled per wake at most, so one wake cannot turn into a loop.
const MAX_EVENTS_PER_WAKE: usize = 16;

/// The supervisor policy for a manifest row's restart spec. Init's unit is nanoseconds on the
/// `WORK_SET` `NOW` clock, the clock it passes to [`SystemInit::on_wake`].
pub const fn restart_policy(spec: RestartSpec) -> RestartPolicy {
    match spec {
        RestartSpec::Never => RestartPolicy::Never,
        RestartSpec::OnFailure {
            max_attempts,
            backoff_base_ns,
            initial_delay_ns,
        }
        | RestartSpec::OnExitUntilUnready {
            max_attempts,
            backoff_base_ns,
            initial_delay_ns,
        } => RestartPolicy::OnFailure(
            BoundedRestart::new(max_attempts, backoff_base_ns).with_initial_delay(initial_delay_ns),
        ),
    }
}

/// Whether a row's restart count goes back to zero when an instance reports ready.
const fn resets_on_ready(spec: RestartSpec) -> bool {
    matches!(spec, RestartSpec::OnExitUntilUnready { .. })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Progress {
    NotStarted,
    /// A `Start::OnRequest` row with no instance: started only by [`SystemInit::launch`].
    Idle,
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

/// How a stopped row's instance ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StopOutcome {
    /// It exited by itself after the notice.
    Ok,
    /// It was terminated at the deadline.
    Timeout,
    /// It crashed.
    Fault,
}

impl StopOutcome {
    const fn name(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Timeout => "timeout",
            Self::Fault => "fault",
        }
    }
}

/// The row init is stopping.
#[derive(Clone, Copy, Debug)]
struct Stopping {
    index: usize,
    /// When init terminates the instance itself if it is still live.
    deadline: MonotonicTicks,
    /// The instance's end, as its lifecycle message reported it.
    ended: Option<StopOutcome>,
    /// Init terminated it after the deadline.
    forced: bool,
}

/// #373: a system stop under way.
#[derive(Clone, Copy, Debug)]
struct SystemStop {
    current: Option<Stopping>,
    /// Rows at this index and above have been dealt with; the next is looked for below it.
    below: usize,
    stopped: usize,
    finished: bool,
}

pub struct SystemInit<C, D, const N: usize> {
    supervisor: ConvergedSupervisor<C, D, N>,
    slots: [Option<ServiceSlot>; N],
    ready_timeout_ns: u64,
    settled_announced: bool,
    system_stop: Option<SystemStop>,
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
            system_stop: None,
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
                progress: match spec.start {
                    Start::AtBoot => Progress::NotStarted,
                    Start::OnRequest => Progress::Idle,
                },
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
        if self.system_stop.is_some() {
            let _ = self.supervisor.advance_ticks(now);
            if let Some(service) = pending {
                self.handle_messages(service, now);
            }
            self.advance_system_stop(now);
            return;
        }
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
        if let Some(stop) = self.system_stop {
            return stop
                .current
                .filter(|stopping| !stopping.forced)
                .map(|stopping| stopping.deadline);
        }
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
            self.note_stop_outcome(service, event.kind, event.status_code);
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
                        if resets_on_ready(slot.spec.restart)
                            && self.supervisor.reset_restart_attempts(service).is_err()
                        {
                            self.give_up(service, "restart reset failed");
                        }
                    }
                }
                ServiceLifecycleState::Faulted | ServiceLifecycleState::Exited => {
                    self.set_ready_deadline(index, None);
                    if !self.idle_if_on_request(index, snapshot.state) {
                        self.give_up_if_exhausted(index);
                    }
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
                if failed && !self.idle_if_on_request(index, ServiceLifecycleState::Exited) {
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
        let mut idle = 0;
        for slot in self.slots.iter().flatten() {
            match slot.progress {
                Progress::GaveUp | Progress::Blocked => down += 1,
                Progress::Idle => idle += 1,
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
        let settled = running + down + idle == total && self.next_deadline().is_none();
        if settled && !self.settled_announced {
            // `idle=` appears only with on-request rows, so manifests without any keep the line.
            let _ = if idle == 0 {
                self.emit(format_args!(
                    "[INIT] boot settled running={running} down={down}; waiting, no deadline"
                ))
            } else {
                self.emit(format_args!(
                    "[INIT] boot settled running={running} down={down} idle={idle}; waiting, no deadline"
                ))
            };
        }
        self.settled_announced = settled;
    }

    /// An on-request row whose instance ended goes back to [`Progress::Idle`]: it restarts
    /// `Never` and starts again only when asked. Returns whether `index` was such a row.
    fn idle_if_on_request(&mut self, index: usize, state: ServiceLifecycleState) -> bool {
        let Some(slot) = self.slots[index] else {
            return false;
        };
        if slot.spec.start != Start::OnRequest || slot.progress != Progress::Started {
            return slot.spec.start == Start::OnRequest;
        }
        if let Some(slot) = self.slots[index].as_mut() {
            slot.progress = Progress::Idle;
            slot.ready_deadline = None;
        }
        let how = if state == ServiceLifecycleState::Faulted {
            "faulted"
        } else {
            "exited"
        };
        let _ = self.emit(format_args!(
            "[INIT] service={} {how}; starts again on request",
            slot.spec.id.0
        ));
        true
    }

    /// #237: a launcher client asks for the row named `name`. Starts it when it is idle (an
    /// on-request row with no instance) and every row it depends on is running. Returns the
    /// answer and the row's service id (0 when no row has that name).
    pub fn launch(&mut self, now: MonotonicTicks, name: &[u8]) -> (StartResult, u32) {
        if self.system_stop.is_some() {
            let service = self
                .slots
                .iter()
                .flatten()
                .find(|slot| {
                    slot.spec
                        .launch_name
                        .is_some_and(|own| own.as_bytes() == name)
                })
                .map_or(0, |slot| slot.spec.id.0);
            if service == 0 {
                return (StartResult::UnknownName, 0);
            }
            let _ = self.emit(format_args!(
                "[INIT] launch service={service} result=refused: system stopping"
            ));
            return (StartResult::Refused, service);
        }
        let Some(index) = self.slots.iter().position(|slot| {
            slot.is_some_and(|slot| {
                slot.spec
                    .launch_name
                    .is_some_and(|own| own.as_bytes() == name)
            })
        }) else {
            return (StartResult::UnknownName, 0);
        };
        let Some(slot) = self.slots[index] else {
            return (StartResult::UnknownName, 0);
        };
        let service = slot.spec.id.0;
        let result = match self.app_state(&slot) {
            AppState::Starting | AppState::Running => StartResult::AlreadyRunning,
            AppState::Restarting => StartResult::Busy,
            AppState::Down => StartResult::Refused,
            AppState::Idle if slot.progress != Progress::Idle => StartResult::Busy,
            AppState::Idle => self.start_on_request(index, now),
        };
        let _ = self.emit(format_args!(
            "[INIT] launch name={} service={service} result={}",
            slot.spec.launch_name.unwrap_or(""),
            result.name()
        ));
        (result, service)
    }

    fn start_on_request(&mut self, index: usize, now: MonotonicTicks) -> StartResult {
        let Some(slot) = self.slots[index] else {
            return StartResult::Refused;
        };
        if slot
            .spec
            .depends_on
            .iter()
            .any(|dependency| self.has_given_up(*dependency))
        {
            return StartResult::Refused;
        }
        if !self.dependencies_running(slot.spec) {
            return StartResult::Busy;
        }
        let _ = self.emit_start_line(slot.spec);
        if self.supervisor.request_start(slot.spec.id).is_err() {
            return StartResult::Refused;
        }
        let generation = self
            .supervisor
            .registry()
            .query(slot.spec.id)
            .map_or(0, |snapshot| snapshot.generation);
        if let Some(slot) = self.slots[index].as_mut() {
            slot.progress = Progress::Started;
        }
        self.set_ready_deadline(
            index,
            Some((generation, ticks_add(now, self.ready_timeout_ns))),
        );
        self.settled_announced = false;
        StartResult::Started
    }

    /// The rows a launcher client may list and start, in manifest order.
    pub fn launch_entries(&self) -> impl Iterator<Item = AppEntry> + '_ {
        self.slots.iter().flatten().filter_map(|slot| {
            let name = AppName::new(slot.spec.launch_name?.as_bytes())?;
            let snapshot = self.supervisor.registry().query(slot.spec.id);
            let state = self.app_state(slot);
            let live = matches!(state, AppState::Starting | AppState::Running);
            Some(AppEntry {
                service: slot.spec.id.0,
                state,
                generation: snapshot.map_or(0, |snapshot| snapshot.generation),
                pid: snapshot
                    .and_then(|snapshot| snapshot.active_pid)
                    .filter(|_| live)
                    .unwrap_or(0),
                name,
            })
        })
    }

    fn app_state(&self, slot: &ServiceSlot) -> AppState {
        match slot.progress {
            Progress::GaveUp | Progress::Blocked => return AppState::Down,
            Progress::Idle | Progress::NotStarted => return AppState::Idle,
            Progress::Started => {}
        }
        let Some(snapshot) = self.supervisor.registry().query(slot.spec.id) else {
            return AppState::Idle;
        };
        match snapshot.state {
            ServiceLifecycleState::Declared => AppState::Idle,
            ServiceLifecycleState::Starting => AppState::Starting,
            ServiceLifecycleState::Running | ServiceLifecycleState::Stopping => AppState::Running,
            ServiceLifecycleState::Exited
            | ServiceLifecycleState::Faulted
            | ServiceLifecycleState::RestartPending => AppState::Restarting,
        }
    }

    /// #373: whether a system stop has been asked for.
    pub fn system_stopping(&self) -> bool {
        self.system_stop.is_some()
    }

    /// #373: whether every row a system stop had to stop is down.
    pub fn system_stopped(&self) -> bool {
        self.system_stop.is_some_and(|stop| stop.finished)
    }

    /// #373: stops the system, once. From here on no restart policy fires and no row starts;
    /// the running rows are stopped in reverse manifest order, one at a time.
    pub fn request_system_stop(&mut self, now: MonotonicTicks) -> StopResult {
        if self.system_stop.is_some() {
            let _ = self.emit(format_args!(
                "[INIT] system stop requested again; already stopping"
            ));
            return StopResult::AlreadyStopping;
        }
        self.supervisor.suspend_restarts();
        let live = (0..N).filter(|index| self.stoppable(*index)).count();
        self.system_stop = Some(SystemStop {
            current: None,
            below: N,
            stopped: 0,
            finished: false,
        });
        let _ = self.emit(format_args!(
            "[INIT] system stop requested; stopping {live} services, last first"
        ));
        self.advance_system_stop(now);
        StopResult::Accepted
    }

    /// #373: a `SYSTEM_STOP` from a client without `LAUNCH_POWER`. Nothing changes.
    pub fn refuse_system_stop(&mut self) {
        let _ = self.emit(format_args!(
            "[INIT] system stop refused: the client does not hold launch_power"
        ));
    }

    /// Whether row `index` has an instance a system stop must end.
    fn stoppable(&self, index: usize) -> bool {
        let Some(slot) = self.slots[index] else {
            return false;
        };
        slot.progress == Progress::Started
            && self
                .supervisor
                .registry()
                .query(slot.spec.id)
                .is_some_and(|snapshot| {
                    matches!(
                        snapshot.state,
                        ServiceLifecycleState::Starting
                            | ServiceLifecycleState::Running
                            | ServiceLifecycleState::Stopping
                    )
                })
    }

    /// Records how the instance being stopped ended, from its lifecycle message.
    fn note_stop_outcome(&mut self, service: ServiceId, kind: LifecycleEventKind, status: u32) {
        let Some(stop) = self.system_stop.as_mut() else {
            return;
        };
        let Some(stopping) = stop.current.as_mut() else {
            return;
        };
        let current = self.slots[stopping.index].map(|slot| slot.spec.id);
        if current != Some(service) || stopping.ended.is_some() {
            return;
        }
        stopping.ended = match kind {
            LifecycleEventKind::Exited if status == STOP_EXIT_STATUS_DEADLINE => {
                Some(StopOutcome::Timeout)
            }
            LifecycleEventKind::Exited if stopping.forced => Some(StopOutcome::Timeout),
            LifecycleEventKind::Exited => Some(StopOutcome::Ok),
            LifecycleEventKind::Faulted => Some(StopOutcome::Fault),
            _ => None,
        };
    }

    /// Moves the system stop on as far as it can without waiting: logs the end of the row being
    /// stopped, then stops the next running row below it, until one is left to wait for.
    fn advance_system_stop(&mut self, now: MonotonicTicks) {
        for _ in 0..=N {
            let Some(stop) = self.system_stop else {
                return;
            };
            if stop.finished {
                return;
            }
            if let Some(stopping) = stop.current {
                if !self.finish_stopping(stopping, now) {
                    return;
                }
                continue;
            }
            let next = (0..stop.below).rev().find(|index| self.stoppable(*index));
            let Some(index) = next else {
                if let Some(stop) = self.system_stop.as_mut() {
                    stop.finished = true;
                    stop.below = 0;
                }
                let _ = self.emit(format_args!(
                    "[INIT] system stopped services={}; waiting, no deadline",
                    stop.stopped
                ));
                return;
            };
            self.begin_stopping(index, now);
        }
    }

    fn begin_stopping(&mut self, index: usize, now: MonotonicTicks) {
        let Some(slot) = self.slots[index] else {
            return;
        };
        if let Some(stop) = self.system_stop.as_mut() {
            stop.below = index;
            stop.current = Some(Stopping {
                index,
                deadline: ticks_add(
                    now,
                    SERVICE_STOP_GRACE_NS.saturating_add(INIT_STOP_SLACK_NS),
                ),
                ended: None,
                forced: false,
            });
        }
        let service = slot.spec.id;
        let _ = self.emit(format_args!(
            "[INIT] stopping {} service={}",
            slot.spec.name(),
            service.0
        ));
        if self.supervisor.stop(service).is_err() {
            let _ = self.emit(format_args!(
                "[INIT] stop {} refused service={}; terminating",
                slot.spec.name(),
                service.0
            ));
            self.force_stop(index);
        }
        // A kernel without a clock ends the instance at once; its message may be queued.
        self.handle_messages(service, now);
    }

    /// Init's fallback: the instance outlived its deadline, so terminate it.
    fn force_stop(&mut self, index: usize) {
        if let Some(stopping) = self
            .system_stop
            .as_mut()
            .and_then(|stop| stop.current.as_mut())
            .filter(|stopping| stopping.index == index)
        {
            stopping.forced = true;
        }
        let Some(slot) = self.slots[index] else {
            return;
        };
        if self.supervisor.terminate(slot.spec.id).is_err() {
            let _ = self.emit(format_args!(
                "[INIT] terminate failed service={}; carrying on",
                slot.spec.id.0
            ));
        }
    }

    /// Handles the row being stopped. Returns whether it is done with, so the next row can go.
    fn finish_stopping(&mut self, stopping: Stopping, now: MonotonicTicks) -> bool {
        let Some(slot) = self.slots[stopping.index] else {
            return true;
        };
        let state = self
            .supervisor
            .registry()
            .query(slot.spec.id)
            .map(|snapshot| snapshot.state);
        let ended = matches!(
            state,
            None | Some(ServiceLifecycleState::Exited)
                | Some(ServiceLifecycleState::Faulted)
                | Some(ServiceLifecycleState::Declared)
        );
        if !ended {
            if stopping.forced || !ticks_reached(now, stopping.deadline) {
                return false;
            }
            let _ = self.emit(format_args!(
                "[INIT] service={} still live after its stop deadline; terminating",
                slot.spec.id.0
            ));
            self.force_stop(stopping.index);
            let still_live =
                self.supervisor
                    .registry()
                    .query(slot.spec.id)
                    .is_some_and(|snapshot| {
                        !matches!(
                            snapshot.state,
                            ServiceLifecycleState::Exited | ServiceLifecycleState::Faulted
                        )
                    });
            if still_live {
                // Nothing more init can do for it; do not hold up the rest.
                let _ = self.emit(format_args!(
                    "[INIT] stop {} timeout service={}; left behind",
                    slot.spec.name(),
                    slot.spec.id.0
                ));
                self.end_current();
                return true;
            }
        }
        let outcome = self
            .system_stop
            .and_then(|stop| stop.current)
            .and_then(|current| {
                current.ended.or(if current.forced {
                    Some(StopOutcome::Timeout)
                } else {
                    None
                })
            })
            .unwrap_or(match state {
                Some(ServiceLifecycleState::Faulted) => StopOutcome::Fault,
                _ => StopOutcome::Ok,
            });
        let _ = self.emit(format_args!(
            "[INIT] stop {} {} service={}",
            slot.spec.name(),
            outcome.name(),
            slot.spec.id.0
        ));
        self.end_current();
        true
    }

    fn end_current(&mut self) {
        if let Some(stop) = self.system_stop.as_mut() {
            stop.current = None;
            stop.stopped += 1;
        }
    }

    fn emit_start_line(&mut self, spec: &ServiceSpec) -> Result<(), ConvergedSupervisorError> {
        let mut line = LineBuffer::new();
        let mut result = write!(line, "[INIT] ");
        // `service=A,B ready; starting service=C`: one line names every dependency and still
        // fits one console message.
        for (index, dependency) in spec.depends_on.iter().enumerate() {
            let separator = if index == 0 { "service=" } else { "," };
            result = result.and(write!(line, "{separator}{}", dependency.0));
        }
        let separator = if spec.depends_on.is_empty() {
            ""
        } else {
            " ready; "
        };
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
pub(crate) mod tests {
    extern crate std;

    use std::cell::RefCell;
    use std::rc::Rc;
    use std::string::{String, ToString};
    use std::vec::Vec;

    use clean_slate_service_fixtures::manifest::SYSTEM_MANIFEST;
    use clean_slate_service_fixtures::{
        AUDIT_SERVICE_ID, CONSOLE_SERVICE_ID, NETWORK_SERVICE_ID, STORAGE_SERVICE_ID,
        SYSTEM_SHELL_SERVICE_ID,
    };
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
    pub(crate) struct KernelModel {
        pub(crate) fake: FakeLifecycleControl<64>,
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

        pub(crate) fn report(&mut self, service: ServiceId, kind: LifecycleEventKind) {
            let event = LifecycleEvent::new(self.instance(service), kind);
            self.fake.push_pending(event).expect("queue event");
        }
    }

    #[derive(Clone, Default)]
    pub(crate) struct SharedKernel(pub(crate) Rc<RefCell<KernelModel>>);

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
    pub(crate) struct SharedLog(Rc<RefCell<Vec<String>>>);

    impl DiagnosticSink for SharedLog {
        fn emit_line(&mut self, line: &str) -> Result<(), SupervisorError> {
            self.0.borrow_mut().push(line.trim_end().to_string());
            Ok(())
        }
    }

    /// Init's `SERVICE_SLOTS`.
    const SLOTS: usize = 12;

    pub(crate) struct Harness {
        pub(crate) init: SystemInit<SharedKernel, SharedLog, SLOTS>,
        pub(crate) kernel: SharedKernel,
        log: SharedLog,
        /// A started audit instance reports ready at once.
        audit_ready_at_once: bool,
    }

    impl Harness {
        fn boot() -> Self {
            Self::boot_manifest(SYSTEM_MANIFEST)
        }

        /// Boots `manifest`; its console service, which depends on nothing, reports ready at
        /// once, and its audit service as soon as it is started after storage's ready, so that
        /// the tests below follow the other rows.
        pub(crate) fn boot_manifest(manifest: &'static [ServiceSpec]) -> Self {
            let mut harness = Self::boot_manifest_unready(manifest);
            harness.audit_ready_at_once = true;
            harness.report(0, CONSOLE_SERVICE_ID, LifecycleEventKind::Ready);
            harness
        }

        pub(crate) fn boot_manifest_unready(manifest: &'static [ServiceSpec]) -> Self {
            let kernel = SharedKernel::default();
            let log = SharedLog::default();
            let mut init = SystemInit::new(
                INIT_PID,
                kernel.clone(),
                log.clone(),
                manifest,
                INIT_READY_TIMEOUT_NS,
            )
            .expect("init registers the manifest");
            init.boot(0);
            Self {
                init,
                kernel,
                log,
                audit_ready_at_once: false,
            }
        }

        pub(crate) fn report(&mut self, now: u64, service: ServiceId, kind: LifecycleEventKind) {
            let audit_starts = self.starts_of(AUDIT_SERVICE_ID);
            self.kernel.0.borrow_mut().report(service, kind);
            self.init.on_wake(now, Some(service));
            if self.audit_ready_at_once && self.starts_of(AUDIT_SERVICE_ID) > audit_starts {
                self.report(now, AUDIT_SERVICE_ID, LifecycleEventKind::Ready);
            }
        }

        pub(crate) fn requests(&self) -> Vec<(ServiceId, ControlRequestKind)> {
            self.kernel
                .0
                .borrow()
                .fake
                .issued_requests()
                .map(|request| (request.service, request.kind))
                .collect()
        }

        pub(crate) fn starts_of(&self, service: ServiceId) -> usize {
            self.requests()
                .iter()
                .filter(|request| **request == (service, ControlRequestKind::Start))
                .count()
        }

        pub(crate) fn lines_with(&self, needle: &str) -> Vec<String> {
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
    fn boot_starts_storage_and_the_console_service_and_announces_itself() {
        let harness = Harness::boot_manifest_unready(SYSTEM_MANIFEST);
        assert_eq!(
            harness.requests(),
            [
                (STORAGE_SERVICE_ID, ControlRequestKind::Start),
                (CONSOLE_SERVICE_ID, ControlRequestKind::Start),
            ]
        );
        assert_eq!(
            harness.lines_with("[INIT] started pid=3 services=5").len(),
            1
        );
        assert_eq!(harness.lines_with("[INIT] starting service=20736").len(), 1);
        assert_eq!(harness.lines_with("[INIT] starting service=22016").len(), 1);
        for service in [STORAGE_SERVICE_ID, CONSOLE_SERVICE_ID] {
            assert_eq!(harness.state(service), ServiceLifecycleState::Starting);
        }
        // The audit service persists through the storage service, so it waits with the
        // network service for storage's ready (#219 stage D).
        for service in [NETWORK_SERVICE_ID, AUDIT_SERVICE_ID] {
            assert_eq!(harness.state(service), ServiceLifecycleState::Declared);
        }
    }

    #[test]
    fn network_and_shell_start_only_after_storage_reports_ready() {
        let mut harness = Harness::boot();
        harness.init.on_wake(SECOND, None);
        assert_eq!(harness.starts_of(NETWORK_SERVICE_ID), 0);
        assert_eq!(harness.starts_of(SYSTEM_SHELL_SERVICE_ID), 0);

        harness.report(2 * SECOND, STORAGE_SERVICE_ID, LifecycleEventKind::Ready);
        assert_eq!(
            harness.requests(),
            [
                (STORAGE_SERVICE_ID, ControlRequestKind::Start),
                (CONSOLE_SERVICE_ID, ControlRequestKind::Start),
                (NETWORK_SERVICE_ID, ControlRequestKind::Start),
                (SYSTEM_SHELL_SERVICE_ID, ControlRequestKind::Start),
                (AUDIT_SERVICE_ID, ControlRequestKind::Start),
            ]
        );
        let storage_ready = harness.position_of("[INIT] service=20736 ready gen=1");
        let network_start =
            harness.position_of("[INIT] service=20736 ready; starting service=20992");
        let shell_start =
            harness.position_of("[INIT] service=20736,22016 ready; starting service=21504");
        assert!(storage_ready < network_start);
        assert!(network_start < shell_start);
    }

    /// The compositor starts at boot beside storage and the console service; the desktop shell
    /// waits for the compositor's ready, the app for the shell's; the serial shell still waits
    /// for storage and the console service only.
    #[test]
    fn the_desktop_rows_start_in_dependency_order_and_settle_at_eight() {
        use clean_slate_service_fixtures::manifest::SYSTEM_DESKTOP_MANIFEST;
        use clean_slate_service_fixtures::{
            COMPOSITOR_SERVICE_ID, DESKTOP_SHELL_SERVICE_ID, PLAYGROUND_SERVICE_ID,
        };

        let mut harness = Harness::boot_manifest(SYSTEM_DESKTOP_MANIFEST);
        assert_eq!(
            harness.requests(),
            [
                (STORAGE_SERVICE_ID, ControlRequestKind::Start),
                (CONSOLE_SERVICE_ID, ControlRequestKind::Start),
                (COMPOSITOR_SERVICE_ID, ControlRequestKind::Start),
            ]
        );
        assert_eq!(
            harness.lines_with("[INIT] started pid=3 services=8").len(),
            1
        );
        harness.report(SECOND, COMPOSITOR_SERVICE_ID, LifecycleEventKind::Ready);
        assert_eq!(harness.starts_of(DESKTOP_SHELL_SERVICE_ID), 1);
        assert_eq!(harness.starts_of(PLAYGROUND_SERVICE_ID), 0);
        assert_eq!(harness.starts_of(SYSTEM_SHELL_SERVICE_ID), 0);
        harness.report(
            2 * SECOND,
            DESKTOP_SHELL_SERVICE_ID,
            LifecycleEventKind::Ready,
        );
        assert_eq!(harness.starts_of(PLAYGROUND_SERVICE_ID), 1);
        harness.position_of("[INIT] service=21248,21249,22016 ready; starting service=21250");
        for (service, at) in [
            (PLAYGROUND_SERVICE_ID, 3),
            (STORAGE_SERVICE_ID, 3),
            (NETWORK_SERVICE_ID, 4),
            (SYSTEM_SHELL_SERVICE_ID, 4),
        ] {
            harness.report(at * SECOND, service, LifecycleEventKind::Ready);
        }
        assert_eq!(
            harness.lines_with("[INIT] boot settled running=8 down=0; waiting, no deadline"),
            ["[INIT] boot settled running=8 down=0; waiting, no deadline"]
        );
        assert_eq!(harness.init.next_deadline(), None);
    }

    #[test]
    fn the_shell_does_not_wait_for_the_network() {
        let mut harness = Harness::boot();
        harness.report(SECOND, STORAGE_SERVICE_ID, LifecycleEventKind::Ready);
        harness.report(
            2 * SECOND,
            SYSTEM_SHELL_SERVICE_ID,
            LifecycleEventKind::Ready,
        );
        assert_eq!(
            harness.state(NETWORK_SERVICE_ID),
            ServiceLifecycleState::Starting
        );
        assert_eq!(
            harness.lines_with("[INIT] service=21504 ready gen=1").len(),
            1
        );
    }

    #[test]
    fn once_every_service_is_ready_init_waits_with_no_deadline_and_does_no_work() {
        let mut harness = Harness::boot();
        harness.report(SECOND, STORAGE_SERVICE_ID, LifecycleEventKind::Ready);
        assert!(
            harness.init.next_deadline().is_some(),
            "network ready deadline"
        );
        harness.report(2 * SECOND, NETWORK_SERVICE_ID, LifecycleEventKind::Ready);
        assert!(
            harness.init.next_deadline().is_some(),
            "shell ready deadline"
        );
        harness.report(
            2 * SECOND,
            SYSTEM_SHELL_SERVICE_ID,
            LifecycleEventKind::Ready,
        );

        assert_eq!(harness.init.next_deadline(), None);
        assert_eq!(
            harness.lines_with("[INIT] boot settled running=5 down=0; waiting, no deadline"),
            ["[INIT] boot settled running=5 down=0; waiting, no deadline"]
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
            harness.lines_with("[INIT] not starting service="),
            [
                "[INIT] not starting service=20992: service=20736 is down",
                "[INIT] not starting service=21504: service=20736 is down",
                "[INIT] not starting service=21760: service=20736 is down",
            ]
        );
        assert_eq!(harness.starts_of(NETWORK_SERVICE_ID), 0);
        assert_eq!(harness.starts_of(AUDIT_SERVICE_ID), 0);
        assert_eq!(harness.starts_of(SYSTEM_SHELL_SERVICE_ID), 0);
        assert_eq!(
            harness.init.next_deadline(),
            None,
            "init blocks instead of looping"
        );
        assert_eq!(
            harness.lines_with("[INIT] boot settled"),
            ["[INIT] boot settled running=1 down=4; waiting, no deadline"]
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
            harness.requests()[2..],
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
        harness.report(
            2 * SECOND,
            SYSTEM_SHELL_SERVICE_ID,
            LifecycleEventKind::Ready,
        );

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
        harness.report(
            2 * SECOND,
            SYSTEM_SHELL_SERVICE_ID,
            LifecycleEventKind::Ready,
        );
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
        ready.report(
            2 * SECOND,
            SYSTEM_SHELL_SERVICE_ID,
            LifecycleEventKind::Ready,
        );
        ready.report(
            3 * SECOND,
            SYSTEM_SHELL_SERVICE_ID,
            LifecycleEventKind::Exited,
        );

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
                backoff_base_ns: 2 * SECOND,
                initial_delay_ns: 2 * SECOND,
            }),
            RestartPolicy::OnFailure(
                BoundedRestart::new(3, 2 * SECOND).with_initial_delay(2 * SECOND)
            )
        );
        assert_eq!(
            restart_policy(RestartSpec::OnExitUntilUnready {
                max_attempts: 3,
                backoff_base_ns: SECOND,
                initial_delay_ns: SECOND / 2,
            }),
            RestartPolicy::OnFailure(BoundedRestart::new(3, SECOND).with_initial_delay(SECOND / 2))
        );
    }

    impl Harness {
        /// Every service ready; the shell's ready report means it read stdin.
        fn boot_to_shell_prompt() -> Self {
            let mut harness = Self::boot();
            harness.report(SECOND, STORAGE_SERVICE_ID, LifecycleEventKind::Ready);
            harness.report(SECOND, NETWORK_SERVICE_ID, LifecycleEventKind::Ready);
            harness.report(SECOND, SYSTEM_SHELL_SERVICE_ID, LifecycleEventKind::Ready);
            harness
        }

        /// The current shell exits at `now`; init is woken at the retry deadline. Returns the
        /// deadline.
        fn shell_exits_and_is_retried(&mut self, now: u64) -> u64 {
            let starts = self.starts_of(SYSTEM_SHELL_SERVICE_ID);
            self.report(now, SYSTEM_SHELL_SERVICE_ID, LifecycleEventKind::Exited);
            let deadline = self
                .init
                .next_deadline()
                .expect("a shell retry is scheduled");
            self.init.on_wake(deadline, None);
            assert_eq!(self.starts_of(SYSTEM_SHELL_SERVICE_ID), starts + 1);
            deadline
        }
    }

    #[test]
    fn a_shell_that_reached_its_prompt_is_restarted_after_every_exit() {
        let mut harness = Harness::boot_to_shell_prompt();
        let mut now = 2 * SECOND;
        for generation in 2..=8 {
            let launched = harness.shell_exits_and_is_retried(now);
            assert_eq!(launched - now, SECOND / 2, "always the first retry's delay");
            harness.report(launched, SYSTEM_SHELL_SERVICE_ID, LifecycleEventKind::Ready);
            assert_eq!(
                harness
                    .lines_with(&std::format!("[INIT] service=21504 ready gen={generation}"))
                    .len(),
                1
            );
            now = launched + SECOND;
        }
        assert_eq!(harness.starts_of(SYSTEM_SHELL_SERVICE_ID), 8);
        assert!(harness.lines_with("[INIT] gave up").is_empty());
        assert_eq!(
            harness.starts_of(STORAGE_SERVICE_ID),
            1,
            "storage untouched"
        );
    }

    #[test]
    fn a_shell_that_exits_before_its_prompt_three_times_in_a_row_is_given_up() {
        let mut harness = Harness::boot_to_shell_prompt();
        let mut now = 2 * SECOND;
        let mut retry_delays = Vec::new();
        for _ in 0..3 {
            let launched = harness.shell_exits_and_is_retried(now);
            retry_delays.push(launched - now);
            now = launched + SECOND;
        }
        assert_eq!(
            retry_delays,
            [SECOND / 2, SECOND / 2 + SECOND, SECOND / 2 + 2 * SECOND]
        );
        harness.report(now, SYSTEM_SHELL_SERVICE_ID, LifecycleEventKind::Exited);
        assert_eq!(
            harness.starts_of(SYSTEM_SHELL_SERVICE_ID),
            4,
            "no fifth launch"
        );
        assert_eq!(
            harness.lines_with("[INIT] gave up service=21504"),
            ["[INIT] gave up service=21504 restarts=3; init carries on"]
        );
        assert_eq!(
            harness.state(STORAGE_SERVICE_ID),
            ServiceLifecycleState::Running
        );
    }

    #[test]
    fn a_ready_report_between_early_exits_starts_the_count_again() {
        let mut harness = Harness::boot_to_shell_prompt();
        let mut now = 2 * SECOND;
        for _ in 0..2 {
            now = harness.shell_exits_and_is_retried(now) + SECOND;
        }
        harness.report(now, SYSTEM_SHELL_SERVICE_ID, LifecycleEventKind::Ready);
        for _ in 0..3 {
            now = harness.shell_exits_and_is_retried(now) + SECOND;
        }
        assert!(harness.lines_with("[INIT] gave up").is_empty());
        assert_eq!(harness.starts_of(SYSTEM_SHELL_SERVICE_ID), 6);
    }

    use clean_slate_service_fixtures::{
        COMPOSITOR_SERVICE_ID, DESKTOP_SHELL_SERVICE_ID, PLAYGROUND_SERVICE_ID,
    };

    const SETTLED_EIGHT: &str = "[INIT] boot settled running=8 down=0; waiting, no deadline";

    impl Harness {
        /// The desktop manifest booted with all seven rows ready and init settled, at 4 s.
        fn boot_desktop_settled() -> Self {
            use clean_slate_service_fixtures::manifest::SYSTEM_DESKTOP_MANIFEST;
            let mut harness = Self::boot_manifest(SYSTEM_DESKTOP_MANIFEST);
            for (service, at) in [
                (COMPOSITOR_SERVICE_ID, 1),
                (DESKTOP_SHELL_SERVICE_ID, 2),
                (PLAYGROUND_SERVICE_ID, 3),
                (STORAGE_SERVICE_ID, 3),
                (NETWORK_SERVICE_ID, 4),
                (SYSTEM_SHELL_SERVICE_ID, 4),
            ] {
                harness.report(at * SECOND, service, LifecycleEventKind::Ready);
            }
            assert_eq!(harness.lines_with(SETTLED_EIGHT).len(), 1);
            harness
        }

        /// The services init asked the kernel to start since request `from`, in order.
        fn starts_since(&self, from: usize) -> Vec<ServiceId> {
            self.requests()[from..]
                .iter()
                .filter(|(_, kind)| *kind == ControlRequestKind::Start)
                .map(|(service, _)| *service)
                .collect()
        }

        /// Wakes init at every due deadline up to and including `until`.
        fn run_until(&mut self, until: u64) {
            while let Some(deadline) = self.init.next_deadline().filter(|at| *at <= until) {
                self.init.on_wake(deadline, None);
            }
            self.init.on_wake(until, None);
        }

        fn assert_terminated_nothing(&self) {
            assert!(
                !self
                    .requests()
                    .iter()
                    .any(|(_, kind)| *kind == ControlRequestKind::Terminate),
                "init terminated a service"
            );
        }
    }

    /// S6d: the compositor dies and its clients exit with `compositor-gone`. Init relaunches the
    /// compositor after the half-second delay, the desktop shell only once the new compositor
    /// is ready, and the app only once the new shell is ready, however long readiness takes.
    #[test]
    fn after_a_compositor_fault_the_desktop_restarts_in_dependency_order() {
        let mut harness = Harness::boot_desktop_settled();
        let from = harness.requests().len();
        let fault = 10 * SECOND;
        harness.report(fault, COMPOSITOR_SERVICE_ID, LifecycleEventKind::Faulted);
        harness.report(fault, DESKTOP_SHELL_SERVICE_ID, LifecycleEventKind::Exited);
        harness.report(fault, PLAYGROUND_SERVICE_ID, LifecycleEventKind::Exited);
        harness.run_until(fault + SECOND / 2 - 1);
        assert!(harness.starts_since(from).is_empty(), "restarted early");
        harness.run_until(fault + SECOND / 2);
        assert_eq!(harness.starts_since(from), [COMPOSITOR_SERVICE_ID]);

        // The new compositor is slow to report ready; its clients' delays pass meanwhile.
        harness.run_until(fault + 5 * SECOND);
        assert_eq!(
            harness.starts_since(from),
            [COMPOSITOR_SERVICE_ID],
            "a client started before the new compositor was ready"
        );
        harness.report(
            fault + 5 * SECOND,
            COMPOSITOR_SERVICE_ID,
            LifecycleEventKind::Ready,
        );
        assert_eq!(
            harness.starts_since(from),
            [COMPOSITOR_SERVICE_ID, DESKTOP_SHELL_SERVICE_ID]
        );
        harness.run_until(fault + 9 * SECOND);
        assert_eq!(
            harness.starts_since(from),
            [COMPOSITOR_SERVICE_ID, DESKTOP_SHELL_SERVICE_ID],
            "the app started before the new desktop shell was ready"
        );
        harness.report(
            fault + 9 * SECOND,
            DESKTOP_SHELL_SERVICE_ID,
            LifecycleEventKind::Ready,
        );
        assert_eq!(
            harness.starts_since(from),
            [
                COMPOSITOR_SERVICE_ID,
                DESKTOP_SHELL_SERVICE_ID,
                PLAYGROUND_SERVICE_ID
            ]
        );
        harness.report(
            fault + 10 * SECOND,
            PLAYGROUND_SERVICE_ID,
            LifecycleEventKind::Ready,
        );
        for generation_line in [
            "[INIT] service=21248 ready gen=2",
            "[INIT] service=21249 ready gen=2",
            "[INIT] service=21250 ready gen=2",
        ] {
            assert_eq!(
                harness.lines_with(generation_line).len(),
                1,
                "{generation_line}"
            );
        }
        assert_eq!(harness.lines_with(SETTLED_EIGHT).len(), 2);
        assert_terminated_nothing_and_base_untouched(&harness);
    }

    /// S6d: a desktop shell crash restarts the shell only; the app keeps its instance.
    #[test]
    fn a_desktop_shell_fault_restarts_the_shell_and_leaves_the_app_running() {
        let mut harness = Harness::boot_desktop_settled();
        let from = harness.requests().len();
        let fault = 10 * SECOND;
        harness.report(fault, DESKTOP_SHELL_SERVICE_ID, LifecycleEventKind::Faulted);
        harness.run_until(fault + SECOND / 2);
        assert_eq!(harness.starts_since(from), [DESKTOP_SHELL_SERVICE_ID]);
        harness.report(
            fault + SECOND,
            DESKTOP_SHELL_SERVICE_ID,
            LifecycleEventKind::Ready,
        );
        harness.run_until(fault + 10 * SECOND);
        assert_eq!(harness.starts_since(from), [DESKTOP_SHELL_SERVICE_ID]);
        assert_eq!(
            harness.state(PLAYGROUND_SERVICE_ID),
            ServiceLifecycleState::Running
        );
        assert_eq!(harness.lines_with(SETTLED_EIGHT).len(), 2);
        assert_terminated_nothing_and_base_untouched(&harness);
    }

    /// #356: an app whose heap runs out logs and exits normally (`exit_out_of_memory`), and that
    /// exit is restarted like any other: every time while it keeps reaching ready, with the
    /// row's heap budget each time.
    #[test]
    fn an_app_that_exits_out_of_memory_is_restarted_with_its_budget() {
        for service in [DESKTOP_SHELL_SERVICE_ID, PLAYGROUND_SERVICE_ID] {
            let spec = clean_slate_service_fixtures::manifest::SYSTEM_DESKTOP_MANIFEST
                .iter()
                .find(|spec| spec.id == service)
                .expect("desktop row");
            assert!(spec.memory_pages >= 16, "{service:?} has a heap chunk");
            let mut harness = Harness::boot_desktop_settled();
            let mut now = 10 * SECOND;
            for _ in 0..5 {
                let from = harness.requests().len();
                harness.report(now, service, LifecycleEventKind::Exited);
                harness.run_until(now + SECOND / 2);
                assert_eq!(harness.starts_since(from), [service], "{service:?}");
                harness.report(now + SECOND, service, LifecycleEventKind::Ready);
                now += 10 * SECOND;
            }
            assert!(harness.lines_with("[INIT] gave up").is_empty());
            assert_terminated_nothing_and_base_untouched(&harness);
        }
    }

    /// S6d: a compositor that keeps dying before it is ready is given up after its three
    /// restarts; its clients are given up with it, and the base rows carry on untouched.
    #[test]
    fn a_crash_looping_compositor_is_given_up_and_the_rest_of_the_system_carries_on() {
        let mut harness = Harness::boot_desktop_settled();
        let from = harness.requests().len();
        let mut now = 10 * SECOND;
        harness.report(now, COMPOSITOR_SERVICE_ID, LifecycleEventKind::Faulted);
        harness.report(now, DESKTOP_SHELL_SERVICE_ID, LifecycleEventKind::Exited);
        harness.report(now, PLAYGROUND_SERVICE_ID, LifecycleEventKind::Exited);
        for restart in 1..=3 {
            now += 10 * SECOND;
            harness.run_until(now);
            assert_eq!(harness.starts_of(COMPOSITOR_SERVICE_ID), 1 + restart);
            harness.report(now, COMPOSITOR_SERVICE_ID, LifecycleEventKind::Faulted);
        }
        harness.run_until(now + 60 * SECOND);
        assert_eq!(
            harness.starts_since(from),
            [COMPOSITOR_SERVICE_ID; 3],
            "no fourth restart, and no client started"
        );
        assert_eq!(
            harness.lines_with("[INIT] gave up service=21248"),
            ["[INIT] gave up service=21248 restarts=3; init carries on"]
        );
        for client in ["21249", "21250"] {
            assert_eq!(
                harness
                    .lines_with(&std::format!(
                        "[INIT] gave up service={client}: service=21248 is down"
                    ))
                    .len(),
                1,
                "{client}"
            );
        }
        assert_terminated_nothing_and_base_untouched(&harness);
    }

    fn assert_terminated_nothing_and_base_untouched(harness: &Harness) {
        harness.assert_terminated_nothing();
        for service in [
            STORAGE_SERVICE_ID,
            NETWORK_SERVICE_ID,
            SYSTEM_SHELL_SERVICE_ID,
        ] {
            assert_eq!(harness.starts_of(service), 1);
            assert_eq!(harness.state(service), ServiceLifecycleState::Running);
        }
    }

    /// #373 system stop.
    mod system_stop {
        use super::*;
        use clean_slate_native_abi::service_stop::{
            SERVICE_STOP_GRACE_NS, STOP_EXIT_STATUS_DEADLINE,
        };
        use clean_slate_service_fixtures::{
            COMPOSITOR_SERVICE_ID, DESKTOP_SHELL_SERVICE_ID, PLAYGROUND_SERVICE_ID,
        };

        /// The desktop rows, last first.
        const REVERSE_DESKTOP: [ServiceId; 8] = [
            PLAYGROUND_SERVICE_ID,
            DESKTOP_SHELL_SERVICE_ID,
            COMPOSITOR_SERVICE_ID,
            AUDIT_SERVICE_ID,
            SYSTEM_SHELL_SERVICE_ID,
            CONSOLE_SERVICE_ID,
            NETWORK_SERVICE_ID,
            STORAGE_SERVICE_ID,
        ];

        const STOP_AT: u64 = 100 * SECOND;

        impl Harness {
            /// The control requests of `kind` since request `from`.
            fn requests_since(&self, from: usize, kind: ControlRequestKind) -> Vec<ServiceId> {
                self.requests()[from..]
                    .iter()
                    .filter(|(_, issued)| *issued == kind)
                    .map(|(service, _)| *service)
                    .collect()
            }

            /// The live instance of `service` ends with `kind` and `status`.
            fn end_with(
                &mut self,
                now: u64,
                service: ServiceId,
                kind: LifecycleEventKind,
                status: u32,
            ) {
                {
                    let mut model = self.kernel.0.borrow_mut();
                    let mut event = LifecycleEvent::new(model.instance(service), kind);
                    event.status_code = status;
                    model.fake.push_pending(event).expect("queue event");
                }
                self.init.on_wake(now, Some(service));
            }

            fn stop_lines(&self) -> Vec<String> {
                self.lines_with("[INIT] stop ")
            }
        }

        #[test]
        fn services_stop_one_at_a_time_last_started_first() {
            let mut harness = Harness::boot_desktop_settled();
            let from = harness.requests().len();
            assert_eq!(
                harness.init.request_system_stop(STOP_AT),
                StopResult::Accepted
            );
            assert_eq!(
                harness.lines_with("[INIT] system stop requested"),
                ["[INIT] system stop requested; stopping 8 services, last first"]
            );
            for (step, service) in REVERSE_DESKTOP.iter().enumerate() {
                // Init waits for each service before it asks the next one.
                assert_eq!(
                    harness.requests_since(from, ControlRequestKind::Stop),
                    REVERSE_DESKTOP[..=step],
                    "step {step}"
                );
                assert_eq!(
                    harness.init.next_deadline(),
                    Some(
                        STOP_AT + step as u64 * SECOND + SERVICE_STOP_GRACE_NS + INIT_STOP_SLACK_NS
                    )
                );
                harness.end_with(
                    STOP_AT + (step as u64 + 1) * SECOND,
                    *service,
                    LifecycleEventKind::Exited,
                    0,
                );
            }
            let expected: Vec<String> = REVERSE_DESKTOP
                .iter()
                .map(|service| {
                    let spec = clean_slate_service_fixtures::manifest::SYSTEM_DESKTOP_MANIFEST
                        .iter()
                        .find(|spec| spec.id == *service)
                        .unwrap();
                    std::format!("[INIT] stop {} ok service={}", spec.name(), service.0)
                })
                .collect();
            assert_eq!(harness.stop_lines(), expected);
            assert_eq!(
                expected[0],
                std::format!(
                    "[INIT] stop playground ok service={}",
                    PLAYGROUND_SERVICE_ID.0
                )
            );
            assert_eq!(
                harness.lines_with("[INIT] system stopped"),
                ["[INIT] system stopped services=8; waiting, no deadline"]
            );
            assert!(harness.init.system_stopped());
            assert_eq!(harness.init.next_deadline(), None);
            // Nothing was terminated, started or restarted.
            assert!(harness
                .requests_since(from, ControlRequestKind::Terminate)
                .is_empty());
            assert!(harness
                .requests_since(from, ControlRequestKind::Start)
                .is_empty());
            harness.run_until(STOP_AT + 600 * SECOND);
            assert!(harness
                .requests_since(from, ControlRequestKind::Start)
                .is_empty());
        }

        #[test]
        fn a_service_that_ignores_the_notice_is_logged_as_a_timeout() {
            let mut harness = Harness::boot_desktop_settled();
            harness.init.request_system_stop(STOP_AT);
            // The kernel ended the playground at its deadline.
            let deadline = harness.init.next_deadline().expect("a stop deadline");
            harness.end_with(
                deadline - INIT_STOP_SLACK_NS,
                PLAYGROUND_SERVICE_ID,
                LifecycleEventKind::Exited,
                STOP_EXIT_STATUS_DEADLINE,
            );
            assert_eq!(
                harness.stop_lines(),
                [std::format!(
                    "[INIT] stop playground timeout service={}",
                    PLAYGROUND_SERVICE_ID.0
                )]
            );
            // If the kernel did not end the desktop shell, init terminates it at its own deadline.
            let from = harness.requests().len();
            let deadline = harness.init.next_deadline().expect("a stop deadline");
            harness.init.on_wake(deadline - 1, None);
            assert!(harness
                .requests_since(from, ControlRequestKind::Terminate)
                .is_empty());
            harness.init.on_wake(deadline, None);
            assert_eq!(
                harness.requests_since(from, ControlRequestKind::Terminate),
                [DESKTOP_SHELL_SERVICE_ID]
            );
            assert_eq!(
                harness.stop_lines()[1],
                std::format!(
                    "[INIT] stop desktop-shell timeout service={}",
                    DESKTOP_SHELL_SERVICE_ID.0
                )
            );
            // The stop carried on with the compositor.
            assert_eq!(
                harness.requests_since(from, ControlRequestKind::Stop),
                [COMPOSITOR_SERVICE_ID]
            );
        }

        #[test]
        fn a_crash_during_the_system_stop_is_not_restarted() {
            let mut harness = Harness::boot_desktop_settled();
            let from = harness.requests().len();
            harness.init.request_system_stop(STOP_AT);
            // The playground crashes while it finishes; storage crashes before its turn.
            harness.end_with(
                STOP_AT + 1,
                PLAYGROUND_SERVICE_ID,
                LifecycleEventKind::Faulted,
                0,
            );
            harness.end_with(
                STOP_AT + 2,
                STORAGE_SERVICE_ID,
                LifecycleEventKind::Faulted,
                0,
            );
            assert_eq!(
                harness.stop_lines(),
                [std::format!(
                    "[INIT] stop playground fault service={}",
                    PLAYGROUND_SERVICE_ID.0
                )]
            );
            for service in &REVERSE_DESKTOP[1..7] {
                harness.end_with(STOP_AT + 3, *service, LifecycleEventKind::Exited, 0);
            }
            // Storage had already gone, so there was nothing left to stop.
            assert_eq!(
                harness.requests_since(from, ControlRequestKind::Stop),
                REVERSE_DESKTOP[..7]
            );
            assert_eq!(harness.stop_lines().len(), 7);
            assert!(harness.init.system_stopped());
            harness.run_until(STOP_AT + 600 * SECOND);
            assert!(harness
                .requests_since(from, ControlRequestKind::Start)
                .is_empty());
            assert!(harness
                .requests_since(from, ControlRequestKind::Restart)
                .is_empty());
        }

        #[test]
        fn a_second_request_and_launches_during_the_stop_are_refused() {
            let mut harness = Harness::boot_desktop_settled();
            assert_eq!(
                harness.init.request_system_stop(STOP_AT),
                StopResult::Accepted
            );
            assert_eq!(
                harness.init.request_system_stop(STOP_AT + 1),
                StopResult::AlreadyStopping
            );
            harness.end_with(
                STOP_AT + 2,
                PLAYGROUND_SERVICE_ID,
                LifecycleEventKind::Exited,
                0,
            );
            let from = harness.requests().len();
            assert_eq!(
                harness.init.launch(STOP_AT + 3, b"playground"),
                (StartResult::Refused, PLAYGROUND_SERVICE_ID.0)
            );
            assert_eq!(
                harness.init.launch(STOP_AT + 3, b"nope"),
                (StartResult::UnknownName, 0)
            );
            assert!(harness
                .requests_since(from, ControlRequestKind::Start)
                .is_empty());
        }

        #[test]
        fn a_service_still_starting_is_stopped_too_and_idle_rows_are_skipped() {
            // Storage never reports ready, so only storage and the console service run.
            let mut harness = Harness::boot_manifest_unready(SYSTEM_MANIFEST);
            harness.report(0, CONSOLE_SERVICE_ID, LifecycleEventKind::Ready);
            let from = harness.requests().len();
            assert_eq!(
                harness.init.request_system_stop(SECOND),
                StopResult::Accepted
            );
            assert_eq!(
                harness.lines_with("[INIT] system stop requested"),
                ["[INIT] system stop requested; stopping 2 services, last first"]
            );
            harness.end_with(
                2 * SECOND,
                CONSOLE_SERVICE_ID,
                LifecycleEventKind::Exited,
                0,
            );
            harness.end_with(
                3 * SECOND,
                STORAGE_SERVICE_ID,
                LifecycleEventKind::Exited,
                0,
            );
            assert_eq!(
                harness.requests_since(from, ControlRequestKind::Stop),
                [CONSOLE_SERVICE_ID, STORAGE_SERVICE_ID]
            );
            assert!(harness.init.system_stopped());
            // Its ready deadline passing changes nothing now.
            harness.run_until(60 * SECOND);
            assert!(harness
                .requests_since(from, ControlRequestKind::Start)
                .is_empty());
            assert!(harness
                .requests_since(from, ControlRequestKind::Terminate)
                .is_empty());
        }
    }
}
