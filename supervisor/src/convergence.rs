//! M4 Wave 2 convergence: registry + health + dependencies + restart policy (#40).

use core::fmt::Write;

use clean_slate_service_lifecycle::{
    format_dependency_blocked_line, format_dependency_ready_line, format_health_healthy_line,
    format_health_unhealthy_line, ticks_reached, ControlRequest, ControlRequestKind,
    DependencyGraph, DependencyGraphError, DependencyHealthSnapshot, DependencyMetadata,
    HealthFailureEvent, HealthReport, HealthReportOutcome, HealthStatus, HealthTrackerError,
    InstanceGeneration, LifecycleEvent, LifecycleEventKind, LifecycleFailureOutcome,
    LivenessConfig, MonotonicTicks, ServiceHealthTracker, ServiceId, ServiceLifecycleState,
    StartBlockReason, StartReadiness, TransitionError,
};

use crate::control::LifecycleControl;
use crate::diagnostics::{
    format_failure_line, format_restart_line, format_restart_suppressed_line, format_restarted_line,
};
use crate::registry::{ServiceRegistry, ServiceRegistryError};
use crate::restart_policy::{
    RecoveryRuntime, RestartDecision, RestartPolicy, RestartSuppressedReason,
};
use crate::runtime::{DiagnosticSink, Supervisor, SupervisorError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConvergedSupervisorError {
    Supervisor(SupervisorError),
    Registry(ServiceRegistryError),
    Health(HealthTrackerError),
    Dependencies(DependencyGraphError),
    StartBlocked(StartBlockReason),
    UnknownService,
}

pub struct ServiceConvergenceConfig {
    pub restart: RestartPolicy,
    pub liveness: LivenessConfig,
}

impl ServiceConvergenceConfig {
    pub const fn new(restart: RestartPolicy, liveness: LivenessConfig) -> Self {
        Self { restart, liveness }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RecoverySlot {
    service: ServiceId,
    runtime: RecoveryRuntime,
    scheduled_attempt: u32,
    restart_old_pid: Option<u64>,
}

/// Userspace supervisor with health, dependency readiness, and bounded restart policy.
pub struct ConvergedSupervisor<C, D, const N: usize> {
    supervisor: Supervisor<C, D, N>,
    health: ServiceHealthTracker<N>,
    dependencies: DependencyGraph<N>,
    recovery: [Option<RecoverySlot>; N],
    default_liveness: LivenessConfig,
    now: MonotonicTicks,
    dep_health: DependencyHealthSnapshot<N>,
}

impl<C, D, const N: usize> ConvergedSupervisor<C, D, N>
where
    C: LifecycleControl,
    D: DiagnosticSink,
{
    pub fn new(
        self_pid: clean_slate_service_lifecycle::ProcessId,
        control: C,
        diagnostics: D,
        default_liveness: LivenessConfig,
    ) -> Self {
        Self {
            supervisor: Supervisor::new(self_pid, control, diagnostics),
            health: ServiceHealthTracker::new(),
            dependencies: DependencyGraph::new(),
            recovery: [None; N],
            default_liveness,
            now: 0,
            dep_health: DependencyHealthSnapshot::empty(),
        }
    }

    pub fn registry(&self) -> &ServiceRegistry<N> {
        self.supervisor.registry()
    }

    pub fn now(&self) -> MonotonicTicks {
        self.now
    }

    pub fn set_virtual_ticks(&mut self, now: MonotonicTicks) {
        self.now = now;
    }

    pub fn start(&mut self) -> Result<(), ConvergedSupervisorError> {
        self.supervisor
            .start()
            .map_err(ConvergedSupervisorError::Supervisor)
    }

    pub fn register_service(
        &mut self,
        service: ServiceId,
        config: ServiceConvergenceConfig,
    ) -> Result<(), ConvergedSupervisorError> {
        self.supervisor
            .register_service(service)
            .map_err(ConvergedSupervisorError::Supervisor)?;
        self.health
            .register(service)
            .map_err(ConvergedSupervisorError::Health)?;
        self.dependencies
            .declare(service)
            .map_err(ConvergedSupervisorError::Dependencies)?;
        let slot = self
            .recovery
            .iter()
            .position(|entry| entry.is_none())
            .ok_or(ConvergedSupervisorError::UnknownService)?;
        self.recovery[slot] = Some(RecoverySlot {
            service,
            runtime: RecoveryRuntime::new(config.restart),
            scheduled_attempt: 0,
            restart_old_pid: None,
        });
        Ok(())
    }

    pub fn set_dependencies(
        &mut self,
        metadata: DependencyMetadata,
    ) -> Result<(), ConvergedSupervisorError> {
        self.dependencies
            .set_dependencies(metadata)
            .map_err(ConvergedSupervisorError::Dependencies)
    }

    pub fn advance_ticks(&mut self, now: MonotonicTicks) -> Result<(), ConvergedSupervisorError> {
        self.now = now;
        self.refresh_dependency_health();
        let mut failures = [None; N];
        let mut failure_count = 0usize;
        self.health.poll_timeouts(now, |event| {
            if failure_count < N {
                failures[failure_count] = Some(event);
                failure_count += 1;
            }
        });
        for event in failures.iter().take(failure_count).flatten() {
            self.on_health_failure(*event, None)?;
        }
        self.drive_pending_restarts()?;
        Ok(())
    }

    pub fn apply_health_report(
        &mut self,
        report: HealthReport,
    ) -> Result<(), ConvergedSupervisorError> {
        let service = report.service;
        let outcome = self
            .health
            .record_mut(service)
            .map_err(ConvergedSupervisorError::Health)?
            .apply_report(report, self.now, self.default_liveness);
        match outcome {
            HealthReportOutcome::MarkedUnhealthy { reason, .. } => {
                self.emit_health_unhealthy(service, reason)?;
                self.on_health_failure(
                    HealthFailureEvent {
                        service,
                        generation: report.generation,
                        reason,
                        observed_at: self.now,
                    },
                    None,
                )?;
            }
            HealthReportOutcome::AcceptedHealthy { generation } => {
                self.emit_health_healthy(service, generation)?;
            }
            HealthReportOutcome::AcceptedDegraded { generation } => {
                self.emit_health_healthy(service, generation)?;
            }
            HealthReportOutcome::IgnoredStale { .. }
            | HealthReportOutcome::IgnoredNoActiveInstance
            | HealthReportOutcome::IgnoredUnknownService => {}
        }
        Ok(())
    }

    pub fn request_start(&mut self, service: ServiceId) -> Result<(), ConvergedSupervisorError> {
        self.ensure_start_ready(service)?;
        self.supervisor
            .issue_control(ControlRequest::new(service, ControlRequestKind::Start))
            .map_err(ConvergedSupervisorError::Supervisor)?;
        self.drain_events(service)?;
        self.supervisor
            .log_service_state_public(service)
            .map_err(ConvergedSupervisorError::Supervisor)
    }

    pub fn handle_lifecycle_event(
        &mut self,
        event: LifecycleEvent,
    ) -> Result<(), ConvergedSupervisorError> {
        let service = event.instance.service;
        let generation = event.instance.generation;
        let pid = event.instance.pid.0;
        let kind = event.kind;

        match self.supervisor.handle_lifecycle_event(event) {
            Ok(()) => {}
            Err(SupervisorError::Registry(ServiceRegistryError::Transition(
                TransitionError::StaleInstance { .. },
            ))) => return Ok(()),
            Err(error) => return Err(ConvergedSupervisorError::Supervisor(error)),
        }

        match kind {
            LifecycleEventKind::InstanceSpawned => {
                self.health
                    .record_mut(service)
                    .map_err(ConvergedSupervisorError::Health)?
                    .begin_instance(generation, self.now, self.default_liveness);
                if let Ok(slot) = self.recovery_slot_mut(service) {
                    if let Some(old_pid) = slot.restart_old_pid.take() {
                        if old_pid != pid {
                            self.emit_restarted(service, old_pid, pid)?;
                        }
                    }
                }
            }
            LifecycleEventKind::Ready => {
                self.emit_health_healthy(service, generation)?;
                if let Ok(slot) = self.recovery_slot_mut(service) {
                    slot.runtime.on_healthy_instance();
                    slot.scheduled_attempt = 0;
                }
            }
            LifecycleEventKind::Exited | LifecycleEventKind::Faulted => {
                let outcome = self
                    .health
                    .record_mut(service)
                    .map_err(ConvergedSupervisorError::Health)?
                    .notify_lifecycle_failure(generation, kind, 0, self.now);
                if let LifecycleFailureOutcome::MarkedUnhealthy(event) = outcome {
                    self.emit_health_unhealthy(service, event.reason)?;
                    self.on_health_failure(event, Some(pid))?;
                }
            }
            _ => {}
        }
        self.drive_pending_restarts()?;
        Ok(())
    }

    fn on_health_failure(
        &mut self,
        event: HealthFailureEvent,
        explicit_pid: Option<u64>,
    ) -> Result<(), ConvergedSupervisorError> {
        let service = event.service;
        let failed_pid = explicit_pid.or_else(|| {
            self.registry()
                .query(service)
                .and_then(|snapshot| snapshot.active_pid)
        });
        if let Some(pid) = failed_pid {
            self.emit_failure(service, pid)?;
        }
        let now = self.now;
        let decision = self
            .recovery_slot_mut(service)?
            .runtime
            .on_failure(failed_pid, now);
        match decision {
            RestartDecision::Suppressed(reason) => self.emit_restart_suppressed(service, reason)?,
            RestartDecision::Scheduled { attempt, .. } => {
                self.recovery_slot_mut(service)?.scheduled_attempt = attempt;
            }
        }
        self.drive_pending_restarts()?;
        Ok(())
    }

    fn drive_pending_restarts(&mut self) -> Result<(), ConvergedSupervisorError> {
        for index in 0..N {
            let Some(slot) = self.recovery[index].as_ref() else {
                continue;
            };
            if !slot.runtime.pending() {
                continue;
            }
            if !ticks_reached(self.now, slot.runtime.not_before()) {
                continue;
            }
            let service = slot.service;
            let attempt = slot.scheduled_attempt;
            self.try_execute_restart(service, attempt)?;
        }
        Ok(())
    }

    fn try_execute_restart(
        &mut self,
        service: ServiceId,
        attempt: u32,
    ) -> Result<(), ConvergedSupervisorError> {
        self.refresh_dependency_health();
        let readiness = self
            .dependencies
            .evaluate_start_readiness(
                service,
                self.registry().lifecycle_tracker(),
                Some(&self.dep_health),
            )
            .map_err(ConvergedSupervisorError::Dependencies)?;
        if let StartReadiness::Blocked(reason) = readiness {
            self.emit_dependency_blocked(service, reason)?;
            return Ok(());
        }
        self.emit_dependency_ready(service)?;

        let old_pid = self
            .recovery_slot_mut(service)?
            .runtime
            .failed_pid()
            .unwrap_or(0);
        self.emit_restart(service, attempt)?;
        if let Ok(slot) = self.recovery_slot_mut(service) {
            slot.restart_old_pid = Some(old_pid);
            slot.runtime.record_attempt_started(attempt);
            slot.runtime.clear_pending_after_attempt();
        }

        self.supervisor
            .issue_restart_sequence(service)
            .map_err(ConvergedSupervisorError::Supervisor)?;
        self.drain_events(service)?;
        self.supervisor
            .log_service_state_public(service)
            .map_err(ConvergedSupervisorError::Supervisor)?;
        Ok(())
    }

    fn drain_events(&mut self, service: ServiceId) -> Result<(), ConvergedSupervisorError> {
        for _ in 0..8 {
            let event = self
                .supervisor
                .poll_event(service)
                .map_err(ConvergedSupervisorError::Supervisor)?;
            let Some(event) = event else {
                break;
            };
            self.handle_lifecycle_event(event)?;
            if self
                .registry()
                .query(service)
                .is_some_and(|snapshot| snapshot.state == ServiceLifecycleState::Running)
            {
                break;
            }
        }
        Ok(())
    }

    fn ensure_start_ready(&mut self, service: ServiceId) -> Result<(), ConvergedSupervisorError> {
        self.refresh_dependency_health();
        let readiness = self
            .dependencies
            .evaluate_start_readiness(
                service,
                self.registry().lifecycle_tracker(),
                Some(&self.dep_health),
            )
            .map_err(ConvergedSupervisorError::Dependencies)?;
        match readiness {
            StartReadiness::Ready => {
                self.emit_dependency_ready(service)?;
                Ok(())
            }
            StartReadiness::Blocked(reason) => {
                self.emit_dependency_blocked(service, reason)?;
                Err(ConvergedSupervisorError::StartBlocked(reason))
            }
        }
    }

    fn recovery_slot_mut(
        &mut self,
        service: ServiceId,
    ) -> Result<&mut RecoverySlot, ConvergedSupervisorError> {
        self.recovery
            .iter_mut()
            .find_map(|entry| entry.as_mut().filter(|slot| slot.service == service))
            .ok_or(ConvergedSupervisorError::UnknownService)
    }

    fn refresh_dependency_health(&mut self) {
        self.dep_health = DependencyHealthSnapshot::empty();
        for slot in &self.recovery {
            let Some(entry) = slot else {
                continue;
            };
            let service = entry.service;
            let Ok(record) = self.health.record_mut(service) else {
                continue;
            };
            let status = if record.is_healthy() {
                HealthStatus::Ok
            } else if record.failure_reason().is_some() {
                HealthStatus::Unhealthy
            } else {
                HealthStatus::Unknown
            };
            let _ = self.dep_health.set(service, status);
        }
    }

    fn emit_line(&mut self, line: &str) -> Result<(), ConvergedSupervisorError> {
        self.supervisor
            .emit_diagnostic(line)
            .map_err(ConvergedSupervisorError::Supervisor)
    }

    fn emit_failure(
        &mut self,
        service: ServiceId,
        pid: u64,
    ) -> Result<(), ConvergedSupervisorError> {
        let mut buffer = LineBuffer::new();
        format_failure_line(&mut buffer, service, pid)
            .map_err(|_| ConvergedSupervisorError::Supervisor(SupervisorError::UnknownService))?;
        self.emit_line(buffer.as_str())
    }

    fn emit_restart(
        &mut self,
        service: ServiceId,
        attempt: u32,
    ) -> Result<(), ConvergedSupervisorError> {
        let mut buffer = LineBuffer::new();
        format_restart_line(&mut buffer, service, attempt)
            .map_err(|_| ConvergedSupervisorError::Supervisor(SupervisorError::UnknownService))?;
        self.emit_line(buffer.as_str())
    }

    fn emit_restarted(
        &mut self,
        service: ServiceId,
        old_pid: u64,
        new_pid: u64,
    ) -> Result<(), ConvergedSupervisorError> {
        let mut buffer = LineBuffer::new();
        format_restarted_line(&mut buffer, service, old_pid, new_pid)
            .map_err(|_| ConvergedSupervisorError::Supervisor(SupervisorError::UnknownService))?;
        self.emit_line(buffer.as_str())
    }

    fn emit_restart_suppressed(
        &mut self,
        service: ServiceId,
        reason: RestartSuppressedReason,
    ) -> Result<(), ConvergedSupervisorError> {
        let mut buffer = LineBuffer::new();
        format_restart_suppressed_line(&mut buffer, service, reason)
            .map_err(|_| ConvergedSupervisorError::Supervisor(SupervisorError::UnknownService))?;
        self.emit_line(buffer.as_str())
    }

    fn emit_health_healthy(
        &mut self,
        service: ServiceId,
        generation: InstanceGeneration,
    ) -> Result<(), ConvergedSupervisorError> {
        let mut buffer = LineBuffer::new();
        format_health_healthy_line(&mut buffer, service, generation)
            .map_err(|_| ConvergedSupervisorError::Supervisor(SupervisorError::UnknownService))?;
        self.emit_line(buffer.as_str())
    }

    fn emit_health_unhealthy(
        &mut self,
        service: ServiceId,
        reason: clean_slate_service_lifecycle::HealthFailureReason,
    ) -> Result<(), ConvergedSupervisorError> {
        let mut buffer = LineBuffer::new();
        format_health_unhealthy_line(&mut buffer, service, reason)
            .map_err(|_| ConvergedSupervisorError::Supervisor(SupervisorError::UnknownService))?;
        self.emit_line(buffer.as_str())
    }

    fn emit_dependency_ready(
        &mut self,
        service: ServiceId,
    ) -> Result<(), ConvergedSupervisorError> {
        let mut buffer = LineBuffer::new();
        format_dependency_ready_line(&mut buffer, service)
            .map_err(|_| ConvergedSupervisorError::Supervisor(SupervisorError::UnknownService))?;
        self.emit_line(buffer.as_str())
    }

    fn emit_dependency_blocked(
        &mut self,
        service: ServiceId,
        reason: StartBlockReason,
    ) -> Result<(), ConvergedSupervisorError> {
        let mut buffer = LineBuffer::new();
        format_dependency_blocked_line(&mut buffer, service, reason)
            .map_err(|_| ConvergedSupervisorError::Supervisor(SupervisorError::UnknownService))?;
        self.emit_line(buffer.as_str())
    }
}

struct LineBuffer {
    bytes: [u8; 128],
    len: usize,
}

impl LineBuffer {
    const fn new() -> Self {
        Self {
            bytes: [0; 128],
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
impl<C, D, const N: usize> ConvergedSupervisor<C, D, N>
where
    C: LifecycleControl,
    D: DiagnosticSink,
{
    pub fn set_now(&mut self, now: MonotonicTicks) {
        self.set_virtual_ticks(now);
    }
}
