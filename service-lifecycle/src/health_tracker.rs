//! Supervisor-side health/liveness tracking (M4.4).
//!
//! Timeout evaluation is isolated from restart policy (#40) and dependency graphs (#39).

use crate::health::{HealthReport, HealthStatus};
use crate::identity::{InstanceGeneration, ServiceId};
use crate::state::LifecycleEventKind;
use crate::time::{ticks_add, ticks_reached, LivenessConfig, MonotonicTicks};

/// Why a watched service instance is considered unhealthy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthFailureReason {
    LivenessTimeout,
    ProcessExited { status_code: u32 },
    ProcessFaulted { status_code: u32 },
    SelfReportedUnhealthy,
}

impl HealthFailureReason {
    /// Stable `reason=` token for `[HLTH]` diagnostics.
    pub const fn diagnostic_token(self) -> &'static str {
        match self {
            Self::LivenessTimeout => "timeout",
            Self::ProcessExited { .. } => "exit",
            Self::ProcessFaulted { .. } => "fault",
            Self::SelfReportedUnhealthy => "self_reported",
        }
    }
}

/// Deterministic failure notification for supervisor integration (#37).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HealthFailureEvent {
    pub service: ServiceId,
    pub generation: InstanceGeneration,
    pub reason: HealthFailureReason,
    pub observed_at: MonotonicTicks,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthReportOutcome {
    AcceptedHealthy {
        generation: InstanceGeneration,
    },
    AcceptedDegraded {
        generation: InstanceGeneration,
    },
    MarkedUnhealthy {
        generation: InstanceGeneration,
        reason: HealthFailureReason,
    },
    IgnoredStale {
        report_generation: InstanceGeneration,
        active_generation: InstanceGeneration,
    },
    IgnoredNoActiveInstance,
    IgnoredUnknownService,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleFailureOutcome {
    MarkedUnhealthy(HealthFailureEvent),
    IgnoredStale {
        observed: InstanceGeneration,
        active: InstanceGeneration,
    },
    IgnoredNoActiveInstance,
    IgnoredUnknownService,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WatchState {
    Healthy,
    Degraded,
    Failed(HealthFailureReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceHealthRecord {
    service: ServiceId,
    active_generation: Option<InstanceGeneration>,
    watch: Option<WatchState>,
    last_report_ticks: Option<MonotonicTicks>,
    deadline_ticks: Option<MonotonicTicks>,
}

impl ServiceHealthRecord {
    pub const fn new(service: ServiceId) -> Self {
        Self {
            service,
            active_generation: None,
            watch: None,
            last_report_ticks: None,
            deadline_ticks: None,
        }
    }

    pub const fn service(self) -> ServiceId {
        self.service
    }

    pub const fn active_generation(self) -> Option<InstanceGeneration> {
        self.active_generation
    }

    pub const fn deadline_ticks(self) -> Option<MonotonicTicks> {
        self.deadline_ticks
    }

    pub const fn is_healthy(self) -> bool {
        matches!(
            self.watch,
            Some(WatchState::Healthy) | Some(WatchState::Degraded)
        )
    }

    pub const fn failure_reason(self) -> Option<HealthFailureReason> {
        match self.watch {
            Some(WatchState::Failed(reason)) => Some(reason),
            _ => None,
        }
    }

    /// Starts or replaces liveness tracking for `generation` at `now`.
    pub fn begin_instance(
        &mut self,
        generation: InstanceGeneration,
        now: MonotonicTicks,
        config: LivenessConfig,
    ) {
        self.active_generation = Some(generation);
        self.watch = None;
        self.last_report_ticks = None;
        self.deadline_ticks = Some(ticks_add(now, config.report_period_ticks));
    }

    pub fn clear_active_instance(&mut self) {
        self.active_generation = None;
        self.watch = None;
        self.last_report_ticks = None;
        self.deadline_ticks = None;
    }

    pub fn apply_report(
        &mut self,
        report: HealthReport,
        now: MonotonicTicks,
        config: LivenessConfig,
    ) -> HealthReportOutcome {
        if report.service != self.service {
            return HealthReportOutcome::IgnoredUnknownService;
        }
        let Some(active) = self.active_generation else {
            return HealthReportOutcome::IgnoredNoActiveInstance;
        };
        if report.generation != active {
            return HealthReportOutcome::IgnoredStale {
                report_generation: report.generation,
                active_generation: active,
            };
        }

        self.last_report_ticks = Some(now);

        if matches!(report.status, HealthStatus::Unhealthy) {
            let reason = HealthFailureReason::SelfReportedUnhealthy;
            self.watch = Some(WatchState::Failed(reason));
            self.deadline_ticks = None;
            return HealthReportOutcome::MarkedUnhealthy {
                generation: active,
                reason,
            };
        }

        if !report_counts_for_liveness(report.status) {
            return HealthReportOutcome::IgnoredNoActiveInstance;
        }

        self.deadline_ticks = Some(ticks_add(now, config.report_period_ticks));
        match report.status {
            HealthStatus::Ok => {
                self.watch = Some(WatchState::Healthy);
                HealthReportOutcome::AcceptedHealthy { generation: active }
            }
            HealthStatus::Degraded => {
                self.watch = Some(WatchState::Degraded);
                HealthReportOutcome::AcceptedDegraded { generation: active }
            }
            HealthStatus::Unknown => {
                if self.watch.is_none() {
                    self.watch = Some(WatchState::Healthy);
                }
                HealthReportOutcome::AcceptedHealthy { generation: active }
            }
            HealthStatus::Unhealthy => unreachable!(),
        }
    }

    pub fn notify_lifecycle_failure(
        &mut self,
        generation: InstanceGeneration,
        kind: LifecycleEventKind,
        status_code: u32,
        now: MonotonicTicks,
    ) -> LifecycleFailureOutcome {
        let Some(active) = self.active_generation else {
            return LifecycleFailureOutcome::IgnoredNoActiveInstance;
        };
        if generation != active {
            return LifecycleFailureOutcome::IgnoredStale {
                observed: generation,
                active,
            };
        }

        let reason = match kind {
            LifecycleEventKind::Exited => HealthFailureReason::ProcessExited { status_code },
            LifecycleEventKind::Faulted => HealthFailureReason::ProcessFaulted { status_code },
            _ => return LifecycleFailureOutcome::IgnoredNoActiveInstance,
        };
        self.watch = Some(WatchState::Failed(reason));
        self.deadline_ticks = None;
        let event = HealthFailureEvent {
            service: self.service,
            generation: active,
            reason,
            observed_at: now,
        };
        LifecycleFailureOutcome::MarkedUnhealthy(event)
    }

    pub fn poll_timeout(&mut self, now: MonotonicTicks) -> Option<HealthFailureEvent> {
        if matches!(self.watch, Some(WatchState::Failed(_))) {
            return None;
        }
        let deadline = self.deadline_ticks?;
        if !ticks_reached(now, deadline) {
            return None;
        }
        let generation = self.active_generation?;
        let reason = HealthFailureReason::LivenessTimeout;
        self.watch = Some(WatchState::Failed(reason));
        self.deadline_ticks = None;
        Some(HealthFailureEvent {
            service: self.service,
            generation,
            reason,
            observed_at: now,
        })
    }
}

const fn report_counts_for_liveness(status: HealthStatus) -> bool {
    matches!(
        status,
        HealthStatus::Ok | HealthStatus::Degraded | HealthStatus::Unknown
    )
}

/// Fixed-capacity registry mirroring `ServiceLifecycleTracker`.
pub struct ServiceHealthTracker<const N: usize> {
    records: [Option<ServiceHealthRecord>; N],
}

impl<const N: usize> Default for ServiceHealthTracker<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ServiceHealthTracker<N> {
    pub const fn new() -> Self {
        Self { records: [None; N] }
    }

    pub fn register(&mut self, service: ServiceId) -> Result<(), HealthTrackerError> {
        if self.find(service).is_some() {
            return Err(HealthTrackerError::DuplicateService);
        }
        let slot = self
            .records
            .iter()
            .position(|entry| entry.is_none())
            .ok_or(HealthTrackerError::CapacityExceeded)?;
        self.records[slot] = Some(ServiceHealthRecord::new(service));
        Ok(())
    }

    pub fn record_mut(
        &mut self,
        service: ServiceId,
    ) -> Result<&mut ServiceHealthRecord, HealthTrackerError> {
        let index = self
            .find(service)
            .ok_or(HealthTrackerError::UnknownService)?;
        self.records[index]
            .as_mut()
            .ok_or(HealthTrackerError::UnknownService)
    }

    pub fn poll_timeouts<F>(&mut self, now: MonotonicTicks, mut emit: F)
    where
        F: FnMut(HealthFailureEvent),
    {
        for entry in self.records.iter_mut().flatten() {
            if let Some(event) = entry.poll_timeout(now) {
                emit(event);
            }
        }
    }

    fn find(&self, service: ServiceId) -> Option<usize> {
        self.records
            .iter()
            .position(|entry| matches!(entry, Some(record) if record.service == service))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthTrackerError {
    DuplicateService,
    UnknownService,
    CapacityExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;
    const PERIOD: LivenessConfig = LivenessConfig::new(100);

    fn svc(id: u32) -> ServiceId {
        ServiceId(id)
    }

    #[test]
    fn healthy_report_advances_deadline() {
        let mut record = ServiceHealthRecord::new(svc(1));
        record.begin_instance(InstanceGeneration(1), 10, PERIOD);
        let outcome = record.apply_report(
            HealthReport::new(svc(1), InstanceGeneration(1), HealthStatus::Ok),
            50,
            PERIOD,
        );
        assert_eq!(
            outcome,
            HealthReportOutcome::AcceptedHealthy {
                generation: InstanceGeneration(1)
            }
        );
        assert!(record.is_healthy());
        assert_eq!(record.deadline_ticks(), Some(150));
        assert!(record.poll_timeout(149).is_none());
        assert!(record
            .poll_timeout(150)
            .is_some_and(|event| event.reason == HealthFailureReason::LivenessTimeout));
    }

    #[test]
    fn missing_reports_produce_timeout_failure() {
        let mut record = ServiceHealthRecord::new(svc(2));
        record.begin_instance(InstanceGeneration(1), 0, PERIOD);
        let event = record.poll_timeout(100).expect("timeout at deadline");
        assert_eq!(event.reason, HealthFailureReason::LivenessTimeout);
        assert_eq!(event.generation, InstanceGeneration(1));
        assert_eq!(
            record.failure_reason(),
            Some(HealthFailureReason::LivenessTimeout)
        );
        assert!(record.poll_timeout(200).is_none());
    }

    #[test]
    fn stale_generation_report_is_ignored() {
        let mut record = ServiceHealthRecord::new(svc(3));
        record.begin_instance(InstanceGeneration(2), 0, PERIOD);
        let outcome = record.apply_report(
            HealthReport::new(svc(3), InstanceGeneration(1), HealthStatus::Ok),
            10,
            PERIOD,
        );
        assert_eq!(
            outcome,
            HealthReportOutcome::IgnoredStale {
                report_generation: InstanceGeneration(1),
                active_generation: InstanceGeneration(2),
            }
        );
        assert!(!record.is_healthy());
        let event = record.poll_timeout(100).expect("still times out");
        assert_eq!(event.reason, HealthFailureReason::LivenessTimeout);
    }

    #[test]
    fn replacement_instance_resets_watch() {
        let mut record = ServiceHealthRecord::new(svc(4));
        record.begin_instance(InstanceGeneration(1), 0, PERIOD);
        assert!(matches!(
            record.apply_report(
                HealthReport::new(svc(4), InstanceGeneration(1), HealthStatus::Ok),
                40,
                PERIOD,
            ),
            HealthReportOutcome::AcceptedHealthy { .. }
        ));
        record.begin_instance(InstanceGeneration(2), 200, PERIOD);
        let stale = record.apply_report(
            HealthReport::new(svc(4), InstanceGeneration(1), HealthStatus::Ok),
            210,
            PERIOD,
        );
        assert!(matches!(stale, HealthReportOutcome::IgnoredStale { .. }));
        assert!(!record.is_healthy());
        assert_eq!(record.deadline_ticks(), Some(300));
        assert!(matches!(
            record.apply_report(
                HealthReport::new(svc(4), InstanceGeneration(2), HealthStatus::Ok),
                220,
                PERIOD,
            ),
            HealthReportOutcome::AcceptedHealthy { .. }
        ));
        assert!(record.is_healthy());
        assert_eq!(record.deadline_ticks(), Some(320));
    }

    #[test]
    fn explicit_fault_marks_failed_without_waiting_for_timeout() {
        let mut record = ServiceHealthRecord::new(svc(5));
        record.begin_instance(InstanceGeneration(1), 0, PERIOD);
        let outcome = record.notify_lifecycle_failure(
            InstanceGeneration(1),
            LifecycleEventKind::Faulted,
            9,
            5,
        );
        let LifecycleFailureOutcome::MarkedUnhealthy(event) = outcome else {
            panic!("expected fault failure");
        };
        assert_eq!(
            event.reason,
            HealthFailureReason::ProcessFaulted { status_code: 9 }
        );
        assert!(record.poll_timeout(10_000).is_none());
    }

    #[test]
    fn explicit_exit_ignored_when_stale_generation() {
        let mut record = ServiceHealthRecord::new(svc(6));
        record.begin_instance(InstanceGeneration(2), 0, PERIOD);
        let outcome = record.notify_lifecycle_failure(
            InstanceGeneration(1),
            LifecycleEventKind::Exited,
            0,
            1,
        );
        assert!(matches!(
            outcome,
            LifecycleFailureOutcome::IgnoredStale { .. }
        ));
        assert!(record.failure_reason().is_none());
    }

    #[test]
    fn tracker_registers_and_polls_multiple_services() {
        let mut tracker = ServiceHealthTracker::<4>::new();
        tracker.register(svc(10)).expect("a");
        tracker.register(svc(11)).expect("b");
        tracker
            .record_mut(svc(10))
            .expect("a")
            .begin_instance(InstanceGeneration(1), 0, PERIOD);
        tracker
            .record_mut(svc(11))
            .expect("b")
            .begin_instance(InstanceGeneration(1), 0, PERIOD);
        let mut events = 0u32;
        tracker.poll_timeouts(100, |_| events += 1);
        assert_eq!(events, 2);
    }

    #[test]
    fn self_reported_unhealthy_is_immediate() {
        let mut record = ServiceHealthRecord::new(svc(7));
        record.begin_instance(InstanceGeneration(1), 0, PERIOD);
        let outcome = record.apply_report(
            HealthReport::new(svc(7), InstanceGeneration(1), HealthStatus::Unhealthy),
            1,
            PERIOD,
        );
        assert!(matches!(
            outcome,
            HealthReportOutcome::MarkedUnhealthy {
                reason: HealthFailureReason::SelfReportedUnhealthy,
                ..
            }
        ));
    }

    #[test]
    fn lifecycle_event_kinds_other_than_exit_fault_do_not_mark_failed() {
        let mut record = ServiceHealthRecord::new(svc(8));
        record.begin_instance(InstanceGeneration(1), 0, PERIOD);
        let outcome =
            record.notify_lifecycle_failure(InstanceGeneration(1), LifecycleEventKind::Ready, 0, 1);
        assert_eq!(outcome, LifecycleFailureOutcome::IgnoredNoActiveInstance);
    }
}
