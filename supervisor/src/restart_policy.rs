//! M4.6 userspace restart policy and bounded crash-loop state (host-testable).

use clean_slate_service_lifecycle::{ticks_add, MonotonicTicks};

/// Whether and how a supervised service may be restarted after failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartPolicy {
    Never,
    OnFailure(BoundedRestart),
}

/// Deterministic bounded retry with linearly increasing backoff ticks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundedRestart {
    pub max_attempts: u32,
    pub backoff_base_ticks: u64,
}

impl BoundedRestart {
    pub const fn new(max_attempts: u32, backoff_base_ticks: u64) -> Self {
        Self {
            max_attempts,
            backoff_base_ticks,
        }
    }
}

/// Why a restart was not attempted after failure detection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartSuppressedReason {
    PolicyNever,
    RetryExhausted,
    DependencyBlocked,
}

impl RestartSuppressedReason {
    pub const fn diagnostic_token(self) -> &'static str {
        match self {
            Self::PolicyNever => "never",
            Self::RetryExhausted => "exhausted",
            Self::DependencyBlocked => "dependency",
        }
    }
}

/// Per-service restart bookkeeping (non-persistent across reboot).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryRuntime {
    policy: RestartPolicy,
    attempts: u32,
    pending: bool,
    not_before: MonotonicTicks,
    failed_pid: Option<u64>,
}

impl RecoveryRuntime {
    pub const fn new(policy: RestartPolicy) -> Self {
        Self {
            policy,
            attempts: 0,
            pending: false,
            not_before: 0,
            failed_pid: None,
        }
    }

    pub const fn policy(self) -> RestartPolicy {
        self.policy
    }

    pub const fn attempts(self) -> u32 {
        self.attempts
    }

    pub const fn pending(self) -> bool {
        self.pending
    }

    pub const fn failed_pid(self) -> Option<u64> {
        self.failed_pid
    }

    pub const fn not_before(self) -> MonotonicTicks {
        self.not_before
    }

    /// Records failure and schedules or suppresses the next restart attempt.
    pub fn on_failure(&mut self, failed_pid: Option<u64>, now: MonotonicTicks) -> RestartDecision {
        self.failed_pid = failed_pid;
        match self.policy {
            RestartPolicy::Never => {
                self.pending = false;
                RestartDecision::Suppressed(RestartSuppressedReason::PolicyNever)
            }
            RestartPolicy::OnFailure(limits) => {
                if self.attempts >= limits.max_attempts {
                    self.pending = false;
                    return RestartDecision::Suppressed(RestartSuppressedReason::RetryExhausted);
                }
                let next_attempt = self.attempts.saturating_add(1);
                let delay = limits
                    .backoff_base_ticks
                    .saturating_mul(u64::from(next_attempt.saturating_sub(1)));
                self.not_before = ticks_add(now, delay);
                self.pending = true;
                RestartDecision::Scheduled {
                    attempt: next_attempt,
                    not_before: self.not_before,
                }
            }
        }
    }

    pub fn suppress_dependency_blocked(&mut self) -> RestartDecision {
        RestartDecision::Suppressed(RestartSuppressedReason::DependencyBlocked)
    }

    pub fn clear_pending_after_attempt(&mut self) {
        self.pending = false;
    }

    pub fn record_attempt_started(&mut self, attempt: u32) {
        self.attempts = attempt;
    }

    /// Successful running instance clears crash-loop counters.
    pub fn on_healthy_instance(&mut self) {
        self.attempts = 0;
        self.pending = false;
        self.failed_pid = None;
        self.not_before = 0;
    }

    pub fn set_policy(&mut self, policy: RestartPolicy) {
        self.policy = policy;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartDecision {
    Suppressed(RestartSuppressedReason),
    Scheduled {
        attempt: u32,
        not_before: MonotonicTicks,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_service_lifecycle::ticks_reached;

    #[test]
    fn never_policy_suppresses() {
        let mut runtime = RecoveryRuntime::new(RestartPolicy::Never);
        assert_eq!(
            runtime.on_failure(Some(10), 0),
            RestartDecision::Suppressed(RestartSuppressedReason::PolicyNever)
        );
        assert!(!runtime.pending());
    }

    #[test]
    fn bounded_policy_schedules_with_increasing_backoff() {
        let limits = BoundedRestart::new(3, 10);
        let mut runtime = RecoveryRuntime::new(RestartPolicy::OnFailure(limits));
        assert_eq!(
            runtime.on_failure(Some(1), 5),
            RestartDecision::Scheduled {
                attempt: 1,
                not_before: 5,
            }
        );
        runtime.record_attempt_started(1);
        runtime.clear_pending_after_attempt();
        assert_eq!(
            runtime.on_failure(Some(1), 5),
            RestartDecision::Scheduled {
                attempt: 2,
                not_before: 15,
            }
        );
    }

    #[test]
    fn exhaustion_after_max_attempts() {
        let limits = BoundedRestart::new(2, 1);
        let mut runtime = RecoveryRuntime::new(RestartPolicy::OnFailure(limits));
        runtime.on_failure(Some(1), 0);
        runtime.record_attempt_started(1);
        runtime.clear_pending_after_attempt();
        runtime.on_failure(Some(1), 0);
        runtime.record_attempt_started(2);
        runtime.clear_pending_after_attempt();
        assert_eq!(
            runtime.on_failure(Some(1), 0),
            RestartDecision::Suppressed(RestartSuppressedReason::RetryExhausted)
        );
    }

    #[test]
    fn healthy_instance_resets_counters() {
        let limits = BoundedRestart::new(3, 5);
        let mut runtime = RecoveryRuntime::new(RestartPolicy::OnFailure(limits));
        runtime.on_failure(Some(9), 0);
        runtime.record_attempt_started(1);
        runtime.on_healthy_instance();
        assert_eq!(runtime.attempts(), 0);
        assert_eq!(
            runtime.on_failure(Some(9), 100),
            RestartDecision::Scheduled {
                attempt: 1,
                not_before: 100,
            }
        );
    }

    #[test]
    fn scheduled_not_before_gates_attempts() {
        let limits = BoundedRestart::new(3, 10);
        let mut runtime = RecoveryRuntime::new(RestartPolicy::OnFailure(limits));
        runtime.on_failure(Some(1), 0);
        runtime.record_attempt_started(1);
        runtime.clear_pending_after_attempt();
        let decision = runtime.on_failure(Some(1), 0);
        let RestartDecision::Scheduled { not_before, .. } = decision else {
            panic!("expected schedule");
        };
        assert!(!ticks_reached(9, not_before));
        assert!(ticks_reached(10, not_before));
    }
}
