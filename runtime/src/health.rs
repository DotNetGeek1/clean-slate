//! The service health report (syscall 29, #376) and a heartbeat that sends it from the
//! service's own loop.
//!
//! A row whose manifest declares a liveness period must report at least every
//! `HEALTH_REPORT_INTERVAL_NS`, or init ends the instance as hung. Report from the loop that
//! does the service's work, never from a thread or timer of its own: the point is that a loop
//! that stops turning stops the reports.
//!
//! ```ignore
//! let mut heartbeat = Heartbeat::new(port::now(&mut Kernel)?);
//! loop {
//!     // ... drain the work ...
//!     let now = port::now(&mut Kernel)?;
//!     heartbeat.beat(&mut Kernel, now);
//!     match work_set.wait(&mut Kernel, mask, Wait::Until(heartbeat.deadline())) {
//!         Ok(_) | Err(Error::TimedOut) => {}
//!         Err(_) => /* fail */,
//!     }
//! }
//! ```

use clean_slate_native_abi::service_health::{
    ServiceHealthResult, HEALTH_REPORT_INTERVAL_NS, HEALTH_STATUS_DEGRADED, HEALTH_STATUS_OK,
    HEALTH_STATUS_UNHEALTHY, SYSCALL_NR_SERVICE_HEALTH,
};

use crate::port::Deadline;
use crate::Syscalls;

/// What a service says about itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Health {
    Ok,
    /// Serving, with something the service counts as wrong. Init treats it as a report.
    Degraded,
    /// Not able to serve: init ends the instance at once and applies its restart policy.
    Unhealthy,
}

impl Health {
    const fn raw(self) -> u64 {
        match self {
            Self::Ok => HEALTH_STATUS_OK,
            Self::Degraded => HEALTH_STATUS_DEGRADED,
            Self::Unhealthy => HEALTH_STATUS_UNHEALTHY,
        }
    }
}

/// Reports `health` for this service instance. Refused (and harmless) before the instance has
/// reported ready, while it is stopping, and from a process that is not a service instance.
pub fn report<S: Syscalls>(sys: &mut S, health: Health) -> ServiceHealthResult {
    ServiceHealthResult::decode(
        sys.syscall(SYSCALL_NR_SERVICE_HEALTH, [health.raw(), 0, 0, 0, 0, 0]),
    )
}

/// Sends [`Health::Ok`] once every `HEALTH_REPORT_INTERVAL_NS` from the caller's loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Heartbeat {
    due_ns: u64,
}

impl Heartbeat {
    /// A heartbeat whose first report is due at `now_ns`.
    pub const fn new(now_ns: u64) -> Self {
        Self { due_ns: now_ns }
    }

    /// When the next report is due: the latest a loop that waits should wake.
    pub const fn deadline(&self) -> Deadline {
        Deadline::at(self.due_ns)
    }

    /// Reports when one is due at `now_ns`, and returns the kernel's answer; `None` when none
    /// was due. The next is due an interval after `now_ns`, so a late wake does not bunch them.
    pub fn beat<S: Syscalls>(&mut self, sys: &mut S, now_ns: u64) -> Option<ServiceHealthResult> {
        if now_ns < self.due_ns {
            return None;
        }
        self.due_ns = now_ns.saturating_add(HEALTH_REPORT_INTERVAL_NS);
        Some(report(sys, Health::Ok))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeKernel;
    use clean_slate_native_abi::status::STATUS_EAGAIN;

    const SECOND: u64 = 1_000_000_000;

    fn health_calls(kernel: &FakeKernel) -> Vec<[u64; 6]> {
        kernel
            .calls()
            .iter()
            .filter(|(nr, _)| *nr == SYSCALL_NR_SERVICE_HEALTH)
            .map(|(_, args)| *args)
            .collect()
    }

    #[test]
    fn report_names_the_status_and_decodes_the_answer() {
        let mut kernel = FakeKernel::new();
        kernel.answer_next(SYSCALL_NR_SERVICE_HEALTH, 0);
        kernel.answer_next(SYSCALL_NR_SERVICE_HEALTH, STATUS_EAGAIN);
        assert_eq!(
            report(&mut kernel, Health::Degraded),
            ServiceHealthResult::Accepted
        );
        assert_eq!(
            report(&mut kernel, Health::Unhealthy),
            ServiceHealthResult::NotRunning
        );
        assert_eq!(
            health_calls(&kernel),
            [
                [HEALTH_STATUS_DEGRADED, 0, 0, 0, 0, 0],
                [HEALTH_STATUS_UNHEALTHY, 0, 0, 0, 0, 0]
            ]
        );
    }

    #[test]
    fn a_heartbeat_reports_once_per_interval_however_often_the_loop_turns() {
        let mut kernel = FakeKernel::new();
        let mut heartbeat = Heartbeat::new(5 * SECOND);
        assert_eq!(heartbeat.deadline(), Deadline::at(5 * SECOND));
        for _ in 0..3 {
            kernel.answer_next(SYSCALL_NR_SERVICE_HEALTH, 0);
        }
        // Due at once.
        assert_eq!(
            heartbeat.beat(&mut kernel, 5 * SECOND),
            Some(ServiceHealthResult::Accepted)
        );
        // A busy loop turning within the interval does not report again.
        for step in 1..10 {
            assert_eq!(heartbeat.beat(&mut kernel, 5 * SECOND + step * 100), None);
        }
        assert_eq!(heartbeat.deadline(), Deadline::at(6 * SECOND));
        // A late wake reports once and counts the next interval from then.
        assert!(heartbeat.beat(&mut kernel, 8 * SECOND).is_some());
        assert_eq!(heartbeat.deadline(), Deadline::at(9 * SECOND));
        assert!(heartbeat.beat(&mut kernel, 9 * SECOND).is_some());
        assert_eq!(
            health_calls(&kernel),
            [[HEALTH_STATUS_OK, 0, 0, 0, 0, 0]; 3]
        );
    }

    #[test]
    fn a_heartbeat_at_clock_zero_still_has_a_deadline() {
        // The kernel reads deadline 0 as "never": a report due at 0 must not sleep forever.
        assert_eq!(Heartbeat::new(0).deadline(), Deadline::at(1));
    }
}
