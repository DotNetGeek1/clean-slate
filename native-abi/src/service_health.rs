//! Syscall 29 `SERVICE_HEALTH` (#376): a running service instance tells init it is still
//! serving.
//!
//! ```text
//! | Register | Meaning                                                                    |
//! | rdi      | status: [`HEALTH_STATUS_OK`], [`HEALTH_STATUS_DEGRADED`] or [`HEALTH_STATUS_UNHEALTHY`] |
//! | rsi, rdx, r10, r8, r9 | reserved, must be 0                                           |
//! ```
//!
//! | Result | Meaning |
//! |--------|---------|
//! | `0` | accepted: one health message is pending for the caller's service |
//! | `STATUS_EINVAL` | an unknown status, or a reserved register is non-zero |
//! | `STATUS_EACCES` | the caller is not the live instance of a declared service |
//! | `STATUS_EAGAIN` | the caller's instance is not running (it has not reported ready yet, or it is stopping) |
//!
//! There is no handle: as with `SERVICE_READY` (22), the kernel resolves the caller's pid to
//! the declared service it is the live instance of. A refusal has no effect. An accepted report
//! wakes `LIFECYCLE_WAIT` (21) callers, and init reads it with `LIFECYCLE_POLL` (5) as a
//! `HealthReported` lifecycle event whose `status_code` is the status.
//!
//! The kernel keeps at most one pending health message per service, outside the shared
//! lifecycle event queue: a newer report replaces one init has not read yet, so a service that
//! reports faster than init reads costs nothing and never crowds out exits and faults.
//!
//! A service whose manifest row declares a liveness period reports at least every
//! [`HEALTH_REPORT_INTERVAL_NS`] from its own loop (the runtime's `health::Heartbeat`), so a
//! loop that stops turning stops the reports. Init terminates an instance that has sent none
//! for a whole period, or that reported itself unhealthy, and the row's restart policy applies
//! to that end like any other.

use crate::status::{STATUS_EACCES, STATUS_EAGAIN, STATUS_EINVAL};

pub const SYSCALL_NR_SERVICE_HEALTH: u64 = 29;

/// Result of an accepted report.
pub const SERVICE_HEALTH_ACCEPTED: u64 = 0;

/// `rdi`: serving normally.
pub const HEALTH_STATUS_OK: u64 = 1;
/// `rdi`: serving, with something the service itself counts as wrong. Counts as a report.
pub const HEALTH_STATUS_DEGRADED: u64 = 2;
/// `rdi`: not able to serve; init ends the instance at once.
pub const HEALTH_STATUS_UNHEALTHY: u64 = 3;

/// How often a service with a liveness period reports from its loop. A row's period must be
/// at least [`MIN_LIVENESS_REPORTS`] of these, so one late wake is never a missed period.
pub const HEALTH_REPORT_INTERVAL_NS: u64 = 1_000_000_000;

/// The fewest report intervals a liveness period may span.
pub const MIN_LIVENESS_REPORTS: u64 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceHealthResult {
    Accepted,
    /// An unknown status, or a reserved register was non-zero.
    Malformed,
    /// The caller is not the live instance of a declared service.
    NotAServiceInstance,
    /// The caller's instance is not running.
    NotRunning,
    /// Any other value.
    Unknown(u64),
}

impl ServiceHealthResult {
    pub const fn encode(self) -> u64 {
        match self {
            Self::Accepted => SERVICE_HEALTH_ACCEPTED,
            Self::Malformed => STATUS_EINVAL,
            Self::NotAServiceInstance => STATUS_EACCES,
            Self::NotRunning => STATUS_EAGAIN,
            Self::Unknown(raw) => raw,
        }
    }

    pub const fn decode(raw: u64) -> Self {
        match raw {
            SERVICE_HEALTH_ACCEPTED => Self::Accepted,
            STATUS_EINVAL => Self::Malformed,
            STATUS_EACCES => Self::NotAServiceInstance,
            STATUS_EAGAIN => Self::NotRunning,
            other => Self::Unknown(other),
        }
    }
}

/// Whether `raw` is a status a caller may report.
pub const fn is_reportable_status(raw: u64) -> bool {
    matches!(
        raw,
        HEALTH_STATUS_OK | HEALTH_STATUS_DEGRADED | HEALTH_STATUS_UNHEALTHY
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SYSCALL_NR_CLOCK;
    use crate::console::SYSCALL_NR_CONSOLE_DEVICE;
    use crate::lifecycle::SYSCALL_NR_LIFECYCLE_WAIT;
    use crate::memory::SYSCALL_NR_MEMORY;
    use crate::service_ready::SYSCALL_NR_SERVICE_READY;
    use crate::service_stop::SYSCALL_NR_SERVICE_STOP;
    use crate::status::{is_status, STATUS_ENOSYS};

    #[test]
    fn number_follows_the_stop_notice_power_and_resources() {
        let taken = [
            SYSCALL_NR_LIFECYCLE_WAIT,
            SYSCALL_NR_SERVICE_READY,
            SYSCALL_NR_MEMORY,
            SYSCALL_NR_CLOCK,
            SYSCALL_NR_CONSOLE_DEVICE,
            SYSCALL_NR_SERVICE_STOP,
        ];
        assert!(!taken.contains(&SYSCALL_NR_SERVICE_HEALTH));
        // 26 is the power call (#372), 28 the resource snapshot (#379).
        assert_eq!(SYSCALL_NR_SERVICE_HEALTH, SYSCALL_NR_SERVICE_STOP + 2);
    }

    #[test]
    fn results_round_trip_and_refusals_are_distinct_statuses() {
        let known = [
            ServiceHealthResult::Accepted,
            ServiceHealthResult::Malformed,
            ServiceHealthResult::NotAServiceInstance,
            ServiceHealthResult::NotRunning,
        ];
        for (index, result) in known.iter().enumerate() {
            assert_eq!(ServiceHealthResult::decode(result.encode()), *result);
            for other in &known[index + 1..] {
                assert_ne!(result.encode(), other.encode());
            }
            assert_eq!(
                is_status(result.encode()),
                *result != ServiceHealthResult::Accepted
            );
        }
        assert_eq!(
            ServiceHealthResult::decode(STATUS_ENOSYS),
            ServiceHealthResult::Unknown(STATUS_ENOSYS)
        );
    }

    #[test]
    fn only_the_three_statuses_are_reportable() {
        assert!(!is_reportable_status(0));
        assert!(is_reportable_status(HEALTH_STATUS_OK));
        assert!(is_reportable_status(HEALTH_STATUS_DEGRADED));
        assert!(is_reportable_status(HEALTH_STATUS_UNHEALTHY));
        assert!(!is_reportable_status(4));
        assert!(!is_reportable_status(u64::MAX));
    }
}
