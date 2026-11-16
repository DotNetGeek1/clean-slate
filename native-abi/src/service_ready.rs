//! Syscall 22 `SERVICE_READY`: a service instance tells the kernel it is ready to serve.
//!
//! ```text
//! | Register | Meaning                                                                 |
//! | rdi      | detail: one service-defined status word, logged as an unverified claim  |
//! | rsi, rdx, r10, r8, r9 | reserved, must be 0                                        |
//! ```
//!
//! | Result | Meaning |
//! |--------|---------|
//! | `0` | accepted: the caller's service moved from starting to running and one ready message is pending for it |
//! | `STATUS_EINVAL` | a reserved register is non-zero |
//! | `STATUS_EACCES` | the caller is not the live instance of a declared service |
//! | `STATUS_EEXIST` | the caller's instance has already left starting (it already reported, or it is stopping) |
//!
//! There is no handle and no service-id argument: the kernel resolves the caller's pid to the
//! declared service it is the live instance of. Every refusal has no effect at all: no state
//! change, no pending message and no wake. An accepted call wakes `LIFECYCLE_WAIT` (21) callers.
//!
//! The kernel keeps at most one pending ready message per service, outside the shared
//! lifecycle event queue, so acceptance never depends on queue space.

use crate::status::{STATUS_EACCES, STATUS_EEXIST, STATUS_EINVAL};

pub const SYSCALL_NR_SERVICE_READY: u64 = 22;

/// Result of an accepted report.
pub const SERVICE_READY_ACCEPTED: u64 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceReadyResult {
    Accepted,
    /// A reserved register was non-zero.
    Malformed,
    /// The caller is not the live instance of a declared service.
    NotAServiceInstance,
    /// The caller's instance is no longer starting.
    NotStarting,
    /// Any other value.
    Unknown(u64),
}

impl ServiceReadyResult {
    pub const fn encode(self) -> u64 {
        match self {
            Self::Accepted => SERVICE_READY_ACCEPTED,
            Self::Malformed => STATUS_EINVAL,
            Self::NotAServiceInstance => STATUS_EACCES,
            Self::NotStarting => STATUS_EEXIST,
            Self::Unknown(raw) => raw,
        }
    }

    pub const fn decode(raw: u64) -> Self {
        match raw {
            SERVICE_READY_ACCEPTED => Self::Accepted,
            STATUS_EINVAL => Self::Malformed,
            STATUS_EACCES => Self::NotAServiceInstance,
            STATUS_EEXIST => Self::NotStarting,
            other => Self::Unknown(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::SYSCALL_NR_LIFECYCLE_WAIT;
    use crate::status::{is_status, STATUS_ENOSYS};
    use clean_slate_capability::syscall_abi::{
        SYSCALL_NR_CAP_AUDIT_READ, SYSCALL_NR_CAP_DELEGATE, SYSCALL_NR_CAP_GRANT,
        SYSCALL_NR_CAP_OBJECT, SYSCALL_NR_CAP_PROCESS_CONTROL, SYSCALL_NR_CAP_REVOKE,
        SYSCALL_NR_DISPLAY, SYSCALL_NR_INPUT, SYSCALL_NR_NETWORK_CAPABILITY,
        SYSCALL_NR_NETWORK_REQUEST, SYSCALL_NR_SERVICE_PORT, SYSCALL_NR_SHARED_BUFFER,
        SYSCALL_NR_WORK_SET,
    };

    #[test]
    fn number_collides_with_no_native_syscall() {
        // 0..=7 are the kernel-local native numbers (version .. block request).
        let taken = [
            SYSCALL_NR_CAP_OBJECT,
            SYSCALL_NR_CAP_PROCESS_CONTROL,
            SYSCALL_NR_CAP_DELEGATE,
            SYSCALL_NR_CAP_REVOKE,
            SYSCALL_NR_CAP_AUDIT_READ,
            SYSCALL_NR_CAP_GRANT,
            SYSCALL_NR_NETWORK_CAPABILITY,
            SYSCALL_NR_NETWORK_REQUEST,
            SYSCALL_NR_SHARED_BUFFER,
            SYSCALL_NR_SERVICE_PORT,
            SYSCALL_NR_DISPLAY,
            SYSCALL_NR_INPUT,
            SYSCALL_NR_WORK_SET,
            SYSCALL_NR_LIFECYCLE_WAIT,
        ];
        const _: () = assert!(SYSCALL_NR_SERVICE_READY > 7);
        assert!(!taken.contains(&SYSCALL_NR_SERVICE_READY));
        assert_eq!(SYSCALL_NR_SERVICE_READY, SYSCALL_NR_LIFECYCLE_WAIT + 1);
    }

    #[test]
    fn results_round_trip_and_refusals_are_distinct_statuses() {
        let known = [
            ServiceReadyResult::Accepted,
            ServiceReadyResult::Malformed,
            ServiceReadyResult::NotAServiceInstance,
            ServiceReadyResult::NotStarting,
        ];
        for (index, result) in known.iter().enumerate() {
            assert_eq!(ServiceReadyResult::decode(result.encode()), *result);
            for other in &known[index + 1..] {
                assert_ne!(result.encode(), other.encode());
            }
            assert_eq!(
                is_status(result.encode()),
                *result != ServiceReadyResult::Accepted
            );
        }
        assert_eq!(
            ServiceReadyResult::decode(STATUS_ENOSYS),
            ServiceReadyResult::Unknown(STATUS_ENOSYS)
        );
        assert_eq!(
            ServiceReadyResult::decode(1),
            ServiceReadyResult::Unknown(1)
        );
    }
}
