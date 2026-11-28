//! Syscall 27 `SERVICE_STOP` (#373): a service instance learns that init asked it to stop.
//!
//! `ControlRequestKind::Stop` is graceful. The kernel moves the service to stopping, records a
//! stop deadline [`SERVICE_STOP_GRACE_NS`] after the request, sets the instance's bound
//! work-set bit, and leaves the instance running. The instance answers by finishing its work
//! and exiting (native: `process::exit`, the exit trap; Linux: `exit` or `exit_group`). The
//! kernel then queues `Exited` for init with status 0. An instance still live at the deadline
//! is terminated by the kernel, and its `Exited` carries [`STOP_EXIT_STATUS_DEADLINE`]. A fault
//! while stopping is reported as `Faulted`, as at any other time. `Terminate` stays immediate.
//!
//! The deadline is enforced the first time init's lifecycle-control holder calls
//! `LIFECYCLE_WAIT` (21) at or after it; init wakes for each stop deadline it is waiting on, so
//! that is at most one wake late.
//!
//! ```text
//! | Register | QUERY (rdi = 0)          | BIND_WAKE (rdi = 1)              |
//! | rdi      | [`SERVICE_STOP_OP_QUERY`] | [`SERVICE_STOP_OP_BIND_WAKE`]    |
//! | rsi      | reserved, must be 0       | work-set id (the caller's own)   |
//! | rdx      | reserved, must be 0       | work-set bit, 0..=31             |
//! | r10, r8, r9 | reserved, must be 0    | reserved, must be 0              |
//! ```
//!
//! | Result | Meaning |
//! |--------|---------|
//! | `0` | QUERY: no stop was asked for; BIND_WAKE: bound |
//! | `1..` (not a status) | QUERY: a stop was asked for; the value is its deadline, absolute monotonic ns (`WORK_SET` op `NOW`) |
//! | `STATUS_EACCES` | the caller is not the live instance of a declared service |
//! | `STATUS_EINVAL` | an unknown op, a reserved register is non-zero, or BIND_WAKE naming a work set or bit the caller does not own |
//!
//! There is no handle: as with `SERVICE_READY` (22), the kernel resolves the caller's pid to the
//! live instance it is. BIND_WAKE with a stop already asked for sets the bit at once; a later
//! bind replaces the earlier one, and the binding ends with the instance.

use crate::status::{is_status, STATUS_EACCES, STATUS_EINVAL, STATUS_RANGE_START};

pub const SYSCALL_NR_SERVICE_STOP: u64 = 27;

/// `rdi` op: has a stop been asked for, and by when must the instance be gone.
pub const SERVICE_STOP_OP_QUERY: u64 = 0;
/// `rdi` op: set a work-set bit when a stop is asked for.
pub const SERVICE_STOP_OP_BIND_WAKE: u64 = 1;

/// How long an instance has between the stop notice and the kernel terminating it.
pub const SERVICE_STOP_GRACE_NS: u64 = 2_000_000_000;

/// `status_code` of the `Exited` event when the kernel terminated a stopping instance at its
/// deadline. An instance that exits by itself is reported with status 0.
pub const STOP_EXIT_STATUS_DEADLINE: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopQuery {
    /// No stop was asked for.
    Running,
    /// Stop now; the kernel terminates the instance at `deadline_ns`.
    StopRequested { deadline_ns: u64 },
    /// The caller is not the live instance of a declared service.
    NotAServiceInstance,
    /// A reserved register was non-zero.
    Malformed,
    /// Any other value.
    Unknown(u64),
}

impl StopQuery {
    pub const fn encode(self) -> u64 {
        match self {
            Self::Running => 0,
            Self::StopRequested { deadline_ns } => deadline_ns,
            Self::NotAServiceInstance => STATUS_EACCES,
            Self::Malformed => STATUS_EINVAL,
            Self::Unknown(raw) => raw,
        }
    }

    pub const fn decode(raw: u64) -> Self {
        match raw {
            0 => Self::Running,
            STATUS_EACCES => Self::NotAServiceInstance,
            STATUS_EINVAL => Self::Malformed,
            raw if is_status(raw) => Self::Unknown(raw),
            deadline_ns => Self::StopRequested { deadline_ns },
        }
    }
}

/// Kernel side: the QUERY answer for a stop deadline. A deadline of 0 cannot be told apart
/// from "running", so it is reported as 1, which has passed as well; one in the status range
/// is reported as the last value below it.
pub const fn encode_deadline(deadline_ns: Option<u64>) -> u64 {
    match deadline_ns {
        None => 0,
        Some(0) => 1,
        Some(deadline_ns) if deadline_ns >= STATUS_RANGE_START => STATUS_RANGE_START - 1,
        Some(deadline_ns) => deadline_ns,
    }
}

/// The stop deadline for a request made at `now_ns`. Saturates and is never 0.
pub const fn stop_deadline_after(now_ns: u64) -> u64 {
    let deadline = now_ns.saturating_add(SERVICE_STOP_GRACE_NS);
    if deadline == 0 {
        1
    } else {
        deadline
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SYSCALL_NR_CLOCK;
    use crate::console::SYSCALL_NR_CONSOLE_DEVICE;
    use crate::lifecycle::SYSCALL_NR_LIFECYCLE_WAIT;
    use crate::memory::SYSCALL_NR_MEMORY;
    use crate::service_ready::SYSCALL_NR_SERVICE_READY;
    use crate::status::{STATUS_ENOSYS, STATUS_ESTALE};

    #[test]
    fn number_follows_console_device_and_power() {
        let taken = [
            SYSCALL_NR_LIFECYCLE_WAIT,
            SYSCALL_NR_SERVICE_READY,
            SYSCALL_NR_MEMORY,
            SYSCALL_NR_CLOCK,
            SYSCALL_NR_CONSOLE_DEVICE,
        ];
        assert!(!taken.contains(&SYSCALL_NR_SERVICE_STOP));
        // 26 is the power call (#372).
        assert_eq!(SYSCALL_NR_SERVICE_STOP, SYSCALL_NR_CONSOLE_DEVICE + 2);
    }

    #[test]
    fn query_answers_round_trip() {
        for answer in [
            StopQuery::Running,
            StopQuery::StopRequested { deadline_ns: 1 },
            StopQuery::StopRequested {
                deadline_ns: 5_000_000_000,
            },
            StopQuery::NotAServiceInstance,
            StopQuery::Malformed,
        ] {
            assert_eq!(StopQuery::decode(answer.encode()), answer);
        }
        assert_eq!(
            StopQuery::decode(STATUS_ENOSYS),
            StopQuery::Unknown(STATUS_ENOSYS)
        );
        assert_eq!(
            StopQuery::decode(STATUS_ESTALE),
            StopQuery::Unknown(STATUS_ESTALE)
        );
    }

    #[test]
    fn deadlines_are_never_zero_and_never_a_status() {
        assert_eq!(encode_deadline(None), 0);
        assert_eq!(encode_deadline(Some(0)), 1);
        assert_eq!(encode_deadline(Some(42)), 42);
        assert_eq!(encode_deadline(Some(u64::MAX)), STATUS_RANGE_START - 1);
        assert!(!is_status(encode_deadline(Some(u64::MAX))));
        assert_eq!(stop_deadline_after(10), 10 + SERVICE_STOP_GRACE_NS);
        assert_eq!(stop_deadline_after(u64::MAX), u64::MAX);
        assert_ne!(stop_deadline_after(0), 0);
        // Monotonic nanoseconds stay far below the status range for centuries of uptime.
        assert!(!is_status(stop_deadline_after(1 << 62)));
    }
}
