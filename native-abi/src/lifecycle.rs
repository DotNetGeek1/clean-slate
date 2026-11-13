//! Syscall 21 `LIFECYCLE_WAIT`: block until the lifecycle controller has a pending message.
//!
//! ```text
//! | Register | Meaning                                                                 |
//! | rdi      | lifecycle-control capability handle (the one `LIFECYCLE_POLL` takes)    |
//! | rsi      | deadline: absolute monotonic ns (`WORK_SET` op `NOW`); 0 = no deadline  |
//! | rdx, r10, r8, r9 | reserved, must be 0                                            |
//! ```
//!
//! | Result | Meaning |
//! |--------|---------|
//! | `1..=u32::MAX` | id of a service with a pending lifecycle message; read it with `LIFECYCLE_POLL` (5) |
//! | `STATUS_ETIMEDOUT` | the deadline was reached with nothing pending |
//! | `STATUS_EACCES` | the caller does not hold this lifecycle-control capability |
//! | `STATUS_ESTALE` | the handle names a revoked capability |
//! | `STATUS_EINVAL` | malformed handle, a reserved register is non-zero, or a deadline without a calibrated clock |
//!
//! A pending message wins over an expired deadline, so a deadline at or before now is a
//! non-blocking check. The kernel only compares the deadline with the clock; it never adds
//! to it. The wait does not consume the message: the caller polls it.

use crate::status::{is_status, STATUS_ETIMEDOUT};

pub const SYSCALL_NR_LIFECYCLE_WAIT: u64 = 21;

/// `rsi` value that waits until a message is pending, however long that takes.
pub const LIFECYCLE_WAIT_NO_DEADLINE: u64 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleWait {
    /// A message for this service is pending.
    Pending {
        service: u32,
    },
    TimedOut,
    /// Any other native status.
    Failed(u64),
}

/// Kernel side: the result for a pending message of `service`. Service id 0 never names a
/// declared service, so it cannot be encoded.
pub const fn encode_pending(service: u32) -> Option<u64> {
    if service == 0 {
        None
    } else {
        Some(service as u64)
    }
}

/// Userspace side: decodes a `LIFECYCLE_WAIT` result.
pub const fn decode_wait_result(raw: u64) -> LifecycleWait {
    if raw == STATUS_ETIMEDOUT {
        return LifecycleWait::TimedOut;
    }
    if is_status(raw) || raw == 0 || raw > u32::MAX as u64 {
        return LifecycleWait::Failed(raw);
    }
    LifecycleWait::Pending {
        service: raw as u32,
    }
}

/// The deadline `timeout_ns` after `now_ns`. Saturates instead of wrapping, and never returns
/// [`LIFECYCLE_WAIT_NO_DEADLINE`], so a zero timeout at clock zero is still a non-blocking check.
pub const fn deadline_after(now_ns: u64, timeout_ns: u64) -> u64 {
    let deadline = now_ns.saturating_add(timeout_ns);
    if deadline == LIFECYCLE_WAIT_NO_DEADLINE {
        1
    } else {
        deadline
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{
        STATUS_EACCES, STATUS_EINVAL, STATUS_ENOSYS, STATUS_ESTALE, STATUS_RANGE_START,
    };
    use clean_slate_capability::syscall_abi::{
        SYSCALL_NR_CAP_AUDIT_READ, SYSCALL_NR_CAP_DELEGATE, SYSCALL_NR_CAP_GRANT,
        SYSCALL_NR_CAP_OBJECT, SYSCALL_NR_CAP_PROCESS_CONTROL, SYSCALL_NR_CAP_REVOKE,
        SYSCALL_NR_DISPLAY, SYSCALL_NR_INPUT, SYSCALL_NR_NETWORK_CAPABILITY,
        SYSCALL_NR_NETWORK_REQUEST, SYSCALL_NR_SERVICE_PORT, SYSCALL_NR_SHARED_BUFFER,
        SYSCALL_NR_WORK_SET,
    };

    #[test]
    fn number_follows_the_reserved_native_range() {
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
        ];
        assert!(SYSCALL_NR_LIFECYCLE_WAIT > 7);
        assert!(!taken.contains(&SYSCALL_NR_LIFECYCLE_WAIT));
        assert_eq!(SYSCALL_NR_LIFECYCLE_WAIT, SYSCALL_NR_WORK_SET + 1);
    }

    #[test]
    fn pending_results_round_trip_and_stay_below_the_status_range() {
        for service in [1, 2, 0x4100, u32::MAX] {
            let raw = encode_pending(service).unwrap();
            assert!(raw < STATUS_RANGE_START);
            assert_eq!(decode_wait_result(raw), LifecycleWait::Pending { service });
        }
        assert_eq!(encode_pending(0), None);
    }

    #[test]
    fn statuses_decode_as_timeout_or_failure() {
        assert_eq!(
            decode_wait_result(STATUS_ETIMEDOUT),
            LifecycleWait::TimedOut
        );
        for status in [STATUS_EACCES, STATUS_ESTALE, STATUS_EINVAL, STATUS_ENOSYS] {
            assert_eq!(decode_wait_result(status), LifecycleWait::Failed(status));
        }
        assert_eq!(decode_wait_result(0), LifecycleWait::Failed(0));
        let too_wide = u64::from(u32::MAX) + 1;
        assert_eq!(
            decode_wait_result(too_wide),
            LifecycleWait::Failed(too_wide)
        );
    }

    #[test]
    fn deadline_after_saturates_and_never_means_no_deadline() {
        assert_eq!(deadline_after(100, 20), 120);
        assert_eq!(deadline_after(0, 0), 1);
        assert_eq!(deadline_after(5, 0), 5);
        assert_eq!(deadline_after(u64::MAX - 1, 10), u64::MAX);
        assert_eq!(deadline_after(u64::MAX, u64::MAX), u64::MAX);
        assert_ne!(deadline_after(0, 0), LIFECYCLE_WAIT_NO_DEADLINE);
    }
}
