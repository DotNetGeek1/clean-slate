//! Syscall 21 `LIFECYCLE_WAIT` (#218 S3a): a lifecycle-control holder blocks until the
//! lifecycle controller has a pending message or its deadline passes. The register contract
//! is in `clean_slate_native_abi::lifecycle`.
//!
//! No lost wake: the authorization, the pending check, the deadline check and the waiter
//! registration run in one interrupts-disabled section ([`block_current_thread_unless`]).
//! Messages are stored only by `ServiceLifecycleController::push_pending`,
//! `push_terminal_pending` and `report_ready_from_pid`, which call [`wake_lifecycle_waiters`]
//! after storing the message and run with interrupts disabled (native syscall path, CPL3 fault path, or inside
//! `without_interrupts`) on the single CPU. A producer therefore runs wholly before the check,
//! which then sees its message, or wholly after the registration, and wakes the waiter.
//!
//! Every wake re-executes the syscall ([`BlockedResume::RetrySyscall`]), so the capability is
//! re-checked and the handler alone decides between a message and a timeout. The deadline is
//! absolute, so it survives the restart unchanged.

use clean_slate_native_abi::lifecycle::{
    encode_pending, LIFECYCLE_WAIT_NO_DEADLINE, SYSCALL_NR_LIFECYCLE_WAIT,
};
use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_EINVAL, STATUS_ETIMEDOUT};
use clean_slate_service_lifecycle::ServiceId;

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::sched::wait::{
    block_current_thread_unless, wake_all_registered, BlockCheck, BlockedResume, Deadline, WaitKey,
};
use crate::service::{service_lifecycle_controller_mut, LifecycleControlError};
use crate::syscall::lifecycle_control_syscall_error;
use crate::time::{monotonic_ns, tsc_hz};

/// The one key every lifecycle waiter blocks on. Any holder may poll any service, so every
/// queued message concerns every waiter.
pub(crate) const LIFECYCLE_WAIT_KEY: WaitKey = WaitKey(0x4C << 56);

/// Wakes every blocked `LIFECYCLE_WAIT`. Records no pending wake: a waiter re-checks the queue
/// before it blocks.
pub(crate) fn wake_lifecycle_waiters() {
    #[cfg(test)]
    tests::WAKES.with(|wakes| wakes.set(wakes.get() + 1));
    wake_all_registered(LIFECYCLE_WAIT_KEY);
}

/// Calls of [`wake_lifecycle_waiters`] made by this test thread.
#[cfg(test)]
pub(crate) fn test_wake_count() -> u64 {
    tests::WAKES.with(core::cell::Cell::get)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WaitArgs {
    capability: u64,
    deadline_ns: Option<u64>,
}

fn decode_args(frame: &SyscallContext) -> Result<WaitArgs, u64> {
    if [frame.rdx, frame.r10, frame.r8, frame.r9]
        .iter()
        .any(|reserved| *reserved != 0)
    {
        return Err(STATUS_EINVAL);
    }
    let deadline_ns = (frame.rsi != LIFECYCLE_WAIT_NO_DEADLINE).then_some(frame.rsi);
    if deadline_ns.is_some() && tsc_hz().is_none() {
        return Err(STATUS_EINVAL);
    }
    Ok(WaitArgs {
        capability: frame.rdi,
        deadline_ns,
    })
}

/// One readiness check. A refused capability completes the syscall before the clock is read
/// or anything is registered; a pending message wins over a deadline that has passed.
fn wait_step(
    pending: Result<Option<ServiceId>, LifecycleControlError>,
    deadline_ns: Option<u64>,
    now_ns: impl FnOnce() -> u64,
) -> BlockCheck {
    let pending = match pending {
        Ok(pending) => pending,
        Err(error) => return BlockCheck::Ready(lifecycle_control_syscall_error(error)),
    };
    if let Some(rax) = pending.and_then(|service| encode_pending(service.0)) {
        return BlockCheck::Ready(rax);
    }
    match deadline_ns {
        Some(deadline_ns) if now_ns() >= deadline_ns => BlockCheck::Ready(STATUS_ETIMEDOUT),
        _ => BlockCheck::Block,
    }
}

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    let args = match decode_args(frame) {
        Ok(args) => args,
        Err(status) => {
            frame.rax = status;
            return;
        }
    };
    let caller_pid = match crate::syscall::current_syscall_caller_pid() {
        Ok(pid) => pid,
        Err(_) => {
            frame.rax = STATUS_EACCES;
            return;
        }
    };
    let check = || {
        let controller = unsafe { service_lifecycle_controller_mut() };
        let pending = controller.pending_service_authorized(caller_pid, args.capability);
        let mut now_read = None;
        let step = wait_step(pending, args.deadline_ns, || {
            *now_read.insert(monotonic_ns())
        });
        #[cfg(feature = "m4-service-lifecycle-self-test")]
        crate::selftest::m4_lifecycle_wait::observe_lifecycle_wait_step(
            caller_pid,
            args.deadline_ns,
            now_read,
            step,
        );
        #[cfg(clean_slate_system_init)]
        crate::service::system_init::observe_lifecycle_wait(
            caller_pid,
            args.deadline_ns,
            matches!(step, BlockCheck::Block),
        );
        step
    };
    match block_current_thread_unless(
        frame,
        LIFECYCLE_WAIT_KEY,
        args.deadline_ns.map(Deadline::MonotonicNs),
        BlockedResume::RetrySyscall {
            nr: SYSCALL_NR_LIFECYCLE_WAIT,
        },
        check,
    ) {
        Ok(rax) => frame.rax = rax,
        Err(message) => crate::diagnostics::qemu::fatal_kernel_error(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_native_abi::status::{STATUS_ESTALE, STATUS_RANGE_START};

    std::thread_local! {
        pub(super) static WAKES: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
    }

    fn frame(rdi: u64, rsi: u64) -> SyscallContext {
        SyscallContext {
            rax: SYSCALL_NR_LIFECYCLE_WAIT,
            rdx: 0,
            rbx: 0,
            rbp: 0,
            rsi,
            rdi,
            r8: 0,
            r9: 0,
            r10: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            user_rip: 0x40_1002,
            user_rflags: 0x202,
            user_rsp: 0x7fff_0000,
        }
    }

    fn calibrated() {
        crate::time::set_test_monotonic_tsc(1_000_000_000, 0);
    }

    fn no_clock() -> u64 {
        panic!("the clock must not be read")
    }

    #[test]
    fn zero_deadline_means_none_and_other_values_are_absolute() {
        calibrated();
        let args = decode_args(&frame(7, 0)).unwrap();
        assert_eq!(
            args,
            WaitArgs {
                capability: 7,
                deadline_ns: None
            }
        );
        for deadline in [1, 5_000_000, u64::MAX] {
            assert_eq!(
                decode_args(&frame(7, deadline)).unwrap().deadline_ns,
                Some(deadline)
            );
        }
    }

    #[test]
    fn reserved_registers_must_be_zero() {
        calibrated();
        for set in 0..4 {
            let mut frame = frame(7, 0);
            match set {
                0 => frame.rdx = 1,
                1 => frame.r10 = 1,
                2 => frame.r8 = 1,
                _ => frame.r9 = 1,
            }
            assert_eq!(decode_args(&frame), Err(STATUS_EINVAL));
        }
    }

    #[test]
    fn a_deadline_needs_a_calibrated_clock() {
        crate::time::set_test_monotonic_tsc(0, 0);
        assert_eq!(decode_args(&frame(7, 100)), Err(STATUS_EINVAL));
        assert_eq!(decode_args(&frame(7, 0)).unwrap().deadline_ns, None);
    }

    #[test]
    fn a_refused_capability_never_blocks_or_reads_the_clock() {
        for (error, status) in [
            (LifecycleControlError::Unauthorized, STATUS_EACCES),
            (LifecycleControlError::StaleHandle, STATUS_ESTALE),
            (LifecycleControlError::InvalidHandle, STATUS_EINVAL),
        ] {
            for deadline in [None, Some(1), Some(u64::MAX)] {
                assert_eq!(
                    wait_step(Err(error), deadline, no_clock),
                    BlockCheck::Ready(status)
                );
            }
        }
    }

    #[test]
    fn a_pending_message_wins_over_any_deadline() {
        for deadline in [None, Some(1), Some(100), Some(u64::MAX)] {
            assert_eq!(
                wait_step(Ok(Some(ServiceId(2))), deadline, no_clock),
                BlockCheck::Ready(2)
            );
        }
    }

    #[test]
    fn deadline_edges_time_out_at_or_after_the_deadline_only() {
        let step = |deadline, now| wait_step(Ok(None), deadline, || now);
        assert_eq!(step(None, u64::MAX), BlockCheck::Block);
        // Past and present deadlines are a non-blocking check.
        assert_eq!(step(Some(1), 500), BlockCheck::Ready(STATUS_ETIMEDOUT));
        assert_eq!(step(Some(500), 500), BlockCheck::Ready(STATUS_ETIMEDOUT));
        assert_eq!(step(Some(501), 500), BlockCheck::Block);
        // Far future: compared, never added to, so it cannot wrap into an early timeout.
        assert_eq!(step(Some(u64::MAX), u64::MAX - 1), BlockCheck::Block);
        assert_eq!(
            step(Some(u64::MAX), u64::MAX),
            BlockCheck::Ready(STATUS_ETIMEDOUT)
        );
    }

    #[test]
    fn results_are_service_ids_or_statuses() {
        assert_eq!(
            wait_step(Ok(Some(ServiceId(u32::MAX))), None, no_clock),
            BlockCheck::Ready(u64::from(u32::MAX))
        );
        assert!(u64::from(u32::MAX) < STATUS_RANGE_START);
        // Service id 0 is never declared; it is not reported as a message.
        assert_eq!(
            wait_step(Ok(Some(ServiceId(0))), None, no_clock),
            BlockCheck::Block
        );
    }

    #[test]
    fn handler_refuses_an_unresolved_caller_without_blocking() {
        calibrated();
        let mut frame = frame(7, LIFECYCLE_WAIT_NO_DEADLINE);
        handle_syscall(&mut frame);
        assert_eq!(frame.rax, STATUS_EACCES);
        assert_eq!(frame.user_rip, 0x40_1002);
    }

    #[test]
    fn handler_rejects_bad_arguments_before_resolving_the_caller() {
        calibrated();
        let mut frame = frame(7, 0);
        frame.r8 = 64;
        handle_syscall(&mut frame);
        assert_eq!(frame.rax, STATUS_EINVAL);
    }
}
