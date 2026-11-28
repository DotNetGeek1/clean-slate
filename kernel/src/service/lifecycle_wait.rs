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
//!
//! `BIND_WAKE` (#237) records one work-set bit that [`wake_lifecycle_waiters`] also sets, so a
//! holder that sleeps in `WORK_SET` `WAIT` learns of each message the same way. Binding with a
//! message already pending sets the bit at once; with interrupts disabled across the check and
//! the store, a message queued meanwhile either is seen by the check or sets the bit itself.

use clean_slate_native_abi::lifecycle::{
    encode_pending, LIFECYCLE_WAIT_NO_DEADLINE, LIFECYCLE_WAIT_OP_BIND_WAKE,
    LIFECYCLE_WAIT_OP_WAIT, SYSCALL_NR_LIFECYCLE_WAIT,
};
use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_EINVAL, STATUS_ETIMEDOUT};
use clean_slate_service_lifecycle::ServiceId;

use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::sched::wait::{
    block_current_thread_unless, wake_all_registered, BlockCheck, BlockedResume, Deadline, WaitKey,
};
use crate::sched::work_set::{self, WorkSetBinding};
use crate::service::{service_lifecycle_controller_mut, LifecycleControlError};
use crate::sync::global_cell::GlobalCell;
use crate::syscall::lifecycle_control_syscall_error;
use crate::time::{monotonic_ns, tsc_hz};

/// The one key every lifecycle waiter blocks on. Any holder may poll any service, so every
/// queued message concerns every waiter.
pub(crate) const LIFECYCLE_WAIT_KEY: WaitKey = WaitKey(0x4C << 56);

/// The work-set bit `BIND_WAKE` recorded, the last bind winning. A binding to a work set that
/// is gone is harmless: signalling a stale work set does nothing.
static WAKE_BINDING: GlobalCell<Option<(WorkSetBinding, u32)>> = GlobalCell::new(None);

/// Wakes every blocked `LIFECYCLE_WAIT` and sets the bound work-set bit. Records no pending
/// wake: a waiter re-checks the queue before it blocks.
pub(crate) fn wake_lifecycle_waiters() {
    #[cfg(test)]
    tests::WAKES.with(|wakes| wakes.set(wakes.get() + 1));
    wake_all_registered(LIFECYCLE_WAIT_KEY);
    signal_bound_work_set();
}

fn signal_bound_work_set() {
    // SAFETY: read with interrupts disabled on the single CPU; the binding is a `Copy` value.
    if let Some((binding, bit)) = without_interrupts(|| unsafe { *WAKE_BINDING.get() }) {
        work_set::signal(binding, bit);
    }
}

#[cfg(test)]
pub(crate) fn test_wake_binding() -> Option<(WorkSetBinding, u32)> {
    unsafe { *WAKE_BINDING.get() }
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

/// #373: a stopping instance still live at its stop deadline is terminated here, on a
/// lifecycle-control holder's wait, so that its `Exited` is queued before the check below.
/// Init wakes for every stop deadline it waits on and then waits here, so a deadline is kept
/// within one of init's wakes. The teardown needs the lifecycle allocator, which the timer path
/// cannot take, and a caller that does not hold the capability changes nothing.
fn terminate_overdue_stops(caller_pid: u64, capability: u64) {
    if tsc_hz().is_none() {
        return;
    }
    let controller = unsafe { service_lifecycle_controller_mut() };
    if controller
        .pending_service_authorized(caller_pid, capability)
        .is_err()
    {
        return;
    }
    let Some(allocator) = crate::syscall::service_lifecycle_syscall_allocator_mut().as_mut() else {
        return;
    };
    controller.terminate_overdue_stops(allocator, monotonic_ns());
}

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    match frame.rdx {
        LIFECYCLE_WAIT_OP_WAIT => handle_wait(frame),
        LIFECYCLE_WAIT_OP_BIND_WAKE => frame.rax = handle_bind_wake(frame),
        _ => frame.rax = STATUS_EINVAL,
    }
}

/// `BIND_WAKE`: the caller must hold the capability, and the work set and bit must be its own.
fn handle_bind_wake(frame: &SyscallContext) -> u64 {
    if frame.r8 != 0 || frame.r9 != 0 {
        return STATUS_EINVAL;
    }
    let Ok(bit) = work_set::bind_bit(frame.r10) else {
        return STATUS_EINVAL;
    };
    let caller_pid = match crate::syscall::current_syscall_caller_pid() {
        Ok(pid) => pid,
        Err(_) => return STATUS_EACCES,
    };
    let binding = match work_set::bind(clean_slate_capability::HolderId(caller_pid), frame.rsi) {
        Ok(binding) => binding,
        Err(_) => return STATUS_EINVAL,
    };
    let pending = without_interrupts(|| {
        let controller = unsafe { service_lifecycle_controller_mut() };
        let pending = controller.pending_service_authorized(caller_pid, frame.rdi);
        if pending.is_ok() {
            unsafe { *WAKE_BINDING.get() = Some((binding, bit)) };
        }
        pending
    });
    match pending {
        Ok(Some(_)) => {
            work_set::signal(binding, bit);
            0
        }
        Ok(None) => 0,
        Err(error) => lifecycle_control_syscall_error(error),
    }
}

fn handle_wait(frame: &mut SyscallContext) {
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
    terminate_overdue_stops(caller_pid, args.capability);
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
        for set in 0..3 {
            let mut frame = frame(7, 0);
            match set {
                0 => frame.r10 = 1,
                1 => frame.r8 = 1,
                _ => frame.r9 = 1,
            }
            assert_eq!(decode_args(&frame), Err(STATUS_EINVAL));
        }
    }

    #[test]
    fn an_unknown_op_is_einval() {
        calibrated();
        let mut call = frame(7, 0);
        call.rdx = 2;
        handle_syscall(&mut call);
        assert_eq!(call.rax, STATUS_EINVAL);
    }

    #[test]
    fn bind_wake_refuses_reserved_registers_and_bad_bits_before_the_caller() {
        for (r10, r8, r9) in [(32, 0, 0), (0, 1, 0), (0, 0, 1), (u64::MAX, 0, 0)] {
            let mut call = frame(7, 1);
            call.rdx = LIFECYCLE_WAIT_OP_BIND_WAKE;
            call.r10 = r10;
            call.r8 = r8;
            call.r9 = r9;
            handle_syscall(&mut call);
            assert_eq!(call.rax, STATUS_EINVAL, "{r10} {r8} {r9}");
        }
        let mut call = frame(7, 1);
        call.rdx = LIFECYCLE_WAIT_OP_BIND_WAKE;
        handle_syscall(&mut call);
        assert_eq!(
            call.rax, STATUS_EACCES,
            "no caller to attribute the bind to"
        );
        assert_eq!(test_wake_binding(), None);
    }

    #[test]
    fn each_wake_sets_the_bound_bit_and_a_rebind_replaces_it() {
        use clean_slate_capability::HolderId;

        let holder = HolderId(31);
        let id = work_set::create_for_test(holder);
        wake_lifecycle_waiters();
        assert_eq!(
            work_set::take_ready_for_test(holder, id),
            0,
            "nothing bound yet"
        );
        let binding = work_set::bind(holder, id.encode()).unwrap();
        unsafe { *WAKE_BINDING.get() = Some((binding, 3)) };
        wake_lifecycle_waiters();
        assert_eq!(work_set::take_ready_for_test(holder, id), 1 << 3);
        unsafe { *WAKE_BINDING.get() = Some((binding, 5)) };
        wake_lifecycle_waiters();
        assert_eq!(work_set::take_ready_for_test(holder, id), 1 << 5);
        assert_eq!(test_wake_binding(), Some((binding, 5)));
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
