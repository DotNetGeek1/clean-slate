//! Syscall 27 `SERVICE_STOP` (#373): the live instance of a declared service asks whether init
//! has asked it to stop, or binds a work-set bit that the stop notice sets. The register
//! contract is in `clean_slate_native_abi::service_stop`.
//!
//! The caller is identified by its pid alone, as for `SERVICE_READY`. The notice itself is
//! recorded by `ServiceLifecycleController::request_stop` when init's `Stop` arrives, and the
//! deadline is kept by `terminate_overdue_stops` on init's `LIFECYCLE_WAIT`.
//!
//! No lost wake: `BIND_WAKE` stores the binding and reads whether a stop is already pending
//! with interrupts disabled, and a `Stop` runs in init's syscall on the single CPU, so the stop
//! either sees the binding and sets the bit or happened first and the bind sets it.

use clean_slate_capability::HolderId;
use clean_slate_native_abi::service_stop::{
    encode_deadline, StopQuery, SERVICE_STOP_OP_BIND_WAKE, SERVICE_STOP_OP_QUERY,
};
use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_EINVAL};

use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::sched::work_set;
use crate::service::control::StopNoticeRefusal;
use crate::service::service_lifecycle_controller_mut;

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    frame.rax = match frame.rdi {
        SERVICE_STOP_OP_QUERY => handle_query(frame),
        SERVICE_STOP_OP_BIND_WAKE => handle_bind_wake(frame),
        _ => STATUS_EINVAL,
    };
}

const fn refusal_status(refusal: StopNoticeRefusal) -> u64 {
    match refusal {
        StopNoticeRefusal::NotAServiceInstance => STATUS_EACCES,
    }
}

fn handle_query(frame: &SyscallContext) -> u64 {
    if [frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9]
        .iter()
        .any(|reserved| *reserved != 0)
    {
        return StopQuery::Malformed.encode();
    }
    let Ok(caller_pid) = crate::syscall::current_syscall_caller_pid() else {
        return StopQuery::NotAServiceInstance.encode();
    };
    let controller = unsafe { service_lifecycle_controller_mut() };
    match controller.stop_deadline_for_pid(caller_pid) {
        Ok(deadline_ns) => encode_deadline(deadline_ns),
        Err(refusal) => refusal_status(refusal),
    }
}

fn handle_bind_wake(frame: &SyscallContext) -> u64 {
    if [frame.r10, frame.r8, frame.r9]
        .iter()
        .any(|reserved| *reserved != 0)
    {
        return STATUS_EINVAL;
    }
    let Ok(bit) = work_set::bind_bit(frame.rdx) else {
        return STATUS_EINVAL;
    };
    let Ok(caller_pid) = crate::syscall::current_syscall_caller_pid() else {
        return STATUS_EACCES;
    };
    // A caller that is no service instance is refused before its work set is looked at.
    let controller = unsafe { service_lifecycle_controller_mut() };
    if let Err(refusal) = controller.stop_deadline_for_pid(caller_pid) {
        return refusal_status(refusal);
    }
    let Ok(binding) = work_set::bind(HolderId(caller_pid), frame.rsi) else {
        return STATUS_EINVAL;
    };
    let bound = without_interrupts(|| {
        let controller = unsafe { service_lifecycle_controller_mut() };
        controller.bind_stop_wake(caller_pid, binding, bit)
    });
    match bound {
        Ok(true) => {
            work_set::signal(binding, bit);
            0
        }
        Ok(false) => 0,
        Err(refusal) => refusal_status(refusal),
    }
}
