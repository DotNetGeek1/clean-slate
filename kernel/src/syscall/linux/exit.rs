//! Linux `exit(2)` (nr 60) for the `LinuxX86_64` personality (#94).
//!
//! `exit(status)` terminates the calling process through the **production**
//! teardown path — [`teardown_current_process`] in `process/domain.rs` — which
//! is exactly what the userspace fault handler (`interrupt/mod.rs`) uses. That
//! function retires the scheduler thread, reclaims the address space, IPC
//! endpoints/capabilities, capability-space holdings and (via #95's hook) the
//! Linux fd table. Nothing is reimplemented here.
//!
//! # Never returning to userspace
//!
//! The Linux handler type returns [`LinuxSyscallResult`], but `exit` must not
//! resume the caller. The SYSCALL entry stub (`clean_slate_syscall_entry`)
//! restores whatever `SyscallContext` frame the dispatcher returns and executes
//! `sysretq`; an interrupt-style frame cannot be handed back through it.
//! Therefore this handler performs the switch itself, exactly like the fault
//! path and the kernel demo task exit do:
//!
//! 1. `teardown_current_process` marks the thread `Exited`, picks the next
//!    runnable thread (`finish_current_thread`), activates its address-space
//!    root and kernel/syscall stacks (`prepare_current_scheduler_thread_dispatch`),
//!    and returns that thread's saved stack pointer.
//! 2. `Some(FRESH_TASK_SENTINEL)` → a never-started kernel thread was chosen;
//!    `set_next_task` already published its stack/entry, so jump via
//!    `start_first_task`.
//! 3. `Some(frame)` → `restore_task_context(frame)` (interrupt-frame `iretq`).
//! 4. `None` → no runnable thread remains; fail closed with a fatal kernel
//!    error, mirroring the fault path.
//!
//! Every branch diverges (`-> !`), so the `LinuxSyscallResult` return type is
//! satisfied by coercion from `!` and `encode_rax` is never reached for
//! `exit`. Interrupts are masked for the whole path (IA32_FMASK clears IF on
//! SYSCALL entry) and the code runs on the exiting thread's kernel stack,
//! which is a static per-slot task stack — the same situation as a fault
//! taken on that thread.

use super::table::LinuxSyscallContext;
use crate::arch::x86_64::context_switch::resume_after_scheduler_handoff;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::mm::address_space::kernel_root_frame;
use crate::process::domain::teardown_current_process;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use clean_slate_linux_abi::{LinuxSyscallRequest, LinuxSyscallResult};

/// Linux passes `int status`; the kernel records `status & 0xff` (the value a
/// parent observes via `WEXITSTATUS`). Higher bits are discarded by contract.
pub(crate) const LINUX_EXIT_STATUS_MASK: u64 = 0xff;

/// Pure exit-status mapping (host-testable): `rdi` → recorded exit status.
pub(crate) const fn exit_status_from_linux(status_arg: u64) -> u64 {
    status_arg & LINUX_EXIT_STATUS_MASK
}

/// Production `exit` handler: `rdi = status`. Diverges; never resumes the caller.
pub(crate) fn handle_sys_exit(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let status = exit_status_from_linux(request.args[0]);
    let pid = ctx.pid;
    kernel_log_fmt(format_args!("[LNX ] exit pid={pid} status={status}\n"));

    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| {
            fatal_kernel_error("linux exit: service lifecycle allocator was unavailable")
        });
    let teardown = teardown_current_process(allocator, kernel_root_frame(), status, false)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    if teardown.process_id != pid {
        fatal_kernel_error("linux exit tore down a process other than the syscall caller");
    }

    #[cfg(feature = "m8-linux-dispatch-self-test")]
    crate::selftest::m8_linux_dispatch::observe_linux_exit(pid, ctx.instance_generation, &teardown);

    #[cfg(feature = "m9-low-va-self-test")]
    crate::selftest::m9_low_va::observe_linux_exit(pid, &teardown);

    #[cfg(feature = "m9-fd-core-self-test")]
    if let Some(next_frame) = crate::selftest::m9_fd_core::after_linux_probe_exit(
        pid,
        ctx.instance_generation,
        &teardown,
        allocator,
    ) {
        switch_after_exit(Some(next_frame));
    }

    // Still executing on the exiting thread's kernel stack. Any re-Start of a
    // supervised service from this hook must refuse a scheduler slot whose
    // task stack contains the current rsp (see `linux_launch::ensure_slot_stack_is_idle`).
    #[cfg(feature = "m8-linux-hello")]
    crate::service::on_supervised_process_exited(allocator, pid, status);

    switch_after_exit(teardown.next_stack_pointer)
}

/// Hand control to the thread selected by teardown; never returns.
fn switch_after_exit(next_stack_pointer: Option<u64>) -> ! {
    resume_after_scheduler_handoff(
        next_stack_pointer,
        "no runnable thread remained after linux exit",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_status_keeps_low_eight_bits_only() {
        assert_eq!(exit_status_from_linux(0), 0);
        assert_eq!(exit_status_from_linux(1), 1);
        assert_eq!(exit_status_from_linux(255), 255);
        assert_eq!(exit_status_from_linux(256), 0);
        assert_eq!(exit_status_from_linux(0x1_02), 2);
        // Negative int status (two's complement in rdi) masks like Linux.
        assert_eq!(exit_status_from_linux((-1i64) as u64), 255);
        assert_eq!(exit_status_from_linux(u64::MAX), 255);
    }
}
