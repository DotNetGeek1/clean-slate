//! Kernel task stacks and the raw stack-switch primitives.
//!
//! Why unsafe: `restore_task_context`/`start_first_task` replace RSP and jump,
//! abandoning the current Rust frame; `build_userspace_entry_frame` writes a
//! synthetic interrupt frame onto another thread's kernel stack. Callers must
//! pass stack pointers that hold a frame laid out exactly as
//! `interrupt_context::InterruptContext` (plus the user RSP/SS pair for ring-3
//! returns) and must have already switched CR3/TSS for the target thread.
//! Link contracts: `NEXT_TASK_STACK_POINTER` / `NEXT_TASK_ENTRY_POINT` are read
//! by `clean_slate_start_fresh_task` in `asm.rs`, and `FRESH_TASK_SENTINEL`
//! is the `-1` compared against `rax` by `clean_slate_interrupt_common`.

use core::arch::asm;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
use core::mem::size_of;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
use core::ptr;

use crate::arch::x86_64::asm::clean_slate_blocked_syscall_resume_from_schedule;
use crate::arch::x86_64::asm::clean_slate_restore_context;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
use crate::arch::x86_64::gdt::userspace_gdt_state;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
use crate::arch::x86_64::interrupt_context::{
    InterruptContext, SyscallContext, UserspaceEntryFrame,
};

pub(crate) const FRESH_TASK_SENTINEL: u64 = u64::MAX;
/// Returned by the timer/block path when the next thread resumes a blocked syscall.
pub(crate) const SYSCALL_BLOCKED_RESUME_SENTINEL: u64 = u64::MAX - 2;
/// Stack frames handed to the CPU must be 16-byte aligned; this is the only
/// alignment the architecture layer needs, so it stays local rather than
/// depending upward on `mm`.
const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

pub(crate) const TASK_STACK_SIZE: usize = 64 * 1024;

#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
pub(crate) const USER_TEST_RFLAGS: u64 = 0x202;

#[repr(align(16))]
pub(crate) struct TaskStack(pub(crate) [u8; TASK_STACK_SIZE]);

// Consumed by arch/x86_64/asm.rs (bootstrap trampolines read the next task's RSP).
#[unsafe(no_mangle)]
static mut NEXT_TASK_STACK_POINTER: u64 = 0;
// Consumed by arch/x86_64/asm.rs (bootstrap trampolines jump to this entry point).
#[unsafe(no_mangle)]
static mut NEXT_TASK_ENTRY_POINT: u64 = 0;

/// Publishes the stack pointer and entry point the bootstrap trampoline will
/// load for the next fresh kernel task.
///
/// # Safety
/// Interrupts must be disabled (or the caller must otherwise guarantee no
/// concurrent dispatch) until the trampoline has consumed the values.
pub(crate) unsafe fn set_next_task(stack_pointer: u64, entry_point: u64) {
    unsafe {
        NEXT_TASK_STACK_POINTER = stack_pointer;
        NEXT_TASK_ENTRY_POINT = entry_point;
    }
}

/// Reads back the `(stack_pointer, entry_point)` pair published by
/// [`set_next_task`].
///
/// # Safety
/// Same as [`set_next_task`]: no concurrent writer may be active.
pub(crate) unsafe fn next_task() -> (u64, u64) {
    unsafe { (NEXT_TASK_STACK_POINTER, NEXT_TASK_ENTRY_POINT) }
}

pub(crate) fn task_stack_top(stack: &TaskStack) -> u64 {
    align_down(((stack.0.as_ptr() as usize) + stack.0.len()) as u64, 16)
}

/// True when `rsp` points into one of the static per-slot task stacks (not user memory).
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
#[cfg_attr(not(feature = "m9-linux-exec-self-test"), allow(dead_code))]
pub(crate) fn rsp_on_static_task_stack(rsp: u64) -> bool {
    task_stack_margin_bytes(rsp).is_some()
}

/// Bytes between `rsp` and the base of the containing static task stack, if any.
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
pub(crate) fn task_stack_margin_bytes(rsp: u64) -> Option<u64> {
    let stacks = unsafe { crate::sched::task_stacks_mut() };
    stacks.iter().find_map(|stack| {
        let base = stack.0.as_ptr() as u64;
        let top = task_stack_top(stack);
        if rsp > base && rsp <= top {
            Some(rsp - base)
        } else {
            None
        }
    })
}

#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
pub(crate) const TASK_STACK_MIN_MARGIN_BYTES: u64 = 16 * 1024;

pub(crate) unsafe fn restore_task_context(stack_pointer: u64) -> ! {
    unsafe {
        asm!(
            "mov rsp, {stack_pointer}",
            "jmp {restore}",
            stack_pointer = in(reg) stack_pointer,
            restore = sym clean_slate_restore_context,
            options(noreturn)
        );
    }
}

pub(crate) unsafe fn start_first_task(stack_pointer: u64, entry_point: u64) -> ! {
    unsafe {
        asm!(
            "mov rsp, {stack_pointer}",
            "jmp {entry_point}",
            stack_pointer = in(reg) stack_pointer,
            entry_point = in(reg) entry_point,
            options(noreturn)
        );
    }
}

/// Resume the thread selected by process teardown or syscall fail-closed containment.
pub(crate) fn resume_after_scheduler_handoff(
    next_stack_pointer: Option<u64>,
    no_runnable_message: &'static str,
) -> ! {
    use crate::diagnostics::qemu::fatal_kernel_error;
    match next_stack_pointer {
        Some(FRESH_TASK_SENTINEL) => {
            let (stack_pointer, entry_point) = unsafe { next_task() };
            unsafe { start_first_task(stack_pointer, entry_point) }
        }
        Some(SYSCALL_BLOCKED_RESUME_SENTINEL) => unsafe {
            clean_slate_blocked_syscall_resume_from_schedule()
        },
        Some(stack_pointer) => unsafe { restore_task_context(stack_pointer) },
        None => fatal_kernel_error(no_runnable_message),
    }
}

#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
pub(crate) fn build_userspace_entry_frame(
    kernel_stack_top: u64,
    instruction_pointer: u64,
    user_stack_pointer: u64,
) -> Result<u64, &'static str> {
    let gdt_state = userspace_gdt_state()?;
    let frame_address = align_down(
        kernel_stack_top - size_of::<UserspaceEntryFrame>() as u64,
        16,
    );
    let frame = UserspaceEntryFrame {
        interrupt: InterruptContext {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rdi: 0,
            rsi: 0,
            rbp: 0,
            rbx: 0,
            rdx: 0,
            rcx: 0,
            rax: 0,
            vector: 0,
            error_code: 0,
            rip: instruction_pointer,
            cs: gdt_state.user_code_selector.0 as u64,
            rflags: USER_TEST_RFLAGS,
        },
        user_stack_pointer,
        user_stack_segment: gdt_state.user_data_selector.0 as u64,
    };
    unsafe {
        ptr::write(frame_address as *mut UserspaceEntryFrame, frame);
    }
    Ok(frame_address)
}

/// Fork child resumes in user mode at the parent's syscall return site with `rax = 0`.
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
pub(crate) fn build_fork_child_userspace_frame(
    kernel_stack_top: u64,
    parent_syscall_frame: &SyscallContext,
) -> Result<u64, &'static str> {
    let gdt_state = userspace_gdt_state()?;
    let frame_address = align_down(
        kernel_stack_top - size_of::<UserspaceEntryFrame>() as u64,
        16,
    );
    let frame = UserspaceEntryFrame {
        interrupt: InterruptContext {
            r15: parent_syscall_frame.r15,
            r14: parent_syscall_frame.r14,
            r13: parent_syscall_frame.r13,
            r12: parent_syscall_frame.r12,
            r11: 0,
            r10: parent_syscall_frame.r10,
            r9: parent_syscall_frame.r9,
            r8: parent_syscall_frame.r8,
            rdi: parent_syscall_frame.rdi,
            rsi: parent_syscall_frame.rsi,
            rbp: parent_syscall_frame.rbp,
            rbx: parent_syscall_frame.rbx,
            rdx: parent_syscall_frame.rdx,
            rcx: 0,
            rax: 0,
            vector: 0,
            error_code: 0,
            rip: parent_syscall_frame.user_rip,
            cs: gdt_state.user_code_selector.0 as u64,
            rflags: parent_syscall_frame.user_rflags,
        },
        user_stack_pointer: parent_syscall_frame.user_rsp,
        user_stack_segment: gdt_state.user_data_selector.0 as u64,
    };
    unsafe {
        ptr::write(frame_address as *mut UserspaceEntryFrame, frame);
    }
    Ok(frame_address)
}
