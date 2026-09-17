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

use crate::arch::x86_64::asm::clean_slate_restore_context;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
use crate::arch::x86_64::gdt::userspace_selectors;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
use crate::arch::x86_64::interrupt_context::{InterruptContext, UserspaceEntryFrame};

pub(crate) const FRESH_TASK_SENTINEL: u64 = u64::MAX;

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
    let (user_code_selector, user_data_selector) = userspace_selectors()?;
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
            cs: user_code_selector as u64,
            rflags: USER_TEST_RFLAGS,
        },
        user_stack_pointer,
        user_stack_segment: user_data_selector as u64,
    };
    unsafe {
        ptr::write(frame_address as *mut UserspaceEntryFrame, frame);
    }
    Ok(frame_address)
}
