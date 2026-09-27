//! #162 kernel stack guard self-test: a test-only kernel thread in scheduler
//! slot [`PROBE_SLOT`] recurses with bounded depth until it has consumed more
//! than its whole task stack. The guard page must stop it: #PF on the guard,
//! #DF on the IST1 stack, then the production `[FAIL] kernel stack overflow`
//! diagnostic, which this module checks before exiting QEMU successfully.
//! If the guard were missing the recursion would reach its depth bound and
//! return, and the thread reports that as a failure.

use crate::arch::x86_64::context_switch::{task_stack_top, TASK_STACK_SIZE};
use crate::arch::x86_64::gdt::DOUBLE_FAULT_STACK;
use crate::arch::x86_64::guarded_stack::KERNEL_STACK_GUARD_BYTES;
use crate::diagnostics::qemu::{qemu_exit, QEMU_EXIT_FAILURE, QEMU_EXIT_SUCCESS};
use crate::diagnostics::serial::{serial_write_fmt, serial_write_line};
use crate::mm::stack_guard::{GuardedStackRecord, KernelStackKind};
use crate::process::id_allocator::id_allocator_mut;
use crate::process::KERNEL_PROCESS_ID;
use crate::sched::{scheduler_mut, task_stacks_mut, Scheduler, ThreadKind};
use core::hint::black_box;
use core::sync::atomic::{AtomicBool, Ordering};

/// Slot 0 below it stays empty, so a missing guard would only scribble on an
/// unused stack before the depth bound ends the recursion.
const PROBE_SLOT: usize = 1;
const FRAME_BYTES: usize = 1024;
/// Enough 1 KiB frames to run two pages past the bottom of the task stack.
const DEPTH_LIMIT: usize = (TASK_STACK_SIZE + 2 * KERNEL_STACK_GUARD_BYTES) / FRAME_BYTES;

static PROBE_RUNNING: AtomicBool = AtomicBool::new(false);

/// Replaces the default demo threads with the probe thread; the normal boot
/// tail then starts the scheduler and timer as in production.
pub(crate) fn configure_stack_guard_probe_thread() -> Result<(), &'static str> {
    let stack_top = task_stack_top(&unsafe { task_stacks_mut() }[PROBE_SLOT]);
    let scheduler = unsafe { scheduler_mut() };
    *scheduler = Scheduler::new();
    let tid = unsafe { id_allocator_mut() }.allocate_tid()?;
    scheduler.configure_thread(
        PROBE_SLOT,
        tid,
        KERNEL_PROCESS_ID,
        ThreadKind::Kernel,
        stack_top,
        stack_top,
        stack_guard_probe_bootstrap_entry as usize as u64,
    )
}

/// Fresh kernel threads start with RSP at the 16-byte aligned stack top.
#[unsafe(naked)]
extern "C" fn stack_guard_probe_bootstrap_entry() -> ! {
    core::arch::naked_asm!(
        "sub rsp, 32",
        "call {task}",
        "ud2",
        task = sym stack_guard_probe_task,
    )
}

extern "C" fn stack_guard_probe_task() -> ! {
    crate::arch::x86_64::cpu::enable_interrupts();
    serial_write_fmt(format_args!(
        "[KSTK] probe start slot={PROBE_SLOT} frame_bytes={FRAME_BYTES} depth_limit={DEPTH_LIMIT} stack_bytes={TASK_STACK_SIZE}\n"
    ));
    PROBE_RUNNING.store(true, Ordering::SeqCst);
    let depth = recurse(0);
    PROBE_RUNNING.store(false, Ordering::SeqCst);
    serial_write_fmt(format_args!(
        "[FAIL] kernel stack guard absent: recursion reached depth={depth} without a fault\n"
    ));
    qemu_exit(QEMU_EXIT_FAILURE)
}

#[inline(never)]
fn recurse(depth: usize) -> usize {
    let mut frame = [0u8; FRAME_BYTES];
    frame[depth % FRAME_BYTES] = depth as u8;
    let frame = black_box(&mut frame);
    if depth + 1 >= DEPTH_LIMIT {
        return depth + 1;
    }
    let reached = recurse(depth + 1);
    black_box(frame[0]);
    reached
}

/// Called from the production overflow report; exits QEMU either way.
pub(crate) fn on_kernel_stack_overflow(
    stack: GuardedStackRecord,
    via: &'static str,
    handler_rsp: u64,
) -> ! {
    let ist = unsafe { &*DOUBLE_FAULT_STACK.get() };
    let on_ist = handler_rsp >= ist.base() && handler_rsp < ist.top();
    let expected_stack = stack.kind == KernelStackKind::Task { slot: PROBE_SLOT };
    serial_write_fmt(format_args!(
        "[KSTK] caught via={via} on_ist={on_ist} expected_slot={expected_stack}\n"
    ));
    if PROBE_RUNNING.load(Ordering::SeqCst) && expected_stack && via == "double-fault" && on_ist {
        serial_write_line("[KSTK] PASS");
        qemu_exit(QEMU_EXIT_SUCCESS)
    }
    serial_write_line("[KSTK] overflow report did not match the probe");
    qemu_exit(QEMU_EXIT_FAILURE)
}
