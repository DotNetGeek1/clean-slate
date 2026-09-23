//! Dedicated kernel idle thread: `hlt` with interrupts enabled while all app threads are blocked.

use crate::arch::x86_64::asm::clean_slate_idle_thread_bootstrap_entry;
use crate::arch::x86_64::context_switch::resume_after_scheduler_handoff;
use crate::arch::x86_64::context_switch::set_next_task;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::context_switch::FRESH_TASK_SENTINEL;
use crate::arch::x86_64::cpu::enable_interrupts;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::interrupt::timer::kernel_ticks;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::KERNEL_PROCESS_ID;
use crate::sched::dispatch::prepare_current_scheduler_thread_dispatch;
use crate::sched::scheduler_mut;
use crate::sched::task_stacks_mut;
use crate::sched::wait;
use crate::sched::ThreadState;
use crate::sched::IDLE_THREAD_INDEX;
use core::sync::atomic::{AtomicBool, Ordering};

static IDLE_THREAD_CONFIGURED: AtomicBool = AtomicBool::new(false);

const IDLE_STACK_GUARD_BYTES: u64 = 1024;

#[unsafe(no_mangle)]
extern "C" fn clean_slate_idle_thread() -> ! {
    loop {
        idle_thread_one_wait();
    }
}

fn idle_thread_one_wait() {
    assert_idle_stack_within_guard();
    #[cfg(feature = "m9-block-wake-self-test")]
    crate::selftest::m9_block_wake::on_idle_loop_wake();
    enable_interrupts();
    unsafe {
        core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
    }
    let next_stack = without_interrupts(|| {
        let _ = wait::expire_deadlines(kernel_ticks());
        unsafe { scheduler_mut().wake_from_idle_loop() }
    });
    match next_stack {
        Ok(stack_pointer) => {
            if let Err(message) = prepare_current_scheduler_thread_dispatch() {
                fatal_kernel_error(message);
            }
            resume_after_scheduler_handoff(
                Some(stack_pointer),
                "idle handoff lost runnable thread",
            );
        }
        Err("idle woke without a runnable thread") => {}
        Err(message) => fatal_kernel_error(message),
    }
}

#[cfg_attr(feature = "m9-block-wake-self-test", allow(dead_code))]
#[cfg_attr(feature = "m9-block-wake-self-test", allow(dead_code))]
fn assert_idle_stack_within_guard() {
    let stack_top = idle_kernel_stack_top();
    let rsp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack));
    }
    let floor = stack_top.saturating_sub(IDLE_STACK_GUARD_BYTES);
    if rsp < floor || rsp > stack_top {
        fatal_kernel_error("idle thread stack depth exceeded guard");
    }
}

pub(crate) fn idle_kernel_stack_top() -> u64 {
    unsafe {
        let stacks = &*task_stacks_mut();
        task_stack_top(&stacks[IDLE_THREAD_INDEX])
    }
}

pub(crate) fn ensure_idle_thread_configured() -> Result<(), &'static str> {
    if IDLE_THREAD_CONFIGURED.load(Ordering::Acquire) {
        return Ok(());
    }
    without_interrupts(|| {
        let scheduler = unsafe { scheduler_mut() };
        if scheduler.threads[IDLE_THREAD_INDEX].state != ThreadState::Empty {
            IDLE_THREAD_CONFIGURED.store(true, Ordering::Release);
            return Ok(());
        }
        let stack_top = idle_kernel_stack_top();
        let tid = unsafe { id_allocator_mut().allocate_tid()? };
        scheduler.configure_thread(
            IDLE_THREAD_INDEX,
            tid,
            KERNEL_PROCESS_ID,
            crate::sched::ThreadKind::Kernel,
            stack_top,
            stack_top,
            clean_slate_idle_thread_bootstrap_entry as usize as u64,
        )?;
        scheduler.threads[IDLE_THREAD_INDEX].state = ThreadState::Empty;
        IDLE_THREAD_CONFIGURED.store(true, Ordering::Release);
        Ok(())
    })
}

pub(crate) fn handoff_to_idle_thread() -> Result<u64, &'static str> {
    ensure_idle_thread_configured()?;
    let scheduler = unsafe { scheduler_mut() };
    let idle = IDLE_THREAD_INDEX;
    scheduler.current_thread = Some(idle);
    scheduler.threads[idle].state = ThreadState::Running;
    scheduler.threads[idle].started = true;
    // Always bootstrap a clean idle stack. Reusing `saved_stack_pointer` here would
    // return through `restore_context`/`iretq` from the syscall path after timer
    // preemption, which corrupts the stack.
    let stack_top = idle_kernel_stack_top();
    unsafe {
        set_next_task(
            stack_top,
            clean_slate_idle_thread_bootstrap_entry as usize as u64,
        );
    }
    Ok(FRESH_TASK_SENTINEL)
}
