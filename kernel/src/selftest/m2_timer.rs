//! Milestone 2 timer self-test: runs a fresh kernel task that waits for the
//! LAPIC timer to deliver a handful of ticks and reports them over serial.
//!
//! `clean_slate_timer_self_test_task` is a `no_mangle` symbol referenced
//! unconditionally by the bootstrap trampoline in `arch::x86_64::asm`, so this
//! module is always compiled; only its body is feature-gated.

#[cfg(feature = "m2-timer-self-test")]
use crate::arch::x86_64::asm::clean_slate_timer_self_test_bootstrap_entry;
#[cfg(feature = "m2-timer-self-test")]
use crate::arch::x86_64::context_switch::start_first_task;
#[cfg(feature = "m2-timer-self-test")]
use crate::arch::x86_64::context_switch::task_stack_top;
#[cfg(feature = "m2-timer-self-test")]
use crate::arch::x86_64::cpu::enable_interrupts;
#[cfg(not(feature = "m2-timer-self-test"))]
use crate::diagnostics::qemu::halt_loop;
#[cfg(feature = "m2-timer-self-test")]
use crate::diagnostics::qemu::qemu_exit;
#[cfg(feature = "m2-timer-self-test")]
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
#[cfg(feature = "m2-timer-self-test")]
use crate::diagnostics::serial::serial_write_fmt;
#[cfg(feature = "m2-timer-self-test")]
use crate::diagnostics::serial::serial_write_line;
#[cfg(feature = "m2-timer-self-test")]
use crate::interrupt::timer::kernel_ticks;
#[cfg(feature = "m2-timer-self-test")]
use crate::sched::task_stacks_mut;
#[cfg(feature = "m2-timer-self-test")]
use core::arch::asm;

#[cfg(feature = "m2-timer-self-test")]
const TIMER_SELF_TEST_REQUIRED_TICKS: u64 = 4;

#[cfg(feature = "m2-timer-self-test")]
pub(crate) fn start_timer_self_test_task() -> ! {
    let stack_pointer = unsafe {
        let stacks = &*task_stacks_mut();
        task_stack_top(&stacks[0])
    };
    unsafe {
        start_first_task(
            stack_pointer,
            clean_slate_timer_self_test_bootstrap_entry as usize as u64,
        )
    }
}

#[unsafe(no_mangle)]
extern "C" fn clean_slate_timer_self_test_task() -> ! {
    #[cfg(feature = "m2-timer-self-test")]
    {
        enable_interrupts();
        let mut first_tick_logged = false;
        loop {
            let ticks = kernel_ticks();
            if ticks >= 1 && !first_tick_logged {
                first_tick_logged = true;
                serial_write_line("[TIME] tick=1");
            }
            if ticks >= TIMER_SELF_TEST_REQUIRED_TICKS {
                serial_write_fmt(format_args!("[TIME] ticks={ticks}\n"));
                serial_write_line("[TIME] PASS");
                qemu_exit(QEMU_EXIT_SUCCESS)
            }
            unsafe {
                asm!("hlt", options(nomem, nostack, preserves_flags));
            }
        }
    }

    #[cfg(not(feature = "m2-timer-self-test"))]
    {
        halt_loop()
    }
}
