//! The two M2 demo kernel tasks and their progress/exit reporting.

use crate::arch::x86_64::context_switch::next_task;
use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::start_first_task;
use crate::arch::x86_64::context_switch::FRESH_TASK_SENTINEL;
use crate::arch::x86_64::cpu::disable_interrupts;
use crate::arch::x86_64::cpu::enable_interrupts;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
#[cfg(all(
    not(feature = "m2-self-test"),
    not(all(feature = "m8-linux-hello", not(feature = "m8-linux-hello-self-test")))
))]
use crate::diagnostics::qemu::halt_loop;
#[cfg(feature = "m2-self-test")]
use crate::diagnostics::qemu::qemu_exit;
#[cfg(feature = "m2-self-test")]
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::interrupt::timer::kernel_ticks;
use crate::sched::dispatch::prepare_current_scheduler_thread_dispatch;
use crate::sched::scheduler_mut;
use crate::sched::with_scheduler;
use crate::sched::TASK_PROGRESS_CHUNK;
use crate::sched::TASK_REQUIRED_PREEMPTIONS;
use core::hint::spin_loop;

/// Sample progress while spinning so a task can log `progress=1` before
/// `thread_should_exit` at ~1 ms LAPIC preemption rates (see `TASK_PROGRESS_CHUNK`).
const PROGRESS_SAMPLE_INTERVAL: u64 = 512;

#[cfg(all(feature = "m8-linux-hello", not(feature = "m8-linux-hello-self-test")))]
fn demo_tasks_may_exit_on_preemption_threshold() -> bool {
    false
}

#[cfg(not(all(feature = "m8-linux-hello", not(feature = "m8-linux-hello-self-test"))))]
fn demo_tasks_may_exit_on_preemption_threshold() -> bool {
    true
}

#[unsafe(no_mangle)]
extern "C" fn clean_slate_task_one() -> ! {
    kernel_log_line("[TASK] task 1 started");
    enable_interrupts();
    run_demo_task(1)
}

#[unsafe(no_mangle)]
extern "C" fn clean_slate_task_two() -> ! {
    kernel_log_line("[TASK] task 2 started");
    enable_interrupts();
    run_demo_task(2)
}

fn run_demo_task(task_id: u64) -> ! {
    let mut progress = 0u64;
    loop {
        for _ in 0..TASK_PROGRESS_CHUNK {
            progress = progress.wrapping_add(1);
            spin_loop();
            if progress % PROGRESS_SAMPLE_INTERVAL == 0 {
                note_task_progress(task_id, progress);
                flush_scheduler_markers(task_id);
                if demo_tasks_may_exit_on_preemption_threshold() && task_ready_to_exit(task_id) {
                    task_exit();
                }
            }
        }
        note_task_progress(task_id, progress);
        flush_scheduler_markers(task_id);
        if demo_tasks_may_exit_on_preemption_threshold() && task_ready_to_exit(task_id) {
            task_exit();
        }
    }
}

fn flush_scheduler_markers(task_id: u64) {
    let (preemption_log, progress_log) = without_interrupts(|| unsafe {
        let scheduler = scheduler_mut();
        let preemption_log = if scheduler.preemption_observed && !scheduler.preemption_logged {
            scheduler.preemption_logged = true;
            true
        } else {
            false
        };

        let progress_log = scheduler
            .threads
            .iter_mut()
            .find(|thread| thread.id == task_id)
            .and_then(|thread| {
                if thread.preemptions >= TASK_REQUIRED_PREEMPTIONS
                    && !thread.progress_logged
                    && thread.observed_progress != 0
                {
                    thread.progress_logged = true;
                    Some(thread.observed_progress)
                } else {
                    None
                }
            });

        (preemption_log, progress_log)
    });

    if preemption_log {
        kernel_log_line("[SCHED] preemption observed");
    }
    if progress_log.is_some() {
        match task_id {
            1 => kernel_log_line("[TASK] task 1 progress=1"),
            2 => kernel_log_line("[TASK] task 2 progress=1"),
            _ => kernel_log_line("[TASK] task progress=1"),
        }
        #[cfg(all(feature = "m8-linux-hello", not(feature = "m8-linux-hello-self-test")))]
        maybe_log_m2_pass_when_both_demo_tasks_ready();
    }
}

#[cfg(all(feature = "m8-linux-hello", not(feature = "m8-linux-hello-self-test")))]
fn maybe_log_m2_pass_when_both_demo_tasks_ready() {
    if both_demo_tasks_logged_acceptance_progress() {
        log_m2_pass_once();
    }
}

fn log_m2_pass_once() {
    unsafe {
        if !scheduler_mut().pass_emitted {
            scheduler_mut().pass_emitted = true;
            kernel_log_fmt(format_args!("[TIME] ticks={}\n", kernel_ticks()));
            kernel_log_line("[M2  ] PASS");
        }
    }
}

fn note_task_progress(task_id: u64, progress: u64) {
    without_interrupts(|| unsafe {
        scheduler_mut().note_progress(task_id, progress);
    });
}

/// Do not retire a demo thread until progress is logged (same gate as
/// `both_demo_tasks_logged_acceptance_progress`).
fn task_ready_to_exit(task_id: u64) -> bool {
    without_interrupts(|| unsafe {
        if !scheduler_mut().thread_should_exit(task_id) {
            return false;
        }
        scheduler_mut()
            .threads
            .iter()
            .find(|thread| thread.id == task_id)
            .is_some_and(|thread| thread.progress_logged)
    })
}

fn both_demo_tasks_logged_acceptance_progress() -> bool {
    without_interrupts(|| unsafe {
        scheduler_mut()
            .threads
            .iter()
            .fold((false, false), |(t1, t2), thread| {
                let logged = thread.progress_logged;
                match thread.id {
                    1 => (logged, t2),
                    2 => (t1, logged),
                    _ => (t1, t2),
                }
            })
            == (true, true)
    })
}

fn task_exit() -> ! {
    disable_interrupts();
    let next = match with_scheduler(|scheduler| scheduler.finish_current_thread()) {
        Ok(next) => next,
        Err(message) => fatal_kernel_error(message),
    };
    match next {
        Some(stack_pointer) => {
            if let Err(message) = prepare_current_scheduler_thread_dispatch() {
                fatal_kernel_error(message);
            }
            if stack_pointer == FRESH_TASK_SENTINEL {
                let (fresh_stack_pointer, entry_point) = unsafe { next_task() };
                unsafe { start_first_task(fresh_stack_pointer, entry_point) }
            } else {
                unsafe { restore_task_context(stack_pointer) }
            }
        }
        None => {
            if with_scheduler(|scheduler| scheduler.all_finished())
                && both_demo_tasks_logged_acceptance_progress()
            {
                emit_m2_pass_and_stop()
            } else if with_scheduler(|scheduler| scheduler.all_finished()) {
                fatal_kernel_error(
                    "demo tasks finished before both logged scheduler acceptance progress",
                )
            } else {
                fatal_kernel_error("scheduler had no runnable thread during task exit")
            }
        }
    }
}

fn emit_m2_pass_and_stop() -> ! {
    log_m2_pass_once();

    #[cfg(feature = "m2-self-test")]
    {
        qemu_exit(QEMU_EXIT_SUCCESS)
    }

    #[cfg(all(
        not(feature = "m2-self-test"),
        feature = "m8-linux-hello",
        not(feature = "m8-linux-hello-self-test")
    ))]
    {
        loop {
            spin_loop();
        }
    }

    #[cfg(all(
        not(feature = "m2-self-test"),
        not(all(feature = "m8-linux-hello", not(feature = "m8-linux-hello-self-test")))
    ))]
    {
        halt_loop()
    }
}
