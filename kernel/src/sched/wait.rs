//! Native blocking/wake substrate for scheduler threads (#145).

#![allow(dead_code)]
//!
//! `Deadline` is an absolute `kernel_ticks()` value (APIC timer increments; uncalibrated).

use crate::arch::x86_64::context_switch::resume_after_scheduler_handoff;
use crate::arch::x86_64::context_switch::SYSCALL_BLOCKED_RESUME_SENTINEL;
use crate::arch::x86_64::cpu::enable_interrupts;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::kernel_log_fmt;
use crate::interrupt::timer::kernel_ticks;
use crate::process::live_instance_generation;
use crate::sched::dispatch::prepare_current_scheduler_thread_dispatch;
use crate::sched::scheduler_mut;
use crate::sched::ThreadState;
use clean_slate_service_lifecycle::InstanceGeneration;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WaitKey(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitOutcome {
    Woken,
    TimedOut,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Deadline(pub u64);

pub(crate) const MAX_WAITERS: usize = super::TASK_COUNT;

const STALE_WAKE_LOG_LIMIT: u64 = 8;
static STALE_WAKE_LOG_COUNT: AtomicU64 = AtomicU64::new(0);

const WOKEN_MAGIC: u64 = 0x0000_4D39_E145_0001;
const TIMEOUT_MAGIC: u64 = 0x0000_4D39_E145_0002;
const CANCEL_MAGIC: u64 = 0x0000_4D39_E145_0003;

pub(crate) fn encode_wait_outcome(outcome: WaitOutcome) -> u64 {
    match outcome {
        WaitOutcome::Woken => WOKEN_MAGIC,
        WaitOutcome::TimedOut => TIMEOUT_MAGIC,
        WaitOutcome::Cancelled => CANCEL_MAGIC,
    }
}

#[derive(Clone, Copy)]
struct WaiterSlot {
    active: bool,
    pid: u64,
    generation: InstanceGeneration,
    tid: u64,
    thread_index: usize,
    key: WaitKey,
    deadline: Option<Deadline>,
}

impl WaiterSlot {
    const EMPTY: Self = Self {
        active: false,
        pid: 0,
        generation: InstanceGeneration(0),
        tid: 0,
        thread_index: 0,
        key: WaitKey(0),
        deadline: None,
    };
}

struct WaitTable {
    slots: [WaiterSlot; MAX_WAITERS],
    pending_wake_keys: [u64; MAX_WAITERS],
}

impl WaitTable {
    const fn new() -> Self {
        Self {
            slots: [WaiterSlot::EMPTY; MAX_WAITERS],
            pending_wake_keys: [0; MAX_WAITERS],
        }
    }

    fn allocate_slot(&mut self) -> Result<usize, &'static str> {
        self.slots
            .iter()
            .position(|slot| !slot.active)
            .ok_or("waiter table exhausted")
    }

    fn occupied(&self) -> usize {
        self.slots.iter().filter(|slot| slot.active).count()
    }

    fn record_pending_wake(&mut self, key: WaitKey) {
        if self.pending_wake_keys.contains(&key.0) {
            return;
        }
        if let Some(slot) = self.pending_wake_keys.iter_mut().find(|k| **k == 0) {
            *slot = key.0;
        }
    }

    fn consume_pending_wake(&mut self, key: WaitKey) -> bool {
        if let Some(slot) = self.pending_wake_keys.iter_mut().find(|k| **k == key.0) {
            *slot = 0;
            return true;
        }
        false
    }
}

static WAIT_TABLE: crate::sync::global_cell::GlobalCell<WaitTable> =
    crate::sync::global_cell::GlobalCell::new(WaitTable::new());

fn wait_table_mut() -> &'static mut WaitTable {
    unsafe { &mut *WAIT_TABLE.get() }
}

pub(crate) fn waiter_occupancy() -> usize {
    without_interrupts(|| wait_table_mut().occupied())
}

fn log_stale_wake(pid: u64, generation: InstanceGeneration) {
    let observed = STALE_WAKE_LOG_COUNT.fetch_add(1, Ordering::Relaxed);
    if observed < STALE_WAKE_LOG_LIMIT {
        kernel_log_fmt(format_args!(
            "[M9.E] stale wake denied pid={} generation={}\n",
            pid, generation.0
        ));
    }
}

fn wake_thread_at_index(thread_index: usize, outcome: WaitOutcome) {
    let scheduler = unsafe { scheduler_mut() };
    let thread = &mut scheduler.threads[thread_index];
    if thread.state != ThreadState::Blocked {
        return;
    }
    thread.wait_resume_outcome = outcome;
    thread.state = ThreadState::Ready;
}

/// Called ONLY from a syscall handler on the current thread.
pub(crate) fn block_current_thread(
    key: WaitKey,
    deadline: Option<Deadline>,
) -> Result<WaitOutcome, &'static str> {
    let must_yield = without_interrupts(|| {
        let scheduler = unsafe { scheduler_mut() };
        let thread_index = scheduler
            .current_thread
            .ok_or("block required a current scheduler thread")?;
        let thread = &scheduler.threads[thread_index];
        if thread.state != ThreadState::Running {
            return Err("block required the running thread state");
        }
        let tid = thread.id;
        let pid = thread.owner_process_id;
        let generation =
            live_instance_generation(pid).ok_or("block process had no live generation")?;
        if thread.blocked_syscall_frame == 0 {
            return Err("block required syscall continuation frame");
        }

        let table = wait_table_mut();
        if table.consume_pending_wake(key) {
            return Ok(false);
        }

        let slot_index = table.allocate_slot()?;
        table.slots[slot_index] = WaiterSlot {
            active: true,
            pid,
            generation,
            tid,
            thread_index,
            key,
            deadline,
        };

        scheduler.threads[thread_index].state = ThreadState::Blocked;
        kernel_log_fmt(format_args!("[M9.E] blocked tid={} key={}\n", tid, key.0));
        Ok(true)
    })?;

    if !must_yield {
        return Ok(WaitOutcome::Woken);
    }

    scheduler_block_and_switch();
}

pub(crate) fn wake_one(key: WaitKey) -> usize {
    without_interrupts(|| wake_matching(key, false))
}

pub(crate) fn wake_all(key: WaitKey) -> usize {
    without_interrupts(|| wake_matching(key, true))
}

/// Voluntary yield from a syscall handler; may resume via blocked-syscall sentinel.
pub(crate) fn voluntary_yield_from_syscall(frame: *mut SyscallContext) -> ! {
    let next = without_interrupts(|| {
        arm_syscall_block_frame(frame);
        let scheduler = unsafe { scheduler_mut() };
        let current = scheduler
            .current_thread
            .ok_or("voluntary yield required current thread")?;
        scheduler.threads[current].state = ThreadState::Ready;
        scheduler.pick_next_runnable_stack_pointer()
    })
    .unwrap_or_else(|message| crate::diagnostics::qemu::fatal_kernel_error(message));
    if let Err(message) = prepare_current_scheduler_thread_dispatch() {
        crate::diagnostics::qemu::fatal_kernel_error(message);
    }
    resume_after_scheduler_handoff(
        Some(next),
        "no runnable thread remained after voluntary syscall yield",
    )
}

fn wake_matching(key: WaitKey, all: bool) -> usize {
    let mut woken = 0usize;
    let table = wait_table_mut();
    let mut found = false;
    for slot in &mut table.slots {
        if !slot.active || slot.key.0 != key.0 {
            continue;
        }
        found = true;
        let live = live_instance_generation(slot.pid);
        if live != Some(slot.generation) {
            log_stale_wake(slot.pid, slot.generation);
            continue;
        }
        let index = slot.thread_index;
        slot.active = false;
        wake_thread_at_index(index, WaitOutcome::Woken);
        woken += 1;
        if !all {
            break;
        }
    }
    if !found {
        table.record_pending_wake(key);
    }
    woken
}

pub(crate) fn cancel_waiters_for_process(pid: u64, generation: InstanceGeneration) -> usize {
    without_interrupts(|| {
        let mut cancelled = 0usize;
        let table = wait_table_mut();
        for slot in &mut table.slots {
            if !slot.active || slot.pid != pid || slot.generation != generation {
                continue;
            }
            let index = slot.thread_index;
            slot.active = false;
            wake_thread_at_index(index, WaitOutcome::Cancelled);
            cancelled += 1;
        }
        cancelled
    })
}

pub(crate) fn expire_deadlines(now_ticks: u64) -> usize {
    without_interrupts(|| {
        let mut expired = 0usize;
        let table = wait_table_mut();
        for slot in &mut table.slots {
            if !slot.active {
                continue;
            }
            let deadline = match slot.deadline {
                Some(Deadline(ticks)) => ticks,
                None => continue,
            };
            if now_ticks < deadline {
                continue;
            }
            let index = slot.thread_index;
            slot.active = false;
            wake_thread_at_index(index, WaitOutcome::TimedOut);
            expired += 1;
        }
        expired
    })
}

pub(crate) fn arm_syscall_block_frame(frame: *mut SyscallContext) {
    without_interrupts(|| {
        let scheduler = unsafe { scheduler_mut() };
        let index = scheduler
            .current_thread
            .expect("syscall frame arm required current thread");
        scheduler.threads[index].blocked_syscall_frame = frame as u64;
    });
}

#[unsafe(no_mangle)]
extern "C" fn clean_slate_complete_blocked_syscall_resume() -> u64 {
    without_interrupts(|| {
        let scheduler = unsafe { scheduler_mut() };
        let index = scheduler
            .current_thread
            .expect("blocked syscall resume required current thread");
        let frame_ptr = scheduler.threads[index].blocked_syscall_frame;
        let outcome = scheduler.threads[index].wait_resume_outcome;
        scheduler.threads[index].blocked_syscall_frame = 0;
        let frame = unsafe { &mut *(frame_ptr as *mut SyscallContext) };
        frame.rax = encode_wait_outcome(outcome);
        #[cfg(feature = "m9-block-wake-self-test")]
        crate::selftest::m9_block_wake::on_blocked_syscall_resumed(outcome, frame.rax);
        frame_ptr
    })
}

fn scheduler_block_and_switch() -> ! {
    let next = without_interrupts(|| unsafe { scheduler_mut().yield_from_blocked_thread() })
        .unwrap_or_else(|message| crate::diagnostics::qemu::fatal_kernel_error(message));
    if let Err(message) = prepare_current_scheduler_thread_dispatch() {
        crate::diagnostics::qemu::fatal_kernel_error(message);
    }
    resume_after_scheduler_handoff(Some(next), "no runnable thread remained after block")
}

pub(crate) fn scheduler_handoff_stack_pointer(next_stack_pointer: u64, thread_index: usize) -> u64 {
    let scheduler = unsafe { scheduler_mut() };
    if scheduler.threads[thread_index].blocked_syscall_frame != 0 {
        return SYSCALL_BLOCKED_RESUME_SENTINEL;
    }
    next_stack_pointer
}

#[allow(clippy::never_loop)]
pub(crate) fn idle_until_runnable() -> Result<u64, &'static str> {
    loop {
        enable_interrupts();
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
        let next = without_interrupts(|| {
            let _ = expire_deadlines(kernel_ticks());
            unsafe { scheduler_mut().pick_next_runnable_stack_pointer() }
        })?;
        return Ok(next);
    }
}

pub(crate) fn clear_wait_table_for_tests() {
    *wait_table_mut() = WaitTable::new();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_wake_is_consumed_on_block_register() {
        let mut table = WaitTable::new();
        let key = WaitKey(99);
        table.record_pending_wake(key);
        assert!(table.consume_pending_wake(key));
        assert!(!table.consume_pending_wake(key));
    }

    #[test]
    fn waiter_capacity_matches_task_count() {
        assert_eq!(MAX_WAITERS, super::super::TASK_COUNT);
    }
}
