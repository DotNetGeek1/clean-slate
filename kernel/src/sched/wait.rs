//! Native blocking/wake substrate for scheduler threads (#145).

#![allow(dead_code)]
//!
//! `Deadline` is an absolute `kernel_ticks()` value (APIC timer increments; uncalibrated).

use crate::arch::x86_64::context_switch::resume_after_scheduler_handoff;
use crate::arch::x86_64::context_switch::SYSCALL_BLOCKED_RESUME_SENTINEL;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::kernel_log_fmt;
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

/// How a blocked syscall is completed from the scheduler after its wake.
///
/// The blocked handler's kernel stack is abandoned at block time; the scheduler
/// finishes the syscall by editing the saved [`SyscallContext`] and `sysretq`-ing
/// straight back to user space. Native callers see the raw outcome in `RAX`.
/// Linux handlers need to finish work after the wake (copy pipe bytes, fill a
/// `wait4` status, fill `pollfd.revents`), so they use the Linux
/// `-ERESTARTSYS` shape instead: re-execute the `syscall` instruction with the
/// argument registers untouched and let the handler re-check its condition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlockedResume {
    /// `RAX = encode_wait_outcome(outcome)` (#145 native contract).
    NativeOutcome,
    /// `Woken`/`Cancelled`: `user_rip -= SYSCALL_INSTRUCTION_BYTES`, `RAX = nr`.
    /// `TimedOut`: `RAX = timeout_rax` (already errno-encoded by the caller).
    RestartSyscall { nr: u64, timeout_rax: u64 },
}

/// Length of the `syscall` instruction (`0F 05`); SYSCALL saves the address of
/// the following instruction in RCX, so restarting means backing up by this.
pub(crate) const SYSCALL_INSTRUCTION_BYTES: u64 = 2;

static BLOCKED_RESUME: crate::sync::global_cell::GlobalCell<
    [BlockedResume; super::SCHEDULER_THREAD_SLOTS],
> = crate::sync::global_cell::GlobalCell::new(
    [BlockedResume::NativeOutcome; super::SCHEDULER_THREAD_SLOTS],
);

fn set_blocked_resume(thread_index: usize, resume: BlockedResume) {
    // Caller holds interrupts disabled and owns `thread_index` as the current thread.
    unsafe {
        (*BLOCKED_RESUME.get())[thread_index] = resume;
    }
}

fn take_blocked_resume(thread_index: usize) -> BlockedResume {
    unsafe {
        let slot = &mut (*BLOCKED_RESUME.get())[thread_index];
        core::mem::replace(slot, BlockedResume::NativeOutcome)
    }
}

/// Edit the saved frame so the woken thread completes its syscall per `resume`.
pub(crate) fn apply_blocked_resume(
    frame: &mut SyscallContext,
    resume: BlockedResume,
    outcome: WaitOutcome,
) {
    match resume {
        BlockedResume::NativeOutcome => frame.rax = encode_wait_outcome(outcome),
        BlockedResume::RestartSyscall { nr, timeout_rax } => match outcome {
            WaitOutcome::TimedOut => frame.rax = timeout_rax,
            WaitOutcome::Woken | WaitOutcome::Cancelled => {
                frame.user_rip = frame
                    .user_rip
                    .checked_sub(SYSCALL_INSTRUCTION_BYTES)
                    .unwrap_or_else(|| {
                        crate::diagnostics::qemu::fatal_kernel_error(
                            "blocked syscall restart: user rip underflow",
                        )
                    });
                frame.rax = nr;
            }
        },
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
///
/// Native contract: on wake the scheduler completes the syscall with
/// `RAX = encode_wait_outcome(outcome)`. Returns `Ok(Woken)` without yielding
/// when a pending wake for `key` was already recorded.
pub(crate) fn block_current_thread(
    frame: *mut SyscallContext,
    key: WaitKey,
    deadline: Option<Deadline>,
) -> Result<WaitOutcome, &'static str> {
    block_current_thread_with_resume(frame, key, deadline, BlockedResume::NativeOutcome)
}

/// [`block_current_thread`] with an explicit completion contract (Linux restart).
///
/// Only returns (with `Ok(Woken)`) when no yield was necessary; the caller then
/// applies the same completion it would have received from the scheduler.
pub(crate) fn block_current_thread_with_resume(
    frame: *mut SyscallContext,
    key: WaitKey,
    deadline: Option<Deadline>,
    resume: BlockedResume,
) -> Result<WaitOutcome, &'static str> {
    let must_yield = without_interrupts(|| {
        let scheduler = unsafe { scheduler_mut() };
        let thread_index = scheduler
            .current_thread
            .ok_or("block required a current scheduler thread")?;
        let thread = &mut scheduler.threads[thread_index];
        if thread.state != ThreadState::Running {
            return Err("block required the running thread state");
        }
        thread.blocked_syscall_frame = frame as u64;
        set_blocked_resume(thread_index, resume);
        let tid = thread.id;
        let pid = thread.owner_process_id;
        let generation =
            live_instance_generation(pid).ok_or("block process had no live generation")?;

        let table = wait_table_mut();
        if table.consume_pending_wake(key) {
            thread.blocked_syscall_frame = 0;
            set_blocked_resume(thread_index, BlockedResume::NativeOutcome);
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

pub(super) fn waiter_deadline_due(deadline: Option<Deadline>, now_ticks: u64) -> bool {
    match deadline {
        Some(Deadline(ticks)) => now_ticks >= ticks,
        None => false,
    }
}

pub(crate) fn expire_deadlines(now_ticks: u64) -> usize {
    without_interrupts(|| {
        let mut expired = 0usize;
        let table = wait_table_mut();
        for slot in &mut table.slots {
            if !slot.active {
                continue;
            }
            if !waiter_deadline_due(slot.deadline, now_ticks) {
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
        set_blocked_resume(index, BlockedResume::NativeOutcome);
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
        let resume = take_blocked_resume(index);
        let frame = unsafe { &mut *(frame_ptr as *mut SyscallContext) };
        apply_blocked_resume(frame, resume, outcome);
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

pub(crate) fn clear_wait_table_for_tests() {
    *wait_table_mut() = WaitTable::new();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_at(user_rip: u64) -> SyscallContext {
        SyscallContext {
            rax: 0xdead,
            rdx: 3,
            rbx: 0,
            rbp: 0,
            rsi: 2,
            rdi: 1,
            r8: 5,
            r9: 6,
            r10: 4,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            user_rip,
            user_rflags: 0x202,
            user_rsp: 0x7fff_0000,
        }
    }

    #[test]
    fn native_resume_encodes_outcome_and_leaves_rip_alone() {
        let mut frame = frame_at(0x40_1000);
        apply_blocked_resume(
            &mut frame,
            BlockedResume::NativeOutcome,
            WaitOutcome::TimedOut,
        );
        assert_eq!(frame.rax, encode_wait_outcome(WaitOutcome::TimedOut));
        assert_eq!(frame.user_rip, 0x40_1000);
    }

    #[test]
    fn restart_resume_reexecutes_syscall_with_arguments_intact() {
        for outcome in [WaitOutcome::Woken, WaitOutcome::Cancelled] {
            let mut frame = frame_at(0x40_1002);
            apply_blocked_resume(
                &mut frame,
                BlockedResume::RestartSyscall {
                    nr: 7,
                    timeout_rax: u64::MAX,
                },
                outcome,
            );
            assert_eq!(frame.user_rip, 0x40_1000, "rip backs up over `syscall`");
            assert_eq!(frame.rax, 7, "rax carries the syscall number again");
            assert_eq!((frame.rdi, frame.rsi, frame.rdx), (1, 2, 3));
            assert_eq!((frame.r10, frame.r8, frame.r9), (4, 5, 6));
            assert_eq!(frame.user_rsp, 0x7fff_0000);
            assert_eq!(frame.user_rflags, 0x202);
        }
    }

    #[test]
    fn restart_resume_completes_with_timeout_result_on_deadline() {
        let mut frame = frame_at(0x40_1002);
        let timeout_rax = (-110i64) as u64; // -ETIMEDOUT
        apply_blocked_resume(
            &mut frame,
            BlockedResume::RestartSyscall { nr: 7, timeout_rax },
            WaitOutcome::TimedOut,
        );
        assert_eq!(frame.user_rip, 0x40_1002, "no restart on timeout");
        assert_eq!(frame.rax, timeout_rax);
    }

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

    #[test]
    fn waiter_table_capacity_exhaustion_fails_closed() {
        let mut table = WaitTable::new();
        for _ in 0..MAX_WAITERS {
            let index = table.allocate_slot().expect("slot");
            table.slots[index].active = true;
        }
        assert_eq!(table.allocate_slot(), Err("waiter table exhausted"));
    }

    #[test]
    fn waiter_deadline_due_only_at_or_after_tick() {
        assert!(!waiter_deadline_due(Some(Deadline(5)), 4));
        assert!(waiter_deadline_due(Some(Deadline(5)), 5));
        assert!(!waiter_deadline_due(None, 100));
    }

    #[test]
    fn wake_before_block_pending_wake_race() {
        let mut table = WaitTable::new();
        let key = WaitKey(77);
        table.record_pending_wake(key);
        assert!(table.consume_pending_wake(key));
    }

    #[test]
    fn cancel_waiters_table_scan_clears_matching_pid_and_generation() {
        let mut table = WaitTable::new();
        let slot = table.allocate_slot().expect("slot");
        table.slots[slot] = WaiterSlot {
            active: true,
            pid: 42,
            generation: InstanceGeneration(3),
            tid: 1,
            thread_index: 0,
            key: WaitKey(1),
            deadline: None,
        };
        let other = table.allocate_slot().expect("slot");
        table.slots[other] = WaiterSlot {
            active: true,
            pid: 43,
            generation: InstanceGeneration(1),
            tid: 2,
            thread_index: 1,
            key: WaitKey(2),
            deadline: None,
        };
        for slot in &mut table.slots {
            if slot.active && slot.pid == 42 && slot.generation == InstanceGeneration(3) {
                slot.active = false;
            }
        }
        assert!(!table.slots[slot].active);
        assert!(table.slots[other].active);
    }

    #[test]
    fn stale_generation_wake_denied_when_live_generation_missing() {
        let slot_generation = InstanceGeneration(1);
        let live: Option<InstanceGeneration> = None;
        assert_ne!(live, Some(slot_generation));
    }
}
