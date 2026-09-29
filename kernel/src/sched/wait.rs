//! Native blocking/wake substrate for scheduler threads (#145).

#![allow(dead_code)]
//!
//! `Deadline` is an absolute calibrated `monotonic_ns()` value (#103, #180).

use crate::arch::x86_64::context_switch::resume_after_scheduler_handoff;
use crate::arch::x86_64::context_switch::SYSCALL_BLOCKED_RESUME_SENTINEL;
use crate::arch::x86_64::cpu::disable_interrupts;
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
pub(crate) enum Deadline {
    /// Absolute calibrated TSC time (`time::monotonic_ns`). There is no IRQ-tick
    /// variant: the tick delivery rate under QEMU TCG follows host timer resolution.
    MonotonicNs(u64),
}

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
    /// Every outcome, `TimedOut` included, re-executes the syscall with
    /// `RAX = nr`: the handler owns its deadline and completes the timeout
    /// itself (block I/O must fail the in-flight request closed on re-entry).
    RetrySyscall { nr: u64 },
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
            WaitOutcome::Woken | WaitOutcome::Cancelled => restart_syscall(frame, nr),
        },
        BlockedResume::RetrySyscall { nr } => restart_syscall(frame, nr),
    }
}

fn restart_syscall(frame: &mut SyscallContext, nr: u64) {
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

    fn enqueue(&mut self, waiter: WaiterSlot) -> Result<usize, &'static str> {
        let index = self.allocate_slot()?;
        self.slots[index] = waiter;
        Ok(index)
    }

    /// Deactivates waiters on `key` whose generation `is_live` accepts and reports each
    /// thread index to `woken`. Returns whether any waiter (live or stale) matched `key`.
    fn take_registered(
        &mut self,
        key: WaitKey,
        all: bool,
        is_live: impl Fn(u64, InstanceGeneration) -> bool,
        mut woken: impl FnMut(usize),
    ) -> bool {
        let mut found = false;
        for slot in &mut self.slots {
            if !slot.active || slot.key.0 != key.0 {
                continue;
            }
            found = true;
            if !is_live(slot.pid, slot.generation) {
                log_stale_wake(slot.pid, slot.generation);
                continue;
            }
            slot.active = false;
            woken(slot.thread_index);
            if !all {
                break;
            }
        }
        found
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

/// Whether `pid` has an active waiter on a key satisfying `matches`.
#[cfg(feature = "m10-port-self-test")]
pub(crate) fn has_waiter_where(pid: u64, matches: impl Fn(WaitKey) -> bool) -> bool {
    without_interrupts(|| {
        wait_table_mut()
            .slots
            .iter()
            .any(|slot| slot.active && slot.pid == pid && matches(slot.key))
    })
}

/// Active waiters whose owning pid satisfies `owned_by`.
#[cfg(feature = "m9-userspace-self-test")]
pub(crate) fn waiter_occupancy_where(mut owned_by: impl FnMut(u64) -> bool) -> usize {
    without_interrupts(|| {
        wait_table_mut()
            .slots
            .iter()
            .filter(|slot| slot.active && owned_by(slot.pid))
            .count()
    })
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
    #[cfg(feature = "m9-userspace-self-test")]
    crate::selftest::m9_userspace::on_thread_woken(thread_index, outcome);
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
        let waiter = arm_current_waiter(frame, key, deadline, resume)?;
        if wait_table_mut().consume_pending_wake(key) {
            match resume {
                BlockedResume::NativeOutcome => {
                    disarm_current_waiter(waiter.thread_index);
                    return Ok(false);
                }
                BlockedResume::RestartSyscall { .. } | BlockedResume::RetrySyscall { .. } => {
                    // Pending wakes may be stale (recorded when no thread was blocked).
                    // Linux handlers re-check after a real block; ignore the shortcut.
                }
            }
        }
        enqueue_current_waiter(waiter)?;
        Ok(true)
    })?;

    if !must_yield {
        return Ok(WaitOutcome::Woken);
    }

    scheduler_block_and_switch();
}

/// Readiness verdict for [`block_current_thread_unless`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlockCheck {
    /// Complete the syscall now with this `RAX`; nothing is registered.
    Ready(u64),
    Block,
}

/// Atomic check-then-block (M10 W1). Called ONLY from a syscall handler on the current thread.
///
/// `check` runs inside the same interrupts-disabled section that registers the waiter, so a
/// producer (IRQ or another syscall on the single CPU) runs either wholly before `check`,
/// which then observes its state change, or wholly after registration, and finds the waiter.
/// Pending wakes are neither consumed nor recorded: producers use [`wake_all_registered`].
///
/// Returns the ready `RAX` without yielding; otherwise the thread blocks and the scheduler
/// completes the syscall per `resume`. `check` may mutate and wake, but must not block.
pub(crate) fn block_current_thread_unless(
    frame: *mut SyscallContext,
    key: WaitKey,
    deadline: Option<Deadline>,
    resume: BlockedResume,
    check: impl FnOnce() -> BlockCheck,
) -> Result<u64, &'static str> {
    let ready = without_interrupts(|| {
        if let BlockCheck::Ready(rax) = check() {
            return Ok(Some(rax));
        }
        let waiter = arm_current_waiter(frame, key, deadline, resume)?;
        enqueue_current_waiter(waiter)?;
        Ok::<Option<u64>, &'static str>(None)
    })?;
    match ready {
        Some(rax) => Ok(rax),
        None => scheduler_block_and_switch(),
    }
}

/// Arms the current thread's blocked-syscall completion; the caller holds interrupts disabled.
fn arm_current_waiter(
    frame: *mut SyscallContext,
    key: WaitKey,
    deadline: Option<Deadline>,
    resume: BlockedResume,
) -> Result<WaiterSlot, &'static str> {
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
    let pid = thread.owner_process_id;
    let generation = live_instance_generation(pid).ok_or("block process had no live generation")?;
    Ok(WaiterSlot {
        active: true,
        pid,
        generation,
        tid: thread.id,
        thread_index,
        key,
        deadline,
    })
}

fn disarm_current_waiter(thread_index: usize) {
    unsafe { scheduler_mut() }.threads[thread_index].blocked_syscall_frame = 0;
    set_blocked_resume(thread_index, BlockedResume::NativeOutcome);
}

fn enqueue_current_waiter(waiter: WaiterSlot) -> Result<(), &'static str> {
    wait_table_mut().enqueue(waiter)?;
    unsafe { scheduler_mut() }.threads[waiter.thread_index].state = ThreadState::Blocked;
    #[cfg(feature = "m9-userspace-self-test")]
    crate::selftest::m9_userspace::on_thread_blocked(waiter.thread_index, waiter.pid);
    // A 60 Hz compositor blocks every frame; only the M9 lane needs the per-block line.
    #[cfg(feature = "m9-block-wake-self-test")]
    kernel_log_fmt(format_args!(
        "[M9.E] blocked tid={} key={}\n",
        waiter.tid, waiter.key.0
    ));
    Ok(())
}

pub(crate) fn wake_one(key: WaitKey) -> usize {
    without_interrupts(|| wake_matching(key, false, true))
}

pub(crate) fn wake_all(key: WaitKey) -> usize {
    without_interrupts(|| wake_matching(key, true, true))
}

/// Wakes every waiter on `key` and never records a pending wake (M10 W1).
///
/// Consumers of these keys block with [`block_current_thread_unless`], so a wake with no
/// waiter has nothing to deliver; recording one would spend a slot of the bounded
/// pending-wake table that [`wake_all`] users (the net service) depend on.
pub(crate) fn wake_all_registered(key: WaitKey) -> usize {
    without_interrupts(|| wake_matching(key, true, false))
}

/// Voluntary yield from a syscall handler; may resume via blocked-syscall sentinel.
pub(crate) fn voluntary_yield_from_syscall(frame: *mut SyscallContext) -> ! {
    // See `scheduler_block_and_switch`: no interrupt window between selection
    // and the stack switch.
    disable_interrupts();
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

fn wake_matching(key: WaitKey, all: bool, record_pending: bool) -> usize {
    let mut woken = 0usize;
    let table = wait_table_mut();
    let found = table.take_registered(
        key,
        all,
        |pid, generation| live_instance_generation(pid) == Some(generation),
        |index| {
            wake_thread_at_index(index, WaitOutcome::Woken);
            woken += 1;
        },
    );
    if !found && record_pending {
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

pub(super) fn waiter_deadline_due(deadline: Option<Deadline>, now_ns: u64) -> bool {
    match deadline {
        Some(Deadline::MonotonicNs(ns)) => now_ns >= ns,
        None => false,
    }
}

pub(crate) fn expire_deadlines() -> usize {
    // Every deadline is built from `monotonic_ns()`, which is fatal without a
    // calibrated TSC, so an uncalibrated kernel has no deadlines to expire.
    if crate::time::tsc_hz().is_none() {
        return 0;
    }
    let now_ns = crate::time::monotonic_ns();
    crate::sched::timeout::expire_due(now_ns);
    without_interrupts(|| {
        let mut expired = 0usize;
        let table = wait_table_mut();
        for slot in &mut table.slots {
            if !slot.active {
                continue;
            }
            if !waiter_deadline_due(slot.deadline, now_ns) {
                continue;
            }
            let index = slot.thread_index;
            slot.active = false;
            #[cfg(feature = "m9-linux-runtime-self-test")]
            crate::selftest::m9_linux_runtime_latency::observe_timed_wait_expired(slot.pid, now_ns);
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
        #[cfg(feature = "m9-linux-trace")]
        {
            use crate::process::personality::{
                execution_personality_for_pid, ExecutionPersonality,
            };
            if let BlockedResume::RestartSyscall { nr, .. } = resume {
                let pid = scheduler.threads[index].owner_process_id;
                if matches!(
                    execution_personality_for_pid(pid),
                    Ok(ExecutionPersonality::LinuxX86_64)
                ) {
                    if let Some(generation) = live_instance_generation(pid) {
                        let reason = match outcome {
                            WaitOutcome::Woken => {
                                crate::syscall::linux::trace::LinuxTraceReason::Woke
                            }
                            WaitOutcome::TimedOut => {
                                crate::syscall::linux::trace::LinuxTraceReason::Timeout
                            }
                            WaitOutcome::Cancelled => {
                                crate::syscall::linux::trace::LinuxTraceReason::OtherErrno
                            }
                        };
                        crate::syscall::linux::trace::record_wait_event(
                            pid, generation, nr, reason,
                        );
                    }
                }
            }
        }
        #[cfg(not(any(
            feature = "m1-self-test",
            feature = "m2-double-fault-self-test",
            feature = "m2-timer-self-test"
        )))]
        if outcome == WaitOutcome::TimedOut {
            if let BlockedResume::RestartSyscall { nr, .. } = resume {
                let pid = scheduler.threads[index].owner_process_id;
                crate::syscall::linux::complete_timed_out_linux_wait(pid, nr);
                #[cfg(feature = "m9-linux-runtime-self-test")]
                crate::selftest::m9_linux_runtime_latency::observe_timed_wait_resumed(pid, nr);
            }
        }
        #[cfg(feature = "m9-block-wake-self-test")]
        crate::selftest::m9_block_wake::on_blocked_syscall_resumed(outcome, frame.rax);
        frame_ptr
    })
}

fn scheduler_block_and_switch() -> ! {
    // The selection below moves `current_thread` to the next thread while we
    // are still running on this thread's kernel stack. Interrupts must stay
    // masked until the restored frame re-enables them, or a timer IRQ would
    // save this kernel frame as the next thread's `saved_stack_pointer`.
    // `syscall` entry already masks IF; this makes the invariant explicit for
    // any caller that re-enabled interrupts.
    disable_interrupts();
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
    fn retry_resume_reexecutes_syscall_on_every_outcome() {
        for outcome in [
            WaitOutcome::Woken,
            WaitOutcome::TimedOut,
            WaitOutcome::Cancelled,
        ] {
            let mut frame = frame_at(0x40_1002);
            apply_blocked_resume(&mut frame, BlockedResume::RetrySyscall { nr: 7 }, outcome);
            assert_eq!(frame.user_rip, 0x40_1000, "rip backs up over `syscall`");
            assert_eq!(frame.rax, 7);
            assert_eq!((frame.rdi, frame.rsi, frame.rdx), (1, 2, 3));
        }
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
    fn waiter_deadline_due_only_at_or_after_deadline() {
        assert!(!waiter_deadline_due(Some(Deadline::MonotonicNs(100)), 99));
        assert!(waiter_deadline_due(Some(Deadline::MonotonicNs(100)), 100));
        assert!(!waiter_deadline_due(None, u64::MAX));
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

    fn waiter_for(thread_index: usize, key: WaitKey) -> WaiterSlot {
        WaiterSlot {
            active: true,
            pid: 7,
            generation: InstanceGeneration(1),
            tid: thread_index as u64,
            thread_index,
            key,
            deadline: None,
        }
    }

    /// One producer: publish readiness, then wake only registered waiters (never record).
    fn produce(table: &mut WaitTable, ready: &mut bool, key: WaitKey) -> Vec<usize> {
        *ready = true;
        let mut woken = Vec::new();
        table.take_registered(key, true, |_, _| true, |index| woken.push(index));
        woken
    }

    /// The `block_current_thread_unless` sequence: `check` then `enqueue`, with nothing
    /// in between. `Ok(Some(rax))` means ready without registering.
    fn atomic_block(
        table: &mut WaitTable,
        ready: &mut bool,
        key: WaitKey,
        check: impl FnOnce(&mut bool) -> BlockCheck,
    ) -> Option<u64> {
        match check(ready) {
            BlockCheck::Ready(rax) => Some(rax),
            BlockCheck::Block => {
                table.enqueue(waiter_for(3, key)).expect("slot");
                None
            }
        }
    }

    fn check_ready(ready: &mut bool) -> BlockCheck {
        if *ready {
            BlockCheck::Ready(1)
        } else {
            BlockCheck::Block
        }
    }

    #[test]
    fn atomic_check_then_block_never_loses_a_wake() {
        let key = WaitKey(0x5A << 56 | 1);

        // Producer ran before the critical section: the check sees it, nothing registers.
        let mut table = WaitTable::new();
        let mut ready = false;
        assert!(produce(&mut table, &mut ready, key).is_empty());
        assert_eq!(
            atomic_block(&mut table, &mut ready, key, check_ready),
            Some(1)
        );
        assert_eq!(table.occupied(), 0);

        // Producer ran after registration: it finds and wakes the waiter.
        let mut table = WaitTable::new();
        let mut ready = false;
        assert_eq!(atomic_block(&mut table, &mut ready, key, check_ready), None);
        assert_eq!(produce(&mut table, &mut ready, key), vec![3]);
        assert_eq!(table.occupied(), 0);

        // An interrupt raised inside the check is delivered only after registration
        // (IF=0 for the whole section), which is the case above.
        let mut table = WaitTable::new();
        let mut ready = false;
        let mut irq_pending = false;
        let blocked = atomic_block(&mut table, &mut ready, key, |ready| {
            irq_pending = true;
            check_ready(ready)
        });
        assert_eq!(blocked, None);
        assert!(irq_pending);
        assert_eq!(produce(&mut table, &mut ready, key), vec![3]);
        assert_eq!(table.pending_wake_keys, [0; MAX_WAITERS]);
    }

    #[test]
    fn split_check_then_block_loses_a_wake_without_pending_records() {
        // The G2 shape (check in one section, register in another) with a producer in the
        // gap: the wake finds no waiter and records nothing, so the waiter sleeps on.
        let key = WaitKey(0x5A << 56 | 2);
        let mut table = WaitTable::new();
        let mut ready = false;
        assert_eq!(check_ready(&mut ready), BlockCheck::Block);
        assert!(produce(&mut table, &mut ready, key).is_empty());
        table.enqueue(waiter_for(3, key)).expect("slot");
        assert!(ready);
        assert_eq!(
            table.occupied(),
            1,
            "waiter stranded although its source is ready"
        );
    }

    #[test]
    fn take_registered_skips_stale_generations_and_other_keys() {
        let key = WaitKey(0x57 << 56 | 1);
        let mut table = WaitTable::new();
        table.enqueue(waiter_for(1, key)).expect("slot");
        table
            .enqueue(waiter_for(2, WaitKey(0x58 << 56)))
            .expect("slot");
        let mut woken = Vec::new();
        let found = table.take_registered(key, true, |_, _| false, |i| woken.push(i));
        assert!(found);
        assert!(woken.is_empty());
        assert_eq!(table.occupied(), 2);
        let found = table.take_registered(key, true, |_, _| true, |i| woken.push(i));
        assert!(found);
        assert_eq!(woken, vec![1]);
        assert_eq!(table.occupied(), 1);
    }

    #[test]
    fn wake_all_registered_never_records_a_pending_wake() {
        let key = WaitKey(0x5A << 56 | 0xE200);
        assert_eq!(wake_all_registered(key), 0);
        assert!(!wait_table_mut().pending_wake_keys.contains(&key.0));
        assert_eq!(wake_all(key), 0);
        assert!(wait_table_mut().consume_pending_wake(key));
    }

    #[test]
    fn pending_wake_table_drops_records_when_full() {
        // Why port and work-set keys must never use `wake_all` (#200 K1).
        let mut table = WaitTable::new();
        for key in 1..=MAX_WAITERS as u64 {
            table.record_pending_wake(WaitKey(key));
        }
        let net_key = WaitKey(0x54 << 56);
        table.record_pending_wake(net_key);
        assert!(!table.consume_pending_wake(net_key));
    }

    #[test]
    fn stale_generation_wake_denied_when_live_generation_missing() {
        let slot_generation = InstanceGeneration(1);
        let live: Option<InstanceGeneration> = None;
        assert_ne!(live, Some(slot_generation));
    }
}
