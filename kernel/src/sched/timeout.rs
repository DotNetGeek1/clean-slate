//! Bounded one-shot kernel timeouts (W3).
//!
//! A device arms one entry while it has a request in flight and cancels it when
//! the last completion is harvested, so nothing is armed while the system is
//! idle. Due entries are expired from the timer path that already expires
//! `Deadline::MonotonicNs` waiters ([`crate::sched::wait::expire_deadlines`]);
//! with nothing armed that costs one comparison and no scan.
//!
//! Handlers run in interrupt context with interrupts masked, under the same
//! rules as device interrupt handlers: record state and notify, never block,
//! allocate or touch device registers. A timeout and the completion it guards
//! are ordered by who reaches the table first: [`cancel`] reports whether the
//! handler already ran.

use crate::arch::x86_64::cpu::without_interrupts;
use crate::sched::wait::Deadline;
use crate::sync::global_cell::GlobalCell;

/// Registry capacity: one entry per in-flight device plus headroom.
pub(crate) const MAX_TIMEOUTS: usize = 8;

/// Called once when an armed timeout expires, with the context given to [`arm`].
pub(crate) type TimeoutHandler = fn(u64);

/// Names one arming of one registry slot; stale once that arming is cancelled
/// or has fired, even if the slot is armed again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TimeoutHandle {
    slot: u8,
    generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TimeoutError {
    Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CancelOutcome {
    /// The timeout was armed and can no longer fire.
    Cancelled,
    /// The handle is not armed: it already fired, or was cancelled before.
    NotArmed,
}

fn ignore_timeout(_context: u64) {}

#[derive(Clone, Copy)]
struct TimeoutSlot {
    armed: bool,
    generation: u64,
    deadline_ns: u64,
    handler: TimeoutHandler,
    context: u64,
}

impl TimeoutSlot {
    const FREE: Self = Self {
        armed: false,
        generation: 0,
        deadline_ns: 0,
        handler: ignore_timeout,
        context: 0,
    };
}

struct TimeoutTable {
    slots: [TimeoutSlot; MAX_TIMEOUTS],
    armed: usize,
    /// Scans of the slot array by [`TimeoutTable::take_due`].
    #[cfg(test)]
    sweeps: u64,
}

impl TimeoutTable {
    const fn new() -> Self {
        Self {
            slots: [TimeoutSlot::FREE; MAX_TIMEOUTS],
            armed: 0,
            #[cfg(test)]
            sweeps: 0,
        }
    }

    fn arm(
        &mut self,
        deadline_ns: u64,
        handler: TimeoutHandler,
        context: u64,
    ) -> Result<TimeoutHandle, TimeoutError> {
        let index = self
            .slots
            .iter()
            .position(|slot| !slot.armed)
            .ok_or(TimeoutError::Exhausted)?;
        let slot = &mut self.slots[index];
        slot.generation = slot.generation.wrapping_add(1);
        slot.armed = true;
        slot.deadline_ns = deadline_ns;
        slot.handler = handler;
        slot.context = context;
        self.armed += 1;
        Ok(TimeoutHandle {
            slot: index as u8,
            generation: slot.generation,
        })
    }

    fn armed_slot(&mut self, handle: TimeoutHandle) -> Option<&mut TimeoutSlot> {
        self.slots
            .get_mut(usize::from(handle.slot))
            .filter(|slot| slot.armed && slot.generation == handle.generation)
    }

    fn cancel(&mut self, handle: TimeoutHandle) -> CancelOutcome {
        let Some(slot) = self.armed_slot(handle) else {
            return CancelOutcome::NotArmed;
        };
        slot.armed = false;
        self.armed -= 1;
        CancelOutcome::Cancelled
    }

    fn rearm(&mut self, handle: TimeoutHandle, deadline_ns: u64) -> CancelOutcome {
        let Some(slot) = self.armed_slot(handle) else {
            return CancelOutcome::NotArmed;
        };
        slot.deadline_ns = deadline_ns;
        CancelOutcome::Cancelled
    }

    /// Disarm every entry due at `now_ns` and return their handlers.
    fn take_due(&mut self, now_ns: u64) -> ([(TimeoutHandler, u64); MAX_TIMEOUTS], usize) {
        let mut due = [(ignore_timeout as TimeoutHandler, 0u64); MAX_TIMEOUTS];
        let mut count = 0;
        if self.armed == 0 {
            return (due, count);
        }
        #[cfg(test)]
        {
            self.sweeps = self.sweeps.wrapping_add(1);
        }
        for slot in &mut self.slots {
            if slot.armed && now_ns >= slot.deadline_ns {
                slot.armed = false;
                due[count] = (slot.handler, slot.context);
                count += 1;
            }
        }
        self.armed -= count;
        (due, count)
    }
}

static TIMEOUTS: GlobalCell<TimeoutTable> = GlobalCell::new(TimeoutTable::new());

fn timeout_table_mut() -> &'static mut TimeoutTable {
    unsafe { &mut *TIMEOUTS.get() }
}

/// Arm a one-shot timeout that runs `handler(context)` once `deadline` passes.
/// Fails deterministically when every slot is armed.
pub(crate) fn arm(
    deadline: Deadline,
    handler: TimeoutHandler,
    context: u64,
) -> Result<TimeoutHandle, TimeoutError> {
    let Deadline::MonotonicNs(deadline_ns) = deadline;
    without_interrupts(|| timeout_table_mut().arm(deadline_ns, handler, context))
}

pub(crate) fn cancel(handle: TimeoutHandle) -> CancelOutcome {
    without_interrupts(|| timeout_table_mut().cancel(handle))
}

/// Move an armed timeout to `deadline`; `NotArmed` if it already fired.
pub(crate) fn rearm(handle: TimeoutHandle, deadline: Deadline) -> CancelOutcome {
    let Deadline::MonotonicNs(deadline_ns) = deadline;
    without_interrupts(|| timeout_table_mut().rearm(handle, deadline_ns))
}

/// Fire every timeout due at `now_ns`; returns how many fired. Called from the
/// timer path only.
pub(crate) fn expire_due(now_ns: u64) -> usize {
    let (due, count) = without_interrupts(|| timeout_table_mut().take_due(now_ns));
    for &(handler, context) in &due[..count] {
        handler(context);
    }
    count
}

#[cfg(any(test, feature = "m10-timeout-introspection"))]
pub(crate) fn armed_count() -> usize {
    without_interrupts(|| timeout_table_mut().armed)
}

#[cfg(test)]
pub(crate) fn sweep_count() -> u64 {
    timeout_table_mut().sweeps
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::vec::Vec;

    std::thread_local! {
        static FIRED: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    }

    fn record(context: u64) {
        FIRED.with(|fired| fired.borrow_mut().push(context));
    }

    fn fired() -> Vec<u64> {
        FIRED.with(|fired| fired.borrow().clone())
    }

    fn at(ns: u64) -> Deadline {
        Deadline::MonotonicNs(ns)
    }

    #[test]
    fn fires_once_at_its_deadline() {
        arm(at(100), record, 7).expect("arm");
        assert_eq!(expire_due(99), 0);
        assert!(fired().is_empty());
        assert_eq!(expire_due(100), 1);
        assert_eq!(fired(), [7]);
        assert_eq!(expire_due(u64::MAX), 0);
        assert_eq!(fired(), [7]);
        assert_eq!(armed_count(), 0);
    }

    #[test]
    fn idle_registry_does_no_sweep() {
        assert_eq!(expire_due(u64::MAX), 0);
        assert_eq!(sweep_count(), 0);
        let handle = arm(at(10), record, 1).expect("arm");
        assert_eq!(expire_due(5), 0);
        assert_eq!(sweep_count(), 1);
        assert_eq!(cancel(handle), CancelOutcome::Cancelled);
        assert_eq!(expire_due(u64::MAX), 0);
        assert_eq!(sweep_count(), 1, "nothing armed: no scan");
        assert!(fired().is_empty());
    }

    #[test]
    fn exhaustion_is_a_deterministic_error_and_slots_are_reused() {
        let handles: Vec<_> = (0..MAX_TIMEOUTS as u64)
            .map(|context| arm(at(1_000), record, context).expect("free slot"))
            .collect();
        assert_eq!(arm(at(1_000), record, 99), Err(TimeoutError::Exhausted));
        assert_eq!(armed_count(), MAX_TIMEOUTS);
        assert_eq!(cancel(handles[3]), CancelOutcome::Cancelled);
        let reused = arm(at(1_000), record, 42).expect("reused slot");
        assert_ne!(reused, handles[3]);
        assert_eq!(expire_due(1_000), MAX_TIMEOUTS);
        let mut contexts = fired();
        contexts.sort_unstable();
        assert_eq!(contexts, [0, 1, 2, 4, 5, 6, 7, 42]);
    }

    #[test]
    fn cancel_before_expiry_never_fires() {
        let handle = arm(at(50), record, 3).expect("arm");
        assert_eq!(cancel(handle), CancelOutcome::Cancelled);
        assert_eq!(cancel(handle), CancelOutcome::NotArmed);
        assert_eq!(expire_due(u64::MAX), 0);
        assert!(fired().is_empty());
    }

    #[test]
    fn expiry_racing_completion_is_decided_once() {
        // Completion first: the handler never runs.
        let completion_first = arm(at(10), record, 1).expect("arm");
        assert_eq!(cancel(completion_first), CancelOutcome::Cancelled);
        assert_eq!(expire_due(10), 0);
        // Expiry first: the late completion learns the handler already ran.
        let expiry_first = arm(at(10), record, 2).expect("arm");
        assert_eq!(expire_due(10), 1);
        assert_eq!(cancel(expiry_first), CancelOutcome::NotArmed);
        assert_eq!(fired(), [2]);
    }

    #[test]
    fn stale_handle_cannot_touch_a_reused_slot() {
        let first = arm(at(10), record, 1).expect("arm");
        assert_eq!(expire_due(10), 1);
        let second = arm(at(20), record, 2).expect("arm");
        assert_eq!(first.slot, second.slot);
        assert_eq!(cancel(first), CancelOutcome::NotArmed);
        assert_eq!(rearm(first, at(u64::MAX)), CancelOutcome::NotArmed);
        assert_eq!(expire_due(20), 1);
        assert_eq!(fired(), [1, 2]);
    }

    #[test]
    fn rearm_moves_an_armed_deadline() {
        let handle = arm(at(10), record, 5).expect("arm");
        assert_eq!(rearm(handle, at(30)), CancelOutcome::Cancelled);
        assert_eq!(expire_due(29), 0);
        assert_eq!(expire_due(30), 1);
        assert_eq!(rearm(handle, at(40)), CancelOutcome::NotArmed);
    }

    fn rearm_from_handler(context: u64) {
        record(context);
        if context == 1 {
            arm(at(200), record, 2).expect("arm from handler");
        }
    }

    #[test]
    fn handlers_may_arm_again() {
        arm(at(100), rearm_from_handler, 1).expect("arm");
        assert_eq!(expire_due(100), 1);
        assert_eq!(armed_count(), 1);
        assert_eq!(expire_due(200), 1);
        assert_eq!(fired(), [1, 2]);
    }
}
