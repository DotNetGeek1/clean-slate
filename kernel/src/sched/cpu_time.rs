//! Per-thread CPU time (#377): every change of the scheduler's current thread charges the
//! time since the previous change to the thread that was running, to the idle thread's
//! counter, or to "no thread" (boot and teardown gaps). The counters are raw TSC ticks so
//! the switch path does one `rdtsc` and an add, with no division and no allocation;
//! readers convert to nanoseconds with [`ticks_to_ns`] once the TSC is calibrated.
//!
//! Invariant: `live slot ticks + retired + idle + unattributed == last charge - start`,
//! so per-process shares and idle add up to the elapsed time.

// Readers are the m3 resources self-test today; #379 adds the snapshot call.
#![cfg_attr(not(test), allow(dead_code))]

use super::SCHEDULER_THREAD_SLOTS;

/// Ticks charged so far, by where they went.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CpuTotals {
    /// Ticks since the first charge (the scheduler's first switch).
    pub(crate) elapsed_ticks: u64,
    /// Ticks the dedicated idle thread was current.
    pub(crate) idle_ticks: u64,
    /// Ticks with no current thread (between a teardown and the next dispatch).
    pub(crate) unattributed_ticks: u64,
    /// Ticks charged to threads that are still in a scheduler slot.
    pub(crate) live_thread_ticks: u64,
    /// Ticks charged to threads whose slots were since reaped.
    pub(crate) retired_ticks: u64,
}

impl CpuTotals {
    /// Ticks charged to some thread other than idle.
    pub(crate) fn busy_ticks(&self) -> u64 {
        self.live_thread_ticks.saturating_add(self.retired_ticks)
    }
}

pub(crate) struct CpuClock {
    started: bool,
    start_ticks: u64,
    last_charge_ticks: u64,
    idle_ticks: u64,
    unattributed_ticks: u64,
    retired_ticks: u64,
    /// Indexed by scheduler slot, beside `Scheduler::threads` so `Thread` stays unchanged.
    slot_ticks: [u64; SCHEDULER_THREAD_SLOTS],
}

/// Where the elapsed ticks of one charge go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChargeTarget {
    Slot(usize),
    Idle,
    Nobody,
}

impl CpuClock {
    pub(crate) const fn new() -> Self {
        Self {
            started: false,
            start_ticks: 0,
            last_charge_ticks: 0,
            idle_ticks: 0,
            unattributed_ticks: 0,
            retired_ticks: 0,
            slot_ticks: [0; SCHEDULER_THREAD_SLOTS],
        }
    }

    /// Charges the ticks since the previous charge to `target`. The first call only
    /// starts the clock.
    pub(crate) fn charge(&mut self, now: u64, target: ChargeTarget) {
        if !self.started {
            self.started = true;
            self.start_ticks = now;
            self.last_charge_ticks = now;
            return;
        }
        // An invariant TSC never runs backwards; saturate rather than wrap if one did.
        let elapsed = now.saturating_sub(self.last_charge_ticks);
        self.last_charge_ticks = self.last_charge_ticks.max(now);
        let counter = match target {
            ChargeTarget::Slot(slot) => match self.slot_ticks.get_mut(slot) {
                Some(counter) => counter,
                None => &mut self.unattributed_ticks,
            },
            ChargeTarget::Idle => &mut self.idle_ticks,
            ChargeTarget::Nobody => &mut self.unattributed_ticks,
        };
        *counter = counter.saturating_add(elapsed);
    }

    pub(crate) fn slot_ticks(&self, slot: usize) -> u64 {
        self.slot_ticks.get(slot).copied().unwrap_or(0)
    }

    /// Empties `slot`'s counter for a new thread or a reaped one and returns what it held,
    /// which stays counted as retired so the totals still add up.
    pub(crate) fn retire_slot(&mut self, slot: usize) -> u64 {
        let Some(counter) = self.slot_ticks.get_mut(slot) else {
            return 0;
        };
        let ticks = core::mem::take(counter);
        self.retired_ticks = self.retired_ticks.saturating_add(ticks);
        ticks
    }

    pub(crate) fn totals(&self) -> CpuTotals {
        let live_thread_ticks = self
            .slot_ticks
            .iter()
            .fold(0u64, |sum, ticks| sum.saturating_add(*ticks));
        CpuTotals {
            elapsed_ticks: self.last_charge_ticks.saturating_sub(self.start_ticks),
            idle_ticks: self.idle_ticks,
            unattributed_ticks: self.unattributed_ticks,
            live_thread_ticks,
            retired_ticks: self.retired_ticks,
        }
    }
}

#[cfg(not(test))]
pub(crate) fn now_ticks() -> u64 {
    crate::time::calibration::read_tsc()
}

#[cfg(test)]
static TEST_TICKS: crate::sync::per_test_thread::PerTestThread<core::sync::atomic::AtomicU64> =
    crate::sync::per_test_thread::PerTestThread::new(core::sync::atomic::AtomicU64::new(0));

/// Host tests drive the clock by hand; it stays at 0 (no time passes) unless a test moves it.
#[cfg(test)]
pub(crate) fn now_ticks() -> u64 {
    TEST_TICKS.load(core::sync::atomic::Ordering::Relaxed)
}

#[cfg(test)]
pub(crate) fn set_test_ticks(ticks: u64) {
    TEST_TICKS.store(ticks, core::sync::atomic::Ordering::Relaxed);
}

/// Nanoseconds for `ticks` of the TSC, or `None` before the TSC is calibrated.
pub(crate) fn ticks_to_ns(ticks: u64) -> Option<u64> {
    let hz = crate::time::tsc_hz()?;
    crate::time::mul_div_u128(ticks, 1_000_000_000, u128::from(hz))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_charge_only_starts_the_clock() {
        let mut clock = CpuClock::new();
        clock.charge(500, ChargeTarget::Slot(0));
        assert_eq!(clock.slot_ticks(0), 0);
        assert_eq!(clock.totals().elapsed_ticks, 0);
    }

    #[test]
    fn charges_add_up_to_elapsed_time() {
        let mut clock = CpuClock::new();
        clock.charge(100, ChargeTarget::Nobody);
        clock.charge(130, ChargeTarget::Nobody);
        clock.charge(200, ChargeTarget::Slot(0));
        clock.charge(260, ChargeTarget::Slot(1));
        clock.charge(300, ChargeTarget::Idle);
        clock.charge(310, ChargeTarget::Slot(0));
        assert_eq!(clock.slot_ticks(0), 80);
        assert_eq!(clock.slot_ticks(1), 60);
        let totals = clock.totals();
        assert_eq!(totals.idle_ticks, 40);
        assert_eq!(totals.unattributed_ticks, 30);
        assert_eq!(totals.elapsed_ticks, 210);
        assert_eq!(
            totals.busy_ticks() + totals.idle_ticks + totals.unattributed_ticks,
            totals.elapsed_ticks
        );
    }

    #[test]
    fn retiring_a_slot_keeps_its_ticks_in_the_totals() {
        let mut clock = CpuClock::new();
        clock.charge(0, ChargeTarget::Nobody);
        clock.charge(50, ChargeTarget::Slot(2));
        assert_eq!(clock.retire_slot(2), 50);
        assert_eq!(clock.slot_ticks(2), 0);
        assert_eq!(clock.retire_slot(2), 0);
        let totals = clock.totals();
        assert_eq!(totals.retired_ticks, 50);
        assert_eq!(totals.live_thread_ticks, 0);
        assert_eq!(totals.busy_ticks(), totals.elapsed_ticks);
    }

    #[test]
    fn a_backwards_clock_charges_nothing() {
        let mut clock = CpuClock::new();
        clock.charge(1_000, ChargeTarget::Nobody);
        clock.charge(900, ChargeTarget::Slot(0));
        assert_eq!(clock.slot_ticks(0), 0);
        clock.charge(1_010, ChargeTarget::Slot(0));
        assert_eq!(clock.slot_ticks(0), 10);
        assert_eq!(clock.totals().elapsed_ticks, 10);
    }

    #[test]
    fn out_of_range_slot_goes_to_unattributed() {
        let mut clock = CpuClock::new();
        clock.charge(0, ChargeTarget::Nobody);
        clock.charge(7, ChargeTarget::Slot(SCHEDULER_THREAD_SLOTS));
        assert_eq!(clock.totals().unattributed_ticks, 7);
    }
}
