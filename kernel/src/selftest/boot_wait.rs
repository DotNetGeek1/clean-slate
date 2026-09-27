//! Real-time waits for self-tests that run in boot context, before any scheduler thread
//! exists (the in-kernel M7 device, DNS and TLS lanes).
//!
//! A lane checks its condition against the calibrated TSC clock and, while it does not
//! hold, halts with interrupts enabled until the next interrupt: the periodic APIC timer
//! bounds each halt to one tick, and a virtio-net completion ends it early. The timer ISR
//! only counts and acknowledges ticks that arrive during such a halt ([`is_halted`]),
//! since there is no current thread to account them to.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::x86_64::cpu::{disable_interrupts, enable_interrupts_and_halt};
use crate::interrupt::timer::initialize_timer;

static HALTED: AtomicBool = AtomicBool::new(false);

/// Arms the periodic APIC timer and calibrates the TSC clock the lanes run on.
pub(crate) fn init_clock() -> Result<(), &'static str> {
    initialize_timer();
    if crate::time::tsc_hz().is_none() {
        // Features that pull in `m3-entry-self-test` skip calibration in `initialize_timer`.
        crate::time::calibration::calibrate_apic_tick();
    }
    crate::time::tsc_hz()
        .map(|_| ())
        .ok_or("boot wait requires a calibrated TSC")
}

/// Calibrated monotonic milliseconds; the network stacks' tick unit.
pub(crate) fn now_ms() -> u64 {
    crate::time::monotonic_ns() / 1_000_000
}

/// Whether the boot CPU is halted in [`wait_until`] (read by the timer ISR).
pub(crate) fn is_halted() -> bool {
    HALTED.load(Ordering::Relaxed)
}

/// Calls `poll(now_ms)` until it yields a value, halting between calls. Fails with
/// `timeout` once `budget_ms` has elapsed without one.
pub(crate) fn wait_until<T>(
    budget_ms: u64,
    timeout: &'static str,
    mut poll: impl FnMut(u64) -> Result<Option<T>, &'static str>,
) -> Result<T, &'static str> {
    let deadline = now_ms().saturating_add(budget_ms);
    loop {
        let now = now_ms();
        if let Some(value) = poll(now)? {
            return Ok(value);
        }
        if now >= deadline {
            return Err(timeout);
        }
        halt_until_interrupt();
    }
}

fn halt_until_interrupt() {
    HALTED.store(true, Ordering::Relaxed);
    enable_interrupts_and_halt();
    disable_interrupts();
    HALTED.store(false, Ordering::Relaxed);
}
