#![cfg_attr(
    not(any(feature = "m2-timer-self-test", feature = "m4-recovery-self-test")),
    allow(dead_code)
)]

//! Timer bring-up and the kernel tick counter. Owns `KERNEL_TICKS`.

use crate::arch::x86_64::apic::enable_local_apic;
use crate::arch::x86_64::apic::mask_legacy_pic;
#[cfg(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test",
    feature = "m3-ipc-self-test"
))]
use crate::arch::x86_64::apic::program_local_apic_timer;
use crate::diagnostics::serial::serial_write_fmt;
use crate::time::apic_timer_initial_count;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
use crate::time::irq_period_ns;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

static KERNEL_TICKS: AtomicU64 = AtomicU64::new(0);

/// Current monotonic tick count (relaxed load, as at the original call sites).
///
/// Supervisors map this value to `clean_slate_service_lifecycle::MonotonicTicks`
/// for M4.4 health deadlines until a dedicated userspace syscall exists.
pub(crate) fn kernel_ticks() -> u64 {
    KERNEL_TICKS.load(Ordering::Relaxed)
}

#[cfg(feature = "m3-syscall-self-test")]
/// Resets the tick counter to zero.
pub(crate) fn reset_kernel_ticks() {
    KERNEL_TICKS.store(0, Ordering::Relaxed);
}

/// Advances the tick counter by one; returns the previous value.
pub(super) fn increment_kernel_ticks() -> u64 {
    KERNEL_TICKS.fetch_add(1, Ordering::Relaxed)
}

// Boot-tail entry point: self-test builds exit QEMU before reaching it.
#[cfg_attr(
    any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m3-address-space-self-test",
        feature = "m3-entry-self-test",
        feature = "m3-ipc-self-test"
    ),
    allow(dead_code)
)]
pub(crate) fn initialize_timer() {
    mask_legacy_pic();
    enable_local_apic();
    // M3 entry self-tests boot through a minimal timer path without the PIT ch2
    // wiring `calibrate_apic_tick` needs; calibrating there hangs (not ~50ms).
    #[cfg(not(any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test",
        feature = "m3-address-space-self-test",
        feature = "m3-entry-self-test",
        feature = "m3-ipc-self-test"
    )))]
    {
        crate::time::calibration::calibrate_apic_tick();
    }
    #[cfg(any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test",
        feature = "m3-address-space-self-test",
        feature = "m3-entry-self-test",
        feature = "m3-ipc-self-test"
    ))]
    {
        crate::time::calibration::apply_fallback_apic_timer_config();
        program_local_apic_timer();
    }
    #[cfg(not(any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test",
        feature = "m3-address-space-self-test",
        feature = "m3-entry-self-test",
        feature = "m3-ipc-self-test"
    )))]
    {
        // `calibrate_apic_tick` arms the production reload count.
    }
}

// Boot-tail entry point: self-test builds exit QEMU before reaching it.
#[cfg_attr(
    any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m3-address-space-self-test",
        feature = "m3-entry-self-test",
        feature = "m3-syscall-self-test",
        feature = "m3-ipc-self-test"
    ),
    allow(dead_code)
)]
pub(crate) fn report_timer_contract() {
    let initial_count = apic_timer_initial_count();
    #[cfg(not(any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test"
    )))]
    if let Some(tick_ns) = irq_period_ns() {
        let counter_hz = crate::time::apic_counter_hz().unwrap_or(0);
        serial_write_fmt(format_args!(
            "[TIME] contract=lapic periodic divide=16 initial_count={} counter_hz={} tick_ns={}\n",
            initial_count, counter_hz, tick_ns
        ));
        return;
    }
    serial_write_fmt(format_args!(
        "[TIME] contract=lapic periodic divide=16 initial_count={} tick-rate=uncalibrated\n",
        initial_count
    ));
}
