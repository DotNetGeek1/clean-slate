#![cfg_attr(
    not(any(feature = "m2-timer-self-test", feature = "m4-recovery-self-test")),
    allow(dead_code)
)]

//! Timer bring-up and the kernel tick counter. Owns `KERNEL_TICKS`.

use crate::arch::x86_64::apic::enable_local_apic;
use crate::arch::x86_64::apic::mask_legacy_pic;
use crate::arch::x86_64::apic::program_local_apic_timer;
use crate::arch::x86_64::apic::APIC_TIMER_INITIAL_COUNT;
use crate::diagnostics::serial::serial_write_fmt;
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
    program_local_apic_timer();
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
    crate::time::calibration::calibrate_apic_tick();
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
    serial_write_fmt(format_args!(
        "[TIME] contract=lapic periodic divide=16 initial_count={} tick-rate=uncalibrated\n",
        APIC_TIMER_INITIAL_COUNT
    ));
}
