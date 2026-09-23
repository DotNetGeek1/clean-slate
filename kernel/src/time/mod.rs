//! Calibrated LAPIC IRQ tick period for monotonic deadlines (#163).

pub(crate) mod calibration;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Fallback initial count for a ~1 ms IRQ at [`QEMU_APIC_COUNTER_HZ_FALLBACK`].
pub(crate) const APIC_TIMER_FALLBACK_INITIAL_COUNT: u32 = 62_500;
/// QEMU local APIC timer counter rate with divide-by-16 (1 GHz / 16).
pub(crate) const QEMU_APIC_COUNTER_HZ_FALLBACK: u64 = 62_500_000;

static APIC_COUNTER_HZ: AtomicU64 = AtomicU64::new(0);
static APIC_TIMER_INITIAL_COUNT: AtomicU32 = AtomicU32::new(0);

pub(crate) fn set_apic_counter_hz(value: u64) {
    APIC_COUNTER_HZ.store(value, Ordering::Release);
}

pub(crate) fn set_apic_timer_initial_count(value: u32) {
    APIC_TIMER_INITIAL_COUNT.store(value, Ordering::Release);
}

pub(crate) fn apic_counter_hz() -> Option<u64> {
    let value = APIC_COUNTER_HZ.load(Ordering::Acquire);
    if value == 0 {
        None
    } else {
        Some(value)
    }
}

pub(crate) fn apic_timer_initial_count() -> u32 {
    let value = APIC_TIMER_INITIAL_COUNT.load(Ordering::Acquire);
    if value == 0 {
        APIC_TIMER_FALLBACK_INITIAL_COUNT
    } else {
        value
    }
}

/// IRQ period in nanoseconds from calibrated counter rate and reload count.
pub(crate) fn irq_period_ns() -> Option<u64> {
    irq_period_ns_from(apic_counter_hz()?, apic_timer_initial_count())
}

pub(crate) fn irq_period_ns_from(counter_hz: u64, initial_count: u32) -> Option<u64> {
    if counter_hz == 0 || initial_count == 0 {
        return None;
    }
    let hz = counter_hz as u128;
    let ic = u128::from(initial_count);
    u64::try_from(1_000_000_000u128 * ic / hz).ok()
}

/// Ceil of `ms` wall time in IRQ ticks (`ms * hz / (1000 * initial_count)`).
pub(crate) fn millis_to_irq_ticks_ceil(
    ms: u64,
    counter_hz: u64,
    initial_count: u32,
) -> Option<u64> {
    if ms == 0 {
        return Some(0);
    }
    if counter_hz == 0 || initial_count == 0 {
        return None;
    }
    let num = u128::from(ms) * u128::from(counter_hz);
    let den = 1000u128 * u128::from(initial_count);
    let ticks = num.div_ceil(den);
    u64::try_from(ticks.max(1)).ok()
}

#[allow(dead_code)]
pub(crate) fn ticks_from_millis(ms: u64) -> Option<u64> {
    millis_to_irq_ticks_ceil(ms, apic_counter_hz()?, apic_timer_initial_count())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn millis_ticks_ceil_one_ms_tick() {
        let hz = 62_500_000;
        let ic = 62_500;
        assert_eq!(millis_to_irq_ticks_ceil(0, hz, ic), Some(0));
        assert_eq!(millis_to_irq_ticks_ceil(1, hz, ic), Some(1));
        assert_eq!(millis_to_irq_ticks_ceil(200, hz, ic), Some(200));
        assert_eq!(millis_to_irq_ticks_ceil(201, hz, ic), Some(201));
    }

    #[test]
    fn millis_ticks_ceil_never_rounds_down() {
        let hz = 62_500_000;
        let ic = 62_500;
        assert_eq!(millis_to_irq_ticks_ceil(2, hz, ic), Some(2));
    }

    #[test]
    fn irq_period_matches_initial_count() {
        let hz = 100_000_000;
        let ic = 100_000;
        assert_eq!(irq_period_ns_from(hz, ic), Some(1_000_000));
    }
}
