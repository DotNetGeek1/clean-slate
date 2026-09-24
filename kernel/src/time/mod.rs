//! Calibrated LAPIC IRQ tick period for monotonic deadlines (#163, #103 Linux clocks).

#![cfg_attr(not(feature = "m9-linux-runtime-self-test"), allow(dead_code))]

pub(crate) mod calibration;

use clean_slate_linux_abi::{LinuxErrno, Timespec, EINVAL};
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

/// Ceil of a Linux timespec in IRQ ticks (never returns early from nanosleep).
pub(crate) fn ticks_from_timespec(ts: Timespec) -> Result<u64, LinuxErrno> {
    if ts.tv_sec == 0 && ts.tv_nsec == 0 {
        return Ok(0);
    }
    if ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return Err(EINVAL);
    }
    let counter_hz = apic_counter_hz().ok_or(EINVAL)?;
    let initial_count = apic_timer_initial_count();
    let ns = (ts.tv_sec as u128)
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(ts.tv_nsec as u128))
        .ok_or(EINVAL)?;
    let den = 1_000_000_000u128 * u128::from(initial_count);
    let num = ns.checked_mul(u128::from(counter_hz)).ok_or(EINVAL)?;
    let ticks = num.div_ceil(den);
    u64::try_from(ticks.max(1)).map_err(|_| EINVAL)
}

pub(crate) fn ticks_from_millis(ms: u64) -> Result<u64, LinuxErrno> {
    if ms == 0 {
        return Ok(0);
    }
    millis_to_irq_ticks_ceil(
        ms,
        apic_counter_hz().ok_or(EINVAL)?,
        apic_timer_initial_count(),
    )
    .ok_or(EINVAL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_linux_abi::Timespec;

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

    #[test]
    fn timespec_ticks_ceil_never_rounds_down() {
        set_apic_counter_hz(62_500_000);
        set_apic_timer_initial_count(62_500);
        assert_eq!(
            ticks_from_timespec(Timespec {
                tv_sec: 0,
                tv_nsec: 1,
            }),
            Ok(1)
        );
        assert_eq!(
            ticks_from_timespec(Timespec {
                tv_sec: 0,
                tv_nsec: 999_999,
            }),
            Ok(1)
        );
        assert_eq!(
            ticks_from_timespec(Timespec {
                tv_sec: 1,
                tv_nsec: 0,
            }),
            Ok(1000)
        );
        set_apic_counter_hz(0);
        set_apic_timer_initial_count(0);
    }
}
