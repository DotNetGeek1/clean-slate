//! Calibrated LAPIC IRQ ticks (#163) and TSC monotonic ns (#103 Linux clocks).

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
static TSC_HZ: AtomicU64 = AtomicU64::new(0);
static TSC_ORIGIN: AtomicU64 = AtomicU64::new(0);

pub(crate) fn set_apic_counter_hz(value: u64) {
    APIC_COUNTER_HZ.store(value, Ordering::Release);
}

pub(crate) fn set_apic_timer_initial_count(value: u32) {
    APIC_TIMER_INITIAL_COUNT.store(value, Ordering::Release);
}

pub(crate) fn set_tsc_hz(value: u64) {
    TSC_HZ.store(value, Ordering::Release);
}

pub(crate) fn set_tsc_origin(value: u64) {
    TSC_ORIGIN.store(value, Ordering::Release);
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

pub(crate) fn tsc_hz() -> Option<u64> {
    let value = TSC_HZ.load(Ordering::Acquire);
    if value == 0 {
        None
    } else {
        Some(value)
    }
}

/// Host-testable: `(value * numer) / denom` with u128 intermediate.
pub(crate) fn mul_div_u128(value: u64, numer: u128, denom: u128) -> Option<u64> {
    if denom == 0 {
        return None;
    }
    let product = u128::from(value).checked_mul(numer)?;
    u64::try_from(product / denom).ok()
}

/// Monotonic nanoseconds from calibrated TSC (QEMU TCG `rdtsc` tracks host time).
pub(crate) fn monotonic_ns() -> u64 {
    let Some(hz) = tsc_hz() else {
        crate::diagnostics::qemu::fatal_kernel_error("monotonic_ns requires calibrated TSC");
    };
    let origin = TSC_ORIGIN.load(Ordering::Acquire);
    let tsc = calibration::read_tsc();
    let delta = tsc.wrapping_sub(origin);
    mul_div_u128(delta, 1_000_000_000, u128::from(hz)).unwrap_or(u64::MAX)
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

fn duration_ns_from_timespec(ts: Timespec) -> Result<u64, LinuxErrno> {
    if ts.tv_sec == 0 && ts.tv_nsec == 0 {
        return Ok(0);
    }
    if ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return Err(EINVAL);
    }
    let ns = (ts.tv_sec as u128)
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(ts.tv_nsec as u128))
        .ok_or(EINVAL)?;
    u64::try_from(ns).map_err(|_| EINVAL)
}

/// Ceil of a timespec to whole IRQ periods in nanoseconds (never wake early).
pub(crate) fn sleep_budget_ns_from_timespec(ts: Timespec) -> Result<u64, LinuxErrno> {
    let request = duration_ns_from_timespec(ts)?;
    if request == 0 {
        return Ok(0);
    }
    let period = irq_period_ns().ok_or(EINVAL)?;
    let budget = u128::from(request)
        .checked_mul(1)
        .map(|n| n.div_ceil(u128::from(period)))
        .and_then(|ticks| ticks.checked_mul(u128::from(period)))
        .ok_or(EINVAL)?;
    u64::try_from(budget.max(u128::from(period))).map_err(|_| EINVAL)
}

pub(crate) fn sleep_budget_ns_from_millis(ms: u64) -> Result<u64, LinuxErrno> {
    if ms == 0 {
        return Ok(0);
    }
    let period = irq_period_ns().ok_or(EINVAL)?;
    let request = ms.checked_mul(1_000_000).ok_or(EINVAL)?;
    let budget = u128::from(request)
        .div_ceil(u128::from(period))
        .checked_mul(u128::from(period))
        .ok_or(EINVAL)?;
    u64::try_from(budget.max(u128::from(period))).map_err(|_| EINVAL)
}

/// Absolute monotonic-ns deadline from now + ceil-rounded sleep budget.
pub(crate) fn monotonic_deadline_from_timespec(
    now_ns: u64,
    ts: Timespec,
) -> Result<u64, LinuxErrno> {
    let budget = sleep_budget_ns_from_timespec(ts)?;
    now_ns.checked_add(budget).ok_or(EINVAL)
}

pub(crate) fn monotonic_deadline_from_millis(now_ns: u64, ms: u64) -> Result<u64, LinuxErrno> {
    let budget = sleep_budget_ns_from_millis(ms)?;
    now_ns.checked_add(budget).ok_or(EINVAL)
}

pub(crate) fn timespec_from_monotonic_ns(ns: u64) -> Timespec {
    Timespec {
        tv_sec: (ns / 1_000_000_000) as i64,
        tv_nsec: (ns % 1_000_000_000) as i64,
    }
}

pub(crate) fn timespec_from_remaining_ns(
    deadline_ns: u64,
    now_ns: u64,
) -> Result<Timespec, LinuxErrno> {
    let rem = deadline_ns.saturating_sub(now_ns);
    Ok(timespec_from_monotonic_ns(rem))
}

/// Ceil of a Linux timespec in IRQ ticks (legacy / self-test tick windows).
#[allow(dead_code)]
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

#[allow(dead_code)]
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
pub(crate) fn set_test_monotonic_tsc(hz: u64, origin: u64) {
    set_tsc_hz(hz);
    set_tsc_origin(origin);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul_div_u128_rounds_down_quotient() {
        assert_eq!(mul_div_u128(5, 1_000_000_000, 2), Some(2_500_000_000));
        assert_eq!(mul_div_u128(0, 1_000_000_000, 1), Some(0));
        assert!(mul_div_u128(1, u128::MAX, 0).is_none());
    }

    /// The APIC counter globals are process-wide, and the test harness runs
    /// tests in parallel, so every assertion that depends on them lives in
    /// this one test.
    #[test]
    fn sleep_budget_and_deadline_use_ceil_apic_period() {
        set_apic_counter_hz(62_500_000);
        set_apic_timer_initial_count(62_500);
        assert_eq!(
            sleep_budget_ns_from_timespec(Timespec {
                tv_sec: 0,
                tv_nsec: 1
            })
            .unwrap(),
            1_000_000
        );
        assert_eq!(
            sleep_budget_ns_from_timespec(Timespec {
                tv_sec: 0,
                tv_nsec: 999_999,
            })
            .unwrap(),
            1_000_000
        );
        assert_eq!(sleep_budget_ns_from_millis(200).unwrap(), 200_000_000);
        let ts = Timespec {
            tv_sec: 0,
            tv_nsec: 200_000_000,
        };
        assert_eq!(
            monotonic_deadline_from_timespec(100, ts).unwrap(),
            100 + 200_000_000
        );
        set_apic_counter_hz(0);
        set_apic_timer_initial_count(0);
    }

    #[test]
    fn timespec_roundtrip_remaining() {
        let ts = timespec_from_monotonic_ns(1_500_000_001);
        assert_eq!(ts.tv_sec, 1);
        assert_eq!(ts.tv_nsec, 500_000_001);
        assert_eq!(
            timespec_from_remaining_ns(2_000_000_000, 500_000_000).unwrap(),
            Timespec {
                tv_sec: 1,
                tv_nsec: 500_000_000,
            }
        );
    }

    #[test]
    fn millis_ticks_ceil_one_ms_tick() {
        let hz = 62_500_000;
        let ic = 62_500;
        assert_eq!(millis_to_irq_ticks_ceil(0, hz, ic), Some(0));
        assert_eq!(millis_to_irq_ticks_ceil(1, hz, ic), Some(1));
        assert_eq!(millis_to_irq_ticks_ceil(200, hz, ic), Some(200));
    }

    #[test]
    fn irq_period_matches_initial_count() {
        let hz = 100_000_000;
        let ic = 100_000;
        assert_eq!(irq_period_ns_from(hz, ic), Some(1_000_000));
    }
}
