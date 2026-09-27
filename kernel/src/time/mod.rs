//! Calibrated LAPIC IRQ ticks (#163) and TSC monotonic ns (#103 Linux clocks).

#![cfg_attr(not(feature = "m9-linux-runtime-self-test"), allow(dead_code))]

pub(crate) mod calibration;

use clean_slate_linux_abi::{LinuxErrno, Timespec, EINVAL};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Fallback initial count for a ~1 ms IRQ at [`QEMU_APIC_COUNTER_HZ_FALLBACK`].
pub(crate) const APIC_TIMER_FALLBACK_INITIAL_COUNT: u32 = 62_500;
/// QEMU local APIC timer counter rate with divide-by-16 (1 GHz / 16).
pub(crate) const QEMU_APIC_COUNTER_HZ_FALLBACK: u64 = 62_500_000;

#[cfg(not(test))]
static APIC_COUNTER_HZ: AtomicU64 = AtomicU64::new(0);
#[cfg(not(test))]
static APIC_TIMER_INITIAL_COUNT: AtomicU32 = AtomicU32::new(0);
#[cfg(not(test))]
static TSC_HZ: AtomicU64 = AtomicU64::new(0);
#[cfg(not(test))]
static TSC_ORIGIN: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
use crate::sync::per_test_thread::PerTestThread;
#[cfg(test)]
static APIC_COUNTER_HZ: PerTestThread<AtomicU64> = PerTestThread::new(AtomicU64::new(0));
#[cfg(test)]
static APIC_TIMER_INITIAL_COUNT: PerTestThread<AtomicU32> = PerTestThread::new(AtomicU32::new(0));
#[cfg(test)]
static TSC_HZ: PerTestThread<AtomicU64> = PerTestThread::new(AtomicU64::new(0));
#[cfg(test)]
static TSC_ORIGIN: PerTestThread<AtomicU64> = PerTestThread::new(AtomicU64::new(0));

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

/// Absolute monotonic-ns deadline: `now + request`, not rounded to IRQ periods.
///
/// Waiters are expired by the first deadline check that observes
/// `monotonic_ns() >= deadline`, so they never wake early; the tick period
/// only bounds how late that first check can be.
pub(crate) fn monotonic_deadline_from_timespec(
    now_ns: u64,
    ts: Timespec,
) -> Result<u64, LinuxErrno> {
    now_ns
        .checked_add(duration_ns_from_timespec(ts)?)
        .ok_or(EINVAL)
}

pub(crate) fn monotonic_deadline_from_millis(now_ns: u64, ms: u64) -> Result<u64, LinuxErrno> {
    now_ns
        .checked_add(ms.checked_mul(1_000_000).ok_or(EINVAL)?)
        .ok_or(EINVAL)
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

    #[test]
    fn deadlines_are_exact_requests() {
        let ts = |tv_sec, tv_nsec| Timespec { tv_sec, tv_nsec };
        assert_eq!(
            monotonic_deadline_from_timespec(100, ts(0, 1)).unwrap(),
            101
        );
        assert_eq!(
            monotonic_deadline_from_timespec(100, ts(0, 20_000_000)).unwrap(),
            20_000_100
        );
        assert_eq!(
            monotonic_deadline_from_timespec(0, ts(2, 5)).unwrap(),
            2_000_000_005
        );
        assert_eq!(monotonic_deadline_from_millis(7, 30).unwrap(), 30_000_007);
        assert_eq!(
            monotonic_deadline_from_timespec(u64::MAX, ts(0, 1)),
            Err(EINVAL)
        );
        assert_eq!(monotonic_deadline_from_millis(0, u64::MAX), Err(EINVAL));
        assert_eq!(monotonic_deadline_from_timespec(0, ts(-1, 0)), Err(EINVAL));
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
    fn irq_period_matches_initial_count() {
        let hz = 100_000_000;
        let ic = 100_000;
        assert_eq!(irq_period_ns_from(hz, ic), Some(1_000_000));
    }
}
