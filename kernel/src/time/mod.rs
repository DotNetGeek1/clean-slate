//! Calibrated monotonic time for Linux personality (#103).

#![cfg_attr(not(feature = "m9-linux-runtime-self-test"), allow(dead_code))]
//!
//! `kernel_ticks()` advances once per local APIC timer **IRQ** (one full countdown
//! from [`APIC_TIMER_INITIAL_COUNT`] to zero). [`APIC_COUNTER_HZ`] is the rate at
//! which the APIC down-counter decrements (measured against the PIT during boot).

pub(crate) mod calibration;

use crate::arch::x86_64::apic::APIC_TIMER_INITIAL_COUNT;
use clean_slate_linux_abi::{LinuxErrno, EINVAL};
use core::sync::atomic::{AtomicU64, Ordering};

static APIC_COUNTER_HZ: AtomicU64 = AtomicU64::new(0);

pub(crate) fn set_apic_counter_hz(value: u64) {
    APIC_COUNTER_HZ.store(value, Ordering::Release);
}

pub(crate) fn irq_period_ns() -> Option<u64> {
    let hz = apic_counter_hz()? as u128;
    let ic = u128::from(APIC_TIMER_INITIAL_COUNT);
    Some(u64::try_from(1_000_000_000u128 * ic / hz).unwrap_or(u64::MAX))
}

pub(crate) fn irq_elapsed_ns_since(start_tick: u64) -> u64 {
    let ticks = crate::interrupt::timer::kernel_ticks().saturating_sub(start_tick);
    irq_period_ns()
        .map(|period| ticks.saturating_mul(period))
        .unwrap_or(0)
}

pub(crate) fn apic_counter_hz() -> Option<u64> {
    let value = APIC_COUNTER_HZ.load(Ordering::Acquire);
    if value == 0 {
        None
    } else {
        Some(value)
    }
}

/// Ceil of `ms * apic_counter_hz / (1000 * INITIAL_COUNT)` IRQ ticks.
pub(crate) fn ticks_from_millis(ms: u64) -> Result<u64, LinuxErrno> {
    if ms == 0 {
        return Ok(0);
    }
    let hz = apic_counter_hz().ok_or(EINVAL)? as u128;
    let ic = u128::from(APIC_TIMER_INITIAL_COUNT);
    let num = ms as u128 * hz;
    let den = 1000u128 * ic;
    let ticks = num
        .checked_add(den / 2)
        .ok_or(EINVAL)?
        .checked_div(den)
        .ok_or(EINVAL)?;
    u64::try_from(ticks.max(1)).map_err(|_| EINVAL)
}

pub(crate) fn ticks_from_timespec(ts: clean_slate_linux_abi::Timespec) -> Result<u64, LinuxErrno> {
    if ts.tv_sec == 0 && ts.tv_nsec == 0 {
        return Ok(0);
    }
    if ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return Err(EINVAL);
    }
    let hz = apic_counter_hz().ok_or(EINVAL)? as u128;
    let ic = u128::from(APIC_TIMER_INITIAL_COUNT);
    let ns = (ts.tv_sec as u128)
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(ts.tv_nsec as u128))
        .ok_or(EINVAL)?;
    let den = 1_000_000_000u128 * ic;
    let num = ns.checked_mul(hz).ok_or(EINVAL)?;
    let ticks = num
        .checked_add(den / 2)
        .ok_or(EINVAL)?
        .checked_div(den)
        .ok_or(EINVAL)?;
    u64::try_from(ticks.max(1)).map_err(|_| EINVAL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_linux_abi::Timespec;

    fn set_ticks_per_second(irq_tps: u64) {
        set_apic_counter_hz(
            irq_tps
                .checked_mul(u64::from(APIC_TIMER_INITIAL_COUNT))
                .unwrap_or(0),
        );
    }

    #[test]
    fn timespec_ticks_round_nearest() {
        set_ticks_per_second(1000);
        assert_eq!(
            ticks_from_timespec(Timespec {
                tv_sec: 0,
                tv_nsec: 1,
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
    }

    #[test]
    fn millis_ticks_round_nearest() {
        set_ticks_per_second(100);
        assert_eq!(ticks_from_millis(1), Ok(1));
        assert_eq!(ticks_from_millis(10), Ok(1));
        assert_eq!(ticks_from_millis(15), Ok(2));
        set_apic_counter_hz(0);
    }
}
