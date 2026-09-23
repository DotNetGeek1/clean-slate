//! Calibrated monotonic time for Linux personality (#103).

pub(crate) mod calibration;

use clean_slate_linux_abi::{LinuxErrno, EINVAL};
use core::sync::atomic::{AtomicU64, Ordering};

static TICKS_PER_SECOND: AtomicU64 = AtomicU64::new(0);

pub(crate) fn set_ticks_per_second(value: u64) {
    TICKS_PER_SECOND.store(value, Ordering::Release);
}

pub(crate) fn ticks_per_second() -> Option<u64> {
    let value = TICKS_PER_SECOND.load(Ordering::Acquire);
    if value == 0 {
        None
    } else {
        Some(value)
    }
}

pub(crate) fn ticks_from_timespec(ts: clean_slate_linux_abi::Timespec) -> Result<u64, LinuxErrno> {
    let tps = ticks_per_second().ok_or(EINVAL)?;
    let sec = u64::try_from(ts.tv_sec).map_err(|_| EINVAL)?;
    let sec_ticks = sec.checked_mul(tps).ok_or(EINVAL)?;
    let ns_ticks = (ts.tv_nsec as u64)
        .checked_mul(tps)
        .and_then(|n| n.checked_add(999_999_999))
        .ok_or(EINVAL)?
        / 1_000_000_000;
    sec_ticks
        .checked_add(ns_ticks)
        .ok_or(EINVAL)
}

pub(crate) fn ticks_from_millis(ms: u64) -> Result<u64, LinuxErrno> {
    let tps = ticks_per_second().ok_or(EINVAL)?;
    ms.checked_mul(tps)
        .and_then(|n| n.checked_add(999))
        .map(|n| n / 1000)
        .ok_or(EINVAL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_linux_abi::Timespec;

    #[test]
    fn timespec_ticks_round_up() {
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
        set_ticks_per_second(0);
    }

    #[test]
    fn millis_ticks_round_up() {
        set_ticks_per_second(100);
        assert_eq!(ticks_from_millis(1), Ok(1));
        assert_eq!(ticks_from_millis(10), Ok(1));
        assert_eq!(ticks_from_millis(11), Ok(2));
        set_ticks_per_second(0);
    }
}
