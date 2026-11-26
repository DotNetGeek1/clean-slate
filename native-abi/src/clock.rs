//! Syscall 24 `CLOCK`: the monotonic clock and, when the kernel knows it, the wall clock (#308).
//!
//! ```text
//! | Register          | Meaning                                         |
//! | rdi               | sub-operation: MONOTONIC (0), WALL (1)          |
//! | rsi, rdx, r10, r8, r9 | reserved, must be 0                         |
//! ```
//!
//! | Sub-operation | Result |
//! |---------------|--------|
//! | MONOTONIC | nanoseconds since the kernel calibrated its clock at boot: the clock every native deadline is measured on (work-set `NOW`, port and work-set waits) |
//! | WALL | nanoseconds since 1970-01-01T00:00:00 UTC (Unix time, no leap seconds), or `STATUS_ENODATA` when the kernel has no wall clock |
//!
//! | Status | Meaning |
//! |--------|---------|
//! | `STATUS_EINVAL` | unknown sub-operation, a reserved register set, or the clock is not calibrated yet |
//! | `STATUS_ENODATA` | WALL only: there is no wall clock this boot (see below) |
//!
//! The wall clock is read once, from UEFI `GetTime` before `ExitBootServices`, and kept as a
//! boot epoch: the Unix time at monotonic 0. WALL is that epoch plus MONOTONIC, so the two
//! clocks never drift apart within a boot, and WALL never goes backwards. The kernel fails
//! closed: when the firmware gives no time, an invalid one, or one earlier than the kernel's
//! build floor (a clock that cannot be right), there is no wall clock and WALL answers
//! `STATUS_ENODATA` for the whole boot, rather than a guess.
//!
//! A firmware time with an unspecified time zone is read as UTC, the PC RTC convention QEMU and
//! most firmware follow. A time zone is minutes east of UTC (UEFI 2.8 and later:
//! `Localtime = UTC + TimeZone`), so `UTC = local - zone`.

use crate::status::{is_status, STATUS_ENODATA};

pub const SYSCALL_NR_CLOCK: u64 = 24;

pub const CLOCK_SUBOP_MONOTONIC: u64 = 0;
pub const CLOCK_SUBOP_WALL: u64 = 1;

pub const NANOS_PER_SECOND: u64 = 1_000_000_000;
const SECONDS_PER_DAY: i64 = 86_400;

/// The oldest wall clock the kernel accepts when nothing newer is known at build time:
/// 2026-11-26T00:00:00Z, the day the native clock was added. A build sets a later floor from
/// `SOURCE_DATE_EPOCH`.
pub const WALL_CLOCK_DEFAULT_FLOOR_UNIX: u64 = 1_795_651_200;

/// WALL's answer: `Some(ns)`, or `None` for `STATUS_ENODATA`. Any other status is an error the
/// caller decodes itself.
pub const fn decode_wall(raw: u64) -> Result<Option<u64>, u64> {
    if raw == STATUS_ENODATA {
        Ok(None)
    } else if is_status(raw) {
        Err(raw)
    } else {
        Ok(Some(raw))
    }
}

/// A calendar date and time of day, as firmware reports it and as programs show it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CivilTime {
    pub year: u16,
    /// 1..=12
    pub month: u8,
    /// 1..=31, within the month
    pub day: u8,
    /// 0..=23
    pub hour: u8,
    /// 0..=59
    pub minute: u8,
    /// 0..=59 (a firmware leap second, 60, is refused)
    pub second: u8,
    /// 0..1_000_000_000
    pub nanosecond: u32,
}

/// Why a civil time has no Unix time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CivilTimeError {
    /// A field is out of range, or the day is past the end of its month.
    Invalid,
    /// The time zone is outside `-1440..=1440` minutes.
    InvalidZone,
    /// The time is before 1970-01-01T00:00:00Z.
    BeforeEpoch,
}

/// Why there is no wall clock this boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WallClockError {
    /// The firmware time is not a valid date and time.
    Invalid(CivilTimeError),
    /// The firmware time is earlier than the build floor: the clock cannot be right.
    BeforeFloor { unix_seconds: u64, floor_unix: u64 },
}

pub const fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

pub const fn days_in_month(year: i64, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days from 1970-01-01 to `year`-`month`-`day` in the proleptic Gregorian calendar
/// (H. Hinnant's `days_from_civil`).
const fn days_from_civil(year: i64, month: u8, day: u8) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = month as i64;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`]: (year, month, day).
const fn civil_from_days(days: i64) -> (i64, u8, u8) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

impl CivilTime {
    pub const fn is_valid(&self) -> bool {
        self.month >= 1
            && self.month <= 12
            && self.day >= 1
            && self.day <= days_in_month(self.year as i64, self.month)
            && self.hour < 24
            && self.minute < 60
            && self.second < 60
            && (self.nanosecond as u64) < NANOS_PER_SECOND
    }

    /// Unix nanoseconds for this time in the zone `zone_minutes` east of UTC (`None`: UTC).
    pub const fn unix_ns(&self, zone_minutes: Option<i16>) -> Result<u64, CivilTimeError> {
        if !self.is_valid() {
            return Err(CivilTimeError::Invalid);
        }
        let zone = match zone_minutes {
            None => 0,
            Some(minutes) if minutes >= -1440 && minutes <= 1440 => minutes as i64,
            Some(_) => return Err(CivilTimeError::InvalidZone),
        };
        let days = days_from_civil(self.year as i64, self.month, self.day);
        let seconds = days * SECONDS_PER_DAY
            + self.hour as i64 * 3600
            + self.minute as i64 * 60
            + self.second as i64
            - zone * 60;
        if seconds < 0 {
            return Err(CivilTimeError::BeforeEpoch);
        }
        // Year 9999 is about 2.5e20 ns, past u64; such a clock is refused, not wrapped.
        match (seconds as u64).checked_mul(NANOS_PER_SECOND) {
            Some(ns) => match ns.checked_add(self.nanosecond as u64) {
                Some(ns) if !is_status(ns) => Ok(ns),
                _ => Err(CivilTimeError::Invalid),
            },
            None => Err(CivilTimeError::Invalid),
        }
    }

    /// The UTC civil time for Unix nanoseconds `unix_ns`.
    pub const fn from_unix_ns(unix_ns: u64) -> Self {
        let seconds = unix_ns / NANOS_PER_SECOND;
        let days = (seconds / SECONDS_PER_DAY as u64) as i64;
        let rem = seconds % SECONDS_PER_DAY as u64;
        let (year, month, day) = civil_from_days(days);
        Self {
            year: year as u16,
            month,
            day,
            hour: (rem / 3600) as u8,
            minute: (rem / 60 % 60) as u8,
            second: (rem % 60) as u8,
            nanosecond: (unix_ns % NANOS_PER_SECOND) as u32,
        }
    }
}

/// The fail-closed rule: the Unix nanoseconds of a firmware time, or why it is not a wall clock.
pub const fn wall_clock_from_firmware(
    time: &CivilTime,
    zone_minutes: Option<i16>,
    floor_unix: u64,
) -> Result<u64, WallClockError> {
    let unix_ns = match time.unix_ns(zone_minutes) {
        Ok(ns) => ns,
        Err(error) => return Err(WallClockError::Invalid(error)),
    };
    let unix_seconds = unix_ns / NANOS_PER_SECOND;
    if unix_seconds < floor_unix {
        return Err(WallClockError::BeforeFloor {
            unix_seconds,
            floor_unix,
        });
    }
    Ok(unix_ns)
}

/// The boot epoch: the Unix time at monotonic 0, from a firmware reading `wall_ns` taken
/// `ns_before_origin` before monotonic 0. Saturates at the epoch instead of underflowing.
pub const fn boot_epoch_ns(wall_ns: u64, ns_before_origin: u64) -> u64 {
    wall_ns.saturating_add(ns_before_origin)
}

/// WALL's value: the boot epoch plus the monotonic time, kept below the status range.
pub const fn wall_now_ns(epoch_ns: u64, monotonic_ns: u64) -> u64 {
    let ns = epoch_ns.saturating_add(monotonic_ns);
    if is_status(ns) {
        crate::status::STATUS_RANGE_START - 1
    } else {
        ns
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{STATUS_EINVAL, STATUS_ENODATA};

    const fn civil(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> CivilTime {
        CivilTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanosecond: 0,
        }
    }

    #[test]
    fn known_dates_convert_to_unix_time() {
        let cases = [
            (civil(1970, 1, 1, 0, 0, 0), 0),
            (civil(2000, 1, 1, 0, 0, 0), 946_684_800),
            (civil(2000, 2, 29, 12, 0, 0), 951_825_600),
            (civil(2026, 11, 26, 0, 0, 0), WALL_CLOCK_DEFAULT_FLOOR_UNIX),
            (civil(2038, 1, 19, 3, 14, 8), 2_147_483_648),
            (civil(2100, 3, 1, 0, 0, 0), 4_107_542_400),
        ];
        for (time, seconds) in cases {
            assert_eq!(
                time.unix_ns(None),
                Ok(seconds * NANOS_PER_SECOND),
                "{time:?}"
            );
            assert_eq!(CivilTime::from_unix_ns(seconds * NANOS_PER_SECOND), time);
        }
    }

    #[test]
    fn every_day_round_trips() {
        // 1970 to 2200, a day at a time, with a time of day that moves.
        for days in 0..84_000u64 {
            let second_of_day = days * 7_919 % 86_400;
            let ns = (days * 86_400 + second_of_day) * NANOS_PER_SECOND + days % 1_000;
            let time = CivilTime::from_unix_ns(ns);
            assert!(time.is_valid(), "{time:?}");
            assert_eq!(time.unix_ns(None), Ok(ns));
        }
    }

    #[test]
    fn invalid_fields_are_refused() {
        let refused = [
            civil(2026, 0, 1, 0, 0, 0),
            civil(2026, 13, 1, 0, 0, 0),
            civil(2026, 2, 29, 0, 0, 0),
            civil(2100, 2, 29, 0, 0, 0),
            civil(2026, 4, 31, 0, 0, 0),
            civil(2026, 1, 0, 0, 0, 0),
            civil(2026, 1, 1, 24, 0, 0),
            civil(2026, 1, 1, 0, 60, 0),
            civil(2026, 1, 1, 0, 0, 60),
        ];
        for time in refused {
            assert_eq!(time.unix_ns(None), Err(CivilTimeError::Invalid), "{time:?}");
        }
        let mut nanos = civil(2026, 1, 1, 0, 0, 0);
        nanos.nanosecond = 1_000_000_000;
        assert_eq!(nanos.unix_ns(None), Err(CivilTimeError::Invalid));
        assert!(civil(2000, 2, 29, 0, 0, 0).is_valid());
        assert_eq!(
            civil(1969, 12, 31, 23, 59, 59).unix_ns(None),
            Err(CivilTimeError::BeforeEpoch)
        );
        assert_eq!(
            civil(9999, 12, 31, 0, 0, 0).unix_ns(None),
            Err(CivilTimeError::Invalid)
        );
    }

    #[test]
    fn time_zones_shift_to_utc() {
        let noon = civil(2027, 6, 1, 12, 0, 0);
        let utc = noon.unix_ns(None).unwrap();
        assert_eq!(noon.unix_ns(Some(0)), Ok(utc));
        // Local noon one hour east of UTC is 11:00 UTC.
        assert_eq!(noon.unix_ns(Some(60)), Ok(utc - 3600 * NANOS_PER_SECOND));
        assert_eq!(
            noon.unix_ns(Some(-300)),
            Ok(utc + 5 * 3600 * NANOS_PER_SECOND)
        );
        assert_eq!(noon.unix_ns(Some(1441)), Err(CivilTimeError::InvalidZone));
        assert_eq!(noon.unix_ns(Some(-1441)), Err(CivilTimeError::InvalidZone));
        assert_eq!(
            civil(1970, 1, 1, 0, 30, 0).unix_ns(Some(60)),
            Err(CivilTimeError::BeforeEpoch)
        );
    }

    #[test]
    fn a_clock_before_the_floor_fails_closed() {
        let floor = WALL_CLOCK_DEFAULT_FLOOR_UNIX;
        let at_floor = CivilTime::from_unix_ns(floor * NANOS_PER_SECOND);
        assert_eq!(
            wall_clock_from_firmware(&at_floor, None, floor),
            Ok(floor * NANOS_PER_SECOND)
        );
        let before = CivilTime::from_unix_ns((floor - 1) * NANOS_PER_SECOND);
        assert_eq!(
            wall_clock_from_firmware(&before, None, floor),
            Err(WallClockError::BeforeFloor {
                unix_seconds: floor - 1,
                floor_unix: floor,
            })
        );
        // A reset CMOS clock (QEMU `-rtc base=2001-01-01`) is not a wall clock.
        assert!(matches!(
            wall_clock_from_firmware(&civil(2001, 1, 1, 0, 0, 0), None, floor),
            Err(WallClockError::BeforeFloor { .. })
        ));
        assert_eq!(
            wall_clock_from_firmware(&civil(2026, 2, 30, 0, 0, 0), None, floor),
            Err(WallClockError::Invalid(CivilTimeError::Invalid))
        );
    }

    #[test]
    fn the_epoch_keeps_wall_and_monotonic_in_step() {
        let read_at = 2_000_000_000 * NANOS_PER_SECOND;
        // Firmware read 3 ms before the clock's origin.
        let epoch = boot_epoch_ns(read_at, 3_000_000);
        assert_eq!(epoch, read_at + 3_000_000);
        assert_eq!(wall_now_ns(epoch, 0), epoch);
        assert_eq!(
            wall_now_ns(epoch, 5 * NANOS_PER_SECOND),
            epoch + 5 * NANOS_PER_SECOND
        );
        assert!(!is_status(wall_now_ns(u64::MAX - 10, 100)));
    }

    #[test]
    fn wall_answers_decode() {
        assert_eq!(decode_wall(42), Ok(Some(42)));
        assert_eq!(decode_wall(STATUS_ENODATA), Ok(None));
        assert_eq!(decode_wall(STATUS_EINVAL), Err(STATUS_EINVAL));
    }
}
