//! The wall clock (#308) and syscall 24 `CLOCK`.
//!
//! UEFI `GetTime` is read once, before `ExitBootServices`, together with the TSC. Once the TSC
//! is calibrated the two give the boot epoch, the Unix time at monotonic 0; the wall clock is
//! that epoch plus [`monotonic_ns`]. A firmware time that is missing, invalid, or earlier than
//! the build floor leaves no wall clock for the whole boot (fail closed, the owner decision on
//! #221). [`wall_clock_ns`] is the one kernel source of wall time: the audit log (#219), the
//! network service's certificate checks (#221) and Linux `CLOCK_REALTIME` (#222) are to read it
//! rather than keep their own.

use core::sync::atomic::{AtomicU64, Ordering};

use clean_slate_native_abi::clock::{
    boot_epoch_ns, wall_clock_from_firmware, wall_now_ns, CivilTime, WallClockError,
    CLOCK_SUBOP_MONOTONIC, CLOCK_SUBOP_WALL, WALL_CLOCK_DEFAULT_FLOOR_UNIX,
};
use clean_slate_native_abi::status::{STATUS_EINVAL, STATUS_ENODATA};

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::time::{monotonic_ns, mul_div_u128, tsc_hz, tsc_origin};

/// The floor a build names (`SOURCE_DATE_EPOCH`, see `build.rs`), or 0.
const BUILD_FLOOR_UNIX: u64 = parse_decimal(env!("CLEAN_SLATE_BUILD_FLOOR_UNIX"));

/// The oldest firmware time taken as a wall clock: the build date when the build names a later
/// one than the built-in floor.
pub(crate) const WALL_CLOCK_FLOOR_UNIX: u64 =
    max_u64(BUILD_FLOOR_UNIX, WALL_CLOCK_DEFAULT_FLOOR_UNIX);

const _: () = assert!(WALL_CLOCK_FLOOR_UNIX >= WALL_CLOCK_DEFAULT_FLOOR_UNIX);

const fn max_u64(a: u64, b: u64) -> u64 {
    if a > b {
        a
    } else {
        b
    }
}

const fn parse_decimal(text: &str) -> u64 {
    let bytes = text.as_bytes();
    let mut value: u64 = 0;
    let mut index = 0;
    while index < bytes.len() {
        let digit = bytes[index];
        assert!(
            digit.is_ascii_digit(),
            "CLEAN_SLATE_BUILD_FLOOR_UNIX is not a number"
        );
        value = value * 10 + (digit - b'0') as u64;
        index += 1;
    }
    value
}

#[cfg(not(test))]
static FIRMWARE_WALL_NS: AtomicU64 = AtomicU64::new(0);
#[cfg(not(test))]
static FIRMWARE_TSC: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
use crate::sync::per_test_thread::PerTestThread;
#[cfg(test)]
static FIRMWARE_WALL_NS: PerTestThread<AtomicU64> = PerTestThread::new(AtomicU64::new(0));
#[cfg(test)]
static FIRMWARE_TSC: PerTestThread<AtomicU64> = PerTestThread::new(AtomicU64::new(0));

/// What boot made of the firmware clock, for the boot log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BootReading {
    /// A wall clock, at this Unix time when it was read.
    Known(CivilTime),
    /// `GetTime` failed.
    Unavailable,
    /// The firmware time is not a wall clock.
    Refused(CivilTime, WallClockError),
}

/// Records a firmware reading taken when the TSC read `tsc`. The fail-closed rule decides here,
/// once; a refused reading leaves no wall clock.
pub(crate) fn record_firmware_time(
    time: Option<(CivilTime, Option<i16>)>,
    tsc: u64,
    floor_unix: u64,
) -> BootReading {
    let Some((civil, zone)) = time else {
        return BootReading::Unavailable;
    };
    match wall_clock_from_firmware(&civil, zone, floor_unix) {
        Ok(wall_ns) => {
            FIRMWARE_TSC.store(tsc, Ordering::Release);
            FIRMWARE_WALL_NS.store(wall_ns, Ordering::Release);
            BootReading::Known(CivilTime::from_unix_ns(wall_ns))
        }
        Err(error) => BootReading::Refused(civil, error),
    }
}

/// Reads UEFI `GetTime`. Boot services must still be active.
#[cfg(not(test))]
pub(crate) fn capture_firmware_time() -> BootReading {
    let time = ::uefi::runtime::get_time().ok().map(|time| {
        (
            CivilTime {
                year: time.year(),
                month: time.month(),
                day: time.day(),
                hour: time.hour(),
                minute: time.minute(),
                second: time.second(),
                nanosecond: time.nanosecond(),
            },
            time.time_zone(),
        )
    });
    let tsc = crate::time::calibration::read_tsc();
    record_firmware_time(time, tsc, WALL_CLOCK_FLOOR_UNIX)
}

/// The boot log line for a reading.
pub(crate) fn log_boot_reading(reading: BootReading) {
    use crate::diagnostics::serial::serial_write_fmt;
    match reading {
        BootReading::Known(t) => serial_write_fmt(format_args!(
            "[TIME] wall clock {:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z from firmware\n",
            t.year, t.month, t.day, t.hour, t.minute, t.second
        )),
        BootReading::Unavailable => {
            serial_write_fmt(format_args!("[TIME] no wall clock: firmware GetTime failed\n"))
        }
        BootReading::Refused(t, error) => serial_write_fmt(format_args!(
            "[TIME] no wall clock: firmware time {:04}-{:02}-{:02}T{:02}:{:02}:{:02} refused ({})\n",
            t.year,
            t.month,
            t.day,
            t.hour,
            t.minute,
            t.second,
            match error {
                WallClockError::BeforeFloor { .. } => "before the build floor",
                WallClockError::Invalid(_) => "invalid",
            }
        )),
    }
}

/// The Unix time at monotonic 0, once the TSC is calibrated; `None` without a wall clock.
pub(crate) fn boot_epoch() -> Option<u64> {
    let wall_ns = FIRMWARE_WALL_NS.load(Ordering::Acquire);
    if wall_ns == 0 {
        return None;
    }
    let hz = tsc_hz()?;
    let read_at = FIRMWARE_TSC.load(Ordering::Acquire);
    let origin = tsc_origin();
    // The firmware was read before calibration set the origin; the gap moves the epoch later.
    let gap_ns = mul_div_u128(
        origin.saturating_sub(read_at),
        1_000_000_000,
        u128::from(hz),
    )?;
    Some(boot_epoch_ns(wall_ns, gap_ns))
}

/// Unix nanoseconds now, or `None` when this boot has no wall clock.
pub(crate) fn wall_clock_ns() -> Option<u64> {
    Some(wall_now_ns(boot_epoch()?, monotonic_ns()))
}

/// Syscall 24 `CLOCK` (see `clean_slate_native_abi::clock`).
pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    frame.rax = dispatch(frame);
}

fn dispatch(frame: &SyscallContext) -> u64 {
    if [frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9]
        .iter()
        .any(|&arg| arg != 0)
    {
        return STATUS_EINVAL;
    }
    if tsc_hz().is_none() {
        return STATUS_EINVAL;
    }
    match frame.rdi {
        CLOCK_SUBOP_MONOTONIC => monotonic_ns(),
        CLOCK_SUBOP_WALL => wall_clock_ns().unwrap_or(STATUS_ENODATA),
        _ => STATUS_EINVAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::set_test_monotonic_tsc;

    const HZ: u64 = 1_000_000_000;

    fn civil(year: u16, month: u8, day: u8) -> CivilTime {
        CivilTime {
            year,
            month,
            day,
            hour: 12,
            minute: 0,
            second: 0,
            nanosecond: 0,
        }
    }

    fn frame(rdi: u64, rsi: u64, r9: u64) -> SyscallContext {
        SyscallContext {
            rax: 0,
            rdx: 0,
            rbx: 0,
            rbp: 0,
            rsi,
            rdi,
            r8: 0,
            r9,
            r10: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            user_rip: 0,
            user_rflags: 0,
            user_rsp: 0,
        }
    }

    fn call(rdi: u64, rsi: u64) -> u64 {
        let mut frame = frame(rdi, rsi, 0);
        handle_syscall(&mut frame);
        frame.rax
    }

    #[test]
    fn the_built_in_floor_holds_without_a_build_date() {
        assert_eq!(
            max_u64(0, WALL_CLOCK_DEFAULT_FLOOR_UNIX),
            WALL_CLOCK_DEFAULT_FLOOR_UNIX
        );
        assert_eq!(
            max_u64(WALL_CLOCK_DEFAULT_FLOOR_UNIX + 1, 5),
            WALL_CLOCK_DEFAULT_FLOOR_UNIX + 1
        );
        assert_eq!(parse_decimal("0"), 0);
        assert_eq!(parse_decimal("1795651200"), 1_795_651_200);
    }

    #[test]
    fn a_refused_reading_leaves_no_wall_clock() {
        set_test_monotonic_tsc(HZ, 0);
        let floor = WALL_CLOCK_DEFAULT_FLOOR_UNIX;
        assert_eq!(
            record_firmware_time(None, 0, floor),
            BootReading::Unavailable
        );
        let reading = record_firmware_time(Some((civil(2001, 1, 1), None)), 0, floor);
        assert!(matches!(
            reading,
            BootReading::Refused(_, WallClockError::BeforeFloor { .. })
        ));
        assert_eq!(wall_clock_ns(), None);
        assert_eq!(call(CLOCK_SUBOP_WALL, 0), STATUS_ENODATA);
    }

    #[test]
    fn wall_time_is_the_epoch_plus_monotonic_time() {
        let origin = crate::time::calibration::read_tsc();
        set_test_monotonic_tsc(HZ, origin);
        // The firmware was read 2 ms of TSC before the origin.
        let reading = record_firmware_time(
            Some((civil(2030, 6, 1), None)),
            origin - 2_000_000,
            WALL_CLOCK_DEFAULT_FLOOR_UNIX,
        );
        let firmware_ns = civil(2030, 6, 1).unix_ns(None).unwrap();
        assert_eq!(
            reading,
            BootReading::Known(CivilTime::from_unix_ns(firmware_ns))
        );
        let epoch = firmware_ns + 2_000_000;
        assert_eq!(boot_epoch(), Some(epoch));
        let mono = call(CLOCK_SUBOP_MONOTONIC, 0);
        let wall = call(CLOCK_SUBOP_WALL, 0);
        let mono_after = call(CLOCK_SUBOP_MONOTONIC, 0);
        assert!(wall >= epoch.saturating_add(mono) && wall <= epoch.saturating_add(mono_after));
    }

    #[test]
    fn bad_calls_are_refused() {
        set_test_monotonic_tsc(HZ, 0);
        assert_eq!(call(2, 0), STATUS_EINVAL);
        assert_eq!(call(CLOCK_SUBOP_MONOTONIC, 1), STATUS_EINVAL);
        let mut frame = frame(CLOCK_SUBOP_MONOTONIC, 0, 1);
        handle_syscall(&mut frame);
        assert_eq!(frame.rax, STATUS_EINVAL);
    }

    #[test]
    fn an_uncalibrated_clock_is_refused() {
        set_test_monotonic_tsc(0, 0);
        assert_eq!(call(CLOCK_SUBOP_MONOTONIC, 0), STATUS_EINVAL);
        assert_eq!(call(CLOCK_SUBOP_WALL, 0), STATUS_EINVAL);
    }
}
