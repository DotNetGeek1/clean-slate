//! #308 native clock lane (`cargo xtask test-m10-clock`).
//!
//! The clock host tests, then two boots of the `m10-clock-self-test` kernel. In the first,
//! QEMU's RTC starts at the host's own time (`-rtc base=<now>`); a fixture reads the monotonic
//! clock across a 50 ms wait and then the wall clock, and the host checks that the wall
//! reading the guest logs is within [`WALL_TOLERANCE_S`] of the host time over the run. In the
//! second, the RTC starts in 2001, before the build floor, and the guest must report no wall
//! clock (fail closed) while the monotonic clock still works.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use time::OffsetDateTime;

use crate::marker_spec::MarkerSet;
use crate::{
    build_m6_fixture_userspace, prepare_vm, run_cargo_package_tests, run_driven_acceptance_command,
    NoDriver, VmLaunchConfig, XtaskError,
};

const FEATURE: &str = "m10-clock-self-test";
const TIMEOUT: Duration = Duration::from_secs(60);
/// The RTC counts whole seconds, so a reading can trail the host by up to one; the rest is
/// slack for the host clock moving while QEMU starts.
const WALL_TOLERANCE_S: u64 = 3;
const WALL_PREFIX: &str = "[M10.clock] wall unix_s=";
/// A reset CMOS clock: valid, but years before any build floor.
const STALE_RTC_BASE: &str = "2001-01-01T00:00:00";

pub(crate) const KNOWN_MARKERS: [&str; 5] = [
    "[TIME] wall clock ",
    "[M10.clock] fixture spawned pid=1",
    "[M10.clock] monotonic advanced across a 50 ms wait",
    WALL_PREFIX,
    "[M10.clock] PASS",
];

pub(crate) const FAIL_CLOSED_MARKERS: [&str; 5] = [
    "[TIME] no wall clock: firmware time 2001-01-01T00:00:",
    "[M10.clock] fixture spawned pid=1",
    "[M10.clock] monotonic advanced across a 50 ms wait",
    "[M10.clock] wall unknown",
    "[M10.clock] PASS",
];

pub(crate) fn run() -> Result<(), XtaskError> {
    run_cargo_package_tests("clean-slate-native-abi", &["clock"])?;
    run_cargo_package_tests("clean-slate-runtime", &["clock"])?;
    run_cargo_package_tests(
        "clean-slate-kernel",
        &["--", "time::wall", "dispatch_native_clock"],
    )?;
    build_m6_fixture_userspace(true)?;

    let start = unix_now()?;
    let output = boot(&rtc_base(start)?, &KNOWN_MARKERS)?;
    let end = unix_now()?;
    let wall = parse_wall_seconds(&output)?;
    check_wall(wall, start, end)?;
    println!("[M10.clock] wall clock unix_s={wall} within {WALL_TOLERANCE_S} s of the host");

    boot(STALE_RTC_BASE, &FAIL_CLOSED_MARKERS)?;
    println!("[M10.clock] a clock before the build floor gives no wall clock");
    println!("[M10.clock] lane PASS");
    Ok(())
}

fn boot(rtc_base: &str, markers: &'static [&'static str]) -> Result<String, XtaskError> {
    let mut vm = prepare_vm(false, false, &[FEATURE], VmLaunchConfig::default())?;
    vm.qemu
        .arg("-rtc")
        .arg(format!("base={rtc_base},clock=host"));
    run_driven_acceptance_command(
        &mut vm.qemu,
        MarkerSet::Ordered(markers),
        TIMEOUT,
        &mut NoDriver,
    )
}

fn unix_now() -> Result<u64, XtaskError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| XtaskError::Validation("host clock is before 1970".to_owned()))
}

/// QEMU's `-rtc base=` form, in UTC.
fn rtc_base(unix_seconds: u64) -> Result<String, XtaskError> {
    let time = i64::try_from(unix_seconds)
        .ok()
        .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
        .ok_or_else(|| XtaskError::Validation("host time out of range".to_owned()))?;
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second()
    ))
}

fn parse_wall_seconds(output: &str) -> Result<u64, XtaskError> {
    output
        .lines()
        .find_map(|line| {
            let rest = &line[line.find(WALL_PREFIX)? + WALL_PREFIX.len()..];
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        })
        .ok_or_else(|| XtaskError::Validation(format!("no `{WALL_PREFIX}<seconds>` line")))
}

fn check_wall(wall: u64, start: u64, end: u64) -> Result<(), XtaskError> {
    if wall + WALL_TOLERANCE_S < start || wall > end + WALL_TOLERANCE_S {
        return Err(XtaskError::Validation(format!(
            "guest wall clock unix_s={wall} is outside the host's {start}..={end} \
             (tolerance {WALL_TOLERANCE_S} s)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtc_base_is_qemu_utc_form() {
        assert_eq!(rtc_base(0).unwrap(), "1970-01-01T00:00:00");
        assert_eq!(rtc_base(1_804_136_767).unwrap(), "2027-03-04T05:06:07");
    }

    #[test]
    fn the_wall_line_parses() {
        let output = "[BOOT] x\n[M10.clock] wall unix_s=1804136767 utc=2027-03-04T05:06:07Z\n";
        assert_eq!(parse_wall_seconds(output).unwrap(), 1_804_136_767);
        assert!(parse_wall_seconds("[M10.clock] wall unknown\n").is_err());
    }

    #[test]
    fn the_wall_reading_must_fall_within_the_run() {
        assert!(check_wall(100, 100, 130).is_ok());
        assert!(check_wall(98, 100, 130).is_ok());
        assert!(check_wall(133, 100, 130).is_ok());
        assert!(check_wall(96, 100, 130).is_err());
        assert!(check_wall(134, 100, 130).is_err());
    }

    #[test]
    fn the_stale_base_is_before_the_floor() {
        // The guest prints the refused firmware time; the marker names the stale base's date.
        assert!(FAIL_CLOSED_MARKERS[0].contains(&STALE_RTC_BASE[..16]));
    }
}
