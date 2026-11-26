//! The clocks (syscall 24 `CLOCK`, #308).
//!
//! [`monotonic`] is the clock every [`Deadline`] is measured on: nanoseconds since boot, never
//! going backwards. [`wall`] is Unix time when the kernel has a wall clock, and `None` when it
//! does not. The kernel fails closed: a firmware clock it cannot trust gives no wall clock for
//! the whole boot, so a program that needs the date (a certificate check, a timestamp) must
//! handle `None` rather than assume one.
//!
//! [`Deadline`]: crate::port::Deadline

use clean_slate_native_abi::clock::{
    decode_wall, CLOCK_SUBOP_MONOTONIC, CLOCK_SUBOP_WALL, NANOS_PER_SECOND, SYSCALL_NR_CLOCK,
};

pub use clean_slate_native_abi::clock::CivilTime;

use crate::{Error, Syscalls};

/// Monotonic nanoseconds since boot.
pub fn monotonic<S: Syscalls>(sys: &mut S) -> Result<u64, Error> {
    sys.call(SYSCALL_NR_CLOCK, [CLOCK_SUBOP_MONOTONIC, 0, 0, 0, 0, 0])
}

/// A wall-clock reading: Unix nanoseconds (UTC, no leap seconds).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WallTime(u64);

impl WallTime {
    pub const fn from_unix_ns(unix_ns: u64) -> Self {
        Self(unix_ns)
    }

    pub const fn unix_ns(self) -> u64 {
        self.0
    }

    pub const fn unix_seconds(self) -> u64 {
        self.0 / NANOS_PER_SECOND
    }

    /// The UTC date and time of day.
    pub const fn civil(self) -> CivilTime {
        CivilTime::from_unix_ns(self.0)
    }
}

/// The wall clock, or `None` when this boot has none.
pub fn wall<S: Syscalls>(sys: &mut S) -> Result<Option<WallTime>, Error> {
    let raw = sys.syscall(SYSCALL_NR_CLOCK, [CLOCK_SUBOP_WALL, 0, 0, 0, 0, 0]);
    match decode_wall(raw) {
        Ok(time) => Ok(time.map(WallTime)),
        Err(status) => Err(Error::from_status(status)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeKernel;
    use clean_slate_native_abi::status::{STATUS_EINVAL, STATUS_ENODATA};

    #[test]
    fn monotonic_time_reads_through_the_clock_call() {
        let mut sys = FakeKernel::new();
        sys.answer_next(SYSCALL_NR_CLOCK, 1_500);
        assert_eq!(monotonic(&mut sys), Ok(1_500));
        assert_eq!(
            sys.last_call(),
            (SYSCALL_NR_CLOCK, [CLOCK_SUBOP_MONOTONIC, 0, 0, 0, 0, 0])
        );
    }

    #[test]
    fn wall_time_is_unix_time_or_none() {
        let mut sys = FakeKernel::new();
        // 2027-03-04T05:06:07.000000008Z
        sys.answer_next(SYSCALL_NR_CLOCK, 1_804_136_767_000_000_008);
        let time = wall(&mut sys).expect("wall").expect("known");
        assert_eq!(sys.last_call().1[0], CLOCK_SUBOP_WALL);
        assert_eq!(time.unix_seconds(), 1_804_136_767);
        assert_eq!(
            time.civil(),
            CivilTime {
                year: 2027,
                month: 3,
                day: 4,
                hour: 5,
                minute: 6,
                second: 7,
                nanosecond: 8,
            }
        );

        sys.answer_next(SYSCALL_NR_CLOCK, STATUS_ENODATA);
        assert_eq!(wall(&mut sys), Ok(None));
        sys.answer_next(SYSCALL_NR_CLOCK, STATUS_EINVAL);
        assert_eq!(wall(&mut sys), Err(Error::Failed(STATUS_EINVAL)));
    }
}
