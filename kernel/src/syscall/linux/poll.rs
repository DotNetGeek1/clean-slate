//! Linux `poll` interest registration for producer wakeups (#103).

#![cfg_attr(
    any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test"
    ),
    allow(dead_code)
)]

use crate::process::linux_fd::open_description::OpenDescriptionId;
use crate::sched::wait::{wake_all, WaitKey};
use crate::sync::global_cell::GlobalCell;

pub(crate) const LINUX_POLL_MAX_FDS: usize = 8;
pub(crate) const LINUX_POLL_INTEREST_MAX: usize = 16;

const LANE: u64 = 0x52;

pub(crate) fn poll_wait_key(pid: u64) -> WaitKey {
    WaitKey((LANE << 56) | (0x01u64 << 48) | pid)
}

pub(crate) fn nanosleep_wait_key(pid: u64) -> WaitKey {
    WaitKey((LANE << 56) | pid)
}

#[derive(Clone, Copy)]
struct InterestEntry {
    desc: OpenDescriptionId,
    pid: u64,
}

struct InterestTable {
    entries: [Option<InterestEntry>; LINUX_POLL_INTEREST_MAX],
}

impl InterestTable {
    const fn new() -> Self {
        Self {
            entries: [const { None }; LINUX_POLL_INTEREST_MAX],
        }
    }

    fn register(&mut self, desc: OpenDescriptionId, pid: u64) -> Result<(), ()> {
        if self
            .entries
            .iter()
            .any(|entry| matches!(entry, Some(e) if e.desc == desc && e.pid == pid))
        {
            return Ok(());
        }
        let free = self
            .entries
            .iter()
            .position(|entry| entry.is_none())
            .ok_or(())?;
        self.entries[free] = Some(InterestEntry { desc, pid });
        Ok(())
    }

    fn clear_for_pid(&mut self, pid: u64) {
        for entry in self.entries.iter_mut() {
            if matches!(entry, Some(e) if e.pid == pid) {
                *entry = None;
            }
        }
    }
}

static INTEREST: GlobalCell<InterestTable> = GlobalCell::new(InterestTable::new());

pub(crate) fn register_poll_interest(desc: OpenDescriptionId, pid: u64) -> Result<(), ()> {
    unsafe { (*INTEREST.get()).register(desc, pid) }
}

#[cfg(feature = "m9-linux-trace-self-test")]
pub(crate) fn reset_poll_interest_for_selftest() {
    unsafe { *INTEREST.get() = InterestTable::new() };
}

pub(crate) fn clear_poll_interest_for_pid(pid: u64) {
    unsafe {
        (*INTEREST.get()).clear_for_pid(pid);
    }
}

pub(crate) fn wake_poll_waiters_for_pid(pid: u64) -> usize {
    wake_all(poll_wait_key(pid))
}

#[allow(dead_code)]
pub(crate) fn notify_readiness_changed(desc: OpenDescriptionId) {
    let table = unsafe { &*INTEREST.get() };
    for entry in table.entries.iter().flatten() {
        if entry.desc == desc {
            wake_all(poll_wait_key(entry.pid));
        }
    }
}

#[cfg(any(test, feature = "m9-linux-runtime-self-test"))]
pub(crate) fn interest_occupied() -> usize {
    unsafe {
        (*INTEREST.get())
            .entries
            .iter()
            .filter(|entry| entry.is_some())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interest_table_bounded() {
        unsafe {
            *INTEREST.get() = InterestTable::new();
        }
        let desc = OpenDescriptionId {
            index: 1,
            generation: 1,
        };
        for pid in 0..LINUX_POLL_INTEREST_MAX {
            register_poll_interest(desc, pid as u64).expect("register");
        }
        assert!(register_poll_interest(desc, 99).is_err());
        assert_eq!(interest_occupied(), LINUX_POLL_INTEREST_MAX);
    }
}
