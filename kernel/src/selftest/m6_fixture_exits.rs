//! Bounded record of the fixture pids that have exited during one harness run.
//!
//! `WAIT_EXIT` consults this log so a wait issued after the fixture's teardown
//! succeeds immediately instead of depending on whether a wakeup was seen.

/// What a `WAIT_EXIT` on a pid should do right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExitWait {
    /// The fixture has already been torn down.
    Exited,
    /// The fixture is still live; block until the next fixture exit.
    Pending,
    /// The pid was never a fixture in this run.
    NotAFixture,
}

pub(crate) struct FixtureExitLog<const N: usize> {
    pids: [u64; N],
    len: usize,
}

impl<const N: usize> FixtureExitLog<N> {
    pub(crate) const fn new() -> Self {
        Self {
            pids: [0; N],
            len: 0,
        }
    }

    /// Records that fixture `pid` is exiting. Recording the same pid twice is a no-op.
    pub(crate) fn record(&mut self, pid: u64) -> Result<(), &'static str> {
        if self.has_exited(pid) {
            return Ok(());
        }
        let slot = self.pids.get_mut(self.len).ok_or("fixture exit log full")?;
        *slot = pid;
        self.len += 1;
        Ok(())
    }

    pub(crate) fn has_exited(&self, pid: u64) -> bool {
        self.pids[..self.len].contains(&pid)
    }

    /// `is_live_fixture` is whether `pid` is currently registered as a fixture.
    pub(crate) fn wait_state(&self, pid: u64, is_live_fixture: bool) -> ExitWait {
        if self.has_exited(pid) {
            ExitWait::Exited
        } else if is_live_fixture {
            ExitWait::Pending
        } else {
            ExitWait::NotAFixture
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_after_exit_is_ready_immediately() {
        let mut log = FixtureExitLog::<4>::new();
        log.record(5).unwrap();
        assert_eq!(log.wait_state(5, false), ExitWait::Exited);
    }

    #[test]
    fn wait_before_exit_blocks_until_recorded() {
        let mut log = FixtureExitLog::<4>::new();
        assert_eq!(log.wait_state(5, true), ExitWait::Pending);
        log.record(5).unwrap();
        assert_eq!(log.wait_state(5, false), ExitWait::Exited);
    }

    #[test]
    fn never_a_fixture_fails_closed() {
        let mut log = FixtureExitLog::<4>::new();
        log.record(5).unwrap();
        assert_eq!(log.wait_state(6, false), ExitWait::NotAFixture);
        assert_eq!(log.wait_state(0, false), ExitWait::NotAFixture);
    }

    #[test]
    fn full_log_rejects_new_pids_but_accepts_repeats() {
        let mut log = FixtureExitLog::<2>::new();
        log.record(1).unwrap();
        log.record(2).unwrap();
        assert_eq!(log.record(2), Ok(()));
        assert_eq!(log.record(3), Err("fixture exit log full"));
        assert_eq!(log.wait_state(3, true), ExitWait::Pending);
    }
}
