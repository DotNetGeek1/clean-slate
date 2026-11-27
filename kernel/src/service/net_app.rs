//! Which app each network client belongs to (#221 stage E).
//!
//! The network service decides what a caller may reach by its app, which it reads from
//! `TrustedCaller::domain`. The kernel is the only party that can say which app a process is:
//! a row launched with `Grant::NetworkClient` is attributed to its manifest row
//! ([`attribute`]), and a Linux `fork` child to its parent's app ([`inherit`]); `execve` keeps
//! the process, so it keeps the app. Every other process is unattributed: in a kernel that
//! launches init that is [`APP_UNATTRIBUTED`], which has no policy, and in a self-test kernel
//! it is [`APP_SELF_TEST`], whose probes and fixtures may reach the lab network.
//!
//! The kernel translates at the service boundary: `SERVICE_NEXT` and `POP_HOLDER_EXIT` write
//! [`app_of`] the caller's `(pid, instance generation)` as its domain. Entries are keyed by that
//! pair, not by liveness, so a request queued by a process that has since exited, and that
//! process's exit, still carry its app: a slot is reused only once no free slot is left, and
//! then the oldest whose process is gone. There are four slots per live process, so the
//! service has taken an exit long before its entry could be reused.

use clean_slate_service_fixtures::{APP_SELF_TEST, APP_UNATTRIBUTED};

use crate::limits::PROCESS_REGISTRY_CAPACITY;
use crate::service::instance_generation::live_instance_generation_for_pid;
use crate::sync::global_cell::GlobalCell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Entry {
    pid: u64,
    generation: u32,
    app: u64,
    /// When the entry was set, for reusing the oldest stale slot first.
    stamp: u64,
}

/// More slots than live processes, so a free or stale one is always found.
const SLOTS: usize = 4 * PROCESS_REGISTRY_CAPACITY;

struct AppTable {
    entries: [Option<Entry>; SLOTS],
    next_stamp: u64,
}

impl AppTable {
    const fn new() -> Self {
        Self {
            entries: [None; SLOTS],
            next_stamp: 0,
        }
    }

    /// Records `pid`'s app. Fails only when every slot names a live process.
    fn set(
        &mut self,
        pid: u64,
        generation: u32,
        app: u64,
        live: impl Fn(u64) -> Option<u32>,
    ) -> Result<(), ()> {
        let stale_oldest = || {
            self.entries
                .iter()
                .enumerate()
                .filter_map(|(index, slot)| slot.map(|e| (index, e)))
                .filter(|(_, e)| live(e.pid) != Some(e.generation))
                .min_by_key(|(_, e)| e.stamp)
                .map(|(index, _)| index)
        };
        let slot = self
            .entries
            .iter()
            .position(|slot| slot.is_some_and(|e| e.pid == pid && e.generation == generation))
            .or_else(|| self.entries.iter().position(Option::is_none))
            .or_else(stale_oldest)
            .ok_or(())?;
        self.entries[slot] = Some(Entry {
            pid,
            generation,
            app,
            stamp: self.next_stamp,
        });
        self.next_stamp += 1;
        Ok(())
    }

    fn get(&self, pid: u64, generation: u32) -> Option<u64> {
        self.entries
            .iter()
            .flatten()
            .find(|e| e.pid == pid && e.generation == generation)
            .map(|e| e.app)
    }
}

static APPS: GlobalCell<AppTable> = GlobalCell::new(AppTable::new());

fn live_generation(pid: u64) -> Option<u32> {
    live_instance_generation_for_pid(pid).map(|generation| generation.0)
}

fn apps() -> &'static mut AppTable {
    unsafe { &mut *APPS.get() }
}

/// What a caller nobody attributed is: no app in a kernel that launches init, the self-test
/// app in any other.
const fn unattributed() -> u64 {
    if cfg!(clean_slate_system_init) {
        APP_UNATTRIBUTED
    } else {
        APP_SELF_TEST
    }
}

/// Attributes the live process `pid` to the manifest row `app` it was launched for.
#[cfg_attr(not(clean_slate_system_init), allow(dead_code))]
pub(crate) fn attribute(pid: u64, app: u64) -> Result<(), &'static str> {
    let generation = live_generation(pid).ok_or("network app: process is not live")?;
    apps()
        .set(pid, generation, app, live_generation)
        .map_err(|()| "network app: attribution table full")
}

/// A fork child belongs to its parent's app. Unattributed parents leave nothing to inherit.
#[cfg_attr(not(clean_slate_linux_proc), allow(dead_code))]
pub(crate) fn inherit(parent: u64, child: u64) {
    let table = apps();
    let Some(app) = live_generation(parent).and_then(|generation| table.get(parent, generation))
    else {
        return;
    };
    let Some(generation) = live_generation(child) else {
        return;
    };
    // The table has room for every live process, so this cannot fail; if it ever did, the
    // child would stay unattributed, which reaches nothing.
    let _ = table.set(child, generation, app, live_generation);
}

/// The app the network service sees for the caller `(pid, instance_generation)`, as its
/// `TrustedCaller::domain`. The process need not be live any more.
pub(crate) fn app_of(pid: u64, instance_generation: u64) -> u64 {
    u32::try_from(instance_generation)
        .ok()
        .and_then(|generation| apps().get(pid, generation))
        .unwrap_or(unattributed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    struct Live(RefCell<BTreeMap<u64, u32>>);

    impl Live {
        fn of(pairs: &[(u64, u32)]) -> Self {
            Self(RefCell::new(pairs.iter().copied().collect()))
        }

        fn lookup(&self) -> impl Fn(u64) -> Option<u32> + '_ {
            |pid| self.0.borrow().get(&pid).copied()
        }
    }

    #[test]
    fn an_entry_answers_only_for_its_instance_and_outlives_it() {
        let live = Live::of(&[(10, 1)]);
        let mut table = AppTable::new();
        table.set(10, 1, 0x5400, live.lookup()).unwrap();
        assert_eq!(table.get(10, 1), Some(0x5400));
        // The process exits: its queued work and its exit still carry the app.
        live.0.borrow_mut().remove(&10);
        assert_eq!(table.get(10, 1), Some(0x5400));
        // A new instance of the pid is not the old one.
        assert_eq!(table.get(10, 2), None);
    }

    #[test]
    fn a_full_table_reuses_the_oldest_slot_of_a_process_that_is_gone() {
        let live = Live::of(&[]);
        let mut table = AppTable::new();
        for pid in 0..SLOTS as u64 {
            live.0.borrow_mut().insert(pid + 100, 1);
            table.set(pid + 100, 1, 7, live.lookup()).unwrap();
        }
        assert_eq!(table.set(999, 1, 7, live.lookup()), Err(()));
        live.0.borrow_mut().remove(&106);
        live.0.borrow_mut().remove(&105);
        live.0.borrow_mut().insert(999, 1);
        table.set(999, 1, 8, live.lookup()).unwrap();
        assert_eq!(table.get(999, 1), Some(8));
        assert_eq!(table.get(105, 1), None, "the older stale entry went first");
        assert_eq!(table.get(106, 1), Some(7));
        assert_eq!(table.get(104, 1), Some(7));
    }

    #[test]
    fn setting_an_instance_again_replaces_its_entry() {
        let live = Live::of(&[(10, 1)]);
        let mut table = AppTable::new();
        table.set(10, 1, 1, live.lookup()).unwrap();
        table.set(10, 1, 2, live.lookup()).unwrap();
        assert_eq!(table.entries.iter().flatten().count(), 1);
        assert_eq!(table.get(10, 1), Some(2));
    }
}
