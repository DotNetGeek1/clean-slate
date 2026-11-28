//! #378 per-app network counters: what the network service has done for each running app, for
//! the task monitor to read with `STATS` (`clean_slate_native_abi::net`).
//!
//! An app is the caller's kernel-attested identity, `TrustedCaller::domain`, the key the per-app
//! policy uses (#221 stage E): a manifest row, its forks included. A row starts with the app's
//! first request and is dropped when the last process of the app the table has seen exits, so
//! the table describes running apps only. Both tables are bounded: requests from an app the full
//! row table has no room for are counted only as untracked, and a process the full process table
//! cannot hold keeps its app's row until the service restarts (it is never dropped early).

use clean_slate_native_abi::net::{NetAppStats, NET_APP_STATS_ROW_BYTES, NET_STATS_MAX_APPS};
use clean_slate_network::protocol::TrustedCaller;

/// The most processes the table follows to know when an app has exited.
pub const NET_STATS_MAX_PROCESSES: usize = 64;

/// Something the service did for a caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetStatsEvent {
    /// A request that changes no counter (an `OPEN`, a `CLOSE`): the app is now running.
    Seen,
    /// Application bytes accepted by a `SEND`.
    Sent(u32),
    /// Application bytes returned by a `RECEIVE`.
    Received(u32),
    /// A `CONNECT` or `ACCEPT` that completed.
    Connection,
    /// A `LISTEN` that completed.
    Listener,
    /// A request the app's policy refused.
    Refusal,
    /// A name lookup that went to the resolver (not one answered from the cache).
    DnsLookup,
}

/// What [`AppNetStats::encode`] wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetStatsTable {
    /// Rows written.
    pub rows: u16,
    /// Rows the table holds.
    pub apps: u16,
    /// Requests from apps the full table had no row for.
    pub untracked: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Process {
    pid: u64,
    instance_generation: u64,
    app: u64,
}

impl Process {
    const fn of(caller: &TrustedCaller) -> Self {
        Self {
            pid: caller.pid,
            instance_generation: caller.instance_generation,
            app: caller.domain,
        }
    }

    const fn is(&self, caller: &TrustedCaller) -> bool {
        self.pid == caller.pid && self.instance_generation == caller.instance_generation
    }
}

#[derive(Clone, Copy, Debug)]
struct Row {
    stats: NetAppStats,
    /// A process of this app did not fit the process table, so its exit cannot be seen.
    pinned: bool,
}

/// The per-app counter table (fixed size, no heap).
pub struct AppNetStats {
    rows: [Option<Row>; NET_STATS_MAX_APPS],
    processes: [Option<Process>; NET_STATS_MAX_PROCESSES],
    untracked: u32,
}

impl Default for AppNetStats {
    fn default() -> Self {
        Self::new()
    }
}

impl AppNetStats {
    pub const fn new() -> Self {
        Self {
            rows: [None; NET_STATS_MAX_APPS],
            processes: [None; NET_STATS_MAX_PROCESSES],
            untracked: 0,
        }
    }

    fn row_index(&self, app: u64) -> Option<usize> {
        self.rows
            .iter()
            .position(|row| row.is_some_and(|row| row.stats.app == app))
    }

    /// Counts `event` for `caller`'s app, starting its row and following the process if new.
    pub fn record(&mut self, caller: &TrustedCaller, event: NetStatsEvent) {
        let index = match self.row_index(caller.domain) {
            Some(index) => index,
            None => {
                let Some(index) = self.rows.iter().position(Option::is_none) else {
                    self.untracked = self.untracked.saturating_add(1);
                    return;
                };
                self.rows[index] = Some(Row {
                    stats: NetAppStats::new(caller.domain),
                    pinned: false,
                });
                index
            }
        };
        if !self.processes.iter().flatten().any(|p| p.is(caller)) {
            match self.processes.iter_mut().find(|slot| slot.is_none()) {
                Some(slot) => *slot = Some(Process::of(caller)),
                None => {
                    if let Some(row) = self.rows[index].as_mut() {
                        row.pinned = true;
                    }
                }
            }
        }
        let Some(row) = self.rows[index].as_mut() else {
            return;
        };
        let stats = &mut row.stats;
        match event {
            NetStatsEvent::Seen => {}
            NetStatsEvent::Sent(bytes) => {
                stats.bytes_sent = stats.bytes_sent.saturating_add(u64::from(bytes));
            }
            NetStatsEvent::Received(bytes) => {
                stats.bytes_received = stats.bytes_received.saturating_add(u64::from(bytes));
            }
            NetStatsEvent::Connection => stats.connections = stats.connections.saturating_add(1),
            NetStatsEvent::Listener => stats.listeners = stats.listeners.saturating_add(1),
            NetStatsEvent::Refusal => stats.refusals = stats.refusals.saturating_add(1),
            NetStatsEvent::DnsLookup => stats.dns_lookups = stats.dns_lookups.saturating_add(1),
        }
    }

    /// `caller` exited: forget it, and its app's row once no process of the app is left.
    pub fn on_holder_exit(&mut self, caller: &TrustedCaller) {
        let mut app = None;
        for slot in self.processes.iter_mut() {
            if slot.is_some_and(|p| p.is(caller)) {
                app = slot.map(|p| p.app);
                *slot = None;
            }
        }
        let Some(app) = app else {
            return;
        };
        if self.processes.iter().flatten().any(|p| p.app == app) {
            return;
        }
        if let Some(index) = self.row_index(app) {
            if self.rows[index].is_some_and(|row| !row.pinned) {
                self.rows[index] = None;
            }
        }
    }

    /// `app`'s counters, with the number of its processes the table follows.
    pub fn app(&self, app: u64) -> Option<NetAppStats> {
        let row = self.rows[self.row_index(app)?]?;
        Some(self.with_processes(row.stats))
    }

    fn with_processes(&self, mut stats: NetAppStats) -> NetAppStats {
        stats.processes = self
            .processes
            .iter()
            .flatten()
            .filter(|p| p.app == stats.app)
            .count() as u32;
        stats
    }

    /// Rows the table holds.
    pub fn apps(&self) -> usize {
        self.rows.iter().flatten().count()
    }

    /// Writes as many rows as whole fit in `out`, in table order.
    pub fn encode(&self, out: &mut [u8]) -> NetStatsTable {
        let mut written = 0usize;
        for row in self.rows.iter().flatten() {
            let Some(chunk) = out.get_mut(
                written * NET_APP_STATS_ROW_BYTES..(written + 1) * NET_APP_STATS_ROW_BYTES,
            ) else {
                break;
            };
            chunk.copy_from_slice(&self.with_processes(row.stats).encode());
            written += 1;
        }
        NetStatsTable {
            rows: written as u16,
            apps: self.apps() as u16,
            untracked: self.untracked,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(pid: u64, app: u64) -> TrustedCaller {
        TrustedCaller::new(pid, app, 1)
    }

    #[test]
    fn each_counter_follows_its_event() {
        let mut stats = AppNetStats::new();
        let probe = caller(9, 0x5700);
        for event in [
            NetStatsEvent::Seen,
            NetStatsEvent::Sent(30),
            NetStatsEvent::Sent(27),
            NetStatsEvent::Received(31),
            NetStatsEvent::Connection,
            NetStatsEvent::Connection,
            NetStatsEvent::Listener,
            NetStatsEvent::Refusal,
            NetStatsEvent::DnsLookup,
        ] {
            stats.record(&probe, event);
        }
        assert_eq!(
            stats.app(0x5700),
            Some(NetAppStats {
                app: 0x5700,
                bytes_sent: 57,
                bytes_received: 31,
                connections: 2,
                listeners: 1,
                refusals: 1,
                dns_lookups: 1,
                processes: 1,
            })
        );
        assert_eq!(stats.app(0x5701), None);
    }

    #[test]
    fn counts_saturate() {
        let mut stats = AppNetStats::new();
        let app = caller(1, 7);
        stats.rows[0] = Some(Row {
            stats: NetAppStats {
                bytes_sent: u64::MAX - 1,
                refusals: u32::MAX,
                ..NetAppStats::new(7)
            },
            pinned: false,
        });
        stats.record(&app, NetStatsEvent::Sent(10));
        stats.record(&app, NetStatsEvent::Refusal);
        let row = stats.app(7).unwrap();
        assert_eq!(row.bytes_sent, u64::MAX);
        assert_eq!(row.refusals, u32::MAX);
    }

    #[test]
    fn a_fork_counts_toward_its_app_and_the_row_outlives_it() {
        let mut stats = AppNetStats::new();
        let parent = caller(10, 0x60);
        let child = caller(11, 0x60);
        stats.record(&parent, NetStatsEvent::Sent(5));
        stats.record(&child, NetStatsEvent::Sent(6));
        let row = stats.app(0x60).unwrap();
        assert_eq!((row.bytes_sent, row.processes), (11, 2));
        stats.on_holder_exit(&child);
        assert_eq!(stats.app(0x60).unwrap().processes, 1);
        stats.on_holder_exit(&parent);
        assert_eq!(stats.app(0x60), None);
        assert_eq!(stats.apps(), 0);
    }

    #[test]
    fn an_unknown_exit_and_a_restarted_instance_leave_rows_alone() {
        let mut stats = AppNetStats::new();
        stats.record(&caller(10, 0x60), NetStatsEvent::Seen);
        stats.on_holder_exit(&caller(99, 0x60));
        stats.on_holder_exit(&TrustedCaller::new(10, 0x60, 2));
        assert!(stats.app(0x60).is_some());
    }

    #[test]
    fn a_full_table_counts_new_apps_as_untracked() {
        let mut stats = AppNetStats::new();
        for app in 0..NET_STATS_MAX_APPS as u64 {
            stats.record(&caller(100 + app, app), NetStatsEvent::Sent(1));
        }
        assert_eq!(stats.apps(), NET_STATS_MAX_APPS);
        stats.record(&caller(1, 999), NetStatsEvent::Sent(1));
        stats.record(&caller(1, 999), NetStatsEvent::Refusal);
        assert_eq!(stats.app(999), None);
        let mut out = [0u8; NET_STATS_MAX_APPS * NET_APP_STATS_ROW_BYTES];
        assert_eq!(
            stats.encode(&mut out),
            NetStatsTable {
                rows: NET_STATS_MAX_APPS as u16,
                apps: NET_STATS_MAX_APPS as u16,
                untracked: 2,
            }
        );
        // An exit makes room again.
        stats.on_holder_exit(&caller(100, 0));
        stats.record(&caller(1, 999), NetStatsEvent::Sent(4));
        assert_eq!(stats.app(999).unwrap().bytes_sent, 4);
    }

    #[test]
    fn a_process_the_full_process_table_cannot_follow_pins_its_row() {
        let mut stats = AppNetStats::new();
        for pid in 0..NET_STATS_MAX_PROCESSES as u64 {
            stats.record(&caller(pid, 0x60), NetStatsEvent::Seen);
        }
        let extra = caller(1000, 0x61);
        stats.record(&extra, NetStatsEvent::Sent(3));
        assert_eq!(stats.app(0x61).unwrap().processes, 0);
        // Its exit is not seen, and the row stays rather than vanish while it may still run.
        stats.on_holder_exit(&extra);
        assert_eq!(stats.app(0x61).unwrap().bytes_sent, 3);
        for pid in 0..NET_STATS_MAX_PROCESSES as u64 {
            stats.on_holder_exit(&caller(pid, 0x60));
        }
        assert_eq!(stats.app(0x60), None);
    }

    #[test]
    fn encode_writes_only_whole_rows_that_fit() {
        let mut stats = AppNetStats::new();
        for app in 1..=3u64 {
            stats.record(&caller(app, app), NetStatsEvent::Received(app as u32));
        }
        let mut out = [0xaau8; 2 * NET_APP_STATS_ROW_BYTES + 47];
        let table = stats.encode(&mut out);
        assert_eq!(
            table,
            NetStatsTable {
                rows: 2,
                apps: 3,
                untracked: 0,
            }
        );
        let first = NetAppStats::decode(&out).unwrap();
        let second = NetAppStats::decode(&out[NET_APP_STATS_ROW_BYTES..]).unwrap();
        assert_eq!(
            (first.app, first.bytes_received, first.processes),
            (1, 1, 1)
        );
        assert_eq!((second.app, second.bytes_received), (2, 2));
        assert!(out[2 * NET_APP_STATS_ROW_BYTES..]
            .iter()
            .all(|&b| b == 0xaa));
        assert_eq!(stats.encode(&mut []).rows, 0);
    }
}
