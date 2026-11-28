//! #379: what init reads from the resource snapshot once boot has settled. Init takes one
//! snapshot as it starts and one when every row is up, and logs a summary the boot lanes
//! check: the second lists init and (on a desktop boot) the compositor, and shows init ran in
//! between.

use clean_slate_runtime::resources::ResourceSnapshot;

/// The summary init logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsageSummary {
    /// Rows in the second snapshot.
    pub rows: u32,
    /// The second snapshot has init's row (pid `self_pid`, named `init`).
    pub lists_init: bool,
    /// The second snapshot has a row named `compositor`.
    pub lists_compositor: bool,
    /// Init's CPU time grew between the two snapshots.
    pub init_cpu_grew: bool,
    /// Busy time over elapsed time in the second snapshot, in thousandths.
    pub busy_permille: u64,
    /// Init's CPU time in the second snapshot, in microseconds.
    pub init_cpu_us: u64,
}

impl UsageSummary {
    pub fn of(before: &ResourceSnapshot, after: &ResourceSnapshot, self_pid: u64) -> Self {
        let init = |snapshot: &ResourceSnapshot| {
            snapshot
                .rows()
                .find(|row| row.pid == self_pid && row.name.as_str() == "init")
        };
        let (init_before, init_after) = (init(before), init(after));
        let header = after.header();
        Self {
            rows: header.rows,
            lists_init: init_after.is_some(),
            lists_compositor: after.find_named("compositor").is_some(),
            init_cpu_grew: match (init_before, init_after) {
                (Some(before), Some(after)) => {
                    before.generation == after.generation && after.cpu_ns > before.cpu_ns
                }
                _ => false,
            },
            busy_permille: header
                .busy_ns
                .saturating_mul(1000)
                .checked_div(header.elapsed_ns)
                .unwrap_or(0),
            init_cpu_us: init_after.map_or(0, |row| row.cpu_ns / 1000),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_native_abi::resources::{
        Personality, ProcessName, ProcessRow, ProcessRunState,
    };
    use clean_slate_runtime::fake::FakeKernel;
    use clean_slate_runtime::resources::snapshot;

    fn row(pid: u64, cpu_ns: u64, name: &str) -> ProcessRow {
        ProcessRow {
            pid,
            generation: pid,
            cpu_ns,
            private_pages: 1,
            shared_pages: 0,
            kernel_pages: 8,
            service_id: 0,
            personality: Personality::Native,
            state: ProcessRunState::Running,
            name: ProcessName::new(name.as_bytes()),
        }
    }

    fn two(rows_after: &[ProcessRow]) -> (ResourceSnapshot, ResourceSnapshot) {
        let mut sys = FakeKernel::new();
        sys.resources(3, true, &[row(3, 1_000_000, "init")]);
        sys.resources_at(1_000);
        let before = snapshot(&mut sys).unwrap();
        sys.resources(3, true, rows_after);
        sys.resources_at(10_000_000);
        (before, snapshot(&mut sys).unwrap())
    }

    #[test]
    fn a_desktop_boot_lists_init_and_the_compositor() {
        let (before, after) = two(&[
            row(3, 3_000_000, "init"),
            row(4, 2_000_000, "storage"),
            row(9, 4_000_000, "compositor"),
        ]);
        let summary = UsageSummary::of(&before, &after, 3);
        assert_eq!(
            summary,
            UsageSummary {
                rows: 3,
                lists_init: true,
                lists_compositor: true,
                init_cpu_grew: true,
                busy_permille: 900,
                init_cpu_us: 3_000,
            }
        );
    }

    #[test]
    fn init_that_did_not_run_or_is_missing_is_reported() {
        let (before, after) = two(&[row(3, 1_000_000, "init")]);
        let summary = UsageSummary::of(&before, &after, 3);
        assert!(summary.lists_init && !summary.init_cpu_grew && !summary.lists_compositor);
        let (before, after) = two(&[row(4, 5, "storage")]);
        let summary = UsageSummary::of(&before, &after, 3);
        assert!(!summary.lists_init && !summary.init_cpu_grew);
        // Another process named init is not init.
        let (before, after) = two(&[row(7, 9_000_000, "init")]);
        assert!(!UsageSummary::of(&before, &after, 3).lists_init);
    }
}
