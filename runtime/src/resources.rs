//! Per-process CPU time and memory (#379), read with syscall 28 `RESOURCES`. The wire format
//! and the rules are `clean_slate_native_abi::resources`.
//!
//! [`snapshot`] lists every process and needs the system observer grant (init, and manifest
//! rows with `Grant::SystemObserver`); without it the kernel refuses with `EACCES`.
//! [`own_usage`] needs nothing and answers with the caller's own row only. CPU shares come from
//! two snapshots: [`cpu_share_permille`].

use clean_slate_native_abi::resources::{
    self, ProcessRow, Snapshot, SnapshotHeader, RESOURCES_OP_SELF, RESOURCES_OP_SYSTEM,
    SNAPSHOT_MAX_BYTES, SYSCALL_NR_RESOURCES,
};
use clean_slate_native_abi::status::STATUS_EINVAL;

use crate::{Error, Syscalls};

/// One answer of the kernel, kept as the bytes it wrote and read through [`Self::rows`].
#[derive(Clone, Copy)]
pub struct ResourceSnapshot {
    bytes: [u8; SNAPSHOT_MAX_BYTES],
    len: usize,
    header: SnapshotHeader,
}

impl ResourceSnapshot {
    pub const fn header(&self) -> &SnapshotHeader {
        &self.header
    }

    /// Monotonic nanoseconds when the kernel took it.
    pub const fn taken_ns(&self) -> u64 {
        self.header.snapshot_ns
    }

    pub fn rows(&self) -> impl Iterator<Item = ProcessRow> + '_ {
        // `read` checked these bytes, so the decode does not fail.
        Snapshot::decode(&self.bytes[..self.len])
            .ok()
            .into_iter()
            .flat_map(|snapshot| snapshot.rows())
    }

    /// The row of `pid` with `generation`: the same process, not a later one with its pid.
    pub fn find(&self, pid: u64, generation: u64) -> Option<ProcessRow> {
        self.rows()
            .find(|row| row.pid == pid && row.generation == generation)
    }

    /// The first row named `name`.
    pub fn find_named(&self, name: &str) -> Option<ProcessRow> {
        self.rows().find(|row| row.name.as_str() == name)
    }

    /// Whether the kernel had more processes than the buffer held. [`snapshot`] passes a
    /// buffer that holds the registry, so this is never true for it.
    pub const fn is_truncated(&self) -> bool {
        self.header.rows < self.header.total_rows
    }
}

impl core::fmt::Debug for ResourceSnapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResourceSnapshot")
            .field("header", &self.header)
            .field("rows", &self.rows().count())
            .finish()
    }
}

/// Every process, with the system totals. Needs the system observer grant.
pub fn snapshot<S: Syscalls>(sys: &mut S) -> Result<ResourceSnapshot, Error> {
    read(sys, RESOURCES_OP_SYSTEM)
}

/// The caller's own row and when it was taken. Needs no grant.
pub fn own_usage<S: Syscalls>(sys: &mut S) -> Result<(u64, ProcessRow), Error> {
    let snapshot = read(sys, RESOURCES_OP_SELF)?;
    let row = snapshot.rows().next().ok_or(Error::Failed(STATUS_EINVAL))?;
    Ok((snapshot.taken_ns(), row))
}

/// The CPU share of the process `pid` with `generation` between two snapshots, in thousandths
/// of the time between them (1000 is one CPU). `None` when it is missing from either, or the
/// snapshots are not in order.
pub fn cpu_share_permille(
    before: &ResourceSnapshot,
    after: &ResourceSnapshot,
    pid: u64,
    generation: u64,
) -> Option<u32> {
    resources::cpu_share_permille(
        before.taken_ns(),
        &before.find(pid, generation)?,
        after.taken_ns(),
        &after.find(pid, generation)?,
    )
}

fn read<S: Syscalls>(sys: &mut S, op: u64) -> Result<ResourceSnapshot, Error> {
    let mut bytes = [0u8; SNAPSHOT_MAX_BYTES];
    let raw = sys.call(
        SYSCALL_NR_RESOURCES,
        [op, bytes.as_mut_ptr() as u64, bytes.len() as u64, 0, 0, 0],
    )?;
    let len = resources::decode_written(raw).map_err(Error::Failed)?;
    let header = Snapshot::decode(&bytes[..len])
        .map_err(|_| Error::Failed(STATUS_EINVAL))?
        .header;
    if op == RESOURCES_OP_SELF && (header.is_system() || header.rows != 1) {
        return Err(Error::Failed(STATUS_EINVAL));
    }
    Ok(ResourceSnapshot { bytes, len, header })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeKernel;
    use clean_slate_native_abi::resources::{Personality, ProcessName, ProcessRunState};
    use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_ENODATA};

    fn row(pid: u64, cpu_ns: u64, name: &str) -> ProcessRow {
        ProcessRow {
            pid,
            generation: pid,
            cpu_ns,
            private_pages: 4,
            shared_pages: 0,
            kernel_pages: 8,
            service_id: 0,
            personality: Personality::Native,
            state: ProcessRunState::Running,
            name: ProcessName::new(name.as_bytes()),
        }
    }

    fn system() -> FakeKernel {
        let mut sys = FakeKernel::new();
        sys.resources(
            3,
            true,
            &[
                row(1, 500, "init"),
                row(3, 200, "monitor"),
                row(4, 900, "compositor"),
            ],
        );
        sys
    }

    #[test]
    fn a_snapshot_lists_every_process() {
        let mut sys = system();
        sys.resources_at(10_000_000);
        let snapshot = snapshot(&mut sys).unwrap();
        assert!(snapshot.header().is_system());
        assert!(!snapshot.is_truncated());
        assert_eq!(snapshot.taken_ns(), 10_000_000);
        let names: std::vec::Vec<_> = snapshot.rows().map(|row| row.name).collect();
        assert_eq!(
            names,
            [
                ProcessName::new(b"init"),
                ProcessName::new(b"monitor"),
                ProcessName::new(b"compositor")
            ]
        );
        assert_eq!(snapshot.find_named("compositor").unwrap().pid, 4);
        let (nr, args) = sys.last_call();
        assert_eq!(nr, SYSCALL_NR_RESOURCES);
        assert_eq!(args[0], RESOURCES_OP_SYSTEM);
        assert_eq!(args[2], SNAPSHOT_MAX_BYTES as u64);
        assert_eq!(&args[3..], &[0, 0, 0]);
    }

    #[test]
    fn without_the_grant_only_the_own_row_is_readable() {
        let mut sys = FakeKernel::new();
        sys.resources(3, false, &[row(1, 500, "init"), row(3, 200, "app")]);
        assert_eq!(
            snapshot(&mut sys).unwrap_err(),
            Error::Failed(STATUS_EACCES)
        );
        let (_, own) = own_usage(&mut sys).unwrap();
        assert_eq!(own.pid, 3);
        assert_eq!(own.name.as_str(), "app");
        assert_eq!(sys.last_call().1[0], RESOURCES_OP_SELF);
    }

    #[test]
    fn the_cpu_share_comes_from_two_snapshots() {
        let mut sys = system();
        sys.resources_at(0);
        let before = snapshot(&mut sys).unwrap();
        sys.resources_at(10_000_000);
        sys.resources_cpu(4, 900 + 2_500_000);
        let after = snapshot(&mut sys).unwrap();
        assert_eq!(cpu_share_permille(&before, &after, 4, 4), Some(250));
        assert_eq!(cpu_share_permille(&before, &after, 1, 1), Some(0));
        assert_eq!(cpu_share_permille(&before, &after, 4, 5), None);
        assert_eq!(cpu_share_permille(&after, &before, 4, 4), None);
    }

    #[test]
    fn statuses_pass_through() {
        let mut sys = system();
        sys.answer_next(SYSCALL_NR_RESOURCES, STATUS_ENODATA);
        assert_eq!(
            snapshot(&mut sys).unwrap_err(),
            Error::Failed(STATUS_ENODATA)
        );
        // A length that is not a snapshot.
        sys.answer_next(SYSCALL_NR_RESOURCES, 3);
        assert_eq!(
            snapshot(&mut sys).unwrap_err(),
            Error::Failed(STATUS_EINVAL)
        );
    }
}
