//! Syscall 28 `RESOURCES`: a bounded snapshot of per-process CPU time and memory (#379).
//!
//! ```text
//! | Register      | Meaning                                                  |
//! | rdi           | sub-operation: SELF (0), SYSTEM (1)                      |
//! | rsi           | user buffer the kernel writes the snapshot into          |
//! | rdx           | buffer length in bytes, at least SNAPSHOT_HEADER_BYTES   |
//! | r10, r8, r9   | reserved, must be 0                                      |
//! ```
//!
//! | Sub-operation | Result |
//! |---------------|--------|
//! | SELF | bytes written: the header and the caller's own row. Needs no capability. The header's system totals are 0, so the call says nothing about other processes |
//! | SYSTEM | bytes written: the header with the system totals and one row per process, as many as fit in the buffer. Needs `OBSERVE` on `ResourceRef::system_observe()` |
//!
//! | Status | Meaning |
//! |--------|---------|
//! | `STATUS_EINVAL` | unknown sub-operation, a reserved register set, a buffer shorter than [`SNAPSHOT_HEADER_BYTES`], or a buffer the caller cannot write |
//! | `STATUS_EACCES` | SYSTEM without the capability (audited), or a caller that is not a registered process |
//! | `STATUS_ENODATA` | the kernel has no calibrated clock yet, so it cannot give times in nanoseconds |
//!
//! The capability is found by the kernel in the caller's table, so the caller passes no handle.
//! Only root grants hold it: init, and manifest rows with `Grant::SystemObserver` (the task
//! monitor, #380). It cannot be delegated. A refused SYSTEM call is audited; a successful one
//! is not, so a monitor that polls every second does not fill the audit log.
//!
//! The snapshot is [`SnapshotHeader`] followed by `rows` × [`ProcessRow`], little-endian, with
//! no padding. `total_rows` is how many processes there were; when it is larger than `rows`
//! the buffer was too short, and [`SNAPSHOT_MAX_BYTES`] always fits every row.
//!
//! Every time is in nanoseconds. `snapshot_ns` is the monotonic clock (syscall 24) when the
//! kernel took the snapshot, so a caller computes CPU shares from two snapshots with
//! [`cpu_share_permille`]. A process's `cpu_ns` counts every thread it ever ran, reaped ones
//! included. In the system totals, `busy_ns + idle_ns + unattributed_ns == elapsed_ns`; busy
//! time of processes that have since gone is in `busy_ns` but in no row.

use crate::status::{is_status, STATUS_EINVAL};

pub const SYSCALL_NR_RESOURCES: u64 = 28;

pub const RESOURCES_OP_SELF: u64 = 0;
pub const RESOURCES_OP_SYSTEM: u64 = 1;

/// The layout version in every header.
pub const SNAPSHOT_VERSION: u16 = 1;
pub const SNAPSHOT_HEADER_BYTES: usize = 64;
pub const SNAPSHOT_ROW_BYTES: usize = 80;
/// The most rows a snapshot holds: the kernel's process registry capacity.
pub const SNAPSHOT_MAX_ROWS: usize = 16;
pub const SNAPSHOT_MAX_BYTES: usize =
    SNAPSHOT_HEADER_BYTES + SNAPSHOT_MAX_ROWS * SNAPSHOT_ROW_BYTES;
/// Bytes of a process name: a manifest row's launch name, or its image's name.
pub const PROCESS_NAME_MAX: usize = 24;

/// Header flag: the snapshot covers every process and carries the system totals (SYSTEM).
/// Without it, it holds only the caller's row and the totals are 0 (SELF).
pub const SNAPSHOT_FLAG_SYSTEM: u16 = 1 << 0;

/// Bytes [`snapshot_len`] gives for `rows` rows.
pub const fn snapshot_len(rows: usize) -> usize {
    SNAPSHOT_HEADER_BYTES + rows * SNAPSHOT_ROW_BYTES
}

/// How many rows fit in a buffer of `len` bytes, at most [`SNAPSHOT_MAX_ROWS`]; `None` when
/// not even the header fits.
pub const fn rows_that_fit(len: usize) -> Option<usize> {
    if len < SNAPSHOT_HEADER_BYTES {
        return None;
    }
    let rows = (len - SNAPSHOT_HEADER_BYTES) / SNAPSHOT_ROW_BYTES;
    Some(if rows > SNAPSHOT_MAX_ROWS {
        SNAPSHOT_MAX_ROWS
    } else {
        rows
    })
}

/// Why bytes are not a snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    /// Shorter than the header, or than the rows the header says it holds.
    Truncated,
    /// A version, size or count this layout does not know.
    Malformed,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SnapshotHeader {
    pub flags: u16,
    /// Rows that follow the header.
    pub rows: u32,
    /// Rows there were; more than `rows` when the buffer was too short.
    pub total_rows: u32,
    /// Monotonic nanoseconds when the kernel took the snapshot.
    pub snapshot_ns: u64,
    /// CPU time since the scheduler's first switch (SYSTEM only).
    pub elapsed_ns: u64,
    /// CPU time charged to some thread other than idle (SYSTEM only).
    pub busy_ns: u64,
    /// CPU time the idle thread ran (SYSTEM only).
    pub idle_ns: u64,
    /// CPU time with no current thread, between a teardown and the next dispatch (SYSTEM only).
    pub unattributed_ns: u64,
}

impl SnapshotHeader {
    pub const fn is_system(&self) -> bool {
        self.flags & SNAPSHOT_FLAG_SYSTEM != 0
    }

    pub fn encode(&self) -> [u8; SNAPSHOT_HEADER_BYTES] {
        let mut out = [0u8; SNAPSHOT_HEADER_BYTES];
        put_u16(&mut out, 0, SNAPSHOT_VERSION);
        put_u16(&mut out, 2, SNAPSHOT_HEADER_BYTES as u16);
        put_u16(&mut out, 4, SNAPSHOT_ROW_BYTES as u16);
        put_u16(&mut out, 6, self.flags);
        put_u32(&mut out, 8, self.rows);
        put_u32(&mut out, 12, self.total_rows);
        put_u64(&mut out, 16, self.snapshot_ns);
        put_u64(&mut out, 24, self.elapsed_ns);
        put_u64(&mut out, 32, self.busy_ns);
        put_u64(&mut out, 40, self.idle_ns);
        put_u64(&mut out, 48, self.unattributed_ns);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SnapshotError> {
        if bytes.len() < SNAPSHOT_HEADER_BYTES {
            return Err(SnapshotError::Truncated);
        }
        if get_u16(bytes, 0) != SNAPSHOT_VERSION
            || usize::from(get_u16(bytes, 2)) != SNAPSHOT_HEADER_BYTES
            || usize::from(get_u16(bytes, 4)) != SNAPSHOT_ROW_BYTES
            || get_u16(bytes, 6) & !SNAPSHOT_FLAG_SYSTEM != 0
            || get_u64(bytes, 56) != 0
        {
            return Err(SnapshotError::Malformed);
        }
        let header = Self {
            flags: get_u16(bytes, 6),
            rows: get_u32(bytes, 8),
            total_rows: get_u32(bytes, 12),
            snapshot_ns: get_u64(bytes, 16),
            elapsed_ns: get_u64(bytes, 24),
            busy_ns: get_u64(bytes, 32),
            idle_ns: get_u64(bytes, 40),
            unattributed_ns: get_u64(bytes, 48),
        };
        if header.rows > header.total_rows || header.rows as usize > SNAPSHOT_MAX_ROWS {
            return Err(SnapshotError::Malformed);
        }
        Ok(header)
    }
}

/// The ABI a process runs under.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Personality {
    Native = 1,
    Linux = 2,
}

impl Personality {
    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Native),
            2 => Some(Self::Linux),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Linux => "linux",
        }
    }
}

/// Where a process is in its life. A reaped process has no row.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessRunState {
    /// Created, not yet run.
    Starting = 1,
    Running = 2,
    /// A thread is exiting.
    Exiting = 3,
    Faulted = 4,
    /// Every thread ended; the record waits to be reaped.
    Exited = 5,
}

impl ProcessRunState {
    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Starting),
            2 => Some(Self::Running),
            3 => Some(Self::Exiting),
            4 => Some(Self::Faulted),
            5 => Some(Self::Exited),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Exiting => "exiting",
            Self::Faulted => "faulted",
            Self::Exited => "exited",
        }
    }
}

/// A process's name: printable ASCII, at most [`PROCESS_NAME_MAX`] bytes; empty when the
/// kernel knows none (a Linux process forked from a shell row).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProcessName {
    len: u8,
    bytes: [u8; PROCESS_NAME_MAX],
}

impl ProcessName {
    pub const EMPTY: Self = Self {
        len: 0,
        bytes: [0; PROCESS_NAME_MAX],
    };

    /// `name` cut to [`PROCESS_NAME_MAX`] bytes; any byte that is not printable ASCII becomes
    /// `?`.
    pub const fn new(name: &[u8]) -> Self {
        let mut out = Self::EMPTY;
        let mut index = 0;
        while index < name.len() && index < PROCESS_NAME_MAX {
            let byte = name[index];
            out.bytes[index] = if byte > b' ' && byte < 0x7f {
                byte
            } else {
                b'?'
            };
            index += 1;
        }
        out.len = index as u8;
        out
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    pub fn as_str(&self) -> &str {
        // `new` and `decode` admit printable ASCII only.
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::fmt::Debug for ProcessName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.as_str())
    }
}

/// One process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessRow {
    pub pid: u64,
    /// The process's instance generation: a pid seen again with another generation is another
    /// process.
    pub generation: u64,
    /// CPU time its threads ran, reaped threads included.
    pub cpu_ns: u64,
    /// User pages its own address space maps.
    pub private_pages: u64,
    /// Shared-buffer pages mapped into its window, once per mapping.
    pub shared_pages: u64,
    /// Kernel frames held for it: page tables and its threads' kernel stacks.
    pub kernel_pages: u64,
    /// Its manifest row's service id; 0 for init and for processes without a row.
    pub service_id: u32,
    pub personality: Personality,
    pub state: ProcessRunState,
    pub name: ProcessName,
}

impl ProcessRow {
    /// Every page held for the process: private, shared and kernel.
    pub const fn total_pages(&self) -> u64 {
        self.private_pages
            .saturating_add(self.shared_pages)
            .saturating_add(self.kernel_pages)
    }

    pub fn encode(&self) -> [u8; SNAPSHOT_ROW_BYTES] {
        let mut out = [0u8; SNAPSHOT_ROW_BYTES];
        put_u64(&mut out, 0, self.pid);
        put_u64(&mut out, 8, self.generation);
        put_u64(&mut out, 16, self.cpu_ns);
        put_u64(&mut out, 24, self.private_pages);
        put_u64(&mut out, 32, self.shared_pages);
        put_u64(&mut out, 40, self.kernel_pages);
        put_u32(&mut out, 48, self.service_id);
        out[52] = self.personality as u8;
        out[53] = self.state as u8;
        out[54] = self.name.len;
        out[56..56 + PROCESS_NAME_MAX].copy_from_slice(&self.name.bytes);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SnapshotError> {
        if bytes.len() < SNAPSHOT_ROW_BYTES {
            return Err(SnapshotError::Truncated);
        }
        let personality = Personality::from_u8(bytes[52]).ok_or(SnapshotError::Malformed)?;
        let state = ProcessRunState::from_u8(bytes[53]).ok_or(SnapshotError::Malformed)?;
        let len = usize::from(bytes[54]);
        if len > PROCESS_NAME_MAX || bytes[55] != 0 {
            return Err(SnapshotError::Malformed);
        }
        let raw_name = &bytes[56..56 + PROCESS_NAME_MAX];
        if raw_name[len..].iter().any(|byte| *byte != 0)
            || raw_name[..len]
                .iter()
                .any(|byte| *byte <= b' ' || *byte >= 0x7f)
        {
            return Err(SnapshotError::Malformed);
        }
        Ok(Self {
            pid: get_u64(bytes, 0),
            generation: get_u64(bytes, 8),
            cpu_ns: get_u64(bytes, 16),
            private_pages: get_u64(bytes, 24),
            shared_pages: get_u64(bytes, 32),
            kernel_pages: get_u64(bytes, 40),
            service_id: get_u32(bytes, 48),
            personality,
            state,
            name: ProcessName::new(&raw_name[..len]),
        })
    }
}

/// A snapshot's header and its rows, checked.
#[derive(Clone, Copy, Debug)]
pub struct Snapshot<'a> {
    pub header: SnapshotHeader,
    rows: &'a [u8],
}

impl<'a> Snapshot<'a> {
    /// Checks the header and every row of `bytes`, the bytes the call wrote.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, SnapshotError> {
        let header = SnapshotHeader::decode(bytes)?;
        let end = snapshot_len(header.rows as usize);
        if bytes.len() < end {
            return Err(SnapshotError::Truncated);
        }
        let rows = &bytes[SNAPSHOT_HEADER_BYTES..end];
        for chunk in rows.chunks_exact(SNAPSHOT_ROW_BYTES) {
            ProcessRow::decode(chunk)?;
        }
        Ok(Self { header, rows })
    }

    pub fn rows(&self) -> impl Iterator<Item = ProcessRow> + 'a {
        self.rows
            .chunks_exact(SNAPSHOT_ROW_BYTES)
            .filter_map(|chunk| ProcessRow::decode(chunk).ok())
    }

    /// The row of `pid` with `generation`.
    pub fn find(&self, pid: u64, generation: u64) -> Option<ProcessRow> {
        self.rows()
            .find(|row| row.pid == pid && row.generation == generation)
    }
}

/// A process's CPU share between two snapshots, in thousandths of the time between them:
/// `(after.cpu_ns - before.cpu_ns) / (after_ns - before_ns)`. `None` when the snapshots are not
/// in order or the rows are not the same process; the share is capped at 1000 (one CPU).
pub fn cpu_share_permille(
    before_ns: u64,
    before: &ProcessRow,
    after_ns: u64,
    after: &ProcessRow,
) -> Option<u32> {
    if before.pid != after.pid || before.generation != after.generation || after_ns <= before_ns {
        return None;
    }
    let ran = u128::from(after.cpu_ns.checked_sub(before.cpu_ns)?);
    let window = u128::from(after_ns - before_ns);
    let permille = (ran * 1000 / window).min(1000);
    Some(permille as u32)
}

/// A RESOURCES answer: bytes written, or the status.
pub const fn decode_written(raw: u64) -> Result<usize, u64> {
    if is_status(raw) {
        Err(raw)
    } else if (raw as usize) < SNAPSHOT_HEADER_BYTES || raw as usize > SNAPSHOT_MAX_BYTES {
        Err(STATUS_EINVAL)
    } else {
        Ok(raw as usize)
    }
}

fn put_u16(out: &mut [u8], at: usize, value: u16) {
    out[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn get_u32(bytes: &[u8], at: usize) -> u32 {
    let mut raw = [0u8; 4];
    raw.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(raw)
}

fn get_u64(bytes: &[u8], at: usize) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{STATUS_EACCES, STATUS_ENODATA};

    fn row(pid: u64, cpu_ns: u64, name: &str) -> ProcessRow {
        ProcessRow {
            pid,
            generation: pid + 100,
            cpu_ns,
            private_pages: 7,
            shared_pages: 3,
            kernel_pages: 9,
            service_id: 0x5100,
            personality: Personality::Native,
            state: ProcessRunState::Running,
            name: ProcessName::new(name.as_bytes()),
        }
    }

    fn header(rows: u32, total_rows: u32) -> SnapshotHeader {
        SnapshotHeader {
            flags: SNAPSHOT_FLAG_SYSTEM,
            rows,
            total_rows,
            snapshot_ns: 5_000,
            elapsed_ns: 4_000,
            busy_ns: 1_000,
            idle_ns: 2_900,
            unattributed_ns: 100,
        }
    }

    fn encode(header: &SnapshotHeader, rows: &[ProcessRow]) -> std::vec::Vec<u8> {
        let mut out = std::vec::Vec::from(header.encode());
        for row in rows {
            out.extend_from_slice(&row.encode());
        }
        out
    }

    #[test]
    fn the_layout_has_the_documented_sizes() {
        assert_eq!(snapshot_len(0), SNAPSHOT_HEADER_BYTES);
        assert_eq!(snapshot_len(SNAPSHOT_MAX_ROWS), SNAPSHOT_MAX_BYTES);
        assert_eq!(SNAPSHOT_MAX_BYTES, 1344);
        assert_eq!(56 + PROCESS_NAME_MAX, SNAPSHOT_ROW_BYTES);
    }

    #[test]
    fn a_snapshot_round_trips() {
        let rows = [row(1, 10, "init"), row(4, 20, "compositor"), row(9, 0, "")];
        let bytes = encode(&header(3, 3), &rows);
        let snapshot = Snapshot::decode(&bytes).unwrap();
        assert_eq!(snapshot.header, header(3, 3));
        assert!(snapshot.header.is_system());
        let decoded: std::vec::Vec<_> = snapshot.rows().collect();
        assert_eq!(decoded, rows);
        assert_eq!(decoded[1].name.as_str(), "compositor");
        assert!(decoded[2].name.is_empty());
        assert_eq!(snapshot.find(4, 104), Some(rows[1]));
        assert_eq!(snapshot.find(4, 5), None);
        assert_eq!(rows[0].total_pages(), 19);
    }

    #[test]
    fn rows_that_fit_are_bounded_by_the_buffer_and_the_registry() {
        assert_eq!(rows_that_fit(SNAPSHOT_HEADER_BYTES - 1), None);
        assert_eq!(rows_that_fit(SNAPSHOT_HEADER_BYTES), Some(0));
        assert_eq!(rows_that_fit(snapshot_len(2) - 1), Some(1));
        assert_eq!(rows_that_fit(snapshot_len(2)), Some(2));
        assert_eq!(rows_that_fit(1 << 20), Some(SNAPSHOT_MAX_ROWS));
    }

    #[test]
    fn truncated_and_malformed_bytes_are_refused() {
        let rows = [row(1, 10, "init"), row(2, 20, "storage")];
        let bytes = encode(&header(2, 2), &rows);
        assert_eq!(
            Snapshot::decode(&bytes[..SNAPSHOT_HEADER_BYTES - 1]).unwrap_err(),
            SnapshotError::Truncated
        );
        assert_eq!(
            Snapshot::decode(&bytes[..bytes.len() - 1]).unwrap_err(),
            SnapshotError::Truncated
        );
        // More rows written than there were.
        let bad = encode(&header(2, 1), &rows);
        assert_eq!(
            Snapshot::decode(&bad).unwrap_err(),
            SnapshotError::Malformed
        );
        let corrupt = |at: usize, value: u8| {
            let mut copy = bytes.clone();
            copy[at] = value;
            Snapshot::decode(&copy).map(|snapshot| snapshot.header)
        };
        // Version, header size, row size, unknown flag, reserved word.
        for (at, value) in [(0, 2), (2, 63), (4, 81), (6, 2), (56, 1)] {
            assert_eq!(corrupt(at, value), Err(SnapshotError::Malformed), "{at}");
        }
        let row_at = SNAPSHOT_HEADER_BYTES;
        // Personality, state, name length, reserved byte, a name byte past the length, a
        // space in the name.
        for (at, value) in [
            (52, 0),
            (53, 9),
            (54, 25),
            (55, 1),
            (56 + 10, b'x'),
            (56, b' '),
        ] {
            assert_eq!(
                corrupt(row_at + at, value),
                Err(SnapshotError::Malformed),
                "row {at}"
            );
        }
    }

    #[test]
    fn a_self_snapshot_has_no_system_totals() {
        let own = SnapshotHeader {
            flags: 0,
            rows: 1,
            total_rows: 1,
            snapshot_ns: 77,
            ..SnapshotHeader::default()
        };
        let bytes = encode(&own, &[row(5, 3, "terminal")]);
        let snapshot = Snapshot::decode(&bytes).unwrap();
        assert!(!snapshot.header.is_system());
        assert_eq!(snapshot.header.busy_ns, 0);
        assert_eq!(snapshot.rows().count(), 1);
    }

    #[test]
    fn names_are_cut_and_made_printable() {
        let long = ProcessName::new(b"a-name-that-is-longer-than-the-field");
        assert_eq!(long.as_str().len(), PROCESS_NAME_MAX);
        assert_eq!(ProcessName::new(b"tab\there").as_str(), "tab?here");
    }

    #[test]
    fn cpu_share_compares_the_same_process() {
        let before = row(4, 1_000_000, "compositor");
        let mut after = before;
        after.cpu_ns = 3_000_000;
        // 2 ms of CPU in 10 ms.
        assert_eq!(
            cpu_share_permille(0, &before, 10_000_000, &after),
            Some(200)
        );
        // Capped at one CPU.
        assert_eq!(
            cpu_share_permille(0, &before, 1_000_000, &after),
            Some(1000)
        );
        assert_eq!(cpu_share_permille(5, &before, 5, &after), None);
        let mut other = after;
        other.generation += 1;
        assert_eq!(cpu_share_permille(0, &before, 10, &other), None);
        // CPU time never goes back for one process.
        assert_eq!(cpu_share_permille(0, &after, 10, &before), None);
    }

    #[test]
    fn answers_decode() {
        assert_eq!(decode_written(snapshot_len(1) as u64), Ok(snapshot_len(1)));
        assert_eq!(decode_written(STATUS_EACCES), Err(STATUS_EACCES));
        assert_eq!(decode_written(STATUS_ENODATA), Err(STATUS_ENODATA));
        assert_eq!(decode_written(3), Err(STATUS_EINVAL));
        assert_eq!(
            decode_written(SNAPSHOT_MAX_BYTES as u64 + 1),
            Err(STATUS_EINVAL)
        );
    }
}
