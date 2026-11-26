//! #312 storage probe: the bootstrap page the `m10-storage-self-test` kernel writes for the
//! native storage probe (`clean-slate-storage-probe-userspace`), and the lane checks it
//! reports through.
//!
//! The probe holds one capability: `READ | WRITE | DIRECTORY` on the directory whose table is
//! [`STORAGE_PROBE_DIRECTORY_ID`]. Each boot it opens [`STORAGE_PROBE_FILE_NAME`] in that
//! directory and moves it one stage along ([`ProbeStage`]), so three boots on one data disk
//! write a 1 MiB object, read it back and truncate it, then read the truncated object back
//! and unlink it.
//!
//! Layout, little-endian, no padding (`repr(C)` of three `u64`s):
//!
//! | Offset | Field | Meaning |
//! | --- | --- | --- |
//! | 0 | `self_pid` | the probe's pid |
//! | 8 | `directory_handle` | the directory capability |
//! | 16 | `directory_id` | the directory's table object id |

/// Where the kernel maps the probe's bootstrap page (the slot every bootstrap-page image uses).
pub const STORAGE_PROBE_BOOTSTRAP_ADDRESS: u64 = 0x0000_4000_0010_0000;

/// The probe's directory: its table object, followed by its 15 entry objects. Clear of the
/// `/home` directory (`0x4D_0000`) and the M6 lanes' object ids.
pub const STORAGE_PROBE_DIRECTORY_ID: u64 = 0x004E_0000;

/// The entry the probe writes.
pub const STORAGE_PROBE_FILE_NAME: &[u8] = b"big.bin";

/// The size the probe writes: a whole directory entry.
pub const STORAGE_PROBE_FILE_BYTES: u64 = 1024 * 1024;

/// The size the probe truncates the entry to.
pub const STORAGE_PROBE_TRUNCATED_BYTES: u64 = 4096;

/// `SYSCALL_NR_CAP_GRANT` harness sub-operation of the M6 fixtures, which the lane serves for
/// the probe as well (`rsi` = check, `rdx` = argument).
pub const STORAGE_PROBE_SUBOP_LANE_CHECK: u64 = 0x104;

/// Lane check: a stage finished; the argument is its [`ProbeStage`] code. The kernel ends
/// the boot there, with a pass.
pub const STORAGE_PROBE_CHECK_STAGE_DONE: u64 = 1;
/// Lane check: a step failed; the argument is [`ProbeFailure::encode`]. The kernel ends the
/// boot there, with a failure.
pub const STORAGE_PROBE_CHECK_FAILED: u64 = 2;
/// Lane check: a progress note, logged; the argument is the [`ProbeStep`] code.
pub const STORAGE_PROBE_CHECK_STEP: u64 = 3;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageProbeBootstrap {
    pub self_pid: u64,
    pub directory_handle: u64,
    pub directory_id: u64,
}

const _: () = assert!(core::mem::size_of::<StorageProbeBootstrap>() == 24);
const _: () = assert!(core::mem::offset_of!(StorageProbeBootstrap, directory_id) == 16);

/// What one boot of the probe did, from the state it found the entry in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum ProbeStage {
    /// No entry: created it, wrote 1 MiB through a shared buffer, committed.
    Wrote = 1,
    /// A 1 MiB entry: read it back through a shared buffer, checked every byte, truncated it
    /// to 4 KiB and committed.
    Truncated = 2,
    /// A 4 KiB entry: read it back, checked it, unlinked it and committed.
    Removed = 3,
}

impl ProbeStage {
    pub const fn code(self) -> u64 {
        self as u64
    }

    pub const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::Wrote),
            2 => Some(Self::Truncated),
            3 => Some(Self::Removed),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Wrote => "wrote",
            Self::Truncated => "truncated",
            Self::Removed => "removed",
        }
    }
}

/// A step of the probe, for progress notes and failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum ProbeStep {
    OpenEntry = 1,
    CreateEntry = 2,
    AllocateBuffer = 3,
    WriteBuffer = 4,
    CommitEntry = 5,
    RecordLength = 6,
    ReadBuffer = 7,
    CheckBytes = 8,
    Truncate = 9,
    ReadTruncated = 10,
    Unlink = 11,
    ReopenEntry = 12,
    UnexpectedLength = 13,
}

impl ProbeStep {
    pub const fn code(self) -> u64 {
        self as u64
    }

    pub const fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            1 => Self::OpenEntry,
            2 => Self::CreateEntry,
            3 => Self::AllocateBuffer,
            4 => Self::WriteBuffer,
            5 => Self::CommitEntry,
            6 => Self::RecordLength,
            7 => Self::ReadBuffer,
            8 => Self::CheckBytes,
            9 => Self::Truncate,
            10 => Self::ReadTruncated,
            11 => Self::Unlink,
            12 => Self::ReopenEntry,
            13 => Self::UnexpectedLength,
            _ => return None,
        })
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::OpenEntry => "open",
            Self::CreateEntry => "create",
            Self::AllocateBuffer => "allocate buffer",
            Self::WriteBuffer => "write through buffer",
            Self::CommitEntry => "commit",
            Self::RecordLength => "record length",
            Self::ReadBuffer => "read through buffer",
            Self::CheckBytes => "check bytes",
            Self::Truncate => "truncate",
            Self::ReadTruncated => "read truncated",
            Self::Unlink => "unlink",
            Self::ReopenEntry => "reopen",
            Self::UnexpectedLength => "entry length",
        }
    }
}

/// A failed step and the value that failed it: a native status, or for a check the first
/// offset or length that was wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeFailure {
    pub step: ProbeStep,
    pub detail: u64,
}

impl ProbeFailure {
    /// The step in the top byte, the detail in the low 56 bits (a native status keeps its
    /// distance from `u64::MAX`, which is all a status needs).
    pub const fn encode(self) -> u64 {
        (self.step.code() << 56) | (self.detail & DETAIL_MASK)
    }

    pub const fn decode(raw: u64) -> Option<Self> {
        match ProbeStep::from_code(raw >> 56) {
            Some(step) => Some(Self {
                step,
                detail: raw & DETAIL_MASK,
            }),
            None => None,
        }
    }

    /// The detail as a native status, when it is one: `n` for the status `u64::MAX - n`.
    pub const fn status_below_max(self) -> Option<u64> {
        let distance = DETAIL_MASK - self.detail;
        if distance < 4096 {
            Some(distance)
        } else {
            None
        }
    }
}

const DETAIL_MASK: u64 = (1 << 56) - 1;

/// The byte at `offset` of the probe's file: varies within and across pages, so a page
/// written to the wrong place or a zeroed range reads back wrong.
pub const fn probe_byte(offset: u64) -> u8 {
    ((offset >> 12) as u8).wrapping_mul(31) ^ (offset as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_native_abi::status::{STATUS_ENOENT, STATUS_ENOSPC};

    #[test]
    fn a_failure_round_trips_with_its_status() {
        let failure = ProbeFailure {
            step: ProbeStep::WriteBuffer,
            detail: STATUS_ENOSPC,
        };
        let decoded = ProbeFailure::decode(failure.encode()).unwrap();
        assert_eq!(decoded.step, ProbeStep::WriteBuffer);
        assert_eq!(decoded.status_below_max(), Some(u64::MAX - STATUS_ENOSPC));
        let missing = ProbeFailure {
            step: ProbeStep::OpenEntry,
            detail: STATUS_ENOENT,
        };
        assert_eq!(
            ProbeFailure::decode(missing.encode())
                .unwrap()
                .status_below_max(),
            Some(u64::MAX - STATUS_ENOENT)
        );
        let offset = ProbeFailure {
            step: ProbeStep::CheckBytes,
            detail: 0x1234,
        };
        assert_eq!(ProbeFailure::decode(offset.encode()), Some(offset));
        assert_eq!(offset.status_below_max(), None);
        assert_eq!(ProbeFailure::decode(0), None);
    }

    #[test]
    fn codes_round_trip() {
        for stage in [
            ProbeStage::Wrote,
            ProbeStage::Truncated,
            ProbeStage::Removed,
        ] {
            assert_eq!(ProbeStage::from_code(stage.code()), Some(stage));
        }
        for code in 1..=13 {
            assert_eq!(ProbeStep::from_code(code).unwrap().code(), code);
        }
        assert_eq!(ProbeStep::from_code(14), None);
    }

    #[test]
    fn the_pattern_differs_between_pages() {
        assert_ne!(probe_byte(0), probe_byte(4096));
        assert_ne!(probe_byte(1), probe_byte(4097));
    }

    #[test]
    fn the_directory_is_clear_of_home() {
        let home = 0x4D_0000u64;
        assert!(STORAGE_PROBE_DIRECTORY_ID > home + 16);
    }
}
