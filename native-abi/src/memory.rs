//! Syscall 23 `MEMORY`: anonymous, private, zeroed pages in the caller's native memory window.
//!
//! ```text
//! | Register | Meaning                                                               |
//! | rdi      | sub-operation: MAP (0), UNMAP (1), PROTECT (2), QUERY (3)             |
//! | rsi      | MAP: address hint, 0 = kernel chooses; UNMAP, PROTECT: start address  |
//! | rdx      | MAP, UNMAP, PROTECT: length in bytes, rounded up to whole pages       |
//! | r10      | MAP: flags (`MEMORY_MAP_FIXED`); PROTECT: access; otherwise 0         |
//! | r8, r9   | reserved, must be 0 (QUERY: rsi, rdx and r10 too)                     |
//! ```
//!
//! | Sub-operation | Result |
//! |---------------|--------|
//! | MAP | the page-aligned start of the new pages |
//! | UNMAP | the number of pages freed (0 when none in the range were mapped) |
//! | PROTECT | 0 |
//! | QUERY | [`MemoryUsage::encode`]: pages in use in the low 32 bits, the budget above them |
//!
//! | Status | Meaning |
//! |--------|---------|
//! | `STATUS_EINVAL` | unknown sub-operation, a reserved register or flag set, a zero length, an unaligned start (UNMAP, PROTECT, and MAP with `MEMORY_MAP_FIXED`), a range outside [`NATIVE_MEMORY_WINDOW_BASE`]`..+`[`NATIVE_MEMORY_WINDOW_BYTES`], or (PROTECT) a page in the range that is not mapped |
//! | `STATUS_ENOSPC` | the map would take the caller past its page budget, the caller's region table is full, or no free run of that length is left in the window |
//! | `STATUS_EEXIST` | `MEMORY_MAP_FIXED` over a page that is already mapped (it is never replaced) |
//! | `STATUS_ENOMEM` | the kernel could not provide frames or page tables right now |
//!
//! Every page is user-accessible and never executable. MAP gives read-write pages; PROTECT can
//! make them read-only and back again. A refused call changes nothing.
//!
//! The budget is a page count the kernel sets for the instance when it starts its manifest row
//! (`ServiceSpec::memory_pages`); nothing the process does can raise it, and a process with no
//! budget has a budget of 0, so every MAP is refused. Pages count against the budget from MAP to
//! UNMAP, and against the address space's mapping table like every other user page. Pages still
//! mapped when the process ends are freed with its address space.

use crate::status::{
    is_status, STATUS_EEXIST, STATUS_EINVAL, STATUS_ENOMEM, STATUS_ENOSPC, STATUS_ENOSYS,
};

pub const SYSCALL_NR_MEMORY: u64 = 23;

pub const MEMORY_SUBOP_MAP: u64 = 0;
pub const MEMORY_SUBOP_UNMAP: u64 = 1;
pub const MEMORY_SUBOP_PROTECT: u64 = 2;
pub const MEMORY_SUBOP_QUERY: u64 = 3;

/// MAP flag: the hint is the exact start. Without it a hint whose run is free is used as given,
/// and any other hint is ignored in favour of a kernel-chosen start.
pub const MEMORY_MAP_FIXED: u64 = 1;
pub const MEMORY_MAP_FLAGS_MASK: u64 = MEMORY_MAP_FIXED;

/// PROTECT access values.
pub const MEMORY_ACCESS_READ: u64 = 1;
pub const MEMORY_ACCESS_READ_WRITE: u64 = 3;

pub const MEMORY_PAGE_BYTES: u64 = 4096;

/// Where every native process's MAP pages live: its own PML4 slot, apart from images (at
/// `0x4000_0000_0000`) and the shared-buffer window (at `0x5000_0000_0000`).
pub const NATIVE_MEMORY_WINDOW_BASE: u64 = 0x0000_6000_0000_0000;
pub const NATIVE_MEMORY_WINDOW_BYTES: u64 = 1 << 30;

/// The largest budget a manifest row may give: 64 MiB, the most user pages one address space
/// can track.
pub const NATIVE_MEMORY_MAX_BUDGET_PAGES: u64 = 16 * 1024;

/// Separate runs of mapped pages one process may hold. A partial UNMAP or PROTECT that splits
/// a run needs a free entry for the new piece.
pub const NATIVE_MEMORY_MAX_REGIONS: usize = 64;

const _: () = assert!(NATIVE_MEMORY_WINDOW_BASE % (1 << 39) == 0);
const _: () = assert!(NATIVE_MEMORY_WINDOW_BASE + NATIVE_MEMORY_WINDOW_BYTES <= 1 << 47);
const _: () = assert!(
    NATIVE_MEMORY_WINDOW_BASE
        >= crate::shared_buffer::SHARED_WINDOW_BASE + crate::shared_buffer::SHARED_WINDOW_BYTES
);
const _: () =
    assert!(NATIVE_MEMORY_MAX_BUDGET_PAGES * MEMORY_PAGE_BYTES <= NATIVE_MEMORY_WINDOW_BYTES);

/// Pages for `byte_len`, rounded up; `None` for 0 or a length past the window.
pub const fn pages_for_bytes(byte_len: u64) -> Option<u64> {
    if byte_len == 0 || byte_len > NATIVE_MEMORY_WINDOW_BYTES {
        return None;
    }
    Some(byte_len.div_ceil(MEMORY_PAGE_BYTES))
}

/// QUERY's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryUsage {
    pub used_pages: u32,
    pub budget_pages: u32,
}

impl MemoryUsage {
    pub const fn encode(self) -> u64 {
        ((self.budget_pages as u64) << 32) | self.used_pages as u64
    }

    /// `None` for a status.
    pub const fn decode(raw: u64) -> Option<Self> {
        if is_status(raw) {
            return None;
        }
        Some(Self {
            used_pages: raw as u32,
            budget_pages: (raw >> 32) as u32,
        })
    }

    pub const fn available_pages(self) -> u32 {
        self.budget_pages.saturating_sub(self.used_pages)
    }
}

// The largest budget must encode below the status range.
const _: () = assert!(!is_status(
    MemoryUsage {
        used_pages: NATIVE_MEMORY_MAX_BUDGET_PAGES as u32,
        budget_pages: NATIVE_MEMORY_MAX_BUDGET_PAGES as u32,
    }
    .encode()
));

/// Why a MEMORY call was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryError {
    Invalid,
    /// Budget, region table or window exhausted.
    NoSpace,
    /// `MEMORY_MAP_FIXED` over a mapped page.
    Exists,
    /// The kernel is out of frames or page tables.
    OutOfMemory,
    /// A kernel without syscall 23.
    Unsupported,
    Other(u64),
}

impl MemoryError {
    pub const fn status(self) -> u64 {
        match self {
            Self::Invalid => STATUS_EINVAL,
            Self::NoSpace => STATUS_ENOSPC,
            Self::Exists => STATUS_EEXIST,
            Self::OutOfMemory => STATUS_ENOMEM,
            Self::Unsupported => STATUS_ENOSYS,
            Self::Other(raw) => raw,
        }
    }

    pub const fn from_status(raw: u64) -> Self {
        match raw {
            STATUS_EINVAL => Self::Invalid,
            STATUS_ENOSPC => Self::NoSpace,
            STATUS_EEXIST => Self::Exists,
            STATUS_ENOMEM => Self::OutOfMemory,
            STATUS_ENOSYS => Self::Unsupported,
            other => Self::Other(other),
        }
    }
}

/// Decodes a MAP, UNMAP or PROTECT result.
pub const fn decode_result(raw: u64) -> Result<u64, MemoryError> {
    if is_status(raw) {
        Err(MemoryError::from_status(raw))
    } else {
        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::SYSCALL_NR_LIFECYCLE_WAIT;
    use crate::service_ready::SYSCALL_NR_SERVICE_READY;
    use clean_slate_capability::syscall_abi::{
        SYSCALL_NR_CAP_AUDIT_READ, SYSCALL_NR_CAP_DELEGATE, SYSCALL_NR_CAP_GRANT,
        SYSCALL_NR_CAP_OBJECT, SYSCALL_NR_CAP_PROCESS_CONTROL, SYSCALL_NR_CAP_REVOKE,
        SYSCALL_NR_DISPLAY, SYSCALL_NR_INPUT, SYSCALL_NR_NETWORK_CAPABILITY,
        SYSCALL_NR_NETWORK_REQUEST, SYSCALL_NR_SERVICE_PORT, SYSCALL_NR_SHARED_BUFFER,
        SYSCALL_NR_WORK_SET,
    };

    #[test]
    fn number_follows_service_ready_and_collides_with_nothing() {
        let taken = [
            SYSCALL_NR_CAP_OBJECT,
            SYSCALL_NR_CAP_PROCESS_CONTROL,
            SYSCALL_NR_CAP_DELEGATE,
            SYSCALL_NR_CAP_REVOKE,
            SYSCALL_NR_CAP_AUDIT_READ,
            SYSCALL_NR_CAP_GRANT,
            SYSCALL_NR_NETWORK_CAPABILITY,
            SYSCALL_NR_NETWORK_REQUEST,
            SYSCALL_NR_SHARED_BUFFER,
            SYSCALL_NR_SERVICE_PORT,
            SYSCALL_NR_DISPLAY,
            SYSCALL_NR_INPUT,
            SYSCALL_NR_WORK_SET,
            SYSCALL_NR_LIFECYCLE_WAIT,
            SYSCALL_NR_SERVICE_READY,
        ];
        assert!(!taken.contains(&SYSCALL_NR_MEMORY));
        assert_eq!(SYSCALL_NR_MEMORY, SYSCALL_NR_SERVICE_READY + 1);
    }

    #[test]
    fn page_rounding() {
        assert_eq!(pages_for_bytes(0), None);
        assert_eq!(pages_for_bytes(1), Some(1));
        assert_eq!(pages_for_bytes(4096), Some(1));
        assert_eq!(pages_for_bytes(4097), Some(2));
        assert_eq!(
            pages_for_bytes(NATIVE_MEMORY_WINDOW_BYTES),
            Some(NATIVE_MEMORY_WINDOW_BYTES / 4096)
        );
        assert_eq!(pages_for_bytes(NATIVE_MEMORY_WINDOW_BYTES + 1), None);
        assert_eq!(pages_for_bytes(u64::MAX), None);
    }

    #[test]
    fn usage_round_trips_and_never_reads_as_a_status() {
        let usage = MemoryUsage {
            used_pages: 7,
            budget_pages: 64,
        };
        assert_eq!(MemoryUsage::decode(usage.encode()), Some(usage));
        assert_eq!(usage.available_pages(), 57);
        assert_eq!(MemoryUsage::decode(STATUS_EINVAL), None);
    }

    #[test]
    fn errors_round_trip() {
        for error in [
            MemoryError::Invalid,
            MemoryError::NoSpace,
            MemoryError::Exists,
            MemoryError::OutOfMemory,
            MemoryError::Unsupported,
        ] {
            assert!(is_status(error.status()));
            assert_eq!(MemoryError::from_status(error.status()), error);
            assert_eq!(decode_result(error.status()), Err(error));
        }
        assert_eq!(
            decode_result(NATIVE_MEMORY_WINDOW_BASE),
            Ok(NATIVE_MEMORY_WINDOW_BASE)
        );
    }
}
