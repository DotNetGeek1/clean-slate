//! PT_LOAD segment metadata and permission helpers.

use crate::error::LoadPlanError;
use crate::header::{PF_R, PF_W, PF_X};

/// Segment R/W/X derived from `p_flags`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SegmentPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl SegmentPermissions {
    /// Derive permissions from ELF `p_flags` (`PF_R`/`PF_W`/`PF_X`).
    pub const fn from_p_flags(flags: u32) -> Self {
        Self {
            read: (flags & PF_R) != 0,
            write: (flags & PF_W) != 0,
            execute: (flags & PF_X) != 0,
        }
    }

    /// True when the segment requests both write and execute.
    pub const fn is_write_execute(&self) -> bool {
        self.write && self.execute
    }
}

/// One validated PT_LOAD segment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoadSegment {
    pub vaddr: u64,
    pub memsz: u64,
    pub file_offset: u64,
    pub filesz: u64,
    pub align: u64,
    pub perms: SegmentPermissions,
}

impl LoadSegment {
    /// File-backed byte range `[file_offset, file_offset + filesz)`.
    pub fn file_range(&self) -> Result<(u64, u64), LoadPlanError> {
        let end = self
            .file_offset
            .checked_add(self.filesz)
            .ok_or(LoadPlanError::FileRangeOverflow)?;
        Ok((self.file_offset, end))
    }

    /// Zero-fill virtual range covering `p_memsz - p_filesz` after the file bytes.
    ///
    /// Returns `None` when there is no BSS tail. When present, the range is
    /// `[vaddr + filesz, vaddr + memsz)`.
    pub fn zero_fill_range(&self) -> Result<Option<(u64, u64)>, LoadPlanError> {
        if self.filesz > self.memsz {
            return Err(LoadPlanError::FileszGreaterThanMemsz);
        }
        if self.filesz == self.memsz {
            return Ok(None);
        }
        let start = self
            .vaddr
            .checked_add(self.filesz)
            .ok_or(LoadPlanError::VaddrRangeOverflow)?;
        let end = self
            .vaddr
            .checked_add(self.memsz)
            .ok_or(LoadPlanError::VaddrRangeOverflow)?;
        Ok(Some((start, end)))
    }

    /// Inclusive page span covering `[vaddr, vaddr + memsz)` for `page_size`.
    ///
    /// Returns `(first_page, page_count)`. `page_count` is 0 when `memsz == 0`.
    pub fn page_span(&self, page_size: u64) -> Result<(u64, u64), LoadPlanError> {
        if page_size == 0 || !page_size.is_power_of_two() {
            return Err(LoadPlanError::AlignmentViolation);
        }
        if self.memsz == 0 {
            return Ok((align_down(self.vaddr, page_size), 0));
        }
        let end = self
            .vaddr
            .checked_add(self.memsz)
            .ok_or(LoadPlanError::VaddrRangeOverflow)?;
        let first = align_down(self.vaddr, page_size);
        let last_exclusive = align_up(end, page_size)?;
        let bytes = last_exclusive
            .checked_sub(first)
            .ok_or(LoadPlanError::ArithmeticOverflow)?;
        let count = bytes / page_size;
        Ok((first, count))
    }

    /// Number of pages required to map this segment.
    pub fn mapped_page_count(&self, page_size: u64) -> Result<u64, LoadPlanError> {
        Ok(self.page_span(page_size)?.1)
    }

    /// Virtual address of the last file-backed byte, if `filesz > 0`.
    pub fn file_backed_end(&self) -> Result<Option<u64>, LoadPlanError> {
        if self.filesz == 0 {
            return Ok(None);
        }
        let end = self
            .vaddr
            .checked_add(self.filesz)
            .ok_or(LoadPlanError::VaddrRangeOverflow)?;
        Ok(Some(end))
    }
}

pub(crate) const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

pub(crate) fn align_up(value: u64, align: u64) -> Result<u64, LoadPlanError> {
    if align == 0 || !align.is_power_of_two() {
        return Err(LoadPlanError::AlignmentViolation);
    }
    if value & (align - 1) == 0 {
        return Ok(value);
    }
    let add = align - (value & (align - 1));
    value
        .checked_add(add)
        .ok_or(LoadPlanError::ArithmeticOverflow)
}
