//! Validated load plan construction from ELF64 bytes.

use crate::error::LoadPlanError;
use crate::header::{read_u32, read_u64, Elf64Header, PT_DYNAMIC, PT_INTERP, PT_LOAD};
use crate::policy::{LoadPlanPolicy, MAX_LOAD_SEGMENTS};
use crate::segment::{LoadSegment, SegmentPermissions};

/// Validated PT_LOAD load plan suitable for build-time embedding and runtime mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadPlan {
    pub entry: u64,
    /// Virtual address of the program-header table when it falls inside a PT_LOAD.
    pub phdr_vaddr: Option<u64>,
    pub phoff: u64,
    pub phentsize: u16,
    pub phnum: u16,
    pub segments: [LoadSegment; MAX_LOAD_SEGMENTS],
    pub segment_count: usize,
    pub has_interp: bool,
    /// True when a `PT_DYNAMIC` program header is present (dynamic-linking metadata).
    /// Recorded so policy layers (e.g. the M8 Linux loader) can reject it; the
    /// generic plan itself does not interpret the dynamic section.
    pub has_dynamic: bool,
    pub e_type: u16,
}

impl LoadPlan {
    /// Iterate over validated load segments.
    pub fn iter_segments(&self) -> impl Iterator<Item = &LoadSegment> {
        self.segments[..self.segment_count].iter()
    }

    /// Exact total mapped-page demand across all PT_LOAD segments (unique pages).
    pub fn total_mapped_pages(&self, page_size: u64) -> Result<u64, LoadPlanError> {
        if page_size == 0 || !page_size.is_power_of_two() {
            return Err(LoadPlanError::AlignmentViolation);
        }
        // Merge page spans so adjacent/shared PT_LOAD pages are counted once.
        let mut spans = [(0u64, 0u64); MAX_LOAD_SEGMENTS];
        let mut span_count = 0usize;
        for segment in self.iter_segments() {
            let (first, count) = segment.page_span(page_size)?;
            if count == 0 {
                continue;
            }
            let end = first
                .checked_add(
                    count
                        .checked_mul(page_size)
                        .ok_or(LoadPlanError::ArithmeticOverflow)?,
                )
                .ok_or(LoadPlanError::ArithmeticOverflow)?;
            spans[span_count] = (first, end);
            span_count += 1;
        }
        for i in 1..span_count {
            let mut j = i;
            while j > 0 && spans[j - 1].0 > spans[j].0 {
                spans.swap(j - 1, j);
                j -= 1;
            }
        }
        let mut total = 0u64;
        let mut index = 0usize;
        while index < span_count {
            let mut end = spans[index].1;
            let start = spans[index].0;
            index += 1;
            while index < span_count && spans[index].0 < end {
                end = end.max(spans[index].1);
                index += 1;
            }
            let bytes = end
                .checked_sub(start)
                .ok_or(LoadPlanError::ArithmeticOverflow)?;
            total = total
                .checked_add(bytes / page_size)
                .ok_or(LoadPlanError::ArithmeticOverflow)?;
        }
        Ok(total)
    }

    /// Lowest PT_LOAD virtual address (image link base), if any segments exist.
    pub fn image_base(&self) -> Option<u64> {
        self.iter_segments().map(|s| s.vaddr).min()
    }
}

/// Parse `bytes` into a validated [`LoadPlan`] under `policy`.
pub fn parse_load_plan(bytes: &[u8], policy: &LoadPlanPolicy) -> Result<LoadPlan, LoadPlanError> {
    if policy.page_size == 0 || !policy.page_size.is_power_of_two() {
        return Err(LoadPlanError::AlignmentViolation);
    }
    if policy.user_va_hi <= policy.user_va_lo {
        return Err(LoadPlanError::OutOfWindowVaddr);
    }

    let header = Elf64Header::parse(bytes)?;
    if !policy.allows_e_type(header.e_type) {
        return Err(LoadPlanError::UnsupportedEType);
    }

    let phentsize = u64::from(header.e_phentsize);
    let phnum = u64::from(header.e_phnum);
    let phdr_table_end = header
        .e_phoff
        .checked_add(
            phnum
                .checked_mul(phentsize)
                .ok_or(LoadPlanError::ArithmeticOverflow)?,
        )
        .ok_or(LoadPlanError::ArithmeticOverflow)?;
    if phdr_table_end > bytes.len() as u64 {
        return Err(LoadPlanError::TruncatedProgramHeaders);
    }
    // Program-header table must be 8-byte aligned for Elf64_Phdr fields.
    if header.e_phoff % 8 != 0 {
        return Err(LoadPlanError::TruncatedProgramHeaders);
    }

    let mut segments = [LoadSegment::default(); MAX_LOAD_SEGMENTS];
    let mut segment_count = 0usize;
    let mut has_interp = false;
    let mut has_dynamic = false;

    for index in 0..header.e_phnum {
        let start = header
            .e_phoff
            .checked_add(
                u64::from(index)
                    .checked_mul(phentsize)
                    .ok_or(LoadPlanError::ArithmeticOverflow)?,
            )
            .ok_or(LoadPlanError::ArithmeticOverflow)? as usize;
        let end = start
            .checked_add(usize::from(header.e_phentsize))
            .ok_or(LoadPlanError::ArithmeticOverflow)?;
        if end > bytes.len() {
            return Err(LoadPlanError::TruncatedProgramHeaders);
        }
        let phdr = &bytes[start..end];
        let p_type = read_u32(phdr, 0).map_err(|_| LoadPlanError::TruncatedProgramHeaders)?;
        if p_type == PT_INTERP {
            has_interp = true;
            continue;
        }
        if p_type == PT_DYNAMIC {
            has_dynamic = true;
            continue;
        }
        if p_type != PT_LOAD {
            continue;
        }

        let p_flags = read_u32(phdr, 4).map_err(|_| LoadPlanError::TruncatedProgramHeaders)?;
        let p_offset = read_u64(phdr, 0x08).map_err(|_| LoadPlanError::TruncatedProgramHeaders)?;
        let p_vaddr = read_u64(phdr, 0x10).map_err(|_| LoadPlanError::TruncatedProgramHeaders)?;
        let p_filesz = read_u64(phdr, 0x20).map_err(|_| LoadPlanError::TruncatedProgramHeaders)?;
        let p_memsz = read_u64(phdr, 0x28).map_err(|_| LoadPlanError::TruncatedProgramHeaders)?;
        let p_align = read_u64(phdr, 0x30).map_err(|_| LoadPlanError::TruncatedProgramHeaders)?;

        let segment = LoadSegment {
            vaddr: p_vaddr,
            memsz: p_memsz,
            file_offset: p_offset,
            filesz: p_filesz,
            align: p_align,
            perms: SegmentPermissions::from_p_flags(p_flags),
        };
        validate_segment(&segment, bytes.len() as u64, policy)?;

        if segment_count >= policy.max_segments || segment_count >= MAX_LOAD_SEGMENTS {
            return Err(LoadPlanError::SegmentBudgetExceeded);
        }
        segments[segment_count] = segment;
        segment_count += 1;
    }

    if segment_count == 0 {
        return Err(LoadPlanError::NoLoadSegments);
    }

    detect_overlaps(&segments[..segment_count], policy.page_size)?;

    let plan = LoadPlan {
        entry: header.e_entry,
        phdr_vaddr: resolve_phdr_vaddr(header.e_phoff, &segments[..segment_count]),
        phoff: header.e_phoff,
        phentsize: header.e_phentsize,
        phnum: header.e_phnum,
        segments,
        segment_count,
        has_interp,
        has_dynamic,
        e_type: header.e_type,
    };
    validate_entry_in_executable(&plan)?;
    Ok(plan)
}

fn validate_segment(
    segment: &LoadSegment,
    file_len: u64,
    policy: &LoadPlanPolicy,
) -> Result<(), LoadPlanError> {
    if segment.filesz > segment.memsz {
        return Err(LoadPlanError::FileszGreaterThanMemsz);
    }
    let (_file_start, file_end) = segment.file_range()?;
    if file_end > file_len {
        return Err(LoadPlanError::FileRangeBeyondEof);
    }
    let vaddr_end = segment
        .vaddr
        .checked_add(segment.memsz)
        .ok_or(LoadPlanError::VaddrRangeOverflow)?;

    if !is_canonical_user(segment.vaddr) || (segment.memsz > 0 && !is_canonical_user(vaddr_end - 1))
    {
        return Err(LoadPlanError::NonCanonicalVaddr);
    }
    if segment.vaddr < policy.user_va_lo || vaddr_end > policy.user_va_hi {
        return Err(LoadPlanError::OutOfWindowVaddr);
    }
    if policy.reject_page_zero {
        let (first_page, page_count) = segment.page_span(policy.page_size)?;
        if page_count > 0 && first_page == 0 {
            return Err(LoadPlanError::PageZero);
        }
    }
    if segment.align > 1 {
        if !segment.align.is_power_of_two() {
            return Err(LoadPlanError::AlignmentViolation);
        }
        // ELF requires p_offset ≡ p_vaddr (mod p_align) when p_align > 1.
        // p_vaddr itself need not be a multiple of p_align (partial-page starts).
        if segment.file_offset % segment.align != segment.vaddr % segment.align {
            return Err(LoadPlanError::OffsetVaddrCongruenceViolation);
        }
    }
    if policy.reject_write_execute && segment.perms.is_write_execute() {
        return Err(LoadPlanError::WriteExecuteConflict);
    }
    Ok(())
}

fn detect_overlaps(segments: &[LoadSegment], _page_size: u64) -> Result<(), LoadPlanError> {
    for i in 0..segments.len() {
        let left = &segments[i];
        if left.memsz == 0 {
            continue;
        }
        let left_end = left
            .vaddr
            .checked_add(left.memsz)
            .ok_or(LoadPlanError::VaddrRangeOverflow)?;
        for right in segments.iter().skip(i + 1) {
            if right.memsz == 0 {
                continue;
            }
            let right_end = right
                .vaddr
                .checked_add(right.memsz)
                .ok_or(LoadPlanError::VaddrRangeOverflow)?;
            // Byte-range overlap is invalid. Page sharing without byte overlap is
            // normal for packed ELF images and is merged by the runtime mapper.
            if left.vaddr < right_end && right.vaddr < left_end {
                return Err(LoadPlanError::SegmentOverlap);
            }
        }
    }
    Ok(())
}

fn resolve_phdr_vaddr(phoff: u64, segments: &[LoadSegment]) -> Option<u64> {
    for segment in segments {
        let file_end = segment.file_offset.checked_add(segment.filesz)?;
        if phoff >= segment.file_offset && phoff < file_end {
            let delta = phoff - segment.file_offset;
            return segment.vaddr.checked_add(delta);
        }
    }
    None
}

fn validate_entry_in_executable(plan: &LoadPlan) -> Result<(), LoadPlanError> {
    for segment in plan.iter_segments() {
        if !segment.perms.execute || segment.memsz == 0 {
            continue;
        }
        let end = segment
            .vaddr
            .checked_add(segment.memsz)
            .ok_or(LoadPlanError::VaddrRangeOverflow)?;
        if plan.entry >= segment.vaddr && plan.entry < end {
            return Ok(());
        }
    }
    Err(LoadPlanError::EntryOutsideExecutableSegment)
}

fn is_canonical_user(addr: u64) -> bool {
    // x86-64 canonical user addresses: bits 48..64 must be zero.
    addr < (1u64 << 47)
}
