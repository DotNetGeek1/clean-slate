//! M8.2 (#92): validated Linux ELF64 loader and process image construction.
//!
//! Turns the frozen M8 fixture bytes (`fixtures/linux-hello/hello-linux-x86_64`)
//! into a fully constructed, isolated Clean-Slate process at **runtime**:
//! address space, PT_LOAD pages with segment-derived R/W/X, zero-filled BSS, an
//! NX Linux user stack with an unmapped guard page, and the initial Linux stack
//! (`argc`/`argv`/`envp`/`auxv`) from `clean_slate_linux_abi::build_initial_stack`.
//!
//! Location rationale: this lives under `process` (not `service`) because the
//! result is a [`Process`] whose trusted [`ExecutionPersonality`] is fixed at
//! construction, and the rollback path needs registry/domain helpers that are
//! private to the `process` module. `service::spawn` stays native-only.
//!
//! Layering:
//! - [`validate_linux_image`] is pure and host-testable: `clean-slate-elf`
//!   structural checks under [`LINUX_M8_LOAD_POLICY`] plus the #92 checks the
//!   generic crate does not make (interp/dynamic rejection, page-size alignment,
//!   stack-reservation overlap, mapping and page-table budgets, initial stack).
//! - [`build_linux_process_image`] is kernel-side and transactional: any failure
//!   after the address space exists destroys it, freeing every frame and
//!   page-table page.
//! - [`launch_linux_process`] registers the [`Process`] with
//!   `ExecutionPersonality::LinuxX86_64` and configures the scheduler thread in
//!   the same order `service::spawn` does. #97 calls it from the supervisor path.
//!
//! The loader logic is production code in every build. Cargo features gate only
//! the embedded fixture bytes (`m8-linux-image`) and the QEMU self-test
//! (`m8-linux-image-self-test`). Consumed by `#97` (`service::linux_launch`)
//! and the `m8-linux-image` self-test.

#![cfg_attr(
    not(feature = "m8-linux-image"),
    // Default builds have no `service::linux_launch` consumer (`m8-linux-image`
    // gates that module); keep the loader compiling without dead_code noise.
    allow(dead_code)
)]

use crate::mm::address_space::{
    create_process_address_space, destroy_process_address_space, translate_address_in_root,
    ProcessAddressSpace, KERNEL_CARVE_OUT_PRIVATE_TABLE_FRAMES,
    MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES, MAX_ADDRESS_SPACE_USER_MAPPINGS,
};
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::image_loader::{map_load_plan_segments, map_user_stack_pages};
use crate::mm::{align_down, phys_to_virt, PAGE_SIZE, USER_CANONICAL_TOP_EXCLUSIVE};
use clean_slate_elf::{
    parse_load_plan, Elf64Header, LoadPlan, LoadPlanError, LoadPlanPolicy, ELF64_PHDR_SIZE,
    ET_EXEC, MAX_LOAD_SEGMENTS, PT_DYNAMIC, PT_INTERP, PT_LOAD,
};
use clean_slate_linux_abi::{
    build_initial_stack, StackLayoutError, AT_ENTRY, AT_PAGESZ, AT_PHDR, AT_PHENT, AT_PHNUM,
};
use core::ptr;
use x86_64::VirtAddr;

/// Frozen M8 fixture bytes, embedded only when the `m8-linux-image` feature is
/// enabled (or for host tests). Provenance is checked by `cargo xtask
/// verify-m8-fixture`; the host test below pins length and `e_entry` so a drift
/// in the bytes fails a test. No other copy of the fixture exists in the kernel.
///
/// Bare `--features m8-linux-image` (no hello / image self-test) embeds the
/// bytes for the feature graph but has no in-crate consumer — allow dead_code
/// there; hello and the image self-test consume it.
#[cfg(any(feature = "m8-linux-image", test))]
#[cfg_attr(
    not(any(feature = "m8-linux-hello", feature = "m8-linux-image-self-test")),
    allow(dead_code)
)]
pub(crate) const LINUX_M8_FIXTURE: &[u8] =
    include_bytes!("../../../fixtures/linux-hello/hello-linux-x86_64");

/// Start of the single private PML4 slot (128) every process owns.
pub(crate) const LINUX_USER_WINDOW_BASE: u64 = 0x0000_4000_0000_0000;
/// Exclusive end of that slot: `LINUX_USER_WINDOW_BASE + 512 GiB`.
pub(crate) const LINUX_USER_WINDOW_END: u64 = 0x0000_4080_0000_0000;
const _: () = assert!(LINUX_USER_WINDOW_END - LINUX_USER_WINDOW_BASE == 1 << 39);
const _: () = assert!(LINUX_USER_WINDOW_END <= USER_CANONICAL_TOP_EXCLUSIVE);

/// Virtual span covered by one page table (512 × 4 KiB).
const PAGE_TABLE_SPAN: u64 = PAGE_SIZE * 512;
/// Virtual span covered by one page directory (512 page tables).
const PAGE_DIRECTORY_SPAN: u64 = PAGE_TABLE_SPAN * 512;

/// Linux user stack size in pages (8 KiB).
///
/// The M8 fixture uses zero stack beyond the initial argc/argv/envp/auxv image
/// (< 256 bytes). Two pages keep the default `MAX_ADDRESS_SPACE_USER_MAPPINGS`
/// (4) budget honest: 1 fixture code page + 2 stack pages leaves one slot of
/// headroom for a data page. M9 may grow this once the mapping bound is raised
/// for Linux images; do not bump the bound just to absorb a bigger stack.
pub(crate) const LINUX_STACK_PAGES: u64 = 2;
/// Exclusive top of the mapped stack. The last page of the slot is deliberately
/// left unmapped so the stack never abuts the slot boundary.
pub(crate) const LINUX_STACK_TOP: u64 = LINUX_USER_WINDOW_END - PAGE_SIZE;
/// Lowest mapped stack page.
pub(crate) const LINUX_STACK_BASE: u64 = LINUX_STACK_TOP - LINUX_STACK_PAGES * PAGE_SIZE;
/// Guard page directly below the stack: never mapped, so overflow faults.
pub(crate) const LINUX_STACK_GUARD_PAGE: u64 = LINUX_STACK_BASE - PAGE_SIZE;
/// `[LINUX_STACK_RESERVATION_START, LINUX_USER_WINDOW_END)` is reserved for the
/// guard, stack and unmapped top page. Any PT_LOAD page inside it is rejected
/// with [`LinuxImageError::SegmentOverlapsStackReservation`].
pub(crate) const LINUX_STACK_RESERVATION_START: u64 = LINUX_STACK_GUARD_PAGE;
// The stack must leave room for at least one image page under the mapping bound.
const _: () = assert!((LINUX_STACK_PAGES as usize) < MAX_ADDRESS_SPACE_USER_MAPPINGS);
const _: () = assert!(LINUX_STACK_BASE % PAGE_SIZE == 0);
const _: () = assert!(LINUX_STACK_GUARD_PAGE > LINUX_USER_WINDOW_BASE);

/// Bytes of the initial stack image built into the top stack page.
///
/// Demand for the fixture: 15 u64 vectors (argc, argv0, NULL, NULL, 5 auxv
/// pairs, AT_NULL pair) = 120 B, 19 B of `argv[0]`, ≤ 15 B alignment padding →
/// 154 B. 256 B leaves headroom without spanning more than the top page.
pub(crate) const LINUX_INITIAL_STACK_IMAGE_BYTES: usize = 256;
/// Upper bound for M9 exec stack images (multiple stack pages).
pub(crate) const LINUX_MAX_STACK_IMAGE_BYTES: usize = 4096;
const _: () = assert!(LINUX_INITIAL_STACK_IMAGE_BYTES as u64 <= PAGE_SIZE);
const _: () = assert!(LINUX_MAX_STACK_IMAGE_BYTES as u64 <= 8 * PAGE_SIZE);
/// `argv[0]` for the M8 fixture (WAVE2 / docs/LINUX_PERSONALITY.md).
pub(crate) const LINUX_ARGV0: &[u8] = b"hello-linux-x86_64";
/// Auxv entries emitted for M8 (excluding the `AT_NULL` terminator the builder
/// appends): `AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_PAGESZ`, `AT_ENTRY`.
pub(crate) const LINUX_AUXV_ENTRIES: usize = 5;
pub(crate) const LINUX_MAX_AUXV_ENTRIES: usize = 16;

const LINUX_ALLOWED_E_TYPES: [u16; 1] = [ET_EXEC];

/// Linux M8 load policy: static `ET_EXEC` only, every PT_LOAD inside the
/// private PML4 slot `[0x0000_4000_0000_0000, 0x0000_4080_0000_0000)`, W^X and
/// page-zero rejection on. Tighter than `LoadPlanPolicy::absolute_user_x86_64()`
/// (which extends to `1 << 47`) because `create_process_address_space` gives a
/// process exactly one slot (docs/ARCHITECTURE.md, "Userspace VA window").
pub(crate) const LINUX_M8_LOAD_POLICY: LoadPlanPolicy = LoadPlanPolicy {
    user_va_lo: LINUX_USER_WINDOW_BASE,
    user_va_hi: LINUX_USER_WINDOW_END,
    max_segments: MAX_LOAD_SEGMENTS,
    page_size: PAGE_SIZE,
    reject_write_execute: true,
    reject_page_zero: true,
    allowed_e_types: &LINUX_ALLOWED_E_TYPES,
};

/// Conventional Linux user window for low-VA `ET_EXEC` images (#142).
#[cfg(any(feature = "m9-low-va-self-test", test))]
pub(crate) const LINUX_CONVENTIONAL_LOAD_POLICY: LoadPlanPolicy =
    LoadPlanPolicy::linux_conventional_x86_64();

/// M9 low-VA hello fixture (`fixtures/linux-low-hello/hello-linux-low-x86_64`).
#[cfg(any(feature = "m9-low-va-self-test", test))]
pub(crate) const LINUX_LOW_VA_FIXTURE: &[u8] =
    include_bytes!("../../../fixtures/linux-low-hello/hello-linux-low-x86_64");

#[cfg(any(feature = "m9-low-va-self-test", test))]
pub(crate) const LINUX_LOW_VA_ARGV0: &[u8] = b"hello-linux-low-x86_64";

/// Stack and window constants selected by load policy (M8 slot 128 vs conventional low VA).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LinuxImageLayout {
    pub(crate) user_region_base: u64,
    pub(crate) window_base: u64,
    pub(crate) window_end: u64,
    pub(crate) stack_top: u64,
    pub(crate) stack_base: u64,
    pub(crate) stack_guard_page: u64,
    pub(crate) stack_reservation_start: u64,
    pub(crate) stack_pages: u64,
    pub(crate) argv0: &'static [u8],
}

impl LinuxImageLayout {
    pub(crate) const fn m8_legacy() -> Self {
        Self {
            user_region_base: LINUX_USER_WINDOW_BASE,
            window_base: LINUX_USER_WINDOW_BASE,
            window_end: LINUX_USER_WINDOW_END,
            stack_top: LINUX_STACK_TOP,
            stack_base: LINUX_STACK_BASE,
            stack_guard_page: LINUX_STACK_GUARD_PAGE,
            stack_reservation_start: LINUX_STACK_RESERVATION_START,
            stack_pages: LINUX_STACK_PAGES,
            argv0: LINUX_ARGV0,
        }
    }

    #[cfg(any(feature = "m9-low-va-self-test", test))]
    pub(crate) const fn conventional(user_region_base: u64) -> Self {
        // Stack a few MiB above typical `0x400000` ET_EXEC mappings so image and
        // stack share page-table depth (same GiB / 2 MiB region as the M8 budget).
        const CONVENTIONAL_STACK_TOP: u64 = 0x0000_0000_0080_0000;
        let stack_base = CONVENTIONAL_STACK_TOP - LINUX_STACK_PAGES * PAGE_SIZE;
        let stack_guard_page = stack_base - PAGE_SIZE;
        Self {
            user_region_base,
            window_base: LINUX_CONVENTIONAL_LOAD_POLICY.user_va_lo,
            window_end: USER_CANONICAL_TOP_EXCLUSIVE,
            stack_top: CONVENTIONAL_STACK_TOP,
            stack_base,
            stack_guard_page,
            stack_reservation_start: stack_guard_page,
            stack_pages: LINUX_STACK_PAGES,
            argv0: LINUX_LOW_VA_ARGV0,
        }
    }

    /// Conventional low-VA layout with an explicit mapped stack page count (#146).
    pub(crate) fn conventional_with_stack(
        user_region_base: u64,
        stack_pages: u64,
        window_base: u64,
    ) -> Result<Self, LinuxImageError> {
        if stack_pages == 0 {
            return Err(LinuxImageError::InitialStack(StackLayoutError::BufferTooSmall));
        }
        const CONVENTIONAL_STACK_TOP: u64 = 0x0000_0000_0080_0000;
        let stack_span = stack_pages
            .checked_mul(PAGE_SIZE)
            .ok_or(LinuxImageError::VaddrOverflow)?;
        let stack_base = CONVENTIONAL_STACK_TOP
            .checked_sub(stack_span)
            .ok_or(LinuxImageError::VaddrOverflow)?;
        let stack_guard_page = stack_base
            .checked_sub(PAGE_SIZE)
            .ok_or(LinuxImageError::VaddrOverflow)?;
        Ok(Self {
            user_region_base,
            window_base,
            window_end: USER_CANONICAL_TOP_EXCLUSIVE,
            stack_top: CONVENTIONAL_STACK_TOP,
            stack_base,
            stack_guard_page,
            stack_reservation_start: stack_guard_page,
            stack_pages,
            argv0: b"",
        })
    }
}

/// Typed, fail-closed loader error. Every variant carries a kernel-log string
/// via [`LinuxImageError::description`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinuxImageError {
    /// Structural or PT_LOAD failure reported by `clean-slate-elf` under
    /// [`LINUX_M8_LOAD_POLICY`] (magic/class/endian/machine/version/`e_type`,
    /// `e_phentsize`, truncation, `filesz > memsz`, file range, VA overflow,
    /// out-of-window, W+X, overlap, budget, entry outside PF_X, ...).
    LoadPlan(LoadPlanError),
    /// A PT_LOAD touches virtual page zero.
    PageZero,
    /// A PT_LOAD lies below the private slot, inside the kernel identity map.
    IdentityMapVaddr,
    /// A PT_LOAD lies at or above the canonical user top (kernel half).
    KernelHalfVaddr,
    /// A PT_LOAD extends past the end of the private PML4 slot.
    OutOfWindow,
    /// `p_vaddr + p_memsz` overflowed.
    VaddrOverflow,
    /// `PT_INTERP` present: dynamic loaders are not supported in M8.
    InterpreterNotAllowed,
    /// `PT_DYNAMIC` present: dynamic linking is not supported in M8.
    DynamicNotAllowed,
    /// `p_align` is neither 0/1 nor a power of two `>= 4096`.
    AlignmentBelowPageSize,
    /// A PT_LOAD page intersects the reserved guard + stack range.
    SegmentOverlapsStackReservation,
    /// The program-header table is not covered by a PT_LOAD, so `AT_PHDR`
    /// cannot be derived.
    ProgramHeadersNotMapped,
    /// Image pages + stack pages exceed `MAX_ADDRESS_SPACE_USER_MAPPINGS`.
    MappingBudgetExceeded,
    /// Page-table frames needed exceed `MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES`.
    PageTableBudgetExceeded,
    /// `build_initial_stack` rejected the argv/auxv layout.
    InitialStack(StackLayoutError),
    /// Kernel side: `create_process_address_space` failed.
    AddressSpaceCreation(&'static str),
    /// Kernel side: `map_load_plan_segments` failed (already rolled back).
    SegmentMapping(&'static str),
    /// Kernel side: `map_user_stack_pages` failed (already rolled back).
    StackMapping(&'static str),
    /// Kernel side: copying the initial stack image into the stack pages failed.
    StackImageWrite(&'static str),
    /// Kernel side: the guard page translated after mapping (must never happen).
    GuardPageMapped,
    /// Kernel side: `build_userspace_entry_frame` failed.
    EntryFrame(&'static str),
    /// Kernel side: pid/tid allocation failed.
    IdAllocation(&'static str),
    /// Kernel side: process registry rejected the insert or a precondition.
    Registry(&'static str),
    /// Kernel side: scheduler slot precondition or `configure_thread` failed.
    Scheduler(&'static str),
    /// Kernel side: a rollback step itself failed (resources may be leaked).
    Rollback(&'static str),
    /// M9 exec: argv/env count or byte budget exceeded.
    ExecArgvBounds,
    /// M9 exec: environment count exceeded.
    ExecEnvBounds,
    /// M9 exec: stack page budget invalid or mapping budget exhausted.
    ExecStackBounds,
    /// M9 exec: live thread count is not exactly one.
    ExecMultiThread,
    /// M9 exec: stale instance generation.
    ExecGenerationMismatch,
}

impl LinuxImageError {
    /// Static description for kernel logs.
    pub(crate) const fn description(&self) -> &'static str {
        match self {
            Self::LoadPlan(error) => load_plan_error_description(*error),
            Self::PageZero => "linux image: PT_LOAD touches page zero",
            Self::IdentityMapVaddr => "linux image: PT_LOAD inside kernel identity map",
            Self::KernelHalfVaddr => "linux image: PT_LOAD in kernel half of the address space",
            Self::OutOfWindow => "linux image: PT_LOAD outside the private user window",
            Self::VaddrOverflow => "linux image: p_vaddr + p_memsz overflow",
            Self::InterpreterNotAllowed => "linux image: PT_INTERP not supported in M8",
            Self::DynamicNotAllowed => "linux image: PT_DYNAMIC not supported in M8",
            Self::AlignmentBelowPageSize => "linux image: p_align below page size",
            Self::SegmentOverlapsStackReservation => {
                "linux image: PT_LOAD overlaps reserved stack/guard range"
            }
            Self::ProgramHeadersNotMapped => "linux image: program headers not inside a PT_LOAD",
            Self::MappingBudgetExceeded => "linux image: mapped pages exceed address-space bound",
            Self::PageTableBudgetExceeded => "linux image: page-table frames exceed bound",
            Self::InitialStack(StackLayoutError::BufferTooSmall) => {
                "linux image: initial stack image buffer too small"
            }
            Self::InitialStack(StackLayoutError::InvalidStackTop) => {
                "linux image: initial stack top invalid"
            }
            Self::InitialStack(StackLayoutError::StringOverflow) => {
                "linux image: initial stack string overflow"
            }
            Self::InitialStack(StackLayoutError::PrematureAtNull) => {
                "linux image: initial stack auxv contained AT_NULL"
            }
            Self::AddressSpaceCreation(message)
            | Self::SegmentMapping(message)
            | Self::StackMapping(message)
            | Self::StackImageWrite(message)
            | Self::EntryFrame(message)
            | Self::IdAllocation(message)
            | Self::Registry(message)
            | Self::Scheduler(message)
            | Self::Rollback(message) => message,
            Self::GuardPageMapped => "linux image: stack guard page was mapped",
            Self::ExecArgvBounds => "linux image: exec argv/env byte or count bounds exceeded",
            Self::ExecEnvBounds => "linux image: exec env count bounds exceeded",
            Self::ExecStackBounds => "linux image: exec stack page budget invalid",
            Self::ExecMultiThread => "linux image: exec with multiple live threads",
            Self::ExecGenerationMismatch => "linux image: exec generation mismatch",
        }
    }
}

const fn load_plan_error_description(error: LoadPlanError) -> &'static str {
    match error {
        LoadPlanError::TruncatedHeader => "linux image: truncated ELF header",
        LoadPlanError::BadMagic => "linux image: bad ELF magic",
        LoadPlanError::BadClass => "linux image: not ELFCLASS64",
        LoadPlanError::BadEndian => "linux image: not little-endian",
        LoadPlanError::BadVersion => "linux image: unsupported ELF version",
        LoadPlanError::BadMachine => "linux image: not EM_X86_64",
        LoadPlanError::TruncatedProgramHeaders => "linux image: program headers beyond file",
        LoadPlanError::BadPhentsize => "linux image: e_phentsize != 56",
        LoadPlanError::FileszGreaterThanMemsz => "linux image: p_filesz > p_memsz",
        LoadPlanError::FileRangeOverflow => "linux image: p_offset + p_filesz overflow",
        LoadPlanError::FileRangeBeyondEof => "linux image: p_offset + p_filesz beyond file",
        LoadPlanError::VaddrRangeOverflow => "linux image: p_vaddr + p_memsz overflow",
        LoadPlanError::NonCanonicalVaddr => "linux image: non-canonical p_vaddr",
        LoadPlanError::OutOfWindowVaddr => "linux image: p_vaddr outside policy window",
        LoadPlanError::PageZero => "linux image: PT_LOAD touches page zero",
        LoadPlanError::AlignmentViolation => "linux image: p_align not a power of two",
        LoadPlanError::OffsetVaddrCongruenceViolation => {
            "linux image: p_vaddr % p_align != p_offset % p_align"
        }
        LoadPlanError::SegmentOverlap => "linux image: PT_LOAD segments overlap",
        LoadPlanError::SegmentBudgetExceeded => "linux image: too many PT_LOAD segments",
        LoadPlanError::EntryOutsideExecutableSegment => {
            "linux image: e_entry outside an executable PT_LOAD"
        }
        LoadPlanError::WriteExecuteConflict => "linux image: PT_LOAD is writable and executable",
        LoadPlanError::NoLoadSegments => "linux image: no PT_LOAD segments",
        LoadPlanError::UnsupportedEType => "linux image: e_type is not ET_EXEC",
        LoadPlanError::ArithmeticOverflow => "linux image: arithmetic overflow",
    }
}

impl From<LoadPlanError> for LinuxImageError {
    fn from(error: LoadPlanError) -> Self {
        Self::LoadPlan(error)
    }
}

/// Initial Linux stack bytes for the top of the stack, built on the host or in
/// the kernel from the validated plan (pure).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LinuxInitialStack {
    /// Exclusive top of the mapped stack pages for this layout.
    pub(crate) stack_top: u64,
    /// Bytes occupying `[image_base(), stack_top)`.
    pub(crate) bytes: [u8; LINUX_MAX_STACK_IMAGE_BYTES],
    /// Active prefix length of `bytes`.
    pub(crate) bytes_len: usize,
    /// 16-byte-aligned user RSP pointing at `argc`.
    pub(crate) rsp: u64,
    /// Auxv pairs as emitted (without the trailing `AT_NULL`).
    pub(crate) auxv: [(u64, u64); LINUX_MAX_AUXV_ENTRIES],
    pub(crate) auxv_len: usize,
}

impl LinuxInitialStack {
    /// Lowest virtual address covered by the active stack image bytes.
    pub(crate) fn image_base(&self) -> u64 {
        self.stack_top - self.bytes_len as u64
    }
}

/// Validated, mapping-ready description of a Linux image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LinuxImagePlan {
    /// The `clean-slate-elf` plan (segments, entry, phdr metadata).
    pub(crate) plan: LoadPlan,
    /// `e_entry`; the launch RIP.
    pub(crate) entry: u64,
    /// `AT_PHDR`: user VA of the program-header table.
    pub(crate) phdr_vaddr: u64,
    /// Unique PT_LOAD pages the mapper will allocate.
    pub(crate) image_pages: u64,
    /// Exact page-table frames the address space will own after mapping
    /// (root + PDPT + distinct PDs + distinct PTs for image and stack).
    pub(crate) page_table_frames: usize,
    /// Initial stack image and launch RSP.
    pub(crate) initial_stack: LinuxInitialStack,
    /// Window, stack, and argv layout used for this image.
    pub(crate) layout: LinuxImageLayout,
}

impl LinuxImagePlan {
    /// Launch RSP (16-byte aligned, inside the mapped stack).
    pub(crate) const fn launch_rsp(&self) -> u64 {
        self.initial_stack.rsp
    }

    /// Total user pages the address space will map (image + stack; the guard
    /// page is never mapped and so never counted).
    pub(crate) const fn mapped_pages(&self) -> u64 {
        self.image_pages + self.layout.stack_pages
    }
}

fn read_le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let raw: [u8; 4] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

fn read_le_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let raw: [u8; 8] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(raw))
}

/// Explicit #92 window assertions and interp/dynamic rejection on the raw
/// program headers, run before the generic parser so each failure has its own
/// distinct variant (the generic crate folds page zero / kernel ranges into
/// `OutOfWindowVaddr` / `NonCanonicalVaddr`).
fn prescan_program_headers(bytes: &[u8], header: &Elf64Header) -> Result<(), LinuxImageError> {
    let phentsize = usize::from(header.e_phentsize);
    let table_end = header
        .e_phoff
        .checked_add(
            u64::from(header.e_phnum)
                .checked_mul(u64::from(header.e_phentsize))
                .ok_or(LoadPlanError::ArithmeticOverflow)?,
        )
        .ok_or(LoadPlanError::ArithmeticOverflow)?;
    if table_end > bytes.len() as u64 {
        return Err(LoadPlanError::TruncatedProgramHeaders.into());
    }
    let phoff = usize::try_from(header.e_phoff).map_err(|_| LoadPlanError::ArithmeticOverflow)?;
    for index in 0..usize::from(header.e_phnum) {
        let start = index
            .checked_mul(phentsize)
            .and_then(|offset| offset.checked_add(phoff))
            .ok_or(LoadPlanError::ArithmeticOverflow)?;
        let p_type = read_le_u32(bytes, start).ok_or(LoadPlanError::TruncatedProgramHeaders)?;
        match p_type {
            PT_INTERP => return Err(LinuxImageError::InterpreterNotAllowed),
            PT_DYNAMIC => return Err(LinuxImageError::DynamicNotAllowed),
            PT_LOAD => {}
            _ => continue,
        }
        let p_vaddr =
            read_le_u64(bytes, start + 0x10).ok_or(LoadPlanError::TruncatedProgramHeaders)?;
        let p_memsz =
            read_le_u64(bytes, start + 0x28).ok_or(LoadPlanError::TruncatedProgramHeaders)?;
        if p_memsz == 0 {
            continue;
        }
        let end = p_vaddr
            .checked_add(p_memsz)
            .ok_or(LinuxImageError::VaddrOverflow)?;
        if p_vaddr >= USER_CANONICAL_TOP_EXCLUSIVE || end > USER_CANONICAL_TOP_EXCLUSIVE {
            return Err(LinuxImageError::KernelHalfVaddr);
        }
        if align_down(p_vaddr, PAGE_SIZE) == 0 {
            return Err(LinuxImageError::PageZero);
        }
        if p_vaddr < LINUX_USER_WINDOW_BASE {
            return Err(LinuxImageError::IdentityMapVaddr);
        }
        if end > LINUX_USER_WINDOW_END {
            return Err(LinuxImageError::OutOfWindow);
        }
    }
    Ok(())
}

/// Reject interp/dynamic, kernel-half, and page-zero touches before parsing under
/// a policy-specific window (conventional low VA).
fn prescan_program_headers_minimal(
    bytes: &[u8],
    header: &Elf64Header,
) -> Result<(), LinuxImageError> {
    let phentsize = usize::from(header.e_phentsize);
    let table_end = header
        .e_phoff
        .checked_add(
            u64::from(header.e_phnum)
                .checked_mul(u64::from(header.e_phentsize))
                .ok_or(LoadPlanError::ArithmeticOverflow)?,
        )
        .ok_or(LoadPlanError::ArithmeticOverflow)?;
    if table_end > bytes.len() as u64 {
        return Err(LoadPlanError::TruncatedProgramHeaders.into());
    }
    let phoff = usize::try_from(header.e_phoff).map_err(|_| LoadPlanError::ArithmeticOverflow)?;
    for index in 0..usize::from(header.e_phnum) {
        let start = index
            .checked_mul(phentsize)
            .and_then(|offset| offset.checked_add(phoff))
            .ok_or(LoadPlanError::ArithmeticOverflow)?;
        let p_type = read_le_u32(bytes, start).ok_or(LoadPlanError::TruncatedProgramHeaders)?;
        match p_type {
            PT_INTERP => return Err(LinuxImageError::InterpreterNotAllowed),
            PT_DYNAMIC => return Err(LinuxImageError::DynamicNotAllowed),
            PT_LOAD => {}
            _ => continue,
        }
        let p_vaddr =
            read_le_u64(bytes, start + 0x10).ok_or(LoadPlanError::TruncatedProgramHeaders)?;
        let p_memsz =
            read_le_u64(bytes, start + 0x28).ok_or(LoadPlanError::TruncatedProgramHeaders)?;
        if p_memsz == 0 {
            continue;
        }
        let end = p_vaddr
            .checked_add(p_memsz)
            .ok_or(LinuxImageError::VaddrOverflow)?;
        if p_vaddr >= USER_CANONICAL_TOP_EXCLUSIVE || end > USER_CANONICAL_TOP_EXCLUSIVE {
            return Err(LinuxImageError::KernelHalfVaddr);
        }
        if align_down(p_vaddr, PAGE_SIZE) == 0 {
            return Err(LinuxImageError::PageZero);
        }
    }
    Ok(())
}

/// Bounded set of distinct page-table granules. Capacity equals the page-table
/// frame budget, so inserting past it is itself the budget failure and bounds
/// the work for arbitrarily large segments.
struct DistinctGranules {
    items: [u64; MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES],
    len: usize,
}

impl DistinctGranules {
    const fn new() -> Self {
        Self {
            items: [0; MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES],
            len: 0,
        }
    }

    fn insert(&mut self, granule: u64) -> Result<(), LinuxImageError> {
        if self.items[..self.len].contains(&granule) {
            return Ok(());
        }
        if self.len == self.items.len() {
            return Err(LinuxImageError::PageTableBudgetExceeded);
        }
        self.items[self.len] = granule;
        self.len += 1;
        Ok(())
    }

    fn insert_range(&mut self, start: u64, end: u64, span: u64) -> Result<(), LinuxImageError> {
        let mut granule = align_down(start, span);
        let last = align_down(end - 1, span);
        loop {
            self.insert(granule)?;
            if granule >= last {
                return Ok(());
            }
            granule = granule
                .checked_add(span)
                .ok_or(LinuxImageError::VaddrOverflow)?;
        }
    }
}

/// Exact page-table frame demand for mapping the half-open page ranges
/// `ranges` inside one PML4 slot: root + one PDPT + one PD per distinct 1 GiB
/// granule + one PT per distinct 2 MiB granule. Pure; host-tested.
pub(crate) fn page_table_frame_demand(ranges: &[(u64, u64)]) -> Result<usize, LinuxImageError> {
    let mut tables = DistinctGranules::new();
    let mut directories = DistinctGranules::new();
    for &(start, end) in ranges {
        if start >= end {
            continue;
        }
        tables.insert_range(start, end, PAGE_TABLE_SPAN)?;
        directories.insert_range(start, end, PAGE_DIRECTORY_SPAN)?;
    }
    // root + PDPT
    2usize
        .checked_add(tables.len)
        .and_then(|total| total.checked_add(directories.len))
        .ok_or(LinuxImageError::PageTableBudgetExceeded)
}

/// Build the M8 initial stack for `entry`/`phdr_vaddr`/`phnum` (pure).
///
/// `argc = 1`, `argv[0] = "hello-linux-x86_64"`, `envp = []`, auxv
/// `AT_PHDR, AT_PHENT (56), AT_PHNUM, AT_PAGESZ (4096), AT_ENTRY` and the
/// builder-appended `AT_NULL`. `AT_RANDOM` is not required by the contract and
/// not emitted (the fixture does not read it).
pub(crate) fn build_linux_initial_stack(
    entry: u64,
    phdr_vaddr: u64,
    phnum: u16,
    layout: &LinuxImageLayout,
) -> Result<LinuxInitialStack, LinuxImageError> {
    let auxv = [
        (AT_PHDR, phdr_vaddr),
        (AT_PHENT, u64::from(ELF64_PHDR_SIZE)),
        (AT_PHNUM, u64::from(phnum)),
        (AT_PAGESZ, PAGE_SIZE),
        (AT_ENTRY, entry),
    ];
    let mut bytes = [0u8; LINUX_MAX_STACK_IMAGE_BYTES];
    let buf = &mut bytes[..LINUX_INITIAL_STACK_IMAGE_BYTES];
    let image = build_initial_stack(buf, layout.stack_top, &[layout.argv0], &[], &auxv)
        .map_err(LinuxImageError::InitialStack)?;
    if image.rsp % 16 != 0 || image.rsp < layout.stack_base || image.rsp >= layout.stack_top {
        return Err(LinuxImageError::InitialStack(
            StackLayoutError::InvalidStackTop,
        ));
    }
    let mut auxv_storage = [(0u64, 0u64); LINUX_MAX_AUXV_ENTRIES];
    for (index, pair) in auxv.iter().enumerate() {
        auxv_storage[index] = *pair;
    }
    Ok(LinuxInitialStack {
        stack_top: layout.stack_top,
        bytes,
        bytes_len: LINUX_INITIAL_STACK_IMAGE_BYTES,
        rsp: image.rsp,
        auxv: auxv_storage,
        auxv_len: LINUX_AUXV_ENTRIES,
    })
}

/// Pure, host-testable validation of a Linux ELF64 image under the M8 policy.
///
/// Runs, in order: ELF header (`clean-slate-elf`), explicit window/interp/dynamic
/// prescan, `parse_load_plan` under [`LINUX_M8_LOAD_POLICY`], then the #92
/// checks the generic crate does not make: page-size alignment, stack
/// reservation overlap, `AT_PHDR` derivability, mapping and page-table budgets,
/// and the initial stack layout. Nothing is allocated or mapped.
pub(crate) fn validate_linux_image(bytes: &[u8]) -> Result<LinuxImagePlan, LinuxImageError> {
    validate_linux_image_with_policy(bytes, &LINUX_M8_LOAD_POLICY, LinuxImageLayout::m8_legacy())
}

/// Validate a Linux image under an arbitrary policy and layout (#142 low VA).
pub(crate) fn validate_linux_image_with_policy(
    bytes: &[u8],
    policy: &LoadPlanPolicy,
    layout: LinuxImageLayout,
) -> Result<LinuxImagePlan, LinuxImageError> {
    let header = Elf64Header::parse(bytes)?;
    if policy.user_va_lo == LINUX_USER_WINDOW_BASE && policy.user_va_hi == LINUX_USER_WINDOW_END {
        prescan_program_headers(bytes, &header)?;
    } else {
        prescan_program_headers_minimal(bytes, &header)?;
    }
    let plan = parse_load_plan(bytes, policy)?;

    if plan.has_interp {
        return Err(LinuxImageError::InterpreterNotAllowed);
    }
    if plan.has_dynamic {
        return Err(LinuxImageError::DynamicNotAllowed);
    }

    let phdr_vaddr = plan
        .phdr_vaddr
        .ok_or(LinuxImageError::ProgramHeadersNotMapped)?;
    let (image_pages, page_table_frames) =
        validate_segment_layout_and_budgets(&plan, &layout, bytes)?;

    let initial_stack = build_linux_initial_stack(plan.entry, phdr_vaddr, plan.phnum, &layout)?;
    finish_linux_image_plan(
        plan,
        phdr_vaddr,
        image_pages,
        page_table_frames,
        initial_stack,
        layout,
    )
}

/// Validate segment layout and budgets, then attach a caller-built initial stack (#146).
pub(crate) fn validate_linux_image_with_stack(
    bytes: &[u8],
    policy: &LoadPlanPolicy,
    layout: LinuxImageLayout,
    initial_stack: LinuxInitialStack,
) -> Result<LinuxImagePlan, LinuxImageError> {
    let header = Elf64Header::parse(bytes)?;
    if policy.user_va_lo == LINUX_USER_WINDOW_BASE && policy.user_va_hi == LINUX_USER_WINDOW_END {
        prescan_program_headers(bytes, &header)?;
    } else {
        prescan_program_headers_minimal(bytes, &header)?;
    }
    let plan = parse_load_plan(bytes, policy)?;
    if plan.has_interp {
        return Err(LinuxImageError::InterpreterNotAllowed);
    }
    if plan.has_dynamic {
        return Err(LinuxImageError::DynamicNotAllowed);
    }
    let phdr_vaddr = plan
        .phdr_vaddr
        .ok_or(LinuxImageError::ProgramHeadersNotMapped)?;
    let (image_pages, page_table_frames) =
        validate_segment_layout_and_budgets(&plan, &layout, bytes)?;
    if initial_stack.stack_top != layout.stack_top
        || initial_stack.rsp < layout.stack_base
        || initial_stack.rsp >= layout.stack_top
    {
        return Err(LinuxImageError::InitialStack(StackLayoutError::InvalidStackTop));
    }
    finish_linux_image_plan(
        plan,
        phdr_vaddr,
        image_pages,
        page_table_frames,
        initial_stack,
        layout,
    )
}

fn finish_linux_image_plan(
    plan: LoadPlan,
    phdr_vaddr: u64,
    image_pages: u64,
    page_table_frames: usize,
    initial_stack: LinuxInitialStack,
    layout: LinuxImageLayout,
) -> Result<LinuxImagePlan, LinuxImageError> {
    let entry = plan.entry;
    Ok(LinuxImagePlan {
        plan,
        entry,
        phdr_vaddr,
        image_pages,
        page_table_frames,
        initial_stack,
        layout,
    })
}

fn validate_segment_layout_and_budgets(
    plan: &LoadPlan,
    layout: &LinuxImageLayout,
    bytes: &[u8],
) -> Result<(u64, usize), LinuxImageError> {
    let _ = bytes;
    let mut ranges = [(0u64, 0u64); MAX_LOAD_SEGMENTS + 1];
    let mut range_count = 0usize;
    for segment in plan.iter_segments() {
        if segment.align > 1 && segment.align < PAGE_SIZE {
            return Err(LinuxImageError::AlignmentBelowPageSize);
        }
        let (first_page, page_count) = segment.page_span(PAGE_SIZE)?;
        if page_count == 0 {
            continue;
        }
        let end = first_page
            .checked_add(
                page_count
                    .checked_mul(PAGE_SIZE)
                    .ok_or(LinuxImageError::VaddrOverflow)?,
            )
            .ok_or(LinuxImageError::VaddrOverflow)?;
        if first_page < layout.window_base || end > layout.window_end {
            return Err(LinuxImageError::OutOfWindow);
        }
        if end > layout.stack_reservation_start {
            return Err(LinuxImageError::SegmentOverlapsStackReservation);
        }
        ranges[range_count] = (first_page, end);
        range_count += 1;
    }
    ranges[range_count] = (layout.stack_base, layout.stack_top);
    range_count += 1;

    let mut page_table_frames = page_table_frame_demand(&ranges[..range_count])?;
    if layout.user_region_base < LINUX_USER_WINDOW_BASE {
        page_table_frames = page_table_frames.saturating_sub(2);
    }
    let page_table_frames_with_carve = page_table_frames
        .checked_add(KERNEL_CARVE_OUT_PRIVATE_TABLE_FRAMES)
        .ok_or(LinuxImageError::PageTableBudgetExceeded)?;
    if page_table_frames_with_carve > MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES {
        return Err(LinuxImageError::PageTableBudgetExceeded);
    }
    let image_pages = plan.total_mapped_pages(PAGE_SIZE)?;
    let total_pages = image_pages
        .checked_add(layout.stack_pages)
        .ok_or(LinuxImageError::MappingBudgetExceeded)?;
    if total_pages > MAX_ADDRESS_SPACE_USER_MAPPINGS as u64 {
        return Err(LinuxImageError::MappingBudgetExceeded);
    }
    Ok((image_pages, page_table_frames))
}

/// Validate the M9 low-VA fixture under [`LINUX_CONVENTIONAL_LOAD_POLICY`].
#[cfg(any(feature = "m9-low-va-self-test", test))]
pub(crate) fn validate_linux_low_va_image(bytes: &[u8]) -> Result<LinuxImagePlan, LinuxImageError> {
    let header = Elf64Header::parse(bytes)?;
    prescan_program_headers_minimal(bytes, &header)?;
    let plan = parse_load_plan(bytes, &LINUX_CONVENTIONAL_LOAD_POLICY)?;
    let image_base = plan
        .image_base()
        .ok_or(LinuxImageError::LoadPlan(LoadPlanError::NoLoadSegments))?;
    validate_linux_image_with_policy(
        bytes,
        &LINUX_CONVENTIONAL_LOAD_POLICY,
        LinuxImageLayout::conventional(align_down(image_base, PAGE_SIZE)),
    )
}

/// A constructed (not yet registered) Linux process image.
#[derive(Debug)]
pub(crate) struct LinuxProcessImage {
    pub(crate) address_space: ProcessAddressSpace,
    /// Launch RIP (`e_entry`).
    pub(crate) entry: u64,
    /// Launch RSP (16-byte aligned, points at `argc`).
    pub(crate) launch_rsp: u64,
    /// PT_LOAD pages mapped.
    pub(crate) image_pages: usize,
}

/// Copy the initial stack image into the freshly mapped stack pages through the
/// process root's translation (kernel context; never via a user pointer).
fn write_initial_stack_image(
    address_space: &ProcessAddressSpace,
    stack: &LinuxInitialStack,
    layout: &LinuxImageLayout,
) -> Result<(), &'static str> {
    let image_base = stack.image_base();
    let mut offset = 0usize;
    while offset < stack.bytes_len {
        let vaddr = image_base
            .checked_add(offset as u64)
            .ok_or("initial stack image address overflow")?;
        let page_vaddr = align_down(vaddr, PAGE_SIZE);
        if !(layout.stack_base..layout.stack_top).contains(&page_vaddr) {
            return Err("initial stack image escaped the mapped stack range");
        }
        let in_page = usize::try_from(vaddr - page_vaddr)
            .map_err(|_| "initial stack image page offset overflow")?;
        let chunk = (PAGE_SIZE as usize - in_page).min(stack.bytes_len - offset);
        let frame = translate_address_in_root(address_space.root_frame, VirtAddr::new(page_vaddr))?;
        unsafe {
            ptr::copy_nonoverlapping(
                stack.bytes[offset..offset + chunk].as_ptr(),
                (phys_to_virt(frame + in_page as u64)) as *mut u8,
                chunk,
            );
        }
        offset += chunk;
    }
    Ok(())
}

/// Destroy a half-built address space; a failure here is reported as
/// [`LinuxImageError::Rollback`] in preference to the original error because it
/// means resources may have leaked.
fn discard_address_space(
    address_space: &ProcessAddressSpace,
    allocator: &mut PageAllocator,
    original: LinuxImageError,
) -> LinuxImageError {
    match destroy_process_address_space(address_space, allocator) {
        Ok(()) => original,
        Err(message) => LinuxImageError::Rollback(message),
    }
}

/// Kernel side: build the process image for a validated plan.
///
/// Order mirrors `service::spawn`: address space → PT_LOAD segments (mapper
/// rolls back its own pages) → NX stack pages (guard stays unmapped) → initial
/// stack bytes → guard-page invariant. Any failure destroys the address space,
/// freeing every user frame and page-table frame allocated so far. Returns the
/// entry RIP and launch RSP; nothing is registered.
#[inline(never)]
pub(crate) fn build_linux_process_image(
    allocator: &mut PageAllocator,
    elf_bytes: &[u8],
    image_plan: &LinuxImagePlan,
) -> Result<LinuxProcessImage, LinuxImageError> {
    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(image_plan.layout.user_region_base))
            .map_err(LinuxImageError::AddressSpaceCreation)?;

    let image_pages =
        match map_load_plan_segments(&mut address_space, allocator, elf_bytes, &image_plan.plan) {
            Ok(pages) => pages,
            Err(message) => {
                return Err(discard_address_space(
                    &address_space,
                    allocator,
                    LinuxImageError::SegmentMapping(message),
                ));
            }
        };
    if image_pages as u64 != image_plan.image_pages {
        return Err(discard_address_space(
            &address_space,
            allocator,
            LinuxImageError::SegmentMapping("mapped page count diverged from the validated plan"),
        ));
    }

    if let Err(message) = map_user_stack_pages(
        &mut address_space,
        allocator,
        image_plan.layout.stack_base,
        image_plan.layout.stack_pages,
    ) {
        return Err(discard_address_space(
            &address_space,
            allocator,
            LinuxImageError::StackMapping(message),
        ));
    }

    if let Err(message) = write_initial_stack_image(
        &address_space,
        &image_plan.initial_stack,
        &image_plan.layout,
    ) {
        return Err(discard_address_space(
            &address_space,
            allocator,
            LinuxImageError::StackImageWrite(message),
        ));
    }

    if translate_address_in_root(
        address_space.root_frame,
        VirtAddr::new(image_plan.layout.stack_guard_page),
    )
    .is_ok()
    {
        return Err(discard_address_space(
            &address_space,
            allocator,
            LinuxImageError::GuardPageMapped,
        ));
    }
    let counts = address_space.resource_counts();
    let expected_pt = image_plan
        .page_table_frames
        .saturating_add(KERNEL_CARVE_OUT_PRIVATE_TABLE_FRAMES);
    if counts.page_table_frames != expected_pt
        || counts.user_pages as u64 != image_plan.mapped_pages()
    {
        return Err(discard_address_space(
            &address_space,
            allocator,
            LinuxImageError::StackMapping("address-space resource counts diverged from the plan"),
        ));
    }

    Ok(LinuxProcessImage {
        address_space,
        entry: image_plan.entry,
        launch_rsp: image_plan.launch_rsp(),
        image_pages,
    })
}

/// Result of [`launch_linux_process`]: what #97 needs to grant capabilities,
/// install stdio (#95) and observe the run (#98).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LaunchedLinuxProcess {
    pub(crate) pid: u64,
    pub(crate) tid: u64,
    pub(crate) instance_generation: clean_slate_service_lifecycle::InstanceGeneration,
    /// Launch RIP (`e_entry`).
    pub(crate) entry: u64,
    /// Launch RSP (16-byte aligned, points at `argc`).
    pub(crate) launch_rsp: u64,
    pub(crate) scheduler_slot: usize,
    /// PT_LOAD pages mapped (stack pages are `LINUX_STACK_PAGES` on top).
    pub(crate) image_pages: usize,
    /// Page-table frames owned by the address space, including the
    /// `KERNEL_CARVE_OUT_PRIVATE_TABLE_FRAMES` private carve-out tables.
    pub(crate) page_table_frames: usize,
}

/// Remove a process that was inserted but whose scheduler configuration failed:
/// destroy its address space, reap the record and release the registry slot.
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
fn rollback_registered_process(
    pid: u64,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    use super::{process_registry_mut, reap_process_record};

    let registry = unsafe { process_registry_mut() };
    let record = registry
        .get_mut(pid)
        .ok_or("linux launch rollback: process missing from registry")?;
    let address_space = record
        .resource_domain
        .take_address_space()
        .ok_or("linux launch rollback: process had no address space")?;
    destroy_process_address_space(&address_space, allocator)?;
    record.live_threads = 0;
    reap_process_record(record)?;
    registry.release_reaped(pid)
}

/// Register a built image as a `LinuxX86_64` process and configure its
/// scheduler thread, in the same order `service::spawn::register_spawned_process`
/// does (registry insert, then `configure_thread`). Kept out of line because it
/// moves a `ProcessAddressSpace` by value.
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
#[inline(never)]
pub(crate) fn register_linux_process(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
    image: LinuxProcessImage,
    page_table_frames: usize,
) -> Result<LaunchedLinuxProcess, LinuxImageError> {
    use super::id_allocator::id_allocator_mut;
    use super::personality::ExecutionPersonality;
    use super::{
        process_registry_mut, Process, ProcessState, ResourceDomain, PROCESS_REGISTRY_CAPACITY,
    };
    use crate::arch::x86_64::context_switch::build_userspace_entry_frame;
    use crate::arch::x86_64::cpu::without_interrupts;
    use crate::sched::{scheduler_mut, ThreadKind, ThreadState};
    use clean_slate_service_lifecycle::InstanceGeneration;

    // Preconditions that would otherwise fail after the registry insert.
    let precondition = without_interrupts(|| unsafe {
        let scheduler = scheduler_mut();
        if scheduler_slot >= scheduler.thread_capacity() {
            return Err(LinuxImageError::Scheduler(
                "linux launch: scheduler slot exceeded fixed capacity",
            ));
        }
        if scheduler.threads[scheduler_slot].state != ThreadState::Empty {
            return Err(LinuxImageError::Scheduler(
                "linux launch: scheduler slot was occupied",
            ));
        }
        if process_registry_mut().occupied_slots() >= PROCESS_REGISTRY_CAPACITY {
            return Err(LinuxImageError::Registry(
                "linux launch: process registry capacity exceeded",
            ));
        }
        Ok(())
    });
    if let Err(error) = precondition {
        return Err(discard_address_space(
            &image.address_space,
            allocator,
            error,
        ));
    }

    let allocated_ids = (|| -> Result<(u64, u64), &'static str> {
        let ids = unsafe { id_allocator_mut() };
        Ok((ids.allocate_pid()?, ids.allocate_tid()?))
    })();
    let (pid, tid) = match allocated_ids {
        Ok(ids) => ids,
        Err(message) => {
            return Err(discard_address_space(
                &image.address_space,
                allocator,
                LinuxImageError::IdAllocation(message),
            ));
        }
    };

    let saved_stack_pointer =
        match build_userspace_entry_frame(kernel_stack_top, image.entry, image.launch_rsp) {
            Ok(frame) => frame,
            Err(message) => {
                return Err(discard_address_space(
                    &image.address_space,
                    allocator,
                    LinuxImageError::EntryFrame(message),
                ));
            }
        };

    // Trusted kernel metadata: this is the one place the Linux personality is
    // assigned at launch. It is fixed at construction, never from user input.
    let process = Process {
        id: pid,
        instance_generation: InstanceGeneration(0),
        state: ProcessState::Ready,
        resource_domain: ResourceDomain::with_address_space(pid, image.address_space),
        live_threads: 1,
        exit_status: None,
        execution_personality: ExecutionPersonality::LinuxX86_64,
    };
    let registered = without_interrupts(|| unsafe {
        // `insert` consumes the process; the preconditions above make failure
        // here a registry invariant violation rather than a capacity issue.
        process_registry_mut()
            .insert(process)
            .map_err(LinuxImageError::Registry)?;
        let instance_generation =
            process_registry_mut()
                .instance_generation(pid)
                .ok_or(LinuxImageError::Registry(
                    "linux launch: inserted process had no instance generation",
                ))?;
        if let Err(message) = scheduler_mut().configure_thread(
            scheduler_slot,
            tid,
            pid,
            ThreadKind::User,
            kernel_stack_top,
            saved_stack_pointer,
            image.entry,
        ) {
            return Err(match rollback_registered_process(pid, allocator) {
                Ok(()) => LinuxImageError::Scheduler(message),
                Err(rollback) => LinuxImageError::Rollback(rollback),
            });
        }
        Ok(instance_generation)
    });
    let instance_generation = registered?;
    Ok(LaunchedLinuxProcess {
        pid,
        tid,
        instance_generation,
        entry: image.entry,
        launch_rsp: image.launch_rsp,
        scheduler_slot,
        image_pages: image.image_pages,
        page_table_frames,
    })
}

/// Validate, build and register a Linux process from `elf_bytes`.
///
/// Order: validate (pure) → address space → segments → stack → stack image →
/// registry insert (`ExecutionPersonality::LinuxX86_64`) → scheduler thread.
/// Any failure after allocation frees every frame and page-table page and
/// leaves the registry and scheduler unchanged. The process is `Ready` on
/// return; the caller (#97) grants capabilities / installs stdio before the
/// scheduler dispatches it.
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
pub(crate) fn launch_linux_process(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
    elf_bytes: &[u8],
) -> Result<LaunchedLinuxProcess, LinuxImageError> {
    launch_linux_process_with_policy(
        allocator,
        kernel_stack_top,
        scheduler_slot,
        elf_bytes,
        validate_linux_image,
    )
}

/// Same as [`launch_linux_process`] but validates with a caller-supplied pure
/// validator (M8 legacy vs conventional low VA).
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
pub(crate) fn launch_linux_process_with_policy(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
    elf_bytes: &[u8],
    validate: fn(&[u8]) -> Result<LinuxImagePlan, LinuxImageError>,
) -> Result<LaunchedLinuxProcess, LinuxImageError> {
    let image_plan = validate(elf_bytes)?;
    let image = build_linux_process_image(allocator, elf_bytes, &image_plan)?;
    // Report what the address space actually owns (mapping-walk frames plus the
    // per-process carve-out private tables), not the pure-plan mapping demand;
    // `build_linux_process_image` has already verified the two agree.
    let page_table_frames = image.address_space.resource_counts().page_table_frames;
    register_linux_process(
        allocator,
        kernel_stack_top,
        scheduler_slot,
        image,
        page_table_frames,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_elf::{ELF64_EHDR_SIZE, PF_R, PF_W, PF_X};
    use clean_slate_linux_abi::AT_NULL;

    // Frozen malformed corpus (fixtures/linux-hello/malformed/README.md).
    const BAD_MAGIC: &[u8] =
        include_bytes!("../../../fixtures/linux-hello/malformed/bad-magic.elf");
    const ELFCLASS32: &[u8] =
        include_bytes!("../../../fixtures/linux-hello/malformed/elfclass32.elf");
    const BIG_ENDIAN: &[u8] =
        include_bytes!("../../../fixtures/linux-hello/malformed/big-endian.elf");
    const EM_AARCH64: &[u8] =
        include_bytes!("../../../fixtures/linux-hello/malformed/em-aarch64.elf");
    const ET_DYN_ELF: &[u8] = include_bytes!("../../../fixtures/linux-hello/malformed/et-dyn.elf");
    const TRUNCATED_PHDR_TABLE: &[u8] =
        include_bytes!("../../../fixtures/linux-hello/malformed/truncated-phdr-table.elf");
    const FILESZ_GT_MEMSZ: &[u8] =
        include_bytes!("../../../fixtures/linux-hello/malformed/filesz-gt-memsz.elf");
    const OVERLAPPING_PT_LOAD: &[u8] =
        include_bytes!("../../../fixtures/linux-hello/malformed/overlapping-pt-load.elf");
    const HAS_PT_INTERP: &[u8] =
        include_bytes!("../../../fixtures/linux-hello/malformed/has-pt-interp.elf");
    const VADDR_KERNEL_RANGE: &[u8] =
        include_bytes!("../../../fixtures/linux-hello/malformed/vaddr-kernel-range.elf");
    const VADDR_PAGE_ZERO: &[u8] =
        include_bytes!("../../../fixtures/linux-hello/malformed/vaddr-page-zero.elf");
    const PHENTSIZE_WRONG: &[u8] =
        include_bytes!("../../../fixtures/linux-hello/malformed/phentsize-wrong.elf");
    const OFFSET_BEYOND_EOF: &[u8] =
        include_bytes!("../../../fixtures/linux-hello/malformed/offset-beyond-eof.elf");

    /// Frozen fixture facts (fixtures/linux-hello/metadata.toml). The file is
    /// 704 bytes (ELF header, phdr, code, then section headers/strtab that are
    /// never mapped); its single PT_LOAD covers the first 0xe5 bytes.
    const FIXTURE_LEN: usize = 704;
    const FIXTURE_LOAD_FILESZ: u64 = 0xe5;
    const FIXTURE_ENTRY: u64 = 0x0000_4000_0040_0078;
    const FIXTURE_IMAGE_BASE: u64 = 0x0000_4000_0040_0000;
    const FIXTURE_PHOFF: u64 = 0x40;
    const FIXTURE_PHNUM: u16 = 1;

    // Elf64 header / phdr field offsets.
    const EH_ENTRY: usize = 0x18;
    const EH_PHOFF: usize = 0x20;
    const EH_PHNUM: usize = 0x38;
    const PH_TYPE: usize = 0x00;
    const PH_FLAGS: usize = 0x04;
    const PH_OFFSET: usize = 0x08;
    const PH_VADDR: usize = 0x10;
    const PH_FILESZ: usize = 0x20;
    const PH_MEMSZ: usize = 0x28;
    const PH_ALIGN: usize = 0x30;

    fn fixture_copy() -> Vec<u8> {
        LINUX_M8_FIXTURE.to_vec()
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn phdr(index: usize) -> usize {
        FIXTURE_PHOFF as usize + index * usize::from(ELF64_PHDR_SIZE)
    }

    /// Extra PT_LOAD description for [`fixture_with_extra_loads`].
    #[derive(Clone, Copy)]
    struct ExtraLoad {
        vaddr: u64,
        filesz: u64,
        memsz: u64,
        flags: u32,
    }

    /// Fixture copy with additional PT_LOADs. The fixture's only PT_LOAD starts
    /// at file offset 0, so the program-header table is relocated past the
    /// original bytes (code untouched) and PT_LOAD[0] is widened to
    /// keep covering it (so `AT_PHDR` stays derivable). Extra loads read their
    /// file bytes from offset 0 and are page-aligned (`p_align = 4096`). Not
    /// executable, but structurally valid under the M8 policy.
    fn fixture_with_extra_loads(extra: &[ExtraLoad]) -> Vec<u8> {
        let mut bytes = fixture_copy();
        let phentsize = usize::from(ELF64_PHDR_SIZE);
        let count = 1 + extra.len();
        let new_phoff = (bytes.len() as u64 + 7) & !7;
        bytes.resize(new_phoff as usize + count * phentsize, 0);
        let original = LINUX_M8_FIXTURE[phdr(0)..phdr(1)].to_vec();
        bytes[new_phoff as usize..new_phoff as usize + phentsize].copy_from_slice(&original);
        put_u64(&mut bytes, EH_PHOFF, new_phoff);
        put_u16(&mut bytes, EH_PHNUM, count as u16);
        for (index, load) in extra.iter().enumerate() {
            let at = new_phoff as usize + (index + 1) * phentsize;
            put_u32(&mut bytes, at + PH_TYPE, PT_LOAD);
            put_u32(&mut bytes, at + PH_FLAGS, load.flags);
            put_u64(&mut bytes, at + PH_OFFSET, 0);
            put_u64(&mut bytes, at + PH_VADDR, load.vaddr);
            put_u64(&mut bytes, at + PH_FILESZ, load.filesz);
            put_u64(&mut bytes, at + PH_MEMSZ, load.memsz);
            put_u64(&mut bytes, at + PH_ALIGN, PAGE_SIZE);
        }
        let covered = new_phoff + (count as u64) * u64::from(ELF64_PHDR_SIZE);
        put_u64(&mut bytes, new_phoff as usize + PH_FILESZ, covered);
        put_u64(&mut bytes, new_phoff as usize + PH_MEMSZ, covered);
        bytes
    }

    fn fixture_with_second_load(vaddr: u64, memsz: u64, flags: u32) -> Vec<u8> {
        fixture_with_extra_loads(&[ExtraLoad {
            vaddr,
            filesz: 0,
            memsz,
            flags,
        }])
    }

    #[test]
    fn frozen_fixture_length_and_entry_are_pinned() {
        assert_eq!(LINUX_M8_FIXTURE.len(), FIXTURE_LEN);
        let header = Elf64Header::parse(LINUX_M8_FIXTURE).expect("header");
        assert_eq!(header.e_entry, FIXTURE_ENTRY);
        assert_eq!(header.e_type, ET_EXEC);
        assert_eq!(header.e_phentsize, ELF64_PHDR_SIZE);
        assert_eq!(header.e_phnum, FIXTURE_PHNUM);
        assert_eq!(header.e_phoff, FIXTURE_PHOFF);
    }

    #[test]
    fn policy_is_slot_128_et_exec_only() {
        // Bind through a function so the assertions are not const-folded away
        // (clippy::assertions_on_constants).
        fn policy() -> LoadPlanPolicy {
            LINUX_M8_LOAD_POLICY
        }
        let policy = policy();
        assert_eq!(policy.user_va_lo, 0x0000_4000_0000_0000);
        assert_eq!(policy.user_va_hi, 0x0000_4080_0000_0000);
        assert!(policy.reject_write_execute);
        assert!(policy.reject_page_zero);
        assert_eq!(policy.page_size, 4096);
        assert!(LINUX_M8_LOAD_POLICY.allows_e_type(ET_EXEC));
        assert!(!LINUX_M8_LOAD_POLICY.allows_e_type(clean_slate_elf::ET_DYN));
        assert!(!LINUX_M8_LOAD_POLICY.allows_e_type(clean_slate_elf::ET_REL));
    }

    #[test]
    fn frozen_fixture_validates_with_expected_plan() {
        let plan = validate_linux_image(LINUX_M8_FIXTURE).expect("fixture validates");
        assert_eq!(plan.entry, FIXTURE_ENTRY);
        assert_eq!(plan.plan.segment_count, 1);
        let segment = plan.plan.iter_segments().next().expect("one PT_LOAD");
        assert_eq!(segment.vaddr, FIXTURE_IMAGE_BASE);
        assert_eq!(segment.file_offset, 0);
        assert_eq!(segment.filesz, FIXTURE_LOAD_FILESZ);
        assert_eq!(segment.memsz, FIXTURE_LOAD_FILESZ);
        assert!(segment.perms.read && segment.perms.execute && !segment.perms.write);
        assert_eq!(plan.image_pages, 1);
        assert_eq!(plan.mapped_pages(), 1 + LINUX_STACK_PAGES);
        // root + PDPT + (PD, PT) for the code page + (PD, PT) for the stack.
        assert_eq!(plan.page_table_frames, 6);
        assert!(plan.page_table_frames <= MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES);
        assert!(plan.mapped_pages() <= MAX_ADDRESS_SPACE_USER_MAPPINGS as u64);
        assert!(!plan.plan.has_interp);
        assert!(!plan.plan.has_dynamic);
    }

    #[test]
    fn at_phdr_is_derived_from_first_load_plus_phoff() {
        let plan = validate_linux_image(LINUX_M8_FIXTURE).expect("fixture validates");
        let first = plan.plan.iter_segments().next().expect("one PT_LOAD");
        assert_eq!(plan.phdr_vaddr, first.vaddr + plan.plan.phoff);
        assert_eq!(plan.phdr_vaddr, 0x0000_4000_0040_0040);
        assert_eq!(plan.initial_stack.auxv[0], (AT_PHDR, 0x0000_4000_0040_0040));
    }

    // ---- #142: conventional low-VA policy ---------------------------------

    const LOW_VA_FIXTURE_IMAGE_BASE: u64 = 0x0000_0000_0040_0000;
    const LOW_VA_FIXTURE_ENTRY: u64 = 0x0000_0000_0040_0078;

    #[test]
    fn low_va_fixture_validates_under_conventional_policy() {
        let plan = validate_linux_low_va_image(LINUX_LOW_VA_FIXTURE)
            .expect("low-VA fixture validates under the conventional policy");
        assert_eq!(plan.entry, LOW_VA_FIXTURE_ENTRY);
        assert_eq!(plan.layout.user_region_base, LOW_VA_FIXTURE_IMAGE_BASE);
        assert_eq!(
            plan.layout.window_base,
            LINUX_CONVENTIONAL_LOAD_POLICY.user_va_lo
        );
        assert_eq!(
            plan.layout.window_end,
            LINUX_CONVENTIONAL_LOAD_POLICY.user_va_hi
        );
        assert_eq!(plan.layout.argv0, LINUX_LOW_VA_ARGV0);
        let first = plan.plan.iter_segments().next().expect("one PT_LOAD");
        assert_eq!(first.vaddr, LOW_VA_FIXTURE_IMAGE_BASE);
        assert!(first.vaddr >= LINUX_CONVENTIONAL_LOAD_POLICY.user_va_lo);
        // Stack sits above the image in the same GiB and never touches page zero.
        assert!(plan.layout.stack_guard_page > LOW_VA_FIXTURE_IMAGE_BASE);
        assert!(plan.layout.stack_top <= 1 << 30);
        assert!(
            plan.page_table_frames + KERNEL_CARVE_OUT_PRIVATE_TABLE_FRAMES
                <= MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES
        );
        assert!(plan.mapped_pages() <= MAX_ADDRESS_SPACE_USER_MAPPINGS as u64);
    }

    #[test]
    fn low_va_fixture_is_rejected_by_m8_legacy_policy() {
        assert!(
            validate_linux_image(LINUX_LOW_VA_FIXTURE).is_err(),
            "M8 legacy slot policy must not accept a conventional 0x400000 image"
        );
    }

    #[test]
    fn conventional_layout_reserves_guard_below_stack() {
        let layout = LinuxImageLayout::conventional(LOW_VA_FIXTURE_IMAGE_BASE);
        assert_eq!(layout.user_region_base, LOW_VA_FIXTURE_IMAGE_BASE);
        assert_eq!(layout.stack_guard_page + PAGE_SIZE, layout.stack_base);
        assert_eq!(
            layout.stack_top - layout.stack_base,
            LINUX_STACK_PAGES * PAGE_SIZE
        );
        assert_eq!(layout.stack_reservation_start, layout.stack_guard_page);
    }

    // ---- malformed corpus → exact variants -------------------------------

    #[test]
    fn corpus_bad_magic() {
        assert_eq!(
            validate_linux_image(BAD_MAGIC),
            Err(LinuxImageError::LoadPlan(LoadPlanError::BadMagic))
        );
    }

    #[test]
    fn corpus_elfclass32() {
        assert_eq!(
            validate_linux_image(ELFCLASS32),
            Err(LinuxImageError::LoadPlan(LoadPlanError::BadClass))
        );
    }

    #[test]
    fn corpus_big_endian() {
        assert_eq!(
            validate_linux_image(BIG_ENDIAN),
            Err(LinuxImageError::LoadPlan(LoadPlanError::BadEndian))
        );
    }

    #[test]
    fn corpus_em_aarch64() {
        assert_eq!(
            validate_linux_image(EM_AARCH64),
            Err(LinuxImageError::LoadPlan(LoadPlanError::BadMachine))
        );
    }

    #[test]
    fn corpus_et_dyn_rejected_as_not_et_exec() {
        assert_eq!(
            validate_linux_image(ET_DYN_ELF),
            Err(LinuxImageError::LoadPlan(LoadPlanError::UnsupportedEType))
        );
    }

    #[test]
    fn corpus_truncated_phdr_table() {
        assert_eq!(
            validate_linux_image(TRUNCATED_PHDR_TABLE),
            Err(LinuxImageError::LoadPlan(
                LoadPlanError::TruncatedProgramHeaders
            ))
        );
    }

    #[test]
    fn corpus_filesz_gt_memsz() {
        assert_eq!(
            validate_linux_image(FILESZ_GT_MEMSZ),
            Err(LinuxImageError::LoadPlan(
                LoadPlanError::FileszGreaterThanMemsz
            ))
        );
    }

    #[test]
    fn corpus_overlapping_pt_load_rejected_alias_policy() {
        // The corpus file is 200 bytes but both PT_LOADs claim 0x1000 file bytes,
        // so clean-slate-elf's per-segment file-range check (which runs before
        // the pairwise overlap check) fires first. Still rejected, fail closed.
        assert_eq!(
            validate_linux_image(OVERLAPPING_PT_LOAD),
            Err(LinuxImageError::LoadPlan(LoadPlanError::FileRangeBeyondEof))
        );
        // Isolate the alias policy: a second PT_LOAD sharing the fixture's code
        // page (file range in bounds) is rejected as SegmentOverlap.
        let bytes = fixture_with_second_load(FIXTURE_IMAGE_BASE, 0x10, PF_R);
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::LoadPlan(LoadPlanError::SegmentOverlap))
        );
    }

    #[test]
    fn corpus_has_pt_interp() {
        assert_eq!(
            validate_linux_image(HAS_PT_INTERP),
            Err(LinuxImageError::InterpreterNotAllowed)
        );
    }

    #[test]
    fn corpus_vaddr_kernel_range() {
        assert_eq!(
            validate_linux_image(VADDR_KERNEL_RANGE),
            Err(LinuxImageError::KernelHalfVaddr)
        );
    }

    #[test]
    fn corpus_vaddr_page_zero() {
        assert_eq!(
            validate_linux_image(VADDR_PAGE_ZERO),
            Err(LinuxImageError::PageZero)
        );
    }

    #[test]
    fn corpus_phentsize_wrong() {
        assert_eq!(
            validate_linux_image(PHENTSIZE_WRONG),
            Err(LinuxImageError::LoadPlan(LoadPlanError::BadPhentsize))
        );
    }

    #[test]
    fn corpus_offset_beyond_eof() {
        assert_eq!(
            validate_linux_image(OFFSET_BEYOND_EOF),
            Err(LinuxImageError::LoadPlan(LoadPlanError::FileRangeBeyondEof))
        );
    }

    // ---- patched-fixture cases not in the corpus -------------------------

    #[test]
    fn patched_phdr_table_beyond_file_is_truncated() {
        let mut bytes = fixture_copy();
        put_u64(&mut bytes, EH_PHOFF, (FIXTURE_LEN - 8) as u64);
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::LoadPlan(
                LoadPlanError::TruncatedProgramHeaders
            ))
        );
        let mut bytes = fixture_copy();
        put_u64(&mut bytes, EH_PHOFF, u64::MAX - 8);
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::LoadPlan(LoadPlanError::ArithmeticOverflow))
        );
    }

    #[test]
    fn patched_file_range_overflow() {
        let mut bytes = fixture_copy();
        put_u64(&mut bytes, phdr(0) + PH_OFFSET, u64::MAX - 4);
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::LoadPlan(LoadPlanError::FileRangeOverflow))
        );
    }

    #[test]
    fn patched_vaddr_plus_memsz_overflow() {
        let mut bytes = fixture_copy();
        put_u64(&mut bytes, phdr(0) + PH_VADDR, u64::MAX - 0x10);
        put_u64(&mut bytes, phdr(0) + PH_MEMSZ, 0x100);
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::VaddrOverflow)
        );
    }

    #[test]
    fn patched_identity_map_vaddr_is_distinct_from_page_zero() {
        let mut bytes = fixture_copy();
        // Classic Linux ET_EXEC base: low half, kernel identity map.
        put_u64(&mut bytes, phdr(0) + PH_VADDR, 0x0040_0000);
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::IdentityMapVaddr)
        );
    }

    #[test]
    fn patched_segment_past_window_end_is_out_of_window() {
        let mut bytes = fixture_copy();
        // Starts inside the slot but memsz runs past its end.
        put_u64(
            &mut bytes,
            phdr(0) + PH_VADDR,
            LINUX_USER_WINDOW_END - PAGE_SIZE,
        );
        put_u64(&mut bytes, phdr(0) + PH_MEMSZ, 2 * PAGE_SIZE);
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::OutOfWindow)
        );
        // The next PML4 slot (129) is outside the window even though canonical.
        let mut bytes = fixture_copy();
        put_u64(&mut bytes, phdr(0) + PH_VADDR, LINUX_USER_WINDOW_END);
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::OutOfWindow)
        );
    }

    #[test]
    fn patched_pt_dynamic_rejected() {
        let mut bytes = fixture_with_second_load(FIXTURE_IMAGE_BASE + 2 * PAGE_SIZE, 0x10, PF_R);
        let phoff = u64::from_le_bytes(bytes[EH_PHOFF..EH_PHOFF + 8].try_into().unwrap()) as usize;
        put_u32(&mut bytes, phoff + 56 + PH_TYPE, PT_DYNAMIC);
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::DynamicNotAllowed)
        );
    }

    #[test]
    fn patched_align_two_rejected_below_page_size() {
        let mut bytes = fixture_copy();
        put_u64(&mut bytes, phdr(0) + PH_ALIGN, 2);
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::AlignmentBelowPageSize)
        );
        // 0 and 1 are accepted (no alignment constraint).
        for align in [0u64, 1] {
            let mut bytes = fixture_copy();
            put_u64(&mut bytes, phdr(0) + PH_ALIGN, align);
            assert!(validate_linux_image(&bytes).is_ok(), "align {align}");
        }
    }

    #[test]
    fn patched_non_power_of_two_align_rejected() {
        let mut bytes = fixture_copy();
        put_u64(&mut bytes, phdr(0) + PH_ALIGN, 0x1800);
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::LoadPlan(LoadPlanError::AlignmentViolation))
        );
    }

    #[test]
    fn patched_vaddr_offset_congruence_violation() {
        let mut bytes = fixture_copy();
        put_u64(&mut bytes, phdr(0) + PH_VADDR, FIXTURE_IMAGE_BASE + 0x10);
        put_u64(&mut bytes, EH_ENTRY, FIXTURE_ENTRY + 0x10);
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::LoadPlan(
                LoadPlanError::OffsetVaddrCongruenceViolation
            ))
        );
    }

    #[test]
    fn patched_write_execute_segment_rejected() {
        let mut bytes = fixture_copy();
        put_u32(&mut bytes, phdr(0) + PH_FLAGS, PF_R | PF_W | PF_X);
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::LoadPlan(
                LoadPlanError::WriteExecuteConflict
            ))
        );
    }

    #[test]
    fn patched_entry_outside_executable_segment() {
        let mut bytes = fixture_copy();
        put_u64(&mut bytes, EH_ENTRY, FIXTURE_IMAGE_BASE + PAGE_SIZE);
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::LoadPlan(
                LoadPlanError::EntryOutsideExecutableSegment
            ))
        );
        // Entry inside a non-executable PT_LOAD is also rejected.
        let mut bytes = fixture_copy();
        put_u32(&mut bytes, phdr(0) + PH_FLAGS, PF_R);
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::LoadPlan(
                LoadPlanError::EntryOutsideExecutableSegment
            ))
        );
    }

    #[test]
    fn patched_zero_load_segments_rejected() {
        let mut bytes = fixture_copy();
        put_u32(&mut bytes, phdr(0) + PH_TYPE, 4); // PT_NOTE
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::LoadPlan(LoadPlanError::NoLoadSegments))
        );
    }

    #[test]
    fn patched_segment_count_over_budget_rejected() {
        // Fixture with 17 PT_LOADs: distinct, in-window, RW, no file bytes.
        let mut bytes = fixture_copy();
        let new_phoff = (bytes.len() as u64 + 7) & !7;
        let count = MAX_LOAD_SEGMENTS + 1;
        bytes.resize(new_phoff as usize + count * 56, 0);
        let original = LINUX_M8_FIXTURE[phdr(0)..phdr(1)].to_vec();
        bytes[new_phoff as usize..new_phoff as usize + 56].copy_from_slice(&original);
        put_u64(&mut bytes, EH_PHOFF, new_phoff);
        put_u16(&mut bytes, EH_PHNUM, count as u16);
        let covered = new_phoff + (count as u64) * 56;
        put_u64(&mut bytes, new_phoff as usize + PH_FILESZ, covered);
        put_u64(&mut bytes, new_phoff as usize + PH_MEMSZ, covered);
        for index in 1..count {
            let at = new_phoff as usize + index * 56;
            put_u32(&mut bytes, at + PH_TYPE, PT_LOAD);
            put_u32(&mut bytes, at + PH_FLAGS, PF_R | PF_W);
            put_u64(&mut bytes, at + PH_OFFSET, 0);
            put_u64(
                &mut bytes,
                at + PH_VADDR,
                FIXTURE_IMAGE_BASE + (index as u64 + 1) * PAGE_SIZE,
            );
            put_u64(&mut bytes, at + PH_FILESZ, 0);
            put_u64(&mut bytes, at + PH_MEMSZ, 0x10);
            put_u64(&mut bytes, at + PH_ALIGN, PAGE_SIZE);
        }
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::LoadPlan(
                LoadPlanError::SegmentBudgetExceeded
            ))
        );
    }

    #[test]
    fn patched_segment_in_stack_reservation_rejected() {
        // Guard page itself.
        let bytes = fixture_with_second_load(LINUX_STACK_GUARD_PAGE, 0x10, PF_R | PF_W);
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::SegmentOverlapsStackReservation)
        );
        // Stack pages (page-aligned so the congruence rule does not fire first).
        let bytes = fixture_with_second_load(LINUX_STACK_BASE + PAGE_SIZE, 0x10, PF_R | PF_W);
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::SegmentOverlapsStackReservation)
        );
        // Unmapped top page of the slot.
        let bytes = fixture_with_second_load(LINUX_STACK_TOP, 0x10, PF_R | PF_W);
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::SegmentOverlapsStackReservation)
        );
        // A segment ending exactly at the reservation start is fine.
        let bytes = fixture_with_second_load(
            LINUX_STACK_RESERVATION_START - PAGE_SIZE,
            PAGE_SIZE,
            PF_R | PF_W,
        );
        let plan = validate_linux_image(&bytes).expect("adjacent segment is allowed");
        assert_eq!(plan.image_pages, 2);
    }

    #[test]
    fn patched_mapping_budget_exceeded_before_mapping() {
        // Enough RW BSS pages to exceed MAX_ADDRESS_SPACE_USER_MAPPINGS with the stack.
        let bss_pages = MAX_ADDRESS_SPACE_USER_MAPPINGS as u64 - LINUX_STACK_PAGES;
        let bytes = fixture_with_second_load(
            FIXTURE_IMAGE_BASE + 2 * PAGE_SIZE,
            bss_pages * PAGE_SIZE,
            PF_R | PF_W,
        );
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::MappingBudgetExceeded)
        );
        // One page fewer fits exactly.
        let bytes = fixture_with_second_load(
            FIXTURE_IMAGE_BASE + 2 * PAGE_SIZE,
            (bss_pages - 1) * PAGE_SIZE,
            PF_R | PF_W,
        );
        let plan = validate_linux_image(&bytes).expect("exactly at the bound");
        assert_eq!(plan.mapped_pages(), MAX_ADDRESS_SPACE_USER_MAPPINGS as u64);
    }

    #[test]
    fn patched_program_headers_outside_load_rejected() {
        // Shrink PT_LOAD[0] so it no longer covers the phdr table (still covers entry).
        let mut bytes = fixture_copy();
        put_u64(&mut bytes, phdr(0) + PH_OFFSET, 0x78);
        put_u64(&mut bytes, phdr(0) + PH_VADDR, FIXTURE_IMAGE_BASE + 0x78);
        put_u64(&mut bytes, phdr(0) + PH_FILESZ, (FIXTURE_LEN - 0x78) as u64);
        put_u64(&mut bytes, phdr(0) + PH_MEMSZ, (FIXTURE_LEN - 0x78) as u64);
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::ProgramHeadersNotMapped)
        );
    }

    #[test]
    fn empty_and_short_inputs_fail_closed() {
        assert_eq!(
            validate_linux_image(&[]),
            Err(LinuxImageError::LoadPlan(LoadPlanError::TruncatedHeader))
        );
        assert_eq!(
            validate_linux_image(&LINUX_M8_FIXTURE[..ELF64_EHDR_SIZE - 1]),
            Err(LinuxImageError::LoadPlan(LoadPlanError::TruncatedHeader))
        );
    }

    // ---- zero-fill / BSS planning --------------------------------------

    #[test]
    fn synthetic_bss_segment_plans_zero_fill_and_page_demand() {
        // memsz > filesz on a data segment: 0x10 file bytes then 0x30 of BSS in
        // the same (partial tail) page. Stays inside the default mapping budget
        // (1 code + 1 data + 2 stack = 4).
        let bytes = fixture_with_extra_loads(&[ExtraLoad {
            vaddr: FIXTURE_IMAGE_BASE + 2 * PAGE_SIZE,
            filesz: 0x10,
            memsz: 0x40,
            flags: PF_R | PF_W,
        }]);
        let plan = validate_linux_image(&bytes).expect("bss segment validates");
        let data = plan
            .plan
            .iter_segments()
            .find(|segment| segment.perms.write)
            .expect("data segment");
        assert_eq!(data.filesz, 0x10);
        assert_eq!(data.memsz, 0x40);
        assert_eq!(
            data.zero_fill_range().unwrap(),
            Some((data.vaddr + 0x10, data.vaddr + 0x40))
        );
        assert_eq!(data.mapped_page_count(PAGE_SIZE).unwrap(), 1);
        assert_eq!(plan.image_pages, 2);
        assert_eq!(plan.mapped_pages(), 4);
        // Per-page decision (image_loader::page_file_span): only the first 0x10
        // bytes of the page are file-backed; the rest of the page is zero-filled
        // by the frame zeroing in map_load_plan_segments.
        let span = crate::mm::image_loader::page_file_span(data.vaddr, data.vaddr, data.filesz)
            .unwrap()
            .expect("file-backed prefix");
        assert_eq!((span.page_offset, span.file_rel, span.len), (0, 0, 0x10));
        // A pure-BSS page (memsz spilling into a second page) carries no file bytes.
        assert_eq!(
            crate::mm::image_loader::page_file_span(
                data.vaddr + PAGE_SIZE,
                data.vaddr,
                data.filesz
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn partial_tail_page_zero_fill_arithmetic() {
        // Segment with 0x20 file bytes and 0x1010 memsz starting mid-page.
        let segment = clean_slate_elf::LoadSegment {
            vaddr: FIXTURE_IMAGE_BASE + 0x800,
            memsz: 0x1010,
            file_offset: 0x800,
            filesz: 0x20,
            align: PAGE_SIZE,
            perms: clean_slate_elf::SegmentPermissions::from_p_flags(PF_R | PF_W),
        };
        assert_eq!(
            segment.zero_fill_range().unwrap(),
            Some((FIXTURE_IMAGE_BASE + 0x820, FIXTURE_IMAGE_BASE + 0x1810))
        );
        assert_eq!(segment.mapped_page_count(PAGE_SIZE).unwrap(), 2);
        // Page 0: file bytes at page offset 0x800..0x820, remainder zero.
        assert_eq!(
            crate::mm::image_loader::page_file_span(
                FIXTURE_IMAGE_BASE,
                segment.vaddr,
                segment.filesz
            )
            .unwrap(),
            Some(crate::mm::image_loader::PageFileSpan {
                page_offset: 0x800,
                file_rel: 0,
                len: 0x20,
            })
        );
        // Page 1: pure zero fill.
        assert_eq!(
            crate::mm::image_loader::page_file_span(
                FIXTURE_IMAGE_BASE + PAGE_SIZE,
                segment.vaddr,
                segment.filesz
            )
            .unwrap(),
            None
        );
    }

    // ---- stack placement / page-table demand -----------------------------

    #[test]
    fn stack_layout_constants_are_consistent() {
        assert_eq!(LINUX_STACK_TOP, 0x0000_407f_ffff_f000);
        assert_eq!(LINUX_STACK_BASE, LINUX_STACK_TOP - 2 * PAGE_SIZE);
        assert_eq!(LINUX_STACK_GUARD_PAGE, LINUX_STACK_BASE - PAGE_SIZE);
        assert_eq!(LINUX_STACK_RESERVATION_START, LINUX_STACK_GUARD_PAGE);
        // Reservation is strictly inside the window (via a fn so the comparison
        // is not const-folded by clippy::assertions_on_constants).
        fn window() -> (u64, u64) {
            (LINUX_USER_WINDOW_BASE, LINUX_USER_WINDOW_END)
        }
        let (window_base, window_end) = window();
        assert!(LINUX_STACK_GUARD_PAGE > window_base);
        assert!(LINUX_STACK_TOP < window_end);
    }

    #[test]
    fn page_table_demand_counts_distinct_tables() {
        // One page: root + PDPT + PD + PT.
        assert_eq!(
            page_table_frame_demand(&[(FIXTURE_IMAGE_BASE, FIXTURE_IMAGE_BASE + PAGE_SIZE)])
                .unwrap(),
            4
        );
        // Two pages in the same 2 MiB region share PD and PT.
        assert_eq!(
            page_table_frame_demand(&[
                (FIXTURE_IMAGE_BASE, FIXTURE_IMAGE_BASE + PAGE_SIZE),
                (
                    FIXTURE_IMAGE_BASE + 8 * PAGE_SIZE,
                    FIXTURE_IMAGE_BASE + 9 * PAGE_SIZE
                ),
            ])
            .unwrap(),
            4
        );
        // Code page + stack at the top of the slot: separate PD and PT each.
        assert_eq!(
            page_table_frame_demand(&[
                (FIXTURE_IMAGE_BASE, FIXTURE_IMAGE_BASE + PAGE_SIZE),
                (LINUX_STACK_BASE, LINUX_STACK_TOP),
            ])
            .unwrap(),
            6
        );
        // A range crossing a 2 MiB boundary needs two PTs, one PD.
        assert_eq!(
            page_table_frame_demand(&[(
                FIXTURE_IMAGE_BASE + PAGE_TABLE_SPAN - PAGE_SIZE,
                FIXTURE_IMAGE_BASE + PAGE_TABLE_SPAN + PAGE_SIZE
            )])
            .unwrap(),
            5
        );
        // Empty ranges are ignored.
        assert_eq!(page_table_frame_demand(&[(0x1000, 0x1000)]).unwrap(), 2);
    }

    #[test]
    fn page_table_demand_over_budget_fails_closed() {
        // Nine distinct 2 MiB regions exceed any budget (root + PDPT + PD + 9 PTs).
        let mut ranges = [(0u64, 0u64); MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES + 1];
        for (index, range) in ranges.iter_mut().enumerate() {
            let start = FIXTURE_IMAGE_BASE + (index as u64) * PAGE_TABLE_SPAN;
            *range = (start, start + PAGE_SIZE);
        }
        assert_eq!(
            page_table_frame_demand(&ranges),
            Err(LinuxImageError::PageTableBudgetExceeded)
        );
        // A single huge segment is bounded by the same early exit.
        assert_eq!(
            page_table_frame_demand(&[(LINUX_USER_WINDOW_BASE, LINUX_STACK_RESERVATION_START)]),
            Err(LinuxImageError::PageTableBudgetExceeded)
        );
    }

    #[test]
    fn patched_image_page_table_demand_is_exact() {
        // Second segment one 1 GiB region away: needs its own PD and PT.
        // root + PDPT + (PD + PT) code + (PD + PT) data + (PD + PT) stack = 8,
        // exactly the default page-table tier.
        let bytes =
            fixture_with_second_load(FIXTURE_IMAGE_BASE + PAGE_DIRECTORY_SPAN, 0x10, PF_R | PF_W);
        let plan = validate_linux_image(&bytes).expect("three-region image");
        assert_eq!(plan.page_table_frames, 8);
        assert!(
            plan.page_table_frames
                .saturating_add(KERNEL_CARVE_OUT_PRIVATE_TABLE_FRAMES)
                <= MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES
        );
        // Same 1 GiB region, different 2 MiB region: shares the PD, needs a PT.
        let bytes =
            fixture_with_second_load(FIXTURE_IMAGE_BASE + PAGE_TABLE_SPAN, 0x10, PF_R | PF_W);
        let plan = validate_linux_image(&bytes).expect("two-PT image");
        assert_eq!(plan.page_table_frames, 7);
    }

    #[test]
    fn patched_image_over_page_table_budget_rejected() {
        // Three extra single-page segments in distinct 1 GiB regions push demand
        // to root + PDPT + 4×(PD + PT) + (PD + PT) stack = 12 > any budget tier
        // that the mapping budget would otherwise admit; the page-table check
        // runs first so this is the variant reported. Only meaningful at the
        // default 8-frame tier; larger tiers are exercised by the pure helper.
        if MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES >= 12 {
            return;
        }
        let extra: Vec<ExtraLoad> = (1..=3u64)
            .map(|region| ExtraLoad {
                vaddr: FIXTURE_IMAGE_BASE + region * PAGE_DIRECTORY_SPAN,
                filesz: 0,
                memsz: 0x10,
                flags: PF_R | PF_W,
            })
            .collect();
        let bytes = fixture_with_extra_loads(&extra);
        assert_eq!(
            validate_linux_image(&bytes),
            Err(LinuxImageError::PageTableBudgetExceeded)
        );
    }

    // ---- initial stack bytes --------------------------------------------

    fn read_u64_at(stack: &LinuxInitialStack, vaddr: u64) -> u64 {
        let base = stack.image_base();
        assert!(
            vaddr >= base && vaddr + 8 <= LINUX_STACK_TOP,
            "vaddr {vaddr:#x} outside image"
        );
        let offset = (vaddr - base) as usize;
        u64::from_le_bytes(stack.bytes[offset..offset + 8].try_into().unwrap())
    }

    #[test]
    fn initial_stack_bytes_match_linux_contract() {
        let plan = validate_linux_image(LINUX_M8_FIXTURE).expect("fixture validates");
        let stack = &plan.initial_stack;
        let rsp = stack.rsp;
        assert_eq!(rsp % 16, 0);
        assert!((LINUX_STACK_BASE..LINUX_STACK_TOP).contains(&rsp));
        // The whole image lives in the top stack page.
        assert!(stack.image_base() >= LINUX_STACK_TOP - PAGE_SIZE);

        let mut cursor = rsp;
        assert_eq!(read_u64_at(stack, cursor), 1, "argc");
        cursor += 8;
        let argv0_ptr = read_u64_at(stack, cursor);
        cursor += 8;
        assert_eq!(read_u64_at(stack, cursor), 0, "argv NULL");
        cursor += 8;
        assert_eq!(read_u64_at(stack, cursor), 0, "envp NULL");
        cursor += 8;
        let expected_auxv = [
            (AT_PHDR, 0x0000_4000_0040_0040u64),
            (AT_PHENT, 56),
            (AT_PHNUM, u64::from(FIXTURE_PHNUM)),
            (AT_PAGESZ, 4096),
            (AT_ENTRY, FIXTURE_ENTRY),
        ];
        assert_eq!(stack.auxv[..LINUX_AUXV_ENTRIES], expected_auxv);
        for (a_type, a_val) in expected_auxv {
            assert_eq!(read_u64_at(stack, cursor), a_type);
            assert_eq!(read_u64_at(stack, cursor + 8), a_val);
            cursor += 16;
        }
        assert_eq!(read_u64_at(stack, cursor), AT_NULL);
        assert_eq!(read_u64_at(stack, cursor + 8), 0);
        cursor += 16;
        // Vectors end below the strings; strings end at the stack top.
        assert!(cursor <= argv0_ptr);
        assert!(argv0_ptr >= rsp && argv0_ptr < LINUX_STACK_TOP);
        let str_off = (argv0_ptr - stack.image_base()) as usize;
        assert_eq!(
            &stack.bytes[str_off..str_off + LINUX_ARGV0.len() + 1],
            b"hello-linux-x86_64\0"
        );
        assert_eq!(argv0_ptr + LINUX_ARGV0.len() as u64 + 1, LINUX_STACK_TOP);
        // Bytes below RSP are untouched zeros.
        let rsp_off = (rsp - stack.image_base()) as usize;
        assert!(stack.bytes[..rsp_off].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn initial_stack_every_pointer_is_inside_the_stack_range() {
        let plan = validate_linux_image(LINUX_M8_FIXTURE).expect("fixture validates");
        let stack = &plan.initial_stack;
        let argv0_ptr = read_u64_at(stack, stack.rsp + 8);
        for pointer in [stack.rsp, argv0_ptr] {
            assert!((LINUX_STACK_BASE..LINUX_STACK_TOP).contains(&pointer));
        }
        // The launch RSP the kernel hands to the entry frame is the same value.
        assert_eq!(plan.launch_rsp(), stack.rsp);
    }

    #[test]
    fn initial_stack_rejects_premature_at_null_from_builder() {
        // The pure builder is the only path; confirm the abi crate's error maps.
        let mut buffer = [0u8; LINUX_INITIAL_STACK_IMAGE_BYTES];
        let error = build_initial_stack(
            &mut buffer,
            LINUX_STACK_TOP,
            &[LINUX_ARGV0],
            &[],
            &[(AT_NULL, 0)],
        )
        .unwrap_err();
        assert_eq!(
            LinuxImageError::InitialStack(error),
            LinuxImageError::InitialStack(StackLayoutError::PrematureAtNull)
        );
        assert_eq!(
            LinuxImageError::InitialStack(error).description(),
            "linux image: initial stack auxv contained AT_NULL"
        );
    }

    #[test]
    fn error_descriptions_are_non_empty_and_distinct_for_window_checks() {
        let errors = [
            LinuxImageError::PageZero,
            LinuxImageError::IdentityMapVaddr,
            LinuxImageError::KernelHalfVaddr,
            LinuxImageError::OutOfWindow,
            LinuxImageError::InterpreterNotAllowed,
            LinuxImageError::DynamicNotAllowed,
            LinuxImageError::SegmentOverlapsStackReservation,
            LinuxImageError::MappingBudgetExceeded,
            LinuxImageError::PageTableBudgetExceeded,
            LinuxImageError::GuardPageMapped,
        ];
        for (index, error) in errors.iter().enumerate() {
            assert!(!error.description().is_empty());
            for other in &errors[index + 1..] {
                assert_ne!(error.description(), other.description());
            }
        }
        assert_eq!(
            LinuxImageError::from(LoadPlanError::BadMagic).description(),
            "linux image: bad ELF magic"
        );
        assert_eq!(
            LinuxImageError::SegmentMapping("mapper said no").description(),
            "mapper said no"
        );
    }
}
