//! Per-process address spaces: cloning the kernel half of the root table,
//! mapping user pages into a process root, activating a root and tearing an
//! address space down. Owns `KERNEL_ROOT_FRAME`.

use crate::arch::x86_64::cpu::without_write_protect;
use crate::diagnostics::serial::serial_write_line;
use crate::mm::align_down;
use crate::mm::carve_out_shared::{
    for_each_shared_two_mib_table, shared_carve_out_page_table_frame,
};
use crate::mm::frame_allocator::free_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::layout::{
    kernel_low_reserved_ranges, va_overlaps_kernel_low_reserved, KERNEL_USER_PML4_SLOT_END,
};
use crate::mm::paging::assert_carve_out_directory_path_has_no_nx;
use crate::mm::paging::leaf_page_flags_for_address_in_root;
use crate::mm::paging::leaf_phys_addr_for_address_in_root;
use crate::mm::paging::level2_table_frame_for_address_in_root;
use crate::mm::USER_CANONICAL_TOP_EXCLUSIVE;

pub(crate) use crate::mm::carve_out_shared::KERNEL_CARVE_OUT_PRIVATE_TABLE_FRAMES;
use crate::mm::paging::offset_page_table_for_root;
use crate::mm::paging::page_table_mut;
use crate::mm::paging::page_table_ref;
use crate::mm::paging::zero_page;
use crate::mm::user_mapping::unmap_userspace_page;
use crate::mm::PAGE_SIZE;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::FrameAllocator;
use x86_64::structures::paging::Mapper;
use x86_64::structures::paging::Page;
use x86_64::structures::paging::PageTable;
use x86_64::structures::paging::PageTableFlags;
use x86_64::structures::paging::PhysFrame;
use x86_64::structures::paging::Size4KiB;
use x86_64::structures::paging::Translate;
use x86_64::PhysAddr;
use x86_64::VirtAddr;

use crate::sync::global_cell::GlobalCell;

// `ProcessAddressSpace` is moved by value through the spawn/exec/fork paths on
// a per-thread kernel stack. Its user-mapping table lives out of line in a
// bounded pool (`UserMappingTableSlot`); the page-table frame list below stays
// inline, so it must stay small.
use crate::limits::BASE_ADDRESS_SPACE_PAGE_TABLE_FRAMES;
use crate::limits::LARGE_USER_MAPPING_TABLES;
pub(crate) use crate::limits::MAX_ADDRESS_SPACE_USER_MAPPINGS;
pub(crate) use crate::limits::SMALL_ADDRESS_SPACE_USER_MAPPINGS;

pub(crate) const MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES: usize =
    BASE_ADDRESS_SPACE_PAGE_TABLE_FRAMES + KERNEL_CARVE_OUT_PRIVATE_TABLE_FRAMES;

const _: () = assert!(SMALL_ADDRESS_SPACE_USER_MAPPINGS <= MAX_ADDRESS_SPACE_USER_MAPPINGS);

static KERNEL_ROOT_FRAME: AtomicU64 = AtomicU64::new(0);

/// Physical frame of the kernel's own root page table (relaxed load).
pub(crate) fn kernel_root_frame() -> u64 {
    KERNEL_ROOT_FRAME.load(Ordering::Relaxed)
}

/// Fault diagnostics: where the kernel root frame is stored, to spot stray writes.
pub(crate) fn kernel_root_frame_storage_address() -> u64 {
    core::ptr::addr_of!(KERNEL_ROOT_FRAME) as u64
}

/// Records the kernel's root page-table frame at boot (relaxed store).
pub(crate) fn set_kernel_root_frame(frame: u64) {
    KERNEL_ROOT_FRAME.store(frame, Ordering::Relaxed);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OwnedUserMapping {
    pub(crate) virtual_address: u64,
    pub(crate) frame_address: u64,
}

impl OwnedUserMapping {
    const EMPTY: Self = Self {
        virtual_address: 0,
        frame_address: 0,
    };
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AddressSpaceResourceCounts {
    pub(crate) user_pages: usize,
    pub(crate) page_table_frames: usize,
}

type SmallUserMappingTable = [OwnedUserMapping; SMALL_ADDRESS_SPACE_USER_MAPPINGS];
type LargeUserMappingTable = [OwnedUserMapping; MAX_ADDRESS_SPACE_USER_MAPPINGS];

/// Address spaces that can own a mapping table at once: every process
/// registry slot plus spaces in flight (an exec replacement or fork child
/// before it is committed, a spawn before registration, self-test fixtures).
const USER_MAPPING_TABLE_POOL_SIZE: usize = crate::process::PROCESS_REGISTRY_CAPACITY + 8;

struct UserMappingTablePool {
    is_claimed: [bool; USER_MAPPING_TABLE_POOL_SIZE],
    tables: [SmallUserMappingTable; USER_MAPPING_TABLE_POOL_SIZE],
}

static USER_MAPPING_TABLES: GlobalCell<UserMappingTablePool> =
    GlobalCell::new(UserMappingTablePool {
        is_claimed: [false; USER_MAPPING_TABLE_POOL_SIZE],
        tables: [[OwnedUserMapping::EMPTY; SMALL_ADDRESS_SPACE_USER_MAPPINGS];
            USER_MAPPING_TABLE_POOL_SIZE],
    });

/// Tables a space moves to when it outgrows its small one (#293).
struct LargeUserMappingTablePool {
    is_claimed: [bool; LARGE_USER_MAPPING_TABLES],
    tables: [LargeUserMappingTable; LARGE_USER_MAPPING_TABLES],
}

static LARGE_USER_MAPPING_TABLES_POOL: GlobalCell<LargeUserMappingTablePool> =
    GlobalCell::new(LargeUserMappingTablePool {
        is_claimed: [false; LARGE_USER_MAPPING_TABLES],
        tables: [[OwnedUserMapping::EMPTY; MAX_ADDRESS_SPACE_USER_MAPPINGS];
            LARGE_USER_MAPPING_TABLES],
    });

/// Self-test switch: while set, no space can move to a large table, so a
/// lane can fill a small table and prove the refusal path.
#[cfg(feature = "m9-syscall-fail-closed-self-test")]
static LARGE_TABLES_WITHHELD: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "m9-syscall-fail-closed-self-test")]
pub(crate) fn withhold_large_mapping_tables_for_selftest(withheld: bool) {
    LARGE_TABLES_WITHHELD.store(withheld, Ordering::Relaxed);
}

fn large_tables_withheld() -> bool {
    #[cfg(feature = "m9-syscall-fail-closed-self-test")]
    {
        LARGE_TABLES_WITHHELD.load(Ordering::Relaxed)
    }
    #[cfg(not(feature = "m9-syscall-fail-closed-self-test"))]
    {
        false
    }
}

/// Large tables not claimed by any address space.
#[cfg_attr(
    not(any(test, feature = "m9-syscall-fail-closed-self-test")),
    allow(dead_code)
)]
pub(crate) fn free_large_mapping_tables() -> usize {
    let pool = unsafe { &*LARGE_USER_MAPPING_TABLES_POOL.get() };
    pool.is_claimed
        .iter()
        .filter(|is_claimed| !**is_claimed)
        .count()
}

/// Exclusive owner of one pooled mapping table, returned to its pool on drop.
/// Keeping the table out of line leaves `ProcessAddressSpace` a few hundred
/// bytes, so the spawn/exec/fork paths can move it by value without
/// multi-KiB stack copies.
#[derive(Debug)]
enum UserMappingTableSlot {
    Small(usize),
    Large(usize),
}

impl UserMappingTableSlot {
    fn claim() -> Result<Self, &'static str> {
        let pool = unsafe { &mut *USER_MAPPING_TABLES.get() };
        let index = pool
            .is_claimed
            .iter()
            .position(|is_claimed| !is_claimed)
            .ok_or("process address-space mapping table pool exhausted")?;
        pool.is_claimed[index] = true;
        pool.tables[index].fill(OwnedUserMapping::EMPTY);
        Ok(Self::Small(index))
    }

    fn claim_large() -> Result<Self, &'static str> {
        if large_tables_withheld() {
            return Err("process address-space large mapping table pool exhausted");
        }
        let pool = unsafe { &mut *LARGE_USER_MAPPING_TABLES_POOL.get() };
        let index = pool
            .is_claimed
            .iter()
            .position(|is_claimed| !is_claimed)
            .ok_or("process address-space large mapping table pool exhausted")?;
        pool.is_claimed[index] = true;
        // In place: a temporary 256 KiB array would not fit on a kernel stack.
        pool.tables[index].fill(OwnedUserMapping::EMPTY);
        Ok(Self::Large(index))
    }

    fn table(&self) -> &[OwnedUserMapping] {
        match *self {
            Self::Small(index) => unsafe { &(*USER_MAPPING_TABLES.get()).tables[index] },
            Self::Large(index) => unsafe { &(*LARGE_USER_MAPPING_TABLES_POOL.get()).tables[index] },
        }
    }

    fn table_mut(&mut self) -> &mut [OwnedUserMapping] {
        match *self {
            Self::Small(index) => unsafe { &mut (*USER_MAPPING_TABLES.get()).tables[index] },
            Self::Large(index) => unsafe {
                &mut (*LARGE_USER_MAPPING_TABLES_POOL.get()).tables[index]
            },
        }
    }

    fn capacity(&self) -> usize {
        self.table().len()
    }
}

impl Drop for UserMappingTableSlot {
    fn drop(&mut self) {
        match *self {
            Self::Small(index) => {
                let pool = unsafe { &mut *USER_MAPPING_TABLES.get() };
                pool.is_claimed[index] = false;
            }
            Self::Large(index) => {
                let pool = unsafe { &mut *LARGE_USER_MAPPING_TABLES_POOL.get() };
                pool.is_claimed[index] = false;
            }
        }
    }
}

impl PartialEq for UserMappingTableSlot {
    fn eq(&self, other: &Self) -> bool {
        self.table() == other.table()
    }
}

impl Eq for UserMappingTableSlot {}

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ProcessAddressSpace {
    pub(crate) root_frame: u64,
    page_table_frames: [u64; MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES],
    page_table_frame_count: usize,
    user_mappings: UserMappingTableSlot,
    user_mapping_count: usize,
}

#[allow(dead_code)]
impl ProcessAddressSpace {
    fn new(root_frame: u64) -> Result<Self, &'static str> {
        let mut address_space = Self {
            root_frame,
            page_table_frames: [0; MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES],
            page_table_frame_count: 0,
            user_mappings: UserMappingTableSlot::claim()?,
            user_mapping_count: 0,
        };
        address_space.record_page_table_frame(root_frame)?;
        Ok(address_space)
    }

    fn record_page_table_frame(&mut self, frame_address: u64) -> Result<(), &'static str> {
        if self.page_table_frame_count == self.page_table_frames.len() {
            return Err("process address-space page-table tracking capacity exceeded");
        }
        self.page_table_frames[self.page_table_frame_count] = frame_address;
        self.page_table_frame_count += 1;
        Ok(())
    }

    /// Makes room for one more tracked page. A full small table moves to a
    /// large one; nothing changes when no large table is free.
    fn ensure_user_mapping_capacity(&mut self) -> Result<(), &'static str> {
        if self.user_mapping_count < self.user_mappings.capacity() {
            return Ok(());
        }
        if matches!(self.user_mappings, UserMappingTableSlot::Large(_)) {
            return Err("process address-space mapping tracking capacity exceeded");
        }
        let mut large = UserMappingTableSlot::claim_large()
            .map_err(|_| "process address-space mapping tracking capacity exceeded")?;
        let count = self.user_mapping_count;
        large.table_mut()[..count].copy_from_slice(&self.user_mappings.table()[..count]);
        // Dropping the small slot returns it to its pool.
        self.user_mappings = large;
        Ok(())
    }

    fn record_user_mapping(
        &mut self,
        virtual_address: u64,
        frame_address: u64,
    ) -> Result<(), &'static str> {
        self.ensure_user_mapping_capacity()?;
        self.user_mappings.table_mut()[self.user_mapping_count] = OwnedUserMapping {
            virtual_address,
            frame_address,
        };
        self.user_mapping_count += 1;
        Ok(())
    }

    /// Pages the current table can track before it must grow.
    pub(crate) fn user_mapping_capacity(&self) -> usize {
        self.user_mappings.capacity()
    }

    pub(crate) fn resource_counts(&self) -> AddressSpaceResourceCounts {
        AddressSpaceResourceCounts {
            user_pages: self.user_mapping_count,
            page_table_frames: self.page_table_frame_count,
        }
    }

    pub(crate) fn user_mapping_count(&self) -> usize {
        self.user_mapping_count
    }

    pub(crate) fn user_mapping_at(&self, index: usize) -> Option<OwnedUserMapping> {
        if index >= self.user_mapping_count {
            return None;
        }
        Some(self.user_mappings.table()[index])
    }

    fn user_mappings(&self) -> &[OwnedUserMapping] {
        &self.user_mappings.table()[..self.user_mapping_count]
    }
}

#[allow(dead_code)]
struct AddressSpaceFrameAllocator<'a, 'space> {
    allocator: &'a mut PageAllocator,
    address_space: &'space mut ProcessAddressSpace,
}

#[allow(dead_code)]
impl<'a, 'space> AddressSpaceFrameAllocator<'a, 'space> {
    fn new(
        allocator: &'a mut PageAllocator,
        address_space: &'space mut ProcessAddressSpace,
    ) -> Self {
        Self {
            allocator,
            address_space,
        }
    }
}

#[allow(dead_code)]
unsafe impl FrameAllocator<Size4KiB> for AddressSpaceFrameAllocator<'_, '_> {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let frame_address = self.allocator.allocate_page()?;
        if self
            .address_space
            .record_page_table_frame(frame_address)
            .is_err()
        {
            unsafe {
                let _ = self.allocator.free_page(frame_address);
            }
            return None;
        }
        Some(PhysFrame::containing_address(PhysAddr::new(frame_address)))
    }
}

#[allow(dead_code)]
pub(crate) fn activate_address_space_root(root_frame: u64) {
    let flags = Cr3::read().1;
    unsafe {
        Cr3::write(
            PhysFrame::containing_address(PhysAddr::new(root_frame)),
            flags,
        );
    }
}

#[allow(dead_code)]
fn sanitize_kernel_root_entries(root: &mut PageTable, _user_region_base: VirtAddr) {
    for (index, entry) in root.iter_mut().enumerate() {
        if index < KERNEL_USER_PML4_SLOT_END {
            entry.set_unused();
            continue;
        }
        if entry.is_unused() {
            continue;
        }
        entry.set_addr(
            entry.addr(),
            entry.flags() & !PageTableFlags::USER_ACCESSIBLE,
        );
    }
}

#[allow(dead_code)]
pub(crate) fn validate_supervisor_only_kernel_root_entries(
    root: &PageTable,
    _user_region_base: VirtAddr,
) -> Result<(), &'static str> {
    for (index, entry) in root.iter().enumerate() {
        if index < KERNEL_USER_PML4_SLOT_END || entry.is_unused() {
            continue;
        }
        if entry.flags().contains(PageTableFlags::USER_ACCESSIBLE) {
            return Err("inherited kernel root entry remained user accessible");
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn clone_kernel_mappings_into_address_space(
    address_space: &mut ProcessAddressSpace,
    user_region_base: VirtAddr,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    let source_root = unsafe { page_table_ref(kernel_root_frame()) };
    let destination_root = unsafe { page_table_mut(address_space.root_frame) };
    for (index, (destination, source)) in destination_root
        .iter_mut()
        .zip(source_root.iter())
        .enumerate()
    {
        if index < KERNEL_USER_PML4_SLOT_END {
            destination.set_unused();
            continue;
        }
        if source.is_unused() {
            destination.set_unused();
            continue;
        }
        destination.set_addr(
            source.addr(),
            source.flags() & !PageTableFlags::USER_ACCESSIBLE,
        );
    }
    attach_shared_carve_outs_to_process(address_space, allocator)?;
    validate_supervisor_only_kernel_root_entries(destination_root, user_region_base)
}

fn pd_entry_points_at_shared_carve_out_pt(root_frame: u64, virtual_address: u64) -> bool {
    if virtual_address >= USER_CANONICAL_TOP_EXCLUSIVE {
        return false;
    }
    let virt = VirtAddr::new(virtual_address);
    match level2_table_frame_for_address_in_root(root_frame, virt) {
        Ok(frame) => shared_carve_out_page_table_frame(frame),
        Err(_) => false,
    }
}

/// Boot-only: prove shared carve-out wiring and private frame accounting.
pub(crate) fn verify_carve_out_attach_at_boot(
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    let ranges = kernel_low_reserved_ranges();
    if ranges.is_empty() {
        return Err("carve-out boot assertion found no reserved ranges");
    }
    let probe_address = align_down(ranges[0].start, PAGE_SIZE);
    let probe = VirtAddr::new(probe_address);
    let kernel_root = kernel_root_frame();

    let free_before = allocator.stats().free_pages;
    let space = create_process_address_space(allocator, VirtAddr::new(0x400_000))?;
    let counts = space.resource_counts();
    let expected_private = 1 + KERNEL_CARVE_OUT_PRIVATE_TABLE_FRAMES;
    if counts.page_table_frames != expected_private {
        return Err("carve-out private page-table frame count mismatch at boot");
    }

    assert_carve_out_directory_path_has_no_nx(space.root_frame, probe)?;
    let leaf = leaf_page_flags_for_address_in_root(space.root_frame, probe)?;
    if !leaf.contains(PageTableFlags::PRESENT) || leaf.contains(PageTableFlags::USER_ACCESSIBLE) {
        return Err("carve-out leaf mapping missing or user-accessible in process root");
    }
    let kernel_phys = leaf_phys_addr_for_address_in_root(kernel_root, probe)?;
    let process_phys = leaf_phys_addr_for_address_in_root(space.root_frame, probe)?;
    if kernel_phys != process_phys {
        return Err("carve-out leaf physical address diverged from kernel root");
    }
    crate::mm::stack_guard::verify_guard_holes_in_root(space.root_frame)?;
    crate::mm::identity_holes::verify_identity_holes_in_root(space.root_frame)?;
    if crate::mm::paging::count_writable_executable_leaves(space.root_frame) != 0 {
        return Err("process root has writable and executable kernel leaves");
    }

    destroy_process_address_space(&space, allocator)?;
    if allocator.stats().free_pages != free_before {
        return Err("carve-out boot round-trip leaked physical frames");
    }
    serial_write_line("[MM  ] carve-out attach boot assertion OK");
    Ok(())
}

fn gib_index(virtual_address: u64) -> usize {
    ((virtual_address >> 30) & 0x1ff) as usize
}

fn pd_index(virtual_address: u64) -> usize {
    ((virtual_address >> 21) & 0x1ff) as usize
}

fn attach_shared_carve_outs_to_process(
    address_space: &mut ProcessAddressSpace,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    let pdpt_frame = allocator
        .allocate_page()
        .ok_or("carve-out PDPT allocation failed")?;
    zero_page(pdpt_frame);
    let pd_gib0_frame = allocator
        .allocate_page()
        .ok_or("carve-out PD(GiB0) allocation failed")?;
    zero_page(pd_gib0_frame);
    let pd_gib3_frame = allocator
        .allocate_page()
        .ok_or("carve-out PD(GiB3) allocation failed")?;
    zero_page(pd_gib3_frame);

    address_space.record_page_table_frame(pdpt_frame)?;
    address_space.record_page_table_frame(pd_gib0_frame)?;
    address_space.record_page_table_frame(pd_gib3_frame)?;

    let slot0_directory_flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
    let supervisor_directory_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    let shared_pd_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    let root = unsafe { page_table_mut(address_space.root_frame) };
    root[0].set_addr(PhysAddr::new(pdpt_frame), slot0_directory_flags);

    let pdpt = unsafe { page_table_mut(pdpt_frame) };
    pdpt[0].set_addr(PhysAddr::new(pd_gib0_frame), slot0_directory_flags);
    pdpt[3].set_addr(PhysAddr::new(pd_gib3_frame), supervisor_directory_flags);

    let pd_gib0 = unsafe { page_table_mut(pd_gib0_frame) };
    let pd_gib3 = unsafe { page_table_mut(pd_gib3_frame) };

    for_each_shared_two_mib_table(|region_base, shared_frame| {
        let gib = gib_index(region_base);
        let pd_entry = pd_index(region_base);
        match gib {
            0 => pd_gib0[pd_entry].set_addr(PhysAddr::new(shared_frame), shared_pd_flags),
            3 => pd_gib3[pd_entry].set_addr(PhysAddr::new(shared_frame), shared_pd_flags),
            _ => {}
        }
    });

    Ok(())
}

#[allow(dead_code)]
pub(crate) fn create_process_address_space(
    allocator: &mut PageAllocator,
    user_region_base: VirtAddr,
) -> Result<ProcessAddressSpace, &'static str> {
    let root_frame = allocator
        .allocate_page()
        .ok_or("allocator could not provide a page-table root for a process")?;
    zero_page(root_frame);
    let address_space = ProcessAddressSpace::new(root_frame);
    if address_space.is_err() {
        unsafe {
            let _ = allocator.free_page(root_frame);
        }
    }
    let mut address_space = address_space?;
    if let Err(message) =
        clone_kernel_mappings_into_address_space(&mut address_space, user_region_base, allocator)
    {
        unsafe {
            let _ = allocator.free_page(root_frame);
        }
        return Err(message);
    }
    Ok(address_space)
}

/// On error nothing has been mapped and `frame_address` still belongs to the caller.
#[allow(dead_code)]
pub(crate) fn map_process_page(
    address_space: &mut ProcessAddressSpace,
    virtual_address: u64,
    frame_address: u64,
    flags: PageTableFlags,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    address_space.ensure_user_mapping_capacity()?;
    let page_end = virtual_address
        .checked_add(PAGE_SIZE)
        .ok_or("user mapping virtual address overflow")?;
    if va_overlaps_kernel_low_reserved(virtual_address, page_end) {
        return Err("user mapping overlaps kernel low carve-out");
    }
    if crate::mm::shared_buffer::overlaps_shared_window(virtual_address, page_end) {
        return Err("user mapping overlaps the shared-buffer window");
    }
    if pd_entry_points_at_shared_carve_out_pt(address_space.root_frame, virtual_address) {
        return Err("user mapping targets shared carve-out page table");
    }
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virtual_address));
    let frame = PhysFrame::containing_address(PhysAddr::new(frame_address));
    let mut mapper = unsafe { offset_page_table_for_root(address_space.root_frame) };
    {
        let mut tracking_allocator = AddressSpaceFrameAllocator::new(allocator, address_space);
        without_write_protect(|| unsafe {
            mapper.map_to(page, frame, flags, &mut tracking_allocator)
        })
        .map(|flush| flush.flush())
        .map_err(|_| "failed to map an address-space page")?;
    }
    address_space.record_user_mapping(virtual_address, frame_address)
}

/// Unmap and free a tracked user mapping at `virtual_address` (#103 brk/munmap).
#[allow(dead_code)]
pub(crate) fn unmap_process_page_at(
    address_space: &mut ProcessAddressSpace,
    virtual_address: u64,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    let aligned = align_down(virtual_address, PAGE_SIZE);
    // From the end: brk shrink, munmap and teardown free the newest pages
    // first, so the match is usually the last entry and the shift is short.
    let index = address_space
        .user_mappings()
        .iter()
        .rposition(|mapping| mapping.virtual_address == aligned);
    let index = index.ok_or("unmap target was not tracked")?;
    let mapping = address_space.user_mappings()[index];
    let mut mapper = unsafe { offset_page_table_for_root(address_space.root_frame) };
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(mapping.virtual_address));
    let frame = unmap_userspace_page(&mut mapper, page)?;
    if frame.start_address().as_u64() != mapping.frame_address {
        return Err("unmap removed an unexpected frame");
    }
    unsafe {
        free_frame(allocator, mapping.frame_address)?;
    }
    let count = address_space.user_mapping_count;
    let table = address_space.user_mappings.table_mut();
    table.copy_within(index + 1..count, index);
    table[count - 1] = OwnedUserMapping::EMPTY;
    address_space.user_mapping_count -= 1;
    Ok(())
}

/// Sets or clears `WRITABLE` on a tracked, present user page; the page stays user-accessible
/// and never executable (#306 `MEMORY` PROTECT).
pub(crate) fn set_process_page_writable(
    address_space: &mut ProcessAddressSpace,
    virtual_address: u64,
    writable: bool,
) -> Result<(), &'static str> {
    let aligned = align_down(virtual_address, PAGE_SIZE);
    if !address_space
        .user_mappings()
        .iter()
        .any(|mapping| mapping.virtual_address == aligned)
    {
        return Err("access change target was not tracked");
    }
    let mut flags =
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE | PageTableFlags::NO_EXECUTE;
    if writable {
        flags |= PageTableFlags::WRITABLE;
    }
    let mut mapper = unsafe { offset_page_table_for_root(address_space.root_frame) };
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(aligned));
    without_write_protect(|| unsafe { mapper.update_flags(page, flags) })
        .map(|flush| flush.flush())
        .map_err(|_| "failed to change a user page's access")
}

/// Unmap and free the most recently recorded user mapping (LIFO rollback helper).
#[allow(dead_code)]
pub(crate) fn unmap_last_user_mapping(
    address_space: &mut ProcessAddressSpace,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    if address_space.user_mapping_count == 0 {
        return Err("no user mapping available to roll back");
    }
    let index = address_space.user_mapping_count - 1;
    let mapping = address_space.user_mappings()[index];
    let mut mapper = unsafe { offset_page_table_for_root(address_space.root_frame) };
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(mapping.virtual_address));
    let frame = unmap_userspace_page(&mut mapper, page)?;
    if frame.start_address().as_u64() != mapping.frame_address {
        return Err("rollback unmapped an unexpected frame");
    }
    unsafe {
        free_frame(allocator, mapping.frame_address)?;
    }
    address_space.user_mappings.table_mut()[index] = OwnedUserMapping::EMPTY;
    address_space.user_mapping_count = index;
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn translate_address_in_root(
    root_frame: u64,
    address: VirtAddr,
) -> Result<u64, &'static str> {
    let mapper = unsafe { offset_page_table_for_root(root_frame) };
    mapper
        .translate_addr(address)
        .map(|translated| translated.as_u64())
        .ok_or("virtual address was not translated in the target address space")
}

#[allow(dead_code)]
pub(crate) fn destroy_process_address_space(
    address_space: &ProcessAddressSpace,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    if !unsafe { crate::mm::paging::page_table_mut(address_space.root_frame) }
        [crate::mm::shared_buffer::WINDOW_PML4_INDEX]
        .is_unused()
    {
        return Err("address-space teardown found a live shared window");
    }
    let mut mapper = unsafe { offset_page_table_for_root(address_space.root_frame) };
    for mapping in address_space.user_mappings().iter().rev() {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(mapping.virtual_address));
        let frame = unmap_userspace_page(&mut mapper, page)?;
        if frame.start_address().as_u64() != mapping.frame_address {
            return Err("address-space teardown unmapped an unexpected frame");
        }
        unsafe {
            free_frame(allocator, mapping.frame_address)?;
        }
    }
    for frame_address in address_space.page_table_frames[..address_space.page_table_frame_count]
        .iter()
        .rev()
    {
        if shared_carve_out_page_table_frame(*frame_address) {
            continue;
        }
        unsafe {
            free_frame(allocator, *frame_address)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pools are process-wide statics; tests that claim from them take turns.
    static POOL_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn mapping_table_pool_is_bounded_released_on_drop_and_reset_on_reuse() {
        let _pool = POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut slots = std::vec::Vec::new();
        for _ in 0..USER_MAPPING_TABLE_POOL_SIZE {
            slots.push(UserMappingTableSlot::claim().expect("pooled table"));
        }
        assert_eq!(
            UserMappingTableSlot::claim().unwrap_err(),
            "process address-space mapping table pool exhausted"
        );

        slots[0].table_mut()[0] = OwnedUserMapping {
            virtual_address: 0x40_0000,
            frame_address: 0x20_0000,
        };
        drop(slots.remove(0));
        let reused = UserMappingTableSlot::claim().expect("released table");
        assert!(reused
            .table()
            .iter()
            .all(|mapping| *mapping == OwnedUserMapping::EMPTY));
    }

    fn record_pages(space: &mut ProcessAddressSpace, pages: usize) -> Result<(), &'static str> {
        let first = space.user_mapping_count as u64;
        for page in first..first + pages as u64 {
            space
                .record_user_mapping(0x40_0000 + page * PAGE_SIZE, 0x100_0000 + page * PAGE_SIZE)?;
        }
        Ok(())
    }

    #[test]
    fn a_full_small_table_moves_to_a_large_one_and_keeps_its_entries() {
        let _pool = POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut space = ProcessAddressSpace::new(0x1000).expect("space");
        assert_eq!(
            space.user_mapping_capacity(),
            SMALL_ADDRESS_SPACE_USER_MAPPINGS
        );
        record_pages(&mut space, SMALL_ADDRESS_SPACE_USER_MAPPINGS).expect("small table");
        let free_before = free_large_mapping_tables();

        record_pages(&mut space, 1).expect("promotion");
        assert_eq!(
            space.user_mapping_capacity(),
            MAX_ADDRESS_SPACE_USER_MAPPINGS
        );
        assert_eq!(free_large_mapping_tables(), free_before - 1);
        assert_eq!(
            space.user_mapping_count(),
            SMALL_ADDRESS_SPACE_USER_MAPPINGS + 1
        );
        for index in 0..space.user_mapping_count() {
            let mapping = space.user_mapping_at(index).expect("entry");
            assert_eq!(
                mapping.virtual_address,
                0x40_0000 + index as u64 * PAGE_SIZE
            );
            assert_eq!(mapping.frame_address, 0x100_0000 + index as u64 * PAGE_SIZE);
        }

        let remaining = MAX_ADDRESS_SPACE_USER_MAPPINGS - space.user_mapping_count();
        record_pages(&mut space, remaining).expect("fill large table");
        assert_eq!(
            record_pages(&mut space, 1),
            Err("process address-space mapping tracking capacity exceeded")
        );
        assert_eq!(space.user_mapping_count(), MAX_ADDRESS_SPACE_USER_MAPPINGS);

        drop(space);
        assert_eq!(
            free_large_mapping_tables(),
            free_before,
            "drop returns the large table"
        );
    }

    #[test]
    fn a_full_small_table_stays_put_when_no_large_table_is_free() {
        let _pool = POOL_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut held = std::vec::Vec::new();
        while let Ok(slot) = UserMappingTableSlot::claim_large() {
            held.push(slot);
        }
        let mut space = ProcessAddressSpace::new(0x1000).expect("space");
        record_pages(&mut space, SMALL_ADDRESS_SPACE_USER_MAPPINGS).expect("small table");
        assert_eq!(
            record_pages(&mut space, 1),
            Err("process address-space mapping tracking capacity exceeded")
        );
        assert_eq!(
            space.user_mapping_count(),
            SMALL_ADDRESS_SPACE_USER_MAPPINGS
        );
        assert_eq!(
            space.user_mapping_capacity(),
            SMALL_ADDRESS_SPACE_USER_MAPPINGS
        );

        held.pop();
        record_pages(&mut space, 1).expect("a released large table is used");
        assert_eq!(
            space.user_mapping_capacity(),
            MAX_ADDRESS_SPACE_USER_MAPPINGS
        );
    }

    #[test]
    fn kernel_root_sanitization_clears_user_flags_and_user_slots() {
        let user_region_base = VirtAddr::new(0x0000_4000_0000_0000);
        let user_slot_index = ((user_region_base.as_u64() >> 39) & 0x1ff) as usize;
        let mut root = PageTable::new();
        root[0].set_addr(
            PhysAddr::new(0x1000),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
        );
        root[user_slot_index].set_addr(
            PhysAddr::new(0x2000),
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        );

        sanitize_kernel_root_entries(&mut root, user_region_base);

        assert!(!root[0].flags().contains(PageTableFlags::USER_ACCESSIBLE));
        assert!(root[0].is_unused());
        assert!(root[user_slot_index].is_unused());
        assert_eq!(
            validate_supervisor_only_kernel_root_entries(&root, user_region_base),
            Ok(())
        );
    }

    #[test]
    fn kernel_root_validation_rejects_inherited_user_accessible_entry() {
        let user_region_base = VirtAddr::new(0x0000_4000_0000_0000);
        let mut root = PageTable::new();
        root[511].set_addr(
            PhysAddr::new(0x3000),
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        );

        assert_eq!(
            validate_supervisor_only_kernel_root_entries(&root, user_region_base),
            Err("inherited kernel root entry remained user accessible")
        );
    }
}
