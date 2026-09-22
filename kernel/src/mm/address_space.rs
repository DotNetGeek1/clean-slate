//! Per-process address spaces: cloning the kernel half of the root table,
//! mapping user pages into a process root, activating a root and tearing an
//! address space down. Owns `KERNEL_ROOT_FRAME`.

use crate::arch::x86_64::cpu::without_write_protect;
use crate::mm::frame_allocator::free_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::layout::{kernel_low_reserved_ranges, va_overlaps_kernel_low_reserved, KERNEL_USER_PML4_SLOT_END};
use crate::mm::paging::leaf_page_flags_for_address_in_root;
use crate::mm::paging::offset_page_table_for_root;
use crate::mm::paging::page_table_mut;
use crate::mm::paging::page_table_ref;
use crate::mm::paging::zero_page;
use crate::mm::user_mapping::unmap_userspace_page;
use crate::mm::{align_down, PAGE_SIZE};
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

// `ProcessAddressSpace` is a fixed-size value type that is moved by value
// through the spawn path while running on a 64 KiB per-thread kernel stack, so
// these tables must stay small: every extra mapping slot costs 16 bytes in
// each of the several copies that live on the stack during a launch.
#[cfg(any(feature = "m4-recovery-self-test", feature = "m4-supervisor-self-test"))]
pub(crate) const MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES: usize = 32;
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m7-net-caps-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test",
    feature = "m7-net-service-self-test"
))]
pub(crate) const MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES: usize = 16;
#[cfg(not(any(
    feature = "m4-recovery-self-test",
    feature = "m4-supervisor-self-test",
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m7-net-caps-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test",
    feature = "m7-net-service-self-test",
    feature = "m9-low-va-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m4-recovery-self-test",
    feature = "m8-linux-image-self-test",
    feature = "m8-linux-hello-self-test",
    feature = "m8-linux-dispatch-self-test"
)))]
pub(crate) const MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES: usize = 8;
#[cfg(any(
    feature = "m9-low-va-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m4-recovery-self-test",
    feature = "m8-linux-image-self-test",
    feature = "m8-linux-hello-self-test",
    feature = "m8-linux-dispatch-self-test"
))]
pub(crate) const MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES: usize = 24;
#[cfg(any(feature = "m4-recovery-self-test", feature = "m4-supervisor-self-test"))]
pub(crate) const MAX_ADDRESS_SPACE_USER_MAPPINGS: usize = 32;
#[cfg(feature = "m7-net-service-self-test")]
pub(crate) const MAX_ADDRESS_SPACE_USER_MAPPINGS: usize = 384;
/// Storage and network userspace images map up to their configured code-page
/// budgets plus stack/bootstrap pages; `service::spawn` asserts each budget
/// against this value.
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m7-net-caps-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
pub(crate) const MAX_ADDRESS_SPACE_USER_MAPPINGS: usize = 104;
#[cfg(not(any(
    feature = "m4-recovery-self-test",
    feature = "m4-supervisor-self-test",
    feature = "m7-net-service-self-test",
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m7-net-caps-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test",
    feature = "m7-net-service-self-test"
)))]
pub(crate) const MAX_ADDRESS_SPACE_USER_MAPPINGS: usize = 4;

static KERNEL_ROOT_FRAME: AtomicU64 = AtomicU64::new(0);

/// Physical frame of the kernel's own root page table (relaxed load).
pub(crate) fn kernel_root_frame() -> u64 {
    KERNEL_ROOT_FRAME.load(Ordering::Relaxed)
}

/// Records the kernel's root page-table frame at boot (relaxed store).
pub(crate) fn set_kernel_root_frame(frame: u64) {
    KERNEL_ROOT_FRAME.store(frame, Ordering::Relaxed);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OwnedUserMapping {
    virtual_address: u64,
    frame_address: u64,
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

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ProcessAddressSpace {
    pub(crate) root_frame: u64,
    page_table_frames: [u64; MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES],
    page_table_frame_count: usize,
    user_mappings: [OwnedUserMapping; MAX_ADDRESS_SPACE_USER_MAPPINGS],
    user_mapping_count: usize,
}

#[allow(dead_code)]
impl ProcessAddressSpace {
    fn new(root_frame: u64) -> Result<Self, &'static str> {
        let mut address_space = Self {
            root_frame,
            page_table_frames: [0; MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES],
            page_table_frame_count: 0,
            user_mappings: [OwnedUserMapping::EMPTY; MAX_ADDRESS_SPACE_USER_MAPPINGS],
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

    fn record_user_mapping(
        &mut self,
        virtual_address: u64,
        frame_address: u64,
    ) -> Result<(), &'static str> {
        if self.user_mapping_count == self.user_mappings.len() {
            return Err("process address-space mapping tracking capacity exceeded");
        }
        self.user_mappings[self.user_mapping_count] = OwnedUserMapping {
            virtual_address,
            frame_address,
        };
        self.user_mapping_count += 1;
        Ok(())
    }

    pub(crate) fn resource_counts(&self) -> AddressSpaceResourceCounts {
        AddressSpaceResourceCounts {
            user_pages: self.user_mapping_count,
            page_table_frames: self.page_table_frame_count,
        }
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
    map_kernel_low_carve_outs(address_space, allocator)?;
    map_low_page_table_frames_at_identity(address_space, allocator)?;
    validate_supervisor_only_kernel_root_entries(destination_root, user_region_base)
}

const LOW_IDENTITY_PT_CUTOFF: u64 = 2 * 1024 * 1024;

fn map_low_page_table_frames_at_identity(
    address_space: &mut ProcessAddressSpace,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    let mut frames = [0u64; 512];
    let mut frame_count = 0usize;
    collect_kernel_low_page_table_frames(&mut frames, &mut frame_count)?;
    for frame in address_space.page_table_frames[..address_space.page_table_frame_count].iter() {
        push_unique_frame(*frame, &mut frames, &mut frame_count)?;
    }
    for frame_address in frames[..frame_count].iter() {
        if *frame_address >= LOW_IDENTITY_PT_CUTOFF {
            continue;
        }
        let virt = VirtAddr::new(*frame_address);
        let mapper = unsafe { offset_page_table_for_root(address_space.root_frame) };
        if mapper.translate_addr(virt).is_some() {
            continue;
        }
        let flags =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
        map_supervisor_page(
            address_space,
            *frame_address,
            *frame_address,
            flags,
            allocator,
        )?;
    }
    Ok(())
}

fn push_unique_frame(
    frame: u64,
    frames: &mut [u64; 512],
    count: &mut usize,
) -> Result<(), &'static str> {
    if frames[..*count].contains(&frame) {
        return Ok(());
    }
    if *count == frames.len() {
        return Ok(());
    }
    frames[*count] = frame;
    *count += 1;
    Ok(())
}

fn collect_kernel_low_page_table_frames(
    frames: &mut [u64; 512],
    count: &mut usize,
) -> Result<(), &'static str> {
    let root = kernel_root_frame();
    walk_low_page_table_frames(root, 0, frames, count)
}

fn walk_low_page_table_frames(
    table_frame: u64,
    level: u8,
    frames: &mut [u64; 512],
    count: &mut usize,
) -> Result<(), &'static str> {
    push_unique_frame(table_frame, frames, count)?;
    if level >= 3 {
        return Ok(());
    }
    let table = unsafe { page_table_ref(table_frame) };
    let index_limit = if level == 0 {
        KERNEL_USER_PML4_SLOT_END
    } else {
        512
    };
    for entry in table.iter().take(index_limit) {
        if entry.is_unused() || entry.flags().contains(PageTableFlags::HUGE_PAGE) {
            continue;
        }
        let child = entry
            .frame()
            .map_err(|_| "invalid kernel page-table child")?
            .start_address()
            .as_u64();
        walk_low_page_table_frames(child, level + 1, frames, count)?;
    }
    Ok(())
}

fn map_supervisor_page(
    address_space: &mut ProcessAddressSpace,
    virtual_address: u64,
    frame_address: u64,
    flags: PageTableFlags,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virtual_address));
    let frame = PhysFrame::containing_address(PhysAddr::new(frame_address));
    let mut mapper = unsafe { offset_page_table_for_root(address_space.root_frame) };
    {
        let mut tracking_allocator = AddressSpaceFrameAllocator::new(allocator, address_space);
        without_write_protect(|| unsafe {
            mapper.map_to(page, frame, flags, &mut tracking_allocator)
        })
        .map(|flush| flush.flush())
        .map_err(|_| "failed to map kernel carve-out page")?;
    }
    Ok(())
}

fn map_kernel_low_carve_outs(
    address_space: &mut ProcessAddressSpace,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    let kernel_root = kernel_root_frame();
    for range in kernel_low_reserved_ranges() {
        let mut virtual_address = align_down(range.start, PAGE_SIZE);
        while virtual_address < range.end {
            let virt = VirtAddr::new(virtual_address);
            let frame_address = match translate_address_in_root(kernel_root, virt) {
                Ok(frame) => frame,
                Err(_) => {
                    virtual_address = virtual_address.saturating_add(PAGE_SIZE);
                    continue;
                }
            };
            let leaf = (leaf_page_flags_for_address_in_root(kernel_root, virt)?)
                & !PageTableFlags::USER_ACCESSIBLE
                & !PageTableFlags::HUGE_PAGE;
            {
                let mapper =
                    unsafe { offset_page_table_for_root(address_space.root_frame) };
                if mapper.translate_addr(virt).map(|addr| addr.as_u64()) == Some(frame_address)
                {
                    virtual_address = virtual_address.saturating_add(PAGE_SIZE);
                    continue;
                }
            }
            map_supervisor_page(
                address_space,
                virtual_address,
                frame_address,
                leaf,
                allocator,
            )?;
            virtual_address = virtual_address.saturating_add(PAGE_SIZE);
        }
    }
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
    activate_address_space_root(kernel_root_frame());
    Ok(address_space)
}

#[allow(dead_code)]
pub(crate) fn map_process_page(
    address_space: &mut ProcessAddressSpace,
    virtual_address: u64,
    frame_address: u64,
    flags: PageTableFlags,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    let page_end = virtual_address
        .checked_add(PAGE_SIZE)
        .ok_or("user mapping virtual address overflow")?;
    if va_overlaps_kernel_low_reserved(virtual_address, page_end) {
        return Err("user mapping overlaps kernel low carve-out");
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
    let mapping = address_space.user_mappings[index];
    let mut mapper = unsafe { offset_page_table_for_root(address_space.root_frame) };
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(mapping.virtual_address));
    let frame = unmap_userspace_page(&mut mapper, page)?;
    if frame.start_address().as_u64() != mapping.frame_address {
        return Err("rollback unmapped an unexpected frame");
    }
    unsafe {
        free_frame(allocator, mapping.frame_address)?;
    }
    address_space.user_mappings[index] = OwnedUserMapping::EMPTY;
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
    let mut mapper = unsafe { offset_page_table_for_root(address_space.root_frame) };
    for mapping in address_space.user_mappings[..address_space.user_mapping_count]
        .iter()
        .rev()
    {
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
        unsafe {
            free_frame(allocator, *frame_address)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
