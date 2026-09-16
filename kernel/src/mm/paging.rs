//! Page-table walking and mapping helpers over the physical-memory offset
//! window: current root lookup, `OffsetPageTable` construction, per-level
//! flag inspection and the boot-time page-table reservation.

use crate::boot::uefi::BootReservedRanges;
use crate::mm::region::ReservedRange;
use crate::mm::PAGE_SIZE;
use crate::mm::PHYSICAL_MEMORY_OFFSET;
use crate::run;
use core::ptr;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::OffsetPageTable;
use x86_64::structures::paging::PageTable;
use x86_64::structures::paging::PageTableFlags;
use x86_64::structures::paging::Translate;
use x86_64::VirtAddr;

pub(crate) struct PageWalkFlags {
    #[allow(dead_code)]
    pub(super) path: PageTableFlags,
    pub(super) leaf: PageTableFlags,
    pub(super) all_levels_user_accessible: bool,
    pub(super) all_levels_writable: bool,
}

pub(crate) fn current_root_frame_address() -> u64 {
    Cr3::read().0.start_address().as_u64()
}

pub(super) unsafe fn offset_page_table_for_root(root_frame: u64) -> OffsetPageTable<'static> {
    let level_4_address = root_frame + PHYSICAL_MEMORY_OFFSET;
    let level_4_table = unsafe { &mut *(level_4_address as *mut PageTable) };
    unsafe { OffsetPageTable::new(level_4_table, VirtAddr::new(PHYSICAL_MEMORY_OFFSET)) }
}

#[allow(dead_code)]
pub(crate) unsafe fn page_table_ref(frame_address: u64) -> &'static PageTable {
    unsafe { &*((frame_address + PHYSICAL_MEMORY_OFFSET) as *const PageTable) }
}

#[allow(dead_code)]
pub(super) unsafe fn page_table_mut(frame_address: u64) -> &'static mut PageTable {
    unsafe { &mut *((frame_address + PHYSICAL_MEMORY_OFFSET) as *mut PageTable) }
}

fn walk_page_flags_in_root(
    root_frame: u64,
    address: VirtAddr,
) -> Result<PageWalkFlags, &'static str> {
    let level_4_table = unsafe { page_table_ref(root_frame) };
    let level_4_entry = &level_4_table[address.p4_index()];
    if level_4_entry.is_unused() {
        return Err("virtual address was not backed by a valid level-4 entry");
    }
    let level_3_frame = level_4_entry
        .frame()
        .map_err(|_| "virtual address was not backed by a valid level-3 frame")?;

    let level_3_table = unsafe {
        &*((level_3_frame.start_address().as_u64() + PHYSICAL_MEMORY_OFFSET) as *const PageTable)
    };
    let level_3_entry = &level_3_table[address.p3_index()];
    if level_3_entry.is_unused() {
        return Err("virtual address was not backed by a valid level-3 entry");
    }
    let mut all_levels_user_accessible = level_4_entry
        .flags()
        .contains(PageTableFlags::USER_ACCESSIBLE)
        && level_3_entry
            .flags()
            .contains(PageTableFlags::USER_ACCESSIBLE);
    let mut all_levels_writable = level_4_entry.flags().contains(PageTableFlags::WRITABLE)
        && level_3_entry.flags().contains(PageTableFlags::WRITABLE);
    if level_3_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        return Ok(PageWalkFlags {
            path: level_4_entry.flags() | level_3_entry.flags(),
            leaf: level_3_entry.flags(),
            all_levels_user_accessible,
            all_levels_writable,
        });
    }
    let level_2_frame = level_3_entry
        .frame()
        .map_err(|_| "virtual address was not backed by a valid level-2 frame")?;

    let level_2_table = unsafe {
        &*((level_2_frame.start_address().as_u64() + PHYSICAL_MEMORY_OFFSET) as *const PageTable)
    };
    let level_2_entry = &level_2_table[address.p2_index()];
    if level_2_entry.is_unused() {
        return Err("virtual address was not backed by a valid level-2 entry");
    }
    all_levels_user_accessible = all_levels_user_accessible
        && level_2_entry
            .flags()
            .contains(PageTableFlags::USER_ACCESSIBLE);
    all_levels_writable =
        all_levels_writable && level_2_entry.flags().contains(PageTableFlags::WRITABLE);
    if level_2_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        return Ok(PageWalkFlags {
            path: level_4_entry.flags() | level_3_entry.flags() | level_2_entry.flags(),
            leaf: level_2_entry.flags(),
            all_levels_user_accessible,
            all_levels_writable,
        });
    }
    let level_1_frame = level_2_entry
        .frame()
        .map_err(|_| "virtual address was not backed by a valid level-1 frame")?;

    let level_1_table = unsafe {
        &*((level_1_frame.start_address().as_u64() + PHYSICAL_MEMORY_OFFSET) as *const PageTable)
    };
    let level_1_entry = &level_1_table[address.p1_index()];
    if level_1_entry.is_unused() {
        return Err("virtual address was not mapped");
    }
    all_levels_user_accessible = all_levels_user_accessible
        && level_1_entry
            .flags()
            .contains(PageTableFlags::USER_ACCESSIBLE);
    all_levels_writable =
        all_levels_writable && level_1_entry.flags().contains(PageTableFlags::WRITABLE);
    Ok(PageWalkFlags {
        path: level_4_entry.flags()
            | level_3_entry.flags()
            | level_2_entry.flags()
            | level_1_entry.flags(),
        leaf: level_1_entry.flags(),
        all_levels_user_accessible,
        all_levels_writable,
    })
}

pub(super) fn walk_page_flags(address: VirtAddr) -> Result<PageWalkFlags, &'static str> {
    walk_page_flags_in_root(current_root_frame_address(), address)
}

#[cfg(feature = "m3-entry-self-test")]
pub(super) fn page_flags_for_address(address: VirtAddr) -> Result<PageTableFlags, &'static str> {
    Ok(walk_page_flags(address)?.path)
}

#[cfg(feature = "m3-entry-self-test")]
pub(super) fn leaf_page_flags_for_address(
    address: VirtAddr,
) -> Result<PageTableFlags, &'static str> {
    Ok(walk_page_flags(address)?.leaf)
}

#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m4-recovery-self-test"
))]
#[cfg_attr(
    any(
        feature = "m4-crash-service-self-test",
        feature = "m4-recovery-self-test"
    ),
    allow(dead_code)
)]
pub(crate) fn page_flags_for_address_in_root(
    root_frame: u64,
    address: VirtAddr,
) -> Result<PageTableFlags, &'static str> {
    Ok(walk_page_flags_in_root(root_frame, address)?.path)
}

#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m4-recovery-self-test"
))]
#[cfg_attr(
    any(
        feature = "m4-crash-service-self-test",
        feature = "m4-recovery-self-test"
    ),
    allow(dead_code)
)]
pub(crate) fn leaf_page_flags_for_address_in_root(
    root_frame: u64,
    address: VirtAddr,
) -> Result<PageTableFlags, &'static str> {
    Ok(walk_page_flags_in_root(root_frame, address)?.leaf)
}

pub(crate) unsafe fn current_offset_page_table() -> OffsetPageTable<'static> {
    unsafe { offset_page_table_for_root(current_root_frame_address()) }
}

pub(crate) fn reserve_mapping_page_tables(
    ranges: &mut BootReservedRanges,
    virtual_address: u64,
) -> Result<(), &'static str> {
    let address = VirtAddr::new(virtual_address);
    let (level_4_frame, _) = Cr3::read();
    ranges.push(ReservedRange::from_base_and_size(
        level_4_frame.start_address().as_u64(),
        PAGE_SIZE,
    ))?;

    let level_4_table = unsafe {
        &*((level_4_frame.start_address().as_u64() + PHYSICAL_MEMORY_OFFSET) as *const PageTable)
    };
    let level_3_frame = level_4_table[address.p4_index()]
        .frame()
        .map_err(|_| "kernel address was not backed by a valid level-3 page-table frame")?;
    ranges.push(ReservedRange::from_base_and_size(
        level_3_frame.start_address().as_u64(),
        PAGE_SIZE,
    ))?;

    let level_3_table = unsafe {
        &*((level_3_frame.start_address().as_u64() + PHYSICAL_MEMORY_OFFSET) as *const PageTable)
    };
    let level_3_entry = &level_3_table[address.p3_index()];
    if level_3_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        return Ok(());
    }

    let level_2_frame = level_3_entry
        .frame()
        .map_err(|_| "kernel address was not backed by a valid level-2 page-table frame")?;
    ranges.push(ReservedRange::from_base_and_size(
        level_2_frame.start_address().as_u64(),
        PAGE_SIZE,
    ))?;

    let level_2_table = unsafe {
        &*((level_2_frame.start_address().as_u64() + PHYSICAL_MEMORY_OFFSET) as *const PageTable)
    };
    let level_2_entry = &level_2_table[address.p2_index()];
    if level_2_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        return Ok(());
    }

    let level_1_frame = level_2_entry
        .frame()
        .map_err(|_| "kernel address was not backed by a valid level-1 page-table frame")?;
    ranges.push(ReservedRange::from_base_and_size(
        level_1_frame.start_address().as_u64(),
        PAGE_SIZE,
    ))?;
    Ok(())
}

pub(crate) fn inspect_current_mapping() -> Result<(u64, u64), &'static str> {
    let mapper = unsafe { current_offset_page_table() };
    let virtual_address = VirtAddr::from_ptr(run as *const ());
    let physical_address = mapper
        .translate_addr(virtual_address)
        .ok_or("failed to inspect the current kernel mapping")?;
    Ok((virtual_address.as_u64(), physical_address.as_u64()))
}

#[allow(dead_code)]
pub(crate) fn zero_page(frame: u64) {
    unsafe {
        ptr::write_bytes(
            (PHYSICAL_MEMORY_OFFSET + frame) as *mut u8,
            0,
            PAGE_SIZE as usize,
        );
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(
        feature = "m3-address-space-self-test",
        feature = "m3-resources-self-test",
        feature = "m4-crash-service-self-test",
        feature = "m4-recovery-self-test",
        feature = "m3-entry-self-test"
    ))]
    use super::*;
    #[cfg(any(
        feature = "m3-address-space-self-test",
        feature = "m3-resources-self-test",
        feature = "m4-crash-service-self-test",
        feature = "m4-recovery-self-test",
        feature = "m3-entry-self-test"
    ))]
    use crate::selftest::USER_TEST_CODE_ADDRESS;
    #[cfg(any(
        feature = "m3-address-space-self-test",
        feature = "m3-resources-self-test",
        feature = "m4-crash-service-self-test",
        feature = "m4-recovery-self-test",
        feature = "m3-entry-self-test"
    ))]
    use x86_64::PhysAddr;

    #[cfg(any(
        feature = "m3-address-space-self-test",
        feature = "m3-resources-self-test",
        feature = "m4-crash-service-self-test",
        feature = "m4-recovery-self-test",
        feature = "m3-entry-self-test",
        feature = "m3-syscall-self-test"
    ))]
    #[test]
    fn user_access_requires_user_bit_on_each_page_table_level() {
        let virtual_address = VirtAddr::new(USER_TEST_CODE_ADDRESS);
        let mut level_4 = Box::new(PageTable::new());
        let mut level_3 = Box::new(PageTable::new());
        let mut level_2 = Box::new(PageTable::new());
        let mut level_1 = Box::new(PageTable::new());

        level_4[virtual_address.p4_index()].set_addr(
            PhysAddr::new((&*level_3 as *const PageTable) as u64),
            PageTableFlags::PRESENT,
        );
        level_3[virtual_address.p3_index()].set_addr(
            PhysAddr::new((&*level_2 as *const PageTable) as u64),
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        );
        level_2[virtual_address.p2_index()].set_addr(
            PhysAddr::new((&*level_1 as *const PageTable) as u64),
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        );
        level_1[virtual_address.p1_index()].set_addr(
            PhysAddr::new(0x4000),
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        );

        let walk = walk_page_flags_in_root((&*level_4 as *const PageTable) as u64, virtual_address)
            .expect("walked mapping");
        assert!(walk.path.contains(PageTableFlags::USER_ACCESSIBLE));
        assert!(walk.leaf.contains(PageTableFlags::USER_ACCESSIBLE));
        assert!(!walk.all_levels_user_accessible);
    }
}
