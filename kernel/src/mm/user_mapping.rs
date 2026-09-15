//! Userspace page mapping in the current address space and validation of
//! user-accessible mappings and user pointer ranges.

use crate::arch::x86_64::cpu::without_write_protect;
use crate::mm::align_down;
use crate::mm::frame_allocator::PageAllocator;
#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test",
    feature = "m3-syscall-self-test"
))]
#[cfg(not(feature = "m3-address-space-self-test"))]
use crate::mm::paging::leaf_page_flags_for_address;
#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test",
    feature = "m3-syscall-self-test"
))]
#[cfg(not(feature = "m3-address-space-self-test"))]
use crate::mm::paging::page_flags_for_address;
use crate::mm::paging::walk_page_flags;
use crate::mm::PAGE_SIZE;
use crate::mm::USER_CANONICAL_TOP_EXCLUSIVE;
#[cfg(feature = "m3-entry-self-test")]
use crate::run;
#[cfg(feature = "m3-entry-self-test")]
use crate::selftest::USER_TEST_CODE_ADDRESS;
#[cfg(feature = "m3-entry-self-test")]
use crate::selftest::USER_TEST_STACK_ADDRESS;
use x86_64::structures::paging::Mapper;
use x86_64::structures::paging::OffsetPageTable;
use x86_64::structures::paging::Page;
use x86_64::structures::paging::PageTableFlags;
use x86_64::structures::paging::PhysFrame;
use x86_64::structures::paging::Size4KiB;
use x86_64::VirtAddr;

#[allow(dead_code)]
pub(crate) fn map_userspace_page(
    mapper: &mut OffsetPageTable<'_>,
    page: Page<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
    flags: PageTableFlags,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    without_write_protect(|| unsafe { mapper.map_to(page, frame, flags, allocator) })
        .map(|flush| flush.flush())
        .map_err(|_| "failed to map userspace page")
}

#[allow(dead_code)]
pub(crate) fn unmap_userspace_page(
    mapper: &mut OffsetPageTable<'_>,
    page: Page<Size4KiB>,
) -> Result<PhysFrame<Size4KiB>, &'static str> {
    without_write_protect(|| mapper.unmap(page))
        .map(|(frame, flush)| {
            flush.flush();
            frame
        })
        .map_err(|_| "failed to unmap userspace page")
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
pub(crate) fn relevant_userspace_leaf_flags(flags: PageTableFlags) -> PageTableFlags {
    flags
        & (PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::USER_ACCESSIBLE)
}

#[cfg(feature = "m3-entry-self-test")]
pub(crate) fn validate_userspace_mappings() -> Result<(), &'static str> {
    let code_path_flags = page_flags_for_address(VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let code_leaf_flags = leaf_page_flags_for_address(VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    if !code_path_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || code_leaf_flags.contains(PageTableFlags::WRITABLE)
        || code_leaf_flags.contains(PageTableFlags::NO_EXECUTE)
    {
        return Err("userspace code mapping flags were incorrect");
    }

    let stack_path_flags = page_flags_for_address(VirtAddr::new(USER_TEST_STACK_ADDRESS))?;
    let stack_leaf_flags = leaf_page_flags_for_address(VirtAddr::new(USER_TEST_STACK_ADDRESS))?;
    let expected_stack_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE
        | PageTableFlags::USER_ACCESSIBLE;
    if !stack_path_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || relevant_userspace_leaf_flags(stack_leaf_flags) != expected_stack_flags
    {
        return Err("userspace stack mapping flags were incorrect");
    }

    let kernel_flags = page_flags_for_address(VirtAddr::from_ptr(run as *const ()))?;
    let kernel_leaf_flags = leaf_page_flags_for_address(VirtAddr::from_ptr(run as *const ()))?;
    if kernel_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || kernel_leaf_flags.contains(PageTableFlags::USER_ACCESSIBLE)
    {
        return Err("kernel mapping unexpectedly became user accessible");
    }

    Ok(())
}

pub(crate) fn validate_user_pointer_range(pointer: u64, length: u64) -> Result<(), &'static str> {
    if length == 0 {
        return Err("userspace pointer range length must be non-zero");
    }
    let end_inclusive = pointer
        .checked_add(length - 1)
        .ok_or("userspace pointer range overflowed")?;
    if pointer >= USER_CANONICAL_TOP_EXCLUSIVE || end_inclusive >= USER_CANONICAL_TOP_EXCLUSIVE {
        return Err("userspace pointer range was outside canonical userspace");
    }

    let mut cursor = align_down(pointer, PAGE_SIZE);
    let end_page = align_down(end_inclusive, PAGE_SIZE);
    loop {
        let walk = walk_page_flags(VirtAddr::new(cursor))?;
        if !walk.all_levels_user_accessible
            || !walk.leaf.contains(PageTableFlags::PRESENT)
            || !walk.leaf.contains(PageTableFlags::USER_ACCESSIBLE)
        {
            return Err("userspace pointer range was not mapped as user accessible");
        }
        if cursor == end_page {
            break;
        }
        cursor = cursor
            .checked_add(PAGE_SIZE)
            .ok_or("userspace pointer range page walk overflowed")?;
    }
    Ok(())
}
