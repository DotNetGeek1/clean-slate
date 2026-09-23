//! Bounded eager user mapping clone for Linux `fork` (#102).

use super::address_space::{
    create_process_address_space, destroy_process_address_space, map_process_page,
    unmap_last_user_mapping, ProcessAddressSpace,
};
use super::frame_allocator::PageAllocator;
use super::phys_to_virt;
use super::PAGE_SIZE;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

/// BusyBox static image + stack + brk headroom (4 MiB); see `readelf.txt` + traces.
pub(crate) const LINUX_FORK_MAX_PAGES: usize = 1024;

pub(crate) fn clone_user_mappings_for_fork(
    parent: &ProcessAddressSpace,
    child: &mut ProcessAddressSpace,
    allocator: &mut PageAllocator,
    max_pages: usize,
) -> Result<usize, &'static str> {
    let count = parent.user_mapping_count();
    if count > max_pages {
        return Err("fork exceeded LINUX_FORK_MAX_PAGES");
    }
    let mut copied = 0usize;
    for index in 0..count {
        let mapping = parent
            .user_mapping_at(index)
            .ok_or("fork parent mapping index out of range")?;
        let flags = user_copy_flags(parent.root_frame, mapping.virtual_address)?;
        let new_frame = allocator
            .allocate_page()
            .ok_or("fork could not allocate user page")?;
        {
            let src = phys_to_virt(mapping.frame_address) as *const u8;
            let dst = phys_to_virt(new_frame) as *mut u8;
            unsafe {
                core::ptr::copy_nonoverlapping(src, dst, PAGE_SIZE as usize);
            }
        }
        if map_process_page(child, mapping.virtual_address, new_frame, flags, allocator).is_err() {
            unsafe {
                let _ = allocator.free_page(new_frame);
            }
            rollback_child_mappings(child, allocator, copied)?;
            return Err("fork map into child failed");
        }
        copied += 1;
    }
    Ok(copied)
}

pub(crate) fn fork_child_address_space(
    parent: &ProcessAddressSpace,
    allocator: &mut PageAllocator,
    user_region_base: VirtAddr,
    max_pages: usize,
) -> Result<ProcessAddressSpace, &'static str> {
    let mut child = create_process_address_space(allocator, user_region_base)?;
    match clone_user_mappings_for_fork(parent, &mut child, allocator, max_pages) {
        Ok(_) => Ok(child),
        Err(message) => {
            let _ = destroy_process_address_space(&child, allocator);
            Err(message)
        }
    }
}

fn rollback_child_mappings(
    child: &mut ProcessAddressSpace,
    allocator: &mut PageAllocator,
    pages: usize,
) -> Result<(), &'static str> {
    for _ in 0..pages {
        unmap_last_user_mapping(child, allocator)?;
    }
    Ok(())
}

fn user_copy_flags(
    _root_frame: u64,
    _virtual_address: u64,
) -> Result<PageTableFlags, &'static str> {
    Ok(PageTableFlags::PRESENT
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE)
}
