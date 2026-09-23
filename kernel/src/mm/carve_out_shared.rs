//! Boot-built shared page tables for kernel low carve-outs (#142).

use crate::mm::frame_allocator::PageAllocator;
use crate::mm::layout::kernel_low_reserved_ranges;
use crate::mm::paging::leaf_page_flags_for_address_in_root;
use crate::mm::paging::leaf_phys_addr_for_address_in_root;
use crate::mm::paging::page_table_mut;
use crate::mm::paging::zero_page;
use crate::mm::{align_down, PAGE_SIZE};
use crate::sync::global_cell::GlobalCell;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

/// Private page-table frames wired per process root for carve-out slot 0 (PDPT + PD GiB0 + PD GiB3).
pub(crate) const KERNEL_CARVE_OUT_PRIVATE_TABLE_FRAMES: usize = 3;

const TWO_MIB: u64 = 2 * 1024 * 1024;
const MAX_SHARED_TWO_MIB_TABLES: usize = 24;

#[derive(Clone, Copy)]
struct SharedTwoMiBTable {
    region_base: u64,
    frame: u64,
}

struct SharedTableRegistry {
    count: usize,
    entries: [SharedTwoMiBTable; MAX_SHARED_TWO_MIB_TABLES],
}

static SHARED_CARVE_OUT_TABLES: GlobalCell<SharedTableRegistry> =
    GlobalCell::new(SharedTableRegistry {
        count: 0,
        entries: [SharedTwoMiBTable {
            region_base: 0,
            frame: 0,
        }; MAX_SHARED_TWO_MIB_TABLES],
    });

pub(crate) fn shared_carve_out_page_table_frame(frame: u64) -> bool {
    unsafe {
        let registry = &*SHARED_CARVE_OUT_TABLES.get();
        registry.entries[..registry.count]
            .iter()
            .any(|entry| entry.frame == frame)
    }
}

fn push_shared(region_base: u64, frame: u64) -> Result<(), &'static str> {
    unsafe {
        let registry = &mut *SHARED_CARVE_OUT_TABLES.get();
        if registry.count == MAX_SHARED_TWO_MIB_TABLES {
            return Err("shared carve-out page-table capacity exceeded");
        }
        if registry.entries[..registry.count]
            .iter()
            .any(|entry| entry.region_base == region_base)
        {
            return Ok(());
        }
        registry.entries[registry.count] = SharedTwoMiBTable { region_base, frame };
        registry.count += 1;
    }
    Ok(())
}

fn populate_shared_table(
    kernel_root: u64,
    frame: u64,
    two_mib_base: u64,
) -> Result<(), &'static str> {
    zero_page(frame);
    let table = unsafe { page_table_mut(frame) };
    for index in 0..512usize {
        let virtual_address = two_mib_base.saturating_add((index as u64).saturating_mul(PAGE_SIZE));
        let virt = VirtAddr::new(virtual_address);
        let frame_address = match leaf_phys_addr_for_address_in_root(kernel_root, virt) {
            Ok(address) => address,
            Err(_) => continue,
        };
        let leaf = match leaf_page_flags_for_address_in_root(kernel_root, virt) {
            Ok(flags) => flags,
            Err(_) => continue,
        };
        if !leaf.contains(PageTableFlags::PRESENT) {
            continue;
        }
        let flags = leaf & !PageTableFlags::USER_ACCESSIBLE & !PageTableFlags::HUGE_PAGE;
        table[index].set_addr(x86_64::PhysAddr::new(frame_address), flags);
    }
    Ok(())
}

fn collect_two_mib_windows(out: &mut [u64; MAX_SHARED_TWO_MIB_TABLES], count: &mut usize) {
    for range in kernel_low_reserved_ranges() {
        let mut base = align_down(range.start, TWO_MIB);
        while base < range.end {
            if *count < MAX_SHARED_TWO_MIB_TABLES && !out[..*count].contains(&base) {
                out[*count] = base;
                *count += 1;
            }
            base = base.saturating_add(TWO_MIB);
        }
    }
}

/// Build supervisor-only 4 KiB leaf tables shared by every process root.
pub(crate) fn install_shared_carve_out_page_tables(
    kernel_root: u64,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    unsafe {
        (*SHARED_CARVE_OUT_TABLES.get()).count = 0;
    }
    let mut windows = [0u64; MAX_SHARED_TWO_MIB_TABLES];
    let mut window_count = 0usize;
    collect_two_mib_windows(&mut windows, &mut window_count);
    for base in windows[..window_count].iter() {
        let frame = allocator
            .allocate_page()
            .ok_or("shared carve-out page-table allocation failed")?;
        populate_shared_table(kernel_root, frame, *base)?;
        push_shared(*base, frame)?;
    }
    Ok(())
}

pub(crate) fn for_each_shared_two_mib_table(mut visit: impl FnMut(u64, u64)) {
    unsafe {
        let registry = &*SHARED_CARVE_OUT_TABLES.get();
        for entry in registry.entries[..registry.count].iter() {
            visit(entry.region_base, entry.frame);
        }
    }
}
