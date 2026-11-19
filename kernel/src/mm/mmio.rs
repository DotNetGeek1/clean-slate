//! Device MMIO access through the kernel root.
//!
//! The kernel root no longer inherits the firmware identity map (#217), so device register
//! pages (I/O APIC, MSI-X tables, virtio capability windows) are mapped explicitly, on first
//! use: [`with_kernel_identity_mmio`] switches to the kernel root with interrupts masked and
//! identity-maps every missing 4 KiB page of the window present + writable + no-execute +
//! uncached (PCD|PWT, the memory type for device registers). Only the pages a driver names are
//! mapped, only in the kernel root; process roots never see them.
//!
//! Page tables come from a fixed pool reserved at boot ([`init_device_identity_map`]). The
//! helper fails closed for a window that overlaps usable RAM (an uncached alias of write-back
//! memory), the local APIC's identity window (kept unmapped by `mm::identity_holes`), a page
//! already mapped with any other permission (the kernel image), or an exhausted pool.

use crate::arch::x86_64::cpu::without_interrupts;
use crate::mm::address_space::{
    activate_address_space_root, kernel_root_frame, translate_address_in_root,
};
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::{
    current_root_frame_address, leaf_page_flags_for_address_in_root, offset_page_table_for_root,
};
use crate::mm::region::{MemoryRegionKind, NormalizedMemoryMap};
use crate::mm::PAGE_SIZE;
use crate::sync::global_cell::GlobalCell;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, Page, PageTableFlags, PhysFrame, Size4KiB,
};
use x86_64::{PhysAddr, VirtAddr};

/// Page-table frames for device mappings: one PDPT per 512 GiB, one PD per GiB and one PT per
/// 2 MiB touched. QEMU's devices sit in at most two GiB-sized windows (the 32-bit hole and the
/// 64-bit BAR aperture), a handful of 2 MiB windows each.
const DEVICE_TABLE_POOL_FRAMES: usize = 16;

const DEVICE_PAGE_FLAGS: PageTableFlags = PageTableFlags::PRESENT
    .union(PageTableFlags::WRITABLE)
    .union(PageTableFlags::NO_EXECUTE)
    .union(PageTableFlags::NO_CACHE)
    .union(PageTableFlags::WRITE_THROUGH);

struct DeviceIdentityMap {
    memory_map: Option<&'static NormalizedMemoryMap>,
    table_frames: [u64; DEVICE_TABLE_POOL_FRAMES],
    tables_used: usize,
}

static DEVICE_IDENTITY_MAP: GlobalCell<DeviceIdentityMap> = GlobalCell::new(DeviceIdentityMap {
    memory_map: None,
    table_frames: [0; DEVICE_TABLE_POOL_FRAMES],
    tables_used: 0,
});

unsafe impl FrameAllocator<Size4KiB> for DeviceIdentityMap {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let frame = *self.table_frames.get(self.tables_used)?;
        self.tables_used += 1;
        Some(PhysFrame::containing_address(PhysAddr::new(frame)))
    }
}

/// Reserves the page-table pool and records which physical ranges are RAM. Boot-only, after the
/// kernel root and the direct map are live.
pub(crate) fn init_device_identity_map(
    allocator: &mut PageAllocator,
    memory_map: &'static NormalizedMemoryMap,
) -> Result<(), &'static str> {
    let state = unsafe { &mut *DEVICE_IDENTITY_MAP.get() };
    for frame in state.table_frames.iter_mut() {
        *frame = allocator
            .allocate_page()
            .ok_or("mmio: device page-table pool allocation failed")?;
    }
    state.tables_used = 0;
    state.memory_map = Some(memory_map);
    Ok(())
}

/// Run `access` with the window `[physical, physical + len)` identity-mapped as device memory
/// in the active (kernel) root, passing the window's virtual base (equal to `physical`).
pub(crate) fn with_kernel_identity_mmio<T>(
    physical: u64,
    len: u64,
    access: impl FnOnce(u64) -> T,
) -> Result<T, &'static str> {
    if len == 0 {
        return Err("mmio window is empty");
    }
    let end = physical
        .checked_add(len)
        .ok_or("mmio window overflows the physical address space")?;
    without_interrupts(|| {
        let kernel_root = kernel_root_frame();
        if kernel_root == 0 {
            return Err("mmio access before the kernel root was installed");
        }
        let previous_root = current_root_frame_address();
        if previous_root != kernel_root {
            activate_address_space_root(kernel_root);
        }
        let result = map_device_window(kernel_root, physical, end).map(|()| access(physical));
        if previous_root != kernel_root {
            activate_address_space_root(previous_root);
        }
        result
    })
}

fn overlaps_usable_ram(memory_map: &NormalizedMemoryMap, start: u64, end: u64) -> bool {
    memory_map.regions().iter().any(|region| {
        region.kind == MemoryRegionKind::Usable && region.start < end && start < region.end
    })
}

fn map_device_window(root: u64, start: u64, end: u64) -> Result<(), &'static str> {
    let state = unsafe { &mut *DEVICE_IDENTITY_MAP.get() };
    let memory_map = state
        .memory_map
        .ok_or("mmio access before the device identity map was initialized")?;
    let first = start & !(PAGE_SIZE - 1);
    if overlaps_usable_ram(memory_map, first, end) {
        return Err("mmio window overlaps usable RAM");
    }
    let local_apic_window = crate::mm::identity_holes::local_apic_identity_window(
        crate::arch::x86_64::apic::local_apic_physical_base(),
    );
    if local_apic_window.overlaps(first, end) {
        return Err("mmio window overlaps the local APIC window");
    }
    let mut page = first;
    while page < end {
        let virt = VirtAddr::try_new(page).map_err(|_| "mmio window is not canonical")?;
        match translate_address_in_root(root, virt) {
            Ok(mapped) => {
                let flags = leaf_page_flags_for_address_in_root(root, virt)?;
                if mapped != page || !flags.contains(DEVICE_PAGE_FLAGS) {
                    return Err("mmio window overlaps a non-device kernel mapping");
                }
            }
            Err(_) => {
                let mut mapper = unsafe { offset_page_table_for_root(root) };
                let frame = PhysFrame::containing_address(PhysAddr::new(page));
                unsafe {
                    mapper.map_to_with_table_flags(
                        Page::<Size4KiB>::containing_address(virt),
                        frame,
                        DEVICE_PAGE_FLAGS,
                        PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
                        state,
                    )
                }
                .map_err(|_| "mmio: device page map failed (page-table pool exhausted?)")?
                .flush();
            }
        }
        page += PAGE_SIZE;
    }
    Ok(())
}
