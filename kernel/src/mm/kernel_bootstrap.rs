//! Install a kernel-owned CR3 with a supervisor direct map (#142).

use crate::arch::x86_64::cpu::without_write_protect;
use crate::mm::address_space::activate_address_space_root;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::layout::{physmap_mapping_allowed, PHYSMAP_BASE};
use crate::mm::PAGE_SIZE;
use crate::mm::region::NormalizedMemoryMap;
use core::ptr;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::FrameAllocator;
use x86_64::structures::paging::Mapper;
use x86_64::structures::paging::OffsetPageTable;
use x86_64::structures::paging::Page;
use x86_64::structures::paging::PageTable;
use x86_64::structures::paging::PageTableFlags;
use x86_64::structures::paging::PhysFrame;
use x86_64::structures::paging::Size2MiB;
use x86_64::structures::paging::Size4KiB;
use x86_64::structures::paging::Translate;
use x86_64::PhysAddr;
use x86_64::VirtAddr;

const LOCAL_APIC_MMIO_BASE: u64 = 0xFEE0_0000;
const TWO_MIB: u64 = 2 * 1024 * 1024;

unsafe fn identity_page_table_mut(frame: u64) -> &'static mut PageTable {
    unsafe { &mut *(frame as *mut PageTable) }
}

unsafe fn identity_page_table_ref(frame: u64) -> &'static PageTable {
    unsafe { &*(frame as *const PageTable) }
}

struct BootstrapFrameAllocator<'a> {
    inner: &'a mut PageAllocator,
}

unsafe impl FrameAllocator<Size4KiB> for BootstrapFrameAllocator<'_> {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.inner
            .allocate_page()
            .map(|address| PhysFrame::containing_address(PhysAddr::new(address)))
    }
}

fn zero_page_identity(frame: u64) {
    unsafe {
        ptr::write_bytes(frame as *mut u8, 0, PAGE_SIZE as usize);
    }
}

pub(crate) fn install_kernel_owned_root(
    allocator: &mut PageAllocator,
    memory_map: &NormalizedMemoryMap,
) -> Result<u64, &'static str> {
    let (firmware_root_frame, _) = Cr3::read();
    let firmware_root = firmware_root_frame.start_address().as_u64();

    let new_root = allocator
        .allocate_page()
        .ok_or("kernel-owned root allocation failed")?;
    zero_page_identity(new_root);

    {
        let source = unsafe { identity_page_table_ref(firmware_root) };
        let destination = unsafe { identity_page_table_mut(new_root) };
        for (dst, src) in destination.iter_mut().zip(source.iter()) {
            if src.is_unused() {
                dst.set_unused();
                continue;
            }
            let flags = src.flags() & !PageTableFlags::USER_ACCESSIBLE;
            dst.set_addr(src.addr(), flags);
        }
    }

    map_physmap_from_memory_map(new_root, memory_map, allocator)?;

    activate_address_space_root(new_root);
    Ok(new_root)
}

fn map_physmap_from_memory_map(
    root_frame: u64,
    memory_map: &NormalizedMemoryMap,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    let mut mapper =
        unsafe { OffsetPageTable::new(identity_page_table_mut(root_frame), VirtAddr::new(0)) };
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
    let mut bootstrap = BootstrapFrameAllocator { inner: allocator };

    for region in memory_map.regions() {
        let mut phys = region.start;
        while phys < region.end {
            if phys >= PAGE_SIZE {
                let virt = PHYSMAP_BASE.wrapping_add(phys);
                if physmap_mapping_allowed(phys, virt) {
                    if phys % TWO_MIB == 0 && phys.saturating_add(TWO_MIB) <= region.end {
                        map_physmap_page_2m(&mut mapper, &mut bootstrap, phys, flags)?;
                        phys = phys.saturating_add(TWO_MIB);
                        continue;
                    }
                    map_physmap_page_4k(&mut mapper, &mut bootstrap, phys, flags)?;
                }
            }
            phys = phys.saturating_add(PAGE_SIZE);
        }
    }

    map_fixed_mmio_page(&mut mapper, &mut bootstrap, LOCAL_APIC_MMIO_BASE, flags)?;
    let _ = root_frame;
    Ok(())
}

fn map_physmap_page_2m(
    mapper: &mut OffsetPageTable<'_>,
    bootstrap: &mut BootstrapFrameAllocator<'_>,
    phys: u64,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    let virt = Page::<Size2MiB>::containing_address(VirtAddr::new(PHYSMAP_BASE.wrapping_add(phys)));
    if mapper.translate_addr(virt.start_address()).is_some() {
        return Ok(());
    }
    let frame = PhysFrame::<Size2MiB>::containing_address(PhysAddr::new(phys));
    let huge_flags = flags | PageTableFlags::HUGE_PAGE;
    without_write_protect(|| unsafe { mapper.map_to(virt, frame, huge_flags, bootstrap) })
        .map_err(|_| "physmap 2MiB map failed")?
        .flush();
    Ok(())
}

fn map_physmap_page_4k(
    mapper: &mut OffsetPageTable<'_>,
    bootstrap: &mut BootstrapFrameAllocator<'_>,
    phys: u64,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    let virt = Page::<Size4KiB>::containing_address(VirtAddr::new(PHYSMAP_BASE.wrapping_add(phys)));
    if mapper.translate_addr(virt.start_address()).is_some() {
        return Ok(());
    }
    let frame = PhysFrame::containing_address(PhysAddr::new(phys));
    without_write_protect(|| unsafe { mapper.map_to(virt, frame, flags, bootstrap) })
        .map_err(|_| "physmap 4KiB map failed")?
        .flush();
    Ok(())
}

fn map_fixed_mmio_page(
    mapper: &mut OffsetPageTable<'_>,
    bootstrap: &mut BootstrapFrameAllocator<'_>,
    mmio_base: u64,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    let virt = Page::<Size4KiB>::containing_address(VirtAddr::new(mmio_base));
    if mapper.translate_addr(virt.start_address()).is_some() {
        return Ok(());
    }
    let frame = PhysFrame::containing_address(PhysAddr::new(mmio_base));
    without_write_protect(|| unsafe { mapper.map_to(virt, frame, flags, bootstrap) })
        .map_err(|_| "MMIO map failed")?
        .flush();
    Ok(())
}
