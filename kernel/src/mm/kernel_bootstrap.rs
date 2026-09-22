//! Install a kernel-owned CR3 with a supervisor direct map (#142).

use crate::arch::x86_64::cpu::without_write_protect;
use crate::mm::address_space::activate_address_space_root;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::layout::phys_to_virt;
use crate::mm::region::NormalizedMemoryMap;
use crate::mm::PAGE_SIZE;
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
const BRINGUP_PHYSMAP_BYTES: u64 = 512 * 1024 * 1024;

/// While still on the firmware CR3, page-table pages are reachable via identity.
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

/// Build a fresh kernel root, populate the physmap, switch CR3, and return the
/// new root frame address.
pub(crate) fn install_kernel_owned_root(
    allocator: &mut PageAllocator,
    _memory_map: &NormalizedMemoryMap,
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

    map_physmap_while_on_firmware_cr3(new_root, allocator)?;

    activate_address_space_root(new_root);
    Ok(new_root)
}

fn map_physmap_while_on_firmware_cr3(
    root_frame: u64,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    let mut mapper =
        unsafe { OffsetPageTable::new(identity_page_table_mut(root_frame), VirtAddr::new(0)) };
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
    let mut bootstrap = BootstrapFrameAllocator { inner: allocator };

    for _pass in 0..2 {
        let mut phys = TWO_MIB;
        while phys < BRINGUP_PHYSMAP_BYTES {
            map_physmap_page_2m(&mut mapper, &mut bootstrap, phys, flags)?;
            phys = phys.saturating_add(TWO_MIB);
        }
    }

    // Map low physical frames (except page zero — M1 scratch at physmap+0 stays unmapped).
    for _pass in 0..2 {
        let mut phys = PAGE_SIZE;
        while phys < TWO_MIB {
            map_physmap_page_4k(&mut mapper, &mut bootstrap, phys, flags)?;
            phys = phys.saturating_add(PAGE_SIZE);
        }
    }
    let _ = root_frame;

    map_fixed_mmio_page(&mut mapper, &mut bootstrap, LOCAL_APIC_MMIO_BASE, flags)?;

    Ok(())
}

fn map_physmap_page_2m(
    mapper: &mut OffsetPageTable<'_>,
    bootstrap: &mut BootstrapFrameAllocator<'_>,
    phys: u64,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    let virt = Page::<Size2MiB>::containing_address(VirtAddr::new(phys_to_virt(phys)));
    if mapper.translate_addr(virt.start_address()).is_some() {
        return Ok(());
    }
    let frame = PhysFrame::<Size2MiB>::containing_address(PhysAddr::new(phys));
    let huge_flags = flags | PageTableFlags::HUGE_PAGE;
    without_write_protect(|| unsafe { mapper.map_to(virt, frame, huge_flags, bootstrap) })
        .map_err(|_| "physmap 2MiB map failed for usable RAM")?
        .flush();
    Ok(())
}

fn map_physmap_page_4k(
    mapper: &mut OffsetPageTable<'_>,
    bootstrap: &mut BootstrapFrameAllocator<'_>,
    phys: u64,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    let virt = Page::<Size4KiB>::containing_address(VirtAddr::new(phys_to_virt(phys)));
    if mapper.translate_addr(virt.start_address()).is_some() {
        return Ok(());
    }
    let frame = PhysFrame::containing_address(PhysAddr::new(phys));
    without_write_protect(|| unsafe { mapper.map_to(virt, frame, flags, bootstrap) })
        .map_err(|_| "physmap map failed for usable RAM")?
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
        .map_err(|_| "MMIO physmap map failed")?
        .flush();
    Ok(())
}
