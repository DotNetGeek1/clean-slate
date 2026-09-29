//! Install a kernel-owned CR3 with a supervisor direct map (#142).

use crate::arch::x86_64::cpu::without_write_protect;
use crate::mm::address_space::activate_address_space_root;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::layout::{physmap_mapping_allowed, PHYSMAP_BASE};
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

/// Half-open physical range kept out of the cached direct map (a device aperture).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PhysExclusion {
    pub(crate) start: u64,
    pub(crate) end: u64,
}

impl PhysExclusion {
    fn overlaps(self, start: u64, end: u64) -> bool {
        self.start < end && start < self.end
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PhysmapStep {
    Map2M,
    Map4K,
    Skip,
}

fn physmap_step(phys: u64, region_end: u64, excluded: Option<PhysExclusion>) -> PhysmapStep {
    let overlaps =
        |len: u64| excluded.is_some_and(|range| range.overlaps(phys, phys.saturating_add(len)));
    if phys % TWO_MIB == 0 && phys.saturating_add(TWO_MIB) <= region_end && !overlaps(TWO_MIB) {
        PhysmapStep::Map2M
    } else if overlaps(PAGE_SIZE) {
        PhysmapStep::Skip
    } else {
        PhysmapStep::Map4K
    }
}

/// `excluded` never receives a write-back physmap alias, even when the firmware reports it inside
/// a memory-map region.
pub(crate) fn install_kernel_owned_root(
    allocator: &mut PageAllocator,
    memory_map: &NormalizedMemoryMap,
    excluded: Option<PhysExclusion>,
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

    map_physmap_from_memory_map(new_root, memory_map, allocator, excluded)?;

    activate_address_space_root(new_root);
    Ok(new_root)
}

/// Maps `[phys_base, phys_base + map_len)` uncached (PCD|PWT, PAT index 3) at its direct-map
/// address with 4 KiB leaves, so nothing past the validated range is reachable. The range sits in
/// PML4 slot 256, which every process root shares, and must already be excluded from the cached
/// physmap. Page-table frames are permanent.
#[cfg(all(feature = "m10-framebuffer-self-test", not(test)))]
pub(crate) fn map_device_aperture_uncached(
    root_frame: u64,
    allocator: &mut PageAllocator,
    phys_base: u64,
    map_len: u64,
) -> Result<UncachedAperture, &'static str> {
    if phys_base % PAGE_SIZE != 0 || map_len == 0 || map_len % PAGE_SIZE != 0 {
        return Err("aperture range not page aligned");
    }
    let phys_end = phys_base
        .checked_add(map_len)
        .ok_or("aperture range overflows")?;
    let mut mapper =
        unsafe { OffsetPageTable::new(identity_page_table_mut(root_frame), VirtAddr::new(0)) };
    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE
        | PageTableFlags::NO_CACHE
        | PageTableFlags::WRITE_THROUGH;
    let mut bootstrap = BootstrapFrameAllocator { inner: allocator };
    let mut phys = phys_base;
    while phys < phys_end {
        let virt = PHYSMAP_BASE.wrapping_add(phys);
        if !physmap_mapping_allowed(phys, virt) {
            return Err("aperture outside the direct map");
        }
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virt));
        if mapper.translate_addr(page.start_address()).is_some() {
            return Err("aperture already has a direct-map alias");
        }
        let frame = PhysFrame::containing_address(PhysAddr::new(phys));
        without_write_protect(|| unsafe { mapper.map_to(page, frame, flags, &mut bootstrap) })
            .map_err(|_| "aperture 4KiB map failed")?
            .flush();
        phys += PAGE_SIZE;
    }
    Ok(UncachedAperture { phys_base, map_len })
}

/// Proof that `map_device_aperture_uncached` mapped this range; only that function creates one.
#[cfg(all(feature = "m10-framebuffer-self-test", not(test)))]
pub(crate) struct UncachedAperture {
    phys_base: u64,
    map_len: u64,
}

#[cfg(all(feature = "m10-framebuffer-self-test", not(test)))]
impl UncachedAperture {
    pub(crate) fn phys_base(&self) -> u64 {
        self.phys_base
    }

    pub(crate) fn len(&self) -> u64 {
        self.map_len
    }

    pub(crate) fn as_mut_ptr(&self) -> *mut u8 {
        PHYSMAP_BASE.wrapping_add(self.phys_base) as *mut u8
    }
}

fn map_physmap_from_memory_map(
    root_frame: u64,
    memory_map: &NormalizedMemoryMap,
    allocator: &mut PageAllocator,
    excluded: Option<PhysExclusion>,
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
                    match physmap_step(phys, region.end, excluded) {
                        PhysmapStep::Map2M => {
                            map_physmap_page_2m(&mut mapper, &mut bootstrap, phys, flags)?;
                            phys = phys.saturating_add(TWO_MIB);
                            continue;
                        }
                        PhysmapStep::Map4K => {
                            map_physmap_page_4k(&mut mapper, &mut bootstrap, phys, flags)?
                        }
                        PhysmapStep::Skip => {}
                    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const APERTURE: PhysExclusion = PhysExclusion {
        start: 0x8000_0000,
        end: 0x8000_0000 + 1000 * PAGE_SIZE,
    };

    #[test]
    fn physmap_step_without_exclusion_prefers_2m() {
        assert_eq!(physmap_step(0x20_0000, 0x40_0000, None), PhysmapStep::Map2M);
        assert_eq!(physmap_step(0x20_0000, 0x3f_f000, None), PhysmapStep::Map4K);
        assert_eq!(physmap_step(0x20_1000, 0x40_0000, None), PhysmapStep::Map4K);
    }

    #[test]
    fn physmap_step_2m_chunks_touching_the_aperture_fall_back_to_4k() {
        let region_end = 0x9000_0000;
        assert_eq!(
            physmap_step(APERTURE.start, region_end, Some(APERTURE)),
            PhysmapStep::Skip
        );
        let last_chunk = APERTURE.end & !(TWO_MIB - 1);
        assert_eq!(
            physmap_step(last_chunk, region_end, Some(APERTURE)),
            PhysmapStep::Skip
        );
        assert_eq!(
            physmap_step(APERTURE.start - TWO_MIB, region_end, Some(APERTURE)),
            PhysmapStep::Map2M,
            "the chunk ending exactly at the aperture keeps its 2 MiB leaf"
        );
        assert_eq!(
            physmap_step(last_chunk + TWO_MIB, region_end, Some(APERTURE)),
            PhysmapStep::Map2M
        );
    }

    #[test]
    fn physmap_step_skips_every_aperture_page_and_nothing_else() {
        let region_start = APERTURE.start - TWO_MIB;
        let region_end = APERTURE.end + 2 * TWO_MIB;
        let mut phys = region_start;
        let mut skipped = 0u64;
        while phys < region_end {
            match physmap_step(phys, region_end, Some(APERTURE)) {
                PhysmapStep::Map2M => {
                    assert!(!APERTURE.overlaps(phys, phys + TWO_MIB), "{phys:#x}");
                    phys += TWO_MIB;
                    continue;
                }
                PhysmapStep::Map4K => assert!(!APERTURE.overlaps(phys, phys + PAGE_SIZE)),
                PhysmapStep::Skip => {
                    assert!((APERTURE.start..APERTURE.end).contains(&phys), "{phys:#x}");
                    skipped += 1;
                }
            }
            phys += PAGE_SIZE;
        }
        assert_eq!(skipped, 1000);
    }
}
