//! Install a kernel-owned CR3 with a supervisor direct map (#142) and a W^X kernel image (#217).

use crate::arch::x86_64::cpu::without_write_protect;
use crate::mm::address_space::activate_address_space_root;
use crate::mm::frame_allocator::{set_kernel_direct_map_ready, PageAllocator};
use crate::mm::kernel_image::KernelImageLayout;
use crate::mm::layout::{physmap_mapping_allowed, PHYSMAP_BASE};
#[cfg(not(test))]
use crate::mm::paging::offset_page_table_for_root;
use crate::mm::region::{NormalizedMemoryMap, ReservedRange};
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

/// Half-open physical range kept out of the cached direct map (a device aperture or the local
/// APIC page).
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

fn physmap_step(phys: u64, region_end: u64, excluded: &[PhysExclusion]) -> PhysmapStep {
    let overlaps = |len: u64| {
        excluded
            .iter()
            .any(|range| range.overlaps(phys, phys.saturating_add(len)))
    };
    if phys % TWO_MIB == 0 && phys.saturating_add(TWO_MIB) <= region_end && !overlaps(TWO_MIB) {
        PhysmapStep::Map2M
    } else if overlaps(PAGE_SIZE) {
        PhysmapStep::Skip
    } else {
        PhysmapStep::Map4K
    }
}

/// What [`install_kernel_owned_root`] built, for the `[MM  ] kernel w^x` boot line.
pub(crate) struct KernelRootInstall {
    pub(crate) root: u64,
    pub(crate) image: KernelImageLayout,
    /// Top-level entries of the new root that still point at a firmware page table, i.e. firmware
    /// mappings that kept their original permissions. Boot fails unless this is 0.
    pub(crate) inherited: usize,
}

/// Builds the kernel root from nothing: the kernel image at its identity address with per-section
/// permissions (`mm::kernel_image`) and the supervisor NX physmap. Nothing is copied from the
/// firmware's page tables; device registers are mapped later, explicitly (`mm::mmio`, the
/// aperture and the local APIC alias). The new root is active, and the allocator reaches frames
/// through the physmap, when this returns.
///
/// No `excluded` range receives a write-back physmap alias, even when the firmware reports it
/// inside a memory-map region.
pub(crate) fn install_kernel_owned_root(
    allocator: &mut PageAllocator,
    memory_map: &NormalizedMemoryMap,
    kernel_image: ReservedRange,
    excluded: &[PhysExclusion],
) -> Result<KernelRootInstall, &'static str> {
    let (firmware_root_frame, _) = Cr3::read();
    let firmware_root = firmware_root_frame.start_address().as_u64();

    if kernel_image.end.saturating_sub(kernel_image.start) < PAGE_SIZE {
        return Err("kernel image: smaller than its headers page");
    }
    let headers =
        unsafe { core::slice::from_raw_parts(kernel_image.start as *const u8, PAGE_SIZE as usize) };
    let image = KernelImageLayout::parse(
        kernel_image.start,
        kernel_image.end - kernel_image.start,
        headers,
    )?;

    let new_root = allocator
        .allocate_page()
        .ok_or("kernel-owned root allocation failed")?;
    zero_page_identity(new_root);

    map_kernel_image(new_root, &image, allocator)?;
    map_physmap_from_memory_map(new_root, memory_map, allocator, excluded)?;
    let inherited = unsafe {
        inherited_top_level_tables(
            identity_page_table_ref(firmware_root),
            identity_page_table_ref(new_root),
        )
    };

    activate_address_space_root(new_root);
    set_kernel_direct_map_ready();
    Ok(KernelRootInstall {
        root: new_root,
        image,
        inherited,
    })
}

/// Identity-maps every page of the kernel image with its section's permission, 4 KiB leaves
/// only, so a stack guard or identity hole never has to split a leaf. Directory entries are
/// present + writable without NX: the carve-out contract (`paging::
/// assert_carve_out_directory_path_has_no_nx`) puts NX on leaves only.
fn map_kernel_image(
    root_frame: u64,
    image: &KernelImageLayout,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    let mut mapper =
        unsafe { OffsetPageTable::new(identity_page_table_mut(root_frame), VirtAddr::new(0)) };
    let mut bootstrap = BootstrapFrameAllocator { inner: allocator };
    let table_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    let mut rva = 0;
    while rva < image.size() {
        let address = image.base() + rva;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(address));
        let frame = PhysFrame::containing_address(PhysAddr::new(address));
        let flags = image.access_at(rva).leaf_flags();
        unsafe { mapper.map_to_with_table_flags(page, frame, flags, table_flags, &mut bootstrap) }
            .map_err(|_| "kernel image 4KiB map failed")?
            .ignore();
        rva += PAGE_SIZE;
    }
    Ok(())
}

/// Entries of `kernel` that point at a table `firmware` also points at.
fn inherited_top_level_tables(firmware: &PageTable, kernel: &PageTable) -> usize {
    kernel
        .iter()
        .filter(|entry| {
            !entry.is_unused()
                && firmware
                    .iter()
                    .any(|source| !source.is_unused() && source.addr() == entry.addr())
        })
        .count()
}

/// Maps `[phys_base, phys_base + map_len)` uncached (PCD|PWT, PAT index 3) at its direct-map
/// address with 4 KiB leaves, so nothing past the validated range is reachable. The range sits in
/// PML4 slot 256, which every process root shares, and must already be excluded from the cached
/// physmap. Page-table frames are permanent.
///
/// A range touching the local APIC's 2 MiB window is refused: `identity_holes` unmaps that
/// window's direct-map image, which would silently take the aperture pages with it.
#[cfg(not(test))]
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
    let local_apic_window = crate::mm::identity_holes::local_apic_identity_window(
        crate::arch::x86_64::apic::local_apic_physical_base(),
    );
    if local_apic_window.overlaps(phys_base, phys_end) {
        return Err("aperture overlaps the local APIC window");
    }
    let mut mapper = unsafe { offset_page_table_for_root(root_frame) };
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
        map_uncached_page(&mut mapper, &mut bootstrap, phys, page)
            .map_err(|_| "aperture 4KiB map failed")?;
        phys += PAGE_SIZE;
    }
    Ok(UncachedAperture { phys_base, map_len })
}

/// Maps the 4 KiB device page at `phys` uncached at `virt`, which must lie outside the direct map
/// and be unmapped. Intermediate page-table frames are permanent.
#[cfg(not(test))]
pub(crate) fn map_device_page_uncached_at(
    root_frame: u64,
    allocator: &mut PageAllocator,
    phys: u64,
    virt: u64,
) -> Result<(), &'static str> {
    if phys % PAGE_SIZE != 0 || virt % PAGE_SIZE != 0 {
        return Err("device page not page aligned");
    }
    if crate::mm::layout::virt_to_phys_direct_map(virt).is_some() {
        return Err("device page alias inside the direct map");
    }
    let mut mapper = unsafe { offset_page_table_for_root(root_frame) };
    let page = Page::<Size4KiB>::containing_address(
        VirtAddr::try_new(virt).map_err(|_| "device page alias is not canonical")?,
    );
    if mapper.translate_addr(page.start_address()).is_some() {
        return Err("device page alias already mapped");
    }
    let mut bootstrap = BootstrapFrameAllocator { inner: allocator };
    map_uncached_page(&mut mapper, &mut bootstrap, phys, page)
        .map_err(|_| "device page 4KiB map failed")
}

/// PCD|PWT (PAT index 3), writable, no-execute: the memory type for device registers.
#[cfg(not(test))]
fn map_uncached_page(
    mapper: &mut OffsetPageTable<'_>,
    bootstrap: &mut BootstrapFrameAllocator<'_>,
    phys: u64,
    page: Page<Size4KiB>,
) -> Result<(), ()> {
    let flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE
        | PageTableFlags::NO_CACHE
        | PageTableFlags::WRITE_THROUGH;
    let frame = PhysFrame::containing_address(PhysAddr::new(phys));
    without_write_protect(|| unsafe { mapper.map_to(page, frame, flags, bootstrap) })
        .map_err(|_| ())?
        .flush();
    Ok(())
}

/// Proof that `map_device_aperture_uncached` mapped this range; only that function creates one.
#[cfg(not(test))]
pub(crate) struct UncachedAperture {
    phys_base: u64,
    map_len: u64,
}

#[cfg(not(test))]
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
    excluded: &[PhysExclusion],
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

#[cfg(test)]
mod tests {
    use super::*;

    const APERTURE: PhysExclusion = PhysExclusion {
        start: 0x8000_0000,
        end: 0x8000_0000 + 1000 * PAGE_SIZE,
    };

    #[test]
    fn inherited_counts_entries_sharing_a_firmware_table() {
        let mut firmware = PageTable::new();
        let mut kernel = PageTable::new();
        let directory = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        firmware[0].set_addr(PhysAddr::new(0x7000), directory);
        firmware[1].set_addr(PhysAddr::new(0x8000), directory);
        kernel[0].set_addr(PhysAddr::new(0x9000), directory);
        kernel[256].set_addr(PhysAddr::new(0xa000), directory);
        assert_eq!(inherited_top_level_tables(&firmware, &kernel), 0);
        kernel[1].set_addr(PhysAddr::new(0x8000), PageTableFlags::PRESENT);
        assert_eq!(inherited_top_level_tables(&firmware, &kernel), 1);
    }

    #[test]
    fn physmap_step_without_exclusion_prefers_2m() {
        assert_eq!(physmap_step(0x20_0000, 0x40_0000, &[]), PhysmapStep::Map2M);
        assert_eq!(physmap_step(0x20_0000, 0x3f_f000, &[]), PhysmapStep::Map4K);
        assert_eq!(physmap_step(0x20_1000, 0x40_0000, &[]), PhysmapStep::Map4K);
    }

    #[test]
    fn physmap_step_2m_chunks_touching_the_aperture_fall_back_to_4k() {
        let region_end = 0x9000_0000;
        assert_eq!(
            physmap_step(APERTURE.start, region_end, &[APERTURE]),
            PhysmapStep::Skip
        );
        let last_chunk = APERTURE.end & !(TWO_MIB - 1);
        assert_eq!(
            physmap_step(last_chunk, region_end, &[APERTURE]),
            PhysmapStep::Skip
        );
        assert_eq!(
            physmap_step(APERTURE.start - TWO_MIB, region_end, &[APERTURE]),
            PhysmapStep::Map2M,
            "the chunk ending exactly at the aperture keeps its 2 MiB leaf"
        );
        assert_eq!(
            physmap_step(last_chunk + TWO_MIB, region_end, &[APERTURE]),
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
            match physmap_step(phys, region_end, &[APERTURE]) {
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

    #[test]
    fn physmap_step_skips_the_local_apic_page_next_to_an_aperture() {
        let apic = PhysExclusion {
            start: 0xFEE0_0000,
            end: 0xFEE0_0000 + PAGE_SIZE,
        };
        let excluded = [APERTURE, apic];
        let region_end = 0x1_0000_0000;
        assert_eq!(
            physmap_step(0xFEE0_0000, region_end, &excluded),
            PhysmapStep::Skip
        );
        assert_eq!(
            physmap_step(0xFEE0_1000, region_end, &excluded),
            PhysmapStep::Map4K
        );
        assert_eq!(
            physmap_step(0xFEC0_0000, region_end, &excluded),
            PhysmapStep::Map2M
        );
        assert_eq!(
            physmap_step(APERTURE.start, region_end, &excluded),
            PhysmapStep::Skip
        );
    }
}
