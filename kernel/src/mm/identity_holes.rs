//! Holes in the firmware identity map that the kernel root inherits (#253).
//!
//! `kernel_bootstrap::install_kernel_owned_root` copies the firmware's lower-half PML4 entries,
//! so the kernel runs with OVMF's writable identity map of the first 1 TiB. A stray kernel
//! pointer into that range writes somewhere real instead of faulting. This module removes the
//! pages where such a write is most damaging, and records them so the page-fault handler can
//! name a hit:
//!
//! - **The 2 MiB identity window around the local APIC** (`[0xFEE0_0000, 0xFF00_0000)` on QEMU).
//!   QEMU treats a store into the APIC register page at offset 0 (or any write outside it in its
//!   1 MiB APIC space) as an MSI whose data is the stored value. A value that encodes INIT
//!   resets the CPU without any trace in the guest. The kernel reaches the APIC only through an
//!   uncached alias at its direct-map address (`arch::x86_64::apic`), which every root shares,
//!   so nothing legitimate uses the identity window.
//!
//! The kernel stack guards (`mm::stack_guard`) are holes of the same kind and use the splitting
//! code below. Every hole is cut once, in the kernel root, before
//! `install_shared_carve_out_page_tables`: process roots reach low kernel memory only through
//! those shared tables, which are copied leaf by leaf from the kernel root and so inherit the
//! holes. `address_space::verify_carve_out_attach_at_boot` checks a real process root with
//! [`verify_identity_holes_in_root`].
//!
//! Limits: only these pages fault. The rest of the identity map stays writable, and device MMIO
//! reached through the identity map (`mm::mmio::with_kernel_identity_mmio`) is not protected.

use crate::mm::layout::VaRange;
use crate::mm::paging::{leaf_page_flags_for_address_in_root, page_table_mut, zero_page};
use crate::mm::{align_down, PAGE_SIZE};
use crate::sync::global_cell::GlobalCell;
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::structures::paging::PageTableFlags;
use x86_64::PhysAddr;
use x86_64::VirtAddr;

const TWO_MIB: u64 = 2 * 1024 * 1024;
const ONE_GIB: u64 = 1024 * 1024 * 1024;
/// PAT selector bit of a 2 MiB / 1 GiB leaf (bit 12, inside the address field).
const HUGE_LEAF_PAT_BIT: u64 = 1 << 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IdentityHole {
    LocalApicWindow,
}

impl IdentityHole {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::LocalApicWindow => "local-apic-window",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ArmedHoles {
    local_apic_window: VaRange,
    /// The uncached alias the kernel uses instead of the window.
    local_apic_alias: u64,
}

/// Set once the holes are cut from the kernel root; `None` before.
static ARMED: GlobalCell<Option<ArmedHoles>> = GlobalCell::new(None);

/// The 2 MiB-aligned identity window holding the local APIC page at `local_apic_phys`.
pub(crate) fn local_apic_identity_window(local_apic_phys: u64) -> VaRange {
    let start = align_down(local_apic_phys, TWO_MIB);
    VaRange::new(start, start + TWO_MIB)
}

fn armed() -> Option<ArmedHoles> {
    unsafe { *ARMED.get() }
}

fn armed_holes() -> Option<[(IdentityHole, VaRange); 1]> {
    let armed = armed()?;
    Some([(IdentityHole::LocalApicWindow, armed.local_apic_window)])
}

/// The armed hole containing `address`, for naming a kernel page fault.
pub(crate) fn identity_hole_for_address(address: u64) -> Option<IdentityHole> {
    armed_holes()?
        .into_iter()
        .find(|(_, range)| range.overlaps(address, address.saturating_add(1)))
        .map(|(hole, _)| hole)
}

/// Maps the local APIC alias, unmaps every hole from `kernel_root` and points the APIC driver at
/// the alias. Boot-only: runs after the direct map is live and before any shared carve-out table
/// or process root is built. Any failure stops the boot; there is no identity-map fallback.
#[cfg(not(test))]
pub(crate) fn arm_identity_holes(
    kernel_root: u64,
    allocator: &mut crate::mm::frame_allocator::PageAllocator,
    local_apic_phys: u64,
) -> Result<(), &'static str> {
    use crate::arch::x86_64::apic::install_local_apic_alias;
    use crate::diagnostics::serial::serial_write_fmt;
    use crate::mm::kernel_bootstrap::map_device_aperture_uncached;

    let alias = map_device_aperture_uncached(kernel_root, allocator, local_apic_phys, PAGE_SIZE)
        .map_err(|_| "identity holes: the local APIC alias could not be mapped")?;
    let window = local_apic_identity_window(local_apic_phys);
    let split_tables = unmap_range(kernel_root, window, &mut || allocator.allocate_page())?;
    let local_apic_alias = alias.as_mut_ptr() as u64;
    unsafe {
        *ARMED.get() = Some(ArmedHoles {
            local_apic_window: window,
            local_apic_alias,
        })
    };
    verify_identity_holes_in_root(kernel_root)?;
    install_local_apic_alias(local_apic_phys, local_apic_alias)?;
    serial_write_fmt(format_args!(
        "[MM  ] identity holes armed local-apic-window=[{:#x},{:#x}) local-apic-alias={:#018x} split_tables={}\n",
        window.start, window.end, local_apic_alias, split_tables
    ));
    Ok(())
}

/// Fails unless no page of any armed hole is present in `root` and the local APIC alias is
/// mapped there writable and uncached.
pub(crate) fn verify_identity_holes_in_root(root: u64) -> Result<(), &'static str> {
    let armed = armed().ok_or("identity holes were not armed")?;
    let alias = leaf_page_flags_for_address_in_root(root, VirtAddr::new(armed.local_apic_alias))
        .map_err(|_| "local APIC alias is not mapped")?;
    let uncached_register_page = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_CACHE
        | PageTableFlags::WRITE_THROUGH;
    if !alias.contains(uncached_register_page) {
        return Err("local APIC alias is not a writable uncached mapping");
    }
    let holes = armed_holes().ok_or("identity holes were not armed")?;
    for (_, range) in holes {
        let mut address = range.start;
        while address < range.end {
            let flags = leaf_page_flags_for_address_in_root(root, VirtAddr::new(address));
            if matches!(flags, Ok(flags) if flags.contains(PageTableFlags::PRESENT)) {
                return Err("identity hole page is mapped");
            }
            address += PAGE_SIZE;
        }
    }
    Ok(())
}

/// Unmaps every 4 KiB page of `range` from `root`; pages that were never mapped are already holes.
/// Returns how many page tables were allocated by splitting huge leaves.
fn unmap_range(
    root: u64,
    range: VaRange,
    allocate_table: &mut dyn FnMut() -> Option<u64>,
) -> Result<usize, &'static str> {
    let mut split_tables = 0usize;
    let mut address = range.start;
    while address < range.end {
        split_tables += unmap_kernel_page(root, address, allocate_table)?.split_tables;
        flush_kernel_translation(address);
        address += PAGE_SIZE;
    }
    Ok(split_tables)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PageUnmap {
    /// The page had a present 4 KiB entry that was cleared.
    pub(crate) was_mapped: bool,
    pub(crate) split_tables: usize,
}

/// Clears the 4 KiB entry mapping `address` in `root`, first splitting any 1 GiB / 2 MiB leaf
/// above it into leaves with the same frames, flags and memory type.
pub(crate) fn unmap_kernel_page(
    root: u64,
    address: u64,
    allocate_table: &mut dyn FnMut() -> Option<u64>,
) -> Result<PageUnmap, &'static str> {
    let address =
        VirtAddr::try_new(address).map_err(|_| "kernel page unmap: address is not canonical")?;
    let mut unmap = PageUnmap {
        was_mapped: false,
        split_tables: 0,
    };

    let level_4 = unsafe { page_table_mut(root) };
    let level_4_entry = &level_4[address.p4_index()];
    if !level_4_entry.flags().contains(PageTableFlags::PRESENT) {
        return Ok(unmap);
    }

    let level_3 = unsafe { page_table_mut(level_4_entry.addr().as_u64()) };
    let level_3_entry = &mut level_3[address.p3_index()];
    if !level_3_entry.flags().contains(PageTableFlags::PRESENT) {
        return Ok(unmap);
    }
    if level_3_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        split_huge_leaf(level_3_entry, ONE_GIB, allocate_table)?;
        unmap.split_tables += 1;
    }

    let level_2 = unsafe { page_table_mut(level_3_entry.addr().as_u64()) };
    let level_2_entry = &mut level_2[address.p2_index()];
    if !level_2_entry.flags().contains(PageTableFlags::PRESENT) {
        return Ok(unmap);
    }
    if level_2_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        split_huge_leaf(level_2_entry, TWO_MIB, allocate_table)?;
        unmap.split_tables += 1;
    }

    let level_1 = unsafe { page_table_mut(level_2_entry.addr().as_u64()) };
    let level_1_entry = &mut level_1[address.p1_index()];
    if level_1_entry.flags().contains(PageTableFlags::PRESENT) {
        level_1_entry.set_unused();
        unmap.was_mapped = true;
    }
    Ok(unmap)
}

#[cfg(not(test))]
pub(crate) fn flush_kernel_translation(address: u64) {
    // INVLPG drops the TLB entry covering `address` whatever its page size or
    // global bit, and flushes the paging-structure caches.
    x86_64::instructions::tlb::flush(VirtAddr::new(address));
}

#[cfg(test)]
pub(crate) fn flush_kernel_translation(_address: u64) {}

/// Replaces a `leaf_size` huge leaf with a table of 512 leaves one level down
/// that map the same frames with the same flags and memory type.
fn split_huge_leaf(
    entry: &mut PageTableEntry,
    leaf_size: u64,
    allocate_table: &mut dyn FnMut() -> Option<u64>,
) -> Result<(), &'static str> {
    let leaf_flags = entry.flags();
    let raw_address = entry.addr().as_u64();
    let uses_pat = raw_address & HUGE_LEAF_PAT_BIT != 0;
    let frame_base = raw_address & !(leaf_size - 1);
    let child_size = leaf_size / 512;

    let table_frame = allocate_table().ok_or("kernel page unmap: page-table allocation failed")?;
    zero_page(table_frame);
    let table = unsafe { page_table_mut(table_frame) };
    for (index, child) in table.iter_mut().enumerate() {
        let frame = frame_base + index as u64 * child_size;
        if child_size == PAGE_SIZE {
            // A 4 KiB PTE keeps its PAT selector where huge leaves keep HUGE_PAGE.
            let mut flags = leaf_flags & !PageTableFlags::HUGE_PAGE;
            if uses_pat {
                flags |= PageTableFlags::HUGE_PAGE;
            }
            child.set_addr(PhysAddr::new(frame), flags);
        } else {
            let pat = if uses_pat { HUGE_LEAF_PAT_BIT } else { 0 };
            child.set_addr(PhysAddr::new(frame | pat), leaf_flags);
        }
    }
    let directory_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | (leaf_flags & PageTableFlags::USER_ACCESSIBLE);
    entry.set_addr(PhysAddr::new(table_frame), directory_flags);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::boxed::Box;
    use std::vec::Vec;
    use x86_64::structures::paging::PageTable;

    fn leaked_table() -> u64 {
        Box::leak(Box::new(PageTable::new())) as *mut PageTable as u64
    }

    fn table(frame: u64) -> &'static mut PageTable {
        unsafe { page_table_mut(frame) }
    }

    const LEAF: PageTableFlags = PageTableFlags::PRESENT
        .union(PageTableFlags::WRITABLE)
        .union(PageTableFlags::GLOBAL)
        .union(PageTableFlags::NO_EXECUTE);

    /// Root -> PDPT -> PD with a 2 MiB leaf mapping `phys` at `virt`.
    fn root_with_two_mib_leaf(virt: VirtAddr, phys: u64) -> (u64, u64) {
        let root = leaked_table();
        let pdpt = leaked_table();
        let pd = leaked_table();
        table(root)[virt.p4_index()].set_addr(PhysAddr::new(pdpt), PageTableFlags::PRESENT);
        table(pdpt)[virt.p3_index()].set_addr(PhysAddr::new(pd), PageTableFlags::PRESENT);
        table(pd)[virt.p2_index()].set_addr(PhysAddr::new(phys), LEAF | PageTableFlags::HUGE_PAGE);
        (root, pd)
    }

    /// Root -> PDPT with a 1 GiB leaf identity-mapping the GiB that holds `virt`.
    fn root_with_one_gib_identity_leaf(virt: VirtAddr) -> u64 {
        let root = leaked_table();
        let pdpt = leaked_table();
        table(root)[virt.p4_index()].set_addr(PhysAddr::new(pdpt), PageTableFlags::PRESENT);
        table(pdpt)[virt.p3_index()].set_addr(
            PhysAddr::new(align_down(virt.as_u64(), ONE_GIB)),
            LEAF | PageTableFlags::HUGE_PAGE,
        );
        root
    }

    fn mapped(root: u64, address: u64) -> bool {
        matches!(
            leaf_page_flags_for_address_in_root(root, VirtAddr::new(address)),
            Ok(flags) if flags.contains(PageTableFlags::PRESENT)
        )
    }

    const TEST_LOCAL_APIC_PHYS: u64 = 0xFEE0_0000;
    const TEST_ALIAS: u64 = crate::mm::layout::PHYSMAP_BASE + TEST_LOCAL_APIC_PHYS;
    const UNCACHED: PageTableFlags = PageTableFlags::PRESENT
        .union(PageTableFlags::WRITABLE)
        .union(PageTableFlags::NO_EXECUTE)
        .union(PageTableFlags::NO_CACHE)
        .union(PageTableFlags::WRITE_THROUGH);

    fn arm_for_test() {
        unsafe {
            *ARMED.get() = Some(ArmedHoles {
                local_apic_window: local_apic_identity_window(TEST_LOCAL_APIC_PHYS),
                local_apic_alias: TEST_ALIAS,
            })
        };
    }

    /// Adds a 4 KiB leaf for the alias in its own PML4 slot of `root`.
    fn map_alias(root: u64, flags: PageTableFlags) {
        let alias = VirtAddr::new(TEST_ALIAS);
        let (pdpt, pd, pt) = (leaked_table(), leaked_table(), leaked_table());
        let directory = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        table(root)[alias.p4_index()].set_addr(PhysAddr::new(pdpt), directory);
        table(pdpt)[alias.p3_index()].set_addr(PhysAddr::new(pd), directory);
        table(pd)[alias.p2_index()].set_addr(PhysAddr::new(pt), directory);
        table(pt)[alias.p1_index()].set_addr(PhysAddr::new(TEST_LOCAL_APIC_PHYS), flags);
    }

    #[test]
    fn splits_two_mib_leaf_and_clears_only_the_target_entry() {
        let virt = VirtAddr::new(0x3e60_0000);
        let target = virt + 5 * PAGE_SIZE;
        let (root, pd) = root_with_two_mib_leaf(virt, 0x3e60_0000);
        let mut allocated = Vec::new();
        let unmap = unmap_kernel_page(root, target.as_u64(), &mut || {
            let frame = leaked_table();
            allocated.push(frame);
            Some(frame)
        })
        .expect("unmap");
        assert_eq!(
            unmap,
            PageUnmap {
                was_mapped: true,
                split_tables: 1
            }
        );
        assert_eq!(allocated.len(), 1);

        let pd_entry = &table(pd)[virt.p2_index()];
        assert!(!pd_entry.flags().contains(PageTableFlags::HUGE_PAGE));
        assert_eq!(pd_entry.addr().as_u64(), allocated[0]);
        let pt = table(allocated[0]);
        for (index, entry) in pt.iter().enumerate() {
            if index == 5 {
                assert!(entry.is_unused());
                continue;
            }
            assert_eq!(entry.flags(), LEAF);
            assert_eq!(
                entry.addr().as_u64(),
                0x3e60_0000 + index as u64 * PAGE_SIZE
            );
        }
        assert!(leaf_page_flags_for_address_in_root(root, target).is_err());
        assert!(leaf_page_flags_for_address_in_root(root, target + PAGE_SIZE).is_ok());
    }

    #[test]
    fn second_page_in_the_same_leaf_reuses_the_split_table() {
        let virt = VirtAddr::new(0x4000_0000);
        let (root, _) = root_with_two_mib_leaf(virt, 0x4000_0000);
        let mut allocate = || Some(leaked_table());
        let mut unmap = |address: VirtAddr| {
            unmap_kernel_page(root, address.as_u64(), &mut allocate).expect("unmap")
        };
        assert_eq!(unmap(virt + PAGE_SIZE).split_tables, 1);
        assert_eq!(
            unmap(virt + 40 * PAGE_SIZE),
            PageUnmap {
                was_mapped: true,
                split_tables: 0
            }
        );
        assert!(!unmap(virt + 40 * PAGE_SIZE).was_mapped);
    }

    #[test]
    fn splits_one_gib_leaf_down_to_four_kib_and_keeps_pat() {
        let virt = VirtAddr::new(0x8000_0000);
        let root = leaked_table();
        let pdpt = leaked_table();
        table(root)[virt.p4_index()].set_addr(PhysAddr::new(pdpt), PageTableFlags::PRESENT);
        table(pdpt)[virt.p3_index()].set_addr(
            PhysAddr::new(0x8000_0000 | HUGE_LEAF_PAT_BIT),
            LEAF | PageTableFlags::HUGE_PAGE,
        );
        let target = virt + 3 * TWO_MIB + 7 * PAGE_SIZE;
        let unmap =
            unmap_kernel_page(root, target.as_u64(), &mut || Some(leaked_table())).expect("unmap");
        assert_eq!(unmap.split_tables, 2);

        let pd = table(pdpt)[virt.p3_index()].addr().as_u64();
        let sibling = &table(pd)[4];
        assert!(sibling.flags().contains(PageTableFlags::HUGE_PAGE));
        assert_eq!(
            sibling.addr().as_u64(),
            (0x8000_0000 + 4 * TWO_MIB) | HUGE_LEAF_PAT_BIT
        );
        let pt = table(table(pd)[3].addr().as_u64());
        assert!(pt[7].is_unused());
        // 4 KiB PTEs carry PAT in bit 7.
        assert_eq!(pt[8].flags(), LEAF | PageTableFlags::HUGE_PAGE);
        assert_eq!(
            pt[8].addr().as_u64(),
            0x8000_0000 + 3 * TWO_MIB + 8 * PAGE_SIZE
        );
    }

    #[test]
    fn unmapped_address_is_already_a_hole() {
        let root = leaked_table();
        assert_eq!(
            unmap_kernel_page(root, 0x1000_0000, &mut || Some(leaked_table())),
            Ok(PageUnmap {
                was_mapped: false,
                split_tables: 0
            })
        );
    }

    #[test]
    fn split_fails_closed_without_a_table_frame() {
        let (root, _) = root_with_two_mib_leaf(VirtAddr::new(0x4000_0000), 0x4000_0000);
        assert_eq!(
            unmap_kernel_page(root, 0x4000_1000, &mut || None),
            Err("kernel page unmap: page-table allocation failed")
        );
    }

    #[test]
    fn local_apic_window_is_the_two_mib_window_around_the_apic_page() {
        assert_eq!(
            local_apic_identity_window(0xFEE0_0000),
            VaRange::new(0xFEE0_0000, 0xFF00_0000)
        );
        assert_eq!(
            local_apic_identity_window(0xFEC0_1000),
            VaRange::new(0xFEC0_0000, 0xFEE0_0000)
        );
    }

    #[test]
    fn unmap_range_clears_the_whole_apic_window_and_nothing_around_it() {
        let window = local_apic_identity_window(0xFEE0_0000);
        let root = root_with_one_gib_identity_leaf(VirtAddr::new(window.start));
        let splits = unmap_range(root, window, &mut || Some(leaked_table())).expect("unmap window");
        assert_eq!(
            splits, 2,
            "1 GiB leaf to 2 MiB leaves, then the window to 4 KiB"
        );
        let mut address = window.start;
        while address < window.end {
            assert!(!mapped(root, address), "{address:#x}");
            address += PAGE_SIZE;
        }
        assert!(mapped(root, window.start - PAGE_SIZE));
        assert!(mapped(root, window.end));
    }

    #[test]
    fn faults_are_named_only_once_the_holes_are_armed() {
        unsafe { *ARMED.get() = None };
        assert_eq!(identity_hole_for_address(0xFEE0_0000), None);
        assert_eq!(
            verify_identity_holes_in_root(leaked_table()),
            Err("identity holes were not armed")
        );

        arm_for_test();
        assert_eq!(
            identity_hole_for_address(0xFEE0_0000),
            Some(IdentityHole::LocalApicWindow)
        );
        assert_eq!(
            identity_hole_for_address(0xFEFF_FFFF),
            Some(IdentityHole::LocalApicWindow)
        );
        assert_eq!(identity_hole_for_address(0xFF00_0000), None);
        assert_eq!(identity_hole_for_address(0xFEDF_FFFF), None);
    }

    #[test]
    fn verify_rejects_a_root_that_still_maps_a_hole_page() {
        arm_for_test();
        let window = local_apic_identity_window(TEST_LOCAL_APIC_PHYS);
        let root = root_with_one_gib_identity_leaf(VirtAddr::new(window.start));
        map_alias(root, UNCACHED);
        assert_eq!(
            verify_identity_holes_in_root(root),
            Err("identity hole page is mapped")
        );
        unmap_range(root, window, &mut || Some(leaked_table())).expect("unmap window");
        assert_eq!(verify_identity_holes_in_root(root), Ok(()));
    }

    #[test]
    fn verify_requires_the_uncached_alias_in_the_root() {
        arm_for_test();
        let without_alias = leaked_table();
        assert_eq!(
            verify_identity_holes_in_root(without_alias),
            Err("local APIC alias is not mapped")
        );
        let cached_alias = leaked_table();
        map_alias(
            cached_alias,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
        );
        assert_eq!(
            verify_identity_holes_in_root(cached_alias),
            Err("local APIC alias is not a writable uncached mapping")
        );
    }
}
