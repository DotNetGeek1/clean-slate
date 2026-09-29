use core::ptr;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

use x86_64::structures::paging::{FrameAllocator, PhysFrame, Size4KiB};
use x86_64::PhysAddr;

use crate::mm::kernel_map_ptr;
use crate::mm::region::{MemoryRegion, MemoryRegionKind, NormalizedMemoryMap, MAX_MEMORY_REGIONS};
use crate::mm::PAGE_SIZE;
#[cfg(not(test))]
use crate::sync::global_cell::GlobalCell;

#[cfg(debug_assertions)]
const FRAME_POISON_QWORD: u64 = 0xDEAD_BEEF_DEAD_BEEF;
#[cfg(debug_assertions)]
const FREE_NODE_BYTES: usize = core::mem::size_of::<FreePageNode>();

#[cfg(debug_assertions)]
fn poison_freed_frame(frame: u64) {
    let base = physical_frame_ptr(frame);
    let mut offset = FREE_NODE_BYTES;
    while offset < PAGE_SIZE as usize {
        unsafe {
            core::ptr::write_unaligned(base.add(offset) as *mut u64, FRAME_POISON_QWORD);
        }
        offset += core::mem::size_of::<u64>();
    }
}

#[cfg(debug_assertions)]
fn assert_frame_poison_intact(frame: u64) -> Result<(), &'static str> {
    let base = physical_frame_ptr(frame);
    let mut offset = FREE_NODE_BYTES;
    while offset < PAGE_SIZE as usize {
        let word = unsafe { core::ptr::read_unaligned(base.add(offset) as *const u64) };
        if word != FRAME_POISON_QWORD {
            return Err("physical page allocator detected frame reuse before poison check");
        }
        offset += core::mem::size_of::<u64>();
    }
    Ok(())
}

static KERNEL_DIRECT_MAP_READY: AtomicBool = AtomicBool::new(false);

/// Called once the kernel-owned page table and physmap are active.
pub(crate) fn set_kernel_direct_map_ready() {
    KERNEL_DIRECT_MAP_READY.store(true, Ordering::Release);
}

/// Pointer to a physical frame for page-table edits and allocator metadata.
pub(crate) fn physical_frame_ptr(frame: u64) -> *mut u8 {
    if KERNEL_DIRECT_MAP_READY.load(Ordering::Acquire) {
        kernel_map_ptr(frame) as *mut u8
    } else {
        frame as *mut u8
    }
}

type UsableRegionTable = [MemoryRegion; MAX_MEMORY_REGIONS];

/// The region table lives outside `PageAllocator` so the allocator stays a
/// few words and can be moved by value into self-tests and the syscall
/// allocator slot without multi-KiB stack copies.
#[cfg(not(test))]
fn claim_usable_region_table() -> Result<&'static mut UsableRegionTable, &'static str> {
    struct ClaimableRegionTable {
        is_claimed: bool,
        regions: UsableRegionTable,
    }
    static TABLE: GlobalCell<ClaimableRegionTable> = GlobalCell::new(ClaimableRegionTable {
        is_claimed: false,
        regions: [MemoryRegion::EMPTY; MAX_MEMORY_REGIONS],
    });
    let table = unsafe { &mut *TABLE.get() };
    if table.is_claimed {
        return Err("page allocator region table is already owned by an allocator");
    }
    table.is_claimed = true;
    Ok(&mut table.regions)
}

#[cfg(test)]
fn claim_usable_region_table() -> Result<&'static mut UsableRegionTable, &'static str> {
    Ok(std::boxed::Box::leak(std::boxed::Box::new(
        [MemoryRegion::EMPTY; MAX_MEMORY_REGIONS],
    )))
}

#[derive(Debug)]
pub(crate) struct PageAllocator {
    usable_regions: &'static mut UsableRegionTable,
    usable_region_count: usize,
    current_region: usize,
    next_page: u64,
    free_list_head: Option<u64>,
    #[cfg(debug_assertions)]
    free_list_tail: Option<u64>,
    total_pages: u64,
    available_pages: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PageAllocatorStats {
    pub(crate) total_pages: u64,
    pub(crate) allocated_pages: u64,
    pub(crate) free_pages: u64,
}

impl PageAllocator {
    pub(crate) fn new(memory_map: &NormalizedMemoryMap) -> Result<Self, &'static str> {
        let mut allocator = Self {
            usable_regions: claim_usable_region_table()?,
            usable_region_count: 0,
            current_region: 0,
            next_page: 0,
            free_list_head: None,
            #[cfg(debug_assertions)]
            free_list_tail: None,
            total_pages: 0,
            available_pages: 0,
        };

        for region in memory_map.regions() {
            if region.kind == MemoryRegionKind::Usable {
                let start = region.start.max(PAGE_SIZE);
                if start >= region.end {
                    continue;
                }
                if allocator.usable_region_count == MAX_MEMORY_REGIONS {
                    return Err("allocator usable-region capacity exceeded");
                }
                allocator.usable_regions[allocator.usable_region_count] = MemoryRegion {
                    start,
                    end: region.end,
                    kind: MemoryRegionKind::Usable,
                };
                allocator.usable_region_count += 1;
                allocator.total_pages += (region.end - start) / PAGE_SIZE;
            }
        }

        if allocator.usable_region_count == 0 {
            return Err("no usable physical memory regions available");
        }

        allocator.next_page = allocator.usable_regions[0].start;
        allocator.available_pages = allocator.total_pages;
        Ok(allocator)
    }

    pub(crate) fn allocate_page(&mut self) -> Option<u64> {
        if let Some(frame) = self.pop_free_page() {
            self.available_pages -= 1;
            return Some(frame);
        }

        while self.current_region < self.usable_region_count {
            let region = self.usable_regions[self.current_region];
            if self.next_page < region.end {
                let frame = self.next_page;
                self.next_page = self.next_page.saturating_add(PAGE_SIZE);
                self.available_pages -= 1;
                return Some(frame);
            }

            self.current_region += 1;
            if self.current_region < self.usable_region_count {
                self.next_page = self.usable_regions[self.current_region].start;
            }
        }

        None
    }

    /// Takes `pages` consecutive frames from the not-yet-allocated tail, moving to a later region
    /// when the current one cannot hold them; the skipped tail pages go to the free list. The free
    /// list itself is never used because its order carries no adjacency. On failure nothing changes.
    #[cfg(any(test, feature = "m10-framebuffer-self-test"))]
    pub(crate) fn allocate_contiguous(&mut self, pages: u64) -> Option<u64> {
        if pages == 0 {
            return None;
        }
        let bytes = pages.checked_mul(PAGE_SIZE)?;
        let mut region_index = self.current_region;
        let mut start = self.next_page;
        while region_index < self.usable_region_count {
            let region = self.usable_regions[region_index];
            if region_index != self.current_region {
                start = region.start;
            }
            if region.end.saturating_sub(start) >= bytes {
                break;
            }
            region_index += 1;
        }
        if region_index == self.usable_region_count {
            return None;
        }

        let skipped_from_region = self.current_region;
        let skipped_from = self.next_page;
        self.current_region = region_index;
        self.next_page = start + bytes;
        self.available_pages -= pages;
        for index in skipped_from_region..region_index {
            let region = self.usable_regions[index];
            let mut frame = if index == skipped_from_region {
                skipped_from.max(region.start)
            } else {
                region.start
            };
            while frame < region.end {
                self.available_pages -= 1;
                let released = unsafe { self.free_page(frame) };
                debug_assert!(released.is_ok());
                frame += PAGE_SIZE;
            }
        }
        Some(start)
    }

    pub(crate) unsafe fn free_page(&mut self, frame: u64) -> Result<(), &'static str> {
        unsafe { self.free_run(frame, 1) }
    }

    /// Up to `max_pages` physically contiguous frames as `(base, pages)`. Takes the
    /// contiguous bump region first and falls back to a single free-list frame, so a
    /// fragmented pool yields short runs rather than failing.
    pub(crate) fn allocate_run(&mut self, max_pages: u64) -> Option<(u64, u64)> {
        if max_pages == 0 {
            return None;
        }
        while self.current_region < self.usable_region_count {
            let region = self.usable_regions[self.current_region];
            let remaining = region.end.saturating_sub(self.next_page) / PAGE_SIZE;
            if remaining > 0 {
                let pages = remaining.min(max_pages);
                let base = self.next_page;
                self.next_page += pages * PAGE_SIZE;
                self.available_pages -= pages;
                return Some((base, pages));
            }
            self.current_region += 1;
            if self.current_region < self.usable_region_count {
                self.next_page = self.usable_regions[self.current_region].start;
            }
        }
        let frame = self.pop_free_page()?;
        self.available_pages -= 1;
        Some((frame, 1))
    }

    /// The run the next `allocate_run(max_pages)` would return while the bump region
    /// still has pages; `None` once it would fall back to the free list.
    #[cfg(feature = "m10-shared-buffer-self-test")]
    pub(crate) fn peek_bump_run(&self, max_pages: u64) -> Option<(u64, u64)> {
        let mut region_index = self.current_region;
        let mut next_page = self.next_page;
        while region_index < self.usable_region_count {
            let region = self.usable_regions[region_index];
            let remaining = region.end.saturating_sub(next_page) / PAGE_SIZE;
            if remaining > 0 {
                return Some((next_page, remaining.min(max_pages)));
            }
            region_index += 1;
            if region_index < self.usable_region_count {
                next_page = self.usable_regions[region_index].start;
            }
        }
        None
    }

    /// Frees `pages` contiguous frames from `base`, validating the whole run before
    /// changing anything; the free list is scanned once for the run, not per frame.
    pub(crate) unsafe fn free_run(&mut self, base: u64, pages: u64) -> Result<(), &'static str> {
        if base % PAGE_SIZE != 0 {
            return Err("attempted to free a non-page-aligned frame");
        }
        let end = pages
            .checked_mul(PAGE_SIZE)
            .and_then(|bytes| base.checked_add(bytes))
            .filter(|end| *end > base)
            .ok_or("attempted to free an empty or overflowing frame run")?;
        let Some(region) = self.region_index_containing(base) else {
            return Err("attempted to free a frame outside usable memory");
        };
        if end > self.usable_regions[region].end {
            return Err("attempted to free a frame run crossing a usable region");
        }
        if !self.was_ever_allocated(end - PAGE_SIZE) {
            return Err("attempted to free a frame that was never allocated");
        }
        if self.free_list_intersects(base, end) {
            return Err("attempted to free an already-free frame");
        }
        let mut frame = base;
        while frame < end {
            self.push_free_page(frame);
            frame += PAGE_SIZE;
        }
        self.available_pages += pages;
        Ok(())
    }

    fn push_free_page(&mut self, frame: u64) {
        #[cfg(not(debug_assertions))]
        {
            let node_ptr = physical_frame_ptr(frame) as *mut FreePageNode;
            unsafe {
                ptr::write(
                    node_ptr,
                    FreePageNode {
                        next: self.free_list_head,
                    },
                );
            }
            self.free_list_head = Some(frame);
        }
        #[cfg(debug_assertions)]
        {
            poison_freed_frame(frame);
            self.push_free_page_fifo(frame);
        }
    }

    pub(crate) fn stats(&self) -> PageAllocatorStats {
        PageAllocatorStats {
            total_pages: self.total_pages,
            allocated_pages: self.total_pages - self.available_pages,
            free_pages: self.available_pages,
        }
    }

    fn pop_free_page(&mut self) -> Option<u64> {
        let frame = self.free_list_head?;
        #[cfg(debug_assertions)]
        if let Err(message) = assert_frame_poison_intact(frame) {
            #[cfg(not(test))]
            crate::diagnostics::qemu::fatal_kernel_error(message);
            #[cfg(test)]
            {
                let _ = message;
                return None;
            }
        }
        let node_ptr = physical_frame_ptr(frame) as *const FreePageNode;
        let node = unsafe { ptr::read(node_ptr) };
        self.free_list_head = node.next;
        #[cfg(debug_assertions)]
        if self.free_list_head.is_none() {
            self.free_list_tail = None;
        }
        Some(frame)
    }

    /// Debug-only FIFO enqueue so reuse order differs from LIFO production paths.
    #[cfg(debug_assertions)]
    fn push_free_page_fifo(&mut self, frame: u64) {
        let node_ptr = physical_frame_ptr(frame) as *mut FreePageNode;
        unsafe {
            (*node_ptr).next = None;
        }
        match self.free_list_tail {
            Some(tail) => {
                let tail_ptr = physical_frame_ptr(tail) as *mut FreePageNode;
                unsafe {
                    (*tail_ptr).next = Some(frame);
                }
            }
            None => self.free_list_head = Some(frame),
        }
        self.free_list_tail = Some(frame);
    }

    fn was_ever_allocated(&self, frame: u64) -> bool {
        let Some(region_index) = self.region_index_containing(frame) else {
            return false;
        };

        if region_index < self.current_region {
            return true;
        }

        region_index == self.current_region && frame < self.next_page
    }

    fn region_index_containing(&self, frame: u64) -> Option<usize> {
        self.usable_regions[..self.usable_region_count]
            .iter()
            .position(|region| frame >= region.start && frame < region.end)
    }

    fn free_list_intersects(&self, start: u64, end: u64) -> bool {
        let mut current = self.free_list_head;
        while let Some(candidate) = current {
            if (start..end).contains(&candidate) {
                return true;
            }
            let node_ptr = physical_frame_ptr(candidate) as *const FreePageNode;
            let node = unsafe { ptr::read(node_ptr) };
            current = node.next;
        }
        false
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FreePageNode {
    next: Option<u64>,
}

unsafe impl FrameAllocator<Size4KiB> for PageAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.allocate_page()
            .map(|address| PhysFrame::containing_address(PhysAddr::new(address)))
    }
}

#[allow(dead_code)]
pub(crate) unsafe fn free_frame(
    allocator: &mut PageAllocator,
    frame: u64,
) -> Result<(), &'static str> {
    unsafe { allocator.free_page(frame) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;
    use uefi::mem::memory_map::{MemoryAttribute, MemoryDescriptor, MemoryType};

    use crate::boot::uefi::normalize_memory_map_boxed;
    use crate::mm::region::ReservedRange;

    fn descriptor(ty: MemoryType, start: u64, pages: u64) -> MemoryDescriptor {
        MemoryDescriptor {
            ty,
            phys_start: start,
            virt_start: 0,
            page_count: pages,
            att: MemoryAttribute::empty(),
        }
    }

    #[repr(align(4096))]
    struct AlignedPages([u8; (PAGE_SIZE as usize) * 4]);

    #[test]
    fn allocator_allocates_and_reuses_freed_pages() {
        let mut pages = AlignedPages([0; (PAGE_SIZE as usize) * 4]);
        let base = pages.0.as_mut_ptr() as u64;
        assert_eq!(base % PAGE_SIZE, 0);

        let descriptors = [descriptor(MemoryType::CONVENTIONAL, base, 4)];
        let map = normalize_memory_map_boxed(descriptors.iter(), &[]).expect("normalize map");
        let mut allocator = PageAllocator::new(&map).expect("allocator");

        let first = allocator.allocate_page().expect("first page");
        let second = allocator.allocate_page().expect("second page");
        assert_eq!(first, base);
        assert_eq!(second, base + PAGE_SIZE);

        unsafe {
            allocator.free_page(first).expect("free page");
        }
        let recycled = allocator.allocate_page().expect("recycled page");
        assert_eq!(recycled, first);

        assert_eq!(
            allocator.stats(),
            PageAllocatorStats {
                total_pages: 4,
                allocated_pages: 2,
                free_pages: 2,
            }
        );
    }

    #[test]
    #[cfg(debug_assertions)]
    fn freed_frame_poison_detects_use_after_free() {
        let mut pages = AlignedPages([0; (PAGE_SIZE as usize) * 4]);
        let base = pages.0.as_mut_ptr() as u64;
        let descriptors = [descriptor(MemoryType::CONVENTIONAL, base, 4)];
        let map = normalize_memory_map_boxed(descriptors.iter(), &[]).expect("normalize map");
        let mut allocator = PageAllocator::new(&map).expect("allocator");
        let frame = allocator.allocate_page().expect("page");
        unsafe {
            allocator.free_page(frame).expect("free");
        }
        assert_frame_poison_intact(frame).expect("poison after free");
        unsafe {
            *(physical_frame_ptr(frame).add(FREE_NODE_BYTES) as *mut u64) = 0;
        }
        assert!(assert_frame_poison_intact(frame).is_err());
    }

    #[test]
    fn allocator_rejects_double_free() {
        let mut pages = AlignedPages([0; (PAGE_SIZE as usize) * 4]);
        let base = pages.0.as_mut_ptr() as u64;
        let descriptors = [descriptor(MemoryType::CONVENTIONAL, base, 4)];
        let map = normalize_memory_map_boxed(descriptors.iter(), &[]).expect("normalize map");
        let mut allocator = PageAllocator::new(&map).expect("allocator");

        let frame = allocator.allocate_page().expect("allocated page");
        unsafe {
            allocator.free_page(frame).expect("first free");
        }
        let second_free = unsafe { allocator.free_page(frame) };
        assert_eq!(second_free, Err("attempted to free an already-free frame"));
    }

    #[test]
    fn allocator_rejects_unallocated_and_unaligned_frees() {
        let mut pages = AlignedPages([0; (PAGE_SIZE as usize) * 4]);
        let base = pages.0.as_mut_ptr() as u64;
        let descriptors = [descriptor(MemoryType::CONVENTIONAL, base, 4)];
        let map = normalize_memory_map_boxed(descriptors.iter(), &[]).expect("normalize map");
        let mut allocator = PageAllocator::new(&map).expect("allocator");

        let never_allocated = unsafe { allocator.free_page(base + PAGE_SIZE) };
        assert_eq!(
            never_allocated,
            Err("attempted to free a frame that was never allocated")
        );

        let unaligned = unsafe { allocator.free_page(base + 1) };
        assert_eq!(unaligned, Err("attempted to free a non-page-aligned frame"));
    }

    #[repr(align(4096))]
    struct AlignedPages12([u8; (PAGE_SIZE as usize) * 12]);

    #[test]
    fn contiguous_allocation_skips_short_regions_and_bypasses_the_free_list() {
        let mut pages = AlignedPages12([0; (PAGE_SIZE as usize) * 12]);
        let base = pages.0.as_mut_ptr() as u64;
        let descriptors = [
            descriptor(MemoryType::CONVENTIONAL, base, 4),
            descriptor(MemoryType::ACPI_NON_VOLATILE, base + 4 * PAGE_SIZE, 1),
            descriptor(MemoryType::CONVENTIONAL, base + 5 * PAGE_SIZE, 7),
        ];
        let map = normalize_memory_map_boxed(descriptors.iter(), &[]).expect("normalize map");
        let mut allocator = PageAllocator::new(&map).expect("allocator");

        let first = allocator.allocate_page().expect("first page");
        unsafe {
            allocator.free_page(first).expect("free first");
        }
        let second = allocator.allocate_page().expect("recycled page");
        assert_eq!(second, first);
        let _ = allocator.allocate_page().expect("bump page");

        assert_eq!(allocator.allocate_contiguous(8), None);
        assert_eq!(allocator.stats().allocated_pages, 2);

        let run = allocator.allocate_contiguous(4).expect("contiguous run");
        assert_eq!(run, base + 5 * PAGE_SIZE);
        assert_eq!(
            allocator.stats(),
            PageAllocatorStats {
                total_pages: 11,
                allocated_pages: 6,
                free_pages: 5,
            }
        );

        let mut recycled = [
            allocator.allocate_page().expect("skipped tail page"),
            allocator.allocate_page().expect("skipped tail page"),
        ];
        recycled.sort_unstable();
        assert_eq!(recycled, [base + 2 * PAGE_SIZE, base + 3 * PAGE_SIZE]);
        assert_eq!(allocator.allocate_page(), Some(base + 9 * PAGE_SIZE));
        assert_eq!(allocator.allocate_contiguous(0), None);
    }

    fn four_page_allocator(pages: &mut AlignedPages) -> (u64, PageAllocator) {
        let base = pages.0.as_mut_ptr() as u64;
        let descriptors = [descriptor(MemoryType::CONVENTIONAL, base, 4)];
        let map = normalize_memory_map_boxed(descriptors.iter(), &[]).expect("normalize map");
        (base, PageAllocator::new(&map).expect("allocator"))
    }

    #[test]
    fn frame_allocator_run_is_contiguous_then_falls_back_to_single_free_frames() {
        let mut pages = AlignedPages([0; (PAGE_SIZE as usize) * 4]);
        let (base, mut allocator) = four_page_allocator(&mut pages);

        assert_eq!(allocator.allocate_run(0), None);
        assert_eq!(allocator.allocate_run(3), Some((base, 3)));
        assert_eq!(allocator.allocate_run(8), Some((base + 3 * PAGE_SIZE, 1)));
        assert_eq!(allocator.allocate_run(1), None);

        unsafe {
            allocator.free_run(base, 2).expect("free run");
        }
        assert_eq!(allocator.stats().free_pages, 2);
        let first = allocator.allocate_run(2).expect("free-list frame");
        assert_eq!(first.1, 1, "free-list fallback hands out single frames");
        assert!(allocator.allocate_run(2).is_some());
        assert_eq!(allocator.stats().free_pages, 0);
    }

    #[test]
    fn frame_allocator_free_run_validates_the_whole_run_before_changing_anything() {
        let mut pages = AlignedPages([0; (PAGE_SIZE as usize) * 4]);
        let (base, mut allocator) = four_page_allocator(&mut pages);
        allocator.allocate_run(2).expect("run");

        let beyond_bump = unsafe { allocator.free_run(base, 3) };
        assert_eq!(
            beyond_bump,
            Err("attempted to free a frame that was never allocated")
        );
        let empty = unsafe { allocator.free_run(base, 0) };
        assert_eq!(
            empty,
            Err("attempted to free an empty or overflowing frame run")
        );
        let crossing = unsafe { allocator.free_run(base, 5) };
        assert_eq!(
            crossing,
            Err("attempted to free a frame run crossing a usable region")
        );
        assert_eq!(
            allocator.stats().free_pages,
            2,
            "failed frees change nothing"
        );

        unsafe {
            allocator.free_page(base + PAGE_SIZE).expect("free one");
        }
        let overlapping = unsafe { allocator.free_run(base, 2) };
        assert_eq!(overlapping, Err("attempted to free an already-free frame"));
        assert_eq!(allocator.stats().free_pages, 3);
    }

    #[test]
    fn allocator_exhaustion_and_reserved_exclusion_are_tracked() {
        let descriptors = [
            descriptor(MemoryType::CONVENTIONAL, 0x1000, 4),
            descriptor(MemoryType::ACPI_NON_VOLATILE, 0x5000, 2),
            descriptor(MemoryType::CONVENTIONAL, 0x7000, 2),
        ];
        let reserved = [ReservedRange::from_base_and_size(0x2000, PAGE_SIZE)];
        let map = normalize_memory_map_boxed(descriptors.iter(), &reserved).expect("normalize map");
        let mut allocator = PageAllocator::new(&map).expect("allocator");

        let mut allocated = Vec::new();
        while let Some(frame) = allocator.allocate_page() {
            allocated.push(frame);
        }

        assert_eq!(allocated, vec![0x1000, 0x3000, 0x4000, 0x7000, 0x8000]);
        assert_eq!(
            allocator.stats(),
            PageAllocatorStats {
                total_pages: 5,
                allocated_pages: 5,
                free_pages: 0,
            }
        );
    }
}
