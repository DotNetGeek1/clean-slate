//! A `GlobalAlloc` over the native memory call (syscall 23, #306).
//!
//! Small allocations (up to [`MAX_SMALL_BYTES`], alignment included) come from eight
//! power-of-two size classes, 16 to 2048 bytes. Each class keeps a free list threaded through
//! its free blocks; an empty list is refilled by carving the current chunk, and a used-up chunk
//! is replaced by mapping [`CHUNK_PAGES`] more pages. Blocks are naturally aligned to their
//! class size. Small blocks go back on their free list and their chunks are never unmapped.
//!
//! Larger allocations map their own pages and unmap them when freed. Alignment above a page is
//! refused (a null pointer), as is anything the page source refuses, such as a map past the
//! process's page budget.
//!
//! A native program opts in with
//!
//! ```ignore
//! #[global_allocator]
//! static HEAP: clean_slate_runtime::heap::RuntimeHeap = clean_slate_runtime::heap::RuntimeHeap::new();
//! ```
//!
//! and a manifest row whose `memory_pages` covers at least one chunk.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr::{null_mut, NonNull};
use core::sync::atomic::{AtomicBool, Ordering};

use clean_slate_native_abi::memory::{
    MEMORY_PAGE_BYTES, MEMORY_SUBOP_MAP, MEMORY_SUBOP_UNMAP, SYSCALL_NR_MEMORY,
};

use crate::{Kernel, Syscalls};

pub const PAGE_BYTES: usize = MEMORY_PAGE_BYTES as usize;
/// Pages mapped at a time for small allocations.
pub const CHUNK_PAGES: usize = 16;
const CHUNK_BYTES: usize = CHUNK_PAGES * PAGE_BYTES;
const MIN_CLASS_SHIFT: u32 = 4;
const MAX_CLASS_SHIFT: u32 = 11;
const CLASSES: usize = (MAX_CLASS_SHIFT - MIN_CLASS_SHIFT + 1) as usize;
/// The largest small allocation.
pub const MAX_SMALL_BYTES: usize = 1 << MAX_CLASS_SHIFT;

/// Where the heap's pages come from.
pub trait PageSource {
    /// `pages` read-write pages, page-aligned; `None` when refused.
    fn map_pages(&mut self, pages: usize) -> Option<NonNull<u8>>;

    /// Gives back pages a [`Self::map_pages`] call returned, all of them at once.
    fn unmap_pages(&mut self, start: NonNull<u8>, pages: usize);
}

/// Pages from syscall 23.
pub struct MemoryPages<S: Syscalls> {
    sys: S,
}

impl<S: Syscalls> MemoryPages<S> {
    pub const fn new(sys: S) -> Self {
        Self { sys }
    }
}

impl<S: Syscalls> PageSource for MemoryPages<S> {
    fn map_pages(&mut self, pages: usize) -> Option<NonNull<u8>> {
        let bytes = pages.checked_mul(PAGE_BYTES)? as u64;
        let start = self
            .sys
            .call(SYSCALL_NR_MEMORY, [MEMORY_SUBOP_MAP, 0, bytes, 0, 0, 0])
            .ok()?;
        NonNull::new(start as *mut u8)
    }

    fn unmap_pages(&mut self, start: NonNull<u8>, pages: usize) {
        let _ = self.sys.call(
            SYSCALL_NR_MEMORY,
            [
                MEMORY_SUBOP_UNMAP,
                start.as_ptr() as u64,
                (pages * PAGE_BYTES) as u64,
                0,
                0,
                0,
            ],
        );
    }
}

/// Pages from a fixed region the caller owns (at most [`ArenaPages::MAX_PAGES`]), first fit,
/// with freed runs reused. For a heap that must not grow, or that is thrown away whole: the
/// network service's TLS scratch heap is one, reset after every transaction.
pub struct ArenaPages {
    base: usize,
    pages: usize,
    /// Bit `i` set: page `i` is mapped.
    used: u64,
    /// Most pages mapped at once.
    high_water: usize,
}

impl ArenaPages {
    pub const MAX_PAGES: usize = 64;

    /// A region with no pages: every map is refused.
    pub const fn empty() -> Self {
        Self {
            base: 0,
            pages: 0,
            used: 0,
            high_water: 0,
        }
    }

    /// The `pages` pages at `base` (page-aligned), all unmapped.
    ///
    /// # Safety
    /// `base` is page-aligned, `pages * PAGE_BYTES` bytes from it are writable and used by
    /// nothing else while this source (or a heap over it) hands them out.
    pub unsafe fn new(base: NonNull<u8>, pages: usize) -> Self {
        debug_assert!(base.as_ptr() as usize % PAGE_BYTES == 0);
        Self {
            base: base.as_ptr() as usize,
            pages: pages.min(Self::MAX_PAGES),
            used: 0,
            high_water: 0,
        }
    }

    /// Whether `ptr` is inside the region.
    pub fn contains(&self, ptr: *const u8) -> bool {
        let at = ptr as usize;
        at >= self.base && at < self.base + self.pages * PAGE_BYTES
    }

    pub fn high_water_pages(&self) -> usize {
        self.high_water
    }

    fn run_mask(start: usize, pages: usize) -> u64 {
        let ones = if pages >= 64 {
            u64::MAX
        } else {
            (1u64 << pages) - 1
        };
        ones << start
    }
}

impl PageSource for ArenaPages {
    fn map_pages(&mut self, pages: usize) -> Option<NonNull<u8>> {
        if pages == 0 || pages > self.pages {
            return None;
        }
        let start = (0..=self.pages - pages)
            .find(|&start| self.used & Self::run_mask(start, pages) == 0)?;
        self.used |= Self::run_mask(start, pages);
        self.high_water = self.high_water.max(self.used.count_ones() as usize);
        NonNull::new((self.base + start * PAGE_BYTES) as *mut u8)
    }

    fn unmap_pages(&mut self, start: NonNull<u8>, pages: usize) {
        if !self.contains(start.as_ptr()) {
            return;
        }
        let first = (start.as_ptr() as usize - self.base) / PAGE_BYTES;
        if first + pages <= self.pages {
            self.used &= !Self::run_mask(first, pages);
        }
    }
}

/// Counters, for tests and diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HeapStats {
    /// Chunks mapped for small allocations.
    pub chunks: usize,
    /// Pages mapped for large allocations and not yet unmapped.
    pub large_pages: usize,
    /// Allocations refused.
    pub refusals: usize,
}

/// The allocator, without a lock.
pub struct Heap<P: PageSource> {
    source: P,
    /// Head of each class's free list (an address, 0 for empty).
    free: [usize; CLASSES],
    bump: usize,
    bump_end: usize,
    stats: HeapStats,
}

enum Kind {
    Small(usize),
    Large(usize),
}

fn kind(layout: Layout) -> Option<Kind> {
    if layout.align() > PAGE_BYTES {
        return None;
    }
    let needed = layout.size().max(layout.align()).max(1);
    if needed <= MAX_SMALL_BYTES {
        let shift = needed
            .next_power_of_two()
            .trailing_zeros()
            .max(MIN_CLASS_SHIFT);
        Some(Kind::Small((shift - MIN_CLASS_SHIFT) as usize))
    } else {
        Some(Kind::Large(layout.size().div_ceil(PAGE_BYTES)))
    }
}

const fn class_bytes(class: usize) -> usize {
    1 << (class as u32 + MIN_CLASS_SHIFT)
}

impl<P: PageSource> Heap<P> {
    pub const fn new(source: P) -> Self {
        Self {
            source,
            free: [0; CLASSES],
            bump: 0,
            bump_end: 0,
            stats: HeapStats {
                chunks: 0,
                large_pages: 0,
                refusals: 0,
            },
        }
    }

    pub const fn stats(&self) -> HeapStats {
        self.stats
    }

    pub const fn source(&self) -> &P {
        &self.source
    }

    /// A block for `layout`, or null.
    pub fn allocate(&mut self, layout: Layout) -> *mut u8 {
        let block = match kind(layout) {
            Some(Kind::Small(class)) => self.small(class),
            Some(Kind::Large(pages)) => self.source.map_pages(pages).map(|start| {
                self.stats.large_pages += pages;
                start.as_ptr()
            }),
            None => None,
        };
        block.unwrap_or_else(|| {
            self.stats.refusals += 1;
            null_mut()
        })
    }

    /// Frees a block [`Self::allocate`] returned for the same `layout`.
    ///
    /// # Safety
    /// `ptr` came from this heap's `allocate(layout)` and is not used again.
    pub unsafe fn deallocate(&mut self, ptr: *mut u8, layout: Layout) {
        let Some(start) = NonNull::new(ptr) else {
            return;
        };
        match kind(layout) {
            Some(Kind::Small(class)) => {
                // SAFETY: the block is at least 16 bytes, 16-aligned, and now unused.
                unsafe { (ptr as *mut usize).write(self.free[class]) };
                self.free[class] = ptr as usize;
            }
            Some(Kind::Large(pages)) => {
                self.source.unmap_pages(start, pages);
                self.stats.large_pages -= pages;
            }
            None => {}
        }
    }

    fn small(&mut self, class: usize) -> Option<*mut u8> {
        let head = self.free[class];
        if head != 0 {
            // SAFETY: `head` is a free block of this class; its first word links the next.
            self.free[class] = unsafe { (head as *const usize).read() };
            return Some(head as *mut u8);
        }
        let size = class_bytes(class);
        let mut start = self.bump.next_multiple_of(size);
        if self.bump == 0 || start + size > self.bump_end {
            // The rest of the old chunk (under 2 KiB) is left unused.
            let chunk = self.source.map_pages(CHUNK_PAGES)?.as_ptr() as usize;
            self.stats.chunks += 1;
            self.bump_end = chunk + CHUNK_BYTES;
            start = chunk;
        }
        self.bump = start + size;
        Some(start as *mut u8)
    }
}

/// [`Heap`] behind a spin lock, as a `GlobalAlloc`.
pub struct LockedHeap<P: PageSource> {
    locked: AtomicBool,
    heap: UnsafeCell<Heap<P>>,
}

// SAFETY: every access to `heap` holds `locked`.
unsafe impl<P: PageSource + Send> Sync for LockedHeap<P> {}

impl<P: PageSource> LockedHeap<P> {
    pub const fn with_source(source: P) -> Self {
        Self {
            locked: AtomicBool::new(false),
            heap: UnsafeCell::new(Heap::new(source)),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut Heap<P>) -> R) -> R {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: the lock is held, so this is the only reference.
        let result = f(unsafe { &mut *self.heap.get() });
        self.locked.store(false, Ordering::Release);
        result
    }

    pub fn stats(&self) -> HeapStats {
        self.with(|heap| heap.stats())
    }
}

// SAFETY: `Heap` returns blocks of at least `layout.size()` bytes aligned to `layout.align()`,
// never hands out a block twice, and refuses with null.
unsafe impl<P: PageSource> GlobalAlloc for LockedHeap<P> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.with(|heap| heap.allocate(layout))
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller passes a block `alloc` returned for `layout`.
        self.with(|heap| unsafe { heap.deallocate(ptr, layout) })
    }
}

/// The heap a native program installs as its `#[global_allocator]`.
pub type RuntimeHeap = LockedHeap<MemoryPages<Kernel>>;

impl RuntimeHeap {
    pub const fn new() -> Self {
        Self::with_source(MemoryPages::new(Kernel))
    }
}

impl Default for RuntimeHeap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeKernel;
    use clean_slate_native_abi::status::STATUS_ENOSPC;
    use std::alloc::{alloc_zeroed, dealloc};
    use std::vec::Vec;

    /// Pages from the host allocator, with a page budget like the kernel's.
    struct HostPages {
        budget: usize,
        live: Vec<(usize, usize)>,
    }

    impl HostPages {
        fn new(budget: usize) -> Self {
            Self {
                budget,
                live: Vec::new(),
            }
        }

        fn used(&self) -> usize {
            self.live.iter().map(|(_, pages)| pages).sum()
        }
    }

    impl PageSource for HostPages {
        fn map_pages(&mut self, pages: usize) -> Option<NonNull<u8>> {
            if self.used() + pages > self.budget {
                return None;
            }
            let layout = Layout::from_size_align(pages * PAGE_BYTES, PAGE_BYTES).ok()?;
            // SAFETY: non-zero size.
            let start = NonNull::new(unsafe { alloc_zeroed(layout) })?;
            self.live.push((start.as_ptr() as usize, pages));
            Some(start)
        }

        fn unmap_pages(&mut self, start: NonNull<u8>, pages: usize) {
            let index = self
                .live
                .iter()
                .position(|&entry| entry == (start.as_ptr() as usize, pages))
                .expect("unmap of pages never mapped");
            self.live.remove(index);
            let layout = Layout::from_size_align(pages * PAGE_BYTES, PAGE_BYTES).unwrap();
            // SAFETY: mapped above with this layout.
            unsafe { dealloc(start.as_ptr(), layout) };
        }
    }

    impl Drop for HostPages {
        fn drop(&mut self) {
            for (start, pages) in core::mem::take(&mut self.live) {
                let layout = Layout::from_size_align(pages * PAGE_BYTES, PAGE_BYTES).unwrap();
                // SAFETY: mapped with this layout and never unmapped.
                unsafe { dealloc(start as *mut u8, layout) };
            }
        }
    }

    fn layout(size: usize, align: usize) -> Layout {
        Layout::from_size_align(size, align).unwrap()
    }

    /// A page-aligned host region of `pages` pages, leaked for the test's lifetime.
    fn host_region(pages: usize) -> NonNull<u8> {
        let layout = Layout::from_size_align(pages * PAGE_BYTES, PAGE_BYTES).unwrap();
        // SAFETY: non-zero size.
        NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap()
    }

    #[test]
    fn arena_pages_reuse_freed_runs_first_fit() {
        let base = host_region(8);
        // SAFETY: the region is ours and unused.
        let mut arena = unsafe { ArenaPages::new(base, 8) };
        let a = arena.map_pages(3).unwrap();
        let b = arena.map_pages(2).unwrap();
        assert_eq!(a, base);
        assert_eq!(b.as_ptr() as usize, base.as_ptr() as usize + 3 * PAGE_BYTES);
        assert!(arena.map_pages(4).is_none(), "only 3 pages left");
        arena.unmap_pages(a, 3);
        assert_eq!(arena.map_pages(2), Some(a), "the freed run is reused");
        assert_eq!(arena.high_water_pages(), 5);
        assert!(arena.contains(b.as_ptr()));
        assert!(!arena.contains((base.as_ptr() as usize + 8 * PAGE_BYTES) as *const u8));
        assert!(ArenaPages::empty().map_pages(1).is_none());
    }

    #[test]
    fn a_heap_over_arena_pages_refuses_past_the_region() {
        let base = host_region(CHUNK_PAGES + 2);
        // SAFETY: the region is ours and unused.
        let mut heap = Heap::new(unsafe { ArenaPages::new(base, CHUNK_PAGES + 2) });
        let small = heap.allocate(layout(64, 8));
        assert!(!small.is_null());
        let large = heap.allocate(layout(2 * PAGE_BYTES, 8));
        assert!(!large.is_null());
        assert!(heap.allocate(layout(PAGE_BYTES + 1, 8)).is_null());
        // SAFETY: allocated above with this layout.
        unsafe { heap.deallocate(large, layout(2 * PAGE_BYTES, 8)) };
        assert!(!heap.allocate(layout(PAGE_BYTES + 1, 8)).is_null());
    }

    #[test]
    fn sizes_pick_the_smallest_class_that_fits() {
        assert!(matches!(kind(layout(0, 1)), Some(Kind::Small(0))));
        assert!(matches!(kind(layout(16, 1)), Some(Kind::Small(0))));
        assert!(matches!(kind(layout(17, 1)), Some(Kind::Small(1))));
        assert!(matches!(kind(layout(8, 64)), Some(Kind::Small(2))));
        assert!(matches!(kind(layout(2048, 8)), Some(Kind::Small(7))));
        assert!(matches!(kind(layout(2049, 8)), Some(Kind::Large(1))));
        assert!(matches!(kind(layout(8, 4096)), Some(Kind::Large(1))));
        assert!(matches!(kind(layout(4097, 4096)), Some(Kind::Large(2))));
        assert!(kind(layout(8, 8192)).is_none());
    }

    #[test]
    fn blocks_are_aligned_distinct_and_hold_their_bytes() {
        let mut heap = Heap::new(HostPages::new(512));
        let mut blocks = Vec::new();
        for round in 0..200usize {
            let size = [1, 8, 16, 24, 100, 512, 2048, 3000, 9000][round % 9];
            let align = [1, 8, 16, 64, 256][round % 5];
            let layout = layout(size, align);
            let ptr = heap.allocate(layout);
            assert!(!ptr.is_null(), "round {round}");
            assert_eq!(ptr as usize % align, 0);
            // SAFETY: a fresh block of `size` bytes.
            unsafe { ptr.write_bytes(round as u8, size) };
            blocks.push((ptr, layout, round as u8));
        }
        for &(ptr, layout, byte) in &blocks {
            // SAFETY: still allocated.
            let bytes = unsafe { core::slice::from_raw_parts(ptr, layout.size()) };
            assert!(bytes.iter().all(|&b| b == byte), "a block was overwritten");
        }
        for (ptr, layout, _) in blocks {
            // SAFETY: allocated above, freed once.
            unsafe { heap.deallocate(ptr, layout) };
        }
        assert_eq!(heap.stats().large_pages, 0);
    }

    #[test]
    fn a_freed_block_is_reused_and_large_pages_go_back() {
        let mut heap = Heap::new(HostPages::new(64));
        let small = layout(40, 8);
        let first = heap.allocate(small);
        // SAFETY: allocated above.
        unsafe { heap.deallocate(first, small) };
        assert_eq!(heap.allocate(small), first);

        let large = layout(3 * PAGE_BYTES, 8);
        let ptr = heap.allocate(large);
        assert_eq!(heap.stats().large_pages, 3);
        // SAFETY: allocated above.
        unsafe { heap.deallocate(ptr, large) };
        assert_eq!(heap.stats().large_pages, 0);
        assert_eq!(heap.source.used(), CHUNK_PAGES);
    }

    #[test]
    fn a_refused_map_is_null() {
        let mut heap = Heap::new(HostPages::new(CHUNK_PAGES + 2));
        assert!(!heap.allocate(layout(2 * PAGE_BYTES, 8)).is_null());
        assert!(!heap.allocate(layout(8, 8)).is_null(), "a chunk fits");
        assert!(
            heap.allocate(layout(PAGE_BYTES * 2, 8)).is_null(),
            "the budget is spent"
        );
        // The 2 KiB blocks after the first 16 bytes fill the chunk; the next needs a new one.
        let mut blocks = 0;
        while !heap.allocate(layout(2048, 8)).is_null() {
            blocks += 1;
        }
        assert_eq!(blocks, CHUNK_BYTES / 2048 - 1);
        assert!(heap.allocate(layout(8, 8192)).is_null());
        assert_eq!(heap.stats().refusals, 3);
        assert_eq!(heap.stats().chunks, 1);
    }

    #[test]
    fn the_locked_heap_is_a_global_alloc() {
        let heap = LockedHeap::with_source(HostPages::new(32));
        let layout = layout(100, 16);
        // SAFETY: GlobalAlloc contract: non-zero size, freed with the same layout.
        unsafe {
            let ptr = GlobalAlloc::alloc(&heap, layout);
            assert!(!ptr.is_null());
            let zeroed = GlobalAlloc::alloc_zeroed(&heap, layout);
            assert!(core::slice::from_raw_parts(zeroed, 100)
                .iter()
                .all(|&b| b == 0));
            let grown = GlobalAlloc::realloc(&heap, ptr, layout, 5000);
            assert!(!grown.is_null());
            GlobalAlloc::dealloc(&heap, grown, Layout::from_size_align(5000, 16).unwrap());
            GlobalAlloc::dealloc(&heap, zeroed, layout);
        }
        assert_eq!(heap.stats().large_pages, 0);
    }

    #[test]
    fn memory_pages_speak_syscall_23() {
        let mut pages = MemoryPages::new(FakeKernel::new());
        pages.sys.answer_next(SYSCALL_NR_MEMORY, 0x6000_0000_0000);
        let start = pages.map_pages(16).expect("mapped");
        assert_eq!(start.as_ptr() as usize, 0x6000_0000_0000);
        assert_eq!(
            pages.sys.last_call(),
            (SYSCALL_NR_MEMORY, [MEMORY_SUBOP_MAP, 0, 16 * 4096, 0, 0, 0])
        );
        pages.sys.answer_next(SYSCALL_NR_MEMORY, 16);
        pages.unmap_pages(start, 16);
        assert_eq!(
            pages.sys.last_call(),
            (
                SYSCALL_NR_MEMORY,
                [MEMORY_SUBOP_UNMAP, 0x6000_0000_0000, 16 * 4096, 0, 0, 0]
            )
        );
        pages.sys.answer_next(SYSCALL_NR_MEMORY, STATUS_ENOSPC);
        assert!(pages.map_pages(1).is_none());
    }
}
