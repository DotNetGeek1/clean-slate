//! A small first-fit free-list heap for the storage service.
//!
//! The service keeps every object in memory and copies them on each commit, so a heap that
//! never frees (a bump allocator) runs out after a bounded number of requests however few
//! objects are live. This one returns freed blocks to an address-ordered free list and merges
//! neighbours, so a long-running service needs only as much heap as its live objects and one
//! commit's copies.
//!
//! It is single-threaded: the service has one thread, and nothing here synchronises.

use core::alloc::Layout;
use core::ptr::{self, NonNull};

/// Every block starts on this alignment and its size is a multiple of it.
pub const HEAP_ALIGN: usize = 16;
/// Bytes before each allocation holding the block's size.
const HEADER: usize = HEAP_ALIGN;
/// The smallest remainder worth splitting off as a free block.
const MIN_BLOCK: usize = 2 * HEAP_ALIGN;

/// A free block: its size (header included) and the next free block at a higher address.
#[repr(C)]
struct FreeBlock {
    size: usize,
    next: *mut FreeBlock,
}

/// A heap over one caller-provided region.
pub struct FreeListHeap {
    head: *mut FreeBlock,
    start: usize,
    end: usize,
}

impl FreeListHeap {
    /// An empty heap. [`init`](Self::init) must give it a region before it allocates.
    pub const fn empty() -> Self {
        Self {
            head: ptr::null_mut(),
            start: 0,
            end: 0,
        }
    }

    /// Hands the heap `len` bytes at `base`.
    ///
    /// # Safety
    /// The region must be valid for reads and writes, unused by anything else, and outlive
    /// the heap. `init` must be called once.
    pub unsafe fn init(&mut self, base: *mut u8, len: usize) {
        let start = (base as usize).next_multiple_of(HEAP_ALIGN);
        let end = (base as usize + len) & !(HEAP_ALIGN - 1);
        self.start = start;
        self.end = end;
        if end.saturating_sub(start) < MIN_BLOCK {
            self.head = ptr::null_mut();
            return;
        }
        let block = start as *mut FreeBlock;
        unsafe {
            block.write(FreeBlock {
                size: end - start,
                next: ptr::null_mut(),
            });
        }
        self.head = block;
    }

    /// Whether [`init`](Self::init) has run.
    pub fn is_initialized(&self) -> bool {
        self.end != 0
    }

    /// A block for `layout`, or `None` when no free block is large enough or the alignment
    /// is above [`HEAP_ALIGN`].
    pub fn allocate(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        if layout.align() > HEAP_ALIGN {
            return None;
        }
        let need = layout
            .size()
            .max(1)
            .checked_add(HEADER)?
            .checked_next_multiple_of(HEAP_ALIGN)?
            .max(MIN_BLOCK);
        let mut previous: *mut FreeBlock = ptr::null_mut();
        let mut current = self.head;
        while !current.is_null() {
            // SAFETY: every pointer on the free list is a free block inside the region.
            let block = unsafe { &mut *current };
            if block.size >= need {
                let next = if block.size - need >= MIN_BLOCK {
                    let rest = (current as usize + need) as *mut FreeBlock;
                    unsafe {
                        rest.write(FreeBlock {
                            size: block.size - need,
                            next: block.next,
                        });
                    }
                    block.size = need;
                    rest
                } else {
                    block.next
                };
                if previous.is_null() {
                    self.head = next;
                } else {
                    unsafe { (*previous).next = next };
                }
                let size = block.size;
                let header = current as *mut usize;
                unsafe { header.write(size) };
                return NonNull::new((current as usize + HEADER) as *mut u8);
            }
            previous = current;
            current = block.next;
        }
        None
    }

    /// Returns a block [`allocate`](Self::allocate) handed out.
    ///
    /// # Safety
    /// `ptr` must come from this heap's `allocate` and not have been freed since.
    pub unsafe fn free(&mut self, ptr: NonNull<u8>) {
        let block_addr = ptr.as_ptr() as usize - HEADER;
        let size = unsafe { (block_addr as *const usize).read() };
        debug_assert!(block_addr >= self.start && block_addr + size <= self.end);

        let mut previous: *mut FreeBlock = ptr::null_mut();
        let mut next = self.head;
        while !next.is_null() && (next as usize) < block_addr {
            previous = next;
            next = unsafe { (*next).next };
        }

        let block = block_addr as *mut FreeBlock;
        unsafe { block.write(FreeBlock { size, next }) };
        // Merge with the following free block.
        if !next.is_null() && block_addr + size == next as usize {
            unsafe {
                (*block).size += (*next).size;
                (*block).next = (*next).next;
            }
        }
        // Merge into the preceding free block, or link after it.
        if previous.is_null() {
            self.head = block;
        } else if previous as usize + unsafe { (*previous).size } == block_addr {
            unsafe {
                (*previous).size += (*block).size;
                (*previous).next = (*block).next;
            }
        } else {
            unsafe { (*previous).next = block };
        }
    }

    /// Bytes on the free list, headers included.
    pub fn free_bytes(&self) -> usize {
        let mut total = 0;
        let mut current = self.head;
        while !current.is_null() {
            unsafe {
                total += (*current).size;
                current = (*current).next;
            }
        }
        total
    }

    /// Blocks on the free list.
    pub fn free_blocks(&self) -> usize {
        let mut count = 0;
        let mut current = self.head;
        while !current.is_null() {
            count += 1;
            current = unsafe { (*current).next };
        }
        count
    }

    /// The region's size after alignment.
    pub fn capacity(&self) -> usize {
        self.end - self.start
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[repr(align(16))]
    struct Region([u8; 4096]);

    fn heap(region: &mut Region) -> FreeListHeap {
        let mut heap = FreeListHeap::empty();
        unsafe { heap.init(region.0.as_mut_ptr(), region.0.len()) };
        heap
    }

    fn layout(size: usize) -> Layout {
        Layout::from_size_align(size, 8).unwrap()
    }

    #[test]
    fn freeing_everything_restores_one_block_of_the_whole_region() {
        let mut region = Region([0; 4096]);
        let mut heap = heap(&mut region);
        let blocks = (1..20)
            .map(|size| heap.allocate(layout(size * 7)).unwrap())
            .collect::<Vec<_>>();
        // Free in an interleaved order so every merge direction runs.
        for block in blocks
            .iter()
            .step_by(2)
            .chain(blocks.iter().skip(1).step_by(2))
        {
            unsafe { heap.free(*block) };
        }
        assert_eq!(heap.free_bytes(), heap.capacity());
        assert_eq!(heap.free_blocks(), 1);
    }

    #[test]
    fn allocations_are_aligned_and_disjoint_and_hold_their_bytes() {
        let mut region = Region([0; 4096]);
        let mut heap = heap(&mut region);
        let sizes = [1usize, 15, 16, 17, 100, 255];
        let blocks = sizes
            .iter()
            .map(|&size| (heap.allocate(layout(size)).unwrap(), size))
            .collect::<Vec<_>>();
        for (index, (block, size)) in blocks.iter().enumerate() {
            assert_eq!(block.as_ptr() as usize % HEAP_ALIGN, 0);
            unsafe { ptr::write_bytes(block.as_ptr(), index as u8, *size) };
        }
        for (index, (block, size)) in blocks.iter().enumerate() {
            let bytes = unsafe { core::slice::from_raw_parts(block.as_ptr(), *size) };
            assert!(bytes.iter().all(|&byte| byte == index as u8));
        }
    }

    #[test]
    fn a_long_run_of_alloc_and_free_never_exhausts_a_heap_that_fits_the_live_set() {
        let mut region = Region([0; 4096]);
        let mut heap = heap(&mut region);
        let mut live = Vec::new();
        for round in 0..10_000usize {
            if live.len() == 8 {
                let block = live.remove(round % 8);
                unsafe { heap.free(block) };
            }
            live.push(heap.allocate(layout(1 + (round * 37) % 300)).unwrap());
        }
        for block in live {
            unsafe { heap.free(block) };
        }
        assert_eq!(heap.free_blocks(), 1);
    }

    #[test]
    fn refuses_what_does_not_fit_and_alignments_above_sixteen() {
        let mut region = Region([0; 4096]);
        let mut heap = heap(&mut region);
        assert!(heap.allocate(layout(4096)).is_none());
        assert!(heap
            .allocate(Layout::from_size_align(8, 32).unwrap())
            .is_none());
        let whole = heap.allocate(layout(4096 - HEADER)).unwrap();
        assert!(heap.allocate(layout(1)).is_none());
        unsafe { heap.free(whole) };
        assert!(heap.allocate(layout(1)).is_some());
    }
}
