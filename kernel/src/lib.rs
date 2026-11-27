#![cfg_attr(not(test), no_std)]

#[cfg(all(clean_slate_bump_allocator, not(test)))]
use core::alloc::{GlobalAlloc, Layout};
#[cfg(all(clean_slate_bump_allocator, not(test)))]
use core::ptr::null_mut;
#[cfg(all(clean_slate_bump_allocator, not(test)))]
use core::sync::atomic::{AtomicUsize, Ordering};

mod arch;
mod boot;
#[cfg(any(test, clean_slate_bump_allocator))]
mod bump_heap;
mod capability;
mod device;
mod diagnostics;
mod interrupt;
mod ipc;
mod limits;
mod mm;
mod process;
mod sched;
mod service;
// The boot tail is compiled out of a self-test build (`clean_slate_boot_tail` in
// `kernel/build.rs`), so this module is reached only from the lanes that name it.
mod selftest;
mod sync;
mod syscall;
mod time;

pub use diagnostics::qemu::qemu_exit_failure;
pub use diagnostics::serial::{serial_write_fmt, serial_write_line};

// Host tests keep the system allocator: the bump heap is 1 MiB and never frees, so a test
// binary built with a storage lane's features would run out of it (#213).
#[cfg(all(clean_slate_bump_allocator, not(test)))]
struct M5BumpAllocator;

#[cfg(all(clean_slate_bump_allocator, not(test)))]
const M5_HEAP_BYTES: usize = 1024 * 1024;
#[cfg(all(clean_slate_bump_allocator, not(test)))]
static M5_HEAP_OFFSET: AtomicUsize = AtomicUsize::new(0);
#[cfg(all(clean_slate_bump_allocator, not(test)))]
#[repr(align(16))]
struct M5Heap([u8; M5_HEAP_BYTES]);
#[cfg(all(clean_slate_bump_allocator, not(test)))]
static mut M5_HEAP: M5Heap = M5Heap([0; M5_HEAP_BYTES]);

#[cfg(all(clean_slate_bump_allocator, not(test)))]
#[global_allocator]
static M5_ALLOCATOR: M5BumpAllocator = M5BumpAllocator;

#[cfg(all(clean_slate_bump_allocator, not(test)))]
unsafe impl GlobalAlloc for M5BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = unsafe { core::ptr::addr_of_mut!(M5_HEAP.0) as *mut u8 };
        let mut current = M5_HEAP_OFFSET.load(Ordering::Relaxed);
        loop {
            // Align the address, not the offset: the heap base is only 16-byte aligned (#350).
            let Some(reservation) = bump_heap::reserve(
                base as usize,
                current,
                layout.size(),
                layout.align(),
                M5_HEAP_BYTES,
            ) else {
                return null_mut();
            };
            match M5_HEAP_OFFSET.compare_exchange(
                current,
                reservation.next,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => return unsafe { base.add(reservation.offset) },
                Err(observed) => current = observed,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

pub fn run() -> uefi::Status {
    boot::run()
}
