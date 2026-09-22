#![cfg_attr(not(test), no_std)]

#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-capabilities-self-test"
))]
use core::alloc::{GlobalAlloc, Layout};
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-capabilities-self-test"
))]
use core::ptr::null_mut;
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-capabilities-self-test"
))]
use core::sync::atomic::{AtomicUsize, Ordering};

mod arch;
mod boot;
mod capability;
mod device;
mod diagnostics;
mod interrupt;
mod ipc;
mod mm;
mod process;
mod sched;
mod service;
// Milestone self-tests exit QEMU before the normal boot tail runs, so each
// feature build leaves parts of its own scaffolding unreferenced. The
// allowance is scoped to this module only; production modules must stay
// warning-clean in every configuration.
#[cfg_attr(
    any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test",
        feature = "m3-address-space-self-test",
        feature = "m3-entry-self-test",
        feature = "m3-resources-self-test",
        feature = "m4-crash-service-self-test",
        feature = "m4-recovery-self-test",
        feature = "m3-syscall-self-test",
        feature = "m3-ipc-self-test",
        feature = "m8-linux-dispatch-self-test",
        feature = "m9-syscall-fail-closed-self-test",
        feature = "m4-service-lifecycle-self-test",
        feature = "m5-block-self-test",
        feature = "m7-net-device-self-test",
        feature = "m7-tls-self-test",
        feature = "m7-tls-fail-closed-self-test",
        feature = "m7-dns-self-test",
        feature = "m5-storage-self-test",
        feature = "m5-persistence-self-test",
        feature = "m5-crash-early-self-test",
        feature = "m5-crash-late-self-test",
        feature = "m5-crash-recovery-self-test",
        feature = "m6-object-self-test",
        feature = "m6-fixture-smoke-self-test"
    ),
    allow(dead_code)
)]
mod selftest;
mod sync;
mod syscall;

pub use diagnostics::qemu::qemu_exit_failure;
pub use diagnostics::serial::{serial_write_fmt, serial_write_line};

#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-capabilities-self-test"
))]
struct M5BumpAllocator;

#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-capabilities-self-test"
))]
const M5_HEAP_BYTES: usize = 1024 * 1024;
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-capabilities-self-test"
))]
static M5_HEAP_OFFSET: AtomicUsize = AtomicUsize::new(0);
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-capabilities-self-test"
))]
#[repr(align(16))]
struct M5Heap([u8; M5_HEAP_BYTES]);
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-capabilities-self-test"
))]
static mut M5_HEAP: M5Heap = M5Heap([0; M5_HEAP_BYTES]);

#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-capabilities-self-test"
))]
#[global_allocator]
static M5_ALLOCATOR: M5BumpAllocator = M5BumpAllocator;

#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-capabilities-self-test"
))]
unsafe impl GlobalAlloc for M5BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align();
        let size = layout.size();
        if align == 0 || size == 0 {
            return null_mut();
        }
        let mut current = M5_HEAP_OFFSET.load(Ordering::Relaxed);
        loop {
            let aligned = (current + (align - 1)) & !(align - 1);
            let Some(next) = aligned.checked_add(size) else {
                return null_mut();
            };
            if next > M5_HEAP_BYTES {
                return null_mut();
            }
            match M5_HEAP_OFFSET.compare_exchange(
                current,
                next,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    let base = unsafe { core::ptr::addr_of_mut!(M5_HEAP.0) as *mut u8 };
                    return unsafe { base.add(aligned) };
                }
                Err(observed) => current = observed,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

pub fn run() -> uefi::Status {
    boot::run()
}
