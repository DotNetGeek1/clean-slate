//! Kernel stacks with a guard page directly below the usable bytes (#162).
//!
//! Every kernel stack (per-slot task stacks, which double as the TSS RSP0 and
//! SYSCALL stacks; the boot stack; the double-fault IST stack) is a
//! `GuardedStack`: a page-aligned block whose lowest page is the guard and
//! whose remaining bytes are the stack. The guard is ordinary image memory
//! until `mm::stack_guard` unmaps it from the kernel root at boot, so a
//! descending overflow faults on the guard instead of writing into whatever
//! the linker placed below. The layout costs nothing at runtime: detection is
//! purely a missing page-table entry.

pub(crate) const KERNEL_STACK_GUARD_BYTES: usize = 4096;

#[repr(C, align(4096))]
pub(crate) struct GuardedStack<const N: usize> {
    guard: [u8; KERNEL_STACK_GUARD_BYTES],
    bytes: [u8; N],
}

impl<const N: usize> GuardedStack<N> {
    const SIZE_IS_PAGE_MULTIPLE: () = assert!(N % KERNEL_STACK_GUARD_BYTES == 0 && N > 0);

    pub(crate) const fn new() -> Self {
        let () = Self::SIZE_IS_PAGE_MULTIPLE;
        Self {
            guard: [0; KERNEL_STACK_GUARD_BYTES],
            bytes: [0; N],
        }
    }

    /// First byte of the guard page (page aligned).
    pub(crate) fn guard_start(&self) -> u64 {
        self.guard.as_ptr() as u64
    }

    /// Lowest usable stack byte; the guard page ends here.
    pub(crate) fn base(&self) -> u64 {
        self.bytes.as_ptr() as u64
    }

    /// Initial stack pointer (exclusive end of the usable bytes, page aligned).
    pub(crate) fn top(&self) -> u64 {
        self.base() + N as u64
    }
}
