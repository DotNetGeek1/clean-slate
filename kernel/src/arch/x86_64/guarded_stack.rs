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

    /// Deepest touched byte, measured from the top. Stacks start zeroed in
    /// `.bss`, so the lowest non-zero byte bounds the peak use (diagnostics
    /// only; a frame that wrote only zeros is not counted).
    pub(crate) fn high_water_bytes(&self) -> usize {
        let lowest_used = unsafe { lowest_nonzero_offset(self.bytes.as_ptr(), N) }.unwrap_or(N);
        N - lowest_used
    }
}

/// Offset of the first non-zero byte in `start[..len]`, read a word at a time
/// (`start` must be 8-byte aligned; a trailing partial word is read bytewise).
///
/// # Safety
/// `start[..len]` must be readable.
pub(crate) unsafe fn lowest_nonzero_offset(start: *const u8, len: usize) -> Option<usize> {
    let words = start as *const u64;
    for word_index in 0..len / 8 {
        let word = unsafe { core::ptr::read_volatile(words.add(word_index)) };
        if word != 0 {
            return Some(word_index * 8 + (word.trailing_zeros() / 8) as usize);
        }
    }
    (len / 8 * 8..len).find(|offset| unsafe { core::ptr::read_volatile(start.add(*offset)) } != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::boxed::Box;

    #[test]
    fn lowest_nonzero_offset_finds_the_exact_byte() {
        let mut bytes = Box::new([0u64; 5]);
        let start = bytes.as_ptr() as *const u8;
        assert_eq!(unsafe { lowest_nonzero_offset(start, 40) }, None);
        bytes[3] = 0x0000_ff00_0000_0000;
        assert_eq!(unsafe { lowest_nonzero_offset(start, 40) }, Some(3 * 8 + 5));
        assert_eq!(unsafe { lowest_nonzero_offset(start, 29) }, None);
        assert_eq!(unsafe { lowest_nonzero_offset(start, 30) }, Some(29));
        bytes[0] = 1;
        assert_eq!(unsafe { lowest_nonzero_offset(start, 40) }, Some(0));
    }

    #[test]
    fn high_water_counts_from_the_top() {
        let mut stack: Box<GuardedStack<8192>> = Box::new(GuardedStack::new());
        assert_eq!(stack.high_water_bytes(), 0);
        stack.bytes[8192 - 100] = 7;
        assert_eq!(stack.high_water_bytes(), 100);
        stack.bytes[10] = 7;
        assert_eq!(stack.high_water_bytes(), 8182);
    }
}
