//! CPU-local register helpers: interrupt flag control, RFLAGS/CS/RSP reads and
//! the CR0.WP toggle used while editing live page tables.
//!
//! Why unsafe: `sti`/`cli` and CR0 writes change global CPU state. Callers of
//! `without_interrupts` must not block or yield inside the closure; callers of
//! `without_write_protect` must finish all page-table writes before the guard
//! restores CR0. No link contracts.

use core::arch::asm;
use core::mem::MaybeUninit;

use x86_64::registers::control::{Cr0, Cr0Flags};

use crate::arch::x86_64::{bit, RFLAGS_INTERRUPT_ENABLE_BIT};

pub(crate) fn without_interrupts<T>(f: impl FnOnce() -> T) -> T {
    let restore = interrupts_enabled();
    if restore {
        disable_interrupts();
    }
    let result = f();
    if restore {
        enable_interrupts();
    }
    result
}

fn interrupts_enabled() -> bool {
    bit(read_rflags(), RFLAGS_INTERRUPT_ENABLE_BIT as u32) != 0
}

pub(crate) fn read_rflags() -> u64 {
    let rflags: u64;
    unsafe {
        asm!("pushfq", "pop {}", out(reg) rflags, options(nomem, preserves_flags));
    }
    rflags
}

pub(crate) fn enable_interrupts() {
    unsafe {
        asm!("sti", options(nomem, nostack, preserves_flags));
    }
}

pub(crate) fn disable_interrupts() {
    unsafe {
        asm!("cli", options(nomem, nostack, preserves_flags));
    }
}

pub(crate) fn read_code_segment() -> u16 {
    let mut selector = MaybeUninit::<u16>::uninit();
    unsafe {
        asm!(
            "mov {0:x}, cs",
            out(reg) * selector.as_mut_ptr(),
            options(nomem, nostack, preserves_flags)
        );
        selector.assume_init()
    }
}

pub(crate) fn read_stack_pointer() -> u64 {
    let value: u64;
    unsafe {
        asm!("mov {}, rsp", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

#[allow(dead_code)]
pub(crate) fn without_write_protect<T>(f: impl FnOnce() -> T) -> T {
    let original = Cr0::read();
    let mut writable = original;
    writable.remove(Cr0Flags::WRITE_PROTECT);
    let _guard = Cr0RestoreGuard(original);
    unsafe {
        Cr0::write(writable);
    }
    let result = f();
    result
}

#[allow(dead_code)]
struct Cr0RestoreGuard(Cr0Flags);

#[allow(dead_code)]
impl Drop for Cr0RestoreGuard {
    fn drop(&mut self) {
        unsafe {
            Cr0::write(self.0);
        }
    }
}
