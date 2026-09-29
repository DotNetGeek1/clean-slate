//! CPU-local register helpers: interrupt flag control, RFLAGS/CS/RSP reads,
//! the CR0.WP toggle used while editing live page tables and the boot-time
//! EFER.NXE enable.
//!
//! Why unsafe: `sti`/`cli` and CR0 writes change global CPU state. Callers of
//! `without_interrupts` must not block or yield inside the closure; callers of
//! `without_write_protect` must finish all page-table writes before the guard
//! restores CR0. `__cpuid` only reads identification leaves. No link contracts.

use core::arch::asm;
use core::arch::x86_64::__cpuid;
use core::mem::MaybeUninit;

use x86_64::registers::control::{Cr0, Cr0Flags};

use crate::arch::x86_64::msr::{read_msr, write_msr};
use crate::arch::x86_64::{
    bit, nx_supported_from_cpuid, CPUID_EXTENDED_FEATURES_LEAF, CPUID_EXTENDED_MAX_LEAF,
    IA32_EFER_MSR, IA32_EFER_NXE, RFLAGS_INTERRUPT_ENABLE_BIT,
};

pub(crate) struct NxeReport {
    pub(crate) firmware_had_nxe: bool,
}

/// Must run before any root containing `NO_EXECUTE` entries is activated.
/// Firmware that left NXE clear cannot have NX bits in its own live tables,
/// so setting it here is safe on the firmware root.
/// EFER is per CPU: every additional core must set NXE (and SCE) before loading
/// the kernel's page tables.
pub(crate) fn enable_and_verify_nxe() -> Result<NxeReport, &'static str> {
    let max_extended_leaf = unsafe { __cpuid(CPUID_EXTENDED_MAX_LEAF) }.eax;
    let ext_edx = if max_extended_leaf >= CPUID_EXTENDED_FEATURES_LEAF {
        unsafe { __cpuid(CPUID_EXTENDED_FEATURES_LEAF) }.edx
    } else {
        0
    };
    if !nx_supported_from_cpuid(max_extended_leaf, ext_edx) {
        return Err("CPU does not support NX (CPUID 8000_0001 EDX.20)");
    }
    let efer = read_msr(IA32_EFER_MSR);
    let firmware_had_nxe = efer & IA32_EFER_NXE != 0;
    if !firmware_had_nxe {
        write_msr(IA32_EFER_MSR, efer | IA32_EFER_NXE);
    }
    if read_msr(IA32_EFER_MSR) & IA32_EFER_NXE == 0 {
        return Err("EFER.NXE did not latch");
    }
    Ok(NxeReport { firmware_had_nxe })
}

pub(crate) fn without_interrupts<T>(f: impl FnOnce() -> T) -> T {
    // Host unit tests run in ring 3 where `cli`/`sti` fault
    // (STATUS_PRIVILEGED_INSTRUCTION); interrupt masking is meaningless there,
    // so the guard degenerates to a plain call. Production builds are unaffected.
    let restore = !cfg!(test) && interrupts_enabled();
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

/// `sti; hlt` as one instruction pair: the STI shadow holds off interrupts
/// until `hlt` has started, so one that becomes pending after the caller's
/// last check wakes the halt instead of being handled before it. With a
/// separate `enable_interrupts()` call the shadow only covers its `ret`.
pub(crate) fn enable_interrupts_and_halt() {
    unsafe {
        asm!("sti", "hlt", options(nomem, nostack, preserves_flags));
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
    f()
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
