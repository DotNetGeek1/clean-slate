//! Model-specific register access (`rdmsr`/`wrmsr`).
//!
//! Why unsafe: writing an MSR reconfigures the CPU (APIC base, SYSCALL
//! entry, EFER). Callers must pass architecturally valid MSR numbers from
//! `super` and values that keep the current execution mode consistent.

use core::arch::asm;

pub(crate) fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

pub(crate) fn write_msr(msr: u32, value: u64) {
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nomem, nostack, preserves_flags)
        );
    }
}
