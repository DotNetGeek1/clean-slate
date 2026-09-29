//! x86-64 CPU mechanism: descriptor tables, entry/exit stubs, APIC, MSRs,
//! ports and the raw constants (vectors, RFLAGS bits, MSR numbers) shared by
//! the submodules. This module provides mechanism only; it must not depend on
//! policy modules (`sched`, `process`, `ipc`, `syscall`, `interrupt`,
//! `selftest`). The assembly in `asm.rs` reaches Rust policy code by symbol
//! name only.

pub(crate) mod apic;
pub(crate) mod asm;
pub(crate) mod context_switch;
pub(crate) mod cpu;
pub(crate) mod gdt;
pub(crate) mod guarded_stack;
pub(crate) mod idt;
pub(crate) mod interrupt_context;
pub(crate) mod ioapic;
pub(crate) mod msr;
pub(crate) mod port;

pub(crate) const DOUBLE_FAULT_VECTOR: usize = 8;
pub(crate) const PAGE_FAULT_VECTOR: usize = 14;
#[cfg(feature = "m3-entry-self-test")]
pub(crate) const GENERAL_PROTECTION_VECTOR: usize = 13;
pub(crate) const TIMER_VECTOR: usize = 32;
pub(crate) const SPURIOUS_VECTOR: usize = 33;
/// Device interrupt vectors `0x30..0x40`; allocation policy lives in `interrupt::irq`.
pub(crate) const DEVICE_VECTOR_FIRST: usize = 0x30;
pub(crate) const DEVICE_VECTOR_COUNT: usize = 16;
#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m4-recovery-self-test",
    feature = "m3-entry-self-test"
))]
pub(crate) const USER_TEST_VECTOR: usize = 0x80;
pub(crate) const IA32_EFER_MSR: u32 = 0xc000_0080;
pub(crate) const IA32_STAR_MSR: u32 = 0xc000_0081;
pub(crate) const IA32_LSTAR_MSR: u32 = 0xc000_0082;
pub(crate) const IA32_FMASK_MSR: u32 = 0xc000_0084;
pub(crate) const IA32_EFER_SCE: u64 = 1;
/// Without it bit 63 of every paging entry is reserved, so any `NO_EXECUTE`
/// entry takes a reserved-bit #PF instead of enforcing no-execute.
pub(crate) const IA32_EFER_NXE: u64 = 1 << 11;
pub(crate) const CPUID_EXTENDED_MAX_LEAF: u32 = 0x8000_0000;
pub(crate) const CPUID_EXTENDED_FEATURES_LEAF: u32 = 0x8000_0001;
const CPUID_EXTENDED_FEATURES_EDX_NX: u32 = 1 << 20;
pub(crate) const RFLAGS_TRAP_FLAG_BIT: u64 = 8;
pub(crate) const RFLAGS_INTERRUPT_ENABLE_BIT: u64 = 9;
pub(crate) const RFLAGS_DIRECTION_FLAG_BIT: u64 = 10;
pub(crate) const RFLAGS_IOPL_SHIFT: u64 = 12;
pub(crate) const RFLAGS_NESTED_TASK_BIT: u64 = 14;
pub(crate) const RFLAGS_RESUME_FLAG_BIT: u64 = 16;
pub(crate) const RFLAGS_ALIGNMENT_CHECK_BIT: u64 = 18;
const RFLAGS_CARRY_FLAG_BIT: u64 = 0;
const RFLAGS_PARITY_FLAG_BIT: u64 = 2;
const RFLAGS_AUXILIARY_CARRY_FLAG_BIT: u64 = 4;
const RFLAGS_ZERO_FLAG_BIT: u64 = 6;
const RFLAGS_SIGN_FLAG_BIT: u64 = 7;
const RFLAGS_OVERFLOW_FLAG_BIT: u64 = 11;
/// Arithmetic status flags that user code legitimately changes between syscalls
/// (e.g. via `cmp`/`test`); they must be ignored when validating return RFLAGS.
pub(crate) const RFLAGS_STATUS_FLAGS_MASK: u64 = (1u64 << RFLAGS_CARRY_FLAG_BIT)
    | (1u64 << RFLAGS_PARITY_FLAG_BIT)
    | (1u64 << RFLAGS_AUXILIARY_CARRY_FLAG_BIT)
    | (1u64 << RFLAGS_ZERO_FLAG_BIT)
    | (1u64 << RFLAGS_SIGN_FLAG_BIT)
    | (1u64 << RFLAGS_OVERFLOW_FLAG_BIT);

pub(crate) const fn bit(value: u64, index: u32) -> u8 {
    ((value >> index) & 1) as u8
}

/// `ext_edx` is CPUID `0x8000_0001` EDX, meaningful only when
/// `max_extended_leaf` reaches that leaf.
pub(crate) const fn nx_supported_from_cpuid(max_extended_leaf: u32, ext_edx: u32) -> bool {
    max_extended_leaf >= CPUID_EXTENDED_FEATURES_LEAF
        && ext_edx & CPUID_EXTENDED_FEATURES_EDX_NX != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nx_supported_from_cpuid_requires_leaf_and_bit() {
        assert!(!nx_supported_from_cpuid(CPUID_EXTENDED_MAX_LEAF, u32::MAX));
        assert!(!nx_supported_from_cpuid(CPUID_EXTENDED_FEATURES_LEAF, 0));
        assert!(!nx_supported_from_cpuid(
            CPUID_EXTENDED_FEATURES_LEAF,
            !CPUID_EXTENDED_FEATURES_EDX_NX
        ));
        assert!(nx_supported_from_cpuid(
            CPUID_EXTENDED_FEATURES_LEAF,
            1 << 20
        ));
        assert!(nx_supported_from_cpuid(0x8000_0008, 1 << 20));
    }

    #[test]
    fn nx_efer_bit_is_bit_11() {
        assert_eq!(IA32_EFER_NXE, 0x800);
        assert_eq!(IA32_EFER_NXE & IA32_EFER_SCE, 0);
    }
}
