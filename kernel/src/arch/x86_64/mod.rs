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

pub(crate) const NMI_VECTOR: usize = 2;
pub(crate) const DOUBLE_FAULT_VECTOR: usize = 8;
pub(crate) const PAGE_FAULT_VECTOR: usize = 14;
pub(crate) const GENERAL_PROTECTION_VECTOR: usize = 13;
pub(crate) const MACHINE_CHECK_VECTOR: usize = 18;
pub(crate) const TIMER_VECTOR: usize = 32;
pub(crate) const SPURIOUS_VECTOR: usize = 33;
/// Device interrupt vectors `0x30..0x40`; allocation policy lives in `interrupt::irq`.
pub(crate) const DEVICE_VECTOR_FIRST: usize = 0x30;
pub(crate) const DEVICE_VECTOR_COUNT: usize = 16;
pub(crate) const USER_TEST_VECTOR: usize = 0x80;
pub(crate) const IA32_EFER_MSR: u32 = 0xc000_0080;
pub(crate) const IA32_STAR_MSR: u32 = 0xc000_0081;
pub(crate) const IA32_LSTAR_MSR: u32 = 0xc000_0082;
pub(crate) const IA32_FMASK_MSR: u32 = 0xc000_0084;
pub(crate) const IA32_EFER_SCE: u64 = 1;
/// Without it bit 63 of every paging entry is reserved, so any `NO_EXECUTE`
/// entry takes a reserved-bit #PF instead of enforcing no-execute.
pub(crate) const IA32_EFER_NXE: u64 = 1 << 11;
/// CPUID leaf 1: feature bits. ECX bit 31 is set when any hypervisor is present.
#[cfg(any(test, clean_slate_system_init))]
pub(crate) const CPUID_FEATURES_LEAF: u32 = 1;
/// CPUID leaf 1 ECX bit 31. QEMU sets it under TCG and under KVM/WHPX.
#[cfg(any(test, clean_slate_system_init))]
pub(crate) const CPUID_FEATURES_ECX_HYPERVISOR: u32 = 1 << 31;
pub(crate) const CPUID_EXTENDED_MAX_LEAF: u32 = 0x8000_0000;
pub(crate) const CPUID_EXTENDED_FEATURES_LEAF: u32 = 0x8000_0001;
const CPUID_EXTENDED_FEATURES_EDX_NX: u32 = 1 << 20;
pub(crate) const CPUID_ADDRESS_SIZES_LEAF: u32 = 0x8000_0008;
/// Physical-address width the SDM specifies for a CPU without CPUID leaf `0x8000_0008`.
const DEFAULT_PHYSICAL_ADDRESS_BITS: u32 = 36;
/// CPUID leaf 7 subleaf 0: structured extended features.
pub(crate) const CPUID_STRUCTURED_FEATURES_LEAF: u32 = 7;
const CPUID_STRUCTURED_EBX_SMEP: u32 = 1 << 7;
const CPUID_STRUCTURED_EBX_SMAP: u32 = 1 << 20;
const CPUID_STRUCTURED_ECX_UMIP: u32 = 1 << 2;
pub(crate) const CR4_UMIP: u64 = 1 << 11;
pub(crate) const CR4_SMEP: u64 = 1 << 20;
pub(crate) const CR4_SMAP: u64 = 1 << 21;
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

/// `feature_ecx` is CPUID leaf 1 ECX. The bit names a hypervisor, not which one.
#[cfg(any(test, clean_slate_system_init))]
pub(crate) const fn hypervisor_present_from_cpuid(feature_ecx: u32) -> bool {
    feature_ecx & CPUID_FEATURES_ECX_HYPERVISOR != 0
}

/// `ext_edx` is CPUID `0x8000_0001` EDX, meaningful only when
/// `max_extended_leaf` reaches that leaf.
pub(crate) const fn nx_supported_from_cpuid(max_extended_leaf: u32, ext_edx: u32) -> bool {
    max_extended_leaf >= CPUID_EXTENDED_FEATURES_LEAF
        && ext_edx & CPUID_EXTENDED_FEATURES_EDX_NX != 0
}

/// MAXPHYADDR: no physical address at or above `1 << bits` can exist on this CPU. `address_sizes_eax`
/// is CPUID `0x8000_0008` EAX, meaningful only when `max_extended_leaf` reaches that leaf.
pub(crate) const fn physical_address_bits_from_cpuid(
    max_extended_leaf: u32,
    address_sizes_eax: u32,
) -> u32 {
    if max_extended_leaf >= CPUID_ADDRESS_SIZES_LEAF {
        address_sizes_eax & 0xff
    } else {
        DEFAULT_PHYSICAL_ADDRESS_BITS
    }
}

/// Supervisor guard features CPUID reports. `ebx`/`ecx` are CPUID leaf 7 subleaf 0, meaningful
/// only when `max_basic_leaf` reaches that leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GuardSupport {
    pub(crate) smep: bool,
    pub(crate) smap: bool,
    pub(crate) umip: bool,
}

pub(crate) const fn guard_support_from_cpuid(max_basic_leaf: u32, ebx: u32, ecx: u32) -> GuardSupport {
    if max_basic_leaf < CPUID_STRUCTURED_FEATURES_LEAF {
        return GuardSupport {
            smep: false,
            smap: false,
            umip: false,
        };
    }
    GuardSupport {
        smep: ebx & CPUID_STRUCTURED_EBX_SMEP != 0,
        smap: ebx & CPUID_STRUCTURED_EBX_SMAP != 0,
        umip: ecx & CPUID_STRUCTURED_ECX_UMIP != 0,
    }
}

/// CR4 with SMEP and UMIP set where `support` allows. SMAP stays clear: kernel code still
/// dereferences user pointers directly (#217 stage B adds the copy helper that SMAP needs).
pub(crate) const fn cr4_with_guards(cr4: u64, support: GuardSupport) -> u64 {
    let mut value = cr4;
    if support.smep {
        value |= CR4_SMEP;
    }
    if support.umip {
        value |= CR4_UMIP;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hypervisor_present_is_leaf_1_ecx_bit_31() {
        assert_eq!(CPUID_FEATURES_LEAF, 1);
        assert!(!hypervisor_present_from_cpuid(0));
        assert!(!hypervisor_present_from_cpuid(1 << 30));
        assert!(hypervisor_present_from_cpuid(CPUID_FEATURES_ECX_HYPERVISOR));
        assert!(hypervisor_present_from_cpuid(u32::MAX));
    }

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
    fn physical_address_bits_come_from_leaf_8000_0008_or_default_to_36() {
        assert_eq!(physical_address_bits_from_cpuid(0x8000_0008, 0x3028), 40);
        assert_eq!(
            physical_address_bits_from_cpuid(0x8000_0021, 0x0030_302e),
            46
        );
        assert_eq!(physical_address_bits_from_cpuid(0x8000_0007, 0x3028), 36);
    }

    #[test]
    fn guard_support_needs_leaf_7_and_the_feature_bits() {
        let none = GuardSupport {
            smep: false,
            smap: false,
            umip: false,
        };
        assert_eq!(guard_support_from_cpuid(6, u32::MAX, u32::MAX), none);
        assert_eq!(guard_support_from_cpuid(7, 0, 0), none);
        assert_eq!(
            guard_support_from_cpuid(7, 1 << 7, 0),
            GuardSupport {
                smep: true,
                ..none
            }
        );
        assert_eq!(
            guard_support_from_cpuid(0xd, 1 << 20, 1 << 2),
            GuardSupport {
                smep: false,
                smap: true,
                umip: true
            }
        );
    }

    #[test]
    fn cr4_guards_set_smep_and_umip_but_never_smap() {
        let all = GuardSupport {
            smep: true,
            smap: true,
            umip: true,
        };
        assert_eq!(CR4_SMEP, 0x10_0000);
        assert_eq!(CR4_SMAP, 0x20_0000);
        assert_eq!(CR4_UMIP, 0x800);
        let base = 0x620;
        assert_eq!(cr4_with_guards(base, all), base | CR4_SMEP | CR4_UMIP);
        assert_eq!(cr4_with_guards(base, all) & CR4_SMAP, 0);
        let only_umip = GuardSupport {
            smep: false,
            smap: false,
            umip: true,
        };
        assert_eq!(cr4_with_guards(base, only_umip), base | CR4_UMIP);
    }

    #[test]
    fn nx_efer_bit_is_bit_11() {
        assert_eq!(IA32_EFER_NXE, 0x800);
        assert_eq!(IA32_EFER_NXE & IA32_EFER_SCE, 0);
    }
}
