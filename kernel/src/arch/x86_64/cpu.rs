//! CPU-local register helpers: interrupt flag control, RFLAGS/CS/RSP reads,
//! the CR0.WP toggle used while editing live page tables, the boot-time
//! EFER.NXE enable and the boot-time supervisor guards (CR0.WP, CR4.SMEP,
//! CR4.SMAP, CR4.UMIP).
//!
//! Why unsafe: `sti`/`cli`, CR0 and CR4 writes change global CPU state. Callers of
//! `without_interrupts` must not block or yield inside the closure; callers of
//! `without_write_protect` must finish all page-table writes before the guard
//! restores CR0. `__cpuid` only reads identification leaves. No link contracts.

use core::arch::asm;
use core::arch::x86_64::{__cpuid, __cpuid_count};
use core::fmt;
use core::mem::MaybeUninit;

use x86_64::registers::control::{Cr0, Cr0Flags};

use crate::arch::x86_64::msr::{read_msr, write_msr};
use crate::arch::x86_64::{
    bit, cr4_with_guards, guard_support_from_cpuid, nx_supported_from_cpuid, GuardSupport,
    CPUID_EXTENDED_FEATURES_LEAF, CPUID_EXTENDED_MAX_LEAF, CPUID_STRUCTURED_FEATURES_LEAF,
    CR4_SMAP, CR4_SMEP, CR4_UMIP, IA32_EFER_MSR, IA32_EFER_NXE, RFLAGS_INTERRUPT_ENABLE_BIT,
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

/// What [`enable_kernel_guards`] found and left set; its `Display` is the boot line's fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GuardReport {
    pub(crate) support: GuardSupport,
    pub(crate) firmware_wp: bool,
    pub(crate) smep: bool,
    pub(crate) smap: bool,
    pub(crate) umip: bool,
}

fn guard_state(supported: bool, enabled: bool) -> &'static str {
    match (supported, enabled) {
        (_, true) => "on",
        (true, false) => "off",
        (false, false) => "unsupported",
    }
}

impl fmt::Display for GuardReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "wp=on smep={} smap={} umip={} firmware_wp={}",
            guard_state(self.support.smep, self.smep),
            guard_state(self.support.smap, self.smap),
            guard_state(self.support.umip, self.umip),
            self.firmware_wp as u8
        )
    }
}

/// Sets CR0.WP, so a supervisor write to a read-only page faults, and CR4.SMEP, CR4.SMAP and
/// CR4.UMIP when CPUID reports them; records the SMAP decision for `mm::user_access`. Fails if a bit does not latch. CR0 and CR4 are per CPU: every
/// additional core must call this before running kernel code that relies on the guards.
pub(crate) fn enable_kernel_guards() -> Result<GuardReport, &'static str> {
    let max_basic_leaf = unsafe { __cpuid(0) }.eax;
    let (ebx, ecx) = if max_basic_leaf >= CPUID_STRUCTURED_FEATURES_LEAF {
        let leaf = unsafe { __cpuid_count(CPUID_STRUCTURED_FEATURES_LEAF, 0) };
        (leaf.ebx, leaf.ecx)
    } else {
        (0, 0)
    };
    let support = guard_support_from_cpuid(max_basic_leaf, ebx, ecx);

    let cr0 = Cr0::read();
    let firmware_wp = cr0.contains(Cr0Flags::WRITE_PROTECT);
    if !firmware_wp {
        unsafe { Cr0::write(cr0 | Cr0Flags::WRITE_PROTECT) };
    }
    if !Cr0::read().contains(Cr0Flags::WRITE_PROTECT) {
        return Err("CR0.WP did not latch");
    }

    let cr4 = read_cr4();
    let desired = cr4_with_guards(cr4, support);
    if desired != cr4 {
        unsafe {
            asm!("mov cr4, {}", in(reg) desired, options(nostack, preserves_flags));
        }
    }
    let cr4 = read_cr4();
    crate::mm::user_access::record_smap_enabled(cr4 & CR4_SMAP != 0);
    if cr4 & desired != desired {
        return Err("CR4 guard bits did not latch");
    }
    Ok(GuardReport {
        support,
        firmware_wp,
        smep: cr4 & CR4_SMEP != 0,
        smap: cr4 & CR4_SMAP != 0,
        umip: cr4 & CR4_UMIP != 0,
    })
}

pub(crate) fn read_cr4() -> u64 {
    let value: u64;
    unsafe {
        asm!("mov {}, cr4", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

/// This CPU's MAXPHYADDR (CPUID `0x8000_0008` EAX[7:0]).
#[cfg(not(test))]
pub(crate) fn physical_address_bits() -> u32 {
    use crate::arch::x86_64::{physical_address_bits_from_cpuid, CPUID_ADDRESS_SIZES_LEAF};
    let max_extended_leaf = unsafe { __cpuid(CPUID_EXTENDED_MAX_LEAF) }.eax;
    let address_sizes_eax = if max_extended_leaf >= CPUID_ADDRESS_SIZES_LEAF {
        unsafe { __cpuid(CPUID_ADDRESS_SIZES_LEAF) }.eax
    } else {
        0
    };
    physical_address_bits_from_cpuid(max_extended_leaf, address_sizes_eax)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_report_names_each_guard_on_off_or_unsupported() {
        let report = GuardReport {
            support: GuardSupport {
                smep: true,
                smap: true,
                umip: false,
            },
            firmware_wp: true,
            smep: true,
            smap: false,
            umip: false,
        };
        assert_eq!(
            format!("{report}"),
            "wp=on smep=on smap=off umip=unsupported firmware_wp=1"
        );
        let all_on = GuardReport {
            support: GuardSupport {
                smep: true,
                smap: true,
                umip: true,
            },
            firmware_wp: false,
            smep: true,
            smap: true,
            umip: true,
        };
        assert_eq!(
            format!("{all_on}"),
            "wp=on smep=on smap=on umip=on firmware_wp=0"
        );
    }
}
