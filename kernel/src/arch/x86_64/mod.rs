//! x86-64 CPU mechanism: descriptor tables, entry/exit stubs, APIC, MSRs,
//! ports and the raw constants (vectors, RFLAGS bits, MSR numbers) shared by
//! the submodules. This module provides mechanism only; it must not depend on
//! policy modules (`sched`, `process`, `ipc`, `syscall`, `interrupt`,
//! `selftest`). The assembly in `asm.rs` reaches Rust policy code by symbol
//! name only.

pub(crate) mod cpu;
pub(crate) mod msr;
pub(crate) mod port;

pub(crate) const DOUBLE_FAULT_VECTOR: usize = 8;
pub(crate) const PAGE_FAULT_VECTOR: usize = 14;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
const GENERAL_PROTECTION_VECTOR: usize = 13;
pub(crate) const TIMER_VECTOR: usize = 32;
pub(crate) const SPURIOUS_VECTOR: usize = 33;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
const USER_TEST_VECTOR: usize = 0x80;
pub(crate) const IA32_EFER_MSR: u32 = 0xc000_0080;
pub(crate) const IA32_STAR_MSR: u32 = 0xc000_0081;
pub(crate) const IA32_LSTAR_MSR: u32 = 0xc000_0082;
pub(crate) const IA32_FMASK_MSR: u32 = 0xc000_0084;
pub(crate) const IA32_EFER_SCE: u64 = 1;
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
