//! Validation of the user return state (selectors, RFLAGS, canonical
//! addresses) before `sysretq`.

#[cfg(feature = "m3-syscall-self-test")]
use crate::arch::x86_64::bit;
#[cfg(feature = "m3-syscall-self-test")]
use crate::arch::x86_64::cpu::read_rflags;
use crate::arch::x86_64::interrupt_context::{InterruptContext, SyscallContext};
use crate::arch::x86_64::GENERAL_PROTECTION_VECTOR;
#[cfg(any(feature = "m3-syscall-self-test", test))]
use crate::arch::x86_64::RFLAGS_DIRECTION_FLAG_BIT;
use crate::arch::x86_64::RFLAGS_STATUS_FLAGS_MASK;
#[cfg(feature = "m3-syscall-self-test")]
use crate::diagnostics::log::kernel_log_line;
#[cfg(feature = "m3-syscall-self-test")]
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::mm::USER_CANONICAL_TOP_EXCLUSIVE;
#[cfg(feature = "m3-syscall-self-test")]
use crate::selftest::m3_syscall::SYSCALL_DF_SANITIZED_MARKER;
#[cfg(feature = "m3-syscall-self-test")]
use crate::selftest::m3_syscall::SYSCALL_DF_SANITIZED_OBSERVED;
#[cfg(feature = "m3-syscall-self-test")]
use core::sync::atomic::Ordering;
use x86_64::structures::gdt::SegmentSelector;

pub(super) fn validate_sysret_selector_triplet(
    base: SegmentSelector,
    user_data: SegmentSelector,
    user_code: SegmentSelector,
) -> Result<(), &'static str> {
    let base_bits = base.0 as u64;
    let expected_user_data = base_bits
        .checked_add(8)
        .ok_or("SYSRET selector base overflowed while validating SS offset")?;
    let expected_user_code = base_bits
        .checked_add(16)
        .ok_or("SYSRET selector base overflowed while validating CS offset")?;
    if (user_data.0 as u64) != expected_user_data {
        return Err("GDT SYSRET user data selector was not base+8");
    }
    if (user_code.0 as u64) != expected_user_code {
        return Err("GDT SYSRET user code selector was not base+16");
    }
    Ok(())
}

/// Compares user RFLAGS captured at syscall entry against an expected value while
/// ignoring the arithmetic status flags, which user code changes freely.
#[allow(dead_code)]
pub(super) fn syscall_return_rflags_match(observed: u64, expected: u64) -> bool {
    (observed & !RFLAGS_STATUS_FLAGS_MASK) == (expected & !RFLAGS_STATUS_FLAGS_MASK)
}

pub(crate) fn validate_canonical_user_return_state(
    frame: &SyscallContext,
) -> Result<(), &'static str> {
    if frame.user_rip >= USER_CANONICAL_TOP_EXCLUSIVE {
        return Err("syscall return RIP was not a canonical userspace address");
    }
    if frame.user_rsp >= USER_CANONICAL_TOP_EXCLUSIVE {
        return Err("syscall return RSP was not a canonical userspace address");
    }
    Ok(())
}

/// The fault frame a user-mode #GP at the syscall return site would have
/// produced, for the CPL3 fault path. RCX/R11 hold what SYSCALL put there.
pub(crate) fn syscall_user_fault_context(
    frame: &SyscallContext,
    user_code_selector: u64,
) -> InterruptContext {
    InterruptContext {
        r15: frame.r15,
        r14: frame.r14,
        r13: frame.r13,
        r12: frame.r12,
        r11: frame.user_rflags,
        r10: frame.r10,
        r9: frame.r9,
        r8: frame.r8,
        rdi: frame.rdi,
        rsi: frame.rsi,
        rbp: frame.rbp,
        rbx: frame.rbx,
        rdx: frame.rdx,
        rcx: frame.user_rip,
        rax: frame.rax,
        vector: GENERAL_PROTECTION_VECTOR as u64,
        error_code: 0,
        rip: frame.user_rip,
        cs: user_code_selector,
        rflags: frame.user_rflags,
    }
}

#[cfg(feature = "m3-syscall-self-test")]
pub(super) fn maybe_validate_syscall_entry_flags(frame: &SyscallContext) {
    if bit(frame.user_rflags, RFLAGS_DIRECTION_FLAG_BIT as u32) == 0 {
        return;
    }

    if bit(read_rflags(), RFLAGS_DIRECTION_FLAG_BIT as u32) != 0 {
        fatal_kernel_error("syscall entry did not clear DF before running kernel code");
    }
    if !SYSCALL_DF_SANITIZED_OBSERVED.swap(true, Ordering::Relaxed) {
        kernel_log_line(SYSCALL_DF_SANITIZED_MARKER);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86_64::RFLAGS_ALIGNMENT_CHECK_BIT;
    use crate::arch::x86_64::RFLAGS_INTERRUPT_ENABLE_BIT;
    use crate::arch::x86_64::RFLAGS_IOPL_SHIFT;
    use crate::arch::x86_64::RFLAGS_NESTED_TASK_BIT;
    use crate::arch::x86_64::RFLAGS_RESUME_FLAG_BIT;
    use crate::arch::x86_64::RFLAGS_TRAP_FLAG_BIT;
    use crate::syscall::SYSCALL_ENTRY_RFLAGS_MASK;

    #[test]
    fn syscall_return_rflags_ignore_arithmetic_status_flags() {
        let base = 0x202u64;
        // ZF | PF set by a preceding `cmp` with equal operands.
        assert!(syscall_return_rflags_match(base | 0x40 | 0x4, base));
        // All status flags set.
        assert!(syscall_return_rflags_match(
            base | RFLAGS_STATUS_FLAGS_MASK,
            base
        ));
        // DF, TF, or a cleared IF must still be rejected.
        assert!(!syscall_return_rflags_match(
            base | (1u64 << RFLAGS_DIRECTION_FLAG_BIT),
            base
        ));
        assert!(!syscall_return_rflags_match(
            base | (1u64 << RFLAGS_TRAP_FLAG_BIT),
            base
        ));
        assert!(!syscall_return_rflags_match(0x2, base));
        assert_eq!(RFLAGS_STATUS_FLAGS_MASK, 0x8d5);
    }

    #[test]
    fn syscall_entry_fmask_clears_unsafe_user_flags() {
        assert_ne!(
            SYSCALL_ENTRY_RFLAGS_MASK & (1u64 << RFLAGS_INTERRUPT_ENABLE_BIT),
            0
        );
        assert_ne!(
            SYSCALL_ENTRY_RFLAGS_MASK & (1u64 << RFLAGS_DIRECTION_FLAG_BIT),
            0
        );
        assert_ne!(
            SYSCALL_ENTRY_RFLAGS_MASK & (1u64 << RFLAGS_TRAP_FLAG_BIT),
            0
        );
        assert_ne!(
            SYSCALL_ENTRY_RFLAGS_MASK & (1u64 << RFLAGS_NESTED_TASK_BIT),
            0
        );
        assert_ne!(
            SYSCALL_ENTRY_RFLAGS_MASK & (1u64 << RFLAGS_RESUME_FLAG_BIT),
            0
        );
        assert_ne!(
            SYSCALL_ENTRY_RFLAGS_MASK & (1u64 << RFLAGS_ALIGNMENT_CHECK_BIT),
            0
        );
        assert_eq!(
            SYSCALL_ENTRY_RFLAGS_MASK & (0b11u64 << RFLAGS_IOPL_SHIFT),
            0b11u64 << RFLAGS_IOPL_SHIFT
        );
    }

    fn syscall_frame(user_rip: u64, user_rsp: u64) -> SyscallContext {
        SyscallContext {
            rax: 39,
            rdx: 2,
            rbx: 3,
            rbp: 4,
            rsi: 5,
            rdi: 6,
            r8: 8,
            r9: 9,
            r10: 10,
            r12: 12,
            r13: 13,
            r14: 14,
            r15: 15,
            user_rip,
            user_rflags: 0x246,
            user_rsp,
        }
    }

    #[test]
    fn user_controlled_rsp_or_rip_outside_the_user_half_is_rejected() {
        let top = USER_CANONICAL_TOP_EXCLUSIVE;
        assert_eq!(
            validate_canonical_user_return_state(&syscall_frame(0x40_1000, top - 8)),
            Ok(())
        );
        for rsp in [top, 0x8000_0000_0000_0000, 0xffff_8000_0000_0000, u64::MAX] {
            assert_eq!(
                validate_canonical_user_return_state(&syscall_frame(0x40_1000, rsp)),
                Err("syscall return RSP was not a canonical userspace address"),
                "rsp {rsp:#x}"
            );
        }
        assert_eq!(
            validate_canonical_user_return_state(&syscall_frame(top, 0x7fff_0000)),
            Err("syscall return RIP was not a canonical userspace address")
        );
    }

    #[test]
    fn syscall_containment_reports_a_user_mode_general_protection_fault() {
        let frame = syscall_frame(0x40_1002, 0x8000_0000_0000_0000);
        let context = syscall_user_fault_context(&frame, 0x2b);
        assert_eq!(context.vector, GENERAL_PROTECTION_VECTOR as u64);
        assert_eq!(context.error_code, 0);
        assert_eq!(context.rip, 0x40_1002);
        assert_eq!(context.cs & 0b11, 3, "must look like a CPL3 fault");
        assert_eq!(context.rflags, 0x246);
        assert_eq!((context.rcx, context.r11), (0x40_1002, 0x246));
        assert_eq!((context.rax, context.rdi, context.r15), (39, 6, 15));
    }

    #[test]
    fn sysret_selector_triplet_requires_base_plus_offsets() {
        let valid = validate_sysret_selector_triplet(
            SegmentSelector(0x001b),
            SegmentSelector(0x0023),
            SegmentSelector(0x002b),
        );
        assert_eq!(valid, Ok(()));

        let bad_data = validate_sysret_selector_triplet(
            SegmentSelector(0x001b),
            SegmentSelector(0x002b),
            SegmentSelector(0x002b),
        );
        assert_eq!(
            bad_data,
            Err("GDT SYSRET user data selector was not base+8")
        );

        let bad_code = validate_sysret_selector_triplet(
            SegmentSelector(0x001b),
            SegmentSelector(0x0023),
            SegmentSelector(0x0033),
        );
        assert_eq!(
            bad_code,
            Err("GDT SYSRET user code selector was not base+16")
        );
    }
}
