//! Validation of the user return state (selectors, RFLAGS, canonical
//! addresses) before `sysretq`.

#[cfg(feature = "m3-syscall-self-test")]
use crate::arch::x86_64::bit;
#[cfg(feature = "m3-syscall-self-test")]
use crate::arch::x86_64::cpu::read_rflags;
use crate::arch::x86_64::interrupt_context::SyscallContext;
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
