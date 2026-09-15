//! Register-frame layouts shared with the assembly entry stubs.
//!
//! Why unsafe: these `#[repr(C)]` structs are the exact memory image pushed by
//! `clean_slate_interrupt_common` / `clean_slate_syscall_entry` in `asm.rs`.
//! Field order and count are a link contract: changing them requires changing
//! the push/pop sequences in `asm.rs` and the `[rsp + 120]` offset used by the
//! syscall stub. Callers receive pointers to live stack frames and must not
//! retain them past the return into the stub.

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct InterruptContext {
    pub(crate) r15: u64,
    pub(crate) r14: u64,
    pub(crate) r13: u64,
    pub(crate) r12: u64,
    pub(crate) r11: u64,
    pub(crate) r10: u64,
    pub(crate) r9: u64,
    pub(crate) r8: u64,
    pub(crate) rdi: u64,
    pub(crate) rsi: u64,
    pub(crate) rbp: u64,
    pub(crate) rbx: u64,
    pub(crate) rdx: u64,
    pub(crate) rcx: u64,
    pub(crate) rax: u64,
    pub(crate) vector: u64,
    pub(crate) error_code: u64,
    pub(crate) rip: u64,
    pub(crate) cs: u64,
    pub(crate) rflags: u64,
}

#[cfg(test)]
impl InterruptContext {
    pub(crate) const ZERO: Self = Self {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rdi: 0,
        rsi: 0,
        rbp: 0,
        rbx: 0,
        rdx: 0,
        rcx: 0,
        rax: 0,
        vector: 0,
        error_code: 0,
        rip: 0,
        cs: 0,
        rflags: 0,
    };
}

/// The `iretq` frame used to enter ring 3: the saved-register block followed
/// by the user `RSP`/`SS` pair the CPU pops after `RIP`/`CS`/`RFLAGS`.
/// `repr(C)` is required because the frame is written raw onto a kernel stack
/// and consumed by hardware, not by Rust.
#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m3-entry-self-test"
))]
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct UserspaceEntryFrame {
    // Written by `context_switch::build_userspace_entry_frame` and consumed by
    // the CPU on `iretq`; Rust only reads it back in host tests.
    #[allow(dead_code)]
    pub(crate) interrupt: InterruptContext,
    pub(crate) user_stack_pointer: u64,
    pub(crate) user_stack_segment: u64,
}

#[repr(C)]
pub(crate) struct SyscallContext {
    pub(crate) rax: u64,
    pub(crate) rdx: u64,
    pub(crate) rbx: u64,
    pub(crate) rbp: u64,
    pub(crate) rsi: u64,
    pub(crate) rdi: u64,
    pub(crate) r8: u64,
    pub(crate) r9: u64,
    pub(crate) r10: u64,
    pub(crate) r12: u64,
    pub(crate) r13: u64,
    pub(crate) r14: u64,
    pub(crate) r15: u64,
    pub(crate) user_rip: u64,
    pub(crate) user_rflags: u64,
    pub(crate) user_rsp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn syscall_context_layout_matches_entry_stub_contract() {
        assert_eq!(size_of::<SyscallContext>(), 16 * size_of::<u64>());
        assert_eq!(core::mem::offset_of!(SyscallContext, rax), 0);
        assert_eq!(core::mem::offset_of!(SyscallContext, rdx), 8);
        assert_eq!(core::mem::offset_of!(SyscallContext, rbx), 16);
        assert_eq!(core::mem::offset_of!(SyscallContext, rbp), 24);
        assert_eq!(core::mem::offset_of!(SyscallContext, rsi), 32);
        assert_eq!(core::mem::offset_of!(SyscallContext, rdi), 40);
        assert_eq!(core::mem::offset_of!(SyscallContext, r8), 48);
        assert_eq!(core::mem::offset_of!(SyscallContext, r9), 56);
        assert_eq!(core::mem::offset_of!(SyscallContext, r10), 64);
        assert_eq!(core::mem::offset_of!(SyscallContext, r12), 72);
        assert_eq!(core::mem::offset_of!(SyscallContext, r13), 80);
        assert_eq!(core::mem::offset_of!(SyscallContext, r14), 88);
        assert_eq!(core::mem::offset_of!(SyscallContext, r15), 96);
        assert_eq!(core::mem::offset_of!(SyscallContext, user_rip), 104);
        assert_eq!(core::mem::offset_of!(SyscallContext, user_rflags), 112);
        assert_eq!(core::mem::offset_of!(SyscallContext, user_rsp), 120);
    }

    #[cfg(any(
        feature = "m3-address-space-self-test",
        feature = "m3-resources-self-test",
        feature = "m3-entry-self-test"
    ))]
    #[test]
    fn userspace_entry_frame_layout_matches_iretq_contract() {
        // InterruptContext (15 GPRs + vector + error_code + rip/cs/rflags)
        // followed immediately by the user RSP/SS pair that `iretq` pops.
        assert_eq!(size_of::<InterruptContext>(), 20 * size_of::<u64>());
        assert_eq!(size_of::<UserspaceEntryFrame>(), 22 * size_of::<u64>());
        assert_eq!(core::mem::offset_of!(UserspaceEntryFrame, interrupt), 0);
        assert_eq!(
            core::mem::offset_of!(UserspaceEntryFrame, user_stack_pointer),
            size_of::<InterruptContext>()
        );
        assert_eq!(
            core::mem::offset_of!(UserspaceEntryFrame, user_stack_segment),
            size_of::<InterruptContext>() + 8
        );
    }
}
