//! Host-testable Linux register decode from [`SyscallContext`].

use crate::arch::x86_64::interrupt_context::SyscallContext;
use clean_slate_linux_abi::{decode_linux_syscall, LinuxSyscallRegisters, LinuxSyscallRequest};

/// Extract the Linux register subset from a saved SYSCALL frame.
pub(crate) const fn linux_registers_from_context(frame: &SyscallContext) -> LinuxSyscallRegisters {
    LinuxSyscallRegisters {
        rax: frame.rax,
        rdi: frame.rdi,
        rsi: frame.rsi,
        rdx: frame.rdx,
        r10: frame.r10,
        r8: frame.r8,
        r9: frame.r9,
    }
}

/// Decode a [`SyscallContext`] into a [`LinuxSyscallRequest`].
pub(crate) const fn decode_request_from_context(frame: &SyscallContext) -> LinuxSyscallRequest {
    decode_linux_syscall(linux_registers_from_context(frame))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_linux_abi::{SYS_EXIT, SYS_WRITE};

    fn frame_with(
        rax: u64,
        rdi: u64,
        rsi: u64,
        rdx: u64,
        r10: u64,
        r8: u64,
        r9: u64,
    ) -> SyscallContext {
        SyscallContext {
            rax,
            rdx,
            rbx: 0,
            rbp: 0,
            rsi,
            rdi,
            r8,
            r9,
            r10,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            user_rip: 0,
            user_rflags: 0,
            user_rsp: 0,
        }
    }

    #[test]
    fn decode_maps_linux_argument_registers() {
        let frame = frame_with(SYS_WRITE, 1, 0x1000, 13, 0xdead, 0xbeef, 0xcafe);
        let req = decode_request_from_context(&frame);
        assert_eq!(req.nr, SYS_WRITE);
        assert_eq!(req.args, [1, 0x1000, 13, 0xdead, 0xbeef, 0xcafe]);
    }

    #[test]
    fn decode_preserves_exit_number() {
        let frame = frame_with(SYS_EXIT, 0, 0, 0, 0, 0, 0);
        assert_eq!(decode_request_from_context(&frame).nr, SYS_EXIT);
    }
}
