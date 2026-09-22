//! Linux syscall handler table (M8 placeholders; #94 fills write/exit).

use crate::arch::x86_64::interrupt_context::SyscallContext;
use clean_slate_linux_abi::{LinuxSyscallRequest, LinuxSyscallResult, ENOSYS, SYS_EXIT, SYS_WRITE};
use clean_slate_service_lifecycle::InstanceGeneration;

/// Trusted caller identity + mutable SYSCALL frame for Linux handlers.
pub(crate) struct LinuxSyscallContext<'a> {
    /// Calling process id (trusted). Consumed by #94 `exit` / fd paths.
    #[allow(dead_code)]
    pub(crate) pid: u64,
    /// Live instance generation for fail-closed fd lookups (#95/#94).
    #[allow(dead_code)]
    pub(crate) instance_generation: InstanceGeneration,
    pub(crate) frame: &'a mut SyscallContext,
}

/// Handler signature consumed by #94 (`write` / `exit`).
pub(crate) type LinuxSyscallHandler =
    fn(&LinuxSyscallRequest, &mut LinuxSyscallContext<'_>) -> LinuxSyscallResult;

/// Look up the M8 handler for `nr`, or `None` for unsupported numbers.
pub(crate) fn lookup_handler(nr: u64) -> Option<LinuxSyscallHandler> {
    match nr {
        SYS_WRITE => Some(handle_sys_write_placeholder),
        SYS_EXIT => Some(handle_sys_exit_placeholder),
        _ => None,
    }
}

/// #94 implements — placeholder returns `-ENOSYS` so the table is wired now.
fn handle_sys_write_placeholder(
    _request: &LinuxSyscallRequest,
    _ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    // #94 implements
    Err(ENOSYS)
}

/// #94 implements — placeholder returns `-ENOSYS` so the table is wired now.
fn handle_sys_exit_placeholder(
    _request: &LinuxSyscallRequest,
    _ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    // #94 implements
    Err(ENOSYS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86_64::interrupt_context::SyscallContext;
    use clean_slate_linux_abi::{encode_rax, SYS_WRITE};

    fn empty_frame() -> SyscallContext {
        SyscallContext {
            rax: 0,
            rdx: 0,
            rbx: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
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
    fn write_and_exit_placeholders_return_enosys() {
        let mut frame = empty_frame();
        let mut ctx = LinuxSyscallContext {
            pid: 1,
            instance_generation: InstanceGeneration(1),
            frame: &mut frame,
        };
        let write_req = LinuxSyscallRequest {
            nr: SYS_WRITE,
            args: [1, 0, 0, 0, 0, 0],
        };
        let exit_req = LinuxSyscallRequest {
            nr: SYS_EXIT,
            args: [0; 6],
        };
        assert_eq!(
            lookup_handler(SYS_WRITE).unwrap()(&write_req, &mut ctx),
            Err(ENOSYS)
        );
        assert_eq!(
            lookup_handler(SYS_EXIT).unwrap()(&exit_req, &mut ctx),
            Err(ENOSYS)
        );
        assert!(lookup_handler(999).is_none());
        assert_eq!(encode_rax(Err(ENOSYS)) as i64, -38);
    }
}
