//! Linux syscall handler table (M8: `write` and `exit` only, #94).

use super::exit::handle_sys_exit;
use super::write::handle_sys_write;
use crate::arch::x86_64::interrupt_context::SyscallContext;
use clean_slate_linux_abi::{LinuxSyscallRequest, LinuxSyscallResult, SYS_EXIT, SYS_WRITE};
use clean_slate_service_lifecycle::InstanceGeneration;

/// Trusted caller identity + mutable SYSCALL frame for Linux handlers.
pub(crate) struct LinuxSyscallContext<'a> {
    /// Calling process id (trusted); the fd projection and `exit` key on it.
    pub(crate) pid: u64,
    /// Live instance generation for fail-closed fd lookups (#95/#94).
    pub(crate) instance_generation: InstanceGeneration,
    /// Saved SYSCALL frame. `dispatch_with` writes the encoded result into
    /// `frame.rax`; `exit` never returns so its frame is never resumed.
    pub(crate) frame: &'a mut SyscallContext,
}

/// Handler signature for Linux syscalls (`write` / `exit`).
pub(crate) type LinuxSyscallHandler =
    fn(&LinuxSyscallRequest, &mut LinuxSyscallContext<'_>) -> LinuxSyscallResult;

/// Look up the M8 handler for `nr`, or `None` for unsupported numbers.
pub(crate) fn lookup_handler(nr: u64) -> Option<LinuxSyscallHandler> {
    match nr {
        SYS_WRITE => Some(handle_sys_write),
        SYS_EXIT => Some(handle_sys_exit),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_linux_abi::{encode_rax, ENOSYS};

    #[test]
    fn table_maps_only_write_and_exit() {
        assert!(lookup_handler(SYS_WRITE).is_some());
        assert!(lookup_handler(SYS_EXIT).is_some());
        assert!(lookup_handler(999).is_none());
        assert!(lookup_handler(1000).is_none());
        // Deliberately not wired in M8 (M9 scope): brk, arch_prctl,
        // set_tid_address, exit_group, futex, mmap.
        for nr in [12u64, 158, 218, 231, 202, 9] {
            assert!(lookup_handler(nr).is_none(), "nr {nr} must be unsupported");
        }
        assert_eq!(encode_rax(Err(ENOSYS)) as i64, -38);
    }

    #[test]
    fn handler_pointers_match_module_functions() {
        let write = lookup_handler(SYS_WRITE).unwrap();
        let exit = lookup_handler(SYS_EXIT).unwrap();
        assert_eq!(write as usize, handle_sys_write as usize);
        assert_eq!(exit as usize, handle_sys_exit as usize);
    }
}
