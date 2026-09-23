//! Linux syscall handler table (M8: `write` and `exit` only, #94).

#[cfg(feature = "m9-linux-exec-self-test")]
use super::execve::handle_sys_execve;
use super::exit::handle_sys_exit;
use super::fd::{
    handle_sys_close, handle_sys_dup2, handle_sys_fcntl, handle_sys_read, handle_sys_writev,
};
use super::write::handle_sys_write;
use crate::arch::x86_64::interrupt_context::SyscallContext;
#[cfg(feature = "m9-linux-exec-self-test")]
use clean_slate_linux_abi::SYS_EXECVE;
use clean_slate_linux_abi::{
    LinuxSyscallRequest, LinuxSyscallResult, SYS_CLOSE, SYS_DUP2, SYS_EXIT, SYS_FCNTL, SYS_READ,
    SYS_WRITE, SYS_WRITEV,
};
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

/// Look up the handler for `nr`, or `None` for unsupported numbers.
///
/// Core arms (M8 `write`/`exit`, #147 fd core) live here; every other Linux
/// syscall family registers through its own module so Wave 2 lanes never edit
/// this table concurrently. Order is irrelevant: the frozen matrix gives each
/// syscall number exactly one owner, and the host test below asserts that no
/// number resolves in more than one family.
pub(crate) fn lookup_handler(nr: u64) -> Option<LinuxSyscallHandler> {
    lookup_core_handler(nr)
        .or_else(|| super::fs::lookup_handler(nr))
        .or_else(|| super::process::lookup_handler(nr))
        .or_else(|| super::runtime::lookup_handler(nr))
        .or_else(|| super::socket::lookup_handler(nr))
}

fn lookup_core_handler(nr: u64) -> Option<LinuxSyscallHandler> {
    match nr {
        SYS_READ => Some(handle_sys_read),
        SYS_WRITE => Some(handle_sys_write),
        SYS_CLOSE => Some(handle_sys_close),
        SYS_WRITEV => Some(handle_sys_writev),
        SYS_DUP2 => Some(handle_sys_dup2),
        SYS_EXIT => Some(handle_sys_exit),
        SYS_FCNTL => Some(handle_sys_fcntl),
        #[cfg(feature = "m9-linux-exec-self-test")]
        SYS_EXECVE => Some(handle_sys_execve),
        _ => None,
    }
}

/// Number of families (core + fs + process + runtime + socket) that claim `nr`.
#[cfg(test)]
fn family_claims(nr: u64) -> usize {
    [
        lookup_core_handler(nr).is_some(),
        super::fs::lookup_handler(nr).is_some(),
        super::process::lookup_handler(nr).is_some(),
        super::runtime::lookup_handler(nr).is_some(),
        super::socket::lookup_handler(nr).is_some(),
    ]
    .iter()
    .filter(|claimed| **claimed)
    .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_linux_abi::{encode_rax, ENOSYS};

    #[test]
    fn table_maps_m8_write_exit_and_m9_fd_core() {
        assert!(lookup_handler(SYS_WRITE).is_some());
        assert!(lookup_handler(SYS_CLOSE).is_some());
        assert!(lookup_handler(SYS_WRITEV).is_some());
        assert!(lookup_handler(SYS_DUP2).is_some());
        assert!(lookup_handler(SYS_FCNTL).is_some());
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

    /// Every syscall number in the frozen matrix has exactly one owning
    /// family; a lane that wires a number someone else owns fails here.
    #[test]
    fn no_syscall_number_is_claimed_by_two_families() {
        for nr in 0..512u64 {
            assert!(
                family_claims(nr) <= 1,
                "nr {nr} is claimed by more than one dispatch family"
            );
        }
    }
}
