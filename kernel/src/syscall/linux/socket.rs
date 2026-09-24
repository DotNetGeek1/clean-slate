//! Linux socket syscall family (#105) translated onto M7 networking.

use super::table::{LinuxSyscallContext, LinuxSyscallHandler};
use clean_slate_linux_abi::{
    LinuxSyscallRequest, LinuxSyscallResult, SYS_BIND, SYS_CONNECT, SYS_SENDTO, SYS_SOCKET,
};

pub(crate) fn lookup_handler(nr: u64) -> Option<LinuxSyscallHandler> {
    match nr {
        SYS_SOCKET => Some(handle_sys_socket),
        SYS_CONNECT => Some(handle_sys_connect),
        SYS_SENDTO => Some(handle_sys_sendto),
        SYS_BIND => Some(handle_sys_bind),
        _ => None,
    }
}

fn handle_sys_socket(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    crate::process::linux_socket::syscalls::sys_socket(request, ctx)
}

fn handle_sys_connect(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    crate::process::linux_socket::syscalls::sys_connect(request, ctx)
}

fn handle_sys_sendto(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    crate::process::linux_socket::syscalls::sys_sendto(request, ctx)
}

fn handle_sys_bind(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    crate::process::linux_socket::syscalls::sys_bind(request, ctx)
}
