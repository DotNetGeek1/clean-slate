//! Linux `execve(2)` (nr 59).
//!
//! Production path: `#102` will parse user pointers into [`LinuxExecSpec`] and call
//! [`crate::process::linux_exec::commit_exec`]. Under `m9-linux-exec-self-test` only,
//! a fixed-spec stub exercises prepare + commit for the #146 acceptance fixture.

#[cfg(feature = "m9-linux-exec-self-test")]
use super::table::LinuxSyscallContext;
#[cfg(feature = "m9-linux-exec-self-test")]
use crate::selftest::m9_linux_exec::handle_execve_selftest;
#[cfg(feature = "m9-linux-exec-self-test")]
use clean_slate_linux_abi::{LinuxSyscallRequest, LinuxSyscallResult};

#[cfg(feature = "m9-linux-exec-self-test")]
pub(crate) fn handle_sys_execve(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let _ = request;
    handle_execve_selftest(ctx)
}
