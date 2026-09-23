//! Linux process/pipe syscall family (#102).
//!
//! Frozen ownership (`fixtures/busybox/frozen/M9_DEPENDENCY_MATRIX.md`):
//! `fork`, `pipe`, `wait4`, `getppid`, `exit_group`, and production `execve`
//! (the self-test-only `execve.rs` arm from #146 is replaced from here).
//! Blocking (`wait4`) goes through the #145 substrate; pipes are #147
//! open-description kinds; exec goes through `process::linux_exec::commit_exec`.
//!
//! This module is the only dispatch-table surface #102 edits: add arms to
//! [`lookup_handler`] here, never to `table.rs`.

use super::table::LinuxSyscallHandler;

/// Handlers owned by the process family, or `None` if `nr` is not ours.
pub(crate) fn lookup_handler(nr: u64) -> Option<LinuxSyscallHandler> {
    let _ = nr;
    None
}
