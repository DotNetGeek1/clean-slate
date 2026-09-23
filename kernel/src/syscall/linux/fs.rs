//! Linux filesystem/path syscall family (#101).
//!
//! Frozen ownership (`fixtures/busybox/frozen/M9_DEPENDENCY_MATRIX.md`):
//! `open`, `stat`, `lstat`, `getcwd`, `mkdir`, `getdents64`.
//! File `read`/`write`/`lseek` on file-backed descriptions are reached through
//! the #147 open-description kinds; the syscall numbers stay owned by `fd.rs`.
//!
//! This module is the only dispatch-table surface #101 edits: add arms to
//! [`lookup_handler`] here, never to `table.rs`.

use super::table::LinuxSyscallHandler;

/// Handlers owned by the filesystem family, or `None` if `nr` is not ours.
pub(crate) fn lookup_handler(nr: u64) -> Option<LinuxSyscallHandler> {
    let _ = nr;
    None
}
