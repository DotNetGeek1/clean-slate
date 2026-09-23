//! Linux runtime/memory/time/poll syscall family (#103).
//!
//! Frozen ownership (`fixtures/busybox/frozen/M9_DEPENDENCY_MATRIX.md`):
//! `arch_prctl`, `brk`, `getpid`, `ioctl`, `mmap`, `munmap`, `nanosleep`,
//! `poll`, `rt_sigaction`, `rt_sigprocmask`, `set_tid_address`, `uname`.
//! `poll`/`nanosleep` block through the #145 substrate; readiness comes from
//! the #147 `ReadinessSource` trait implemented by each backend.
//!
//! This module is the only dispatch-table surface #103 edits: add arms to
//! [`lookup_handler`] here, never to `table.rs`.

use super::table::LinuxSyscallHandler;

/// Handlers owned by the runtime family, or `None` if `nr` is not ours.
pub(crate) fn lookup_handler(nr: u64) -> Option<LinuxSyscallHandler> {
    let _ = nr;
    None
}
