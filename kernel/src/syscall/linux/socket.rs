//! Linux socket syscall family (#105) translated onto M7 networking.
//!
//! Frozen ownership (`fixtures/busybox/frozen/M9_DEPENDENCY_MATRIX.md`):
//! `socket`, `connect`, `sendto`, `bind` (AF_INET, SOCK_STREAM/SOCK_DGRAM).
//! Socket `read`/`write` arrive through #147 open-description kinds; blocking
//! `connect`/receive uses the #145 substrate; DNS is real UDP traffic to the
//! fixture resolver, never an internal resolver call.
//!
//! This module is the only dispatch-table surface #105 edits: add arms to
//! [`lookup_handler`] here, never to `table.rs`.

use super::table::LinuxSyscallHandler;

/// Handlers owned by the socket family, or `None` if `nr` is not ours.
pub(crate) fn lookup_handler(nr: u64) -> Option<LinuxSyscallHandler> {
    let _ = nr;
    None
}
