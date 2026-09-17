//! M6.3 persistent object/file capability surface (kernel side of SYSCALL_NR_CAP_OBJECT).
//!
//! Syscall entry: `SYSCALL_NR_CAP_OBJECT` (see `clean_slate_capability::syscall_abi`).
//! Stub installed by the M6 coordinator; the owning lane replaces the body.

use crate::arch::x86_64::interrupt_context::SyscallContext;
use clean_slate_capability::syscall_abi::SYSCALL_ENOSYS;

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    frame.rax = SYSCALL_ENOSYS;
}
