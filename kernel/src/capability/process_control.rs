//! M6.4 process/domain control capability surface (SYSCALL_NR_CAP_PROCESS_CONTROL).
//!
//! Syscall entry: `SYSCALL_NR_CAP_PROCESS_CONTROL` (see `clean_slate_capability::syscall_abi`).
//! Stub installed by the M6 coordinator; the owning lane replaces the body.

use crate::arch::x86_64::interrupt_context::SyscallContext;
use clean_slate_capability::syscall_abi::SYSCALL_ENOSYS;

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    frame.rax = SYSCALL_ENOSYS;
}
