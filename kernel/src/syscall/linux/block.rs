//! Blocking for Linux syscall handlers on the #145 substrate (restart-on-wake).
//!
//! A Linux handler that finds its condition unmet (empty pipe, no exited child,
//! no ready descriptor, sleep not elapsed) calls [`block_linux_syscall`] and
//! returns its result. The thread sleeps on `key`; when it is woken the
//! `syscall` instruction is re-executed with the argument registers intact
//! (`sched::wait::BlockedResume::RestartSyscall`), so the handler runs again
//! from the top and re-checks. When the optional deadline expires instead, the
//! syscall completes with `on_timeout`. Handlers must therefore be idempotent
//! up to the point where they block, and must derive absolute deadlines from
//! their own per-process state when a restart must not extend the wait.

// Consumed by the Wave 2 families (#101 read, #102 wait4/pipe, #103 poll/
// nanosleep, #105 connect/recv); remove once the first consumer lands.
#![allow(dead_code)]

use super::table::LinuxSyscallContext;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::sched::wait::{
    block_current_thread_with_resume, BlockedResume, Deadline, WaitKey, WaitOutcome,
    SYSCALL_INSTRUCTION_BYTES,
};
use clean_slate_linux_abi::{encode_rax, LinuxErrno, LinuxSyscallRequest, LinuxSyscallResult};

/// What the syscall returns to user space if the wait ends by deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinuxTimeoutResult {
    /// `poll` with no ready descriptor, `nanosleep` that elapsed: return 0.
    Zero,
    /// `connect` and friends: return `-errno`.
    Errno(LinuxErrno),
}

impl LinuxTimeoutResult {
    pub(crate) const fn encode(self) -> u64 {
        match self {
            LinuxTimeoutResult::Zero => encode_rax(Ok(0)),
            LinuxTimeoutResult::Errno(errno) => encode_rax(Err(errno)),
        }
    }
}

/// Block the calling Linux thread on `key` until woken or `deadline`.
///
/// Returns only when a wake was already pending (no yield happened); the
/// returned value is then the restart itself (`Ok(nr)` with `user_rip` backed
/// up), which the dispatcher writes into `RAX` like any other result. In every
/// other case the thread is switched out and the scheduler completes the
/// syscall directly, so the handler's stack frame is abandoned; callers must
/// `return` this value immediately without holding kernel state that needs
/// cleanup.
pub(crate) fn block_linux_syscall(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    key: WaitKey,
    deadline: Option<Deadline>,
    on_timeout: LinuxTimeoutResult,
) -> LinuxSyscallResult {
    let resume = BlockedResume::RestartSyscall {
        nr: request.nr,
        timeout_rax: on_timeout.encode(),
    };
    let frame: *mut _ = ctx.frame;
    match block_current_thread_with_resume(frame, key, deadline, resume) {
        Ok(WaitOutcome::Woken) => {
            ctx.frame.user_rip = ctx
                .frame
                .user_rip
                .checked_sub(SYSCALL_INSTRUCTION_BYTES)
                .unwrap_or_else(|| fatal_kernel_error("linux block: user rip underflow"));
            Ok(request.nr)
        }
        #[cfg(feature = "m9-linux-runtime-self-test")]
        Ok(WaitOutcome::TimedOut) => Ok(on_timeout.encode()),
        #[cfg(not(feature = "m9-linux-runtime-self-test"))]
        Ok(WaitOutcome::TimedOut) => {
            fatal_kernel_error("linux block: unexpected immediate TimedOut")
        }
        Ok(_) => fatal_kernel_error("linux block: unexpected immediate outcome"),
        Err(message) => fatal_kernel_error(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_linux_abi::EINVAL;

    #[test]
    fn timeout_results_encode_like_syscall_results() {
        assert_eq!(LinuxTimeoutResult::Zero.encode(), 0);
        assert_eq!(
            LinuxTimeoutResult::Errno(EINVAL).encode() as i64,
            -(EINVAL.0 as i64)
        );
    }
}
