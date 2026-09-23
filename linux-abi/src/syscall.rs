//! x86-64 Linux syscall register convention and unsupported-syscall contract.
//!
//! # Register convention
//!
//! On `SYSCALL` entry (Linux x86-64):
//! - `RAX` — syscall number
//! - `RDI`, `RSI`, `RDX`, `R10`, `R8`, `R9` — arguments 0..5
//! - `RCX` — clobbered (hardware saves user RIP here; not an argument)
//! - `R11` — clobbered (hardware saves user RFLAGS here; not an argument)
//!
//! On return, `RAX` carries an `i64`-shaped result: non-negative success, or
//! `-errno` (see [`crate::errno`]).
//!
//! # M8 supported numbers
//!
//! Only [`SYS_WRITE`] and [`SYS_EXIT`] are required for the M8 fixture.
//! Any other number returns `-ENOSYS`, the process continues, and diagnostics
//! are bounded by [`UnsupportedSyscallBudget`] (kernel plumbing is #93).
//!
//! # M9 extension points
//!
//! Additional syscall numbers/handlers are added here without changing the
//! register decode shape. TLS and broader POSIX coverage land in M9.

use crate::errno::{LinuxErrno, ENOSYS};

/// Linux `write` — `write(fd, buf, count)`.
pub const SYS_WRITE: u64 = 1;
/// Linux `close` — `close(fd)`.
pub const SYS_CLOSE: u64 = 3;
/// Linux `writev` — `writev(fd, iov, iovcnt)`.
pub const SYS_WRITEV: u64 = 20;
/// Linux `dup2` — `dup2(oldfd, newfd)`.
pub const SYS_DUP2: u64 = 33;
/// Linux `exit` — `exit(error_code)` (thread/group exit; M8 uses this for `_exit`).
pub const SYS_EXIT: u64 = 60;
/// Linux `execve` — `execve(path, argv, envp)` (M9 #102 will parse pointers; M9.F self-test stub).
pub const SYS_EXECVE: u64 = 59;
/// Linux `fcntl` — `fcntl(fd, cmd, arg)`.
pub const SYS_FCNTL: u64 = 72;

/// Raw registers captured for Linux personality decode (subset of the full frame).
///
/// `RCX`/`R11` are intentionally absent: the `SYSCALL` instruction clobbers them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinuxSyscallRegisters {
    pub rax: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub r10: u64,
    pub r8: u64,
    pub r9: u64,
}

/// Decoded Linux syscall request (number + six arguments).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinuxSyscallRequest {
    pub nr: u64,
    pub args: [u64; 6],
}

/// Pure decode from Linux register convention into a request.
pub const fn decode_linux_syscall(regs: LinuxSyscallRegisters) -> LinuxSyscallRequest {
    LinuxSyscallRequest {
        nr: regs.rax,
        args: [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9],
    }
}

/// Returns `true` if M8 requires a real handler for `nr` (write or exit).
pub const fn is_m8_supported_syscall(nr: u64) -> bool {
    nr == SYS_WRITE || nr == SYS_EXIT
}

/// Fixed result for any syscall number outside the M8 supported set.
pub const fn unsupported_syscall_result() -> Result<u64, LinuxErrno> {
    Err(ENOSYS)
}

/// One observation of an unsupported syscall (for bounded diagnostics).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnsupportedSyscallObservation {
    pub nr: u64,
    pub count_after: u64,
}

/// Bounded counter/limit for unsupported-syscall diagnostics (#93 wires this).
///
/// Contract: each unsupported syscall returns `-ENOSYS`, the process continues,
/// and at most `limit` observations are recorded (further hits increment
/// `suppressed` only). Soft limit is deliberate and small — not an arbitrary
/// capacity chosen to paper over unbounded logging.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedSyscallBudget {
    pub limit: u64,
    pub observed: u64,
    pub suppressed: u64,
    pub last_nr: u64,
}

impl UnsupportedSyscallBudget {
    /// Default M8 budget: enough for a fixture probe plus a few surprises.
    pub const DEFAULT_LIMIT: u64 = 8;

    pub const fn new(limit: u64) -> Self {
        Self {
            limit,
            observed: 0,
            suppressed: 0,
            last_nr: 0,
        }
    }

    pub const fn default_budget() -> Self {
        Self::new(Self::DEFAULT_LIMIT)
    }

    /// Record one unsupported syscall. Returns `Some(observation)` while under
    /// the limit (caller may emit a diagnostic); `None` when suppressed.
    pub fn record(&mut self, nr: u64) -> Option<UnsupportedSyscallObservation> {
        self.last_nr = nr;
        if self.observed < self.limit {
            self.observed = self.observed.saturating_add(1);
            Some(UnsupportedSyscallObservation {
                nr,
                count_after: self.observed,
            })
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::{decode_rax, encode_rax};

    #[test]
    fn decode_maps_linux_register_order() {
        let regs = LinuxSyscallRegisters {
            rax: SYS_WRITE,
            rdi: 1,
            rsi: 0x1000,
            rdx: 13,
            r10: 0xdead,
            r8: 0xbeef,
            r9: 0xcafe,
        };
        let req = decode_linux_syscall(regs);
        assert_eq!(req.nr, SYS_WRITE);
        assert_eq!(req.args, [1, 0x1000, 13, 0xdead, 0xbeef, 0xcafe]);
    }

    #[test]
    fn exit_number_is_sixty() {
        assert_eq!(SYS_EXIT, 60);
        assert!(is_m8_supported_syscall(SYS_EXIT));
        assert!(is_m8_supported_syscall(SYS_WRITE));
        assert!(!is_m8_supported_syscall(0));
        assert!(!is_m8_supported_syscall(2));
    }

    #[test]
    fn unsupported_returns_enosys_encoded() {
        let encoded = encode_rax(unsupported_syscall_result());
        assert_eq!(decode_rax(encoded), Err(ENOSYS));
    }

    #[test]
    fn unsupported_budget_bounds_diagnostics() {
        let mut budget = UnsupportedSyscallBudget::new(2);
        assert!(budget.record(99).is_some());
        assert!(budget.record(100).is_some());
        assert!(budget.record(101).is_none());
        assert_eq!(budget.observed, 2);
        assert_eq!(budget.suppressed, 1);
        assert_eq!(budget.last_nr, 101);
    }
}
