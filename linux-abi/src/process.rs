//! M9 #102 Linux process syscall numbers and wait status encoding.

/// Linux `pipe` — `pipe(int pipefd[2])`.
pub const SYS_PIPE: u64 = 22;
/// Linux `fork` — `fork()`.
pub const SYS_FORK: u64 = 57;
/// Linux `execve` — `execve(path, argv, envp)` (also declared in `syscall.rs`).
pub const SYS_EXECVE: u64 = 59;
/// Linux `wait4` — `wait4(pid, wstatus, options, rusage)`.
pub const SYS_WAIT4: u64 = 61;
/// Linux `getppid` — `getppid()`.
pub const SYS_GETPPID: u64 = 110;
/// Linux `exit_group` — `exit_group(status)`.
pub const SYS_EXIT_GROUP: u64 = 231;

pub const SIGKILL: u32 = 9;
pub const SIGSEGV: u32 = 11;

/// `W_EXITCODE(ret, sig)` with `sig == 0`: status word for normal exit `ret`.
pub const fn w_exitcode(code: u32) -> i32 {
    (code << 8) as i32
}

/// Extract exit code from a wait status word (`WEXITSTATUS`).
pub const fn w_exitstatus(status: i32) -> u32 {
    ((status >> 8) & 0xff) as u32
}

/// Signalled child: low 7 bits = signal, bit 7 set in low byte per Linux.
pub const fn w_signalled_status(signal: u32) -> i32 {
    (signal & 0x7f) as i32
}

pub const fn w_ifsignalled(status: i32) -> bool {
    (status & 0x7f) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_status_encoding_matches_linux() {
        assert_eq!(w_exitcode(3), 768);
        assert_eq!(w_exitstatus(768), 3);
        assert_eq!(w_signalled_status(SIGSEGV), 11);
        assert!(w_ifsignalled(11));
        assert!(!w_ifsignalled(768));
    }
}
