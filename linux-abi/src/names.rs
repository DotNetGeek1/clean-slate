//! Static Linux syscall names for diagnostics (bounded, no allocation).

/// Human-readable syscall name for known numbers, or `UNKNOWN(nr)`.
pub const fn linux_syscall_name(nr: u64) -> SyscallName {
    use crate::fs::{
        SYS_GETCWD, SYS_GETDENTS64, SYS_LSEEK, SYS_LSTAT, SYS_MKDIR, SYS_OPEN, SYS_READ, SYS_STAT,
    };
    use crate::process::{SYS_EXIT_GROUP, SYS_FORK, SYS_GETPPID, SYS_PIPE, SYS_WAIT4};
    use crate::socket::{SYS_BIND, SYS_CONNECT, SYS_SENDTO, SYS_SOCKET};
    use crate::syscall::{
        SYS_CLOSE, SYS_DUP2, SYS_EXECVE, SYS_EXIT, SYS_FCNTL, SYS_WRITE, SYS_WRITEV,
    };

    match nr {
        SYS_READ => SyscallName::Known("read"),
        SYS_WRITE => SyscallName::Known("write"),
        SYS_OPEN => SyscallName::Known("open"),
        SYS_CLOSE => SyscallName::Known("close"),
        SYS_STAT => SyscallName::Known("stat"),
        SYS_LSTAT => SyscallName::Known("lstat"),
        SYS_LSEEK => SyscallName::Known("lseek"),
        SYS_EXECVE => SyscallName::Known("execve"),
        SYS_WRITEV => SyscallName::Known("writev"),
        SYS_PIPE => SyscallName::Known("pipe"),
        SYS_DUP2 => SyscallName::Known("dup2"),
        SYS_FORK => SyscallName::Known("fork"),
        SYS_WAIT4 => SyscallName::Known("wait4"),
        SYS_EXIT => SyscallName::Known("exit"),
        SYS_FCNTL => SyscallName::Known("fcntl"),
        SYS_GETCWD => SyscallName::Known("getcwd"),
        SYS_MKDIR => SyscallName::Known("mkdir"),
        SYS_GETDENTS64 => SyscallName::Known("getdents64"),
        SYS_SOCKET => SyscallName::Known("socket"),
        SYS_CONNECT => SyscallName::Known("connect"),
        SYS_SENDTO => SyscallName::Known("sendto"),
        SYS_BIND => SyscallName::Known("bind"),
        SYS_GETPPID => SyscallName::Known("getppid"),
        SYS_EXIT_GROUP => SyscallName::Known("exit_group"),
        9 => SyscallName::Known("mmap"),
        other => SyscallName::Unknown(other),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallName {
    Known(&'static str),
    Unknown(u64),
}

impl SyscallName {
    pub const fn as_str(self) -> &'static str {
        match self {
            SyscallName::Known(name) => name,
            SyscallName::Unknown(_) => "UNKNOWN",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscall::SYS_WRITE;

    #[test]
    fn known_write_name() {
        assert_eq!(linux_syscall_name(SYS_WRITE), SyscallName::Known("write"));
    }

    #[test]
    fn unknown_reports_number() {
        let name = linux_syscall_name(999);
        assert_eq!(name, SyscallName::Unknown(999));
    }
}
