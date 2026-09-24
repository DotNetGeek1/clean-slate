//! M8.1 Linux x86-64 ABI personality contract.
//!
//! Host-testable, `no_std`, zero-alloc types shared by the kernel Linux
//! personality lane (#92/#93/#94/#95) and documentation. This crate never
//! mixes Clean-Slate native sentinel errno encoding with Linux negative-errno
//! semantics — those live in separate types by construction.
//!
//! # M9 extension points
//!
//! - Additional syscall numbers and handlers beyond `SYS_WRITE` / `SYS_EXIT`
//! - Auxv keys such as `AT_RANDOM`, `AT_SECURE`, `AT_PLATFORM` (defined here as
//!   unsupported-for-M8 constants; not emitted by the stack builder)
//! - Thread-local storage (TLS) setup at process entry

#![cfg_attr(not(test), no_std)]

pub mod errno;
pub mod fs;
pub mod names;
pub mod process;
pub mod socket;
pub mod stack;
pub mod syscall;

pub use errno::{
    decode_rax, encode_rax, LinuxErrno, LinuxSyscallResult, E2BIG, EACCES, EAGAIN, EBADF, ECHILD,
    EFAULT, EINVAL, EMFILE, ENFILE, ENOENT, ENOEXEC, ENOMEM, ENOSPC, ENOSYS, EPERM, EPIPE, ESRCH,
    ESTALE,
};
pub use fs::{
    encode_dirent64, encode_stat144, LinuxStatFields, DT_DIR, DT_LNK, DT_REG, EEXIST, EFBIG,
    EISDIR, ELOOP, ENAMETOOLONG, ENOTDIR, ERANGE, EROFS, ESPIPE, O_APPEND, O_CLOEXEC, O_CREAT,
    O_DIRECTORY, O_LARGEFILE, O_NONBLOCK, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, SEEK_CUR, SEEK_END,
    SEEK_SET, SYS_GETCWD, SYS_GETDENTS64, SYS_LSEEK, SYS_LSTAT, SYS_MKDIR, SYS_OPEN, SYS_READ,
    SYS_STAT, S_IFDIR, S_IFLNK, S_IFREG,
};
pub use names::{linux_syscall_name, SyscallName};
pub use process::{
    w_exitcode, w_exitstatus, w_ifsignalled, w_signalled_status, SIGKILL, SIGSEGV, SYS_EXIT_GROUP,
    SYS_FORK, SYS_GETPPID, SYS_PIPE, SYS_WAIT4,
};
pub use socket::{
    SockaddrIn, AF_INET, AF_INET6, EADDRINUSE, EAFNOSUPPORT, ECONNREFUSED, ECONNRESET,
    EDESTADDRREQ, EIO, EISCONN, EMSGSIZE, ENETUNREACH, ENOBUFS, ENOTCONN, EPROTONOSUPPORT,
    ETIMEDOUT, IPPROTO_IP, IPPROTO_TCP, IPPROTO_UDP, MSG_NOSIGNAL, SOCKADDR_IN_LEN, SOCK_CLOEXEC,
    SOCK_DGRAM, SOCK_NONBLOCK, SOCK_STREAM, SYS_BIND, SYS_CONNECT, SYS_SENDTO, SYS_SOCKET,
};
pub use stack::{
    build_initial_stack, build_initial_stack_with_tail, InitialStackBuilder, InitialStackImage,
    StackLayoutError, StackTailBlob, AT_BASE, AT_CLKTCK, AT_EGID, AT_ENTRY, AT_EUID, AT_EXECFN,
    AT_FLAGS, AT_GID, AT_HWCAP, AT_NULL, AT_PAGESZ, AT_PHDR, AT_PHENT, AT_PHNUM, AT_PLATFORM,
    AT_RANDOM, AT_SECURE, AT_UID,
};
pub use syscall::{
    decode_linux_syscall, is_m8_supported_syscall, unsupported_syscall_result,
    LinuxSyscallRegisters, LinuxSyscallRequest, UnsupportedSyscallBudget,
    UnsupportedSyscallObservation, SYS_CLOSE, SYS_DUP2, SYS_EXECVE, SYS_EXIT, SYS_FCNTL, SYS_WRITE,
    SYS_WRITEV,
};
