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
pub mod runtime;
pub mod stack;
pub mod syscall;

pub use errno::{
    decode_rax, encode_rax, LinuxErrno, LinuxSyscallResult, EACCES, EBADF, EFAULT, EINVAL, EMFILE,
    ENFILE, ENOENT, ENOEXEC, ENOMEM, ENOSYS, EPERM, ESRCH,
};
pub use runtime::{
    decode_pollfd, decode_sigaction, decode_timespec, encode_pollfd, encode_sigaction,
    encode_utsname_fields, PollFd, Sigaction, Timespec, ARCH_SET_FS, EAGAIN, EINTR, ENOTTY,
    ETIMEDOUT, MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT,
    PROT_EXEC, PROT_NONE, PROT_READ, PROT_WRITE, SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK, SYS_ARCH_PRCTL,
    SYS_BRK, SYS_GETPID, SYS_IOCTL, SYS_MMAP, SYS_MUNMAP, SYS_NANOSLEEP, SYS_POLL,
    SYS_RT_SIGACTION, SYS_RT_SIGPROCMASK, SYS_SET_TID_ADDRESS, SYS_UNAME, TIOCGWINSZ, UTSNAME_SIZE,
    _NSIG, SIGACTION_SIZE,
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
