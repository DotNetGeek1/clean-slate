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
pub mod stack;
pub mod syscall;

pub use errno::{
    decode_rax, encode_rax, LinuxErrno, LinuxSyscallResult, EACCES, EBADF, EFAULT, EINVAL, EMFILE,
    ENFILE, ENOENT, ENOMEM, ENOSYS, EPERM, ESRCH,
};
pub use stack::{
    build_initial_stack, InitialStackBuilder, InitialStackImage, StackLayoutError, AT_ENTRY,
    AT_NULL, AT_PAGESZ, AT_PHDR, AT_PHENT, AT_PHNUM, AT_PLATFORM, AT_RANDOM, AT_SECURE,
};
pub use syscall::{
    decode_linux_syscall, is_m8_supported_syscall, unsupported_syscall_result,
    LinuxSyscallRegisters, LinuxSyscallRequest, UnsupportedSyscallBudget,
    UnsupportedSyscallObservation, SYS_CLOSE, SYS_DUP2, SYS_EXIT, SYS_FCNTL, SYS_WRITE, SYS_WRITEV,
};
