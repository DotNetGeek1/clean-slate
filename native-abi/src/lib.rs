//! Generic native kernel ABI shared by the kernel and userspace binaries.
//!
//! This crate is deliberately not graphics-specific: shared buffers live here now;
//! the bounded service port and work sets will be added by the service-port foundation
//! issue. Graphics protocol types remain in `clean-slate-graphics`.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod shared_buffer;

pub use shared_buffer::{
    SharedBufferAccess, SharedBufferId, SharedBufferIdError, MAX_ATTACHMENTS_PER_BUFFER,
    MAX_EXTENTS_PER_BUFFER, MAX_SHARED_BUFFERS, MAX_SHARED_BUFFERS_PER_OWNER,
    MAX_SHARED_MAPPINGS_PER_PROCESS, MAX_SHARED_PAGES_PER_OWNER, MAX_SHARED_PAGES_TOTAL,
};

#[cfg(test)]
mod graphics_status_mirrors_capability_syscall_abi {
    //! Cross-check §8.1 mirrors vs `clean_slate_capability::syscall_abi`.
    //!
    //! `NETWORK_STATUS_PENDING` is `u64::MAX - 15` (`service-fixtures/src/network_transport.rs`).

    use clean_slate_capability::syscall_abi::{
        SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_ENOSPC, SYSCALL_ENOSYS, SYSCALL_ESTALE,
    };
    use clean_slate_graphics::abi::status::{
        STATUS_EACCES, STATUS_EAGAIN, STATUS_EINVAL, STATUS_ENOSPC, STATUS_ENOSYS, STATUS_ESTALE,
    };

    const NETWORK_STATUS_PENDING: u64 = u64::MAX - 15;

    #[test]
    fn graphics_status_mirrors_capability_syscall_abi() {
        assert_eq!(STATUS_EACCES, SYSCALL_EACCES);
        assert_eq!(STATUS_EINVAL, SYSCALL_EINVAL);
        assert_eq!(STATUS_ENOSPC, SYSCALL_ENOSPC);
        assert_eq!(STATUS_ENOSYS, SYSCALL_ENOSYS);
        assert_eq!(STATUS_ESTALE, SYSCALL_ESTALE);
    }

    #[test]
    fn status_eagain_not_network_pending_literal() {
        assert_ne!(STATUS_EAGAIN, NETWORK_STATUS_PENDING);
    }
}
