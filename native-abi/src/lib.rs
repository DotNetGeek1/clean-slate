//! Generic native kernel ABI shared by the kernel and userspace binaries.
//!
//! Shared buffers, the bounded service port, and work-set ABI live here; the port engine
//! is the separate `clean-slate-port` crate. Graphics protocol types remain in
//! `clean-slate-graphics`.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod shared_buffer;

#[macro_use]
pub mod port;
pub mod status;
pub mod work_set;

pub use shared_buffer::{
    page_count_for_bytes, shared_window_slot_base, SharedBufferAccess, SharedBufferId,
    SharedBufferIdError, SharedBufferInfo, SharedBufferInfoError, MAX_ATTACHMENTS_PER_BUFFER,
    MAX_EXTENTS_PER_BUFFER, MAX_SHARED_BUFFERS, MAX_SHARED_BUFFERS_PER_OWNER,
    MAX_SHARED_BUFFER_BYTES, MAX_SHARED_MAPPINGS_PER_PROCESS, MAX_SHARED_PAGES_PER_OWNER,
    MAX_SHARED_PAGES_TOTAL, SHARED_BUFFER_ACCESS_READ, SHARED_BUFFER_ACCESS_READ_WRITE,
    SHARED_BUFFER_INFO_BYTES, SHARED_BUFFER_INFO_CALLER_IS_OWNER,
    SHARED_BUFFER_INFO_CALLER_MAPPED_READ_WRITE, SHARED_BUFFER_PAGE_BYTES,
    SHARED_BUFFER_STATUS_EACCES, SHARED_BUFFER_STATUS_EAGAIN, SHARED_BUFFER_STATUS_EBADF,
    SHARED_BUFFER_STATUS_EINVAL, SHARED_BUFFER_STATUS_ENOSPC, SHARED_BUFFER_STATUS_ENOSYS,
    SHARED_BUFFER_STATUS_ESTALE, SHARED_BUFFER_SUBOP_ALLOCATE, SHARED_BUFFER_SUBOP_MAP,
    SHARED_BUFFER_SUBOP_QUERY, SHARED_BUFFER_SUBOP_RELEASE, SHARED_BUFFER_SUBOP_UNMAP,
    SHARED_WINDOW_BASE, SHARED_WINDOW_BYTES, SHARED_WINDOW_SLOT_STRIDE, SYSCALL_NR_SHARED_BUFFER,
};
pub use status::{
    is_status, NETWORK_STATUS_PENDING, STATUS_EACCES, STATUS_EAGAIN, STATUS_EBADF,
    STATUS_ECONNREFUSED, STATUS_EEXIST, STATUS_EINVAL, STATUS_ENOSPC, STATUS_ENOSYS, STATUS_EPIPE,
    STATUS_ESTALE, STATUS_ETIMEDOUT, STATUS_RANGE_START,
};

pub use port::{
    port_rights_for, ConnectionId, ConnectionIdError, EventKind, PortEventRecord, PortParamError,
    PortParams, PortRecvRecord, PortRights, RecordError, RecvKind, TransferredCap, TrustedEnvelope,
};
pub use work_set::{WorkSetId, WorkSetIdError};

#[cfg(test)]
mod graphics_status_mirrors_capability_syscall_abi {
    //! Cross-check §8.1 mirrors vs `clean_slate_capability::syscall_abi`.
    //!
    //! `NETWORK_STATUS_PENDING` is `u64::MAX - 15` (`service-fixtures/src/network_transport.rs`).

    use clean_slate_capability::syscall_abi::{
        SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_ENOSPC, SYSCALL_ENOSYS, SYSCALL_ESTALE,
    };
    use clean_slate_graphics::abi::status::{
        STATUS_EACCES as GFX_EACCES, STATUS_EAGAIN as GFX_EAGAIN, STATUS_EBADF as GFX_EBADF,
        STATUS_EINVAL as GFX_EINVAL, STATUS_EIO as GFX_EIO, STATUS_ENODEV as GFX_ENODEV,
        STATUS_ENOSPC as GFX_ENOSPC, STATUS_ENOSYS as GFX_ENOSYS,
        STATUS_ENOTRECOVERABLE as GFX_ENOTRECOVERABLE, STATUS_ERANGE as GFX_ERANGE,
        STATUS_ESTALE as GFX_ESTALE, STATUS_ETIMEDOUT as GFX_ETIMEDOUT,
    };

    use crate::status::{
        self, STATUS_EACCES, STATUS_EAGAIN, STATUS_ECONNREFUSED, STATUS_EEXIST, STATUS_EINVAL,
        STATUS_ENOSPC, STATUS_ENOSYS, STATUS_EPIPE, STATUS_ESTALE, STATUS_ETIMEDOUT,
        STATUS_RANGE_START,
    };
    use crate::{ConnectionId, WorkSetId};

    #[test]
    fn graphics_status_mirrors_capability_syscall_abi() {
        assert_eq!(GFX_EACCES, SYSCALL_EACCES);
        assert_eq!(GFX_EINVAL, SYSCALL_EINVAL);
        assert_eq!(GFX_ENOSPC, SYSCALL_ENOSPC);
        assert_eq!(GFX_ENOSYS, SYSCALL_ENOSYS);
        assert_eq!(GFX_ESTALE, SYSCALL_ESTALE);
    }

    #[test]
    fn status_eagain_not_network_pending_literal() {
        assert_ne!(GFX_EAGAIN, status::NETWORK_STATUS_PENDING);
    }

    #[test]
    fn w8_native_and_graphics_status_distinctness() {
        let entries: [(&str, u64); 22] = [
            ("native.EACCES", STATUS_EACCES),
            ("native.EINVAL", STATUS_EINVAL),
            ("native.ENOSPC", STATUS_ENOSPC),
            ("native.ENOSYS", STATUS_ENOSYS),
            ("native.ESTALE", STATUS_ESTALE),
            ("native.EAGAIN", STATUS_EAGAIN),
            ("native.EEXIST", STATUS_EEXIST),
            ("native.EPIPE", STATUS_EPIPE),
            ("native.ETIMEDOUT", STATUS_ETIMEDOUT),
            ("native.ECONNREFUSED", STATUS_ECONNREFUSED),
            ("graphics.EACCES", GFX_EACCES),
            ("graphics.EINVAL", GFX_EINVAL),
            ("graphics.ENOSPC", GFX_ENOSPC),
            ("graphics.ENOSYS", GFX_ENOSYS),
            ("graphics.ESTALE", GFX_ESTALE),
            ("graphics.EBADF", GFX_EBADF),
            ("graphics.EIO", GFX_EIO),
            ("graphics.EAGAIN", GFX_EAGAIN),
            ("graphics.ENODEV", GFX_ENODEV),
            ("graphics.ERANGE", GFX_ERANGE),
            ("graphics.ETIMEDOUT", GFX_ETIMEDOUT),
            ("graphics.ENOTRECOVERABLE", GFX_ENOTRECOVERABLE),
        ];

        for (name, value) in &entries {
            assert!(status::is_status(*value), "{name} must be a status");
            assert_ne!(
                *value,
                status::NETWORK_STATUS_PENDING,
                "{name} must not be pending"
            );
        }

        for (i, (name_i, value_i)) in entries.iter().enumerate() {
            let errno_i = name_i.split('.').nth(1).unwrap();
            for (name_j, value_j) in entries.iter().skip(i + 1) {
                let errno_j = name_j.split('.').nth(1).unwrap();
                if errno_i == errno_j {
                    assert_eq!(value_i, value_j, "{name_i} and {name_j}");
                } else {
                    assert_ne!(value_i, value_j, "{name_i} vs {name_j}");
                }
            }
        }

        assert_eq!(STATUS_EAGAIN, GFX_EAGAIN);
        assert_eq!(STATUS_ETIMEDOUT, GFX_ETIMEDOUT);

        let conn_raw = ConnectionId::new(u16::MAX, u32::MAX).unwrap().encode();
        assert!(conn_raw < STATUS_RANGE_START);
        let ws_raw = WorkSetId::new(u16::MAX, u32::MAX).unwrap().encode();
        assert!(ws_raw < STATUS_RANGE_START);
    }
}

#[cfg(test)]
mod graphics_role_crosscheck;
