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
