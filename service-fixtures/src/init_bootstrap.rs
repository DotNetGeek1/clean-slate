//! #218 S3b bootstrap page the kernel writes for userspace init.
//!
//! It holds init's own pid and two capability handles, and nothing else: init reads the clock
//! with `WORK_SET` op `NOW` and needs no block-device, object-service or network authority.

/// Where the kernel maps init's bootstrap page (the same slot as the storage service's).
pub const INIT_BOOTSTRAP_ADDRESS: u64 = 0x0000_4000_0010_0000;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitBootstrap {
    pub self_pid: u64,
    /// IPC send capability for init's console lines.
    pub console_capability: u64,
    /// Lifecycle-control capability: `LIFECYCLE_CONTROL` (4), `LIFECYCLE_POLL` (5) and
    /// `LIFECYCLE_WAIT` (21).
    pub lifecycle_capability: u64,
}
