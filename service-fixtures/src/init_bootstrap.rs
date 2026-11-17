//! #218 S3b bootstrap page the kernel writes for userspace init.
//!
//! It holds init's own pid, two capability handles and (#218 S6a) the desktop boot mode. Init
//! reads the clock with `WORK_SET` op `NOW` and needs no block-device, object-service or network
//! authority.
//!
//! Layout, little-endian, no padding (`repr(C)` of four `u64`s):
//!
//! | Offset | Field | Meaning |
//! | --- | --- | --- |
//! | 0 | `self_pid` | init's pid |
//! | 8 | `console_capability` | IPC send handle for init's console lines |
//! | 16 | `lifecycle_capability` | `LIFECYCLE_CONTROL` (4), `LIFECYCLE_POLL` (5), `LIFECYCLE_WAIT` (21) |
//! | 24 | `desktop_mode` | [`DESKTOP_MODE_OFF`], [`DESKTOP_MODE_FRAMEBUFFER`] (`q0`) or [`DESKTOP_MODE_VIRTIO_GPU`] (`q1`) |

/// Where the kernel maps init's bootstrap page (the same slot as the storage service's).
pub const INIT_BOOTSTRAP_ADDRESS: u64 = 0x0000_4000_0010_0000;

/// `desktop_mode` when the desktop is off: no fw_cfg entry, or a value the kernel rejected.
pub const DESKTOP_MODE_OFF: u64 = 0;
/// `desktop_mode` when `opt/clean-slate/desktop` is `q0` (GOP framebuffer).
pub const DESKTOP_MODE_FRAMEBUFFER: u64 = 1;
/// `desktop_mode` when `opt/clean-slate/desktop` is `q1` (VirtIO-GPU).
pub const DESKTOP_MODE_VIRTIO_GPU: u64 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitBootstrap {
    pub self_pid: u64,
    /// IPC send capability for init's console lines.
    pub console_capability: u64,
    /// Lifecycle-control capability: `LIFECYCLE_CONTROL` (4), `LIFECYCLE_POLL` (5) and
    /// `LIFECYCLE_WAIT` (21).
    pub lifecycle_capability: u64,
    /// Desktop boot mode. See [`DESKTOP_MODE_OFF`].
    pub desktop_mode: u64,
}

const _: () = assert!(core::mem::size_of::<InitBootstrap>() == 32);
const _: () = assert!(core::mem::offset_of!(InitBootstrap, desktop_mode) == 24);
