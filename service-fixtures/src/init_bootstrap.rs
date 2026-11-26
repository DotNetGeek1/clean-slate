//! #218 S3b bootstrap page the kernel writes for userspace init.
//!
//! It holds init's own pid, two capability handles, (#218 S6a) the desktop boot mode and (#237)
//! init's serve handle on the launcher port. Init reads the clock with `WORK_SET` op `NOW` and
//! needs no block-device, object-service or network authority.
//!
//! Layout, little-endian, no padding (`repr(C)` of five `u64`s):
//!
//! | Offset | Field | Meaning |
//! | --- | --- | --- |
//! | 0 | `self_pid` | init's pid |
//! | 8 | `console_capability` | IPC send handle for init's console lines |
//! | 16 | `lifecycle_capability` | `LIFECYCLE_CONTROL` (4), `LIFECYCLE_POLL` (5), `LIFECYCLE_WAIT` (21) |
//! | 24 | `desktop_mode` | [`DESKTOP_MODE_OFF`], [`DESKTOP_MODE_FRAMEBUFFER`] (`q0`) or [`DESKTOP_MODE_VIRTIO_GPU`] (`q1`), with [`DESKTOP_MODE_TERMINAL`] for `q0-terminal` or `q1-terminal` |
//! | 32 | `launcher_capability` | `LAUNCH_SERVE` on `ResourceRef::launcher_port()` (#237) |

/// Where the kernel maps init's bootstrap page (the same slot as the storage service's).
pub const INIT_BOOTSTRAP_ADDRESS: u64 = 0x0000_4000_0010_0000;

/// `desktop_mode` when the desktop is off: no fw_cfg entry, or a value the kernel rejected.
pub const DESKTOP_MODE_OFF: u64 = 0;
/// `desktop_mode` when `opt/clean-slate/desktop` is `q0` (GOP framebuffer).
pub const DESKTOP_MODE_FRAMEBUFFER: u64 = 1;
/// `desktop_mode` when `opt/clean-slate/desktop` is `q1` (VirtIO-GPU).
pub const DESKTOP_MODE_VIRTIO_GPU: u64 = 2;
/// Set on a desktop word when `opt/clean-slate/desktop` is `q0-terminal` or `q1-terminal`: the
/// desktop also declares the terminal window and its shell (#311). Never set on
/// [`DESKTOP_MODE_OFF`].
pub const DESKTOP_MODE_TERMINAL: u64 = 1 << 8;

/// The tier part of a `desktop_mode` word: off, `q0` or `q1`.
pub const fn desktop_tier(desktop_mode: u64) -> u64 {
    desktop_mode & !DESKTOP_MODE_TERMINAL
}

/// Whether a `desktop_mode` word asks for the terminal rows.
pub const fn desktop_terminal(desktop_mode: u64) -> bool {
    desktop_mode & DESKTOP_MODE_TERMINAL != 0
}

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
    /// `LAUNCH_SERVE` on the launcher port the kernel registered for init (#237).
    pub launcher_capability: u64,
}

const _: () = assert!(core::mem::size_of::<InitBootstrap>() == 40);
const _: () = assert!(core::mem::offset_of!(InitBootstrap, launcher_capability) == 32);
const _: () = assert!(core::mem::offset_of!(InitBootstrap, desktop_mode) == 24);
