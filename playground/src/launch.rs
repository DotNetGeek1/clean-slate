//! Launch page the CPL3 binary reads at start-up.
//!
//! The layout matches the #112 client fixture (`{ self_pid, graphics_resource_id }`); the
//! desktop launch policy (#118) writes it and grants exactly one `Graphics{GFX_CONNECT}`
//! capability for `graphics_resource_id`. Nothing else is read from the page.

/// Address of the launch page (the convention shared with the compositor and its client fixture).
pub const BOOTSTRAP_ADDRESS: u64 = 0x0000_4000_0000_1000;

/// Launch page layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlaygroundBootstrap {
    /// The app's own pid, for diagnostics only; authority comes from capabilities.
    pub self_pid: u64,
    /// Resource id of the compositor's `Graphics` port (`ResourceRef::graphics`).
    pub graphics_resource_id: u64,
}

/// Bytes the launch policy must write.
pub const BOOTSTRAP_BYTES: usize = core::mem::size_of::<PlaygroundBootstrap>();

const _: () = assert!(BOOTSTRAP_BYTES == 16);
const _: () = assert!(core::mem::offset_of!(PlaygroundBootstrap, graphics_resource_id) == 8);
