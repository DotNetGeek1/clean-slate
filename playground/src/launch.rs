//! Launch page the CPL3 binary reads at start-up.
//!
//! The desktop launch policy (#118) writes the shared [`DesktopLaunchPage`] and grants exactly
//! one `Graphics{GFX_CONNECT}` capability for `graphics_resource_id` (plus the console handle
//! for diagnostics). The first two words keep the #112 client-fixture layout.

pub use clean_slate_native_abi::desktop::{
    DesktopLaunchPage as PlaygroundBootstrap, DESKTOP_LAUNCH_ADDRESS as BOOTSTRAP_ADDRESS,
    DESKTOP_LAUNCH_BYTES as BOOTSTRAP_BYTES,
};

const _: () = assert!(BOOTSTRAP_ADDRESS == 0x0000_4000_0000_1000);
const _: () = assert!(core::mem::offset_of!(PlaygroundBootstrap, self_pid) == 0);
const _: () = assert!(core::mem::offset_of!(PlaygroundBootstrap, graphics_resource_id) == 8);
