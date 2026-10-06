//! M10 desktop shell (#116/#118): the persistent left rail and the background (wallpaper,
//! workspace and static placeholders) as an ordinary CPL3 compositor client.
//!
//! The shell holds one `Graphics{GFX_CONNECT|GFX_SHELL}` capability. `GFX_SHELL` is what lets the
//! compositor grant its two surfaces the `Background` and `ShellPanel` roles; everything else
//! (placement, layering above or below windows, the cursor, window chrome) is window-manager
//! policy in the compositor. There is no dock surface, no framebuffer, display or input
//! authority, and no redraw that time alone causes.
//!
//! - [`session`]: the sans-IO protocol client (setup, rail input, double-buffered rail commits).
//! - [`diag`]: the serial diagnostic lines the CPL3 binary prints through the console.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod diag;
pub mod session;

pub use session::{BufferSlot, ExitReason, Host, HostError, Outcome, SessionStats, ShellSession};
