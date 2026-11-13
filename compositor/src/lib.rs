//! M10 userspace compositor (#112): the surface-protocol server, damage-driven software
//! composition and non-blocking present scheduling.
//!
//! **Authority.** The compositor process holds `Graphics{GFX_SERVE}` for its service port,
//! `Display{DISPLAY_PRESENT}`, `Input{INPUT_CONSUME}`, and one `SharedBuffer{READ}` child per
//! registered client buffer, received only through a port transfer. It reads client pixels
//! exclusively through those mappings ([`backend::SharedBufferMapper`]); it never sees process
//! memory, physical frames or device registers.
//!
//! **Isolation.** Every protocol object lives in its connection's own generational table and
//! every scene entry is keyed by `(ConnectionId, ObjectId)`, so an id guessed by one client
//! names nothing in another client's table.
//!
//! **Loop.** [`Compositor::iterate`] blocks on the work set until requests, notices, raw input
//! or display completion are ready. With nothing in flight and no stalled client the wait has no
//! deadline, so an idle desktop costs nothing.
//!
//! **Kernel boundary.** All kernel access goes through the traits in [`backend`]; the userspace
//! binary implements them over syscalls 16–20 and host tests over [`fake`].
//!
//! **Window management (#115).** [`wm`] owns focus, z-order, hit targets, interactive
//! move/resize, server-side decorations and the software cursor; a [`wm::WindowPolicy`]
//! supplies only placement and look (the #116 `ChromeStyle` and cursor image).

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod backend;
pub mod client;
pub mod compose;
pub mod compositor;
pub mod diag;
#[cfg(any(test, feature = "fake"))]
pub mod fake;
pub mod input;
pub mod present;
pub mod scene;
pub mod wm;

pub use compositor::{
    Compositor, Config, Io, Iteration, OutputDamage, ServiceError, Stats, WaitPlan, UNSOLICITED_TAG,
};
pub use scene::SurfaceKey;
pub use wm::{DefaultPolicy, WindowPolicy, WmHit};

#[cfg(test)]
mod tests;
