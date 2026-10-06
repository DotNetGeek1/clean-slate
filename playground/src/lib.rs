//! M10 System Playground (#117): a small native Clean-Slate GUI application that uses only the
//! app-facing contract: a `Graphics{GFX_CONNECT}` port connection (#200), two shared pixel
//! buffers (#195), the #110 surface protocol served by the #112 compositor, and the #116 design
//! primitives. It has no framebuffer, GPU, display or raw-input authority, and draws no window
//! chrome of its own: the compositor's window manager (#115) owns the frame.
//!
//! Everything except the syscalls is here and host-testable:
//!
//! - [`layout`]: the panel geometry, derived from design tokens.
//! - [`app`]: application state, input handling and the [`app::View`] snapshot whose diff is
//!   the damage of every state change.
//! - [`render`]: paints a [`app::View`] with `clean-slate-ui` widgets; a pure function of the
//!   view, so a damage-clipped repaint equals a full repaint.
//! - [`session`]: the sans-IO protocol client (setup, double buffering, input routing, close).
//! - [`launch`]: the launch-page layout the CPL3 binary reads.
//! - [`diag`]: the serial diagnostic lines the CPL3 binary prints through the console.
//!
//! The app is event-driven: it renders only when an event changed the view and a buffer is
//! free, and it never redraws because time passed.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod app;
pub mod diag;
pub mod keys;
pub mod launch;
pub mod layout;
pub mod render;
pub mod session;
pub mod text;

pub use app::{Control, Playground, View};
pub use layout::{PanelLayout, PANEL_SIZE};
pub use session::{BufferSlot, ExitReason, Host, HostError, Outcome, Session, WINDOW_TITLE};

#[cfg(test)]
mod tests;
