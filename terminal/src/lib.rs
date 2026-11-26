//! Native terminal window (#311): a compositor toplevel showing an 80x25 character grid in the
//! Spleen 8x16 font, with scrollback and a cursor, whose text comes from a console stream of the
//! console service (#310) and whose typed lines go back to it.
//!
//! Everything but the syscalls is here and host-testable:
//!
//! - [`screen`]: the grid, its scrollback ring, the cursor and the rows that changed.
//! - [`vt`]: the VT100/ANSI subset BusyBox `ash` and its applets use.
//! - [`line`]: canonical-mode line editing and echo, since the Linux personality has no termios.
//! - [`keys`]: what a key press means to the terminal.
//! - [`app`]: the terminal's state tying those together, and the input waiting for the stream.
//! - [`render`]: paints the view's rows.
//! - [`session`]: the compositor protocol client, sans IO.
//! - [`host`]: the runtime compositor client as the session's host.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod app;
pub mod host;
pub mod keys;
pub mod line;
pub mod render;
pub mod screen;
pub mod session;
pub mod vt;

pub use app::Terminal;
pub use session::{ExitReason, Host, Outcome, Session, WINDOW_TITLE};

#[cfg(test)]
mod tests;
