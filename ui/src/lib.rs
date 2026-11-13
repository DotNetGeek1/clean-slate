//! Clean-Slate M10 design system: tokens, UI primitives, native window chrome visuals, the
//! cursor visual and the first desktop shell, rendered with [`clean_slate_raster`] into any
//! `&mut [u8]` described by a [`clean_slate_graphics::BufferLayout`].
//!
//! - [`tokens`]: every colour, spacing, radius, type, chrome, shell and budget value
//!   ([`CLEAN_SLATE_DARK`]).
//! - [`quality`]: Q0–Q3 tiers, switchable [`Effects`] and the [`Style`] passed to primitives.
//! - [`widgets`]: text, card, button, toggle, rail item, search field (shell and #117).
//! - [`chrome`]: [`ChromeStyle`], the look/metrics boundary consumed by the window manager.
//! - [`cursor`]: the compositor-owned pointer visual.
//! - [`shell`]: zones, surface plan, wallpaper, rail and rail interaction.
//! - [`surface`]: damage accumulation and `Damage` request batching for surface hosts.
//! - [`reference`]: host-side reference desktop and structural probes.
//!
//! The crate is `no_std`, allocation-free and `forbid(unsafe_code)`; nothing in it animates,
//! polls or redraws on a timer.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod chrome;
pub mod cursor;
pub mod icon;
pub mod layout;
pub mod paint;
pub mod quality;
pub mod reference;
pub mod shell;
pub mod surface;
pub mod text;
pub mod tokens;
pub mod widgets;

pub use chrome::{ChromeControl, ChromeState, ChromeStyle, CleanSlateChrome};
pub use icon::Icon;
pub use quality::{Effects, QualityTier, Style};
pub use shell::{RailInput, Shell, ShellConfig, ShellZones};
pub use surface::Damage;
pub use tokens::{Rgba, Theme, CLEAN_SLATE_DARK};
pub use widgets::{Button, Card, CardKind, RailItem, Text, Toggle, WidgetState};

#[cfg(test)]
mod tests;
