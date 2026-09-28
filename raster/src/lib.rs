//! no_std software rasterizer over [`clean_slate_graphics`] buffer layouts.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod blit;
mod canvas;
mod clip;
mod color;
mod convert;
mod font;
mod pattern;
mod pixel;
mod text;

pub use blit::BlitMode;
pub use clean_slate_graphics::{BufferLayout, PixelFormat, Rect};
pub use color::Color;

/// Raster operation failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RasterError {
    /// Backing slice shorter than [`BufferLayout::byte_len`].
    BufferTooSmall,
    /// Reserved for future format pairs.
    Unsupported,
    /// Clip/layout intersection empty or non-representable.
    InvalidGeometry,
}

pub use canvas::Canvas;
pub use text::{measure_text, TextExtent};

pub use convert::{bgrx_to_rgbx, rgbx_to_bgrx};
pub use font::{Glyph, GlyphAtlas, Spleen8x16, SPLEEN_8X16};
pub use pattern::{
    draw_reference_a, draw_reference_b, draw_reference_decoy, pixel_at, reference_layout,
    visible_crc32, Crc32, REFERENCE_B_DAMAGE, REFERENCE_DECOY, REFERENCE_PROBES,
};

#[cfg(test)]
mod tests;
