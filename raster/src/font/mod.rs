//! Embedded Spleen 8×16 glyph atlas.

mod spleen_8x16;

use spleen_8x16::{ASCENT, GLYPHS, REPLACEMENT};

/// One-bpp row-major glyph; MSB of each byte is the leftmost pixel.
pub struct Glyph<'a> {
    /// Row data (`ceil(width/8)` bytes per row).
    pub rows: &'a [u8],
    /// Pixel width.
    pub width: u32,
    /// Pixel height.
    pub height: u32,
}

/// Replaceable glyph source for fixed-cell text rendering.
pub trait GlyphAtlas {
    /// Fixed cell size `(width, height)`.
    fn cell(&self) -> (u32, u32);
    /// Distance from cell top to baseline.
    fn baseline(&self) -> u32;
    /// Glyph for `ch` (replacement glyph when unmapped).
    fn glyph(&self, ch: char) -> Glyph<'_>;
}

/// Spleen 8×16 medium (ASCII printable + replacement).
pub struct Spleen8x16;

impl GlyphAtlas for Spleen8x16 {
    fn cell(&self) -> (u32, u32) {
        (8, 16)
    }

    fn baseline(&self) -> u32 {
        ASCENT
    }

    fn glyph(&self, ch: char) -> Glyph<'_> {
        let code = ch as u32;
        if (0x20..=0x7E).contains(&code) {
            let idx = (code - 0x20) as usize;
            Glyph {
                rows: &GLYPHS[idx],
                width: 8,
                height: 16,
            }
        } else {
            Glyph {
                rows: &REPLACEMENT,
                width: 8,
                height: 16,
            }
        }
    }
}

/// Default atlas instance.
pub static SPLEEN_8X16: Spleen8x16 = Spleen8x16;
