//! Fixed-cell glyph runs.

use crate::canvas::Canvas;
use crate::clip::draw_rect;
use crate::color::Color;
use crate::font::GlyphAtlas;
use crate::pixel::{row_offset, write_coverage};
use clean_slate_graphics::Rect;

/// Bounding box for a single-line glyph run (same as [`measure_text`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextExtent {
    /// Total width in pixels.
    pub width: u32,
    /// Cell height in pixels.
    pub height: u32,
}

/// Returns `(cell_width × char_count, cell_height)` with saturating width.
pub fn measure_text(font: &dyn GlyphAtlas, text: &str) -> TextExtent {
    let (cw, ch) = font.cell();
    let mut count = 0u32;
    for ch in text.chars() {
        if ch == '\n' {
            continue;
        }
        count = count.saturating_add(1);
    }
    TextExtent {
        width: cw.saturating_mul(count),
        height: ch,
    }
}

impl Canvas<'_> {
    /// Draws `text` at `origin` (cell top-left); `\n` is ignored (no advance).
    pub fn draw_text(
        &mut self,
        font: &dyn GlyphAtlas,
        origin: (i32, i32),
        text: &str,
        c: Color,
    ) -> TextExtent {
        let extent = measure_text(font, text);
        let (cell_w, _) = font.cell();
        let fmt = self.layout.format();
        let clip_right = self.clip.x as i64 + i64::from(self.clip.width);
        let mut pen_x = origin.0 as i64;
        for ch in text.chars() {
            if ch == '\n' {
                continue;
            }
            if pen_x > clip_right {
                break;
            }
            let g = if (ch as u32) < 0x20 {
                font.glyph('\u{FFFD}')
            } else {
                font.glyph(ch)
            };
            draw_glyph(self, pen_x as i32, origin.1, &g, c, fmt);
            pen_x += i64::from(cell_w);
        }
        extent
    }
}

fn draw_glyph(
    canvas: &mut Canvas<'_>,
    x0: i32,
    y0: i32,
    glyph: &crate::font::Glyph<'_>,
    c: Color,
    fmt: clean_slate_graphics::pixel::PixelFormat,
) {
    let target = Rect {
        x: x0,
        y: y0,
        width: glyph.width,
        height: glyph.height,
    };
    let r = draw_rect(canvas.clip, target, canvas.layout);
    if r.width == 0 || r.height == 0 {
        return;
    }
    let row_bytes = glyph.width.div_ceil(8);
    for row in 0..r.height {
        let gy = r.y + row as i32 - y0;
        if gy < 0 || gy >= glyph.height as i32 {
            continue;
        }
        let row_off = gy as usize * row_bytes as usize;
        let bits = glyph.rows.get(row_off).copied().unwrap_or(0);
        for col in 0..r.width {
            let gx = r.x + col as i32 - x0;
            if gx < 0 || gx >= glyph.width as i32 {
                continue;
            }
            let bit = 7 - (gx as u32);
            if (bits >> bit) & 1 == 0 {
                continue;
            }
            let px = r.x as u32 + col;
            let py = r.y as u32 + row;
            if let Some(off) = row_offset(canvas.layout, px, py) {
                write_coverage(canvas.bytes, off, c, 255, fmt);
            }
        }
    }
}
