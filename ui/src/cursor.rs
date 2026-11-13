//! Pointer cursor visual. The compositor owns the cursor as a trusted internal layer (#115);
//! this module only supplies its pixels, hotspot and damage bounds.

use clean_slate_graphics::{Point, Rect};
use clean_slate_raster::Canvas;

use crate::layout::offset;
use crate::paint::fill;
use crate::tokens::{Rgba, Theme};

/// A palette-indexed cursor image. Row characters: `.` transparent, `o` outline,
/// `#` fill, `a` accent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorImage {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Hotspot offset from the image top-left.
    pub hotspot: Point,
    /// `height` rows of `width` palette characters.
    pub rows: &'static [&'static str],
}

/// The default arrow: near-white fill, deep outline that reads on light and dark content,
/// and a cyan spine in the Clean-Slate accent.
pub const ARROW: CursorImage = CursorImage {
    width: 12,
    height: 18,
    hotspot: Point { x: 0, y: 0 },
    rows: &[
        "o...........",
        "oo..........",
        "o#o.........",
        "oa#o........",
        "oa##o.......",
        "oa###o......",
        "oa####o.....",
        "oa#####o....",
        "oa######o...",
        "oa#######o..",
        "o#####ooooo.",
        "o##o##o.....",
        "o#o.o##o....",
        "oo..o##o....",
        "o....o##o...",
        ".....o##o...",
        "......oo....",
        "............",
    ],
};

/// Screen rect covered by `image` with its hotspot at `hotspot` (damage for show/move/hide).
pub fn cursor_rect(image: &CursorImage, hotspot: Point) -> Rect {
    Rect {
        x: hotspot.x.saturating_sub(image.hotspot.x),
        y: hotspot.y.saturating_sub(image.hotspot.y),
        width: image.width,
        height: image.height,
    }
}

/// Paints `image` with its hotspot at `hotspot`.
pub fn paint_cursor(canvas: &mut Canvas<'_>, theme: &Theme, image: &CursorImage, hotspot: Point) {
    let origin = cursor_rect(image, hotspot);
    let p = &theme.palette;
    for (y, row) in image.rows.iter().enumerate().take(image.height as usize) {
        for (x, cell) in row.bytes().enumerate().take(image.width as usize) {
            let color: Rgba = match cell {
                b'o' => p.cursor_outline,
                b'#' => p.cursor_fill,
                b'a' => p.cursor_accent,
                _ => continue,
            };
            fill(
                canvas,
                Rect {
                    x: offset(origin.x, x as u32),
                    y: offset(origin.y, y as u32),
                    width: 1,
                    height: 1,
                },
                color,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arrow_rows_match_declared_size_and_hotspot_is_opaque() {
        assert_eq!(ARROW.rows.len(), ARROW.height as usize);
        for row in ARROW.rows {
            assert_eq!(row.len(), ARROW.width as usize);
            assert!(row.bytes().all(|b| matches!(b, b'.' | b'o' | b'#' | b'a')));
        }
        let hs = ARROW.rows[ARROW.hotspot.y as usize].as_bytes()[ARROW.hotspot.x as usize];
        assert_ne!(hs, b'.');
    }
}
