//! Typography over the #111 fixed-cell bitmap path: integer scale, faux-bold and ellipsis.

use clean_slate_graphics::{Point, Rect, Size};
use clean_slate_raster::{Canvas, GlyphAtlas};

use crate::layout::offset;
use crate::paint::fill;
use crate::tokens::{Rgba, TextStyle, Theme};

const ELLIPSIS: &str = "...";

/// Single-line extent of `text` in `style` (newlines are ignored, as in the raster path).
pub fn measure(theme: &Theme, style: TextStyle, text: &str) -> Size {
    let (cell_w, cell_h) = theme.font.cell();
    let count = visible_chars(text);
    let mut width = cell_w.saturating_mul(style.scale).saturating_mul(count);
    if style.strong && width > 0 {
        width = width.saturating_add(1);
    }
    Size {
        width,
        height: cell_h.saturating_mul(style.scale),
    }
}

/// Line advance: cell height × scale + leading.
pub fn line_height(theme: &Theme, style: TextStyle) -> u32 {
    theme
        .font
        .cell()
        .1
        .saturating_mul(style.scale)
        .saturating_add(style.leading)
}

/// Prefix of `text` that fits `max_width`, with whether an ellipsis must follow it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fit<'s> {
    /// Visible prefix (a char-boundary slice of the input).
    pub visible: &'s str,
    /// True when the text was truncated and `...` is appended.
    pub ellipsis: bool,
    /// Rendered width including the ellipsis.
    pub width: u32,
}

/// Truncates `text` to `max_width`, appending `...` when anything is cut.
pub fn fit<'s>(theme: &Theme, style: TextStyle, text: &'s str, max_width: u32) -> Fit<'s> {
    let full = measure(theme, style, text);
    if full.width <= max_width {
        return Fit {
            visible: text,
            ellipsis: false,
            width: full.width,
        };
    }
    let advance = theme.font.cell().0.saturating_mul(style.scale).max(1);
    let bold = u32::from(style.strong);
    let ellipsis_w = advance.saturating_mul(3);
    let ellipsis = max_width >= ellipsis_w + bold;
    let budget = if ellipsis {
        max_width - ellipsis_w - bold
    } else {
        max_width.saturating_sub(bold)
    };
    let (visible, kept) = prefix_chars(text, budget / advance);
    let tail = if ellipsis { 3 } else { 0 };
    Fit {
        visible,
        ellipsis,
        width: advance * (kept + tail) + if kept + tail > 0 { bold } else { 0 },
    }
}

/// The first `keep` non-newline chars of `text` and how many were kept.
fn prefix_chars(text: &str, keep: u32) -> (&str, u32) {
    let mut end = 0;
    let mut kept = 0u32;
    for (index, ch) in text.char_indices() {
        if ch == '\n' {
            continue;
        }
        if kept == keep {
            break;
        }
        kept += 1;
        end = index + ch.len_utf8();
    }
    (&text[..end], kept)
}

/// Draws `text` with its cell top-left at `origin`; returns the drawn extent.
pub fn draw(
    canvas: &mut Canvas<'_>,
    theme: &Theme,
    origin: Point,
    text: &str,
    style: TextStyle,
    color: Rgba,
) -> Size {
    draw_run(canvas, theme.font, origin, text, style, color);
    if style.strong {
        draw_run(
            canvas,
            theme.font,
            Point {
                x: offset(origin.x, 1),
                y: origin.y,
            },
            text,
            style,
            color,
        );
    }
    measure(theme, style, text)
}

/// Draws `text` truncated with an ellipsis to `max_width`; returns the drawn extent.
pub fn draw_fitted(
    canvas: &mut Canvas<'_>,
    theme: &Theme,
    origin: Point,
    text: &str,
    style: TextStyle,
    color: Rgba,
    max_width: u32,
) -> Size {
    let f = fit(theme, style, text, max_width);
    let first = draw(canvas, theme, origin, f.visible, style, color);
    if f.ellipsis {
        let advance = theme.font.cell().0.saturating_mul(style.scale);
        let at = Point {
            x: offset(origin.x, advance.saturating_mul(visible_chars(f.visible))),
            y: origin.y,
        };
        draw(canvas, theme, at, ELLIPSIS, style, color);
    }
    Size {
        width: f.width,
        height: first.height.max(measure(theme, style, ELLIPSIS).height),
    }
}

fn visible_chars(text: &str) -> u32 {
    text.chars()
        .filter(|&c| c != '\n')
        .fold(0u32, |n, _| n.saturating_add(1))
}

fn draw_run(
    canvas: &mut Canvas<'_>,
    font: &dyn GlyphAtlas,
    origin: Point,
    text: &str,
    style: TextStyle,
    color: Rgba,
) {
    if style.scale <= 1 {
        canvas.draw_text(font, (origin.x, origin.y), text, color.premultiplied());
        return;
    }
    let scale = style.scale;
    let (cell_w, _) = font.cell();
    let clip = canvas.clip();
    let clip_right = i64::from(clip.x) + i64::from(clip.width);
    let mut pen = i64::from(origin.x);
    for ch in text.chars() {
        if ch == '\n' {
            continue;
        }
        if pen > clip_right {
            break;
        }
        let glyph = if (ch as u32) < 0x20 {
            font.glyph('\u{FFFD}')
        } else {
            font.glyph(ch)
        };
        let row_bytes = glyph.width.div_ceil(8) as usize;
        for gy in 0..glyph.height {
            for gx in 0..glyph.width {
                let byte = glyph
                    .rows
                    .get(gy as usize * row_bytes + gx as usize / 8)
                    .copied()
                    .unwrap_or(0);
                if (byte >> (7 - gx % 8)) & 1 == 0 {
                    continue;
                }
                let x = pen + i64::from(gx * scale);
                let Ok(x) = i32::try_from(x) else {
                    continue;
                };
                fill(
                    canvas,
                    Rect {
                        x,
                        y: offset(origin.y, gy * scale),
                        width: scale,
                        height: scale,
                    },
                    color,
                );
            }
        }
        pen += i64::from(cell_w * scale);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::{TextRole, CLEAN_SLATE_DARK};

    #[test]
    fn type_scale_maps_onto_the_8x16_cell() {
        let t = &CLEAN_SLATE_DARK;
        let m = |role| measure(t, t.type_scale.style(role), "Ab");
        assert_eq!(
            m(TextRole::Body),
            Size {
                width: 16,
                height: 16
            }
        );
        assert_eq!(
            m(TextRole::Heading),
            Size {
                width: 17,
                height: 16
            }
        );
        assert_eq!(
            m(TextRole::Title),
            Size {
                width: 32,
                height: 32
            }
        );
        assert_eq!(
            m(TextRole::Display),
            Size {
                width: 48,
                height: 48
            }
        );
    }

    #[test]
    fn fit_truncates_on_char_boundaries_with_ellipsis() {
        let t = &CLEAN_SLATE_DARK;
        let body = t.type_scale.body;
        assert_eq!(fit(t, body, "Settings", 64).visible, "Settings");
        let cut = fit(t, body, "Settings", 56);
        assert_eq!((cut.visible, cut.ellipsis, cut.width), ("Sett", true, 56));
        let wide = fit(t, body, "héllo wörld", 48);
        assert_eq!((wide.visible, wide.ellipsis), ("hél", true));
        let narrow = fit(t, body, "Settings", 20);
        assert_eq!(
            (narrow.visible, narrow.ellipsis, narrow.width),
            ("Se", false, 16)
        );
    }
}
