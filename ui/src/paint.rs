//! Token-aware shape helpers over a raster [`Canvas`]. All of them respect the canvas clip,
//! so repainting a damage rect is "set the clip, paint everything".

use clean_slate_graphics::pixel::PixelFormat;
use clean_slate_graphics::Rect;
use clean_slate_raster::{Canvas, Color};

use crate::layout::offset;
use crate::tokens::Rgba;

/// Which corners of a rectangle are rounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Corners {
    /// Top-left and top-right.
    pub top: bool,
    /// Bottom-left and bottom-right.
    pub bottom: bool,
}

impl Corners {
    /// All four corners.
    pub const ALL: Self = Self {
        top: true,
        bottom: true,
    };
    /// Top corners only (window title bars).
    pub const TOP: Self = Self {
        top: true,
        bottom: false,
    };
    /// Square.
    pub const NONE: Self = Self {
        top: false,
        bottom: false,
    };
}

/// Writes `color` into `r`.
///
/// Opaque colours, and any colour on an `Argb8888Premultiplied` target, store the
/// premultiplied value so an alpha-carrying surface hands its translucency to the compositor.
/// A translucent colour on an opaque `Xrgb8888` target blends over what is already there.
pub fn fill(canvas: &mut Canvas<'_>, r: Rect, color: Rgba) {
    let c = color.premultiplied();
    if color.is_opaque() || canvas.layout().format() == PixelFormat::Argb8888Premultiplied {
        canvas.fill_rect(r, c);
    } else {
        canvas.blend_rect(r, c);
    }
}

/// Blends `color` over `r` regardless of the target format (shadows, overlays).
pub fn blend(canvas: &mut Canvas<'_>, r: Rect, color: Rgba) {
    canvas.blend_rect(r, color.premultiplied());
}

/// Sets every pixel in the clip to transparent black (opaque black on `Xrgb8888`).
pub fn clear_transparent(canvas: &mut Canvas<'_>) {
    canvas.clear(Color([0, 0, 0, 0]));
}

/// Fills `r` with rounded `corners` of `radius` (clamped to half the shorter side).
pub fn fill_rounded(canvas: &mut Canvas<'_>, r: Rect, radius: u32, corners: Corners, color: Rgba) {
    if r.is_empty() {
        return;
    }
    let radius = clamp_radius(r, radius);
    for row in 0..r.height {
        let inset = row_inset(r.height, row, radius, corners);
        fill(
            canvas,
            Rect {
                x: offset(r.x, inset),
                y: offset(r.y, row),
                width: r.width - 2 * inset,
                height: 1,
            },
            color,
        );
    }
}

/// Blends a rounded rectangle (see [`fill_rounded`]) regardless of the target format.
pub fn blend_rounded(canvas: &mut Canvas<'_>, r: Rect, radius: u32, color: Rgba) {
    if r.is_empty() {
        return;
    }
    let radius = clamp_radius(r, radius);
    for row in 0..r.height {
        let inset = row_inset(r.height, row, radius, Corners::ALL);
        blend(
            canvas,
            Rect {
                x: offset(r.x, inset),
                y: offset(r.y, row),
                width: r.width - 2 * inset,
                height: 1,
            },
            color,
        );
    }
}

/// Inside border of width `width` following the same rounded outline as [`fill_rounded`].
pub fn stroke_rounded(
    canvas: &mut Canvas<'_>,
    r: Rect,
    radius: u32,
    corners: Corners,
    width: u32,
    color: Rgba,
) {
    let width = width.min(r.width / 2).min(r.height / 2);
    if width == 0 {
        return;
    }
    let radius = clamp_radius(r, radius);
    let inner_w = r.width - 2 * width;
    let inner_h = r.height - 2 * width;
    let inner_radius = radius.saturating_sub(width);
    for row in 0..r.height {
        let y = offset(r.y, row);
        let outer = row_inset(r.height, row, radius, corners);
        let left = i64::from(r.x) + i64::from(outer);
        let right = i64::from(r.x) + i64::from(r.width - outer);
        if row < width || row >= r.height - width || inner_w == 0 || inner_h == 0 {
            span(canvas, y, left, right, color);
            continue;
        }
        let inner = row_inset(inner_h, row - width, inner_radius.min(inner_w / 2), corners);
        let inner_left = i64::from(r.x) + i64::from(width + inner);
        let inner_right = i64::from(r.x) + i64::from(r.width - width - inner);
        span(canvas, y, left, inner_left, color);
        span(canvas, y, inner_right, right, color);
    }
}

fn span(canvas: &mut Canvas<'_>, y: i32, x0: i64, x1: i64, color: Rgba) {
    if x1 <= x0 {
        return;
    }
    let (Ok(x), Ok(width)) = (i32::try_from(x0), u32::try_from(x1 - x0)) else {
        return;
    };
    fill(
        canvas,
        Rect {
            x,
            y,
            width,
            height: 1,
        },
        color,
    );
}

fn clamp_radius(r: Rect, radius: u32) -> u32 {
    radius.min(r.width / 2).min(r.height / 2)
}

/// Horizontal inset of `row` for a shape of `height` with the given rounding.
fn row_inset(height: u32, row: u32, radius: u32, corners: Corners) -> u32 {
    if radius == 0 {
        return 0;
    }
    if corners.top && row < radius {
        return corner_inset(radius, row);
    }
    let from_bottom = height - 1 - row;
    if corners.bottom && from_bottom < radius {
        return corner_inset(radius, from_bottom);
    }
    0
}

/// Pixels cut from a row `row` pixels in from the edge of a quarter circle of `radius`,
/// sampled at pixel centres in doubled integer coordinates.
fn corner_inset(radius: u32, row: u32) -> u32 {
    let r2 = u64::from(radius) * 2;
    let d = r2 - u64::from(row) * 2 - 1;
    let chord = isqrt(r2 * r2 - d * d);
    let cut = r2.saturating_sub(chord + 1);
    cut.div_ceil(2) as u32
}

fn isqrt(n: u64) -> u64 {
    if n < 2 {
        return n;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isqrt_matches_floor_sqrt() {
        for n in 0u64..10_000 {
            let s = isqrt(n);
            assert!(s * s <= n && (s + 1) * (s + 1) > n, "n={n}");
        }
    }

    #[test]
    fn corner_inset_is_monotonic_and_reaches_zero() {
        for radius in 1..=32 {
            let mut prev = u32::MAX;
            for row in 0..radius {
                let inset = corner_inset(radius, row);
                assert!(inset <= prev, "r={radius} row={row}");
                assert!(inset < radius);
                prev = inset;
            }
            assert_eq!(corner_inset(radius, radius - 1), 0);
        }
    }
}
