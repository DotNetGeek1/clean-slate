//! Clipped drawing into a validated [`BufferLayout`] slice.

use clean_slate_graphics::limits::MAX_SURFACE_EXTENT;
use clean_slate_graphics::pixel::PixelFormat;
use clean_slate_graphics::{BufferLayout, Rect};

use crate::clip::{draw_rect, intersect_rect, layout_bounds};
use crate::color::Color;
use crate::pixel::{row_offset, write_coverage, write_opaque, write_over};
use crate::RasterError;

/// Mutable view of a pixel buffer with a clip rect (never expanded by [`Self::with_clip`]).
pub struct Canvas<'a> {
    pub(crate) bytes: &'a mut [u8],
    pub(crate) layout: BufferLayout,
    pub(crate) clip: Rect,
}

impl<'a> Canvas<'a> {
    /// Validates `bytes` against `layout` and sets clip to the full layout bounds.
    pub fn new(bytes: &'a mut [u8], layout: BufferLayout) -> Result<Self, RasterError> {
        if !layout.fits_in(bytes.len() as u64) {
            return Err(RasterError::BufferTooSmall);
        }
        Ok(Self {
            bytes,
            layout,
            clip: layout_bounds(layout),
        })
    }

    /// Buffer layout frozen at construction.
    pub fn layout(&self) -> BufferLayout {
        self.layout
    }

    /// Current clip in buffer coordinates (half-open).
    pub fn clip(&self) -> Rect {
        self.clip
    }

    /// Immutable view of backing bytes (includes stride padding).
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Narrows clip to the intersection with `clip` (empty intersection ⇒ all draws no-op).
    pub fn with_clip(&mut self, clip: Rect) -> Canvas<'_> {
        let inner = intersect_rect(self.clip, clip);
        Canvas {
            bytes: &mut *self.bytes,
            layout: self.layout,
            clip: inner,
        }
    }

    /// Fills the clip rect with `c`.
    pub fn clear(&mut self, c: Color) {
        let r = self.clip;
        self.fill_rect(r, c);
    }

    /// Opaque fill; Xrgb byte 3 forced to `0xFF`.
    pub fn fill_rect(&mut self, r: Rect, c: Color) {
        let r = draw_rect(self.clip, r, self.layout);
        if r.width == 0 || r.height == 0 {
            return;
        }
        let fmt = self.layout.format();
        for row in 0..r.height {
            let y = r.y as u32 + row;
            for col in 0..r.width {
                let x = r.x as u32 + col;
                if let Some(off) = row_offset(self.layout, x, y) {
                    write_opaque(self.bytes, off, c, fmt);
                }
            }
        }
    }

    /// Per-pixel premultiplied blend.
    pub fn blend_rect(&mut self, r: Rect, c: Color) {
        let r = draw_rect(self.clip, r, self.layout);
        if r.width == 0 || r.height == 0 {
            return;
        }
        let fmt = self.layout.format();
        for row in 0..r.height {
            let y = r.y as u32 + row;
            for col in 0..r.width {
                let x = r.x as u32 + col;
                if let Some(off) = row_offset(self.layout, x, y) {
                    write_over(self.bytes, off, c.0, fmt);
                }
            }
        }
    }

    /// Inside border of `r` with thickness clamped to half width/height.
    pub fn stroke_rect(&mut self, r: Rect, width: u32, c: Color) {
        if width == 0 || r.width == 0 || r.height == 0 {
            return;
        }
        let t = width.min(r.width / 2).min(r.height / 2);
        if t == 0 {
            return;
        }
        let top = Rect {
            x: r.x,
            y: r.y,
            width: r.width,
            height: t,
        };
        let bottom = Rect {
            x: r.x,
            y: offset(r.y, r.height - t),
            width: r.width,
            height: t,
        };
        let inner_h = r.height.saturating_sub(t * 2);
        let left = Rect {
            x: r.x,
            y: offset(r.y, t),
            width: t,
            height: inner_h,
        };
        let right = Rect {
            x: offset(r.x, r.width - t),
            y: offset(r.y, t),
            width: t,
            height: inner_h,
        };
        self.fill_rect(top, c);
        self.fill_rect(bottom, c);
        self.fill_rect(left, c);
        self.fill_rect(right, c);
    }

    /// Inclusive horizontal segment, order independent.
    pub fn hline(&mut self, x0: i32, x1: i32, y: i32, c: Color) {
        let (start, len) = inclusive_span(x0, x1);
        self.fill_rect(
            Rect {
                x: start,
                y,
                width: len,
                height: 1,
            },
            c,
        );
    }

    /// Inclusive vertical segment, order independent.
    pub fn vline(&mut self, x: i32, y0: i32, y1: i32, c: Color) {
        let (start, len) = inclusive_span(y0, y1);
        self.fill_rect(
            Rect {
                x,
                y: start,
                width: 1,
                height: len,
            },
            c,
        );
    }

    /// Integer Bresenham. Lines whose span on either axis exceeds twice the compositor extent are
    /// skipped, which bounds the step count; so are lines whose bbox misses the clip.
    pub fn line(&mut self, p0: (i32, i32), p1: (i32, i32), c: Color) {
        let dx = (i64::from(p1.0) - i64::from(p0.0)).abs();
        let dy = (i64::from(p1.1) - i64::from(p0.1)).abs();
        let max_span = i64::from(MAX_SURFACE_EXTENT) * 2;
        if dx > max_span || dy > max_span {
            return;
        }
        let bbox = Rect {
            x: p0.0.min(p1.0),
            y: p0.1.min(p1.1),
            width: dx as u32 + 1,
            height: dy as u32 + 1,
        };
        if draw_rect(self.clip, bbox, self.layout).width == 0 {
            return;
        }

        let mut x = i64::from(p0.0);
        let mut y = i64::from(p0.1);
        let sx = if p0.0 <= p1.0 { 1 } else { -1 };
        let sy = if p0.1 <= p1.1 { 1 } else { -1 };
        let mut err = dx - dy;
        let fmt = self.layout.format();
        loop {
            self.plot(x, y, c, fmt);
            if x == i64::from(p1.0) && y == i64::from(p1.1) {
                break;
            }
            let e2 = 2 * err;
            if e2 > -dy {
                err -= dy;
                x += sx;
            }
            if e2 < dx {
                err += dx;
                y += sy;
            }
        }
    }

    fn plot(&mut self, x: i64, y: i64, c: Color, fmt: PixelFormat) {
        let (Ok(xi), Ok(yi)) = (i32::try_from(x), i32::try_from(y)) else {
            return;
        };
        let pixel = Rect {
            x: xi,
            y: yi,
            width: 1,
            height: 1,
        };
        if draw_rect(self.clip, pixel, self.layout).width == 0 {
            return;
        }
        if let Some(off) = row_offset(self.layout, xi as u32, yi as u32) {
            write_opaque(self.bytes, off, c, fmt);
        }
    }

    /// A8 coverage mask blended like [`Self::blend_rect`].
    pub fn fill_mask(
        &mut self,
        mask: &[u8],
        mask_w: u32,
        mask_h: u32,
        origin: (i32, i32),
        c: Color,
    ) {
        let need = (mask_w as u64).saturating_mul(mask_h as u64) as usize;
        if mask.len() < need {
            return;
        }
        let target = Rect {
            x: origin.0,
            y: origin.1,
            width: mask_w,
            height: mask_h,
        };
        let r = draw_rect(self.clip, target, self.layout);
        if r.width == 0 || r.height == 0 {
            return;
        }
        let fmt = self.layout.format();
        for py in r.y..r.y + r.height as i32 {
            for px in r.x..r.x + r.width as i32 {
                let mx = px - origin.0;
                let my = py - origin.1;
                if mx < 0 || my < 0 {
                    continue;
                }
                let mx = mx as u32;
                let my = my as u32;
                if mx >= mask_w || my >= mask_h {
                    continue;
                }
                let cov = mask[my as usize * mask_w as usize + mx as usize];
                if let Ok(x) = u32::try_from(px) {
                    if let Ok(y) = u32::try_from(py) {
                        if let Some(off) = row_offset(self.layout, x, y) {
                            write_coverage(self.bytes, off, c, cov, fmt);
                        }
                    }
                }
            }
        }
    }
}

/// Start and length of the inclusive range between `a` and `b`, saturating at `u32::MAX`.
fn inclusive_span(a: i32, b: i32) -> (i32, u32) {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let len = i64::from(hi) - i64::from(lo) + 1;
    (lo, u32::try_from(len).unwrap_or(u32::MAX))
}

/// `base + delta` clamped to `i32`; a clamped edge lies outside every layout either way.
fn offset(base: i32, delta: u32) -> i32 {
    (i64::from(base) + i64::from(delta)).clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}
