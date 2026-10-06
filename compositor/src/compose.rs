//! Software composition: occlusion tests and painting damaged output rects bottom to top.
//!
//! Everything here is pure over its inputs so it is host-tested without a scene. Occlusion
//! is deliberately cheap: a rect is occluded only when a single opaque rect of one surface above
//! contains it entirely (an `Xrgb8888` buffer is opaque over its whole extent; an
//! `Argb8888Premultiplied` buffer is opaque only inside its committed opaque region).

use clean_slate_graphics::geometry::{Rect, RectSet};
use clean_slate_graphics::limits::MAX_REGION_RECTS;
use clean_slate_graphics::pixel::{BufferLayout, PixelFormat};
use clean_slate_raster::{BlitMode, Canvas, Color};

use crate::backend::{BufferMapping, SharedBufferMapper};

/// Where a surface is opaque, in global coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpaqueCover {
    /// Opaque over the whole surface rect.
    Full,
    /// Opaque only inside these rects (already translated and clipped to the surface rect).
    Rects(RectSet<MAX_REGION_RECTS>),
    None,
}

impl OpaqueCover {
    /// Cover for a surface at global `rect` with buffer `format` and surface-local opaque rects.
    pub fn for_surface(rect: Rect, format: PixelFormat, local_opaque: &[Rect]) -> Self {
        if format == PixelFormat::Xrgb8888 {
            return Self::Full;
        }
        let mut set = RectSet::new();
        for r in local_opaque {
            let translated = Rect {
                x: rect.x.saturating_add(r.x),
                y: rect.y.saturating_add(r.y),
                width: r.width,
                height: r.height,
            };
            if let Ok(Some(clipped)) = translated.intersect(rect) {
                let _ = set.insert(clipped);
            }
        }
        if set.is_empty() {
            Self::None
        } else if set.rects().len() == 1 && set.rects()[0] == rect {
            Self::Full
        } else {
            Self::Rects(set)
        }
    }
}

/// A visible surface's global rect and opacity, ordered bottom to top by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Footprint {
    pub rect: Rect,
    pub cover: OpaqueCover,
}

/// `true` iff `outer` contains `inner` (empty `inner` is contained everywhere).
pub fn contains(outer: Rect, inner: Rect) -> bool {
    if inner.is_empty() {
        return true;
    }
    let (ox0, oy0) = (i64::from(outer.x), i64::from(outer.y));
    let (ox1, oy1) = (ox0 + i64::from(outer.width), oy0 + i64::from(outer.height));
    let (ix0, iy0) = (i64::from(inner.x), i64::from(inner.y));
    let (ix1, iy1) = (ix0 + i64::from(inner.width), iy0 + i64::from(inner.height));
    ix0 >= ox0 && iy0 >= oy0 && ix1 <= ox1 && iy1 <= oy1
}

impl Footprint {
    /// `true` iff this surface alone paints every pixel of `rect` opaquely.
    pub fn covers(&self, rect: Rect) -> bool {
        match &self.cover {
            OpaqueCover::Full => contains(self.rect, rect),
            OpaqueCover::Rects(set) => set.rects().iter().any(|r| contains(*r, rect)),
            OpaqueCover::None => false,
        }
    }
}

/// `true` iff some footprint in `above` covers `rect`.
pub fn occluded(rect: Rect, above: &[Footprint]) -> bool {
    above.iter().any(|f| f.covers(rect))
}

/// Pixels staged per [`SharedBufferMapper::read`]; client rows are copied in chunks this wide.
const STAGE_PIXELS: usize = 1024;
const STAGE_BYTES: usize = STAGE_PIXELS * 4;

/// One surface to paint: footprint plus the read-only mapping of its current buffer.
#[derive(Clone, Copy, Debug)]
pub struct Visual {
    pub footprint: Footprint,
    pub layout: BufferLayout,
    pub mapping: BufferMapping,
}

/// Paints every rect of `damage` into `dst` from `visuals` (bottom to top) over `background`.
///
/// Per rect, painting starts at the topmost visual that covers it; everything below is skipped
/// (occlusion rejection), and the background is filled only when no visual covers the rect.
/// Client pixels are copied out of `buffers` a row span at a time, never borrowed. Returns how
/// many surface blits were performed, for tests and diagnostics.
pub fn paint(
    dst: &mut Canvas<'_>,
    damage: &[Rect],
    visuals: &[Visual],
    buffers: &dyn SharedBufferMapper,
    background: Color,
) -> usize {
    let mut blits = 0;
    for &rect in damage {
        let start = visuals
            .iter()
            .rposition(|v| v.footprint.covers(rect))
            .unwrap_or(0);
        let mut clipped = dst.with_clip(rect);
        if !visuals.get(start).is_some_and(|v| v.footprint.covers(rect)) {
            clipped.fill_rect(rect, background);
        }
        for visual in &visuals[start.min(visuals.len())..] {
            let Ok(Some(part)) = visual.footprint.rect.intersect(rect) else {
                continue;
            };
            let src_rect = Rect {
                x: part.x - visual.footprint.rect.x,
                y: part.y - visual.footprint.rect.y,
                width: part.width,
                height: part.height,
            };
            if blit_staged(&mut clipped, visual, src_rect, buffers) {
                blits += 1;
            }
        }
    }
    blits
}

/// Blits `src_rect` (surface-local) of `visual` row span by row span through a stack stage.
/// `false` when the layout does not fit the attested length or a read fails.
fn blit_staged(
    dst: &mut Canvas<'_>,
    visual: &Visual,
    src_rect: Rect,
    buffers: &dyn SharedBufferMapper,
) -> bool {
    let layout = visual.layout;
    if !layout.fits_in(visual.mapping.byte_len) {
        return false;
    }
    let mode = match layout.format() {
        PixelFormat::Xrgb8888 => BlitMode::Copy,
        PixelFormat::Argb8888Premultiplied => BlitMode::Over,
    };
    let span = |start: i32, len: u32, limit: u32| {
        let start = i64::from(start);
        let lo = start.clamp(0, i64::from(limit));
        let hi = (start + i64::from(len)).clamp(0, i64::from(limit));
        (lo as u32, hi as u32)
    };
    let (x0, x1) = span(src_rect.x, src_rect.width, layout.width());
    let (y0, y1) = span(src_rect.y, src_rect.height, layout.height());
    let origin = visual.footprint.rect;
    let mut stage = [0u8; STAGE_BYTES];
    for y in y0..y1 {
        let mut x = x0;
        while x < x1 {
            let width = (x1 - x).min(STAGE_PIXELS as u32);
            let bytes = &mut stage[..width as usize * 4];
            let offset = u64::from(y) * u64::from(layout.stride_bytes()) + u64::from(x) * 4;
            if !buffers.read(&visual.mapping, offset, bytes) {
                return false;
            }
            let at = |base: i32, local: u32| i32::try_from(i64::from(base) + i64::from(local));
            let (Ok(dx), Ok(dy), Ok(row)) = (
                at(origin.x, x),
                at(origin.y, y),
                BufferLayout::new(width, 1, width * 4, layout.format()),
            ) else {
                return true;
            };
            let whole_row = Rect {
                x: 0,
                y: 0,
                width,
                height: 1,
            };
            if dst.blit(bytes, row, whole_row, (dx, dy), mode).is_err() {
                return false;
            }
            x += width;
        }
    }
    true
}
