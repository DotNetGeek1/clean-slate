//! Software composition: occlusion tests and painting damaged output rects bottom to top.
//!
//! Everything here is pure over borrowed inputs so it is host-tested without a scene. Occlusion
//! is deliberately cheap: a rect is occluded only when a single opaque rect of one surface above
//! contains it entirely (an `Xrgb8888` buffer is opaque over its whole extent; an
//! `Argb8888Premultiplied` buffer is opaque only inside its committed opaque region).

use clean_slate_graphics::geometry::{Rect, RectSet};
use clean_slate_graphics::limits::MAX_REGION_RECTS;
use clean_slate_graphics::pixel::{BufferLayout, PixelFormat};
use clean_slate_raster::{BlitMode, Canvas, Color};

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

/// One surface to paint: footprint plus the read-only bytes of its current buffer.
#[derive(Clone, Copy, Debug)]
pub struct Visual<'a> {
    pub footprint: Footprint,
    pub layout: BufferLayout,
    pub bytes: &'a [u8],
}

/// Paints every rect of `damage` into `dst` from `visuals` (bottom to top) over `background`.
///
/// Per rect, painting starts at the topmost visual that covers it; everything below is skipped
/// (occlusion rejection), and the background is filled only when no visual covers the rect.
/// Returns how many surface blits were performed, for tests and diagnostics.
pub fn paint(
    dst: &mut Canvas<'_>,
    damage: &[Rect],
    visuals: &[Visual<'_>],
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
            let mode = match visual.layout.format() {
                PixelFormat::Xrgb8888 => BlitMode::Copy,
                PixelFormat::Argb8888Premultiplied => BlitMode::Over,
            };
            if clipped
                .blit(
                    visual.bytes,
                    visual.layout,
                    src_rect,
                    (part.x, part.y),
                    mode,
                )
                .is_ok()
            {
                blits += 1;
            }
        }
    }
    blits
}
