//! Hosting primitives in a compositor surface: paint into a client-owned buffer, accumulate
//! damage, and hand it to the protocol as `Damage` batches. No compositor API is assumed
//! beyond the frozen #110 types (`BufferLayout`, `BufferRect`, `DAMAGE_RECTS_PER_FRAME`).

use clean_slate_graphics::limits::{MAX_DAMAGE_RECTS_PER_COMMIT, MAX_SURFACE_EXTENT};
use clean_slate_graphics::protocol::request::DAMAGE_RECTS_PER_FRAME;
use clean_slate_graphics::surface::DamageSet;
use clean_slate_graphics::{BufferLayout, BufferRect, Rect, Size};
use clean_slate_raster::Canvas;

/// Surface-local damage in buffer pixels (scale 1.0), bounded like a commit's damage set:
/// overflowing 16 rects collapses to the bounding box.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Damage {
    set: DamageSet,
}

impl Damage {
    /// No damage.
    pub const fn new() -> Self {
        Self {
            set: DamageSet::new(),
        }
    }

    /// Damage covering a whole `layout`.
    pub fn full(layout: BufferLayout) -> Self {
        let mut d = Self::new();
        d.add(layout_rect(layout));
        d
    }

    /// Adds `r` clipped to `[0, MAX_SURFACE_EXTENT)²`; empty rects are ignored.
    pub fn add(&mut self, r: Rect) {
        let extent = Size {
            width: MAX_SURFACE_EXTENT,
            height: MAX_SURFACE_EXTENT,
        };
        if let Ok(Some(clipped)) = r.clip_to(extent) {
            // A clipped rect always validates, so insertion cannot fail.
            let _ = self.set.insert(clipped);
        }
    }

    /// Adds every rect of `other`.
    pub fn merge(&mut self, other: &Damage) {
        for r in other.rects() {
            self.add(*r);
        }
    }

    /// Accumulated rects.
    pub fn rects(&self) -> &[Rect] {
        self.set.rects()
    }

    /// True when nothing is damaged.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Sum of rect areas (an upper bound on repainted pixels).
    pub fn area(&self) -> u64 {
        self.rects()
            .iter()
            .map(|r| u64::from(r.width) * u64::from(r.height))
            .sum()
    }

    /// Rects clipped to `layout` as protocol buffer rects, in `Damage` request batches of at
    /// most [`DAMAGE_RECTS_PER_FRAME`].
    pub fn batches(&self, layout: BufferLayout) -> DamageBatches {
        let mut rects = [ZERO; MAX_DAMAGE_RECTS_PER_COMMIT];
        let mut len = 0;
        for r in self.rects() {
            let clipped = r.clip_to(Size {
                width: layout.width(),
                height: layout.height(),
            });
            if let Ok(Some(c)) = clipped {
                if let Some(b) = to_buffer_rect(c) {
                    rects[len] = b;
                    len += 1;
                }
            }
        }
        DamageBatches { rects, len, pos: 0 }
    }
}

const ZERO: BufferRect = BufferRect {
    x: 0,
    y: 0,
    width: 0,
    height: 0,
};

fn to_buffer_rect(r: Rect) -> Option<BufferRect> {
    Some(BufferRect {
        x: u16::try_from(r.x).ok()?,
        y: u16::try_from(r.y).ok()?,
        width: u16::try_from(r.width).ok()?,
        height: u16::try_from(r.height).ok()?,
    })
}

/// One `Damage` request body: rects and count.
pub type DamageBatch = ([BufferRect; DAMAGE_RECTS_PER_FRAME], u8);

/// Iterator over [`DamageBatch`]es.
#[derive(Clone, Debug)]
pub struct DamageBatches {
    rects: [BufferRect; MAX_DAMAGE_RECTS_PER_COMMIT],
    len: usize,
    pos: usize,
}

impl Iterator for DamageBatches {
    type Item = DamageBatch;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.len {
            return None;
        }
        let n = (self.len - self.pos).min(DAMAGE_RECTS_PER_FRAME);
        let mut out = [ZERO; DAMAGE_RECTS_PER_FRAME];
        out[..n].copy_from_slice(&self.rects[self.pos..self.pos + n]);
        self.pos += n;
        Some((out, n as u8))
    }
}

/// Whole-buffer rect of `layout`.
pub fn layout_rect(layout: BufferLayout) -> Rect {
    Rect {
        x: 0,
        y: 0,
        width: layout.width(),
        height: layout.height(),
    }
}

/// Repaints only `damage`: `paint` runs once per damage rect with the canvas clipped to it.
/// Primitives respect the clip, so pixels outside the damage are never written.
pub fn repaint(canvas: &mut Canvas<'_>, damage: &Damage, mut paint: impl FnMut(&mut Canvas<'_>)) {
    for r in damage.rects() {
        let mut clipped = canvas.with_clip(*r);
        paint(&mut clipped);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_graphics::PixelFormat;

    fn rect(x: i32, y: i32, width: u32, height: u32) -> Rect {
        Rect {
            x,
            y,
            width,
            height,
        }
    }

    #[test]
    fn batches_respect_the_per_request_limit_and_clip_to_the_buffer() {
        let layout = BufferLayout::packed(100, 100, PixelFormat::Xrgb8888).unwrap();
        let mut d = Damage::new();
        for i in 0..7 {
            d.add(rect(i * 10, 0, 5, 5));
        }
        d.add(rect(95, 95, 50, 50));
        d.add(rect(-10, -10, 5, 5));
        let batches: Vec<_> = d.batches(layout).collect();
        assert_eq!(batches.iter().map(|b| b.1).collect::<Vec<_>>(), vec![5, 3]);
        assert_eq!(
            batches[1].0[2],
            BufferRect {
                x: 95,
                y: 95,
                width: 5,
                height: 5
            }
        );
    }

    #[test]
    fn overflow_stays_bounded_and_keeps_covering_every_rect() {
        let mut d = Damage::new();
        for i in 0..40 {
            d.add(rect(i, i, 1, 1));
        }
        assert!(d.rects().len() <= MAX_DAMAGE_RECTS_PER_COMMIT);
        for i in 0..40 {
            let p = clean_slate_graphics::Point { x: i, y: i };
            assert!(d.rects().iter().any(|r| {
                p.x >= r.x
                    && p.y >= r.y
                    && i64::from(p.x) < i64::from(r.x) + i64::from(r.width)
                    && i64::from(p.y) < i64::from(r.y) + i64::from(r.height)
            }));
        }
    }
}
