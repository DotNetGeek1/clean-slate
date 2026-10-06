//! Saturating rectangle arithmetic and allocation-free flow layout for primitives and hosts.

use clean_slate_graphics::{Point, Rect, Size};

/// `base + delta` clamped to `i32`.
pub(crate) fn offset(base: i32, delta: u32) -> i32 {
    (i64::from(base) + i64::from(delta)).clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

/// Edge insets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Insets {
    /// Top edge.
    pub top: u32,
    /// Right edge.
    pub right: u32,
    /// Bottom edge.
    pub bottom: u32,
    /// Left edge.
    pub left: u32,
}

impl Insets {
    /// Same inset on every edge.
    pub const fn uniform(n: u32) -> Self {
        Self {
            top: n,
            right: n,
            bottom: n,
            left: n,
        }
    }

    /// `horizontal` on left/right, `vertical` on top/bottom.
    pub const fn symmetric(horizontal: u32, vertical: u32) -> Self {
        Self {
            top: vertical,
            right: horizontal,
            bottom: vertical,
            left: horizontal,
        }
    }
}

/// Rectangle helpers. Shrinking never underflows: an over-inset rect becomes zero-sized.
pub trait RectExt: Sized {
    /// Shrinks by `insets`.
    fn inset(self, insets: Insets) -> Self;
    /// Shrinks by `n` on every edge.
    fn shrink(self, n: u32) -> Self;
    /// Grows by `n` on every edge.
    fn expand(self, n: u32) -> Self;
    /// Top `height` pixels and the remainder.
    fn split_top(self, height: u32) -> (Self, Self);
    /// Left `width` pixels and the remainder.
    fn split_left(self, width: u32) -> (Self, Self);
    /// Right `width` pixels and the remainder (remainder first).
    fn split_right(self, width: u32) -> (Self, Self);
    /// `size` centred in `self` (clamped to `self`).
    fn centered(self, size: Size) -> Self;
    /// Half-open containment of `p`.
    fn contains(self, p: Point) -> bool;
    /// Exclusive right edge.
    fn right(self) -> i32;
    /// Exclusive bottom edge.
    fn bottom(self) -> i32;
    /// Pixel area.
    fn area(self) -> u64;
}

impl RectExt for Rect {
    fn inset(self, i: Insets) -> Self {
        let width = self.width.saturating_sub(i.left.saturating_add(i.right));
        let height = self.height.saturating_sub(i.top.saturating_add(i.bottom));
        Rect {
            x: offset(self.x, i.left.min(self.width)),
            y: offset(self.y, i.top.min(self.height)),
            width,
            height,
        }
    }

    fn shrink(self, n: u32) -> Self {
        self.inset(Insets::uniform(n))
    }

    fn expand(self, n: u32) -> Self {
        Rect {
            x: self.x.saturating_sub_unsigned(n),
            y: self.y.saturating_sub_unsigned(n),
            width: self.width.saturating_add(n.saturating_mul(2)),
            height: self.height.saturating_add(n.saturating_mul(2)),
        }
    }

    fn split_top(self, height: u32) -> (Self, Self) {
        let h = height.min(self.height);
        (
            Rect { height: h, ..self },
            Rect {
                y: offset(self.y, h),
                height: self.height - h,
                ..self
            },
        )
    }

    fn split_left(self, width: u32) -> (Self, Self) {
        let w = width.min(self.width);
        (
            Rect { width: w, ..self },
            Rect {
                x: offset(self.x, w),
                width: self.width - w,
                ..self
            },
        )
    }

    fn split_right(self, width: u32) -> (Self, Self) {
        let w = width.min(self.width);
        let (rest, right) = self.split_left(self.width - w);
        (rest, right)
    }

    fn centered(self, size: Size) -> Self {
        let width = size.width.min(self.width);
        let height = size.height.min(self.height);
        Rect {
            x: offset(self.x, (self.width - width) / 2),
            y: offset(self.y, (self.height - height) / 2),
            width,
            height,
        }
    }

    fn contains(self, p: Point) -> bool {
        let x = i64::from(p.x);
        let y = i64::from(p.y);
        x >= i64::from(self.x)
            && y >= i64::from(self.y)
            && x < i64::from(self.x) + i64::from(self.width)
            && y < i64::from(self.y) + i64::from(self.height)
    }

    fn right(self) -> i32 {
        offset(self.x, self.width)
    }

    fn bottom(self) -> i32 {
        offset(self.y, self.height)
    }

    fn area(self) -> u64 {
        u64::from(self.width) * u64::from(self.height)
    }
}

/// Flow direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Axis {
    /// Top to bottom.
    Vertical,
    /// Left to right.
    Horizontal,
}

/// Allocation-free sequential layout: each [`Flow::next`] takes a slot along the axis,
/// separated by `gap`, spanning the full cross axis. Exhausted flows yield zero-sized slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flow {
    remaining: Rect,
    gap: u32,
    axis: Axis,
    started: bool,
}

impl Flow {
    /// Vertical flow inside `bounds`.
    pub const fn column(bounds: Rect, gap: u32) -> Self {
        Self {
            remaining: bounds,
            gap,
            axis: Axis::Vertical,
            started: false,
        }
    }

    /// Horizontal flow inside `bounds`.
    pub const fn row(bounds: Rect, gap: u32) -> Self {
        Self {
            remaining: bounds,
            gap,
            axis: Axis::Horizontal,
            started: false,
        }
    }

    /// Next slot of `extent` pixels along the axis (clamped to what is left).
    pub fn next(&mut self, extent: u32) -> Rect {
        if self.started {
            self.skip(self.gap);
        }
        self.started = true;
        let (slot, rest) = match self.axis {
            Axis::Vertical => self.remaining.split_top(extent),
            Axis::Horizontal => self.remaining.split_left(extent),
        };
        self.remaining = rest;
        slot
    }

    /// Advances by `extent` without producing a slot.
    pub fn skip(&mut self, extent: u32) {
        self.remaining = match self.axis {
            Axis::Vertical => self.remaining.split_top(extent).1,
            Axis::Horizontal => self.remaining.split_left(extent).1,
        };
    }

    /// Space not yet consumed.
    pub const fn remaining(&self) -> Rect {
        self.remaining
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(x: i32, y: i32, width: u32, height: u32) -> Rect {
        Rect {
            x,
            y,
            width,
            height,
        }
    }

    #[test]
    fn inset_saturates() {
        assert_eq!(rect(10, 10, 4, 4).shrink(3), rect(13, 13, 0, 0));
        assert_eq!(rect(0, 0, 10, 8).shrink(2), rect(2, 2, 6, 4));
    }

    #[test]
    fn splits_partition_the_rect() {
        let r = rect(5, 5, 100, 50);
        let (a, b) = r.split_left(30);
        assert_eq!((a, b), (rect(5, 5, 30, 50), rect(35, 5, 70, 50)));
        let (rest, right) = r.split_right(20);
        assert_eq!((rest, right), (rect(5, 5, 80, 50), rect(85, 5, 20, 50)));
        let (top, bottom) = r.split_top(80);
        assert_eq!((top, bottom), (r, rect(5, 55, 100, 0)));
    }

    #[test]
    fn contains_is_half_open() {
        let r = rect(0, 0, 10, 10);
        assert!(r.contains(Point { x: 0, y: 0 }));
        assert!(r.contains(Point { x: 9, y: 9 }));
        assert!(!r.contains(Point { x: 10, y: 5 }));
        assert!(!r.contains(Point { x: -1, y: 5 }));
    }

    #[test]
    fn flow_column_places_gapped_slots_and_exhausts() {
        let mut flow = Flow::column(rect(0, 0, 50, 30), 4);
        assert_eq!(flow.next(10), rect(0, 0, 50, 10));
        assert_eq!(flow.next(10), rect(0, 14, 50, 10));
        assert_eq!(flow.next(10), rect(0, 28, 50, 2));
        assert_eq!(flow.next(10).height, 0);
    }
}
