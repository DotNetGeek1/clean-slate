//! Logical and buffer-space geometry with checked arithmetic.

use crate::error::GeometryError;

/// Logical point in global or surface-local space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

/// Non-negative width and height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Size {
    pub width: u32,
    pub height: u32,
}

/// Half-open logical rectangle `[x, x + width) × [y, y + height)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

/// Buffer-pixel damage rectangle; axes are bounded by [`MAX_SURFACE_EXTENT`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferRect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

/// Signed 24.8 fixed-point coordinate (sub-pixel ready).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fixed24_8(pub i32);

/// Display scale in 1/120 units; [`Scale120::ONE`] is 1.0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scale120(pub u16);

impl Scale120 {
    pub const ONE: Self = Self(120);
}

impl BufferRect {
    pub fn to_rect(self) -> Rect {
        Rect {
            x: i32::from(self.x),
            y: i32::from(self.y),
            width: u32::from(self.width),
            height: u32::from(self.height),
        }
    }

    /// Clips to `[0, width) × [0, height)` in buffer space using `u32` arithmetic.
    pub fn clip_to_extent(self, width: u32, height: u32) -> Option<BufferRect> {
        if self.width == 0 || self.height == 0 {
            return None;
        }
        let x0 = u32::from(self.x);
        let y0 = u32::from(self.y);
        let x1 = x0.checked_add(u32::from(self.width))?;
        let y1 = y0.checked_add(u32::from(self.height))?;
        if x0 >= width || y0 >= height {
            return None;
        }
        let clip_x1 = x1.min(width);
        let clip_y1 = y1.min(height);
        let w = clip_x1.checked_sub(x0)?;
        let h = clip_y1.checked_sub(y0)?;
        if w == 0 || h == 0 {
            return None;
        }
        Some(BufferRect {
            x: u16::try_from(x0).ok()?,
            y: u16::try_from(y0).ok()?,
            width: u16::try_from(w).ok()?,
            height: u16::try_from(h).ok()?,
        })
    }
}

impl Rect {
    pub fn is_empty(self) -> bool {
        self.width == 0 || self.height == 0
    }

    pub fn validate(self) -> Result<Rect, GeometryError> {
        if self.width > i32::MAX as u32 || self.height > i32::MAX as u32 {
            return Err(GeometryError::Overflow);
        }
        self.checked_right()?;
        self.checked_bottom()?;
        Ok(self)
    }

    pub fn checked_right(self) -> Result<i32, GeometryError> {
        self.x
            .checked_add(i32::try_from(self.width).map_err(|_| GeometryError::Overflow)?)
            .ok_or(GeometryError::Overflow)
    }

    pub fn checked_bottom(self) -> Result<i32, GeometryError> {
        self.y
            .checked_add(i32::try_from(self.height).map_err(|_| GeometryError::Overflow)?)
            .ok_or(GeometryError::Overflow)
    }

    pub fn intersect(self, other: Rect) -> Result<Option<Rect>, GeometryError> {
        self.validate()?;
        other.validate()?;
        let left = self.x.max(other.x);
        let top = self.y.max(other.y);
        let right = self.checked_right()?.min(other.checked_right()?);
        let bottom = self.checked_bottom()?.min(other.checked_bottom()?);
        let width = match right.checked_sub(left) {
            Some(w) if w > 0 => w,
            _ => return Ok(None),
        };
        let height = match bottom.checked_sub(top) {
            Some(h) if h > 0 => h,
            _ => return Ok(None),
        };
        Ok(Some(Rect {
            x: left,
            y: top,
            width: u32::try_from(width).map_err(|_| GeometryError::Overflow)?,
            height: u32::try_from(height).map_err(|_| GeometryError::Overflow)?,
        }))
    }

    pub fn union_bounds(self, other: Rect) -> Result<Rect, GeometryError> {
        if self.is_empty() {
            return Ok(other);
        }
        if other.is_empty() {
            return Ok(self);
        }
        let left = self.x.min(other.x);
        let top = self.y.min(other.y);
        let right = self.checked_right()?.max(other.checked_right()?);
        let bottom = self.checked_bottom()?.max(other.checked_bottom()?);
        let width = right.checked_sub(left).ok_or(GeometryError::Overflow)?;
        let height = bottom.checked_sub(top).ok_or(GeometryError::Overflow)?;
        if width == 0 || height == 0 {
            return Err(GeometryError::EmptyExtent);
        }
        Ok(Rect {
            x: left,
            y: top,
            width: u32::try_from(width).map_err(|_| GeometryError::Overflow)?,
            height: u32::try_from(height).map_err(|_| GeometryError::Overflow)?,
        })
    }

    pub fn clip_to(self, bounds: Size) -> Result<Option<Rect>, GeometryError> {
        if bounds.width > i32::MAX as u32 || bounds.height > i32::MAX as u32 {
            return Err(GeometryError::Overflow);
        }
        self.validate()?;
        if self.is_empty() {
            return Ok(None);
        }
        let clip = Rect {
            x: 0,
            y: 0,
            width: bounds.width,
            height: bounds.height,
        };
        clip.validate()?;
        self.intersect(clip)
    }
}

/// Fixed-capacity rectangle list; overflow collapses to the bounding box.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RectSet<const N: usize> {
    rects: [Rect; N],
    len: usize,
    collapsed: bool,
}

impl<const N: usize> Default for RectSet<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RectSet<N> {
    pub const fn new() -> Self {
        Self {
            rects: [Rect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            }; N],
            len: 0,
            collapsed: false,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn is_collapsed(&self) -> bool {
        self.collapsed
    }

    pub fn rects(&self) -> &[Rect] {
        &self.rects[..self.len]
    }

    pub fn insert(&mut self, rect: Rect) -> Result<(), GeometryError> {
        if rect.is_empty() {
            return Ok(());
        }
        rect.validate()?;
        if self.len < N {
            self.rects[self.len] = rect;
            self.len += 1;
            return Ok(());
        }
        let mut acc = self.rects[0];
        for i in 1..self.len {
            acc = acc.union_bounds(self.rects[i])?;
        }
        acc = acc.union_bounds(rect)?;
        acc.validate()?;
        self.rects[0] = acc;
        self.len = 1;
        self.collapsed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::MAX_SURFACE_EXTENT;

    fn rect(x: i32, y: i32, w: u32, h: u32) -> Rect {
        Rect {
            x,
            y,
            width: w,
            height: h,
        }
    }

    #[test]
    fn checked_right_bottom_extremes() {
        let r = rect(i32::MAX - 1, i32::MIN, 1, 1);
        assert_eq!(r.checked_right(), Ok(i32::MAX));
        assert_eq!(r.checked_bottom(), Ok(i32::MIN + 1));

        let overflow = rect(i32::MAX, 0, 1, 0);
        assert_eq!(overflow.checked_right(), Err(GeometryError::Overflow));

        let big = rect(0, 0, u32::MAX, 1);
        assert_eq!(big.checked_right(), Err(GeometryError::Overflow));
    }

    #[test]
    fn validate_rejects_non_representable_extent() {
        assert_eq!(
            rect(0, 0, u32::MAX, 1).validate(),
            Err(GeometryError::Overflow)
        );
    }

    #[test]
    fn intersect_commutative_and_empty() {
        let a = rect(0, 0, 10, 10);
        let b = rect(5, 5, 10, 10);
        assert_eq!(a.intersect(b), b.intersect(a));
        assert_eq!(a.intersect(b), Ok(Some(rect(5, 5, 5, 5))));
        assert_eq!(a.intersect(rect(20, 0, 5, 5)), Ok(None));
    }

    #[test]
    fn intersect_err_on_overflowing_operand() {
        let bad = rect(i32::MAX, 0, 1, 1);
        let ok = rect(0, 0, 10, 10);
        assert_eq!(bad.intersect(ok), Err(GeometryError::Overflow));
        assert_eq!(ok.intersect(bad), Err(GeometryError::Overflow));
    }

    #[test]
    fn clip_to_err_on_overflowing_rect_or_bounds() {
        let bad = rect(i32::MAX, 0, 1, 1);
        assert_eq!(
            bad.clip_to(Size {
                width: 10,
                height: 10
            }),
            Err(GeometryError::Overflow)
        );
        assert_eq!(
            rect(0, 0, 1, 1).clip_to(Size {
                width: u32::MAX,
                height: 1
            }),
            Err(GeometryError::Overflow)
        );
    }

    #[test]
    fn union_bounds_empty_operand() {
        let a = rect(1, 2, 3, 4);
        assert_eq!(a.union_bounds(rect(0, 0, 0, 5)), Ok(a));
        assert_eq!(rect(0, 0, 0, 5).union_bounds(a), Ok(a));
    }

    #[test]
    fn union_and_clip() {
        let a = rect(0, 0, 10, 10);
        let b = rect(10, 10, 5, 5);
        let u = a.union_bounds(b).unwrap();
        assert_eq!(u, rect(0, 0, 15, 15));

        let inside = rect(2, 2, 3, 3);
        assert_eq!(
            inside.clip_to(Size {
                width: 10,
                height: 10
            }),
            Ok(Some(inside))
        );
        assert_eq!(
            rect(8, 8, 5, 5).clip_to(Size {
                width: 10,
                height: 10
            }),
            Ok(Some(rect(8, 8, 2, 2)))
        );
        assert_eq!(
            rect(10, 0, 1, 1).clip_to(Size {
                width: 10,
                height: 10
            }),
            Ok(None)
        );
    }

    #[test]
    fn rect_set_overflow_collapses_to_bbox() {
        let mut set = RectSet::<2>::new();
        assert!(set.insert(rect(0, 0, 10, 10)).is_ok());
        assert!(set.insert(rect(20, 0, 5, 5)).is_ok());
        assert!(set.insert(rect(0, 20, 3, 3)).is_ok());
        assert!(set.is_collapsed());
        assert_eq!(set.len(), 1);
        assert_eq!(set.rects()[0], rect(0, 0, 25, 23));
    }

    #[test]
    fn rect_set_drops_zero_area() {
        let mut set = RectSet::<4>::new();
        assert!(set.insert(rect(0, 0, 0, 5)).is_ok());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn rect_set_unchanged_on_validate_failure() {
        let mut set = RectSet::<2>::new();
        assert!(set.insert(rect(0, 0, 10, 10)).is_ok());
        let before = set;
        assert_eq!(
            set.insert(rect(i32::MAX, 0, 1, 1)),
            Err(GeometryError::Overflow)
        );
        assert_eq!(set, before);

        let mut full = RectSet::<2>::new();
        assert!(full.insert(rect(0, 0, 10, 10)).is_ok());
        assert!(full.insert(rect(20, 0, 5, 5)).is_ok());
        let before_full = full;
        assert_eq!(
            full.insert(rect(i32::MAX, 0, 1, 1)),
            Err(GeometryError::Overflow)
        );
        assert_eq!(full, before_full);
    }

    #[test]
    fn buffer_rect_clip_at_u16_max_and_extent() {
        let edge = BufferRect {
            x: u16::MAX,
            y: 0,
            width: 1,
            height: 1,
        };
        assert!(edge.clip_to_extent(u32::from(u16::MAX) + 1, 1).is_some());
        assert!(edge.clip_to_extent(u32::from(u16::MAX), 1).is_none());

        let partial = BufferRect {
            x: 100,
            y: 100,
            width: 500,
            height: 500,
        };
        let clipped = partial
            .clip_to_extent(MAX_SURFACE_EXTENT, MAX_SURFACE_EXTENT)
            .unwrap();
        assert_eq!(clipped.x, 100);
        assert_eq!(clipped.width, 500);
        assert!(partial
            .clip_to_extent(200, 200)
            .is_some_and(|r| r.width == 100 && r.height == 100));
    }

    #[test]
    fn buffer_rect_to_rect_round_trip_fields() {
        let br = BufferRect {
            x: 1,
            y: 2,
            width: 3,
            height: 4,
        };
        let r = br.to_rect();
        assert_eq!(r.x, 1);
        assert_eq!(r.width, 3);
    }
}
