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

impl Rect {
    pub fn is_empty(self) -> bool {
        self.width == 0 || self.height == 0
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

    pub fn intersect(self, other: Rect) -> Option<Rect> {
        let left = self.x.max(other.x);
        let top = self.y.max(other.y);
        let right = self.checked_right().ok()?.min(other.checked_right().ok()?);
        let bottom = self
            .checked_bottom()
            .ok()?
            .min(other.checked_bottom().ok()?);
        let width = right.checked_sub(left);
        let height = bottom.checked_sub(top);
        match (width, height) {
            (Some(w), Some(h)) if w > 0 && h > 0 => Some(Rect {
                x: left,
                y: top,
                width: u32::try_from(w).ok()?,
                height: u32::try_from(h).ok()?,
            }),
            _ => None,
        }
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

    pub fn clip_to(self, bounds: Size) -> Option<Rect> {
        if self.is_empty() {
            return None;
        }
        let clip = Rect {
            x: 0,
            y: 0,
            width: bounds.width,
            height: bounds.height,
        };
        if i32::try_from(bounds.width).is_err() || i32::try_from(bounds.height).is_err() {
            return None;
        }
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

    pub fn len(self) -> usize {
        self.len
    }

    pub fn is_empty(self) -> bool {
        self.len == 0
    }

    pub fn is_collapsed(self) -> bool {
        self.collapsed
    }

    pub fn rects(&self) -> &[Rect] {
        &self.rects[..self.len]
    }

    pub fn insert(&mut self, rect: Rect) -> Result<(), GeometryError> {
        if rect.is_empty() {
            return Ok(());
        }
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
        self.rects[0] = acc;
        self.len = 1;
        self.collapsed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn intersect_commutative_and_empty() {
        let a = rect(0, 0, 10, 10);
        let b = rect(5, 5, 10, 10);
        assert_eq!(a.intersect(b), b.intersect(a));
        assert_eq!(a.intersect(b), Some(rect(5, 5, 5, 5)));
        assert_eq!(a.intersect(rect(20, 0, 5, 5)), None);
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
            Some(inside)
        );
        assert_eq!(
            rect(8, 8, 5, 5).clip_to(Size {
                width: 10,
                height: 10
            }),
            Some(rect(8, 8, 2, 2))
        );
        assert_eq!(
            rect(10, 0, 1, 1).clip_to(Size {
                width: 10,
                height: 10
            }),
            None
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
}
