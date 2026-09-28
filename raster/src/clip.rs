//! Half-open rectangle intersection without panicking on extreme coordinates.

use clean_slate_graphics::{BufferLayout, Rect};

pub(crate) fn empty_rect() -> Rect {
    Rect {
        x: 0,
        y: 0,
        width: 0,
        height: 0,
    }
}

pub(crate) fn layout_bounds(layout: BufferLayout) -> Rect {
    Rect {
        x: 0,
        y: 0,
        width: layout.width(),
        height: layout.height(),
    }
}

pub(crate) fn intersect_rect(a: Rect, b: Rect) -> Rect {
    if a.width == 0 || a.height == 0 || b.width == 0 || b.height == 0 {
        return empty_rect();
    }
    let ax0 = i64::from(a.x);
    let ay0 = i64::from(a.y);
    let ax1 = ax0 + i64::from(a.width);
    let ay1 = ay0 + i64::from(a.height);
    let bx0 = i64::from(b.x);
    let by0 = i64::from(b.y);
    let bx1 = bx0 + i64::from(b.width);
    let by1 = by0 + i64::from(b.height);
    let x0 = ax0.max(bx0);
    let y0 = ay0.max(by0);
    let x1 = ax1.min(bx1);
    let y1 = ay1.min(by1);
    if x1 <= x0 || y1 <= y0 {
        return empty_rect();
    }
    let width = (x1 - x0) as u32;
    let height = (y1 - y0) as u32;
    Rect {
        x: x0 as i32,
        y: y0 as i32,
        width,
        height,
    }
}

pub(crate) fn draw_rect(clip: Rect, target: Rect, layout: BufferLayout) -> Rect {
    intersect_rect(intersect_rect(clip, target), layout_bounds(layout))
}
