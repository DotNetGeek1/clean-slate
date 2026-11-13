//! Native window chrome look and metrics.
//!
//! The window manager (#115, `compositor::wm`) owns decoration *behaviour*: hit testing,
//! move/resize, focus and stacking. It consumes this module only through [`ChromeStyle`],
//! which supplies geometry derived from [`ChromeMetrics`] and paints the frame. Nothing here
//! decides what a click does.

use clean_slate_graphics::{Point, Rect};
use clean_slate_raster::Canvas;

use crate::layout::{offset, Insets, RectExt};
use crate::paint::{blend, fill, fill_rounded, stroke_rounded, Corners};
use crate::quality::Style;
use crate::text;
use crate::tokens::{ChromeMetrics, Rgba, ShadowToken};

/// Window control buttons, right to left order is Close, Maximize, Minimize.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChromeControl {
    /// Minimise.
    Minimize,
    /// Maximise or restore.
    Maximize,
    /// Close.
    Close,
}

impl ChromeControl {
    /// Left-to-right order in the title bar.
    pub const ALL: [Self; 3] = [Self::Minimize, Self::Maximize, Self::Close];

    const fn slot_from_right(self) -> u32 {
        match self {
            Self::Close => 0,
            Self::Maximize => 1,
            Self::Minimize => 2,
        }
    }
}

/// Visual state of one window frame, supplied by the window manager.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChromeState {
    /// The window has keyboard focus (`WindowStates::ACTIVATED`).
    pub focused: bool,
    /// Control under the pointer.
    pub hovered: Option<ChromeControl>,
    /// Control held by the pointer.
    pub pressed: Option<ChromeControl>,
    /// Maximised (the maximise glyph shows "restore").
    pub maximized: bool,
}

/// The narrow chrome boundary between the theme and the window manager.
pub trait ChromeStyle {
    /// Metrics the frame geometry derives from.
    fn metrics(&self) -> ChromeMetrics;

    /// Frame rect around a client surface placed at `content`.
    fn frame_rect(&self, content: Rect) -> Rect {
        let m = self.metrics();
        Rect {
            x: content.x.saturating_sub_unsigned(m.border_width),
            y: content
                .y
                .saturating_sub_unsigned(m.border_width + m.title_bar_height),
            width: content.width.saturating_add(2 * m.border_width),
            height: content
                .height
                .saturating_add(2 * m.border_width + m.title_bar_height),
        }
    }

    /// Client surface rect inside `frame` (inverse of [`Self::frame_rect`]).
    fn content_rect(&self, frame: Rect) -> Rect {
        let m = self.metrics();
        frame.inset(Insets {
            top: m.border_width + m.title_bar_height,
            right: m.border_width,
            bottom: m.border_width,
            left: m.border_width,
        })
    }

    /// Title bar inside the border (move-grab area minus the controls).
    fn title_bar_rect(&self, frame: Rect) -> Rect {
        let m = self.metrics();
        frame
            .inset(Insets {
                top: m.border_width,
                right: m.border_width,
                bottom: 0,
                left: m.border_width,
            })
            .split_top(m.title_bar_height)
            .0
    }

    /// Rect of one window control inside the title bar.
    fn control_rect(&self, frame: Rect, control: ChromeControl) -> Rect {
        let m = self.metrics();
        let bar = self.title_bar_rect(frame);
        let step = m.control_size + m.control_gap;
        let from_right = m.control_inset + m.control_size + control.slot_from_right() * step;
        Rect {
            x: i32::try_from(i64::from(bar.right()) - i64::from(from_right)).unwrap_or(bar.x),
            y: offset(bar.y, bar.height.saturating_sub(m.control_size) / 2),
            width: m.control_size,
            height: m.control_size,
        }
    }

    /// Outer resize grab rect: `frame` grown by the resize margin.
    fn resize_rect(&self, frame: Rect) -> Rect {
        frame.expand(self.metrics().resize_margin)
    }

    /// Everything [`Self::paint_frame`] may touch (frame plus shadow); damage on map, unmap,
    /// move and focus change.
    fn visual_rect(&self, frame: Rect) -> Rect;

    /// Paints border, title bar, title and controls. The content area is left untouched for
    /// the client surface.
    fn paint_frame(&self, canvas: &mut Canvas<'_>, frame: Rect, title: &str, state: ChromeState);
}

/// Clean-Slate chrome: monochrome, left-aligned title, square controls, top-rounded frame and
/// a cyan underline plus tinted border on the focused window.
#[derive(Clone, Copy)]
pub struct CleanSlateChrome<'t> {
    /// Theme and effects.
    pub style: Style<'t>,
}

impl<'t> CleanSlateChrome<'t> {
    /// Chrome for `style`.
    pub const fn new(style: Style<'t>) -> Self {
        Self { style }
    }

    fn shadow(&self, focused: bool) -> ShadowToken {
        let e = &self.style.theme.elevation;
        if focused {
            e.window_focused
        } else {
            e.window_inactive
        }
    }

    /// One-pixel rings around the frame (shifted down), fading outwards; nothing is blended
    /// under the frame itself, so the cost is proportional to the perimeter.
    fn paint_shadow(&self, canvas: &mut Canvas<'_>, frame: Rect, focused: bool) {
        let token = self.shadow(focused);
        let shadow = self.style.theme.palette.shadow;
        let base = Rect {
            y: offset(frame.y, token.offset_y),
            ..frame
        };
        blend(
            canvas,
            Rect {
                y: frame.bottom(),
                height: token.offset_y,
                ..base
            },
            shadow,
        );
        for layer in 1..=token.layers {
            let alpha = u32::from(shadow.a) * (token.layers + 1 - layer) / (token.layers + 1);
            let color = shadow.with_alpha(alpha as u8);
            let outer = base.expand(layer);
            let sides = outer.height.saturating_sub(2);
            for strip in [
                Rect { height: 1, ..outer },
                Rect {
                    y: outer.bottom() - 1,
                    height: 1,
                    ..outer
                },
                Rect {
                    y: offset(outer.y, 1),
                    width: 1,
                    height: sides,
                    ..outer
                },
                Rect {
                    x: outer.right() - 1,
                    y: offset(outer.y, 1),
                    width: 1,
                    height: sides,
                },
            ] {
                blend(canvas, strip, color);
            }
        }
    }

    fn paint_control(
        &self,
        canvas: &mut Canvas<'_>,
        rect: Rect,
        control: ChromeControl,
        state: ChromeState,
    ) {
        let t = self.style.theme;
        let p = &t.palette;
        let bg = if state.pressed == Some(control) {
            Some(p.chrome_control_pressed)
        } else if state.hovered == Some(control) {
            Some(p.chrome_control_hover)
        } else {
            None
        };
        if let Some(bg) = bg {
            fill_rounded(canvas, rect, t.radius.sm, Corners::ALL, bg);
        }
        let fg = if bg.is_some() {
            p.chrome_active_title
        } else if state.focused {
            p.chrome_control_active
        } else {
            p.chrome_control_inactive
        };
        let glyph = rect.centered(clean_slate_graphics::Size {
            width: 10,
            height: 10,
        });
        paint_control_glyph(canvas, glyph, control, state.maximized, fg);
    }
}

fn paint_control_glyph(
    canvas: &mut Canvas<'_>,
    g: Rect,
    control: ChromeControl,
    maximized: bool,
    color: Rgba,
) {
    let c = color.premultiplied();
    let x1 = offset(g.x, g.width - 1);
    let y1 = offset(g.y, g.height - 1);
    match control {
        ChromeControl::Minimize => {
            fill(
                canvas,
                Rect {
                    x: g.x,
                    y: offset(g.y, g.height / 2),
                    width: g.width,
                    height: 1,
                },
                color,
            );
        }
        ChromeControl::Maximize if maximized => {
            let back = Rect {
                x: offset(g.x, 2),
                y: g.y,
                width: g.width - 2,
                height: g.height - 2,
            };
            let front = Rect {
                x: g.x,
                y: offset(g.y, 2),
                width: g.width - 2,
                height: g.height - 2,
            };
            canvas.hline(back.x, back.right() - 1, back.y, c);
            canvas.vline(back.right() - 1, back.y, back.bottom() - 1, c);
            canvas.stroke_rect(front, 1, c);
        }
        ChromeControl::Maximize => canvas.stroke_rect(g, 1, c),
        ChromeControl::Close => {
            canvas.line((g.x, g.y), (x1, y1), c);
            canvas.line((g.x, y1), (x1, g.y), c);
        }
    }
}

impl ChromeStyle for CleanSlateChrome<'_> {
    fn metrics(&self) -> ChromeMetrics {
        self.style.theme.chrome
    }

    fn visual_rect(&self, frame: Rect) -> Rect {
        if !self.style.effects.shadows {
            return frame;
        }
        let token = self.style.theme.elevation.window_focused;
        let grown = frame.expand(token.layers);
        Rect {
            height: grown.height.saturating_add(token.offset_y),
            ..grown
        }
    }

    fn paint_frame(&self, canvas: &mut Canvas<'_>, frame: Rect, title: &str, state: ChromeState) {
        let t = self.style.theme;
        let p = &t.palette;
        let m = t.chrome;
        if frame.width <= 2 * m.border_width || frame.height <= 2 * m.border_width {
            return;
        }
        if self.style.effects.shadows {
            self.paint_shadow(canvas, frame, state.focused);
        }
        let (bar_color, border_color, title_color) = if state.focused {
            (
                p.chrome_active_bar,
                p.chrome_active_border,
                p.chrome_active_title,
            )
        } else {
            (
                p.chrome_inactive_bar,
                p.chrome_inactive_border,
                p.chrome_inactive_title,
            )
        };
        let bar = self.title_bar_rect(frame);
        fill_rounded(
            canvas,
            bar,
            m.corner_radius.saturating_sub(m.border_width),
            Corners::TOP,
            bar_color,
        );
        let underline = Rect {
            y: offset(bar.y, bar.height.saturating_sub(1)),
            height: 1,
            ..bar
        };
        fill(
            canvas,
            underline,
            if state.focused {
                p.chrome_accent
            } else {
                p.border_subtle
            },
        );
        stroke_rounded(
            canvas,
            frame,
            m.corner_radius,
            Corners::TOP,
            m.border_width,
            border_color,
        );

        let leftmost = self.control_rect(frame, ChromeControl::Minimize);
        let title_style = if state.focused {
            t.type_scale.heading
        } else {
            t.type_scale.body
        };
        let lh = text::measure(t, title_style, title).height;
        let title_x = offset(bar.x, m.title_padding);
        let max_w =
            u32::try_from(i64::from(leftmost.x) - i64::from(title_x) - i64::from(t.spacing.sm))
                .unwrap_or(0);
        let mut clipped = canvas.with_clip(bar);
        text::draw_fitted(
            &mut clipped,
            t,
            Point {
                x: title_x,
                y: offset(bar.y, bar.height.saturating_sub(lh) / 2),
            },
            title,
            title_style,
            title_color,
            max_w,
        );
        for control in ChromeControl::ALL {
            let rect = self.control_rect(frame, control);
            self.paint_control(&mut clipped, rect, control, state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quality::QualityTier;
    use crate::tokens::CLEAN_SLATE_DARK;

    #[test]
    fn frame_and_content_rects_are_inverse() {
        let chrome = CleanSlateChrome::new(Style::new(&CLEAN_SLATE_DARK, QualityTier::Q0));
        let content = Rect {
            x: 300,
            y: 200,
            width: 480,
            height: 320,
        };
        let frame = chrome.frame_rect(content);
        assert_eq!(chrome.content_rect(frame), content);
        assert_eq!(frame.y, 200 - 33);
        assert_eq!(chrome.title_bar_rect(frame).height, 32);
    }

    #[test]
    fn controls_sit_inside_the_title_bar_without_overlap() {
        let chrome = CleanSlateChrome::new(Style::new(&CLEAN_SLATE_DARK, QualityTier::Q0));
        let frame = Rect {
            x: 0,
            y: 0,
            width: 400,
            height: 300,
        };
        let bar = chrome.title_bar_rect(frame);
        let rects = ChromeControl::ALL.map(|c| chrome.control_rect(frame, c));
        for r in rects {
            assert!(r.x >= bar.x && r.right() <= bar.right());
            assert!(r.y >= bar.y && r.bottom() <= bar.bottom());
        }
        assert!(rects[0].right() <= rects[1].x && rects[1].right() <= rects[2].x);
        assert_eq!(rects[2].right(), bar.right() - 6);
    }

    #[test]
    fn visual_rect_grows_only_with_shadows() {
        let frame = Rect {
            x: 100,
            y: 100,
            width: 200,
            height: 100,
        };
        let q0 = CleanSlateChrome::new(Style::new(&CLEAN_SLATE_DARK, QualityTier::Q0));
        let q1 = CleanSlateChrome::new(Style::new(&CLEAN_SLATE_DARK, QualityTier::Q1));
        assert_eq!(q0.visual_rect(frame), frame);
        let v = q1.visual_rect(frame);
        assert!(v.x < frame.x && v.bottom() > frame.bottom());
    }
}
