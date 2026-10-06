//! Reusable primitives for the shell and native apps (#117).
//!
//! Every widget is plain data plus `measure` and `paint`. A widget paints only inside the
//! `bounds` it is given (its focus ring included), so the caller's damage rect for a state
//! change is exactly those bounds. Application state (toggled, selected) lives with the
//! caller; [`WidgetState`] carries only interaction state.

use clean_slate_graphics::{Point, Rect, Size};
use clean_slate_raster::Canvas;

use crate::icon::{paint_icon, Icon, ICON_SIZE};
use crate::layout::{offset, Insets, RectExt};
use crate::paint::{fill, fill_rounded, stroke_rounded, Corners};
use crate::quality::Style;
use crate::text;
use crate::tokens::{Rgba, TextRole, TextStyle, TextTone};

/// Interaction state of one widget.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WidgetState {
    /// Pointer is over the widget.
    pub hovered: bool,
    /// Pointer button is held on the widget.
    pub pressed: bool,
    /// Widget has keyboard focus.
    pub focused: bool,
    /// Widget ignores input.
    pub disabled: bool,
}

/// The fill state a widget renders, after precedence: disabled > pressed > hovered > rest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interaction {
    /// No pointer interaction.
    Rest,
    /// Pointer over.
    Hover,
    /// Pointer held.
    Pressed,
    /// Input ignored.
    Disabled,
}

impl WidgetState {
    /// At rest.
    pub const REST: Self = Self {
        hovered: false,
        pressed: false,
        focused: false,
        disabled: false,
    };
    /// Pointer over.
    pub const HOVERED: Self = Self {
        hovered: true,
        ..Self::REST
    };
    /// Pointer held.
    pub const PRESSED: Self = Self {
        hovered: true,
        pressed: true,
        ..Self::REST
    };
    /// Keyboard focus.
    pub const FOCUSED: Self = Self {
        focused: true,
        ..Self::REST
    };
    /// Disabled.
    pub const DISABLED: Self = Self {
        disabled: true,
        ..Self::REST
    };

    /// Effective fill state.
    pub const fn interaction(self) -> Interaction {
        if self.disabled {
            Interaction::Disabled
        } else if self.pressed {
            Interaction::Pressed
        } else if self.hovered {
            Interaction::Hover
        } else {
            Interaction::Rest
        }
    }

    /// True when a focus ring is drawn (focused and enabled).
    pub const fn shows_focus(self) -> bool {
        self.focused && !self.disabled
    }
}

/// Hit test for pointer routing: `p` inside `bounds`.
pub fn hit(bounds: Rect, p: Point) -> bool {
    bounds.contains(p)
}

/// Focus ring at the edge of `bounds` with a dark inner hairline, so it stays visible on
/// accent-filled widgets too.
fn focus_ring(canvas: &mut Canvas<'_>, style: Style<'_>, bounds: Rect, radius: u32) {
    let t = style.theme;
    let w = t.stroke.focus;
    stroke_rounded(
        canvas,
        bounds,
        radius,
        Corners::ALL,
        w,
        t.palette.focus_ring,
    );
    stroke_rounded(
        canvas,
        bounds.shrink(w),
        radius.saturating_sub(w),
        Corners::ALL,
        t.stroke.hairline,
        t.palette.background,
    );
}

/// Heading, body or caption text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Text<'a> {
    /// Content.
    pub text: &'a str,
    /// Type-scale role.
    pub role: TextRole,
    /// Colour override; `None` uses the role's tone.
    pub tone: Option<TextTone>,
}

impl<'a> Text<'a> {
    /// Text in `role`.
    pub const fn new(text: &'a str, role: TextRole) -> Self {
        Self {
            text,
            role,
            tone: None,
        }
    }
    /// [`TextRole::Display`].
    pub const fn display(text: &'a str) -> Self {
        Self::new(text, TextRole::Display)
    }
    /// [`TextRole::Title`].
    pub const fn title(text: &'a str) -> Self {
        Self::new(text, TextRole::Title)
    }
    /// [`TextRole::Heading`].
    pub const fn heading(text: &'a str) -> Self {
        Self::new(text, TextRole::Heading)
    }
    /// [`TextRole::Body`].
    pub const fn body(text: &'a str) -> Self {
        Self::new(text, TextRole::Body)
    }
    /// [`TextRole::Caption`].
    pub const fn caption(text: &'a str) -> Self {
        Self::new(text, TextRole::Caption)
    }
    /// Same text with a colour override.
    pub const fn with_tone(self, tone: TextTone) -> Self {
        Self {
            tone: Some(tone),
            ..self
        }
    }

    fn text_style(&self, style: Style<'_>) -> TextStyle {
        style.theme.type_scale.style(self.role)
    }

    /// Single-line size including leading.
    pub fn measure(&self, style: Style<'_>) -> Size {
        let ts = self.text_style(style);
        Size {
            width: text::measure(style.theme, ts, self.text).width,
            height: text::line_height(style.theme, ts),
        }
    }

    /// Paints at the top-left of `bounds`, truncated with an ellipsis to its width.
    pub fn paint(&self, canvas: &mut Canvas<'_>, style: Style<'_>, bounds: Rect) {
        let ts = self.text_style(style);
        let color = style.tone(self.tone.unwrap_or(ts.tone));
        let mut clipped = canvas.with_clip(bounds);
        text::draw_fitted(
            &mut clipped,
            style.theme,
            Point {
                x: bounds.x,
                y: bounds.y,
            },
            self.text,
            ts,
            color,
            bounds.width,
        );
    }
}

/// Container treatment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardKind {
    /// Rounded, bordered content card (translucent from Q1).
    Card,
    /// Flat, square region such as a sidebar.
    Panel,
    /// Recessed field or well.
    Inset,
}

/// Card, panel or inset container with an optional heading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Card<'a> {
    /// Treatment.
    pub kind: CardKind,
    /// Heading drawn at the top of the card.
    pub title: Option<&'a str>,
    /// Accent border marking the card as selected.
    pub selected: bool,
}

impl<'a> Card<'a> {
    /// Untitled [`CardKind::Card`].
    pub const fn new() -> Self {
        Self {
            kind: CardKind::Card,
            title: None,
            selected: false,
        }
    }
    /// Titled [`CardKind::Card`].
    pub const fn titled(title: &'a str) -> Self {
        Self {
            title: Some(title),
            ..Self::new()
        }
    }
    /// Same card with another kind.
    pub const fn with_kind(self, kind: CardKind) -> Self {
        Self { kind, ..self }
    }

    fn radius(&self, style: Style<'_>) -> u32 {
        match self.kind {
            CardKind::Card => style.theme.radius.lg,
            CardKind::Panel => 0,
            CardKind::Inset => style.theme.radius.md,
        }
    }

    /// Area left for children inside `bounds` (below the title, inside the padding).
    pub fn content_rect(&self, style: Style<'_>, bounds: Rect) -> Rect {
        let t = style.theme;
        let pad = match self.kind {
            CardKind::Inset => t.spacing.md,
            _ => t.spacing.lg,
        };
        let inner = bounds.shrink(pad);
        match self.title {
            Some(_) => {
                let heading = text::line_height(t, t.type_scale.heading);
                inner.split_top(heading + t.spacing.xs).1
            }
            None => inner,
        }
    }

    /// Paints the container (and title) and returns [`Self::content_rect`].
    pub fn paint(
        &self,
        canvas: &mut Canvas<'_>,
        style: Style<'_>,
        bounds: Rect,
        state: WidgetState,
    ) -> Rect {
        let t = style.theme;
        let p = &t.palette;
        let radius = self.radius(style);
        let bg = match self.kind {
            CardKind::Card => style.surface(p.card),
            CardKind::Panel => p.surface,
            CardKind::Inset => p.surface_sunken,
        };
        fill_rounded(canvas, bounds, radius, Corners::ALL, bg);
        let border = match (self.selected, state.interaction()) {
            (true, _) => Some(p.accent_cyan),
            (false, Interaction::Hover | Interaction::Pressed) => Some(p.border_strong),
            (false, _) if self.kind == CardKind::Panel => None,
            (false, _) => Some(p.border_subtle),
        };
        if let Some(border) = border {
            stroke_rounded(
                canvas,
                bounds,
                radius,
                Corners::ALL,
                t.stroke.hairline,
                border,
            );
        }
        if state.shows_focus() {
            focus_ring(canvas, style, bounds, radius);
        }
        if let Some(title) = self.title {
            let pad = match self.kind {
                CardKind::Inset => t.spacing.md,
                _ => t.spacing.lg,
            };
            let tone = if state.disabled {
                Some(TextTone::Disabled)
            } else {
                None
            };
            Text {
                text: title,
                role: TextRole::Heading,
                tone,
            }
            .paint(canvas, style, bounds.shrink(pad));
        }
        self.content_rect(style, bounds)
    }
}

impl Default for Card<'_> {
    fn default() -> Self {
        Self::new()
    }
}

/// Button emphasis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ButtonKind {
    /// Accent-filled main action.
    Primary,
    /// Bordered neutral action.
    Secondary,
    /// Text-only action that gains a fill on hover.
    Quiet,
}

/// Push button.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Button<'a> {
    /// Label.
    pub label: &'a str,
    /// Emphasis.
    pub kind: ButtonKind,
    /// Leading icon.
    pub icon: Option<Icon>,
}

/// Button height.
pub const BUTTON_HEIGHT: u32 = 32;

impl<'a> Button<'a> {
    /// [`ButtonKind::Secondary`] button.
    pub const fn new(label: &'a str) -> Self {
        Self {
            label,
            kind: ButtonKind::Secondary,
            icon: None,
        }
    }
    /// [`ButtonKind::Primary`] button.
    pub const fn primary(label: &'a str) -> Self {
        Self {
            kind: ButtonKind::Primary,
            ..Self::new(label)
        }
    }
    /// [`ButtonKind::Quiet`] button.
    pub const fn quiet(label: &'a str) -> Self {
        Self {
            kind: ButtonKind::Quiet,
            ..Self::new(label)
        }
    }
    /// Same button with a leading icon.
    pub const fn with_icon(self, icon: Icon) -> Self {
        Self {
            icon: Some(icon),
            ..self
        }
    }

    /// Natural size: padding + optional icon + label, [`BUTTON_HEIGHT`] tall.
    pub fn measure(&self, style: Style<'_>) -> Size {
        let t = style.theme;
        let label = text::measure(t, t.type_scale.label, self.label).width;
        let icon = match self.icon {
            Some(_) => ICON_SIZE + t.spacing.sm,
            None => 0,
        };
        Size {
            width: t.spacing.lg * 2 + icon + label,
            height: BUTTON_HEIGHT,
        }
    }

    fn colors(&self, style: Style<'_>, state: WidgetState) -> (Option<Rgba>, Option<Rgba>, Rgba) {
        let p = &style.theme.palette;
        match (self.kind, state.interaction()) {
            (_, Interaction::Disabled) => (Some(p.surface), Some(p.border_subtle), p.text_disabled),
            (ButtonKind::Primary, Interaction::Rest) => {
                (Some(p.accent_cyan), None, p.text_on_accent)
            }
            (ButtonKind::Primary, Interaction::Hover) => {
                (Some(p.primary_hover), None, p.text_on_accent)
            }
            (ButtonKind::Primary, Interaction::Pressed) => {
                (Some(p.primary_pressed), None, p.text_on_accent)
            }
            (ButtonKind::Secondary, Interaction::Rest) => {
                (Some(p.control), Some(p.border_subtle), p.text_primary)
            }
            (ButtonKind::Secondary, Interaction::Hover) => {
                (Some(p.control_hover), Some(p.border_strong), p.text_primary)
            }
            (ButtonKind::Secondary, Interaction::Pressed) => (
                Some(p.control_pressed),
                Some(p.border_strong),
                p.text_primary,
            ),
            (ButtonKind::Quiet, Interaction::Rest) => (None, None, p.text_secondary),
            (ButtonKind::Quiet, Interaction::Hover) => {
                (Some(p.control_hover), None, p.text_primary)
            }
            (ButtonKind::Quiet, Interaction::Pressed) => {
                (Some(p.control_pressed), None, p.text_primary)
            }
        }
    }

    /// Paints into `bounds` with the label centred.
    pub fn paint(
        &self,
        canvas: &mut Canvas<'_>,
        style: Style<'_>,
        bounds: Rect,
        state: WidgetState,
    ) {
        let t = style.theme;
        let radius = t.radius.md;
        let (bg, border, fg) = self.colors(style, state);
        if let Some(bg) = bg {
            fill_rounded(canvas, bounds, radius, Corners::ALL, bg);
        }
        if let Some(border) = border {
            stroke_rounded(
                canvas,
                bounds,
                radius,
                Corners::ALL,
                t.stroke.hairline,
                border,
            );
        }
        if state.shows_focus() {
            focus_ring(canvas, style, bounds, radius);
        }
        let ts = t.type_scale.label;
        let label = text::measure(t, ts, self.label);
        let icon_w = match self.icon {
            Some(_) => ICON_SIZE + t.spacing.sm,
            None => 0,
        };
        let inner = bounds.inset(Insets::symmetric(t.spacing.sm, 0));
        let content = inner.centered(Size {
            width: icon_w + label.width,
            height: label.height.max(ICON_SIZE),
        });
        let mut clipped = canvas.with_clip(inner);
        if let Some(icon) = self.icon {
            paint_icon(
                &mut clipped,
                t,
                icon,
                Point {
                    x: content.x,
                    y: offset(content.y, content.height.saturating_sub(ICON_SIZE) / 2),
                },
                1,
                fg,
            );
        }
        text::draw_fitted(
            &mut clipped,
            t,
            Point {
                x: offset(content.x, icon_w),
                y: offset(content.y, content.height.saturating_sub(label.height) / 2),
            },
            self.label,
            ts,
            fg,
            content.width.saturating_sub(icon_w),
        );
    }
}

/// On/off switch with an optional trailing label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Toggle<'a> {
    /// Current value (owned by the caller).
    pub on: bool,
    /// Trailing label.
    pub label: Option<&'a str>,
}

/// Toggle track width (excluding the 2 px focus margin on each side).
pub const TOGGLE_TRACK_WIDTH: u32 = 44;
/// Toggle track height (excluding the 2 px focus margin on each side).
pub const TOGGLE_TRACK_HEIGHT: u32 = 24;

impl<'a> Toggle<'a> {
    /// Unlabelled toggle.
    pub const fn new(on: bool) -> Self {
        Self { on, label: None }
    }
    /// Labelled toggle.
    pub const fn labelled(on: bool, label: &'a str) -> Self {
        Self {
            on,
            label: Some(label),
        }
    }

    fn track_area(style: Style<'_>, bounds: Rect) -> Rect {
        let ring = style.theme.stroke.focus;
        let w = TOGGLE_TRACK_WIDTH + 2 * ring;
        let h = TOGGLE_TRACK_HEIGHT + 2 * ring;
        Rect {
            x: bounds.x,
            y: offset(bounds.y, bounds.height.saturating_sub(h) / 2),
            width: w.min(bounds.width),
            height: h.min(bounds.height),
        }
    }

    /// Natural size: focus margin + track, then gap + label.
    pub fn measure(&self, style: Style<'_>) -> Size {
        let t = style.theme;
        let ring = t.stroke.focus;
        let label = match self.label {
            Some(l) => t.spacing.md + text::measure(t, t.type_scale.label, l).width,
            None => 0,
        };
        Size {
            width: TOGGLE_TRACK_WIDTH + 2 * ring + label,
            height: TOGGLE_TRACK_HEIGHT + 2 * ring,
        }
    }

    /// `(track, knob)` colours for the current value and interaction.
    pub fn colors(&self, style: Style<'_>, state: WidgetState) -> (Rgba, Rgba) {
        let p = &style.theme.palette;
        match (self.on, state.interaction()) {
            (_, Interaction::Disabled) => (p.surface_raised, p.text_disabled),
            (true, Interaction::Rest) => (p.accent_cyan, p.text_on_accent),
            (true, Interaction::Hover) => (p.primary_hover, p.text_on_accent),
            (true, Interaction::Pressed) => (p.primary_pressed, p.text_on_accent),
            (false, Interaction::Rest) => (p.surface_sunken, p.text_secondary),
            (false, Interaction::Hover) => (p.control_hover, p.text_primary),
            (false, Interaction::Pressed) => (p.control_pressed, p.text_primary),
        }
    }

    /// Paints the track at the left of `bounds` and the label after it.
    pub fn paint(
        &self,
        canvas: &mut Canvas<'_>,
        style: Style<'_>,
        bounds: Rect,
        state: WidgetState,
    ) {
        let t = style.theme;
        let p = &t.palette;
        let area = Self::track_area(style, bounds);
        let track = area.shrink(t.stroke.focus);
        let (track_color, knob_color) = self.colors(style, state);
        fill_rounded(canvas, track, t.radius.pill, Corners::ALL, track_color);
        if !self.on {
            stroke_rounded(
                canvas,
                track,
                t.radius.pill,
                Corners::ALL,
                t.stroke.hairline,
                p.border_strong,
            );
        }
        let knob_size = track.height.saturating_sub(6);
        let travel = track.width.saturating_sub(knob_size + 6);
        let knob = Rect {
            x: offset(track.x, 3 + if self.on { travel } else { 0 }),
            y: offset(track.y, 3),
            width: knob_size,
            height: knob_size,
        };
        fill_rounded(canvas, knob, t.radius.pill, Corners::ALL, knob_color);
        if state.shows_focus() {
            focus_ring(canvas, style, area, t.radius.pill);
        }
        if let Some(label) = self.label {
            let ts = t.type_scale.label;
            let tone = if state.disabled {
                TextTone::Disabled
            } else {
                ts.tone
            };
            let x = offset(area.x, area.width + t.spacing.md);
            let lh = text::measure(t, ts, label).height;
            let label_rect = Rect {
                x,
                y: offset(bounds.y, bounds.height.saturating_sub(lh) / 2),
                width: u32::try_from(i64::from(bounds.x) + i64::from(bounds.width) - i64::from(x))
                    .unwrap_or(0),
                height: lh,
            };
            Text {
                text: label,
                role: TextRole::Label,
                tone: Some(tone),
            }
            .paint(canvas, style, label_rect);
        }
    }
}

/// One entry of the persistent left rail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RailItem<'a> {
    /// Icon (shell affordances use the built-in masks).
    pub icon: Icon,
    /// Caption under the icon.
    pub label: &'a str,
    /// Current destination.
    pub selected: bool,
}

impl<'a> RailItem<'a> {
    /// Unselected item.
    pub const fn new(icon: Icon, label: &'a str) -> Self {
        Self {
            icon,
            label,
            selected: false,
        }
    }

    /// Size from [`crate::tokens::ShellMetrics`].
    pub fn measure(&self, style: Style<'_>) -> Size {
        Size {
            width: style.theme.shell.rail_width,
            height: style.theme.shell.rail_item_height,
        }
    }

    /// Paints into `bounds` (a full-width rail slot).
    pub fn paint(
        &self,
        canvas: &mut Canvas<'_>,
        style: Style<'_>,
        bounds: Rect,
        state: WidgetState,
    ) {
        let t = style.theme;
        let p = &t.palette;
        let pill = bounds.inset(Insets::symmetric(t.shell.rail_item_inset, 0));
        let bg = match (self.selected, state.interaction()) {
            (_, Interaction::Disabled) => None,
            (true, Interaction::Pressed) | (false, Interaction::Pressed) => Some(p.surface_sunken),
            (true, _) => Some(p.surface_raised),
            (false, Interaction::Hover) => Some(p.rail_hover),
            (false, _) => None,
        };
        if let Some(bg) = bg {
            fill_rounded(canvas, pill, t.radius.md, Corners::ALL, bg);
        }
        if self.selected && !state.disabled {
            let bar_h = bounds.height / 2;
            fill_rounded(
                canvas,
                Rect {
                    x: bounds.x,
                    y: offset(bounds.y, (bounds.height - bar_h) / 2),
                    width: t.stroke.indicator,
                    height: bar_h,
                },
                t.radius.sm,
                Corners::ALL,
                p.accent_cyan,
            );
        }
        if state.shows_focus() {
            focus_ring(canvas, style, pill, t.radius.md);
        }
        let (icon_color, label_tone) = match (self.selected, state.interaction()) {
            (_, Interaction::Disabled) => (p.text_disabled, TextTone::Disabled),
            (true, _) => (p.accent_cyan, TextTone::Primary),
            (false, Interaction::Hover | Interaction::Pressed) => {
                (p.text_primary, TextTone::Primary)
            }
            (false, _) => (p.text_secondary, TextTone::Muted),
        };
        let ts = t.type_scale.caption;
        let caption_h = text::measure(t, ts, self.label).height;
        let stack = pill.centered(Size {
            width: pill.width,
            height: ICON_SIZE + t.spacing.xs + caption_h,
        });
        paint_icon(
            canvas,
            t,
            self.icon,
            Point {
                x: offset(stack.x, (stack.width - ICON_SIZE.min(stack.width)) / 2),
                y: stack.y,
            },
            1,
            icon_color,
        );
        let label_w = text::fit(t, ts, self.label, pill.width.saturating_sub(t.spacing.xs)).width;
        let label_rect = Rect {
            x: offset(stack.x, stack.width.saturating_sub(label_w) / 2),
            y: offset(stack.y, ICON_SIZE + t.spacing.xs),
            width: label_w,
            height: caption_h,
        };
        Text {
            text: self.label,
            role: TextRole::Caption,
            tone: Some(label_tone),
        }
        .paint(canvas, style, label_rect);
    }
}

/// Static global-search field (the M10 search zone is a placeholder).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SearchField<'a> {
    /// Placeholder text.
    pub placeholder: &'a str,
}

impl SearchField<'_> {
    /// Paints the pill, magnifier and placeholder into `bounds`.
    pub fn paint(
        &self,
        canvas: &mut Canvas<'_>,
        style: Style<'_>,
        bounds: Rect,
        state: WidgetState,
    ) {
        let t = style.theme;
        let p = &t.palette;
        fill_rounded(
            canvas,
            bounds,
            t.radius.pill,
            Corners::ALL,
            style.surface(p.card),
        );
        let border = if state.hovered {
            p.border_strong
        } else {
            p.border_subtle
        };
        stroke_rounded(
            canvas,
            bounds,
            t.radius.pill,
            Corners::ALL,
            t.stroke.hairline,
            border,
        );
        if state.shows_focus() {
            focus_ring(canvas, style, bounds, t.radius.pill);
        }
        let inner = bounds.inset(Insets::symmetric(t.spacing.lg, 0));
        let icon_y = offset(inner.y, inner.height.saturating_sub(ICON_SIZE) / 2);
        paint_icon(
            canvas,
            t,
            Icon::Search,
            Point {
                x: inner.x,
                y: icon_y,
            },
            1,
            p.text_muted,
        );
        let ts = t.type_scale.body;
        let lh = text::measure(t, ts, self.placeholder).height;
        let (_, rest) = inner.split_left(ICON_SIZE + t.spacing.sm);
        Text::body(self.placeholder)
            .with_tone(TextTone::Muted)
            .paint(
                canvas,
                style,
                Rect {
                    y: offset(inner.y, inner.height.saturating_sub(lh) / 2),
                    height: lh,
                    ..rest
                },
            );
    }
}

/// One-pixel horizontal separator across `bounds` (vertically centred).
pub fn divider(canvas: &mut Canvas<'_>, style: Style<'_>, bounds: Rect) {
    fill(
        canvas,
        Rect {
            x: bounds.x,
            y: offset(bounds.y, bounds.height / 2),
            width: bounds.width,
            height: 1,
        },
        style.theme.palette.border_subtle,
    );
}
