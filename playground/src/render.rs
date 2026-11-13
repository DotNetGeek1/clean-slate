//! Paints a [`View`] with the #116 primitives. The output is a pure function of the view and
//! layout, and every primitive honours the canvas clip, so repainting only the damage of a
//! change yields exactly the pixels of a full repaint (proven in the tests).

use clean_slate_graphics::{Point, Rect, Size};
use clean_slate_raster::Canvas;
use clean_slate_ui::layout::RectExt;
use clean_slate_ui::paint::{fill, fill_rounded, stroke_rounded, Corners};
use clean_slate_ui::surface::{repaint, Damage};
use clean_slate_ui::text;
use clean_slate_ui::tokens::{Rgba, TextTone};
use clean_slate_ui::widgets::{Button, Card, CardKind, Text, Toggle, WidgetState};
use clean_slate_ui::Style;

use crate::app::View;
use crate::keys;
use crate::layout::{
    PanelLayout, CLICK_MARK_SIZE, CONTROLS_HEADING, INCREMENT_LABEL, KEYBOARD_HEADING, MARKER_SIZE,
    POINTER_HEADING, RESET_LABEL, SUBTITLE, TITLE, TOGGLE_LABEL,
};
use crate::text::{format, Line};

/// Status dot edge length.
const STATUS_DOT: u32 = 8;

/// Paints the whole panel (clipped to the canvas clip).
pub fn paint(canvas: &mut Canvas<'_>, style: Style<'_>, layout: &PanelLayout, view: &View) {
    let t = style.theme;
    let p = &t.palette;
    fill(canvas, layout.bounds, p.surface);

    Text::title(TITLE).paint(canvas, style, layout.title);
    paint_status(canvas, style, layout.status, view);
    Text::body(SUBTITLE).paint(canvas, style, layout.subtitle);

    Card::titled(CONTROLS_HEADING).paint(canvas, style, layout.controls_card, WidgetState::REST);
    Button::primary(INCREMENT_LABEL).paint(canvas, style, layout.increment, view.increment);
    Button::new(RESET_LABEL).paint(canvas, style, layout.reset, view.reset);
    let clicks: Line<8> = format(format_args!("{}", view.clicks));
    Text::title(clicks.as_str())
        .with_tone(TextTone::Accent)
        .paint(canvas, style, layout.counter);
    Toggle::labelled(view.magenta, TOGGLE_LABEL).paint(canvas, style, layout.toggle, view.toggle);

    Card::titled(POINTER_HEADING).paint(canvas, style, layout.pointer_card, WidgetState::REST);
    paint_pad(canvas, style, layout, view);
    let readout: Line<32> = match view.cursor {
        Some(c) => {
            let local = Point {
                x: c.x - layout.pad.x,
                y: c.y - layout.pad.y,
            };
            format(format_args!("x {}  y {}", local.x, local.y))
        }
        None => format(format_args!("Move the pointer here")),
    };
    Text::caption(readout.as_str()).paint(canvas, style, layout.readout);

    Card::titled(KEYBOARD_HEADING).paint(canvas, style, layout.keyboard_card, WidgetState::REST);
    paint_keycap(canvas, style, layout.keycap, view);
    paint_key_line(canvas, style, layout.key_line, view);
    paint_text_line(canvas, style, layout.text_line, view);
}

/// Repaints only `damage` of `view`.
pub fn paint_damage(
    canvas: &mut Canvas<'_>,
    style: Style<'_>,
    layout: &PanelLayout,
    view: &View,
    damage: &Damage,
) {
    repaint(canvas, damage, |c| paint(c, style, layout, view));
}

fn paint_status(canvas: &mut Canvas<'_>, style: Style<'_>, bounds: Rect, view: &View) {
    let p = &style.theme.palette;
    let (dot, label, tone) = match (view.keyboard_focus, view.window_active) {
        (true, _) => (p.success, "Focused", TextTone::Primary),
        (false, true) => (p.accent_blue, "Active", TextTone::Secondary),
        (false, false) => (p.text_disabled, "Inactive", TextTone::Muted),
    };
    let (dot_slot, rest) = bounds.split_left(STATUS_DOT + style.theme.spacing.sm);
    let dot_rect = dot_slot.split_left(STATUS_DOT).0.centered(Size {
        width: STATUS_DOT,
        height: STATUS_DOT,
    });
    fill_rounded(canvas, dot_rect, style.theme.radius.pill, Corners::ALL, dot);
    Text::caption(label)
        .with_tone(tone)
        .paint(canvas, style, rest);
}

fn mark_color(style: Style<'_>, view: &View) -> Rgba {
    let p = &style.theme.palette;
    if view.magenta {
        p.accent_magenta
    } else {
        p.accent_cyan
    }
}

fn paint_pad(canvas: &mut Canvas<'_>, style: Style<'_>, layout: &PanelLayout, view: &View) {
    let t = style.theme;
    let state = WidgetState {
        hovered: view.pad_hovered,
        ..WidgetState::REST
    };
    Card::new()
        .with_kind(CardKind::Inset)
        .paint(canvas, style, layout.pad, state);
    let color = mark_color(style, view);
    let interior = layout.pad_interior(style);
    let mut marks = canvas.with_clip(interior);
    if let Some(at) = view.click_mark {
        let r = square(at, CLICK_MARK_SIZE);
        fill_rounded(&mut marks, r, t.radius.sm, Corners::ALL, color);
    }
    if let Some(at) = view.cursor {
        let ring = square(at, MARKER_SIZE);
        stroke_rounded(
            &mut marks,
            ring,
            t.radius.pill,
            Corners::ALL,
            t.stroke.focus,
            color,
        );
        fill(&mut marks, square(at, 1), t.palette.text_primary);
    }
}

fn square(center: Point, size: u32) -> Rect {
    let half = (size / 2) as i32;
    Rect {
        x: center.x - half,
        y: center.y - half,
        width: size,
        height: size,
    }
}

fn paint_keycap(canvas: &mut Canvas<'_>, style: Style<'_>, bounds: Rect, view: &View) {
    let t = style.theme;
    let cap = Card {
        kind: CardKind::Inset,
        title: None,
        selected: view.key_held,
    };
    cap.paint(canvas, style, bounds, WidgetState::REST);
    let label = match view.key {
        Some(usage) => keys::label(usage),
        None => format(format_args!("-")),
    };
    let ts = t.type_scale.heading;
    let fitted = text::fit(
        t,
        ts,
        label.as_str(),
        bounds.width.saturating_sub(t.spacing.sm),
    );
    let size = Size {
        width: fitted.width,
        height: text::measure(t, ts, label.as_str()).height,
    };
    let tone = if view.key_held {
        TextTone::Accent
    } else {
        TextTone::Primary
    };
    Text::heading(label.as_str())
        .with_tone(tone)
        .paint(canvas, style, bounds.centered(size));
}

fn paint_key_line(canvas: &mut Canvas<'_>, style: Style<'_>, bounds: Rect, view: &View) {
    let line: Line<48> = match view.key {
        Some(usage) => {
            let prefix = if keys::is_modifier(usage) {
                Line::new()
            } else {
                keys::modifier_prefix(view.modifiers)
            };
            format(format_args!(
                "Key {}{}   presses {}",
                prefix.as_str(),
                keys::label(usage).as_str(),
                view.presses
            ))
        }
        None => format(format_args!("Press any key")),
    };
    Text::body(line.as_str()).paint(canvas, style, bounds);
}

fn paint_text_line(canvas: &mut Canvas<'_>, style: Style<'_>, bounds: Rect, view: &View) {
    let t = style.theme;
    let (label_slot, value) = bounds.split_left(text::measure(t, t.type_scale.body, "Text ").width);
    Text::body("Text").paint(canvas, style, label_slot);
    let caret = if view.keyboard_focus { "_" } else { "" };
    let line: Line<40> = if view.text.is_empty() && !view.keyboard_focus {
        format(format_args!("(focus the window and type)"))
    } else {
        format(format_args!("{}{}", view.text.as_str(), caret))
    };
    let tone = if view.text.is_empty() && !view.keyboard_focus {
        TextTone::Muted
    } else {
        TextTone::Primary
    };
    Text::body(line.as_str())
        .with_tone(tone)
        .paint(canvas, style, value);
}
