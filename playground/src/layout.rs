//! Panel geometry. Every rect is derived from #116 tokens and widget measurements, never from
//! literal positions, and the interactive regions never overlap, so the damage of a state
//! change is exactly the rects of the regions whose view changed.

use clean_slate_graphics::{Point, Rect, Size};
use clean_slate_ui::layout::{Flow, RectExt};
use clean_slate_ui::text;
use clean_slate_ui::widgets::{Button, Card, CardKind, Text, Toggle, BUTTON_HEIGHT};
use clean_slate_ui::Style;

/// Fixed client-area size (the #116 reference desktop's sample window).
pub const PANEL_SIZE: Size = Size {
    width: 520,
    height: 360,
};

/// Label of the increment button.
pub const INCREMENT_LABEL: &str = "+1";
/// Label of the reset button.
pub const RESET_LABEL: &str = "Reset";
/// Label of the accent toggle.
pub const TOGGLE_LABEL: &str = "Magenta pointer";
/// Window heading.
pub const TITLE: &str = "System Playground";
/// Line under the heading.
pub const SUBTITLE: &str = "Shared UI primitives over the compositor protocol.";
/// Controls card heading.
pub const CONTROLS_HEADING: &str = "Controls";
/// Pointer card heading.
pub const POINTER_HEADING: &str = "Pointer";
/// Keyboard card heading.
pub const KEYBOARD_HEADING: &str = "Keyboard";

/// Edge length of the pointer marker drawn in the pad.
pub const MARKER_SIZE: u32 = 11;
/// Edge length of the last-click mark drawn in the pad.
pub const CLICK_MARK_SIZE: u32 = 5;

/// Width of the controls column; the pointer column takes the rest.
const CONTROLS_WIDTH: u32 = 260;
/// Width of the focus status block at the right of the title row.
const STATUS_WIDTH: u32 = 104;
/// Key cap width.
const KEYCAP_WIDTH: u32 = 72;

/// Every region of the panel, in surface-local buffer pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PanelLayout {
    /// The whole surface.
    pub bounds: Rect,
    /// Heading.
    pub title: Rect,
    /// Focus status dot and caption (right of the heading).
    pub status: Rect,
    /// Line under the heading.
    pub subtitle: Rect,
    /// Controls card.
    pub controls_card: Rect,
    /// `+1` button.
    pub increment: Rect,
    /// Reset button.
    pub reset: Rect,
    /// Click counter value.
    pub counter: Rect,
    /// Accent toggle (track and label).
    pub toggle: Rect,
    /// Pointer card.
    pub pointer_card: Rect,
    /// Pointer target well.
    pub pad: Rect,
    /// Pointer coordinate readout under the pad.
    pub readout: Rect,
    /// Keyboard card.
    pub keyboard_card: Rect,
    /// Key cap showing the last key (accent border while held).
    pub keycap: Rect,
    /// Last key, modifiers and press count.
    pub key_line: Rect,
    /// Typed text line.
    pub text_line: Rect,
}

const ZERO: Rect = Rect {
    x: 0,
    y: 0,
    width: 0,
    height: 0,
};

impl PanelLayout {
    /// All-zero layout (before [`Self::compute`]).
    pub const EMPTY: Self = Self {
        bounds: ZERO,
        title: ZERO,
        status: ZERO,
        subtitle: ZERO,
        controls_card: ZERO,
        increment: ZERO,
        reset: ZERO,
        counter: ZERO,
        toggle: ZERO,
        pointer_card: ZERO,
        pad: ZERO,
        readout: ZERO,
        keyboard_card: ZERO,
        keycap: ZERO,
        key_line: ZERO,
        text_line: ZERO,
    };

    /// Lays the panel out in `size` for `style`.
    pub fn compute(style: Style<'_>, size: Size) -> Self {
        let t = style.theme;
        let ts = &t.type_scale;
        let bounds = Rect {
            x: 0,
            y: 0,
            width: size.width,
            height: size.height,
        };
        let content = bounds.shrink(t.spacing.xl);
        let mut column = Flow::column(content, t.spacing.md);

        let title_h = Text::title(TITLE).measure(style).height;
        let subtitle_h = Text::body(SUBTITLE).measure(style).height;
        let header = column.next(title_h + t.spacing.xs + subtitle_h);
        let (title_row, rest) = header.split_top(title_h);
        let (title, status_slot) = title_row.split_right(STATUS_WIDTH);
        let caption_h = text::line_height(t, ts.caption);
        let status = status_slot.centered(Size {
            width: status_slot.width,
            height: caption_h,
        });
        let subtitle = rest.split_top(t.spacing.xs).1.split_top(subtitle_h).0;

        let card = Card::titled(CONTROLS_HEADING);
        let toggle_size = Toggle::labelled(false, TOGGLE_LABEL).measure(style);
        let counter_h = text::measure(t, ts.title, "0").height;
        let row_h = BUTTON_HEIGHT.max(counter_h);
        let controls_content_h = row_h + t.spacing.xs + toggle_size.height;
        let card_chrome_h = card_chrome_height(style);
        let cards = column.next(card_chrome_h + controls_content_h);
        let (controls_card, pointer_rest) = cards.split_left(CONTROLS_WIDTH);
        let pointer_card = pointer_rest.split_left(t.spacing.md).1;

        let controls = card.content_rect(style, controls_card);
        let mut rows = Flow::column(controls, t.spacing.xs);
        let mut buttons = Flow::row(rows.next(row_h), t.spacing.sm);
        let increment = buttons.next(Button::primary(INCREMENT_LABEL).measure(style).width);
        let reset = buttons.next(Button::new(RESET_LABEL).measure(style).width);
        let increment = increment.centered(Size {
            width: increment.width,
            height: BUTTON_HEIGHT,
        });
        let reset = reset.centered(Size {
            width: reset.width,
            height: BUTTON_HEIGHT,
        });
        buttons.skip(t.spacing.sm);
        let counter = buttons.remaining();
        let toggle_row = rows.next(toggle_size.height);
        let toggle = Rect {
            width: toggle_size.width.min(toggle_row.width),
            ..toggle_row
        };

        let pointer = Card::titled(POINTER_HEADING).content_rect(style, pointer_card);
        let (pad_area, readout_area) = pointer.split_top(pointer.height.saturating_sub(caption_h));
        let pad = pad_area
            .split_top(pad_area.height.saturating_sub(t.spacing.xs))
            .0;
        let readout = readout_area;

        let lines_h = 2 * caption_h;
        let keyboard_card = column.next(card_chrome_h + lines_h);
        let keyboard = Card::titled(KEYBOARD_HEADING).content_rect(style, keyboard_card);
        let (keycap, lines) = keyboard.split_left(KEYCAP_WIDTH);
        let lines = lines.split_left(t.spacing.md).1;
        let (key_line, text_line) = lines.split_top(caption_h);
        let text_line = text_line.split_top(caption_h).0;

        Self {
            bounds,
            title,
            status,
            subtitle,
            controls_card,
            increment,
            reset,
            counter,
            toggle,
            pointer_card,
            pad,
            readout,
            keyboard_card,
            keycap,
            key_line,
            text_line,
        }
    }

    /// The interactive control at `p`, if any.
    pub fn control_at(&self, p: Point) -> Option<crate::app::Control> {
        use crate::app::Control;
        [
            (self.increment, Control::Increment),
            (self.reset, Control::Reset),
            (self.toggle, Control::Toggle),
        ]
        .into_iter()
        .find(|(r, _)| r.contains(p))
        .map(|(_, c)| c)
    }

    /// Bounds of `control`.
    pub fn control_rect(&self, control: crate::app::Control) -> Rect {
        use crate::app::Control;
        match control {
            Control::Increment => self.increment,
            Control::Reset => self.reset,
            Control::Toggle => self.toggle,
        }
    }

    /// Area inside the pad where markers may be drawn (inside its border).
    pub fn pad_interior(&self, style: Style<'_>) -> Rect {
        self.pad.shrink(style.theme.stroke.hairline)
    }

    /// The `size`-square centred on `center`, clipped to the pad interior.
    pub fn mark_rect(&self, style: Style<'_>, center: Point, size: u32) -> Rect {
        let half = (size / 2) as i32;
        let square = Rect {
            x: center.x - half,
            y: center.y - half,
            width: size,
            height: size,
        };
        square
            .intersect(self.pad_interior(style))
            .ok()
            .flatten()
            .unwrap_or(ZERO)
    }

    /// Every region a full repaint must cover, in paint order (for invariants and tests).
    pub fn regions(&self) -> [Rect; 15] {
        [
            self.title,
            self.status,
            self.subtitle,
            self.controls_card,
            self.increment,
            self.reset,
            self.counter,
            self.toggle,
            self.pointer_card,
            self.pad,
            self.readout,
            self.keyboard_card,
            self.keycap,
            self.key_line,
            self.text_line,
        ]
    }
}

/// Vertical space a titled card adds around its content.
fn card_chrome_height(style: Style<'_>) -> u32 {
    let probe = Rect {
        x: 0,
        y: 0,
        width: 1000,
        height: 1000,
    };
    let inner = Card::titled("")
        .with_kind(CardKind::Card)
        .content_rect(style, probe);
    probe.height - inner.height
}
