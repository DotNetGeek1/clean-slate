//! Application state and input handling.
//!
//! Input methods mutate [`Playground`]; rendering reads only the [`View`] snapshot. The damage
//! of any state change is [`View::damage`] between the snapshots before and after it, so an
//! event that changes nothing visible produces no damage and therefore no repaint or commit.

use clean_slate_graphics::input::{KeyState, KeyUsage, Modifiers, PointerButton};
use clean_slate_graphics::{Point, Rect, Size};
use clean_slate_ui::layout::RectExt;
use clean_slate_ui::surface::Damage;
use clean_slate_ui::{Style, WidgetState};

use crate::keys::{self, KEY_BACKSPACE, KEY_ENTER, KEY_ESCAPE, KEY_SPACE, KEY_TAB};
use crate::layout::{PanelLayout, CLICK_MARK_SIZE, MARKER_SIZE};
use crate::text::Line;

/// Keyboard-focusable controls, in Tab order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    /// `+1` button.
    Increment,
    /// Reset button.
    Reset,
    /// Accent toggle.
    Toggle,
}

impl Control {
    /// Tab order.
    pub const ORDER: [Self; 3] = [Self::Increment, Self::Reset, Self::Toggle];

    fn index(self) -> usize {
        match self {
            Self::Increment => 0,
            Self::Reset => 1,
            Self::Toggle => 2,
        }
    }

    /// Next control in Tab order (wrapping).
    pub fn next(self) -> Self {
        Self::ORDER[(self.index() + 1) % Self::ORDER.len()]
    }

    /// Previous control in Tab order (wrapping).
    pub fn prev(self) -> Self {
        Self::ORDER[(self.index() + Self::ORDER.len() - 1) % Self::ORDER.len()]
    }
}

/// Capacity of the typed-text line.
pub const TEXT_CAPACITY: usize = 32;
/// Typed text.
pub type TypedText = Line<TEXT_CAPACITY>;
/// Largest displayed click count; the counter saturates here.
pub const MAX_CLICKS: u32 = 99_999;

/// Everything the panel shows. Two equal views paint identical pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct View {
    /// Keyboard input is routed to this surface (`KeyboardFocus`).
    pub keyboard_focus: bool,
    /// The window manager reports the window active (`Configure` `ACTIVATED`).
    pub window_active: bool,
    /// `+1` button interaction.
    pub increment: WidgetState,
    /// Reset button interaction.
    pub reset: WidgetState,
    /// Toggle interaction.
    pub toggle: WidgetState,
    /// Click count.
    pub clicks: u32,
    /// Toggle value: magenta instead of cyan pointer marks.
    pub magenta: bool,
    /// Pointer is over the pad.
    pub pad_hovered: bool,
    /// Pointer position while it is over the pad.
    pub cursor: Option<Point>,
    /// Last press position inside the pad.
    pub click_mark: Option<Point>,
    /// Last key pressed.
    pub key: Option<KeyUsage>,
    /// [`Self::key`] is still held.
    pub key_held: bool,
    /// Modifiers with the last key event.
    pub modifiers: Modifiers,
    /// Key presses received.
    pub presses: u32,
    /// Typed text.
    pub text: TypedText,
}

impl View {
    /// Damage turning `self` into `next` on `layout`: the rects of exactly the regions whose
    /// content differs.
    pub fn damage(&self, next: &View, layout: &PanelLayout, style: Style<'_>) -> Damage {
        let mut d = Damage::new();
        if (self.keyboard_focus, self.window_active) != (next.keyboard_focus, next.window_active) {
            d.add(layout.status);
        }
        if self.increment != next.increment {
            d.add(layout.increment);
        }
        if self.reset != next.reset {
            d.add(layout.reset);
        }
        if self.clicks != next.clicks {
            d.add(layout.counter);
        }
        if (self.toggle, self.magenta) != (next.toggle, next.magenta) {
            d.add(layout.toggle);
        }
        if self.pad_hovered != next.pad_hovered {
            d.add(layout.pad);
        } else {
            let recolor = self.magenta != next.magenta;
            for (old, new, size) in [
                (self.cursor, next.cursor, MARKER_SIZE),
                (self.click_mark, next.click_mark, CLICK_MARK_SIZE),
            ] {
                if old != new || recolor {
                    for p in [old, new].into_iter().flatten() {
                        d.add(layout.mark_rect(style, p, size));
                    }
                }
            }
        }
        if self.cursor != next.cursor {
            d.add(layout.readout);
        }
        if (self.key, self.key_held) != (next.key, next.key_held) {
            d.add(layout.keycap);
        }
        if (self.key, self.modifiers, self.presses) != (next.key, next.modifiers, next.presses) {
            d.add(layout.key_line);
        }
        if (self.text, self.keyboard_focus) != (next.text, next.keyboard_focus) {
            d.add(layout.text_line);
        }
        d
    }
}

/// Application state.
#[derive(Clone, Copy)]
pub struct Playground {
    style: Style<'static>,
    layout: PanelLayout,
    clicks: u32,
    magenta: bool,
    window_active: bool,
    keyboard_focus: bool,
    focus: Control,
    hovered: Option<Control>,
    pressed: Option<Control>,
    pointer: Option<Point>,
    click_mark: Option<Point>,
    modifiers: Modifiers,
    last_key: Option<KeyUsage>,
    key_held: bool,
    presses: u32,
    text: TypedText,
}

const NO_MODIFIERS: Modifiers = match Modifiers::from_bits(0) {
    Some(m) => m,
    None => unreachable!(),
};

impl Playground {
    /// Fresh state; call [`Self::relayout`] before use.
    pub const fn new(style: Style<'static>) -> Self {
        Self {
            style,
            layout: PanelLayout::EMPTY,
            clicks: 0,
            magenta: false,
            window_active: false,
            keyboard_focus: false,
            focus: Control::Increment,
            hovered: None,
            pressed: None,
            pointer: None,
            click_mark: None,
            modifiers: NO_MODIFIERS,
            last_key: None,
            key_held: false,
            presses: 0,
            text: Line::new(),
        }
    }

    /// Fresh state laid out at `size`.
    pub fn laid_out(style: Style<'static>, size: Size) -> Self {
        let mut app = Self::new(style);
        app.relayout(size);
        app
    }

    /// Recomputes the layout for `size`.
    pub fn relayout(&mut self, size: Size) {
        self.layout = PanelLayout::compute(self.style, size);
    }

    /// Style everything is painted with.
    pub fn style(&self) -> Style<'static> {
        self.style
    }

    /// Current layout.
    pub fn layout(&self) -> &PanelLayout {
        &self.layout
    }

    /// Click count.
    pub fn clicks(&self) -> u32 {
        self.clicks
    }

    /// Toggle value.
    pub fn magenta(&self) -> bool {
        self.magenta
    }

    /// Keyboard-focused control.
    pub fn focus(&self) -> Control {
        self.focus
    }

    /// Typed text.
    pub fn text(&self) -> &str {
        self.text.as_str()
    }

    /// Snapshot of everything visible.
    pub fn view(&self) -> View {
        let state = |c: Control| {
            let hovered = self.hovered == Some(c);
            WidgetState {
                hovered,
                pressed: hovered && self.pressed == Some(c),
                focused: self.keyboard_focus && self.focus == c,
                disabled: false,
            }
        };
        let interior = self.layout.pad_interior(self.style);
        let cursor = self.pointer.filter(|p| interior.contains(*p));
        View {
            keyboard_focus: self.keyboard_focus,
            window_active: self.window_active,
            increment: state(Control::Increment),
            reset: state(Control::Reset),
            toggle: state(Control::Toggle),
            clicks: self.clicks,
            magenta: self.magenta,
            pad_hovered: self.pointer.is_some_and(|p| self.layout.pad.contains(p)),
            cursor,
            click_mark: self.click_mark,
            key: self.last_key,
            key_held: self.key_held,
            modifiers: self.modifiers,
            presses: self.presses,
            text: self.text,
        }
    }

    // ---- window and focus -------------------------------------------------------------------

    /// `Configure` state from the window manager.
    pub fn set_window_active(&mut self, active: bool) {
        self.window_active = active;
    }

    /// `KeyboardFocus` gained (`true`) or lost.
    pub fn set_keyboard_focus(&mut self, focused: bool) {
        self.keyboard_focus = focused;
        if !focused {
            self.key_held = false;
        }
    }

    // ---- pointer ----------------------------------------------------------------------------

    /// `PointerEnter` / `PointerMotion` at surface-local `p`.
    pub fn pointer_motion(&mut self, p: Point) {
        self.pointer = Some(p);
        self.hovered = self.layout.control_at(p);
    }

    /// `PointerLeave`.
    pub fn pointer_leave(&mut self) {
        self.pointer = None;
        self.hovered = None;
    }

    /// `PointerButton` at the last pointer position.
    pub fn pointer_button(&mut self, button: PointerButton, state: KeyState) {
        if button != PointerButton::Left {
            return;
        }
        let Some(p) = self.pointer else {
            if state == KeyState::Released {
                self.pressed = None;
            }
            return;
        };
        let target = self.layout.control_at(p);
        match state {
            KeyState::Pressed => {
                self.pressed = target;
                if let Some(control) = target {
                    self.focus = control;
                }
                if self.layout.pad_interior(self.style).contains(p) {
                    self.click_mark = Some(p);
                }
            }
            KeyState::Released => {
                if let (Some(pressed), Some(over)) = (self.pressed, target) {
                    if pressed == over {
                        self.activate(pressed);
                    }
                }
                self.pressed = None;
            }
        }
    }

    // ---- keyboard ---------------------------------------------------------------------------

    /// `Key` transition.
    pub fn key(&mut self, usage: KeyUsage, state: KeyState, modifiers: Modifiers) {
        self.modifiers = modifiers;
        match state {
            KeyState::Pressed => {
                self.last_key = Some(usage);
                self.key_held = true;
                self.presses = self.presses.saturating_add(1);
                self.key_command(usage, modifiers);
            }
            KeyState::Released => {
                if self.last_key == Some(usage) {
                    self.key_held = false;
                }
            }
        }
    }

    fn key_command(&mut self, usage: KeyUsage, modifiers: Modifiers) {
        if usage == KEY_TAB {
            self.focus = if modifiers.contains(Modifiers::SHIFT) {
                self.focus.prev()
            } else {
                self.focus.next()
            };
        } else if usage == KEY_SPACE || usage == KEY_ENTER {
            self.activate(self.focus);
        } else if usage == KEY_BACKSPACE {
            self.text.pop();
        } else if usage == KEY_ESCAPE {
            self.text.clear();
        } else if let Some(byte) = keys::ascii(usage, modifiers) {
            self.text.push(byte);
        }
    }

    /// `ModifiersChanged`.
    pub fn modifiers_changed(&mut self, modifiers: Modifiers) {
        self.modifiers = modifiers;
    }

    /// `InputReset`: every held key and button is released.
    pub fn input_reset(&mut self) {
        self.pressed = None;
        self.key_held = false;
        self.modifiers =
            Modifiers::from_bits(self.modifiers.bits() & LOCK_BITS).unwrap_or(NO_MODIFIERS);
    }

    fn activate(&mut self, control: Control) {
        match control {
            Control::Increment => self.clicks = (self.clicks + 1).min(MAX_CLICKS),
            Control::Reset => self.clicks = 0,
            Control::Toggle => self.magenta = !self.magenta,
        }
    }

    /// Damage from `before` to the current view.
    pub fn damage_since(&self, before: &View) -> Damage {
        before.damage(&self.view(), &self.layout, self.style)
    }

    /// Full-surface damage (first paint).
    pub fn full_damage(&self) -> Damage {
        let mut d = Damage::new();
        d.add(self.layout.bounds);
        d
    }

    /// Surface bounds.
    pub fn bounds(&self) -> Rect {
        self.layout.bounds
    }
}

const LOCK_BITS: u16 = Modifiers::CAPS_LOCK | Modifiers::NUM_LOCK;
