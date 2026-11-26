//! What a key press means to the terminal.
//!
//! Control keys (Enter, Backspace, the arrows, Ctrl and a letter) always come from raw `Key`
//! and `KeyRepeat` events. Printable text comes from the compositor's `Text` events (#309).
//! A compositor without `TEXT_INPUT` sends none, so then the US layout maps printable keys here.

use clean_slate_graphics::input::{KeyUsage, Modifiers};
use clean_slate_graphics::keymap;

use crate::line::Key;

/// What a pressed key does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Goes to the line editor.
    Edit(Key),
    /// Shift+Page Up: the view scrolls back half a screen.
    ScrollBack,
    /// Shift+Page Down: the view scrolls forward half a screen.
    ScrollForward,
}

const USAGE_ENTER: u16 = 0x28;
const USAGE_BACKSPACE: u16 = 0x2A;
const USAGE_HOME: u16 = 0x4A;
const USAGE_PAGE_UP: u16 = 0x4B;
const USAGE_DELETE: u16 = 0x4C;
const USAGE_END: u16 = 0x4D;
const USAGE_PAGE_DOWN: u16 = 0x4E;
const USAGE_RIGHT: u16 = 0x4F;
const USAGE_LEFT: u16 = 0x50;
const USAGE_DOWN: u16 = 0x51;
const USAGE_UP: u16 = 0x52;
const USAGE_KEYPAD_ENTER: u16 = 0x58;

/// The action for a press of `usage`. With `text_events`, printable keys are left to the
/// compositor's text events and only control keys map here.
pub fn action(usage: KeyUsage, modifiers: Modifiers, text_events: bool) -> Option<Action> {
    let shift = modifiers.contains(Modifiers::SHIFT);
    let ctrl = modifiers.contains(Modifiers::CTRL);
    let key = match usage.0 {
        USAGE_ENTER | USAGE_KEYPAD_ENTER => Key::Enter,
        USAGE_BACKSPACE => Key::Backspace,
        USAGE_DELETE => Key::Delete,
        USAGE_LEFT => Key::Left,
        USAGE_RIGHT => Key::Right,
        USAGE_UP => Key::Up,
        USAGE_DOWN => Key::Down,
        USAGE_HOME => Key::Home,
        USAGE_END => Key::End,
        USAGE_PAGE_UP if shift => return Some(Action::ScrollBack),
        USAGE_PAGE_DOWN if shift => return Some(Action::ScrollForward),
        0x04..=0x1D if ctrl => Key::Ctrl(char::from(b'a' + (usage.0 - 0x04) as u8)),
        _ if text_events => return None,
        _ => Key::Char(keymap::US.text(usage, modifiers)?),
    };
    Some(Action::Edit(key))
}
