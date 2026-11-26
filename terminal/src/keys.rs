//! What a key press means to the terminal.
//!
//! Control keys (Enter, Backspace, the arrows, Ctrl and a letter) always come from raw `Key`
//! events. Printable text comes from the compositor's text events once it sends them (#309);
//! until then [`us_text`] maps a US layout here, the same table the playground uses.

use clean_slate_graphics::input::{KeyUsage, Modifiers};

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
        _ => Key::Char(char::from(us_text(usage, modifiers)?)),
    };
    Some(Action::Edit(key))
}

/// US layout for usages `0x2D..=0x38`: (unshifted, shifted); `0x32` (non-US `#`) is unused.
const PUNCTUATION: [(u8, u8); 12] = [
    (b'-', b'_'),
    (b'=', b'+'),
    (b'[', b'{'),
    (b']', b'}'),
    (b'\\', b'|'),
    (0, 0),
    (b';', b':'),
    (b'\'', b'"'),
    (b'`', b'~'),
    (b',', b'<'),
    (b'.', b'>'),
    (b'/', b'?'),
];

const DIGIT_SHIFTED: [u8; 10] = *b"!@#$%^&*()";

/// Printable ASCII typed by `usage` with `modifiers` on a US layout, if any. The stopgap until
/// the compositor's text events (#309) arrive.
pub fn us_text(usage: KeyUsage, modifiers: Modifiers) -> Option<u8> {
    if modifiers.contains(Modifiers::CTRL)
        || modifiers.contains(Modifiers::ALT)
        || modifiers.contains(Modifiers::SUPER)
    {
        return None;
    }
    let shift = modifiers.contains(Modifiers::SHIFT);
    let u = usage.0;
    match u {
        0x04..=0x1D => {
            let upper = shift != modifiers.contains(Modifiers::CAPS_LOCK);
            let base = if upper { b'A' } else { b'a' };
            Some(base + (u - 0x04) as u8)
        }
        0x1E..=0x27 => {
            let index = usize::from(u - 0x1E);
            if shift {
                Some(DIGIT_SHIFTED[index])
            } else if u == 0x27 {
                Some(b'0')
            } else {
                Some(b'1' + index as u8)
            }
        }
        0x2C => Some(b' '),
        0x2D..=0x38 => {
            let (plain, shifted) = PUNCTUATION[usize::from(u - 0x2D)];
            match (plain, shift) {
                (0, _) => None,
                (_, true) => Some(shifted),
                (_, false) => Some(plain),
            }
        }
        _ => None,
    }
}
