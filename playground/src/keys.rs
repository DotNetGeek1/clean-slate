//! HID usage (page 0x07) naming and the US-layout text mapping for the key indicator and the
//! text line. Input stays raw on the wire (#110); turning usages into text is client policy.

use clean_slate_graphics::input::{KeyUsage, Modifiers};

use crate::text::{format, Line};

/// `Tab`.
pub const KEY_TAB: KeyUsage = KeyUsage(0x2B);
/// `Space`.
pub const KEY_SPACE: KeyUsage = KeyUsage(0x2C);
/// `Backspace`.
pub const KEY_BACKSPACE: KeyUsage = KeyUsage(0x2A);
/// `Enter`.
pub use clean_slate_graphics::input::KEY_ENTER;
/// `Escape`.
pub use clean_slate_graphics::input::KEY_ESCAPE;

/// Short label for a key cap, such as `A`, `7`, `Enter`, `F5` or `LShift`.
pub type KeyLabel = Line<8>;

const NAMED: [(u16, &str); 30] = [
    (0x28, "Enter"),
    (0x29, "Esc"),
    (0x2A, "Bksp"),
    (0x2B, "Tab"),
    (0x2C, "Space"),
    (0x39, "Caps"),
    (0x46, "PrtSc"),
    (0x47, "ScrLk"),
    (0x48, "Pause"),
    (0x49, "Ins"),
    (0x4A, "Home"),
    (0x4B, "PgUp"),
    (0x4C, "Del"),
    (0x4D, "End"),
    (0x4E, "PgDn"),
    (0x4F, "Right"),
    (0x50, "Left"),
    (0x51, "Down"),
    (0x52, "Up"),
    (0x53, "NumLk"),
    (0x65, "Menu"),
    (0xE0, "LCtrl"),
    (0xE1, "LShift"),
    (0xE2, "LAlt"),
    (0xE3, "LSuper"),
    (0xE4, "RCtrl"),
    (0xE5, "RShift"),
    (0xE6, "RAlt"),
    (0xE7, "RSuper"),
    (0x64, "\\"),
];

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

/// Key-cap label for `usage`.
pub fn label(usage: KeyUsage) -> KeyLabel {
    let u = usage.0;
    if let Some((_, name)) = NAMED.iter().find(|(code, _)| *code == u) {
        return format(format_args!("{name}"));
    }
    match u {
        0x04..=0x1D => format(format_args!("{}", char::from(b'A' + (u - 0x04) as u8))),
        0x1E..=0x26 => format(format_args!("{}", u - 0x1D)),
        0x27 => format(format_args!("0")),
        0x3A..=0x45 => format(format_args!("F{}", u - 0x39)),
        0x2D..=0x38 => match PUNCTUATION[usize::from(u - 0x2D)].0 {
            0 => format(format_args!("0x{u:02X}")),
            c => format(format_args!("{}", char::from(c))),
        },
        _ => format(format_args!("0x{u:02X}")),
    }
}

/// True for the modifier usages `0xE0..=0xE7`.
pub const fn is_modifier(usage: KeyUsage) -> bool {
    usage.0 >= 0xE0 && usage.0 <= 0xE7
}

/// Printable ASCII typed by `usage` with `modifiers` on a US layout, if any.
pub fn ascii(usage: KeyUsage, modifiers: Modifiers) -> Option<u8> {
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

/// Held-modifier prefix such as `Ctrl+Shift+` (lock states are not shown).
pub fn modifier_prefix(modifiers: Modifiers) -> Line<24> {
    let mut out = Line::new();
    for (mask, name) in [
        (Modifiers::CTRL, "Ctrl+"),
        (Modifiers::ALT, "Alt+"),
        (Modifiers::SHIFT, "Shift+"),
        (Modifiers::SUPER, "Super+"),
    ] {
        if modifiers.contains(mask) {
            let _ = core::fmt::Write::write_str(&mut out, name);
        }
    }
    out
}
