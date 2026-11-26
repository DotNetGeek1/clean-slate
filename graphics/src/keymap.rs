//! Keyboard layouts: HID page-0x07 usage plus modifier state to typed text (#309).
//!
//! The compositor owns the layout so every client gets the same text for the same keys and an
//! app that wants raw keys (a game) still has [`Event::Key`](crate::protocol::Event::Key).
//! Clients see the result as [`Event::Text`](crate::protocol::Event::Text).
//!
//! **What is text.** Only printable characters. Enter, Tab, Backspace, Escape, Delete, the
//! arrow, navigation and function keys produce none, and nothing is typed while Ctrl, Alt or
//! Super is held: clients map those from the raw key themselves, so no key reaches a client
//! twice. Caps Lock changes letters only; the keypad types digits only with Num Lock on.
//!
//! Dead keys and compose are later work; they will arrive as preedit events beside `Text`.

use crate::input::{KeyUsage, Modifiers};

/// A layout table: one plain and one shifted character per usage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Short name, such as `us`.
    pub name: &'static str,
    /// Usages `0x04..=0x1D` (A–Z): plain, shifted.
    letters: [(char, char); 26],
    /// Usages `0x1E..=0x27` (1–9, 0): plain, shifted.
    digits: [(char, char); 10],
    /// Usages `0x2C..=0x38`: plain, shifted; `'\0'` for no text.
    punctuation: [(char, char); 13],
    /// Usage `0x64` (the key beside left Shift on ISO boards): plain, shifted; `'\0'` for none.
    non_us_backslash: (char, char),
}

const NONE: char = '\0';

/// US layout.
pub const US: Layout = Layout {
    name: "us",
    letters: [
        ('a', 'A'),
        ('b', 'B'),
        ('c', 'C'),
        ('d', 'D'),
        ('e', 'E'),
        ('f', 'F'),
        ('g', 'G'),
        ('h', 'H'),
        ('i', 'I'),
        ('j', 'J'),
        ('k', 'K'),
        ('l', 'L'),
        ('m', 'M'),
        ('n', 'N'),
        ('o', 'O'),
        ('p', 'P'),
        ('q', 'Q'),
        ('r', 'R'),
        ('s', 'S'),
        ('t', 'T'),
        ('u', 'U'),
        ('v', 'V'),
        ('w', 'W'),
        ('x', 'X'),
        ('y', 'Y'),
        ('z', 'Z'),
    ],
    digits: [
        ('1', '!'),
        ('2', '@'),
        ('3', '#'),
        ('4', '$'),
        ('5', '%'),
        ('6', '^'),
        ('7', '&'),
        ('8', '*'),
        ('9', '('),
        ('0', ')'),
    ],
    punctuation: [
        (' ', ' '),
        ('-', '_'),
        ('=', '+'),
        ('[', '{'),
        (']', '}'),
        ('\\', '|'),
        (NONE, NONE),
        (';', ':'),
        ('\'', '"'),
        ('`', '~'),
        (',', '<'),
        ('.', '>'),
        ('/', '?'),
    ],
    non_us_backslash: ('\\', '|'),
};

/// Keypad usages `0x59..=0x63` with Num Lock on: 1–9, 0, `.`.
const KEYPAD_DIGITS: [char; 11] = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '.'];

impl Layout {
    /// The character `usage` types with `modifiers` held, or `None` for a key that types no
    /// text (see the module docs).
    pub fn text(&self, usage: KeyUsage, modifiers: Modifiers) -> Option<char> {
        if modifiers.contains(Modifiers::CTRL)
            || modifiers.contains(Modifiers::ALT)
            || modifiers.contains(Modifiers::SUPER)
        {
            return None;
        }
        let shift = modifiers.contains(Modifiers::SHIFT);
        let pick = |(plain, shifted): (char, char), shift: bool| {
            let c = if shift { shifted } else { plain };
            (c != NONE).then_some(c)
        };
        let u = usage.0;
        match u {
            0x04..=0x1D => {
                let upper = shift != modifiers.contains(Modifiers::CAPS_LOCK);
                pick(self.letters[usize::from(u - 0x04)], upper)
            }
            0x1E..=0x27 => pick(self.digits[usize::from(u - 0x1E)], shift),
            0x2C..=0x38 => pick(self.punctuation[usize::from(u - 0x2C)], shift),
            0x64 => pick(self.non_us_backslash, shift),
            0x54 => Some('/'),
            0x55 => Some('*'),
            0x56 => Some('-'),
            0x57 => Some('+'),
            0x59..=0x63 => {
                // Shift inverts Num Lock on the keypad, as on PC keyboards.
                let digits = modifiers.contains(Modifiers::NUM_LOCK) != shift;
                digits.then(|| KEYPAD_DIGITS[usize::from(u - 0x59)])
            }
            _ => None,
        }
    }
}

/// True for keys the compositor repeats while held: everything except the modifiers
/// (`0xE0..=0xE7`) and the lock keys (Caps Lock, Num Lock, Scroll Lock).
pub const fn repeats(usage: KeyUsage) -> bool {
    !matches!(usage.0, 0xE0..=0xE7 | 0x39 | 0x47 | 0x53)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(bits: u16) -> Modifiers {
        Modifiers::from_bits(bits).unwrap()
    }

    fn text(usage: u16, bits: u16) -> Option<char> {
        US.text(KeyUsage(usage), m(bits))
    }

    #[test]
    fn letters_follow_shift_and_caps_lock() {
        assert_eq!(text(0x04, 0), Some('a'));
        assert_eq!(text(0x1D, 0), Some('z'));
        assert_eq!(text(0x04, Modifiers::SHIFT), Some('A'));
        assert_eq!(text(0x04, Modifiers::CAPS_LOCK), Some('A'));
        assert_eq!(
            text(0x04, Modifiers::CAPS_LOCK | Modifiers::SHIFT),
            Some('a')
        );
    }

    #[test]
    fn caps_lock_leaves_digits_and_punctuation_alone() {
        assert_eq!(text(0x1E, Modifiers::CAPS_LOCK), Some('1'));
        assert_eq!(text(0x2D, Modifiers::CAPS_LOCK), Some('-'));
        assert_eq!(
            text(0x1E, Modifiers::CAPS_LOCK | Modifiers::SHIFT),
            Some('!')
        );
    }

    #[test]
    fn digit_row_and_punctuation() {
        let plain: [char; 10] = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'];
        let shifted = "!@#$%^&*()";
        for (i, (p, s)) in plain.iter().zip(shifted.chars()).enumerate() {
            let usage = 0x1E + i as u16;
            assert_eq!(text(usage, 0), Some(*p));
            assert_eq!(text(usage, Modifiers::SHIFT), Some(s));
        }
        let row = [
            (0x2C, ' ', ' '),
            (0x2D, '-', '_'),
            (0x2E, '=', '+'),
            (0x2F, '[', '{'),
            (0x30, ']', '}'),
            (0x31, '\\', '|'),
            (0x33, ';', ':'),
            (0x34, '\'', '"'),
            (0x35, '`', '~'),
            (0x36, ',', '<'),
            (0x37, '.', '>'),
            (0x38, '/', '?'),
            (0x64, '\\', '|'),
        ];
        for (usage, p, s) in row {
            assert_eq!(text(usage, 0), Some(p), "usage {usage:#x}");
            assert_eq!(text(usage, Modifiers::SHIFT), Some(s), "usage {usage:#x}");
        }
        assert_eq!(text(0x32, 0), None, "non-US # is not on a US board");
    }

    #[test]
    fn control_keys_type_nothing() {
        // Enter, Escape, Backspace, Tab, Caps Lock, F1, F12, PrtSc..Up, Num Lock, keypad Enter.
        let control = [0x28, 0x29, 0x2A, 0x2B, 0x39, 0x3A, 0x45];
        for usage in control.into_iter().chain(0x46..=0x53).chain([0x58, 0x65]) {
            assert_eq!(text(usage, 0), None, "usage {usage:#x}");
            assert_eq!(text(usage, Modifiers::SHIFT), None, "usage {usage:#x}");
        }
        for usage in 0xE0..=0xE7 {
            assert_eq!(text(usage, 0), None);
        }
    }

    #[test]
    fn ctrl_alt_and_super_suppress_text() {
        for held in [Modifiers::CTRL, Modifiers::ALT, Modifiers::SUPER] {
            assert_eq!(text(0x06, held), None);
            assert_eq!(text(0x06, held | Modifiers::SHIFT), None);
            assert_eq!(text(0x2C, held), None);
        }
    }

    #[test]
    fn keypad_digits_need_num_lock() {
        assert_eq!(text(0x59, 0), None, "keypad 1 is End without Num Lock");
        assert_eq!(text(0x59, Modifiers::NUM_LOCK), Some('1'));
        assert_eq!(text(0x61, Modifiers::NUM_LOCK), Some('9'));
        assert_eq!(text(0x62, Modifiers::NUM_LOCK), Some('0'));
        assert_eq!(text(0x63, Modifiers::NUM_LOCK), Some('.'));
        assert_eq!(text(0x59, Modifiers::NUM_LOCK | Modifiers::SHIFT), None);
        assert_eq!(text(0x59, Modifiers::SHIFT), Some('1'));
        for (usage, c) in [(0x54, '/'), (0x55, '*'), (0x56, '-'), (0x57, '+')] {
            assert_eq!(text(usage, 0), Some(c));
            assert_eq!(text(usage, Modifiers::NUM_LOCK), Some(c));
        }
    }

    #[test]
    fn modifiers_and_locks_do_not_repeat() {
        assert!(repeats(KeyUsage(0x04)));
        assert!(repeats(KeyUsage(0x2A)), "Backspace repeats");
        assert!(repeats(KeyUsage(0x52)), "Up repeats");
        for usage in [0x39, 0x47, 0x53, 0xE0, 0xE1, 0xE7] {
            assert!(!repeats(KeyUsage(usage)), "usage {usage:#x}");
        }
    }
}
