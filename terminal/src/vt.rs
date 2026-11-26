//! A VT100/ANSI parser: bytes in, [`Screen`] operations out.
//!
//! Enough for BusyBox `ash` and its applets: printable UTF-8, `BS`, `HT`, `LF` (also `VT`, `FF`),
//! `CR`, the `ESC 7`/`ESC 8`/`ESC D`/`ESC E`/`ESC M`/`ESC c` escapes, and the CSI sequences
//! for cursor movement (`A B C D E F G H d f`), erasing (`J K X`), inserting and deleting
//! (`@ P L M`), cursor save and restore (`s u`), cursor visibility (`?25h`, `?25l`) and SGR
//! colours and attributes (`m`). Everything else is consumed and ignored, including OSC strings
//! and character set designations, so an unknown sequence never prints as text.

use crate::screen::{Attr, Color, Screen};

/// Parameters one CSI sequence keeps; later ones are ignored.
const MAX_PARAMS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Ground,
    Escape,
    /// `ESC (`, `ESC )` and friends: one more byte names a character set.
    Charset,
    Csi,
    /// An OSC or other string, until `BEL` or `ESC \`.
    String,
    StringEscape,
}

#[derive(Clone, Copy, Debug)]
pub struct Parser {
    state: State,
    params: [u16; MAX_PARAMS],
    count: usize,
    /// The current parameter has a digit (an empty one means its default).
    has_digit: bool,
    private: bool,
    /// UTF-8 bytes still expected, and the code point so far.
    utf8_left: u8,
    utf8: u32,
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser {
    pub const fn new() -> Self {
        Self {
            state: State::Ground,
            params: [0; MAX_PARAMS],
            count: 0,
            has_digit: false,
            private: false,
            utf8_left: 0,
            utf8: 0,
        }
    }

    pub fn feed(&mut self, screen: &mut Screen, bytes: &[u8]) {
        for &byte in bytes {
            self.byte(screen, byte);
        }
    }

    fn byte(&mut self, screen: &mut Screen, byte: u8) {
        // CAN and SUB abort a sequence; ESC starts a new one wherever it appears.
        match byte {
            0x18 | 0x1A => {
                self.state = State::Ground;
                return;
            }
            0x1B if self.state != State::String => {
                self.utf8_left = 0;
                self.state = State::Escape;
                return;
            }
            _ => {}
        }
        match self.state {
            State::Ground => self.ground(screen, byte),
            State::Escape => self.escape(screen, byte),
            State::Charset => self.state = State::Ground,
            State::Csi => self.csi(screen, byte),
            State::String => match byte {
                0x07 => self.state = State::Ground,
                0x1B => self.state = State::StringEscape,
                _ => {}
            },
            State::StringEscape => {
                self.state = if byte == b'\\' {
                    State::Ground
                } else {
                    State::String
                };
            }
        }
    }

    fn ground(&mut self, screen: &mut Screen, byte: u8) {
        if self.utf8_left > 0 {
            if byte & 0xC0 == 0x80 {
                self.utf8 = (self.utf8 << 6) | u32::from(byte & 0x3F);
                self.utf8_left -= 1;
                if self.utf8_left == 0 {
                    screen.put(char::from_u32(self.utf8).unwrap_or('\u{FFFD}'));
                }
                return;
            }
            // A sequence cut short shows as one replacement, then the byte is read afresh.
            self.utf8_left = 0;
            screen.put('\u{FFFD}');
        }
        match byte {
            0x08 => screen.backspace(),
            0x09 => screen.tab(),
            0x0A..=0x0C => screen.line_feed(),
            0x0D => screen.carriage_return(),
            0x00..=0x1F | 0x7F => {}
            0x20..=0x7E => screen.put(char::from(byte)),
            0xC2..=0xDF => self.start_utf8(1, byte & 0x1F),
            0xE0..=0xEF => self.start_utf8(2, byte & 0x0F),
            0xF0..=0xF4 => self.start_utf8(3, byte & 0x07),
            _ => screen.put('\u{FFFD}'),
        }
    }

    fn start_utf8(&mut self, left: u8, bits: u8) {
        self.utf8_left = left;
        self.utf8 = u32::from(bits);
    }

    fn escape(&mut self, screen: &mut Screen, byte: u8) {
        self.state = State::Ground;
        match byte {
            b'[' => {
                self.params = [0; MAX_PARAMS];
                self.count = 0;
                self.has_digit = false;
                self.private = false;
                self.state = State::Csi;
            }
            b']' | b'P' | b'X' | b'^' | b'_' => self.state = State::String,
            b'(' | b')' | b'*' | b'+' | b'#' | b'%' => self.state = State::Charset,
            b'7' => screen.save_cursor(),
            b'8' => screen.restore_cursor(),
            b'D' => screen.line_feed(),
            b'E' => {
                screen.carriage_return();
                screen.line_feed();
            }
            b'M' => screen.reverse_line_feed(),
            b'c' => screen.reset(),
            _ => {}
        }
    }

    fn csi(&mut self, screen: &mut Screen, byte: u8) {
        match byte {
            b'0'..=b'9' => {
                if self.count < MAX_PARAMS {
                    let digit = u16::from(byte - b'0');
                    let p = &mut self.params[self.count];
                    *p = p.saturating_mul(10).saturating_add(digit);
                }
                self.has_digit = true;
            }
            b';' | b':' => {
                self.count += 1;
                self.has_digit = false;
            }
            b'?' | b'>' | b'=' | b'<' => self.private = true,
            // Intermediate bytes: none of the sequences here use one.
            0x20..=0x2F => {}
            0x40..=0x7E => {
                if self.has_digit || self.count > 0 {
                    self.count += 1;
                }
                self.count = self.count.min(MAX_PARAMS);
                self.state = State::Ground;
                self.dispatch(screen, byte);
            }
            // C0 controls inside a sequence act as they would outside it.
            0x08 => screen.backspace(),
            0x0D => screen.carriage_return(),
            0x0A..=0x0C => screen.line_feed(),
            _ => {}
        }
    }

    /// Parameter `index`, or `default` when it is missing or 0.
    fn param(&self, index: usize, default: u16) -> u16 {
        match self.params[..self.count].get(index) {
            Some(&value) if value != 0 => value,
            _ => default,
        }
    }

    fn n(&self) -> usize {
        usize::from(self.param(0, 1))
    }

    fn dispatch(&mut self, screen: &mut Screen, byte: u8) {
        if self.private {
            if self.params[..self.count].contains(&25) {
                match byte {
                    b'h' => screen.set_cursor_visible(true),
                    b'l' => screen.set_cursor_visible(false),
                    _ => {}
                }
            }
            return;
        }
        match byte {
            b'A' => screen.cursor_up(self.n()),
            b'B' | b'e' => screen.cursor_down(self.n()),
            b'C' | b'a' => screen.cursor_forward(self.n()),
            b'D' => screen.cursor_back(self.n()),
            b'E' => {
                screen.cursor_down(self.n());
                screen.carriage_return();
            }
            b'F' => {
                screen.cursor_up(self.n());
                screen.carriage_return();
            }
            b'G' | b'`' => screen.cursor_to_col(self.n() - 1),
            b'd' => screen.cursor_to_row(self.n() - 1),
            b'H' | b'f' => screen.cursor_to(
                usize::from(self.param(0, 1)) - 1,
                usize::from(self.param(1, 1)) - 1,
            ),
            b'J' => screen.erase_in_display(self.params[0]),
            b'K' => screen.erase_in_line(self.params[0]),
            b'X' => screen.erase_chars(self.n()),
            b'P' => screen.delete_chars(self.n()),
            b'@' => screen.insert_chars(self.n()),
            b'L' => screen.insert_lines(self.n()),
            b'M' => screen.delete_lines(self.n()),
            b's' => screen.save_cursor(),
            b'u' => screen.restore_cursor(),
            b'm' => self.sgr(screen),
            _ => {}
        }
    }

    fn sgr(&self, screen: &mut Screen) {
        let mut attr = screen.attr();
        if self.count == 0 {
            screen.set_attr(Attr::DEFAULT);
            return;
        }
        let mut index = 0;
        while index < self.count {
            let p = self.params[index];
            match p {
                0 => attr = Attr::DEFAULT,
                1 => attr.bold = true,
                22 => attr.bold = false,
                7 => attr.inverse = true,
                27 => attr.inverse = false,
                30..=37 => attr.fg = Color::Ansi((p - 30) as u8),
                39 => attr.fg = Color::Default,
                40..=47 => attr.bg = Color::Ansi((p - 40) as u8),
                49 => attr.bg = Color::Default,
                90..=97 => attr.fg = Color::Ansi((p - 90 + 8) as u8),
                100..=107 => attr.bg = Color::Ansi((p - 100 + 8) as u8),
                // 256-colour and true-colour forms: skip their arguments.
                38 | 48 => {
                    index += match self.params[..self.count].get(index + 1) {
                        Some(5) => 2,
                        Some(2) => 4,
                        _ => 0,
                    };
                }
                _ => {}
            }
            index += 1;
        }
        screen.set_attr(attr);
    }
}
