//! The terminal's state: the screen, the parser that writes the stream's output onto it, the
//! line editor that turns keys into input, and the input waiting to go to the console stream.

use clean_slate_graphics::input::{KeyUsage, Modifiers};

use crate::keys::{self, Action};
use crate::line::{Key, LineEditor, Sink};
use crate::screen::{Screen, ROWS};
use crate::vt::Parser;

/// Input bytes held for the console stream before more are dropped.
pub const INPUT_CAPACITY: usize = 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TerminalStats {
    pub output_bytes: u64,
    pub input_bytes: u64,
    pub input_dropped: u64,
}

pub struct Terminal {
    screen: Screen,
    parser: Parser,
    editor: LineEditor,
    focused: bool,
    /// The compositor sends text events (#309), so printable keys are not mapped here.
    text_events: bool,
    input: [u8; INPUT_CAPACITY],
    input_len: usize,
    end_of_input: bool,
    stats: TerminalStats,
}

impl Default for Terminal {
    fn default() -> Self {
        Self::new()
    }
}

/// The editor's effects: echo onto the screen, input into the queue.
struct Effects<'a> {
    screen: &'a mut Screen,
    parser: &'a mut Parser,
    input: &'a mut [u8; INPUT_CAPACITY],
    input_len: &'a mut usize,
    end_of_input: &'a mut bool,
    stats: &'a mut TerminalStats,
}

impl Sink for Effects<'_> {
    fn echo(&mut self, bytes: &[u8]) {
        self.parser.feed(self.screen, bytes);
    }

    fn send(&mut self, bytes: &[u8]) {
        let room = INPUT_CAPACITY - *self.input_len;
        let taken = bytes.len().min(room);
        self.input[*self.input_len..*self.input_len + taken].copy_from_slice(&bytes[..taken]);
        *self.input_len += taken;
        self.stats.input_bytes += taken as u64;
        self.stats.input_dropped += (bytes.len() - taken) as u64;
    }

    fn end(&mut self) {
        *self.end_of_input = true;
    }
}

impl Terminal {
    pub const fn new() -> Self {
        Self {
            screen: Screen::new(),
            parser: Parser::new(),
            editor: LineEditor::new(),
            focused: false,
            text_events: false,
            input: [0; INPUT_CAPACITY],
            input_len: 0,
            end_of_input: false,
            stats: TerminalStats {
                output_bytes: 0,
                input_bytes: 0,
                input_dropped: 0,
            },
        }
    }

    pub const fn screen(&self) -> &Screen {
        &self.screen
    }

    pub fn screen_mut(&mut self) -> &mut Screen {
        &mut self.screen
    }

    pub const fn editor(&self) -> &LineEditor {
        &self.editor
    }

    pub const fn stats(&self) -> TerminalStats {
        self.stats
    }

    pub const fn focused(&self) -> bool {
        self.focused
    }

    pub fn set_focused(&mut self, focused: bool) {
        if focused != self.focused {
            self.focused = focused;
            // The cursor changes shape.
            self.screen.touch_all();
        }
    }

    pub const fn text_events(&self) -> bool {
        self.text_events
    }

    /// Whether printable keys arrive as the compositor's text events.
    pub fn set_text_events(&mut self, on: bool) {
        self.text_events = on;
    }

    /// Output from the console stream. A bare `\n` also returns the cursor (a tty's `onlcr`):
    /// the Linux personality has no termios, so programs write plain newlines.
    pub fn output(&mut self, bytes: &[u8]) {
        self.stats.output_bytes += bytes.len() as u64;
        for line in bytes.split_inclusive(|&byte| byte == b'\n') {
            match line.split_last() {
                Some((b'\n', text)) => {
                    self.parser.feed(&mut self.screen, text);
                    self.parser.feed(&mut self.screen, b"\r\n");
                }
                _ => self.parser.feed(&mut self.screen, line),
            }
        }
    }

    fn edit(&mut self, key: Key) {
        self.screen.reset_view();
        let mut effects = Effects {
            screen: &mut self.screen,
            parser: &mut self.parser,
            input: &mut self.input,
            input_len: &mut self.input_len,
            end_of_input: &mut self.end_of_input,
            stats: &mut self.stats,
        };
        self.editor.key(key, &mut effects);
    }

    /// A key press, or a repeat of a held key.
    pub fn key(&mut self, usage: KeyUsage, modifiers: Modifiers) {
        match keys::action(usage, modifiers, self.text_events) {
            Some(Action::Edit(key)) => self.edit(key),
            Some(Action::ScrollBack) => self.screen.scroll_view_back(ROWS / 2),
            Some(Action::ScrollForward) => self.screen.scroll_view_forward(ROWS / 2),
            None => {}
        }
    }

    /// Typed text from the compositor's text event.
    pub fn text(&mut self, text: &str) {
        for ch in text.chars() {
            self.edit(Key::Char(ch));
        }
    }

    /// Input waiting for the console stream.
    pub fn pending_input(&self) -> &[u8] {
        &self.input[..self.input_len]
    }

    /// Whether an end of input waits to be sent after the pending bytes.
    pub const fn end_pending(&self) -> bool {
        self.end_of_input
    }

    /// Drops the first `count` pending bytes: the stream took them.
    pub fn consume_input(&mut self, count: usize) {
        let count = count.min(self.input_len);
        self.input.copy_within(count..self.input_len, 0);
        self.input_len -= count;
    }

    /// The end of input was sent.
    pub fn consume_end(&mut self) {
        self.end_of_input = false;
    }
}
