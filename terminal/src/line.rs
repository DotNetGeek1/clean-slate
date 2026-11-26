//! The terminal's line editor: canonical-mode input, as the kernel's serial line discipline does
//! it for the serial console.
//!
//! The Linux personality has no termios and no signals yet (`TCGETS` is `ENOTTY`), so `ash`
//! reads plain lines and never echoes. The terminal edits a line locally, echoes it onto its own
//! screen, and sends it to the console stream when it is finished:
//!
//! | Key | Effect |
//! |-----|--------|
//! | text | inserted at the edit point |
//! | Enter | the line and `\n` are sent; a non-empty line goes into the history |
//! | Backspace, Delete | the character before, or at, the edit point is removed |
//! | Left, Right, Home, End | move the edit point |
//! | Up, Down | step through the last [`HISTORY`] lines sent |
//! | Ctrl-U | the line is cleared |
//! | Ctrl-C | the line is dropped, `^C` echoed and a bare `\n` sent, so the shell prompts again (there is no signal to interrupt a command with) |
//! | Ctrl-D | on an empty line, the end of input; otherwise the line is sent without a newline |
//!
//! Echo uses only `BS`, printable bytes and `CR LF`, so it works on any screen. An edit line
//! longer than a screen row does not redraw across the wrap.

/// Characters one edit line holds.
pub const LINE_CAPACITY: usize = 255;
/// Lines kept for Up and Down.
pub const HISTORY: usize = 8;

/// One key, as the line editor sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Enter,
    Backspace,
    Delete,
    Left,
    Right,
    Home,
    End,
    Up,
    Down,
    /// Ctrl and a letter, as the letter in lower case.
    Ctrl(char),
}

/// Where the editor's effects go.
pub trait Sink {
    /// Bytes to show on the terminal's own screen.
    fn echo(&mut self, bytes: &[u8]);
    /// Bytes for the console stream.
    fn send(&mut self, bytes: &[u8]);
    /// The end of input (Ctrl-D on an empty line).
    fn end(&mut self);
}

#[derive(Clone, Copy)]
struct Line {
    chars: [char; LINE_CAPACITY],
    len: usize,
}

impl Line {
    const EMPTY: Self = Self {
        chars: ['\0'; LINE_CAPACITY],
        len: 0,
    };

    fn as_slice(&self) -> &[char] {
        &self.chars[..self.len]
    }
}

pub struct LineEditor {
    line: Line,
    /// The edit point, `0..=line.len`.
    at: usize,
    history: [Line; HISTORY],
    /// Lines in `history`, newest at `history_len - 1`.
    history_len: usize,
    /// While stepping through the history: the entry shown, counted back from the newest.
    browsing: Option<usize>,
    /// The line being typed when browsing started, shown again past the newest entry.
    draft: Line,
}

impl Default for LineEditor {
    fn default() -> Self {
        Self::new()
    }
}

fn echo_char(sink: &mut dyn Sink, ch: char) {
    let mut utf8 = [0u8; 4];
    sink.echo(ch.encode_utf8(&mut utf8).as_bytes());
}

fn echo_chars(sink: &mut dyn Sink, chars: &[char]) {
    for &ch in chars {
        echo_char(sink, ch);
    }
}

fn echo_repeat(sink: &mut dyn Sink, byte: u8, count: usize) {
    for _ in 0..count {
        sink.echo(&[byte]);
    }
}

fn send_chars(sink: &mut dyn Sink, chars: &[char]) {
    let mut buffer = [0u8; 64];
    let mut len = 0;
    for &ch in chars {
        if len + 4 > buffer.len() {
            sink.send(&buffer[..len]);
            len = 0;
        }
        len += ch.encode_utf8(&mut buffer[len..]).len();
    }
    if len > 0 {
        sink.send(&buffer[..len]);
    }
}

impl LineEditor {
    pub const fn new() -> Self {
        Self {
            line: Line::EMPTY,
            at: 0,
            history: [Line::EMPTY; HISTORY],
            history_len: 0,
            browsing: None,
            draft: Line::EMPTY,
        }
    }

    /// The line being edited.
    pub fn line(&self) -> &[char] {
        self.line.as_slice()
    }

    /// The edit point.
    pub const fn edit_point(&self) -> usize {
        self.at
    }

    pub fn key(&mut self, key: Key, sink: &mut dyn Sink) {
        match key {
            Key::Char(ch) if !ch.is_control() => self.insert(ch, sink),
            Key::Char(_) => {}
            Key::Enter => {
                echo_chars(sink, &self.line.as_slice()[self.at..]);
                sink.echo(b"\r\n");
                send_chars(sink, self.line.as_slice());
                sink.send(b"\n");
                self.remember();
                self.clear_line();
            }
            Key::Backspace if self.at > 0 => {
                self.at -= 1;
                sink.echo(b"\x08");
                self.remove_at_point(sink);
            }
            Key::Delete if self.at < self.line.len => self.remove_at_point(sink),
            Key::Backspace | Key::Delete => {}
            Key::Left if self.at > 0 => {
                self.at -= 1;
                sink.echo(b"\x08");
            }
            Key::Right if self.at < self.line.len => {
                echo_char(sink, self.line.chars[self.at]);
                self.at += 1;
            }
            Key::Left | Key::Right => {}
            Key::Home => {
                echo_repeat(sink, 0x08, self.at);
                self.at = 0;
            }
            Key::End => {
                echo_chars(sink, &self.line.as_slice()[self.at..]);
                self.at = self.line.len;
            }
            Key::Up => self.browse_older(sink),
            Key::Down => self.browse_newer(sink),
            Key::Ctrl('u') => {
                self.replace(Line::EMPTY, sink);
                self.browsing = None;
            }
            Key::Ctrl('c') => {
                echo_chars(sink, &self.line.as_slice()[self.at..]);
                sink.echo(b"^C\r\n");
                sink.send(b"\n");
                self.clear_line();
            }
            Key::Ctrl('d') => {
                if self.line.len == 0 {
                    sink.end();
                } else {
                    send_chars(sink, self.line.as_slice());
                    echo_chars(sink, &self.line.as_slice()[self.at..]);
                    self.remember();
                    self.clear_line();
                }
            }
            Key::Ctrl(_) => {}
        }
    }

    fn clear_line(&mut self) {
        self.line = Line::EMPTY;
        self.at = 0;
        self.browsing = None;
    }

    fn insert(&mut self, ch: char, sink: &mut dyn Sink) {
        if self.line.len == LINE_CAPACITY {
            return;
        }
        let (at, len) = (self.at, self.line.len);
        self.line.chars.copy_within(at..len, at + 1);
        self.line.chars[at] = ch;
        self.line.len += 1;
        self.at += 1;
        let tail = len - at;
        echo_chars(sink, &self.line.chars[at..=len]);
        echo_repeat(sink, 0x08, tail);
    }

    /// Removes the character at the edit point and redraws the rest of the line.
    fn remove_at_point(&mut self, sink: &mut dyn Sink) {
        let (at, len) = (self.at, self.line.len);
        self.line.chars.copy_within(at + 1..len, at);
        self.line.len -= 1;
        let tail = self.line.len - at;
        echo_chars(sink, &self.line.chars[at..self.line.len]);
        sink.echo(b" ");
        echo_repeat(sink, 0x08, tail + 1);
    }

    /// Replaces the shown line with `line`, the edit point at its end.
    fn replace(&mut self, line: Line, sink: &mut dyn Sink) {
        let old = self.line.len;
        echo_repeat(sink, 0x08, self.at);
        echo_repeat(sink, b' ', old);
        echo_repeat(sink, 0x08, old);
        self.line = line;
        self.at = line.len;
        echo_chars(sink, line.as_slice());
    }

    fn remember(&mut self) {
        if self.line.len == 0 {
            return;
        }
        let newest = self.history_len.checked_sub(1).map(|i| &self.history[i]);
        if newest.is_some_and(|newest| newest.as_slice() == self.line.as_slice()) {
            return;
        }
        if self.history_len == HISTORY {
            self.history.copy_within(1.., 0);
            self.history_len -= 1;
        }
        self.history[self.history_len] = self.line;
        self.history_len += 1;
    }

    fn browse_older(&mut self, sink: &mut dyn Sink) {
        let back = match self.browsing {
            None if self.history_len > 0 => {
                self.draft = self.line;
                0
            }
            Some(back) if back + 1 < self.history_len => back + 1,
            _ => return,
        };
        self.browsing = Some(back);
        let line = self.history[self.history_len - 1 - back];
        self.replace(line, sink);
    }

    fn browse_newer(&mut self, sink: &mut dyn Sink) {
        match self.browsing {
            Some(0) => {
                self.browsing = None;
                let draft = self.draft;
                self.replace(draft, sink);
            }
            Some(back) => {
                self.browsing = Some(back - 1);
                let line = self.history[self.history_len - back];
                self.replace(line, sink);
            }
            None => {}
        }
    }
}
