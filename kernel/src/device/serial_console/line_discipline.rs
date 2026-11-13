//! Canonical-mode line discipline for the serial console (#218 S4).
//!
//! A pure state machine: bytes go in through [`LineDiscipline::feed`], echo comes out through
//! the caller's [`EchoSink`], and finished lines wait in a committed buffer until a reader takes
//! them with [`LineDiscipline::read`] and [`LineDiscipline::take_eof`]. Nothing here touches a
//! port. The rules and limits are documented in `docs/LINUX_PERSONALITY.md`, "Serial console
//! input (#218 S4)".

/// Bytes the edit line holds; a full line commits as this many bytes plus its `\n`.
const EDIT_CAPACITY: usize = 256;
/// Committed bytes waiting for a reader.
pub(crate) const COMMITTED_CAPACITY: usize = 1024;

const BACKSPACE: u8 = 0x08;
const LINE_FEED: u8 = b'\n';
const CARRIAGE_RETURN: u8 = b'\r';
const CTRL_D: u8 = 0x04;
const CTRL_U: u8 = 0x15;
const DELETE: u8 = 0x7F;

const ECHO_NEWLINE: &[u8] = b"\r\n";
const ECHO_ERASE: &[u8] = b"\x08 \x08";

/// Where echo goes; the kernel implementation writes it to the UART.
pub(crate) trait EchoSink {
    fn echo(&mut self, bytes: &[u8]);
}

/// How a finished edit line ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Terminator {
    /// CR or LF: the line is committed with a trailing `\n`.
    Newline,
    /// Ctrl-D on a non-empty line: committed as typed, and a read stops after it.
    Push,
}

impl Terminator {
    const fn extra_bytes(self) -> usize {
        match self {
            Self::Newline => 1,
            Self::Push => 0,
        }
    }
}

/// Monotonic counters; none of them ever wraps back to a smaller value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct LineStats {
    /// Lines committed, by newline or by Ctrl-D on a non-empty line.
    pub(crate) lines: u32,
    /// End-of-file indications recorded (Ctrl-D on an empty edit line).
    pub(crate) eofs: u32,
    /// Lines whose commit had to wait for committed space.
    pub(crate) deferred: u32,
    /// Printable bytes refused because the edit line was full.
    pub(crate) edit_overflow: u32,
    /// Bytes refused because a finished line was waiting for committed space.
    pub(crate) dropped_while_deferred: u32,
    /// Ctrl-D on an empty line refused because an earlier end-of-file was still unread.
    pub(crate) eof_dropped: u32,
    /// Control bytes with no meaning in canonical mode, and bytes outside printable ASCII.
    pub(crate) control_dropped: u32,
}

pub(crate) struct LineDiscipline {
    edit: [u8; EDIT_CAPACITY],
    edit_len: usize,
    /// The edit line is finished but did not fit; it is committed as soon as a read makes room,
    /// and every byte received until then is refused.
    deferred: Option<Terminator>,
    ring: [u8; COMMITTED_CAPACITY],
    head: usize,
    len: usize,
    /// Bit `i` set: a Ctrl-D line ends after ring slot `i`, so a read stops there.
    push_ends: [u8; COMMITTED_CAPACITY / 8],
    /// Committed bytes ahead of the unread end-of-file, if there is one.
    eof_after: Option<usize>,
    /// A line was committed or an end-of-file recorded since the last [`Self::take_wake`].
    wake: bool,
    stats: LineStats,
}

impl LineDiscipline {
    pub(crate) const fn new() -> Self {
        Self {
            edit: [0; EDIT_CAPACITY],
            edit_len: 0,
            deferred: None,
            ring: [0; COMMITTED_CAPACITY],
            head: 0,
            len: 0,
            push_ends: [0; COMMITTED_CAPACITY / 8],
            eof_after: None,
            wake: false,
            stats: LineStats {
                lines: 0,
                eofs: 0,
                deferred: 0,
                edit_overflow: 0,
                dropped_while_deferred: 0,
                eof_dropped: 0,
                control_dropped: 0,
            },
        }
    }

    /// One received byte.
    pub(crate) fn feed(&mut self, byte: u8, echo: &mut impl EchoSink) {
        if self.deferred.is_some() {
            bump(&mut self.stats.dropped_while_deferred);
            return;
        }
        match byte {
            CARRIAGE_RETURN | LINE_FEED => {
                echo.echo(ECHO_NEWLINE);
                self.finish(Terminator::Newline);
            }
            BACKSPACE | DELETE => {
                if self.edit_len > 0 {
                    self.edit_len -= 1;
                    echo.echo(ECHO_ERASE);
                }
            }
            CTRL_U => {
                for _ in 0..self.edit_len {
                    echo.echo(ECHO_ERASE);
                }
                self.edit_len = 0;
            }
            CTRL_D if self.edit_len == 0 => self.record_eof(),
            CTRL_D => self.finish(Terminator::Push),
            b' '..=b'~' => {
                if self.edit_len == EDIT_CAPACITY {
                    bump(&mut self.stats.edit_overflow);
                    return;
                }
                self.edit[self.edit_len] = byte;
                self.edit_len += 1;
                echo.echo(&[byte]);
            }
            _ => bump(&mut self.stats.control_dropped),
        }
    }

    /// Copies committed bytes into `out`, stopping after a `\n`, at the end of a Ctrl-D line,
    /// and before an unread end-of-file. Returns how many were copied; 0 when `out` is empty,
    /// when nothing is committed, or when the end-of-file is next (see [`Self::take_eof`]).
    pub(crate) fn read(&mut self, out: &mut [u8]) -> usize {
        let available = self.eof_after.unwrap_or(self.len);
        let mut copied = 0;
        while copied < out.len() && copied < available {
            let slot = self.head;
            let byte = self.ring[slot];
            out[copied] = byte;
            copied += 1;
            self.head = (self.head + 1) % COMMITTED_CAPACITY;
            self.len -= 1;
            let pushed = self.take_push_end(slot);
            if byte == LINE_FEED || pushed {
                break;
            }
        }
        if let Some(ahead) = self.eof_after.as_mut() {
            *ahead -= copied;
        }
        if copied > 0 {
            self.commit_deferred();
        }
        copied
    }

    /// Whether a reader has nothing to take: no committed bytes ahead of an end-of-file, and no
    /// end-of-file next.
    pub(crate) fn would_block(&self) -> bool {
        self.eof_after.unwrap_or(self.len) == 0 && self.eof_after != Some(0)
    }

    /// Consumes the end-of-file if it is next. Committed bytes typed before it are read first.
    pub(crate) fn take_eof(&mut self) -> bool {
        if self.eof_after != Some(0) {
            return false;
        }
        self.eof_after = None;
        true
    }

    /// Whether a line was committed or an end-of-file recorded since the last call.
    pub(crate) fn take_wake(&mut self) -> bool {
        core::mem::take(&mut self.wake)
    }

    pub(crate) const fn stats(&self) -> LineStats {
        self.stats
    }

    /// Committed bytes waiting for a reader.
    pub(crate) const fn committed_len(&self) -> usize {
        self.len
    }

    /// Whether a finished line is waiting for committed space.
    pub(crate) const fn has_deferred_line(&self) -> bool {
        self.deferred.is_some()
    }

    fn finish(&mut self, terminator: Terminator) {
        self.deferred = Some(terminator);
        if !self.commit_deferred() {
            bump(&mut self.stats.deferred);
        }
    }

    /// Commits the deferred line if it fits; returns whether it did (or there was none).
    fn commit_deferred(&mut self) -> bool {
        let Some(terminator) = self.deferred else {
            return true;
        };
        if COMMITTED_CAPACITY - self.len < self.edit_len + terminator.extra_bytes() {
            return false;
        }
        for index in 0..self.edit_len {
            self.push_committed(self.edit[index]);
        }
        match terminator {
            Terminator::Newline => self.push_committed(LINE_FEED),
            Terminator::Push => {
                let last = (self.head + self.len - 1) % COMMITTED_CAPACITY;
                self.push_ends[last / 8] |= 1 << (last % 8);
            }
        }
        self.edit_len = 0;
        self.deferred = None;
        self.wake = true;
        bump(&mut self.stats.lines);
        true
    }

    fn push_committed(&mut self, byte: u8) {
        let slot = (self.head + self.len) % COMMITTED_CAPACITY;
        self.ring[slot] = byte;
        self.len += 1;
    }

    fn take_push_end(&mut self, slot: usize) -> bool {
        let mask = 1 << (slot % 8);
        let was_set = self.push_ends[slot / 8] & mask != 0;
        self.push_ends[slot / 8] &= !mask;
        was_set
    }

    fn record_eof(&mut self) {
        if self.eof_after.is_some() {
            bump(&mut self.stats.eof_dropped);
            return;
        }
        self.eof_after = Some(self.len);
        self.wake = true;
        bump(&mut self.stats.eofs);
    }
}

fn bump(counter: &mut u32) {
    *counter = counter.saturating_add(1);
}

#[cfg(test)]
mod tests;
