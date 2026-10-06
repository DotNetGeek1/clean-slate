//! Fixed-capacity ASCII strings for labels built at runtime (no allocator in CPL3).

use core::fmt;

/// Up to `N` bytes of ASCII text. Writes past capacity are dropped, never an error, so a
/// formatted label truncates instead of failing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Line<N> {
    /// Empty line.
    pub const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    /// Text so far.
    pub fn as_str(&self) -> &str {
        // Only printable ASCII is ever stored (see `push`).
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }

    /// Stored bytes.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// True when nothing is stored.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// True when another byte would be dropped.
    pub const fn is_full(&self) -> bool {
        self.len == N
    }

    /// Appends one printable ASCII byte; `false` (and no change) when full or not printable.
    pub fn push(&mut self, byte: u8) -> bool {
        if self.len == N || !(0x20..0x7f).contains(&byte) {
            return false;
        }
        self.bytes[self.len] = byte;
        self.len += 1;
        true
    }

    /// Removes the last byte; `false` when empty.
    pub fn pop(&mut self) -> bool {
        if self.len == 0 {
            return false;
        }
        self.len -= 1;
        self.bytes[self.len] = 0;
        true
    }

    /// Removes everything.
    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

impl<const N: usize> Default for Line<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> fmt::Write for Line<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            if !self.push(byte) {
                break;
            }
        }
        Ok(())
    }
}

/// Formats `args` into a fresh line.
pub fn format<const N: usize>(args: fmt::Arguments<'_>) -> Line<N> {
    let mut line = Line::new();
    let _ = fmt::Write::write_fmt(&mut line, args);
    line
}
