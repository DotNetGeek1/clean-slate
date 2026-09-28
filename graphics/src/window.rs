//! Window wire types (configure and title).

use crate::limits::MAX_TITLE_BYTES;
use crate::protocol::ProtocolError;

/// Window state bitset on `Configure`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowStates(u32);

impl WindowStates {
    pub const ACTIVATED: u32 = 1 << 0;
    pub const MAXIMIZED: u32 = 1 << 1;
    pub const MINIMIZED: u32 = 1 << 2;
    pub const FULLSCREEN: u32 = 1 << 3;
    pub const RESIZING: u32 = 1 << 4;
    pub const ALL: u32 = 0x1F;
    pub const EMPTY: Self = Self(0);

    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::ALL != 0 {
            None
        } else {
            Some(Self(bits))
        }
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn contains(self, mask: u32) -> bool {
        (self.0 & mask) == mask
    }
}

/// Server vs client decoration (Configure byte 26).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecorationMode {
    Server = 1,
    Client = 2,
}

impl DecorationMode {
    pub fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Server),
            2 => Some(Self::Client),
            _ => None,
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Valid `BeginResize` edge mask (§2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResizeEdges(u8);

impl ResizeEdges {
    pub const TOP: u8 = 1;
    pub const BOTTOM: u8 = 2;
    pub const LEFT: u8 = 4;
    pub const RIGHT: u8 = 8;

    pub fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            1 | 2 | 4 | 8 | 5 | 6 | 9 | 10 => Some(Self(raw)),
            _ => None,
        }
    }

    pub const fn bits(self) -> u8 {
        self.0
    }
}

/// UTF-8 title payload for `SetTitle` (at most [`MAX_TITLE_BYTES`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowTitle {
    bytes: [u8; MAX_TITLE_BYTES],
    len: u8,
}

impl WindowTitle {
    pub fn from_str_truncating(s: &str) -> Self {
        let mut end = s.len().min(MAX_TITLE_BYTES);
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        let mut bytes = [0u8; MAX_TITLE_BYTES];
        bytes[..end].copy_from_slice(&s.as_bytes()[..end]);
        Self {
            bytes,
            len: end as u8,
        }
    }

    pub fn from_wire(len: u8, bytes: &[u8; MAX_TITLE_BYTES]) -> Result<Self, ProtocolError> {
        if len as usize > MAX_TITLE_BYTES {
            return Err(ProtocolError::MalformedFrame);
        }
        if bytes[len as usize..].iter().any(|&b| b != 0) {
            return Err(ProtocolError::ReservedBitsSet);
        }
        core::str::from_utf8(&bytes[..len as usize]).map_err(|_| ProtocolError::MalformedFrame)?;
        Ok(Self { bytes: *bytes, len })
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len as usize]).unwrap_or("")
    }

    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn wire_bytes(&self) -> ([u8; MAX_TITLE_BYTES], u8) {
        (self.bytes, self.len)
    }
}
