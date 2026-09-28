//! Window wire types (configure and title).

use crate::geometry::{Scale120, Size};
use crate::ids::{Serial, WindowId};
use crate::limits::{MAX_OUTSTANDING_CONFIGURES, MAX_SURFACE_EXTENT, MAX_TITLE_BYTES};
use crate::protocol::{Event, ProtocolError};

/// Per-connection serial source shared by configures and input events.
///
/// Serials start at 1, increase by one, and skip 0 on wrap (wire C3), so `0` always means
/// "no serial" on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SerialMinter {
    next: u32,
}

impl Default for SerialMinter {
    fn default() -> Self {
        Self::new()
    }
}

impl SerialMinter {
    pub const fn new() -> Self {
        Self { next: 1 }
    }

    /// Minter whose next serial is `next` (0 is treated as 1).
    pub const fn starting_at(next: u32) -> Self {
        Self {
            next: if next == 0 { 1 } else { next },
        }
    }

    /// The serial the next [`Self::mint`] returns.
    pub const fn peek(&self) -> Serial {
        Serial(self.next)
    }

    pub fn mint(&mut self) -> Serial {
        let serial = Serial(self.next);
        self.next = match self.next.wrapping_add(1) {
            0 => 1,
            n => n,
        };
        serial
    }
}

/// Body of one `Configure` event (everything except window and serial).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowConfig {
    pub size: Size,
    pub scale: Scale120,
    pub decoration: DecorationMode,
    pub states: WindowStates,
    pub bounds: Size,
}

impl WindowConfig {
    /// M10 configure: scale 1.0, server decorations.
    pub const fn new(size: Size, states: WindowStates, bounds: Size) -> Self {
        Self {
            size,
            scale: Scale120::ONE,
            decoration: DecorationMode::Server,
            states,
            bounds,
        }
    }

    /// M10 vocabulary: extents ≤ `MAX_SURFACE_EXTENT` (`InvalidLayout`), scale 1.0
    /// (`InvalidScale`), server decorations and only `ACTIVATED` (`UnsupportedFeature`).
    pub fn validate_m10(&self) -> Result<(), ProtocolError> {
        let within = |s: Size| s.width <= MAX_SURFACE_EXTENT && s.height <= MAX_SURFACE_EXTENT;
        if !within(self.size) || !within(self.bounds) {
            return Err(ProtocolError::InvalidLayout);
        }
        if self.scale != Scale120::ONE {
            return Err(ProtocolError::InvalidScale);
        }
        if self.decoration != DecorationMode::Server
            || self.states.bits() & !WindowStates::ACTIVATED != 0
        {
            return Err(ProtocolError::UnsupportedFeature);
        }
        Ok(())
    }

    pub fn event(&self, window: WindowId, serial: Serial) -> Event {
        Event::Configure {
            window,
            serial,
            size: self.size,
            scale: self.scale,
            decoration: self.decoration,
            states: self.states,
            bounds: self.bounds,
        }
    }
}

/// Configure/ack state machine for one window.
///
/// Outstanding configures are kept oldest first. Acking serial `s` consumes `s` and every
/// older outstanding configure; each serial can be acknowledged at most once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigureState {
    outstanding: [Option<(Serial, WindowConfig)>; MAX_OUTSTANDING_CONFIGURES],
    len: usize,
    acked: Option<(Serial, WindowConfig)>,
}

impl Default for ConfigureState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigureState {
    pub const fn new() -> Self {
        Self {
            outstanding: [None; MAX_OUTSTANDING_CONFIGURES],
            len: 0,
            acked: None,
        }
    }

    /// Mints a serial and records `config` as outstanding. Fails without consuming a serial:
    /// `validate_m10` errors, or `LimitExceeded` when `MAX_OUTSTANDING_CONFIGURES` are
    /// outstanding.
    pub fn send(
        &mut self,
        minter: &mut SerialMinter,
        config: WindowConfig,
    ) -> Result<Serial, ProtocolError> {
        config.validate_m10()?;
        if self.len == MAX_OUTSTANDING_CONFIGURES {
            return Err(ProtocolError::LimitExceeded);
        }
        let serial = minter.mint();
        self.outstanding[self.len] = Some((serial, config));
        self.len += 1;
        Ok(serial)
    }

    fn position(&self, serial: Serial) -> Option<usize> {
        self.outstanding[..self.len]
            .iter()
            .position(|entry| matches!(entry, Some((s, _)) if *s == serial))
    }

    /// `Ok` iff [`Self::ack`] would succeed; never mutates.
    pub fn check_ack(&self, serial: Serial) -> Result<(), ProtocolError> {
        self.position(serial)
            .map(|_| ())
            .ok_or(ProtocolError::SerialMismatch)
    }

    /// Unknown, already-acked or superseded serial → `SerialMismatch` (state unchanged).
    pub fn ack(&mut self, serial: Serial) -> Result<WindowConfig, ProtocolError> {
        let index = self.position(serial).ok_or(ProtocolError::SerialMismatch)?;
        let (_, config) = self.outstanding[index].ok_or(ProtocolError::SerialMismatch)?;
        let consumed = index + 1;
        for i in 0..MAX_OUTSTANDING_CONFIGURES {
            self.outstanding[i] = if i + consumed < self.len {
                self.outstanding[i + consumed]
            } else {
                None
            };
        }
        self.len -= consumed;
        self.acked = Some((serial, config));
        Ok(config)
    }

    /// True once any configure has been acknowledged.
    pub fn is_configured(&self) -> bool {
        self.acked.is_some()
    }

    pub fn acked(&self) -> Option<(Serial, WindowConfig)> {
        self.acked
    }

    pub fn outstanding_len(&self) -> usize {
        self.len
    }

    /// Most recently sent outstanding configure (for compositor coalescing).
    pub fn last_sent(&self) -> Option<(Serial, WindowConfig)> {
        if self.len == 0 {
            None
        } else {
            self.outstanding[self.len - 1]
        }
    }
}

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

#[cfg(test)]
mod tests;
