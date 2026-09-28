//! Compositor protocol 1.0: fixed 64-byte frames (§1).
//!
//! Per-opcode body offset tables live in [`reference`]; [`frame_spec`] drives decode steps 4–6.

pub mod error;
pub mod event;
pub mod frame_spec;
pub mod reference;
pub mod request;

pub use error::{DisconnectReason, ProtocolError};
pub use event::Event;
pub use request::Request;

use crate::ids::{ObjectId, Serial};

/// Frame size in bytes (§1.1).
pub const FRAME_BYTES: usize = 64;
/// Header size in bytes (§1.2).
pub const HEADER_BYTES: usize = 12;
/// First body byte offset (§1.1).
pub const BODY_OFFSET: usize = 12;
/// Body size in bytes (§1.1).
pub const BODY_BYTES: usize = 52;
/// Negotiated major version (§1.1).
pub const PROTOCOL_MAJOR: u16 = 1;
/// Negotiated minor version (§1.1).
pub const PROTOCOL_MINOR: u16 = 0;

/// Server feature set for M10 (§1.1).
pub const M10_SERVER_FEATURES: Features = Features(0);

/// Wire header fields (§1.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub opcode: u16,
    pub flags: u8,
    pub tag: u32,
    pub object: u32,
}

/// Decoded message plus client tag (§1.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tagged<T> {
    pub tag: u32,
    pub message: T,
}

/// Decode failure with raw header echo (§1.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeError {
    pub code: ProtocolError,
    pub tag: u32,
    pub opcode: u16,
    pub object: u32,
}

/// Protocol version pair (§4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

/// Server version constant (§4).
pub const SERVER_VERSION: ProtocolVersion = ProtocolVersion {
    major: PROTOCOL_MAJOR,
    minor: PROTOCOL_MINOR,
};

/// Negotiated feature bitset (§5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Features(pub u64);

impl Features {
    /// Bits assigned in protocol 1.x (§5.2).
    pub const KNOWN: u64 = 0x3F;

    pub const fn bits(self) -> u64 {
        self.0
    }

    /// True when every bit set in `other` is also set in `self`.
    pub const fn contains(self, other: Features) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn intersection(self, other: Features) -> Features {
        Features(self.0 & other.0)
    }
}

// Request opcodes (§2.1). Body layouts: [`reference`](reference).
/// `Hello` (`0x0001`): see [`reference`] § Hello.
pub const OP_HELLO: u16 = 0x0001;
pub const OP_REGISTER_BUFFER: u16 = 0x0010;
pub const OP_UNREGISTER_BUFFER: u16 = 0x0011;
pub const OP_CREATE_SURFACE: u16 = 0x0020;
pub const OP_DESTROY_SURFACE: u16 = 0x0021;
pub const OP_ASSIGN_ROLE: u16 = 0x0022;
pub const OP_ATTACH: u16 = 0x0023;
pub const OP_DAMAGE: u16 = 0x0024;
pub const OP_SET_OPAQUE_REGION: u16 = 0x0025;
pub const OP_SET_INPUT_REGION: u16 = 0x0026;
pub const OP_COMMIT: u16 = 0x0027;
pub const OP_CREATE_WINDOW: u16 = 0x0030;
pub const OP_DESTROY_WINDOW: u16 = 0x0031;
pub const OP_SET_TITLE: u16 = 0x0032;
pub const OP_SET_SIZE_LIMITS: u16 = 0x0033;
pub const OP_SHOW: u16 = 0x0034;
pub const OP_HIDE: u16 = 0x0035;
pub const OP_BEGIN_MOVE: u16 = 0x0036;
pub const OP_BEGIN_RESIZE: u16 = 0x0037;
pub const OP_ACK_CONFIGURE: u16 = 0x0038;

// Event opcodes (§3.1)
pub const OP_WELCOME: u16 = 0x8001;
pub const OP_ERROR: u16 = 0x8002;
pub const OP_BUFFER_REGISTERED: u16 = 0x8010;
pub const OP_BUFFER_RELEASED: u16 = 0x8011;
pub const OP_BUFFER_UNREGISTERED: u16 = 0x8012;
pub const OP_SURFACE_CREATED: u16 = 0x8020;
pub const OP_FRAME_DONE: u16 = 0x8021;
pub const OP_WINDOW_CREATED: u16 = 0x8030;
pub const OP_CONFIGURE: u16 = 0x8031;
pub const OP_CLOSE_REQUESTED: u16 = 0x8032;
pub const OP_KEYBOARD_FOCUS: u16 = 0x8040;
pub const OP_KEY: u16 = 0x8041;
pub const OP_MODIFIERS_CHANGED: u16 = 0x8042;
pub const OP_POINTER_ENTER: u16 = 0x8050;
pub const OP_POINTER_LEAVE: u16 = 0x8051;
pub const OP_POINTER_MOTION: u16 = 0x8052;
pub const OP_POINTER_BUTTON: u16 = 0x8053;
pub const OP_POINTER_AXIS: u16 = 0x8054;
pub const OP_INPUT_RESET: u16 = 0x8060;

/// Version and feature negotiation (§4).
pub fn negotiate(
    client: ProtocolVersion,
    client_features: Features,
    server: ProtocolVersion,
    server_supported: Features,
) -> Result<(ProtocolVersion, Features), ProtocolError> {
    if client.major != server.major {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let minor = client.minor.min(server.minor);
    let features = client_features
        .intersection(server_supported)
        .intersection(Features(Features::KNOWN));
    Ok((
        ProtocolVersion {
            major: server.major,
            minor,
        },
        features,
    ))
}

pub(crate) fn read_u16_le(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([bytes[off], bytes[off + 1]])
}

pub(crate) fn write_u16_le(out: &mut [u8], off: usize, v: u16) {
    out[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

pub(crate) fn read_u32_le(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

pub(crate) fn write_u32_le(out: &mut [u8], off: usize, v: u32) {
    out[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

pub(crate) fn read_u64_le(bytes: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        bytes[off],
        bytes[off + 1],
        bytes[off + 2],
        bytes[off + 3],
        bytes[off + 4],
        bytes[off + 5],
        bytes[off + 6],
        bytes[off + 7],
    ])
}

pub(crate) fn write_u64_le(out: &mut [u8], off: usize, v: u64) {
    out[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

pub(crate) fn read_i32_le(bytes: &[u8], off: usize) -> i32 {
    i32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

pub(crate) fn write_i32_le(out: &mut [u8], off: usize, v: i32) {
    out[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

pub(crate) fn raw_header(bytes: &[u8]) -> (u16, u32, u32) {
    if bytes.len() >= HEADER_BYTES {
        (
            read_u16_le(bytes, 0),
            read_u32_le(bytes, 4),
            read_u32_le(bytes, 8),
        )
    } else {
        (0, 0, 0)
    }
}

pub(crate) fn decode_error(code: ProtocolError, bytes: &[u8]) -> DecodeError {
    let (opcode, tag, object) = raw_header(bytes);
    DecodeError {
        code,
        tag,
        opcode,
        object,
    }
}

pub(crate) fn check_frame_len(bytes: &[u8]) -> Result<(), DecodeError> {
    if bytes.len() != FRAME_BYTES {
        Err(decode_error(ProtocolError::MalformedFrame, bytes))
    } else {
        Ok(())
    }
}

pub(crate) fn check_header_reserved(bytes: &[u8]) -> Result<(), DecodeError> {
    if bytes[2] != 0 {
        return Err(decode_error(ProtocolError::ReservedBitsSet, bytes));
    }
    if bytes[3] != 0 {
        return Err(decode_error(ProtocolError::ReservedBitsSet, bytes));
    }
    Ok(())
}

pub(crate) fn check_range_zero(
    bytes: &[u8],
    start: usize,
    end: usize,
) -> Result<(), ProtocolError> {
    for &b in &bytes[start..end] {
        if b != 0 {
            return Err(ProtocolError::ReservedBitsSet);
        }
    }
    Ok(())
}

pub(crate) fn decode_bool(raw: u8) -> Result<bool, ProtocolError> {
    match raw {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ProtocolError::MalformedFrame),
    }
}

pub(crate) fn serial_required_request(raw: u32) -> Result<Serial, ProtocolError> {
    if raw == 0 {
        Err(ProtocolError::SerialMismatch)
    } else {
        Ok(Serial(raw))
    }
}

pub(crate) fn serial_required_event(raw: u32) -> Result<Serial, ProtocolError> {
    if raw == 0 {
        Err(ProtocolError::MalformedFrame)
    } else {
        Ok(Serial(raw))
    }
}

pub(crate) fn serial_optional(raw: u32) -> Option<Serial> {
    if raw == 0 {
        None
    } else {
        Some(Serial(raw))
    }
}

pub(crate) fn decode_object_required(raw: u32) -> Result<ObjectId, ProtocolError> {
    if raw == 0 {
        Err(ProtocolError::InvalidObject)
    } else {
        ObjectId::decode(raw).map_err(|_| ProtocolError::InvalidObject)
    }
}

pub(crate) fn decode_object_optional(raw: u32) -> Result<Option<ObjectId>, ProtocolError> {
    ObjectId::decode_optional(raw).map_err(|_| ProtocolError::InvalidObject)
}

pub(crate) fn object_must_be_zero(raw: u32) -> Result<(), ProtocolError> {
    if raw != 0 {
        Err(ProtocolError::ReservedBitsSet)
    } else {
        Ok(())
    }
}

pub(crate) use frame_spec::{run_decode_prelude, EVENT_SPECS, REQUEST_SPECS};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_layout;
#[cfg(test)]
mod tests_malformed;
