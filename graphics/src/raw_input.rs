//! Kernel → compositor raw input records (32 bytes, §6).
//!
//! ```text
//! [0..8]   seq (u64)
//! [8..16]  time_ns (u64)
//! [16..20] device (InputDeviceId)
//! [20]     kind (u8 tag)
//! [21..24] pad (0)
//! [24..32] payload (per kind)
//! ```
//!
//! # Kernel-side semantics (§6.2, binding on #113)
//!
//! **`seq`**
//! - Assigned when a record is placed in the queue, including synthesised [`RawInputKind::Overflow`]
//!   records.
//! - Starts at 1 and increases by exactly 1 per queued record, per boot.
//! - Dropped records get no seq, so the consumer always observes contiguous seqs across batches.
//! - A coalesced [`RawInputKind::RelMotion`] keeps the seq of the tail record it merged into.
//!
//! **`time_ns`**
//! - `time::monotonic_ns()` at enqueue, non-decreasing across records.
//! - A coalesced `RelMotion` updates `time_ns` to the latest merged event.
//!
//! **`device`**
//! - [`RawInputKind::Key`] records carry the keyboard device ([`crate::ids::KEYBOARD_INDEX`]).
//! - `RelMotion`, [`RawInputKind::Button`], and [`RawInputKind::Wheel`] carry the mouse
//!   ([`crate::ids::MOUSE_INDEX`]).
//! - The generation bumps on controller reset.
//! - `Overflow` carries the device of the **first** record dropped since the previous `Overflow`.
//! - The codec does not enforce the index-to-kind mapping.
//!
//! **Signs**
//! - `dx > 0` means right and `dy > 0` means **down** (screen convention); the PS/2 Y axis is
//!   negated by the driver.
//! - `vertical > 0` means scroll **down** (towards the user) and `horizontal > 0` means scroll
//!   right. The M11 evdev shim negates `vertical` for `REL_WHEEL`.
//! - 120 = one detent ([`crate::input::AxisValue120`]).
//!
//! **Coalescing**
//! - When the queue length is ≥ [`crate::limits::RAW_INPUT_COALESCE_HIGH_WATER`] (96), a new
//!   `RelMotion` whose unread tail record is a `RelMotion` from the same device is merged into
//!   that tail with `i32::saturating_add` per axis. Nothing else is ever coalesced.
//!
//! **Drops and `Overflow` ordering (C5)**
//! - When a record cannot be queued (full and not mergeable), it is dropped, `pending_dropped` is
//!   incremented (saturating), and the first dropped device is remembered if this is the first drop
//!   since the last `Overflow`.
//! - `Overflow { dropped }` is materialised **in order**: at the first moment a slot is free, either
//!   at the next enqueue attempt (before that record) or inside `READ_BATCH` once queued records
//!   have been copied out, if the caller's array has room.
//! - Invariant: every record before the `Overflow` happened before the first loss, and every record
//!   after it happened after the last loss. The consumer resets key, button and modifier state on
//!   `Overflow` and then continues.
//!
//! **Key domain**
//! - The driver emits `Key` `Pressed` only on released→pressed per usage (typematic suppressed).
//! - `Released` only on pressed→released.
//! - Scancodes with no page-0x07 mapping are dropped by the driver (driver statistic, not
//!   `Overflow`).

use crate::ids::InputDeviceId;
use crate::input::{AxisValue120, KeyState, KeyUsage, PointerButton};

/// Fixed size of one queued raw-input record (§6.1).
pub const RAW_INPUT_RECORD_BYTES: usize = 32;

const _: () = assert!(RAW_INPUT_RECORD_BYTES == 32);

/// One kernel raw-input queue entry (§6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawInputRecord {
    pub seq: u64,
    pub time_ns: u64,
    pub device: InputDeviceId,
    pub kind: RawInputKind,
}

/// Payload tag in byte 20 plus kind-specific fields (§6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawInputKind {
    Key {
        usage: KeyUsage,
        state: KeyState,
    },
    RelMotion {
        dx: i32,
        dy: i32,
    },
    Button {
        button: PointerButton,
        state: KeyState,
    },
    Wheel {
        vertical: AxisValue120,
        horizontal: AxisValue120,
    },
    Overflow {
        dropped: u32,
    },
}

impl RawInputKind {
    pub const fn tag(self) -> u8 {
        match self {
            Self::Key { .. } => 1,
            Self::RelMotion { .. } => 2,
            Self::Button { .. } => 3,
            Self::Wheel { .. } => 4,
            Self::Overflow { .. } => 5,
        }
    }

    fn decode_payload(bytes: &[u8], tag: u8) -> Result<Self, RawInputDecodeError> {
        match tag {
            1 => decode_key_payload(bytes),
            2 => decode_relmotion_payload(bytes),
            3 => decode_button_payload(bytes),
            4 => decode_wheel_payload(bytes),
            5 => decode_overflow_payload(bytes),
            _ => Err(RawInputDecodeError::UnknownKind),
        }
    }
}

/// Decode failure for [`RawInputRecord::decode`] (§6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawInputDecodeError {
    Truncated,
    ReservedBitsSet,
    UnknownKind,
    InvalidField,
}

impl RawInputRecord {
    pub fn encode(self) -> [u8; RAW_INPUT_RECORD_BYTES] {
        let mut out = [0u8; RAW_INPUT_RECORD_BYTES];
        write_u64_le(&mut out, 0, self.seq);
        write_u64_le(&mut out, 8, self.time_ns);
        write_u32_le(&mut out, 16, self.device.encode());
        out[20] = self.kind.tag();
        match self.kind {
            RawInputKind::Key { usage, state } => {
                write_u16_le(&mut out, 24, usage.0);
                out[26] = state.as_u8();
            }
            RawInputKind::RelMotion { dx, dy } => {
                write_i32_le(&mut out, 24, dx);
                write_i32_le(&mut out, 28, dy);
            }
            RawInputKind::Button { button, state } => {
                write_u16_le(&mut out, 24, button.as_u16());
                out[26] = state.as_u8();
            }
            RawInputKind::Wheel {
                vertical,
                horizontal,
            } => {
                write_i32_le(&mut out, 24, vertical.0);
                write_i32_le(&mut out, 28, horizontal.0);
            }
            RawInputKind::Overflow { dropped } => {
                write_u32_le(&mut out, 24, dropped);
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RawInputDecodeError> {
        if bytes.len() != RAW_INPUT_RECORD_BYTES {
            return Err(RawInputDecodeError::Truncated);
        }
        let seq = read_u64_le(bytes, 0);
        if seq == 0 {
            return Err(RawInputDecodeError::InvalidField);
        }
        let time_ns = read_u64_le(bytes, 8);
        let device = InputDeviceId::decode(read_u32_le(bytes, 16))
            .map_err(|_| RawInputDecodeError::InvalidField)?;
        let tag = bytes[20];
        if !matches!(tag, 1..=5) {
            return Err(RawInputDecodeError::UnknownKind);
        }
        if !check_range_zero(bytes, 21, 24) {
            return Err(RawInputDecodeError::ReservedBitsSet);
        }
        let kind = RawInputKind::decode_payload(bytes, tag)?;
        Ok(Self {
            seq,
            time_ns,
            device,
            kind,
        })
    }
}

fn decode_key_payload(bytes: &[u8]) -> Result<RawInputKind, RawInputDecodeError> {
    let usage = KeyUsage(read_u16_le(bytes, 24));
    if !usage.is_valid() {
        return Err(RawInputDecodeError::InvalidField);
    }
    let state = KeyState::from_u8(bytes[26]).ok_or(RawInputDecodeError::InvalidField)?;
    if bytes[27] != 0 || !check_range_zero(bytes, 28, 32) {
        return Err(RawInputDecodeError::ReservedBitsSet);
    }
    Ok(RawInputKind::Key { usage, state })
}

fn decode_relmotion_payload(bytes: &[u8]) -> Result<RawInputKind, RawInputDecodeError> {
    Ok(RawInputKind::RelMotion {
        dx: read_i32_le(bytes, 24),
        dy: read_i32_le(bytes, 28),
    })
}

fn decode_button_payload(bytes: &[u8]) -> Result<RawInputKind, RawInputDecodeError> {
    let button =
        PointerButton::from_u16(read_u16_le(bytes, 24)).ok_or(RawInputDecodeError::InvalidField)?;
    let state = KeyState::from_u8(bytes[26]).ok_or(RawInputDecodeError::InvalidField)?;
    if bytes[27] != 0 || !check_range_zero(bytes, 28, 32) {
        return Err(RawInputDecodeError::ReservedBitsSet);
    }
    Ok(RawInputKind::Button { button, state })
}

fn decode_wheel_payload(bytes: &[u8]) -> Result<RawInputKind, RawInputDecodeError> {
    Ok(RawInputKind::Wheel {
        vertical: AxisValue120(read_i32_le(bytes, 24)),
        horizontal: AxisValue120(read_i32_le(bytes, 28)),
    })
}

fn decode_overflow_payload(bytes: &[u8]) -> Result<RawInputKind, RawInputDecodeError> {
    let dropped = read_u32_le(bytes, 24);
    if dropped == 0 {
        return Err(RawInputDecodeError::InvalidField);
    }
    if !check_range_zero(bytes, 28, 32) {
        return Err(RawInputDecodeError::ReservedBitsSet);
    }
    Ok(RawInputKind::Overflow { dropped })
}

fn read_u16_le(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([bytes[off], bytes[off + 1]])
}

fn write_u16_le(out: &mut [u8], off: usize, v: u16) {
    out[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn read_u32_le(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

fn write_u32_le(out: &mut [u8], off: usize, v: u32) {
    out[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn read_u64_le(bytes: &[u8], off: usize) -> u64 {
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

fn write_u64_le(out: &mut [u8], off: usize, v: u64) {
    out[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn read_i32_le(bytes: &[u8], off: usize) -> i32 {
    i32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

fn write_i32_le(out: &mut [u8], off: usize, v: i32) {
    out[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn check_range_zero(bytes: &[u8], start: usize, end: usize) -> bool {
    bytes[start..end].iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_layout;
