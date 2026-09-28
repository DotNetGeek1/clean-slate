//! Display syscall ABI wire types (`SYSCALL_NR_DISPLAY = 18`, §8).
//!
//! # Syscall convention (§7)
//!
//! See [`super`] and [`crate::abi::input`]: `rax` = 18, `rdi` subop, `rsi` capability handle,
//! `rdx`/`r10`/`r8`/`r9` arguments, `rax` out success or [`super::status`] sentinel. Non-blocking.
//!
//! # Presenter binding (§8.2)
//!
//! The first successful [`DISPLAY_SUBOP_MAP_SCANOUT`] binds the caller's holder as presenter;
//! [`DISPLAY_SUBOP_MAP_SCANOUT`], [`DISPLAY_SUBOP_PRESENT`], and [`DISPLAY_SUBOP_BIND_WAKE`] from
//! any other holder return [`DisplayError::NotPresenter`]. Binding is released only by process
//! teardown. `MAP_SCANOUT` is idempotent for a given buffer index.
//!
//! # Wake (§8.2)
//!
//! The bound work-set bit is signalled on every present completion (success or failure), every
//! backend state change (`ResetRequired`, back to `Idle` with a new epoch, or `Poisoned`), and every
//! epoch bump. The consumer calls [`DISPLAY_SUBOP_PRESENT_STATUS`] after each wake.
//!
//! # `PRESENT` evaluation order (§8.2)
//!
//! The first failure wins: length/pointer → capability auth → [`PresentRequest::decode`] → backend
//! presence/poison/reset → presenter binding → [`PresentRequest::validate`] → mapped buffer →
//! in-flight gate → accept (`present_seq += 1`).
//!
//! # Backend copy semantics (R8)
//!
//! Pixels outside the submitted damage keep their previously presented content on **every**
//! backend (not only GOP): undamaged regions must not flip stale content from another buffer.

use crate::geometry::{BufferRect, Scale120};
use crate::ids::OutputId;
use crate::limits::{MAX_PRESENT_DAMAGE_RECTS, SCANOUT_BUFFER_COUNT};
use crate::mode::DisplayMode;
use crate::pixel::PixelFormat;

use super::status::{
    STATUS_EACCES, STATUS_EAGAIN, STATUS_EBADF, STATUS_EIO, STATUS_ENODEV, STATUS_ENOTRECOVERABLE,
    STATUS_ERANGE, STATUS_ESTALE, STATUS_ETIMEDOUT,
};
use super::wire::{
    check_range_zero, read_u16_le, read_u32_le, read_u64_le, write_u16_le, write_u32_le,
    write_u64_le,
};

/// ABI version passed in `FIND_HANDLE` (`rdx`, §8.2).
pub const DISPLAY_ABI_VERSION: u64 = 1;

pub const DISPLAY_SUBOP_FIND_HANDLE: u64 = 1;
pub const DISPLAY_SUBOP_QUERY_MODE: u64 = 2;
pub const DISPLAY_SUBOP_MAP_SCANOUT: u64 = 3;
pub const DISPLAY_SUBOP_PRESENT: u64 = 4;
pub const DISPLAY_SUBOP_PRESENT_STATUS: u64 = 5;
pub const DISPLAY_SUBOP_BIND_WAKE: u64 = 6;

/// At most one in-flight present per backend (§8.2).
pub const MAX_PRESENTS_IN_FLIGHT: usize = 1;

pub const DISPLAY_MODE_INFO_BYTES: usize = 32;
pub const SCANOUT_MAPPING_BYTES: usize = 32;
pub const PRESENT_REQUEST_BYTES: usize = 136;
pub const PRESENT_STATUS_BYTES: usize = 40;

const _: () = assert!(PRESENT_REQUEST_BYTES == 8 + MAX_PRESENT_DAMAGE_RECTS * 8);

/// Display-side failure codes (§8.1).
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayError {
    NotPresenter = 1,
    StaleEpoch = 2,
    InvalidBuffer = 3,
    BufferBusy = 4,
    InvalidDamage = 5,
    ModeUnavailable = 6,
    DeviceTimeout = 7,
    ResetRequired = 8,
    Poisoned = 9,
}

impl DisplayError {
    pub const fn code(self) -> u16 {
        self as u16
    }

    pub fn from_code(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::NotPresenter),
            2 => Some(Self::StaleEpoch),
            3 => Some(Self::InvalidBuffer),
            4 => Some(Self::BufferBusy),
            5 => Some(Self::InvalidDamage),
            6 => Some(Self::ModeUnavailable),
            7 => Some(Self::DeviceTimeout),
            8 => Some(Self::ResetRequired),
            9 => Some(Self::Poisoned),
            _ => None,
        }
    }

    pub const fn status(self) -> u64 {
        match self {
            Self::NotPresenter => STATUS_EACCES,
            Self::StaleEpoch => STATUS_ESTALE,
            Self::InvalidBuffer => STATUS_EBADF,
            Self::BufferBusy => STATUS_EAGAIN,
            Self::InvalidDamage => STATUS_ERANGE,
            Self::ModeUnavailable => STATUS_ENODEV,
            Self::DeviceTimeout => STATUS_ETIMEDOUT,
            Self::ResetRequired => STATUS_EIO,
            Self::Poisoned => STATUS_ENOTRECOVERABLE,
        }
    }

    /// Lossy for shared capability statuses (`EACCES`, `ESTALE`).
    pub fn from_status(raw: u64) -> Option<Self> {
        match raw {
            STATUS_EACCES => Some(Self::NotPresenter),
            STATUS_ESTALE => Some(Self::StaleEpoch),
            STATUS_EBADF => Some(Self::InvalidBuffer),
            STATUS_EAGAIN => Some(Self::BufferBusy),
            STATUS_ERANGE => Some(Self::InvalidDamage),
            STATUS_ENODEV => Some(Self::ModeUnavailable),
            STATUS_ETIMEDOUT => Some(Self::DeviceTimeout),
            STATUS_EIO => Some(Self::ResetRequired),
            STATUS_ENOTRECOVERABLE => Some(Self::Poisoned),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayWireError {
    Malformed,
}

/// Output of `QUERY_MODE` (§8.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayModeInfo {
    pub output: OutputId,
    pub mode: DisplayMode,
    pub scanout_buffer_count: u8,
    pub max_present_damage_rects: u8,
}

impl DisplayModeInfo {
    pub fn encode(self) -> [u8; DISPLAY_MODE_INFO_BYTES] {
        let mut out = [0u8; DISPLAY_MODE_INFO_BYTES];
        write_u32_le(&mut out, 0, self.output.encode());
        write_u32_le(&mut out, 4, self.mode.width_px);
        write_u32_le(&mut out, 8, self.mode.height_px);
        write_u32_le(&mut out, 12, self.mode.stride_bytes);
        out[16] = self.mode.format as u8;
        write_u16_le(&mut out, 18, self.mode.scale.0);
        write_u32_le(&mut out, 20, self.mode.refresh_mhz);
        out[24] = self.scanout_buffer_count;
        out[25] = self.max_present_damage_rects;
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DisplayWireError> {
        if bytes.len() != DISPLAY_MODE_INFO_BYTES {
            return Err(DisplayWireError::Malformed);
        }
        if !check_range_zero(bytes, 17, 18) || !check_range_zero(bytes, 26, 32) {
            return Err(DisplayWireError::Malformed);
        }
        let output =
            OutputId::decode(read_u32_le(bytes, 0)).map_err(|_| DisplayWireError::Malformed)?;
        let format = PixelFormat::from_u8(bytes[16]).ok_or(DisplayWireError::Malformed)?;
        let scale = read_u16_le(bytes, 18);
        if scale == 0 {
            return Err(DisplayWireError::Malformed);
        }
        Ok(Self {
            output,
            mode: DisplayMode {
                width_px: read_u32_le(bytes, 4),
                height_px: read_u32_le(bytes, 8),
                stride_bytes: read_u32_le(bytes, 12),
                format,
                scale: Scale120(scale),
                refresh_mhz: read_u32_le(bytes, 20),
            },
            scanout_buffer_count: bytes[24],
            max_present_damage_rects: bytes[25],
        })
    }
}

/// Output of `MAP_SCANOUT` (§8.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanoutMapping {
    pub output: OutputId,
    pub buffer_index: u8,
    pub user_va: u64,
    pub byte_len: u64,
    pub stride_bytes: u32,
}

impl ScanoutMapping {
    pub fn encode(self) -> [u8; SCANOUT_MAPPING_BYTES] {
        let mut out = [0u8; SCANOUT_MAPPING_BYTES];
        write_u32_le(&mut out, 0, self.output.encode());
        out[4] = self.buffer_index;
        write_u64_le(&mut out, 8, self.user_va);
        write_u64_le(&mut out, 16, self.byte_len);
        write_u32_le(&mut out, 24, self.stride_bytes);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DisplayWireError> {
        if bytes.len() != SCANOUT_MAPPING_BYTES {
            return Err(DisplayWireError::Malformed);
        }
        if !check_range_zero(bytes, 5, 8) || !check_range_zero(bytes, 28, 32) {
            return Err(DisplayWireError::Malformed);
        }
        Ok(Self {
            output: OutputId::decode(read_u32_le(bytes, 0))
                .map_err(|_| DisplayWireError::Malformed)?,
            buffer_index: bytes[4],
            user_va: read_u64_le(bytes, 8),
            byte_len: read_u64_le(bytes, 16),
            stride_bytes: read_u32_le(bytes, 24),
        })
    }
}

/// Input of `PRESENT` (§8.3).
///
/// # Kernel evaluation order (§8.2)
///
/// After length/pointer checks and capability auth: `decode` → backend state → presenter binding →
/// `validate` → mapped buffer → in-flight gate → accept.
///
/// # Backend copy semantics (R8)
///
/// Pixels outside the submitted damage keep their previously presented content on **every**
/// backend (not only GOP): undamaged regions must not flip stale content from another buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PresentRequest {
    pub output: OutputId,
    pub buffer_index: u8,
    pub damage_count: u8,
    pub rects: [BufferRect; MAX_PRESENT_DAMAGE_RECTS],
}

impl PresentRequest {
    pub fn encode(self) -> [u8; PRESENT_REQUEST_BYTES] {
        let mut out = [0u8; PRESENT_REQUEST_BYTES];
        write_u32_le(&mut out, 0, self.output.encode());
        out[4] = self.buffer_index;
        out[5] = self.damage_count;
        let used = usize::from(self.damage_count).min(MAX_PRESENT_DAMAGE_RECTS);
        for (i, r) in self.rects.iter().enumerate().take(MAX_PRESENT_DAMAGE_RECTS) {
            let base = 8 + 8 * i;
            if i < used {
                write_u16_le(&mut out, base, r.x);
                write_u16_le(&mut out, base + 2, r.y);
                write_u16_le(&mut out, base + 4, r.width);
                write_u16_le(&mut out, base + 6, r.height);
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DisplayWireError> {
        if bytes.len() != PRESENT_REQUEST_BYTES {
            return Err(DisplayWireError::Malformed);
        }
        if !check_range_zero(bytes, 6, 8) {
            return Err(DisplayWireError::Malformed);
        }
        let output =
            OutputId::decode(read_u32_le(bytes, 0)).map_err(|_| DisplayWireError::Malformed)?;
        let damage_count = bytes[5];
        let mut rects = [BufferRect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        }; MAX_PRESENT_DAMAGE_RECTS];
        let unused_from = usize::from(damage_count).min(MAX_PRESENT_DAMAGE_RECTS);
        for (i, slot) in rects.iter_mut().enumerate().take(MAX_PRESENT_DAMAGE_RECTS) {
            let base = 8 + 8 * i;
            if i < unused_from {
                *slot = BufferRect {
                    x: read_u16_le(bytes, base),
                    y: read_u16_le(bytes, base + 2),
                    width: read_u16_le(bytes, base + 4),
                    height: read_u16_le(bytes, base + 6),
                };
            } else if !check_range_zero(bytes, base, base + 8) {
                return Err(DisplayWireError::Malformed);
            }
        }
        Ok(Self {
            output,
            buffer_index: bytes[4],
            damage_count,
            rects,
        })
    }

    pub fn validate(&self, current: OutputId, mode: &DisplayMode) -> Result<(), DisplayError> {
        if self.output != current {
            return Err(DisplayError::StaleEpoch);
        }
        if self.buffer_index as usize >= SCANOUT_BUFFER_COUNT {
            return Err(DisplayError::InvalidBuffer);
        }
        if !(1..=MAX_PRESENT_DAMAGE_RECTS as u8).contains(&self.damage_count) {
            return Err(DisplayError::InvalidDamage);
        }
        let count = usize::from(self.damage_count);
        for i in 0..count {
            let r = self.rects[i];
            if r.width == 0 || r.height == 0 {
                return Err(DisplayError::InvalidDamage);
            }
            let x = u32::from(r.x);
            let y = u32::from(r.y);
            let w = u32::from(r.width);
            let h = u32::from(r.height);
            if x.saturating_add(w) > mode.width_px || y.saturating_add(h) > mode.height_px {
                return Err(DisplayError::InvalidDamage);
            }
        }
        Ok(())
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresentState {
    Idle = 0,
    InFlight = 1,
    ResetRequired = 2,
    Poisoned = 3,
}

impl PresentState {
    fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Idle),
            1 => Some(Self::InFlight),
            2 => Some(Self::ResetRequired),
            3 => Some(Self::Poisoned),
            _ => None,
        }
    }
}

/// Output of `PRESENT_STATUS` (§8.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PresentStatus {
    pub output: OutputId,
    pub state: PresentState,
    pub in_flight_index: Option<u8>,
    pub last_error: Option<DisplayError>,
    pub submitted_seq: u64,
    pub completed_seq: u64,
    pub completed_ns: u64,
}

impl PresentStatus {
    pub fn encode(self) -> [u8; PRESENT_STATUS_BYTES] {
        let mut out = [0u8; PRESENT_STATUS_BYTES];
        write_u32_le(&mut out, 0, self.output.encode());
        out[4] = self.state as u8;
        out[5] = self.in_flight_index.map_or(0xFF, |i| i);
        write_u16_le(&mut out, 6, self.last_error.map_or(0, DisplayError::code));
        write_u64_le(&mut out, 8, self.submitted_seq);
        write_u64_le(&mut out, 16, self.completed_seq);
        write_u64_le(&mut out, 24, self.completed_ns);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DisplayWireError> {
        if bytes.len() != PRESENT_STATUS_BYTES {
            return Err(DisplayWireError::Malformed);
        }
        if !check_range_zero(bytes, 32, 40) {
            return Err(DisplayWireError::Malformed);
        }
        let output =
            OutputId::decode(read_u32_le(bytes, 0)).map_err(|_| DisplayWireError::Malformed)?;
        let state = PresentState::from_u8(bytes[4]).ok_or(DisplayWireError::Malformed)?;
        let in_flight_raw = bytes[5];
        let in_flight_index = if in_flight_raw == 0xFF {
            None
        } else if (in_flight_raw as usize) < SCANOUT_BUFFER_COUNT {
            Some(in_flight_raw)
        } else {
            return Err(DisplayWireError::Malformed);
        };
        let in_flight_matches_state =
            in_flight_index.is_some() == matches!(state, PresentState::InFlight);
        if !in_flight_matches_state {
            return Err(DisplayWireError::Malformed);
        }
        let last_error_raw = read_u16_le(bytes, 6);
        let last_error = if last_error_raw == 0 {
            None
        } else {
            Some(DisplayError::from_code(last_error_raw).ok_or(DisplayWireError::Malformed)?)
        };
        let submitted_seq = read_u64_le(bytes, 8);
        let completed_seq = read_u64_le(bytes, 16);
        if completed_seq > submitted_seq {
            return Err(DisplayWireError::Malformed);
        }
        let completed_ns = read_u64_le(bytes, 24);
        if (completed_seq == 0) != (completed_ns == 0) {
            return Err(DisplayWireError::Malformed);
        }
        Ok(Self {
            output,
            state,
            in_flight_index,
            last_error,
            submitted_seq,
            completed_seq,
            completed_ns,
        })
    }
}
