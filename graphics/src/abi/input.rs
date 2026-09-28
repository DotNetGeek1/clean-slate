//! Input syscall ABI wire types (`SYSCALL_NR_INPUT = 19`, §9).
//!
//! # Syscall convention (§7)
//!
//! Matches `kernel/src/service/net_syscall.rs`: `rax` carries syscall number 19, `rdi` subop,
//! `rsi` capability handle, `rdx`/`r10`/`r8`/`r9` arguments in order, `rax` out is success or a
//! status sentinel from [`super::status`]. Both display and input syscalls are non-blocking.
//!
//! # `READ_BATCH` (subop 3)
//!
//! Copies records to user memory **one [`RawInputRecord`](crate::raw_input::RawInputRecord) (32
//! bytes) at a time**; it must never stage the whole batch (up to 4096 bytes) on the kernel stack
//! (R9). Only fixed structs of at most 256 bytes (`PresentRequest` is the largest at 136) may be
//! copied through a kernel stack buffer (§7).

use crate::ids::InputDeviceId;
use crate::limits::RAW_INPUT_QUEUE_DEPTH;

use super::wire::{check_range_zero, read_u16_le, read_u32_le, write_u16_le, write_u32_le};

pub const INPUT_ABI_VERSION: u64 = 1;
pub const INPUT_SUBOP_FIND_HANDLE: u64 = 1;
pub const INPUT_SUBOP_QUERY_DEVICES: u64 = 2;
pub const INPUT_SUBOP_READ_BATCH: u64 = 3;
pub const INPUT_SUBOP_BIND_WAKE: u64 = 4;

pub const READ_BATCH_MAX_RECORDS: usize = RAW_INPUT_QUEUE_DEPTH;
pub const INPUT_DEVICE_INFO_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputWireError {
    Malformed,
}

/// Output of `QUERY_DEVICES` (§9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputDeviceInfo {
    pub keyboard: Option<InputDeviceId>,
    pub mouse: Option<InputDeviceId>,
    pub queue_depth: u16,
    pub record_bytes: u16,
}

impl InputDeviceInfo {
    pub fn encode(self) -> [u8; INPUT_DEVICE_INFO_BYTES] {
        let mut out = [0u8; INPUT_DEVICE_INFO_BYTES];
        write_u32_le(&mut out, 0, self.keyboard.map_or(0, InputDeviceId::encode));
        write_u32_le(&mut out, 4, self.mouse.map_or(0, InputDeviceId::encode));
        write_u16_le(&mut out, 8, self.queue_depth);
        write_u16_le(&mut out, 10, self.record_bytes);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, InputWireError> {
        if bytes.len() != INPUT_DEVICE_INFO_BYTES {
            return Err(InputWireError::Malformed);
        }
        if !check_range_zero(bytes, 12, 16) {
            return Err(InputWireError::Malformed);
        }
        let kb_raw = read_u32_le(bytes, 0);
        let keyboard = if kb_raw == 0 {
            None
        } else {
            Some(InputDeviceId::decode(kb_raw).map_err(|_| InputWireError::Malformed)?)
        };
        let mouse_raw = read_u32_le(bytes, 4);
        let mouse = if mouse_raw == 0 {
            None
        } else {
            Some(InputDeviceId::decode(mouse_raw).map_err(|_| InputWireError::Malformed)?)
        };
        Ok(Self {
            keyboard,
            mouse,
            queue_depth: read_u16_le(bytes, 8),
            record_bytes: read_u16_le(bytes, 10),
        })
    }
}
