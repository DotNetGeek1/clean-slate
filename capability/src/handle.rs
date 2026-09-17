//! Capability handle encoding (slot + generation).

use crate::error::CapabilityError;

/// Default slot-table capacity hint for M6.2 implementations.
pub const MAX_SLOTS: usize = 64;

/// Maximum delegation chain depth (root grant is depth 0).
pub const MAX_DELEGATION_DEPTH: u8 = 4;

/// Opaque capability reference presented across syscalls and IPC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CapabilityHandle {
    pub slot: u16,
    pub generation: u32,
}

impl CapabilityHandle {
    /// Sentinel handle; generation 0 is never valid on the wire.
    pub const INVALID: Self = Self {
        slot: 0,
        generation: 0,
    };

    pub const fn new(slot: u16, generation: u32) -> Self {
        Self { slot, generation }
    }

    /// Encodes as `slot | generation << 16`; bits 48..64 must be zero.
    pub fn encode(self) -> u64 {
        u64::from(self.slot) | (u64::from(self.generation) << 16)
    }

    pub fn decode(raw: u64) -> Result<Self, CapabilityError> {
        if raw & 0xffff_0000_0000_0000 != 0 {
            return Err(CapabilityError::InvalidHandle);
        }
        let slot = raw as u16;
        let generation = (raw >> 16) as u32;
        if generation == 0 {
            return Err(CapabilityError::InvalidHandle);
        }
        Ok(Self { slot, generation })
    }
}

/// Generation advancement without wrap (exhaustion retires the slot in M6.2).
pub struct Generation;

impl Generation {
    /// Returns the next generation, or `None` at `u32::MAX` (never wraps).
    pub const fn next(current: u32) -> Option<u32> {
        if current == u32::MAX {
            None
        } else {
            Some(current + 1)
        }
    }
}
