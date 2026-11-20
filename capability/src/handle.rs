//! Capability handle encoding (slot + generation).

use crate::error::CapabilityError;

/// Slots in the kernel's capability table.
pub const MAX_SLOTS: usize = 128;

/// Occupied slots (live or revoked) one holder may be charged for; [`crate::HolderId::KERNEL`]
/// is exempt. With [`MAX_SLOTS`], no single holder can fill more than an eighth of the table.
pub const HOLDER_SLOT_QUOTA: usize = 16;

/// Largest slot allowance a holder may be given in place of [`HOLDER_SLOT_QUOTA`]. Only the
/// kernel sets one, from a launch-manifest row, and never more than a quarter of the table.
pub const MAX_SLOT_ALLOWANCE: usize = 32;

/// Holders that may carry a slot allowance at once.
pub const MAX_SLOT_ALLOWANCES: usize = 8;

const _: () =
    assert!(HOLDER_SLOT_QUOTA < MAX_SLOT_ALLOWANCE && MAX_SLOT_ALLOWANCE <= MAX_SLOTS / 4);

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
