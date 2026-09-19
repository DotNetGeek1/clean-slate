//! Ethernet frame buffer ownership model.
//!
//! Buffers are moved by value across contract boundaries. Whoever holds the
//! [`FrameBuf`] value owns the bytes until they transfer ownership again.
//! Device-owned vs service-owned transitions are explicit API calls on
//! [`crate::device::NetworkLink`] (`transmit` / `receive`), not implicit aliases.

use crate::limits::MAX_ETHERNET_FRAME_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameBufError {
    WouldOverflow,
    LenOutOfBounds,
    TruncateOutOfBounds,
}

/// Fixed-capacity owned Ethernet frame buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameBuf {
    bytes: [u8; MAX_ETHERNET_FRAME_BYTES],
    len: usize,
}

impl FrameBuf {
    pub const fn empty() -> Self {
        Self {
            bytes: [0; MAX_ETHERNET_FRAME_BYTES],
            len: 0,
        }
    }

    pub fn from_slice(data: &[u8]) -> Result<Self, FrameBufError> {
        if data.len() > MAX_ETHERNET_FRAME_BYTES {
            return Err(FrameBufError::WouldOverflow);
        }
        let mut buf = Self::empty();
        buf.bytes[..data.len()].copy_from_slice(data);
        buf.len = data.len();
        Ok(buf)
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn capacity(&self) -> usize {
        MAX_ETHERNET_FRAME_BYTES
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }

    pub fn push_bytes(&mut self, data: &[u8]) -> Result<(), FrameBufError> {
        let new_len = self
            .len
            .checked_add(data.len())
            .ok_or(FrameBufError::WouldOverflow)?;
        if new_len > MAX_ETHERNET_FRAME_BYTES {
            return Err(FrameBufError::WouldOverflow);
        }
        self.bytes[self.len..new_len].copy_from_slice(data);
        self.len = new_len;
        Ok(())
    }

    pub fn truncate(&mut self, new_len: usize) -> Result<(), FrameBufError> {
        if new_len > self.len {
            return Err(FrameBufError::TruncateOutOfBounds);
        }
        self.len = new_len;
        Ok(())
    }
}
