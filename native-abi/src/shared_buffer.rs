//! Shared-buffer identity and proposed memory-level limits (#195 owns adjustment).

use clean_slate_capability::{ResourceRef, Rights};

/// Proposed memory-level limits; #195 owns these values and may adjust within protocol bounds.
pub const MAX_SHARED_BUFFERS: usize = 32;
pub const MAX_SHARED_BUFFERS_PER_OWNER: usize = 8;
pub const MAX_SHARED_PAGES_TOTAL: usize = 8192;
pub const MAX_SHARED_PAGES_PER_OWNER: usize = 4096;
pub const MAX_ATTACHMENTS_PER_BUFFER: usize = 2;
pub const MAX_SHARED_MAPPINGS_PER_PROCESS: usize = 20;
pub const MAX_EXTENTS_PER_BUFFER: usize = 16;

const HIGH_BITS_MASK: u64 = 0xffff_0000_0000_0000;
const GENERATION_SHIFT: u32 = 16;

/// Wire/decode failures for [`SharedBufferId`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SharedBufferIdError {
    InvalidGeneration,
    ReservedBitsSet,
}

/// Kernel-minted shared buffer identity: slot in bits 0..16, generation in 16..48 (0 invalid).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SharedBufferId(u64);

impl SharedBufferId {
    pub fn new(slot: u16, generation: u32) -> Result<Self, SharedBufferIdError> {
        if generation == 0 {
            return Err(SharedBufferIdError::InvalidGeneration);
        }
        Ok(Self(
            u64::from(slot) | (u64::from(generation) << GENERATION_SHIFT),
        ))
    }

    pub fn encode(self) -> u64 {
        self.0
    }

    pub fn decode(raw: u64) -> Result<Self, SharedBufferIdError> {
        if raw & HIGH_BITS_MASK != 0 {
            return Err(SharedBufferIdError::ReservedBitsSet);
        }
        let generation = (raw >> GENERATION_SHIFT) as u32;
        if generation == 0 {
            return Err(SharedBufferIdError::InvalidGeneration);
        }
        Ok(Self(raw))
    }

    pub fn slot(self) -> u16 {
        self.0 as u16
    }

    pub fn generation(self) -> u32 {
        (self.0 >> GENERATION_SHIFT) as u32
    }

    pub fn resource_ref(self) -> ResourceRef {
        ResourceRef::shared_buffer(self.encode())
    }
}

/// Attachee mapping mode for a shared buffer grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SharedBufferAccess {
    Read,
    ReadWrite,
}

impl SharedBufferAccess {
    pub const fn rights(self) -> Rights {
        match self {
            Self::Read => Rights::READ,
            Self::ReadWrite => Rights::READ.union(Rights::WRITE),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_capability::ResourceClass;
    use clean_slate_graphics::{
        MAX_BUFFERS_PER_CLIENT, MAX_BUFFER_BYTES, MAX_REGISTERED_BUFFERS, SCANOUT_BUFFER_COUNT,
    };

    #[test]
    fn shared_buffer_id_round_trip_and_rejections() {
        let id = SharedBufferId::new(3, 42).unwrap();
        assert_eq!(SharedBufferId::decode(id.encode()), Ok(id));
        assert_eq!(id.slot(), 3);
        assert_eq!(id.generation(), 42);
        assert_eq!(
            SharedBufferId::new(0, 0),
            Err(SharedBufferIdError::InvalidGeneration)
        );
        assert_eq!(
            SharedBufferId::decode(0),
            Err(SharedBufferIdError::InvalidGeneration)
        );
        assert_eq!(
            SharedBufferId::decode(1 | HIGH_BITS_MASK),
            Err(SharedBufferIdError::ReservedBitsSet)
        );
    }

    #[test]
    fn shared_buffer_id_max_slot_and_generation() {
        let id = SharedBufferId::new(u16::MAX, u32::MAX).unwrap();
        assert_eq!(id.slot(), u16::MAX);
        assert_eq!(id.generation(), u32::MAX);
        assert_eq!(SharedBufferId::decode(id.encode()), Ok(id));
    }

    #[test]
    fn shared_buffer_resource_ref_fields() {
        let id = SharedBufferId::new(5, 9).unwrap();
        let resource = id.resource_ref();
        assert_eq!(resource.class, ResourceClass::SharedBuffer);
        assert_eq!(resource.id, id.encode());
        assert_eq!(resource.instance_generation, 0);
    }

    #[test]
    fn shared_buffer_access_rights() {
        assert_eq!(SharedBufferAccess::Read.rights(), Rights::READ);
        assert_eq!(
            SharedBufferAccess::ReadWrite.rights(),
            Rights::READ.union(Rights::WRITE)
        );
    }

    #[test]
    fn proposed_limits_satisfy_graphics_protocol_budget() {
        let mappings = MAX_SHARED_MAPPINGS_PER_PROCESS;
        let registered = MAX_REGISTERED_BUFFERS;
        let scanout = SCANOUT_BUFFER_COUNT;
        assert!(
            mappings >= registered + scanout,
            "mappings {mappings} must cover registered {registered} + scanout {scanout}"
        );
        let owner_bytes = (MAX_SHARED_PAGES_PER_OWNER as u64) * 4096;
        assert!(
            owner_bytes >= MAX_BUFFER_BYTES,
            "owner quota {owner_bytes} must cover max buffer {MAX_BUFFER_BYTES}"
        );
        let per_owner = MAX_SHARED_BUFFERS_PER_OWNER;
        let per_client = MAX_BUFFERS_PER_CLIENT;
        assert!(
            per_owner >= per_client,
            "per-owner buffer cap {per_owner} must cover per-client cap {per_client}"
        );
    }
}
