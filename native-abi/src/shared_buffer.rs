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

pub const SYSCALL_NR_SHARED_BUFFER: u64 = 16;

pub const SHARED_BUFFER_SUBOP_ALLOCATE: u64 = 1;
pub const SHARED_BUFFER_SUBOP_MAP: u64 = 2;
pub const SHARED_BUFFER_SUBOP_UNMAP: u64 = 3;
pub const SHARED_BUFFER_SUBOP_QUERY: u64 = 4;
pub const SHARED_BUFFER_SUBOP_RELEASE: u64 = 5;

pub const SHARED_BUFFER_ACCESS_READ: u64 = 0;
pub const SHARED_BUFFER_ACCESS_READ_WRITE: u64 = 1;

pub const MAX_SHARED_BUFFER_BYTES: u64 = 8 * 1024 * 1024;
pub const SHARED_BUFFER_PAGE_BYTES: u64 = 4096;

pub const fn page_count_for_bytes(byte_len: u64) -> Option<u32> {
    if byte_len == 0 || byte_len > MAX_SHARED_BUFFER_BYTES {
        None
    } else {
        Some(byte_len.div_ceil(SHARED_BUFFER_PAGE_BYTES) as u32)
    }
}

pub const SHARED_WINDOW_BASE: u64 = 0x0000_5000_0000_0000;
pub const SHARED_WINDOW_SLOT_STRIDE: u64 = 16 << 20;
pub const SHARED_WINDOW_BYTES: u64 =
    SHARED_WINDOW_SLOT_STRIDE * MAX_SHARED_MAPPINGS_PER_PROCESS as u64;

pub const fn shared_window_slot_base(slot: usize) -> Option<u64> {
    if slot >= MAX_SHARED_MAPPINGS_PER_PROCESS {
        None
    } else {
        Some(SHARED_WINDOW_BASE + slot as u64 * SHARED_WINDOW_SLOT_STRIDE)
    }
}

const _: () = assert!(SHARED_WINDOW_BASE % (1 << 30) == 0);
const _: () = assert!(SHARED_WINDOW_BYTES <= 1 << 30);
const _: () = assert!(SHARED_WINDOW_SLOT_STRIDE >= 2 * MAX_SHARED_BUFFER_BYTES);
const _: () = assert!(SHARED_WINDOW_SLOT_STRIDE % (2 << 20) == 0);
const _: () = assert!(
    MAX_SHARED_BUFFER_BYTES / SHARED_BUFFER_PAGE_BYTES <= MAX_SHARED_PAGES_PER_OWNER as u64
);
const _: () = assert!(SHARED_WINDOW_BASE + SHARED_WINDOW_BYTES <= 1 << 47);

pub const SHARED_BUFFER_INFO_BYTES: usize = 40;
pub const SHARED_BUFFER_INFO_CALLER_IS_OWNER: u32 = 1;
pub const SHARED_BUFFER_INFO_CALLER_MAPPED_READ_WRITE: u32 = 2;

/// QUERY reply, little-endian: id@0, byte_len@8, page_count@16, rights@20, flags@24,
/// reserved-zero@28, mapped_va@32 (0 when the caller has no mapping).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedBufferInfo {
    pub id: SharedBufferId,
    pub byte_len: u64,
    pub page_count: u32,
    pub rights_bits: u32,
    pub flags: u32,
    pub mapped_va: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SharedBufferInfoError {
    WrongLength,
    ReservedNonZero,
    UnknownFlags,
    InvalidId(SharedBufferIdError),
}

impl SharedBufferInfo {
    pub fn encode(&self) -> [u8; SHARED_BUFFER_INFO_BYTES] {
        let mut out = [0u8; SHARED_BUFFER_INFO_BYTES];
        write_u64_le(&mut out, 0, self.id.encode());
        write_u64_le(&mut out, 8, self.byte_len);
        write_u32_le(&mut out, 16, self.page_count);
        write_u32_le(&mut out, 20, self.rights_bits);
        write_u32_le(&mut out, 24, self.flags);
        write_u64_le(&mut out, 32, self.mapped_va);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, SharedBufferInfoError> {
        if bytes.len() != SHARED_BUFFER_INFO_BYTES {
            return Err(SharedBufferInfoError::WrongLength);
        }
        if read_u32_le(bytes, 28) != 0 {
            return Err(SharedBufferInfoError::ReservedNonZero);
        }
        let flags = read_u32_le(bytes, 24);
        let allowed =
            SHARED_BUFFER_INFO_CALLER_IS_OWNER | SHARED_BUFFER_INFO_CALLER_MAPPED_READ_WRITE;
        if flags & !allowed != 0 {
            return Err(SharedBufferInfoError::UnknownFlags);
        }
        let id = SharedBufferId::decode(read_u64_le(bytes, 0))
            .map_err(SharedBufferInfoError::InvalidId)?;
        Ok(Self {
            id,
            byte_len: read_u64_le(bytes, 8),
            page_count: read_u32_le(bytes, 16),
            rights_bits: read_u32_le(bytes, 20),
            flags,
            mapped_va: read_u64_le(bytes, 32),
        })
    }
}

fn write_u32_le(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset] = value as u8;
    buf[offset + 1] = (value >> 8) as u8;
    buf[offset + 2] = (value >> 16) as u8;
    buf[offset + 3] = (value >> 24) as u8;
}

fn write_u64_le(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset] = value as u8;
    buf[offset + 1] = (value >> 8) as u8;
    buf[offset + 2] = (value >> 16) as u8;
    buf[offset + 3] = (value >> 24) as u8;
    buf[offset + 4] = (value >> 32) as u8;
    buf[offset + 5] = (value >> 40) as u8;
    buf[offset + 6] = (value >> 48) as u8;
    buf[offset + 7] = (value >> 56) as u8;
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn read_u64_le(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

pub const SHARED_BUFFER_STATUS_EINVAL: u64 = crate::status::STATUS_EINVAL;
pub const SHARED_BUFFER_STATUS_EACCES: u64 = crate::status::STATUS_EACCES;
pub const SHARED_BUFFER_STATUS_ESTALE: u64 = crate::status::STATUS_ESTALE;
pub const SHARED_BUFFER_STATUS_ENOSPC: u64 = crate::status::STATUS_ENOSPC;
pub const SHARED_BUFFER_STATUS_ENOSYS: u64 = crate::status::STATUS_ENOSYS;
pub const SHARED_BUFFER_STATUS_EAGAIN: u64 = crate::status::STATUS_EAGAIN;
pub const SHARED_BUFFER_STATUS_EBADF: u64 = crate::status::STATUS_EBADF;

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

    pub const fn encode(self) -> u64 {
        match self {
            Self::Read => SHARED_BUFFER_ACCESS_READ,
            Self::ReadWrite => SHARED_BUFFER_ACCESS_READ_WRITE,
        }
    }

    pub const fn decode(code: u64) -> Option<Self> {
        match code {
            SHARED_BUFFER_ACCESS_READ => Some(Self::Read),
            SHARED_BUFFER_ACCESS_READ_WRITE => Some(Self::ReadWrite),
            _ => None,
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
    fn shared_buffer_access_encode_decode() {
        assert_eq!(SharedBufferAccess::Read.encode(), SHARED_BUFFER_ACCESS_READ);
        assert_eq!(
            SharedBufferAccess::ReadWrite.encode(),
            SHARED_BUFFER_ACCESS_READ_WRITE
        );
        assert_eq!(
            SharedBufferAccess::decode(SHARED_BUFFER_ACCESS_READ),
            Some(SharedBufferAccess::Read)
        );
        assert_eq!(
            SharedBufferAccess::decode(SHARED_BUFFER_ACCESS_READ_WRITE),
            Some(SharedBufferAccess::ReadWrite)
        );
        assert_eq!(SharedBufferAccess::decode(2), None);
        assert_eq!(SharedBufferAccess::decode(u64::MAX), None);
    }

    #[test]
    fn shared_buffer_info_round_trip_and_rejections() {
        let id = SharedBufferId::new(2, 7).unwrap();
        let info = SharedBufferInfo {
            id,
            byte_len: 8192,
            page_count: 2,
            rights_bits: 3,
            flags: SHARED_BUFFER_INFO_CALLER_IS_OWNER | SHARED_BUFFER_INFO_CALLER_MAPPED_READ_WRITE,
            mapped_va: 0x5000_0000_1000,
        };
        let bytes = info.encode();
        assert_eq!(bytes[28..32], [0, 0, 0, 0]);
        assert_eq!(SharedBufferInfo::decode(&bytes), Ok(info));

        let short = &bytes[..39];
        assert_eq!(
            SharedBufferInfo::decode(short),
            Err(SharedBufferInfoError::WrongLength)
        );
        let mut long = bytes.to_vec();
        long.push(0);
        assert_eq!(
            SharedBufferInfo::decode(&long),
            Err(SharedBufferInfoError::WrongLength)
        );

        let mut reserved = bytes;
        reserved[29] = 1;
        assert_eq!(
            SharedBufferInfo::decode(&reserved),
            Err(SharedBufferInfoError::ReservedNonZero)
        );

        let mut bad_flags = bytes;
        write_u32_le(&mut bad_flags, 24, 4);
        assert_eq!(
            SharedBufferInfo::decode(&bad_flags),
            Err(SharedBufferInfoError::UnknownFlags)
        );

        let mut bad_id = bytes;
        write_u64_le(&mut bad_id, 0, 0);
        assert_eq!(
            SharedBufferInfo::decode(&bad_id),
            Err(SharedBufferInfoError::InvalidId(
                SharedBufferIdError::InvalidGeneration
            ))
        );

        let mut high_bit_id = bytes;
        write_u64_le(&mut high_bit_id, 0, 1 | (1u64 << 63));
        assert_eq!(
            SharedBufferInfo::decode(&high_bit_id),
            Err(SharedBufferInfoError::InvalidId(
                SharedBufferIdError::ReservedBitsSet
            ))
        );
    }

    #[test]
    fn page_count_for_bytes_cases() {
        assert_eq!(page_count_for_bytes(0), None);
        assert_eq!(page_count_for_bytes(1), Some(1));
        assert_eq!(page_count_for_bytes(4096), Some(1));
        assert_eq!(page_count_for_bytes(4097), Some(2));
        assert_eq!(page_count_for_bytes(MAX_SHARED_BUFFER_BYTES), Some(2048));
        assert_eq!(page_count_for_bytes(MAX_SHARED_BUFFER_BYTES + 1), None);
    }

    #[test]
    fn shared_window_slot_base_layout() {
        assert_eq!(shared_window_slot_base(0), Some(SHARED_WINDOW_BASE));
        assert_eq!(
            shared_window_slot_base(19),
            Some(SHARED_WINDOW_BASE + 19 * SHARED_WINDOW_SLOT_STRIDE)
        );
        assert_eq!(shared_window_slot_base(20), None);
        for slot in 0..MAX_SHARED_MAPPINGS_PER_PROCESS {
            let base = shared_window_slot_base(slot).unwrap();
            assert_eq!(base % (2 << 20), 0);
        }
    }

    #[test]
    fn shared_buffer_subops_distinct_nonzero() {
        let subops = [
            SHARED_BUFFER_SUBOP_ALLOCATE,
            SHARED_BUFFER_SUBOP_MAP,
            SHARED_BUFFER_SUBOP_UNMAP,
            SHARED_BUFFER_SUBOP_QUERY,
            SHARED_BUFFER_SUBOP_RELEASE,
        ];
        for &subop in &subops {
            assert_ne!(subop, 0);
        }
        for i in 0..subops.len() {
            for j in (i + 1)..subops.len() {
                assert_ne!(subops[i], subops[j]);
            }
        }
    }

    #[test]
    fn shared_buffer_status_sentinels() {
        use clean_slate_graphics::abi::status::{
            STATUS_EACCES, STATUS_EAGAIN, STATUS_EBADF, STATUS_EINVAL, STATUS_ENOSPC,
            STATUS_ENOSYS, STATUS_ESTALE,
        };

        const NETWORK_STATUS_PENDING: u64 = u64::MAX - 15;

        let statuses = [
            SHARED_BUFFER_STATUS_EINVAL,
            SHARED_BUFFER_STATUS_EACCES,
            SHARED_BUFFER_STATUS_ESTALE,
            SHARED_BUFFER_STATUS_ENOSPC,
            SHARED_BUFFER_STATUS_ENOSYS,
            SHARED_BUFFER_STATUS_EAGAIN,
            SHARED_BUFFER_STATUS_EBADF,
        ];
        for i in 0..statuses.len() {
            assert!(crate::status::is_status(statuses[i]));
            assert_ne!(statuses[i], NETWORK_STATUS_PENDING);
            for j in (i + 1)..statuses.len() {
                assert_ne!(statuses[i], statuses[j]);
            }
        }
        assert_eq!(SHARED_BUFFER_STATUS_EAGAIN, STATUS_EAGAIN);
        assert_eq!(SHARED_BUFFER_STATUS_EBADF, STATUS_EBADF);
        assert_eq!(SHARED_BUFFER_STATUS_EACCES, STATUS_EACCES);
        assert_eq!(SHARED_BUFFER_STATUS_EINVAL, STATUS_EINVAL);
        assert_eq!(SHARED_BUFFER_STATUS_ENOSPC, STATUS_ENOSPC);
        assert_eq!(SHARED_BUFFER_STATUS_ENOSYS, STATUS_ENOSYS);
        assert_eq!(SHARED_BUFFER_STATUS_ESTALE, STATUS_ESTALE);
        assert_eq!(MAX_SHARED_BUFFER_BYTES, MAX_BUFFER_BYTES);
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
