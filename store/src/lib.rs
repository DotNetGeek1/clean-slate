//! M5 persistent object store: a boot/config and `/tmp` store, not a filesystem.
//!
//! Version 3 uses a fixed, host-testable on-disk layout encoded explicitly in
//! little-endian bytes:
//!
//! - LBA 0: superblock slot A
//! - LBA 1: superblock slot B
//! - LBA 2..: two alternating committed arenas selected by the active
//!   superblock slot; each commit writes its object payloads and then its
//!   object table into the arena of the slot it commits to
//!
//! Each superblock occupies exactly one logical block and contains:
//!
//! - magic (`CSO1`);
//! - format version (`3`);
//! - CRC-32C over the full superblock block with the checksum field zeroed;
//! - expected logical block size and device block count;
//! - generation number for slot selection;
//! - the object limit for this geometry ([`object_limit`]) and the live object
//!   count;
//! - the next object epoch, so a re-created object never reuses an epoch;
//! - the extent of the object table and its CRC-32C.
//!
//! The object table holds one entry per live object: object id, epoch, UTF-8
//! name, exact byte length, data extent, and a payload CRC-32C. The table CRC
//! covers the committing generation and the table's location as well as its
//! bytes. Each payload CRC covers the object's id, epoch, start LBA and length
//! as well as its bytes, so a payload that is intact but sits at another
//! object's place (two objects can hold the same bytes) is rejected rather
//! than read as the object the table names.
//!
//! Versions 1 (an additive byte sum) and 2 (CRC-32C, with the object table
//! inside the superblock and a fixed limit of seven objects) are not migrated:
//! an older image is refused with [`IncompatibleFormatError::UnsupportedVersion`]
//! and never reformatted.
//!
//! [`probe`] decides what may be done with a device: only a blank one (both
//! superblock slots entirely zero) may be formatted, and [`ObjectStore::open`]
//! refuses every other unmountable device rather than reformatting it.
//!
//! Commits never need in-place multi-block metadata mutation: object data and
//! the object table are written first and flushed, then a complete
//! next-generation superblock is written to the alternate metadata slot and
//! flushed. The first flush keeps a write-back cache from persisting the
//! superblock ahead of the table and payload it references.
//!
//! The device is assumed to write one logical block (512 bytes on today's
//! disks) atomically on power loss. Each superblock is one block, so a slot
//! holds either a whole superblock or its previous bytes, and no crash,
//! including one during the first [`ObjectStore::format`], leaves a device that
//! is neither blank nor mountable. A device that tears inside a block can
//! interrupt the first
//! format with a slot holding only a byte prefix of the new superblock;
//! [`probe`] refuses that as [`Refusal::InterruptedFormat`] rather than treat
//! it as blank, because damage to a real store can leave the same bytes.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod crc32c;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use clean_slate_block::{BlockDevice, BlockGeometry, BlockIoError};
use core::cmp::Ordering;
use crc32c::Crc32c;

pub const STORE_MAGIC: u32 = 0x4353_4F31; // "CSO1"
pub const STORE_VERSION: u16 = 3;
pub const SUPERBLOCK_SLOTS: u64 = 2;
pub const DATA_START_LBA: u64 = SUPERBLOCK_SLOTS;
/// The fewest live objects any supported geometry allows; see [`object_limit`].
pub const MIN_OBJECT_LIMIT: usize = 128;
/// The most live objects any geometry allows; see [`object_limit`].
pub const MAX_OBJECT_LIMIT: usize = 65_536;
pub const MAX_OBJECT_NAME_BYTES: usize = 32;
/// Bytes of one object-table entry on disk.
pub const TABLE_ENTRY_BYTES: usize = 72;
/// The epoch of the first object a fresh store creates. Epoch 0 is never assigned, so a
/// caller can use it to mean "not bound to an epoch".
pub const FIRST_OBJECT_EPOCH: u64 = 1;

/// Superblock bytes in use; the rest of the block must be zero.
const HEADER_BYTES: usize = 72;
const MIN_BLOCK_BYTES: usize = 512;
/// Arena blocks per object the limit allows above [`MIN_OBJECT_LIMIT`].
const ARENA_BLOCKS_PER_OBJECT: u64 = 16;
const CHECKSUM_RANGE: core::ops::Range<usize> = 8..12;

/// Most live objects the store allows on `geometry`: one per 16 blocks of a payload arena,
/// at least [`MIN_OBJECT_LIMIT`] and at most [`MAX_OBJECT_LIMIT`]. A small disk can run out
/// of space before it reaches the limit. The 64 MiB data disk the QEMU lanes attach allows
/// 4095. The limit is recorded in each superblock and checked on mount.
pub fn object_limit(geometry: BlockGeometry) -> usize {
    let by_size = usize::try_from(data_arena_blocks(geometry) / ARENA_BLOCKS_PER_OBJECT)
        .unwrap_or(MAX_OBJECT_LIMIT);
    by_size.clamp(MIN_OBJECT_LIMIT, MAX_OBJECT_LIMIT)
}

/// Format version recorded in a superblock block written by any store version, or `None`
/// when the block does not start with the store magic (for example a blank disk).
pub fn superblock_format_version(block: &[u8]) -> Option<u16> {
    if block.len() < 6 || read_u32(block, 0) != STORE_MAGIC {
        return None;
    }
    Some(read_u16(block, 4))
}

pub use clean_slate_service_fixtures::DiskRefusal as Refusal;

/// What a device holds, as far as deciding between mount, format, and refusal goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    /// Both superblock slots are entirely zero: nothing to lose, safe to format.
    Blank,
    /// [`ObjectStore::mount`] succeeds.
    Mountable,
    /// Neither mountable nor blank. Formatting would destroy whatever is there.
    Refused(Refusal),
}

/// Classifies `device` without writing to it. Errors are only block I/O failures and
/// unsupported geometry: a device that cannot be read gives no basis for any decision.
pub fn probe<D: BlockDevice>(device: &mut D) -> Result<Probe, StoreError> {
    let geometry = validate_geometry(device.geometry())?;
    Ok(match classify(device, geometry)? {
        Classified::Blank => Probe::Blank,
        Classified::Mountable(_) => Probe::Mountable,
        Classified::Refused(refusal) => Probe::Refused(refusal),
    })
}

type CommittedState = (u64, Superblock, Vec<StoredObject>);

enum Classified {
    Blank,
    Mountable(CommittedState),
    Refused(Refusal),
}

fn classify<D: BlockDevice>(
    device: &mut D,
    geometry: BlockGeometry,
) -> Result<Classified, StoreError> {
    let mut slots = [
        vec![0; block_size_bytes(geometry)],
        vec![0; block_size_bytes(geometry)],
    ];
    for (lba, bytes) in (0..SUPERBLOCK_SLOTS).zip(slots.iter_mut()) {
        device.read_blocks(lba, 1, bytes)?;
    }
    if slots
        .iter()
        .all(|bytes| bytes.iter().all(|&byte| byte == 0))
    {
        return Ok(Classified::Blank);
    }

    match select_committed_state(device, geometry) {
        Ok(state) => return Ok(Classified::Mountable(state)),
        Err(StoreError::Block(error)) => return Err(StoreError::Block(error)),
        Err(_) => {}
    }

    // A slot that still decodes makes this a damaged store of this version, whatever the other
    // slot holds. Only a slot whose checksum holds names another format: a damaged version field
    // must not make a corrupt store look like a foreign one. Version 0 was never written, so a
    // slot claiming it is damaged, not foreign.
    let refusal = if (0..SUPERBLOCK_SLOTS)
        .zip(slots.iter())
        .any(|(slot, bytes)| decode_superblock(geometry, slot, bytes).is_ok())
    {
        Refusal::PayloadInvalid
    } else if let Some(version) = slots
        .iter()
        .filter_map(|bytes| checksummed_format_version(bytes))
        .find(|&version| version != 0 && version != STORE_VERSION)
    {
        Refusal::UnsupportedVersion(version)
    } else if holds_interrupted_first_format(geometry, &slots)? {
        Refusal::InterruptedFormat
    } else if slots
        .iter()
        .all(|bytes| superblock_format_version(bytes).is_none())
    {
        Refusal::NotAStore
    } else {
        Refusal::SuperblocksInvalid
    };
    Ok(Classified::Refused(refusal))
}

/// Each slot is blank or the superblock [`ObjectStore::format`] writes on this geometry, cut
/// after some byte and zero-filled. Called only on an unmountable, non-blank device, so at least
/// one slot is a strict prefix: a whole copy would have mounted.
fn holds_interrupted_first_format(
    geometry: BlockGeometry,
    slots: &[Vec<u8>],
) -> Result<bool, StoreError> {
    let fresh = encode_superblock(geometry, &Superblock::fresh())?;
    Ok(slots.iter().all(|slot| {
        let written = slot
            .iter()
            .rposition(|&byte| byte != 0)
            .map_or(0, |last| last + 1);
        slot[..written] == fresh[..written]
    }))
}

/// Format version of a superblock block carrying the store magic and a checksum that holds under
/// that version's rules: an additive byte sum in version 1, CRC-32C since, each computed with the
/// checksum field (bytes 8..12) zeroed. A later version that moves or changes the checksum reads
/// as corrupt here, not as foreign.
fn checksummed_format_version(block: &[u8]) -> Option<u16> {
    let version = superblock_format_version(block)?;
    let stored = read_u32(block, CHECKSUM_RANGE.start);
    let computed = match version {
        1 => version_one_checksum(block),
        _ => superblock_checksum(block),
    };
    (computed == stored).then_some(version)
}

/// How [`ObjectStore::open`] obtained its store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opened {
    Mounted,
    Formatted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// The device was left exactly as it was found.
    Refused(Refusal),
    Store(StoreError),
}

impl From<StoreError> for OpenError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredObject {
    id: u64,
    epoch: u64,
    name: String,
    data: Vec<u8>,
}

impl StoredObject {
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Assigned when the object was created and kept across rewrites. A later object
    /// created under the same id or name, after a delete, gets a larger epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    Block(BlockIoError),
    UnsupportedGeometry {
        logical_block_size: u32,
        block_count: u64,
    },
    InvalidObjectName,
    ObjectNameTooLong {
        len: usize,
        max: usize,
    },
    ObjectTooLarge {
        len: usize,
        max: u32,
    },
    ObjectTableFull {
        max_objects: usize,
    },
    StorageFull {
        required_blocks: u64,
        available_blocks: u64,
    },
    NotFound,
    IdentityConflict,
    GenerationExhausted,
    EpochExhausted,
    Incompatible(IncompatibleFormatError),
    Corrupt(CorruptFormatError),
}

impl From<BlockIoError> for StoreError {
    fn from(value: BlockIoError) -> Self {
        Self::Block(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncompatibleFormatError {
    BadMagic,
    UnsupportedVersion(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorruptFormatError {
    ChecksumMismatch,
    InvalidHeader,
    InvalidObjectCount { count: u32 },
    InvalidNameEncoding,
    DuplicateObjectId(u64),
    DuplicateObjectName,
    InvalidObjectLength,
    InvalidObjectExtent,
    OverlappingObjectExtents,
    ObjectChecksumMismatch,
    InvalidObjectEpoch,
    InvalidTableExtent,
    TableChecksumMismatch,
}

#[derive(Debug)]
pub struct ObjectStore<D> {
    device: D,
    geometry: BlockGeometry,
    generation: u64,
    active_slot: u64,
    next_epoch: u64,
    objects: Vec<StoredObject>,
}

impl<D: BlockDevice> ObjectStore<D> {
    pub fn format(mut device: D) -> Result<Self, StoreError> {
        let geometry = validate_geometry(device.geometry())?;
        let superblock = Superblock::fresh();

        write_superblock(&mut device, geometry, 0, &superblock)?;
        write_superblock(&mut device, geometry, 1, &superblock)?;
        device.flush()?;

        Ok(Self {
            device,
            geometry,
            generation: 0,
            active_slot: 0,
            next_epoch: superblock.next_epoch,
            objects: Vec::new(),
        })
    }

    pub fn mount(mut device: D) -> Result<Self, StoreError> {
        let geometry = validate_geometry(device.geometry())?;
        let state = select_committed_state(&mut device, geometry)?;
        Ok(Self::with_committed_state(device, geometry, state))
    }

    /// Mounts the store on `device`, formatting it only when [`probe`] finds it blank.
    pub fn open(mut device: D) -> Result<(Self, Opened), OpenError> {
        let geometry = validate_geometry(device.geometry())?;
        match classify(&mut device, geometry)? {
            Classified::Blank => Ok((Self::format(device)?, Opened::Formatted)),
            Classified::Mountable(state) => Ok((
                Self::with_committed_state(device, geometry, state),
                Opened::Mounted,
            )),
            Classified::Refused(refusal) => Err(OpenError::Refused(refusal)),
        }
    }

    fn with_committed_state(
        device: D,
        geometry: BlockGeometry,
        (active_slot, superblock, objects): CommittedState,
    ) -> Self {
        Self {
            device,
            geometry,
            generation: superblock.generation,
            active_slot,
            next_epoch: superblock.next_epoch,
            objects,
        }
    }

    pub fn geometry(&self) -> BlockGeometry {
        self.geometry
    }

    pub fn committed_generation(&self) -> u64 {
        self.generation
    }

    pub fn objects(&self) -> &[StoredObject] {
        &self.objects
    }

    /// Most live objects this store allows: [`object_limit`] of its geometry.
    pub fn max_objects(&self) -> usize {
        object_limit(self.geometry)
    }

    /// Epoch of the live (possibly staged) object `id`.
    pub fn epoch_of(&self, id: u64) -> Result<u64, StoreError> {
        self.objects
            .iter()
            .find(|object| object.id == id)
            .map(|object| object.epoch)
            .ok_or(StoreError::NotFound)
    }

    pub fn into_inner(self) -> D {
        self.device
    }

    pub fn write_object(&mut self, id: u64, name: &str, data: &[u8]) -> Result<(), StoreError> {
        validate_object_name(name)?;
        if data.len() > u32::MAX as usize {
            return Err(StoreError::ObjectTooLarge {
                len: data.len(),
                max: u32::MAX,
            });
        }

        let id_index = self.objects.iter().position(|object| object.id == id);
        let name_index = self.objects.iter().position(|object| object.name == name);

        let target_index = match (id_index, name_index) {
            (Some(left), Some(right)) if left == right => Some(left),
            (Some(_), Some(_)) => return Err(StoreError::IdentityConflict),
            (Some(index), None) | (None, Some(index)) => Some(index),
            (None, None) => None,
        };

        match target_index {
            Some(index) => {
                // Writing under an existing name with a new id makes a new object: the id a
                // capability names changed, so it gets a new epoch as well.
                let epoch = if self.objects[index].id == id {
                    self.objects[index].epoch
                } else {
                    self.take_epoch()?
                };
                self.objects[index] = StoredObject {
                    id,
                    epoch,
                    name: String::from(name),
                    data: data.to_vec(),
                };
            }
            None => {
                let max_objects = self.max_objects();
                if self.objects.len() >= max_objects {
                    return Err(StoreError::ObjectTableFull { max_objects });
                }
                let epoch = self.take_epoch()?;
                self.objects.push(StoredObject {
                    id,
                    epoch,
                    name: String::from(name),
                    data: data.to_vec(),
                });
            }
        }

        Ok(())
    }

    /// The epoch for an object created now. It is staged with the object: a crash before the
    /// commit point forgets both, so an epoch is durable, and may be handed out, only once
    /// the commit that created its object has returned.
    fn take_epoch(&mut self) -> Result<u64, StoreError> {
        let epoch = self.next_epoch;
        self.next_epoch = epoch.checked_add(1).ok_or(StoreError::EpochExhausted)?;
        Ok(epoch)
    }

    /// Stages the removal of object `id`. Like a write, it takes effect at the next
    /// [`commit`](Self::commit): the committed generation that follows simply has no entry for
    /// it, so the store keeps no tombstone and the payload's blocks are free in the arena that
    /// commit writes. Until then a crash leaves the object as last committed.
    ///
    /// The id and name are free again at once: a later staged write may create a different
    /// object under either, and the commit applies the delete and that write together.
    pub fn delete_object(&mut self, id: u64) -> Result<(), StoreError> {
        let index = self
            .objects
            .iter()
            .position(|object| object.id == id)
            .ok_or(StoreError::NotFound)?;
        self.objects.remove(index);
        Ok(())
    }

    pub fn read_object_by_id(&self, id: u64) -> Result<Vec<u8>, StoreError> {
        self.objects
            .iter()
            .find(|object| object.id == id)
            .map(|object| object.data.clone())
            .ok_or(StoreError::NotFound)
    }

    pub fn read_object_by_name(&self, name: &str) -> Result<Vec<u8>, StoreError> {
        self.objects
            .iter()
            .find(|object| object.name == name)
            .map(|object| object.data.clone())
            .ok_or(StoreError::NotFound)
    }

    pub fn commit(&mut self) -> Result<(), StoreError> {
        let next_slot = (self.active_slot + 1) % SUPERBLOCK_SLOTS;
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(StoreError::GenerationExhausted)?;
        let (object_layout, table) =
            build_object_layout(self.geometry, next_slot, next_generation, &self.objects)?;
        for object in &object_layout {
            write_object_data(&mut self.device, self.geometry, object)?;
        }
        write_table(
            &mut self.device,
            self.geometry,
            table,
            &encode_table(&object_layout),
        )?;
        self.device.flush()?;

        let superblock = Superblock {
            generation: next_generation,
            object_count: u32::try_from(object_layout.len())
                .expect("object layout count fits within u32"),
            next_epoch: self.next_epoch,
            table,
            objects: object_layout,
        };

        write_superblock(&mut self.device, self.geometry, next_slot, &superblock)?;
        self.device.flush()?;
        self.generation = next_generation;
        self.active_slot = next_slot;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ObjectLayout {
    id: u64,
    epoch: u64,
    name: String,
    data: Vec<u8>,
    data_len: u32,
    start_lba: u64,
    block_count: u32,
    data_checksum: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Superblock {
    generation: u64,
    object_count: u32,
    next_epoch: u64,
    table: TableExtent,
    /// Filled from the object table once it is read; empty when only the superblock is.
    objects: Vec<ObjectLayout>,
}

/// Where a commit wrote its object table, and the CRC-32C [`table_checksum`] gives it.
/// An empty table has no blocks and starts at LBA 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TableExtent {
    start_lba: u64,
    block_count: u32,
    checksum: u32,
}

impl Superblock {
    /// What [`ObjectStore::format`] writes to both slots.
    fn fresh() -> Self {
        Self {
            generation: 0,
            object_count: 0,
            next_epoch: FIRST_OBJECT_EPOCH,
            table: TableExtent {
                start_lba: 0,
                block_count: 0,
                checksum: table_checksum(0, 0, &[]),
            },
            objects: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotDecodeError {
    Incompatible(IncompatibleFormatError),
    Corrupt(CorruptFormatError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotLoadError {
    Block(BlockIoError),
    Decode(SlotDecodeError),
}

fn validate_geometry(geometry: BlockGeometry) -> Result<BlockGeometry, StoreError> {
    let logical_block_size = usize::try_from(geometry.logical_block_size()).map_err(|_| {
        StoreError::UnsupportedGeometry {
            logical_block_size: geometry.logical_block_size(),
            block_count: geometry.block_count(),
        }
    })?;
    if logical_block_size < MIN_BLOCK_BYTES || geometry.max_transfer_blocks() == 0 {
        return Err(StoreError::UnsupportedGeometry {
            logical_block_size: geometry.logical_block_size(),
            block_count: geometry.block_count(),
        });
    }
    if data_arena_blocks(geometry) == 0 {
        return Err(StoreError::UnsupportedGeometry {
            logical_block_size: geometry.logical_block_size(),
            block_count: geometry.block_count(),
        });
    }
    Ok(geometry)
}

fn validate_object_name(name: &str) -> Result<(), StoreError> {
    if name.is_empty() {
        return Err(StoreError::InvalidObjectName);
    }
    if name.len() > MAX_OBJECT_NAME_BYTES {
        return Err(StoreError::ObjectNameTooLong {
            len: name.len(),
            max: MAX_OBJECT_NAME_BYTES,
        });
    }
    Ok(())
}

fn block_size_bytes(geometry: BlockGeometry) -> usize {
    usize::try_from(geometry.logical_block_size()).expect("validated block size fits in usize")
}

fn select_committed_state<D: BlockDevice>(
    device: &mut D,
    geometry: BlockGeometry,
) -> Result<CommittedState, StoreError> {
    let slot0 = read_superblock_slot(device, geometry, 0);
    let slot1 = read_superblock_slot(device, geometry, 1);

    let mut candidates = Vec::new();
    let mut block_error = None;
    let mut incompatible_error = None;
    let mut corrupt_error = None;
    for (slot, result) in [(0, slot0), (1, slot1)] {
        match result {
            Ok(superblock) => candidates.push((slot, superblock)),
            Err(SlotLoadError::Block(error)) => block_error = Some(error),
            Err(SlotLoadError::Decode(SlotDecodeError::Incompatible(error))) => {
                incompatible_error = Some(error)
            }
            Err(SlotLoadError::Decode(SlotDecodeError::Corrupt(error))) => {
                corrupt_error = Some(error)
            }
        }
    }

    candidates.sort_unstable_by(
        |left, right| match right.1.generation.cmp(&left.1.generation) {
            Ordering::Equal => left.0.cmp(&right.0),
            order => order,
        },
    );
    for (slot, mut superblock) in candidates {
        let loaded = read_table(device, geometry, slot, &superblock).and_then(|layouts| {
            superblock.objects = layouts;
            load_objects(device, geometry, &superblock.objects)
        });
        match loaded {
            Ok(objects) => return Ok((slot, superblock, objects)),
            Err(StoreError::Corrupt(error)) => corrupt_error = Some(error),
            Err(StoreError::Block(error)) => block_error = Some(error),
            Err(StoreError::Incompatible(error)) => incompatible_error = Some(error),
            Err(other) => return Err(other),
        }
    }

    if let Some(error) = block_error {
        Err(StoreError::Block(error))
    } else if let Some(error) = incompatible_error {
        Err(StoreError::Incompatible(error))
    } else if let Some(error) = corrupt_error {
        Err(StoreError::Corrupt(error))
    } else {
        Err(StoreError::Incompatible(IncompatibleFormatError::BadMagic))
    }
}

fn read_superblock_slot<D: BlockDevice>(
    device: &mut D,
    geometry: BlockGeometry,
    slot: u64,
) -> Result<Superblock, SlotLoadError> {
    let mut bytes = vec![0; block_size_bytes(geometry)];
    device
        .read_blocks(slot, 1, &mut bytes)
        .map_err(SlotLoadError::Block)?;
    decode_superblock(geometry, slot, &bytes).map_err(SlotLoadError::Decode)
}

fn decode_superblock(
    geometry: BlockGeometry,
    slot: u64,
    bytes: &[u8],
) -> Result<Superblock, SlotDecodeError> {
    let magic = read_u32(bytes, 0);
    if magic != STORE_MAGIC {
        return Err(SlotDecodeError::Incompatible(
            IncompatibleFormatError::BadMagic,
        ));
    }

    let version = read_u16(bytes, 4);
    if version != STORE_VERSION {
        return Err(SlotDecodeError::Incompatible(
            IncompatibleFormatError::UnsupportedVersion(version),
        ));
    }

    if superblock_checksum(bytes) != read_u32(bytes, CHECKSUM_RANGE.start) {
        return Err(SlotDecodeError::Corrupt(
            CorruptFormatError::ChecksumMismatch,
        ));
    }

    let reserved = read_u16(bytes, 6);
    let generation = read_u64(bytes, 12);
    let expected_block_size = read_u32(bytes, 20);
    let expected_block_count = read_u64(bytes, 24);
    let max_objects = read_u32(bytes, 32);
    let object_count = read_u32(bytes, 36);
    let data_start_lba = read_u64(bytes, 40);
    let next_epoch = read_u64(bytes, 48);
    let table = TableExtent {
        start_lba: read_u64(bytes, 56),
        block_count: read_u32(bytes, 64),
        checksum: read_u32(bytes, 68),
    };

    if reserved != 0
        || expected_block_size != geometry.logical_block_size()
        || expected_block_count != geometry.block_count()
        || usize::try_from(max_objects).ok() != Some(object_limit(geometry))
        || data_start_lba != DATA_START_LBA
        || bytes[HEADER_BYTES..].iter().any(|&byte| byte != 0)
    {
        return Err(SlotDecodeError::Corrupt(CorruptFormatError::InvalidHeader));
    }
    if object_count > max_objects {
        return Err(SlotDecodeError::Corrupt(
            CorruptFormatError::InvalidObjectCount {
                count: object_count,
            },
        ));
    }
    if next_epoch < FIRST_OBJECT_EPOCH {
        return Err(SlotDecodeError::Corrupt(
            CorruptFormatError::InvalidObjectEpoch,
        ));
    }
    validate_table_extent(geometry, slot, object_count, table).map_err(SlotDecodeError::Corrupt)?;

    Ok(Superblock {
        generation,
        object_count,
        next_epoch,
        table,
        objects: Vec::new(),
    })
}

/// Blocks an object table of `count` entries occupies.
fn table_blocks(geometry: BlockGeometry, count: usize) -> u64 {
    let bytes = u64::try_from(count * TABLE_ENTRY_BYTES).expect("table size fits in u64");
    bytes.div_ceil(u64::from(geometry.logical_block_size()))
}

fn validate_table_extent(
    geometry: BlockGeometry,
    slot: u64,
    object_count: u32,
    table: TableExtent,
) -> Result<(), CorruptFormatError> {
    let count = usize::try_from(object_count).expect("object count fits in usize");
    if u64::from(table.block_count) != table_blocks(geometry, count) {
        return Err(CorruptFormatError::InvalidTableExtent);
    }
    if table.block_count == 0 {
        return if table.start_lba == 0 {
            Ok(())
        } else {
            Err(CorruptFormatError::InvalidTableExtent)
        };
    }
    let arena = slot_data_arena(geometry, slot);
    let end = table
        .start_lba
        .checked_add(u64::from(table.block_count))
        .ok_or(CorruptFormatError::InvalidTableExtent)?;
    if table.start_lba < arena.start || end > arena.end {
        return Err(CorruptFormatError::InvalidTableExtent);
    }
    Ok(())
}

/// Reads and checks the object table `superblock` names, then the layouts it holds.
fn read_table<D: BlockDevice>(
    device: &mut D,
    geometry: BlockGeometry,
    slot: u64,
    superblock: &Superblock,
) -> Result<Vec<ObjectLayout>, StoreError> {
    let count = usize::try_from(superblock.object_count).expect("object count fits in usize");
    let mut bytes = vec![
        0;
        usize::try_from(superblock.table.block_count).expect("fits")
            * block_size_bytes(geometry)
    ];
    if superblock.table.block_count != 0 {
        read_blocks_chunked(
            device,
            geometry,
            superblock.table.start_lba,
            superblock.table.block_count,
            &mut bytes,
        )?;
    }
    let entries = &bytes[..count * TABLE_ENTRY_BYTES];
    if bytes[entries.len()..].iter().any(|&byte| byte != 0)
        || table_checksum(superblock.generation, superblock.table.start_lba, entries)
            != superblock.table.checksum
    {
        return Err(StoreError::Corrupt(
            CorruptFormatError::TableChecksumMismatch,
        ));
    }
    let layouts = decode_table(entries).map_err(StoreError::Corrupt)?;
    validate_layouts(geometry, slot, superblock, &layouts).map_err(StoreError::Corrupt)?;
    Ok(layouts)
}

fn decode_table(entries: &[u8]) -> Result<Vec<ObjectLayout>, CorruptFormatError> {
    let mut layouts = Vec::with_capacity(entries.len() / TABLE_ENTRY_BYTES);
    for entry in entries.chunks_exact(TABLE_ENTRY_BYTES) {
        let name_len = usize::from(read_u16(entry, 36));
        if read_u16(entry, 38) != 0 {
            return Err(CorruptFormatError::InvalidHeader);
        }
        if name_len == 0 || name_len > MAX_OBJECT_NAME_BYTES {
            return Err(CorruptFormatError::InvalidNameEncoding);
        }
        let name_bytes = &entry[40..40 + MAX_OBJECT_NAME_BYTES];
        if name_bytes[name_len..].iter().any(|byte| *byte != 0) {
            return Err(CorruptFormatError::InvalidNameEncoding);
        }
        let name = core::str::from_utf8(&name_bytes[..name_len])
            .map_err(|_| CorruptFormatError::InvalidNameEncoding)?;
        layouts.push(ObjectLayout {
            id: read_u64(entry, 0),
            epoch: read_u64(entry, 8),
            name: String::from(name),
            data: Vec::new(),
            start_lba: read_u64(entry, 16),
            data_len: read_u32(entry, 24),
            block_count: read_u32(entry, 28),
            data_checksum: read_u32(entry, 32),
        });
    }
    Ok(layouts)
}

fn encode_table(layouts: &[ObjectLayout]) -> Vec<u8> {
    let mut bytes = vec![0; layouts.len() * TABLE_ENTRY_BYTES];
    for (entry, object) in bytes.chunks_exact_mut(TABLE_ENTRY_BYTES).zip(layouts) {
        write_u64(entry, 0, object.id);
        write_u64(entry, 8, object.epoch);
        write_u64(entry, 16, object.start_lba);
        write_u32(entry, 24, object.data_len);
        write_u32(entry, 28, object.block_count);
        write_u32(entry, 32, object.data_checksum);
        write_u16(
            entry,
            36,
            u16::try_from(object.name.len()).expect("validated name length fits in u16"),
        );
        let name_bytes = object.name.as_bytes();
        entry[40..40 + name_bytes.len()].copy_from_slice(name_bytes);
    }
    bytes
}

fn write_table<D: BlockDevice>(
    device: &mut D,
    geometry: BlockGeometry,
    table: TableExtent,
    entries: &[u8],
) -> Result<(), StoreError> {
    if table.block_count == 0 {
        return Ok(());
    }
    let block_size = block_size_bytes(geometry);
    let max_blocks = usize::try_from(geometry.max_transfer_blocks()).expect("max transfer fits");
    let total_blocks = usize::try_from(table.block_count).expect("table block count fits");
    let mut bytes = vec![0; total_blocks * block_size];
    bytes[..entries.len()].copy_from_slice(entries);
    for chunk_index in 0..total_blocks.div_ceil(max_blocks) {
        let chunk_start = chunk_index * max_blocks;
        let chunk_blocks = core::cmp::min(max_blocks, total_blocks - chunk_start);
        device.write_blocks(
            table.start_lba + u64::try_from(chunk_start).expect("chunk start fits"),
            u32::try_from(chunk_blocks).expect("chunk blocks fit in u32"),
            &bytes[chunk_start * block_size..(chunk_start + chunk_blocks) * block_size],
        )?;
    }
    Ok(())
}

/// CRC-32C of an object table, bound to the generation that wrote it and where it was
/// written as well as to its bytes.
fn table_checksum(generation: u64, start_lba: u64, entries: &[u8]) -> u32 {
    let mut crc = Crc32c::new();
    crc.update(&generation.to_le_bytes());
    crc.update(&start_lba.to_le_bytes());
    crc.update(
        &u32::try_from(entries.len() / TABLE_ENTRY_BYTES)
            .expect("entry count fits in u32")
            .to_le_bytes(),
    );
    crc.update(entries);
    crc.finish()
}

/// CRC-32C of an object payload, bound to the object's id, epoch, start LBA and length:
/// another object's payload, or this one's at another place, does not match.
fn payload_checksum(id: u64, epoch: u64, start_lba: u64, data: &[u8]) -> u32 {
    let mut crc = Crc32c::new();
    crc.update(&id.to_le_bytes());
    crc.update(&epoch.to_le_bytes());
    crc.update(&start_lba.to_le_bytes());
    crc.update(
        &u32::try_from(data.len())
            .expect("object length fits in u32")
            .to_le_bytes(),
    );
    crc.update(data);
    crc.finish()
}

fn validate_layouts(
    geometry: BlockGeometry,
    slot: u64,
    superblock: &Superblock,
    objects: &[ObjectLayout],
) -> Result<(), CorruptFormatError> {
    let arena = slot_data_arena(geometry, slot);
    for (left_index, left) in objects.iter().enumerate() {
        if objects[..left_index]
            .iter()
            .any(|other| other.id == left.id)
        {
            return Err(CorruptFormatError::DuplicateObjectId(left.id));
        }
        if objects[..left_index]
            .iter()
            .any(|other| other.name == left.name)
        {
            return Err(CorruptFormatError::DuplicateObjectName);
        }
        if left.epoch < FIRST_OBJECT_EPOCH
            || left.epoch >= superblock.next_epoch
            || objects[..left_index]
                .iter()
                .any(|other| other.epoch == left.epoch)
        {
            return Err(CorruptFormatError::InvalidObjectEpoch);
        }

        if left.data_len == 0 {
            if left.block_count != 0 || left.start_lba < arena.start || left.start_lba > arena.end {
                return Err(CorruptFormatError::InvalidObjectExtent);
            }
            continue;
        }

        if left.block_count == 0 {
            return Err(CorruptFormatError::InvalidObjectExtent);
        }

        let max_len = u64::from(left.block_count) * u64::from(geometry.logical_block_size());
        if u64::from(left.data_len) > max_len {
            return Err(CorruptFormatError::InvalidObjectLength);
        }

        let end_lba = left
            .start_lba
            .checked_add(u64::from(left.block_count))
            .ok_or(CorruptFormatError::InvalidObjectExtent)?;
        if left.start_lba < arena.start || end_lba > arena.end {
            return Err(CorruptFormatError::InvalidObjectExtent);
        }
    }

    let mut ranges = objects
        .iter()
        .filter(|object| object.block_count != 0)
        .map(|object| {
            (
                object.start_lba,
                object.start_lba + u64::from(object.block_count),
            )
        })
        .collect::<Vec<_>>();
    if superblock.table.block_count != 0 {
        ranges.push((
            superblock.table.start_lba,
            superblock.table.start_lba + u64::from(superblock.table.block_count),
        ));
    }
    ranges.sort_unstable_by_key(|range| range.0);

    for window in ranges.windows(2) {
        if window[0].1 > window[1].0 {
            return Err(CorruptFormatError::OverlappingObjectExtents);
        }
    }

    Ok(())
}

fn load_objects<D: BlockDevice>(
    device: &mut D,
    geometry: BlockGeometry,
    layouts: &[ObjectLayout],
) -> Result<Vec<StoredObject>, StoreError> {
    let mut objects = Vec::with_capacity(layouts.len());
    for layout in layouts {
        let data = read_object_data(device, geometry, layout)?;
        objects.push(StoredObject {
            id: layout.id,
            epoch: layout.epoch,
            name: layout.name.clone(),
            data,
        });
    }
    Ok(objects)
}

fn build_object_layout(
    geometry: BlockGeometry,
    slot: u64,
    generation: u64,
    objects: &[StoredObject],
) -> Result<(Vec<ObjectLayout>, TableExtent), StoreError> {
    let block_size = u64::from(geometry.logical_block_size());
    let arena = slot_data_arena(geometry, slot);
    let mut next_lba = arena.start;
    let mut layouts = Vec::with_capacity(objects.len());

    for object in objects {
        validate_object_name(object.name())?;
        let data_len_u32 =
            u32::try_from(object.data.len()).map_err(|_| StoreError::ObjectTooLarge {
                len: object.data.len(),
                max: u32::MAX,
            })?;
        let block_count = if object.data.is_empty() {
            0
        } else {
            u32::try_from(
                (u64::from(data_len_u32) + (block_size - 1))
                    .checked_div(block_size)
                    .expect("non-zero block size"),
            )
            .expect("device-sized object block count fits in u32")
        };

        let object_start = next_lba;
        next_lba = next_lba
            .checked_add(u64::from(block_count))
            .ok_or(StoreError::StorageFull {
                required_blocks: u64::MAX,
                available_blocks: data_arena_blocks(geometry),
            })?;

        layouts.push(ObjectLayout {
            id: object.id,
            epoch: object.epoch,
            name: object.name.clone(),
            data: object.data.clone(),
            data_len: data_len_u32,
            start_lba: object_start,
            block_count,
            data_checksum: payload_checksum(
                object.id,
                object.epoch,
                object_start,
                object.data.as_slice(),
            ),
        });
    }

    // The table follows the payloads it describes.
    let table_block_count = table_blocks(geometry, layouts.len());
    let table_start = if table_block_count == 0 { 0 } else { next_lba };
    next_lba = next_lba.saturating_add(table_block_count);

    let available_blocks = data_arena_blocks(geometry);
    let required_blocks = next_lba.saturating_sub(arena.start);
    if next_lba > arena.end {
        return Err(StoreError::StorageFull {
            required_blocks,
            available_blocks,
        });
    }

    let table = TableExtent {
        start_lba: table_start,
        block_count: u32::try_from(table_block_count).expect("table fits within the arena"),
        checksum: table_checksum(generation, table_start, &encode_table(&layouts)),
    };
    Ok((layouts, table))
}

fn write_superblock<D: BlockDevice>(
    device: &mut D,
    geometry: BlockGeometry,
    slot: u64,
    superblock: &Superblock,
) -> Result<(), StoreError> {
    let bytes = encode_superblock(geometry, superblock)?;
    device.write_blocks(slot, 1, &bytes)?;
    Ok(())
}

fn encode_superblock(
    geometry: BlockGeometry,
    superblock: &Superblock,
) -> Result<Vec<u8>, StoreError> {
    let mut bytes = vec![0; block_size_bytes(geometry)];
    write_u32(&mut bytes, 0, STORE_MAGIC);
    write_u16(&mut bytes, 4, STORE_VERSION);
    write_u64(&mut bytes, 12, superblock.generation);
    write_u32(&mut bytes, 20, geometry.logical_block_size());
    write_u64(&mut bytes, 24, geometry.block_count());
    write_u32(
        &mut bytes,
        32,
        u32::try_from(object_limit(geometry)).expect("object limit fits in u32"),
    );
    write_u32(&mut bytes, 36, superblock.object_count);
    write_u64(&mut bytes, 40, DATA_START_LBA);
    write_u64(&mut bytes, 48, superblock.next_epoch);
    write_u64(&mut bytes, 56, superblock.table.start_lba);
    write_u32(&mut bytes, 64, superblock.table.block_count);
    write_u32(&mut bytes, 68, superblock.table.checksum);

    let checksum = superblock_checksum(&bytes);
    write_u32(&mut bytes, CHECKSUM_RANGE.start, checksum);
    Ok(bytes)
}

fn write_object_data<D: BlockDevice>(
    device: &mut D,
    geometry: BlockGeometry,
    object: &ObjectLayout,
) -> Result<(), StoreError> {
    if object.block_count == 0 {
        return Ok(());
    }

    let block_size = block_size_bytes(geometry);
    let max_blocks = usize::try_from(geometry.max_transfer_blocks()).expect("max transfer fits");
    let total_blocks = usize::try_from(object.block_count).expect("object block count fits");

    for chunk_index in 0..total_blocks.div_ceil(max_blocks) {
        let chunk_start_block = chunk_index * max_blocks;
        let chunk_blocks = core::cmp::min(max_blocks, total_blocks - chunk_start_block);
        let mut buffer = vec![0; chunk_blocks * block_size];
        let data_start = chunk_start_block * block_size;
        let data_end = core::cmp::min(object.data.len(), data_start + buffer.len());
        if data_start < data_end {
            buffer[..(data_end - data_start)].copy_from_slice(&object.data[data_start..data_end]);
        }
        device.write_blocks(
            object.start_lba + u64::try_from(chunk_start_block).expect("chunk start fits"),
            u32::try_from(chunk_blocks).expect("chunk blocks fit in u32"),
            &buffer,
        )?;
    }

    Ok(())
}

fn data_arena_blocks(geometry: BlockGeometry) -> u64 {
    geometry
        .block_count()
        .saturating_sub(DATA_START_LBA)
        .checked_div(SUPERBLOCK_SLOTS)
        .expect("constant non-zero slot count")
}

fn slot_data_arena(geometry: BlockGeometry, slot: u64) -> core::ops::Range<u64> {
    let arena_blocks = data_arena_blocks(geometry);
    let start = DATA_START_LBA + (slot * arena_blocks);
    start..(start + arena_blocks)
}

fn read_object_data<D: BlockDevice>(
    device: &mut D,
    geometry: BlockGeometry,
    object: &ObjectLayout,
) -> Result<Vec<u8>, StoreError> {
    if object.block_count == 0 {
        return Ok(Vec::new());
    }

    let block_size = block_size_bytes(geometry);
    let total_len = usize::try_from(object.block_count)
        .expect("object block count fits")
        .checked_mul(block_size)
        .expect("object byte length fits");
    let mut bytes = vec![0; total_len];
    read_blocks_chunked(
        device,
        geometry,
        object.start_lba,
        object.block_count,
        &mut bytes,
    )?;
    bytes.truncate(usize::try_from(object.data_len).expect("data length fits"));
    if payload_checksum(object.id, object.epoch, object.start_lba, bytes.as_slice())
        != object.data_checksum
    {
        return Err(StoreError::Corrupt(
            CorruptFormatError::ObjectChecksumMismatch,
        ));
    }
    Ok(bytes)
}

fn read_blocks_chunked<D: BlockDevice>(
    device: &mut D,
    geometry: BlockGeometry,
    start_lba: u64,
    total_blocks: u32,
    buffer: &mut [u8],
) -> Result<(), StoreError> {
    let block_size = block_size_bytes(geometry);
    let max_blocks = usize::try_from(geometry.max_transfer_blocks()).expect("max transfer fits");
    let total_blocks = usize::try_from(total_blocks).expect("total blocks fit");

    for chunk_index in 0..total_blocks.div_ceil(max_blocks) {
        let chunk_start_block = chunk_index * max_blocks;
        let chunk_blocks = core::cmp::min(max_blocks, total_blocks - chunk_start_block);
        let byte_start = chunk_start_block * block_size;
        let byte_end = byte_start + (chunk_blocks * block_size);
        device.read_blocks(
            start_lba + u64::try_from(chunk_start_block).expect("chunk start fits"),
            u32::try_from(chunk_blocks).expect("chunk blocks fit"),
            &mut buffer[byte_start..byte_end],
        )?;
    }

    Ok(())
}

/// CRC-32C of a superblock block, computed as if its checksum field were zero.
fn superblock_checksum(bytes: &[u8]) -> u32 {
    let mut crc = Crc32c::new();
    crc.update(&bytes[..CHECKSUM_RANGE.start]);
    crc.update(&[0; CHECKSUM_RANGE.end - CHECKSUM_RANGE.start]);
    crc.update(&bytes[CHECKSUM_RANGE.end..]);
    crc.finish()
}

/// Format version 1's superblock checksum: an additive byte sum skipping the checksum field.
fn version_one_checksum(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .enumerate()
        .filter(|(index, _)| !CHECKSUM_RANGE.contains(index))
        .fold(0u32, |sum, (_, byte)| sum.wrapping_add(u32::from(*byte)))
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("slice"))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("slice"))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("slice"))
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_block::fake::FakeBlockDevice;
    use clean_slate_block::{BlockDeviceId, BlockGeometry};

    const GENERATION_BYTE: usize = 12;

    fn geometry() -> BlockGeometry {
        BlockGeometry::new(BlockDeviceId::new(11), 512, 32, 2, false).unwrap()
    }

    fn tiny_geometry() -> BlockGeometry {
        BlockGeometry::new(BlockDeviceId::new(12), 512, 4, 2, false).unwrap()
    }

    fn single_block_transfer_geometry() -> BlockGeometry {
        BlockGeometry::new(BlockDeviceId::new(13), 512, 32, 1, false).unwrap()
    }

    fn reboot(store: ObjectStore<FakeBlockDevice>) -> ObjectStore<FakeBlockDevice> {
        let device = store.into_inner();
        let rebooted =
            FakeBlockDevice::from_durable_bytes(device.geometry(), device.durable_bytes()).unwrap();
        ObjectStore::mount(rebooted).unwrap()
    }

    fn durable_slot(device: &mut FakeBlockDevice, slot: u64) -> Vec<u8> {
        let mut bytes = vec![0; block_size_bytes(device.geometry())];
        device.read_blocks(slot, 1, &mut bytes).unwrap();
        bytes
    }

    /// The object layouts the superblock in `slot` commits, read through its table.
    fn committed_layouts(device: &mut FakeBlockDevice, slot: u64) -> Vec<ObjectLayout> {
        let geometry = device.geometry();
        let bytes = durable_slot(device, slot);
        let superblock = decode_superblock(geometry, slot, &bytes).unwrap();
        read_table(device, geometry, slot, &superblock).unwrap()
    }

    /// Writes `layouts` as the table of a generation-1 superblock in slot 0 and slot 1, with
    /// valid table and superblock checksums whatever the entries hold, so a mount reaches
    /// the layout checks.
    fn forge_committed_table(device: &mut FakeBlockDevice, layouts: &[ObjectLayout]) {
        forge_committed_tables(device, |_| layouts.to_vec());
    }

    /// As [`forge_committed_table`], with each slot's layouts from `layouts_for(slot)`.
    fn forge_committed_tables(
        device: &mut FakeBlockDevice,
        layouts_for: impl Fn(u64) -> Vec<ObjectLayout>,
    ) {
        let geometry = device.geometry();
        for slot in 0..SUPERBLOCK_SLOTS {
            let layouts = layouts_for(slot);
            let layouts = layouts.as_slice();
            let table_start = slot_data_arena(geometry, slot).end - 1;
            let entries = encode_table(layouts);
            let superblock = Superblock {
                generation: 1,
                object_count: u32::try_from(layouts.len()).unwrap(),
                next_epoch: 100,
                table: TableExtent {
                    start_lba: table_start,
                    block_count: 1,
                    checksum: table_checksum(1, table_start, &entries),
                },
                objects: Vec::new(),
            };
            let mut block = vec![0; 512];
            block[..entries.len()].copy_from_slice(&entries);
            device.write_blocks(table_start, 1, &block).unwrap();
            write_superblock(device, geometry, slot, &superblock).unwrap();
        }
        device.flush().unwrap();
    }

    fn forged_layout(start_lba: u64, data_len: u32, block_count: u32) -> ObjectLayout {
        ObjectLayout {
            id: 7,
            epoch: 1,
            name: String::from("alpha"),
            data: Vec::new(),
            data_len,
            start_lba,
            block_count,
            data_checksum: 0,
        }
    }

    #[test]
    fn format_commit_and_remount_round_trip_two_objects() {
        let device = FakeBlockDevice::new(geometry()).unwrap();
        let mut store = ObjectStore::format(device).unwrap();

        store.write_object(1, "alpha", b"hello").unwrap();
        store.write_object(2, "beta", b"world!").unwrap();
        store.commit().unwrap();

        let store = reboot(store);
        assert_eq!(store.read_object_by_id(1).unwrap(), b"hello");
        assert_eq!(store.read_object_by_name("beta").unwrap(), b"world!");
        assert_eq!(store.objects().len(), 2);
        assert_eq!(store.committed_generation(), 1);
    }

    #[test]
    fn format_empty_device_mounts_from_durable_bytes() {
        let device = FakeBlockDevice::new(geometry()).unwrap();
        let store = ObjectStore::format(device).unwrap();

        let store = reboot(store);
        assert!(store.objects().is_empty());
        assert_eq!(store.committed_generation(), 0);
    }

    #[test]
    fn overwrite_preserves_unrelated_object() {
        let device = FakeBlockDevice::new(geometry()).unwrap();
        let mut store = ObjectStore::format(device).unwrap();

        store.write_object(1, "alpha", b"old").unwrap();
        store.write_object(2, "beta", b"keep-me").unwrap();
        store.commit().unwrap();

        store.write_object(1, "alpha", b"replacement-data").unwrap();
        store.commit().unwrap();

        let store = reboot(store);
        assert_eq!(store.read_object_by_id(1).unwrap(), b"replacement-data");
        assert_eq!(store.read_object_by_id(2).unwrap(), b"keep-me");
        assert_eq!(store.committed_generation(), 2);
    }

    #[test]
    fn commits_alternate_disjoint_payload_arenas() {
        let device = FakeBlockDevice::new(geometry()).unwrap();
        let mut store = ObjectStore::format(device).unwrap();

        store.write_object(1, "alpha", &[0x11; 700]).unwrap();
        store.commit().unwrap();
        let mut device = store.into_inner();
        let first = committed_layouts(&mut device, 1);
        let first_extent = (
            first[0].start_lba,
            first[0].start_lba + u64::from(first[0].block_count),
        );

        let mut store = ObjectStore::mount(device).unwrap();
        store.write_object(1, "alpha", &[0x22; 700]).unwrap();
        store.commit().unwrap();
        let mut device = store.into_inner();
        let second = committed_layouts(&mut device, 0);
        let second_extent = (
            second[0].start_lba,
            second[0].start_lba + u64::from(second[0].block_count),
        );

        assert!(first_extent.1 <= second_extent.0 || second_extent.1 <= first_extent.0);
        assert_eq!(first_extent.0, slot_data_arena(geometry(), 1).start);
        assert_eq!(second_extent.0, slot_data_arena(geometry(), 0).start);
    }

    #[test]
    fn multi_chunk_commit_and_read_round_trip() {
        let device = FakeBlockDevice::new(single_block_transfer_geometry()).unwrap();
        let mut store = ObjectStore::format(device).unwrap();
        let payload = vec![0x5a; 1300];

        store.write_object(7, "chunked", &payload).unwrap();
        store.commit().unwrap();

        let store = reboot(store);
        assert_eq!(store.read_object_by_id(7).unwrap(), payload);
    }

    #[test]
    fn not_found_is_deterministic() {
        let device = FakeBlockDevice::new(geometry()).unwrap();
        let store = ObjectStore::format(device).unwrap();

        assert_eq!(store.read_object_by_id(99), Err(StoreError::NotFound));
        assert_eq!(
            store.read_object_by_name("missing"),
            Err(StoreError::NotFound)
        );
    }

    #[test]
    fn commit_reports_storage_full() {
        let device = FakeBlockDevice::new(tiny_geometry()).unwrap();
        let mut store = ObjectStore::format(device).unwrap();

        store.write_object(1, "alpha", &[0x55; 1025]).unwrap();

        assert_eq!(
            store.commit(),
            Err(StoreError::StorageFull {
                // Three payload blocks and one table block.
                required_blocks: 4,
                available_blocks: 1,
            })
        );
    }

    #[test]
    fn commit_rejects_generation_exhaustion() {
        let device = FakeBlockDevice::new(geometry()).unwrap();
        let mut store = ObjectStore::format(device).unwrap();
        store.generation = u64::MAX;

        assert_eq!(store.commit(), Err(StoreError::GenerationExhausted));
    }

    #[test]
    fn staged_writes_are_not_durable_until_commit() {
        let device = FakeBlockDevice::new(geometry()).unwrap();
        let mut store = ObjectStore::format(device).unwrap();

        store.write_object(1, "alpha", b"pending").unwrap();
        assert_eq!(store.read_object_by_id(1).unwrap(), b"pending");

        let store = reboot(store);
        assert_eq!(store.read_object_by_id(1), Err(StoreError::NotFound));
    }

    #[test]
    fn write_rejects_full_object_table() {
        let device = FakeBlockDevice::new(geometry()).unwrap();
        let mut store = ObjectStore::format(device).unwrap();
        assert_eq!(store.max_objects(), MIN_OBJECT_LIMIT);

        for index in 0..MIN_OBJECT_LIMIT as u64 {
            store
                .write_object(index, &format!("obj{index}"), &[])
                .unwrap();
        }

        assert_eq!(
            store.write_object(999, "overflow", b"x"),
            Err(StoreError::ObjectTableFull {
                max_objects: MIN_OBJECT_LIMIT,
            })
        );
    }

    #[test]
    fn object_limit_grows_with_the_disk_between_its_bounds() {
        let geometry_of =
            |blocks| BlockGeometry::new(BlockDeviceId::new(14), 512, blocks, 8, false).unwrap();
        assert_eq!(object_limit(geometry_of(32)), MIN_OBJECT_LIMIT);
        // The 64 MiB QEMU data disk: two arenas of 65535 blocks.
        assert_eq!(object_limit(geometry_of(131_072)), 4095);
        assert_eq!(object_limit(geometry_of(1 << 40)), MAX_OBJECT_LIMIT);
    }

    #[test]
    fn many_more_than_seven_objects_commit_and_survive_a_reboot() {
        let geometry = BlockGeometry::new(BlockDeviceId::new(15), 512, 8192, 8, false).unwrap();
        let mut store = ObjectStore::format(FakeBlockDevice::new(geometry).unwrap()).unwrap();
        for index in 0..200u64 {
            let data = vec![index as u8; usize::try_from(index % 3).unwrap() * 300];
            store
                .write_object(index, &format!("obj{index}"), &data)
                .unwrap();
        }
        store.commit().unwrap();
        for index in (0..200u64).step_by(2) {
            store.delete_object(index).unwrap();
        }
        store.commit().unwrap();

        let device = store.into_inner();
        let store = ObjectStore::mount(
            FakeBlockDevice::from_durable_bytes(geometry, device.durable_bytes()).unwrap(),
        )
        .unwrap();
        assert_eq!(store.objects().len(), 100);
        for index in 0..200u64 {
            let read = store.read_object_by_id(index);
            if index % 2 == 0 {
                assert_eq!(read, Err(StoreError::NotFound));
            } else {
                assert_eq!(
                    read.unwrap(),
                    vec![index as u8; usize::try_from(index % 3).unwrap() * 300]
                );
            }
        }
    }

    #[test]
    fn epochs_are_kept_by_rewrites_and_never_reused_after_a_delete() {
        let device = FakeBlockDevice::new(geometry()).unwrap();
        let mut store = ObjectStore::format(device).unwrap();
        store.write_object(1, "alpha", b"v1").unwrap();
        store.write_object(2, "beta", b"v1").unwrap();
        let alpha = store.epoch_of(1).unwrap();
        assert_eq!(alpha, FIRST_OBJECT_EPOCH);
        store.commit().unwrap();

        store.write_object(1, "alpha", b"v2").unwrap();
        assert_eq!(store.epoch_of(1).unwrap(), alpha);
        store.delete_object(1).unwrap();
        store.commit().unwrap();

        // Re-created under the same id and name after a reboot: a new, larger epoch.
        let mut store = reboot(store);
        store.write_object(1, "alpha", b"again").unwrap();
        let recreated = store.epoch_of(1).unwrap();
        assert!(recreated > store.epoch_of(2).unwrap());
        store.commit().unwrap();
        let store = reboot(store);
        assert_eq!(store.epoch_of(1).unwrap(), recreated);
        assert_ne!(recreated, alpha);
    }

    #[test]
    fn taking_a_name_under_a_new_id_is_a_new_epoch() {
        let device = FakeBlockDevice::new(geometry()).unwrap();
        let mut store = ObjectStore::format(device).unwrap();
        store.write_object(1, "alpha", b"v1").unwrap();
        let first = store.epoch_of(1).unwrap();
        store.write_object(5, "alpha", b"v2").unwrap();
        assert_eq!(store.epoch_of(1), Err(StoreError::NotFound));
        assert!(store.epoch_of(5).unwrap() > first);
    }

    #[test]
    fn an_older_version_two_image_is_refused_not_reformatted() {
        let mut device = device_holding_one_object();
        for slot_lba in 0..SUPERBLOCK_SLOTS {
            let mut slot = durable_slot(&mut device, slot_lba);
            set_version_with_valid_crc(&mut slot, 2);
            device.write_blocks(slot_lba, 1, &slot).unwrap();
        }
        device.flush().unwrap();
        assert_open_refuses(device, Refusal::UnsupportedVersion(2));
    }

    #[test]
    fn a_payload_moved_to_another_objects_place_is_rejected() {
        // Two objects with the same bytes: only the id and location binding tells their
        // payloads apart. Swap the table's extents and the payloads still read back
        // byte for byte, so the binding is all that rejects the generation.
        let device = FakeBlockDevice::new(geometry()).unwrap();
        let mut store = ObjectStore::format(device).unwrap();
        store.write_object(1, "alpha", &[0x5a; 300]).unwrap();
        store.write_object(2, "beta", &[0x5a; 300]).unwrap();
        store.commit().unwrap();
        let mut device = store.into_inner();
        let mut layouts = committed_layouts(&mut device, 1);
        let (left, right) = (layouts[0].start_lba, layouts[1].start_lba);
        layouts[0].start_lba = right;
        layouts[1].start_lba = left;
        let mut slot = durable_slot(&mut device, 1);
        let superblock = decode_superblock(geometry(), 1, &slot).unwrap();
        let entries = encode_table(&layouts);
        let mut block = vec![0; 512];
        block[..entries.len()].copy_from_slice(&entries);
        device
            .write_blocks(superblock.table.start_lba, 1, &block)
            .unwrap();
        let checksum = table_checksum(1, superblock.table.start_lba, &entries);
        slot[68..72].copy_from_slice(&checksum.to_le_bytes());
        let sum = superblock_checksum(&slot);
        slot[CHECKSUM_RANGE].copy_from_slice(&sum.to_le_bytes());
        device.write_blocks(1, 1, &slot).unwrap();
        device.flush().unwrap();

        assert_eq!(
            ObjectStore::mount(device).unwrap().committed_generation(),
            0,
            "generation 1 must be rejected, leaving the fresh generation 0"
        );
    }

    #[test]
    fn delete_commits_and_survives_a_reboot() {
        let device = FakeBlockDevice::new(geometry()).unwrap();
        let mut store = ObjectStore::format(device).unwrap();
        store.write_object(1, "alpha", b"hello").unwrap();
        store.write_object(2, "beta", b"world").unwrap();
        store.commit().unwrap();

        store.delete_object(1).unwrap();
        assert_eq!(store.read_object_by_id(1), Err(StoreError::NotFound));
        assert_eq!(
            store.read_object_by_name("alpha"),
            Err(StoreError::NotFound)
        );
        store.commit().unwrap();

        let store = reboot(store);
        assert_eq!(store.committed_generation(), 2);
        assert_eq!(store.read_object_by_id(1), Err(StoreError::NotFound));
        assert_eq!(store.read_object_by_id(2).unwrap(), b"world");
        assert_eq!(store.objects().len(), 1);
    }

    #[test]
    fn staged_delete_is_not_durable_until_commit() {
        let device = FakeBlockDevice::new(geometry()).unwrap();
        let mut store = ObjectStore::format(device).unwrap();
        store.write_object(1, "alpha", b"kept").unwrap();
        store.commit().unwrap();

        store.delete_object(1).unwrap();
        let store = reboot(store);
        assert_eq!(store.read_object_by_id(1).unwrap(), b"kept");
    }

    #[test]
    fn delete_of_an_absent_object_is_not_found_and_changes_nothing() {
        let device = FakeBlockDevice::new(geometry()).unwrap();
        let mut store = ObjectStore::format(device).unwrap();
        store.write_object(1, "alpha", b"a").unwrap();
        assert_eq!(store.delete_object(9), Err(StoreError::NotFound));
        store.delete_object(1).unwrap();
        assert_eq!(store.delete_object(1), Err(StoreError::NotFound));
        assert!(store.objects().is_empty());
    }

    #[test]
    fn delete_frees_a_table_entry_and_a_name_for_reuse() {
        // Large enough for a full table of the minimum limit.
        let geometry = BlockGeometry::new(BlockDeviceId::new(17), 512, 256, 8, false).unwrap();
        let mut store = ObjectStore::format(FakeBlockDevice::new(geometry).unwrap()).unwrap();
        for index in 0..MIN_OBJECT_LIMIT as u64 {
            store
                .write_object(index, &format!("obj{index}"), &[])
                .unwrap();
        }
        store.commit().unwrap();
        assert!(matches!(
            store.write_object(999, "extra", b"x"),
            Err(StoreError::ObjectTableFull { .. })
        ));

        // One commit deletes obj0, then gives its name to a new id and its id to a new name.
        store.delete_object(0).unwrap();
        store.write_object(999, "obj0", b"new-name-owner").unwrap();
        store.delete_object(1).unwrap();
        store.write_object(1, "renamed", b"new-id-owner").unwrap();
        store.commit().unwrap();

        let store = reboot(store);
        assert_eq!(store.objects().len(), MIN_OBJECT_LIMIT);
        assert_eq!(
            store.read_object_by_name("obj0").unwrap(),
            b"new-name-owner"
        );
        assert_eq!(store.read_object_by_id(0), Err(StoreError::NotFound));
        assert_eq!(store.read_object_by_id(1).unwrap(), b"new-id-owner");
        assert_eq!(store.read_object_by_name("obj1"), Err(StoreError::NotFound));
    }

    #[test]
    fn deleted_payload_space_is_free_for_the_next_commit() {
        // Each arena holds three blocks: one two-block payload and the table's block.
        let geometry = BlockGeometry::new(BlockDeviceId::new(16), 512, 8, 2, false).unwrap();
        let mut store = ObjectStore::format(FakeBlockDevice::new(geometry).unwrap()).unwrap();
        store.write_object(1, "alpha", &[0x11; 1024]).unwrap();
        store.commit().unwrap();
        store.write_object(2, "beta", &[0x22; 1024]).unwrap();
        assert!(matches!(
            store.commit(),
            Err(StoreError::StorageFull { .. })
        ));

        store.delete_object(1).unwrap();
        store.commit().unwrap();
        let store = reboot(store);
        assert_eq!(store.read_object_by_id(1), Err(StoreError::NotFound));
        assert_eq!(store.read_object_by_id(2).unwrap(), [0x22; 1024]);
    }

    #[test]
    fn corrupt_magic_is_rejected() {
        let mut device = FakeBlockDevice::new(geometry()).unwrap();
        let zeroes = vec![0; 512];
        device.write_blocks(0, 1, &zeroes).unwrap();
        device.write_blocks(1, 1, &zeroes).unwrap();
        device.flush().unwrap();

        assert_eq!(
            ObjectStore::mount(device).unwrap_err(),
            StoreError::Incompatible(IncompatibleFormatError::BadMagic)
        );
    }

    #[test]
    fn corrupt_version_is_rejected() {
        let device = FakeBlockDevice::new(geometry()).unwrap();
        let store = ObjectStore::format(device).unwrap();
        let mut device = store.into_inner();
        let mut slot = vec![0; 512];
        device.read_blocks(0, 1, &mut slot).unwrap();
        slot[4..6].copy_from_slice(&99u16.to_le_bytes());
        slot[CHECKSUM_RANGE.start..CHECKSUM_RANGE.end].copy_from_slice(&0u32.to_le_bytes());
        let sum = superblock_checksum(&slot);
        slot[CHECKSUM_RANGE.start..CHECKSUM_RANGE.end].copy_from_slice(&sum.to_le_bytes());
        device.write_blocks(0, 1, &slot).unwrap();
        device.write_blocks(1, 1, &slot).unwrap();
        device.flush().unwrap();

        assert_eq!(
            ObjectStore::mount(device).unwrap_err(),
            StoreError::Incompatible(IncompatibleFormatError::UnsupportedVersion(99))
        );
    }

    /// Rewrite a superblock as format version 1 wrote it: version field 1 and
    /// an additive byte sum over the block with the checksum field skipped.
    fn downgrade_to_version_one(slot: &mut [u8]) {
        slot[4..6].copy_from_slice(&1u16.to_le_bytes());
        let byte_sum = version_one_checksum(slot);
        slot[CHECKSUM_RANGE.start..CHECKSUM_RANGE.end].copy_from_slice(&byte_sum.to_le_bytes());
    }

    /// Rewrite a superblock as a later format version would, keeping a valid CRC-32C.
    fn set_version_with_valid_crc(slot: &mut [u8], version: u16) {
        slot[4..6].copy_from_slice(&version.to_le_bytes());
        let crc = superblock_checksum(slot);
        slot[CHECKSUM_RANGE.start..CHECKSUM_RANGE.end].copy_from_slice(&crc.to_le_bytes());
    }

    #[test]
    fn version_one_image_is_refused_as_unsupported_version() {
        let device = FakeBlockDevice::new(geometry()).unwrap();
        let mut store = ObjectStore::format(device).unwrap();
        store.write_object(1, "alpha", b"v1-era payload").unwrap();
        store.commit().unwrap();
        let mut device = store.into_inner();
        for slot_lba in 0..SUPERBLOCK_SLOTS {
            let mut slot = durable_slot(&mut device, slot_lba);
            downgrade_to_version_one(&mut slot);
            device.write_blocks(slot_lba, 1, &slot).unwrap();
        }
        device.flush().unwrap();

        assert_eq!(
            ObjectStore::mount(device).unwrap_err(),
            StoreError::Incompatible(IncompatibleFormatError::UnsupportedVersion(1))
        );
    }

    fn device_holding_one_object() -> FakeBlockDevice {
        let mut store = ObjectStore::format(FakeBlockDevice::new(geometry()).unwrap()).unwrap();
        store.write_object(1, "alpha", b"keep me").unwrap();
        store.commit().unwrap();
        store.into_inner()
    }

    /// Counts the writes and flushes that reach `inner`; clones share the counter.
    #[derive(Clone, Debug)]
    struct CountingDevice {
        inner: FakeBlockDevice,
        mutations: std::rc::Rc<core::cell::Cell<usize>>,
    }

    impl BlockDevice for CountingDevice {
        fn geometry(&self) -> BlockGeometry {
            self.inner.geometry()
        }

        fn read_blocks(
            &mut self,
            lba: u64,
            blocks: u32,
            buffer: &mut [u8],
        ) -> Result<(), BlockIoError> {
            self.inner.read_blocks(lba, blocks, buffer)
        }

        fn write_blocks(
            &mut self,
            lba: u64,
            blocks: u32,
            buffer: &[u8],
        ) -> Result<(), BlockIoError> {
            self.mutations.set(self.mutations.get() + 1);
            self.inner.write_blocks(lba, blocks, buffer)
        }

        fn flush(&mut self) -> Result<(), BlockIoError> {
            self.mutations.set(self.mutations.get() + 1);
            self.inner.flush()
        }
    }

    fn assert_open_refuses(mut device: FakeBlockDevice, expected: Refusal) {
        assert_eq!(probe(&mut device), Ok(Probe::Refused(expected)));
        let counting = CountingDevice {
            inner: device,
            mutations: Default::default(),
        };
        assert_eq!(
            ObjectStore::open(counting.clone()).unwrap_err(),
            OpenError::Refused(expected)
        );
        assert_eq!(
            counting.mutations.get(),
            0,
            "open wrote to a refused device"
        );
    }

    #[test]
    fn open_on_a_blank_device_is_the_only_open_that_writes() {
        let counting = CountingDevice {
            inner: FakeBlockDevice::new(geometry()).unwrap(),
            mutations: Default::default(),
        };
        let (_, opened) = ObjectStore::open(counting.clone()).unwrap();
        assert_eq!(opened, Opened::Formatted);
        assert!(counting.mutations.get() > 0);

        let counting = CountingDevice {
            inner: device_holding_one_object(),
            mutations: Default::default(),
        };
        let (store, opened) = ObjectStore::open(counting.clone()).unwrap();
        assert_eq!(opened, Opened::Mounted);
        assert_eq!(store.read_object_by_id(1).unwrap(), b"keep me");
        assert_eq!(counting.mutations.get(), 0);
    }

    fn fresh_superblock_prefix(bytes: usize) -> Vec<u8> {
        let mut slot = encode_superblock(geometry(), &Superblock::fresh()).unwrap();
        slot[bytes..].fill(0);
        slot
    }

    fn device_with_slots(slot_a: &[u8], slot_b: &[u8]) -> FakeBlockDevice {
        let mut device = FakeBlockDevice::new(geometry()).unwrap();
        device.write_blocks(0, 1, slot_a).unwrap();
        device.write_blocks(1, 1, slot_b).unwrap();
        device.flush().unwrap();
        device
    }

    #[test]
    fn a_torn_first_format_is_refused_as_interrupted_not_formatted() {
        let blank = vec![0; 512];
        for bytes in [1, 3, 4, 9, 40] {
            assert_open_refuses(
                device_with_slots(&fresh_superblock_prefix(bytes), &blank),
                Refusal::InterruptedFormat,
            );
            assert_open_refuses(
                device_with_slots(&blank, &fresh_superblock_prefix(bytes)),
                Refusal::InterruptedFormat,
            );
        }
        assert_open_refuses(
            device_with_slots(&fresh_superblock_prefix(12), &fresh_superblock_prefix(30)),
            Refusal::InterruptedFormat,
        );
    }

    #[test]
    fn a_slot_that_departs_from_the_fresh_superblock_is_not_an_interrupted_format() {
        let blank = vec![0; 512];
        let mut slot = fresh_superblock_prefix(20);
        slot[16] ^= 0x01;
        assert_open_refuses(
            device_with_slots(&slot, &blank),
            Refusal::SuperblocksInvalid,
        );

        let mut device = device_holding_one_object();
        let mut generation_one = durable_slot(&mut device, 1);
        generation_one[60..].fill(0);
        device.write_blocks(0, 1, &blank).unwrap();
        device.write_blocks(1, 1, &generation_one).unwrap();
        device.flush().unwrap();
        assert_open_refuses(device, Refusal::SuperblocksInvalid);
    }

    #[test]
    fn a_damaged_version_field_is_corruption_not_another_format() {
        let mut device = device_holding_one_object();
        let mut slot_a = durable_slot(&mut device, 0);
        slot_a[4] ^= 0x04;
        let mut slot_b = durable_slot(&mut device, 1);
        slot_b[GENERATION_BYTE] ^= 0x01;
        device.write_blocks(0, 1, &slot_a).unwrap();
        device.write_blocks(1, 1, &slot_b).unwrap();
        device.flush().unwrap();
        assert_eq!(superblock_format_version(&slot_a), Some(7));

        assert_open_refuses(device, Refusal::SuperblocksInvalid);
    }

    #[test]
    fn an_old_version_field_without_its_checksum_is_corruption() {
        let mut device = device_holding_one_object();
        for slot_lba in 0..SUPERBLOCK_SLOTS {
            let mut slot = durable_slot(&mut device, slot_lba);
            slot[4..6].copy_from_slice(&1u16.to_le_bytes());
            device.write_blocks(slot_lba, 1, &slot).unwrap();
        }
        device.flush().unwrap();

        assert_open_refuses(device, Refusal::SuperblocksInvalid);
    }

    #[test]
    fn a_later_version_with_a_valid_checksum_is_another_format() {
        let mut device = device_holding_one_object();
        let mut slot_a = durable_slot(&mut device, 0);
        set_version_with_valid_crc(&mut slot_a, STORE_VERSION + 1);
        let mut slot_b = durable_slot(&mut device, 1);
        slot_b[GENERATION_BYTE] ^= 0x01;
        device.write_blocks(0, 1, &slot_a).unwrap();
        device.write_blocks(1, 1, &slot_b).unwrap();
        device.flush().unwrap();

        assert_open_refuses(device, Refusal::UnsupportedVersion(STORE_VERSION + 1));
    }

    #[test]
    fn version_zero_with_a_valid_checksum_is_corruption() {
        let mut device = device_holding_one_object();
        for slot_lba in 0..SUPERBLOCK_SLOTS {
            let mut slot = durable_slot(&mut device, slot_lba);
            set_version_with_valid_crc(&mut slot, 0);
            device.write_blocks(slot_lba, 1, &slot).unwrap();
        }
        device.flush().unwrap();

        assert_open_refuses(device, Refusal::SuperblocksInvalid);
    }

    #[test]
    fn open_formats_a_blank_device() {
        let mut device = FakeBlockDevice::new(geometry()).unwrap();
        assert_eq!(probe(&mut device), Ok(Probe::Blank));

        let (store, opened) = ObjectStore::open(device).unwrap();
        assert_eq!(opened, Opened::Formatted);
        let mut device = reboot(store).into_inner();
        assert_eq!(probe(&mut device), Ok(Probe::Mountable));
    }

    #[test]
    fn open_mounts_an_existing_store_without_formatting() {
        let mut device = device_holding_one_object();
        assert_eq!(probe(&mut device), Ok(Probe::Mountable));

        let (store, opened) = ObjectStore::open(device).unwrap();
        assert_eq!(opened, Opened::Mounted);
        assert_eq!(store.read_object_by_id(1).unwrap(), b"keep me");
    }

    #[test]
    fn open_refuses_a_corrupt_device_and_leaves_its_bytes_unchanged() {
        let mut device = device_holding_one_object();
        let mut slot_a = durable_slot(&mut device, 0);
        slot_a[0] ^= 0x01;
        let mut slot_b = durable_slot(&mut device, 1);
        slot_b[HEADER_BYTES] ^= 0x80;
        device.write_blocks(0, 1, &slot_a).unwrap();
        device.write_blocks(1, 1, &slot_b).unwrap();
        device.flush().unwrap();
        assert_eq!(
            ObjectStore::mount(device.clone()).unwrap_err(),
            StoreError::Incompatible(IncompatibleFormatError::BadMagic)
        );

        assert_open_refuses(device, Refusal::SuperblocksInvalid);
    }

    #[test]
    fn open_refuses_an_old_version_device() {
        let mut device = device_holding_one_object();
        for slot_lba in 0..SUPERBLOCK_SLOTS {
            let mut slot = durable_slot(&mut device, slot_lba);
            downgrade_to_version_one(&mut slot);
            device.write_blocks(slot_lba, 1, &slot).unwrap();
        }
        device.flush().unwrap();

        assert_open_refuses(device, Refusal::UnsupportedVersion(1));
    }

    #[test]
    fn open_refuses_foreign_bytes_and_unreadable_payloads() {
        let mut device = FakeBlockDevice::new(geometry()).unwrap();
        device.write_blocks(1, 1, &[0xee; 512]).unwrap();
        device.flush().unwrap();
        assert_open_refuses(device, Refusal::NotAStore);

        let mut device = device_holding_one_object();
        let start_lba = committed_layouts(&mut device, 1)[0].start_lba;
        let mut slot = durable_slot(&mut device, 1);
        let mut payload = vec![0; 512];
        device.read_blocks(start_lba, 1, &mut payload).unwrap();
        payload[0] ^= 0xff;
        device.write_blocks(start_lba, 1, &payload).unwrap();
        slot.fill(0);
        device.write_blocks(0, 1, &slot).unwrap();
        device.flush().unwrap();
        assert_open_refuses(device, Refusal::PayloadInvalid);
    }

    #[test]
    fn all_zero_superblock_does_not_carry_a_valid_checksum() {
        assert_ne!(superblock_checksum(&[0; 512]), 0);
    }

    #[test]
    fn malformed_object_extent_is_rejected_before_data_read() {
        let mut device = FakeBlockDevice::new(geometry()).unwrap();
        forge_committed_table(
            &mut device,
            &[forged_layout(geometry().block_count() - 1, 1024, 2)],
        );
        assert_eq!(
            ObjectStore::mount(device).unwrap_err(),
            StoreError::Corrupt(CorruptFormatError::InvalidObjectExtent)
        );
    }

    #[test]
    fn malformed_object_length_is_rejected() {
        let mut device = FakeBlockDevice::new(geometry()).unwrap();
        forge_committed_table(&mut device, &[forged_layout(DATA_START_LBA, 513, 1)]);
        assert_eq!(
            ObjectStore::mount(device).unwrap_err(),
            StoreError::Corrupt(CorruptFormatError::InvalidObjectLength)
        );
    }

    #[test]
    fn an_epoch_the_superblock_never_issued_is_rejected() {
        let mut device = FakeBlockDevice::new(geometry()).unwrap();
        let mut layout = forged_layout(DATA_START_LBA, 0, 0);
        layout.epoch = 100;
        forge_committed_table(&mut device, &[layout]);
        assert_eq!(
            ObjectStore::mount(device).unwrap_err(),
            StoreError::Corrupt(CorruptFormatError::InvalidObjectEpoch)
        );
    }

    #[test]
    fn a_table_overlapping_a_payload_is_rejected() {
        let mut device = FakeBlockDevice::new(geometry()).unwrap();
        forge_committed_tables(&mut device, |slot| {
            let table_start = slot_data_arena(geometry(), slot).end - 1;
            vec![forged_layout(table_start, 10, 1)]
        });
        assert_eq!(
            ObjectStore::mount(device).unwrap_err(),
            StoreError::Corrupt(CorruptFormatError::OverlappingObjectExtents)
        );
    }

    #[test]
    fn mount_uses_valid_slot_when_other_slot_is_incompatible() {
        let device = FakeBlockDevice::new(geometry()).unwrap();
        let mut store = ObjectStore::format(device).unwrap();
        store.write_object(1, "alpha", b"committed").unwrap();
        store.commit().unwrap();

        let mut device = store.into_inner();
        let mut stale_slot = vec![0; 512];
        device.read_blocks(0, 1, &mut stale_slot).unwrap();
        stale_slot[0..4].copy_from_slice(b"BAD!");
        stale_slot[CHECKSUM_RANGE.start..CHECKSUM_RANGE.end].copy_from_slice(&0u32.to_le_bytes());
        let sum = superblock_checksum(&stale_slot);
        stale_slot[CHECKSUM_RANGE.start..CHECKSUM_RANGE.end].copy_from_slice(&sum.to_le_bytes());
        device.write_blocks(0, 1, &stale_slot).unwrap();
        device.flush().unwrap();

        let store = ObjectStore::mount(device).unwrap();
        assert_eq!(store.read_object_by_id(1).unwrap(), b"committed");
        assert_eq!(store.committed_generation(), 1);
    }

    #[test]
    fn mount_falls_back_to_previous_generation_when_newer_payload_checksum_mismatches() {
        let device = FakeBlockDevice::new(geometry()).unwrap();
        let mut store = ObjectStore::format(device).unwrap();
        store.write_object(1, "alpha", &[0x11; 700]).unwrap();
        store.commit().unwrap();
        store.write_object(1, "alpha", &[0x22; 700]).unwrap();
        store.commit().unwrap();

        let mut device = store.into_inner();
        let generation_two = committed_layouts(&mut device, 0);
        let payload_offset = usize::try_from(
            generation_two[0].start_lba * u64::from(geometry().logical_block_size()),
        )
        .unwrap();
        device.durable_bytes_mut()[payload_offset] ^= 0xff;
        let rebooted =
            FakeBlockDevice::from_durable_bytes(geometry(), device.durable_bytes()).unwrap();
        let store = ObjectStore::mount(rebooted).unwrap();
        assert_eq!(store.committed_generation(), 1);
        assert_eq!(store.read_object_by_id(1).unwrap(), vec![0x11; 700]);
    }
}
