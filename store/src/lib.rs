//! M5 minimal persistent object store.
//!
//! Version 1 uses a fixed, host-testable on-disk layout encoded explicitly in
//! little-endian bytes:
//!
//! - LBA 0: superblock slot A
//! - LBA 1: superblock slot B
//! - LBA 2..: committed object payload blocks
//!
//! Each superblock occupies exactly one logical block and contains:
//!
//! - magic (`CSO1`);
//! - format version (`1`);
//! - checksum over the full superblock block with the checksum field zeroed;
//! - expected logical block size and device block count;
//! - generation number for slot selection;
//! - fixed table capacity and active object count;
//! - a fixed object table whose entries store object id, UTF-8 name, exact byte
//!   length, and validated data extent.
//!
//! Commits never need in-place multi-block metadata mutation: object data is
//! written first, then a complete next-generation superblock is written to the
//! alternate metadata slot, and finally the block backend `flush` boundary is
//! invoked.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use clean_slate_block::{BlockDevice, BlockGeometry, BlockIoError};
use core::cmp::Ordering;

pub const STORE_MAGIC: u32 = 0x4353_4F31; // "CSO1"
pub const STORE_VERSION: u16 = 1;
pub const SUPERBLOCK_SLOTS: u64 = 2;
pub const DATA_START_LBA: u64 = SUPERBLOCK_SLOTS;
pub const MAX_OBJECTS: usize = 7;
pub const MAX_OBJECT_NAME_BYTES: usize = 32;

const HEADER_BYTES: usize = 48;
const ENTRY_BYTES: usize = 64;
const CHECKSUM_RANGE: core::ops::Range<usize> = 8..12;
const ENTRY_PRESENT_FLAG: u8 = 0x01;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredObject {
    id: u64,
    name: String,
    data: Vec<u8>,
}

impl StoredObject {
    pub fn id(&self) -> u64 {
        self.id
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
}

#[derive(Debug)]
pub struct ObjectStore<D> {
    device: D,
    geometry: BlockGeometry,
    generation: u64,
    active_slot: u64,
    objects: Vec<StoredObject>,
}

impl<D: BlockDevice> ObjectStore<D> {
    pub fn format(mut device: D) -> Result<Self, StoreError> {
        let geometry = validate_geometry(device.geometry())?;
        let superblock = Superblock {
            generation: 0,
            object_count: 0,
            objects: Vec::new(),
        };

        write_superblock(&mut device, geometry, 0, &superblock)?;
        write_superblock(&mut device, geometry, 1, &superblock)?;
        device.flush()?;

        Ok(Self {
            device,
            geometry,
            generation: 0,
            active_slot: 0,
            objects: Vec::new(),
        })
    }

    pub fn mount(mut device: D) -> Result<Self, StoreError> {
        let geometry = validate_geometry(device.geometry())?;
        let (active_slot, superblock) = select_superblock(&mut device, geometry)?;
        let objects = load_objects(&mut device, geometry, &superblock.objects)?;

        Ok(Self {
            device,
            geometry,
            generation: superblock.generation,
            active_slot,
            objects,
        })
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
                self.objects[index].name.clear();
                self.objects[index].name.push_str(name);
                self.objects[index].data.clear();
                self.objects[index].data.extend_from_slice(data);
            }
            None => {
                if self.objects.len() == MAX_OBJECTS {
                    return Err(StoreError::ObjectTableFull {
                        max_objects: MAX_OBJECTS,
                    });
                }
                self.objects.push(StoredObject {
                    id,
                    name: String::from(name),
                    data: data.to_vec(),
                });
            }
        }

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
        let object_layout = build_object_layout(self.geometry, &self.objects)?;
        for object in &object_layout {
            write_object_data(&mut self.device, self.geometry, object)?;
        }

        let next_slot = (self.active_slot + 1) % SUPERBLOCK_SLOTS;
        let next_generation = self.generation + 1;
        let superblock = Superblock {
            generation: next_generation,
            object_count: u32::try_from(object_layout.len())
                .expect("object layout count fits within u32"),
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
    name: String,
    data: Vec<u8>,
    data_len: u32,
    start_lba: u64,
    block_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Superblock {
    generation: u64,
    object_count: u32,
    objects: Vec<ObjectLayout>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotDecodeError {
    Incompatible(IncompatibleFormatError),
    Corrupt(CorruptFormatError),
}

fn validate_geometry(geometry: BlockGeometry) -> Result<BlockGeometry, StoreError> {
    let logical_block_size = usize::try_from(geometry.logical_block_size()).map_err(|_| {
        StoreError::UnsupportedGeometry {
            logical_block_size: geometry.logical_block_size(),
            block_count: geometry.block_count(),
        }
    })?;
    let min_block_size = HEADER_BYTES + (ENTRY_BYTES * MAX_OBJECTS);
    if logical_block_size < min_block_size || geometry.block_count() < SUPERBLOCK_SLOTS {
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

fn select_superblock<D: BlockDevice>(
    device: &mut D,
    geometry: BlockGeometry,
) -> Result<(u64, Superblock), StoreError> {
    let slot0 = read_superblock_slot(device, geometry, 0);
    let slot1 = read_superblock_slot(device, geometry, 1);

    match (slot0, slot1) {
        (Ok(left), Ok(right)) => match left.generation.cmp(&right.generation) {
            Ordering::Greater | Ordering::Equal => Ok((0, left)),
            Ordering::Less => Ok((1, right)),
        },
        (Ok(left), Err(_)) => Ok((0, left)),
        (Err(_), Ok(right)) => Ok((1, right)),
        (Err(SlotDecodeError::Incompatible(err)), Err(_)) => Err(StoreError::Incompatible(err)),
        (Err(SlotDecodeError::Corrupt(err)), Err(_)) => Err(StoreError::Corrupt(err)),
    }
}

fn read_superblock_slot<D: BlockDevice>(
    device: &mut D,
    geometry: BlockGeometry,
    slot: u64,
) -> Result<Superblock, SlotDecodeError> {
    let mut bytes = vec![0; block_size_bytes(geometry)];
    device
        .read_blocks(slot, 1, &mut bytes)
        .map_err(|error| SlotDecodeError::Corrupt(map_block_error(error)))?;
    decode_superblock(geometry, &bytes)
}

fn map_block_error(error: BlockIoError) -> CorruptFormatError {
    match error {
        BlockIoError::InvalidRequest(_) => CorruptFormatError::InvalidObjectExtent,
        BlockIoError::Unsupported(_) | BlockIoError::Transport(_) => {
            CorruptFormatError::InvalidHeader
        }
    }
}

fn decode_superblock(geometry: BlockGeometry, bytes: &[u8]) -> Result<Superblock, SlotDecodeError> {
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

    if checksum(bytes) != read_u32(bytes, CHECKSUM_RANGE.start) {
        return Err(SlotDecodeError::Corrupt(
            CorruptFormatError::ChecksumMismatch,
        ));
    }

    let expected_block_size = read_u32(bytes, 20);
    let expected_block_count = read_u64(bytes, 24);
    let max_objects = read_u32(bytes, 32);
    let object_count = read_u32(bytes, 36);
    let data_start_lba = read_u64(bytes, 40);

    if expected_block_size != geometry.logical_block_size()
        || expected_block_count != geometry.block_count()
        || max_objects != MAX_OBJECTS as u32
        || data_start_lba != DATA_START_LBA
        || object_count > MAX_OBJECTS as u32
    {
        return Err(SlotDecodeError::Corrupt(CorruptFormatError::InvalidHeader));
    }

    let generation = read_u64(bytes, 12);
    let mut objects = Vec::new();
    for index in 0..MAX_OBJECTS {
        let start = HEADER_BYTES + (ENTRY_BYTES * index);
        let flags = bytes[start];
        if flags & !ENTRY_PRESENT_FLAG != 0 {
            return Err(SlotDecodeError::Corrupt(CorruptFormatError::InvalidHeader));
        }
        if flags & ENTRY_PRESENT_FLAG == 0 {
            continue;
        }

        let name_len = usize::from(read_u16(bytes, start + 2));
        if name_len == 0 || name_len > MAX_OBJECT_NAME_BYTES {
            return Err(SlotDecodeError::Corrupt(
                CorruptFormatError::InvalidNameEncoding,
            ));
        }

        let name_bytes = &bytes[(start + 32)..(start + 32 + MAX_OBJECT_NAME_BYTES)];
        if name_bytes[name_len..].iter().any(|byte| *byte != 0) {
            return Err(SlotDecodeError::Corrupt(
                CorruptFormatError::InvalidNameEncoding,
            ));
        }

        let name = core::str::from_utf8(&name_bytes[..name_len])
            .map_err(|_| SlotDecodeError::Corrupt(CorruptFormatError::InvalidNameEncoding))?;

        objects.push(ObjectLayout {
            id: read_u64(bytes, start + 24),
            name: String::from(name),
            data: Vec::new(),
            data_len: read_u32(bytes, start + 4),
            start_lba: read_u64(bytes, start + 8),
            block_count: read_u32(bytes, start + 16),
        });
    }

    if objects.len() != object_count as usize {
        return Err(SlotDecodeError::Corrupt(
            CorruptFormatError::InvalidObjectCount {
                count: object_count,
            },
        ));
    }

    validate_layouts(geometry, &objects).map_err(SlotDecodeError::Corrupt)?;

    Ok(Superblock {
        generation,
        object_count,
        objects,
    })
}

fn validate_layouts(
    geometry: BlockGeometry,
    objects: &[ObjectLayout],
) -> Result<(), CorruptFormatError> {
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

        if left.data_len == 0 {
            if left.block_count != 0
                || left.start_lba < DATA_START_LBA
                || left.start_lba > geometry.block_count()
            {
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
        if left.start_lba < DATA_START_LBA || end_lba > geometry.block_count() {
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
            name: layout.name.clone(),
            data,
        });
    }
    Ok(objects)
}

fn build_object_layout(
    geometry: BlockGeometry,
    objects: &[StoredObject],
) -> Result<Vec<ObjectLayout>, StoreError> {
    let block_size = u64::from(geometry.logical_block_size());
    let mut next_lba = DATA_START_LBA;
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
                available_blocks: geometry.block_count().saturating_sub(DATA_START_LBA),
            })?;

        layouts.push(ObjectLayout {
            id: object.id,
            name: object.name.clone(),
            data: object.data.clone(),
            data_len: data_len_u32,
            start_lba: object_start,
            block_count,
        });
    }

    let available_blocks = geometry.block_count().saturating_sub(DATA_START_LBA);
    let required_blocks = next_lba.saturating_sub(DATA_START_LBA);
    if required_blocks > available_blocks {
        return Err(StoreError::StorageFull {
            required_blocks,
            available_blocks,
        });
    }

    Ok(layouts)
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
        u32::try_from(MAX_OBJECTS).expect("MAX_OBJECTS fits in u32"),
    );
    write_u32(&mut bytes, 36, superblock.object_count);
    write_u64(&mut bytes, 40, DATA_START_LBA);

    for (index, object) in superblock.objects.iter().enumerate() {
        let start = HEADER_BYTES + (ENTRY_BYTES * index);
        bytes[start] = ENTRY_PRESENT_FLAG;
        write_u16(
            &mut bytes,
            start + 2,
            u16::try_from(object.name.len()).expect("validated name length fits in u16"),
        );
        write_u32(&mut bytes, start + 4, object.data_len);
        write_u64(&mut bytes, start + 8, object.start_lba);
        write_u32(&mut bytes, start + 16, object.block_count);
        write_u64(&mut bytes, start + 24, object.id);
        let name_bytes = object.name.as_bytes();
        bytes[(start + 32)..(start + 32 + name_bytes.len())].copy_from_slice(name_bytes);
    }

    let superblock_checksum = checksum(&bytes);
    write_u32(&mut bytes, CHECKSUM_RANGE.start, superblock_checksum);
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

fn checksum(bytes: &[u8]) -> u32 {
    let mut sum = 0u32;
    for (index, byte) in bytes.iter().enumerate() {
        if CHECKSUM_RANGE.contains(&index) {
            continue;
        }
        sum = sum.wrapping_add(u32::from(*byte));
    }
    sum
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

    fn geometry() -> BlockGeometry {
        BlockGeometry::new(BlockDeviceId::new(11), 512, 32, 2, false).unwrap()
    }

    fn tiny_geometry() -> BlockGeometry {
        BlockGeometry::new(BlockDeviceId::new(12), 512, 4, 2, false).unwrap()
    }

    fn reboot(store: ObjectStore<FakeBlockDevice>) -> ObjectStore<FakeBlockDevice> {
        let device = store.into_inner();
        let rebooted =
            FakeBlockDevice::from_durable_bytes(device.geometry(), device.durable_bytes()).unwrap();
        ObjectStore::mount(rebooted).unwrap()
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
                required_blocks: 3,
                available_blocks: 2,
            })
        );
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

        for index in 0..MAX_OBJECTS {
            let name = match index {
                0 => "obj0",
                1 => "obj1",
                2 => "obj2",
                3 => "obj3",
                4 => "obj4",
                5 => "obj5",
                _ => "obj6",
            };
            store
                .write_object(index as u64, name, &[index as u8])
                .unwrap();
        }

        assert_eq!(
            store.write_object(99, "overflow", b"x"),
            Err(StoreError::ObjectTableFull {
                max_objects: MAX_OBJECTS,
            })
        );
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
        let sum = checksum(&slot);
        slot[CHECKSUM_RANGE.start..CHECKSUM_RANGE.end].copy_from_slice(&sum.to_le_bytes());
        device.write_blocks(0, 1, &slot).unwrap();
        device.write_blocks(1, 1, &slot).unwrap();
        device.flush().unwrap();

        assert_eq!(
            ObjectStore::mount(device).unwrap_err(),
            StoreError::Incompatible(IncompatibleFormatError::UnsupportedVersion(99))
        );
    }

    #[test]
    fn malformed_object_extent_is_rejected_before_data_read() {
        let device = FakeBlockDevice::new(geometry()).unwrap();
        let store = ObjectStore::format(device).unwrap();
        let mut device = store.into_inner();
        let mut slot = vec![0; 512];
        device.read_blocks(0, 1, &mut slot).unwrap();

        let entry_start = HEADER_BYTES;
        slot[36..40].copy_from_slice(&1u32.to_le_bytes());
        slot[entry_start] = ENTRY_PRESENT_FLAG;
        slot[(entry_start + 2)..(entry_start + 4)].copy_from_slice(&5u16.to_le_bytes());
        slot[(entry_start + 4)..(entry_start + 8)].copy_from_slice(&1024u32.to_le_bytes());
        slot[(entry_start + 8)..(entry_start + 16)]
            .copy_from_slice(&(geometry().block_count() - 1).to_le_bytes());
        slot[(entry_start + 16)..(entry_start + 20)].copy_from_slice(&2u32.to_le_bytes());
        slot[(entry_start + 24)..(entry_start + 32)].copy_from_slice(&7u64.to_le_bytes());
        slot[(entry_start + 32)..(entry_start + 37)].copy_from_slice(b"alpha");
        slot[CHECKSUM_RANGE.start..CHECKSUM_RANGE.end].copy_from_slice(&0u32.to_le_bytes());
        let sum = checksum(&slot);
        slot[CHECKSUM_RANGE.start..CHECKSUM_RANGE.end].copy_from_slice(&sum.to_le_bytes());
        device.write_blocks(0, 1, &slot).unwrap();
        device.write_blocks(1, 1, &slot).unwrap();
        device.flush().unwrap();

        assert_eq!(
            ObjectStore::mount(device).unwrap_err(),
            StoreError::Corrupt(CorruptFormatError::InvalidObjectExtent)
        );
    }

    #[test]
    fn malformed_object_length_is_rejected() {
        let device = FakeBlockDevice::new(geometry()).unwrap();
        let store = ObjectStore::format(device).unwrap();
        let mut device = store.into_inner();
        let mut slot = vec![0; 512];
        device.read_blocks(0, 1, &mut slot).unwrap();

        let entry_start = HEADER_BYTES;
        slot[36..40].copy_from_slice(&1u32.to_le_bytes());
        slot[entry_start] = ENTRY_PRESENT_FLAG;
        slot[(entry_start + 2)..(entry_start + 4)].copy_from_slice(&5u16.to_le_bytes());
        slot[(entry_start + 4)..(entry_start + 8)].copy_from_slice(&513u32.to_le_bytes());
        slot[(entry_start + 8)..(entry_start + 16)].copy_from_slice(&DATA_START_LBA.to_le_bytes());
        slot[(entry_start + 16)..(entry_start + 20)].copy_from_slice(&1u32.to_le_bytes());
        slot[(entry_start + 24)..(entry_start + 32)].copy_from_slice(&9u64.to_le_bytes());
        slot[(entry_start + 32)..(entry_start + 37)].copy_from_slice(b"alpha");
        slot[CHECKSUM_RANGE.start..CHECKSUM_RANGE.end].copy_from_slice(&0u32.to_le_bytes());
        let sum = checksum(&slot);
        slot[CHECKSUM_RANGE.start..CHECKSUM_RANGE.end].copy_from_slice(&sum.to_le_bytes());
        device.write_blocks(0, 1, &slot).unwrap();
        device.write_blocks(1, 1, &slot).unwrap();
        device.flush().unwrap();

        assert_eq!(
            ObjectStore::mount(device).unwrap_err(),
            StoreError::Corrupt(CorruptFormatError::InvalidObjectLength)
        );
    }
}
