//! Torn-write tests for the `clean-slate-store` commit protocol.
//!
//! A torn write leaves a block whose leading bytes are new and whose trailing
//! bytes are whatever the block held before. These tests build the same
//! history the QEMU crash lane uses (generation 1 and 2, then a generation-3
//! commit of `alpha`), tear one write of the generation-3 commit in the durable
//! image, and assert that recovery mounts exactly generation 2.
//!
//! Generation 3 lands in superblock slot 1 and payload arena 1, which still
//! hold generation 1, so every stale byte a tear exposes is real generation-1
//! content rather than zeros.

use clean_slate_block::fake::FakeBlockDevice;
use clean_slate_block::{BlockDevice, BlockDeviceId, BlockGeometry};
use clean_slate_store::ObjectStore;

const ALPHA_ID: u64 = 1;
const BETA_ID: u64 = 2;
const ALPHA_V1: [u8; 1300] = [0x11; 1300];
const ALPHA_V2: [u8; 900] = [0x22; 900];
const ALPHA_V3: [u8; 700] = [0x33; 700];
const BETA_V1: &[u8] = b"beta-stable";
/// Byte offset of the superblock's object-table extent. A tear here keeps
/// generation 3's header up to its next epoch and leaves generation 1's table
/// extent and table checksum behind (generation 1's table sits one block
/// later in the arena, after its larger `alpha`).
const SUPERBLOCK_TEAR_OFFSET: usize = 56;
const SECTOR_BYTES: usize = 512;

fn geometry(block_size: u32) -> BlockGeometry {
    BlockGeometry::new(BlockDeviceId::new(31), block_size, 64, 8, false).unwrap()
}

fn block_bytes(geometry: BlockGeometry) -> usize {
    usize::try_from(geometry.logical_block_size()).unwrap()
}

fn remount(geometry: BlockGeometry, image: &[u8]) -> ObjectStore<FakeBlockDevice> {
    ObjectStore::mount(FakeBlockDevice::from_durable_bytes(geometry, image).unwrap()).unwrap()
}

/// First LBA of the payload arena paired with superblock `slot`.
fn arena_start(geometry: BlockGeometry, slot: u64) -> u64 {
    2 + slot * ((geometry.block_count() - 2) / 2)
}

/// Durable images before and after a complete generation-3 commit of
/// `alpha_v3`, on top of generation 1 (`alpha_v1`, `beta`) and generation 2
/// (`alpha_v2`, `beta`).
fn generation_three_images(
    geometry: BlockGeometry,
    alpha_v1: &[u8],
    alpha_v2: &[u8],
    alpha_v3: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let mut store = ObjectStore::format(FakeBlockDevice::new(geometry).unwrap()).unwrap();
    store.write_object(ALPHA_ID, "alpha", alpha_v1).unwrap();
    store.write_object(BETA_ID, "beta", BETA_V1).unwrap();
    store.commit().unwrap();
    store.write_object(ALPHA_ID, "alpha", alpha_v2).unwrap();
    store.commit().unwrap();
    assert_eq!(store.committed_generation(), 2);
    let before = store.into_inner().durable_bytes().to_vec();

    let mut store = remount(geometry, &before);
    store.write_object(ALPHA_ID, "alpha", alpha_v3).unwrap();
    store.commit().unwrap();
    assert_eq!(store.committed_generation(), 3);
    let after = store.into_inner().durable_bytes().to_vec();
    (before, after)
}

/// `after` with bytes `start..end` of the image put back to `before`.
fn torn(before: &[u8], after: &[u8], start: usize, end: usize) -> Vec<u8> {
    let mut image = after.to_vec();
    image[start..end].copy_from_slice(&before[start..end]);
    image
}

fn assert_generation_two(geometry: BlockGeometry, image: &[u8], alpha_v2: &[u8]) {
    let store = remount(geometry, image);
    assert_eq!(store.committed_generation(), 2);
    assert_eq!(store.read_object_by_id(ALPHA_ID).unwrap(), alpha_v2);
    assert_eq!(store.read_object_by_id(BETA_ID).unwrap(), BETA_V1);
}

#[test]
fn sub_sector_torn_superblock_falls_back_to_previous_commit() {
    let geometry = geometry(512);
    let (before, after) = generation_three_images(geometry, &ALPHA_V1, &ALPHA_V2, &ALPHA_V3);
    let slot = block_bytes(geometry);
    let image = torn(&before, &after, slot + SUPERBLOCK_TEAR_OFFSET, 2 * slot);

    assert_ne!(
        image[slot..2 * slot],
        after[slot..2 * slot],
        "tear changed nothing"
    );
    assert_ne!(
        image[slot..2 * slot],
        before[slot..2 * slot],
        "tear wrote nothing"
    );
    assert_generation_two(geometry, &image, &ALPHA_V2);
}

/// Every meaningful superblock byte sits in its first sector, so on a device
/// that tears only at sector boundaries a multi-sector superblock write
/// recovers to exactly the old or exactly the new commit.
#[test]
fn sector_granular_torn_superblock_recovers_old_or_new_commit() {
    let geometry = geometry(4096);
    let (before, after) = generation_three_images(geometry, &ALPHA_V1, &ALPHA_V2, &ALPHA_V3);
    let slot = block_bytes(geometry);
    for sectors_written in 0..(slot / SECTOR_BYTES) {
        let image = torn(
            &before,
            &after,
            slot + sectors_written * SECTOR_BYTES,
            2 * slot,
        );
        let store = remount(geometry, &image);
        if sectors_written == 0 {
            assert_eq!(store.committed_generation(), 2);
            assert_eq!(store.read_object_by_id(ALPHA_ID).unwrap(), ALPHA_V2);
        } else {
            assert_eq!(store.committed_generation(), 3, "sectors={sectors_written}");
            assert_eq!(store.read_object_by_id(ALPHA_ID).unwrap(), ALPHA_V3);
        }
        assert_eq!(store.read_object_by_id(BETA_ID).unwrap(), BETA_V1);
    }
}

/// The commit flushes its payload before writing the superblock, so this image
/// needs a device that acknowledged that flush without persisting a payload
/// write in full, or a misdirected write. The payload checksum is what rejects
/// that commit.
#[test]
fn torn_payload_under_landed_superblock_falls_back_to_previous_commit() {
    let geometry = geometry(512);
    let (before, after) = generation_three_images(geometry, &ALPHA_V1, &ALPHA_V2, &ALPHA_V3);
    let block = block_bytes(geometry);
    let alpha_second_block = usize::try_from(arena_start(geometry, 1) + 1).unwrap() * block;
    let image = torn(
        &before,
        &after,
        alpha_second_block,
        alpha_second_block + block,
    );

    assert_ne!(image, after, "tear changed nothing");
    assert_eq!(image[block..2 * block], after[block..2 * block]);
    assert_generation_two(geometry, &image, &ALPHA_V2);
}

/// `alpha` is a sorted table rewritten with each block's records in reverse
/// order. Both blocks differ between versions, but each holds the same bytes
/// in another order, so tearing the second block leaves an additive byte sum
/// unchanged; the payload CRC-32C must still reject the mixed payload.
#[test]
fn torn_payload_with_equal_byte_sum_falls_back_to_previous_commit() {
    let geometry = geometry(512);
    let block = block_bytes(geometry);
    let table: Vec<u8> = (0..2 * block).map(|index| (index % 251) as u8).collect();
    let mut reversed = table.clone();
    reversed.chunks_mut(block).for_each(|chunk| chunk.reverse());
    let (before, after) = generation_three_images(geometry, &table, &ALPHA_V2, &reversed);
    let alpha_second_block = usize::try_from(arena_start(geometry, 1) + 1).unwrap() * block;
    let image = torn(
        &before,
        &after,
        alpha_second_block,
        alpha_second_block + block,
    );
    assert_ne!(image, after, "tear changed nothing");

    let mut device = FakeBlockDevice::from_durable_bytes(geometry, &image).unwrap();
    let mut mixed = vec![0; 2 * block];
    device
        .read_blocks(arena_start(geometry, 1), 2, &mut mixed)
        .unwrap();
    assert_ne!(mixed, table);
    assert_ne!(mixed, reversed);
    assert_generation_two(geometry, &image, &ALPHA_V2);
}
