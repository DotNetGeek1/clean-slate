//! Commit ordering for the `clean-slate-store` protocol.
//!
//! A write-back cache may persist writes issued between two flushes in any
//! order, so the only ordering a commit can rely on is the flush boundary.
//! These tests record the block operations a commit issues and require:
//! every payload write, then a flush, then the superblock write, then a flush.

use clean_slate_block::fake::FakeBlockDevice;
use clean_slate_block::{BlockDevice, BlockDeviceId, BlockGeometry, BlockIoError};
use clean_slate_store::{ObjectStore, SUPERBLOCK_SLOTS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockOp {
    Write { lba: u64, blocks: u32 },
    Flush,
}

/// [`FakeBlockDevice`] that records every write and flush it is given.
struct RecordingBlockDevice {
    inner: FakeBlockDevice,
    ops: Vec<BlockOp>,
}

impl BlockDevice for RecordingBlockDevice {
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

    fn write_blocks(&mut self, lba: u64, blocks: u32, buffer: &[u8]) -> Result<(), BlockIoError> {
        self.ops.push(BlockOp::Write { lba, blocks });
        self.inner.write_blocks(lba, blocks, buffer)
    }

    fn flush(&mut self) -> Result<(), BlockIoError> {
        self.ops.push(BlockOp::Flush);
        self.inner.flush()
    }
}

/// Single-block transfers split each multi-block payload into several writes.
fn geometry() -> BlockGeometry {
    BlockGeometry::new(BlockDeviceId::new(41), 512, 32, 1, false).unwrap()
}

/// Ops issued by commit number `generation` of `alpha` (1300 bytes, three
/// blocks) and `beta` (one block), after `generation - 1` earlier commits.
fn record_commit(generation: u64) -> Vec<BlockOp> {
    let device = RecordingBlockDevice {
        inner: FakeBlockDevice::new(geometry()).unwrap(),
        ops: Vec::new(),
    };
    let mut store = ObjectStore::format(device).unwrap();
    store.write_object(1, "alpha", &[0x11; 1300]).unwrap();
    store.write_object(2, "beta", b"beta-stable").unwrap();
    for _ in 1..generation {
        store.commit().unwrap();
    }
    let mut device = store.into_inner();
    device.ops.clear();
    let mut store = ObjectStore::mount(device).unwrap();
    store.write_object(1, "alpha", &[0x22; 1300]).unwrap();
    store.write_object(2, "beta", b"beta-stable").unwrap();
    store.commit().unwrap();
    assert_eq!(store.committed_generation(), generation);
    store.into_inner().ops
}

#[test]
fn commit_is_payload_then_flush_then_superblock_then_flush() {
    for generation in 1..=2 {
        let ops = record_commit(generation);
        let superblock_slot = generation % SUPERBLOCK_SLOTS;
        let (payload, commit_tail) = ops.split_at(ops.len() - 3);

        assert_eq!(
            commit_tail,
            [
                BlockOp::Flush,
                BlockOp::Write {
                    lba: superblock_slot,
                    blocks: 1
                },
                BlockOp::Flush,
            ],
            "generation {generation}: {ops:?}"
        );
        assert_eq!(payload.len(), 4, "alpha's 3 blocks and beta's 1: {ops:?}");
        assert!(
            payload
                .iter()
                .all(|op| matches!(op, BlockOp::Write { lba, .. } if *lba >= SUPERBLOCK_SLOTS)),
            "payload phase must hold only payload writes: {ops:?}"
        );
    }
}
