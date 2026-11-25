//! Host-side evidence for the M5 torn-write phases of `test-m5-crash-recovery`.
//!
//! The guest's storage service reports what it mounted, but it is the program under
//! test. These checks read the persistent disk image directly: they confirm that the
//! crash boot really left a torn write on the disk, and they run the store's own mount
//! over the image to confirm that it recovers exactly generation 2, the last complete
//! commit, with both objects' generation-2 bytes.

use clean_slate_block::fake::FakeBlockDevice;
use clean_slate_block::{BlockDeviceId, BlockGeometry};
use clean_slate_store::{ObjectStore, DATA_START_LBA, SUPERBLOCK_SLOTS};

const BLOCK_BYTES: usize = 512;
const SLOT_ONE_OFFSET: usize = BLOCK_BYTES;
const GENERATION_OFFSET: usize = 12;
/// Must match `SUPERBLOCK_TEAR_OFFSET` in `kernel/src/selftest/m5_storage.rs`.
pub const SUPERBLOCK_TEAR_OFFSET: usize = 56;
const ALPHA_ID: u64 = 1;
const BETA_ID: u64 = 2;
const ALPHA_V2: [u8; 900] = [0x22; 900];
const ALPHA_V3: [u8; 700] = [0x33; 700];
const BETA_V1: &[u8] = b"beta-stable";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TornWrite {
    /// Generation 3's superblock in slot 1 keeps only its first `SUPERBLOCK_TEAR_OFFSET`
    /// bytes; the rest of the sector still holds generation 1's superblock.
    SuperblockSuffix,
    /// Only the first of alpha's two generation-3 payload blocks landed; beta's payload,
    /// the object table and the generation-3 superblock landed in full.
    PayloadPrefix,
}

/// Checks `image`, the disk after the torn crash boot, against `baseline`, the disk
/// holding generations 1 and 2 before that boot.
pub fn check_torn_image(baseline: &[u8], image: &[u8], torn: TornWrite) -> Result<(), String> {
    if baseline.len() != image.len() || image.len() % BLOCK_BYTES != 0 {
        return Err(format!(
            "image is {} bytes, baseline {} bytes",
            image.len(),
            baseline.len()
        ));
    }
    if image[..BLOCK_BYTES] != baseline[..BLOCK_BYTES] {
        return Err("superblock slot 0 (generation 2) changed during the crash boot".to_owned());
    }
    let slot_one = SLOT_ONE_OFFSET..SLOT_ONE_OFFSET + BLOCK_BYTES;
    if read_u64(baseline, SLOT_ONE_OFFSET + GENERATION_OFFSET) != 1 {
        return Err("baseline superblock slot 1 does not hold generation 1".to_owned());
    }
    if read_u64(image, SLOT_ONE_OFFSET + GENERATION_OFFSET) != 3 {
        return Err("superblock slot 1 does not carry generation 3's header".to_owned());
    }
    match torn {
        TornWrite::SuperblockSuffix => {
            let kept = SLOT_ONE_OFFSET + SUPERBLOCK_TEAR_OFFSET..slot_one.end;
            if image[kept.clone()] != baseline[kept] {
                return Err("torn superblock suffix is not slot 1's previous bytes".to_owned());
            }
            if image[SLOT_ONE_OFFSET..SLOT_ONE_OFFSET + SUPERBLOCK_TEAR_OFFSET]
                == baseline[SLOT_ONE_OFFSET..SLOT_ONE_OFFSET + SUPERBLOCK_TEAR_OFFSET]
            {
                return Err("torn superblock prefix was never written".to_owned());
            }
        }
        TornWrite::PayloadPrefix => {
            let first = block_range(arena_one_start(image));
            let second = block_range(arena_one_start(image) + 1);
            if image[first.clone()] != ALPHA_V3[..BLOCK_BYTES] {
                return Err("alpha's first generation-3 payload block did not land".to_owned());
            }
            if image[second.clone()] != baseline[second.clone()] {
                return Err(
                    "alpha's second payload block changed; the write was not torn".to_owned(),
                );
            }
            if baseline[second.start..second.start + (ALPHA_V3.len() - BLOCK_BYTES)]
                == ALPHA_V3[BLOCK_BYTES..]
            {
                return Err("alpha's second block already held generation-3 bytes".to_owned());
            }
        }
    }
    check_recovers_generation_two(image)
}

/// The store's mount over `image` must select generation 2 with its exact objects.
pub fn check_recovers_generation_two(image: &[u8]) -> Result<(), String> {
    let block_count = (image.len() / BLOCK_BYTES) as u64;
    let geometry = BlockGeometry::new(
        BlockDeviceId::new(5),
        BLOCK_BYTES as u32,
        block_count,
        8,
        false,
    )
    .map_err(|error| format!("disk geometry: {error:?}"))?;
    let device = FakeBlockDevice::from_durable_bytes(geometry, image)
        .map_err(|error| format!("disk image: {error:?}"))?;
    let store = ObjectStore::mount(device).map_err(|error| format!("mount failed: {error:?}"))?;
    let generation = store.committed_generation();
    if generation != 2 {
        return Err(format!(
            "store recovered generation {generation}; the last complete commit is 2"
        ));
    }
    let alpha = store
        .read_object_by_id(ALPHA_ID)
        .map_err(|error| format!("alpha: {error:?}"))?;
    let beta = store
        .read_object_by_id(BETA_ID)
        .map_err(|error| format!("beta: {error:?}"))?;
    if alpha != ALPHA_V2 || beta != BETA_V1 {
        return Err("recovered objects are not generation 2's bytes".to_owned());
    }
    Ok(())
}

fn arena_one_start(image: &[u8]) -> u64 {
    let block_count = (image.len() / BLOCK_BYTES) as u64;
    DATA_START_LBA + (block_count - DATA_START_LBA) / SUPERBLOCK_SLOTS
}

fn block_range(lba: u64) -> core::ops::Range<usize> {
    let start = lba as usize * BLOCK_BYTES;
    start..start + BLOCK_BYTES
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("8-byte slice"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALPHA_V1: [u8; 1300] = [0x11; 1300];

    fn geometry() -> BlockGeometry {
        BlockGeometry::new(BlockDeviceId::new(5), BLOCK_BYTES as u32, 64, 8, false).unwrap()
    }

    fn mount(image: &[u8]) -> ObjectStore<FakeBlockDevice> {
        ObjectStore::mount(FakeBlockDevice::from_durable_bytes(geometry(), image).unwrap()).unwrap()
    }

    /// The images the lane's baseline boots and an untorn generation-3 commit leave.
    fn baseline_and_generation_three() -> (Vec<u8>, Vec<u8>) {
        let mut store = ObjectStore::format(FakeBlockDevice::new(geometry()).unwrap()).unwrap();
        store.write_object(ALPHA_ID, "alpha", &ALPHA_V1).unwrap();
        store.write_object(BETA_ID, "beta", BETA_V1).unwrap();
        store.commit().unwrap();
        store.write_object(ALPHA_ID, "alpha", &ALPHA_V2).unwrap();
        store.commit().unwrap();
        let baseline = store.into_inner().durable_bytes().to_vec();
        let mut store = mount(&baseline);
        store.write_object(ALPHA_ID, "alpha", &ALPHA_V3).unwrap();
        store.commit().unwrap();
        (baseline, store.into_inner().durable_bytes().to_vec())
    }

    fn restore(image: &mut [u8], baseline: &[u8], range: core::ops::Range<usize>) {
        image[range.clone()].copy_from_slice(&baseline[range]);
    }

    #[test]
    fn torn_superblock_image_passes() {
        let (baseline, mut image) = baseline_and_generation_three();
        restore(
            &mut image,
            &baseline,
            SLOT_ONE_OFFSET + SUPERBLOCK_TEAR_OFFSET..SLOT_ONE_OFFSET + BLOCK_BYTES,
        );
        check_torn_image(&baseline, &image, TornWrite::SuperblockSuffix).unwrap();
    }

    #[test]
    fn torn_payload_image_passes() {
        let (baseline, mut image) = baseline_and_generation_three();
        let second_block = block_range(arena_one_start(&image) + 1);
        restore(&mut image, &baseline, second_block);
        check_torn_image(&baseline, &image, TornWrite::PayloadPrefix).unwrap();
    }

    #[test]
    fn untorn_commit_is_rejected_for_both_tears() {
        let (baseline, image) = baseline_and_generation_three();
        for torn in [TornWrite::SuperblockSuffix, TornWrite::PayloadPrefix] {
            assert!(
                check_torn_image(&baseline, &image, torn).is_err(),
                "{torn:?}"
            );
        }
    }

    #[test]
    fn unchanged_baseline_is_rejected() {
        let (baseline, _) = baseline_and_generation_three();
        for torn in [TornWrite::SuperblockSuffix, TornWrite::PayloadPrefix] {
            assert!(
                check_torn_image(&baseline, &baseline, torn).is_err(),
                "{torn:?}"
            );
        }
    }

    #[test]
    fn recovery_to_the_torn_generation_is_rejected() {
        let (_, image) = baseline_and_generation_three();
        let error = check_recovers_generation_two(&image).unwrap_err();
        assert!(error.contains("generation 3"), "{error}");
    }
}
