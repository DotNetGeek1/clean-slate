//! Crash-consistency tests for the canonical `clean-slate-store` object store.
//!
//! The commit protocol is: object data into the inactive arena, then the
//! next-generation superblock into the inactive slot, then `flush`. The commit
//! point is the successful return from that `flush`. These tests inject a
//! deterministic power loss or I/O error at every counted write boundary and
//! at the flush boundary, then reboot from the durable image and assert that
//! recovery exposes exactly the previous generation or exactly the new one.

use clean_slate_block::fake::FakeBlockDevice;
use clean_slate_block::fault::{
    FaultAction, FaultController, FaultInjectingBlockDevice, FaultPlan, FaultTrigger,
};
use clean_slate_block::{BlockDeviceId, BlockGeometry, BlockIoError, BlockTransportError};
use clean_slate_store::{ObjectStore, StoreError, SUPERBLOCK_SLOTS};

const ALPHA_ID: u64 = 0xaaaa;
const ALPHA_NAME: &str = "alpha";
const BETA_ID: u64 = 0xbbbb;
const BETA_NAME: &str = "beta";
const BETA_BYTES: &[u8] = b"beta-stable";

/// Byte range of the superblock checksum field (see `clean-slate-store` docs).
const SUPERBLOCK_CHECKSUM_OFFSET: usize = 8;

type FaultStore = ObjectStore<FaultInjectingBlockDevice>;

/// Single-block transfers force multi-block objects to be written in several
/// chunks, so a crash can land between chunks of one object.
fn geometry() -> BlockGeometry {
    BlockGeometry::new(BlockDeviceId::new(21), 512, 32, 1, false).unwrap()
}

fn previous_alpha() -> Vec<u8> {
    vec![0x11; 1300]
}

fn next_alpha() -> Vec<u8> {
    vec![0x22; 900]
}

fn device_fault() -> BlockIoError {
    BlockIoError::Transport(BlockTransportError::DeviceFault)
}

fn fault_error() -> StoreError {
    StoreError::Block(device_fault())
}

/// Reboot the device from its durable image and mount it, handing back the
/// new device's fault controller so the caller can arm faults after mount.
fn reboot_and_mount(device: &FaultInjectingBlockDevice) -> (FaultStore, FaultController) {
    let rebooted = device.rebooted_from_durable().unwrap();
    let controller = rebooted.controller();
    (ObjectStore::mount(rebooted).unwrap(), controller)
}

/// Format, commit generation 1 (with or without `alpha`), then remount from
/// the durable image so no un-flushed state leaks into the test.
fn build_baseline(include_alpha: bool) -> (FaultStore, FaultController) {
    let device = FaultInjectingBlockDevice::new(FakeBlockDevice::new(geometry()).unwrap());
    let mut store = ObjectStore::format(device).unwrap();
    if include_alpha {
        store
            .write_object(ALPHA_ID, ALPHA_NAME, &previous_alpha())
            .unwrap();
    }
    store.write_object(BETA_ID, BETA_NAME, BETA_BYTES).unwrap();
    store.commit().unwrap();
    assert_eq!(store.committed_generation(), 1);
    reboot_and_mount(&store.into_inner())
}

/// Stage the mutation under test: create or overwrite `alpha`.
fn stage_alpha_update(store: &mut FaultStore) {
    store
        .write_object(ALPHA_ID, ALPHA_NAME, &next_alpha())
        .unwrap();
}

/// Run one un-faulted commit of the mutation and return how many block writes
/// it issues, so the crash matrix covers every write boundary exactly once.
fn count_commit_writes(include_alpha: bool) -> u64 {
    let (mut store, controller) = build_baseline(include_alpha);
    stage_alpha_update(&mut store);
    let before = controller.write_count();
    store.commit().unwrap();
    let writes = controller.write_count() - before;
    assert_eq!(controller.flush_count(), 1);
    writes
}

fn assert_previous_generation(store: &FaultStore, had_alpha: bool) {
    assert_eq!(store.committed_generation(), 1);
    if had_alpha {
        assert_eq!(store.read_object_by_id(ALPHA_ID).unwrap(), previous_alpha());
    } else {
        assert_eq!(store.read_object_by_id(ALPHA_ID), Err(StoreError::NotFound));
    }
    assert_eq!(store.read_object_by_name(BETA_NAME).unwrap(), BETA_BYTES);
}

fn assert_new_generation(store: &FaultStore) {
    assert_eq!(store.committed_generation(), 2);
    assert_eq!(store.read_object_by_id(ALPHA_ID).unwrap(), next_alpha());
    assert_eq!(store.read_object_by_name(BETA_NAME).unwrap(), BETA_BYTES);
}

/// Commit with `plan` armed, assert the deterministic error, reboot, remount.
fn commit_under_fault(include_alpha: bool, plan: FaultPlan) -> FaultStore {
    let (mut store, controller) = build_baseline(include_alpha);
    stage_alpha_update(&mut store);
    controller.arm(plan);

    let result = store.commit();
    assert_eq!(result, Err(fault_error()), "plan {plan:?}");

    let (remounted, _) = reboot_and_mount(&store.into_inner());
    remounted
}

fn crash_matrix(include_alpha: bool) {
    let commit_writes = count_commit_writes(include_alpha);
    // At least one data chunk for each object plus the superblock write.
    assert!(commit_writes >= 3, "commit issued {commit_writes} writes");

    // Power loss after any write before the commit flush: previous generation.
    for write_index in 1..=commit_writes {
        let store = commit_under_fault(
            include_alpha,
            FaultPlan {
                trigger: FaultTrigger::AfterWrite(write_index),
                action: FaultAction::PowerLoss,
            },
        );
        assert_previous_generation(&store, include_alpha);
    }

    // Rejected write (device stays online, nothing applied): previous generation.
    for write_index in 1..=commit_writes {
        let store = commit_under_fault(
            include_alpha,
            FaultPlan {
                trigger: FaultTrigger::AfterWrite(write_index),
                action: FaultAction::IoError(device_fault()),
            },
        );
        assert_previous_generation(&store, include_alpha);
    }

    // Flush rejected: nothing became durable, previous generation.
    let store = commit_under_fault(
        include_alpha,
        FaultPlan {
            trigger: FaultTrigger::AfterFlush(1),
            action: FaultAction::IoError(device_fault()),
        },
    );
    assert_previous_generation(&store, include_alpha);

    // Power loss immediately after the flush completed: the commit point has
    // passed, so the new generation is the only valid recovery target even
    // though the caller observed an error.
    let store = commit_under_fault(
        include_alpha,
        FaultPlan {
            trigger: FaultTrigger::AfterFlush(1),
            action: FaultAction::PowerLoss,
        },
    );
    assert_new_generation(&store);
}

#[test]
fn crash_matrix_for_create_exposes_only_previous_or_new_generation() {
    crash_matrix(false);
}

#[test]
fn crash_matrix_for_overwrite_exposes_only_previous_or_new_generation() {
    crash_matrix(true);
}

#[test]
fn recovery_falls_back_to_previous_generation_when_newer_superblock_is_corrupted() {
    let (mut store, _) = build_baseline(true);
    stage_alpha_update(&mut store);
    store.commit().unwrap();
    assert_eq!(store.committed_generation(), 2);

    // Commit `k` lands in superblock slot `k % SUPERBLOCK_SLOTS`; corrupt the
    // checksum field of the slot holding generation 2.
    let newer_slot = usize::try_from(2 % SUPERBLOCK_SLOTS).unwrap();
    let block_size = usize::try_from(geometry().logical_block_size()).unwrap();
    let mut device = store.into_inner();
    device.durable_bytes_mut()[newer_slot * block_size + SUPERBLOCK_CHECKSUM_OFFSET] ^= 0xff;

    let (remounted, _) = reboot_and_mount(&device);
    assert_previous_generation(&remounted, true);
}

#[test]
fn successful_commit_after_recovered_crash_reuses_the_freed_arena() {
    // Crash mid-commit, recover to generation 1, then commit again cleanly.
    // The retried commit must land in the same inactive slot/arena the
    // interrupted commit was targeting, and read back consistently.
    let mut store = commit_under_fault(
        true,
        FaultPlan {
            trigger: FaultTrigger::AfterWrite(2),
            action: FaultAction::PowerLoss,
        },
    );
    assert_previous_generation(&store, true);

    stage_alpha_update(&mut store);
    store.commit().unwrap();

    let (remounted, _) = reboot_and_mount(&store.into_inner());
    assert_new_generation(&remounted);
}
