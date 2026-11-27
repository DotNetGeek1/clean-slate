use super::*;
use clean_slate_capability::{CapabilityError, CapabilityHandle, HolderId, ResourceRef};
use clean_slate_native_abi::directory::entry_object_id;
use clean_slate_native_abi::object::SYSCALL_NR_CAP_OBJECT;
use clean_slate_native_abi::status::STATUS_EIO;
use clean_slate_runtime::fake::FakeKernel;
use std::vec::Vec;

const HANDLE: u64 = 0x4f;
const STORE: u64 = 0x004F_0000;
const DIRECTORY: Directory = Directory::new(HANDLE, STORE);
const READER: u64 = 9;

fn store_kernel() -> FakeKernel {
    let mut sys = FakeKernel::new();
    sys.grant_directory(HANDLE, STORE);
    sys
}

fn bytes_of(event: &AuditEvent) -> [u8; AUDIT_EVENT_SIZE_BYTES] {
    let mut bytes = [0u8; AUDIT_EVENT_SIZE_BYTES];
    // SAFETY: `AuditEvent` is `repr(C)`, 64 bytes, with its padding spelled out as fields.
    unsafe {
        core::ptr::copy_nonoverlapping(
            (event as *const AuditEvent).cast::<u8>(),
            bytes.as_mut_ptr(),
            AUDIT_EVENT_SIZE_BYTES,
        );
    }
    bytes
}

fn denial(sequence: u64, timestamp_ns: u64) -> [u8; AUDIT_EVENT_SIZE_BYTES] {
    let mut event = clean_slate_capability::event_for(
        sequence,
        HolderId(4),
        ResourceRef::object(7),
        Rights::READ,
        CapabilityHandle::INVALID,
        0,
        Err(CapabilityError::MissingRight),
    );
    event.timestamp_ns = timestamp_ns;
    bytes_of(&event)
}

fn denials(sequences: core::ops::RangeInclusive<u64>) -> Vec<[u8; AUDIT_EVENT_SIZE_BYTES]> {
    sequences
        .map(|sequence| denial(sequence, sequence * 10))
        .collect()
}

/// The committed bytes of the entry `name`.
fn committed(sys: &mut FakeKernel, name: &[u8]) -> Vec<u8> {
    let entry = DIRECTORY.open(sys, name).expect("entry");
    let bytes = sys
        .object_committed(entry.object.id())
        .unwrap_or_default()
        .to_vec();
    assert_eq!(bytes.len() as u64, entry.len);
    bytes
}

fn header_of(bytes: &[u8]) -> SegmentHeader {
    SegmentHeader::decode(bytes[..AUDIT_STORE_BLOCK_BYTES].try_into().unwrap()).expect("header")
}

#[test]
fn a_header_round_trips_and_a_foreign_one_is_refused() {
    let header = SegmentHeader {
        boot: 3,
        next_since: 70,
        records: 12,
        segment: 2,
        anchor: [7; 32],
        head: [9; 32],
    };
    let bytes = header.encode();
    assert_eq!(SegmentHeader::decode(&bytes), Some(header));
    let mut foreign = bytes;
    foreign[0] = b'X';
    assert_eq!(SegmentHeader::decode(&foreign), None);
    let mut reserved = bytes;
    reserved[50] = 1;
    assert_eq!(SegmentHeader::decode(&reserved), None);
    assert_eq!(header.entry_len(), 13 * 128);
}

#[test]
fn the_chain_is_sha256_of_the_previous_hash_and_the_record_body() {
    // SHA-256 of 128 zero bytes (32 of anchor, 96 of body), from `head -c128 /dev/zero | sha256sum`.
    let empty = StoredRecord {
        event: [0; 64],
        wall_ns: 0,
        boot: 0,
    };
    let (block, hash) = empty.chain(&GENESIS);
    assert_eq!(&block[96..], &hash);
    assert_eq!(
        hash,
        [
            0x38, 0x72, 0x3a, 0x2e, 0x5e, 0x8a, 0x17, 0xaa, 0x79, 0x50, 0xdc, 0x00, 0x82, 0x09,
            0x94, 0x4e, 0x89, 0x8f, 0x69, 0xa7, 0xbd, 0x10, 0xa2, 0x3c, 0x83, 0x9d, 0x34, 0x1e,
            0x93, 0x5f, 0xd5, 0xca
        ]
    );
    let other = StoredRecord { boot: 1, ..empty };
    assert_ne!(other.chain(&GENESIS).1, hash, "the boot is covered");
    assert_ne!(empty.chain(&hash).1, hash, "the previous hash is covered");
}

#[test]
fn wall_time_is_the_boot_epoch_plus_the_record_time() {
    let event = denial(1, 2_000);
    assert_eq!(StoredRecord::wall_ns_of(&event, Some(1_000_000)), 1_002_000);
    assert_eq!(StoredRecord::wall_ns_of(&event, None), 0);
    let untimed = denial(1, 0);
    assert_eq!(StoredRecord::wall_ns_of(&untimed, Some(1_000_000)), 0);
}

#[test]
fn an_empty_store_gets_a_genesis_segment_and_appends_commit_records_with_the_cursor() {
    let mut sys = store_kernel();
    let (mut store, report) = AuditStore::open(&mut sys, DIRECTORY).unwrap();
    assert_eq!(
        report,
        OpenReport {
            started_segment: true,
            ..OpenReport::default()
        }
    );
    assert_eq!(*store.header(), SegmentHeader::GENESIS);
    store.begin_boot(&mut sys).unwrap();
    assert_eq!(header_of(&committed(&mut sys, AUDIT_LOG_NAME)).boot, 1);

    let batch = denials(1..=3);
    store
        .append(&mut sys, &batch, |_| true, Some(1_000_000_000), 4)
        .unwrap();
    let bytes = committed(&mut sys, AUDIT_LOG_NAME);
    assert_eq!(bytes.len(), 4 * 128);
    let header = header_of(&bytes);
    assert_eq!((header.boot, header.next_since, header.records), (1, 4, 3));
    let mut head = GENESIS;
    for (index, event) in batch.iter().enumerate() {
        let block = &bytes[(index + 1) * 128..][..128];
        assert_eq!(&block[..64], event);
        assert_eq!(
            word(block, 64),
            1_000_000_000 + (index as u64 + 1) * 10,
            "wall time"
        );
        assert_eq!(word(block, 72), 1, "boot");
        head = chain_hash(&head, &block[..96]);
        assert_eq!(&block[96..], &head);
    }
    assert_eq!(header.head, head);
    assert_eq!(*store.header(), header);

    // Nothing to append writes nothing.
    let requests = sys.object_requests().len();
    store.append(&mut sys, &[], |_| true, None, 9).unwrap();
    assert_eq!(sys.object_requests().len(), requests);
}

#[test]
fn a_reboot_finds_the_records_verified_and_a_new_boot_starts_at_sequence_one() {
    let mut sys = store_kernel();
    let (mut store, _) = AuditStore::open(&mut sys, DIRECTORY).unwrap();
    store.begin_boot(&mut sys).unwrap();
    store
        .append(&mut sys, &denials(1..=8), |_| true, None, 9)
        .unwrap();
    store
        .append(&mut sys, &denials(9..=10), |_| true, None, 11)
        .unwrap();
    let before = *store.header();
    sys.restart_storage();

    let (mut store, report) = AuditStore::open(&mut sys, DIRECTORY).unwrap();
    assert_eq!(
        report,
        OpenReport {
            verified: 10,
            ..OpenReport::default()
        }
    );
    assert_eq!(*store.header(), before);
    store.begin_boot(&mut sys).unwrap();
    assert_eq!((store.header().boot, store.header().next_since), (2, 1));
    store
        .append(&mut sys, &denials(1..=2), |_| true, None, 3)
        .unwrap();
    let bytes = committed(&mut sys, AUDIT_LOG_NAME);
    assert_eq!(word(&bytes[11 * 128..], 72), 2, "a boot 2 record");
    assert_eq!(&bytes[128..128 + 64], &denial(1, 10)[..], "boot 1's first");
}

#[test]
fn staged_records_a_crash_loses_leave_the_cursor_where_the_last_commit_put_it() {
    let mut sys = store_kernel();
    let (mut store, _) = AuditStore::open(&mut sys, DIRECTORY).unwrap();
    store.begin_boot(&mut sys).unwrap();
    store
        .append(&mut sys, &denials(1..=2), |_| true, None, 3)
        .unwrap();
    // The commit of the next batch fails: the store keeps its last committed header.
    let entry = DIRECTORY.open(&mut sys, AUDIT_LOG_NAME).unwrap();
    entry
        .object
        .write_at(&mut sys, 5 * 128, &[0xEE; 128])
        .unwrap();
    sys.restart_storage();
    let (store, report) = AuditStore::open(&mut sys, DIRECTORY).unwrap();
    assert_eq!(report.verified, 2);
    assert_eq!(store.header().next_since, 3);
}

#[test]
fn a_failed_commit_leaves_the_header_as_it_was() {
    let mut sys = store_kernel();
    let (mut store, _) = AuditStore::open(&mut sys, DIRECTORY).unwrap();
    store.begin_boot(&mut sys).unwrap();
    let before = *store.header();
    sys.answer_next(SYSCALL_NR_CAP_OBJECT, STATUS_EIO);
    assert_eq!(
        store.append(&mut sys, &denials(1..=1), |_| true, None, 2),
        Err(Error::Failed(STATUS_EIO))
    );
    assert_eq!(*store.header(), before);
}

fn fill_segment(sys: &mut FakeKernel, store: &mut AuditStore, mut sequence: u64) -> u64 {
    while store.header().records + 8 <= AUDIT_SEGMENT_MAX_RECORDS {
        store
            .append(
                sys,
                &denials(sequence..=sequence + 7),
                |_| true,
                None,
                sequence + 8,
            )
            .unwrap();
        sequence += 8;
    }
    sequence
}

#[test]
fn a_full_segment_rotates_and_the_new_one_chains_from_its_head() {
    let mut sys = store_kernel();
    let (mut store, _) = AuditStore::open(&mut sys, DIRECTORY).unwrap();
    store.begin_boot(&mut sys).unwrap();
    let sequence = fill_segment(&mut sys, &mut store, 1);
    let full = *store.header();
    assert_eq!(full.records, AUDIT_SEGMENT_MAX_RECORDS - 7);
    store
        .append(
            &mut sys,
            &denials(sequence..=sequence + 7),
            |_| true,
            None,
            sequence + 8,
        )
        .unwrap();
    let header = *store.header();
    assert_eq!(
        (header.segment, header.records, header.anchor),
        (1, 8, full.head)
    );
    assert_eq!(header_of(&committed(&mut sys, AUDIT_OLD_NAME)), full);

    sys.restart_storage();
    let (store, report) = AuditStore::open(&mut sys, DIRECTORY).unwrap();
    assert_eq!(report.verified, full.records + 8);
    assert_eq!(*store.header(), header);

    // A second rotation replaces the old segment.
    let mut store = store;
    let sequence = fill_segment(&mut sys, &mut store, sequence + 8);
    store
        .append(
            &mut sys,
            &denials(sequence..=sequence + 7),
            |_| true,
            None,
            sequence + 8,
        )
        .unwrap();
    assert_eq!(store.header().segment, 2);
    assert_eq!(header_of(&committed(&mut sys, AUDIT_OLD_NAME)).segment, 1);
    assert_eq!(DIRECTORY.table(&mut sys).unwrap().live_count(), 2);
}

#[test]
fn a_rotation_a_crash_interrupted_resumes_from_the_old_segment() {
    let mut sys = store_kernel();
    let (mut store, _) = AuditStore::open(&mut sys, DIRECTORY).unwrap();
    store.begin_boot(&mut sys).unwrap();
    store
        .append(&mut sys, &denials(1..=3), |_| true, None, 4)
        .unwrap();
    let old = *store.header();
    // The rename committed; the new segment never did.
    DIRECTORY
        .rename(&mut sys, AUDIT_LOG_NAME, AUDIT_OLD_NAME)
        .unwrap();
    let (store, report) = AuditStore::open(&mut sys, DIRECTORY).unwrap();
    assert!(report.started_segment);
    assert_eq!(report.verified, 3);
    assert_eq!(*store.header(), old.successor());
    assert_eq!(store.header().next_since, 4);
}

#[test]
fn a_changed_record_is_found_and_the_segment_set_aside() {
    let mut sys = store_kernel();
    let (mut store, _) = AuditStore::open(&mut sys, DIRECTORY).unwrap();
    store.begin_boot(&mut sys).unwrap();
    store
        .append(&mut sys, &denials(1..=6), |_| true, None, 7)
        .unwrap();
    let header = *store.header();
    let entry = DIRECTORY.open(&mut sys, AUDIT_LOG_NAME).unwrap();
    // Record 4's actor, changed without recomputing the chain.
    entry.object.write_at(&mut sys, 5 * 128 + 16, &[5]).unwrap();
    DIRECTORY.set_len(&mut sys, entry.slot, entry.len).unwrap();

    let (store, report) = AuditStore::open(&mut sys, DIRECTORY).unwrap();
    assert_eq!(report.log_damage, Some(Damage::Chain(4)));
    assert!(report.started_segment);
    assert_eq!(*store.header(), SegmentHeader::GENESIS);
    let bad = committed(&mut sys, AUDIT_BAD_NAME);
    assert_eq!(header_of(&bad), header, "kept, not overwritten");
}

#[test]
fn a_cut_segment_a_foreign_header_and_a_broken_link_are_found() {
    let mut sys = store_kernel();
    let (mut store, _) = AuditStore::open(&mut sys, DIRECTORY).unwrap();
    store.begin_boot(&mut sys).unwrap();
    store
        .append(&mut sys, &denials(1..=2), |_| true, None, 3)
        .unwrap();
    let entry = DIRECTORY.open(&mut sys, AUDIT_LOG_NAME).unwrap();
    assert_eq!(verify(&mut sys, &entry).unwrap(), Ok(*store.header()));
    let cut = Entry {
        len: entry.len - 128,
        ..entry
    };
    assert_eq!(verify(&mut sys, &cut).unwrap(), Err(Damage::Length));
    let mut head_changed = *store.header();
    head_changed.head[0] ^= 1;
    entry
        .object
        .write_at(&mut sys, 0, &head_changed.encode())
        .unwrap();
    assert_eq!(verify(&mut sys, &entry).unwrap(), Err(Damage::Chain(2)));
    entry.object.write_at(&mut sys, 0, b"NOTAUDIT").unwrap();
    assert_eq!(verify(&mut sys, &entry).unwrap(), Err(Damage::Header));

    // A current segment that does not chain from the old one's head.
    let mut sys = store_kernel();
    let (mut store, _) = AuditStore::open(&mut sys, DIRECTORY).unwrap();
    store.begin_boot(&mut sys).unwrap();
    store
        .append(&mut sys, &denials(1..=2), |_| true, None, 3)
        .unwrap();
    DIRECTORY
        .rename(&mut sys, AUDIT_LOG_NAME, AUDIT_OLD_NAME)
        .unwrap();
    AuditStore::start_segment(&mut sys, DIRECTORY, SegmentHeader::GENESIS).unwrap();
    let (store, report) = AuditStore::open(&mut sys, DIRECTORY).unwrap();
    assert_eq!(report.log_damage, Some(Damage::Link));
    assert_eq!(
        store.header().anchor,
        header_of(&committed(&mut sys, AUDIT_OLD_NAME)).head
    );
}

#[test]
fn the_readers_own_allowed_uses_and_the_storage_services_serving_uses_are_not_kept() {
    let use_of = |actor: u64, resource: ResourceRef, rights: Rights, result| {
        bytes_of(&clean_slate_capability::event_for(
            1,
            HolderId(actor),
            resource,
            rights,
            CapabilityHandle::new(1, 1),
            0,
            result,
        ))
    };
    let log = ResourceRef {
        class: ResourceClass::Audit,
        id: 0,
        instance_generation: 0,
    };
    let entry = ResourceRef::object(entry_object_id(STORE, 3));
    let keep = |event| worth_keeping(&event, READER, STORE);
    assert!(!keep(use_of(READER, log, Rights::AUDIT_READ, Ok(()))));
    assert!(!keep(use_of(
        READER,
        ResourceRef::object(STORE),
        Rights::WRITE,
        Ok(())
    )));
    assert!(!keep(use_of(READER, entry, Rights::READ, Ok(()))));
    // Its denials, anyone else's uses and its uses of anything else are kept.
    assert!(keep(use_of(
        READER,
        ResourceRef::object(STORE),
        Rights::WRITE,
        Err(CapabilityError::MissingRight)
    )));
    assert!(keep(use_of(READER + 1, log, Rights::AUDIT_READ, Ok(()))));
    assert!(keep(use_of(
        READER,
        ResourceRef::object(STORE + 16),
        Rights::READ,
        Ok(())
    )));
    assert!(keep(use_of(
        READER,
        ResourceRef::object(STORE - 1),
        Rights::READ,
        Ok(())
    )));
    assert!(keep(bytes_of(&AuditEvent::lost(1, 3))));
    // The storage service serving the store: its allowed uses of its role and its block
    // device are not kept, whoever holds them; their denials are.
    let role = ResourceRef::object(OBJECT_SERVICE_ROLE_ID);
    let block = ResourceRef {
        class: ResourceClass::BlockDevice,
        id: 1,
        instance_generation: 0,
    };
    const STORAGE: u64 = READER + 7;
    assert!(!keep(use_of(STORAGE, role, Rights::INSPECT, Ok(()))));
    assert!(!keep(use_of(STORAGE, block, Rights::READ, Ok(()))));
    assert!(keep(use_of(
        STORAGE,
        role,
        Rights::INSPECT,
        Err(CapabilityError::MissingRight)
    )));
    assert!(keep(use_of(
        STORAGE,
        block,
        Rights::WRITE,
        Err(CapabilityError::UnauthorizedHolder)
    )));
}

#[test]
fn a_whole_drain_is_one_commit_and_only_kept_records_are_chained() {
    let mut sys = store_kernel();
    let (mut store, _) = AuditStore::open(&mut sys, DIRECTORY).unwrap();
    store.begin_boot(&mut sys).unwrap();
    let before = sys.object_requests().len();
    let drain = denials(1..=20);
    store
        .append(&mut sys, &drain, |event| event[0] % 2 == 1, None, 21)
        .unwrap();
    let commits = sys.object_requests()[before..]
        .iter()
        .filter(|(op, ..)| *op == clean_slate_native_abi::object::OBJECT_OP_COMMIT)
        .count();
    assert_eq!(commits, 1);
    let bytes = committed(&mut sys, AUDIT_LOG_NAME);
    let header = header_of(&bytes);
    assert_eq!((header.records, header.next_since), (10, 21));
    for (index, sequence) in (1..=20).step_by(2).enumerate() {
        assert_eq!(word(&bytes[(index + 1) * 128..], 0), sequence);
    }
    let entry = DIRECTORY.open(&mut sys, AUDIT_LOG_NAME).unwrap();
    assert_eq!(verify(&mut sys, &entry).unwrap(), Ok(header));
}
