use super::*;
use clean_slate_native_abi::directory::entry_object_id;
use clean_slate_native_abi::status::STATUS_ENOSPC;
use clean_slate_runtime::fake::FakeKernel;
use clean_slate_runtime::storage::Object;
use clean_slate_service_fixtures::storage_probe::STORAGE_PROBE_DIRECTORY_ID;

const HANDLE: u64 = 0x71;
const DIRECTORY: Directory = Directory::new(HANDLE, STORAGE_PROBE_DIRECTORY_ID);

fn kernel() -> FakeKernel {
    let mut sys = FakeKernel::new();
    sys.grant_directory(HANDLE, STORAGE_PROBE_DIRECTORY_ID);
    sys
}

/// One boot: the storage service starts from what was committed, then the probe runs.
fn boot(sys: &mut FakeKernel) -> (Result<ProbeStage, ProbeFailure>, Vec<ProbeStep>) {
    sys.restart_storage();
    let mut steps = Vec::new();
    let result = run(sys, DIRECTORY, |_, step| steps.push(step));
    (result, steps)
}

fn entry_bytes(sys: &FakeKernel) -> Option<&[u8]> {
    sys.object_committed(entry_object_id(STORAGE_PROBE_DIRECTORY_ID, 0))
}

#[test]
fn three_boots_write_truncate_and_remove_the_file() {
    let mut sys = kernel();

    let (result, steps) = boot(&mut sys);
    assert_eq!(result, Ok(ProbeStage::Wrote));
    assert!(steps.contains(&ProbeStep::WriteBuffer));
    let bytes = entry_bytes(&sys).unwrap();
    assert_eq!(bytes.len(), FILE_BYTES);
    assert!(bytes
        .iter()
        .enumerate()
        .all(|(offset, byte)| *byte == probe_byte(offset as u64)));
    assert_eq!(sys.live_buffers(), 0, "the buffer is released");

    let (result, steps) = boot(&mut sys);
    assert_eq!(result, Ok(ProbeStage::Truncated));
    assert!(steps.contains(&ProbeStep::ReadBuffer));
    assert_eq!(entry_bytes(&sys).unwrap().len(), TRUNCATED_BYTES);

    assert_eq!(boot(&mut sys).0, Ok(ProbeStage::Removed));
    assert_eq!(entry_bytes(&sys).unwrap().len(), 0);
    assert_eq!(
        DIRECTORY.open(&mut sys, STORAGE_PROBE_FILE_NAME),
        Err(Error::Failed(STATUS_ENOENT))
    );

    // The cycle starts over on the next boot.
    assert_eq!(boot(&mut sys).0, Ok(ProbeStage::Wrote));
}

#[test]
fn a_write_the_store_has_no_room_for_fails_and_the_next_boot_fills_the_empty_entry() {
    let mut sys = kernel();
    sys.set_object_budget(FILE_BYTES / 2);
    let (result, _) = boot(&mut sys);
    let failure = result.unwrap_err();
    assert_eq!(failure.step, ProbeStep::WriteBuffer);
    assert_eq!(failure.detail, STATUS_ENOSPC);
    // The name was committed when it was created; none of the bytes were.
    assert_eq!(
        DIRECTORY
            .open(&mut sys, STORAGE_PROBE_FILE_NAME)
            .unwrap()
            .len,
        0
    );
    assert_eq!(sys.live_buffers(), 0);

    sys.set_object_budget(4 * FILE_BYTES);
    assert_eq!(boot(&mut sys).0, Ok(ProbeStage::Wrote));
}

#[test]
fn a_changed_byte_fails_the_read_back_at_its_offset() {
    let mut sys = kernel();
    assert_eq!(boot(&mut sys).0, Ok(ProbeStage::Wrote));
    let entry = Object::new(HANDLE, entry_object_id(STORAGE_PROBE_DIRECTORY_ID, 0));
    let wrong = !probe_byte(300_000);
    entry.write_at(&mut sys, 300_000, &[wrong]).unwrap();
    entry.commit(&mut sys).unwrap();
    let failure = boot(&mut sys).0.unwrap_err();
    assert_eq!(
        failure,
        ProbeFailure {
            step: ProbeStep::CheckBytes,
            detail: 300_000
        }
    );
    // Nothing was truncated.
    assert_eq!(entry_bytes(&sys).unwrap().len(), FILE_BYTES);
}

#[test]
fn an_entry_of_another_length_is_refused() {
    let mut sys = kernel();
    let entry = DIRECTORY.create(&mut sys, STORAGE_PROBE_FILE_NAME).unwrap();
    entry.object.write_at(&mut sys, 0, &[1, 2, 3]).unwrap();
    DIRECTORY.set_len(&mut sys, entry.slot, 3).unwrap();
    assert_eq!(
        boot(&mut sys).0,
        Err(ProbeFailure {
            step: ProbeStep::UnexpectedLength,
            detail: 3
        })
    );
}
