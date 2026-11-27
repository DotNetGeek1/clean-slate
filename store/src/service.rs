//! How the storage service serves one object request (#304, #312): the epoch check, the
//! live-byte budget, staging and commits. The service binary runs it against the disk; host
//! tests run it against a fake device.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use clean_slate_block::BlockDevice;
use clean_slate_service_fixtures::{
    ObjectServiceRequest, OBJECT_EPOCH_UNBOUND, OBJECT_MAX_PAYLOAD_BYTES, OBJECT_OP_COMMIT,
    OBJECT_OP_DELETE, OBJECT_OP_READ, OBJECT_OP_READ_AT, OBJECT_OP_TRUNCATE, OBJECT_OP_WRITE,
    OBJECT_OP_WRITE_AT, OBJECT_STATUS_NOT_FOUND, OBJECT_STATUS_NO_SPACE, OBJECT_STATUS_OK,
    OBJECT_STATUS_STALE, OBJECT_STATUS_STORE_ERROR, OBJECT_STATUS_TOO_LARGE,
};

use crate::{ObjectStore, StoreError};

/// `OBJECT_STATUS_STALE` when the request's capability is bound to an object epoch and the
/// object it names is gone, or now has another epoch: a capability to a deleted object never
/// reaches one re-created under its id. `None` lets the request go ahead.
fn stale_status<D: BlockDevice>(
    store: &ObjectStore<D>,
    request: &ObjectServiceRequest,
) -> Option<u64> {
    if request.epoch == OBJECT_EPOCH_UNBOUND {
        return None;
    }
    match store.epoch_of(request.object_id) {
        Ok(epoch) if epoch == request.epoch => None,
        _ => Some(OBJECT_STATUS_STALE),
    }
}

/// Whether staging `request` would take the store's live bytes past `budget`: the heap must
/// still hold a commit's second copy of every payload, so a full store refuses the write
/// rather than running out of heap.
fn over_budget<D: BlockDevice>(
    store: &ObjectStore<D>,
    request: &ObjectServiceRequest,
    len: usize,
    budget: u64,
) -> bool {
    let current = store.object_len(request.object_id).unwrap_or(0) as u64;
    let new_len = match request.op {
        OBJECT_OP_WRITE => len as u64,
        OBJECT_OP_WRITE_AT => current.max(request.offset.saturating_add(len as u64)),
        OBJECT_OP_TRUNCATE => request.offset,
        _ => return false,
    };
    if new_len <= current {
        return false;
    }
    let live = store.live_bytes() as u64;
    live.saturating_add(new_len - current) > budget
}

/// Serves one request: its completion status and, for a read, the bytes. `payload` is a
/// write's bytes: the request frame's, or for a staged request (#312) the service's staging
/// area. A read asks for `request.len` bytes. A write, delete or commit is committed before it completes, so `OBJECT_STATUS_OK`
/// means it is durable, and the commit takes every staged offset write and truncate with it.
/// `WRITE_AT` and `TRUNCATE` only stage: many requests build an object, and one commit makes
/// it durable. A write that would take the store's live bytes past `budget` is refused with
/// `OBJECT_STATUS_NO_SPACE` and stages nothing.
pub fn serve<D: BlockDevice>(
    store: &mut ObjectStore<D>,
    request: &ObjectServiceRequest,
    payload: &[u8],
    budget: u64,
) -> (u64, Option<Vec<u8>>) {
    if let Some(status) = stale_status(store, request) {
        return (status, None);
    }
    if over_budget(store, request, payload.len(), budget) {
        return (OBJECT_STATUS_NO_SPACE, None);
    }
    let staged = match request.op {
        OBJECT_OP_READ_AT => {
            let Ok(len) = usize::try_from(request.len) else {
                return (OBJECT_STATUS_TOO_LARGE, None);
            };
            let mut out = vec![0u8; len];
            return match store.read_object_at(request.object_id, request.offset, &mut out) {
                Ok(read) => {
                    out.truncate(read);
                    (OBJECT_STATUS_OK, Some(out))
                }
                Err(StoreError::NotFound) => (OBJECT_STATUS_NOT_FOUND, None),
                Err(_) => (OBJECT_STATUS_STORE_ERROR, None),
            };
        }
        OBJECT_OP_WRITE_AT | OBJECT_OP_TRUNCATE => {
            let name = object_name(request.object_id);
            let result = if request.op == OBJECT_OP_WRITE_AT {
                store.write_object_at(request.object_id, &name, request.offset, payload)
            } else {
                store.truncate_object(request.object_id, &name, request.offset)
            };
            let status = match result {
                Ok(()) => OBJECT_STATUS_OK,
                Err(StoreError::ObjectTooLarge { .. }) => OBJECT_STATUS_TOO_LARGE,
                Err(StoreError::ObjectTableFull { .. }) => OBJECT_STATUS_NO_SPACE,
                Err(_) => OBJECT_STATUS_STORE_ERROR,
            };
            return (status, None);
        }
        OBJECT_OP_READ => {
            return match store.read_object_by_id(request.object_id) {
                Ok(bytes) if bytes.len() <= OBJECT_MAX_PAYLOAD_BYTES => {
                    (OBJECT_STATUS_OK, Some(bytes))
                }
                Ok(_) => (OBJECT_STATUS_TOO_LARGE, None),
                Err(StoreError::NotFound) => (OBJECT_STATUS_NOT_FOUND, None),
                Err(_) => (OBJECT_STATUS_STORE_ERROR, None),
            };
        }
        OBJECT_OP_WRITE => {
            let name = object_name(request.object_id);
            store.write_object(request.object_id, &name, payload)
        }
        OBJECT_OP_DELETE => store.delete_object(request.object_id),
        OBJECT_OP_COMMIT => Ok(()),
        _ => return (OBJECT_STATUS_STORE_ERROR, None),
    };
    let status = match staged.and_then(|()| store.commit()) {
        Ok(()) => OBJECT_STATUS_OK,
        Err(StoreError::NotFound) => OBJECT_STATUS_NOT_FOUND,
        Err(_) => OBJECT_STATUS_STORE_ERROR,
    };
    (status, None)
}

/// The store name of the object the service keeps for `id`: its id in hex, so every id has
/// its own name.
pub fn object_name(id: u64) -> String {
    alloc::format!("o{id:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_block::fake::FakeBlockDevice;
    use clean_slate_block::{BlockDeviceId, BlockGeometry};

    const BUDGET: u64 = 4096;

    fn store() -> ObjectStore<FakeBlockDevice> {
        let geometry = BlockGeometry::new(BlockDeviceId::new(21), 512, 128, 8, false).unwrap();
        ObjectStore::format(FakeBlockDevice::new(geometry).unwrap()).unwrap()
    }

    fn reboot(store: ObjectStore<FakeBlockDevice>) -> ObjectStore<FakeBlockDevice> {
        let device = store.into_inner();
        let rebooted =
            FakeBlockDevice::from_durable_bytes(device.geometry(), device.durable_bytes()).unwrap();
        ObjectStore::mount(rebooted).unwrap()
    }

    fn request(
        op: u64,
        object_id: u64,
        epoch: u64,
        offset: u64,
        payload: &[u8],
    ) -> ObjectServiceRequest {
        let mut request = ObjectServiceRequest::new(1, op, object_id, payload.len() as u64);
        request.epoch = epoch;
        request.offset = offset;
        request.payload[..payload.len()].copy_from_slice(payload);
        request
    }

    fn run(
        store: &mut ObjectStore<FakeBlockDevice>,
        op: u64,
        object_id: u64,
        epoch: u64,
        offset: u64,
        payload: &[u8],
    ) -> (u64, Option<Vec<u8>>) {
        serve(
            store,
            &request(op, object_id, epoch, offset, payload),
            payload,
            BUDGET,
        )
    }

    fn read_at(
        store: &mut ObjectStore<FakeBlockDevice>,
        id: u64,
        offset: u64,
        len: usize,
    ) -> (u64, Option<Vec<u8>>) {
        let mut request = request(OBJECT_OP_READ_AT, id, OBJECT_EPOCH_UNBOUND, offset, &[]);
        request.len = len as u64;
        serve(store, &request, &[], BUDGET)
    }

    #[test]
    fn offset_writes_stage_until_an_explicit_commit() {
        let mut store = store();
        assert_eq!(
            run(&mut store, OBJECT_OP_WRITE_AT, 9, 0, 0, b"head").0,
            OBJECT_STATUS_OK
        );
        assert_eq!(
            run(&mut store, OBJECT_OP_WRITE_AT, 9, 0, 600, b"tail").0,
            OBJECT_STATUS_OK
        );
        assert_eq!(
            read_at(&mut store, 9, 600, 512),
            (OBJECT_STATUS_OK, Some(b"tail".to_vec()))
        );
        // Not committed: a reboot forgets the object.
        let mut rebooted = reboot(store);
        assert_eq!(read_at(&mut rebooted, 9, 0, 4).0, OBJECT_STATUS_NOT_FOUND);

        assert_eq!(
            run(&mut rebooted, OBJECT_OP_WRITE_AT, 9, 0, 0, b"head").0,
            OBJECT_STATUS_OK
        );
        assert_eq!(
            run(&mut rebooted, OBJECT_OP_TRUNCATE, 9, 0, 1024, &[]).0,
            OBJECT_STATUS_OK
        );
        assert_eq!(
            run(&mut rebooted, OBJECT_OP_COMMIT, 9, 0, 0, &[]).0,
            OBJECT_STATUS_OK
        );
        let mut durable = reboot(rebooted);
        assert_eq!(durable.object_len(9), Ok(1024));
        assert_eq!(
            read_at(&mut durable, 9, 0, 4),
            (OBJECT_STATUS_OK, Some(b"head".to_vec()))
        );
        assert_eq!(
            read_at(&mut durable, 9, 1020, 512),
            (OBJECT_STATUS_OK, Some(vec![0; 4]))
        );
        assert_eq!(
            read_at(&mut durable, 9, 4096, 512),
            (OBJECT_STATUS_OK, Some(Vec::new()))
        );
    }

    #[test]
    fn a_staged_request_moves_more_than_a_frame() {
        let mut store = store();
        let bytes: Vec<u8> = (0..3000u32).map(|n| n as u8).collect();
        let mut write = request(OBJECT_OP_WRITE_AT, 9, 0, 100, &[]);
        write.len = bytes.len() as u64;
        write.flags = clean_slate_service_fixtures::OBJECT_REQUEST_STAGED;
        assert_eq!(
            serve(&mut store, &write, &bytes, BUDGET).0,
            OBJECT_STATUS_OK
        );
        let (status, read) = read_at(&mut store, 9, 100, 3000);
        assert_eq!(
            (status, read.as_deref()),
            (OBJECT_STATUS_OK, Some(&bytes[..]))
        );
        // The budget counts the staged bytes, not the frame.
        let mut big = write;
        big.offset = 0;
        big.object_id = 10;
        assert_eq!(
            serve(&mut store, &big, &bytes, BUDGET).0,
            OBJECT_STATUS_NO_SPACE
        );
    }

    #[test]
    fn a_commit_needs_no_object_and_changes_no_bytes() {
        let mut store = store();
        let generation = store.committed_generation();
        assert_eq!(
            run(&mut store, OBJECT_OP_COMMIT, 9, 0, 0, &[]).0,
            OBJECT_STATUS_OK
        );
        assert_eq!(store.committed_generation(), generation + 1);
        assert_eq!(store.object_len(9), Err(StoreError::NotFound));
    }

    #[test]
    fn writes_past_the_budget_are_refused_and_stage_nothing() {
        let mut store = store();
        assert_eq!(
            run(&mut store, OBJECT_OP_TRUNCATE, 9, 0, BUDGET, &[]).0,
            OBJECT_STATUS_OK
        );
        assert_eq!(store.live_bytes() as u64, BUDGET);
        // Growing anything now is past the budget.
        assert_eq!(
            run(&mut store, OBJECT_OP_WRITE_AT, 9, 0, BUDGET, b"x"),
            (OBJECT_STATUS_NO_SPACE, None)
        );
        assert_eq!(
            run(&mut store, OBJECT_OP_TRUNCATE, 9, 0, BUDGET + 1, &[]).0,
            OBJECT_STATUS_NO_SPACE
        );
        assert_eq!(
            run(&mut store, OBJECT_OP_WRITE_AT, 10, 0, 0, b"x").0,
            OBJECT_STATUS_NO_SPACE
        );
        assert_eq!(
            run(&mut store, OBJECT_OP_WRITE, 10, 0, 0, b"x").0,
            OBJECT_STATUS_NO_SPACE
        );
        assert_eq!(store.object_len(9), Ok(BUDGET as usize));
        assert_eq!(store.object_len(10), Err(StoreError::NotFound));
        // Rewriting bytes in place, shrinking and committing still work on a full store.
        assert_eq!(
            run(&mut store, OBJECT_OP_WRITE_AT, 9, 0, 0, b"in-place").0,
            OBJECT_STATUS_OK
        );
        assert_eq!(
            run(&mut store, OBJECT_OP_COMMIT, 9, 0, 0, &[]).0,
            OBJECT_STATUS_OK
        );
        assert_eq!(
            run(&mut store, OBJECT_OP_TRUNCATE, 9, 0, 16, &[]).0,
            OBJECT_STATUS_OK
        );
        assert_eq!(
            run(&mut store, OBJECT_OP_WRITE_AT, 10, 0, 0, b"room").0,
            OBJECT_STATUS_OK
        );
    }

    #[test]
    fn an_epoch_bound_request_never_reaches_a_recreated_object() {
        let mut store = store();
        assert_eq!(
            run(&mut store, OBJECT_OP_WRITE_AT, 9, 0, 0, b"v1").0,
            OBJECT_STATUS_OK
        );
        assert_eq!(
            run(&mut store, OBJECT_OP_COMMIT, 9, 0, 0, &[]).0,
            OBJECT_STATUS_OK
        );
        let epoch = store.epoch_of(9).unwrap();
        for op in [OBJECT_OP_WRITE_AT, OBJECT_OP_TRUNCATE, OBJECT_OP_COMMIT] {
            assert_eq!(run(&mut store, op, 9, epoch, 0, &[]).0, OBJECT_STATUS_OK);
        }
        assert_eq!(
            run(&mut store, OBJECT_OP_DELETE, 9, epoch, 0, &[]).0,
            OBJECT_STATUS_OK
        );
        assert_eq!(
            run(&mut store, OBJECT_OP_WRITE_AT, 9, 0, 0, b"v2").0,
            OBJECT_STATUS_OK
        );
        assert_ne!(store.epoch_of(9).unwrap(), epoch);
        for op in [
            OBJECT_OP_READ_AT,
            OBJECT_OP_WRITE_AT,
            OBJECT_OP_TRUNCATE,
            OBJECT_OP_COMMIT,
        ] {
            assert_eq!(
                run(&mut store, op, 9, epoch, 0, &[]),
                (OBJECT_STATUS_STALE, None)
            );
        }
        // Unbound requests reach whatever object has the id.
        assert_eq!(
            read_at(&mut store, 9, 0, 2),
            (OBJECT_STATUS_OK, Some(b"v2".to_vec()))
        );
    }
}
