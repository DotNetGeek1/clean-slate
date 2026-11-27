//! The persistent-object capability (syscall 8, `SYSCALL_NR_CAP_OBJECT`): the subops, ops,
//! statuses and the `SUBMIT_AT` descriptor a native client uses (M6.3, #304, #312). The
//! storage service's request frame stays in `clean-slate-service-fixtures`.

pub use clean_slate_capability::syscall_abi::SYSCALL_NR_CAP_OBJECT;

pub const OBJECT_SUBOP_SUBMIT: u64 = 1;
/// `rsi` = request id, `rdx` = output capacity, `r10` = output pointer, `r8` = deadline
/// (absolute `WORK_SET` `NOW` nanoseconds, [`OBJECT_POLL_NO_DEADLINE`] = wait until
/// completion). A pending request whose deadline has passed returns `ETIMEDOUT` and stays
/// queued, so the caller may poll it again.
pub const OBJECT_SUBOP_POLL: u64 = 2;
/// The storage service's next request. `rsi` = service role handle, `rdx` = request frame
/// output, `r10`/`r8` = the service's staging area and its length: a staged `WRITE_AT`'s
/// bytes are copied there (#312).
pub const OBJECT_SUBOP_SERVICE_NEXT: u64 = 3;
/// Completes a request. `rsi` = service role handle, `rdx` = request id, `r10` = status,
/// `r8`/`r9` = completion payload: at most [`OBJECT_MAX_PAYLOAD_BYTES`], or for a staged
/// `READ_AT` up to the request's length, copied into the client's buffer.
pub const OBJECT_SUBOP_SERVICE_COMPLETE: u64 = 4;
pub const OBJECT_SUBOP_CLAIM_BOOTSTRAP_GRANT: u64 = 5;
/// A native submit of an offset op or a commit (#312). `rsi` = object capability handle,
/// `rdx` = pointer to an [`ObjectSubmitAt`] descriptor, `r10` = its length
/// ([`OBJECT_SUBMIT_AT_BYTES`]). Returns the request id, polled like
/// [`OBJECT_SUBOP_SUBMIT`]'s. [`OBJECT_SUBOP_SUBMIT`] keeps the whole-object ops: it has no
/// register left for an offset.
pub const OBJECT_SUBOP_SUBMIT_AT: u64 = 6;

pub const OBJECT_OP_READ: u64 = 1;
pub const OBJECT_OP_WRITE: u64 = 2;
/// Removes the object; it takes effect at the storage service's next commit, which the
/// service runs before completing the request. Needs `Rights::WRITE`, like a write.
pub const OBJECT_OP_DELETE: u64 = 3;
/// Reads up to `len` bytes (at most [`OBJECT_MAX_PAYLOAD_BYTES`]) from `offset`; the
/// completion's payload holds the bytes, fewer at the object's end. Needs `Rights::READ`.
pub const OBJECT_OP_READ_AT: u64 = 4;
/// Stages the payload at `offset`, creating the object when it is missing and zero-filling
/// past its end. It is not committed: `OBJECT_STATUS_OK` means staged, and the next
/// committing op ([`OBJECT_OP_WRITE`] or [`OBJECT_OP_DELETE`]) makes it durable. A crash
/// or service restart before then forgets it. Needs `Rights::WRITE`.
pub const OBJECT_OP_WRITE_AT: u64 = 5;
/// Stages the object cut or zero-extended to `offset` bytes, creating it when it is
/// missing. Staged like [`OBJECT_OP_WRITE_AT`]. Needs `Rights::WRITE`.
pub const OBJECT_OP_TRUNCATE: u64 = 6;
/// Commits every staged change in the store, so that it survives a crash or restart:
/// `OBJECT_STATUS_OK` means durable. It carries no payload and no offset. Needs
/// `Rights::WRITE` on the object it names. The store has one commit point, so this also
/// commits other holders' staged changes, as [`OBJECT_OP_WRITE`] and [`OBJECT_OP_DELETE`]
/// always have.
pub const OBJECT_OP_COMMIT: u64 = 7;

pub const OBJECT_MAX_PAYLOAD_BYTES: usize = 512;
pub const OBJECT_REQUEST_SLOTS: usize = 4;

pub const OBJECT_POLL_NO_DEADLINE: u64 = 0;

pub const OBJECT_STATUS_PENDING: u64 = u64::MAX - 200;
pub const OBJECT_STATUS_OK: u64 = 0;
pub const OBJECT_STATUS_NOT_FOUND: u64 = 1;
pub const OBJECT_STATUS_STORE_ERROR: u64 = 2;
pub const OBJECT_STATUS_TOO_LARGE: u64 = 3;
/// The request's capability is bound to an object epoch, and the object it names is gone
/// or was deleted and re-created under the same id with a later epoch.
pub const OBJECT_STATUS_STALE: u64 = 4;
/// The write would take the store's live bytes past the service's budget: the store is
/// full. Nothing was staged.
pub const OBJECT_STATUS_NO_SPACE: u64 = 5;

/// The native status a poll returns for a failed [`OBJECT_SUBOP_SUBMIT_AT`] request
/// (#312), so that a failure never reads as a byte count: `NOT_FOUND` is `ENOENT`, `NO_SPACE`
/// `ENOSPC`, `STALE` `ESTALE` (the object the capability named is gone), `TOO_LARGE` `EFBIG`,
/// and a store error or any other status `EIO`. [`OBJECT_SUBOP_SUBMIT`]'s requests keep the
/// raw object status.
pub const fn object_status_to_native(status: u64) -> u64 {
    use crate::status::{STATUS_EFBIG, STATUS_EIO, STATUS_ENOENT, STATUS_ENOSPC, STATUS_ESTALE};
    match status {
        OBJECT_STATUS_NOT_FOUND => STATUS_ENOENT,
        OBJECT_STATUS_NO_SPACE => STATUS_ENOSPC,
        OBJECT_STATUS_STALE => STATUS_ESTALE,
        OBJECT_STATUS_TOO_LARGE => STATUS_EFBIG,
        _ => STATUS_EIO,
    }
}

/// [`ObjectServiceRequest::epoch`] for a capability not bound to one object epoch: it
/// reaches whatever object currently has the id.
pub const OBJECT_EPOCH_UNBOUND: u64 = 0;

pub const OBJECT_SERVICE_ROLE_ID: u64 = u64::MAX;

/// Most bytes one [`OBJECT_SUBOP_SUBMIT_AT`] request moves through a shared buffer (#312):
/// a 1 MiB object is eight requests.
pub const OBJECT_MAX_BUFFER_PAYLOAD_BYTES: usize = 128 * 1024;

/// Bytes of an [`ObjectSubmitAt`] descriptor.
pub const OBJECT_SUBMIT_AT_BYTES: usize = 64;

/// What [`OBJECT_SUBOP_SUBMIT_AT`] submits, little-endian: op@0, object_id@8, offset@16,
/// len@24, data@32, buffer@40, buffer_offset@48, reserved-zero@56.
///
/// - `READ_AT`: `len` bytes from `offset`. Without a buffer, at most
///   [`OBJECT_MAX_PAYLOAD_BYTES`], and the poll copies them to its output; `data` is ignored.
/// - `WRITE_AT`: `len` bytes staged at `offset`. Without a buffer, at most
///   [`OBJECT_MAX_PAYLOAD_BYTES`] read from `data`.
/// - `TRUNCATE`: `offset` is the new length; `len` is 0.
/// - `COMMIT`: `offset` and `len` are 0.
///
/// With `buffer`, a shared-buffer capability handle (0 for none), a `READ_AT` or `WRITE_AT`
/// moves up to [`OBJECT_MAX_BUFFER_PAYLOAD_BYTES`] between the object and the buffer's bytes
/// at `buffer_offset`; `data` is then 0. A `WRITE_AT` needs `READ` on the buffer and a
/// `READ_AT` `WRITE`; the range must lie inside the buffer. The buffer stays pinned until the
/// request completes, and a buffered `READ_AT`'s poll returns the byte count with nothing
/// copied to its output.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObjectSubmitAt {
    pub op: u64,
    pub object_id: u64,
    pub offset: u64,
    pub len: u64,
    pub data: u64,
    pub buffer: u64,
    pub buffer_offset: u64,
}

/// Why an [`ObjectSubmitAt`] was refused before it reached the queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectSubmitAtError {
    WrongLength,
    ReservedNonZero,
    /// Not an op [`OBJECT_SUBOP_SUBMIT_AT`] takes.
    UnsupportedOp,
    /// A length or offset the op does not take, or a payload past
    /// [`OBJECT_MAX_PAYLOAD_BYTES`].
    BadLength,
    /// A buffer on an op that moves no bytes, a buffer offset without a buffer, or both a
    /// buffer and `data`.
    BadBuffer,
}

impl ObjectSubmitAt {
    pub fn encode(&self) -> [u8; OBJECT_SUBMIT_AT_BYTES] {
        let mut out = [0u8; OBJECT_SUBMIT_AT_BYTES];
        let fields = [
            self.op,
            self.object_id,
            self.offset,
            self.len,
            self.data,
            self.buffer,
            self.buffer_offset,
            0,
        ];
        for (chunk, value) in out.chunks_exact_mut(8).zip(fields) {
            chunk.copy_from_slice(&value.to_le_bytes());
        }
        out
    }

    /// Decodes and checks a descriptor: the op is one [`OBJECT_SUBOP_SUBMIT_AT`] takes, and
    /// its length and offset are ones that op takes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ObjectSubmitAtError> {
        if bytes.len() != OBJECT_SUBMIT_AT_BYTES {
            return Err(ObjectSubmitAtError::WrongLength);
        }
        let field =
            |index: usize| u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap());
        if field(7) != 0 {
            return Err(ObjectSubmitAtError::ReservedNonZero);
        }
        let submit = Self {
            op: field(0),
            object_id: field(1),
            offset: field(2),
            len: field(3),
            data: field(4),
            buffer: field(5),
            buffer_offset: field(6),
        };
        let moves_bytes = matches!(submit.op, OBJECT_OP_READ_AT | OBJECT_OP_WRITE_AT);
        if submit.buffer == 0 {
            if submit.buffer_offset != 0 {
                return Err(ObjectSubmitAtError::BadBuffer);
            }
        } else if !moves_bytes || submit.data != 0 {
            return Err(ObjectSubmitAtError::BadBuffer);
        }
        let max = if submit.buffer == 0 {
            OBJECT_MAX_PAYLOAD_BYTES
        } else {
            OBJECT_MAX_BUFFER_PAYLOAD_BYTES
        };
        let len_ok = match submit.op {
            OBJECT_OP_READ_AT | OBJECT_OP_WRITE_AT => submit.len <= max as u64,
            OBJECT_OP_TRUNCATE => submit.len == 0,
            OBJECT_OP_COMMIT => submit.len == 0 && submit.offset == 0,
            _ => return Err(ObjectSubmitAtError::UnsupportedOp),
        };
        if !len_ok {
            return Err(ObjectSubmitAtError::BadLength);
        }
        Ok(submit)
    }

    /// Bytes the kernel copies from `data` into the request: an unbuffered write's payload,
    /// else none.
    pub fn payload_len(&self) -> usize {
        if self.op == OBJECT_OP_WRITE_AT && self.buffer == 0 {
            self.len as usize
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_at_round_trips_and_has_a_fixed_layout() {
        let submit = ObjectSubmitAt {
            op: OBJECT_OP_WRITE_AT,
            object_id: 0x5100_0001,
            offset: 0x0010_0000,
            len: 512,
            data: 0x4000_2000,
            buffer: 0,
            buffer_offset: 0,
        };
        let bytes = submit.encode();
        assert_eq!(bytes.len(), OBJECT_SUBMIT_AT_BYTES);
        assert_eq!(&bytes[16..24], &0x0010_0000u64.to_le_bytes());
        assert_eq!(ObjectSubmitAt::decode(&bytes), Ok(submit));
        assert_eq!(submit.payload_len(), 512);
    }

    #[test]
    fn submit_at_refuses_what_its_op_does_not_take() {
        let check = |op, offset, len| {
            ObjectSubmitAt::decode(
                &ObjectSubmitAt {
                    op,
                    object_id: 7,
                    offset,
                    len,
                    ..Default::default()
                }
                .encode(),
            )
        };
        assert!(check(OBJECT_OP_READ_AT, 4096, 512).is_ok());
        assert_eq!(
            check(OBJECT_OP_READ_AT, 0, 513),
            Err(ObjectSubmitAtError::BadLength)
        );
        assert_eq!(
            check(OBJECT_OP_WRITE_AT, 0, 513),
            Err(ObjectSubmitAtError::BadLength)
        );
        assert!(check(OBJECT_OP_TRUNCATE, 1 << 20, 0).is_ok());
        assert_eq!(
            check(OBJECT_OP_TRUNCATE, 0, 1),
            Err(ObjectSubmitAtError::BadLength)
        );
        assert!(check(OBJECT_OP_COMMIT, 0, 0).is_ok());
        assert_eq!(
            check(OBJECT_OP_COMMIT, 1, 0),
            Err(ObjectSubmitAtError::BadLength)
        );
        for op in [OBJECT_OP_READ, OBJECT_OP_WRITE, OBJECT_OP_DELETE, 0, 99] {
            assert_eq!(check(op, 0, 0), Err(ObjectSubmitAtError::UnsupportedOp));
        }
        assert_eq!(
            ObjectSubmitAt::decode(&[0; OBJECT_SUBMIT_AT_BYTES - 1]),
            Err(ObjectSubmitAtError::WrongLength)
        );
        let mut reserved = check_bytes(OBJECT_OP_COMMIT);
        reserved[60] = 1;
        assert_eq!(
            ObjectSubmitAt::decode(&reserved),
            Err(ObjectSubmitAtError::ReservedNonZero)
        );
        let mut offset_only = check_bytes(OBJECT_OP_WRITE_AT);
        offset_only[48] = 3;
        assert_eq!(
            ObjectSubmitAt::decode(&offset_only),
            Err(ObjectSubmitAtError::BadBuffer)
        );
        assert_eq!(
            ObjectSubmitAt {
                op: OBJECT_OP_READ_AT,
                len: 512,
                ..Default::default()
            }
            .payload_len(),
            0
        );
    }

    #[test]
    fn submit_at_failures_poll_as_native_statuses() {
        use crate::status::{is_status, STATUS_ENOSPC, STATUS_ESTALE};
        for status in [
            OBJECT_STATUS_NOT_FOUND,
            OBJECT_STATUS_STORE_ERROR,
            OBJECT_STATUS_TOO_LARGE,
            OBJECT_STATUS_STALE,
            OBJECT_STATUS_NO_SPACE,
            99,
        ] {
            assert!(is_status(object_status_to_native(status)));
        }
        assert_eq!(
            object_status_to_native(OBJECT_STATUS_NO_SPACE),
            STATUS_ENOSPC
        );
        assert_eq!(object_status_to_native(OBJECT_STATUS_STALE), STATUS_ESTALE);
    }

    #[test]
    fn a_buffer_carries_larger_payloads_for_the_ops_that_move_bytes() {
        let buffered = |op, len, data| {
            ObjectSubmitAt::decode(
                &ObjectSubmitAt {
                    op,
                    object_id: 7,
                    len,
                    data,
                    buffer: 0x1234,
                    buffer_offset: 4096,
                    ..Default::default()
                }
                .encode(),
            )
        };
        let max = OBJECT_MAX_BUFFER_PAYLOAD_BYTES as u64;
        for op in [OBJECT_OP_READ_AT, OBJECT_OP_WRITE_AT] {
            let submit = buffered(op, max, 0).expect("buffered");
            assert_eq!(submit.payload_len(), 0);
            assert_eq!(
                buffered(op, max + 1, 0),
                Err(ObjectSubmitAtError::BadLength)
            );
            assert_eq!(
                buffered(op, 16, 0x4000_0000),
                Err(ObjectSubmitAtError::BadBuffer)
            );
        }
        for op in [OBJECT_OP_TRUNCATE, OBJECT_OP_COMMIT] {
            assert_eq!(buffered(op, 0, 0), Err(ObjectSubmitAtError::BadBuffer));
        }
    }

    fn check_bytes(op: u64) -> [u8; OBJECT_SUBMIT_AT_BYTES] {
        ObjectSubmitAt {
            op,
            ..Default::default()
        }
        .encode()
    }
}
