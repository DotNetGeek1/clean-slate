//! M6.3 object-capability request/response protocol shared by kernel, storage service, and clients.
//!
//! The client-facing wire definitions live in [`clean_slate_native_abi::object`]; this module
//! re-exports them and adds the storage service's request frame.

pub use clean_slate_native_abi::object::*;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectServiceRequest {
    pub request_id: u64,
    pub op: u64,
    pub object_id: u64,
    pub len: u64,
    /// The object epoch the authorizing capability is bound to (its resource's
    /// `instance_generation`), or [`OBJECT_EPOCH_UNBOUND`]. Set by the kernel, never by
    /// the client.
    pub epoch: u64,
    /// Byte offset for [`OBJECT_OP_READ_AT`] and [`OBJECT_OP_WRITE_AT`], and the new length
    /// for [`OBJECT_OP_TRUNCATE`]; 0 for the whole-object ops.
    pub offset: u64,
    /// [`OBJECT_REQUEST_STAGED`] for a request whose bytes move through the client's shared
    /// buffer (#312), else 0.
    pub flags: u64,
    pub payload: [u8; OBJECT_MAX_PAYLOAD_BYTES],
}

/// [`ObjectServiceRequest::flags`]: the request's `len` bytes (up to
/// [`OBJECT_MAX_BUFFER_PAYLOAD_BYTES`]) do not travel in `payload`. A `WRITE_AT`'s bytes are
/// in the staging area the service passed to [`OBJECT_SUBOP_SERVICE_NEXT`]; a `READ_AT`'s
/// completion passes up to `len` bytes, which the kernel copies into the client's buffer.
pub const OBJECT_REQUEST_STAGED: u64 = 1;

pub const OBJECT_SERVICE_REQUEST_BYTES: usize = core::mem::size_of::<ObjectServiceRequest>();

impl ObjectServiceRequest {
    pub const fn new(request_id: u64, op: u64, object_id: u64, len: u64) -> Self {
        Self {
            request_id,
            op,
            object_id,
            len,
            epoch: OBJECT_EPOCH_UNBOUND,
            offset: 0,
            flags: 0,
            payload: [0; OBJECT_MAX_PAYLOAD_BYTES],
        }
    }

    pub fn encode(&self) -> [u8; OBJECT_SERVICE_REQUEST_BYTES] {
        let mut bytes = [0u8; OBJECT_SERVICE_REQUEST_BYTES];
        bytes[..8].copy_from_slice(&self.request_id.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.op.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.object_id.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.len.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.epoch.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.offset.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.flags.to_le_bytes());
        bytes[56..56 + OBJECT_MAX_PAYLOAD_BYTES].copy_from_slice(&self.payload);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ObjectServiceDecodeError> {
        if bytes.len() < OBJECT_SERVICE_REQUEST_BYTES {
            return Err(ObjectServiceDecodeError::TooShort);
        }
        let request_id = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let op = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let object_id = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let len = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        let epoch = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        let offset = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
        let flags = u64::from_le_bytes(bytes[48..56].try_into().unwrap());
        let max = match flags {
            0 => OBJECT_MAX_PAYLOAD_BYTES,
            OBJECT_REQUEST_STAGED => OBJECT_MAX_BUFFER_PAYLOAD_BYTES,
            _ => return Err(ObjectServiceDecodeError::UnknownFlags),
        };
        if len > max as u64 {
            return Err(ObjectServiceDecodeError::LengthOutOfRange);
        }
        let mut payload = [0u8; OBJECT_MAX_PAYLOAD_BYTES];
        payload.copy_from_slice(&bytes[56..56 + OBJECT_MAX_PAYLOAD_BYTES]);
        Ok(Self {
            request_id,
            op,
            object_id,
            len,
            epoch,
            offset,
            flags,
            payload,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectServiceDecodeError {
    TooShort,
    LengthOutOfRange,
    UnknownFlags,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_service_request_size_matches_repr_c() {
        assert_eq!(OBJECT_SERVICE_REQUEST_BYTES, 56 + OBJECT_MAX_PAYLOAD_BYTES);
    }

    #[test]
    fn object_subop_constants_are_stable() {
        assert_eq!(OBJECT_SUBOP_SUBMIT, 1);
        assert_eq!(OBJECT_SUBOP_POLL, 2);
        assert_eq!(OBJECT_SUBOP_SERVICE_NEXT, 3);
        assert_eq!(OBJECT_SUBOP_SERVICE_COMPLETE, 4);
        assert_eq!(OBJECT_SUBOP_CLAIM_BOOTSTRAP_GRANT, 5);
        assert_eq!(OBJECT_SUBOP_SUBMIT_AT, 6);
    }

    #[test]
    fn object_service_request_round_trip() {
        let mut request = ObjectServiceRequest::new(9, OBJECT_OP_WRITE, 7, 4);
        request.epoch = 0x1234_5678_9abc;
        request.offset = 0x0002_d000;
        request.payload[..4].copy_from_slice(b"test");
        let bytes = request.encode();
        let decoded = ObjectServiceRequest::decode(&bytes).expect("decode");
        assert_eq!(decoded, request);
    }

    #[test]
    fn only_a_staged_request_carries_more_than_a_frame() {
        let mut request = ObjectServiceRequest::new(9, OBJECT_OP_WRITE_AT, 7, 4096);
        assert_eq!(
            ObjectServiceRequest::decode(&request.encode()),
            Err(ObjectServiceDecodeError::LengthOutOfRange)
        );
        request.flags = OBJECT_REQUEST_STAGED;
        assert_eq!(ObjectServiceRequest::decode(&request.encode()), Ok(request));
        request.len = OBJECT_MAX_BUFFER_PAYLOAD_BYTES as u64 + 1;
        assert_eq!(
            ObjectServiceRequest::decode(&request.encode()),
            Err(ObjectServiceDecodeError::LengthOutOfRange)
        );
        request.len = 0;
        request.flags = 2;
        assert_eq!(
            ObjectServiceRequest::decode(&request.encode()),
            Err(ObjectServiceDecodeError::UnknownFlags)
        );
    }

    #[test]
    fn object_ops_and_statuses_are_stable() {
        assert_eq!(
            [
                OBJECT_OP_READ,
                OBJECT_OP_WRITE,
                OBJECT_OP_DELETE,
                OBJECT_OP_READ_AT,
                OBJECT_OP_WRITE_AT,
                OBJECT_OP_TRUNCATE,
                OBJECT_OP_COMMIT
            ],
            [1, 2, 3, 4, 5, 6, 7]
        );
        assert_eq!(
            [
                OBJECT_STATUS_OK,
                OBJECT_STATUS_NOT_FOUND,
                OBJECT_STATUS_STORE_ERROR,
                OBJECT_STATUS_TOO_LARGE,
                OBJECT_STATUS_STALE,
                OBJECT_STATUS_NO_SPACE
            ],
            [0, 1, 2, 3, 4, 5]
        );
        assert_eq!(OBJECT_EPOCH_UNBOUND, 0);
    }

    #[test]
    fn object_status_pending_does_not_collide_with_syscall_errors() {
        use clean_slate_capability::syscall_abi::{
            SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_ENOSPC, SYSCALL_ESTALE,
        };
        assert_ne!(OBJECT_STATUS_PENDING, SYSCALL_EACCES);
        assert_ne!(OBJECT_STATUS_PENDING, SYSCALL_EINVAL);
        assert_ne!(OBJECT_STATUS_PENDING, SYSCALL_ENOSPC);
        assert_ne!(OBJECT_STATUS_PENDING, SYSCALL_ESTALE);
    }
}
