//! M6.3 object-capability request/response protocol shared by kernel, storage service, and clients.

pub const OBJECT_SUBOP_SUBMIT: u64 = 1;
/// `rsi` = request id, `rdx` = output capacity, `r10` = output pointer, `r8` = deadline
/// (absolute `WORK_SET` `NOW` nanoseconds, [`OBJECT_POLL_NO_DEADLINE`] = wait until
/// completion). A pending request whose deadline has passed returns `ETIMEDOUT` and stays
/// queued, so the caller may poll it again.
pub const OBJECT_SUBOP_POLL: u64 = 2;
pub const OBJECT_SUBOP_SERVICE_NEXT: u64 = 3;
pub const OBJECT_SUBOP_SERVICE_COMPLETE: u64 = 4;
pub const OBJECT_SUBOP_CLAIM_BOOTSTRAP_GRANT: u64 = 5;

pub const OBJECT_OP_READ: u64 = 1;
pub const OBJECT_OP_WRITE: u64 = 2;
/// Removes the object; it takes effect at the storage service's next commit, which the
/// service runs before completing the request. Needs `Rights::WRITE`, like a write.
pub const OBJECT_OP_DELETE: u64 = 3;

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

/// [`ObjectServiceRequest::epoch`] for a capability not bound to one object epoch: it
/// reaches whatever object currently has the id.
pub const OBJECT_EPOCH_UNBOUND: u64 = 0;

pub const OBJECT_SERVICE_ROLE_ID: u64 = u64::MAX;

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
    pub payload: [u8; OBJECT_MAX_PAYLOAD_BYTES],
}

pub const OBJECT_SERVICE_REQUEST_BYTES: usize = core::mem::size_of::<ObjectServiceRequest>();

impl ObjectServiceRequest {
    pub const fn new(request_id: u64, op: u64, object_id: u64, len: u64) -> Self {
        Self {
            request_id,
            op,
            object_id,
            len,
            epoch: OBJECT_EPOCH_UNBOUND,
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
        bytes[40..40 + OBJECT_MAX_PAYLOAD_BYTES].copy_from_slice(&self.payload);
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
        if len > OBJECT_MAX_PAYLOAD_BYTES as u64 {
            return Err(ObjectServiceDecodeError::LengthOutOfRange);
        }
        let epoch = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        let mut payload = [0u8; OBJECT_MAX_PAYLOAD_BYTES];
        payload.copy_from_slice(&bytes[40..40 + OBJECT_MAX_PAYLOAD_BYTES]);
        Ok(Self {
            request_id,
            op,
            object_id,
            len,
            epoch,
            payload,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectServiceDecodeError {
    TooShort,
    LengthOutOfRange,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_service_request_size_matches_repr_c() {
        assert_eq!(OBJECT_SERVICE_REQUEST_BYTES, 40 + OBJECT_MAX_PAYLOAD_BYTES);
    }

    #[test]
    fn object_subop_constants_are_stable() {
        assert_eq!(OBJECT_SUBOP_SUBMIT, 1);
        assert_eq!(OBJECT_SUBOP_POLL, 2);
        assert_eq!(OBJECT_SUBOP_SERVICE_NEXT, 3);
        assert_eq!(OBJECT_SUBOP_SERVICE_COMPLETE, 4);
        assert_eq!(OBJECT_SUBOP_CLAIM_BOOTSTRAP_GRANT, 5);
    }

    #[test]
    fn object_service_request_round_trip() {
        let mut request = ObjectServiceRequest::new(9, OBJECT_OP_WRITE, 7, 4);
        request.epoch = 0x1234_5678_9abc;
        request.payload[..4].copy_from_slice(b"test");
        let bytes = request.encode();
        let decoded = ObjectServiceRequest::decode(&bytes).expect("decode");
        assert_eq!(decoded, request);
    }

    #[test]
    fn object_ops_and_statuses_are_stable() {
        assert_eq!(
            [OBJECT_OP_READ, OBJECT_OP_WRITE, OBJECT_OP_DELETE],
            [1, 2, 3]
        );
        assert_eq!(
            [
                OBJECT_STATUS_OK,
                OBJECT_STATUS_NOT_FOUND,
                OBJECT_STATUS_STORE_ERROR,
                OBJECT_STATUS_TOO_LARGE,
                OBJECT_STATUS_STALE
            ],
            [0, 1, 2, 3, 4]
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
