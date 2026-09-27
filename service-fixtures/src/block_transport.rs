//! Bounded M5 block request/response transport shared by userspace service and kernel adapter.

use clean_slate_block::{
    BlockGeometry, BlockIoError, BlockRequestError, BlockTransportError, BlockUnsupportedError,
};

pub const STORAGE_BLOCK_DEVICE_ID: u64 = 1;
pub const BLOCK_TRANSPORT_MAGIC: u32 = 0x424C_4B31; // "BLK1"
pub const BLOCK_TRANSPORT_VERSION: u16 = 1;
pub const BLOCK_TRANSPORT_REQUEST_BYTES: usize = 40;
pub const BLOCK_TRANSPORT_RESPONSE_BYTES: usize = 40;
pub const BLOCK_TRANSPORT_MAX_PAYLOAD_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockTransportOp {
    Geometry = 1,
    Read = 2,
    Write = 3,
    Flush = 4,
}

impl BlockTransportOp {
    pub const fn from_repr(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Geometry),
            2 => Some(Self::Read),
            3 => Some(Self::Write),
            4 => Some(Self::Flush),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTransportDecodeError {
    BadMagic,
    UnsupportedVersion(u16),
    InvalidOperation(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockTransportStatus {
    Ok = 0,
    InvalidProtocol = 1,
    InvalidRequest = 2,
    Unsupported = 3,
    DeviceFault = 4,
    Timeout = 5,
    ResetRequired = 6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockTransportRequest {
    pub request_id: u64,
    pub device_id: u64,
    pub operation: BlockTransportOp,
    pub lba: u64,
    pub blocks: u32,
    pub buffer_len: u32,
}

impl BlockTransportRequest {
    pub const fn geometry(request_id: u64, device_id: u64) -> Self {
        Self {
            request_id,
            device_id,
            operation: BlockTransportOp::Geometry,
            lba: 0,
            blocks: 0,
            buffer_len: 0,
        }
    }

    pub fn encode(&self) -> [u8; BLOCK_TRANSPORT_REQUEST_BYTES] {
        let mut out = [0u8; BLOCK_TRANSPORT_REQUEST_BYTES];
        out[0..4].copy_from_slice(&BLOCK_TRANSPORT_MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&BLOCK_TRANSPORT_VERSION.to_le_bytes());
        out[6] = self.operation as u8;
        out[8..16].copy_from_slice(&self.request_id.to_le_bytes());
        out[16..24].copy_from_slice(&self.device_id.to_le_bytes());
        out[24..32].copy_from_slice(&self.lba.to_le_bytes());
        out[32..36].copy_from_slice(&self.blocks.to_le_bytes());
        out[36..40].copy_from_slice(&self.buffer_len.to_le_bytes());
        out
    }

    pub fn decode(
        bytes: &[u8; BLOCK_TRANSPORT_REQUEST_BYTES],
    ) -> Result<Self, BlockTransportDecodeError> {
        let magic = u32::from_le_bytes(bytes[0..4].try_into().expect("slice"));
        if magic != BLOCK_TRANSPORT_MAGIC {
            return Err(BlockTransportDecodeError::BadMagic);
        }
        let version = u16::from_le_bytes(bytes[4..6].try_into().expect("slice"));
        if version != BLOCK_TRANSPORT_VERSION {
            return Err(BlockTransportDecodeError::UnsupportedVersion(version));
        }
        let op_raw = bytes[6];
        let operation = BlockTransportOp::from_repr(op_raw)
            .ok_or(BlockTransportDecodeError::InvalidOperation(op_raw))?;
        Ok(Self {
            request_id: u64::from_le_bytes(bytes[8..16].try_into().expect("slice")),
            device_id: u64::from_le_bytes(bytes[16..24].try_into().expect("slice")),
            operation,
            lba: u64::from_le_bytes(bytes[24..32].try_into().expect("slice")),
            blocks: u32::from_le_bytes(bytes[32..36].try_into().expect("slice")),
            buffer_len: u32::from_le_bytes(bytes[36..40].try_into().expect("slice")),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockTransportResponse {
    pub request_id: u64,
    pub device_id: u64,
    pub operation: BlockTransportOp,
    pub status: BlockTransportStatus,
    pub logical_block_size: u32,
    pub block_count: u64,
    pub max_transfer_blocks: u32,
}

impl BlockTransportResponse {
    pub fn encode(&self) -> [u8; BLOCK_TRANSPORT_RESPONSE_BYTES] {
        let mut out = [0u8; BLOCK_TRANSPORT_RESPONSE_BYTES];
        out[0..4].copy_from_slice(&BLOCK_TRANSPORT_MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&BLOCK_TRANSPORT_VERSION.to_le_bytes());
        out[6] = self.operation as u8;
        out[7] = self.status as u8;
        out[8..16].copy_from_slice(&self.request_id.to_le_bytes());
        out[16..24].copy_from_slice(&self.device_id.to_le_bytes());
        out[24..28].copy_from_slice(&self.logical_block_size.to_le_bytes());
        out[28..36].copy_from_slice(&self.block_count.to_le_bytes());
        out[36..40].copy_from_slice(&self.max_transfer_blocks.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8; BLOCK_TRANSPORT_RESPONSE_BYTES]) -> Result<Self, &'static str> {
        let magic = u32::from_le_bytes(bytes[0..4].try_into().expect("slice"));
        if magic != BLOCK_TRANSPORT_MAGIC {
            return Err("response magic was invalid");
        }
        let version = u16::from_le_bytes(bytes[4..6].try_into().expect("slice"));
        if version != BLOCK_TRANSPORT_VERSION {
            return Err("response version was invalid");
        }
        let operation =
            BlockTransportOp::from_repr(bytes[6]).ok_or("response operation was invalid")?;
        let status = match bytes[7] {
            0 => BlockTransportStatus::Ok,
            1 => BlockTransportStatus::InvalidProtocol,
            2 => BlockTransportStatus::InvalidRequest,
            3 => BlockTransportStatus::Unsupported,
            4 => BlockTransportStatus::DeviceFault,
            5 => BlockTransportStatus::Timeout,
            6 => BlockTransportStatus::ResetRequired,
            _ => return Err("response status was invalid"),
        };
        Ok(Self {
            request_id: u64::from_le_bytes(bytes[8..16].try_into().expect("slice")),
            device_id: u64::from_le_bytes(bytes[16..24].try_into().expect("slice")),
            operation,
            status,
            logical_block_size: u32::from_le_bytes(bytes[24..28].try_into().expect("slice")),
            block_count: u64::from_le_bytes(bytes[28..36].try_into().expect("slice")),
            max_transfer_blocks: u32::from_le_bytes(bytes[36..40].try_into().expect("slice")),
        })
    }
}

/// What a decoded request needs: an immediate status, or one device operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockRequestAction {
    Respond(BlockTransportStatus),
    Read,
    Write,
    Flush,
}

/// Transport checks every backend shares: device id, payload length, and the
/// zero-argument shape of geometry and flush. LBA range checks stay with the device.
pub fn classify_block_request(
    request: &BlockTransportRequest,
    geometry: BlockGeometry,
    payload_len: usize,
) -> BlockRequestAction {
    if request.device_id != geometry.device_id().get() {
        return BlockRequestAction::Respond(BlockTransportStatus::InvalidRequest);
    }
    let request_len = usize::try_from(request.buffer_len).unwrap_or(usize::MAX);
    if request_len > BLOCK_TRANSPORT_MAX_PAYLOAD_BYTES || request_len != payload_len {
        return BlockRequestAction::Respond(BlockTransportStatus::InvalidRequest);
    }
    let zero_arguments = request.blocks == 0 && request.lba == 0 && request.buffer_len == 0;
    match request.operation {
        BlockTransportOp::Geometry if zero_arguments => {
            BlockRequestAction::Respond(BlockTransportStatus::Ok)
        }
        BlockTransportOp::Flush if zero_arguments => BlockRequestAction::Flush,
        BlockTransportOp::Geometry | BlockTransportOp::Flush => {
            BlockRequestAction::Respond(BlockTransportStatus::InvalidRequest)
        }
        BlockTransportOp::Read => BlockRequestAction::Read,
        BlockTransportOp::Write => BlockRequestAction::Write,
    }
}

/// Response to `request` carrying `status` and the backend's geometry.
pub fn block_response(
    request: &BlockTransportRequest,
    geometry: BlockGeometry,
    status: BlockTransportStatus,
) -> BlockTransportResponse {
    BlockTransportResponse {
        request_id: request.request_id,
        device_id: request.device_id,
        operation: request.operation,
        status,
        logical_block_size: geometry.logical_block_size(),
        block_count: geometry.block_count(),
        max_transfer_blocks: geometry.max_transfer_blocks(),
    }
}

/// Response to a request that did not decode.
pub fn invalid_protocol_response() -> BlockTransportResponse {
    BlockTransportResponse {
        request_id: 0,
        device_id: 0,
        operation: BlockTransportOp::Geometry,
        status: BlockTransportStatus::InvalidProtocol,
        logical_block_size: 0,
        block_count: 0,
        max_transfer_blocks: 0,
    }
}

pub fn block_io_status(error: BlockIoError) -> BlockTransportStatus {
    match error {
        BlockIoError::InvalidRequest(
            BlockRequestError::ZeroBlocks
            | BlockRequestError::TransferTooLarge { .. }
            | BlockRequestError::BufferLengthNotAligned { .. }
            | BlockRequestError::BufferLengthMismatch { .. }
            | BlockRequestError::RangeOutOfBounds { .. }
            | BlockRequestError::BufferLengthOverflow,
        ) => BlockTransportStatus::InvalidRequest,
        BlockIoError::Unsupported(
            BlockUnsupportedError::WriteProtected | BlockUnsupportedError::FlushUnsupported,
        ) => BlockTransportStatus::Unsupported,
        BlockIoError::Transport(BlockTransportError::DeviceFault) => {
            BlockTransportStatus::DeviceFault
        }
        BlockIoError::Transport(BlockTransportError::Timeout) => BlockTransportStatus::Timeout,
        BlockIoError::Transport(BlockTransportError::ResetRequired) => {
            BlockTransportStatus::ResetRequired
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_block::BlockDeviceId;

    fn geometry() -> BlockGeometry {
        BlockGeometry::new(BlockDeviceId::new(1), 512, 8, 4, false).unwrap()
    }

    fn request(
        operation: BlockTransportOp,
        lba: u64,
        blocks: u32,
        buffer_len: u32,
    ) -> BlockTransportRequest {
        BlockTransportRequest {
            request_id: 7,
            device_id: 1,
            operation,
            lba,
            blocks,
            buffer_len,
        }
    }

    #[test]
    fn classifies_device_operations() {
        let read = request(BlockTransportOp::Read, 2, 1, 512);
        assert_eq!(
            classify_block_request(&read, geometry(), 512),
            BlockRequestAction::Read
        );
        let write = request(BlockTransportOp::Write, 2, 1, 512);
        assert_eq!(
            classify_block_request(&write, geometry(), 512),
            BlockRequestAction::Write
        );
        let flush = request(BlockTransportOp::Flush, 0, 0, 0);
        assert_eq!(
            classify_block_request(&flush, geometry(), 0),
            BlockRequestAction::Flush
        );
        let geometry_request = BlockTransportRequest::geometry(1, 1);
        assert_eq!(
            classify_block_request(&geometry_request, geometry(), 0),
            BlockRequestAction::Respond(BlockTransportStatus::Ok)
        );
    }

    #[test]
    fn rejects_wrong_device_and_length_mismatch() {
        let mut wrong_device = request(BlockTransportOp::Read, 0, 1, 512);
        wrong_device.device_id = 9;
        assert_eq!(
            classify_block_request(&wrong_device, geometry(), 512),
            BlockRequestAction::Respond(BlockTransportStatus::InvalidRequest)
        );
        let short_payload = request(BlockTransportOp::Write, 0, 1, 512);
        assert_eq!(
            classify_block_request(&short_payload, geometry(), 256),
            BlockRequestAction::Respond(BlockTransportStatus::InvalidRequest)
        );
        let oversized = request(BlockTransportOp::Read, 0, 16, 8192);
        assert_eq!(
            classify_block_request(&oversized, geometry(), 8192),
            BlockRequestAction::Respond(BlockTransportStatus::InvalidRequest)
        );
    }

    #[test]
    fn rejects_flush_and_geometry_with_arguments() {
        let flush = request(BlockTransportOp::Flush, 1, 0, 0);
        assert_eq!(
            classify_block_request(&flush, geometry(), 0),
            BlockRequestAction::Respond(BlockTransportStatus::InvalidRequest)
        );
        let geometry_request = request(BlockTransportOp::Geometry, 0, 1, 0);
        assert_eq!(
            classify_block_request(&geometry_request, geometry(), 0),
            BlockRequestAction::Respond(BlockTransportStatus::InvalidRequest)
        );
    }

    #[test]
    fn malformed_request_does_not_decode() {
        let mut wire = BlockTransportRequest::geometry(1, 1).encode();
        wire[0] = 0;
        assert_eq!(
            BlockTransportRequest::decode(&wire),
            Err(BlockTransportDecodeError::BadMagic)
        );
        assert_eq!(
            invalid_protocol_response().status,
            BlockTransportStatus::InvalidProtocol
        );
    }

    #[test]
    fn transport_errors_map_to_statuses() {
        assert_eq!(
            block_io_status(BlockIoError::Transport(BlockTransportError::ResetRequired)),
            BlockTransportStatus::ResetRequired
        );
        assert_eq!(
            block_io_status(BlockIoError::Unsupported(
                BlockUnsupportedError::WriteProtected
            )),
            BlockTransportStatus::Unsupported
        );
    }
}
