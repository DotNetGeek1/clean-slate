//! Bounded M5 block request/response transport shared by userspace service and kernel adapter.

use clean_slate_block::{
    BlockDevice, BlockIoError, BlockRequestError, BlockTransportError, BlockUnsupportedError,
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

pub fn handle_block_request<B: BlockDevice>(
    backend: &mut B,
    request: &[u8; BLOCK_TRANSPORT_REQUEST_BYTES],
    payload: &mut [u8],
) -> [u8; BLOCK_TRANSPORT_RESPONSE_BYTES] {
    let decoded = match BlockTransportRequest::decode(request) {
        Ok(request) => request,
        Err(_) => {
            return BlockTransportResponse {
                request_id: 0,
                device_id: 0,
                operation: BlockTransportOp::Geometry,
                status: BlockTransportStatus::InvalidProtocol,
                logical_block_size: 0,
                block_count: 0,
                max_transfer_blocks: 0,
            }
            .encode();
        }
    };
    let geometry = backend.geometry();
    let mut response = BlockTransportResponse {
        request_id: decoded.request_id,
        device_id: decoded.device_id,
        operation: decoded.operation,
        status: BlockTransportStatus::Ok,
        logical_block_size: geometry.logical_block_size(),
        block_count: geometry.block_count(),
        max_transfer_blocks: geometry.max_transfer_blocks(),
    };
    if decoded.device_id != geometry.device_id().get() {
        response.status = BlockTransportStatus::InvalidRequest;
        return response.encode();
    }
    let request_len = usize::try_from(decoded.buffer_len).unwrap_or(usize::MAX);
    if request_len > BLOCK_TRANSPORT_MAX_PAYLOAD_BYTES || request_len != payload.len() {
        response.status = BlockTransportStatus::InvalidRequest;
        return response.encode();
    }
    let result = match decoded.operation {
        BlockTransportOp::Geometry => {
            if decoded.blocks != 0 || decoded.lba != 0 || decoded.buffer_len != 0 {
                response.status = BlockTransportStatus::InvalidRequest;
            }
            Ok(())
        }
        BlockTransportOp::Read => backend.read_blocks(decoded.lba, decoded.blocks, payload),
        BlockTransportOp::Write => backend.write_blocks(decoded.lba, decoded.blocks, payload),
        BlockTransportOp::Flush => {
            if decoded.blocks != 0 || decoded.lba != 0 || decoded.buffer_len != 0 {
                response.status = BlockTransportStatus::InvalidRequest;
                Ok(())
            } else {
                backend.flush()
            }
        }
    };
    if let Err(error) = result {
        response.status = map_status(error);
    }
    response.encode()
}

fn map_status(error: BlockIoError) -> BlockTransportStatus {
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
    use clean_slate_block::fake::FakeBlockDevice;
    use clean_slate_block::{BlockDeviceId, BlockGeometry};

    fn fake() -> FakeBlockDevice {
        FakeBlockDevice::new(BlockGeometry::new(BlockDeviceId::new(1), 512, 8, 4, false).unwrap())
            .unwrap()
    }

    #[test]
    fn transport_read_write_and_flush_round_trip() {
        let mut backend = fake();
        let write_request = BlockTransportRequest {
            request_id: 7,
            device_id: 1,
            operation: BlockTransportOp::Write,
            lba: 2,
            blocks: 1,
            buffer_len: 512,
        };
        let mut write_payload = [0x5a; 512];
        let write_response =
            handle_block_request(&mut backend, &write_request.encode(), &mut write_payload);
        let write = BlockTransportResponse::decode(&write_response).expect("decode write");
        assert_eq!(write.status, BlockTransportStatus::Ok);

        let flush_request = BlockTransportRequest {
            request_id: 8,
            device_id: 1,
            operation: BlockTransportOp::Flush,
            lba: 0,
            blocks: 0,
            buffer_len: 0,
        };
        let mut flush_payload = [];
        let flush_response =
            handle_block_request(&mut backend, &flush_request.encode(), &mut flush_payload);
        let flush = BlockTransportResponse::decode(&flush_response).expect("decode flush");
        assert_eq!(flush.status, BlockTransportStatus::Ok);
        assert_eq!(backend.flush_count(), 1);

        let read_request = BlockTransportRequest {
            request_id: 9,
            device_id: 1,
            operation: BlockTransportOp::Read,
            lba: 2,
            blocks: 1,
            buffer_len: 512,
        };
        let mut read_payload = [0u8; 512];
        let read_response =
            handle_block_request(&mut backend, &read_request.encode(), &mut read_payload);
        let read = BlockTransportResponse::decode(&read_response).expect("decode read");
        assert_eq!(read.status, BlockTransportStatus::Ok);
        assert_eq!(read_payload, [0x5a; 512]);
    }

    #[test]
    fn transport_reports_device_errors_for_bad_request() {
        let mut backend = fake();
        let request = BlockTransportRequest {
            request_id: 12,
            device_id: 9,
            operation: BlockTransportOp::Read,
            lba: 0,
            blocks: 1,
            buffer_len: 512,
        };
        let mut payload = [0u8; 512];
        let response = handle_block_request(&mut backend, &request.encode(), &mut payload);
        let decoded = BlockTransportResponse::decode(&response).expect("decode");
        assert_eq!(decoded.status, BlockTransportStatus::InvalidRequest);
    }

    #[test]
    fn transport_rejects_malformed_request() {
        let mut backend = fake();
        let mut request = BlockTransportRequest::geometry(1, 1).encode();
        request[0] = 0;
        let mut payload = [];
        let response = handle_block_request(&mut backend, &request, &mut payload);
        let decoded = BlockTransportResponse::decode(&response).expect("decode");
        assert_eq!(decoded.status, BlockTransportStatus::InvalidProtocol);
    }

    #[test]
    fn transport_rejects_invalid_bounds() {
        let mut backend = fake();
        let request = BlockTransportRequest {
            request_id: 15,
            device_id: 1,
            operation: BlockTransportOp::Read,
            lba: 8,
            blocks: 1,
            buffer_len: 512,
        };
        let mut payload = [0u8; 512];
        let response = handle_block_request(&mut backend, &request.encode(), &mut payload);
        let decoded = BlockTransportResponse::decode(&response).expect("decode");
        assert_eq!(decoded.status, BlockTransportStatus::InvalidRequest);
    }
}
