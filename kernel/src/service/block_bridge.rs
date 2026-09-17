use crate::device::virtio::block::VirtioBlockDevice;
use crate::diagnostics::log::kernel_log_fmt;
use crate::sync::global_cell::GlobalCell;
use clean_slate_block::{
    BlockDevice, BlockDeviceId, BlockGeometry, BlockIoError, BlockTransportError,
};
use clean_slate_service_fixtures::{
    handle_block_request, BlockTransportDecodeError, BlockTransportOp, BlockTransportRequest,
    BlockTransportResponse, BlockTransportStatus, BLOCK_TRANSPORT_REQUEST_BYTES,
    BLOCK_TRANSPORT_RESPONSE_BYTES, STORAGE_BLOCK_DEVICE_ID,
};

const KERNEL_BLOCK_SIZE: u32 = 512;
const KERNEL_BLOCK_COUNT: u64 = 8;
const KERNEL_MAX_TRANSFER_BLOCKS: u32 = 4;

struct KernelBlockBackend {
    transport_initialized: bool,
    transport_faulted: bool,
    virtio: Option<VirtioBlockDevice>,
}

impl KernelBlockBackend {
    const fn new() -> Self {
        Self {
            transport_initialized: false,
            transport_faulted: false,
            virtio: None,
        }
    }

    fn ensure_transport(&mut self) {
        if self.transport_initialized {
            return;
        }
        self.transport_initialized = true;
        match VirtioBlockDevice::discover() {
            Ok(device) => {
                let geometry = device.geometry();
                kernel_log_fmt(format_args!(
                    "[BLK ] virtio-block ready blocks={} block-size={}\n",
                    geometry.block_count(),
                    geometry.logical_block_size()
                ));
                self.virtio = Some(device);
            }
            Err(message) => {
                self.transport_faulted = true;
                kernel_log_fmt(format_args!(
                    "[FAIL] virtio block discovery failed: {message}\n"
                ));
            }
        }
    }
}

impl BlockDevice for KernelBlockBackend {
    fn geometry(&self) -> BlockGeometry {
        if let Some(device) = self.virtio.as_ref() {
            return publish_contract_geometry(device.geometry());
        }
        contract_geometry_fallback()
    }

    fn read_blocks(
        &mut self,
        lba: u64,
        blocks: u32,
        buffer: &mut [u8],
    ) -> Result<(), BlockIoError> {
        self.ensure_transport();
        match self.virtio.as_mut() {
            Some(device) => device.read_blocks(lba, blocks, buffer),
            None => Err(BlockIoError::Transport(BlockTransportError::DeviceFault)),
        }
    }

    fn write_blocks(&mut self, lba: u64, blocks: u32, buffer: &[u8]) -> Result<(), BlockIoError> {
        self.ensure_transport();
        match self.virtio.as_mut() {
            Some(device) => device.write_blocks(lba, blocks, buffer),
            None => Err(BlockIoError::Transport(BlockTransportError::DeviceFault)),
        }
    }

    fn flush(&mut self) -> Result<(), BlockIoError> {
        self.ensure_transport();
        match self.virtio.as_mut() {
            Some(device) => device.flush(),
            None => Err(BlockIoError::Transport(BlockTransportError::DeviceFault)),
        }
    }
}

static BLOCK_BACKEND: GlobalCell<KernelBlockBackend> = GlobalCell::new(KernelBlockBackend::new());

pub(crate) fn handle_kernel_block_request(
    request: &[u8; BLOCK_TRANSPORT_REQUEST_BYTES],
    payload: &mut [u8],
) -> [u8; BLOCK_TRANSPORT_RESPONSE_BYTES] {
    let backend = unsafe { &mut *BLOCK_BACKEND.get() };
    backend.ensure_transport();
    if backend.transport_faulted {
        let decoded = BlockTransportRequest::decode(request);
        return transport_fault_response(decoded);
    }
    handle_block_request(backend, request, payload)
}

fn transport_fault_response(
    request: Result<BlockTransportRequest, BlockTransportDecodeError>,
) -> [u8; BLOCK_TRANSPORT_RESPONSE_BYTES] {
    let geometry = contract_geometry_fallback();
    let response = match request {
        Ok(request) => BlockTransportResponse {
            request_id: request.request_id,
            device_id: request.device_id,
            operation: request.operation,
            status: BlockTransportStatus::DeviceFault,
            logical_block_size: geometry.logical_block_size(),
            block_count: geometry.block_count(),
            max_transfer_blocks: geometry.max_transfer_blocks(),
        },
        Err(_) => BlockTransportResponse {
            request_id: 0,
            device_id: 0,
            operation: BlockTransportOp::Geometry,
            status: BlockTransportStatus::InvalidProtocol,
            logical_block_size: 0,
            block_count: 0,
            max_transfer_blocks: 0,
        },
    };
    response.encode()
}

fn contract_geometry_fallback() -> BlockGeometry {
    BlockGeometry::new(
        BlockDeviceId::new(STORAGE_BLOCK_DEVICE_ID),
        KERNEL_BLOCK_SIZE,
        KERNEL_BLOCK_COUNT,
        KERNEL_MAX_TRANSFER_BLOCKS,
        false,
    )
    .expect("fallback geometry must be valid")
}

fn publish_contract_geometry(transport_geometry: BlockGeometry) -> BlockGeometry {
    BlockGeometry::new(
        BlockDeviceId::new(STORAGE_BLOCK_DEVICE_ID),
        transport_geometry.logical_block_size(),
        transport_geometry.block_count(),
        transport_geometry.max_transfer_blocks(),
        transport_geometry.is_read_only(),
    )
    .expect("virtio geometry should stay valid when published with contract device id")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_fault_response_marks_device_fault_for_valid_request() {
        let request = BlockTransportRequest::decode(
            &BlockTransportRequest::geometry(7, STORAGE_BLOCK_DEVICE_ID).encode(),
        );
        let response = transport_fault_response(request);
        let decoded = BlockTransportResponse::decode(&response).expect("decode");
        assert_eq!(decoded.request_id, 7);
        assert_eq!(decoded.device_id, STORAGE_BLOCK_DEVICE_ID);
        assert_eq!(decoded.operation, BlockTransportOp::Geometry);
        assert_eq!(decoded.status, BlockTransportStatus::DeviceFault);
    }

    #[test]
    fn transport_fault_response_marks_invalid_protocol_for_malformed_request() {
        let mut request_wire = BlockTransportRequest::geometry(9, STORAGE_BLOCK_DEVICE_ID).encode();
        request_wire[0] = 0;
        let request = BlockTransportRequest::decode(&request_wire);
        let response = transport_fault_response(request);
        let decoded = BlockTransportResponse::decode(&response).expect("decode");
        assert_eq!(decoded.status, BlockTransportStatus::InvalidProtocol);
        assert_eq!(decoded.request_id, 0);
    }
}
