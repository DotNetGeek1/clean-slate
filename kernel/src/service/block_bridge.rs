#[cfg(feature = "m5-storage-self-test")]
use crate::device::virtio::block::VirtioBlockDevice;
#[cfg(feature = "m5-storage-self-test")]
use crate::diagnostics::log::kernel_log_fmt;
use crate::sync::global_cell::GlobalCell;
#[cfg(feature = "m5-storage-self-test")]
use clean_slate_block::BlockTransportError;
use clean_slate_block::{BlockDevice, BlockDeviceId, BlockGeometry, BlockIoError};
use clean_slate_service_fixtures::{
    handle_block_request, BlockTransportOp, BlockTransportRequest, BlockTransportResponse,
    BlockTransportStatus, BLOCK_TRANSPORT_REQUEST_BYTES, BLOCK_TRANSPORT_RESPONSE_BYTES,
    STORAGE_BLOCK_DEVICE_ID,
};

const KERNEL_BLOCK_SIZE: u32 = 512;
const KERNEL_BLOCK_COUNT: u64 = 8;
const KERNEL_MAX_TRANSFER_BLOCKS: u32 = 4;
const KERNEL_BLOCK_CAPACITY_BYTES: usize =
    (KERNEL_BLOCK_SIZE as usize) * (KERNEL_BLOCK_COUNT as usize);

struct KernelBlockBackend {
    #[cfg(not(feature = "m5-storage-self-test"))]
    live_bytes: [u8; KERNEL_BLOCK_CAPACITY_BYTES],
    #[cfg(not(feature = "m5-storage-self-test"))]
    durable_bytes: [u8; KERNEL_BLOCK_CAPACITY_BYTES],
    #[cfg(not(feature = "m5-storage-self-test"))]
    flush_count: u64,
    transport_initialized: bool,
    transport_faulted: bool,
    #[cfg(feature = "m5-storage-self-test")]
    virtio: Option<VirtioBlockDevice>,
}

impl KernelBlockBackend {
    const fn new() -> Self {
        Self {
            #[cfg(not(feature = "m5-storage-self-test"))]
            live_bytes: [0; KERNEL_BLOCK_CAPACITY_BYTES],
            #[cfg(not(feature = "m5-storage-self-test"))]
            durable_bytes: [0; KERNEL_BLOCK_CAPACITY_BYTES],
            #[cfg(not(feature = "m5-storage-self-test"))]
            flush_count: 0,
            transport_initialized: false,
            transport_faulted: false,
            #[cfg(feature = "m5-storage-self-test")]
            virtio: None,
        }
    }

    fn ensure_transport(&mut self) {
        if self.transport_initialized {
            return;
        }
        self.transport_initialized = true;
        #[cfg(feature = "m5-storage-self-test")]
        {
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

    fn transport_faulted(&self) -> bool {
        self.transport_faulted
    }
}

impl BlockDevice for KernelBlockBackend {
    fn geometry(&self) -> BlockGeometry {
        #[cfg(feature = "m5-storage-self-test")]
        {
            if let Some(device) = self.virtio.as_ref() {
                return publish_contract_geometry(device.geometry());
            }
            contract_geometry_fallback()
        }
        #[cfg(not(feature = "m5-storage-self-test"))]
        {
            BlockGeometry::new(
                BlockDeviceId::new(STORAGE_BLOCK_DEVICE_ID),
                KERNEL_BLOCK_SIZE,
                KERNEL_BLOCK_COUNT,
                KERNEL_MAX_TRANSFER_BLOCKS,
                false,
            )
            .expect("static kernel block geometry must be valid")
        }
    }

    fn read_blocks(
        &mut self,
        lba: u64,
        blocks: u32,
        buffer: &mut [u8],
    ) -> Result<(), BlockIoError> {
        self.ensure_transport();
        #[cfg(feature = "m5-storage-self-test")]
        {
            if let Some(device) = self.virtio.as_mut() {
                return device.read_blocks(lba, blocks, buffer);
            }
            return Err(BlockIoError::Transport(BlockTransportError::DeviceFault));
        }
        #[cfg(not(feature = "m5-storage-self-test"))]
        let range = self.geometry().validate_read(lba, blocks, buffer.len())?;
        #[cfg(not(feature = "m5-storage-self-test"))]
        buffer.copy_from_slice(&self.live_bytes[range]);
        #[cfg(not(feature = "m5-storage-self-test"))]
        Ok(())
    }

    fn write_blocks(&mut self, lba: u64, blocks: u32, buffer: &[u8]) -> Result<(), BlockIoError> {
        self.ensure_transport();
        #[cfg(feature = "m5-storage-self-test")]
        {
            if let Some(device) = self.virtio.as_mut() {
                return device.write_blocks(lba, blocks, buffer);
            }
            return Err(BlockIoError::Transport(BlockTransportError::DeviceFault));
        }
        #[cfg(not(feature = "m5-storage-self-test"))]
        let range = self.geometry().validate_write(lba, blocks, buffer.len())?;
        #[cfg(not(feature = "m5-storage-self-test"))]
        self.live_bytes[range].copy_from_slice(buffer);
        #[cfg(not(feature = "m5-storage-self-test"))]
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BlockIoError> {
        self.ensure_transport();
        #[cfg(feature = "m5-storage-self-test")]
        {
            if let Some(device) = self.virtio.as_mut() {
                return device.flush();
            }
            return Err(BlockIoError::Transport(BlockTransportError::DeviceFault));
        }
        #[cfg(not(feature = "m5-storage-self-test"))]
        {
            self.durable_bytes.copy_from_slice(&self.live_bytes);
            self.flush_count = self.flush_count.saturating_add(1);
            Ok(())
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
    if backend.transport_faulted() {
        let decoded = BlockTransportRequest::decode(request);
        return transport_fault_response(decoded);
    }
    handle_block_request(backend, request, payload)
}

fn transport_fault_response(
    request: Result<BlockTransportRequest, clean_slate_service_fixtures::BlockTransportDecodeError>,
) -> [u8; BLOCK_TRANSPORT_RESPONSE_BYTES] {
    let contract_geometry = contract_geometry_fallback();
    let response = match request {
        Ok(request) => BlockTransportResponse {
            request_id: request.request_id,
            device_id: request.device_id,
            operation: request.operation,
            status: BlockTransportStatus::DeviceFault,
            logical_block_size: contract_geometry.logical_block_size(),
            block_count: contract_geometry.block_count(),
            max_transfer_blocks: contract_geometry.max_transfer_blocks(),
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

    #[test]
    fn transport_fault_response_marks_invalid_protocol_for_invalid_operation() {
        let mut request_wire =
            BlockTransportRequest::geometry(10, STORAGE_BLOCK_DEVICE_ID).encode();
        request_wire[6] = 99;
        let request = BlockTransportRequest::decode(&request_wire);
        let response = transport_fault_response(request);
        let decoded = BlockTransportResponse::decode(&response).expect("decode");
        assert_eq!(decoded.status, BlockTransportStatus::InvalidProtocol);
    }
}

#[cfg(feature = "m5-storage-self-test")]
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
