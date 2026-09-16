use crate::sync::global_cell::GlobalCell;
use clean_slate_block::{BlockDevice, BlockDeviceId, BlockGeometry, BlockIoError};
use clean_slate_service_fixtures::{
    handle_block_request, BLOCK_TRANSPORT_REQUEST_BYTES, BLOCK_TRANSPORT_RESPONSE_BYTES,
    STORAGE_BLOCK_DEVICE_ID,
};

const KERNEL_BLOCK_SIZE: u32 = 512;
const KERNEL_BLOCK_COUNT: u64 = 8;
const KERNEL_MAX_TRANSFER_BLOCKS: u32 = 4;
const KERNEL_BLOCK_CAPACITY_BYTES: usize =
    (KERNEL_BLOCK_SIZE as usize) * (KERNEL_BLOCK_COUNT as usize);

#[derive(Clone, Copy)]
struct KernelBlockBackend {
    live_bytes: [u8; KERNEL_BLOCK_CAPACITY_BYTES],
    durable_bytes: [u8; KERNEL_BLOCK_CAPACITY_BYTES],
    flush_count: u64,
}

impl KernelBlockBackend {
    const fn new() -> Self {
        Self {
            live_bytes: [0; KERNEL_BLOCK_CAPACITY_BYTES],
            durable_bytes: [0; KERNEL_BLOCK_CAPACITY_BYTES],
            flush_count: 0,
        }
    }
}

impl BlockDevice for KernelBlockBackend {
    fn geometry(&self) -> BlockGeometry {
        BlockGeometry::new(
            BlockDeviceId::new(STORAGE_BLOCK_DEVICE_ID),
            KERNEL_BLOCK_SIZE,
            KERNEL_BLOCK_COUNT,
            KERNEL_MAX_TRANSFER_BLOCKS,
            false,
        )
        .expect("static kernel block geometry must be valid")
    }

    fn read_blocks(
        &mut self,
        lba: u64,
        blocks: u32,
        buffer: &mut [u8],
    ) -> Result<(), BlockIoError> {
        let range = self.geometry().validate_read(lba, blocks, buffer.len())?;
        buffer.copy_from_slice(&self.live_bytes[range]);
        Ok(())
    }

    fn write_blocks(&mut self, lba: u64, blocks: u32, buffer: &[u8]) -> Result<(), BlockIoError> {
        let range = self.geometry().validate_write(lba, blocks, buffer.len())?;
        self.live_bytes[range].copy_from_slice(buffer);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BlockIoError> {
        self.durable_bytes.copy_from_slice(&self.live_bytes);
        self.flush_count = self.flush_count.saturating_add(1);
        Ok(())
    }
}

static BLOCK_BACKEND: GlobalCell<KernelBlockBackend> = GlobalCell::new(KernelBlockBackend::new());

pub(crate) fn handle_kernel_block_request(
    request: &[u8; BLOCK_TRANSPORT_REQUEST_BYTES],
    payload: &mut [u8],
) -> [u8; BLOCK_TRANSPORT_RESPONSE_BYTES] {
    let backend = unsafe { &mut *BLOCK_BACKEND.get() };
    handle_block_request(backend, request, payload)
}
