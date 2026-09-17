#[cfg(feature = "m5-storage-self-test")]
use crate::device::virtio::block::VirtioBlockDevice;
#[cfg(feature = "m5-storage-self-test")]
use crate::diagnostics::log::kernel_log_fmt;
use crate::sync::global_cell::GlobalCell;
use clean_slate_block::BlockTransportError;
use clean_slate_block::{BlockDevice, BlockDeviceId, BlockGeometry, BlockIoError};
use clean_slate_service_fixtures::{
    handle_block_request, BLOCK_TRANSPORT_REQUEST_BYTES, BLOCK_TRANSPORT_RESPONSE_BYTES,
    STORAGE_BLOCK_DEVICE_ID,
};

#[cfg(not(feature = "m5-storage-self-test"))]
const KERNEL_BLOCK_SIZE: u32 = 512;
#[cfg(not(feature = "m5-storage-self-test"))]
const KERNEL_BLOCK_COUNT: u64 = 8;
#[cfg(not(feature = "m5-storage-self-test"))]
const KERNEL_MAX_TRANSFER_BLOCKS: u32 = 4;
#[cfg(not(feature = "m5-storage-self-test"))]
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

    fn transport_error(&self) -> BlockIoError {
        if self.transport_faulted {
            BlockIoError::Transport(BlockTransportError::DeviceFault)
        } else {
            BlockIoError::Transport(BlockTransportError::ResetRequired)
        }
    }
}

impl BlockDevice for KernelBlockBackend {
    fn geometry(&self) -> BlockGeometry {
        #[cfg(feature = "m5-storage-self-test")]
        {
            if let Some(device) = self.virtio.as_ref() {
                return device.geometry();
            }
            BlockGeometry::new(
                BlockDeviceId::new(STORAGE_BLOCK_DEVICE_ID),
                512,
                8,
                4,
                false,
            )
            .expect("fallback geometry must be valid")
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
            return Err(self.transport_error());
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
            return Err(self.transport_error());
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
            return Err(self.transport_error());
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
    handle_block_request(backend, request, payload)
}
