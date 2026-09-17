use alloc::vec;
use alloc::vec::Vec;

use crate::{BlockDevice, BlockGeometry, BlockIoError};

/// Deterministic fixed-size in-memory backend for host tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeBlockDevice {
    geometry: BlockGeometry,
    live_bytes: Vec<u8>,
    durable_bytes: Vec<u8>,
    flush_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeBlockDeviceError {
    CapacityExceedsHostAddressSpace,
    DurableBytesLengthMismatch { expected: usize, actual: usize },
}

impl FakeBlockDevice {
    pub fn new(geometry: BlockGeometry) -> Result<Self, FakeBlockDeviceError> {
        let len = usize::try_from(geometry.capacity_bytes())
            .map_err(|_| FakeBlockDeviceError::CapacityExceedsHostAddressSpace)?;

        Ok(Self {
            geometry,
            live_bytes: vec![0; len],
            durable_bytes: vec![0; len],
            flush_count: 0,
        })
    }

    pub fn from_durable_bytes(
        geometry: BlockGeometry,
        durable_bytes: &[u8],
    ) -> Result<Self, FakeBlockDeviceError> {
        let mut device = Self::new(geometry)?;
        if device.durable_bytes.len() != durable_bytes.len() {
            return Err(FakeBlockDeviceError::DurableBytesLengthMismatch {
                expected: device.durable_bytes.len(),
                actual: durable_bytes.len(),
            });
        }
        device.live_bytes.copy_from_slice(durable_bytes);
        device.durable_bytes.copy_from_slice(durable_bytes);
        Ok(device)
    }

    pub fn flush_count(&self) -> u64 {
        self.flush_count
    }

    pub fn durable_bytes(&self) -> &[u8] {
        &self.durable_bytes
    }

    pub fn durable_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.durable_bytes
    }

    pub fn persist_blocks(&mut self, lba: u64, blocks: u32) -> Result<(), BlockIoError> {
        let block_size =
            usize::try_from(self.geometry.logical_block_size()).expect("block size fits usize");
        let byte_len = usize::try_from(blocks)
            .expect("block count fits usize")
            .checked_mul(block_size)
            .expect("validated device byte length fits usize");
        let range = self.geometry.validate_read(lba, blocks, byte_len)?;
        self.durable_bytes[range.clone()].copy_from_slice(&self.live_bytes[range]);
        Ok(())
    }

    /// Model a reboot: live state is discarded and reloaded from the durable
    /// image, so anything written but not yet flushed is lost.
    pub fn rebooted(&self) -> Result<Self, FakeBlockDeviceError> {
        Self::from_durable_bytes(self.geometry, &self.durable_bytes)
    }
}

impl BlockDevice for FakeBlockDevice {
    fn geometry(&self) -> BlockGeometry {
        self.geometry
    }

    fn read_blocks(
        &mut self,
        lba: u64,
        blocks: u32,
        buffer: &mut [u8],
    ) -> Result<(), BlockIoError> {
        let range = self.geometry.validate_read(lba, blocks, buffer.len())?;
        buffer.copy_from_slice(&self.live_bytes[range]);
        Ok(())
    }

    fn write_blocks(&mut self, lba: u64, blocks: u32, buffer: &[u8]) -> Result<(), BlockIoError> {
        let range = self.geometry.validate_write(lba, blocks, buffer.len())?;
        self.live_bytes[range].copy_from_slice(buffer);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BlockIoError> {
        self.durable_bytes.copy_from_slice(&self.live_bytes);
        self.flush_count += 1;
        Ok(())
    }
}
