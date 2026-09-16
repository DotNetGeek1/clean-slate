use alloc::vec;
use alloc::vec::Vec;

use crate::{BlockDevice, BlockGeometry, BlockGeometryError, BlockIoError};

/// Deterministic fixed-size in-memory backend for host tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeBlockDevice {
    geometry: BlockGeometry,
    live_bytes: Vec<u8>,
    durable_bytes: Vec<u8>,
    flush_count: u64,
}

impl FakeBlockDevice {
    pub fn new(geometry: BlockGeometry) -> Result<Self, BlockGeometryError> {
        let len = usize::try_from(geometry.capacity_bytes())
            .map_err(|_| BlockGeometryError::CapacityExceedsHostAddressSpace)?;

        Ok(Self {
            geometry,
            live_bytes: vec![0; len],
            durable_bytes: vec![0; len],
            flush_count: 0,
        })
    }

    pub fn flush_count(&self) -> u64 {
        self.flush_count
    }

    pub fn durable_bytes(&self) -> &[u8] {
        &self.durable_bytes
    }
}

impl BlockDevice for FakeBlockDevice {
    fn geometry(&self) -> BlockGeometry {
        self.geometry
    }

    fn read_blocks(&self, lba: u64, blocks: u32, buffer: &mut [u8]) -> Result<(), BlockIoError> {
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
