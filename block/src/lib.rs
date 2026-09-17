//! Shared M5 block I/O contract.
//!
//! This contract is intentionally transport-independent so persistent-store code
//! can be host-tested without importing kernel, PCI, or VirtIO queue types.
//! M5 exposes only synchronous calls. If a later layer adds asynchronous
//! submission/completion plumbing, it must introduce request IDs above this
//! contract instead of leaking transport structures into store code.

#![cfg_attr(not(test), no_std)]

#[cfg(any(test, feature = "alloc"))]
extern crate alloc;

use core::ops::Range;

#[cfg(any(test, feature = "alloc"))]
pub mod fake;
#[cfg(any(test, feature = "alloc"))]
pub mod fault;

/// Stable logical identity for a single boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlockDeviceId(u64);

impl BlockDeviceId {
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Transport-independent geometry and transfer limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockGeometry {
    device_id: BlockDeviceId,
    logical_block_size: u32,
    block_count: u64,
    max_transfer_blocks: u32,
    read_only: bool,
    capacity_bytes: u64,
}

impl BlockGeometry {
    pub fn new(
        device_id: BlockDeviceId,
        logical_block_size: u32,
        block_count: u64,
        max_transfer_blocks: u32,
        read_only: bool,
    ) -> Result<Self, BlockGeometryError> {
        if logical_block_size == 0 {
            return Err(BlockGeometryError::ZeroBlockSize);
        }
        if block_count == 0 {
            return Err(BlockGeometryError::ZeroBlockCount);
        }
        if max_transfer_blocks == 0 {
            return Err(BlockGeometryError::ZeroMaxTransferBlocks);
        }

        let capacity_bytes = u64::from(logical_block_size)
            .checked_mul(block_count)
            .ok_or(BlockGeometryError::CapacityOverflow)?;

        Ok(Self {
            device_id,
            logical_block_size,
            block_count,
            max_transfer_blocks,
            read_only,
            capacity_bytes,
        })
    }

    pub const fn device_id(self) -> BlockDeviceId {
        self.device_id
    }

    pub const fn logical_block_size(self) -> u32 {
        self.logical_block_size
    }

    pub const fn block_count(self) -> u64 {
        self.block_count
    }

    pub const fn max_transfer_blocks(self) -> u32 {
        self.max_transfer_blocks
    }

    pub const fn capacity_bytes(self) -> u64 {
        self.capacity_bytes
    }

    pub const fn is_read_only(self) -> bool {
        self.read_only
    }

    /// Validates a bounded aligned read request.
    ///
    /// Deterministic validation order is: zero blocks, transfer bound,
    /// buffer alignment, exact buffer length, then device range.
    pub fn validate_read(
        &self,
        lba: u64,
        blocks: u32,
        buffer_len: usize,
    ) -> Result<Range<usize>, BlockIoError> {
        self.validate_transfer(lba, blocks, buffer_len, false)
    }

    /// Validates a bounded aligned write request.
    ///
    /// Deterministic validation order is: zero blocks, transfer bound,
    /// buffer alignment, exact buffer length, device range, then read-only
    /// rejection for otherwise valid writes.
    pub fn validate_write(
        &self,
        lba: u64,
        blocks: u32,
        buffer_len: usize,
    ) -> Result<Range<usize>, BlockIoError> {
        self.validate_transfer(lba, blocks, buffer_len, true)
    }

    fn validate_transfer(
        &self,
        lba: u64,
        blocks: u32,
        buffer_len: usize,
        is_write: bool,
    ) -> Result<Range<usize>, BlockIoError> {
        let request_error = |error| Err(BlockIoError::InvalidRequest(error));

        if blocks == 0 {
            return request_error(BlockRequestError::ZeroBlocks);
        }
        if blocks > self.max_transfer_blocks {
            return request_error(BlockRequestError::TransferTooLarge {
                requested_blocks: blocks,
                max_blocks: self.max_transfer_blocks,
            });
        }

        let block_size = usize::try_from(self.logical_block_size)
            .map_err(|_| BlockIoError::InvalidRequest(BlockRequestError::BufferLengthOverflow))?;
        if buffer_len % block_size != 0 {
            return request_error(BlockRequestError::BufferLengthNotAligned {
                buffer_len,
                block_size: self.logical_block_size,
            });
        }

        let expected_len = block_size
            .checked_mul(usize::try_from(blocks).map_err(|_| {
                BlockIoError::InvalidRequest(BlockRequestError::BufferLengthOverflow)
            })?)
            .ok_or(BlockIoError::InvalidRequest(
                BlockRequestError::BufferLengthOverflow,
            ))?;
        if buffer_len != expected_len {
            return request_error(BlockRequestError::BufferLengthMismatch {
                buffer_len,
                expected_len,
            });
        }

        let end_lba = lba
            .checked_add(u64::from(blocks))
            .ok_or(BlockIoError::InvalidRequest(
                BlockRequestError::RangeOutOfBounds {
                    lba,
                    blocks,
                    block_count: self.block_count,
                },
            ))?;
        if end_lba > self.block_count {
            return request_error(BlockRequestError::RangeOutOfBounds {
                lba,
                blocks,
                block_count: self.block_count,
            });
        }

        if is_write && self.read_only {
            return Err(BlockIoError::Unsupported(
                BlockUnsupportedError::WriteProtected,
            ));
        }

        let byte_start =
            usize::try_from(lba.checked_mul(u64::from(self.logical_block_size)).ok_or(
                BlockIoError::InvalidRequest(BlockRequestError::BufferLengthOverflow),
            )?)
            .map_err(|_| BlockIoError::InvalidRequest(BlockRequestError::BufferLengthOverflow))?;
        let byte_end = byte_start
            .checked_add(expected_len)
            .ok_or(BlockIoError::InvalidRequest(
                BlockRequestError::BufferLengthOverflow,
            ))?;

        Ok(byte_start..byte_end)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockGeometryError {
    ZeroBlockSize,
    ZeroBlockCount,
    ZeroMaxTransferBlocks,
    CapacityOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockIoError {
    InvalidRequest(BlockRequestError),
    Unsupported(BlockUnsupportedError),
    Transport(BlockTransportError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockRequestError {
    ZeroBlocks,
    TransferTooLarge {
        requested_blocks: u32,
        max_blocks: u32,
    },
    BufferLengthNotAligned {
        buffer_len: usize,
        block_size: u32,
    },
    BufferLengthMismatch {
        buffer_len: usize,
        expected_len: usize,
    },
    RangeOutOfBounds {
        lba: u64,
        blocks: u32,
        block_count: u64,
    },
    BufferLengthOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockUnsupportedError {
    WriteProtected,
    FlushUnsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockTransportError {
    DeviceFault,
    Timeout,
    ResetRequired,
}

/// Synchronous block device contract shared by kernel bring-up and host tests.
///
/// Even read requests take `&mut self`: real transports may consume and recycle
/// descriptors, advance completion state, or update reset/error bookkeeping
/// while servicing a read. The shared contract keeps that exclusive transport
/// ownership explicit instead of forcing interior mutability into backends.
///
/// Implementations may borrow caller buffers only for the duration of a call
/// and must not retain raw pointers or references after returning.
///
/// Successful `write_blocks` makes the new bytes visible to subsequent
/// `read_blocks` calls through the same device instance, but durability is not
/// guaranteed until `flush` returns `Ok(())`.
///
/// Successful `flush` is the M5 durability barrier: every earlier successful
/// write on this device must survive the backend's reboot/crash model once the
/// call returns. A failed flush provides no new durability guarantee.
pub trait BlockDevice {
    fn geometry(&self) -> BlockGeometry;

    fn read_blocks(&mut self, lba: u64, blocks: u32, buffer: &mut [u8])
        -> Result<(), BlockIoError>;

    fn write_blocks(&mut self, lba: u64, blocks: u32, buffer: &[u8]) -> Result<(), BlockIoError>;

    fn flush(&mut self) -> Result<(), BlockIoError>;
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::fake::FakeBlockDevice;
    use super::*;

    fn geometry() -> BlockGeometry {
        BlockGeometry::new(BlockDeviceId::new(7), 512, 8, 4, false).unwrap()
    }

    #[test]
    fn geometry_reports_capacity() {
        let geometry = geometry();

        assert_eq!(geometry.device_id(), BlockDeviceId::new(7));
        assert_eq!(geometry.logical_block_size(), 512);
        assert_eq!(geometry.block_count(), 8);
        assert_eq!(geometry.max_transfer_blocks(), 4);
        assert_eq!(geometry.capacity_bytes(), 4096);
        assert!(!geometry.is_read_only());
    }

    #[test]
    fn validation_errors_are_deterministic() {
        let geometry = geometry();

        assert_eq!(
            geometry.validate_read(0, 0, 0),
            Err(BlockIoError::InvalidRequest(BlockRequestError::ZeroBlocks))
        );
        assert_eq!(
            geometry.validate_read(0, 5, 5 * 512),
            Err(BlockIoError::InvalidRequest(
                BlockRequestError::TransferTooLarge {
                    requested_blocks: 5,
                    max_blocks: 4,
                }
            ))
        );
        assert_eq!(
            geometry.validate_read(0, 1, 1),
            Err(BlockIoError::InvalidRequest(
                BlockRequestError::BufferLengthNotAligned {
                    buffer_len: 1,
                    block_size: 512,
                }
            ))
        );
        assert_eq!(
            geometry.validate_read(0, 1, 1024),
            Err(BlockIoError::InvalidRequest(
                BlockRequestError::BufferLengthMismatch {
                    buffer_len: 1024,
                    expected_len: 512,
                }
            ))
        );
        assert_eq!(
            geometry.validate_read(8, 1, 512),
            Err(BlockIoError::InvalidRequest(
                BlockRequestError::RangeOutOfBounds {
                    lba: 8,
                    blocks: 1,
                    block_count: 8,
                }
            ))
        );
    }

    #[test]
    fn fake_backend_supports_read_after_write_and_flush_observation() {
        let mut device = FakeBlockDevice::new(geometry()).unwrap();
        let write = vec![0x5a; 512];
        let mut read = vec![0; 512];

        device.write_blocks(2, 1, &write).unwrap();
        device.read_blocks(2, 1, &mut read).unwrap();

        assert_eq!(read, write);
        assert_eq!(device.flush_count(), 0);
        assert!(device.durable_bytes().iter().all(|byte| *byte == 0));

        device.flush().unwrap();

        assert_eq!(device.flush_count(), 1);
        assert_eq!(&device.durable_bytes()[1024..1536], &write[..]);
    }

    #[test]
    fn fake_backend_rejects_writes_to_read_only_geometry() {
        let geometry = BlockGeometry::new(BlockDeviceId::new(9), 512, 8, 4, true).unwrap();
        let mut device = FakeBlockDevice::new(geometry).unwrap();
        let write = vec![0xaa; 512];

        assert_eq!(
            device.write_blocks(0, 1, &write),
            Err(BlockIoError::Unsupported(
                BlockUnsupportedError::WriteProtected,
            ))
        );
    }
}
