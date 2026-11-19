//! Fault-injecting block device for the store's crash-matrix tests.
//!
//! [`FaultDevice`] wraps a [`FakeBlockDevice`], which holds the live image
//! that reads see, and models a volatile write-back cache in front of a
//! separate durable image. A write lands in the live image and joins the
//! pending (unflushed) set; an honoured flush persists every pending write in
//! issue order. What survives a power loss is decided afterwards by a crash
//! plan ([`CrashStep`]), so one device state can be crashed many ways.
//!
//! Faults:
//! - power loss at a counted operation: that operation fails, a write in
//!   flight stays pending (so a plan can persist or tear it), and every later
//!   call fails;
//! - torn write: a plan persists only the first `bytes` bytes of a pending
//!   write, at any byte offset, leaving the rest of the old durable bytes;
//! - dropped flush: the flush reports success and persists nothing, so its
//!   writes stay pending;
//! - unflushed writes persisted in any subset and order at the crash point;
//! - bit flip in a stored sector;
//! - misdirected write: the write lands at another LBA, in both images.
//!
//! Every operation the device receives is recorded in an [`Op`] log.

use std::cell::RefCell;
use std::rc::Rc;

use clean_slate_block::fake::FakeBlockDevice;
use clean_slate_block::{BlockDevice, BlockGeometry, BlockIoError, BlockTransportError};

/// Faults armed before the device is handed to the code under test.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FaultConfig {
    /// 0-based index, over writes and flushes together, of the operation the
    /// power loss interrupts.
    pub power_loss_at_op: Option<usize>,
    /// 0-based flush ordinals that are acknowledged without persisting.
    pub dropped_flushes: Vec<usize>,
    /// (0-based write ordinal, LBA the write lands at instead).
    pub misdirected_writes: Vec<(usize, u64)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpKind {
    Write {
        /// Where the caller aimed the write.
        lba: u64,
        /// Where the device put it.
        landed_lba: u64,
        data: Vec<u8>,
    },
    Flush,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpOutcome {
    Completed,
    /// A flush acknowledged without persisting anything.
    Dropped,
    /// The operation the power loss interrupted. It returned an error.
    PowerLoss,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    pub kind: OpKind,
    pub outcome: OpOutcome,
}

/// A write that is in the live image but not yet in the durable one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingWrite {
    /// Index into the op log.
    pub op: usize,
    pub landed_lba: u64,
    pub data: Vec<u8>,
}

/// One step of a crash plan, applied in order to a copy of the durable image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashStep {
    /// Persist pending write `index` in full.
    Persist(usize),
    /// Persist only the first `bytes` bytes of pending write `index`.
    Tear { index: usize, bytes: usize },
    /// Flip bit `bit` (0 = least significant bit of the first byte) of the
    /// stored block at `lba`.
    FlipBit { lba: u64, bit: usize },
}

#[derive(Debug)]
struct State {
    live: FakeBlockDevice,
    durable: Vec<u8>,
    pending: Vec<PendingWrite>,
    log: Vec<Op>,
    config: FaultConfig,
    write_count: usize,
    flush_count: usize,
    powered_off: bool,
}

/// Cloning shares the device, so a test keeps a handle after the store under
/// test takes ownership (or drops it, as a failed `ObjectStore::format` does).
#[derive(Clone, Debug)]
pub struct FaultDevice {
    state: Rc<RefCell<State>>,
}

impl FaultDevice {
    pub fn new(geometry: BlockGeometry, config: FaultConfig) -> Self {
        let live = FakeBlockDevice::new(geometry).expect("host-sized test geometry");
        let durable = live.durable_bytes().to_vec();
        Self {
            state: Rc::new(RefCell::new(State {
                live,
                durable,
                pending: Vec::new(),
                log: Vec::new(),
                config,
                write_count: 0,
                flush_count: 0,
                powered_off: false,
            })),
        }
    }

    pub fn log(&self) -> Vec<Op> {
        self.state.borrow().log.clone()
    }

    pub fn pending(&self) -> Vec<PendingWrite> {
        self.state.borrow().pending.clone()
    }

    pub fn is_powered_off(&self) -> bool {
        self.state.borrow().powered_off
    }

    /// The bytes that survive a power loss in which no pending write persists.
    pub fn durable_image(&self) -> Vec<u8> {
        self.state.borrow().durable.clone()
    }

    /// The durable image after a power loss that applies `plan`.
    pub fn crash_image(&self, plan: &[CrashStep]) -> Vec<u8> {
        let state = self.state.borrow();
        let block_size = block_bytes(state.live.geometry());
        let mut image = state.durable.clone();
        for step in plan {
            match *step {
                CrashStep::Persist(index) => {
                    let write = &state.pending[index];
                    let start = lba_offset(write.landed_lba, block_size);
                    image[start..start + write.data.len()].copy_from_slice(&write.data);
                }
                CrashStep::Tear { index, bytes } => {
                    let write = &state.pending[index];
                    assert!(bytes <= write.data.len(), "tear past the end of the write");
                    let start = lba_offset(write.landed_lba, block_size);
                    image[start..start + bytes].copy_from_slice(&write.data[..bytes]);
                }
                CrashStep::FlipBit { lba, bit } => {
                    assert!(bit < block_size * 8, "bit outside the block");
                    image[lba_offset(lba, block_size) + bit / 8] ^= 1 << (bit % 8);
                }
            }
        }
        image
    }

    /// Count the operation about to run; `true` if the power loss interrupts it.
    fn begin_op(state: &mut State) -> Result<bool, BlockIoError> {
        if state.powered_off {
            return Err(power_loss_error());
        }
        let index = state.log.len();
        let interrupted = state.config.power_loss_at_op == Some(index);
        if interrupted {
            state.powered_off = true;
        }
        Ok(interrupted)
    }
}

impl BlockDevice for FaultDevice {
    fn geometry(&self) -> BlockGeometry {
        self.state.borrow().live.geometry()
    }

    fn read_blocks(
        &mut self,
        lba: u64,
        blocks: u32,
        buffer: &mut [u8],
    ) -> Result<(), BlockIoError> {
        let mut state = self.state.borrow_mut();
        if state.powered_off {
            return Err(power_loss_error());
        }
        state.live.read_blocks(lba, blocks, buffer)
    }

    fn write_blocks(&mut self, lba: u64, blocks: u32, buffer: &[u8]) -> Result<(), BlockIoError> {
        let mut state = self.state.borrow_mut();
        let geometry = state.live.geometry();
        geometry.validate_write(lba, blocks, buffer.len())?;
        let interrupted = Self::begin_op(&mut state)?;

        let ordinal = state.write_count;
        state.write_count += 1;
        let landed_lba = state
            .config
            .misdirected_writes
            .iter()
            .find(|(write, _)| *write == ordinal)
            .map_or(lba, |(_, target)| *target);
        geometry.validate_write(landed_lba, blocks, buffer.len())?;

        let op = state.log.len();
        state.log.push(Op {
            kind: OpKind::Write {
                lba,
                landed_lba,
                data: buffer.to_vec(),
            },
            outcome: if interrupted {
                OpOutcome::PowerLoss
            } else {
                OpOutcome::Completed
            },
        });
        state.pending.push(PendingWrite {
            op,
            landed_lba,
            data: buffer.to_vec(),
        });
        if interrupted {
            return Err(power_loss_error());
        }
        state.live.write_blocks(landed_lba, blocks, buffer)
    }

    fn flush(&mut self) -> Result<(), BlockIoError> {
        let mut state = self.state.borrow_mut();
        let interrupted = Self::begin_op(&mut state)?;

        let ordinal = state.flush_count;
        state.flush_count += 1;
        let dropped = state.config.dropped_flushes.contains(&ordinal);
        let outcome = if interrupted {
            OpOutcome::PowerLoss
        } else if dropped {
            OpOutcome::Dropped
        } else {
            OpOutcome::Completed
        };
        state.log.push(Op {
            kind: OpKind::Flush,
            outcome,
        });
        match outcome {
            OpOutcome::PowerLoss => Err(power_loss_error()),
            OpOutcome::Dropped => Ok(()),
            OpOutcome::Completed => {
                let block_size = block_bytes(state.live.geometry());
                let State {
                    durable, pending, ..
                } = &mut *state;
                for write in pending.drain(..) {
                    let start = lba_offset(write.landed_lba, block_size);
                    durable[start..start + write.data.len()].copy_from_slice(&write.data);
                }
                Ok(())
            }
        }
    }
}

pub fn block_bytes(geometry: BlockGeometry) -> usize {
    usize::try_from(geometry.logical_block_size()).expect("block size fits usize")
}

fn lba_offset(lba: u64, block_size: usize) -> usize {
    usize::try_from(lba).expect("test LBA fits usize") * block_size
}

pub fn power_loss_error() -> BlockIoError {
    BlockIoError::Transport(BlockTransportError::DeviceFault)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_block::BlockDeviceId;

    const BLOCK: usize = 512;

    fn geometry() -> BlockGeometry {
        BlockGeometry::new(BlockDeviceId::new(41), 512, 8, 2, false).unwrap()
    }

    fn block(byte: u8) -> Vec<u8> {
        vec![byte; BLOCK]
    }

    fn stored_block(image: &[u8], lba: usize) -> &[u8] {
        &image[lba * BLOCK..(lba + 1) * BLOCK]
    }

    #[test]
    fn flush_persists_pending_writes_and_logs_them() {
        let mut device = FaultDevice::new(geometry(), FaultConfig::default());
        device.write_blocks(3, 1, &block(0xaa)).unwrap();
        assert!(device.durable_image().iter().all(|byte| *byte == 0));
        assert_eq!(device.pending().len(), 1);

        device.flush().unwrap();

        assert_eq!(stored_block(&device.durable_image(), 3), &block(0xaa)[..]);
        assert!(device.pending().is_empty());
        assert_eq!(
            device.log(),
            vec![
                Op {
                    kind: OpKind::Write {
                        lba: 3,
                        landed_lba: 3,
                        data: block(0xaa),
                    },
                    outcome: OpOutcome::Completed,
                },
                Op {
                    kind: OpKind::Flush,
                    outcome: OpOutcome::Completed,
                },
            ]
        );
    }

    #[test]
    fn dropped_flush_acks_without_persisting_and_keeps_writes_pending() {
        let config = FaultConfig {
            dropped_flushes: vec![0],
            ..FaultConfig::default()
        };
        let mut device = FaultDevice::new(geometry(), config);
        device.write_blocks(2, 1, &block(0x11)).unwrap();

        assert_eq!(device.flush(), Ok(()));

        assert!(device.durable_image().iter().all(|byte| *byte == 0));
        assert_eq!(device.pending().len(), 1);
        assert_eq!(device.log()[1].outcome, OpOutcome::Dropped);
        let mut read = block(0);
        device.read_blocks(2, 1, &mut read).unwrap();
        assert_eq!(read, block(0x11));

        device.flush().unwrap();
        assert_eq!(stored_block(&device.durable_image(), 2), &block(0x11)[..]);
    }

    #[test]
    fn power_loss_interrupts_the_counted_op_and_keeps_an_in_flight_write_pending() {
        let config = FaultConfig {
            power_loss_at_op: Some(1),
            ..FaultConfig::default()
        };
        let mut device = FaultDevice::new(geometry(), config);
        device.write_blocks(0, 1, &block(0x01)).unwrap();

        assert_eq!(
            device.write_blocks(1, 1, &block(0x02)),
            Err(power_loss_error())
        );
        assert!(device.is_powered_off());
        assert_eq!(device.flush(), Err(power_loss_error()));
        let mut read = block(0);
        assert_eq!(device.read_blocks(0, 1, &mut read), Err(power_loss_error()));

        assert_eq!(device.pending().len(), 2);
        assert_eq!(device.log().len(), 2);
        assert_eq!(device.log()[1].outcome, OpOutcome::PowerLoss);
    }

    #[test]
    fn crash_plan_persists_any_subset_in_any_order() {
        let mut device = FaultDevice::new(geometry(), FaultConfig::default());
        device.write_blocks(4, 1, &block(0x10)).unwrap();
        device.write_blocks(5, 1, &block(0x20)).unwrap();
        device.write_blocks(4, 1, &block(0x30)).unwrap();

        let only_second = device.crash_image(&[CrashStep::Persist(1)]);
        assert_eq!(stored_block(&only_second, 4), &block(0)[..]);
        assert_eq!(stored_block(&only_second, 5), &block(0x20)[..]);

        let newest_first = device.crash_image(&[CrashStep::Persist(2), CrashStep::Persist(0)]);
        assert_eq!(stored_block(&newest_first, 4), &block(0x10)[..]);

        assert!(device.crash_image(&[]).iter().all(|byte| *byte == 0));
    }

    #[test]
    fn torn_write_persists_a_byte_prefix_over_the_old_bytes() {
        let mut device = FaultDevice::new(geometry(), FaultConfig::default());
        device
            .write_blocks(2, 2, &[block(0x11), block(0x11)].concat())
            .unwrap();
        device.flush().unwrap();
        device
            .write_blocks(2, 2, &[block(0x22), block(0x22)].concat())
            .unwrap();

        let image = device.crash_image(&[CrashStep::Tear {
            index: 0,
            bytes: BLOCK + 13,
        }]);

        assert_eq!(stored_block(&image, 2), &block(0x22)[..]);
        assert!(stored_block(&image, 3)[..13]
            .iter()
            .all(|byte| *byte == 0x22));
        assert!(stored_block(&image, 3)[13..]
            .iter()
            .all(|byte| *byte == 0x11));
    }

    #[test]
    fn bit_flip_changes_exactly_one_stored_bit() {
        let mut device = FaultDevice::new(geometry(), FaultConfig::default());
        device.write_blocks(1, 1, &block(0xf0)).unwrap();
        device.flush().unwrap();

        let image = device.crash_image(&[CrashStep::FlipBit {
            lba: 1,
            bit: 8 * 7 + 1,
        }]);

        let mut expected = device.durable_image();
        expected[BLOCK + 7] = 0xf2;
        assert_eq!(image, expected);
    }

    #[test]
    fn misdirected_write_lands_at_the_other_lba_and_logs_both() {
        let config = FaultConfig {
            misdirected_writes: vec![(1, 6)],
            ..FaultConfig::default()
        };
        let mut device = FaultDevice::new(geometry(), config);
        device.write_blocks(2, 1, &block(0x01)).unwrap();
        device.write_blocks(3, 1, &block(0x02)).unwrap();
        device.flush().unwrap();

        let image = device.durable_image();
        assert_eq!(stored_block(&image, 3), &block(0)[..]);
        assert_eq!(stored_block(&image, 6), &block(0x02)[..]);
        let mut read = block(0);
        device.read_blocks(6, 1, &mut read).unwrap();
        assert_eq!(read, block(0x02));
        assert_eq!(
            device.log()[1].kind,
            OpKind::Write {
                lba: 3,
                landed_lba: 6,
                data: block(0x02),
            }
        );
    }
}
