use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::fake::{FakeBlockDevice, FakeBlockDeviceError};
use crate::{BlockDevice, BlockGeometry, BlockIoError, BlockTransportError};

/// When an armed fault fires, counted from the moment the plan is armed
/// (counts are cumulative over the device's lifetime, not reset by `arm`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultTrigger {
    /// Fire on the `n`th `write_blocks` call (1-based).
    AfterWrite(u64),
    /// Fire on the `n`th `flush` call (1-based).
    AfterFlush(u64),
}

/// What happens when a fault fires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultAction {
    /// The triggering operation completes against the live image, then the
    /// device powers off: the call returns an error and every later call
    /// fails until the device is rebooted from its durable bytes.
    PowerLoss,
    /// The triggering operation is rejected without touching the live image
    /// and the device stays online.
    IoError(BlockIoError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultPlan {
    pub trigger: FaultTrigger,
    pub action: FaultAction,
}

/// Shared handle used to arm faults on a [`FaultInjectingBlockDevice`] after
/// ownership of the device has moved into the code under test.
#[derive(Clone, Debug)]
pub struct FaultController {
    state: Rc<RefCell<FaultState>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FaultState {
    write_count: u64,
    flush_count: u64,
    plan: Option<FaultPlan>,
    powered_off: bool,
    early_persist_writes: Vec<u64>,
}

impl FaultController {
    fn new() -> Self {
        Self {
            state: Rc::new(RefCell::new(FaultState {
                write_count: 0,
                flush_count: 0,
                plan: None,
                powered_off: false,
                early_persist_writes: Vec::new(),
            })),
        }
    }

    pub fn arm(&self, plan: FaultPlan) {
        let mut state = self.state.borrow_mut();
        state.plan = Some(plan);
        state.powered_off = false;
    }

    pub fn set_early_persist_writes(&self, writes: &[u64]) {
        let mut state = self.state.borrow_mut();
        state.early_persist_writes.clear();
        state.early_persist_writes.extend_from_slice(writes);
    }

    pub fn write_count(&self) -> u64 {
        self.state.borrow().write_count
    }

    pub fn flush_count(&self) -> u64 {
        self.state.borrow().flush_count
    }

    fn ensure_online(&self) -> Result<(), BlockIoError> {
        if self.state.borrow().powered_off {
            return Err(power_loss_error());
        }
        Ok(())
    }

    fn next_write_plan(&self) -> Result<(u64, bool, Option<FaultAction>), BlockIoError> {
        let mut state = self.state.borrow_mut();
        if state.powered_off {
            return Err(power_loss_error());
        }
        state.write_count += 1;
        let write_count = state.write_count;
        let persist_early = state.early_persist_writes.contains(&write_count);
        let Some(plan) = state.plan else {
            return Ok((write_count, persist_early, None));
        };
        if plan.trigger != FaultTrigger::AfterWrite(write_count) {
            return Ok((write_count, persist_early, None));
        }
        state.plan = None;
        Ok((write_count, persist_early, Some(plan.action)))
    }

    fn next_flush_plan(&self) -> Result<Option<FaultAction>, BlockIoError> {
        let mut state = self.state.borrow_mut();
        if state.powered_off {
            return Err(power_loss_error());
        }
        state.flush_count += 1;
        let Some(plan) = state.plan else {
            return Ok(None);
        };
        if plan.trigger != FaultTrigger::AfterFlush(state.flush_count) {
            return Ok(None);
        }
        state.plan = None;
        Ok(Some(plan.action))
    }

    fn power_off(&self) {
        self.state.borrow_mut().powered_off = true;
    }
}

/// [`FakeBlockDevice`] wrapper that fails deterministically at counted
/// write/flush boundaries so host tests can exercise a store's crash model.
#[derive(Clone, Debug)]
pub struct FaultInjectingBlockDevice {
    inner: FakeBlockDevice,
    controller: FaultController,
}

impl FaultInjectingBlockDevice {
    pub fn new(inner: FakeBlockDevice) -> Self {
        Self {
            inner,
            controller: FaultController::new(),
        }
    }

    pub fn controller(&self) -> FaultController {
        self.controller.clone()
    }

    pub fn durable_bytes(&self) -> &[u8] {
        self.inner.durable_bytes()
    }

    pub fn durable_bytes_mut(&mut self) -> &mut [u8] {
        self.inner.durable_bytes_mut()
    }

    /// Model a reboot: a fresh, powered-on device whose live and durable
    /// images both equal this device's durable bytes. Un-flushed writes and
    /// any armed fault plan are discarded.
    pub fn rebooted_from_durable(&self) -> Result<Self, FakeBlockDeviceError> {
        Ok(Self::new(self.inner.rebooted()?))
    }

    pub fn into_inner(self) -> FakeBlockDevice {
        self.inner
    }
}

impl BlockDevice for FaultInjectingBlockDevice {
    fn geometry(&self) -> BlockGeometry {
        self.inner.geometry()
    }

    fn read_blocks(
        &mut self,
        lba: u64,
        blocks: u32,
        buffer: &mut [u8],
    ) -> Result<(), BlockIoError> {
        self.controller.ensure_online()?;
        self.inner.read_blocks(lba, blocks, buffer)
    }

    fn write_blocks(&mut self, lba: u64, blocks: u32, buffer: &[u8]) -> Result<(), BlockIoError> {
        let (_, persist_early, action) = self.controller.next_write_plan()?;
        match action {
            Some(FaultAction::IoError(error)) => Err(error),
            Some(FaultAction::PowerLoss) => {
                self.inner.write_blocks(lba, blocks, buffer)?;
                if persist_early {
                    self.inner.persist_blocks(lba, blocks)?;
                }
                self.controller.power_off();
                Err(power_loss_error())
            }
            None => {
                self.inner.write_blocks(lba, blocks, buffer)?;
                if persist_early {
                    self.inner.persist_blocks(lba, blocks)?;
                }
                Ok(())
            }
        }
    }

    fn flush(&mut self) -> Result<(), BlockIoError> {
        match self.controller.next_flush_plan()? {
            Some(FaultAction::IoError(error)) => Err(error),
            Some(FaultAction::PowerLoss) => {
                self.inner.flush()?;
                self.controller.power_off();
                Err(power_loss_error())
            }
            None => self.inner.flush(),
        }
    }
}

fn power_loss_error() -> BlockIoError {
    BlockIoError::Transport(BlockTransportError::DeviceFault)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::{BlockDeviceId, BlockGeometry};

    fn geometry() -> BlockGeometry {
        BlockGeometry::new(BlockDeviceId::new(11), 512, 8, 4, false).unwrap()
    }

    #[test]
    fn power_loss_after_write_keeps_old_durable_bytes() {
        let inner = FakeBlockDevice::new(geometry()).unwrap();
        let mut device = FaultInjectingBlockDevice::new(inner);
        device.controller().arm(FaultPlan {
            trigger: FaultTrigger::AfterWrite(1),
            action: FaultAction::PowerLoss,
        });

        let result = device.write_blocks(0, 1, &vec![0x55; 512]);

        assert_eq!(result, Err(power_loss_error()));
        assert!(device.durable_bytes().iter().all(|byte| *byte == 0));
    }

    #[test]
    fn configured_write_can_persist_before_flush() {
        let inner = FakeBlockDevice::new(geometry()).unwrap();
        let mut device = FaultInjectingBlockDevice::new(inner);
        device.controller().set_early_persist_writes(&[1]);

        device.write_blocks(0, 1, &vec![0x33; 512]).unwrap();

        assert_eq!(&device.durable_bytes()[..512], &vec![0x33; 512]);
        assert!(device.durable_bytes()[512..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn failed_flush_does_not_make_new_bytes_durable() {
        let inner = FakeBlockDevice::new(geometry()).unwrap();
        let mut device = FaultInjectingBlockDevice::new(inner);
        device.write_blocks(0, 1, &vec![0xaa; 512]).unwrap();
        device.controller().arm(FaultPlan {
            trigger: FaultTrigger::AfterFlush(1),
            action: FaultAction::IoError(power_loss_error()),
        });

        let result = device.flush();

        assert_eq!(result, Err(power_loss_error()));
        assert!(device.durable_bytes().iter().all(|byte| *byte == 0));
    }
}
