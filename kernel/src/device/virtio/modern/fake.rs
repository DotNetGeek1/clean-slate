//! Host model of a modern VirtIO device's `common_cfg` and device config,
//! following the register semantics of virtio 1.2 §4.1.4.3. Accesses at the
//! wrong width fail, so every test also proves natural-width access.

use std::vec::Vec;

use super::regs::{
    AccessError, DeviceAccess, Width, Window, CONFIG_GENERATION, CONFIG_MSIX_VECTOR,
    DEVICE_FEATURE, DEVICE_FEATURE_SELECT, DEVICE_STATUS, DRIVER_FEATURE, DRIVER_FEATURE_SELECT,
    NO_VECTOR, NUM_QUEUES, QUEUE_DESC, QUEUE_DEVICE, QUEUE_DRIVER, QUEUE_ENABLE, QUEUE_MSIX_VECTOR,
    QUEUE_NOTIFY_OFF, QUEUE_SELECT, QUEUE_SIZE, STATUS_DEVICE_NEEDS_RESET, STATUS_DRIVER_OK,
    STATUS_FEATURES_OK,
};

pub(crate) const FAKE_QUEUES: usize = 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FakeQueue {
    pub(crate) max_size: u16,
    pub(crate) size: u16,
    pub(crate) msix_vector: u16,
    pub(crate) enable: u16,
    pub(crate) notify_off: u16,
    pub(crate) desc: u64,
    pub(crate) driver: u64,
    pub(crate) device: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Access {
    pub(crate) write: bool,
    pub(crate) window: Window,
    pub(crate) offset: u32,
    pub(crate) width: Width,
    pub(crate) value: u32,
}

pub(crate) struct FakeDevice {
    pub(crate) device_features: u64,
    pub(crate) driver_features: u64,
    device_feature_select: u32,
    driver_feature_select: u32,
    pub(crate) config_msix_vector: u16,
    pub(crate) num_queues: u16,
    status: u8,
    pub(crate) status_writes: Vec<u8>,
    pub(crate) status_reads: usize,
    pub(crate) config_generation: u8,
    queue_select: u16,
    pub(crate) queues: [FakeQueue; FAKE_QUEUES],
    pub(crate) device_config: Vec<u8>,
    /// Status reads after a reset write that still see the old status (`u32::MAX`: stuck).
    pub(crate) reset_latency_reads: u32,
    pending_reset_reads: u32,
    stale_status: u8,
    pub(crate) veto_features_ok: bool,
    pub(crate) reject_msix_vector: bool,
    pub(crate) needs_reset_after_driver_ok: bool,
    /// Queue 0 comes out of reset still enabled.
    pub(crate) stale_queue_enable: bool,
    /// Device-config reads that each change the config generation.
    pub(crate) config_changes: u32,
    pub(crate) log: Vec<Access>,
    pub(crate) notifies: Vec<(u64, u16)>,
    pub(crate) bus_master: bool,
}

impl FakeDevice {
    /// A block-like device: VERSION_1 plus the given device-class bits, one
    /// 256-entry queue, notify offsets equal to queue indices, 8-byte capacity.
    pub(crate) fn new(device_class_features: u64) -> Self {
        let mut queues = [FakeQueue::default(); FAKE_QUEUES];
        for (index, queue) in queues.iter_mut().enumerate() {
            queue.max_size = 256;
            queue.notify_off = index as u16;
        }
        let mut device = Self {
            device_features: super::features::VERSION_1 | device_class_features,
            driver_features: 0,
            device_feature_select: 0,
            driver_feature_select: 0,
            config_msix_vector: NO_VECTOR,
            num_queues: 1,
            status: 0,
            status_writes: Vec::new(),
            status_reads: 0,
            config_generation: 0,
            queue_select: 0,
            queues,
            device_config: 2048u64.to_le_bytes().to_vec(),
            reset_latency_reads: 0,
            pending_reset_reads: 0,
            stale_status: 0,
            veto_features_ok: false,
            reject_msix_vector: false,
            needs_reset_after_driver_ok: false,
            stale_queue_enable: false,
            config_changes: 0,
            log: Vec::new(),
            notifies: Vec::new(),
            bus_master: false,
        };
        device.reset_registers();
        device
    }

    pub(crate) fn raise_needs_reset(&mut self) {
        self.status |= STATUS_DEVICE_NEEDS_RESET;
    }

    fn reset_registers(&mut self) {
        self.driver_features = 0;
        self.device_feature_select = 0;
        self.driver_feature_select = 0;
        self.config_msix_vector = NO_VECTOR;
        self.queue_select = 0;
        for (index, queue) in self.queues.iter_mut().enumerate() {
            queue.size = queue.max_size;
            queue.msix_vector = NO_VECTOR;
            queue.enable = u16::from(self.stale_queue_enable && index == 0);
            queue.desc = 0;
            queue.driver = 0;
            queue.device = 0;
        }
    }

    fn selected(&mut self) -> Option<&mut FakeQueue> {
        self.queues.get_mut(usize::from(self.queue_select))
    }

    fn common_width(offset: u32) -> Option<Width> {
        Some(match offset {
            DEVICE_FEATURE_SELECT | DEVICE_FEATURE | DRIVER_FEATURE_SELECT | DRIVER_FEATURE => {
                Width::U32
            }
            DEVICE_STATUS | CONFIG_GENERATION => Width::U8,
            CONFIG_MSIX_VECTOR | NUM_QUEUES | QUEUE_SELECT | QUEUE_SIZE | QUEUE_MSIX_VECTOR
            | QUEUE_ENABLE | QUEUE_NOTIFY_OFF => Width::U16,
            0x20..=0x37 if offset % 4 == 0 => Width::U32,
            _ => return None,
        })
    }

    fn read_common(&mut self, offset: u32) -> u32 {
        match offset {
            DEVICE_FEATURE_SELECT => self.device_feature_select,
            DEVICE_FEATURE => match self.device_feature_select {
                0 => self.device_features as u32,
                1 => (self.device_features >> 32) as u32,
                _ => 0,
            },
            DRIVER_FEATURE_SELECT => self.driver_feature_select,
            DRIVER_FEATURE => match self.driver_feature_select {
                0 => self.driver_features as u32,
                1 => (self.driver_features >> 32) as u32,
                _ => 0,
            },
            CONFIG_MSIX_VECTOR => u32::from(self.config_msix_vector),
            NUM_QUEUES => u32::from(self.num_queues),
            DEVICE_STATUS => {
                self.status_reads += 1;
                if self.pending_reset_reads > 0 {
                    if self.pending_reset_reads != u32::MAX {
                        self.pending_reset_reads -= 1;
                    }
                    return u32::from(self.stale_status);
                }
                u32::from(self.status)
            }
            CONFIG_GENERATION => u32::from(self.config_generation),
            QUEUE_SELECT => u32::from(self.queue_select),
            _ => {
                let Some(queue) = self.selected().copied() else {
                    return 0;
                };
                match offset {
                    QUEUE_SIZE => u32::from(queue.size),
                    QUEUE_MSIX_VECTOR => u32::from(queue.msix_vector),
                    QUEUE_ENABLE => u32::from(queue.enable),
                    QUEUE_NOTIFY_OFF => u32::from(queue.notify_off),
                    _ => 0,
                }
            }
        }
    }

    fn write_common(&mut self, offset: u32, value: u32) {
        match offset {
            DEVICE_FEATURE_SELECT => self.device_feature_select = value,
            DRIVER_FEATURE_SELECT => self.driver_feature_select = value,
            DRIVER_FEATURE => match self.driver_feature_select {
                0 => {
                    self.driver_features = (self.driver_features & !0xffff_ffff) | u64::from(value)
                }
                1 => {
                    self.driver_features =
                        (self.driver_features & 0xffff_ffff) | (u64::from(value) << 32)
                }
                _ => {}
            },
            CONFIG_MSIX_VECTOR => self.config_msix_vector = value as u16,
            DEVICE_STATUS => {
                let mut status = value as u8;
                self.status_writes.push(status);
                if status == 0 {
                    self.stale_status = self.status;
                    self.pending_reset_reads = self.reset_latency_reads;
                    self.status = 0;
                    self.reset_registers();
                    return;
                }
                if self.veto_features_ok {
                    status &= !STATUS_FEATURES_OK;
                }
                if status & STATUS_DRIVER_OK != 0 && self.needs_reset_after_driver_ok {
                    status |= STATUS_DEVICE_NEEDS_RESET;
                }
                self.status = status;
            }
            QUEUE_SELECT => self.queue_select = value as u16,
            _ => {
                let reject_msix_vector = self.reject_msix_vector;
                let Some(queue) = self.selected() else {
                    return;
                };
                let set_half = |field: &mut u64, high: bool| {
                    if high {
                        *field = (*field & 0xffff_ffff) | (u64::from(value) << 32);
                    } else {
                        *field = (*field & !0xffff_ffff) | u64::from(value);
                    }
                };
                match offset {
                    QUEUE_SIZE => queue.size = value as u16,
                    QUEUE_MSIX_VECTOR => {
                        queue.msix_vector = if reject_msix_vector {
                            NO_VECTOR
                        } else {
                            value as u16
                        }
                    }
                    QUEUE_ENABLE => queue.enable = value as u16,
                    0x20 | 0x24 => set_half(&mut queue.desc, offset == 0x24),
                    0x28 | 0x2c => set_half(&mut queue.driver, offset == 0x2c),
                    0x30 | 0x34 => set_half(&mut queue.device, offset == 0x34),
                    _ => {}
                }
            }
        }
    }

    fn device_bytes(&mut self, offset: u32, width: Width) -> Result<u32, AccessError> {
        let start = offset as usize;
        let end = start + width.bytes() as usize;
        if offset % width.bytes() != 0 || end > self.device_config.len() {
            return Err(AccessError::OutOfWindow);
        }
        if self.config_changes > 0 {
            self.config_changes -= 1;
            self.config_generation = self.config_generation.wrapping_add(1);
        }
        let mut value = 0u32;
        for (shift, byte) in self.device_config[start..end].iter().enumerate() {
            value |= u32::from(*byte) << (8 * shift);
        }
        Ok(value)
    }

    pub(crate) fn common_writes_to(&self, offset: u32) -> Vec<u32> {
        self.log
            .iter()
            .filter(|access| {
                access.write && access.window == Window::Common && access.offset == offset
            })
            .map(|access| access.value)
            .collect()
    }
}

impl DeviceAccess for FakeDevice {
    fn read(&mut self, window: Window, offset: u32, width: Width) -> Result<u32, AccessError> {
        let value = match window {
            Window::Common => {
                if Self::common_width(offset) != Some(width) {
                    return Err(AccessError::OutOfWindow);
                }
                self.read_common(offset)
            }
            Window::Device => self.device_bytes(offset, width)?,
        };
        self.log.push(Access {
            write: false,
            window,
            offset,
            width,
            value,
        });
        Ok(value)
    }

    fn write(
        &mut self,
        window: Window,
        offset: u32,
        width: Width,
        value: u32,
    ) -> Result<(), AccessError> {
        match window {
            Window::Common => {
                if Self::common_width(offset) != Some(width) {
                    return Err(AccessError::OutOfWindow);
                }
                self.write_common(offset, value);
            }
            Window::Device => {
                self.device_bytes(offset, width)?;
                let start = offset as usize;
                for (index, byte) in value.to_le_bytes()[..width.bytes() as usize]
                    .iter()
                    .enumerate()
                {
                    self.device_config[start + index] = *byte;
                }
            }
        }
        self.log.push(Access {
            write: true,
            window,
            offset,
            width,
            value,
        });
        Ok(())
    }

    fn notify(&mut self, address: u64, queue: u16) -> Result<(), AccessError> {
        self.notifies.push((address, queue));
        Ok(())
    }

    fn set_bus_master(&mut self, enabled: bool) {
        self.bus_master = enabled;
    }

    fn dma_address(&self, va: *const u8, _len: usize) -> Result<u64, AccessError> {
        Ok(va as u64)
    }
}

// Queue register offsets the fake decodes by value.
const _: () = assert!(QUEUE_DESC == 0x20 && QUEUE_DRIVER == 0x28 && QUEUE_DEVICE == 0x30);
