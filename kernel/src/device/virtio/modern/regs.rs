//! `virtio_pci_common_cfg` layout (virtio 1.2 §4.1.4.3), device status bits,
//! and the register-access seam the transport runs against (MMIO in the
//! kernel, a device model in host tests).

pub(crate) const DEVICE_FEATURE_SELECT: u32 = 0x00;
pub(crate) const DEVICE_FEATURE: u32 = 0x04;
pub(crate) const DRIVER_FEATURE_SELECT: u32 = 0x08;
pub(crate) const DRIVER_FEATURE: u32 = 0x0c;
pub(crate) const CONFIG_MSIX_VECTOR: u32 = 0x10;
pub(crate) const NUM_QUEUES: u32 = 0x12;
pub(crate) const DEVICE_STATUS: u32 = 0x14;
pub(crate) const CONFIG_GENERATION: u32 = 0x15;
pub(crate) const QUEUE_SELECT: u32 = 0x16;
pub(crate) const QUEUE_SIZE: u32 = 0x18;
pub(crate) const QUEUE_MSIX_VECTOR: u32 = 0x1a;
pub(crate) const QUEUE_ENABLE: u32 = 0x1c;
pub(crate) const QUEUE_NOTIFY_OFF: u32 = 0x1e;
pub(crate) const QUEUE_DESC: u32 = 0x20;
pub(crate) const QUEUE_DRIVER: u32 = 0x28;
pub(crate) const QUEUE_DEVICE: u32 = 0x30;

pub(crate) const STATUS_ACKNOWLEDGE: u8 = 1;
pub(crate) const STATUS_DRIVER: u8 = 2;
pub(crate) const STATUS_DRIVER_OK: u8 = 4;
pub(crate) const STATUS_FEATURES_OK: u8 = 8;
pub(crate) const STATUS_DEVICE_NEEDS_RESET: u8 = 64;
pub(crate) const STATUS_FAILED: u8 = 128;

pub(crate) const NO_VECTOR: u16 = 0xffff;

pub(crate) const ISR_QUEUE: u8 = 1;
pub(crate) const ISR_CONFIG: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Window {
    Common,
    Device,
}

/// Natural access widths; `common_cfg` and device config are never accessed
/// with a wider or unaligned access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Width {
    U8,
    U16,
    U32,
}

impl Width {
    pub(crate) const fn bytes(self) -> u32 {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U32 => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AccessError {
    /// Outside the window, misaligned, or wider than the value.
    OutOfWindow,
    /// The window is not identity-mapped in the kernel root.
    Unmapped,
}

/// Everything the transport does to the device besides touching its rings.
pub(crate) trait DeviceAccess {
    fn read(&mut self, window: Window, offset: u32, width: Width) -> Result<u32, AccessError>;
    fn write(
        &mut self,
        window: Window,
        offset: u32,
        width: Width,
        value: u32,
    ) -> Result<(), AccessError>;
    /// 16-bit write of `queue` to a notify address computed by `caps::notify_address`.
    fn notify(&mut self, address: u64, queue: u16) -> Result<(), AccessError>;
    /// PCI COMMAND bus mastering; cleared closes device DMA at the function.
    fn set_bus_master(&mut self, enabled: bool);
    /// Device-visible address of kernel memory `[va, va + len)`.
    fn dma_address(&self, va: *const u8, len: usize) -> Result<u64, AccessError>;
}

/// Bounds and alignment check shared by every [`DeviceAccess`] implementation.
pub(crate) fn check_window(length: u32, offset: u32, width: Width) -> Result<(), AccessError> {
    let bytes = width.bytes();
    let end = offset.checked_add(bytes).ok_or(AccessError::OutOfWindow)?;
    if offset % bytes != 0 || end > length {
        return Err(AccessError::OutOfWindow);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_checks_bounds_and_natural_alignment() {
        assert_eq!(check_window(0x38, 0x30, Width::U32), Ok(()));
        assert_eq!(check_window(0x38, 0x34, Width::U32), Ok(()));
        assert_eq!(
            check_window(0x38, 0x36, Width::U32),
            Err(AccessError::OutOfWindow)
        );
        assert_eq!(
            check_window(0x38, 0x15, Width::U16),
            Err(AccessError::OutOfWindow)
        );
        assert_eq!(check_window(0x38, 0x15, Width::U8), Ok(()));
        assert_eq!(
            check_window(1, 0, Width::U16),
            Err(AccessError::OutOfWindow)
        );
        assert_eq!(
            check_window(u32::MAX, u32::MAX - 1, Width::U32),
            Err(AccessError::OutOfWindow)
        );
    }
}
