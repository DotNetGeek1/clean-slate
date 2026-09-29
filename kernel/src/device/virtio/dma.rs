//! DMA buffers a modern VirtIO device may be pointed at (S5).
//!
//! A [`DmaSegment`] can only be cut from a [`DmaRegion`], and a region can only
//! be built from kernel-owned `'static` memory whose physical range was checked
//! contiguous in the kernel root, so no descriptor can name a client buffer or a
//! caller-chosen physical address.

#![cfg_attr(not(feature = "m10-virtio-modern-self-test"), allow(dead_code))]

use core::ptr::{read_volatile, write_volatile};

use crate::mm::address_space::{kernel_root_frame, translate_address_in_root};
use crate::mm::PAGE_SIZE;
use x86_64::VirtAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DmaError {
    Empty,
    TooLarge,
    Unmapped,
    NotContiguous,
    OutOfRange,
}

/// A device-visible byte range: readable by the device, or writable by it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DmaSegment {
    phys: u64,
    len: u32,
    device_writes: bool,
}

impl DmaSegment {
    pub(crate) fn phys(&self) -> u64 {
        self.phys
    }

    pub(crate) fn len(&self) -> u32 {
        self.len
    }

    pub(crate) fn device_writes(&self) -> bool {
        self.device_writes
    }

    #[cfg(test)]
    pub(crate) fn fake(phys: u64, len: u32, device_writes: bool) -> Self {
        Self {
            phys,
            len,
            device_writes,
        }
    }
}

/// Kernel-static memory shared with a device. The CPU side reads and writes it
/// only through volatile copies, since the device may be writing concurrently.
pub(crate) struct DmaRegion {
    base: *mut u8,
    phys: u64,
    len: u32,
}

impl DmaRegion {
    pub(crate) fn from_static(buffer: &'static mut [u8]) -> Result<Self, DmaError> {
        let len = u32::try_from(buffer.len()).map_err(|_| DmaError::TooLarge)?;
        let phys = kernel_physical_range(buffer.as_ptr() as u64, buffer.len())?;
        Ok(Self {
            base: buffer.as_mut_ptr(),
            phys,
            len,
        })
    }

    pub(crate) fn readable(&self, offset: u32, len: u32) -> Result<DmaSegment, DmaError> {
        self.segment(offset, len, false)
    }

    pub(crate) fn writable(&self, offset: u32, len: u32) -> Result<DmaSegment, DmaError> {
        self.segment(offset, len, true)
    }

    pub(crate) fn copy_in(&mut self, offset: u32, bytes: &[u8]) -> Result<(), DmaError> {
        let start = self.checked_range(offset, bytes.len())?;
        for (index, byte) in bytes.iter().enumerate() {
            // SAFETY: `checked_range` keeps `start + index` inside the owned buffer.
            unsafe { write_volatile(self.base.add(start + index), *byte) };
        }
        Ok(())
    }

    pub(crate) fn copy_out(&self, offset: u32, bytes: &mut [u8]) -> Result<(), DmaError> {
        let start = self.checked_range(offset, bytes.len())?;
        for (index, byte) in bytes.iter_mut().enumerate() {
            // SAFETY: as in `copy_in`.
            *byte = unsafe { read_volatile(self.base.add(start + index)) };
        }
        Ok(())
    }

    fn segment(&self, offset: u32, len: u32, device_writes: bool) -> Result<DmaSegment, DmaError> {
        if len == 0 {
            return Err(DmaError::Empty);
        }
        self.checked_range(offset, len as usize)?;
        Ok(DmaSegment {
            phys: self.phys + u64::from(offset),
            len,
            device_writes,
        })
    }

    fn checked_range(&self, offset: u32, len: usize) -> Result<usize, DmaError> {
        let end = (offset as usize)
            .checked_add(len)
            .ok_or(DmaError::OutOfRange)?;
        if end > self.len as usize {
            return Err(DmaError::OutOfRange);
        }
        Ok(offset as usize)
    }

    #[cfg(test)]
    pub(crate) fn fake(buffer: &'static mut [u8], phys: u64) -> Self {
        Self {
            len: buffer.len() as u32,
            base: buffer.as_mut_ptr(),
            phys,
        }
    }
}

/// Physical base of `[va, va + len)` in the kernel root, which must be mapped
/// and physically contiguous.
pub(crate) fn kernel_physical_range(va: u64, len: usize) -> Result<u64, DmaError> {
    if len == 0 {
        return Err(DmaError::Empty);
    }
    let root = kernel_root_frame();
    let translate = |address: u64| {
        translate_address_in_root(
            root,
            VirtAddr::try_new(address).map_err(|_| DmaError::Unmapped)?,
        )
        .map_err(|_| DmaError::Unmapped)
    };
    let first = translate(va)?;
    let end = va.checked_add(len as u64).ok_or(DmaError::OutOfRange)?;
    let mut page = (va & !(PAGE_SIZE - 1)) + PAGE_SIZE;
    while page < end {
        if translate(page)? != first + (page - va) {
            return Err(DmaError::NotContiguous);
        }
        page += PAGE_SIZE;
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(len: usize) -> DmaRegion {
        DmaRegion::fake(std::vec![0u8; len].leak(), 0x10_0000)
    }

    #[test]
    fn segments_stay_inside_the_region() {
        let region = region(512);
        let segment = region.writable(8, 504).expect("tail");
        assert_eq!((segment.phys(), segment.len()), (0x10_0008, 504));
        assert!(segment.device_writes());
        assert!(!region.readable(0, 16).expect("head").device_writes());
        assert_eq!(region.readable(8, 505), Err(DmaError::OutOfRange));
        assert_eq!(region.readable(u32::MAX, 2), Err(DmaError::OutOfRange));
        assert_eq!(region.readable(0, 0), Err(DmaError::Empty));
    }

    #[test]
    fn copies_are_bounds_checked() {
        let mut region = region(16);
        region.copy_in(12, b"abcd").expect("fits");
        let mut out = [0u8; 4];
        region.copy_out(12, &mut out).expect("fits");
        assert_eq!(&out, b"abcd");
        assert_eq!(region.copy_in(13, b"abcd"), Err(DmaError::OutOfRange));
        assert_eq!(region.copy_out(16, &mut out), Err(DmaError::OutOfRange));
    }
}
