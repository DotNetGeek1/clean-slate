//! The only write path into the mapped GOP aperture.

use core::ptr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ApertureError {
    Geometry,
    Misaligned,
    OutOfBounds,
}

/// Owns the uncached aperture mapping. Every access is a row segment checked against the visible
/// area, so stride padding and bytes past `byte_len` are never touched.
pub(crate) struct ApertureWriter {
    base: *mut u8,
    byte_len: usize,
    stride_bytes: usize,
    width: u32,
    height: u32,
}

impl ApertureWriter {
    /// # Safety
    /// `base` must map `byte_len` writable bytes for as long as the writer lives, and nothing else
    /// may access them while it does.
    pub(crate) unsafe fn new(
        base: *mut u8,
        byte_len: usize,
        stride_bytes: u32,
        width: u32,
        height: u32,
    ) -> Result<Self, ApertureError> {
        let visible_row = u64::from(width) * 4;
        let needed = u64::from(stride_bytes).checked_mul(u64::from(height));
        if base.is_null()
            || width == 0
            || height == 0
            || u64::from(stride_bytes) < visible_row
            || needed.is_none_or(|needed| needed > byte_len as u64)
        {
            return Err(ApertureError::Geometry);
        }
        Ok(Self {
            base,
            byte_len,
            stride_bytes: stride_bytes as usize,
            width,
            height,
        })
    }

    pub(crate) fn width(&self) -> u32 {
        self.width
    }

    pub(crate) fn height(&self) -> u32 {
        self.height
    }

    fn segment_offset(&self, y: u32, x_px: u32, len: usize) -> Result<usize, ApertureError> {
        if len % 4 != 0 {
            return Err(ApertureError::Misaligned);
        }
        let pixels = (len / 4) as u64;
        if y >= self.height || u64::from(x_px) + pixels > u64::from(self.width) {
            return Err(ApertureError::OutOfBounds);
        }
        let offset = (y as usize)
            .checked_mul(self.stride_bytes)
            .and_then(|row| row.checked_add(x_px as usize * 4))
            .ok_or(ApertureError::OutOfBounds)?;
        match offset.checked_add(len) {
            Some(end) if end <= self.byte_len => Ok(offset),
            _ => Err(ApertureError::OutOfBounds),
        }
    }

    pub(crate) fn write_row_segment(
        &mut self,
        y: u32,
        x_px: u32,
        src: &[u8],
    ) -> Result<(), ApertureError> {
        let offset = self.segment_offset(y, x_px, src.len())?;
        unsafe { ptr::copy_nonoverlapping(src.as_ptr(), self.base.add(offset), src.len()) };
        Ok(())
    }

    #[cfg(any(test, feature = "m10-framebuffer-self-test"))]
    pub(crate) fn read_row_segment(
        &self,
        y: u32,
        x_px: u32,
        dst: &mut [u8],
    ) -> Result<(), ApertureError> {
        let offset = self.segment_offset(y, x_px, dst.len())?;
        unsafe { ptr::copy_nonoverlapping(self.base.add(offset), dst.as_mut_ptr(), dst.len()) };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    const SENTINEL: u8 = 0xA5;

    #[test]
    fn new_rejects_bad_geometry() {
        let mut bytes = vec![0u8; 64];
        let base = bytes.as_mut_ptr();
        unsafe {
            assert!(ApertureWriter::new(base, 64, 16, 4, 4).is_ok());
            assert_eq!(
                ApertureWriter::new(base, 63, 16, 4, 4).err(),
                Some(ApertureError::Geometry)
            );
            assert_eq!(
                ApertureWriter::new(base, 64, 12, 4, 4).err(),
                Some(ApertureError::Geometry)
            );
            assert_eq!(
                ApertureWriter::new(base, 64, 16, 0, 4).err(),
                Some(ApertureError::Geometry)
            );
            assert_eq!(
                ApertureWriter::new(core::ptr::null_mut(), 64, 16, 4, 4).err(),
                Some(ApertureError::Geometry)
            );
            assert_eq!(
                ApertureWriter::new(base, 64, u32::MAX, u32::MAX, u32::MAX).err(),
                Some(ApertureError::Geometry)
            );
        }
    }

    #[test]
    fn write_bounds_matrix_with_padded_stride() {
        let (width, height, stride) = (5u32, 3u32, 24u32);
        let len = (stride * height) as usize;
        let mut bytes = vec![SENTINEL; len + 8];
        let mut writer =
            unsafe { ApertureWriter::new(bytes.as_mut_ptr(), len, stride, width, height) }.unwrap();

        assert_eq!(writer.write_row_segment(2, 4, &[1, 2, 3, 4]), Ok(()));
        assert_eq!(writer.write_row_segment(0, 0, &[7; 20]), Ok(()));
        assert_eq!(writer.write_row_segment(1, 1, &[]), Ok(()));
        assert_eq!(
            writer.write_row_segment(0, 5, &[0; 4]),
            Err(ApertureError::OutOfBounds)
        );
        assert_eq!(
            writer.write_row_segment(0, 1, &[0; 20]),
            Err(ApertureError::OutOfBounds)
        );
        assert_eq!(
            writer.write_row_segment(3, 0, &[0; 4]),
            Err(ApertureError::OutOfBounds)
        );
        assert_eq!(
            writer.write_row_segment(0, 0, &[0; 3]),
            Err(ApertureError::Misaligned)
        );
        assert_eq!(
            writer.write_row_segment(u32::MAX, u32::MAX, &[0; 4]),
            Err(ApertureError::OutOfBounds)
        );

        let last = (2 * stride + 16) as usize;
        assert_eq!(&bytes[last..last + 4], &[1, 2, 3, 4]);
        assert_eq!(&bytes[..20], &[7; 20]);
        for row in 0..height as usize {
            let pad = row * stride as usize + width as usize * 4;
            assert!(
                bytes[pad..(row + 1) * stride as usize]
                    .iter()
                    .all(|&b| b == SENTINEL),
                "row {row} padding written"
            );
        }
        assert!(bytes[len..].iter().all(|&b| b == SENTINEL));
    }

    #[test]
    fn read_back_matches_write() {
        let mut bytes = vec![0u8; 16 * 2];
        let mut writer = unsafe { ApertureWriter::new(bytes.as_mut_ptr(), 32, 16, 4, 2) }.unwrap();
        writer
            .write_row_segment(1, 1, &[9, 8, 7, 6, 5, 4, 3, 2])
            .unwrap();
        let mut out = [0u8; 8];
        writer.read_row_segment(1, 1, &mut out).unwrap();
        assert_eq!(out, [9, 8, 7, 6, 5, 4, 3, 2]);
        assert_eq!(
            writer.read_row_segment(1, 3, &mut out),
            Err(ApertureError::OutOfBounds)
        );
    }
}
