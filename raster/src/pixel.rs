//! Buffer indexing and format-specific pixel writes.

use clean_slate_graphics::pixel::{over, PixelFormat};
use clean_slate_graphics::BufferLayout;

use crate::color::Color;

pub(crate) fn row_offset(layout: BufferLayout, x: u32, y: u32) -> Option<usize> {
    if x >= layout.width() || y >= layout.height() {
        return None;
    }
    let row = u64::from(y).checked_mul(u64::from(layout.stride_bytes()))?;
    let col = u64::from(x).checked_mul(4)?;
    usize::try_from(row.checked_add(col)?).ok()
}

pub(crate) fn force_xrgb_byte3(bytes: &mut [u8], offset: usize, format: PixelFormat) {
    if format == PixelFormat::Xrgb8888 {
        bytes[offset + 3] = 0xFF;
    }
}

pub(crate) fn write_opaque(bytes: &mut [u8], offset: usize, c: Color, format: PixelFormat) {
    bytes[offset..offset + 4].copy_from_slice(&c.0);
    force_xrgb_byte3(bytes, offset, format);
}

pub(crate) fn write_over(bytes: &mut [u8], offset: usize, src: [u8; 4], format: PixelFormat) {
    let dst = [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ];
    let out = over(src, dst);
    bytes[offset..offset + 4].copy_from_slice(&out);
    force_xrgb_byte3(bytes, offset, format);
}

pub(crate) fn write_coverage(
    bytes: &mut [u8],
    offset: usize,
    c: Color,
    cov: u8,
    format: PixelFormat,
) {
    if cov == 0 {
        return;
    }
    let src = premultiply_coverage(c, cov);
    write_over(bytes, offset, src, format);
}

pub(crate) fn premultiply_coverage(c: Color, cov: u8) -> [u8; 4] {
    use clean_slate_graphics::pixel::div255;
    let k = u16::from(cov);
    [
        div255(u16::from(c.0[0]) * k) as u8,
        div255(u16::from(c.0[1]) * k) as u8,
        div255(u16::from(c.0[2]) * k) as u8,
        div255(u16::from(c.0[3]) * k) as u8,
    ]
}
