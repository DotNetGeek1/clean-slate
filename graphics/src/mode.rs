//! Reference display mode and output metadata.

use crate::geometry::Scale120;
use crate::geometry::Size;
use crate::ids::OutputId;
use crate::pixel::PixelFormat;

/// Physical scanout parameters visible to clients after negotiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayMode {
    pub width_px: u32,
    pub height_px: u32,
    pub stride_bytes: u32,
    pub format: PixelFormat,
    pub scale: Scale120,
    pub refresh_mhz: u32,
}

/// One physical output described to clients at connect time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputInfo {
    pub id: OutputId,
    pub mode: DisplayMode,
    pub logical_size: Size,
}

/// Frozen QEMU/OVMF reference mode: 1280×800 `Xrgb8888`, scale 1.0, stride 5120.
pub const REFERENCE_MODE: DisplayMode = DisplayMode {
    width_px: 1280,
    height_px: 800,
    stride_bytes: 5120,
    format: PixelFormat::Xrgb8888,
    scale: Scale120::ONE,
    refresh_mhz: 0,
};

/// One full reference frame (1000 × 4096-byte pages).
pub const REFERENCE_FRAME_BYTES: usize = 4_096_000;

const _: () = assert!(
    REFERENCE_FRAME_BYTES
        == REFERENCE_MODE.stride_bytes as usize * REFERENCE_MODE.height_px as usize
);
const _: () = assert!(REFERENCE_FRAME_BYTES == 1000 * 4096);
