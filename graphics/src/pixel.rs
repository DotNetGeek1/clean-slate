//! Pixel formats, buffer layout validation, and reference premultiplied blending.

use crate::error::GeometryError;
use crate::limits::{MAX_BUFFER_BYTES, MAX_STRIDE_BYTES, MAX_SURFACE_EXTENT};

/// Little-endian pixel layout in buffer byte order.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    /// LE u32 `0xXXRRGGBB`; bytes B, G, R, X. Producers set X to `0xFF`.
    Xrgb8888 = 1,
    /// LE u32 `0xAARRGGBB`; bytes B, G, R, A; R/G/B premultiplied by A.
    Argb8888Premultiplied = 2,
}

impl PixelFormat {
    pub fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Xrgb8888),
            2 => Some(Self::Argb8888Premultiplied),
            _ => None,
        }
    }
}

/// Colour encoding; M10 accepts only sRGB.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorSpace {
    Srgb = 0,
}

/// Validated buffer geometry shared by clients and the compositor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferLayout {
    width: u32,
    height: u32,
    stride_bytes: u32,
    format: PixelFormat,
}

impl BufferLayout {
    pub fn new(
        width: u32,
        height: u32,
        stride_bytes: u32,
        format: PixelFormat,
    ) -> Result<Self, GeometryError> {
        if width == 0 || height == 0 {
            return Err(GeometryError::EmptyExtent);
        }
        if width > MAX_SURFACE_EXTENT || height > MAX_SURFACE_EXTENT {
            return Err(GeometryError::ExtentTooLarge);
        }
        if stride_bytes % 4 != 0 {
            return Err(GeometryError::StrideMisaligned);
        }
        let min_stride = width.checked_mul(4).ok_or(GeometryError::Overflow)?;
        if stride_bytes < min_stride {
            return Err(GeometryError::StrideTooSmall);
        }
        if stride_bytes > MAX_STRIDE_BYTES {
            return Err(GeometryError::StrideTooLarge);
        }
        let byte_len = u64::from(stride_bytes)
            .checked_mul(u64::from(height))
            .ok_or(GeometryError::Overflow)?;
        if byte_len > MAX_BUFFER_BYTES {
            return Err(GeometryError::BufferTooLarge);
        }
        Ok(Self {
            width,
            height,
            stride_bytes,
            format,
        })
    }

    pub fn packed(width: u32, height: u32, format: PixelFormat) -> Result<Self, GeometryError> {
        if width == 0 || height == 0 {
            return Err(GeometryError::EmptyExtent);
        }
        let row = width.checked_mul(4).ok_or(GeometryError::Overflow)?;
        let stride = align_up_u32(row, 64)?;
        Self::new(width, height, stride, format)
    }

    pub fn width(self) -> u32 {
        self.width
    }

    pub fn height(self) -> u32 {
        self.height
    }

    pub fn stride_bytes(self) -> u32 {
        self.stride_bytes
    }

    pub fn format(self) -> PixelFormat {
        self.format
    }

    pub fn byte_len(&self) -> usize {
        match u64::from(self.stride_bytes).checked_mul(u64::from(self.height)) {
            Some(n) if n <= usize::MAX as u64 => n as usize,
            _ => 0,
        }
    }

    pub fn fits_in(&self, buffer_len_bytes: u64) -> bool {
        u64::from(self.stride_bytes)
            .checked_mul(u64::from(self.height))
            .map(|need| need <= buffer_len_bytes)
            .unwrap_or(false)
    }
}

fn align_up_u32(value: u32, alignment: u32) -> Result<u32, GeometryError> {
    if alignment == 0 {
        return Err(GeometryError::Overflow);
    }
    let rem = value % alignment;
    if rem == 0 {
        Ok(value)
    } else {
        value
            .checked_add(alignment - rem)
            .ok_or(GeometryError::Overflow)
    }
}

/// Exact `div255` rounding shared by raster, compositor, and tests.
#[inline]
pub const fn div255(x: u16) -> u32 {
    let x = x as u32;
    (x + 128 + ((x + 128) >> 8)) >> 8
}

#[inline]
fn blend_dst_channel(dst_channel: u8, inv: u32) -> u32 {
    let product = u32::from(dst_channel) * inv;
    div255(product as u16)
}

/// Reference premultiplied B,G,R,A `over` (bytes in that order).
pub fn over(src: [u8; 4], dst: [u8; 4]) -> [u8; 4] {
    let a = src[3];
    let sb = u32::from(src[0].min(a));
    let sg = u32::from(src[1].min(a));
    let sr = u32::from(src[2].min(a));
    let inv = 255u32 - u32::from(a);
    let out_b = sb + blend_dst_channel(dst[0], inv);
    let out_g = sg + blend_dst_channel(dst[1], inv);
    let out_r = sr + blend_dst_channel(dst[2], inv);
    let out_a = u32::from(a) + blend_dst_channel(dst[3], inv);
    [
        out_b.min(255) as u8,
        out_g.min(255) as u8,
        out_r.min(255) as u8,
        out_a.min(255) as u8,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mode::REFERENCE_MODE;

    #[test]
    fn buffer_layout_matrix() {
        assert_eq!(
            BufferLayout::new(0, 10, 40, PixelFormat::Xrgb8888),
            Err(GeometryError::EmptyExtent)
        );
        assert_eq!(
            BufferLayout::new(10, 0, 40, PixelFormat::Xrgb8888),
            Err(GeometryError::EmptyExtent)
        );
        assert_eq!(
            BufferLayout::new(MAX_SURFACE_EXTENT + 1, 1, 4, PixelFormat::Xrgb8888),
            Err(GeometryError::ExtentTooLarge)
        );
        assert_eq!(
            BufferLayout::new(10, 10, 36, PixelFormat::Xrgb8888),
            Err(GeometryError::StrideTooSmall)
        );
        assert_eq!(
            BufferLayout::new(10, 10, 42, PixelFormat::Xrgb8888),
            Err(GeometryError::StrideMisaligned)
        );
        assert_eq!(
            BufferLayout::new(
                MAX_SURFACE_EXTENT,
                1,
                MAX_STRIDE_BYTES + 4,
                PixelFormat::Xrgb8888
            ),
            Err(GeometryError::StrideTooLarge)
        );
        let tall = (MAX_BUFFER_BYTES / u64::from(MAX_STRIDE_BYTES)) as u32 + 1;
        assert_eq!(
            BufferLayout::new(
                MAX_SURFACE_EXTENT,
                tall,
                MAX_STRIDE_BYTES,
                PixelFormat::Xrgb8888
            ),
            Err(GeometryError::BufferTooLarge)
        );

        let reference = BufferLayout::new(
            REFERENCE_MODE.width_px,
            REFERENCE_MODE.height_px,
            REFERENCE_MODE.stride_bytes,
            REFERENCE_MODE.format,
        )
        .unwrap();
        assert_eq!(reference.byte_len(), 4_096_000);
        assert_eq!(reference.width(), REFERENCE_MODE.width_px);

        let packed = BufferLayout::packed(127, 1, PixelFormat::Xrgb8888).unwrap();
        assert_eq!(packed.stride_bytes(), 512);
    }

    #[test]
    fn buffer_layout_fields_not_constructible_without_validation() {
        fn uses_accessors(layout: BufferLayout) -> u32 {
            layout.width() + layout.stride_bytes()
        }
        let layout = BufferLayout::new(10, 10, 40, PixelFormat::Xrgb8888).unwrap();
        assert_eq!(uses_accessors(layout), 50);
    }

    #[test]
    fn fits_in_boundaries() {
        let layout = BufferLayout::new(10, 10, 40, PixelFormat::Xrgb8888).unwrap();
        assert!(layout.fits_in(400));
        assert!(!layout.fits_in(399));
    }

    #[test]
    fn div255_accepts_full_blend_domain() {
        assert_eq!(div255(65025), 255);
        assert_eq!(div255(0), 0);
    }

    #[test]
    fn over_fixed_vectors() {
        let opaque = [10u8, 20, 30, 255];
        let dst = [100u8, 110, 120, 200];
        assert_eq!(over(opaque, dst), opaque);

        let clear = [0u8, 0, 0, 0];
        assert_eq!(over(clear, dst), dst);

        let half = [64u8, 64, 64, 128];
        let out = over(half, [0, 0, 0, 255]);
        assert_eq!(out[0], 64);
        assert_eq!(out[1], 64);
        assert_eq!(out[2], 64);
        assert_eq!(out[3], 255);
    }

    #[test]
    fn over_clamps_invariant_violating_src() {
        let bad = [200u8, 200, 200, 50];
        let dst = [10u8, 20, 30, 255];
        let expected = over([50, 50, 50, 50], dst);
        assert_eq!(over(bad, dst), expected);
    }

    fn over_channels_u32(src: [u8; 4], dst: [u8; 4]) -> [u32; 4] {
        let a = src[3];
        let sb = u32::from(src[0].min(a));
        let sg = u32::from(src[1].min(a));
        let sr = u32::from(src[2].min(a));
        let inv = 255u32 - u32::from(a);
        let db = u32::from(dst[0]);
        let dg = u32::from(dst[1]);
        let dr = u32::from(dst[2]);
        let da = u32::from(dst[3]);
        [
            sb + div255(u16::try_from(db * inv).unwrap()),
            sg + div255(u16::try_from(dg * inv).unwrap()),
            sr + div255(u16::try_from(dr * inv).unwrap()),
            u32::from(a) + div255(u16::try_from(da * inv).unwrap()),
        ]
    }

    #[test]
    fn over_never_exceeds_255() {
        for a in 0u32..=255 {
            for sc in 0u32..=255 {
                for dc in 0u32..=255 {
                    let src = [sc as u8, sc as u8, sc as u8, a as u8];
                    let dst = [dc as u8, dc as u8, dc as u8, 255];
                    let raw = over_channels_u32(src, dst);
                    assert!(raw[0] <= 255);
                    assert!(raw[1] <= 255);
                    assert!(raw[2] <= 255);
                    assert!(raw[3] <= 255);
                    assert_eq!(
                        over(src, dst),
                        [raw[0] as u8, raw[1] as u8, raw[2] as u8, raw[3] as u8,]
                    );
                }
            }
        }
    }

    #[test]
    fn pixel_format_round_trip() {
        assert_eq!(PixelFormat::from_u8(1), Some(PixelFormat::Xrgb8888));
        assert_eq!(PixelFormat::from_u8(99), None);
    }
}
