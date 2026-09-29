//! Copy and premultiplied `over` blits between supported [`PixelFormat`] pairs.

use clean_slate_graphics::pixel::{over, PixelFormat};
use clean_slate_graphics::{BufferLayout, Rect};

use crate::canvas::Canvas;
use crate::clip::{draw_rect, layout_bounds};
use crate::pixel::{force_xrgb_byte3, row_offset, write_opaque, write_over};
use crate::RasterError;

/// Whether source pixels replace or blend over the destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlitMode {
    /// Replace (Xrgb destinations still force byte 3 to `0xFF` where required).
    Copy,
    /// Premultiplied `over` (Xrgb forces byte 3 after blend).
    Over,
}

impl Canvas<'_> {
    /// Blits `src_rect` from `src` at `dst` top-left, clipped to the canvas clip.
    pub fn blit(
        &mut self,
        src: &[u8],
        src_layout: BufferLayout,
        src_rect: Rect,
        dst: (i32, i32),
        mode: BlitMode,
    ) -> Result<(), RasterError> {
        if !src_layout.fits_in(src.len() as u64) {
            return Err(RasterError::BufferTooSmall);
        }
        let src_bounds = layout_bounds(src_layout);
        let clipped_src = draw_rect(src_bounds, src_rect, src_layout);
        if clipped_src.width == 0 || clipped_src.height == 0 {
            return Ok(());
        }
        let shift = |d: i32, clipped: i32, requested: i32| {
            i32::try_from(i64::from(d) + i64::from(clipped) - i64::from(requested)).ok()
        };
        let (Some(dx), Some(dy)) = (
            shift(dst.0, clipped_src.x, src_rect.x),
            shift(dst.1, clipped_src.y, src_rect.y),
        ) else {
            return Ok(());
        };
        let dst_rect = Rect {
            x: dx,
            y: dy,
            width: clipped_src.width,
            height: clipped_src.height,
        };
        let clipped_dst = draw_rect(self.clip, dst_rect, self.layout);
        if clipped_dst.width == 0 || clipped_dst.height == 0 {
            return Ok(());
        }
        let skip_x = (clipped_dst.x - dst_rect.x) as u32;
        let skip_y = (clipped_dst.y - dst_rect.y) as u32;
        let src_x0 = clipped_src.x as u32 + skip_x;
        let src_y0 = clipped_src.y as u32 + skip_y;

        let dst_fmt = self.layout.format();
        let src_fmt = src_layout.format();
        blit_inner(
            self.bytes,
            self.layout,
            src,
            src_layout,
            src_x0,
            src_y0,
            clipped_dst,
            dst_fmt,
            src_fmt,
            mode,
        );
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn blit_inner(
    dst_bytes: &mut [u8],
    dst_layout: BufferLayout,
    src_bytes: &[u8],
    src_layout: BufferLayout,
    src_x0: u32,
    src_y0: u32,
    dst_rect: Rect,
    dst_fmt: PixelFormat,
    src_fmt: PixelFormat,
    mode: BlitMode,
) {
    for row in 0..dst_rect.height {
        let sy = src_y0 + row;
        let dy = dst_rect.y as u32 + row;
        for col in 0..dst_rect.width {
            let sx = src_x0 + col;
            let dx = dst_rect.x as u32 + col;
            let Some(src_off) = row_offset(src_layout, sx, sy) else {
                continue;
            };
            let Some(dst_off) = row_offset(dst_layout, dx, dy) else {
                continue;
            };
            if src_off + 4 > src_bytes.len() || dst_off + 4 > dst_bytes.len() {
                continue;
            }
            let sp = [
                src_bytes[src_off],
                src_bytes[src_off + 1],
                src_bytes[src_off + 2],
                src_bytes[src_off + 3],
            ];
            match (src_fmt, dst_fmt, mode) {
                (PixelFormat::Xrgb8888, PixelFormat::Xrgb8888, BlitMode::Copy)
                | (PixelFormat::Xrgb8888, PixelFormat::Xrgb8888, BlitMode::Over) => {
                    dst_bytes[dst_off..dst_off + 4].copy_from_slice(&sp);
                    force_xrgb_byte3(dst_bytes, dst_off, dst_fmt);
                }
                (PixelFormat::Argb8888Premultiplied, PixelFormat::Xrgb8888, BlitMode::Copy) => {
                    dst_bytes[dst_off] = sp[0];
                    dst_bytes[dst_off + 1] = sp[1];
                    dst_bytes[dst_off + 2] = sp[2];
                    dst_bytes[dst_off + 3] = 0xFF;
                }
                (PixelFormat::Argb8888Premultiplied, PixelFormat::Xrgb8888, BlitMode::Over) => {
                    let blended = over(
                        sp,
                        [
                            dst_bytes[dst_off],
                            dst_bytes[dst_off + 1],
                            dst_bytes[dst_off + 2],
                            0xFF,
                        ],
                    );
                    dst_bytes[dst_off] = blended[0];
                    dst_bytes[dst_off + 1] = blended[1];
                    dst_bytes[dst_off + 2] = blended[2];
                    dst_bytes[dst_off + 3] = 0xFF;
                }
                (
                    PixelFormat::Argb8888Premultiplied,
                    PixelFormat::Argb8888Premultiplied,
                    BlitMode::Copy,
                ) => {
                    dst_bytes[dst_off..dst_off + 4].copy_from_slice(&sp);
                }
                (
                    PixelFormat::Argb8888Premultiplied,
                    PixelFormat::Argb8888Premultiplied,
                    BlitMode::Over,
                ) => {
                    write_over(dst_bytes, dst_off, sp, dst_fmt);
                }
                (PixelFormat::Xrgb8888, PixelFormat::Argb8888Premultiplied, BlitMode::Copy)
                | (PixelFormat::Xrgb8888, PixelFormat::Argb8888Premultiplied, BlitMode::Over) => {
                    let px = [sp[0], sp[1], sp[2], 255];
                    if mode == BlitMode::Copy {
                        write_opaque(dst_bytes, dst_off, crate::color::Color(px), dst_fmt);
                    } else {
                        write_over(dst_bytes, dst_off, px, dst_fmt);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_graphics::pixel::PixelFormat;

    fn layout(w: u32, h: u32, fmt: PixelFormat) -> BufferLayout {
        BufferLayout::new(w, h, w * 4, fmt).unwrap()
    }

    #[test]
    fn blit_with_extreme_source_origin_is_a_no_op() {
        let mut dst = vec![7u8; 16];
        let src = [1u8; 16];
        let mut canvas = Canvas::new(&mut dst, layout(2, 2, PixelFormat::Xrgb8888)).unwrap();
        let far = Rect {
            x: i32::MIN,
            y: i32::MIN,
            width: u32::MAX,
            height: u32::MAX,
        };
        canvas
            .blit(
                &src,
                layout(2, 2, PixelFormat::Xrgb8888),
                far,
                (i32::MAX, 0),
                BlitMode::Copy,
            )
            .unwrap();
        assert!(dst.iter().all(|byte| *byte == 7));
    }

    #[test]
    fn blit_xrgb_copy_forces_x() {
        let mut dst = vec![0u8; 16];
        dst[3] = 0;
        let src = [1u8, 2, 3, 0, 5, 6, 7, 0, 9, 10, 11, 0, 13, 14, 15, 0];
        let mut canvas = Canvas::new(&mut dst, layout(2, 2, PixelFormat::Xrgb8888)).unwrap();
        canvas
            .blit(
                &src,
                layout(2, 2, PixelFormat::Xrgb8888),
                Rect {
                    x: 0,
                    y: 0,
                    width: 2,
                    height: 2,
                },
                (0, 0),
                BlitMode::Copy,
            )
            .unwrap();
        assert_eq!(dst[3], 0xFF);
    }
}
