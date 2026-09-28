//! Host-side raster tests.

use clean_slate_graphics::pixel::{over, PixelFormat};
use clean_slate_graphics::{BufferLayout, Rect};

use crate::blit::BlitMode;
use crate::color::Color;
use crate::font::{GlyphAtlas, SPLEEN_8X16};
use crate::pattern::{
    draw_reference_a, draw_reference_b, draw_reference_decoy, pixel_at, reference_layout,
    visible_crc32, Crc32, REFERENCE_B_DAMAGE, REFERENCE_DECOY, REFERENCE_PROBES,
};
use crate::{Canvas, RasterError};

struct XorShift32(u32);

impl XorShift32 {
    fn new(seed: u32) -> Self {
        Self(seed.max(1))
    }

    fn next(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }

    fn range(&mut self, max: u32) -> u32 {
        if max == 0 {
            0
        } else {
            self.next() % max
        }
    }
}

fn layout_xrgb(w: u32, h: u32, extra_stride: u32) -> BufferLayout {
    let extra = extra_stride - (extra_stride % 4);
    BufferLayout::new(w, h, w * 4 + extra, PixelFormat::Xrgb8888).unwrap()
}

fn sentinel_buffer(w: u32, h: u32, extra_stride: u32, tail: usize) -> Vec<u8> {
    let layout = layout_xrgb(w, h, extra_stride);
    let mut v = vec![0xA5u8; layout.byte_len() + tail];
    for row in 0..h {
        let start = row as usize * layout.stride_bytes() as usize;
        for col in (w * 4) as usize..layout.stride_bytes() as usize {
            v[start + col] = 0x5A;
        }
    }
    v
}

fn rect_at(x: i32, y: i32, w: u32, h: u32) -> Rect {
    Rect {
        x,
        y,
        width: w,
        height: h,
    }
}

#[test]
fn crc32_known_answer() {
    let mut c = Crc32::new();
    c.update(b"123456789");
    assert_eq!(c.finish(), 0xCBF43926);
}

#[test]
fn canvas_new_buffer_too_small() {
    let layout = layout_xrgb(4, 4, 0);
    let mut bytes = vec![0u8; layout.byte_len() - 1];
    assert!(matches!(
        Canvas::new(&mut bytes, layout),
        Err(RasterError::BufferTooSmall)
    ));
}

#[test]
fn from_straight_premultiply_vectors() {
    assert_eq!(Color::from_straight(10, 20, 30, 0), Color([0, 0, 0, 0]));
    assert_eq!(
        Color::from_straight(10, 20, 30, 255),
        Color::opaque(10, 20, 30)
    );
    assert_eq!(Color::from_straight(255, 255, 255, 128).0[0], 128);
}

#[test]
fn blend_matches_over_argb() {
    let layout = BufferLayout::new(1, 1, 4, PixelFormat::Argb8888Premultiplied).unwrap();
    let mut rng = XorShift32::new(0x1111_1111);
    for _ in 0..10_000 {
        let src = [
            (rng.next() % 256) as u8,
            (rng.next() % 256) as u8,
            (rng.next() % 256) as u8,
            (rng.next() % 256) as u8,
        ];
        let dst = [
            (rng.next() % 256) as u8,
            (rng.next() % 256) as u8,
            (rng.next() % 256) as u8,
            (rng.next() % 256) as u8,
        ];
        let mut bytes = dst.to_vec();
        Canvas::new(&mut bytes, layout)
            .unwrap()
            .blend_rect(rect_at(0, 0, 1, 1), Color(src));
        assert_eq!(bytes[..4], over(src, dst));
    }
}

#[test]
fn blend_xrgb_forces_x_byte() {
    let layout = layout_xrgb(1, 1, 0);
    let mut bytes = vec![0, 0, 0, 0];
    Canvas::new(&mut bytes, layout)
        .unwrap()
        .blend_rect(rect_at(0, 0, 1, 1), Color::opaque(1, 2, 3));
    assert_eq!(bytes[3], 0xFF);
}

#[test]
fn convert_round_trip_and_odd_length_no_write() {
    let src = [1u8, 2, 3, 4, 5, 6, 7];
    let mut dst = [9u8; 8];
    crate::convert::bgrx_to_rgbx(&src, &mut dst);
    assert_eq!(dst, [9; 8]);
    let src2 = [1u8, 2, 3, 4];
    let mut mid = [0u8; 4];
    let mut back = [0u8; 4];
    crate::convert::bgrx_to_rgbx(&src2, &mut mid);
    assert_eq!(mid, [3, 2, 1, 0xFF]);
    crate::convert::rgbx_to_bgrx(&mid, &mut back);
    assert_eq!(back, [1, 2, 3, 0xFF]);
}

#[test]
fn stride_padding_untouched() {
    let layout = layout_xrgb(37, 3, 20);
    let mut bytes = sentinel_buffer(37, 3, 20, 0);
    let pad_snapshot = bytes.clone();
    let mut canvas = Canvas::new(&mut bytes, layout).unwrap();
    canvas.fill_rect(rect_at(0, 0, 37, 3), Color::opaque(1, 2, 3));
    canvas.blend_rect(rect_at(5, 1, 10, 1), Color::from_straight(4, 5, 6, 128));
    canvas.line((0, 0), (36, 2), Color::opaque(7, 8, 9));
    for (i, (&a, &b)) in bytes.iter().zip(pad_snapshot.iter()).enumerate() {
        let row = i / layout.stride_bytes() as usize;
        let col = i % layout.stride_bytes() as usize;
        if col >= 37 * 4 {
            assert_eq!(a, b, "padding byte {i} row {row} col {col}");
        }
    }
}

#[test]
fn bresenham_octants_and_count() {
    let layout = layout_xrgb(64, 64, 0);
    let cases: [((i32, i32), (i32, i32)); 8] = [
        ((0, 0), (5, 0)),
        ((0, 0), (0, 5)),
        ((5, 0), (0, 0)),
        ((0, 5), (0, 0)),
        ((0, 0), (5, 5)),
        ((5, 5), (0, 0)),
        ((0, 5), (5, 0)),
        ((5, 0), (0, 5)),
    ];
    for (p0, p1) in cases {
        let mut bytes = vec![0u8; layout.byte_len()];
        Canvas::new(&mut bytes, layout)
            .unwrap()
            .line(p0, p1, Color::opaque(255, 255, 255));
        let dx = (p1.0 - p0.0).unsigned_abs();
        let dy = (p1.1 - p0.1).unsigned_abs();
        let expected = dx.max(dy) + 1;
        let mut count = 0u32;
        for y in 0..64 {
            for x in 0..64 {
                let o = (y * 64 + x) as usize * 4;
                if bytes[o + 3] == 0xFF && bytes[o..o + 3] != [0, 0, 0] {
                    count += 1;
                }
            }
        }
        assert_eq!(count, expected, "line {p0:?} {p1:?}");
    }
}

#[test]
fn line_extreme_coords_no_panic() {
    let layout = layout_xrgb(10, 10, 0);
    let mut bytes = vec![0u8; layout.byte_len()];
    let mut c = Canvas::new(&mut bytes, layout).unwrap();
    c.line(
        (i32::MIN, i32::MIN),
        (i32::MAX, i32::MAX),
        Color::opaque(1, 1, 1),
    );
    c.line((0, 0), (i32::MAX, 0), Color::opaque(1, 1, 1));
    c.line((i32::MIN, 5), (i32::MAX, 5), Color::opaque(1, 1, 1));
    c.hline(i32::MIN, i32::MAX, 3, Color::opaque(2, 2, 2));
    c.vline(4, i32::MAX, i32::MIN, Color::opaque(3, 3, 3));
    c.stroke_rect(
        rect_at(i32::MAX - 1, i32::MAX - 1, u32::MAX, u32::MAX),
        3,
        Color::opaque(4, 4, 4),
    );
    c.fill_mask(
        &[255; 4],
        2,
        2,
        (i32::MIN, i32::MAX),
        Color::opaque(5, 5, 5),
    );
    // Only the in-bounds hline and vline land; over-long lines are skipped, not stepped.
    for (i, px) in bytes.chunks_exact(4).enumerate() {
        let (x, y) = (i % 10, i / 10);
        let expected = match (x, y) {
            (4, _) => [3, 3, 3, 255],
            (_, 3) => [2, 2, 2, 255],
            _ => [0, 0, 0, 0],
        };
        assert_eq!(px, expected, "pixel ({x}, {y})");
    }
}

#[test]
fn stroke_rect_thickness_and_no_double_draw() {
    let layout = layout_xrgb(20, 20, 0);
    let mut fill = vec![0u8; layout.byte_len()];
    Canvas::new(&mut fill, layout)
        .unwrap()
        .fill_rect(rect_at(2, 2, 16, 16), Color::opaque(0, 0, 0));
    let mut stroke = fill.clone();
    Canvas::new(&mut stroke, layout).unwrap().stroke_rect(
        rect_at(2, 2, 16, 16),
        2,
        Color::opaque(255, 0, 0),
    );
    let mut count = 0u32;
    for y in 2..18 {
        for x in 2..18 {
            let o = (y * 20 + x) as usize * 4;
            if stroke[o..o + 3] != fill[o..o + 3] {
                count += 1;
            }
        }
    }
    assert_eq!(count, 112);
}

#[test]
fn clip_matrix_fill_and_blend() {
    let layout = layout_xrgb(20, 20, 0);
    let clips = [
        rect_at(5, 5, 10, 10),
        rect_at(15, 5, 10, 10),
        rect_at(5, 15, 10, 10),
        rect_at(-5, 5, 10, 10),
        rect_at(5, -5, 10, 10),
        rect_at(0, 0, 0, 0),
        rect_at(i32::MIN, 0, 1, 1),
        rect_at(0, 0, u32::MAX, 1),
    ];
    for clip in clips {
        let mut bytes = vec![0u8; layout.byte_len()];
        let mut c = Canvas::new(&mut bytes, layout).unwrap();
        c.with_clip(clip)
            .fill_rect(rect_at(0, 0, 20, 20), Color::opaque(1, 2, 3));
        let mut bytes2 = vec![0u8; layout.byte_len()];
        let mut c2 = Canvas::new(&mut bytes2, layout).unwrap();
        c2.with_clip(clip)
            .blend_rect(rect_at(0, 0, 20, 20), Color::from_straight(1, 2, 3, 128));
    }
}

#[test]
fn blit_buffer_too_small() {
    let layout = layout_xrgb(4, 4, 0);
    let mut dst = vec![0u8; layout.byte_len()];
    let src = vec![0u8; layout.byte_len() - 1];
    let mut c = Canvas::new(&mut dst, layout).unwrap();
    assert_eq!(
        c.blit(&src, layout, rect_at(0, 0, 4, 4), (0, 0), BlitMode::Copy),
        Err(RasterError::BufferTooSmall)
    );
}

#[test]
fn text_golden_crc32() {
    const GOLDEN: u32 = 0x65F3_56D1;
    let layout = BufferLayout::packed(256, 32, PixelFormat::Xrgb8888).unwrap();
    let mut bytes = vec![0u8; layout.byte_len()];
    Canvas::new(&mut bytes, layout).unwrap().draw_text(
        &SPLEEN_8X16,
        (0, 8),
        "Clean-Slate M10 0123456789",
        Color::opaque(255, 255, 255),
    );
    let crc = visible_crc32(&bytes, layout).unwrap();
    assert_eq!(crc, GOLDEN);
}

#[test]
fn reference_pattern_golden_crc() {
    const GOLDEN: u32 = 0x20F2_EEC9;
    let layout = reference_layout();
    let mut bytes = vec![0u8; layout.byte_len()];
    let mut c = Canvas::new(&mut bytes, layout).unwrap();
    draw_reference_a(&mut c);
    draw_reference_b(&mut c);
    let crc = visible_crc32(&bytes, layout).unwrap();
    assert_eq!(crc, GOLDEN);
}

#[test]
fn reference_red_bar_centre_pixel() {
    let layout = reference_layout();
    let mut bytes = vec![0u8; layout.byte_len()];
    let mut c = Canvas::new(&mut bytes, layout).unwrap();
    draw_reference_a(&mut c);
    let px = pixel_at(&bytes, layout, 80, 160).unwrap();
    assert_eq!(px, [0, 0, 255, 255]);
}

#[test]
fn reference_b_damage_only() {
    let layout = reference_layout();
    let mut a = vec![0u8; layout.byte_len()];
    let mut ab = a.clone();
    draw_reference_a(&mut Canvas::new(&mut a, layout).unwrap());
    let mut cab = Canvas::new(&mut ab, layout).unwrap();
    draw_reference_a(&mut cab);
    draw_reference_b(&mut cab);
    for y in 0..800 {
        for x in 0..1280 {
            let in_b = REFERENCE_B_DAMAGE.iter().any(|r| {
                x >= r.x as u32
                    && y >= r.y as u32
                    && x < r.x as u32 + r.width
                    && y < r.y as u32 + r.height
            });
            let o = (y * layout.stride_bytes() + x * 4) as usize;
            if in_b {
                assert_ne!(a[o..o + 4], ab[o..o + 4]);
            } else {
                assert_eq!(a[o..o + 4], ab[o..o + 4]);
            }
        }
    }
}

#[test]
fn reference_decoy_isolated() {
    let layout = reference_layout();
    let mut base = vec![0u8; layout.byte_len()];
    draw_reference_a(&mut Canvas::new(&mut base, layout).unwrap());
    let mut with = base.clone();
    draw_reference_decoy(&mut Canvas::new(&mut with, layout).unwrap());
    let r = REFERENCE_DECOY;
    for y in r.y..r.y + r.height as i32 {
        for x in r.x..r.x + r.width as i32 {
            let o = (y * layout.stride_bytes() as i32 + x * 4) as usize;
            assert_ne!(base[o..o + 4], with[o..o + 4]);
        }
    }
}

#[test]
fn reference_probes() {
    let layout = reference_layout();
    let mut a = vec![0u8; layout.byte_len()];
    let mut ab = a.clone();
    draw_reference_a(&mut Canvas::new(&mut a, layout).unwrap());
    let mut cab = Canvas::new(&mut ab, layout).unwrap();
    draw_reference_a(&mut cab);
    draw_reference_b(&mut cab);
    for &(x, y) in &REFERENCE_PROBES[..3] {
        let o = (y * layout.stride_bytes() + x * 4) as usize;
        assert_ne!(a[o..o + 4], ab[o..o + 4]);
    }
    for &(x, y) in &REFERENCE_PROBES[3..5] {
        let o = (y * layout.stride_bytes() + x * 4) as usize;
        assert_eq!(a[o..o + 4], ab[o..o + 4]);
    }
    let (dx, dy) = REFERENCE_PROBES[5];
    let o = (dy * layout.stride_bytes() + dx * 4) as usize;
    assert_eq!(a[o..o + 4], ab[o..o + 4]);
}

#[test]
fn text_a_popcount() {
    let g = SPLEEN_8X16.glyph('A');
    let expected = g.rows.iter().map(|b| b.count_ones()).sum::<u32>();
    let layout = layout_xrgb(16, 16, 0);
    let mut bytes = vec![0u8; layout.byte_len()];
    Canvas::new(&mut bytes, layout).unwrap().draw_text(
        &SPLEEN_8X16,
        (0, 0),
        "A",
        Color::opaque(255, 255, 255),
    );
    let mut count = 0u32;
    for y in 0..16 {
        for x in 0..16 {
            let o = (y * 16 + x) as usize * 4;
            if bytes[o + 3] == 0xFF && bytes[o] == 255 {
                count += 1;
            }
        }
    }
    assert_eq!(count, expected);
}

#[test]
fn fuzz_random_ops_preserve_outside_clip() {
    let layout = layout_xrgb(37, 23, 17);
    let mut rng = XorShift32::new(0xDEAD_BEEF);
    for _ in 0..2_000 {
        let mut bytes = sentinel_buffer(37, 23, 17, 64);
        let snapshot = bytes.clone();
        let clip = rect_at(
            rng.range(37) as i32 - 5,
            rng.range(23) as i32 - 5,
            rng.range(37).max(1),
            rng.range(23).max(1),
        );
        let mut c = Canvas::new(&mut bytes, layout).unwrap();
        let mut sub = c.with_clip(clip);
        match rng.next() % 7 {
            0 => sub.fill_rect(
                rect_at(rng.range(40) as i32 - 10, rng.range(30) as i32 - 10, 5, 5),
                Color::opaque(1, 2, 3),
            ),
            1 => sub.blend_rect(rect_at(0, 0, 10, 10), Color::from_straight(4, 5, 6, 100)),
            2 => sub.line(
                (rng.range(37) as i32, rng.range(23) as i32),
                (rng.range(37) as i32, rng.range(23) as i32),
                Color::opaque(1, 1, 1),
            ),
            3 => {
                let mask = [255u8; 16];
                sub.fill_mask(&mask, 4, 4, (2, 2), Color::opaque(2, 3, 4));
            }
            4 => {
                let src = vec![0xFFu8; 64];
                let _ = sub.blit(
                    &src,
                    BufferLayout::new(4, 4, 16, PixelFormat::Xrgb8888).unwrap(),
                    rect_at(0, 0, 4, 4),
                    (1, 1),
                    BlitMode::Over,
                );
            }
            5 => {
                sub.draw_text(
                    &SPLEEN_8X16,
                    (rng.range(10) as i32, rng.range(10) as i32),
                    "X",
                    Color::opaque(1, 2, 3),
                );
            }
            _ => sub.stroke_rect(rect_at(3, 3, 10, 10), 1, Color::opaque(9, 9, 9)),
        }
        for (i, (&a, &b)) in bytes.iter().zip(snapshot.iter()).enumerate() {
            if !pixel_in_clip(i, layout, clip) {
                assert_eq!(a, b, "byte {i}");
            }
        }
    }
}

fn pixel_in_clip(i: usize, layout: BufferLayout, clip: Rect) -> bool {
    let stride = layout.stride_bytes() as usize;
    let row = i / stride;
    let col = i % stride;
    if col >= layout.width() as usize * 4 {
        return false;
    }
    let x = (col / 4) as i32;
    let y = row as i32;
    x >= clip.x && y >= clip.y && x < clip.x + clip.width as i32 && y < clip.y + clip.height as i32
}
