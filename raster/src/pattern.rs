//! Shared deterministic renders and CRC helpers for guest/host parity.

use clean_slate_graphics::mode::REFERENCE_MODE;
use clean_slate_graphics::{BufferLayout, Rect};

use crate::canvas::Canvas;
use crate::color::Color;
use crate::font::SPLEEN_8X16;

/// Damage rects for [`draw_reference_b`].
pub const REFERENCE_B_DAMAGE: [Rect; 3] = [
    Rect {
        x: 100,
        y: 100,
        width: 64,
        height: 48,
    },
    Rect {
        x: 600,
        y: 500,
        width: 32,
        height: 32,
    },
    Rect {
        x: 1100,
        y: 650,
        width: 80,
        height: 40,
    },
];

/// Off-screen decoy region (drawn but not presented in the guest test).
pub const REFERENCE_DECOY: Rect = Rect {
    x: 300,
    y: 600,
    width: 40,
    height: 40,
};

/// Probe coordinates for parity checks (B rects, A-only, decoy).
pub const REFERENCE_PROBES: [(u32, u32); 6] = [
    (120, 120),
    (610, 510),
    (1140, 670),
    (80, 400),
    (640, 400),
    (320, 620),
];

/// Reference 1280×800 colour bars, blend band, border, diagonal, and title.
pub fn draw_reference_a(canvas: &mut Canvas<'_>) {
    let h = canvas.layout().height();
    let bar_w = 160u32;
    let colors = [
        Color::opaque(255, 0, 0),
        Color::opaque(0, 255, 0),
        Color::opaque(0, 0, 255),
        Color::opaque(255, 255, 255),
        Color::opaque(0, 0, 0),
        Color::opaque(0, 255, 255),
        Color::opaque(255, 0, 255),
        Color::opaque(255, 255, 0),
    ];
    for (i, &c) in colors.iter().enumerate() {
        canvas.fill_rect(
            Rect {
                x: (i as i32) * bar_w as i32,
                y: 0,
                width: bar_w,
                height: h,
            },
            c,
        );
    }
    canvas.blend_rect(
        Rect {
            x: 0,
            y: 320,
            width: 1280,
            height: 160,
        },
        Color::from_straight(255, 255, 255, 128),
    );
    canvas.stroke_rect(
        Rect {
            x: 0,
            y: 0,
            width: 1280,
            height: 800,
        },
        2,
        Color::opaque(128, 128, 128),
    );
    canvas.line((0, 799), (1279, 0), Color::opaque(255, 128, 0));
    canvas.draw_text(
        &SPLEEN_8X16,
        (16, 16),
        "CLEAN-SLATE M10 GOP",
        Color::opaque(255, 255, 255),
    );
}

/// Fills and strokes only inside [`REFERENCE_B_DAMAGE`].
pub fn draw_reference_b(canvas: &mut Canvas<'_>) {
    let fills = [
        Color::opaque(17, 34, 51),
        Color::opaque(68, 85, 102),
        Color::opaque(119, 136, 153),
    ];
    for (i, &rect) in REFERENCE_B_DAMAGE.iter().enumerate() {
        let mut sub = canvas.with_clip(rect);
        sub.fill_rect(rect, fills[i]);
        sub.stroke_rect(rect, 1, Color::opaque(250, 250, 250));
    }
}

/// Writes the decoy patch only.
pub fn draw_reference_decoy(canvas: &mut Canvas<'_>) {
    canvas.fill_rect(REFERENCE_DECOY, Color::opaque(1, 2, 3));
}

/// IEEE 802.3 CRC-32 (reflected, poly `0xEDB88320`).
#[derive(Clone, Copy, Debug, Default)]
pub struct Crc32 {
    state: u32,
}

impl Crc32 {
    /// Initial value `0xFFFFFFFF`.
    pub const fn new() -> Self {
        Self { state: 0xFFFF_FFFF }
    }

    /// Absorb bytes.
    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            self.state ^= u32::from(byte);
            for _ in 0..8 {
                if self.state & 1 != 0 {
                    self.state = (self.state >> 1) ^ 0xEDB8_8320;
                } else {
                    self.state >>= 1;
                }
            }
        }
    }

    /// Final XOR `0xFFFFFFFF`.
    pub fn finish(self) -> u32 {
        self.state ^ 0xFFFF_FFFF
    }
}

/// CRC over visible pixels (stride padding excluded).
pub fn visible_crc32(bytes: &[u8], layout: BufferLayout) -> Option<u32> {
    if !layout.fits_in(bytes.len() as u64) {
        return None;
    }
    let row_bytes = (layout.width() * 4) as usize;
    let stride = layout.stride_bytes() as usize;
    let mut crc = Crc32::new();
    for row in 0..layout.height() as usize {
        let start = row * stride;
        let end = start + row_bytes;
        if end > bytes.len() {
            return None;
        }
        crc.update(&bytes[start..end]);
    }
    Some(crc.finish())
}

/// Reads one pixel in B,G,R,X/A order.
pub fn pixel_at(bytes: &[u8], layout: BufferLayout, x: u32, y: u32) -> Option<[u8; 4]> {
    if !layout.fits_in(bytes.len() as u64) || x >= layout.width() || y >= layout.height() {
        return None;
    }
    let stride = layout.stride_bytes() as usize;
    let off = y as usize * stride + x as usize * 4;
    if off + 4 > bytes.len() {
        return None;
    }
    Some([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

/// Reference layout matching [`REFERENCE_MODE`].
pub fn reference_layout() -> BufferLayout {
    BufferLayout::new(
        REFERENCE_MODE.width_px,
        REFERENCE_MODE.height_px,
        REFERENCE_MODE.stride_bytes,
        REFERENCE_MODE.format,
    )
    .expect("reference layout valid")
}
