//! Premultiplied B,G,R,A colours for raster operations.

use clean_slate_graphics::pixel::div255;

/// Premultiplied pixel bytes in B, G, R, A order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Color(pub [u8; 4]);

impl Color {
    /// Opaque sRGB channels with A = 255.
    pub const fn opaque(r: u8, g: u8, b: u8) -> Self {
        Self([b, g, r, 255])
    }

    /// Straight sRGB inputs premultiplied with [`div255`].
    pub const fn from_straight(r: u8, g: u8, b: u8, a: u8) -> Self {
        if a == 0 {
            return Self([0, 0, 0, 0]);
        }
        if a == 255 {
            return Self::opaque(r, g, b);
        }
        let a16 = a as u16;
        Self([
            div255(b as u16 * a16) as u8,
            div255(g as u16 * a16) as u8,
            div255(r as u16 * a16) as u8,
            a,
        ])
    }
}
