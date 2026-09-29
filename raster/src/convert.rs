//! In-place channel order swaps for packed 32-bit pixels.

/// Swaps B and R per pixel; byte 3 set to `0xFF`. No-op if either slice length is not a multiple of 4.
pub fn bgrx_to_rgbx(src: &[u8], dst: &mut [u8]) {
    convert(src, dst);
}

/// Swaps B and R per pixel; byte 3 set to `0xFF`. No-op if either slice length is not a multiple of 4.
pub fn rgbx_to_bgrx(src: &[u8], dst: &mut [u8]) {
    convert(src, dst);
}

fn convert(src: &[u8], dst: &mut [u8]) {
    if src.len() % 4 != 0 || dst.len() % 4 != 0 {
        return;
    }
    let pixels = src.len().min(dst.len()) / 4;
    for i in 0..pixels {
        let s = i * 4;
        let d = i * 4;
        dst[d] = src[s + 2];
        dst[d + 1] = src[s + 1];
        dst[d + 2] = src[s];
        dst[d + 3] = 0xFF;
    }
}
