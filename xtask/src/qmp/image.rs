//! `screendump` PPM parsing and PNG encoding without external tools.

pub(crate) const MAX_DIMENSION: u32 = 8192;
pub(crate) const MAX_RGB_BYTES: usize = 192 * 1024 * 1024;
/// Largest PPM file accepted: pixel bytes plus a generous header allowance.
pub(crate) const MAX_PPM_FILE_BYTES: usize = MAX_RGB_BYTES + 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Screenshot {
    width: u32,
    height: u32,
    rgb: Vec<u8>,
}

impl Screenshot {
    pub(crate) fn new(width: u32, height: u32, rgb: Vec<u8>) -> Result<Self, ImageError> {
        if width == 0 || height == 0 {
            return Err(ImageError::DimensionsOutOfRange {
                width: u64::from(width),
                height: u64::from(height),
            });
        }
        if width > MAX_DIMENSION || height > MAX_DIMENSION {
            return Err(ImageError::DimensionsOutOfRange {
                width: u64::from(width),
                height: u64::from(height),
            });
        }
        let expected = pixel_byte_len(width, height)?;
        if rgb.len() != expected {
            return Err(ImageError::LengthMismatch {
                expected,
                actual: rgb.len(),
            });
        }
        Ok(Self { width, height, rgb })
    }

    pub(crate) fn width(&self) -> u32 {
        self.width
    }

    pub(crate) fn height(&self) -> u32 {
        self.height
    }

    /// Row-major RGB, three bytes per pixel.
    pub(crate) fn rgb(&self) -> &[u8] {
        &self.rgb
    }

    pub(crate) fn pixel(&self, x: u32, y: u32) -> Option<[u8; 3]> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let idx = (y as usize * self.width as usize + x as usize) * 3;
        Some([self.rgb[idx], self.rgb[idx + 1], self.rgb[idx + 2]])
    }

    pub(crate) fn encode_png(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

        let mut ihdr = Vec::with_capacity(13);
        ihdr.extend_from_slice(&self.width.to_be_bytes());
        ihdr.extend_from_slice(&self.height.to_be_bytes());
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
        write_chunk(&mut out, b"IHDR", &ihdr);

        let idat = build_idat(&self.rgb, self.width, self.height);
        write_chunk(&mut out, b"IDAT", &idat);

        write_chunk(&mut out, b"IEND", &[]);
        out
    }

    pub(crate) fn write_png(&self, path: &std::path::Path) -> std::io::Result<()> {
        std::fs::write(path, self.encode_png())
    }
}

fn pixel_byte_len(width: u32, height: u32) -> Result<usize, ImageError> {
    let w = u64::from(width);
    let h = u64::from(height);
    let pixels = w.checked_mul(h).ok_or(ImageError::DimensionsOutOfRange {
        width: w,
        height: h,
    })?;
    let bytes = pixels
        .checked_mul(3)
        .ok_or(ImageError::DimensionsOutOfRange {
            width: w,
            height: h,
        })?;
    if bytes > MAX_RGB_BYTES as u64 {
        return Err(ImageError::DimensionsOutOfRange {
            width: w,
            height: h,
        });
    }
    Ok(bytes as usize)
}

fn write_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut crc_input = [0u8; 4];
    crc_input.copy_from_slice(kind);
    let crc = crc32_update(0, &crc_input);
    let crc = crc32_update(crc, data);
    out.extend_from_slice(&crc.to_be_bytes());
}

fn build_idat(rgb: &[u8], width: u32, height: u32) -> Vec<u8> {
    let row_len = 1 + width as usize * 3;
    let mut raw = Vec::with_capacity(height as usize * row_len);
    let mut off = 0usize;
    for _ in 0..height {
        raw.push(0);
        let end = off + width as usize * 3;
        raw.extend_from_slice(&rgb[off..end]);
        off = end;
    }
    let mut zlib = Vec::new();
    zlib.extend_from_slice(&[0x78, 0x01]);
    append_stored_blocks_full(&mut zlib, &raw);
    zlib
}

fn append_stored_blocks_full(zlib: &mut Vec<u8>, raw: &[u8]) {
    let mut pos = 0usize;
    while pos < raw.len() {
        let chunk = (raw.len() - pos).min(65535);
        let final_block = pos + chunk == raw.len();
        zlib.push(if final_block { 0x01 } else { 0x00 });
        let len = chunk as u16;
        zlib.extend_from_slice(&len.to_le_bytes());
        zlib.extend_from_slice(&(!len).to_le_bytes());
        zlib.extend_from_slice(&raw[pos..pos + chunk]);
        pos += chunk;
    }
    let adler = adler32(raw);
    zlib.extend_from_slice(&adler.to_be_bytes());
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ImageError {
    BadMagic,
    BadHeader(&'static str),
    UnsupportedMaxval(u32),
    DimensionsOutOfRange { width: u64, height: u64 },
    Truncated { expected: usize, actual: usize },
    TrailingData { extra: usize },
    TooLarge { limit: usize },
    LengthMismatch { expected: usize, actual: usize },
}

impl std::fmt::Display for ImageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImageError::BadMagic => write!(f, "bad PPM magic"),
            ImageError::BadHeader(msg) => write!(f, "bad PPM header: {msg}"),
            ImageError::UnsupportedMaxval(v) => write!(f, "unsupported maxval {v}"),
            ImageError::DimensionsOutOfRange { width, height } => {
                write!(f, "dimensions out of range: {width}x{height}")
            }
            ImageError::Truncated { expected, actual } => {
                write!(
                    f,
                    "truncated pixel data: expected {expected} bytes, got {actual}"
                )
            }
            ImageError::TrailingData { extra } => {
                write!(f, "trailing pixel data: {extra} extra bytes")
            }
            ImageError::TooLarge { limit } => write!(f, "PPM file too large (limit {limit})"),
            ImageError::LengthMismatch { expected, actual } => {
                write!(f, "RGB length mismatch: expected {expected}, got {actual}")
            }
        }
    }
}

pub(crate) fn parse_ppm(bytes: &[u8]) -> Result<Screenshot, ImageError> {
    if bytes.len() < 2 || &bytes[0..2] != b"P6" {
        return Err(ImageError::BadMagic);
    }
    let mut i = 2usize;
    let width = read_ppm_token(bytes, &mut i)?;
    let height = read_ppm_token(bytes, &mut i)?;
    let maxval = read_ppm_token(bytes, &mut i)?;

    if i >= bytes.len() {
        return Err(ImageError::BadHeader("missing separator after maxval"));
    }
    if !is_ppm_ws_byte(bytes[i]) {
        return Err(ImageError::BadHeader("missing separator after maxval"));
    }
    let data_start = i + 1;
    if data_start > 4096 {
        return Err(ImageError::BadHeader("header too long"));
    }

    if maxval != 255 {
        return Err(ImageError::UnsupportedMaxval(
            u32::try_from(maxval).unwrap_or(u32::MAX),
        ));
    }

    if width == 0 || height == 0 {
        return Err(ImageError::DimensionsOutOfRange { width, height });
    }
    if width > u64::from(MAX_DIMENSION) || height > u64::from(MAX_DIMENSION) {
        return Err(ImageError::DimensionsOutOfRange { width, height });
    }

    let expected = match width.checked_mul(height).and_then(|p| p.checked_mul(3)) {
        Some(n) if n <= MAX_RGB_BYTES as u64 => n as usize,
        _ => {
            return Err(ImageError::DimensionsOutOfRange { width, height });
        }
    };

    let available = bytes.len().saturating_sub(data_start);
    if available < expected {
        return Err(ImageError::Truncated {
            expected,
            actual: available,
        });
    }
    if available > expected {
        return Err(ImageError::TrailingData {
            extra: available - expected,
        });
    }

    let rgb = bytes[data_start..data_start + expected].to_vec();
    Screenshot::new(width as u32, height as u32, rgb)
}

fn is_ppm_ws_byte(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn skip_ppm_ws(bytes: &[u8], i: &mut usize) -> Result<(), ImageError> {
    if *i > 4096 {
        return Err(ImageError::BadHeader("header too long"));
    }
    while *i < bytes.len() {
        if *i >= 4096 {
            return Err(ImageError::BadHeader("header too long"));
        }
        let b = bytes[*i];
        if is_ppm_ws_byte(b) {
            *i += 1;
            continue;
        }
        if b == b'#' {
            *i += 1;
            while *i < bytes.len() && bytes[*i] != b'\n' && bytes[*i] != b'\r' {
                *i += 1;
            }
            continue;
        }
        return Ok(());
    }
    Err(ImageError::BadHeader("missing token"))
}

fn read_ppm_token(bytes: &[u8], i: &mut usize) -> Result<u64, ImageError> {
    if !bytes
        .get(*i)
        .is_some_and(|&b| is_ppm_ws_byte(b) || b == b'#')
    {
        return Err(ImageError::BadHeader("missing separator before token"));
    }
    skip_ppm_ws(bytes, i)?;
    if *i >= bytes.len() {
        return Err(ImageError::BadHeader("missing token"));
    }
    if !bytes[*i].is_ascii_digit() {
        return Err(ImageError::BadHeader("non-digit in dimension"));
    }
    let start = *i;
    let mut value: u64 = 0;
    while *i < bytes.len() && bytes[*i].is_ascii_digit() {
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(bytes[*i] - b'0')))
            .ok_or(ImageError::BadHeader("dimension overflow"))?;
        *i += 1;
    }
    if *i == start {
        return Err(ImageError::BadHeader("missing token"));
    }
    Ok(value)
}

const CRC32_TABLE: [u32; 256] = build_crc32_table();

const fn build_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut n = 0usize;
    while n < 256 {
        let mut crc = n as u32;
        let mut bit = 0;
        while bit < 8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
            bit += 1;
        }
        table[n] = crc;
        n += 1;
    }
    table
}

pub(crate) fn crc32_update(crc: u32, bytes: &[u8]) -> u32 {
    let mut state = crc ^ 0xFFFF_FFFF;
    for &b in bytes {
        let idx = ((state ^ u32::from(b)) & 0xFF) as usize;
        state = (state >> 8) ^ CRC32_TABLE[idx];
    }
    state ^ 0xFFFF_FFFF
}

#[cfg(test)]
pub(crate) fn crc32(bytes: &[u8]) -> u32 {
    crc32_update(0, bytes)
}

pub(crate) fn adler32(bytes: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    let mut off = 0usize;
    while off < bytes.len() {
        let end = (off + 5552).min(bytes.len());
        for &byte in &bytes[off..end] {
            a = (a + u32::from(byte)) % MOD;
            b = (b + a) % MOD;
        }
        off = end;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_vectors() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        let a = b"123";
        let b = b"456789";
        assert_eq!(crc32_update(crc32_update(0, a), b), crc32(b"123456789"));
    }

    #[test]
    fn adler32_vectors() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        let buf = vec![0xFFu8; 1024 * 1024];
        let naive = naive_adler(&buf);
        assert_eq!(adler32(&buf), naive);
    }

    fn naive_adler(data: &[u8]) -> u32 {
        const MOD: u32 = 65521;
        let mut a: u32 = 1;
        let mut b: u32 = 0;
        for &byte in data {
            a = (a + u32::from(byte)) % MOD;
            b = (b + a) % MOD;
        }
        (b << 16) | a
    }

    #[test]
    fn png_one_by_one_red_layout() {
        let img = Screenshot::new(1, 1, vec![255, 0, 0]).unwrap();
        let png = img.encode_png();
        assert_eq!(
            &png[0..8],
            &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
        );
        assert_eq!(&png[8..12], &[0, 0, 0, 13]);
        assert_eq!(&png[12..16], b"IHDR");
        assert_eq!(&png[29..33], &[0x90, 0x77, 0x53, 0xDE]);
        let idat_len = u32::from_be_bytes(png[33..37].try_into().unwrap()) as usize;
        assert_eq!(&png[37..41], b"IDAT");
        let idat = &png[41..41 + idat_len];
        assert_eq!(
            idat,
            &[
                0x78, 0x01, 0x01, 0x04, 0x00, 0xFB, 0xFF, 0x00, 0xFF, 0x00, 0x00, 0x03, 0x01, 0x01,
                0x00
            ]
        );
        assert_eq!(adler32(&[0, 255, 0, 0]), 0x0301_0100);
        assert_eq!(
            &png[png.len() - 12..],
            &[0, 0, 0, 0, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]
        );
    }

    #[test]
    fn png_round_trip() {
        for (w, h) in [(1, 1), (300, 1), (200, 120)] {
            let rgb = pattern_rgb(w, h);
            let img = Screenshot::new(w, h, rgb.clone()).unwrap();
            let png = img.encode_png();
            let (dw, dh, drgb, blocks) = decode_test_png(&png).unwrap();
            assert_eq!((dw, dh), (w, h));
            assert_eq!(drgb, rgb);
            if w == 200 && h == 120 {
                assert!(blocks >= 2);
            }
        }
    }

    fn pattern_rgb(w: u32, h: u32) -> Vec<u8> {
        let mut rgb = Vec::with_capacity((w * h * 3) as usize);
        for y in 0..h {
            for x in 0..w {
                rgb.push((x.wrapping_mul(3).wrapping_add(y)) as u8);
                rgb.push((x.wrapping_add(y.wrapping_mul(2))) as u8);
                rgb.push((x ^ y) as u8);
            }
        }
        rgb
    }

    fn decode_test_png(data: &[u8]) -> Result<(u32, u32, Vec<u8>, usize), String> {
        if data.len() < 8 || data[0..8] != [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
            return Err("bad signature".into());
        }
        let mut pos = 8usize;
        let mut width = 0u32;
        let mut height = 0u32;
        let mut idat = Vec::new();
        while pos + 12 <= data.len() {
            let len = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let kind = &data[pos..pos + 4];
            pos += 4;
            let chunk_data = &data[pos..pos + len];
            pos += len;
            let crc_bytes = &data[pos..pos + 4];
            pos += 4;
            let mut crc_in = Vec::with_capacity(4 + len);
            crc_in.extend_from_slice(kind);
            crc_in.extend_from_slice(chunk_data);
            if crc32(&crc_in) != u32::from_be_bytes(crc_bytes.try_into().unwrap()) {
                return Err("chunk crc".into());
            }
            if kind == b"IHDR" {
                width = u32::from_be_bytes(chunk_data[0..4].try_into().unwrap());
                height = u32::from_be_bytes(chunk_data[4..8].try_into().unwrap());
            } else if kind == b"IDAT" {
                idat.extend_from_slice(chunk_data);
            } else if kind == b"IEND" {
                break;
            }
        }
        if idat.len() < 2 || idat[0] != 0x78 || idat[1] != 0x01 {
            return Err("zlib header".into());
        }
        let (raw, blocks) = inflate_stored(&idat[2..])?;
        let row = 1 + width as usize * 3;
        if raw.len() != height as usize * row {
            return Err("raw len".into());
        }
        let mut rgb = Vec::with_capacity((width * height * 3) as usize);
        for y in 0..height as usize {
            let start = y * row;
            if raw[start] != 0 {
                return Err("filter".into());
            }
            rgb.extend_from_slice(&raw[start + 1..start + row]);
        }
        Ok((width, height, rgb, blocks))
    }

    fn inflate_stored(zlib: &[u8]) -> Result<(Vec<u8>, usize), String> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        let mut blocks = 0usize;
        while pos < zlib.len() {
            if pos + 5 > zlib.len() {
                return Err("truncated block".into());
            }
            let header = zlib[pos];
            pos += 1;
            let btype = (header >> 1) & 0b11;
            if btype != 0 {
                return Err("btype".into());
            }
            blocks += 1;
            let len = u16::from_le_bytes(zlib[pos..pos + 2].try_into().unwrap());
            pos += 2;
            let nlen = u16::from_le_bytes(zlib[pos..pos + 2].try_into().unwrap());
            pos += 2;
            if nlen != !len {
                return Err("nlen".into());
            }
            let end = pos + usize::from(len);
            if end > zlib.len() {
                return Err("block data".into());
            }
            out.extend_from_slice(&zlib[pos..end]);
            pos = end;
            if header & 1 != 0 {
                if pos + 4 > zlib.len() {
                    return Err("adler".into());
                }
                let adler = u32::from_be_bytes(zlib[pos..pos + 4].try_into().unwrap());
                if adler32(&out) != adler {
                    return Err("adler mismatch".into());
                }
                return Ok((out, blocks));
            }
        }
        Err("no final block".into())
    }

    #[test]
    fn parse_ppm_cases() {
        let mut minimal = b"P6\n2 1\n255\n".to_vec();
        minimal.extend_from_slice(&[255, 0, 0, 0, 255, 0]);
        let img = parse_ppm(&minimal).unwrap();
        assert_eq!(img.width(), 2);
        assert_eq!(img.height(), 1);

        let commented = b"P6\n# w\n2\t# h\n1\r\n255\n";
        let mut c = commented.to_vec();
        c.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        parse_ppm(&c).unwrap();

        assert_eq!(parse_ppm(b"P3").unwrap_err(), ImageError::BadMagic);
        assert_eq!(parse_ppm(b"P5").unwrap_err(), ImageError::BadMagic);
        assert_eq!(parse_ppm(b"").unwrap_err(), ImageError::BadMagic);

        let mut big = b"P6\n1 1\n65535\n".to_vec();
        big.extend_from_slice(&[0, 0, 0]);
        assert_eq!(
            parse_ppm(&big).unwrap_err(),
            ImageError::UnsupportedMaxval(65535)
        );

        let mut trunc = b"P6\n1 1\n255\n".to_vec();
        trunc.push(1);
        assert_eq!(
            parse_ppm(&trunc).unwrap_err(),
            ImageError::Truncated {
                expected: 3,
                actual: 1
            }
        );

        let mut extra = b"P6\n1 1\n255\n".to_vec();
        extra.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(
            parse_ppm(&extra).unwrap_err(),
            ImageError::TrailingData { extra: 1 }
        );

        assert!(matches!(
            parse_ppm(b"P6\n0 1\n255\n"),
            Err(ImageError::DimensionsOutOfRange { .. })
        ));
        assert!(matches!(
            parse_ppm(b"P6\n1 0\n255\n"),
            Err(ImageError::DimensionsOutOfRange { .. })
        ));
        assert!(matches!(
            parse_ppm(b"P6\n8193 1\n255\n"),
            Err(ImageError::DimensionsOutOfRange { .. })
        ));

        let huge = b"P6\n8192 8192\n255\n";
        assert_eq!(
            parse_ppm(huge).unwrap_err(),
            ImageError::Truncated {
                expected: 201_326_592,
                actual: 0
            }
        );

        let overflow = b"P6\n999999999999999999999 1\n255\n";
        assert!(matches!(
            parse_ppm(overflow),
            Err(ImageError::BadHeader("dimension overflow"))
        ));

        assert!(matches!(
            parse_ppm(b"P6\n1 1\n255"),
            Err(ImageError::BadHeader(_))
        ));
        assert_eq!(
            parse_ppm(b"P61 1\n255\n\0\0\0").unwrap_err(),
            ImageError::BadHeader("missing separator before token")
        );
        assert_eq!(
            parse_ppm(b"P6\n1 1\n4294967551\n\0\0\0").unwrap_err(),
            ImageError::UnsupportedMaxval(u32::MAX)
        );
    }

    #[test]
    fn screenshot_new_and_pixel() {
        assert!(Screenshot::new(0, 1, vec![]).is_err());
        assert!(Screenshot::new(1, 0, vec![]).is_err());
        assert!(matches!(
            Screenshot::new(1, 1, vec![1, 2]),
            Err(ImageError::LengthMismatch { .. })
        ));
        let rgb = vec![
            10, 20, 30, 40, 50, 60, 70, 80, 90, 110, 120, 130, 140, 150, 160, 170, 180, 190,
        ];
        let img = Screenshot::new(3, 2, rgb).unwrap();
        assert_eq!(img.pixel(0, 0), Some([10, 20, 30]));
        assert_eq!(img.pixel(2, 1), Some([170, 180, 190]));
        assert_eq!(img.pixel(3, 0), None);
        assert_eq!(img.pixel(0, 2), None);
    }
}
