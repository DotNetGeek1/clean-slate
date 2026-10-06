//! Renders the M10 reference desktop at Q0 and Q1 to PNG for design review.
//!
//! ```text
//! cargo run -p clean-slate-ui --example render_reference -- [OUTPUT_DIR]
//! ```
//!
//! The default output directory is `target/ui-reference`; the committed copies live in
//! `docs/design/`. CI never compares these files: structural checks use
//! `clean_slate_ui::reference::probes`.

use std::path::PathBuf;

use clean_slate_raster::{Canvas, Crc32};
use clean_slate_ui::{reference, QualityTier, CLEAN_SLATE_DARK};

fn main() -> std::io::Result<()> {
    let dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target/ui-reference"));
    std::fs::create_dir_all(&dir)?;
    for (tier, name) in [
        (QualityTier::Q0, "m10-shell-reference-q0.png"),
        (QualityTier::Q1, "m10-shell-reference-q1.png"),
    ] {
        let layout = clean_slate_raster::reference_layout();
        let mut bytes = vec![0u8; layout.byte_len()];
        let mut canvas = Canvas::new(&mut bytes, layout).expect("reference layout");
        reference::render(&mut canvas, &CLEAN_SLATE_DARK, tier);
        let rgb = bgrx_rows_to_rgb(
            &bytes,
            layout.width(),
            layout.height(),
            layout.stride_bytes(),
        );
        let path = dir.join(name);
        std::fs::write(&path, encode_png(layout.width(), layout.height(), &rgb))?;
        println!("wrote {}", path.display());
    }
    Ok(())
}

fn bgrx_rows_to_rgb(bytes: &[u8], width: u32, height: u32, stride: u32) -> Vec<u8> {
    let mut rgb = Vec::with_capacity((width * height * 3) as usize);
    for y in 0..height as usize {
        let row = &bytes[y * stride as usize..][..width as usize * 4];
        for px in row.chunks_exact(4) {
            rgb.extend_from_slice(&[px[2], px[1], px[0]]);
        }
    }
    rgb
}

fn encode_png(width: u32, height: u32, rgb: &[u8]) -> Vec<u8> {
    let row = width as usize * 3;
    let mut filtered = Vec::with_capacity((row + 1) * height as usize);
    for line in rgb.chunks_exact(row) {
        filtered.push(1); // Sub
        for i in 0..row {
            let left = if i >= 3 { line[i - 3] } else { 0 };
            filtered.push(line[i].wrapping_sub(left));
        }
    }
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);

    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &zlib(&filtered));
    chunk(&mut out, b"IEND", &[]);
    out
}

fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let mut crc = Crc32::new();
    crc.update(kind);
    crc.update(data);
    out.extend_from_slice(&crc.finish().to_be_bytes());
}

/// zlib stream with one fixed-Huffman block using only distance-1 matches (run lengths).
fn zlib(data: &[u8]) -> Vec<u8> {
    let mut bits = BitWriter::default();
    bits.out.extend_from_slice(&[0x78, 0x01]);
    bits.put(1, 1);
    bits.put(1, 2);
    let mut i = 0;
    while i < data.len() {
        let run = if i > 0 {
            data[i..]
                .iter()
                .take(258)
                .take_while(|&&b| b == data[i - 1])
                .count()
        } else {
            0
        };
        if run >= 3 {
            bits.length(run);
            bits.huffman(0, 5);
            i += run;
        } else {
            bits.literal(data[i]);
            i += 1;
        }
    }
    bits.symbol(256);
    let mut out = bits.finish();
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

const LEN_BASE: [usize; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u32; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

#[derive(Default)]
struct BitWriter {
    out: Vec<u8>,
    acc: u64,
    n: u32,
}

impl BitWriter {
    fn put(&mut self, value: u32, bits: u32) {
        self.acc |= u64::from(value) << self.n;
        self.n += bits;
        while self.n >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.n -= 8;
        }
    }

    fn huffman(&mut self, code: u32, len: u32) {
        let reversed = code.reverse_bits() >> (32 - len);
        self.put(reversed, len);
    }

    fn symbol(&mut self, sym: u32) {
        match sym {
            0..=143 => self.huffman(0x30 + sym, 8),
            144..=255 => self.huffman(0x190 + sym - 144, 9),
            256..=279 => self.huffman(sym - 256, 7),
            _ => self.huffman(0xC0 + sym - 280, 8),
        }
    }

    fn literal(&mut self, byte: u8) {
        self.symbol(u32::from(byte));
    }

    fn length(&mut self, len: usize) {
        let idx = LEN_BASE.iter().rposition(|&b| b <= len).expect("len >= 3");
        self.symbol(257 + idx as u32);
        if LEN_EXTRA[idx] > 0 {
            self.put((len - LEN_BASE[idx]) as u32, LEN_EXTRA[idx]);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.n > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}
