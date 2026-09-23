//! Host-only deterministic packer.

extern crate alloc;

use alloc::vec::Vec;

use super::manifest::{Manifest, ManifestKind};
use super::{
    crc32, RootfsError, DATA_ALIGN, ENTRY_SIZE, FLAG_WRITABLE_ROOT, HEADER_SIZE, KIND_DIR,
    KIND_FILE, KIND_LINK, MAGIC, MAX_ENTRIES, MAX_IMAGE_BYTES, MAX_PATH_BYTES, VERSION,
};
use std::collections::BTreeMap;
use std::path::Path;

struct PackedEntry {
    path: Vec<u8>,
    kind: u8,
    flags: u8,
    data: Vec<u8>,
}

pub fn pack(
    manifest: &Manifest,
    mut resolve_file: impl FnMut(&Path) -> std::io::Result<Vec<u8>>,
) -> Result<Vec<u8>, RootfsError> {
    if manifest.version != VERSION {
        return Err(RootfsError::BadVersion);
    }
    let mut map: BTreeMap<Vec<u8>, PackedEntry> = BTreeMap::new();
    map.insert(
        b"/".to_vec(),
        PackedEntry {
            path: b"/".to_vec(),
            kind: KIND_DIR,
            flags: 0,
            data: Vec::new(),
        },
    );

    for entry in &manifest.entries {
        if entry.path == b"/" {
            if let Some(slot) = map.get_mut(b"/".as_slice()) {
                if entry.writable {
                    slot.flags |= FLAG_WRITABLE_ROOT;
                }
            }
            continue;
        }
        if entry.path.len() > MAX_PATH_BYTES {
            return Err(RootfsError::PathTooLong);
        }
        if !entry.path.starts_with(b"/") {
            return Err(RootfsError::BadPath);
        }
        let (kind, data) = match entry.kind {
            ManifestKind::Dir => (KIND_DIR, Vec::new()),
            ManifestKind::File => {
                let bytes = if let Some(inline) = &entry.inline {
                    inline.clone()
                } else if let Some(source) = &entry.source {
                    let path = Path::new(source);
                    let file_bytes =
                        resolve_file(path).map_err(|_| RootfsError::DataOutOfBounds)?;
                    if let Some(expected) = &entry.sha256 {
                        let actual = hex_sha256(&file_bytes);
                        if actual != *expected {
                            return Err(RootfsError::DataOutOfBounds);
                        }
                    }
                    file_bytes
                } else {
                    return Err(RootfsError::BadPath);
                };
                (KIND_FILE, bytes)
            }
            ManifestKind::Link => {
                let target = entry.target.clone().ok_or(RootfsError::BadPath)?;
                (KIND_LINK, target)
            }
        };
        let flags = if entry.writable {
            if entry.path != b"/tmp" {
                return Err(RootfsError::BadPath);
            }
            FLAG_WRITABLE_ROOT
        } else {
            0
        };
        if map.contains_key(&entry.path) {
            return Err(RootfsError::DuplicatePath);
        }
        map.insert(
            entry.path.clone(),
            PackedEntry {
                path: entry.path.clone(),
                kind,
                flags,
                data,
            },
        );
    }

    if map.len() > MAX_ENTRIES {
        return Err(RootfsError::EntryCountOutOfRange);
    }

    let entry_count = map.len();
    let entries_offset = HEADER_SIZE;
    let mut data_blob = Vec::new();
    let mut entry_records = Vec::with_capacity(entry_count);

    for (_, ent) in map.iter() {
        let (data_offset, data_len) = if ent.kind == KIND_DIR {
            (0u32, 0u32)
        } else {
            let offset = align_up(data_blob.len(), DATA_ALIGN);
            while data_blob.len() < offset {
                data_blob.push(0);
            }
            let data_offset = offset as u32;
            data_blob.extend_from_slice(&ent.data);
            (data_offset, ent.data.len() as u32)
        };
        entry_records.push((ent, data_offset, data_len));
    }

    let data_offset = entries_offset + entry_count * ENTRY_SIZE;
    let data_len = data_blob.len();
    let total = data_offset + data_len;
    if total > MAX_IMAGE_BYTES {
        return Err(RootfsError::ImageTooLarge);
    }

    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(entry_count as u16).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(entries_offset as u32).to_le_bytes());
    out.extend_from_slice(&(data_offset as u32).to_le_bytes());
    out.extend_from_slice(&(data_len as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    let crc = crc32(&out[..28]);
    out[28..32].copy_from_slice(&crc.to_le_bytes());

    for (ent, data_off, data_len) in entry_records {
        let mut rec = [0u8; ENTRY_SIZE];
        rec[0] = ent.kind;
        rec[1] = ent.flags;
        rec[2] = ent.path.len() as u8;
        rec[4..8].copy_from_slice(&data_off.to_le_bytes());
        rec[8..12].copy_from_slice(&data_len.to_le_bytes());
        let copy_len = ent.path.len().min(MAX_PATH_BYTES);
        rec[12..12 + copy_len].copy_from_slice(&ent.path[..copy_len]);
        out.extend_from_slice(&rec);
    }
    out.extend_from_slice(&data_blob);
    Ok(out)
}

fn align_up(value: usize, align: usize) -> usize {
    value.div_ceil(align) * align
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = sha256(bytes);
    let mut hex = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(hex, "{:02x}", b);
    }
    hex
}

fn sha256(data: &[u8]) -> [u8; 32] {
    // Minimal SHA-256 (same structure as xtask m8_fixture).
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            let j = i * 4;
            *word = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}
