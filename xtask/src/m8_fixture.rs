//! M8.6 Linux ELF fixture provenance checks (`cargo xtask verify-m8-fixture`).
//!
//! Owns a tiny checked-arithmetic ELF64 parser and a self-contained SHA-256
//! implementation so this lane does not depend on the unmerged `clean-slate-elf`
//! crate or on a new `sha2` dependency.

use std::fs;
use std::path::{Path, PathBuf};

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PT_DYNAMIC: u32 = 2;
const ELF64_EHDR_SIZE: usize = 64;
const ELF64_PHDR_SIZE: usize = 56;

/// Clean-Slate M8 private user VA window (PML4 slot 128).
const M8_USER_VA_LO: u64 = 0x0000_4000_0000_0000;
const M8_USER_VA_HI: u64 = 0x0000_4080_0000_0000;

/// Pinned fields from `fixtures/linux-hello/metadata.toml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct M8FixtureMetadata {
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub pt_load_count: usize,
    pub has_pt_interp: bool,
    pub has_pt_dynamic: bool,
    pub pt_loads: Vec<PtLoadMeta>,
    pub sha256_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PtLoadMeta {
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_flags: u32,
    pub p_align: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedElf {
    e_type: u16,
    e_machine: u16,
    ei_class: u8,
    ei_data: u8,
    e_entry: u64,
    e_phoff: u64,
    e_phentsize: u16,
    e_phnum: u16,
    has_pt_interp: bool,
    has_pt_dynamic: bool,
    pt_loads: Vec<PtLoadMeta>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PinnedMetadata {
    meta: M8FixtureMetadata,
    user_va_lo: u64,
    user_va_hi: u64,
}

/// Verify the committed M8 Linux hello fixture against hash + metadata pins.
pub fn verify_m8_fixture() -> Result<M8FixtureMetadata, String> {
    verify_m8_fixture_at(&fixture_dir())
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask in workspace")
        .join("fixtures")
        .join("linux-hello")
}

fn verify_m8_fixture_at(dir: &Path) -> Result<M8FixtureMetadata, String> {
    let binary_path = dir.join("hello-linux-x86_64");
    let hash_path = dir.join("hello-linux-x86_64.sha256");
    let meta_path = dir.join("metadata.toml");

    let bytes =
        fs::read(&binary_path).map_err(|e| format!("read {}: {e}", binary_path.display()))?;
    let expected_hash = fs::read_to_string(&hash_path)
        .map_err(|e| format!("read {}: {e}", hash_path.display()))?
        .split_whitespace()
        .next()
        .ok_or_else(|| format!("empty hash file {}", hash_path.display()))?
        .trim()
        .to_ascii_lowercase();

    let actual_hash = hex_encode(&sha256(&bytes));
    if actual_hash != expected_hash {
        return Err(format!(
            "SHA-256 mismatch for {}: expected {expected_hash}, got {actual_hash}",
            binary_path.display()
        ));
    }

    let pinned = parse_metadata_toml(
        &fs::read_to_string(&meta_path)
            .map_err(|e| format!("read {}: {e}", meta_path.display()))?,
    )?;
    let parsed = parse_elf64(&bytes)?;

    assert_eq_field("ei_class", parsed.ei_class, ELFCLASS64)?;
    assert_eq_field("ei_data", parsed.ei_data, ELFDATA2LSB)?;
    assert_eq_field("e_type", parsed.e_type, ET_EXEC)?;
    assert_eq_field("e_machine", parsed.e_machine, EM_X86_64)?;
    assert_eq_field("e_entry", parsed.e_entry, pinned.meta.e_entry)?;
    assert_eq_field("e_phoff", parsed.e_phoff, pinned.meta.e_phoff)?;
    assert_eq_field("e_phentsize", parsed.e_phentsize, pinned.meta.e_phentsize)?;
    assert_eq_field("e_phnum", parsed.e_phnum, pinned.meta.e_phnum)?;
    assert_eq_field(
        "pt_load_count",
        parsed.pt_loads.len(),
        pinned.meta.pt_load_count,
    )?;
    assert_eq_field(
        "has_pt_interp",
        parsed.has_pt_interp,
        pinned.meta.has_pt_interp,
    )?;
    assert_eq_field(
        "has_pt_dynamic",
        parsed.has_pt_dynamic,
        pinned.meta.has_pt_dynamic,
    )?;
    assert_eq_field("user_va_lo", pinned.user_va_lo, M8_USER_VA_LO)?;
    assert_eq_field("user_va_hi", pinned.user_va_hi, M8_USER_VA_HI)?;

    if parsed.pt_loads != pinned.meta.pt_loads {
        return Err(format!(
            "PT_LOAD table mismatch: parsed={:?} pinned={:?}",
            parsed.pt_loads, pinned.meta.pt_loads
        ));
    }

    assert_loads_in_user_window(&parsed.pt_loads, pinned.user_va_lo, pinned.user_va_hi)?;
    assert_phdr_table_in_pt_load(
        parsed.e_phoff,
        parsed.e_phentsize,
        parsed.e_phnum,
        &parsed.pt_loads,
    )?;

    Ok(M8FixtureMetadata {
        e_entry: parsed.e_entry,
        e_phoff: parsed.e_phoff,
        e_phentsize: parsed.e_phentsize,
        e_phnum: parsed.e_phnum,
        pt_load_count: parsed.pt_loads.len(),
        has_pt_interp: parsed.has_pt_interp,
        has_pt_dynamic: parsed.has_pt_dynamic,
        pt_loads: parsed.pt_loads,
        sha256_hex: actual_hash,
    })
}

fn assert_loads_in_user_window(loads: &[PtLoadMeta], lo: u64, hi: u64) -> Result<(), String> {
    for (i, seg) in loads.iter().enumerate() {
        let end = seg
            .p_vaddr
            .checked_add(seg.p_memsz)
            .ok_or_else(|| format!("pt_load[{i}] vaddr+memsz overflow"))?;
        if seg.p_vaddr < lo || end > hi {
            return Err(format!(
                "pt_load[{i}] VA [{:#x}, {:#x}) outside user window [{:#x}, {:#x})",
                seg.p_vaddr, end, lo, hi
            ));
        }
    }
    Ok(())
}

fn assert_phdr_table_in_pt_load(
    e_phoff: u64,
    e_phentsize: u16,
    e_phnum: u16,
    loads: &[PtLoadMeta],
) -> Result<(), String> {
    let table_len = (e_phnum as u64)
        .checked_mul(u64::from(e_phentsize))
        .ok_or("phdr table length overflow")?;
    let table_end = e_phoff
        .checked_add(table_len)
        .ok_or("phdr table end overflow")?;
    let covered = loads.iter().any(|seg| {
        let file_end = seg.p_offset.checked_add(seg.p_filesz);
        match file_end {
            Some(end) => seg.p_offset <= e_phoff && table_end <= end,
            None => false,
        }
    });
    if !covered {
        return Err(format!(
            "program header table file range [{e_phoff:#x}, {table_end:#x}) is not covered by any PT_LOAD"
        ));
    }
    Ok(())
}

fn assert_eq_field<T: PartialEq + std::fmt::Debug>(
    name: &str,
    actual: T,
    expected: T,
) -> Result<(), String> {
    if actual != expected {
        Err(format!(
            "{name} mismatch: expected {expected:?}, got {actual:?}"
        ))
    } else {
        Ok(())
    }
}

fn parse_elf64(bytes: &[u8]) -> Result<ParsedElf, String> {
    if bytes.len() < ELF64_EHDR_SIZE {
        return Err("ELF truncated: shorter than Elf64_Ehdr".into());
    }
    if bytes[0..4] != ELF_MAGIC {
        return Err("bad ELF magic".into());
    }
    let ei_class = bytes[4];
    let ei_data = bytes[5];
    if ei_class != ELFCLASS64 {
        return Err(format!("unsupported EI_CLASS {ei_class} (need ELFCLASS64)"));
    }
    if ei_data != ELFDATA2LSB {
        return Err(format!("unsupported EI_DATA {ei_data} (need ELFDATA2LSB)"));
    }

    let e_type = read_u16(bytes, 16)?;
    let e_machine = read_u16(bytes, 18)?;
    let e_entry = read_u64(bytes, 24)?;
    let e_phoff = read_u64(bytes, 32)?;
    let e_phentsize = read_u16(bytes, 54)?;
    let e_phnum = read_u16(bytes, 56)?;

    if e_phentsize as usize != ELF64_PHDR_SIZE {
        return Err(format!(
            "bad e_phentsize {e_phentsize} (need {ELF64_PHDR_SIZE})"
        ));
    }

    let phoff = usize::try_from(e_phoff).map_err(|_| "e_phoff does not fit usize")?;
    let ph_table_len = (e_phnum as usize)
        .checked_mul(ELF64_PHDR_SIZE)
        .ok_or("phdr table length overflow")?;
    let ph_end = phoff
        .checked_add(ph_table_len)
        .ok_or("phdr table end overflow")?;
    if ph_end > bytes.len() {
        return Err("truncated program header table".into());
    }

    let mut pt_loads = Vec::new();
    let mut has_pt_interp = false;
    let mut has_pt_dynamic = false;

    for i in 0..e_phnum as usize {
        let off = phoff + i * ELF64_PHDR_SIZE;
        let p_type = read_u32(bytes, off)?;
        let p_flags = read_u32(bytes, off + 4)?;
        let p_offset = read_u64(bytes, off + 8)?;
        let p_vaddr = read_u64(bytes, off + 16)?;
        let p_filesz = read_u64(bytes, off + 32)?;
        let p_memsz = read_u64(bytes, off + 40)?;
        let p_align = read_u64(bytes, off + 48)?;

        match p_type {
            PT_LOAD => pt_loads.push(PtLoadMeta {
                p_offset,
                p_vaddr,
                p_filesz,
                p_memsz,
                p_flags,
                p_align,
            }),
            PT_INTERP => has_pt_interp = true,
            PT_DYNAMIC => has_pt_dynamic = true,
            _ => {}
        }
    }

    Ok(ParsedElf {
        e_type,
        e_machine,
        ei_class,
        ei_data,
        e_entry,
        e_phoff,
        e_phentsize,
        e_phnum,
        has_pt_interp,
        has_pt_dynamic,
        pt_loads,
    })
}

fn parse_metadata_toml(text: &str) -> Result<PinnedMetadata, String> {
    let mut e_entry = None;
    let mut e_phoff = None;
    let mut e_phentsize = None;
    let mut e_phnum = None;
    let mut pt_load_count = None;
    let mut has_pt_interp = None;
    let mut has_pt_dynamic = None;
    let mut user_va_lo = None;
    let mut user_va_hi = None;
    let mut pt_loads = Vec::new();
    let mut current: Option<PtLoadMeta> = None;

    let flush = |current: &mut Option<PtLoadMeta>, pt_loads: &mut Vec<PtLoadMeta>| {
        if let Some(seg) = current.take() {
            pt_loads.push(seg);
        }
    };

    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[pt_load]]" {
            flush(&mut current, &mut pt_loads);
            current = Some(PtLoadMeta {
                p_offset: 0,
                p_vaddr: 0,
                p_filesz: 0,
                p_memsz: 0,
                p_flags: 0,
                p_align: 0,
            });
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "e_entry" => e_entry = Some(parse_int(value)?),
            "e_phoff" => e_phoff = Some(parse_int(value)?),
            "e_phentsize" => e_phentsize = Some(parse_int(value)? as u16),
            "e_phnum" => e_phnum = Some(parse_int(value)? as u16),
            "pt_load_count" => pt_load_count = Some(parse_int(value)? as usize),
            "has_pt_interp" => has_pt_interp = Some(parse_bool(value)?),
            "has_pt_dynamic" => has_pt_dynamic = Some(parse_bool(value)?),
            "user_va_lo" => user_va_lo = Some(parse_int(value)?),
            "user_va_hi" => user_va_hi = Some(parse_int(value)?),
            "p_offset" => {
                current
                    .as_mut()
                    .ok_or("p_offset outside [[pt_load]]")?
                    .p_offset = parse_int(value)?;
            }
            "p_vaddr" => {
                current
                    .as_mut()
                    .ok_or("p_vaddr outside [[pt_load]]")?
                    .p_vaddr = parse_int(value)?;
            }
            "p_filesz" => {
                current
                    .as_mut()
                    .ok_or("p_filesz outside [[pt_load]]")?
                    .p_filesz = parse_int(value)?;
            }
            "p_memsz" => {
                current
                    .as_mut()
                    .ok_or("p_memsz outside [[pt_load]]")?
                    .p_memsz = parse_int(value)?;
            }
            "p_flags" => {
                current
                    .as_mut()
                    .ok_or("p_flags outside [[pt_load]]")?
                    .p_flags = parse_int(value)? as u32;
            }
            "p_align" => {
                current
                    .as_mut()
                    .ok_or("p_align outside [[pt_load]]")?
                    .p_align = parse_int(value)?;
            }
            _ => {}
        }
    }
    flush(&mut current, &mut pt_loads);

    Ok(PinnedMetadata {
        meta: M8FixtureMetadata {
            e_entry: e_entry.ok_or("metadata missing e_entry")?,
            e_phoff: e_phoff.ok_or("metadata missing e_phoff")?,
            e_phentsize: e_phentsize.ok_or("metadata missing e_phentsize")?,
            e_phnum: e_phnum.ok_or("metadata missing e_phnum")?,
            pt_load_count: pt_load_count.ok_or("metadata missing pt_load_count")?,
            has_pt_interp: has_pt_interp.ok_or("metadata missing has_pt_interp")?,
            has_pt_dynamic: has_pt_dynamic.ok_or("metadata missing has_pt_dynamic")?,
            pt_loads,
            sha256_hex: String::new(),
        },
        user_va_lo: user_va_lo.ok_or("metadata missing user_va_lo")?,
        user_va_hi: user_va_hi.ok_or("metadata missing user_va_hi")?,
    })
}

fn parse_bool(value: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!("invalid bool {other}")),
    }
}

fn parse_int(value: &str) -> Result<u64, String> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).map_err(|e| format!("bad hex {value}: {e}"))
    } else {
        value
            .parse::<u64>()
            .map_err(|e| format!("bad int {value}: {e}"))
    }
}

fn read_u16(bytes: &[u8], off: usize) -> Result<u16, String> {
    let end = off.checked_add(2).ok_or("u16 offset overflow")?;
    let slice = bytes.get(off..end).ok_or("u16 truncated")?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32(bytes: &[u8], off: usize) -> Result<u32, String> {
    let end = off.checked_add(4).ok_or("u32 offset overflow")?;
    let slice = bytes.get(off..end).ok_or("u32 truncated")?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64(bytes: &[u8], off: usize) -> Result<u64, String> {
    let end = off.checked_add(8).ok_or("u64 offset overflow")?;
    let slice = bytes.get(off..end).ok_or("u64 truncated")?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

/// Checks a committed fixture binary against the first token of its tracked `.sha256` file.
pub fn verify_pinned_sha256(binary_path: &Path, hash_path: &Path) -> Result<(), String> {
    let bytes =
        fs::read(binary_path).map_err(|e| format!("read {}: {e}", binary_path.display()))?;
    let expected_hash = fs::read_to_string(hash_path)
        .map_err(|e| format!("read {}: {e}", hash_path.display()))?
        .split_whitespace()
        .next()
        .ok_or_else(|| format!("empty hash file {}", hash_path.display()))?
        .to_ascii_lowercase();
    let actual_hash = hex_encode(&sha256(&bytes));
    if actual_hash != expected_hash {
        return Err(format!(
            "SHA-256 mismatch for {}: expected {expected_hash}, got {actual_hash}",
            binary_path.display()
        ));
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// Self-contained SHA-256 (FIPS 180-4). Prefer this over adding `sha2` to xtask.
fn sha256(message: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
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

    let bit_len = (message.len() as u64).saturating_mul(8);
    let mut padded = message.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

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
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn sha256_known_answers() {
        assert_eq!(
            hex_encode(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_encode(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn committed_fixture_verifies() {
        let meta = verify_m8_fixture().expect("committed fixture must verify");
        assert_eq!(meta.e_entry, 0x0000_4000_0040_0078);
        assert_eq!(meta.e_phoff, 64);
        assert_eq!(meta.pt_load_count, 1);
        assert!(!meta.has_pt_interp);
        assert!(!meta.has_pt_dynamic);
        assert_eq!(meta.e_phentsize, 56);
        assert_eq!(meta.e_phnum, 1);
        assert_eq!(meta.pt_loads[0].p_offset, 0);
        assert_eq!(meta.pt_loads[0].p_vaddr, 0x0000_4000_0040_0000);
        assert_loads_in_user_window(&meta.pt_loads, M8_USER_VA_LO, M8_USER_VA_HI).unwrap();
        assert_phdr_table_in_pt_load(meta.e_phoff, meta.e_phentsize, meta.e_phnum, &meta.pt_loads)
            .unwrap();
    }

    #[test]
    fn tampered_byte_fails_hash() {
        let dir = tempfile_fixture_copy();
        let path = dir.join("hello-linux-x86_64");
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] ^= 0xff;
        fs::write(&path, &bytes).unwrap();
        let err = verify_m8_fixture_at(&dir).expect_err("tamper must fail");
        assert!(err.contains("SHA-256 mismatch"), "{err}");
    }

    #[test]
    fn metadata_mismatch_detected() {
        let dir = tempfile_fixture_copy();
        let meta_path = dir.join("metadata.toml");
        let mut text = fs::read_to_string(&meta_path).unwrap();
        text = text.replace("e_entry = 0x400000400078", "e_entry = 0x400000401000");
        fs::write(&meta_path, text).unwrap();
        let err = verify_m8_fixture_at(&dir).expect_err("metadata mismatch must fail");
        assert!(err.contains("e_entry mismatch"), "{err}");
    }

    #[test]
    fn out_of_window_load_rejected() {
        let err = assert_loads_in_user_window(
            &[PtLoadMeta {
                p_offset: 0,
                p_vaddr: 0x400000,
                p_filesz: 0x100,
                p_memsz: 0x100,
                p_flags: 5,
                p_align: 0x1000,
            }],
            M8_USER_VA_LO,
            M8_USER_VA_HI,
        )
        .expect_err("classic 0x400000 must be rejected");
        assert!(err.contains("outside user window"), "{err}");
    }

    #[test]
    fn phdr_table_outside_load_rejected() {
        let err = assert_phdr_table_in_pt_load(
            64,
            56,
            1,
            &[PtLoadMeta {
                p_offset: 0x78,
                p_vaddr: 0x0000_4000_0040_0078,
                p_filesz: 0x6d,
                p_memsz: 0x6d,
                p_flags: 5,
                p_align: 0x1000,
            }],
        )
        .expect_err("phdrs below first mapped byte must fail");
        assert!(err.contains("not covered by any PT_LOAD"), "{err}");
    }

    fn tempfile_fixture_copy() -> PathBuf {
        let src = fixture_dir();
        let dest = std::env::temp_dir().join(format!(
            "m8-fixture-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dest).unwrap();
        for name in [
            "hello-linux-x86_64",
            "hello-linux-x86_64.sha256",
            "metadata.toml",
        ] {
            fs::copy(src.join(name), dest.join(name)).unwrap();
        }
        let mut f = fs::File::create(dest.join(".copied")).unwrap();
        writeln!(f, "ok").unwrap();
        dest
    }
}
