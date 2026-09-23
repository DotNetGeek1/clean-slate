//! M9 #104 BusyBox + rootfs fixture verification (`cargo xtask verify-m9-fixture`).

use clean_slate_rootfs::{pack, EntryKind, Image, Manifest, ManifestKind};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const BUSYBOX_SHA256: &str = "7ba56acec9fb89deace4ebfab6f4baaa8d1b778754b8f7ae3dbd7cf7990fe380";
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PT_DYNAMIC: u32 = 2;
const ELF64_EHDR_SIZE: usize = 64;
const ELF64_PHDR_SIZE: usize = 56;
const EXPECTED_FIRST_PT_LOAD_VADDR: u64 = 0x400_000;

pub struct M9FixtureReport {
    pub busybox_sha256: String,
    pub image_sha256: String,
    pub entry_count: usize,
}

pub fn verify_m9_fixture() -> Result<M9FixtureReport, String> {
    let dir = fixture_dir();
    let busybox_path = dir.join("busybox");
    let bytes =
        fs::read(&busybox_path).map_err(|e| format!("read {}: {e}", busybox_path.display()))?;

    let actual_hash = hex_encode(&sha256(&bytes));
    if actual_hash != BUSYBOX_SHA256 {
        return Err(format!(
            "BusyBox SHA-256 mismatch: expected {BUSYBOX_SHA256}, got {actual_hash}"
        ));
    }

    verify_busybox_elf(&bytes)?;
    verify_applets_from_commands(&dir)?;

    let manifest_text = fs::read_to_string(dir.join("rootfs.toml"))
        .map_err(|e| format!("read rootfs.toml: {e}"))?;
    let manifest =
        Manifest::parse_toml(&manifest_text).map_err(|e| format!("parse rootfs.toml: {e:?}"))?;

    verify_manifest_links(&manifest, &dir)?;

    let pack_once = |bytes_out: &mut Vec<u8>| -> Result<(), String> {
        *bytes_out = pack(&manifest, |p| {
            let rel = if p.is_relative() {
                p
            } else {
                p.strip_prefix(&dir)
                    .map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, "outside"))?
            };
            fs::read(dir.join(rel))
        })
        .map_err(|e| format!("pack: {e:?}"))?;
        Ok(())
    };

    let mut image_a = Vec::new();
    let mut image_b = Vec::new();
    pack_once(&mut image_a)?;
    pack_once(&mut image_b)?;
    if image_a != image_b {
        return Err("packed image is not byte-identical across two consecutive packs".into());
    }

    let image = Image::parse(&image_a).map_err(|e| format!("parse packed image: {e:?}"))?;
    print_entry_table(&image);
    let image_sha256 = hex_encode(&sha256(&image_a));
    println!("M9 rootfs image sha256={image_sha256}");

    Ok(M9FixtureReport {
        busybox_sha256: actual_hash,
        image_sha256,
        entry_count: image.len(),
    })
}

fn print_entry_table(image: &Image) {
    println!("M9 rootfs entries ({}):", image.len());
    for i in 0..image.len() {
        let entry = image.entry(i).expect("entry index");
        let kind = match entry.kind {
            EntryKind::Dir => "dir",
            EntryKind::File => "file",
            EntryKind::Link => "link",
        };
        let path = escape_path(entry.path);
        if entry.kind == EntryKind::Link {
            println!("  [{i}] {kind} {path} -> {}", escape_path(entry.data));
        } else if entry.kind == EntryKind::File {
            println!("  [{i}] {kind} {path} bytes={}", entry.data.len());
        } else {
            let wr = if entry.writable_root { " writable" } else { "" };
            println!("  [{i}] {kind} {path}{wr}");
        }
    }
}

fn escape_path(path: &[u8]) -> String {
    let mut out = String::new();
    for b in path {
        if *b == b'\\' {
            out.push_str("\\\\");
        } else if b.is_ascii() && !b.is_ascii_control() {
            out.push(*b as char);
        } else {
            out.push_str(&format!("\\x{:02x}", *b));
        }
    }
    out
}

fn verify_busybox_elf(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() < ELF64_EHDR_SIZE {
        return Err("ELF truncated".into());
    }
    if bytes[0..4] != ELF_MAGIC {
        return Err("bad ELF magic".into());
    }
    let e_type = read_u16(bytes, 16)?;
    let e_machine = read_u16(bytes, 18)?;
    if e_type != ET_EXEC {
        return Err(format!("expected ET_EXEC, got {e_type}"));
    }
    if e_machine != EM_X86_64 {
        return Err(format!("expected EM_X86_64, got {e_machine}"));
    }
    let e_phoff = read_u64(bytes, 32)?;
    let e_phentsize = read_u16(bytes, 54)?;
    let e_phnum = read_u16(bytes, 56)?;
    if e_phentsize as usize != ELF64_PHDR_SIZE {
        return Err(format!("bad e_phentsize {e_phentsize}"));
    }
    let phoff = usize::try_from(e_phoff).map_err(|_| "e_phoff overflow")?;
    let mut first_pt_load_vaddr: Option<u64> = None;
    let mut saw_interp = false;
    let mut saw_dynamic = false;
    for i in 0..e_phnum as usize {
        let off = phoff + i * ELF64_PHDR_SIZE;
        let p_type = read_u32(bytes, off)?;
        if p_type == PT_INTERP {
            saw_interp = true;
        }
        if p_type == PT_DYNAMIC {
            saw_dynamic = true;
        }
        if p_type == PT_LOAD && first_pt_load_vaddr.is_none() {
            first_pt_load_vaddr = Some(read_u64(bytes, off + 16)?);
        }
    }
    if saw_interp {
        return Err("unexpected PT_INTERP".into());
    }
    if saw_dynamic {
        return Err("unexpected PT_DYNAMIC".into());
    }
    let vaddr = first_pt_load_vaddr.ok_or("missing PT_LOAD")?;
    if vaddr != EXPECTED_FIRST_PT_LOAD_VADDR {
        return Err(format!(
            "first PT_LOAD vaddr {vaddr:#x} != {EXPECTED_FIRST_PT_LOAD_VADDR:#x}"
        ));
    }
    Ok(())
}

fn verify_applets_from_commands(dir: &Path) -> Result<(), String> {
    let applets_text = fs::read_to_string(dir.join("applets.txt"))
        .map_err(|e| format!("read applets.txt: {e}"))?;
    let applets: BTreeSet<String> = applets_text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();

    let commands_text = fs::read_to_string(dir.join("commands.toml"))
        .map_err(|e| format!("read commands.toml: {e}"))?;
    let shells = extract_shell_lines(&commands_text);
    let mut required = BTreeSet::new();
    for shell in shells {
        collect_applets_from_shell(&shell, &mut required);
    }
    for name in required {
        if !applets.contains(&name) {
            return Err(format!(
                "applets.txt missing applet '{name}' required by commands.toml shells"
            ));
        }
    }
    Ok(())
}

fn extract_shell_lines(text: &str) -> Vec<String> {
    let mut shells = Vec::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.starts_with("shell = ") {
            let value = line["shell = ".len()..].trim();
            if let Some(unquoted) = strip_quotes(value) {
                shells.push(unquoted);
            }
        }
    }
    shells
}

fn strip_quotes(s: &str) -> Option<String> {
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        Some(s[1..s.len() - 1].to_string())
    } else {
        None
    }
}

fn collect_applets_from_shell(shell: &str, out: &mut BTreeSet<String>) {
    let bytes = shell.as_bytes();
    let mut i = 0;
    while i + 5 < bytes.len() {
        if bytes[i..].starts_with(b"/bin/") {
            let start = i + 5;
            let mut end = start;
            while end < bytes.len() && is_applet_char(bytes[end]) {
                end += 1;
            }
            if end > start {
                let name = String::from_utf8_lossy(&bytes[start..end]).to_string();
                if name != "busybox" {
                    out.insert(name);
                }
            }
            i = end;
            continue;
        }
        i += 1;
    }
    if let Some(first) = shell.split_whitespace().next() {
        if !first.contains('/') && is_applet_token(first) {
            out.insert(first.to_string());
        }
    }
}

fn is_applet_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn is_applet_token(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn verify_manifest_links(manifest: &Manifest, dir: &Path) -> Result<(), String> {
    let applets_text = fs::read_to_string(dir.join("applets.txt"))
        .map_err(|e| format!("read applets.txt: {e}"))?;
    let applets: BTreeSet<String> = applets_text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();

    for entry in &manifest.entries {
        if entry.kind != ManifestKind::Link {
            continue;
        }
        let path = String::from_utf8_lossy(&entry.path);
        if !path.starts_with("/bin/") {
            continue;
        }
        let applet = path.strip_prefix("/bin/").unwrap_or("");
        if applet.is_empty() || applet.contains('/') {
            return Err(format!("invalid link path {path}"));
        }
        if !applets.contains(applet) {
            return Err(format!(
                "manifest link {path} names applet '{applet}' missing from applets.txt"
            ));
        }
    }
    Ok(())
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask in workspace")
        .join("fixtures")
        .join("busybox")
        .join("frozen")
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    if offset + 2 > bytes.len() {
        return Err("read_u16 past end".into());
    }
    Ok(u16::from_le_bytes([bytes[offset], bytes[offset + 1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    if offset + 4 > bytes.len() {
        return Err("read_u32 past end".into());
    }
    Ok(u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, String> {
    if offset + 8 > bytes.len() {
        return Err("read_u64 past end".into());
    }
    Ok(u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ]))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(hex, "{:02x}", b);
    }
    hex
}

fn sha256(data: &[u8]) -> [u8; 32] {
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
        for i in 0..16 {
            let j = i * 4;
            w[i] = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
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
