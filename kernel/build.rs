use clean_slate_elf::{
    parse_load_plan, LoadPlan, LoadPlanPolicy, SegmentPermissions, PF_R, PF_W, PF_X,
};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const SHT_RELA: u32 = 4;
const R_X86_64_RELATIVE: u32 = 8;
const USERSPACE_IMAGE_LOAD_BASE: u64 = 0x0000_4000_0000_0000;

fn main() {
    let m6_fixture_self_test = env::var("CARGO_FEATURE_M6_PROCESS_CONTROL_SELF_TEST").is_ok()
        || env::var("CARGO_FEATURE_M6_DELEGATION_SELF_TEST").is_ok()
        || env::var("CARGO_FEATURE_M6_REVOCATION_SELF_TEST").is_ok()
        || env::var("CARGO_FEATURE_M6_AUDIT_SELF_TEST").is_ok()
        || env::var("CARGO_FEATURE_M6_FIXTURE_SMOKE_SELF_TEST").is_ok()
        || env::var("CARGO_FEATURE_M6_OBJECT_SELF_TEST").is_ok()
        || env::var("CARGO_FEATURE_M6_CAPABILITIES_SELF_TEST").is_ok()
        || env::var("CARGO_FEATURE_M7_NET_CAPS_SELF_TEST").is_ok();
    let m6_self_test = env::var("CARGO_FEATURE_M6_OBJECT_SELF_TEST").is_ok()
        || env::var("CARGO_FEATURE_M6_CAPABILITIES_SELF_TEST").is_ok()
        || m6_fixture_self_test;
    if env::var("CARGO_FEATURE_M4_SUPERVISOR_SELF_TEST").is_ok() {
        embed_userspace_image(
            "supervisor_userspace.bin",
            "clean-slate-supervisor-userspace",
            true,
        );
    }
    if env::var("CARGO_FEATURE_M4_RECOVERY_SELF_TEST").is_ok() {
        embed_userspace_image(
            "recovery_userspace.bin",
            "clean-slate-supervisor-recovery-userspace",
            true,
        );
    }
    if env::var("CARGO_FEATURE_M5_STORAGE_SELF_TEST").is_ok()
        || env::var("CARGO_FEATURE_M5_PERSISTENCE_SELF_TEST").is_ok()
        || env::var("CARGO_FEATURE_M5_CRASH_EARLY_SELF_TEST").is_ok()
        || env::var("CARGO_FEATURE_M5_CRASH_LATE_SELF_TEST").is_ok()
        || env::var("CARGO_FEATURE_M5_CRASH_RECOVERY_SELF_TEST").is_ok()
        || m6_self_test
    {
        embed_userspace_image(
            "storage_userspace.bin",
            "clean-slate-storage-userspace",
            true,
        );
    }
    if m6_fixture_self_test {
        embed_userspace_image(
            "m6_fixture_userspace.bin",
            "clean-slate-m6-fixture-userspace",
            true,
        );
    }
    if env::var("CARGO_FEATURE_M7_NET_SERVICE_SELF_TEST").is_ok() {
        embed_userspace_image(
            "network_userspace.bin",
            "clean-slate-network-userspace",
            true,
        );
    }
    if env::var("CARGO_FEATURE_M9_ROOTFS").is_ok() {
        embed_m9_rootfs_image();
    }
}

fn embed_m9_rootfs_image() {
    use clean_slate_rootfs::{pack, Manifest};

    const BUSYBOX_SHA256: &str = "7ba56acec9fb89deace4ebfab6f4baaa8d1b778754b8f7ae3dbd7cf7990fe380";

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let fixture_dir = manifest_dir
        .join("..")
        .join("fixtures")
        .join("busybox")
        .join("frozen");
    let busybox_path = fixture_dir.join("busybox");
    let manifest_path = fixture_dir.join("rootfs.toml");
    let busybox_bytes = fs::read(&busybox_path).expect("read frozen busybox for m9-rootfs embed");
    let actual_hash = hex_sha256(&busybox_bytes);
    if actual_hash != BUSYBOX_SHA256 {
        panic!(
            "BusyBox SHA-256 drift: expected {BUSYBOX_SHA256}, got {actual_hash} ({})",
            busybox_path.display()
        );
    }

    let manifest_toml =
        fs::read_to_string(&manifest_path).expect("read fixtures/busybox/frozen/rootfs.toml");
    let manifest =
        Manifest::parse_toml(&manifest_toml).expect("parse fixtures/busybox/frozen/rootfs.toml");
    let image = pack(&manifest, |source| {
        let rel = source
            .file_name()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "source"))?;
        fs::read(fixture_dir.join(rel))
    })
    .expect("pack m9 rootfs image");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let out_path = out_dir.join("m9-rootfs.img");
    fs::write(&out_path, &image).expect("write m9-rootfs.img");

    println!("cargo:rerun-if-changed={}", busybox_path.display());
    println!("cargo:rerun-if-changed={}", manifest_path.display());
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("build.rs").display()
    );
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

fn embed_userspace_image(raw_name: &str, bin_name: &str, record_entry_offset: bool) {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let profile = env::var("PROFILE").expect("PROFILE");
    let elf = userspace_elf(&manifest_dir, &profile, bin_name);
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let raw_image = out_dir.join(raw_name);

    if !elf.is_file() {
        panic!(
            "missing userspace ELF at {}; build with:\n  \
             RUSTC_BOOTSTRAP=1 cargo build -p clean-slate-supervisor \
             --bin {bin_name} --features userspace \
             --target x86_64-unknown-none -Z build-std=core,compiler_builtins --release",
            elf.display(),
            bin_name = bin_name
        );
    }

    let elf_bytes = fs::read(&elf).expect("failed to read userspace ELF");
    let (image, plan, image_base) = materialize_elf_image(&elf_bytes).unwrap_or_else(|message| {
        panic!(
            "failed to materialize userspace ELF {}: {message}",
            elf.display()
        )
    });

    fs::write(&raw_image, &image).expect("failed to write materialized userspace image");

    if record_entry_offset {
        let entry_offset = plan
            .entry
            .checked_sub(image_base)
            .expect("ELF entry point was below the image base");
        let mapped_pages = plan
            .total_mapped_pages(4096)
            .expect("mapped page derivation failed") as usize;
        let (generated_file, prefix) = match raw_name {
            "supervisor_userspace.bin" => ("supervisor_userspace_entry.rs", "SUPERVISOR_USERSPACE"),
            "recovery_userspace.bin" => ("recovery_userspace_entry.rs", "RECOVERY_SUPERVISOR"),
            "storage_userspace.bin" => ("storage_userspace_entry.rs", "STORAGE_USERSPACE"),
            "m6_fixture_userspace.bin" => ("m6_fixture_userspace_entry.rs", "M6_FIXTURE_USERSPACE"),
            "network_userspace.bin" => ("network_userspace_entry.rs", "NETWORK_USERSPACE"),
            _ => panic!("unexpected userspace image {raw_name}"),
        };
        let generated = out_dir.join(generated_file);
        fs::write(
            &generated,
            format_segment_metadata(prefix, entry_offset, mapped_pages, image_base, &plan),
        )
        .expect("failed to write userspace_entry metadata");
    }

    println!("cargo:rerun-if-changed={}", elf.display());
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("build.rs").display()
    );
}

fn format_segment_metadata(
    prefix: &str,
    entry_offset: u64,
    mapped_pages: usize,
    image_base: u64,
    plan: &LoadPlan,
) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "pub(super) const {prefix}_ENTRY_OFFSET: u64 = {entry_offset};\n"
    ));
    out.push_str(&format!(
        "pub(super) const {prefix}_MAPPED_CODE_PAGES: usize = {mapped_pages};\n"
    ));
    out.push_str(&format!(
        "pub(super) const {prefix}_IMAGE_BASE: u64 = {image_base:#x};\n"
    ));
    out.push_str(&format!(
        "pub(super) const {prefix}_SEGMENT_COUNT: usize = {};\n",
        plan.segment_count
    ));
    out.push_str(&format!(
        "pub(super) static {prefix}_SEGMENTS: [crate::mm::image_loader::EmbeddedSegment; {}] = [\n",
        plan.segment_count
    ));
    for segment in plan.iter_segments() {
        let offset_from_base = segment
            .vaddr
            .checked_sub(image_base)
            .expect("segment vaddr below image base");
        let file_offset = offset_from_base; // sparse file-backed blob layout
        let flags = perm_bits(segment.perms);
        out.push_str(&format!(
            "    crate::mm::image_loader::EmbeddedSegment {{ offset_from_base: {offset_from_base}, filesz: {}, memsz: {}, file_offset: {file_offset}, flags: {flags} }},\n",
            segment.filesz, segment.memsz
        ));
    }
    out.push_str("];\n");
    out
}

fn perm_bits(perms: SegmentPermissions) -> u8 {
    let mut flags = 0u8;
    if perms.read {
        flags |= PF_R as u8;
    }
    if perms.write {
        flags |= PF_W as u8;
    }
    if perms.execute {
        flags |= PF_X as u8;
    }
    flags
}

/// Emit only file-backed PT_LOAD bytes (never `p_memsz` zero-fill) plus a validated plan.
fn materialize_elf_image(elf: &[u8]) -> Result<(Vec<u8>, LoadPlan, u64), String> {
    let policy = LoadPlanPolicy::native_x86_64();
    let plan =
        parse_load_plan(elf, &policy).map_err(|err| format!("load-plan validation: {err:?}"))?;
    let image_base = plan
        .image_base()
        .ok_or_else(|| "ELF had no PT_LOAD segments".to_string())?;

    let mut image_end = image_base;
    for segment in plan.iter_segments() {
        if segment.filesz == 0 {
            continue;
        }
        let end = segment
            .vaddr
            .checked_add(segment.filesz)
            .ok_or("segment file-backed end overflow")?;
        image_end = image_end.max(end);
    }
    let image_size = usize::try_from(
        image_end
            .checked_sub(image_base)
            .ok_or("image span underflow")?,
    )
    .map_err(|_| "userspace image span exceeded addressable size")?;
    let mut image = vec![0u8; image_size];

    for segment in plan.iter_segments() {
        if segment.filesz == 0 {
            continue;
        }
        let dest_start = usize::try_from(
            segment
                .vaddr
                .checked_sub(image_base)
                .ok_or("segment virtual address underflow")?,
        )
        .map_err(|_| "segment virtual address underflow")?;
        let dest_end = dest_start
            .checked_add(usize::try_from(segment.filesz).map_err(|_| "filesz too large")?)
            .ok_or("segment file copy overflow")?;
        if dest_end > image.len() {
            return Err("segment file range exceeded materialized image".into());
        }
        let src_start =
            usize::try_from(segment.file_offset).map_err(|_| "file offset too large")?;
        let src_end = src_start
            .checked_add(usize::try_from(segment.filesz).map_err(|_| "filesz too large")?)
            .ok_or("segment file read overflow")?;
        if src_end > elf.len() {
            return Err("segment file range exceeded ELF file".into());
        }
        image[dest_start..dest_end].copy_from_slice(&elf[src_start..src_end]);
    }

    apply_rela_dyn(elf, &mut image, image_base, USERSPACE_IMAGE_LOAD_BASE)?;
    Ok((image, plan, image_base))
}

fn apply_rela_dyn(
    elf: &[u8],
    image: &mut [u8],
    link_base: u64,
    load_base: u64,
) -> Result<(), String> {
    let e_shoff = u64::from_le_bytes(elf[0x28..0x30].try_into().map_err(|_| "e_shoff")?);
    let e_shentsize =
        u16::from_le_bytes(elf[0x3a..0x3c].try_into().map_err(|_| "e_shentsize")?) as u64;
    let e_shnum = u16::from_le_bytes(elf[0x3c..0x3e].try_into().map_err(|_| "e_shnum")?) as u64;
    let e_shstrndx =
        u16::from_le_bytes(elf[0x3e..0x40].try_into().map_err(|_| "e_shstrndx")?) as u64;

    let shstrtab = section_data(elf, e_shoff, e_shentsize, e_shnum, e_shstrndx)?;

    for index in 0..e_shnum {
        let header = section_header(elf, e_shoff, e_shentsize, index)?;
        let name_offset =
            u32::from_le_bytes(header[0..4].try_into().map_err(|_| "sh_name")?) as usize;
        let name = read_cstr(shstrtab, name_offset)?;
        if name != ".rela.dyn" {
            continue;
        }
        let sh_type = u32::from_le_bytes(header[4..8].try_into().map_err(|_| "sh_type")?);
        if sh_type != SHT_RELA {
            return Err(".rela.dyn section had an unexpected type".into());
        }
        let sh_offset = u64::from_le_bytes(header[0x18..0x20].try_into().map_err(|_| "sh_offset")?);
        let sh_size = u64::from_le_bytes(header[0x20..0x28].try_into().map_err(|_| "sh_size")?);
        let sh_entsize =
            u64::from_le_bytes(header[0x38..0x40].try_into().map_err(|_| "sh_entsize")?);
        if sh_entsize != 24 {
            return Err(".rela.dyn entry size was not 24 bytes".into());
        }
        let count = sh_size / sh_entsize;
        for entry_index in 0..count {
            let entry_offset = sh_offset + entry_index * sh_entsize;
            let entry_end = entry_offset + sh_entsize;
            if entry_end > elf.len() as u64 {
                return Err("relocation entry exceeded ELF bounds".into());
            }
            let entry = &elf[entry_offset as usize..entry_end as usize];
            let r_offset = u64::from_le_bytes(entry[0..8].try_into().map_err(|_| "r_offset")?);
            let r_info = u64::from_le_bytes(entry[8..16].try_into().map_err(|_| "r_info")?);
            let r_addend = i64::from_le_bytes(entry[16..24].try_into().map_err(|_| "r_addend")?);
            let r_type = (r_info & 0xff_ff_ff_ff) as u32;
            match r_type {
                R_X86_64_RELATIVE => {
                    // lld stores absolute virtual addends for this fixed-base PIE link script.
                    let value = (r_addend as u64)
                        .wrapping_sub(link_base)
                        .wrapping_add(load_base);
                    write_u64(image, link_base, r_offset, value)?;
                }
                _ => {
                    return Err(format!(
                        "unsupported relocation type {r_type} in .rela.dyn (only R_X86_64_RELATIVE is supported)"
                    ));
                }
            }
        }
        return Ok(());
    }

    Ok(())
}

fn write_u64(image: &mut [u8], load_base: u64, vaddr: u64, value: u64) -> Result<(), String> {
    let offset = usize::try_from(
        vaddr
            .checked_sub(load_base)
            .ok_or("relocation below image base")?,
    )
    .map_err(|_| "relocation virtual address underflow")?;
    let end = offset.checked_add(8).ok_or("relocation write overflow")?;
    if end > image.len() {
        return Err("relocation write exceeded file-backed image (BSS targets are unsupported at embed time)".into());
    }
    image[offset..end].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn section_header(elf: &[u8], shoff: u64, shentsize: u64, index: u64) -> Result<&[u8], String> {
    let start = shoff + index * shentsize;
    let end = start + shentsize;
    if end > elf.len() as u64 {
        return Err("section header exceeded ELF bounds".into());
    }
    Ok(&elf[start as usize..end as usize])
}

fn section_data(
    elf: &[u8],
    shoff: u64,
    shentsize: u64,
    _shnum: u64,
    index: u64,
) -> Result<&[u8], String> {
    let header = section_header(elf, shoff, shentsize, index)?;
    let sh_offset = u64::from_le_bytes(header[0x18..0x20].try_into().map_err(|_| "sh_offset")?);
    let sh_size = u64::from_le_bytes(header[0x20..0x28].try_into().map_err(|_| "sh_size")?);
    let start = sh_offset as usize;
    let end = start
        .checked_add(sh_size as usize)
        .ok_or("section data overflow")?;
    if end > elf.len() {
        return Err("section data exceeded ELF bounds".into());
    }
    Ok(&elf[start..end])
}

fn read_cstr(table: &[u8], offset: usize) -> Result<&str, String> {
    if offset >= table.len() {
        return Err("section name offset exceeded string table".into());
    }
    let tail = &table[offset..];
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or("section name was not NUL-terminated")?;
    std::str::from_utf8(&tail[..end]).map_err(|_| "section name was not valid UTF-8".into())
}

fn userspace_elf(manifest_dir: &Path, profile: &str, bin_name: &str) -> PathBuf {
    let base = manifest_dir
        .join("..")
        .join("target")
        .join("x86_64-unknown-none");
    for profile in [profile, "release"] {
        let candidate = base.join(profile).join(bin_name);
        if candidate.is_file() {
            return candidate;
        }
        if env::consts::OS == "windows" {
            let mut with_exe = candidate.clone();
            with_exe.set_extension("exe");
            if with_exe.is_file() {
                return with_exe;
            }
        }
    }
    base.join(profile).join(bin_name)
}
