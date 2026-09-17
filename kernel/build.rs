use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const PT_LOAD: u32 = 1;
const SHT_RELA: u32 = 4;
const R_X86_64_RELATIVE: u32 = 8;
const USERSPACE_IMAGE_LOAD_BASE: u64 = 0x0000_4000_0000_0000;

fn main() {
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
    {
        embed_userspace_image(
            "storage_userspace.bin",
            "clean-slate-storage-userspace",
            true,
        );
    }
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
    let (image, image_base, entry) = materialize_elf_image(&elf_bytes).unwrap_or_else(|message| {
        panic!(
            "failed to materialize userspace ELF {}: {message}",
            elf.display()
        )
    });

    fs::write(&raw_image, &image).expect("failed to write materialized userspace image");

    if record_entry_offset {
        let entry_offset = entry
            .checked_sub(image_base)
            .expect("ELF entry point was below the image base");
        let (generated_file, generated_const) = match raw_name {
            "supervisor_userspace.bin" => (
                "supervisor_userspace_entry.rs",
                "SUPERVISOR_USERSPACE_ENTRY_OFFSET",
            ),
            "recovery_userspace.bin" => (
                "recovery_userspace_entry.rs",
                "RECOVERY_SUPERVISOR_ENTRY_OFFSET",
            ),
            "storage_userspace.bin" => (
                "storage_userspace_entry.rs",
                "STORAGE_USERSPACE_ENTRY_OFFSET",
            ),
            _ => panic!("unexpected userspace image {raw_name}"),
        };
        let generated = out_dir.join(generated_file);
        fs::write(
            &generated,
            format!("pub(super) const {generated_const}: u64 = {entry_offset};\n"),
        )
        .expect("failed to write userspace_entry metadata");
    }

    println!("cargo:rerun-if-changed={}", elf.display());
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("build.rs").display()
    );
}

fn materialize_elf_image(elf: &[u8]) -> Result<(Vec<u8>, u64, u64), String> {
    if elf.len() < 0x40 || &elf[0..4] != b"\x7fELF" || elf[4] != 2 || elf[5] != 1 {
        return Err("expected a little-endian ELF64 file".into());
    }

    let entry = u64::from_le_bytes(elf[0x18..0x20].try_into().map_err(|_| "e_entry")?);
    let phoff = u64::from_le_bytes(elf[0x20..0x28].try_into().map_err(|_| "e_phoff")?);
    let phentsize =
        u16::from_le_bytes(elf[0x36..0x38].try_into().map_err(|_| "e_phentsize")?) as u64;
    let phnum = u16::from_le_bytes(elf[0x38..0x3a].try_into().map_err(|_| "e_phnum")?) as u64;

    struct LoadSegment {
        vaddr: u64,
        offset: u64,
        filesz: u64,
        _memsz: u64,
    }

    let mut segments = Vec::new();
    let mut image_base = u64::MAX;
    let mut image_end = 0u64;

    for index in 0..phnum {
        let start = phoff + index * phentsize;
        let end = start + phentsize;
        if end > elf.len() as u64 {
            break;
        }
        let header = &elf[start as usize..end as usize];
        let p_type = u32::from_le_bytes(header[0..4].try_into().map_err(|_| "p_type")?);
        if p_type != PT_LOAD {
            continue;
        }
        let p_offset = u64::from_le_bytes(header[0x08..0x10].try_into().map_err(|_| "p_offset")?);
        let p_vaddr = u64::from_le_bytes(header[0x10..0x18].try_into().map_err(|_| "p_vaddr")?);
        let p_filesz = u64::from_le_bytes(header[0x20..0x28].try_into().map_err(|_| "p_filesz")?);
        let p_memsz = u64::from_le_bytes(header[0x28..0x30].try_into().map_err(|_| "p_memsz")?);
        image_base = image_base.min(p_vaddr);
        image_end = image_end.max(p_vaddr.saturating_add(p_memsz));
        segments.push(LoadSegment {
            vaddr: p_vaddr,
            offset: p_offset,
            filesz: p_filesz,
            _memsz: p_memsz,
        });
    }

    if segments.is_empty() {
        return Err("ELF had no PT_LOAD segments".into());
    }

    let image_size = usize::try_from(image_end.saturating_sub(image_base))
        .map_err(|_| "userspace image span exceeded addressable size")?;
    let mut image = vec![0u8; image_size];

    for segment in &segments {
        let dest_start = usize::try_from(segment.vaddr.saturating_sub(image_base))
            .map_err(|_| "segment virtual address underflow")?;
        let dest_end = dest_start
            .checked_add(segment.filesz as usize)
            .ok_or("segment file copy overflow")?;
        if dest_end > image.len() {
            return Err("segment file range exceeded materialized image".into());
        }
        let src_start = segment.offset as usize;
        let src_end = src_start
            .checked_add(segment.filesz as usize)
            .ok_or("segment file read overflow")?;
        if src_end > elf.len() {
            return Err("segment file range exceeded ELF file".into());
        }
        image[dest_start..dest_end].copy_from_slice(&elf[src_start..src_end]);
    }

    apply_rela_dyn(elf, &mut image, image_base, USERSPACE_IMAGE_LOAD_BASE)?;

    Ok((image, image_base, entry))
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
                    write_u64(image, load_base, r_offset, value)?;
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
    let offset = usize::try_from(vaddr.saturating_sub(load_base))
        .map_err(|_| "relocation virtual address underflow")?;
    let end = offset.checked_add(8).ok_or("relocation write overflow")?;
    if end > image.len() {
        return Err("relocation write exceeded materialized image".into());
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
