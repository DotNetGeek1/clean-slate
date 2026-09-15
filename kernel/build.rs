use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    if env::var("CARGO_FEATURE_M4_SUPERVISOR_SELF_TEST").is_ok() {
        embed_userspace_image(
            "supervisor_userspace.bin",
            "clean-slate-supervisor-userspace",
            false,
        );
    }
    if env::var("CARGO_FEATURE_M4_RECOVERY_SELF_TEST").is_ok() {
        embed_userspace_image(
            "recovery_userspace.bin",
            "clean-slate-supervisor-recovery-userspace",
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

    let objcopy = llvm_objcopy_path();
    let status = Command::new(&objcopy)
        .arg("-O")
        .arg("binary")
        .arg(&elf)
        .arg(&raw_image)
        .status()
        .expect("failed to run llvm-objcopy");
    if !status.success() {
        panic!("llvm-objcopy failed with status {status}");
    }

    if record_entry_offset {
        let entry_offset = elf_image_entry_offset(&elf);
        let generated = out_dir.join("recovery_userspace_entry.rs");
        fs::write(
            &generated,
            format!("pub(super) const RECOVERY_SUPERVISOR_ENTRY_OFFSET: u64 = {entry_offset};\n"),
        )
        .expect("failed to write recovery_userspace_entry.rs");
    }

    println!("cargo:rerun-if-changed={}", elf.display());
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("build.rs").display()
    );
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

fn llvm_objcopy_path() -> PathBuf {
    let sysroot = rustc_sysroot();
    let host = env::var("HOST").expect("HOST");
    let mut candidate = Path::new(&sysroot)
        .join("lib")
        .join("rustlib")
        .join(host)
        .join("bin")
        .join("llvm-objcopy");
    if env::consts::OS == "windows" {
        candidate.set_extension("exe");
    }
    if candidate.is_file() {
        return candidate;
    }
    panic!(
        "llvm-objcopy not found at {}; install the llvm-tools rustup component",
        candidate.display()
    );
}

fn elf_image_entry_offset(elf: &Path) -> u64 {
    let bytes = fs::read(elf).expect("failed to read userspace ELF");
    if bytes.len() < 0x40 || &bytes[0..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        panic!(
            "userspace ELF at {} was not a little-endian ELF64 file",
            elf.display()
        );
    }
    let entry = u64::from_le_bytes(bytes[0x18..0x20].try_into().expect("e_entry"));
    let phoff = u64::from_le_bytes(bytes[0x20..0x28].try_into().expect("e_phoff"));
    let phentsize = u16::from_le_bytes(bytes[0x36..0x38].try_into().expect("e_phentsize")) as u64;
    let phnum = u16::from_le_bytes(bytes[0x38..0x3a].try_into().expect("e_phnum")) as u64;
    let mut image_base: Option<u64> = None;
    for index in 0..phnum {
        let start = phoff + index * phentsize;
        let end = start + phentsize;
        if end > bytes.len() as u64 {
            break;
        }
        let header = &bytes[start as usize..end as usize];
        let p_type = u32::from_le_bytes(header[0..4].try_into().expect("p_type"));
        if p_type != 1 {
            continue;
        }
        let p_vaddr = u64::from_le_bytes(header[0x10..0x18].try_into().expect("p_vaddr"));
        image_base = Some(match image_base {
            Some(current) => current.min(p_vaddr),
            None => p_vaddr,
        });
    }
    let image_base = image_base.expect("userspace ELF had no PT_LOAD program headers");
    entry - image_base
}

fn rustc_sysroot() -> String {
    let output = Command::new("rustc")
        .arg("--print")
        .arg("sysroot")
        .output()
        .expect("failed to run rustc --print sysroot");
    if !output.status.success() {
        panic!("rustc --print sysroot failed");
    }
    String::from_utf8(output.stdout)
        .expect("sysroot utf8")
        .trim()
        .to_string()
}
