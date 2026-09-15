use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    if env::var("CARGO_FEATURE_M4_SUPERVISOR_SELF_TEST").is_err() {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let profile = env::var("PROFILE").expect("PROFILE");
    let elf = manifest_dir
        .join("..")
        .join("target")
        .join("x86_64-unknown-none")
        .join(profile)
        .join("clean-slate-supervisor-userspace");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let raw_image = out_dir.join("supervisor_userspace.bin");

    if !elf.is_file() {
        panic!(
            "missing supervisor userspace ELF at {}; build with:\n  \
             RUSTC_BOOTSTRAP=1 cargo build -p clean-slate-supervisor \
             --bin clean-slate-supervisor-userspace --features userspace \
             --target x86_64-unknown-none -Z build-std=core,compiler_builtins --release",
            elf.display()
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

    println!("cargo:rerun-if-changed={}", elf.display());
    println!(
        "cargo:rerun-if-changed={}",
        manifest_dir.join("build.rs").display()
    );
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
