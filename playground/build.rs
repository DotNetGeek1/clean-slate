use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let script = manifest_dir.join("userspace.ld");
    println!("cargo:rerun-if-changed={}", script.display());
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "none" {
        println!(
            "cargo:rustc-link-arg=-T{}",
            script.display().to_string().replace('\\', "/")
        );
    }
}
