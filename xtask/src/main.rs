use std::env;
use std::ffi::OsString;
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const KERNEL_PACKAGE: &str = "clean-slate-kernel";
const KERNEL_TARGET: &str = "x86_64-unknown-uefi";

fn main() -> ExitCode {
    match run(env::args_os()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn run(args: impl IntoIterator<Item = OsString>) -> Result<(), XtaskError> {
    let mut args = args.into_iter();
    let _exe = args.next();

    match args.next().as_deref() {
        Some(cmd) if cmd == "run" => run_vm(),
        Some(cmd) if cmd == "run-gdb" => run_vm_with_gdb(),
        Some(cmd) if cmd == "build" => build_kernel(false),
        Some(cmd) if cmd == "build-release" => build_kernel(true),
        Some(_) | None => {
            print_help();
            Ok(())
        }
    }
}

fn run_vm() -> Result<(), XtaskError> {
    run_vm_inner(false)
}

fn run_vm_with_gdb() -> Result<(), XtaskError> {
    run_vm_inner(true)
}

fn run_vm_inner(wait_for_gdb: bool) -> Result<(), XtaskError> {
    let release = false;
    build_kernel(release)?;

    let kernel = kernel_artifact(release);
    if !kernel.is_file() {
        return Err(XtaskError::MissingFile(kernel));
    }

    let esp_dir = workspace_root().join("target").join("esp");
    let esp_boot_dir = esp_dir.join("EFI").join("BOOT");
    fs::create_dir_all(&esp_boot_dir)?;
    fs::copy(&kernel, esp_boot_dir.join("BOOTX64.EFI"))?;

    let ovmf = find_ovmf()?;
    let vars_copy = workspace_root().join("target").join("OVMF_VARS.fd");
    fs::copy(&ovmf.vars_template, &vars_copy)?;

    let mut qemu = Command::new("qemu-system-x86_64");
    qemu
        .arg("-machine")
        .arg("q35")
        .arg("-m")
        .arg("512M")
        .arg("-serial")
        .arg("stdio")
        .arg("-display")
        .arg("none")
        .arg("-no-reboot")
        .arg("-no-shutdown")
        .arg("-drive")
        .arg(format!("if=pflash,format=raw,readonly=on,file={}", ovmf.code.display()))
        .arg("-drive")
        .arg(format!("if=pflash,format=raw,file={}", vars_copy.display()))
        .arg("-drive")
        .arg(format!("format=raw,file=fat:rw:{}", esp_dir.display()));

    if wait_for_gdb {
        qemu.arg("-S").arg("-s");
    }

    run_command(&mut qemu)
}

fn build_kernel(release: bool) -> Result<(), XtaskError> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace_root())
        .arg("build")
        .arg("-p")
        .arg(KERNEL_PACKAGE)
        .arg("--target")
        .arg(KERNEL_TARGET);

    if release {
        cmd.arg("--release");
    }

    run_command(&mut cmd)
}

fn kernel_artifact(release: bool) -> PathBuf {
    let profile = if release { "release" } else { "debug" };
    workspace_root()
        .join("target")
        .join(KERNEL_TARGET)
        .join(profile)
        .join(format!("{KERNEL_PACKAGE}.efi"))
}

fn find_ovmf() -> Result<OvmfPaths, XtaskError> {
    if let (Some(code), Some(vars)) = (
        env::var_os("OVMF_CODE"),
        env::var_os("OVMF_VARS"),
    ) {
        return Ok(OvmfPaths {
            code: PathBuf::from(code),
            vars_template: PathBuf::from(vars),
        });
    }

    let candidates = [
        OvmfPaths {
            code: PathBuf::from("/usr/share/OVMF/OVMF_CODE.fd"),
            vars_template: PathBuf::from("/usr/share/OVMF/OVMF_VARS.fd"),
        },
        OvmfPaths {
            code: PathBuf::from("/usr/share/edk2/ovmf/OVMF_CODE.fd"),
            vars_template: PathBuf::from("/usr/share/edk2/ovmf/OVMF_VARS.fd"),
        },
        OvmfPaths {
            code: PathBuf::from("/usr/share/edk2-ovmf/x64/OVMF_CODE.fd"),
            vars_template: PathBuf::from("/usr/share/edk2-ovmf/x64/OVMF_VARS.fd"),
        },
    ];

    candidates
        .into_iter()
        .find(|ovmf| ovmf.code.is_file() && ovmf.vars_template.is_file())
        .ok_or(XtaskError::MissingOvmf)
}

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("xtask in workspace")
}

fn run_command(command: &mut Command) -> Result<(), XtaskError> {
    let command_display = format!(
        "{} {}",
        command.get_program().to_string_lossy(),
        command
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(XtaskError::CommandFailed {
            command: command_display,
            status: status.to_string(),
        })
    }
}

fn print_help() {
    println!("Usage: cargo xtask <command>");
    println!("  run          Build kernel and launch QEMU");
    println!("  run-gdb      Build kernel, launch paused with gdb endpoint (:1234)");
    println!("  build        Build debug UEFI kernel only");
    println!("  build-release  Build release UEFI kernel only");
}

#[derive(Debug)]
struct OvmfPaths {
    code: PathBuf,
    vars_template: PathBuf,
}

#[derive(Debug)]
enum XtaskError {
    CommandFailed { command: String, status: String },
    Io(std::io::Error),
    MissingFile(PathBuf),
    MissingOvmf,
}

impl Display for XtaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            XtaskError::CommandFailed { command, status } => {
                write!(f, "command `{command}` failed with status {status}")
            }
            XtaskError::Io(error) => write!(f, "{error}"),
            XtaskError::MissingFile(path) => write!(f, "missing file: {}", path.display()),
            XtaskError::MissingOvmf => write!(
                f,
                "OVMF firmware not found. Set OVMF_CODE and OVMF_VARS or install OVMF."
            ),
        }
    }
}

impl From<std::io::Error> for XtaskError {
    fn from(value: std::io::Error) -> Self {
        XtaskError::Io(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_debug_artifact_path_is_expected() {
        let artifact = kernel_artifact(false);
        assert!(artifact.ends_with("target/x86_64-unknown-uefi/debug/clean-slate-kernel.efi"));
    }

    #[test]
    fn kernel_release_artifact_path_is_expected() {
        let artifact = kernel_artifact(true);
        assert!(artifact.ends_with("target/x86_64-unknown-uefi/release/clean-slate-kernel.efi"));
    }
}
