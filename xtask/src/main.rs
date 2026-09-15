use std::env;
use std::ffi::OsString;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const KERNEL_PACKAGE: &str = "clean-slate-kernel";
const KERNEL_TARGET: &str = "x86_64-unknown-uefi";
const QEMU_DEBUG_EXIT_SUCCESS: i32 = 33;
const M1_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M2_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M2_DOUBLE_FAULT_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M2_TIMER_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M3_ADDRESS_SPACE_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M3_ENTRY_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M3_SYSCALL_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M3_LIFECYCLE_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M3_IPC_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M3_RESOURCES_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M1_ACCEPTANCE_MARKERS: [&str; 8] = [
    "[BOOT] UEFI memory map acquired",
    "[BOOT] ExitBootServices OK",
    "[MEM ] physical allocator initialized",
    "[MM  ] page-fault diagnostics installed",
    "[MM  ] scratch page map/unmap OK",
    "[PF  ] page fault",
    "[PF  ] rip=0x",
    "[M1  ] PASS",
];
const M2_DOUBLE_FAULT_ACCEPTANCE_MARKERS: [&str; 4] = [
    "[INT ] double-fault IST initialized",
    "[DF  ] double fault",
    "[DF  ] emergency stack OK",
    "[DF  ] PASS",
];
const M2_ACCEPTANCE_MARKERS: [&str; 12] = [
    "[BOOT] UEFI memory map acquired",
    "[BOOT] ExitBootServices OK",
    "[MEM ] physical allocator initialized",
    "[INT ] IDT initialized",
    "[TIME] timer initialized",
    "[TASK] task 1 started",
    "[TASK] task 2 started",
    "[SCHED] preemption observed",
    "[TASK] task 1 progress=",
    "[TASK] task 2 progress=",
    "[TIME] ticks=",
    "[M2  ] PASS",
];
const M2_TIMER_ACCEPTANCE_MARKERS: [&str; 6] = [
    "[INT ] IDT initialized",
    "[TIME] timer initialized",
    "[TIME] contract=lapic periodic divide=16 initial_count=10000000 tick-rate=uncalibrated",
    "[TIME] tick=1",
    "[TIME] ticks=",
    "[TIME] PASS",
];
const M3_ENTRY_ACCEPTANCE_MARKERS: [&str; 4] = [
    "[USER] entered ring3 rip=0x",
    "[GP  ] privileged instruction denied",
    "cpl=3",
    "[M3.1] PASS",
];
const M3_ADDRESS_SPACE_ACCEPTANCE_MARKERS: [&str; 7] = [
    "[MM  ] process address space created pid=1",
    "[MM  ] process address space created pid=2",
    "[MM  ] address-space switch OK",
    "[SEC ] kernel-memory read denied",
    "[SEC ] cross-process read denied",
    "[MM  ] address-space teardown OK",
    "[M3.2] PASS",
];
const M3_SYSCALL_ACCEPTANCE_MARKERS: [&str; 2] = [
    "[TIME] timer initialized",
    "[SYSC] syscall entry/return PASS",
];
const M3_LIFECYCLE_ACCEPTANCE_MARKERS: [&str; 6] = [
    "[PROC] created pid=1 tid=1",
    "[PROC] created pid=2 tid=2",
    "[PROC] fault pid=1",
    "[PROC] pid=1 exited status=1",
    "[PROC] pid=2 exited status=0",
    "[M3.4] PASS",
];
const M3_IPC_ACCEPTANCE_MARKERS: [&str; 4] = [
    "[CAP ] endpoint capability granted pid=1",
    "[IPC ] send OK bytes=",
    "[CAP ] unauthorized send denied pid=2",
    "[M3.5] PASS",
];
const M3_RESOURCES_ACCEPTANCE_MARKERS: [&str; 4] = [
    "[RES ] baseline pages=",
    "[RES ] pid=1 pages=",
    "[PROC] teardown pid=1 resources=0",
    "[M3.6] PASS",
];

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

    match parse_command(args.next().as_deref()) {
        ParsedCommand::Run => run_vm(),
        ParsedCommand::TestM1 => run_m1_acceptance(),
        ParsedCommand::TestM2 => run_m2_acceptance(),
        ParsedCommand::TestM3AddressSpace => run_m3_address_space_acceptance(),
        ParsedCommand::TestM3Entry => run_m3_entry_acceptance(),
        ParsedCommand::TestM3Syscall => run_m3_syscall_acceptance(),
        ParsedCommand::TestM3Lifecycle => run_m3_lifecycle_acceptance(),
        ParsedCommand::TestM3Ipc => run_m3_ipc_acceptance(),
        ParsedCommand::TestM3Resources => run_m3_resources_acceptance(),
        ParsedCommand::RunGdb => run_vm_with_gdb(false),
        ParsedCommand::RunGdbEntry => run_vm_with_gdb(true),
        ParsedCommand::Build => build_kernel(false, false, &[]),
        ParsedCommand::BuildRelease => build_kernel(true, false, &[]),
        ParsedCommand::Help => {
            print_help();
            Ok(())
        }
        ParsedCommand::Invalid(command) => {
            print_help();
            Err(XtaskError::InvalidCommand(command))
        }
    }
}

fn run_vm() -> Result<(), XtaskError> {
    run_vm_inner(false, false, &[], None)
}

fn run_vm_with_gdb(debug_entry: bool) -> Result<(), XtaskError> {
    run_vm_inner(true, debug_entry, &[], None)
}

fn run_m1_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m1-self-test"],
        Some((&M1_ACCEPTANCE_MARKERS, M1_ACCEPTANCE_TIMEOUT)),
    )
}

fn run_m2_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m2-double-fault-self-test"],
        Some((
            &M2_DOUBLE_FAULT_ACCEPTANCE_MARKERS,
            M2_DOUBLE_FAULT_ACCEPTANCE_TIMEOUT,
        )),
    )?;
    run_vm_inner(
        false,
        false,
        &["m2-timer-self-test"],
        Some((&M2_TIMER_ACCEPTANCE_MARKERS, M2_TIMER_ACCEPTANCE_TIMEOUT)),
    )?;
    run_vm_inner(
        false,
        false,
        &["m2-self-test"],
        Some((&M2_ACCEPTANCE_MARKERS, M2_ACCEPTANCE_TIMEOUT)),
    )
}

fn run_m3_entry_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m3-entry-self-test"],
        Some((&M3_ENTRY_ACCEPTANCE_MARKERS, M3_ENTRY_ACCEPTANCE_TIMEOUT)),
    )
}

fn run_m3_address_space_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m3-address-space-self-test"],
        Some((
            &M3_ADDRESS_SPACE_ACCEPTANCE_MARKERS,
            M3_ADDRESS_SPACE_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m3_syscall_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m3-entry-self-test", "m3-syscall-self-test"],
        Some((
            &M3_SYSCALL_ACCEPTANCE_MARKERS,
            M3_SYSCALL_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m3_lifecycle_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m3-address-space-self-test"],
        Some((
            &M3_LIFECYCLE_ACCEPTANCE_MARKERS,
            M3_LIFECYCLE_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m3_ipc_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m3-ipc-self-test"],
        Some((&M3_IPC_ACCEPTANCE_MARKERS, M3_IPC_ACCEPTANCE_TIMEOUT)),
    )
}

fn run_m3_resources_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m3-resources-self-test"],
        Some((
            &M3_RESOURCES_ACCEPTANCE_MARKERS,
            M3_RESOURCES_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_vm_inner(
    wait_for_gdb: bool,
    debug_entry: bool,
    features: &[&str],
    acceptance: Option<(&[&str], Duration)>,
) -> Result<(), XtaskError> {
    let release = false;
    build_kernel(release, debug_entry, features)?;

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
    if !vars_copy.is_file() {
        fs::copy(&ovmf.vars_template, &vars_copy)?;
    }

    let mut qemu = Command::new("qemu-system-x86_64");
    qemu.arg("-machine")
        .arg("q35")
        .arg("-m")
        .arg("512M")
        .arg("-serial")
        .arg("stdio")
        .arg("-display")
        .arg("none")
        .arg("-no-reboot")
        .arg("-no-shutdown")
        .arg("-device")
        .arg("isa-debug-exit,iobase=0xf4,iosize=0x04")
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,readonly=on,file={}",
            ovmf.code.display()
        ))
        .arg("-drive")
        .arg(format!("if=pflash,format=raw,file={}", vars_copy.display()))
        .arg("-drive")
        .arg(format!("format=raw,file=fat:rw:{}", esp_dir.display()));

    if wait_for_gdb {
        qemu.arg("-S").arg("-s");
    }

    match acceptance {
        Some((markers, timeout)) => run_acceptance_command(&mut qemu, markers, timeout),
        None => run_command(&mut qemu),
    }
}

fn build_kernel(release: bool, debug_entry: bool, features: &[&str]) -> Result<(), XtaskError> {
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
    let mut feature_list = Vec::new();
    if debug_entry {
        feature_list.push("gdb-entry");
    }
    feature_list.extend(features.iter().copied());
    if !feature_list.is_empty() {
        cmd.arg("--features").arg(feature_list.join(","));
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
    let env_ovmf = ovmf_from_env(env::var_os("OVMF_CODE"), env::var_os("OVMF_VARS"));
    if let Some(ovmf) = env_ovmf {
        if ovmf.code.is_file() && ovmf.vars_template.is_file() {
            return Ok(ovmf);
        }
        return Err(XtaskError::MissingOvmf);
    }

    let candidates = [
        OvmfPaths {
            code: PathBuf::from("/usr/share/OVMF/OVMF_CODE.fd"),
            vars_template: PathBuf::from("/usr/share/OVMF/OVMF_VARS.fd"),
        },
        OvmfPaths {
            code: PathBuf::from("/usr/share/OVMF/OVMF_CODE_4M.fd"),
            vars_template: PathBuf::from("/usr/share/OVMF/OVMF_VARS_4M.fd"),
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

    select_ovmf_from_candidates(candidates.into_iter()).ok_or(XtaskError::MissingOvmf)
}

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask in workspace")
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
    if status.success() || status.code() == Some(QEMU_DEBUG_EXIT_SUCCESS) {
        Ok(())
    } else {
        Err(XtaskError::CommandFailed {
            command: command_display,
            status: status.to_string(),
        })
    }
}

fn run_acceptance_command(
    command: &mut Command,
    markers: &[&str],
    timeout: Duration,
) -> Result<(), XtaskError> {
    let start = std::time::Instant::now();
    let command_display = format!(
        "{} {}",
        command.get_program().to_string_lossy(),
        command
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );

    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("failed to capture child stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("failed to capture child stderr"))?;
    let (tx, rx) = mpsc::channel();
    let stdout_handle = spawn_output_reader(stdout, false, tx.clone());
    let stderr_handle = spawn_output_reader(stderr, true, tx);

    let mut tracker = MarkerTracker::new(markers);
    let mut output = String::new();
    let mut readers_finished = 0usize;
    let mut authoritative_pass = false;
    let mut child_status = None;

    loop {
        if start.elapsed() >= timeout && !authoritative_pass {
            terminate_child(&mut child)?;
            let _ = child.wait();
            join_output_reader(stdout_handle);
            join_output_reader(stderr_handle);
            drain_output_events(&rx, &mut output);
            return Err(XtaskError::CommandTimedOut {
                command: command_display,
                timeout: timeout.as_secs(),
            });
        }

        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(OutputEvent::Chunk(chunk)) => {
                if chunk.is_stderr {
                    eprint!("{}", chunk.text);
                } else {
                    print!("{}", chunk.text);
                }
                output.push_str(&chunk.text);
                if tracker.consume(&output) && !authoritative_pass {
                    authoritative_pass = true;
                    terminate_child(&mut child)?;
                    child_status = Some(child.wait()?);
                }
            }
            Ok(OutputEvent::Finished) => {
                readers_finished += 1;
            }
            Ok(OutputEvent::ReadError(error)) => {
                terminate_child(&mut child).ok();
                let _ = child.wait();
                join_output_reader(stdout_handle);
                join_output_reader(stderr_handle);
                return Err(XtaskError::Io(error));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                readers_finished = 2;
            }
        }

        if child_status.is_none() {
            child_status = child.try_wait()?;
        }

        if readers_finished == 2 && child_status.is_some() {
            break;
        }
    }

    join_output_reader(stdout_handle);
    join_output_reader(stderr_handle);
    drain_output_events(&rx, &mut output);

    if authoritative_pass {
        return Ok(());
    }

    let status = child_status.unwrap_or(child.wait()?);
    if !(status.success() || status.code() == Some(QEMU_DEBUG_EXIT_SUCCESS)) {
        return Err(XtaskError::CommandFailed {
            command: command_display,
            status: status.to_string(),
        });
    }

    validate_output_markers(&output, markers)
}

fn validate_output_markers(output: &str, markers: &[&str]) -> Result<(), XtaskError> {
    let mut tracker = MarkerTracker::new(markers);
    if tracker.consume(output) {
        Ok(())
    } else {
        Err(XtaskError::MissingMarker(
            markers[tracker.next_marker].to_owned(),
        ))
    }
}

struct MarkerTracker<'a> {
    markers: &'a [&'a str],
    next_marker: usize,
    search_start: usize,
}

impl<'a> MarkerTracker<'a> {
    fn new(markers: &'a [&'a str]) -> Self {
        Self {
            markers,
            next_marker: 0,
            search_start: 0,
        }
    }

    fn consume(&mut self, output: &str) -> bool {
        while self.next_marker < self.markers.len() {
            let marker = self.markers[self.next_marker];
            let Some(offset) = output[self.search_start..].find(marker) else {
                break;
            };
            self.search_start += offset + marker.len();
            self.next_marker += 1;
        }
        self.next_marker == self.markers.len()
    }
}

struct OutputChunk {
    is_stderr: bool,
    text: String,
}

enum OutputEvent {
    Chunk(OutputChunk),
    Finished,
    ReadError(std::io::Error),
}

fn spawn_output_reader<R: Read + Send + 'static>(
    mut reader: R,
    is_stderr: bool,
    tx: mpsc::Sender<OutputEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0u8; 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    let _ = tx.send(OutputEvent::Finished);
                    break;
                }
                Ok(bytes_read) => {
                    let text = String::from_utf8_lossy(&buffer[..bytes_read]).into_owned();
                    let _ = tx.send(OutputEvent::Chunk(OutputChunk { is_stderr, text }));
                }
                Err(error) => {
                    let _ = tx.send(OutputEvent::ReadError(error));
                    break;
                }
            }
        }
    })
}

fn terminate_child(child: &mut std::process::Child) -> Result<(), XtaskError> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    match child.kill() {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
        Err(error) => Err(XtaskError::Io(error)),
    }
}

fn join_output_reader(handle: thread::JoinHandle<()>) {
    let _ = handle.join();
}

fn drain_output_events(receiver: &mpsc::Receiver<OutputEvent>, output: &mut String) {
    while let Ok(event) = receiver.try_recv() {
        if let OutputEvent::Chunk(chunk) = event {
            if chunk.is_stderr {
                eprint!("{}", chunk.text);
            } else {
                print!("{}", chunk.text);
            }
            output.push_str(&chunk.text);
        }
    }
}

fn print_help() {
    println!("Usage: cargo xtask <command>");
    println!("  run          Build kernel and launch QEMU for normal development boot");
    println!("  test-m1      Build the M1 self-test kernel, run QEMU, and validate PASS markers");
    println!("  test-m2      Build the M2 self-test kernel, run QEMU, and validate PASS markers");
    println!("  test-m3-address-space Build the M3.2 address-space kernel, run QEMU, and validate PASS markers");
    println!("  test-m3-entry Build the M3.1 userspace-entry kernel, run QEMU, and validate PASS markers");
    println!("  test-m3-syscall Build the M3.3 syscall-entry kernel, run QEMU, and validate PASS markers");
    println!("  test-m3-lifecycle Build the M3.4 process/thread-lifecycle kernel, run QEMU, and validate PASS markers");
    println!("  test-m3-ipc Build the M3.5 capability-authorized IPC kernel, run QEMU, and validate PASS markers");
    println!("  test-m3-resources Build the M3.6 resource-accounting kernel, run QEMU, and validate PASS markers");
    println!("  run-gdb      Build kernel, launch paused with gdb endpoint (:1234)");
    println!("  run-gdb-entry Build debug-entry kernel, pause QEMU, trap in efi_main");
    println!("  build        Build debug UEFI kernel only");
    println!("  build-release  Build release UEFI kernel only");
}

#[derive(Clone, Debug)]
struct OvmfPaths {
    code: PathBuf,
    vars_template: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
enum ParsedCommand {
    Run,
    TestM1,
    TestM2,
    TestM3AddressSpace,
    TestM3Entry,
    TestM3Syscall,
    TestM3Lifecycle,
    TestM3Ipc,
    TestM3Resources,
    RunGdb,
    RunGdbEntry,
    Build,
    BuildRelease,
    Help,
    Invalid(String),
}

fn parse_command(command: Option<&std::ffi::OsStr>) -> ParsedCommand {
    match command {
        Some(cmd) if cmd == "run" => ParsedCommand::Run,
        Some(cmd) if cmd == "test-m1" => ParsedCommand::TestM1,
        Some(cmd) if cmd == "test-m2" => ParsedCommand::TestM2,
        Some(cmd) if cmd == "test-m3-address-space" => ParsedCommand::TestM3AddressSpace,
        Some(cmd) if cmd == "test-m3-entry" => ParsedCommand::TestM3Entry,
        Some(cmd) if cmd == "test-m3-syscall" => ParsedCommand::TestM3Syscall,
        Some(cmd) if cmd == "test-m3-lifecycle" => ParsedCommand::TestM3Lifecycle,
        Some(cmd) if cmd == "test-m3-ipc" => ParsedCommand::TestM3Ipc,
        Some(cmd) if cmd == "test-m3-resources" => ParsedCommand::TestM3Resources,
        Some(cmd) if cmd == "run-gdb" => ParsedCommand::RunGdb,
        Some(cmd) if cmd == "run-gdb-entry" => ParsedCommand::RunGdbEntry,
        Some(cmd) if cmd == "build" => ParsedCommand::Build,
        Some(cmd) if cmd == "build-release" => ParsedCommand::BuildRelease,
        Some(cmd) if cmd == "help" || cmd == "--help" || cmd == "-h" => ParsedCommand::Help,
        Some(cmd) => ParsedCommand::Invalid(cmd.to_string_lossy().into_owned()),
        None => ParsedCommand::Help,
    }
}

fn ovmf_from_env(code: Option<OsString>, vars: Option<OsString>) -> Option<OvmfPaths> {
    match (code, vars) {
        (Some(code), Some(vars)) => Some(OvmfPaths {
            code: PathBuf::from(code),
            vars_template: PathBuf::from(vars),
        }),
        _ => None,
    }
}

fn select_ovmf_from_candidates(
    candidates: impl IntoIterator<Item = OvmfPaths>,
) -> Option<OvmfPaths> {
    candidates
        .into_iter()
        .find(|ovmf| ovmf.code.is_file() && ovmf.vars_template.is_file())
}

#[derive(Debug)]
enum XtaskError {
    CommandFailed { command: String, status: String },
    CommandTimedOut { command: String, timeout: u64 },
    InvalidCommand(String),
    Io(std::io::Error),
    MissingMarker(String),
    MissingFile(PathBuf),
    MissingOvmf,
}

impl Display for XtaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            XtaskError::CommandFailed { command, status } => {
                write!(f, "command `{command}` failed with status {status}")
            }
            XtaskError::CommandTimedOut { command, timeout } => {
                write!(f, "command `{command}` timed out after {timeout}s")
            }
            XtaskError::InvalidCommand(command) => write!(f, "unknown command `{command}`"),
            XtaskError::Io(error) => write!(f, "{error}"),
            XtaskError::MissingMarker(marker) => {
                write!(f, "acceptance output missing required marker `{marker}`")
            }
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
    use std::time::{SystemTime, UNIX_EPOCH};

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

    #[test]
    fn parse_known_command() {
        assert_eq!(parse_command(Some("run".as_ref())), ParsedCommand::Run);
        assert_eq!(
            parse_command(Some("test-m1".as_ref())),
            ParsedCommand::TestM1
        );
        assert_eq!(
            parse_command(Some("test-m2".as_ref())),
            ParsedCommand::TestM2
        );
        assert_eq!(
            parse_command(Some("test-m3-address-space".as_ref())),
            ParsedCommand::TestM3AddressSpace
        );
        assert_eq!(
            parse_command(Some("test-m3-entry".as_ref())),
            ParsedCommand::TestM3Entry
        );
        assert_eq!(
            parse_command(Some("test-m3-syscall".as_ref())),
            ParsedCommand::TestM3Syscall
        );
        assert_eq!(
            parse_command(Some("test-m3-lifecycle".as_ref())),
            ParsedCommand::TestM3Lifecycle
        );
        assert_eq!(
            parse_command(Some("test-m3-ipc".as_ref())),
            ParsedCommand::TestM3Ipc
        );
        assert_eq!(
            parse_command(Some("test-m3-resources".as_ref())),
            ParsedCommand::TestM3Resources
        );
        assert_eq!(
            parse_command(Some("run-gdb-entry".as_ref())),
            ParsedCommand::RunGdbEntry
        );
    }

    #[test]
    fn parse_unknown_command() {
        assert_eq!(
            parse_command(Some("wat".as_ref())),
            ParsedCommand::Invalid("wat".to_owned())
        );
    }

    #[test]
    fn prefer_env_ovmf_when_both_set() {
        let ovmf = ovmf_from_env(Some("code.fd".into()), Some("vars.fd".into()));
        assert!(ovmf.is_some());
        let ovmf = ovmf.expect("must return env ovmf");
        assert_eq!(ovmf.code, PathBuf::from("code.fd"));
        assert_eq!(ovmf.vars_template, PathBuf::from("vars.fd"));
    }

    #[test]
    fn select_existing_ovmf_candidate() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time works")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("clean-slate-ovmf-test-{unique}"));
        fs::create_dir_all(&base).expect("create temp dir");

        let missing = OvmfPaths {
            code: base.join("missing_code.fd"),
            vars_template: base.join("missing_vars.fd"),
        };
        let valid = OvmfPaths {
            code: base.join("OVMF_CODE.fd"),
            vars_template: base.join("OVMF_VARS.fd"),
        };
        fs::write(&valid.code, b"code").expect("write code");
        fs::write(&valid.vars_template, b"vars").expect("write vars");

        let selected = select_ovmf_from_candidates([missing.clone(), valid.clone()]);
        assert!(selected.is_some());
        let selected = selected.expect("must select valid candidate");
        assert_eq!(selected.code, valid.code);
        assert_eq!(selected.vars_template, valid.vars_template);

        fs::remove_dir_all(base).expect("cleanup temp dir");
    }

    #[test]
    fn acceptance_marker_validation_requires_ordered_sequence() {
        let valid = "\
[BOOT] UEFI memory map acquired\n\
[BOOT] ExitBootServices OK\n\
[MEM ] physical allocator initialized\n\
[MM  ] page-fault diagnostics installed\n\
[MM  ] scratch page map/unmap OK\n\
[PF  ] page fault\n\
[PF  ] rip=0x0000000012345678 cs=0x0038 rflags=0x0000000000000002\n\
[M1  ] PASS\n";
        assert!(validate_output_markers(valid, &M1_ACCEPTANCE_MARKERS).is_ok());

        let invalid = "\
[BOOT] UEFI memory map acquired\n\
[MEM ] physical allocator initialized\n\
[BOOT] ExitBootServices OK\n";
        assert!(validate_output_markers(invalid, &M1_ACCEPTANCE_MARKERS).is_err());
    }

    #[test]
    fn marker_tracker_detects_ordered_markers_incrementally() {
        let mut tracker = MarkerTracker::new(&M2_ACCEPTANCE_MARKERS);
        assert!(!tracker.consume("[BOOT] UEFI memory map acquired\n[TIME] timer initialized\n"));
        assert!(!tracker.consume(
            "[BOOT] UEFI memory map acquired\n\
[BOOT] ExitBootServices OK\n\
[MEM ] physical allocator initialized\n\
[INT ] IDT initialized\n\
[TIME] timer initialized\n\
[TASK] task 1 started\n\
[TASK] task 2 started\n\
[SCHED] preemption observed\n"
        ));
        assert!(tracker.consume(
            "[BOOT] UEFI memory map acquired\n\
[BOOT] ExitBootServices OK\n\
[MEM ] physical allocator initialized\n\
[INT ] IDT initialized\n\
[TIME] timer initialized\n\
[TASK] task 1 started\n\
[TASK] task 2 started\n\
[SCHED] preemption observed\n\
[TASK] task 1 progress=1\n\
[TASK] task 2 progress=1\n\
[TIME] ticks=4\n\
[M2  ] PASS\n"
        ));
    }
}
