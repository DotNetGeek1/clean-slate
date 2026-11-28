//! #372 power lane (`cargo xtask test-m10-power`).
//!
//! The power host tests (FADT and `\_S5` parsing against captured QEMU q35 tables, the
//! `POWER` syscall's refusals and their audit records), then two QEMU boots:
//!
//! - `power-off-self-test` powers the machine off at the end of boot. QEMU must exit on its
//!   own with status 0, the guest-shutdown status: not the `isa-debug-exit` status a kernel
//!   verdict uses, and not because the lane killed it.
//! - `power-reset-self-test` resets the machine at the end of boot, through the FADT reset
//!   register. QEMU runs without `-no-reboot`, so the guest boots again in the same session; the
//!   lane waits for the second kernel banner ([`KERNEL_BOOT_BANNER`]) and then stops QEMU.

use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::guest_reboot::KERNEL_BOOT_BANNER;
use crate::{
    drain_output_events, join_output_reader, prepare_vm, run_cargo_package_tests,
    spawn_output_reader, terminate_child, timeout_context, OutputEvent, ReapOnDrop, VmLaunchConfig,
    XtaskError,
};

pub(crate) const OFF_FEATURE: &str = "power-off-self-test";
pub(crate) const RESET_FEATURE: &str = "power-reset-self-test";
const TIMEOUT: Duration = Duration::from_secs(60);

const SELF_TEST_LINE: &str = "[PWR ] self-test at the end of boot";
const ACPI_LINE: &str = "[PWR ] acpi pm1a=";
const OFF_LINE: &str = "[PWR ] off slp_typ=";
const OFF_FAILED: &str = "[PWR ] off failed";
const RESET_FADT_LINE: &str = "[PWR ] reset method=fadt";
const RESET_FALLBACK: &str = "[PWR ] reset method=8042";

pub(crate) fn run() -> Result<(), XtaskError> {
    run_cargo_package_tests("clean-slate-capability", &["power"])?;
    run_cargo_package_tests("clean-slate-native-abi", &["power"])?;
    run_cargo_package_tests(
        "clean-slate-kernel",
        &["--", "power::", "dispatch_native_power"],
    )?;

    let mut vm = prepare_vm(false, false, &[OFF_FEATURE], VmLaunchConfig::default())?;
    let session = run_session(&mut vm.qemu, Stop::OnExit)?;
    check_power_off(&session)?;
    println!("[M10.power] the guest powered QEMU off (exit status 0)");

    let vm = prepare_vm(false, false, &[RESET_FEATURE], VmLaunchConfig::default())?;
    let mut rebooting = without_no_reboot(&vm.qemu);
    let session = run_session(&mut rebooting, Stop::OnSecondBoot)?;
    check_reset(&session)?;
    println!("[M10.power] the guest reset through the FADT reset register and booted again");
    println!("[M10.power] lane PASS");
    Ok(())
}

/// `qemu` without `-no-reboot`, so a guest reset boots again in the same QEMU session.
fn without_no_reboot(qemu: &Command) -> Command {
    let mut rebooting = Command::new(qemu.get_program());
    rebooting.args(qemu.get_args().filter(|arg| *arg != "-no-reboot"));
    rebooting
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    /// Wait for QEMU to exit by itself.
    OnExit,
    /// Stop QEMU once the kernel banner has been printed twice.
    OnSecondBoot,
}

struct Session {
    command: String,
    output: String,
    /// QEMU's status when it exited by itself; `None` when the lane stopped it.
    exited: Option<ExitStatus>,
}

/// Runs QEMU until it exits ([`Stop::OnExit`]) or the guest has booted twice
/// ([`Stop::OnSecondBoot`]), printing its output as it comes.
fn run_session(command: &mut Command, stop: Stop) -> Result<Session, XtaskError> {
    let display = format!(
        "{} {}",
        command.get_program().to_string_lossy(),
        command
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = ReapOnDrop(command.spawn()?);
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
    let start = Instant::now();
    let mut output = String::new();
    let mut readers_finished = 0usize;
    let mut exited = None;
    loop {
        if start.elapsed() >= TIMEOUT {
            terminate_child(&mut child)?;
            let _ = child.wait();
            join_output_reader(stdout_handle);
            join_output_reader(stderr_handle);
            drain_output_events(&rx, &mut output);
            return Err(XtaskError::CommandTimedOut {
                command: display,
                timeout: TIMEOUT.as_secs(),
                context: timeout_context(&output, None),
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
            }
            Ok(OutputEvent::Finished) => readers_finished += 1,
            Ok(OutputEvent::ReadError(error)) => {
                terminate_child(&mut child).ok();
                let _ = child.wait();
                return Err(XtaskError::Io(error));
            }
            Ok(OutputEvent::DriverWake) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => readers_finished = 2,
        }
        if stop == Stop::OnSecondBoot && kernel_banners(&output) >= 2 {
            terminate_child(&mut child)?;
            let _ = child.wait();
            break;
        }
        if exited.is_none() {
            exited = child.try_wait()?;
        }
        if readers_finished == 2 && exited.is_some() {
            break;
        }
    }
    join_output_reader(stdout_handle);
    join_output_reader(stderr_handle);
    drain_output_events(&rx, &mut output);
    Ok(Session {
        command: display,
        output,
        exited,
    })
}

fn kernel_banners(output: &str) -> usize {
    let banner = std::str::from_utf8(KERNEL_BOOT_BANNER).unwrap_or("");
    output.matches(banner).count()
}

fn fail(session: &Session, why: String) -> XtaskError {
    XtaskError::CommandFailed {
        command: session.command.clone(),
        status: why,
    }
}

/// Every line the off boot needs, in order, at most one boot, no failure, and QEMU's own exit
/// with status 0.
fn check_power_off(session: &Session) -> Result<(), XtaskError> {
    let output = &session.output;
    check_common(session)?;
    if kernel_banners(output) != 1 {
        return Err(fail(
            session,
            format!("expected one boot, saw {}", kernel_banners(output)),
        ));
    }
    in_order(session, &[ACPI_LINE, SELF_TEST_LINE, OFF_LINE])?;
    if output.contains(OFF_FAILED) {
        return Err(fail(
            session,
            "the kernel reports the S5 write failed".into(),
        ));
    }
    match session.exited {
        Some(status) if status.success() => Ok(()),
        Some(status) => Err(fail(
            session,
            format!("QEMU exited with {status}, not the guest-shutdown status 0"),
        )),
        None => Err(fail(session, "QEMU did not exit".into())),
    }
}

/// The reset line through the FADT register before the second banner, and no fallback.
fn check_reset(session: &Session) -> Result<(), XtaskError> {
    let output = &session.output;
    check_common(session)?;
    let banner = std::str::from_utf8(KERNEL_BOOT_BANNER).unwrap_or("");
    let second = output
        .match_indices(banner)
        .nth(1)
        .map(|(at, _)| at)
        .ok_or_else(|| fail(session, "the guest did not boot a second time".into()))?;
    let first_boot = &output[..second];
    let first = Session {
        command: session.command.clone(),
        output: first_boot.to_owned(),
        exited: None,
    };
    in_order(&first, &[ACPI_LINE, SELF_TEST_LINE, RESET_FADT_LINE])?;
    if first_boot.contains(RESET_FALLBACK) {
        return Err(fail(
            session,
            "the FADT reset register did not reset the machine (the 8042 fallback ran)".into(),
        ));
    }
    Ok(())
}

fn check_common(session: &Session) -> Result<(), XtaskError> {
    if let Some(line) = session.output.lines().find(|line| line.contains("[FAIL]")) {
        return Err(fail(session, format!("guest reported a failure: {line}")));
    }
    Ok(())
}

fn in_order(session: &Session, lines: &[&str]) -> Result<(), XtaskError> {
    let mut from = 0;
    for line in lines {
        match session.output[from..].find(line) {
            Some(at) => from += at + line.len(),
            None => return Err(fail(session, format!("missing `{line}` (in order)"))),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    const ACPI: &str = "[PWR ] acpi pm1a=0x604 pm1b=none reset=io:0xcf9=0x0f s5=0/0 source=dsdt\n";
    const BANNER: &str = "[BOOT] UEFI memory map acquired\n";

    fn session(output: &str, exited: Option<i32>) -> Session {
        Session {
            command: "qemu".into(),
            output: output.into(),
            exited: exited.map(|code| ExitStatus::from_raw(code << 8)),
        }
    }

    fn off_boot() -> String {
        format!(
            "{BANNER}{ACPI}[PWR ] self-test at the end of boot\n[PWR ] off slp_typ=0/0 source=dsdt pm1a=0x604 pm1b=none\n"
        )
    }

    fn reset_boot() -> String {
        format!(
            "{BANNER}{ACPI}[PWR ] self-test at the end of boot\n[PWR ] reset method=fadt port=0xcf9 value=0x0f\n"
        )
    }

    #[test]
    fn the_reset_boot_drops_only_no_reboot() {
        let mut qemu = Command::new("qemu-system-x86_64");
        qemu.args(["-machine", "q35", "-no-reboot", "-device", "isa-debug-exit"]);
        let rebooting = without_no_reboot(&qemu);
        assert_eq!(rebooting.get_program(), "qemu-system-x86_64");
        let args: Vec<_> = rebooting.get_args().collect();
        assert_eq!(args, ["-machine", "q35", "-device", "isa-debug-exit"]);
    }

    #[test]
    fn the_off_boot_passes_only_on_qemus_own_zero_exit() {
        assert!(check_power_off(&session(&off_boot(), Some(0))).is_ok());
        // `isa-debug-exit` failure status (0x11 << 1 | 1) or a killed QEMU.
        assert!(check_power_off(&session(&off_boot(), Some(35))).is_err());
        assert!(check_power_off(&session(&off_boot(), None)).is_err());
    }

    #[test]
    fn the_off_boot_needs_every_line_once_and_no_failure() {
        let missing = off_boot().replace("[PWR ] off slp_typ", "[PWR ] of");
        assert!(check_power_off(&session(&missing, Some(0))).is_err());
        let twice = format!("{}{}", off_boot(), off_boot());
        assert!(check_power_off(&session(&twice, Some(0))).is_err());
        let failed = format!("{}[PWR ] off failed: still running\n", off_boot());
        assert!(check_power_off(&session(&failed, Some(0))).is_err());
        let fail = format!("{}[FAIL] something\n", off_boot());
        assert!(check_power_off(&session(&fail, Some(0))).is_err());
    }

    #[test]
    fn the_reset_boot_needs_the_fadt_reset_before_a_second_boot() {
        let rebooted = format!("{}BdsDxe: loading Boot0001\n{BANNER}", reset_boot());
        assert!(check_reset(&session(&rebooted, None)).is_ok());
        assert!(check_reset(&session(&reset_boot(), None)).is_err());
        let fallback = rebooted.replace(
            "[PWR ] reset method=fadt port=0xcf9 value=0x0f\n",
            "[PWR ] reset method=fadt port=0xcf9 value=0x0f\n[PWR ] reset method=8042\n",
        );
        assert!(check_reset(&session(&fallback, None)).is_err());
        // The reset line must come from the first boot.
        let late = format!(
            "{BANNER}{ACPI}[PWR ] self-test at the end of boot\n{BANNER}[PWR ] reset method=fadt\n"
        );
        assert!(check_reset(&session(&late, None)).is_err());
    }
}
