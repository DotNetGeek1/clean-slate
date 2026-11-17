//! `test-system`'s desktop boot, driven over COM1 (#218 S6d): the hooks build faults each
//! desktop row in turn and init brings the desktop back.

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::Path;
use std::process::Stdio;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::guest_reboot::GuestRebootDetector;
use crate::serial_input_lane::{accept_serial, find, spawn_serial_reader, tail, SerialEvent};
use crate::system_boot::{desktop_qemu_args, start_shell_fixture_peer, system_vm_config};
use crate::system_shell::qemu_state;
use crate::{
    announce_qemu_version, prepare_vm, xtask_artifact_root, ReapOnDrop, VmLaunchConfig, XtaskError,
};

const LANE_TIMEOUT: Duration = Duration::from_secs(300);
const STEP_TIMEOUT: Duration = Duration::from_secs(60);

/// One thing typed on COM1 and what must follow it.
pub(crate) struct Step {
    pub(crate) name: &'static str,
    pub(crate) send: &'static [u8],
}

/// Checks the output since the previous step was typed (the boot for the first call); `Ok`
/// once the step is complete.
pub(crate) type Check<'a, S> = dyn FnMut(usize, &str, Option<&S>) -> Result<S, String> + 'a;

/// Boots the hooks build with the desktop entry and a VirtIO-GPU, then types each step once the
/// one before it is complete. Returns the transcript and the state after the boot and each step.
pub(crate) fn drive<S: Clone>(
    features: &[&str],
    disk: &Path,
    steps: &[Step],
    forbidden: &[&str],
    check: &mut Check<'_, S>,
) -> Result<(Vec<u8>, Vec<S>), XtaskError> {
    let peer = start_shell_fixture_peer()?;
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let config = VmLaunchConfig {
        machine_extra: Some("vmport=off"),
        extra_args: desktop_qemu_args(false),
        serial_tcp_port: Some(listener.local_addr()?.port()),
        ..system_vm_config(disk.to_path_buf(), Some(peer.port()))
    };
    let result = run(features, &listener, config, steps, forbidden, check);
    peer.shutdown();
    result
}

fn save_transcript(transcript: &[u8]) -> Result<(), XtaskError> {
    let dir = xtask_artifact_root().join("system");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("desktop-serial.log");
    std::fs::write(&path, transcript)?;
    println!("[STM ] desktop serial transcript: {}", path.display());
    Ok(())
}

fn run<S: Clone>(
    features: &[&str],
    listener: &TcpListener,
    config: VmLaunchConfig,
    steps: &[Step],
    forbidden: &[&str],
    check: &mut Check<'_, S>,
) -> Result<(Vec<u8>, Vec<S>), XtaskError> {
    let mut vm = prepare_vm(false, false, features, config)?;
    announce_qemu_version(&vm.qemu);
    vm.qemu.stdin(Stdio::null());
    let deadline = Instant::now() + LANE_TIMEOUT;
    let mut child = ReapOnDrop(vm.qemu.spawn()?);
    let stream = accept_serial(listener, &mut child, deadline)?;
    let mut writer = stream.try_clone()?;
    let (tx, rx) = mpsc::channel();
    let _reader = spawn_serial_reader(stream, tx);

    let mut transcript = Vec::new();
    let mut reboot_detector = GuestRebootDetector::default();
    let mut states: Vec<S> = Vec::new();
    let mut typed_at = 0usize;
    let mut step_started = Instant::now();
    let fail = |transcript: &[u8], message: String| {
        let _ = save_transcript(transcript);
        Err(XtaskError::Validation(format!(
            "desktop boot: {message}; tail {:?}",
            tail(transcript)
        )))
    };
    loop {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(SerialEvent::Bytes(bytes)) => {
                print!("{}", String::from_utf8_lossy(&bytes));
                let _ = std::io::stdout().flush();
                transcript.extend_from_slice(&bytes);
            }
            Ok(SerialEvent::Closed) => {
                let qemu = qemu_state(&mut child)?;
                return fail(
                    &transcript,
                    format!("QEMU closed the serial port; QEMU {qemu}"),
                );
            }
            Ok(SerialEvent::Failed(error)) => {
                let qemu = qemu_state(&mut child)?;
                return fail(
                    &transcript,
                    format!("reading the serial port failed ({error}); QEMU {qemu}"),
                );
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return fail(&transcript, "serial reader stopped".to_owned())
            }
        }
        if let Some(reboot) = reboot_detector.observe(&transcript) {
            return fail(&transcript, reboot);
        }
        let waiting = match states.len() {
            0 => "boot",
            done => steps[done - 1].name,
        };
        let segment = String::from_utf8_lossy(&transcript[typed_at..]);
        let checked = check(states.len(), &segment, states.last());
        for forbidden in forbidden {
            if let Some(at) = find(&transcript, forbidden.as_bytes()) {
                let line = String::from_utf8_lossy(&transcript[at..]);
                let line = line.lines().next().unwrap_or_default().to_owned();
                let step = match &checked {
                    Ok(_) => String::new(),
                    Err(reason) => format!("; the step's check: {reason}"),
                };
                return fail(
                    &transcript,
                    format!("{line:?} printed in {waiting:?}{step}"),
                );
            }
        }
        let now = Instant::now();
        match checked {
            Ok(next) => {
                states.push(next);
                if states.len() == steps.len() + 1 {
                    if let Err(missing) = reboot_detector.require_kernel_banner() {
                        return fail(&transcript, missing);
                    }
                    save_transcript(&transcript)?;
                    return Ok((transcript, states));
                }
                let step = &steps[states.len() - 1];
                println!("\n[STM ] desktop step {:?}", step.name);
                typed_at = transcript.len();
                writer.write_all(step.send)?;
                writer.flush()?;
                step_started = now;
            }
            Err(reason) => {
                if now >= deadline || now.duration_since(step_started) >= STEP_TIMEOUT {
                    return fail(&transcript, format!("timed out in {waiting:?}: {reason}"));
                }
                if let Some(status) = child.try_wait()? {
                    return fail(
                        &transcript,
                        format!("QEMU exited with {status} in {waiting:?}: {reason}"),
                    );
                }
            }
        }
    }
}
