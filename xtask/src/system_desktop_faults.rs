//! The hooks build booted with the desktop entry, driven over COM1 (#218 S6d) and, for
//! `test-system-desktop` and `test-m10-desktop`, over QMP too (S6e, S6f). [`Session`] owns QEMU, the serial
//! transcript and the QMP client; every wait fails at once on a reboot, a forbidden line or QEMU
//! going away, and names what it was waiting for.

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::Stdio;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::guest_reboot::GuestRebootDetector;
use crate::marker_spec::GuestFailureScan;
use crate::qmp::image::Screenshot;
use crate::qmp::{InputAction, QmpClient, QmpEndpoint, QmpError, QmpTimeouts};
use crate::serial_input_lane::{accept_serial, find, spawn_serial_reader, tail, SerialEvent};
use crate::system_boot::{desktop_qemu_args, start_shell_fixture_peer, system_vm_config};
use crate::system_desktop::{DesktopMachine, VIRTIO_GPU_Q1};
use crate::system_shell::qemu_state;
use crate::{
    announce_qemu_version, prepare_vm, xtask_artifact_root, PreparedVm, ReapOnDrop, VmLaunchConfig,
    XtaskError,
};

const STEP_TIMEOUT: Duration = Duration::from_secs(60);

/// One thing typed on COM1 and what must follow it.
pub(crate) struct Step {
    pub(crate) name: &'static str,
    pub(crate) send: &'static [u8],
}

/// Checks the output since the previous step was typed (the boot for the first call); `Ok`
/// once the step is complete.
pub(crate) type Check<'a, S> = dyn FnMut(usize, &str, Option<&S>) -> Result<S, String> + 'a;

/// One boot of the hooks build with the desktop entry on a modern-only VirtIO-GPU.
/// Output one [`Session::receive`] takes in before it checks it, so a guest that prints
/// without pause still gets its failure lines checked.
const MAX_RECEIVE_BYTES: usize = 64 * 1024;

pub(crate) struct Session {
    child: ReapOnDrop,
    /// OVMF vars copy [`prepare_vm`] built for this boot. Declared after
    /// `child` so it drops only once [`ReapOnDrop`] has killed and reaped QEMU
    /// (fields drop in declaration order). Dropping it from [`Session::start`]
    /// deleted the `.fd` while QEMU was still opening it.
    _prepared: PreparedVm,
    writer: TcpStream,
    rx: mpsc::Receiver<SerialEvent>,
    _reader: JoinHandle<()>,
    qmp: Option<QmpClient>,
    transcript: Vec<u8>,
    /// Where the output the current wait checks begins.
    mark: usize,
    reboot: GuestRebootDetector,
    failures: GuestFailureScan,
    forbidden: &'static [&'static str],
    deadline: Instant,
    /// Under the artifact root.
    transcript_path: &'static str,
}

impl Session {
    /// Boots QEMU and connects COM1, and QMP when `qmp` is set. `lane_timeout` bounds the whole
    /// session.
    pub(crate) fn start(
        features: &[&str],
        config: VmLaunchConfig,
        qmp: bool,
        forbidden: &'static [&'static str],
        lane_timeout: Duration,
        transcript_path: &'static str,
    ) -> Result<Self, XtaskError> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let config = VmLaunchConfig {
            serial_tcp_port: Some(listener.local_addr()?.port()),
            ..config
        };
        let mut vm = prepare_vm(false, false, features, config)?;
        announce_qemu_version(&vm.qemu);
        vm.qemu.stdin(Stdio::null());
        let endpoint = if qmp {
            let endpoint = QmpEndpoint::bind()?;
            vm.qemu.args(endpoint.qemu_args());
            Some(endpoint.listen(QmpTimeouts::DEFAULT, || {}))
        } else {
            None
        };
        let deadline = Instant::now() + lane_timeout;
        let mut child = ReapOnDrop(vm.qemu.spawn()?);
        let qmp = match endpoint {
            Some(pending) => Some(pending.wait().map_err(|error| XtaskError::Qmp {
                lane: "test-system-desktop",
                step: "connect".to_owned(),
                error,
            })?),
            None => None,
        };
        let stream = accept_serial(&listener, &mut child, deadline)?;
        let writer = stream.try_clone()?;
        let (tx, rx) = mpsc::channel();
        let reader = spawn_serial_reader(stream, tx);
        Ok(Self {
            child,
            _prepared: vm,
            writer,
            rx,
            _reader: reader,
            qmp,
            transcript: Vec::new(),
            mark: 0,
            reboot: GuestRebootDetector::default(),
            failures: GuestFailureScan::default(),
            forbidden,
            deadline,
            transcript_path,
        })
    }

    pub(crate) fn transcript(&self) -> String {
        String::from_utf8_lossy(&self.transcript).into_owned()
    }

    /// Later waits see only output from here on.
    pub(crate) fn mark(&mut self) {
        self.mark = self.transcript.len();
    }

    /// Where the transcript ends now, for a later [`Self::mark_at`].
    pub(crate) fn offset(&self) -> usize {
        self.transcript.len()
    }

    pub(crate) fn mark_at(&mut self, offset: usize) {
        self.mark = offset.min(self.transcript.len());
    }

    pub(crate) fn type_serial(&mut self, bytes: &[u8]) -> Result<(), XtaskError> {
        self.mark();
        self.writer.write_all(bytes)?;
        self.writer.flush()?;
        Ok(())
    }

    fn qmp(&mut self, what: &str) -> Result<&mut QmpClient, XtaskError> {
        self.qmp.as_mut().ok_or_else(|| {
            XtaskError::Validation(format!("{what}: this session has no QMP connection"))
        })
    }

    fn qmp_error(what: &str, error: QmpError) -> XtaskError {
        XtaskError::Qmp {
            lane: "test-system-desktop",
            step: what.to_owned(),
            error,
        }
    }

    /// One `input-send-event`. Does not move the mark: a wait after a series of inputs sees the
    /// output of all of them.
    pub(crate) fn input(&mut self, what: &str, actions: &[InputAction]) -> Result<(), XtaskError> {
        let timeout = QmpTimeouts::DEFAULT.command;
        self.qmp(what)?
            .send_input(actions, timeout)
            .map_err(|error| Self::qmp_error(what, error))
    }

    pub(crate) fn screendump(&mut self, name: &str, ppm: &Path) -> Result<Screenshot, XtaskError> {
        self.qmp(name)?
            .screendump(ppm, Duration::from_secs(20))
            .map_err(|error| Self::qmp_error(name, error))
    }

    /// The output since the mark.
    pub(crate) fn segment(&self) -> String {
        String::from_utf8_lossy(&self.transcript[self.mark..]).into_owned()
    }

    /// Saves the transcript and fails with `message`.
    pub(crate) fn fail<T>(&self, message: String) -> Result<T, XtaskError> {
        let _ = self.save();
        Err(XtaskError::Validation(format!(
            "desktop boot: {message}; tail {:?}",
            tail(&self.transcript)
        )))
    }

    fn save(&self) -> Result<(), XtaskError> {
        let path = xtask_artifact_root().join(self.transcript_path);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, &self.transcript)?;
        println!("[STM ] desktop serial transcript: {}", path.display());
        Ok(())
    }

    /// Takes in serial output for at most `wait`; fails on a reboot, a guest failure line, a
    /// forbidden line, or QEMU closing the port.
    ///
    /// Everything the reader has queued is taken in one go, and the checks scan only what is
    /// new. The reader forwards each socket read, often a byte or two, and a check of the whole
    /// transcript per read made the lane fall seconds behind the guest under host load (#349).
    fn receive(&mut self, wait: Duration, waiting: &str) -> Result<(), XtaskError> {
        let scanned = self.transcript.len();
        let mut event = self.rx.recv_timeout(wait);
        loop {
            match event {
                Ok(SerialEvent::Bytes(bytes)) => self.transcript.extend_from_slice(&bytes),
                Ok(SerialEvent::Closed) => {
                    self.flush_output(scanned);
                    let qemu = qemu_state(&mut self.child)?;
                    return self.fail(format!("QEMU closed the serial port; QEMU {qemu}"));
                }
                Ok(SerialEvent::Failed(error)) => {
                    self.flush_output(scanned);
                    let qemu = qemu_state(&mut self.child)?;
                    return self.fail(format!(
                        "reading the serial port failed ({error}); QEMU {qemu}"
                    ));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    self.flush_output(scanned);
                    return self.fail("serial reader stopped".to_owned());
                }
            }
            if self.transcript.len() - scanned >= MAX_RECEIVE_BYTES {
                break;
            }
            event = match self.rx.try_recv() {
                Ok(next) => Ok(next),
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => Err(mpsc::RecvTimeoutError::Disconnected),
            };
        }
        if self.transcript.len() == scanned {
            return Ok(());
        }
        self.flush_output(scanned);
        if let Some(reboot) = self.reboot.observe(&self.transcript) {
            return self.fail(reboot);
        }
        if let Some(failure) = self.failures.next_in(&self.transcript) {
            return self.fail(format!("{failure:?} printed in {waiting:?}"));
        }
        for forbidden in self.forbidden {
            let from = scanned.saturating_sub(forbidden.len().saturating_sub(1));
            if let Some(at) = find(&self.transcript[from..], forbidden.as_bytes()) {
                let line = String::from_utf8_lossy(&self.transcript[from + at..]);
                let line = line.lines().next().unwrap_or_default().to_owned();
                return self.fail(format!("{line:?} printed in {waiting:?}"));
            }
        }
        Ok(())
    }

    /// Echoes the output from `from` on.
    fn flush_output(&self, from: usize) {
        print!("{}", String::from_utf8_lossy(&self.transcript[from..]));
        let _ = std::io::stdout().flush();
    }

    /// Waits until `check` accepts the output since the mark, for at most `timeout`. On a
    /// timeout the error names `waiting` and the check's last reason.
    pub(crate) fn wait<T>(
        &mut self,
        waiting: &str,
        timeout: Duration,
        check: &mut dyn FnMut(&str) -> Result<T, String>,
    ) -> Result<T, XtaskError> {
        match self.poll(waiting, timeout, check)? {
            Ok(done) => Ok(done),
            Err(reason) => self.fail(format!("timed out in {waiting:?}: {reason}")),
        }
    }

    /// [`Self::wait`], but a timeout returns the check's last reason instead of failing.
    pub(crate) fn poll<T>(
        &mut self,
        waiting: &str,
        timeout: Duration,
        check: &mut dyn FnMut(&str) -> Result<T, String>,
    ) -> Result<Result<T, String>, XtaskError> {
        let started = Instant::now();
        loop {
            let segment = self.segment();
            let reason = match check(&segment) {
                Ok(done) => return Ok(Ok(done)),
                Err(reason) => reason,
            };
            let now = Instant::now();
            if now >= self.deadline {
                return self.fail(format!("lane deadline passed in {waiting:?}: {reason}"));
            }
            if now.duration_since(started) >= timeout {
                // What the reader already queued decides the step, not the moment it was
                // read: a line printed just before the timeout passes it.
                self.receive(Duration::ZERO, waiting)?;
                return Ok(check(&self.segment()));
            }
            if let Some(status) = self.child.try_wait()? {
                return self.fail(format!(
                    "QEMU exited with {status} in {waiting:?}: {reason}"
                ));
            }
            let wait = Duration::from_millis(50).min(timeout - now.duration_since(started));
            if let Err(error) = self.receive(wait, waiting) {
                return Err(match error {
                    XtaskError::Validation(message) => {
                        XtaskError::Validation(format!("{message}; the step's check: {reason}"))
                    }
                    other => other,
                });
            }
        }
    }

    /// Requires the kernel banner and saves the transcript.
    pub(crate) fn finish(self) -> Result<Vec<u8>, XtaskError> {
        if let Err(missing) = self.reboot.require_kernel_banner() {
            return self.fail(missing);
        }
        self.save()?;
        Ok(self.transcript)
    }
}

/// The hooks build with the desktop entry on `machine` (a modern-only VirtIO-GPU, or the
/// `-vga std` framebuffer) and `test-system`'s fixture peer, on `disk`.
pub(crate) fn desktop_config(
    disk: &Path,
    fixture_port: u16,
    machine: &DesktopMachine,
) -> VmLaunchConfig {
    VmLaunchConfig {
        machine_extra: Some("vmport=off"),
        vga: machine.framebuffer.then_some("std"),
        extra_args: desktop_qemu_args(machine.framebuffer),
        ..system_vm_config(disk.to_path_buf(), Some(fixture_port))
    }
}

/// Boots the desktop, then types each step once the one before it is complete. Returns the
/// transcript and the state after the boot and each step.
pub(crate) fn drive<S: Clone>(
    features: &[&str],
    disk: &Path,
    steps: &[Step],
    forbidden: &'static [&'static str],
    check: &mut Check<'_, S>,
) -> Result<(Vec<u8>, Vec<S>), XtaskError> {
    let peer = start_shell_fixture_peer()?;
    let result = (|| {
        let mut session = Session::start(
            features,
            desktop_config(disk, peer.port(), &VIRTIO_GPU_Q1),
            false,
            forbidden,
            Duration::from_secs(300),
            "system/desktop-serial.log",
        )?;
        let mut states: Vec<S> = Vec::new();
        for done in 0..=steps.len() {
            if done > 0 {
                let step = &steps[done - 1];
                println!("\n[STM ] desktop step {:?}", step.name);
                session.type_serial(step.send)?;
            }
            let waiting = match done {
                0 => "boot",
                _ => steps[done - 1].name,
            };
            let before = states.last().cloned();
            let state = session.wait(waiting, STEP_TIMEOUT, &mut |segment| {
                check(done, segment, before.as_ref())
            })?;
            states.push(state);
        }
        Ok((session.finish()?, states))
    })();
    peer.shutdown();
    result
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::process::Command;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use super::Session;
    use crate::guest_reboot::GuestRebootDetector;
    use crate::marker_spec::GuestFailureScan;
    use crate::ovmf_vars::RuntimeVarsCopy;
    use crate::{PreparedVm, ReapOnDrop};

    /// A process that exits at once. [`ReapOnDrop`] still owns it, and it does not
    /// hold the vars file, so the copy can be deleted as soon as the session drops.
    fn helper_child() -> std::process::Child {
        let mut command = if cfg!(windows) {
            let mut command = Command::new("cmd");
            command.args(["/c", "exit", "0"]);
            command
        } else {
            Command::new("true")
        };
        command.spawn().expect("helper process")
    }

    #[test]
    fn session_owns_the_ovmf_vars_copy_until_it_drops() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "clean-slate-session-ovmf-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("mkdir");
        let template = dir.join("template.fd");
        fs::write(&template, b"pristine").expect("template");
        let copy = RuntimeVarsCopy::create(&dir, &template).expect("vars copy");
        let vars = copy.path().to_path_buf();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let writer = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
        let _accepted = listener.accept().expect("accept");
        let (_tx, rx) = mpsc::channel();

        let session = Session {
            child: ReapOnDrop(helper_child()),
            _prepared: PreparedVm {
                qemu: Command::new("qemu-system-x86_64"),
                _runtime_vars: Some(copy),
            },
            writer,
            rx,
            _reader: thread::spawn(|| {}),
            qmp: None,
            transcript: Vec::new(),
            mark: 0,
            reboot: GuestRebootDetector::default(),
            failures: GuestFailureScan::default(),
            forbidden: &[],
            deadline: Instant::now() + Duration::from_secs(1),
            transcript_path: "system/session-guard-test.log",
        };

        assert_eq!(
            session
                ._prepared
                ._runtime_vars
                .as_ref()
                .map(RuntimeVarsCopy::path),
            Some(vars.as_path()),
            "the session must own the vars copy prepared for its QEMU"
        );
        assert!(vars.is_file());
        drop(session);
        assert!(
            !vars.exists(),
            "the vars copy is deleted only when the session drops"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
