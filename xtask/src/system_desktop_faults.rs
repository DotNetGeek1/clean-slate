//! The hooks build booted with the desktop entry and a VirtIO-GPU, driven over COM1 (#218 S6d)
//! and, for `test-system-desktop`, over QMP too (S6e). [`Session`] owns QEMU, the serial
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
use crate::qmp::image::Screenshot;
use crate::qmp::{InputAction, QmpClient, QmpEndpoint, QmpError, QmpTimeouts};
use crate::serial_input_lane::{accept_serial, find, spawn_serial_reader, tail, SerialEvent};
use crate::system_boot::{desktop_qemu_args, start_shell_fixture_peer, system_vm_config};
use crate::system_shell::qemu_state;
use crate::{
    announce_qemu_version, prepare_vm, xtask_artifact_root, ReapOnDrop, VmLaunchConfig, XtaskError,
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
pub(crate) struct Session {
    child: ReapOnDrop,
    writer: TcpStream,
    rx: mpsc::Receiver<SerialEvent>,
    _reader: JoinHandle<()>,
    qmp: Option<QmpClient>,
    transcript: Vec<u8>,
    /// Where the output the current wait checks begins.
    mark: usize,
    reboot: GuestRebootDetector,
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
            writer,
            rx,
            _reader: reader,
            qmp,
            transcript: Vec::new(),
            mark: 0,
            reboot: GuestRebootDetector::default(),
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

    /// Takes in serial output for at most `wait`; fails on a reboot, a forbidden line, or QEMU
    /// closing the port.
    fn receive(&mut self, wait: Duration, waiting: &str) -> Result<(), XtaskError> {
        match self.rx.recv_timeout(wait) {
            Ok(SerialEvent::Bytes(bytes)) => {
                print!("{}", String::from_utf8_lossy(&bytes));
                let _ = std::io::stdout().flush();
                self.transcript.extend_from_slice(&bytes);
            }
            Ok(SerialEvent::Closed) => {
                let qemu = qemu_state(&mut self.child)?;
                return self.fail(format!("QEMU closed the serial port; QEMU {qemu}"));
            }
            Ok(SerialEvent::Failed(error)) => {
                let qemu = qemu_state(&mut self.child)?;
                return self.fail(format!(
                    "reading the serial port failed ({error}); QEMU {qemu}"
                ));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return self.fail("serial reader stopped".to_owned())
            }
        }
        if let Some(reboot) = self.reboot.observe(&self.transcript) {
            return self.fail(reboot);
        }
        for forbidden in self.forbidden {
            if let Some(at) = find(&self.transcript, forbidden.as_bytes()) {
                let line = String::from_utf8_lossy(&self.transcript[at..]);
                let line = line.lines().next().unwrap_or_default().to_owned();
                return self.fail(format!("{line:?} printed in {waiting:?}"));
            }
        }
        Ok(())
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
                return Ok(Err(reason));
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

/// The hooks build with the desktop entry, a modern-only VirtIO-GPU and `test-system`'s fixture
/// peer, on `disk`.
pub(crate) fn desktop_config(disk: &Path, fixture_port: u16) -> VmLaunchConfig {
    VmLaunchConfig {
        machine_extra: Some("vmport=off"),
        extra_args: desktop_qemu_args(false),
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
            desktop_config(disk, peer.port()),
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
