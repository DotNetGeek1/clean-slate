//! Acceptance-loop driver that runs a QMP script paced by serial lines.
//!
//! Stimuli run only after the serial line they wait for has arrived; the
//! script never sleeps. `MarkerSet` stays the oracle for the expected serial
//! sequence, and the script only decides when to act.

use std::collections::VecDeque;
use std::fs;
use std::io::{self, ErrorKind, Read};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::image::Screenshot;
use super::json::JsonValue;
use super::{InputAction, PendingSession, QemuVersion, QmpClient, QmpEndpoint, QmpError};
use super::{QmpEvent, QmpTimeouts};
use crate::{AcceptanceDriver, DriverWake, XtaskError};

/// Longest serial line the driver keeps; longer lines are dropped unmatched.
pub(crate) const MAX_SERIAL_LINE_BYTES: usize = 64 * 1024;
/// Complete lines held while a stimulus waits for QMP to connect.
pub(crate) const MAX_QUEUED_LINES: usize = 4096;
/// Per-lane run directories kept under the artifact root; older ones go.
pub(crate) const MAX_ARTIFACT_RUNS_PER_LANE: usize = 8;
const SCREENDUMP_TIMEOUT: Duration = Duration::from_secs(20);
const QUIT_TIMEOUT: Duration = Duration::from_secs(5);

static NEXT_RUN: AtomicU64 = AtomicU64::new(0);

pub(crate) type ScreenshotCheck = fn(&Screenshot) -> Result<(), String>;
pub(crate) type ReturnCheck = fn(&JsonValue) -> Result<(), String>;

pub(crate) enum ScriptStep {
    /// The next complete serial line containing the text. A line is
    /// consumed by at most one step. At teardown the unterminated tail
    /// counts as a line.
    AwaitLine(&'static str),
    /// One `input-send-event` command.
    Input(Vec<InputAction>),
    /// Captures `<run dir>/<name>.png`, then applies `check`.
    Screendump {
        name: &'static str,
        check: ScreenshotCheck,
    },
    /// Any other command; `check` sees its return value.
    Command {
        command: &'static str,
        arguments: Option<JsonValue>,
        check: ReturnCheck,
    },
    /// A command that must fail with this QMP error class.
    CommandError {
        command: &'static str,
        class: &'static str,
    },
    /// `quit`, then reads until QEMU closes the connection.
    Quit,
}

impl ScriptStep {
    fn describe(&self) -> String {
        match self {
            ScriptStep::AwaitLine(text) => format!("await line `{text}`"),
            ScriptStep::Input(actions) => format!("input {actions:?}"),
            ScriptStep::Screendump { name, .. } => format!("screendump `{name}`"),
            ScriptStep::Command { command, .. } => format!("command `{command}`"),
            ScriptStep::CommandError { command, class } => {
                format!("command `{command}` failing with {class}")
            }
            ScriptStep::Quit => "quit".to_owned(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Capture {
    pub(crate) name: &'static str,
    pub(crate) png: PathBuf,
    pub(crate) screenshot: Screenshot,
}

enum Link {
    Idle(QmpEndpoint),
    Pending(PendingSession),
    Ready(QmpClient),
    Closed,
}

pub(crate) struct QmpScriptDriver {
    lane: &'static str,
    timeouts: QmpTimeouts,
    link: Link,
    port: u16,
    qemu_args: Vec<String>,
    steps: Vec<ScriptStep>,
    next_step: usize,
    partial_line: String,
    /// Serial text through the next newline belongs to a line that was
    /// dropped (over-long, or begun before an input was sent).
    discarding_line: bool,
    queued_lines: VecDeque<String>,
    run_dir: PathBuf,
    captures: Vec<Capture>,
    events: Vec<QmpEvent>,
    version: Option<QemuVersion>,
    keep_peer_probe: bool,
    peer_probe: Option<TcpStream>,
}

impl QmpScriptDriver {
    /// Binds this run's endpoint and creates its artifact directory under
    /// `artifact_root/<lane>/`.
    pub(crate) fn new(
        lane: &'static str,
        steps: Vec<ScriptStep>,
        artifact_root: &Path,
    ) -> io::Result<Self> {
        Self::with_timeouts(lane, steps, artifact_root, QmpTimeouts::DEFAULT)
    }

    pub(crate) fn with_timeouts(
        lane: &'static str,
        steps: Vec<ScriptStep>,
        artifact_root: &Path,
        timeouts: QmpTimeouts,
    ) -> io::Result<Self> {
        let endpoint = QmpEndpoint::bind()?;
        let run_dir = create_run_dir(&artifact_root.join(lane))?;
        Ok(Self {
            lane,
            timeouts,
            port: endpoint.port(),
            qemu_args: endpoint.qemu_args(),
            link: Link::Idle(endpoint),
            steps,
            next_step: 0,
            partial_line: String::new(),
            discarding_line: false,
            queued_lines: VecDeque::new(),
            run_dir,
            captures: Vec::new(),
            events: Vec::new(),
            version: None,
            keep_peer_probe: false,
            peer_probe: None,
        })
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn run_dir(&self) -> &Path {
        &self.run_dir
    }

    pub(crate) fn captures(&self) -> &[Capture] {
        &self.captures
    }

    /// Events seen so far, including those drained by [`ScriptStep::Quit`].
    pub(crate) fn events(&mut self) -> &[QmpEvent] {
        if let Link::Ready(client) = &mut self.link {
            self.events.extend(client.take_events());
        }
        &self.events
    }

    pub(crate) fn version(&self) -> Option<QemuVersion> {
        self.version
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.next_step == self.steps.len()
    }

    /// Keeps a duplicate of the QMP socket past [`AcceptanceDriver::shutdown`]
    /// so [`Self::peer_closed_within`] can prove QEMU's side went away.
    pub(crate) fn keep_peer_probe(&mut self) {
        self.keep_peer_probe = true;
    }

    /// Whether QEMU closed its end of the QMP connection within `timeout`.
    pub(crate) fn peer_closed_within(&mut self, timeout: Duration) -> io::Result<bool> {
        let Some(mut probe) = self.peer_probe.take() else {
            return Err(io::Error::other("no QMP peer probe was kept"));
        };
        probe.set_read_timeout(Some(timeout))?;
        let mut byte = [0u8; 1];
        loop {
            match probe.read(&mut byte) {
                Ok(0) => return Ok(true),
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
                    ) =>
                {
                    return Ok(true)
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    return Ok(false)
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }

    fn position(&self) -> String {
        match self.steps.get(self.next_step) {
            Some(step) => format!(
                "step {}/{} ({})",
                self.next_step + 1,
                self.steps.len(),
                step.describe()
            ),
            None => "complete".to_owned(),
        }
    }

    fn qmp_error(&self, error: QmpError) -> XtaskError {
        XtaskError::Qmp {
            lane: self.lane,
            step: self.position(),
            error,
        }
    }

    fn resolve_link(&mut self) -> Result<(), XtaskError> {
        let Link::Pending(pending) = &mut self.link else {
            return Ok(());
        };
        match pending.try_take() {
            None => Ok(()),
            Some(Ok(client)) => {
                println!(
                    "[qmp ] {} QEMU {} ({}) on 127.0.0.1:{}",
                    self.lane,
                    client.version(),
                    client.package(),
                    self.port
                );
                self.version = Some(client.version());
                self.link = Link::Ready(client);
                Ok(())
            }
            Some(Err(error)) => {
                self.link = Link::Closed;
                Err(self.qmp_error(error))
            }
        }
    }

    /// Runs every step the received lines allow.
    fn pump(&mut self, deadline: Instant) -> Result<(), XtaskError> {
        self.resolve_link()?;
        loop {
            self.consume_awaited_lines();
            match self.steps.get(self.next_step) {
                None => {
                    self.queued_lines.clear();
                    return Ok(());
                }
                Some(ScriptStep::AwaitLine(_)) => return Ok(()),
                Some(_) => {
                    if !matches!(self.link, Link::Ready(_)) {
                        return match self.link {
                            Link::Closed => Err(XtaskError::Validation(format!(
                                "{} QMP script at {} but the QMP connection is closed",
                                self.lane,
                                self.position()
                            ))),
                            _ => Ok(()),
                        };
                    }
                    self.run_step(deadline)?;
                    self.next_step += 1;
                }
            }
        }
    }

    fn consume_awaited_lines(&mut self) {
        while let Some(ScriptStep::AwaitLine(text)) = self.steps.get(self.next_step) {
            let text = *text;
            let Some(line) = self.queued_lines.pop_front() else {
                return;
            };
            if line.contains(text) {
                self.next_step += 1;
            }
        }
    }

    fn run_step(&mut self, deadline: Instant) -> Result<(), XtaskError> {
        let Link::Ready(client) = &mut self.link else {
            return Ok(());
        };
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(XtaskError::Validation(format!(
                "{} QMP script at {} after the acceptance deadline",
                self.lane,
                self.position()
            )));
        }
        let command_timeout = self.timeouts.command.min(left);
        let outcome = match &self.steps[self.next_step] {
            ScriptStep::AwaitLine(_) => Ok(None),
            ScriptStep::Input(actions) => {
                // Output received so far cannot be a response to this input.
                self.queued_lines.clear();
                if !self.partial_line.is_empty() {
                    self.partial_line.clear();
                    self.discarding_line = true;
                }
                client.send_input(actions, command_timeout).map(|()| None)
            }
            ScriptStep::Screendump { name, check } => {
                let ppm = self.run_dir.join(format!("{name}.ppm"));
                client
                    .screendump(&ppm, SCREENDUMP_TIMEOUT.min(left))
                    .map(|shot| Some((*name, *check, ppm, shot)))
            }
            ScriptStep::Command {
                command,
                arguments,
                check,
            } => client
                .execute(command, arguments.clone(), command_timeout)
                .and_then(|reply| {
                    check(&reply).map_err(|detail| QmpError::Protocol {
                        context: (*command).to_owned(),
                        detail,
                    })
                })
                .map(|()| None),
            ScriptStep::CommandError { command, class } => {
                match client.execute(command, None, command_timeout) {
                    Err(QmpError::Command { class: got, .. }) if got == *class => Ok(None),
                    Err(error) => Err(error),
                    Ok(reply) => Err(QmpError::Protocol {
                        context: (*command).to_owned(),
                        detail: format!("expected {class}, got return {}", reply.to_json()),
                    }),
                }
            }
            ScriptStep::Quit => {
                let quit_timeout = QUIT_TIMEOUT.min(left);
                match client.execute("quit", None, quit_timeout) {
                    Ok(_) | Err(QmpError::Disconnected { .. }) => {
                        client.wait_for_close(quit_timeout).map(|()| None)
                    }
                    Err(error) => Err(error),
                }
            }
        };
        let capture = outcome.map_err(|error| self.qmp_error(error))?;
        if let Some((name, check, ppm, screenshot)) = capture {
            self.store_capture(name, check, &ppm, screenshot)?;
        }
        if matches!(self.steps[self.next_step], ScriptStep::Quit) {
            self.events();
            self.close_link();
        }
        Ok(())
    }

    fn store_capture(
        &mut self,
        name: &'static str,
        check: ScreenshotCheck,
        ppm: &Path,
        screenshot: Screenshot,
    ) -> Result<(), XtaskError> {
        let png = self.run_dir.join(format!("{name}.png"));
        screenshot.write_png(&png)?;
        println!(
            "[qmp ] {} captured `{name}` {}x{} -> {}",
            self.lane,
            screenshot.width(),
            screenshot.height(),
            png.display()
        );
        if let Err(reason) = check(&screenshot) {
            return Err(XtaskError::Validation(format!(
                "{} screenshot `{name}` failed its check: {reason} (kept {} and {})",
                self.lane,
                png.display(),
                ppm.display()
            )));
        }
        let _ = fs::remove_file(ppm);
        self.captures.push(Capture {
            name,
            png,
            screenshot,
        });
        Ok(())
    }

    fn close_link(&mut self) {
        match std::mem::replace(&mut self.link, Link::Closed) {
            Link::Ready(mut client) => {
                self.events.extend(client.take_events());
                if client.dropped_events() > 0 {
                    println!(
                        "[qmp ] {} dropped {} QMP events past the ring capacity",
                        self.lane,
                        client.dropped_events()
                    );
                }
                if self.keep_peer_probe {
                    self.peer_probe = client.try_clone_stream().ok();
                } else {
                    client.close();
                }
            }
            Link::Pending(mut pending) => pending.cancel(),
            Link::Idle(_) | Link::Closed => {}
        }
    }

    /// The tracker matches marker text without waiting for the newline, so
    /// the line that ends the run may still be unterminated at teardown.
    fn flush_partial_line(&mut self) -> Result<(), XtaskError> {
        if self.partial_line.is_empty() {
            return Ok(());
        }
        let line = std::mem::take(&mut self.partial_line);
        self.push_line(&line)
    }

    fn push_line(&mut self, line: &str) -> Result<(), XtaskError> {
        if self.is_complete() {
            return Ok(());
        }
        if self.queued_lines.len() == MAX_QUEUED_LINES {
            return Err(XtaskError::Validation(format!(
                "{} QMP script at {}: more than {MAX_QUEUED_LINES} serial lines queued",
                self.lane,
                self.position()
            )));
        }
        self.queued_lines
            .push_back(line.trim_end_matches('\r').to_owned());
        Ok(())
    }
}

impl AcceptanceDriver for QmpScriptDriver {
    fn qemu_args(&self) -> Vec<String> {
        self.qemu_args.clone()
    }

    fn start(&mut self, wake: DriverWake) -> Result<(), XtaskError> {
        match std::mem::replace(&mut self.link, Link::Closed) {
            Link::Idle(endpoint) => {
                self.link = Link::Pending(endpoint.listen(self.timeouts, move || wake.wake()));
                Ok(())
            }
            other => {
                self.link = other;
                Err(XtaskError::Validation(format!(
                    "{} QMP driver started twice",
                    self.lane
                )))
            }
        }
    }

    fn on_serial(&mut self, text: &str, deadline: Instant) -> Result<(), XtaskError> {
        let text = if self.discarding_line {
            match text.find('\n') {
                Some(end) => {
                    self.discarding_line = false;
                    &text[end + 1..]
                }
                None => "",
            }
        } else {
            text
        };
        self.partial_line.push_str(text);
        while let Some(end) = self.partial_line.find('\n') {
            let line: String = self.partial_line.drain(..=end).collect();
            let line = &line[..line.len() - 1];
            if line.len() <= MAX_SERIAL_LINE_BYTES {
                self.push_line(line)?;
            }
        }
        if self.partial_line.len() > MAX_SERIAL_LINE_BYTES {
            self.partial_line.clear();
            self.discarding_line = true;
        }
        self.pump(deadline)
    }

    fn on_wake(&mut self, deadline: Instant) -> Result<(), XtaskError> {
        self.pump(deadline)
    }

    fn before_teardown(&mut self, deadline: Instant) -> Result<(), XtaskError> {
        self.flush_partial_line()?;
        self.pump(deadline)?;
        if matches!(self.link, Link::Idle(_) | Link::Pending(_)) {
            return Err(XtaskError::Validation(format!(
                "{} QMP script at {}: QEMU never connected to 127.0.0.1:{}",
                self.lane,
                self.position(),
                self.port
            )));
        }
        if !self.is_complete() {
            return Err(XtaskError::Validation(format!(
                "{} passed its serial markers but the QMP script stopped at {}",
                self.lane,
                self.position()
            )));
        }
        Ok(())
    }

    fn after_exit(&mut self, status: ExitStatus) -> Result<(), XtaskError> {
        if matches!(self.link, Link::Idle(_) | Link::Pending(_)) {
            let error = QmpError::ChildExitedBeforeConnect {
                status: status.to_string(),
            };
            self.close_link();
            return Err(self.qmp_error(error));
        }
        self.flush_partial_line()?;
        self.consume_awaited_lines();
        if !self.is_complete() {
            return Err(XtaskError::Validation(format!(
                "{} QEMU exited ({status}) with the QMP script at {}",
                self.lane,
                self.position()
            )));
        }
        Ok(())
    }

    fn pending(&self) -> Option<String> {
        Some(match self.link {
            Link::Idle(_) | Link::Pending(_) => {
                format!("QMP waiting for QEMU on 127.0.0.1:{}", self.port)
            }
            _ => format!("QMP script at {}", self.position()),
        })
    }

    fn shutdown(&mut self) {
        self.close_link();
    }
}

/// `<lane dir>/<pid>.<seq>`, after pruning the lane's oldest run directories
/// so at most [`MAX_ARTIFACT_RUNS_PER_LANE`] remain including the new one.
fn create_run_dir(lane_dir: &Path) -> io::Result<PathBuf> {
    fs::create_dir_all(lane_dir)?;
    prune_runs(lane_dir, MAX_ARTIFACT_RUNS_PER_LANE - 1)?;
    let pid = std::process::id();
    loop {
        let run = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
        let dir = lane_dir.join(format!("{pid}.{run}"));
        match fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
}

fn prune_runs(lane_dir: &Path, keep: usize) -> io::Result<()> {
    let mut runs: Vec<(std::time::SystemTime, PathBuf)> = fs::read_dir(lane_dir)?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| {
            let modified = entry.metadata().and_then(|meta| meta.modified()).ok()?;
            Some((modified, entry.path()))
        })
        .collect();
    runs.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, stale) in runs.into_iter().skip(keep) {
        if let Err(error) = fs::remove_dir_all(&stale) {
            eprintln!(
                "[qmp ] warning: could not prune {}: {error}",
                stale.display()
            );
        }
    }
    Ok(())
}
