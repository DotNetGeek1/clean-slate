//! `test-system-shell` (#218 S5): the default image ends at an interactive BusyBox shell on the
//! serial console, and the host types into it.
//!
//! COM1 is a loopback socket, as in `test-serial-input` (QEMU's Windows stdio backend drops
//! `\r` from piped stdin); the boot is otherwise `cargo xtask run`'s: the default image on a
//! data disk of the lane's own, here with the network fixture peer (in the profile BusyBox's
//! `nslookup` and `wget` need) so every service settles.
//! Each [`Step`] is typed once the step before it is [`check_step`]-complete, and the same check
//! is the verdict: a step passes only on output the command's execution produces, never on the
//! echo of what was typed. `exit` and Ctrl-D must each end the shell and be followed by a new
//! instance, one generation on, with a new prompt. The network steps also need the fixture
//! peer's own report that it answered the query or served the request while the step ran.

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::process::Stdio;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::m7_fixture::{FixtureCounts, M7FixturePeer};
use crate::serial_input_lane::{accept_serial, find, spawn_serial_reader, tail, SerialEvent};
use crate::system_boot::{
    ensure_data_disk, field, number, start_shell_fixture_peer, system_vm_config,
    SYSTEM_DATA_DISK_FILENAME,
};
use crate::{
    announce_qemu_version, prepare_vm, workspace_root, xtask_artifact_root, ReapOnDrop,
    VmLaunchConfig, XtaskError,
};

const SHELL_SERVICE: u32 = 0x5400;
/// ash's prompt for uid 0.
const PROMPT: &str = "# ";
/// The applets the rootfs links in `/bin` (`fixtures/busybox/frozen/rootfs.toml`). `ls` prints
/// one per line when stdout is not a terminal, in directory order: this BusyBox does not sort.
const BIN_ENTRIES: [&str; 15] = [
    "busybox", "cat", "echo", "env", "grep", "ls", "mkdir", "nslookup", "printf", "pwd", "sh",
    "sleep", "true", "uname", "wget",
];
/// `/tmp` backing objects are `0x4C0000..0x4C0004`.
const TMP_OBJECT_IDS: std::ops::Range<u64> = 0x004C_0000..0x004C_0004;
/// Boot to the first prompt plus every step; the kernel build before it is not counted.
const LANE_TIMEOUT: Duration = Duration::from_secs(240);
const STEP_TIMEOUT: Duration = Duration::from_secs(60);

/// What a step must produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    /// These whole lines, in order and adjacent, then a prompt; `absent` lines must not appear.
    Lines {
        lines: &'static [&'static str],
        absent: &'static [&'static str],
    },
    /// Exactly these whole lines, adjacent and in any order, then a prompt.
    LineSet(&'static [&'static str]),
    /// As `Lines`, plus a kernel-observed `/tmp` object write of `bytes` bytes.
    TmpWrite {
        lines: &'static [&'static str],
        bytes: u64,
    },
    /// The shell exits with status 0; a new instance one generation on is launched, prints a
    /// prompt and blocks reading stdin.
    Relaunch,
    /// As `Lines`, and the fixture peer reports having served at least `served` while the step
    /// ran: the lines can only come from a real exchange with it.
    Network {
        lines: &'static [&'static str],
        served: Served,
    },
}

/// What the fixture peer served while one step ran.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Served {
    /// DNS replies carrying the A record of `m7.fixture.test`.
    fixture_a_answers: u32,
    http_responses: u32,
}

impl Served {
    fn between(before: FixtureCounts, after: FixtureCounts) -> Self {
        Self {
            fixture_a_answers: after
                .fixture_a_answers
                .saturating_sub(before.fixture_a_answers),
            http_responses: after.http_responses.saturating_sub(before.http_responses),
        }
    }

    fn covers(self, want: Self) -> bool {
        self.fixture_a_answers >= want.fixture_a_answers
            && self.http_responses >= want.http_responses
    }
}

#[derive(Clone, Copy, Debug)]
struct Step {
    name: &'static str,
    send: &'static [u8],
    expect: Expect,
}

/// The script. Every expected line differs from the command that produces it, so the echo of
/// a command cannot satisfy its own step.
const STEPS: [Step; 10] = [
    Step {
        name: "echo",
        send: b"echo hel''lo-shell\r",
        expect: Expect::Lines {
            lines: &["hello-shell"],
            absent: &[],
        },
    },
    Step {
        name: "ls /bin",
        send: b"ls /bin\r",
        expect: Expect::LineSet(&BIN_ENTRIES),
    },
    Step {
        name: "pipeline",
        send: b"printf 'pipe-%s\\n' yes no | grep yes\r",
        expect: Expect::Lines {
            lines: &["pipe-yes"],
            absent: &["pipe-no"],
        },
    },
    Step {
        name: "/tmp write and read",
        send: b"printf 'obj-%d\\n' 7 > /tmp/a; cat /tmp/a\r",
        expect: Expect::TmpWrite {
            lines: &["obj-7"],
            bytes: 6,
        },
    },
    Step {
        name: "backspace",
        send: b"echo typo\x08\x08\x08\x08fix''ed\r",
        expect: Expect::Lines {
            lines: &["fixed"],
            absent: &["typofixed"],
        },
    },
    Step {
        name: "exit",
        send: b"exit\r",
        expect: Expect::Relaunch,
    },
    Step {
        name: "second shell",
        send: b"echo aga''in; cat /tmp/a\r",
        expect: Expect::Lines {
            lines: &["again", "obj-7"],
            absent: &[],
        },
    },
    Step {
        name: "ctrl-d",
        send: b"\x04",
        expect: Expect::Relaunch,
    },
    // The fixture answers `m7.fixture.test` with 10.77.0.50 (`start_shell_fixture_peer`);
    // BusyBox prints the answer as these two lines, after a spurious "can't resolve '(null)'"
    // on stderr (`fixtures/busybox/frozen/traces/nslookup-fixture.strace`).
    Step {
        name: "nslookup",
        send: b"nslookup m7.fixture.test\r",
        expect: Expect::Network {
            lines: &["Name:      m7.fixture.test", "Address 1: 10.77.0.50"],
            served: Served {
                fixture_a_answers: 1,
                http_responses: 0,
            },
        },
    },
    // `-q` leaves only the body on the console; wget resolves the name through the fixture too.
    Step {
        name: "wget",
        send: b"wget -q -O - http://m7.fixture.test:4001/\r",
        expect: Expect::Network {
            lines: &["M9-FIXTURE-HTTP"],
            served: Served {
                fixture_a_answers: 1,
                http_responses: 1,
            },
        },
    },
];

/// The live shell instance a step runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Shell {
    pid: u64,
    generation: u64,
}

fn lines(segment: &str) -> impl Iterator<Item = &str> {
    segment.lines().map(|line| line.trim_end_matches('\r'))
}

/// The text from the first occurrence of `prefix` to the end of its line, wherever the line
/// starts: kernel lines can follow a prompt that has no newline.
fn kernel_lines<'a>(segment: &'a str, prefix: &'a str) -> impl Iterator<Item = &'a str> {
    lines(segment).filter_map(move |line| line.find(prefix).map(|at| &line[at..]))
}

fn only_kernel_line<'a>(segment: &'a str, prefix: &str) -> Result<&'a str, String> {
    let mut found = lines(segment).filter_map(|line| line.find(prefix).map(|at| &line[at..]));
    let line = found
        .next()
        .ok_or_else(|| format!("no line containing {prefix:?}"))?;
    if found.next().is_some() {
        return Err(format!("more than one line containing {prefix:?}"));
    }
    Ok(line)
}

/// Byte offset just past `needle` in `segment`, from `from` on.
fn offset_after(segment: &str, from: usize, needle: &str) -> Option<usize> {
    segment[from..]
        .find(needle)
        .map(|at| from + at + needle.len())
}

/// A kernel log line (`[TAG ] ...`) or a blank one. Kernel lines are printed between the
/// writes of the processes a command runs, so they are not part of any command's output.
fn is_interleaved(line: &str) -> bool {
    let bytes = line.as_bytes();
    line.is_empty() || (bytes.len() > 6 && bytes[0] == b'[' && bytes[5] == b']' && bytes[6] == b' ')
}

/// The finished lines of shell output in `segment`, each with the offset just past its newline.
fn output_lines(segment: &str) -> Vec<(usize, &str)> {
    let mut found = Vec::new();
    let mut at = 0;
    for line in segment.split_inclusive('\n') {
        at += line.len();
        let text = line.trim_end_matches('\n').trim_end_matches('\r');
        if line.ends_with('\n') && !is_interleaved(text) {
            found.push((at, text));
        }
    }
    found
}

/// Where `expected` first appears as consecutive output lines; returns the offset past them.
fn whole_lines_at(segment: &str, expected: &[&str]) -> Option<usize> {
    output_lines(segment)
        .windows(expected.len())
        .find(|window| window.iter().map(|(_, line)| line).eq(expected))
        .map(|window| window[window.len() - 1].0)
}

/// Where `expected`, in some order, first appears as consecutive output lines; returns the
/// offset past them.
fn line_set_at(segment: &str, expected: &[&str]) -> Option<usize> {
    let mut want: Vec<&str> = expected.to_vec();
    want.sort_unstable();
    output_lines(segment)
        .windows(expected.len())
        .find(|window| {
            let mut got: Vec<&str> = window.iter().map(|(_, line)| *line).collect();
            got.sort_unstable();
            got == want
        })
        .map(|window| window[window.len() - 1].0)
}

/// A prompt at the start of a line after `from`.
fn prompt_after(segment: &str, from: usize) -> Option<usize> {
    let rest = &segment[from..];
    if rest.starts_with(PROMPT) {
        return Some(from + PROMPT.len());
    }
    offset_after(segment, from, &format!("\n{PROMPT}"))
}

/// The kernel's authority line for a shell instance must be exactly the row's grants.
fn expected_authority(pid: u64) -> String {
    format!(
        "[SVC ] authority service={SHELL_SERVICE} pid={pid} lifecycle-control=0 console=1 block-device=0 object-service=0 network=0 net-client=1 net-client-entitlement=1 tmp-objects=4 other=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0 linux=1 console-input=1 matches-manifest=1"
    )
}

/// One shell instance came up in `segment`: authority, launch, the process line, a prompt and
/// then the kernel's ready report from that pid and generation, and init's announcement.
fn check_instance(segment: &str, generation: u64, init_pid: u64) -> Result<Shell, String> {
    let launch = only_kernel_line(segment, &format!("[SVC ] launch service={SHELL_SERVICE} "))?;
    let pid = number(launch, "pid")?;
    if number(launch, "gen")? != generation {
        return Err(format!("expected shell gen={generation}: {launch:?}"));
    }
    let authority = only_kernel_line(
        segment,
        &format!("[SVC ] authority service={SHELL_SERVICE} "),
    )?;
    if authority != expected_authority(pid) {
        return Err(format!("shell authority {authority:?}"));
    }
    let process = only_kernel_line(segment, "[SVC ] shell process ")?;
    let want_process = format!(
        "[SVC ] shell process pid={pid} gen={generation} argv=/bin/sh,-i env=PATH=/bin stdin=1 stdout=1 tmp=1 net-client=1"
    );
    if process != want_process {
        return Err(format!("shell process line {process:?}"));
    }
    let ready_prefix = format!("[SVC ] ready service={SHELL_SERVICE} ");
    let ready = only_kernel_line(segment, &ready_prefix)?;
    if number(ready, "pid")? != pid
        || number(ready, "gen")? != generation
        || field(ready, "source") != Some("live-instance")
        || !ready.ends_with(" kernel-observed first-console-input-wait")
    {
        return Err(format!(
            "shell launched as pid={pid} gen={generation} but ready says {ready:?}"
        ));
    }
    let launched_at = segment.find(launch).unwrap_or(0);
    let ready_at = segment
        .find(&ready_prefix)
        .ok_or_else(|| "ready line vanished".to_owned())?;
    match prompt_after(segment, launched_at) {
        Some(prompt) if prompt <= ready_at => {}
        _ => {
            return Err(format!(
                "no prompt between launch and ready of gen={generation}"
            ))
        }
    }
    let announced = format!(
        "[IPC ] console pid={init_pid}: [INIT] service={SHELL_SERVICE} ready gen={generation}"
    );
    if !lines(segment).any(|line| line.contains(&announced)) {
        return Err(format!("init did not announce {announced:?}"));
    }
    Ok(Shell { pid, generation })
}

/// The boot segment: from power-on to the first instance's ready report.
fn check_boot(segment: &str) -> Result<(u64, Shell), String> {
    let launched = only_kernel_line(segment, "[KERN] init launched pid=")?;
    let init_pid = number(launched, "pid")?;
    only_kernel_line(segment, "[KERN] serial console input on vector=")?;
    let shell = check_instance(segment, 1, init_pid)?;
    Ok((init_pid, shell))
}

/// Whether `step`, typed into `shell`, has completed within `segment` (the output from the
/// moment it was typed), with the fixture peer having `served` that much meanwhile. `Ok`
/// carries the shell the next step runs in.
fn check_step(
    step: &Step,
    segment: &str,
    served: Served,
    shell: Shell,
    init_pid: u64,
) -> Result<Shell, String> {
    match step.expect {
        Expect::Network {
            lines: want,
            served: want_served,
        } => {
            check_lines(segment, want)?;
            if !served.covers(want_served) {
                return Err(format!(
                    "the fixture peer served {served:?} while the step ran, not {want_served:?}"
                ));
            }
            Ok(shell)
        }
        Expect::Lines {
            lines: want,
            absent,
        } => {
            check_lines(segment, want)?;
            for line in absent {
                if lines(segment).any(|got| got == *line) {
                    return Err(format!("unexpected line {line:?}"));
                }
            }
            Ok(shell)
        }
        Expect::LineSet(want) => {
            let end = line_set_at(segment, want)
                .ok_or_else(|| format!("no output lines, in any order, {want:?}"))?;
            prompt_after(segment, end)
                .map(|_| shell)
                .ok_or_else(|| format!("no prompt after {want:?}"))
        }
        Expect::TmpWrite { lines: want, bytes } => {
            check_lines(segment, want)?;
            let write = only_kernel_line(segment, "[STOR] write object=")?;
            let object = number(write, "object")?;
            if !TMP_OBJECT_IDS.contains(&object) || number(write, "bytes")? != bytes {
                return Err(format!(
                    "expected a {bytes}-byte /tmp object write: {write:?}"
                ));
            }
            Ok(shell)
        }
        Expect::Relaunch => {
            let exit = format!("[LNX ] exit pid={} status=0", shell.pid);
            let exited = segment.find(&exit).ok_or_else(|| format!("no {exit:?}"))?;
            let next = check_instance(&segment[exited..], shell.generation + 1, init_pid)?;
            if next.pid == shell.pid {
                return Err(format!("the new shell reuses pid={}", shell.pid));
            }
            Ok(next)
        }
    }
}

fn check_lines(segment: &str, want: &[&str]) -> Result<(), String> {
    let end = whole_lines_at(segment, want).ok_or_else(|| format!("no output lines {want:?}"))?;
    prompt_after(segment, end)
        .map(|_| ())
        .ok_or_else(|| format!("no prompt after {want:?}"))
}

/// The whole run. `segments[0]` is the boot, `segments[i]` the output after step `i` was typed,
/// and `served[i - 1]` what the fixture peer served from then until the next step was typed.
fn validate(segments: &[&str], served: &[Served]) -> Result<Vec<Shell>, String> {
    if segments.len() != STEPS.len() + 1 || served.len() != STEPS.len() {
        return Err(format!(
            "expected {} segments and {} fixture reports, got {} and {}",
            STEPS.len() + 1,
            STEPS.len(),
            segments.len(),
            served.len()
        ));
    }
    let whole = segments.concat();
    for forbidden in ["[FAIL]", "[INIT] gave up", "[INIT] not starting"] {
        if let Some(line) = lines(&whole).find(|line| line.contains(forbidden)) {
            return Err(format!("{forbidden:?} in {line:?}"));
        }
    }
    let (init_pid, mut shell) =
        check_boot(segments[0]).map_err(|reason| format!("boot: {reason}"))?;
    let mut shells = vec![shell];
    for ((step, segment), served) in STEPS.iter().zip(&segments[1..]).zip(served) {
        let next = check_step(step, segment, *served, shell, init_pid)
            .map_err(|reason| format!("step {:?}: {reason}", step.name))?;
        if next != shell {
            shells.push(next);
        }
        shell = next;
    }
    let launches = kernel_lines(&whole, &format!("[SVC ] launch service={SHELL_SERVICE} ")).count();
    if launches != shells.len() {
        return Err(format!(
            "{launches} shell launches for {} instances",
            shells.len()
        ));
    }
    Ok(shells)
}

fn save_transcript(transcript: &[u8]) -> Result<(), XtaskError> {
    let dir = xtask_artifact_root().join("system-shell");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("serial.log");
    std::fs::write(&path, transcript)?;
    println!("[SHL ] serial transcript: {}", path.display());
    Ok(())
}

/// `test-system-shell`: one boot of the default image on a fresh lane-owned disk; the host
/// types [`STEPS`] into the shell over a loopback COM1.
pub(crate) fn run() -> Result<(), XtaskError> {
    let disk = workspace_root()
        .join("target")
        .join("system-shell")
        .join(SYSTEM_DATA_DISK_FILENAME);
    if disk.is_file() {
        std::fs::remove_file(&disk)?;
    }
    ensure_data_disk(&disk)?;
    let peer = start_shell_fixture_peer()?;
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let config = VmLaunchConfig {
        serial_tcp_port: Some(listener.local_addr()?.port()),
        ..system_vm_config(disk, Some(peer.port()))
    };
    let result = drive(&listener, config, &peer);
    peer.shutdown();
    let (transcript, boundaries) = result?;
    let typed_at = &boundaries[..boundaries.len().saturating_sub(1)];
    let offsets: Vec<usize> = typed_at.iter().map(|(at, _)| *at).collect();
    let segments = split_at(&transcript, &offsets);
    let borrowed: Vec<&str> = segments.iter().map(String::as_str).collect();
    let served: Vec<Served> = boundaries
        .windows(2)
        .map(|pair| Served::between(pair[0].1, pair[1].1))
        .collect();
    let shells = validate(&borrowed, &served)
        .map_err(|reason| XtaskError::Validation(format!("system shell: {reason}")))?;
    let pids: Vec<String> = shells
        .iter()
        .map(|shell| format!("pid={} gen={}", shell.pid, shell.generation))
        .collect();
    println!(
        "\n[SHL ] PASS the serial-console shell ran echo, ls /bin, a pipeline, a /tmp object write and read and a backspace edit; exit ended it and its successor read /tmp back; Ctrl-D ended that one; init relaunched it each time; the third shell resolved m7.fixture.test and fetched http://m7.fixture.test:4001/ from the fixture peer, which reported serving both: {}",
        pids.join(", ")
    );
    Ok(())
}

/// The transcript cut at the byte offsets where steps were typed, each piece decoded on its own
/// so an invalid byte cannot move a boundary.
fn split_at(transcript: &[u8], boundaries: &[usize]) -> Vec<String> {
    let mut segments = Vec::new();
    let mut from = 0;
    for &at in boundaries {
        let at = at.clamp(from, transcript.len());
        segments.push(String::from_utf8_lossy(&transcript[from..at]).into_owned());
        from = at;
    }
    segments.push(String::from_utf8_lossy(&transcript[from..]).into_owned());
    segments
}

/// A point in the run: the transcript length and what the fixture peer had served by then.
type Boundary = (usize, FixtureCounts);

/// Boots QEMU and types the script. Returns the transcript and a [`Boundary`] for each step,
/// taken as it was typed, and one at the end.
fn drive(
    listener: &TcpListener,
    config: VmLaunchConfig,
    peer: &M7FixturePeer,
) -> Result<(Vec<u8>, Vec<Boundary>), XtaskError> {
    let mut vm = prepare_vm(false, false, &[], config)?;
    announce_qemu_version(&vm.qemu);
    vm.qemu.stdin(Stdio::null());
    let deadline = Instant::now() + LANE_TIMEOUT;
    let mut child = ReapOnDrop(vm.qemu.spawn()?);
    let stream = accept_serial(listener, &mut child, deadline)?;
    let mut writer = stream.try_clone()?;
    let (tx, rx) = mpsc::channel();
    let _reader = spawn_serial_reader(stream, tx);

    let mut transcript = Vec::new();
    let mut boundaries: Vec<Boundary> = Vec::new();
    let mut state: Option<(u64, Shell)> = None;
    let mut step_started = Instant::now();
    let fail = |transcript: &[u8], message: String| {
        let _ = save_transcript(transcript);
        Err(XtaskError::Validation(format!(
            "system shell: {message}; tail {:?}",
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
        for forbidden in [&b"[FAIL]"[..], b"[INIT] gave up"] {
            if find(&transcript, forbidden).is_some() {
                return fail(
                    &transcript,
                    format!("{:?} printed", String::from_utf8_lossy(forbidden)),
                );
            }
        }
        let (from, counts_from) = boundaries
            .last()
            .copied()
            .unwrap_or((0, FixtureCounts::default()));
        let segment = String::from_utf8_lossy(&transcript[from..]);
        let progress = match state {
            None => check_boot(&segment),
            Some((init_pid, shell)) => {
                let step = &STEPS[boundaries.len() - 1];
                let served = Served::between(counts_from, peer.counts());
                check_step(step, &segment, served, shell, init_pid).map(|next| (init_pid, next))
            }
        };
        let now = Instant::now();
        match progress {
            Ok(next) => {
                state = Some(next);
                if boundaries.len() == STEPS.len() {
                    boundaries.push((transcript.len(), peer.counts()));
                    save_transcript(&transcript)?;
                    return Ok((transcript, boundaries));
                }
                let step = &STEPS[boundaries.len()];
                println!("\n[SHL ] step {:?}", step.name);
                boundaries.push((transcript.len(), peer.counts()));
                writer.write_all(step.send)?;
                writer.flush()?;
                step_started = now;
            }
            Err(reason) => {
                let waiting = match boundaries.len() {
                    0 => "boot",
                    sent => STEPS[sent - 1].name,
                };
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

/// QEMU's exit status once its serial port has gone, or that it was still running two seconds on.
fn qemu_state(child: &mut ReapOnDrop) -> Result<String, XtaskError> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(format!("exited with {status}"));
        }
        if Instant::now() >= deadline {
            return Ok("was still running".to_owned());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance(pid: u64, generation: u64, init_pid: u64) -> String {
        format!(
            "{}\n\
             [SVC ] shell process pid={pid} gen={generation} argv=/bin/sh,-i env=PATH=/bin stdin=1 stdout=1 tmp=1 net-client=1\n\
             [SVC ] console input so far lines=0 eofs=0\n\
             [SVC ] launch service=21504 pid={pid} gen={generation}\n\
             \n\n# BusyBox v1.37.0 (2026-09-23 09:18:28 UTC) built-in shell (ash)\n\n\
             [SVC ] ready service=21504 pid={pid} gen={generation} source=live-instance kernel-observed first-console-input-wait\n\
             [IPC ] console pid={init_pid}: [INIT] service=21504 ready gen={generation}\n",
            expected_authority(pid)
        )
    }

    fn boot() -> String {
        format!(
            "[KERN] serial console input on vector=0x31\n\
             [KERN] init launched pid=3 slot=0 declared-services=3\n\
             [IPC ] console pid=3: [INIT] service=20736 ready; starting service=21504\n{}",
            instance(6, 1, 3)
        )
    }

    /// What a correct guest prints after each step is typed, echo included.
    fn good_segments() -> Vec<String> {
        let ls: String = BIN_ENTRIES.iter().map(|name| format!("{name}\n")).collect();
        vec![
            boot(),
            "echo hel''lo-shell\r\nhello-shell\n# ".to_owned(),
            format!("ls /bin\r\n{ls}# "),
            "printf 'pipe-%s\\n' yes no | grep yes\r\n[LNX ] exit pid=7 status=0\npipe-yes\n# "
                .to_owned(),
            "printf 'obj-%d\\n' 7 > /tmp/a; cat /tmp/a\r\n[STOR] write object=4980736 bytes=6\nobj-7\n# "
                .to_owned(),
            "echo typo\x08 \x08\x08 \x08\x08 \x08\x08 \x08fix''ed\r\nfixed\n# ".to_owned(),
            format!("exit\r\n[LNX ] exit pid=6 status=0\n{}", instance(9, 2, 3)),
            "echo aga''in; cat /tmp/a\r\nagain\nobj-7\n# ".to_owned(),
            format!("[LNX ] exit pid=9 status=0\n{}", instance(11, 3, 3)),
            "nslookup m7.fixture.test\r\n\
             [CAP ] net allow op=connect holder=11\n\
             nslookup: can't resolve '(null)'\n\n\
             Name:      m7.fixture.test\nAddress 1: 10.77.0.50\n\n# "
                .to_owned(),
            "wget -q -O - http://m7.fixture.test:4001/\r\nM9-FIXTURE-HTTP\n# ".to_owned(),
        ]
    }

    const NSLOOKUP_SEGMENT: usize = 9;
    const WGET_SEGMENT: usize = 10;

    /// What the fixture reports for a correct run: one A answer during `nslookup`, one more
    /// and the HTTP response during `wget`, nothing otherwise.
    fn good_served() -> Vec<Served> {
        let mut served = vec![Served::default(); STEPS.len()];
        served[NSLOOKUP_SEGMENT - 1].fixture_a_answers = 1;
        served[WGET_SEGMENT - 1] = Served {
            fixture_a_answers: 1,
            http_responses: 1,
        };
        served
    }

    fn run(segments: &[String]) -> Result<Vec<Shell>, String> {
        run_served(segments, &good_served())
    }

    fn run_served(segments: &[String], served: &[Served]) -> Result<Vec<Shell>, String> {
        let borrowed: Vec<&str> = segments.iter().map(String::as_str).collect();
        validate(&borrowed, served)
    }

    #[test]
    fn network_steps_need_their_output_lines() {
        let mut segments = good_segments();
        segments[NSLOOKUP_SEGMENT] =
            "nslookup m7.fixture.test\r\nnslookup: can't resolve 'm7.fixture.test'\n# ".to_owned();
        assert!(run(&segments).unwrap_err().contains("nslookup"));
        let mut segments = good_segments();
        segments[NSLOOKUP_SEGMENT] = segments[NSLOOKUP_SEGMENT].replace("10.77.0.50", "10.77.0.1");
        assert!(run(&segments).is_err());
        let mut segments = good_segments();
        segments[WGET_SEGMENT] = "wget -q -O - http://m7.fixture.test:4001/\r\n\
             wget: can't connect to remote host: Permission denied\n# "
            .to_owned();
        assert!(run(&segments).unwrap_err().contains("wget"));
    }

    #[test]
    fn network_steps_need_the_fixture_peer_to_have_served_them() {
        for (step, field) in [
            (NSLOOKUP_SEGMENT, "dns"),
            (WGET_SEGMENT, "dns"),
            (WGET_SEGMENT, "http"),
        ] {
            let mut served = good_served();
            match field {
                "dns" => served[step - 1].fixture_a_answers = 0,
                _ => served[step - 1].http_responses = 0,
            }
            let error = run_served(&good_segments(), &served).unwrap_err();
            assert!(
                error.contains("fixture peer served"),
                "{step} {field}: {error}"
            );
        }
        let mut early = good_served();
        early[NSLOOKUP_SEGMENT - 2].fixture_a_answers = 1;
        early[NSLOOKUP_SEGMENT - 1].fixture_a_answers = 0;
        assert!(run_served(&good_segments(), &early).is_err());
        assert!(run_served(&good_segments(), &good_served()[1..]).is_err());
    }

    #[test]
    fn fixture_reports_are_differences_between_step_boundaries() {
        let at = |dns, http| FixtureCounts {
            fixture_a_answers: dns,
            http_responses: http,
        };
        assert_eq!(
            Served::between(at(2, 1), at(4, 1)),
            Served {
                fixture_a_answers: 2,
                http_responses: 0,
            }
        );
        assert!(Served::between(at(2, 1), at(3, 2)).covers(STEP_WGET_SERVED));
        assert!(!Served::between(at(3, 2), at(3, 2)).covers(STEP_WGET_SERVED));
    }

    const STEP_WGET_SERVED: Served = Served {
        fixture_a_answers: 1,
        http_responses: 1,
    };

    #[test]
    fn a_correct_session_validates_with_three_generations() {
        assert_eq!(
            run(&good_segments()),
            Ok(vec![
                Shell {
                    pid: 6,
                    generation: 1
                },
                Shell {
                    pid: 9,
                    generation: 2
                },
                Shell {
                    pid: 11,
                    generation: 3
                },
            ])
        );
    }

    #[test]
    fn the_echo_of_a_command_is_not_its_output() {
        let mut segments = good_segments();
        segments[1] = "echo hel''lo-shell\r\n# ".to_owned();
        assert!(run(&segments).unwrap_err().contains("hello-shell"));
        let mut segments = good_segments();
        segments[3] = "printf 'pipe-%s\\n' yes no | grep yes\r\n# ".to_owned();
        assert!(run(&segments).is_err());
    }

    #[test]
    fn output_must_be_followed_by_a_prompt() {
        let mut segments = good_segments();
        segments[1] = "echo hel''lo-shell\r\nhello-shell\n".to_owned();
        assert!(run(&segments).unwrap_err().contains("no prompt"));
    }

    #[test]
    fn applets_may_come_in_directory_order() {
        let mut segments = good_segments();
        let reversed: String = BIN_ENTRIES
            .iter()
            .rev()
            .map(|name| format!("{name}\n"))
            .collect();
        segments[2] = format!("ls /bin\r\n[LNX ] personality=x86_64 pid=8\n{reversed}# ");
        assert!(run(&segments).is_ok());
    }

    #[test]
    fn a_missing_or_extra_applet_fails() {
        let mut segments = good_segments();
        segments[2] = segments[2].replace("grep\n", "");
        assert!(run(&segments).is_err());
        let mut segments = good_segments();
        segments[2] = segments[2].replace("ls /bin\r\nbusybox\n", "ls /bin\r\nbusybox\nbash\n");
        assert!(run(&segments).is_err());
        let mut segments = good_segments();
        segments[2] = segments[2]
            .replace("grep\n", "grep\ngrep\n")
            .replace("wget\n", "");
        assert!(run(&segments).is_err());
    }

    #[test]
    fn grep_must_filter() {
        let mut segments = good_segments();
        segments[3] = segments[3].replace("pipe-yes\n", "pipe-yes\npipe-no\n");
        assert!(run(&segments).unwrap_err().contains("pipe-no"));
    }

    #[test]
    fn the_tmp_write_must_reach_a_tmp_object() {
        let mut segments = good_segments();
        segments[4] = segments[4].replace("[STOR] write object=4980736 bytes=6\n", "");
        assert!(run(&segments).unwrap_err().contains("[STOR] write"));
        let mut segments = good_segments();
        segments[4] = segments[4].replace("object=4980736", "object=1");
        assert!(run(&segments).is_err());
        let mut segments = good_segments();
        segments[4] = segments[4].replace("bytes=6", "bytes=7");
        assert!(run(&segments).is_err());
    }

    #[test]
    fn backspace_must_edit_the_line() {
        let mut segments = good_segments();
        segments[5] = segments[5].replace("\nfixed\n", "\ntypofixed\n");
        assert!(run(&segments).is_err());
    }

    #[test]
    fn exit_without_a_new_generation_fails() {
        let mut segments = good_segments();
        segments[6] = "exit\r\n[LNX ] exit pid=6 status=0\n".to_owned();
        assert!(run(&segments).is_err());
        let mut segments = good_segments();
        segments[6] = segments[6].replace("gen=2", "gen=1");
        assert!(run(&segments).is_err());
        let mut segments = good_segments();
        segments[6] = segments[6].replace("status=0", "status=1");
        assert!(run(&segments).is_err());
    }

    #[test]
    fn the_new_shell_must_print_a_prompt_before_it_is_ready() {
        let mut segments = good_segments();
        segments[6] = segments[6].replace("# BusyBox", "BusyBox");
        assert!(run(&segments).unwrap_err().contains("no prompt"));
    }

    #[test]
    fn ready_must_come_from_the_launched_instance() {
        let mut segments = good_segments();
        segments[0] = segments[0].replace(
            "[SVC ] ready service=21504 pid=6",
            "[SVC ] ready service=21504 pid=7",
        );
        assert!(run(&segments).unwrap_err().contains("ready says"));
    }

    #[test]
    fn extra_shell_authority_fails() {
        for (from, to) in [
            ("tmp-objects=4", "tmp-objects=3"),
            ("console-input=1", "console-input=0"),
            ("network=0", "network=1"),
            ("net-client=1 ", "net-client=0 "),
            ("net-client-entitlement=1", "net-client-entitlement=0"),
            ("linux=1", "linux=0"),
            ("matches-manifest=1", "matches-manifest=0"),
        ] {
            let mut segments = good_segments();
            segments[0] = segments[0].replace(from, to);
            assert!(run(&segments).unwrap_err().contains("authority"), "{to}");
        }
        let mut segments = good_segments();
        segments[0] = segments[0].replace("stdin=1", "stdin=0");
        assert!(run(&segments).is_err());
        let mut segments = good_segments();
        segments[0] = segments[0].replace("tmp=1 net-client=1", "tmp=1 net-client=0");
        assert!(run(&segments).is_err());
    }

    #[test]
    fn a_failure_or_give_up_anywhere_fails() {
        for line in [
            "[FAIL] something\n",
            "[IPC ] console pid=3: [INIT] gave up service=21504 restarts=3; init carries on\n",
        ] {
            let mut segments = good_segments();
            segments[7].push_str(line);
            assert!(run(&segments).is_err(), "{line}");
        }
    }

    #[test]
    fn init_must_announce_each_generation() {
        let mut segments = good_segments();
        segments[8] = segments[8].replace("[INIT] service=21504 ready gen=3", "");
        assert!(run(&segments).unwrap_err().contains("announce"));
    }

    #[test]
    fn every_step_waits_for_its_own_output_only() {
        for step in STEPS {
            if let Expect::Lines { lines, .. }
            | Expect::LineSet(lines)
            | Expect::TmpWrite { lines, .. }
            | Expect::Network { lines, .. } = step.expect
            {
                let typed = String::from_utf8_lossy(step.send);
                for line in lines {
                    assert!(
                        !typed
                            .lines()
                            .any(|typed| typed.trim_end_matches('\r') == *line),
                        "{:?} would be satisfied by its echo",
                        step.name
                    );
                }
            }
        }
        assert!(STEPS.iter().any(|step| step.send.contains(&0x08)));
        assert!(STEPS.iter().any(|step| step.send == b"\x04"));
        assert!(STEPS.iter().any(|step| step.send == b"exit\r"));
    }

    #[test]
    fn segments_are_cut_at_byte_offsets_of_the_raw_transcript() {
        let transcript = b"boot\xff# \xffecho\n";
        assert_eq!(
            split_at(transcript, &[7]),
            ["boot\u{fffd}# ", "\u{fffd}echo\n"]
        );
    }

    #[test]
    fn whole_lines_must_match_exactly_and_adjacently() {
        assert_eq!(whole_lines_at("a\nb\nc\n", &["b", "c"]), Some(6));
        assert_eq!(whole_lines_at("a\r\nbb\n", &["b"]), None);
        assert_eq!(whole_lines_at("b\nx\nc\n", &["b", "c"]), None);
        assert_eq!(whole_lines_at("b", &["b"]), None, "an unfinished line");
        assert_eq!(
            whole_lines_at("b\n[LNX ] exit pid=4 status=0\n\nc\n", &["b", "c"]),
            Some(32)
        );
        assert_eq!(whole_lines_at("b\n[LNX] x\nc\n", &["b", "c"]), None);
    }
}
