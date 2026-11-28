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

use crate::guest_reboot::GuestRebootDetector;
use crate::m7_fixture::{FixtureCounts, M7FixturePeer};
use crate::marker_spec::{first_guest_failure, first_guest_failure_in_bytes};
use crate::serial_input_lane::{accept_serial, find, spawn_serial_reader, tail, SerialEvent};
use crate::system_boot::{
    ensure_data_disk, field, number, start_shell_fixture_peer, system_vm_config,
    SYSTEM_DATA_DISK_FILENAME,
};
use crate::{
    announce_qemu_version, prepare_vm, workspace_root, xtask_artifact_root, ReapOnDrop,
    VmLaunchConfig, XtaskError,
};

pub(crate) const SHELL_SERVICE: u32 = 0x5400;
/// ash's prompt for uid 0.
pub(crate) const PROMPT: &str = "# ";
/// How a line a process wrote to its console fds starts on serial (#310), before its pid.
pub(crate) const CONSOLE_LINE_PREFIX: &str = "[CON ] pid=";
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
/// The `system-test-hooks` fault bytes the first step types: network, compositor, desktop
/// shell, app.
const HOOK_BYTES: u64 = 4;
/// Lines that fail the run wherever they appear, besides any guest failure line. `[HOOK]` lines
/// come only from the `system-test-hooks` build, which this default-image lane must never be.
const FORBIDDEN: [&str; 3] = ["[INIT] gave up", "[INIT] not starting", "[HOOK]"];

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
    /// As `Lines`, where the line is a lane marker the shell must not be able to forge (#310):
    /// it is the shell's output, so it must reach serial labeled and tagged, and no serial line
    /// may start with it.
    Forged(&'static str),
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
const STEPS: [Step; 11] = [
    // The leading bytes are `test-system`'s fault bytes (Ctrl-\, Ctrl-], Ctrl-^, Ctrl-_). This
    // default image has no hook, so they must be four dropped control bytes and nothing else
    // (see `validate`).
    Step {
        name: "echo",
        send: b"\x1c\x1d\x1e\x1fecho hel''lo-shell\r",
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
    // The M4 gate's own pass marker, printed at the start of a line, as `marker_spec` reads it.
    Step {
        name: "forged marker",
        send: b"printf '\\n[M4  ] PASS\\n'\r",
        expect: Expect::Forged(FORGED_MARKER),
    },
];

/// A lane marker the forge step prints (`[M4  ] PASS`, the M4 gate's).
const FORGED_MARKER: &str = "[M4  ] PASS";

/// The `wget` step's one `GET /`; no other step talks HTTP.
const SHELL_HTTP_REQUESTS: u32 = 1;

/// The live shell instance a step runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Shell {
    pub(crate) pid: u64,
    pub(crate) generation: u64,
}

pub(crate) fn lines(segment: &str) -> impl Iterator<Item = &str> {
    segment.lines().map(|line| line.trim_end_matches('\r'))
}

/// The text from the first occurrence of `prefix` to the end of its line, wherever the line
/// starts: kernel lines can follow a prompt that has no newline.
/// The console service's line, once a boot, when typed input first answers a read.
const SERIAL_INPUT_SERVED: &str = "[CONS] serial input answered a read";

pub(crate) fn kernel_lines<'a>(segment: &'a str, prefix: &'a str) -> impl Iterator<Item = &'a str> {
    lines(segment).filter_map(move |line| line.find(prefix).map(|at| &line[at..]))
}

pub(crate) fn only_kernel_line<'a>(segment: &'a str, prefix: &str) -> Result<&'a str, String> {
    let mut found = lines(segment).filter_map(|line| line.find(prefix).map(|at| &line[at..]));
    let line = found
        .next()
        .ok_or_else(|| format!("no line containing {prefix:?}"))?;
    if found.next().is_some() {
        return Err(format!("more than one line containing {prefix:?}"));
    }
    Ok(line)
}

/// What a process wrote, from its console line `[CON ] pid=N: text` (#310): the console
/// service labels every line of a Linux process's console fds with its pid, and the kernel tags
/// it. `None` for any other line: kernel lines, which are printed between the writes of the
/// processes a command runs, and the echo of typed input, which is tagged but not labeled.
pub(crate) fn console_text(line: &str) -> Option<&str> {
    let rest = line.strip_prefix(CONSOLE_LINE_PREFIX)?;
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    rest[digits..].strip_prefix(": ")
}

/// The finished, non-blank lines of process output in `segment`, each with the offset just
/// past its newline.
fn output_lines(segment: &str) -> Vec<(usize, &str)> {
    let mut found = Vec::new();
    let mut at = 0;
    for line in segment.split_inclusive('\n') {
        at += line.len();
        if !line.ends_with('\n') {
            continue;
        }
        let line = line.trim_end_matches('\n').trim_end_matches('\r');
        if let Some(text) = console_text(line).filter(|text| !text.is_empty()) {
            found.push((at, text));
        }
    }
    found
}

/// Where `expected` first appears as consecutive output lines; returns the offset past them.
pub(crate) fn whole_lines_at(segment: &str, expected: &[&str]) -> Option<usize> {
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

/// A prompt at the start of a process's console line that starts at or after `from` (a line
/// start); returns the offset just past it. The console service shows a line without a newline
/// (the prompt) open once it is idle, so the prompt is the end of the transcript so far.
pub(crate) fn prompt_after(segment: &str, from: usize) -> Option<usize> {
    let mut start = from;
    for piece in segment[from..].split_inclusive('\n') {
        if let Some(text) = console_text(piece).filter(|text| text.starts_with(PROMPT)) {
            return Some(start + (piece.len() - text.len()) + PROMPT.len());
        }
        start += piece.len();
    }
    None
}

/// The kernel's authority line for a shell instance must be exactly the row's grants.
pub(crate) fn expected_authority(pid: u64) -> String {
    format!(
        "[SVC ] authority service={SHELL_SERVICE} pid={pid} lifecycle-control=0 console=1 block-device=0 object-service=0 network=0 net-client=1 net-client-entitlement=1 tmp-objects=5 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 audit-read=0 audit-store=0 con-serve=0 con-device=0 con-client=1 launch-serve=0 launch-client=0 power=0 other=0 revoked=0 allowance=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0 linux=1 console-input=1 matches-manifest=1"
    )
}

/// One shell instance came up in `segment`: authority, launch, the process line, the kernel's
/// ready report from that pid and generation, init's announcement and a prompt.
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
    // The shell's console text reaches serial through the console service, after the shell
    // wrote it: the prompt can follow the kernel's ready report, which comes when the shell
    // blocks reading stdin.
    let launched_at = segment.find(launch).unwrap_or(0);
    if prompt_after(segment, launched_at).is_none() {
        return Err(format!("no prompt since the launch of gen={generation}"));
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
pub(crate) fn check_boot(segment: &str) -> Result<(u64, Shell), String> {
    let launched = only_kernel_line(segment, "[KERN] init launched pid=")?;
    let init_pid = number(launched, "pid")?;
    only_kernel_line(segment, "[KERN] serial console input on vector=")?;
    require_base_profile(segment, init_pid)?;
    crate::system_boot::check_no_desktop_rows(segment, launched)?;
    let shell = check_instance(segment, 1, init_pid)?;
    Ok((init_pid, shell))
}

/// No fw_cfg entry: the kernel and init each say the desktop is off, once.
pub(crate) fn require_base_profile(segment: &str, init_pid: u64) -> Result<(), String> {
    let kernel = only_kernel_line(segment, "[KERN] boot profile=")?;
    if kernel != "[KERN] boot profile=base" {
        return Err(format!(
            "desktop boot option: no fw_cfg entry must leave the desktop off, got {kernel:?}"
        ));
    }
    let init = format!("[IPC ] console pid={init_pid}: [INIT] boot profile=base");
    let count = lines(segment).filter(|line| line.contains(&init)).count();
    if count != 1 {
        return Err(format!(
            "desktop boot option: expected one {init:?}, found {count}"
        ));
    }
    Ok(())
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
                if lines(segment)
                    .filter_map(console_text)
                    .any(|got| got == *line)
                {
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
        Expect::Forged(marker) => {
            check_lines(segment, &[marker])?;
            if let Some(line) = lines(segment).find(|line| line.starts_with(marker)) {
                return Err(format!("the shell forged a serial line: {line:?}"));
            }
            Ok(shell)
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

pub(crate) fn check_lines(segment: &str, want: &[&str]) -> Result<(), String> {
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
    if let Some(failure) = first_guest_failure(&whole, true) {
        return Err(format!("guest failure {failure:?}"));
    }
    for forbidden in FORBIDDEN {
        if let Some(line) = lines(&whole).find(|line| line.contains(forbidden)) {
            return Err(format!("{forbidden:?} in {line:?}"));
        }
    }
    // Every shell launch reports the console counters so far; the last one comes after the
    // fault bytes typed with the first step, which only the hooks build acts on.
    let counters = kernel_lines(&whole, "[SVC ] console input so far ")
        .last()
        .ok_or_else(|| "no console input counters".to_owned())?;
    if number(counters, "control-dropped")? != HOOK_BYTES {
        return Err(format!(
            "the {HOOK_BYTES} fault bytes must be exactly {HOOK_BYTES} dropped control bytes: {counters:?}"
        ));
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
    // The step's segment starts on the prompt's line, so only the whole transcript shows how
    // every line starts.
    if crate::marker_spec::find_marker(&whole, 0, FORGED_MARKER).is_some() {
        return Err(format!(
            "a lane's marker reader accepts the shell's {FORGED_MARKER:?}"
        ));
    }
    // Typed input reaches the shell through the console service (#310), which says so once.
    if kernel_lines(&whole, SERIAL_INPUT_SERVED).count() != 1 {
        return Err(format!(
            "the console service must answer a read with typed input, once saying {SERIAL_INPUT_SERVED:?}"
        ));
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
    let counts = peer.shutdown();
    let (transcript, boundaries) = result?;
    counts
        .require_http_requests("test-system-shell", SHELL_HTTP_REQUESTS)
        .map_err(XtaskError::Validation)?;
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
        "\n[SHL ] PASS the serial-console shell ran echo, ls /bin, a pipeline, a /tmp object write and read and a backspace edit; exit ended it and its successor read /tmp back; Ctrl-D ended that one; init relaunched it each time; the third shell resolved m7.fixture.test and fetched http://m7.fixture.test:4001/ from the fixture peer, which reported serving both; its printed `[M4  ] PASS` reached serial labeled and tagged, never as a line of its own: {}",
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
    let mut reboot_detector = GuestRebootDetector::default();
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
        if let Some(reboot) = reboot_detector.observe(&transcript) {
            return fail(&transcript, reboot);
        }
        if let Some(failure) = first_guest_failure_in_bytes(&transcript, false) {
            return fail(&transcript, format!("{failure:?} printed"));
        }
        for forbidden in FORBIDDEN {
            if find(&transcript, forbidden.as_bytes()).is_some() {
                return fail(&transcript, format!("{forbidden:?} printed"));
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
                    if let Err(missing) = reboot_detector.require_kernel_banner() {
                        return fail(&transcript, missing);
                    }
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
pub(crate) fn qemu_state(child: &mut ReapOnDrop) -> Result<String, XtaskError> {
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

    /// Lines process `pid` wrote, as the console service labels them and the kernel tags them.
    fn con(pid: u64, lines: &[&str]) -> String {
        lines
            .iter()
            .map(|line| format!("{CONSOLE_LINE_PREFIX}{pid}: {line}\n"))
            .collect()
    }

    /// `pid`'s prompt, shown open once the console service is idle.
    fn prompt(pid: u64) -> String {
        format!("{CONSOLE_LINE_PREFIX}{pid}: {PROMPT}")
    }

    fn instance(pid: u64, generation: u64, init_pid: u64) -> String {
        format!(
            "{}\n\
             [SVC ] shell process pid={pid} gen={generation} argv=/bin/sh,-i env=PATH=/bin stdin=1 stdout=1 tmp=1 net-client=1\n\
             [SVC ] console input so far lines=0 eofs=0 control-dropped={}\n\
             [CONS] authority granted pid={pid} port=22016:3 rights=connect\n\
             [SVC ] launch service=21504 pid={pid} gen={generation}\n\
             {}\
             [SVC ] ready service=21504 pid={pid} gen={generation} source=live-instance kernel-observed first-console-input-wait\n\
             [IPC ] console pid={init_pid}: [INIT] service=21504 ready gen={generation}\n",
            expected_authority(pid),
            // The fault bytes are typed with the first step, so every later shell has seen
            // them dropped.
            if generation > 1 { HOOK_BYTES } else { 0 },
            con(
                pid,
                &[
                    "",
                    "",
                    "# BusyBox v1.37.0 (2026-09-23 09:18:28 UTC) built-in shell (ash)",
                    ""
                ]
            ),
        )
    }

    fn boot() -> String {
        format!(
            "[KERN] serial console input on vector=0x31\n\
             [KERN] boot profile=base\n\
             [KERN] init launched pid=3 slot=0 declared-services=5\n\
             [IPC ] console pid=3: [INIT] boot profile=base\n\
             [IPC ] console pid=3: [INIT] service=20736,22016 ready; starting service=21504\n{}",
            instance(6, 1, 3)
        )
    }

    /// What a correct guest prints after each step is typed, echo included. The echo of a
    /// command goes on the prompt's open line, which is where each segment starts.
    fn good_segments() -> Vec<String> {
        vec![
            boot(),
            format!(
                "echo hel''lo-shell\r\n[IPC ] console pid=4: {SERIAL_INPUT_SERVED}\n{}{}",
                con(6, &["hello-shell"]),
                prompt(6)
            ),
            format!("ls /bin\r\n{}{}", con(8, &BIN_ENTRIES), prompt(6)),
            format!(
                "printf 'pipe-%s\\n' yes no | grep yes\r\n[LNX ] exit pid=7 status=0\n{}{}",
                con(8, &["pipe-yes"]),
                prompt(6)
            ),
            format!(
                "printf 'obj-%d\\n' 7 > /tmp/a; cat /tmp/a\r\n[STOR] write object=4980736 bytes=6\n{}{}",
                con(9, &["obj-7"]),
                prompt(6)
            ),
            format!(
                "echo typo\x08 \x08\x08 \x08\x08 \x08\x08 \x08fix''ed\r\n{}{}",
                con(6, &["fixed"]),
                prompt(6)
            ),
            format!("exit\r\n[LNX ] exit pid=6 status=0\n{}", instance(9, 2, 3)),
            format!(
                "echo aga''in; cat /tmp/a\r\n{}{}{}",
                con(9, &["again"]),
                con(10, &["obj-7"]),
                prompt(9)
            ),
            format!("[LNX ] exit pid=9 status=0\n{}", instance(11, 3, 3)),
            format!(
                "nslookup m7.fixture.test\r\n\
                 [CAP ] net allow op=connect holder=12\n{}{}",
                con(
                    12,
                    &[
                        "nslookup: can't resolve '(null)'",
                        "",
                        "Name:      m7.fixture.test",
                        "Address 1: 10.77.0.50",
                        ""
                    ]
                ),
                prompt(11)
            ),
            format!(
                "wget -q -O - http://m7.fixture.test:4001/\r\n{}{}",
                con(13, &["M9-FIXTURE-HTTP"]),
                prompt(11)
            ),
            format!(
                "printf '\\n[M4  ] PASS\\n'\r\n{}{}",
                con(11, &["", FORGED_MARKER]),
                prompt(11)
            ),
        ]
    }

    const FORGE_SEGMENT: usize = 11;

    #[test]
    fn the_shell_cannot_forge_a_lane_marker() {
        assert!(run(&good_segments()).is_ok());
        // The marker as the shell's output, but on a line of its own: what a guest whose
        // console fds bypass the service would print.
        let mut segments = good_segments();
        segments[FORGE_SEGMENT] = format!(
            "printf '\\n[M4  ] PASS\\n'\r\n{}{}\n{}",
            con(11, &[FORGED_MARKER]),
            FORGED_MARKER,
            prompt(11)
        );
        assert!(run(&segments).unwrap_err().contains("forged a serial line"));
        // Labeled but untagged: a line a marker reader would take as the gate's.
        let mut segments = good_segments();
        segments[FORGE_SEGMENT] =
            segments[FORGE_SEGMENT].replace("[CON ] pid=11: [M4", "pid=11: [M4");
        assert!(run(&segments).is_err());
        // Never printed at all.
        let mut segments = good_segments();
        segments[FORGE_SEGMENT] = format!("printf '\\n[M4  ] PASS\\n'\r\n{}", prompt(11));
        assert!(run(&segments).unwrap_err().contains("[M4  ] PASS"));
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
        segments[NSLOOKUP_SEGMENT] = format!(
            "nslookup m7.fixture.test\r\n{}{}",
            con(12, &["nslookup: can't resolve 'm7.fixture.test'"]),
            prompt(11)
        );
        assert!(run(&segments).unwrap_err().contains("nslookup"));
        let mut segments = good_segments();
        segments[NSLOOKUP_SEGMENT] = segments[NSLOOKUP_SEGMENT].replace("10.77.0.50", "10.77.0.1");
        assert!(run(&segments).is_err());
        let mut segments = good_segments();
        segments[WGET_SEGMENT] = format!(
            "wget -q -O - http://m7.fixture.test:4001/\r\n{}{}",
            con(
                13,
                &["wget: can't connect to remote host: Permission denied"]
            ),
            prompt(11)
        );
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
            ..FixtureCounts::default()
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
        segments[1] = format!("echo hel''lo-shell\r\n{}", prompt(6));
        assert!(run(&segments).unwrap_err().contains("hello-shell"));
        let mut segments = good_segments();
        segments[3] = format!("printf 'pipe-%s\\n' yes no | grep yes\r\n{}", prompt(6));
        assert!(run(&segments).is_err());
        // Typed text is echoed tagged but not labeled: it is never a process's output, even
        // on a line of its own.
        let mut segments = good_segments();
        segments[1] = format!("[CON ] hello-shell\r\n{}", prompt(6));
        assert!(run(&segments).unwrap_err().contains("hello-shell"));
        // Nor is untagged text, which no process can write any more.
        let mut segments = good_segments();
        segments[1] = format!("echo hel''lo-shell\r\nhello-shell\n{}", prompt(6));
        assert!(run(&segments).unwrap_err().contains("hello-shell"));
    }

    #[test]
    fn output_must_be_followed_by_a_prompt() {
        let mut segments = good_segments();
        segments[1] = format!("echo hel''lo-shell\r\n{}", con(6, &["hello-shell"]));
        assert!(run(&segments).unwrap_err().contains("no prompt"));
        // A bare `# ` is not the shell's prompt.
        let mut segments = good_segments();
        segments[1] = format!("echo hel''lo-shell\r\n{}# ", con(6, &["hello-shell"]));
        assert!(run(&segments).unwrap_err().contains("no prompt"));
    }

    #[test]
    fn applets_may_come_in_directory_order() {
        let mut segments = good_segments();
        let reversed: Vec<&str> = BIN_ENTRIES.iter().rev().copied().collect();
        segments[2] = format!(
            "ls /bin\r\n[LNX ] personality=x86_64 pid=8\n{}{}",
            con(8, &reversed),
            prompt(6)
        );
        assert!(run(&segments).is_ok());
    }

    #[test]
    fn a_missing_or_extra_applet_fails() {
        let mut segments = good_segments();
        segments[2] = segments[2].replace("[CON ] pid=8: grep\n", "");
        assert!(run(&segments).is_err());
        let mut segments = good_segments();
        segments[2] = segments[2].replace(": busybox\n", ": busybox\n[CON ] pid=8: bash\n");
        assert!(run(&segments).is_err());
        let mut segments = good_segments();
        segments[2] = segments[2]
            .replace(": grep\n", ": grep\n[CON ] pid=8: grep\n")
            .replace("[CON ] pid=8: wget\n", "");
        assert!(run(&segments).is_err());
    }

    #[test]
    fn grep_must_filter() {
        let mut segments = good_segments();
        segments[3] = segments[3].replace(": pipe-yes\n", ": pipe-yes\n[CON ] pid=8: pipe-no\n");
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
        segments[5] = segments[5].replace(": fixed\n", ": typofixed\n");
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
    fn the_new_shell_must_print_a_prompt() {
        let mut segments = good_segments();
        segments[6] = segments[6].replace(": # BusyBox", ": BusyBox");
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
            ("tmp-objects=5", "tmp-objects=4"),
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
            "[IPC ] console pid=3: [SHL ] FAIL something\n",
            "[IPC ] console pid=3: [INIT] gave up service=21504 restarts=3; init carries on\n",
        ] {
            let mut segments = good_segments();
            segments[7].push_str(line);
            assert!(run(&segments).is_err(), "{line}");
        }
    }

    #[test]
    fn the_fault_bytes_must_be_dropped_control_bytes_and_nothing_else() {
        let mut segments = good_segments();
        segments[8] = segments[8].replace("control-dropped=4", "control-dropped=3");
        assert!(run(&segments).unwrap_err().contains("fault bytes"));
        for armed in [
            "[HOOK] network fault armed pid=4 gen=1 user_rip=0x0 parked-in=native\n",
            "[HOOK] compositor fault armed pid=7 gen=1 user_rip=0x0 parked-in=restart\n",
        ] {
            let mut segments = good_segments();
            segments[1].push_str(armed);
            assert!(run(&segments).unwrap_err().contains("[HOOK]"));
        }
        assert!(STEPS[0].send.starts_with(b"\x1c\x1d\x1e\x1f"));
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
            let forged;
            let want = match step.expect {
                Expect::Lines { lines, .. }
                | Expect::LineSet(lines)
                | Expect::TmpWrite { lines, .. }
                | Expect::Network { lines, .. } => Some(lines),
                Expect::Forged(marker) => {
                    forged = [marker];
                    Some(&forged[..])
                }
                Expect::Relaunch => None,
            };
            if let Some(lines) = want {
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
        let abc = con(4, &["a", "b", "c"]);
        assert_eq!(whole_lines_at(&abc, &["b", "c"]), Some(abc.len()));
        assert_eq!(whole_lines_at(&con(4, &["a", "bb"]), &["b"]), None);
        assert_eq!(whole_lines_at(&con(4, &["b", "x", "c"]), &["b", "c"]), None);
        assert_eq!(
            whole_lines_at(&format!("{CONSOLE_LINE_PREFIX}4: b"), &["b"]),
            None,
            "an unfinished line"
        );
        let between = format!(
            "{}[LNX ] exit pid=4 status=0\n{}{}",
            con(4, &["b"]),
            con(4, &[""]),
            con(5, &["c"])
        );
        assert_eq!(whole_lines_at(&between, &["b", "c"]), Some(between.len()));
        assert_eq!(whole_lines_at("b\nc\n", &["b", "c"]), None, "untagged");
        assert_eq!(
            whole_lines_at(
                &format!("{}[CON ] x\n{}", con(4, &["b"]), con(4, &["c"])),
                &["b", "c"]
            ),
            Some(con(4, &["b"]).len() + 9 + con(4, &["c"]).len()),
            "an echo line between two output lines is not output"
        );
    }

    #[test]
    fn console_text_is_what_follows_a_pid_label() {
        assert_eq!(console_text("[CON ] pid=6: # ls"), Some("# ls"));
        assert_eq!(console_text("[CON ] pid=6: "), Some(""));
        assert_eq!(console_text("[CON ] ls"), None);
        assert_eq!(console_text("[CON ] pid=: x"), None);
        assert_eq!(console_text("[M4  ] PASS"), None);
        assert_eq!(console_text("x [CON ] pid=6: y"), None);
    }
}
