//! `test-system` (#218 S7b): the network service faults under a live shell, and init restarts
//! it.
//!
//! This lane tests the **`system-test-hooks` build**: the default image plus the test hooks in
//! `kernel/src/service/system_test_hooks.rs`. Here Ctrl-\ on COM1 faults the live network
//! service with a real user-mode page fault. Everything from the fault on is the default image's
//! own code: the fault report, the Linux socket loss, the client capability revoke, init's
//! restart policy, the new instance's launch audit and the capability re-issue.
//!
//! Before that boot, three short headless boots of the same kernel pass
//! `-fw_cfg name=opt/clean-slate/desktop,string=q1` ([`crate::system_desktop`]): one with a
//! VirtIO-GPU, where init launches the compositor, desktop shell and app rows next to the base
//! rows; one with no display, which boots base; and one with only the `-vga std` framebuffer,
//! which runs the desktop at Q0. The shell boot passes no entry and requires `profile=base` and
//! no desktop row.
//!
//! The shell boot is `test-system-shell`'s: a fresh lane-owned data disk, the network fixture
//! peer and COM1 on a loopback socket. Each [`Step`] is typed once the step before it is complete:
//!
//! 1. `nslookup` and `wget` from the shell reach the fixture through network generation 1.
//! 2. A foreground `wget` to the fixture's hold port, which accepts and never answers, leaves
//!    the shell's child blocked in a TCP read.
//! 3. Ctrl-\ faults the network service. The blocked read must fail with the reset error and
//!    the shell must still prompt; init restarts the service once; generation 2 passes its
//!    launch audit, the shell's client capability is re-issued for it, and init settles again.
//! 4. `nslookup` and `wget` from the same shell work again, through generation 2.
//!
//! Each `wget` step proves a full exchange both ways: the fixture answers port 4001 only after
//! receiving the complete request, and the step requires it to have answered exactly one
//! request while the step ran and to have refused none (#255). The hold port reads the blocked
//! reader's request and reports its arrival, but never answers; the held step requires both
//! the held connection and that request. A connection the fixture refuses for lack of a
//! complete request fails the lane at once.
//!
//! TLS is not exercised here: this BusyBox has no TLS, and TLS stays covered by the M7 lanes.

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::process::Stdio;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::guest_reboot::GuestRebootDetector;
use crate::m7_fixture::{FixtureCounts, M7FixturePeer};
use crate::serial_input_lane::{accept_serial, find, spawn_serial_reader, tail, SerialEvent};
use crate::system_boot::{
    ensure_data_disk, field, number, start_shell_fixture_peer, system_vm_config,
    SYSTEM_DATA_DISK_FILENAME,
};
use crate::system_shell::{
    check_boot, check_lines, kernel_lines, lines, only_kernel_line, prompt_after, qemu_state,
    whole_lines_at, Shell, SHELL_SERVICE,
};
use crate::{
    announce_qemu_version, prepare_vm, workspace_root, xtask_artifact_root, ReapOnDrop,
    VmLaunchConfig, XtaskError,
};

/// The kernel feature this lane builds; nothing else enables it.
const HOOKS_FEATURE: &str = "system-test-hooks";
const NETWORK_SERVICE: u32 = 0x5200;
/// Boot to the first prompt plus every step, the restart's backoff included; the kernel build
/// before it is not counted.
const LANE_TIMEOUT: Duration = Duration::from_secs(300);
const STEP_TIMEOUT: Duration = Duration::from_secs(60);
/// How long the held connection must stay unanswered, with no prompt, before the fault: the
/// reader is then parked in its read, not still on its way to it.
const HOLD_SETTLE: Duration = Duration::from_secs(1);
/// BusyBox `wget` when the response read fails with `ECONNRESET`.
const RESET_ERROR: &str = "wget: error getting response: Connection reset by peer";
const HOOKS_BANNER: &str =
    "[HOOK] system-test-hooks build: Ctrl-\\ on COM1 faults the network service";
const SETTLED: &str = "[INIT] boot settled running=3 down=0; waiting, no deadline";
/// What a step must produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    /// These whole lines, in order and adjacent, then a prompt, with the fixture peer having
    /// sent at least `fixture_a_answers` A records meanwhile, and answered exactly
    /// `http_responses` received HTTP requests and refused none.
    Network {
        lines: &'static [&'static str],
        fixture_a_answers: u32,
        http_responses: u32,
    },
    /// The fixture peer holds the reader's connection unanswered, has received its request,
    /// and the shell has printed no prompt.
    Held,
    /// The fault, the woken reader, the restart and generation 2 (see [`check_fault`]).
    Fault,
}

#[derive(Clone, Copy, Debug)]
struct Step {
    name: &'static str,
    send: &'static [u8],
    expect: Expect,
}

const NSLOOKUP: Step = Step {
    name: "nslookup",
    send: b"nslookup m7.fixture.test\r",
    expect: Expect::Network {
        lines: &["Name:      m7.fixture.test", "Address 1: 10.77.0.50"],
        fixture_a_answers: 1,
        http_responses: 0,
    },
};
const WGET: Step = Step {
    name: "wget",
    send: b"wget -q -O - http://m7.fixture.test:4001/\r",
    expect: Expect::Network {
        lines: &["M9-FIXTURE-HTTP"],
        fixture_a_answers: 1,
        http_responses: 1,
    },
};

const STEPS: [Step; 6] = [
    NSLOOKUP,
    WGET,
    Step {
        name: "blocked reader",
        send: b"wget -q -O - http://m7.fixture.test:4003/\r",
        expect: Expect::Held,
    },
    Step {
        name: "fault",
        send: b"\x1c",
        expect: Expect::Fault,
    },
    Step {
        name: "nslookup after restart",
        ..NSLOOKUP
    },
    Step {
        name: "wget after restart",
        ..WGET
    },
];

/// The live network service instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Network {
    pid: u64,
    generation: u64,
}

/// What the lane knows between steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct State {
    init_pid: u64,
    shell: Shell,
    network: Network,
}

/// The kernel's launch audit for a network instance must be exactly the row's grants.
fn expected_network_authority(pid: u64) -> String {
    format!(
        "[SVC ] authority service={NETWORK_SERVICE} pid={pid} lifecycle-control=0 console=0 block-device=0 object-service=0 network=1 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 other=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=1 linux=0 console-input=0 matches-manifest=1"
    )
}

/// One network instance came up in `segment`: launch, launch audit, the kernel's ready report
/// from that pid and generation, and init's announcement. Returns it with the offset just past
/// init's announcement.
fn check_network_instance(
    segment: &str,
    generation: u64,
    init_pid: u64,
) -> Result<(Network, usize), String> {
    let launch_prefix = format!("[SVC ] launch service={NETWORK_SERVICE} ");
    let launch = only_kernel_line(segment, &launch_prefix)
        .map_err(|reason| format!("network generation {generation}: {reason}"))?;
    let pid = number(launch, "pid")?;
    if number(launch, "gen")? != generation {
        return Err(format!("expected network gen={generation}: {launch:?}"));
    }
    let authority = only_kernel_line(
        segment,
        &format!("[SVC ] authority service={NETWORK_SERVICE} "),
    )?;
    if authority != expected_network_authority(pid) {
        return Err(format!(
            "network generation {generation} launch audit {authority:?}"
        ));
    }
    let ready = only_kernel_line(segment, &format!("[SVC ] ready service={NETWORK_SERVICE} "))
        .map_err(|reason| format!("network generation {generation}: {reason}"))?;
    if number(ready, "pid")? != pid
        || number(ready, "gen")? != generation
        || field(ready, "source") != Some("live-instance")
    {
        return Err(format!(
            "network launched as pid={pid} gen={generation} but ready says {ready:?}"
        ));
    }
    let announced = format!(
        "[IPC ] console pid={init_pid}: [INIT] service={NETWORK_SERVICE} ready gen={generation}"
    );
    let announced_at = segment
        .find(&announced)
        .ok_or_else(|| format!("init did not announce {announced:?}"))?;
    Ok((Network { pid, generation }, announced_at + announced.len()))
}

/// The boot: the hooks build's banner, network generation 1, the first shell and init settled
/// with all three services running.
fn check_boot_segment(segment: &str) -> Result<State, String> {
    if !lines(segment).any(|line| line.contains(HOOKS_BANNER)) {
        return Err(format!("no {HOOKS_BANNER:?}: this is not the hooks build"));
    }
    let (init_pid, shell) = check_boot(segment)?;
    let (network, _) = check_network_instance(segment, 1, init_pid)?;
    if !lines(segment).any(|line| line.contains(SETTLED)) {
        return Err(format!("init has not printed {SETTLED:?}"));
    }
    Ok(State {
        init_pid,
        shell,
        network,
    })
}

/// Offset of the first line containing `needle` in `segment`.
fn line_at(segment: &str, needle: &str) -> Result<usize, String> {
    segment
        .find(needle)
        .ok_or_else(|| format!("no line containing {needle:?}"))
}

/// The `[TAG ] ... count=N reason=instance-gone` report, with `N >= 1`.
fn check_loss_report(segment: &str, prefix: &str) -> Result<usize, String> {
    let line = only_kernel_line(segment, prefix)?;
    if number(line, "count")? == 0 || field(line, "reason") != Some("instance-gone") {
        return Err(format!("unexpected {line:?}"));
    }
    line_at(segment, line)
}

/// Everything Ctrl-\ must cause, in `segment` (the output since it was typed), checked in the
/// order it happens so the first missing piece is what a failure names.
fn check_fault(segment: &str, state: State) -> Result<State, String> {
    let State {
        init_pid,
        shell,
        network,
    } = state;
    let armed = format!(
        "[HOOK] network fault armed pid={} gen={} user_rip=0x0 parked-in=native",
        network.pid, network.generation
    );
    let line = only_kernel_line(segment, "[HOOK] network fault armed ")?;
    // The trailing ` at-ms=` stamp is for the desktop lane's timing report.
    if line.split(" at-ms=").next() != Some(armed.as_str()) {
        return Err(format!("expected {armed:?}"));
    }
    let fault_prefix = format!("[PROC] fault pid={} vector=14 ", network.pid);
    let faulted_at = line_at(segment, &fault_prefix)
        .map_err(|_| format!("the network service did not fault: no {fault_prefix:?}"))?;
    let lost_at = check_loss_report(segment, "[NET ] linux sockets lost ")?;
    check_loss_report(segment, "[CAP ] net client revoked ")?;
    if lost_at < faulted_at {
        return Err("linux sockets were reported lost before the fault".to_owned());
    }

    let reset_end = whole_lines_at(segment, &[RESET_ERROR]).ok_or_else(|| {
        format!("the blocked reader was not woken with the reset error {RESET_ERROR:?}")
    })?;
    if reset_end < lost_at {
        return Err("the reset error came before the sockets were lost".to_owned());
    }
    prompt_after(segment, reset_end)
        .ok_or_else(|| "the shell printed no prompt after the reset error".to_owned())?;
    if lines(segment).any(|line| line.contains(&format!("[LNX ] exit pid={} ", shell.pid))) {
        return Err(format!("the shell pid={} exited", shell.pid));
    }
    if kernel_lines(segment, &format!("[SVC ] launch service={SHELL_SERVICE} ")).count() != 0 {
        return Err("a new shell was launched".to_owned());
    }

    let after_fault = &segment[faulted_at..];
    let restart = format!(
        "[IPC ] console pid={init_pid}: [SUP ] restart service={NETWORK_SERVICE} attempt=1"
    );
    if !lines(after_fault).any(|line| line.contains(&restart)) {
        return Err(format!(
            "waiting for network generation 2: init has not restarted it ({restart:?})"
        ));
    }
    let (next, announced_end) =
        check_network_instance(after_fault, network.generation + 1, init_pid)
            .map_err(|reason| format!("waiting for network generation 2: {reason}"))?;
    if next.pid == network.pid {
        return Err(format!("network generation 2 reuses pid={}", network.pid));
    }
    let reissued = format!(
        "[CAP ] net client reissued holder={} generation={}",
        shell.pid, next.generation
    );
    if !lines(after_fault).any(|line| line.contains(&reissued)) {
        return Err(format!("no {reissued:?}"));
    }
    if !lines(&after_fault[announced_end..]).any(|line| line.contains(SETTLED)) {
        return Err(format!(
            "init has not printed {SETTLED:?} since generation 2 became ready"
        ));
    }
    Ok(State {
        network: next,
        ..state
    })
}

/// Whether `step` has completed within `segment` (the output since it was typed), the fixture
/// peer having gone from `before` to `now` meanwhile.
fn check_step(
    step: &Step,
    segment: &str,
    before: FixtureCounts,
    now: FixtureCounts,
    state: State,
) -> Result<State, String> {
    match step.expect {
        Expect::Network {
            lines: want,
            fixture_a_answers,
            http_responses,
        } => {
            check_lines(segment, want)?;
            let answers = now
                .fixture_a_answers
                .saturating_sub(before.fixture_a_answers);
            let responses = now.http_responses.saturating_sub(before.http_responses);
            let refused = now.http_refused.saturating_sub(before.http_refused);
            if answers < fixture_a_answers || responses != http_responses || refused != 0 {
                return Err(format!(
                    "the fixture peer sent {answers} A answers, answered {responses} received HTTP requests and refused {refused} while the step ran, not {fixture_a_answers}, {http_responses} and 0"
                ));
            }
            Ok(state)
        }
        Expect::Held => {
            if now.held_connections <= before.held_connections {
                return Err("the fixture peer holds no connection from the reader".to_owned());
            }
            if now.held_requests <= before.held_requests {
                return Err(
                    "the fixture peer has not received the reader's request on the hold port"
                        .to_owned(),
                );
            }
            if prompt_after(segment, 0).is_some() {
                return Err("the shell prompted: the reader is not blocked".to_owned());
            }
            Ok(state)
        }
        Expect::Fault => check_fault(segment, state),
    }
}

/// Whole-run checks once every step has passed.
fn check_whole(transcript: &str) -> Result<(), String> {
    for forbidden in ["[FAIL]", "[INIT] gave up", "[INIT] not starting"] {
        if let Some(line) = lines(transcript).find(|line| line.contains(forbidden)) {
            return Err(format!("{forbidden:?} in {line:?}"));
        }
    }
    for (prefix, want) in [
        (format!("[SVC ] launch service={SHELL_SERVICE} "), 1),
        (format!("[SVC ] launch service={NETWORK_SERVICE} "), 2),
        ("[SUP ] restart service=".to_owned(), 1),
        ("[PROC] fault pid=".to_owned(), 1),
        ("[HOOK] network fault armed ".to_owned(), 1),
        ("[NET ] linux sockets lost ".to_owned(), 1),
    ] {
        let got = kernel_lines(transcript, &prefix).count();
        if got != want {
            return Err(format!("{got} lines {prefix:?}, expected {want}"));
        }
    }
    Ok(())
}

fn save_transcript(transcript: &[u8]) -> Result<(), XtaskError> {
    let dir = xtask_artifact_root().join("system");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("serial.log");
    std::fs::write(&path, transcript)?;
    println!("[STM ] serial transcript: {}", path.display());
    Ok(())
}

/// `test-system`: the three desktop boots, then one boot of the hooks build
/// on a fresh lane-owned disk; the host types [`STEPS`] into the shell over a loopback COM1.
pub(crate) fn run() -> Result<(), XtaskError> {
    println!(
        "[STM ] test-system boots the {HOOKS_FEATURE} build: the default image plus test hooks (COM1 fault bytes for the network service, compositor, desktop shell and app; desktop resource, quiet and stale-generation evidence; per-input trace lines)"
    );
    let disk = workspace_root()
        .join("target")
        .join("system")
        .join(SYSTEM_DATA_DISK_FILENAME);
    if disk.is_file() {
        std::fs::remove_file(&disk)?;
    }
    ensure_data_disk(&disk)?;
    crate::system_desktop::run(&[HOOKS_FEATURE], &disk)?;
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
    let (transcript, states) = result?;
    check_whole(&String::from_utf8_lossy(&transcript))
        .and_then(|()| check_fixture_totals(counts))
        .map_err(|reason| XtaskError::Validation(format!("system: {reason}")))?;
    let before = states[0];
    let after = states[states.len() - 1];
    println!(
        "\n[STM ] PASS ({HOOKS_FEATURE} build) shell pid={} resolved through the fixture and fetched from it through network pid={} gen={}, the fixture answering the request it received; the next wget's request reached the fixture's hold port, which held it unanswered; Ctrl-\\ faulted the network service, the blocked wget read failed with ECONNRESET and the shell prompted again, init restarted the service as pid={} gen={}, its launch audit matched, the shell's client capability was re-issued for it, init settled, and from the same shell nslookup resolved through the fixture again and wget's request reached the fixture and was answered again",
        before.shell.pid, before.network.pid, before.network.generation, after.network.pid, after.network.generation
    );
    Ok(())
}

/// The two `wget` steps' requests, one per network generation.
const SYSTEM_HTTP_REQUESTS: u32 = 2;

/// What the fixture peer served over the whole run: each `wget` step's request answered, no
/// connection refused, and the one held connection's request received and never answered.
fn check_fixture_totals(counts: FixtureCounts) -> Result<(), String> {
    counts.require_http_requests("test-system", SYSTEM_HTTP_REQUESTS)?;
    if counts.held_connections != 1 || counts.held_requests != 1 {
        return Err(format!(
            "the fixture's hold port held {} connection(s) and received {} request(s) on them, expected 1 and 1",
            counts.held_connections, counts.held_requests
        ));
    }
    Ok(())
}

/// Boots QEMU and types the script. Returns the transcript and the [`State`] after the boot
/// and after each step.
fn drive(
    listener: &TcpListener,
    config: VmLaunchConfig,
    peer: &M7FixturePeer,
) -> Result<(Vec<u8>, Vec<State>), XtaskError> {
    let mut vm = prepare_vm(false, false, &[HOOKS_FEATURE], config)?;
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
    let mut states: Vec<State> = Vec::new();
    // Where the step being waited for was typed, and the fixture counts then.
    let mut typed_at = 0usize;
    let mut counts_then = FixtureCounts::default();
    let mut step_started = Instant::now();
    // When the current step's check first passed, for steps that must stay passing.
    let mut passing_since: Option<Instant> = None;
    let fail = |transcript: &[u8], message: String| {
        let _ = save_transcript(transcript);
        Err(XtaskError::Validation(format!(
            "system: {message}; tail {:?}",
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
        let segment = String::from_utf8_lossy(&transcript[typed_at..]);
        let waiting = match states.len() {
            0 => "boot",
            done => STEPS[done - 1].name,
        };
        let progress = match states.last() {
            None => check_boot_segment(&segment),
            Some(state) => check_step(
                &STEPS[states.len() - 1],
                &segment,
                counts_then,
                peer.counts(),
                *state,
            ),
        };
        let refused = peer.counts().http_refused;
        if refused != 0 {
            return fail(
                &transcript,
                format!(
                    "the fixture refused {refused} HTTP connection(s) without a complete request in {waiting:?}"
                ),
            );
        }
        for forbidden in [&b"[FAIL]"[..], b"[INIT] gave up"] {
            if let Some(at) = find(&transcript, forbidden) {
                let line = String::from_utf8_lossy(&transcript[at..]);
                let line = line.lines().next().unwrap_or_default();
                let reason = progress.as_ref().err().cloned().unwrap_or_default();
                return fail(
                    &transcript,
                    format!("{line:?} printed in {waiting:?} ({reason})"),
                );
            }
        }
        let now = Instant::now();
        match progress {
            Ok(next) => {
                let must_hold = states
                    .len()
                    .checked_sub(1)
                    .is_some_and(|index| STEPS[index].expect == Expect::Held);
                let since = *passing_since.get_or_insert(now);
                if must_hold && now.duration_since(since) < HOLD_SETTLE {
                    continue;
                }
                passing_since = None;
                states.push(next);
                if states.len() == STEPS.len() + 1 {
                    if let Err(missing) = reboot_detector.require_kernel_banner() {
                        return fail(&transcript, missing);
                    }
                    save_transcript(&transcript)?;
                    return Ok((transcript, states));
                }
                let step = &STEPS[states.len() - 1];
                println!("\n[STM ] step {:?}", step.name);
                typed_at = transcript.len();
                counts_then = peer.counts();
                writer.write_all(step.send)?;
                writer.flush()?;
                step_started = now;
            }
            Err(reason) => {
                passing_since = None;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_shell::expected_authority;

    const INIT: u64 = 1;
    const SHELL: u64 = 4;
    const NET1: u64 = 3;
    const NET2: u64 = 8;

    fn network_instance(pid: u64, generation: u64) -> String {
        format!(
            "{}\n\
             [SVC ] launch service=20992 pid={pid} gen={generation}\n\
             [SVC ] ready service=20992 pid={pid} gen={generation} source=live-instance kernel-observed raw-backend=virtio service-reported link-up=1\n\
             [IPC ] console pid={INIT}: [INIT] service=20992 ready gen={generation}\n",
            expected_network_authority(pid)
        )
    }

    fn boot() -> String {
        format!(
            "{HOOKS_BANNER}\n\
             [KERN] serial console input on vector=0x31\n\
             [KERN] boot profile=base\n\
             [KERN] init launched pid={INIT} slot=0 declared-services=3\n\
             [IPC ] console pid={INIT}: [INIT] boot profile=base\n\
             {}\
             {}\n\
             [SVC ] shell process pid={SHELL} gen=1 argv=/bin/sh,-i env=PATH=/bin stdin=1 stdout=1 tmp=1 net-client=1\n\
             [SVC ] launch service=21504 pid={SHELL} gen=1\n\
             \n# BusyBox v1.37.0 built-in shell (ash)\n\n\
             [SVC ] ready service=21504 pid={SHELL} gen=1 source=live-instance kernel-observed first-console-input-wait\n\
             [IPC ] console pid={INIT}: [INIT] service=21504 ready gen=1\n\
             [IPC ] console pid={INIT}: {SETTLED}\n",
            network_instance(NET1, 1),
            expected_authority(SHELL)
        )
    }

    fn fault() -> String {
        format!(
            "[HOOK] network fault armed pid={NET1} gen=1 user_rip=0x0 parked-in=native\n\
             [PROC] fault pid={NET1} vector=14 err=0x14\n\
             [PROC] fault rip=0x0000000000000000 cr2=0x0000000000000000 instruction_fetch=1\n\
             [NET ] linux sockets lost count=1 reason=instance-gone\n\
             [CAP ] net client revoked count=2 reason=instance-gone\n\
             {RESET_ERROR}\n\
             [LNX ] exit pid=7 status=1\n\
             # [IPC ] console pid={INIT}: [SUP ] restart service=20992 attempt=1\n\
             [CAP ] net client reissued holder={SHELL} generation=2\n\
             {}\
             [IPC ] console pid={INIT}: {SETTLED}\n",
            network_instance(NET2, 2)
        )
    }

    fn booted() -> State {
        check_boot_segment(&boot()).expect("boot")
    }

    /// Counts with every held connection's request received and nothing refused.
    fn counts(dns: u32, http: u32, held: u32) -> FixtureCounts {
        FixtureCounts {
            fixture_a_answers: dns,
            http_responses: http,
            http_refused: 0,
            held_connections: held,
            held_requests: held,
        }
    }

    fn fault_error(segment: &str) -> String {
        check_fault(segment, booted()).unwrap_err()
    }

    #[test]
    fn a_correct_boot_and_fault_reach_generation_2_under_the_same_shell() {
        let state = booted();
        assert_eq!(
            state,
            State {
                init_pid: INIT,
                shell: Shell {
                    pid: SHELL,
                    generation: 1
                },
                network: Network {
                    pid: NET1,
                    generation: 1
                },
            }
        );
        let after = check_fault(&fault(), state).expect("fault");
        assert_eq!(
            after.network,
            Network {
                pid: NET2,
                generation: 2
            }
        );
        assert_eq!(after.shell, state.shell);
    }

    #[test]
    fn the_boot_must_be_the_hooks_build_and_settled() {
        let error = check_boot_segment(&boot().replace(HOOKS_BANNER, "")).unwrap_err();
        assert!(error.contains("not the hooks build"), "{error}");
        assert!(check_boot_segment(&boot().replace("running=3", "running=2")).is_err());
        let wrong_audit = boot().replace("raw-net-link=1", "raw-net-link=0");
        assert!(check_boot_segment(&wrong_audit)
            .unwrap_err()
            .contains("launch audit"));
    }

    #[test]
    fn the_blocked_reader_must_wake_with_the_reset_error_and_a_prompt() {
        let error = fault_error(&fault().replace(RESET_ERROR, ""));
        assert!(error.contains("blocked reader was not woken"), "{error}");
        let error = fault_error(&fault().replace("# [IPC ]", "[IPC ]"));
        assert!(error.contains("no prompt"), "{error}");
        let error = fault_error(&format!("{}[LNX ] exit pid={SHELL} status=0\n", fault()));
        assert!(error.contains("shell"), "{error}");
    }

    #[test]
    fn the_fault_must_be_real_and_lose_the_sockets() {
        assert!(fault_error(&fault().replace("vector=14", "vector=13")).contains("did not fault"));
        assert!(
            fault_error(&fault().replace("gen=1 user_rip", "gen=2 user_rip")).contains("armed")
        );
        assert!(
            fault_error(&fault().replace("[NET ] linux sockets lost count=1", ""))
                .contains("sockets lost")
        );
        assert!(
            fault_error(&fault().replace("sockets lost count=1", "sockets lost count=0"))
                .contains("unexpected")
        );
        assert!(fault_error(&fault().replace("[CAP ] net client revoked", "")).contains("revoked"));
    }

    #[test]
    fn generation_2_needs_the_restart_its_audit_the_reissue_and_init_settled() {
        let error = fault_error(&fault().replace("[SUP ] restart service=20992 attempt=1", ""));
        assert!(
            error.contains("waiting for network generation 2"),
            "{error}"
        );
        let error = fault_error(&fault().replace("[SVC ] launch service=20992 pid=8 gen=2", ""));
        assert!(
            error.contains("waiting for network generation 2"),
            "{error}"
        );
        let error = fault_error(&fault().replace(
            &expected_network_authority(NET2),
            &expected_network_authority(NET2).replace("network=1", "network=0"),
        ));
        assert!(error.contains("launch audit"), "{error}");
        let error =
            fault_error(&fault().replace("[CAP ] net client reissued", "[CAP ] net client"));
        assert!(error.contains("reissued"), "{error}");
        let error = fault_error(&fault().replace("holder=4 generation=2", "holder=9 generation=2"));
        assert!(error.contains("reissued"), "{error}");
        let settled_last = format!("[IPC ] console pid={INIT}: {SETTLED}\n");
        let error = fault_error(&fault().replace(&settled_last, ""));
        assert!(error.contains("since generation 2"), "{error}");
    }

    #[test]
    fn steps_need_the_fixture_to_have_served_them() {
        let state = booted();
        let nslookup =
            "nslookup m7.fixture.test\r\nName:      m7.fixture.test\nAddress 1: 10.77.0.50\n# ";
        assert!(check_step(&NSLOOKUP, nslookup, counts(0, 0, 0), counts(1, 0, 0), state).is_ok());
        assert!(
            check_step(&NSLOOKUP, nslookup, counts(1, 0, 0), counts(1, 0, 0), state)
                .unwrap_err()
                .contains("fixture peer")
        );
        let wget = "wget -q -O - http://m7.fixture.test:4001/\r\nM9-FIXTURE-HTTP\n# ";
        assert!(check_step(&WGET, wget, counts(1, 0, 0), counts(2, 1, 0), state).is_ok());
        assert!(check_step(&WGET, wget, counts(1, 0, 0), counts(2, 0, 0), state).is_err());
        assert!(check_step(&WGET, wget, counts(1, 0, 0), counts(2, 2, 0), state).is_err());
        let refused = FixtureCounts {
            http_refused: 1,
            ..counts(2, 1, 0)
        };
        let error = check_step(&WGET, wget, counts(1, 0, 0), refused, state).unwrap_err();
        assert!(error.contains("refused 1"), "{error}");
        assert!(check_step(&NSLOOKUP, nslookup, counts(0, 0, 0), counts(1, 1, 0), state).is_err());
    }

    #[test]
    fn the_run_needs_both_requests_answered_and_the_held_request_received() {
        assert_eq!(check_fixture_totals(counts(4, 2, 1)), Ok(()));
        assert!(check_fixture_totals(counts(4, 1, 1)).is_err());
        assert!(check_fixture_totals(counts(4, 2, 0)).is_err());
        let unheard = FixtureCounts {
            held_requests: 0,
            ..counts(4, 2, 1)
        };
        assert!(check_fixture_totals(unheard)
            .unwrap_err()
            .contains("received 0 request"));
        let refused = FixtureCounts {
            http_refused: 1,
            ..counts(4, 2, 1)
        };
        assert!(check_fixture_totals(refused).is_err());
    }

    #[test]
    fn the_reader_must_be_held_and_unprompted() {
        let held = &STEPS[2];
        let state = booted();
        let typed =
            "wget -q -O - http://m7.fixture.test:4003/\r\n[LNX ] personality=x86_64 pid=7\n";
        assert!(check_step(held, typed, counts(2, 1, 0), counts(3, 1, 1), state).is_ok());
        assert!(
            check_step(held, typed, counts(2, 1, 0), counts(3, 1, 0), state)
                .unwrap_err()
                .contains("holds no connection")
        );
        let unheard = FixtureCounts {
            held_requests: 0,
            ..counts(3, 1, 1)
        };
        assert!(check_step(held, typed, counts(2, 1, 0), unheard, state)
            .unwrap_err()
            .contains("has not received"));
        let prompted = format!("{typed}wget: bad address\n# ");
        assert!(
            check_step(held, &prompted, counts(2, 1, 0), counts(3, 1, 1), state)
                .unwrap_err()
                .contains("not blocked")
        );
    }

    #[test]
    fn the_whole_run_allows_one_fault_one_restart_and_no_failure() {
        let whole = format!("{}{}", boot(), fault());
        assert_eq!(check_whole(&whole), Ok(()));
        for extra in [
            "[FAIL] something\n",
            "[IPC ] console pid=1: [INIT] gave up service=20992 restarts=3; init carries on\n",
            "[PROC] fault pid=4 vector=14 err=0x4\n",
            "[IPC ] console pid=1: [SUP ] restart service=20992 attempt=2\n",
            "[SVC ] launch service=21504 pid=9 gen=2\n",
            "[NET ] linux sockets lost count=1 reason=instance-gone\n",
        ] {
            assert!(check_whole(&format!("{whole}{extra}")).is_err(), "{extra}");
        }
    }

    #[test]
    fn the_script_faults_only_once_and_after_the_reader_is_held() {
        let faults: Vec<usize> = STEPS
            .iter()
            .enumerate()
            .filter(|(_, step)| step.send.contains(&0x1c))
            .map(|(index, _)| index)
            .collect();
        assert_eq!(faults.len(), 1);
        assert_eq!(STEPS[faults[0]].expect, Expect::Fault);
        assert_eq!(STEPS[faults[0] - 1].expect, Expect::Held);
        assert_eq!(STEPS[faults[0] + 1].send, NSLOOKUP.send);
        assert_eq!(STEPS[faults[0] + 2].send, WGET.send);
    }
}
