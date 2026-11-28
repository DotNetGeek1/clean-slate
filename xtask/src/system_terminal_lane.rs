//! `cargo xtask test-system-terminal` (#311): the terminal window on the system image's desktop,
//! driven over QMP and COM1 on the hooks build, with `opt/clean-slate/desktop=q1` (the default desktop) on a
//! modern-only VirtIO-GPU.
//!
//! 1. **Boot**: init settles with its ten rows, the terminal's shell holds a console session
//!    record and the terminal a front-end one, and the terminal attaches and reports ready.
//! 2. **Focus**: the terminal opens behind the playground, which keeps focus, so a click on
//!    the part of its content the playground does not cover raises and focuses it, closed loop on the compositor's
//!    `[INPT] pointer settled` and `[INPT] button` lines as in `test-system-desktop`.
//! 3. **Type**: `echo hello` and Enter, one key per command. The shell's answer must come
//!    back through the console session, which still logs it on serial under the shell's pid,
//!    and the terminal's rows must have changed on screen.
//! 4. **Serial shell**: COM1 still reaches the serial shell, whose input the session never sees.
//! 5. **Rail** (#237): the shell listed both launchable rows from init's launcher port. A click
//!    on the rail's Playground slot focuses the playground's window, and one on the Terminal
//!    slot brings the terminal back, each closed loop on the shell's `[SHELL] rail switch=` line.
//! 6. **Terminal fault** (#358, the hooks build's Ctrl-T): the terminal faults and its shell
//!    reads the session's hang-up and exits; init starts both again under their restart
//!    policies, the other rows keep their pids, the resources return to the baseline, and
//!    `echo hello` typed into the new window comes back from the new shell (a fresh session).
//! 7. **Terminal shell fault** (Ctrl-W): only the shell restarts; the terminal keeps its pid
//!    and window, and the new shell answers through it.
//! 8. **Console service fault** (Ctrl-X) with the terminal attached: the console service
//!    restarts, the terminal exits `console-gone` and its shell hangs up rather than reading the
//!    serial line; both come back on the new service's port, the new session's output reaches
//!    the new window, and COM1 still reaches the serial shell, from its own pid.
//! 9. **Playground console stream** (#368): the playground kept its pid through the console
//!    restart; the kernel reissued its console record on the new port, and once a rail click
//!    wakes it the playground connects again and writes through the new service.

use std::time::Duration;

use clean_slate_graphics::{Point, Rect, Size};
use clean_slate_ui::QualityTier;

use crate::m10_desktop_lane::motion_chunks;
use crate::m10_desktop_visual::{
    center, cursor, rail_item, region_changed, sized_window_origin, OUTPUT,
};
use crate::qmp::image::Screenshot;
use crate::qmp::{InputAction, MouseButton, QCode};
use crate::system_boot::{
    desktop_qemu_args_for, desktop_qemu_args_with, ensure_data_disk, field, number,
    start_shell_fixture_peer, system_vm_config, DesktopProfile,
};
use crate::system_desktop::{whole_line, GIVE_UP_LINES, SETTLED_TERMINAL_DESKTOP};
use crate::system_desktop_faults::Session;
use crate::system_shell::lines;
use crate::{workspace_root, xtask_artifact_root, VmLaunchConfig, XtaskError};

const HOOKS_FEATURE: &str = "system-test-hooks";
const LANE_TIMEOUT: Duration = Duration::from_secs(600);
const STEP_TIMEOUT: Duration = Duration::from_secs(60);
const ARTIFACTS: &str = "system-terminal";
const SERIAL_LOG: &str = "system-terminal/serial.log";
/// A terminal exit is expected only at the console fault, so it is checked per step.
const FORBIDDEN: [&str; 3] = [
    GIVE_UP_LINES[0],
    GIVE_UP_LINES[1],
    "[SHELL] launcher unavailable",
];
const TERMINAL_EXIT: &str = "[TERM] exit";

const COMPOSITOR: u32 = 0x5300;
const DESKTOP_SHELL: u32 = 0x5301;
const APP: u32 = 0x5302;
const TERMINAL: u32 = 0x5303;
const SERIAL_SHELL: u32 = 0x5400;
const TERMINAL_SHELL: u32 = 0x5401;
const CONSOLE: u32 = 0x5600;
/// The hooks build's fault bytes (`kernel/src/service/system_test_hooks.rs`).
const TERMINAL_FAULT: &[u8] = b"\x14";
const TERMINAL_SHELL_FAULT: &[u8] = b"\x17";
const CONSOLE_FAULT: &[u8] = b"\x18";
/// `[SVC ] launch` lines per row over the run: the terminal at boot and after the terminal and
/// console faults, its shell after each of the three faults, the console service after its
/// fault, and every other row once.
const LAUNCHES: [(u32, usize); 7] = [
    (COMPOSITOR, 1),
    (DESKTOP_SHELL, 1),
    (APP, 1),
    (SERIAL_SHELL, 1),
    (CONSOLE, 2),
    (TERMINAL, 3),
    (TERMINAL_SHELL, 4),
];
const TERMINAL_PROFILE: &str = "[INIT] boot profile=desktop tier=Q1 terminal=on";

/// Where a starting compositor puts the pointer: the middle of the output.
const START: Point = Point {
    x: OUTPUT.width as i32 / 2,
    y: OUTPUT.height as i32 / 2,
};
/// See `test-system-desktop`: four PS/2 packets always fit the device's queue.
const PACKETS_PER_BATCH: usize = 4;
const SETTLE_WAIT: Duration = Duration::from_secs(10);
const EDGE_WAIT: Duration = Duration::from_secs(30);
const SETTLED: &str = "[INPT] pointer settled ";
/// Between key taps: the keyboard's queue is not the bottleneck, the guest's input path is.
const KEY_PACE: Duration = Duration::from_millis(150);

/// `echo hello-$$`, then Enter: one key per entry, shifted when its flag is set. The shell
/// that reads the line expands `$$` to its own pid, so the answer names the shell whatever
/// process prints it (this BusyBox runs `echo` as a child).
const TYPED: [(QCode, bool); 14] = [
    (QCode::E, false),
    (QCode::C, false),
    (QCode::H, false),
    (QCode::O, false),
    (QCode::SPC, false),
    (QCode::H, false),
    (QCode::E, false),
    (QCode::L, false),
    (QCode::L, false),
    (QCode::O, false),
    (QCode::MINUS, false),
    (QCode::N4, true),
    (QCode::N4, true),
    (QCode::RET, false),
];
const ANSWER: &str = "hello-";

/// One typed key, with shift held around it when `shifted`.
fn key_actions(qcode: QCode, shifted: bool) -> Vec<InputAction> {
    let mut actions = Vec::with_capacity(4);
    if shifted {
        actions.push(InputAction::Key {
            qcode: QCode::SHIFT,
            down: true,
        });
    }
    actions.extend(InputAction::tap(qcode));
    if shifted {
        actions.push(InputAction::Key {
            qcode: QCode::SHIFT,
            down: false,
        });
    }
    actions
}

/// The shell's listing of init's launchable rows: the playground and the terminal.
const LISTED: &str = "[SHELL] launcher listed=2";
/// Rail slots in the order init lists its rows (manifest order).
const RAIL: [(usize, &str); 2] = [(0, "playground"), (1, "terminal")];

/// The live terminal rows, and the console service they go through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Terminal {
    terminal_pid: u64,
    shell_pid: u64,
    console_pid: u64,
}

fn launched_pid(segment: &str, service: u32) -> Result<u64, String> {
    let (_, rest) = whole_line(segment, &format!("[SVC ] launch service={service} "))
        .ok_or_else(|| format!("service {service} has not launched"))?;
    number(&format!(" {rest}"), "pid")
}

/// The terminal boot: the profile, ten rows settled, the two console grants with their rights,
/// and the terminal attached and ready.
fn check_boot(segment: &str) -> Result<Terminal, String> {
    if !segment.contains(TERMINAL_PROFILE) {
        return Err(format!("no {TERMINAL_PROFILE:?}"));
    }
    if !segment.contains(SETTLED_TERMINAL_DESKTOP) {
        return Err(format!(
            "init has not settled: no {SETTLED_TERMINAL_DESKTOP:?}"
        ));
    }
    let terminal_pid = launched_pid(segment, TERMINAL)?;
    let shell_pid = launched_pid(segment, TERMINAL_SHELL)?;
    let console_pid = launched_pid(segment, CONSOLE)?;
    check_session_grants(segment, shell_pid, terminal_pid, None)?;
    check_attached(segment, terminal_pid)?;
    if !segment.contains(LISTED) {
        return Err(format!("no {LISTED:?}"));
    }
    for (service, pid) in [(TERMINAL, terminal_pid), (TERMINAL_SHELL, shell_pid)] {
        check_audit(segment, service, pid)?;
    }
    baseline_counts(segment)?;
    Ok(Terminal {
        terminal_pid,
        shell_pid,
        console_pid,
    })
}

/// The shell's session record and the terminal's front-end one, on the console port; on
/// `generation` when it is given.
fn check_session_grants(
    segment: &str,
    shell_pid: u64,
    terminal_pid: u64,
    generation: Option<&str>,
) -> Result<(), String> {
    for (pid, rights) in [
        (shell_pid, "connect|session"),
        (terminal_pid, "connect|attach"),
    ] {
        let prefix = format!("[CONS] authority granted pid={pid} port={CONSOLE}:");
        let (_, rest) = whole_line(segment, &prefix).ok_or_else(|| format!("no {prefix:?}"))?;
        if field(&format!(" {rest}"), "rights") != Some(rights) {
            return Err(format!(
                "pid={pid} console grant {rest:?}, expected rights={rights}"
            ));
        }
        if let Some(generation) = generation {
            if rest.split_whitespace().next() != Some(generation) {
                return Err(format!(
                    "pid={pid} console grant {rest:?} does not name the live port {CONSOLE}:{generation}"
                ));
            }
        }
    }
    Ok(())
}

fn check_attached(segment: &str, terminal_pid: u64) -> Result<(), String> {
    for line in ["[TERM] attached", "[TERM] ready text=on"] {
        let want = format!("[IPC ] console pid={terminal_pid}: {line}");
        if !lines(segment).any(|l| l.starts_with(&want)) {
            return Err(format!("no {want:?}"));
        }
    }
    Ok(())
}

fn check_audit(segment: &str, service: u32, pid: u64) -> Result<(), String> {
    let prefix = format!("[SVC ] authority service={service} pid={pid} ");
    let (_, rest) = whole_line(segment, &prefix).ok_or_else(|| format!("no {prefix:?}"))?;
    if !rest.ends_with("matches-manifest=1") {
        return Err(format!("service {service} launch audit {rest:?}"));
    }
    Ok(())
}

/// The hooks build faulted `name`'s live instance `pid`: armed, a user page fault, and the
/// kernel reaped it with no residue.
fn check_faulted(segment: &str, name: &str, service: u32, pid: u64) -> Result<(), String> {
    for want in [
        format!("[HOOK] {name} fault armed pid={pid} "),
        format!("[PROC] fault pid={pid} vector=14 "),
        format!("[SVC ] reaped service={service} pid={pid} residue=0"),
    ] {
        if !segment.contains(&want) {
            return Err(format!("{name} fault: no {want:?}"));
        }
    }
    Ok(())
}

/// `service` launched again under a new pid that passed its launch audit; returns the pid.
fn check_relaunched(segment: &str, service: u32, before: u64) -> Result<u64, String> {
    let pid = launched_pid(segment, service)?;
    if pid == before {
        return Err(format!("service {service} relaunched as its old pid={pid}"));
    }
    check_audit(segment, service, pid)?;
    Ok(pid)
}

/// None of `services` launched in `segment`.
fn check_kept(segment: &str, services: &[u32]) -> Result<(), String> {
    for service in services {
        if let Some((_, rest)) = whole_line(segment, &format!("[SVC ] launch service={service} ")) {
            return Err(format!(
                "service {service} should have kept running but launched {rest:?}"
            ));
        }
    }
    Ok(())
}

/// The hooks build's resource snapshot after `label`'s restart matched the baseline, and init
/// settled with its ten rows after it.
fn check_back_to_baseline(segment: &str, label: &str) -> Result<(), String> {
    let compare = format!("[RSRC] compare after={label} baseline=");
    let (at, outcome) =
        whole_line(segment, &compare).ok_or_else(|| format!("residue: no {compare:?}"))?;
    if outcome != "match" {
        return Err(format!(
            "residue after the {label}: the snapshot does not match the baseline ({outcome})"
        ));
    }
    if !segment[..at].contains(SETTLED_TERMINAL_DESKTOP) {
        return Err(format!(
            "init has not settled again: no {SETTLED_TERMINAL_DESKTOP:?}"
        ));
    }
    Ok(())
}

/// Ctrl-T: the terminal faults, its shell reads the session's hang-up and exits, and both come
/// back under their restart policies with a fresh session; nothing else restarts.
fn check_terminal_fault(segment: &str, before: Terminal) -> Result<Terminal, String> {
    check_faulted(segment, "terminal", TERMINAL, before.terminal_pid)?;
    let hung_up = format!("[LNX ] exit pid={} ", before.shell_pid);
    if !segment.contains(&hung_up) {
        return Err(format!(
            "the terminal's shell pid={} did not exit when its front end went: no {hung_up:?}",
            before.shell_pid
        ));
    }
    let terminal_pid = check_relaunched(segment, TERMINAL, before.terminal_pid)?;
    let shell_pid = check_relaunched(segment, TERMINAL_SHELL, before.shell_pid)?;
    check_session_grants(segment, shell_pid, terminal_pid, None)?;
    check_attached(segment, terminal_pid)?;
    check_kept(
        segment,
        &[COMPOSITOR, DESKTOP_SHELL, APP, CONSOLE, SERIAL_SHELL],
    )?;
    check_back_to_baseline(segment, "terminal-restart")?;
    Ok(Terminal {
        terminal_pid,
        shell_pid,
        ..before
    })
}

/// Ctrl-W: only the terminal's shell restarts; the terminal keeps its pid and its window.
fn check_terminal_shell_fault(segment: &str, before: Terminal) -> Result<Terminal, String> {
    check_faulted(segment, "terminal-shell", TERMINAL_SHELL, before.shell_pid)?;
    let shell_pid = check_relaunched(segment, TERMINAL_SHELL, before.shell_pid)?;
    check_session_grants(segment, shell_pid, before.terminal_pid, None).or_else(|reason| {
        // The terminal's grant is from its launch, before this segment.
        if reason.contains(&format!("pid={}", before.terminal_pid)) {
            Ok(())
        } else {
            Err(reason)
        }
    })?;
    if let Some(line) = lines(segment).find(|line| line.contains(TERMINAL_EXIT)) {
        return Err(format!(
            "the terminal exited at its shell's fault: {line:?}"
        ));
    }
    check_kept(
        segment,
        &[
            COMPOSITOR,
            DESKTOP_SHELL,
            APP,
            CONSOLE,
            SERIAL_SHELL,
            TERMINAL,
        ],
    )?;
    check_back_to_baseline(segment, "terminal-shell-restart")?;
    Ok(Terminal {
        shell_pid,
        ..before
    })
}

/// The hooks build's `[RSRC] baseline` counts, after the five desktop pids.
fn baseline_counts(segment: &str) -> Result<String, String> {
    let (_, rest) =
        whole_line(segment, "[RSRC] baseline ").ok_or("no complete \"[RSRC] baseline\" line")?;
    counts_after_pids(rest)
}

fn counts_after_pids(rest: &str) -> Result<String, String> {
    let (_, counts) = rest
        .split_once(" terminal-shell=")
        .and_then(|(_, rest)| rest.split_once(' '))
        .ok_or_else(|| format!("no terminal pids in the snapshot {rest:?}"))?;
    Ok(counts.to_owned())
}

/// The snapshot after the console service's restart is the baseline less the streams that
/// ended with the old service and are not connected again yet: the serial shell's, which the
/// kernel connects again only at the shell's next write (the lane's serial step then makes
/// one), and the playground's (`app_pid`) unless its `reopened` line came before the snapshot
/// (#368: the kernel's reissue revoked the record its dead connection was made with, which
/// ends that connection, and the playground connects again only when an event wakes it).
/// Every other count must match.
fn check_console_residue(
    segment: &str,
    rows: Terminal,
    app_pid: u64,
    baseline: &str,
) -> Result<(), String> {
    const SNAPSHOT: &str = "[RSRC] snapshot ";
    let wanted_pids = format!(
        " terminal={} terminal-shell={} ",
        rows.terminal_pid, rows.shell_pid
    );
    let complete = segment.rfind('\n').map_or("", |end| &segment[..=end]);
    let (snapshot_at, rest) = complete
        .match_indices(SNAPSHOT)
        .map(|(at, _)| {
            let rest = &complete[at + SNAPSHOT.len()..];
            (at, &rest[..rest.find('\n').unwrap_or(rest.len())])
        })
        .find(|(_, rest)| rest.contains(&wanted_pids))
        .ok_or_else(|| format!("residue: no snapshot with{wanted_pids}"))?;
    let reopened = format!("[CON ] pid={app_pid}: {APP_CONSOLE_REOPENED}");
    let app_back = complete[..snapshot_at].contains(&reopened);
    let ended: u64 = if app_back { 1 } else { 2 };
    let counts = counts_after_pids(rest)?;
    let fields = |text: &str| -> Vec<(String, String)> {
        text.split_whitespace()
            .filter_map(|token| token.split_once('='))
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect()
    };
    let (now, then) = (fields(&counts), fields(baseline));
    if now.len() != then.len() {
        return Err(format!(
            "residue: snapshot {counts:?}, baseline {baseline:?}"
        ));
    }
    for ((key, value), (base_key, base_value)) in now.iter().zip(&then) {
        let want = if key == "conns" {
            base_value
                .parse::<u64>()
                .ok()
                .and_then(|conns| conns.checked_sub(ended))
                .map(|conns| conns.to_string())
        } else {
            Some(base_value.clone())
        };
        if key != base_key || Some(value) != want.as_ref() {
            return Err(format!(
                "residue after the console restart: {key}={value}, expected {base_key}={} (baseline {baseline:?}, less {ended} stream(s) not yet connected again: the serial shell's{})",
                want.unwrap_or_default(),
                if app_back { "" } else { " and the playground's" }
            ));
        }
    }
    Ok(())
}

/// Ctrl-X with the terminal attached: the console service restarts; the terminal exits
/// `console-gone` and its shell hangs up instead of reading the serial line; both come back
/// once the new service is ready, holding records on its port.
fn check_console_fault(
    segment: &str,
    before: Terminal,
    app_pid: u64,
    baseline: &str,
) -> Result<Terminal, String> {
    check_faulted(segment, "console", CONSOLE, before.console_pid)?;
    let exit = format!(
        "[IPC ] console pid={}: [TERM] exit reason=console-gone",
        before.terminal_pid
    );
    if !segment.contains(&exit) {
        return Err(format!(
            "the terminal did not exit console-gone: no {exit:?}"
        ));
    }
    let reaped = format!(
        "[SVC ] reaped service={TERMINAL} pid={} residue=0",
        before.terminal_pid
    );
    if !segment.contains(&reaped) {
        return Err(format!("no {reaped:?}"));
    }
    let hung_up = format!("[LNX ] exit pid={} ", before.shell_pid);
    if !segment.contains(&hung_up) {
        return Err(format!(
            "the terminal's shell pid={} did not hang up when the console service went: no {hung_up:?}",
            before.shell_pid
        ));
    }
    let console_pid = check_relaunched(segment, CONSOLE, before.console_pid)?;
    let serve = format!("[CONS] authority granted pid={console_pid} port={CONSOLE}:");
    let (_, rest) = whole_line(segment, &serve).ok_or_else(|| format!("no {serve:?}"))?;
    let generation = rest
        .split_whitespace()
        .next()
        .ok_or_else(|| format!("console port grant {rest:?}"))?
        .to_owned();
    let ready = segment
        .find(&format!(
            "[SVC ] ready service={CONSOLE} pid={console_pid} "
        ))
        .ok_or_else(|| format!("the new console service pid={console_pid} is not ready"))?;
    let terminal_pid = check_relaunched(segment, TERMINAL, before.terminal_pid)?;
    let shell_pid = check_relaunched(segment, TERMINAL_SHELL, before.shell_pid)?;
    for (service, pid) in [(TERMINAL, terminal_pid), (TERMINAL_SHELL, shell_pid)] {
        let launch = format!("[SVC ] launch service={service} pid={pid} ");
        if segment.find(&launch).is_none_or(|at| at < ready) {
            return Err(format!(
                "order: service {service} launched before the new console service was ready"
            ));
        }
    }
    check_session_grants(segment, shell_pid, terminal_pid, Some(&generation))?;
    check_attached(segment, terminal_pid)?;
    check_kept(segment, &[COMPOSITOR, DESKTOP_SHELL, APP, SERIAL_SHELL])?;
    let rows = Terminal {
        terminal_pid,
        shell_pid,
        console_pid,
    };
    check_console_residue(segment, rows, app_pid, baseline)?;
    let settled = segment
        .rfind(SETTLED_TERMINAL_DESKTOP)
        .ok_or_else(|| format!("init has not settled again: no {SETTLED_TERMINAL_DESKTOP:?}"))?;
    if segment
        .find(&format!(
            "[SVC ] ready service={TERMINAL} pid={terminal_pid} "
        ))
        .is_none_or(|at| at > settled)
    {
        return Err(format!(
            "init has not settled again after the terminal pid={terminal_pid} was ready"
        ));
    }
    Ok(rows)
}

/// What the playground writes once it has connected its console stream again (#368).
const APP_CONSOLE_REOPENED: &str = "playground: console stream reopened";

/// Since the console fault: the kernel reissued the playground's console record on the new
/// service's port (named by its grant line), and then the playground, from its unchanged
/// pid, wrote a line through a stream on that service, on a line of its own.
fn check_app_console_reopened(segment: &str, app_pid: u64, console_pid: u64) -> Result<(), String> {
    let serve = format!("[CONS] authority granted pid={console_pid} port={CONSOLE}:");
    let (granted_at, rest) = whole_line(segment, &serve).ok_or_else(|| format!("no {serve:?}"))?;
    let generation = rest
        .split_whitespace()
        .next()
        .ok_or_else(|| format!("console port grant {rest:?}"))?;
    let reissued = format!("[CONS] client reissued holder={app_pid} port={CONSOLE}:{generation}\n");
    let reissued_at = segment.find(&reissued).ok_or_else(|| {
        format!("the playground's console record was not reissued: no {reissued:?}")
    })?;
    if reissued_at < granted_at {
        return Err("the playground's console record was reissued before the new port".to_owned());
    }
    let line = format!("[CON ] pid={app_pid}: {APP_CONSOLE_REOPENED}");
    let written_at = segment
        .match_indices(&line)
        .map(|(at, _)| at)
        .find(|&at| {
            (at == 0 || segment[..at].ends_with('\n'))
                && segment[at + line.len()..].starts_with(['\n', '\r'])
        })
        .ok_or_else(|| format!("no line {line:?} from the playground's console stream"))?;
    if written_at < reissued_at {
        return Err("the playground wrote before its record was reissued".to_owned());
    }
    Ok(())
}

/// Where the compositor last put a new window's content, from its `[WIN ] created` line.
fn created_origin(segment: &str) -> Option<Point> {
    let complete = segment.rfind('\n').map_or("", |end| &segment[..=end]);
    lines(complete)
        .filter_map(|line| line.find("[WIN ] created ").map(|at| &line[at..]))
        .filter_map(|line| {
            Some(Point {
                x: number(line, "x").ok()? as i32,
                y: number(line, "y").ok()? as i32,
            })
        })
        .last()
}

/// `[SVC ] launch` lines per row, as [`LAUNCHES`] wants them, and the one terminal exit.
fn check_whole(transcript: &str) -> Result<(), String> {
    for (service, want) in LAUNCHES {
        let prefix = format!("[SVC ] launch service={service} ");
        let count = lines(transcript)
            .filter(|line| line.contains(&prefix))
            .count();
        if count != want {
            return Err(format!(
                "service {service} launched {count} times, expected {want}"
            ));
        }
    }
    let exits: Vec<&str> = lines(transcript)
        .filter(|line| line.contains(TERMINAL_EXIT))
        .collect();
    if exits.len() != 1 || !exits[0].ends_with("[TERM] exit reason=console-gone") {
        return Err(format!(
            "expected one terminal exit, console-gone at the console fault: {exits:?}"
        ));
    }
    Ok(())
}

/// The answer to `echo hello-$$` typed into the terminal: `hello-<pid>` on a `[CON ]` line,
/// through the session and logged on serial, with the pid of the terminal's shell, which
/// expanded `$$` (the `echo` child that prints it is not named: the kernel logs only the first
/// few Linux pids).
fn answered(segment: &str, shell_pid: u64) -> Result<(), String> {
    answered_with(segment, &format!("{ANSWER}{shell_pid}")).map_err(|reason| {
        format!("{reason}: the terminal's shell pid={shell_pid} has not answered")
    })
}

/// `answer` on a `[CON ]` line, alone or after the prompt.
fn answered_with(segment: &str, answer: &str) -> Result<(), String> {
    let found = lines(segment)
        .filter_map(|line| line.find("[CON ] pid=").map(|at| &line[at..]))
        .filter_map(|rest| rest.split_once(": ").map(|(_, text)| text.trim_end()))
        .any(|text| text == answer || text.ends_with(&format!(" {answer}")));
    if found {
        Ok(())
    } else {
        Err(format!("no [CON ] {answer:?} line"))
    }
}

/// The shell's `[SHELL] rail switch=<name> window=<n>` line, with a nonzero handle.
fn switched(segment: &str, name: &str) -> Result<(), String> {
    let prefix = format!("[SHELL] rail switch={name} ");
    let (_, rest) = whole_line(segment, &prefix).ok_or_else(|| format!("no {prefix:?}"))?;
    match number(&format!(" {rest}"), "window") {
        Ok(handle) if handle != 0 => Ok(()),
        _ => Err(format!("rail switch to {name} names no window: {rest:?}")),
    }
}

fn last_settled(segment: &str) -> Option<Point> {
    let complete = segment.rfind('\n').map_or("", |end| &segment[..=end]);
    lines(complete)
        .filter_map(|line| line.find(SETTLED).map(|at| &line[at..]))
        .filter_map(|line| {
            Some(Point {
                x: number(line, "x").ok()? as i32,
                y: number(line, "y").ok()? as i32,
            })
        })
        .last()
}

struct Lane {
    session: Session,
    pointer: Point,
}

impl Lane {
    /// Moves the pointer to `target` in batches, each waited on until the compositor reports
    /// it settled where the batch should have left it. A batch that settles elsewhere is
    /// corrected from where the guest says it is.
    fn move_to(&mut self, target: Point) -> Result<(), XtaskError> {
        for _ in 0..4 {
            let delta = Point {
                x: target.x - self.pointer.x,
                y: target.y - self.pointer.y,
            };
            if delta == (Point { x: 0, y: 0 }) {
                return Ok(());
            }
            let mut expected = self.pointer;
            let mut off_course = false;
            for batch in motion_chunks(delta).chunks(PACKETS_PER_BATCH) {
                self.session.mark();
                for chunk in batch {
                    self.session
                        .input("move", &InputAction::move_rel(chunk.x, chunk.y))?;
                    expected = Point {
                        x: expected.x + chunk.x,
                        y: expected.y + chunk.y,
                    };
                }
                let polled =
                    self.session.poll(
                        "pointer",
                        SETTLE_WAIT,
                        &mut |segment| match last_settled(segment) {
                            Some(at) if at == expected => Ok(()),
                            _ => Err("not settled".to_owned()),
                        },
                    )?;
                match polled {
                    Ok(()) => self.pointer = expected,
                    Err(_) => {
                        let Some(at) = last_settled(&self.session.segment()) else {
                            return self.session.fail(format!(
                                "focus: the guest never reported the pointer settled on its way to x={} y={}",
                                target.x, target.y
                            ));
                        };
                        self.pointer = at;
                        off_course = true;
                        break;
                    }
                }
            }
            if !off_course && self.pointer == target {
                return Ok(());
            }
        }
        self.session.fail(format!(
            "focus: the pointer did not settle at x={} y={}; it is at x={} y={}",
            target.x, target.y, self.pointer.x, self.pointer.y
        ))
    }

    fn button(&mut self, down: bool, hit: &str) -> Result<(), XtaskError> {
        let edge = if down { "down" } else { "up" };
        self.session.mark();
        self.session.input(
            "click",
            &[InputAction::Button {
                button: MouseButton::Left,
                down,
            }],
        )?;
        let prefix = format!("[INPT] button left {edge} ");
        let rest = self.session.wait("click", EDGE_WAIT, &mut |segment| {
            whole_line(segment, &prefix)
                .map(|(_, rest)| format!(" {rest}"))
                .ok_or_else(|| format!("no {prefix:?}"))
        })?;
        if field(&rest, "hit") != Some(hit) {
            return self.session.fail(format!(
                "the click landed on {:?}, expected hit={hit}: {rest:?}",
                field(&rest, "hit")
            ));
        }
        Ok(())
    }

    /// Clicks rail slot `slot` and requires the shell's switch to the `name` window.
    fn rail_switch(&mut self, slot: usize, name: &str) -> Result<(), XtaskError> {
        let Some(item) = rail_item(QualityTier::Q1, slot) else {
            return self.session.fail(format!("the rail has no slot {slot}"));
        };
        self.move_to(center(item))?;
        self.session.mark();
        let mark = self.session.offset();
        self.button(true, "surface")?;
        self.button(false, "surface")?;
        self.session.mark_at(mark);
        self.session
            .wait("rail switch", STEP_TIMEOUT, &mut |segment| {
                switched(segment, name)
            })?;
        Ok(())
    }

    /// Sleeps `wait` on the guest's output without expecting anything.
    fn pace(&mut self, wait: Duration) -> Result<(), XtaskError> {
        let _ = self
            .session
            .poll("pace", wait, &mut |_| Err::<(), _>(String::new()))?;
        Ok(())
    }

    /// Where the compositor put the window created since the step's byte was typed.
    fn created_origin(&self, step: &str) -> Result<Point, XtaskError> {
        match created_origin(&self.session.segment()) {
            Some(origin) => Ok(origin),
            None => self
                .session
                .fail(format!("{step}: the compositor logged no new window")),
        }
    }

    /// Focuses the terminal whose content starts at `origin` with a click on the part the
    /// playground does not cover, types `echo hello`, and requires the answer from `shell_pid`
    /// (or a process it forked) through the console session, and the window to change on
    /// screen. Screendumps are named after `name`.
    fn type_in_terminal(
        &mut self,
        origin: Point,
        shell_pid: u64,
        name: &str,
    ) -> Result<(), XtaskError> {
        self.type_in_terminal_into(origin, shell_pid, name, ARTIFACTS)
    }

    /// [`Self::type_in_terminal`] with its screendumps under `artifacts`.
    fn type_in_terminal_into(
        &mut self,
        origin: Point,
        shell_pid: u64,
        name: &str,
        artifacts: &str,
    ) -> Result<(), XtaskError> {
        let content = terminal_content(origin);
        // A window that maps while another has focus opens behind it (no focus stealing), so
        // the click goes to the terminal's right-hand part, clear of the playground's window.
        self.move_to(focus_target(content))?;
        self.button(true, "content")?;
        self.button(false, "content")?;
        self.pace(Duration::from_millis(500))?;
        let before = self.screendump_into(artifacts, &format!("before-{name}"))?;
        self.session.mark();
        let mark = self.session.offset();
        for (key, shifted) in TYPED {
            self.session.input("type", &key_actions(key, shifted))?;
            self.pace(KEY_PACE)?;
        }
        self.session.mark_at(mark);
        self.session
            .wait("the shell's answer", STEP_TIMEOUT, &mut |segment| {
                answered(segment, shell_pid)
            })?;
        self.pace(Duration::from_millis(500))?;
        let after = self.screendump_into(artifacts, &format!("after-{name}"))?;
        if !region_changed(&before, &after, content, &[cursor(self.pointer)]) {
            return self.session.fail(format!(
                "{name}: the terminal's window did not change after the shell answered"
            ));
        }
        Ok(())
    }

    /// COM1 reaches the serial shell: `$$` is expanded by the shell that read the line, so the
    /// answer names the serial shell's pid and not a session member's.
    fn serial_shell(&mut self, serial_shell: u64) -> Result<(), XtaskError> {
        self.session.type_serial(b"echo serial-$$\r")?;
        let answer = format!("serial-{serial_shell}");
        self.session
            .wait("serial shell", STEP_TIMEOUT, &mut |segment| {
                answered_with(segment, &answer)
            })?;
        Ok(())
    }

    fn screendump_into(&mut self, artifacts: &str, name: &str) -> Result<Screenshot, XtaskError> {
        let dir = xtask_artifact_root().join(artifacts);
        std::fs::create_dir_all(&dir)?;
        self.session
            .screendump(name, &dir.join(format!("{name}.ppm")))
    }
}

/// The terminal window's content rectangle at `origin`.
fn terminal_content(origin: Point) -> Rect {
    let Size { width, height } = clean_slate_terminal::render::WINDOW_SIZE;
    Rect {
        x: origin.x,
        y: origin.y,
        width,
        height,
    }
}

/// A point in the terminal's content that the playground's window does not cover.
fn focus_target(content: Rect) -> Point {
    Point {
        x: content.x + content.width as i32 - 80,
        y: center(content).y,
    }
}

fn config(disk: &std::path::Path, fixture_port: u16) -> VmLaunchConfig {
    VmLaunchConfig {
        machine_extra: Some("vmport=off"),
        extra_args: desktop_qemu_args_with(false, true),
        ..system_vm_config(disk.to_path_buf(), Some(fixture_port))
    }
}

fn run_on(disk: &std::path::Path, fixture_port: u16) -> Result<(), XtaskError> {
    let session = Session::start(
        &[HOOKS_FEATURE],
        config(disk, fixture_port),
        true,
        &FORBIDDEN,
        LANE_TIMEOUT,
        SERIAL_LOG,
    )?;
    let mut lane = Lane {
        session,
        pointer: START,
    };
    println!("[STT ] step: boot");
    let mut rows = lane
        .session
        .wait("boot", STEP_TIMEOUT * 3, &mut check_boot)?;
    let (serial_shell, app_pid, baseline) = {
        let segment = lane.session.segment();
        match launched_pid(&segment, SERIAL_SHELL).and_then(|pid| {
            Ok((
                pid,
                launched_pid(&segment, APP)?,
                baseline_counts(&segment)?,
            ))
        }) {
            Ok(found) => found,
            Err(reason) => return lane.session.fail(reason),
        }
    };
    println!(
        "\n[STT ] terminal pid={} attached; its shell pid={}",
        rows.terminal_pid, rows.shell_pid
    );

    println!("\n[STT ] step: focus and type `echo hello`");
    let mut origin = sized_window_origin(
        QualityTier::Q1,
        clean_slate_terminal::render::WINDOW_SIZE,
        1,
    );
    lane.type_in_terminal(origin, rows.shell_pid, "typing")?;

    println!("\n[STT ] step: serial shell");
    lane.serial_shell(serial_shell)?;

    println!("\n[STT ] step: rail");
    for (slot, name) in RAIL {
        lane.rail_switch(slot, name)?;
        println!("\n[STT ] rail slot {slot} focused the {name} window");
    }

    let transcript = lane.session.transcript();
    if let Some(line) = lines(&transcript)
        .find(|line| line.contains("[SUP ] restart service=") || line.contains(TERMINAL_EXIT))
    {
        return lane
            .session
            .fail(format!("a row went before the fault steps: {line:?}"));
    }

    println!("\n[STT ] step: terminal fault");
    let before = rows;
    lane.session.type_serial(TERMINAL_FAULT)?;
    rows = lane
        .session
        .wait("terminal fault", STEP_TIMEOUT, &mut |segment| {
            check_terminal_fault(segment, before)
        })?;
    origin = lane.created_origin("terminal fault")?;
    println!(
        "\n[STT ] terminal fault: terminal pid={} and shell pid={} relaunched as pid={} and pid={}",
        before.terminal_pid, before.shell_pid, rows.terminal_pid, rows.shell_pid
    );
    lane.type_in_terminal(origin, rows.shell_pid, "terminal-fault")?;

    println!("\n[STT ] step: terminal shell fault");
    let before = rows;
    lane.session.type_serial(TERMINAL_SHELL_FAULT)?;
    rows = lane
        .session
        .wait("terminal shell fault", STEP_TIMEOUT, &mut |segment| {
            check_terminal_shell_fault(segment, before)
        })?;
    println!(
        "\n[STT ] terminal shell fault: shell pid={} relaunched as pid={}; terminal pid={} kept",
        before.shell_pid, rows.shell_pid, rows.terminal_pid
    );
    lane.type_in_terminal(origin, rows.shell_pid, "shell-fault")?;

    println!("\n[STT ] step: console fault with the terminal attached");
    let before = rows;
    lane.session.mark();
    let console_fault_at = lane.session.offset();
    lane.session.type_serial(CONSOLE_FAULT)?;
    rows = lane
        .session
        .wait("console fault", STEP_TIMEOUT, &mut |segment| {
            check_console_fault(segment, before, app_pid, &baseline)
        })?;
    origin = lane.created_origin("console fault")?;
    println!(
        "\n[STT ] console fault: console pid={} relaunched as pid={}, terminal pid={} and its shell pid={} on its port",
        before.console_pid, rows.console_pid, rows.terminal_pid, rows.shell_pid
    );
    lane.type_in_terminal(origin, rows.shell_pid, "console-fault")?;
    lane.serial_shell(serial_shell)?;

    println!("\n[STT ] step: playground console stream after the console restart");
    // The click wakes the playground; it may have connected again already, on an earlier
    // event, so the check reads everything since the fault.
    lane.rail_switch(RAIL[0].0, RAIL[0].1)?;
    lane.session.mark_at(console_fault_at);
    lane.session
        .wait("playground console stream", STEP_TIMEOUT, &mut |segment| {
            check_app_console_reopened(segment, app_pid, rows.console_pid)
        })?;
    println!(
        "\n[STT ] playground pid={app_pid} wrote through console pid={}",
        rows.console_pid
    );

    let transcript = lane.session.transcript();
    if let Err(reason) = check_whole(&transcript) {
        return lane.session.fail(format!("whole transcript: {reason}"));
    }
    lane.session.finish()?;
    Ok(())
}

/// `cargo xtask test-system-terminal`, on a fresh lane-owned disk.
pub(crate) fn run() -> Result<(), XtaskError> {
    let disk = workspace_root()
        .join("target")
        .join(ARTIFACTS)
        .join("data.img");
    if disk.is_file() {
        std::fs::remove_file(&disk)?;
    }
    ensure_data_disk(&disk)?;
    let peer = start_shell_fixture_peer()?;
    let result = run_on(&disk, peer.port());
    peer.shutdown();
    result?;
    println!("[STT ] test-system-terminal PASS");
    Ok(())
}

// `cargo xtask test-system-native-shell` (#388): the same terminal on the same desktop, with the
// native shell in the terminal's shell row (`opt/clean-slate/desktop=q1-native-shell`).
//
// 1. **Boot**: init says the profile, settles with its ten rows, the native shell holds a console
//    session record and passed its launch audit, reports ready, and the terminal attaches.
// 2. **Type**: `echo hello-$$` comes back from the native shell, which expanded `$$` to its pid.
// 3. **Ctrl-D** on an empty line ends the shell's input: it logs `end-of-input`, the kernel
//    reaps it, and init starts a new one under its restart policy while the terminal keeps its
//    pid and window.
// 4. **Type again**: the new shell answers `echo hello-$$` with its own pid.

const NATIVE_ARTIFACTS: &str = "system-native-shell";
const NATIVE_SERIAL_LOG: &str = "system-native-shell/serial.log";
const NATIVE_PROFILE: &str = "[INIT] boot profile=desktop tier=Q1 terminal=on shell=native";
const NATIVE_READY: &str = "[NSH ] ready";
/// Ctrl-D: on an empty line the terminal ends the session's input.
const CTRL_D: [InputAction; 4] = [
    InputAction::Key {
        qcode: QCode::CTRL,
        down: true,
    },
    InputAction::Key {
        qcode: QCode::D,
        down: true,
    },
    InputAction::Key {
        qcode: QCode::D,
        down: false,
    },
    InputAction::Key {
        qcode: QCode::CTRL,
        down: false,
    },
];
/// `[SVC ] launch` lines per row over the run: the shell twice, every other row once.
const NATIVE_LAUNCHES: [(u32, usize); 7] = [
    (COMPOSITOR, 1),
    (DESKTOP_SHELL, 1),
    (APP, 1),
    (SERIAL_SHELL, 1),
    (CONSOLE, 1),
    (TERMINAL, 1),
    (TERMINAL_SHELL, 2),
];

/// `pid` wrote `line` on its console line.
fn logged(segment: &str, pid: u64, line: &str) -> Result<(), String> {
    let want = format!("[IPC ] console pid={pid}: {line}");
    if lines(segment).any(|l| l.starts_with(&want)) {
        Ok(())
    } else {
        Err(format!("no {want:?}"))
    }
}

/// The native shell's boot: the profile, ten rows settled, the shell's session record and
/// clean launch audit, its ready line, and the terminal attached.
fn check_native_boot(segment: &str) -> Result<Terminal, String> {
    if !segment.contains(NATIVE_PROFILE) {
        return Err(format!("no {NATIVE_PROFILE:?}"));
    }
    if !segment.contains("[KERN] boot option shell=native") {
        return Err("the kernel did not read shell=native from the boot option".to_owned());
    }
    if !segment.contains(SETTLED_TERMINAL_DESKTOP) {
        return Err(format!(
            "init has not settled: no {SETTLED_TERMINAL_DESKTOP:?}"
        ));
    }
    let terminal_pid = launched_pid(segment, TERMINAL)?;
    let shell_pid = launched_pid(segment, TERMINAL_SHELL)?;
    let console_pid = launched_pid(segment, CONSOLE)?;
    check_session_grants(segment, shell_pid, terminal_pid, None)?;
    check_attached(segment, terminal_pid)?;
    for (service, pid) in [(TERMINAL, terminal_pid), (TERMINAL_SHELL, shell_pid)] {
        check_audit(segment, service, pid)?;
    }
    logged(segment, shell_pid, &format!("[NSH ] start pid={shell_pid}"))?;
    logged(segment, shell_pid, NATIVE_READY)?;
    Ok(Terminal {
        terminal_pid,
        shell_pid,
        console_pid,
    })
}

/// Ctrl-D: the shell logged the end of its input and was reaped clean; a new shell with a
/// session record of its own is ready; the terminal and every other row kept running.
fn check_end_of_input(segment: &str, before: Terminal) -> Result<Terminal, String> {
    logged(
        segment,
        before.shell_pid,
        "[NSH ] exit reason=end-of-input status=0",
    )?;
    let reaped = format!(
        "[SVC ] reaped service={TERMINAL_SHELL} pid={} residue=0",
        before.shell_pid
    );
    if !segment.contains(&reaped) {
        return Err(format!("no {reaped:?}"));
    }
    let shell_pid = check_relaunched(segment, TERMINAL_SHELL, before.shell_pid)?;
    let prefix = format!("[CONS] authority granted pid={shell_pid} port={CONSOLE}:");
    let (_, rest) = whole_line(segment, &prefix).ok_or_else(|| format!("no {prefix:?}"))?;
    if field(&format!(" {rest}"), "rights") != Some("connect|session") {
        return Err(format!("the new shell's console grant {rest:?}"));
    }
    logged(segment, shell_pid, NATIVE_READY)?;
    if let Some(line) = lines(segment).find(|line| line.contains(TERMINAL_EXIT)) {
        return Err(format!("the terminal exited with its shell: {line:?}"));
    }
    check_kept(
        segment,
        &[
            COMPOSITOR,
            DESKTOP_SHELL,
            APP,
            CONSOLE,
            SERIAL_SHELL,
            TERMINAL,
        ],
    )?;
    Ok(Terminal {
        shell_pid,
        ..before
    })
}

fn check_native_whole(transcript: &str) -> Result<(), String> {
    for (service, want) in NATIVE_LAUNCHES {
        let prefix = format!("[SVC ] launch service={service} ");
        let count = lines(transcript)
            .filter(|line| line.contains(&prefix))
            .count();
        if count != want {
            return Err(format!(
                "service {service} launched {count} times, expected {want}"
            ));
        }
    }
    if let Some(line) = lines(transcript).find(|line| line.contains(TERMINAL_EXIT)) {
        return Err(format!("the terminal exited: {line:?}"));
    }
    Ok(())
}

fn native_config(disk: &std::path::Path, fixture_port: u16) -> VmLaunchConfig {
    VmLaunchConfig {
        machine_extra: Some("vmport=off"),
        extra_args: desktop_qemu_args_for(false, DesktopProfile::NativeShell),
        ..system_vm_config(disk.to_path_buf(), Some(fixture_port))
    }
}

fn run_native_on(disk: &std::path::Path, fixture_port: u16) -> Result<(), XtaskError> {
    let session = Session::start(
        &[HOOKS_FEATURE],
        native_config(disk, fixture_port),
        true,
        &FORBIDDEN,
        LANE_TIMEOUT,
        NATIVE_SERIAL_LOG,
    )?;
    let mut lane = Lane {
        session,
        pointer: START,
    };
    println!("[STT ] step: boot with the native shell");
    let rows = lane
        .session
        .wait("boot", STEP_TIMEOUT * 3, &mut check_native_boot)?;
    println!(
        "\n[STT ] terminal pid={} attached; its native shell pid={}",
        rows.terminal_pid, rows.shell_pid
    );

    println!("\n[STT ] step: focus and type `echo hello-$$`");
    let origin = sized_window_origin(
        QualityTier::Q1,
        clean_slate_terminal::render::WINDOW_SIZE,
        1,
    );
    lane.type_in_terminal_into(origin, rows.shell_pid, "typing", NATIVE_ARTIFACTS)?;

    println!("\n[STT ] step: Ctrl-D on an empty line");
    let before = rows;
    lane.session.mark();
    lane.session.input("ctrl-d", &CTRL_D)?;
    let rows = lane
        .session
        .wait("end of input", STEP_TIMEOUT, &mut |segment| {
            check_end_of_input(segment, before)
        })?;
    println!(
        "\n[STT ] native shell pid={} ended at Ctrl-D; init started pid={}; terminal pid={} kept",
        before.shell_pid, rows.shell_pid, rows.terminal_pid
    );
    lane.type_in_terminal_into(origin, rows.shell_pid, "after-ctrl-d", NATIVE_ARTIFACTS)?;

    let transcript = lane.session.transcript();
    if let Err(reason) = check_native_whole(&transcript) {
        return lane.session.fail(format!("whole transcript: {reason}"));
    }
    lane.session.finish()?;
    Ok(())
}

/// `cargo xtask test-system-native-shell`, on a fresh lane-owned disk.
pub(crate) fn run_native_shell() -> Result<(), XtaskError> {
    let disk = workspace_root()
        .join("target")
        .join(NATIVE_ARTIFACTS)
        .join("data.img");
    if disk.is_file() {
        std::fs::remove_file(&disk)?;
    }
    ensure_data_disk(&disk)?;
    let peer = start_shell_fixture_peer()?;
    let result = run_native_on(&disk, peer.port());
    peer.shutdown();
    result?;
    println!("[STT ] test-system-native-shell PASS");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot() -> String {
        "[IPC ] console pid=1: [INIT] boot profile=desktop tier=Q1 terminal=on\n\
         [SVC ] launch service=22016 pid=3 gen=1\n\
         [CONS] authority granted pid=9 port=22016:3 rights=connect|session\n\
         [SVC ] authority service=21505 pid=9 counts matches-manifest=1\n\
         [SVC ] launch service=21505 pid=9 gen=1\n\
         [CONS] authority granted pid=10 port=22016:3 rights=connect|attach\n\
         [SVC ] authority service=21251 pid=10 counts matches-manifest=1\n\
         [SVC ] launch service=21251 pid=10 gen=1\n\
         [IPC ] console pid=10: [TERM] attached as the console session front end\n\
         [IPC ] console pid=10: [TERM] ready text=on\n\
         [IPC ] console pid=7: [SHELL] launcher listed=2\n\
         [IPC ] console pid=1: [INIT] boot settled running=10 down=0; waiting, no deadline\n\
         [RSRC] baseline compositor=4 desktop-shell=7 app=8 terminal=10 terminal-shell=9 procs=11 conns=8\n"
            .to_owned()
    }

    #[test]
    fn a_good_terminal_boot_names_both_pids() {
        assert_eq!(
            check_boot(&boot()),
            Ok(Terminal {
                terminal_pid: 10,
                shell_pid: 9,
                console_pid: 3,
            })
        );
    }

    #[test]
    fn a_shell_without_its_session_right_fails_by_pid() {
        let text = boot().replace("rights=connect|session", "rights=connect");
        let error = check_boot(&text).unwrap_err();
        assert!(error.contains("pid=9"), "{error}");
        let text = boot().replace("[TERM] ready", "[TERM] waiting");
        assert!(check_boot(&text).unwrap_err().contains("[TERM] ready"));
        let text = boot().replace("ready text=on", "ready text=off");
        assert!(check_boot(&text).unwrap_err().contains("text=on"));
        let text = boot().replace("listed=2", "listed=1");
        assert!(check_boot(&text).unwrap_err().contains(LISTED));
    }

    #[test]
    fn a_rail_switch_must_name_the_app_and_a_window() {
        let line = "[IPC ] console pid=7: [SHELL] rail switch=playground window=1\n";
        assert!(switched(line, "playground").is_ok());
        assert!(switched(line, "terminal").is_err());
        let zero = "[IPC ] console pid=7: [SHELL] rail switch=terminal window=0\n";
        assert!(switched(zero, "terminal").is_err());
        assert!(
            switched("[SHELL] rail switch=terminal window=2", "terminal").is_err(),
            "no newline yet"
        );
    }

    #[test]
    fn the_rail_slots_are_inside_the_rail() {
        use clean_slate_ui::layout::RectExt;
        let rail = crate::m10_desktop_visual::rail(QualityTier::Q1);
        for (slot, _) in RAIL {
            let item = rail_item(QualityTier::Q1, slot).unwrap();
            assert!(rail.contains(center(item)), "slot {slot}");
        }
    }

    #[test]
    fn the_answer_must_name_the_terminal_shell() {
        assert!(answered("[CON ] pid=9: hello-9\n", 9).is_ok());
        assert!(answered("[CON ] pid=12: ~ # hello-9\n", 9).is_ok());
        assert!(answered("[CON ] pid=9: hello-8\n", 9).is_err());
        assert!(answered("[CON ] pid=9: hello-99\n", 9).is_err());
        assert!(
            answered("[CON ] pid=9: ~ # echo hello-$$\n", 9).is_err(),
            "the echoed command line is not the answer"
        );
    }

    #[test]
    fn the_typed_keys_spell_echo_hello_pid() {
        let names: String = TYPED[..13]
            .iter()
            .map(|(key, shifted)| match (key.name(), shifted) {
                ("spc", _) => ' ',
                ("minus", _) => '-',
                ("4", true) => '$',
                (name, _) => name.chars().next().unwrap(),
            })
            .collect();
        assert_eq!(names, "echo hello-$$");
        assert_eq!(TYPED[13], (QCode::RET, false));
        assert_eq!(key_actions(QCode::N4, true).len(), 4);
    }

    #[test]
    fn the_console_residue_is_the_baseline_less_the_streams_not_back_yet() {
        let rows = Terminal {
            terminal_pid: 21,
            shell_pid: 20,
            console_pid: 19,
        };
        const APP_PID: u64 = 10;
        let baseline = "procs=11 caps=55 conns=8 qreq=0";
        let snapshot = |counts: &str| {
            format!("[RSRC] snapshot compositor=4 desktop-shell=9 app=10 terminal=21 terminal-shell=20 {counts}\n")
        };
        let reopened = "[CON ] pid=10: playground: console stream reopened\n";
        let check = |segment: &str| check_console_residue(segment, rows, APP_PID, baseline);
        // The playground not yet woken: its stream and the serial shell's are both gone.
        assert_eq!(check(&snapshot("procs=11 caps=55 conns=6 qreq=0")), Ok(()));
        assert!(check(&snapshot("procs=11 caps=55 conns=7 qreq=0")).is_err());
        // The playground connected again before the snapshot: only the serial shell's.
        let back = |counts: &str| format!("{reopened}{}", snapshot(counts));
        assert_eq!(check(&back("procs=11 caps=55 conns=7 qreq=0")), Ok(()));
        assert!(check(&back("procs=11 caps=55 conns=6 qreq=0")).is_err());
        // A reopened line after the snapshot does not count.
        let late = format!("{}{reopened}", snapshot("procs=11 caps=55 conns=7 qreq=0"));
        assert!(check(&late).is_err());
        let other_app = back("procs=11 caps=55 conns=7 qreq=0").replace("pid=10:", "pid=11:");
        assert!(check(&other_app).is_err());
        assert!(check(&snapshot("procs=11 caps=56 conns=6 qreq=0"))
            .unwrap_err()
            .contains("caps=56"));
        let other =
            snapshot("procs=11 caps=55 conns=6 qreq=0").replace("terminal=21", "terminal=15");
        assert!(check(&other).is_err());
        assert_eq!(
            baseline_counts("[RSRC] baseline compositor=4 desktop-shell=9 app=10 terminal=11 terminal-shell=8 procs=11 conns=8\n"),
            Ok("procs=11 conns=8".to_owned())
        );
    }

    #[test]
    fn the_playground_writes_through_the_new_console_after_its_reissue() {
        let good = "[CONS] authority granted pid=30 port=22016:31 rights=serve registered=1 device=read|write\n\
                    [CONS] client reissued holder=10 port=22016:31\n\
                    [CON ] pid=10: playground: console stream reopened\n";
        assert_eq!(check_app_console_reopened(good, 10, 30), Ok(()));
        for (from, to) in [
            ("holder=10 port=22016:31", "holder=10 port=22016:5"),
            ("holder=10", "holder=11"),
            ("pid=10: playground", "pid=11: playground"),
            ("reopened", "open"),
            ("granted pid=30", "granted pid=29"),
        ] {
            let bad = good.replace(from, to);
            assert!(
                check_app_console_reopened(&bad, 10, 30).is_err(),
                "{from:?}"
            );
        }
        // The line must be one of its own, and come after the reissue.
        let glued = good.replace("[CON ] pid=10", "x[CON ] pid=10");
        assert!(check_app_console_reopened(&glued, 10, 30).is_err());
        let early = "[CON ] pid=10: playground: console stream reopened\n\
                     [CONS] authority granted pid=30 port=22016:31 rights=serve\n\
                     [CONS] client reissued holder=10 port=22016:31\n";
        assert!(check_app_console_reopened(early, 10, 30).is_err());
    }

    #[test]
    fn a_new_window_is_found_by_its_created_line() {
        let segment = "[IPC ] console pid=4: [WIN ] created x=153 y=97 windows=2\n\
                       [IPC ] console pid=4: [WIN ] created x=185 y=129 windows=2\n";
        assert_eq!(created_origin(segment), Some(Point { x: 185, y: 129 }));
        assert_eq!(
            created_origin("[IPC ] console pid=4: [WIN ] created x=1"),
            None
        );
        // The boot's terminal window, second in the cascade, is where the lane first clicks.
        assert_eq!(
            sized_window_origin(
                QualityTier::Q1,
                clean_slate_terminal::render::WINDOW_SIZE,
                1
            ),
            Point { x: 153, y: 97 }
        );
    }

    fn native_boot() -> String {
        boot()
            .replace(
                "terminal=on\n",
                "terminal=on shell=native\n[KERN] boot option shell=native: the terminal's shell is the native shell\n",
            )
            .replace(
                "[SVC ] launch service=21505 pid=9 gen=1\n",
                "[SVC ] launch service=21505 pid=9 gen=1\n\
                 [IPC ] console pid=9: [NSH ] start pid=9\n\
                 [IPC ] console pid=9: [NSH ] ready\n",
            )
    }

    #[test]
    fn a_native_shell_boot_needs_its_profile_and_ready_line() {
        assert_eq!(
            check_native_boot(&native_boot()),
            Ok(Terminal {
                terminal_pid: 10,
                shell_pid: 9,
                console_pid: 3,
            })
        );
        assert!(check_native_boot(&boot())
            .unwrap_err()
            .contains("shell=native"));
        let text = native_boot().replace("[NSH ] ready", "[NSH ] waiting");
        assert!(check_native_boot(&text)
            .unwrap_err()
            .contains("[NSH ] ready"));
        let text = native_boot().replace("rights=connect|session", "rights=connect");
        assert!(check_native_boot(&text).unwrap_err().contains("pid=9"));
    }

    #[test]
    fn ctrl_d_must_end_the_shell_and_start_a_new_one_beside_the_same_terminal() {
        let before = Terminal {
            terminal_pid: 10,
            shell_pid: 9,
            console_pid: 3,
        };
        let good = "[IPC ] console pid=9: [NSH ] exit reason=end-of-input status=0\n\
                    [SVC ] reaped service=21505 pid=9 residue=0\n\
                    [CONS] authority granted pid=14 port=22016:3 rights=connect|session\n\
                    [SVC ] authority service=21505 pid=14 counts matches-manifest=1\n\
                    [SVC ] launch service=21505 pid=14 gen=2\n\
                    [IPC ] console pid=14: [NSH ] ready\n";
        assert_eq!(
            check_end_of_input(good, before),
            Ok(Terminal {
                shell_pid: 14,
                ..before
            })
        );
        let exit = good.replace("end-of-input", "console-gone");
        assert!(check_end_of_input(&exit, before).is_err());
        let terminal_went = format!("{good}[IPC ] console pid=10: [TERM] exit reason=closed\n");
        assert!(check_end_of_input(&terminal_went, before)
            .unwrap_err()
            .contains("terminal exited"));
        let relaunched = format!("{good}[SVC ] launch service=21251 pid=15 gen=2\n");
        assert!(check_end_of_input(&relaunched, before).is_err());
        assert!(
            check_end_of_input(&good.replace("pid=14: [NSH ] ready", "pid=14: x"), before).is_err()
        );
    }

    #[test]
    fn ctrl_d_is_one_ctrl_chord() {
        assert_eq!(CTRL_D.len(), 4);
        assert_eq!(
            CTRL_D[0],
            InputAction::Key {
                qcode: QCode::CTRL,
                down: true
            }
        );
        assert!(NATIVE_LAUNCHES.contains(&(TERMINAL_SHELL, 2)));
    }
}
