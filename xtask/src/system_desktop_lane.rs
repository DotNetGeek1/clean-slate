//! `cargo xtask test-system-desktop` (#218 S6e): the system image's desktop, driven over QMP and
//! COM1 on the hooks build, with `opt/clean-slate/desktop=q1-bare` on a modern-only VirtIO-GPU.
//! `test-m10-desktop` (S6f) runs the same driver on that machine and on the `-vga std`
//! framebuffer with `q0-bare` ([`run_each`]).
//!
//! 1. **Boot**: init's eight-row settle line, so only the system image passes, then
//!    `test-system`'s eight-row checks ([`check_baseline_boot`]) at the machine's tier.
//! 2. **Serial shell**: COM1 still reaches the BusyBox shell with the desktop up.
//! 3. **The M10 script**, closed loop (#240): every pointer move waits for the compositor's
//!    `[INPT] pointer settled` at the target, and every button edge for its `[INPT] button` line
//!    with the expected position and hit, before the next input is sent. Increment, toggle, a
//!    background click, key `a` (delivered by focus), `s` held for a second so the compositor
//!    repeats it and stops at the release (#309), a title-bar drag and the close control.
//! 4. **App closed** and 5. **app fault** (`0x1F`): init brings the app back, and after a fault
//!    not before about half a second (D2).
//! 6. **Desktop shell fault** (`0x1E`): the app keeps its pid and a click still reaches it.
//! 7. **Compositor fault** (`0x1D`) and 8. **input after its restart**: a click reaches the new
//!    app through the re-bound seat.
//! 9. **Whole transcript**: launch counts per row, one `[PROC] fault` per injected fault, the
//!    first app's input lines (ending with the held key's growing `s` run), where each app window was created, and every `[IDLE ] quiet`
//!    stretch with `presents=0`.
//!
//! Screendumps are taken once the guest has reported a quiet stretch since the last input and
//! two dumps in a row are identical, and checked against a host render
//! ([`crate::m10_desktop_visual`]).

use std::path::PathBuf;
use std::time::Duration;

use clean_slate_graphics::Point;
use clean_slate_ui::{ChromeControl, ChromeStyle};

use crate::m10_desktop_lane::{
    check_held_key, is_held_key_line, motion_chunks, validate_captures, PlannedCapture,
    BACKGROUND_POINT, DRAG, EXPECTED_INPUT, HELD_KEY_HOLD, HELD_KEY_MIN_REPEATS,
};
use crate::m10_desktop_visual::{center, chrome, frame_rect, panel, translate, window_origin};
use crate::m10_desktop_visual::{Scene, OUTPUT};
use crate::qmp::lane::Capture;
use crate::qmp::{InputAction, MouseButton, QCode};
use crate::system_boot::{ensure_data_disk, field, number, start_shell_fixture_peer};
use crate::system_desktop::{
    check_baseline_boot, check_row_gone, report_fault, whole_line, Desktop, DesktopMachine, Gone,
    AUDIT, DESKTOP_ROWS, GIVE_UP_LINES, NETWORK, ROW_NAMES, SETTLED_DESKTOP, SHELL, SHELL_ANSWER,
    STORAGE, VIRTIO_GPU_Q1,
};
use crate::system_desktop_faults::{desktop_config, Session};
use crate::system_shell::{console_text, lines};
use crate::{workspace_root, xtask_artifact_root, XtaskError};

const HOOKS_FEATURE: &str = "system-test-hooks";
const LANE_TIMEOUT: Duration = Duration::from_secs(600);
const STEP_TIMEOUT: Duration = Duration::from_secs(60);
/// QEMU queues a PS/2 mouse packet only while its 16-byte queue has room for it, and keeps
/// motion it could not queue until the next input event; buttons ride on whichever packet goes
/// next. Four packets (4 bytes each with the IntelliMouse Explorer protocol the guest selects)
/// always fit once the guest has drained the queue.
///
/// A button edge sent while the queue is full is kept only as button state, so a release sent
/// before the guest drains erases the press and the click never reaches the guest at all (#240:
/// a busy host leaves the guest behind on a burst of motion). Every edge is therefore sent only
/// once the guest has reported the pointer settled, which means it has read every queued byte.
const PACKETS_PER_BATCH: usize = 4;
/// How long a batch may take to settle where it should, or to settle somewhere else with the
/// guest quiet after it, which the lane then corrects from.
const SETTLE_WAIT: Duration = Duration::from_secs(20);
const CORRECTIONS: usize = 3;
const EDGE_WAIT: Duration = Duration::from_secs(30);
/// D2: init restarts a closed or crashed app after 0.5 s; the guest's clock is in whole ms.
const MIN_APP_RESTART_MS: u64 = 450;
const FORBIDDEN: [&str; 2] = [GIVE_UP_LINES[0], GIVE_UP_LINES[1]];
const SETTLED: &str = "[INPT] pointer settled ";
/// The hooks build's quiet proof: nothing ran for half a second and nothing was presented.
const QUIET: &str = "[IDLE ] quiet ";
/// Where a starting compositor puts the pointer (the compositor policy's `cursor_at_start`). The first
/// move after a start corrects from the guest's report if it is not.
const START: Point = Point {
    x: OUTPUT.width as i32 / 2,
    y: OUTPUT.height as i32 / 2,
};
const APP_INPUT: &str = "[APP ] input state=changed ";
const FRESH_INPUT: &str = "clicks=1 magenta=0 presses=0 text=";
/// Each fault byte's row, as an index into [`DESKTOP_ROWS`].
const FAULTS: [(&str, &[u8], usize); 3] = [
    ("app fault", b"\x1f", 2),
    ("desktop shell fault", b"\x1e", 1),
    ("compositor fault", b"\x1d", 0),
];
/// `[SVC ] launch` lines per row over the run: the base rows once; the compositor again after
/// its fault; the desktop shell after its fault and the compositor's; the app after the close,
/// its fault and the compositor's.
const LAUNCHES: [(u32, usize); 7] = [
    (STORAGE, 1),
    (AUDIT, 1),
    (NETWORK, 1),
    (SHELL, 1),
    (DESKTOP_ROWS[0], 2),
    (DESKTOP_ROWS[1], 3),
    (DESKTOP_ROWS[2], 4),
];

/// One boot of the lane's driver: the machine, and where its screendumps and serial log go.
#[derive(Clone, Copy, Debug)]
pub(crate) struct LaneRun {
    pub(crate) machine: DesktopMachine,
    /// Directory under the artifact root (and under `target/` for the data disk).
    pub(crate) artifacts: &'static str,
    /// The serial log, relative to the artifact root.
    pub(crate) serial_log: &'static str,
}

const SYSTEM_DESKTOP_RUN: LaneRun = LaneRun {
    machine: VIRTIO_GPU_Q1,
    artifacts: "system-desktop",
    serial_log: "system-desktop/serial.log",
};

struct Lane {
    machine: DesktopMachine,
    session: Session,
    desktop: Desktop,
    /// Where the compositor last said the pointer settled, once known.
    pointer: Option<Point>,
    run_dir: PathBuf,
    captures: Vec<Capture>,
    planned: Vec<PlannedCapture>,
}

/// `segment` up to its last newline: a line the guest is still printing can parse as a number
/// it is not (`y=22` of `y=223`).
fn complete_lines(segment: &str) -> &str {
    segment.rfind('\n').map_or("", |end| &segment[..=end])
}

/// The last complete `[INPT] pointer settled` position in `segment`.
fn last_settled(segment: &str) -> Option<Point> {
    lines(complete_lines(segment))
        .filter_map(|line| line.find(SETTLED).map(|at| &line[at..]))
        .filter_map(|line| {
            Some(Point {
                x: number(line, "x").ok()? as i32,
                y: number(line, "y").ok()? as i32,
            })
        })
        .last()
}

/// Where a motion batch left the pointer, once that is settled: the expected position, or
/// another one the guest reported settled and then went quiet at (`[IDLE ] quiet` after it,
/// so it has read every packet the batch queued).
///
/// A batch whose packets the guest reads in more than one drain settles part-way first.
/// Correcting from that position while the rest is still on its way moves the pointer past the
/// target: the #349 drag released 100 px (one motion chunk) beyond its target. Only a quiet
/// guest's position is safe to correct from.
fn settled_for_batch(segment: &str, expected: Point) -> Result<Point, String> {
    let complete = complete_lines(segment);
    let Some(at) = last_settled(complete) else {
        return Err("no [INPT] pointer settled line since the move".to_owned());
    };
    if at == expected {
        return Ok(at);
    }
    let after = complete
        .rfind(SETTLED)
        .map_or("", |start| &complete[start..]);
    if lines(after).skip(1).any(|line| line.contains(QUIET)) {
        Ok(at)
    } else {
        Err(format!(
            "the pointer last settled at x={} y={} and the guest has not gone quiet since",
            at.x, at.y
        ))
    }
}

/// The first complete `[INPT] button left <edge>` line in `segment`: its position and hit.
fn button_edge(segment: &str, edge: &str) -> Option<(Point, String)> {
    let prefix = format!("[INPT] button left {edge} ");
    let (_, rest) = whole_line(segment, &prefix)?;
    let rest = format!(" {rest}");
    Some((
        Point {
            x: number(&rest, "x").ok()? as i32,
            y: number(&rest, "y").ok()? as i32,
        },
        field(&rest, "hit")?.to_owned(),
    ))
}

/// What the guest last said about the pointer in `transcript`, for a failure message: where it
/// last settled and its last button edge, so a click that never arrived (#240) shows whether
/// the guest saw the pointer where the lane put it.
fn pointer_report(transcript: &str) -> String {
    let settled = last_settled(transcript).map_or_else(
        || "never reported the pointer settled".to_owned(),
        |at| format!("last reported the pointer settled at x={} y={}", at.x, at.y),
    );
    let edge = lines(complete_lines(transcript))
        .filter_map(|line| line.find("[INPT] button ").map(|at| &line[at..]))
        .last()
        .map_or_else(
            || "no button edge".to_owned(),
            |line| format!("last button edge {line:?}"),
        );
    format!("the guest {settled}, {edge}")
}

impl Lane {
    fn fail<T>(&self, message: String) -> Result<T, XtaskError> {
        self.session.fail(message)
    }

    /// Moves the pointer to `target` in batches of at most [`PACKETS_PER_BATCH`] motion
    /// commands, waiting after each for the compositor to report the pointer settled where the
    /// batch should have left it. A batch that settles elsewhere is corrected from the position
    /// the guest reports once it has gone quiet there ([`settled_for_batch`]).
    fn move_to(&mut self, what: &str, target: Point) -> Result<(), XtaskError> {
        let mut corrections = 0;
        loop {
            let Some(from) = self.pointer else {
                return self.fail(format!("{what}: the pointer position is not known"));
            };
            if from == target {
                return Ok(());
            }
            let delta = Point {
                x: target.x - from.x,
                y: target.y - from.y,
            };
            let mut expected = from;
            for batch in motion_chunks(delta).chunks(PACKETS_PER_BATCH) {
                self.session.mark();
                for chunk in batch {
                    self.session
                        .input(what, &InputAction::move_rel(chunk.x, chunk.y))?;
                    expected = Point {
                        x: expected.x + chunk.x,
                        y: expected.y + chunk.y,
                    };
                }
                let waiting = format!(
                    "{what}: pointer settled at x={} y={}",
                    expected.x, expected.y
                );
                let polled = self.session.poll(&waiting, SETTLE_WAIT, &mut |segment| {
                    settled_for_batch(segment, expected)
                })?;
                match polled {
                    Ok(at) if at == expected => {}
                    Ok(at) => {
                        println!(
                            "\n[STD ] {waiting}: the pointer settled at x={} y={} and the guest went quiet; correcting",
                            at.x, at.y
                        );
                        corrections += 1;
                        if corrections > CORRECTIONS {
                            return self.fail(format!(
                                "{what}: the pointer did not settle at x={} y={} after {CORRECTIONS} corrections; it is at x={} y={}",
                                target.x, target.y, at.x, at.y
                            ));
                        }
                        self.pointer = Some(at);
                        break;
                    }
                    Err(reason) => {
                        return self.fail(format!(
                            "{what}: the pointer did not settle after it was moved from x={} y={} towards x={} y={}: {reason}",
                            from.x, from.y, expected.x, expected.y
                        ));
                    }
                }
                self.pointer = Some(expected);
            }
        }
    }

    /// One left-button edge at the settled pointer, then the compositor's line for it, which
    /// must name the same position and one of `hits`.
    fn button(&mut self, what: &str, down: bool, hits: &[&str]) -> Result<(), XtaskError> {
        let edge = if down { "down" } else { "up" };
        let Some(expected) = self.pointer else {
            return self.fail(format!("{what}: the pointer position is not known"));
        };
        self.session.mark();
        self.session.input(
            what,
            &[InputAction::Button {
                button: MouseButton::Left,
                down,
            }],
        )?;
        let waiting = format!("{what}: button {edge}");
        let polled = self.session.poll(&waiting, EDGE_WAIT, &mut |segment| {
            button_edge(segment, edge).ok_or_else(|| {
                format!(
                    "the guest has not reported [INPT] button left {edge} with the pointer settled at x={} y={}",
                    expected.x, expected.y
                )
            })
        })?;
        let (at, hit) = match polled {
            Ok(found) => found,
            Err(reason) => {
                let report = pointer_report(&self.session.transcript());
                return self.fail(format!("timed out in {waiting:?}: {reason}; {report}"));
            }
        };
        if at != expected || !hits.contains(&hit.as_str()) {
            return self.fail(format!(
                "{what}: the guest reported the left button {edge} at x={} y={} hit={hit}, expected x={} y={} hit={}",
                at.x,
                at.y,
                expected.x,
                expected.y,
                hits.join("|")
            ));
        }
        Ok(())
    }

    fn click(&mut self, what: &str, at: Point, hits: &[&str]) -> Result<(), XtaskError> {
        self.move_to(what, at)?;
        self.button(what, true, hits)?;
        self.button(what, false, hits)
    }

    fn app_pid(&self) -> u64 {
        self.desktop.rows[2].pid
    }

    /// Waits for the current app to log `state` (the fields after `state=changed`).
    fn await_app_input(&mut self, what: &str, state: &str) -> Result<(), XtaskError> {
        let line = format!("[IPC ] console pid={}: {APP_INPUT}{state}", self.app_pid());
        let polled = self.session.poll(what, STEP_TIMEOUT, &mut |segment| {
            if lines(segment).any(|l| l == line) {
                Ok(())
            } else {
                Err(format!("no {line:?}"))
            }
        })?;
        if let Err(reason) = polled {
            let report = pointer_report(&self.session.transcript());
            return self.fail(format!("timed out in {what:?}: {reason}; {report}"));
        }
        Ok(())
    }

    /// Clicks the current app's increment button at its window `origin`; its fresh state must
    /// change to one click.
    fn click_increment(&mut self, what: &str, origin: Point) -> Result<(), XtaskError> {
        let increment = center(translate(panel(self.machine.tier).increment, origin));
        self.click(what, increment, &["content"])?;
        self.await_app_input(what, FRESH_INPUT)
    }

    /// A screendump taken once the guest has been quiet since the last input (an `[IDLE ] quiet`
    /// line since the mark) and two dumps in a row are identical, checked later against `window`
    /// and the settled pointer.
    fn capture(&mut self, name: &'static str, window: Option<Point>) -> Result<(), XtaskError> {
        self.session.wait(
            &format!("screendump `{name}`: quiet"),
            STEP_TIMEOUT,
            &mut |segment| {
                if lines(segment).any(|line| line.contains(QUIET)) {
                    Ok(())
                } else {
                    Err(format!(
                        "no {QUIET:?} line: nothing may run for half a second before a capture"
                    ))
                }
            },
        )?;
        let ppm = self.run_dir.join(format!("{name}.ppm"));
        let mut last = self.session.screendump(name, &ppm)?;
        let mut stable = false;
        for _ in 0..10 {
            std::thread::sleep(Duration::from_millis(200));
            let next = self.session.screendump(name, &ppm)?;
            stable = next == last;
            last = next;
            if stable {
                break;
            }
        }
        let _ = std::fs::remove_file(&ppm);
        if !stable {
            return self.fail(format!(
                "screendump `{name}`: the frame never stopped changing"
            ));
        }
        let png = self.run_dir.join(format!("{name}.png"));
        last.write_png(&png)?;
        println!("\n[STD ] captured `{name}` -> {}", png.display());
        let pointer = self.pointer.unwrap_or(Point {
            x: OUTPUT.width as i32 / 2,
            y: OUTPUT.height as i32 / 2,
        });
        self.captures.push(Capture {
            name,
            png,
            screenshot: last,
        });
        self.planned.push(PlannedCapture {
            name,
            scene: Scene {
                tier: self.machine.tier,
                window,
                pointer,
                output: OUTPUT,
            },
        });
        Ok(())
    }

    /// Waits for `row` to go (`how`) and come back as `test-system` requires, from the mark.
    fn await_restart(&mut self, what: &str, row: usize, how: Gone) -> Result<(), XtaskError> {
        let before = self.desktop.clone();
        let after = self.session.wait(what, STEP_TIMEOUT, &mut |segment| {
            check_row_gone(segment, &before, row, how)
        })?;
        if how == Gone::Fault {
            let delay = report_fault(what, row, &self.session.segment(), &before, &after);
            if row == 2 && delay.is_none_or(|ms| ms < MIN_APP_RESTART_MS) {
                return self.fail(format!(
                    "{what}: the app was relaunched {delay:?} ms after its fault, expected about 500"
                ));
            }
        }
        self.desktop = after;
        Ok(())
    }
}

/// When each app but the first connects, the compositor (the new one, after a compositor
/// restart) holds the desktop shell's rows alone: the old app's surfaces were released first.
/// Init launches the app once the desktop shell reports ready, which can precede the
/// compositor's rows line for the shell's second surface, so the check is anchored on the
/// app's connection (the first `clients=2` rows line after its launch), not on its launch.
fn check_rows(transcript: &str) -> Result<(), String> {
    const SHELL_ONLY: &str = "[COMP] rows clients=1 surfaces=2 windows=0";
    let compositor = format!("[SVC ] launch service={} ", DESKTOP_ROWS[0]);
    let app = format!("[SVC ] launch service={} ", DESKTOP_ROWS[2]);
    let mut last_rows: Option<&str> = None;
    let mut app_launches = 0;
    let mut awaiting_connection = false;
    for line in lines(transcript) {
        if let Some(at) = line.find("[COMP] rows ") {
            let rows = line[at..].trim_end();
            if awaiting_connection && number(rows, "clients")? > 1 {
                if last_rows != Some(SHELL_ONLY) {
                    return Err(format!(
                        "app launch {app_launches} connected after compositor rows {last_rows:?}, expected `{SHELL_ONLY}`"
                    ));
                }
                awaiting_connection = false;
            }
            last_rows = Some(rows);
        }
        if line.contains(&compositor) {
            last_rows = None;
        }
        if line.contains(&app) {
            if awaiting_connection {
                return Err(format!("app launch {app_launches} never connected"));
            }
            app_launches += 1;
            awaiting_connection = app_launches > 1;
        }
    }
    if awaiting_connection {
        return Err(format!("app launch {app_launches} never connected"));
    }
    Ok(())
}

/// Every quiet stretch presented nothing, and there was one before each of the `captures`.
fn check_quiet(transcript: &str, captures: usize) -> Result<(), String> {
    let quiet: Vec<&str> = lines(transcript)
        .filter_map(|line| line.find(QUIET).map(|at| &line[at..]))
        .collect();
    if quiet.len() < captures {
        return Err(format!(
            "{} {QUIET:?} lines, expected at least one per capture ({captures})",
            quiet.len()
        ));
    }
    for line in quiet {
        if number(line, "presents")? != 0 {
            return Err(format!("the desktop presented while nothing ran: {line:?}"));
        }
        if number(line, "ms")? < 500 {
            return Err(format!("a quiet stretch shorter than 500 ms: {line:?}"));
        }
    }
    Ok(())
}

/// Everything over the whole transcript.
fn check_whole(transcript: &str, first_app: u64, created: &[Point]) -> Result<(), String> {
    for (service, expected) in LAUNCHES {
        let launches = lines(transcript)
            .filter(|line| line.contains(&format!("[SVC ] launch service={service} ")))
            .count();
        if launches != expected {
            return Err(format!(
                "service={service} launched {launches} times, expected {expected}"
            ));
        }
    }
    // Vector 128 is a native process's `int 0x80` exit; the hooks fault with a page fault.
    let faults: Vec<&str> = lines(transcript)
        .filter(|line| line.contains("[PROC] fault pid=") && !line.contains(" vector=128 "))
        .collect();
    if faults.len() != FAULTS.len() || faults.iter().any(|line| !line.contains(" vector=14 ")) {
        return Err(format!(
            "faults {faults:?}, expected one page fault per injected fault ({})",
            FAULTS.len()
        ));
    }
    let first_input: Vec<&str> = lines(transcript)
        .filter_map(|line| {
            line.strip_prefix(&format!("[IPC ] console pid={first_app}: {APP_INPUT}"))
        })
        .collect();
    if first_input.len() < EXPECTED_INPUT.len()
        || first_input[..EXPECTED_INPUT.len()] != EXPECTED_INPUT
    {
        return Err(format!(
            "the first app logged {first_input:?}, expected {EXPECTED_INPUT:?} then the held key"
        ));
    }
    check_held_key(&first_input[EXPECTED_INPUT.len()..])
        .map_err(|reason| format!("the first app's held key: {reason}"))?;
    let windows: Vec<Point> = lines(transcript)
        .filter_map(|line| line.find("[WIN ] created ").map(|at| &line[at..]))
        .filter_map(|line| {
            Some(Point {
                x: number(line, "x").ok()? as i32,
                y: number(line, "y").ok()? as i32,
            })
        })
        .collect();
    if windows != created {
        return Err(format!(
            "app windows created at {windows:?}, expected {created:?}"
        ));
    }
    Ok(())
}

/// #309: holds `s` (focus is still app 1) long enough for the compositor to repeat it, then
/// checks the repeats stop with the release.
fn hold_key(lane: &mut Lane) -> Result<(), XtaskError> {
    println!("\n[STD ] step: held key");
    let prefix = format!("[IPC ] console pid={}: {APP_INPUT}", lane.app_pid());
    // Held-key lines in a segment: the press, then one per (coalesced) repeat.
    let held = |segment: &str| -> usize {
        lines(segment)
            .filter_map(|line| line.strip_prefix(prefix.as_str()))
            .filter(|line| is_held_key_line(line))
            .count()
    };
    lane.session.mark();
    lane.session.input(
        "hold s",
        &[InputAction::Key {
            qcode: QCode::S,
            down: true,
        }],
    )?;
    std::thread::sleep(HELD_KEY_HOLD);
    lane.session.input(
        "release s",
        &[InputAction::Key {
            qcode: QCode::S,
            down: false,
        }],
    )?;
    // The release is proven by quiet: the hooks build prints `[IDLE ] quiet` only after half a
    // second in which nothing ran, which a key repeating at 30 per second never allows. Serial
    // keeps order, so a quiet line after the last held-key line means the repeats stopped (a
    // quiet line from the 500 ms repeat delay comes before the first repeat).
    let count = lane
        .session
        .wait("held key", STEP_TIMEOUT, &mut |segment| {
            let all: Vec<&str> = lines(segment).collect();
            let last_held = all.iter().rposition(|line| {
                line.strip_prefix(prefix.as_str())
                    .is_some_and(is_held_key_line)
            });
            let count = held(segment);
            let quiet_after =
                last_held.is_some_and(|at| all[at + 1..].iter().any(|line| line.contains(QUIET)));
            if count > HELD_KEY_MIN_REPEATS && quiet_after {
                Ok(count)
            } else {
                Err(format!(
                    "holding `s` logged {count} lines (the press and at least \
                 {HELD_KEY_MIN_REPEATS} repeats are expected), quiet after them: {quiet_after}"
                ))
            }
        })?;
    println!(
        "[STD ] held key: the press and {} repeat lines, then quiet",
        count - 1
    );
    Ok(())
}

fn drive(lane: &mut Lane) -> Result<Vec<Point>, XtaskError> {
    let tier = lane.machine.tier;
    let first = window_origin(tier, 0);
    let layout = panel(tier);
    let chrome = chrome(tier);

    println!("\n[STD ] step: serial shell");
    lane.session.type_serial(b"echo hel''lo-desktop\r")?;
    lane.session
        .wait("serial shell", STEP_TIMEOUT, &mut |segment| {
            if lines(segment)
                .filter_map(console_text)
                .any(|line| line == SHELL_ANSWER)
            {
                Ok(())
            } else {
                Err(format!("the serial shell has not printed {SHELL_ANSWER:?}"))
            }
        })?;

    println!("\n[STD ] step: M10 script");
    lane.pointer = Some(START);
    lane.capture("desktop", Some(first))?;
    lane.click(
        "increment",
        center(translate(layout.increment, first)),
        &["content"],
    )?;
    lane.await_app_input("increment", EXPECTED_INPUT[0])?;
    lane.click(
        "toggle",
        center(translate(layout.toggle, first)),
        &["content"],
    )?;
    lane.await_app_input("toggle", EXPECTED_INPUT[1])?;
    lane.click("background", BACKGROUND_POINT, &["none", "surface"])?;
    lane.session.mark();
    lane.session.input("key a", &InputAction::tap(QCode::A))?;
    lane.await_app_input("key a", EXPECTED_INPUT[2])?;
    lane.capture("input", Some(first))?;
    hold_key(lane)?;

    let grip = center(chrome.title_bar_rect(frame_rect(tier, first)));
    lane.move_to("drag", grip)?;
    let pressed_at = lane.session.offset();
    lane.button("drag", true, &["title"])?;
    lane.move_to(
        "drag",
        Point {
            x: grip.x + DRAG.x,
            y: grip.y + DRAG.y,
        },
    )?;
    lane.button("drag", false, &["title"])?;
    let dragged = Point {
        x: first.x + DRAG.x,
        y: first.y + DRAG.y,
    };
    let moved = format!("[WIN ] moved x={} y={}", dragged.x, dragged.y);
    lane.session.mark_at(pressed_at);
    lane.session.wait("drag", STEP_TIMEOUT, &mut |segment| {
        if lines(segment).any(|line| line.ends_with(&moved)) {
            Ok(())
        } else {
            Err(format!("no {moved:?}"))
        }
    })?;
    lane.capture("dragged", Some(dragged))?;

    println!("\n[STD ] step: close");
    let close = center(chrome.control_rect(frame_rect(tier, dragged), ChromeControl::Close));
    lane.move_to("close", close)?;
    lane.button("close", true, &["close"])?;
    lane.button("close", false, &["close"])?;
    lane.await_restart("close", 2, Gone::Closed)?;
    let second = window_origin(tier, 1);
    lane.capture("relaunched", Some(second))?;

    let third = window_origin(tier, 2);
    for (name, byte, row) in FAULTS {
        println!("\n[STD ] step: {name}");
        let app = lane.app_pid();
        lane.session.type_serial(byte)?;
        lane.await_restart(name, row, Gone::Fault)?;
        match row {
            2 => lane.capture("recovered", Some(third))?,
            1 => {
                if lane.app_pid() != app {
                    return lane.fail(format!("{name}: the app pid changed from {app}"));
                }
                lane.click_increment("click after the desktop shell restart", third)?;
            }
            _ => {
                lane.pointer = Some(START);
                lane.capture("restarted", Some(first))?;
                lane.click_increment("click after the compositor restart", first)?;
            }
        }
    }
    Ok(vec![first, second, third, first])
}

/// The boot is the system image's: init launched the desktop and settled with its eight rows.
/// Every other kernel (a self-test build, the retired M10 policy) fails here by name.
fn check_system_image_boot(segment: &str, machine: &DesktopMachine) -> Result<Desktop, String> {
    if !lines(segment).any(|line| line.contains(SETTLED_DESKTOP)) {
        return Err(format!(
            "not booted as the system image: no init eight-row settle line {SETTLED_DESKTOP:?}"
        ));
    }
    check_baseline_boot(segment, machine)
}

fn run_on(run: &LaneRun, disk: &std::path::Path, fixture_port: u16) -> Result<(), XtaskError> {
    let machine = run.machine;
    println!(
        "[STD ] {}: the hooks build on {} at {}",
        run.artifacts,
        machine.name,
        machine.tier_name()
    );
    let mut session = Session::start(
        &[HOOKS_FEATURE],
        desktop_config(disk, fixture_port, &machine),
        true,
        &FORBIDDEN,
        LANE_TIMEOUT,
        run.serial_log,
    )?;
    println!("[STD ] step: boot");
    let desktop = session.wait("boot", STEP_TIMEOUT, &mut |segment| {
        check_system_image_boot(segment, &machine)
    })?;
    let run_dir = xtask_artifact_root().join(run.artifacts);
    std::fs::create_dir_all(&run_dir)?;
    let mut lane = Lane {
        machine,
        session,
        desktop,
        pointer: None,
        run_dir,
        captures: Vec::new(),
        planned: Vec::new(),
    };
    let first_app = lane.app_pid();
    let created = drive(&mut lane)?;
    let transcript = lane.session.transcript();
    if let Err(reason) = check_whole(&transcript, first_app, &created)
        .and_then(|()| check_rows(&transcript))
        .and_then(|()| check_quiet(&transcript, lane.planned.len()))
    {
        return lane.fail(format!("whole transcript: {reason}"));
    }
    if let Err(reason) = validate_captures(&lane.captures, &lane.planned) {
        return lane.fail(format!("screendumps: {reason}"));
    }
    let Lane {
        session,
        desktop,
        planned,
        ..
    } = lane;
    session.finish()?;
    println!(
        "[STD ] {} captures matched; desktop ended with {} pids {:?}",
        planned.len(),
        ROW_NAMES.join("/"),
        desktop.rows.map(|row| row.pid)
    );
    Ok(())
}

/// Each of `runs` in turn, each on a fresh disk of its own.
pub(crate) fn run_each(runs: &[LaneRun]) -> Result<(), XtaskError> {
    for run in runs {
        let disk = workspace_root()
            .join("target")
            .join(run.artifacts)
            .join("data.img");
        if disk.is_file() {
            std::fs::remove_file(&disk)?;
        }
        ensure_data_disk(&disk)?;
        let peer = start_shell_fixture_peer()?;
        let result = run_on(run, &disk, peer.port());
        peer.shutdown();
        result?;
    }
    Ok(())
}

/// `cargo xtask test-system-desktop`, on a fresh lane-owned disk.
pub(crate) fn run() -> Result<(), XtaskError> {
    run_each(&[SYSTEM_DESKTOP_RUN])?;
    println!("[STD ] test-system-desktop PASS");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{check_rows, last_settled, pointer_report, settled_for_batch};
    use clean_slate_graphics::Point;

    #[test]
    fn a_batch_settled_part_way_is_corrected_only_once_the_guest_is_quiet() {
        let expected = Point { x: 581, y: 33 };
        let part_way = "[IPC ] console pid=4: [INPT] pointer settled x=481 y=41\n";
        assert!(settled_for_batch(part_way, expected)
            .unwrap_err()
            .contains("has not gone quiet"));
        // A quiet stretch before the part-way settle says nothing about the packets after it.
        let quiet_before = format!("[IDLE ] quiet ms=500 presents=0 seq=4\n{part_way}");
        assert!(settled_for_batch(&quiet_before, expected).is_err());
        let quiet_after = format!("{part_way}[IDLE ] quiet ms=500 presents=0 seq=4\n");
        assert_eq!(
            settled_for_batch(&quiet_after, expected),
            Ok(Point { x: 481, y: 41 })
        );
        let arrived =
            format!("{part_way}[IPC ] console pid=4: [INPT] pointer settled x=581 y=33\n");
        assert_eq!(settled_for_batch(&arrived, expected), Ok(expected));
        assert!(settled_for_batch("[IDLE ] quiet ms=500 presents=0 seq=4\n", expected).is_err());
    }

    #[test]
    fn a_settled_line_still_being_printed_is_not_read() {
        let printing = "[IPC ] console pid=4: [INPT] pointer settled x=185 y=223\n\
                        [IPC ] console pid=4: [INPT] pointer settled x=401 y=4";
        assert_eq!(last_settled(printing), Some(Point { x: 185, y: 223 }));
        assert_eq!(
            last_settled(&format!("{printing}9\n")),
            Some(Point { x: 401, y: 49 })
        );
    }

    #[test]
    fn a_missing_click_reports_where_the_guest_saw_the_pointer() {
        let transcript = "[IPC ] console pid=4: [INPT] pointer settled x=299 y=268\n\
                          [IPC ] console pid=4: [INPT] button left down x=299 y=268 hit=title\n\
                          [IPC ] console pid=4: [INPT] button left up x=401 y=49 hit=title\n\
                          [IPC ] console pid=4: [INPT] pointer settled x=721 y=58\n\
                          [IDLE ] quiet ms=500 presents=0 seq=20\n";
        assert_eq!(
            pointer_report(transcript),
            "the guest last reported the pointer settled at x=721 y=58, last button edge \
             \"[INPT] button left up x=401 y=49 hit=title\""
        );
        assert_eq!(
            pointer_report("[IDLE ] quiet ms=500 presents=0 seq=7\n"),
            "the guest never reported the pointer settled, no button edge"
        );
    }

    /// Compositor restart from a soak run: the desktop shell reports ready and init launches
    /// the app before the compositor logs the shell's second surface; the app connects after.
    const RESTART: &str = "\
[SVC ] launch service=21250 pid=5 gen=1
[IPC ] console pid=3: [COMP] rows clients=2 surfaces=3 windows=1
[IPC ] console pid=3: [COMP] rows clients=1 surfaces=2 windows=0
[SVC ] launch service=21250 pid=10 gen=2
[IPC ] console pid=3: [COMP] rows clients=2 surfaces=3 windows=1
[SVC ] launch service=21248 pid=12 gen=2
[IPC ] console pid=12: [COMP] rows clients=0 surfaces=0 windows=0
[SVC ] launch service=21249 pid=13 gen=3
[IPC ] console pid=12: [COMP] rows clients=1 surfaces=0 windows=0
[IPC ] console pid=12: [COMP] rows clients=1 surfaces=1 windows=0
[IPC ] console pid=13: [SHELL] ready rail=88x800 surfaces=2 dock=none tier=Q1
[SVC ] launch service=21250 pid=14 gen=3
[IPC ] console pid=12: [COMP] rows clients=1 surfaces=2 windows=0
[IPC ] console pid=12: [COMP] rows clients=2 surfaces=2 windows=0
[IPC ] console pid=12: [COMP] rows clients=2 surfaces=3 windows=1
";

    #[test]
    fn rows_are_checked_when_the_app_connects_not_when_it_launches() {
        check_rows(RESTART).expect("shell-only rows when each relaunched app connected");
    }

    #[test]
    fn rows_left_by_the_old_app_or_a_missing_connection_fail() {
        let residue = RESTART.replacen(
            "pid=3: [COMP] rows clients=1 surfaces=2 windows=0",
            "pid=3: [COMP] rows clients=1 surfaces=3 windows=1",
            1,
        );
        let err = check_rows(&residue).unwrap_err();
        assert!(err.starts_with("app launch 2 connected after"), "{err}");

        let unconnected = RESTART
            .lines()
            .filter(|line| !line.contains("pid=12: [COMP] rows clients=2"))
            .collect::<Vec<_>>()
            .join("\n");
        let err = check_rows(&unconnected).unwrap_err();
        assert_eq!(err, "app launch 3 never connected");
    }
}
