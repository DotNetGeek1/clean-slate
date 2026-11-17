//! `cargo xtask test-system-desktop` (#218 S6e): the system image's desktop, driven over QMP and
//! COM1 on the hooks build, with `opt/clean-slate/desktop=q1` on a modern-only VirtIO-GPU.
//!
//! 1. **Boot**: `test-system`'s six-row checks ([`check_baseline_boot`]).
//! 2. **Serial shell**: COM1 still reaches the BusyBox shell with the desktop up.
//! 3. **The M10 script**, closed loop (#240): every pointer move waits for the compositor's
//!    `[INPT] pointer settled` at the target, and every button edge for its `[INPT] button` line
//!    with the expected position and hit, before the next input is sent. Increment, toggle, a
//!    background click, key `a` (delivered by focus), a title-bar drag and the close control.
//! 4. **App closed** and 5. **app fault** (`0x1F`): init brings the app back, and after a fault
//!    not before about half a second (D2).
//! 6. **Desktop shell fault** (`0x1E`): the app keeps its pid and a click still reaches it.
//! 7. **Compositor fault** (`0x1D`) and 8. **input after its restart**: a click reaches the new
//!    app through the re-bound seat.
//! 9. **Whole transcript**: launch counts per row, one `[PROC] fault` per injected fault, the
//!    first app's input lines, and where each app window was created.
//!
//! Screendumps are taken once two in a row are identical and checked against a host render
//! ([`crate::m10_desktop_visual`]).

use std::path::PathBuf;
use std::time::Duration;

use clean_slate_graphics::Point;
use clean_slate_ui::{ChromeControl, ChromeStyle, QualityTier};

use crate::m10_desktop_lane::{
    motion_chunks, validate_captures, Plan, PlannedCapture, BACKGROUND_POINT, DRAG, EXPECTED_INPUT,
};
use crate::m10_desktop_visual::{center, chrome, frame_rect, panel, translate, window_origin};
use crate::m10_desktop_visual::{Scene, OUTPUT};
use crate::qmp::lane::Capture;
use crate::qmp::{InputAction, MouseButton, QCode};
use crate::system_boot::{ensure_data_disk, field, number, start_shell_fixture_peer};
use crate::system_desktop::{
    check_baseline_boot, check_row_gone, report_fault, whole_line, Desktop, Gone, DESKTOP_ROWS,
    GIVE_UP_LINES, NETWORK, ROW_NAMES, SHELL, SHELL_ANSWER, STORAGE,
};
use crate::system_desktop_faults::{desktop_config, Session};
use crate::system_shell::lines;
use crate::{workspace_root, xtask_artifact_root, XtaskError};

const HOOKS_FEATURE: &str = "system-test-hooks";
const TIER: QualityTier = QualityTier::Q1;
const LANE_TIMEOUT: Duration = Duration::from_secs(600);
const STEP_TIMEOUT: Duration = Duration::from_secs(60);
/// QEMU queues a PS/2 mouse packet only while its 16-byte queue has room for it, and keeps
/// motion it could not queue until the next input event; buttons ride on whichever packet goes
/// next. Four 3-byte packets always fit once the guest has drained the queue.
const PACKETS_PER_BATCH: usize = 4;
/// How long a batch may take to settle where it should before the lane corrects from where the
/// guest says the pointer is.
const SETTLE_WAIT: Duration = Duration::from_secs(10);
const CORRECTIONS: usize = 3;
const EDGE_WAIT: Duration = Duration::from_secs(30);
/// D2: init restarts a closed or crashed app after 0.5 s; the guest's clock is in whole ms.
const MIN_APP_RESTART_MS: u64 = 450;
const FORBIDDEN: [&str; 3] = ["[FAIL]", GIVE_UP_LINES[0], GIVE_UP_LINES[1]];
const SETTLED: &str = "[INPT] pointer settled ";
/// Where a starting compositor puts the pointer (the M10 policy's `cursor_at_start`). The first
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
const LAUNCHES: [(u32, usize); 6] = [
    (STORAGE, 1),
    (NETWORK, 1),
    (SHELL, 1),
    (DESKTOP_ROWS[0], 2),
    (DESKTOP_ROWS[1], 3),
    (DESKTOP_ROWS[2], 4),
];

struct Lane {
    session: Session,
    desktop: Desktop,
    /// Where the compositor last said the pointer settled, once known.
    pointer: Option<Point>,
    run_dir: PathBuf,
    captures: Vec<Capture>,
    planned: Vec<PlannedCapture>,
}

/// The last complete `[INPT] pointer settled` position in `segment`.
fn last_settled(segment: &str) -> Option<Point> {
    lines(segment)
        .filter_map(|line| line.find(SETTLED).map(|at| &line[at..]))
        .filter_map(|line| {
            Some(Point {
                x: number(line, "x").ok()? as i32,
                y: number(line, "y").ok()? as i32,
            })
        })
        .last()
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

impl Lane {
    fn fail<T>(&self, message: String) -> Result<T, XtaskError> {
        self.session.fail(message)
    }

    /// Moves the pointer to `target` in batches of at most [`PACKETS_PER_BATCH`] motion
    /// commands, waiting after each for the compositor to report the pointer settled where the
    /// batch should have left it. A batch that settles elsewhere is corrected from the position
    /// the guest reports.
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
                let polled =
                    self.session
                        .poll(
                            &waiting,
                            SETTLE_WAIT,
                            &mut |segment| match last_settled(segment) {
                                Some(at) if at == expected => Ok(()),
                                Some(at) => Err(format!(
                                    "the pointer last settled at x={} y={}",
                                    at.x, at.y
                                )),
                                None => {
                                    Err("no [INPT] pointer settled line since the move".to_owned())
                                }
                            },
                        )?;
                if let Err(reason) = polled {
                    let Some(at) = last_settled(&self.session.segment()) else {
                        return self.fail(format!(
                            "{what}: the guest never reported [INPT] pointer settled after the pointer was moved from x={} y={} towards x={} y={}",
                            from.x, from.y, expected.x, expected.y
                        ));
                    };
                    println!("\n[STD ] {waiting}: {reason}; correcting");
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
        let (at, hit) = self.session.wait(&waiting, EDGE_WAIT, &mut |segment| {
            button_edge(segment, edge).ok_or_else(|| {
                format!(
                    "the guest has not reported [INPT] button left {edge} (pointer at x={} y={})",
                    expected.x, expected.y
                )
            })
        })?;
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
        self.session.wait(what, STEP_TIMEOUT, &mut |segment| {
            if lines(segment).any(|l| l == line) {
                Ok(())
            } else {
                Err(format!("no {line:?}"))
            }
        })
    }

    /// Clicks the current app's increment button at its window `origin`; its fresh state must
    /// change to one click.
    fn click_increment(&mut self, what: &str, origin: Point) -> Result<(), XtaskError> {
        let increment = center(translate(panel(TIER).increment, origin));
        self.click(what, increment, &["content"])?;
        self.await_app_input(what, FRESH_INPUT)
    }

    /// A screendump once two in a row are identical, checked later against `window` and the
    /// settled pointer.
    fn capture(&mut self, name: &'static str, window: Option<Point>) -> Result<(), XtaskError> {
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
                tier: TIER,
                window,
                pointer,
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
    if first_input != EXPECTED_INPUT {
        return Err(format!(
            "the first app logged {first_input:?}, expected {EXPECTED_INPUT:?}"
        ));
    }
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

fn drive(lane: &mut Lane) -> Result<Vec<Point>, XtaskError> {
    let first = window_origin(TIER, 0);
    let layout = panel(TIER);
    let chrome = chrome(TIER);

    println!("\n[STD ] step: serial shell");
    lane.session.type_serial(b"echo hel''lo-desktop\r")?;
    lane.session
        .wait("serial shell", STEP_TIMEOUT, &mut |segment| {
            if lines(segment).any(|line| line == SHELL_ANSWER) {
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

    let grip = center(chrome.title_bar_rect(frame_rect(TIER, first)));
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
    let close = center(chrome.control_rect(frame_rect(TIER, dragged), ChromeControl::Close));
    lane.move_to("close", close)?;
    lane.button("close", true, &["close"])?;
    lane.button("close", false, &["close"])?;
    lane.await_restart("close", 2, Gone::Closed)?;
    let second = window_origin(TIER, 1);
    lane.capture("relaunched", Some(second))?;

    let third = window_origin(TIER, 2);
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

fn run_on(disk: &std::path::Path, fixture_port: u16) -> Result<(), XtaskError> {
    let mut session = Session::start(
        &[HOOKS_FEATURE],
        desktop_config(disk, fixture_port),
        true,
        &FORBIDDEN,
        LANE_TIMEOUT,
        "system-desktop/serial.log",
    )?;
    println!("[STD ] step: boot");
    let desktop = session.wait("boot", STEP_TIMEOUT, &mut check_baseline_boot)?;
    let run_dir = xtask_artifact_root().join("system-desktop");
    std::fs::create_dir_all(&run_dir)?;
    let mut lane = Lane {
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
    if let Err(reason) = check_whole(&transcript, first_app, &created) {
        return lane.fail(format!("whole transcript: {reason}"));
    }
    let plan = Plan {
        steps: Vec::new(),
        captures: lane.planned.clone(),
        created: [created[0], created[1], created[2], created[3]],
        dragged: Point {
            x: created[0].x + DRAG.x,
            y: created[0].y + DRAG.y,
        },
    };
    if let Err(reason) = validate_captures(&lane.captures, &plan) {
        return lane.fail(format!("screendumps: {reason}"));
    }
    let Lane {
        session, desktop, ..
    } = lane;
    session.finish()?;
    println!(
        "[STD ] {} captures matched; desktop ended with {} pids {:?}",
        plan.captures.len(),
        ROW_NAMES.join("/"),
        desktop.rows.map(|row| row.pid)
    );
    Ok(())
}

/// `cargo xtask test-system-desktop`, on a fresh lane-owned disk.
pub(crate) fn run() -> Result<(), XtaskError> {
    let disk = workspace_root()
        .join("target")
        .join("system-desktop")
        .join("data.img");
    if disk.is_file() {
        std::fs::remove_file(&disk)?;
    }
    ensure_data_disk(&disk)?;
    let peer = start_shell_fixture_peer()?;
    let result = run_on(&disk, peer.port());
    peer.shutdown();
    result?;
    println!("[STD ] test-system-desktop PASS");
    Ok(())
}
