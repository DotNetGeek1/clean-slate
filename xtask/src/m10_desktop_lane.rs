//! M10 #118/#119 desktop lane (`cargo xtask test-m10-desktop`).
//!
//! Boots the `m10-desktop-self-test` kernel twice: on a modern-only VirtIO-GPU at Q1, and on the
//! `-vga std` GOP framebuffer at Q0. The kernel's supervisor launches the compositor, the shell
//! and the playground as native CPL3 processes; a private headless QMP script then drives the
//! desktop through real PS/2 input — click the playground's increment button and toggle, click
//! the background, type a key, drag the title bar, close the window, crash the app (F12) and
//! crash the compositor (F11) — capturing a screendump after each quiet stretch. The host checks
//! the serial transcript (launch/exit/relaunch order, focus-routed input, resource baselines,
//! idle presents) and each capture's structure against a host render
//! ([`crate::m10_desktop_visual`]).

use std::time::Duration;

use clean_slate_graphics::Point;
use clean_slate_ui::{ChromeControl, ChromeStyle, QualityTier};

use crate::m10_desktop_visual::{
    center, check_scene, chrome, frame_rect, panel, region_changed, translate, window_origin,
    Scene, OUTPUT,
};
use crate::marker_spec::{MarkerSet, MarkerStep};
use crate::qmp::image::Screenshot;
use crate::qmp::input::Axis;
use crate::qmp::lane::Capture;
use crate::qmp::lane::{input_lane_config, run_kernel_lane_capturing, KernelLane};
use crate::qmp::{InputAction, MouseButton, QCode, ScriptStep};
use crate::{VmLaunchConfig, XtaskError};

const TIMEOUT: Duration = Duration::from_secs(240);

/// Largest per-axis motion in one `input-send-event`; QEMU's PS/2 mouse saturates at ±127.
pub(crate) const MAX_MOTION: i32 = 120;

/// A workspace point left of and below the first window, away from every control.
pub(crate) const BACKGROUND_POINT: Point = Point { x: 400, y: 650 };

/// Title-bar drag offset.
pub(crate) const DRAG: Point = Point { x: 200, y: -16 };

const IDLE: &str = "[IDLE ] quiet";
const APP_READY: &str = "[APP ] ready";
const INPUT_PREFIX: &str = "[APP ] input state=changed ";

/// The three state changes app 1 must log, in order; no other app instance logs any. The
/// background click and the key typed with the pointer off the window prove delivery follows
/// focus, not the pointer.
pub(crate) const EXPECTED_INPUT: [&str; 3] = [
    "clicks=1 magenta=0 presses=0 text=",
    "clicks=1 magenta=1 presses=0 text=",
    "clicks=1 magenta=1 presses=1 text=a",
];

/// Serial milestones; the host validation below checks their figures.
pub(crate) const MARKERS: [MarkerStep<'static>; 19] = [
    MarkerStep::Ordered("[DESK] launch role=compositor"),
    MarkerStep::Ordered("[COMP] started output=1280x800"),
    MarkerStep::Ordered("[SHELL] ready"),
    MarkerStep::UnorderedGroup(&[APP_READY, "[WIN ] created", "[INPT] focus window"]),
    MarkerStep::Ordered(IDLE),
    MarkerStep::Ordered("[APP ] input state=changed clicks=1 magenta=0"),
    MarkerStep::Ordered("[APP ] input state=changed clicks=1 magenta=1 presses=0"),
    MarkerStep::Ordered("[APP ] input state=changed clicks=1 magenta=1 presses=1 text=a"),
    MarkerStep::Ordered("[WIN ] moved"),
    MarkerStep::UnorderedGroup(&[
        "[APP ] exit reason=closed",
        "[DESK] exit role=app",
        "[WIN ] closed windows=0",
    ]),
    MarkerStep::Ordered("[RSRC] compare after=app-exit"),
    MarkerStep::UnorderedGroup(&["[RSRC] stale handle", APP_READY, "[WIN ] created"]),
    MarkerStep::Ordered("[DESK] exit role=app"),
    MarkerStep::Ordered("[RSRC] compare after=app-exit"),
    MarkerStep::UnorderedGroup(&["[RSRC] stale handle", APP_READY, "[WIN ] created"]),
    MarkerStep::Ordered("[DESK] exit role=compositor"),
    MarkerStep::UnorderedGroup(&[
        "[COMP] started",
        "[SHELL] ready",
        "[RSRC] compare after=compositor-restart",
    ]),
    MarkerStep::UnorderedGroup(&[
        "[RSRC] stale handle",
        APP_READY,
        "[WIN ] created",
        "[INPT] focus window",
    ]),
    MarkerStep::Ordered(IDLE),
];

/// One boot of the desktop.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DesktopRun {
    pub(crate) lane: &'static str,
    pub(crate) features: &'static [&'static str],
    pub(crate) tier: QualityTier,
    /// `[DISP] backend=` value the kernel must pick.
    pub(crate) backend: &'static str,
    /// The backend that must not appear.
    pub(crate) other_backend: &'static str,
}

pub(crate) const RUNS: [DesktopRun; 2] = [
    DesktopRun {
        lane: "m10-desktop-virtio-gpu",
        features: &["m10-desktop-self-test"],
        tier: QualityTier::Q1,
        backend: "virtio-gpu",
        other_backend: "gop",
    },
    DesktopRun {
        lane: "m10-desktop-framebuffer",
        features: &["m10-desktop-self-test", "m10-desktop-q0"],
        tier: QualityTier::Q0,
        backend: "gop",
        other_backend: "virtio-gpu",
    },
];

impl DesktopRun {
    fn config(&self) -> VmLaunchConfig {
        match self.backend {
            "gop" => VmLaunchConfig {
                vga: Some("std"),
                ..input_lane_config()
            },
            _ => input_lane_config(),
        }
    }

    fn extra_args(&self) -> Vec<String> {
        match self.backend {
            "gop" => Vec::new(),
            _ => crate::m10_virtio_gpu::qemu_args(),
        }
    }

    fn tier_name(&self) -> &'static str {
        match self.tier {
            QualityTier::Q0 => "Q0",
            QualityTier::Q1 => "Q1",
            QualityTier::Q2 => "Q2",
            QualityTier::Q3 => "Q3",
        }
    }
}

/// What the script expects each named capture to show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PlannedCapture {
    pub(crate) name: &'static str,
    pub(crate) scene: Scene,
}

/// The QMP script plus the scenes it captures and the window origins the serial must report.
pub(crate) struct Plan {
    pub(crate) steps: Vec<ScriptStep>,
    pub(crate) captures: Vec<PlannedCapture>,
    /// `[WIN ] created` origins, one per app instance.
    pub(crate) created: [Point; 4],
    /// Where the drag leaves app 1's window.
    pub(crate) dragged: Point,
}

struct Builder {
    tier: QualityTier,
    steps: Vec<ScriptStep>,
    captures: Vec<PlannedCapture>,
    pointer: Point,
}

fn clamp_axis(value: i32, extent: u32) -> i32 {
    value.clamp(0, extent as i32 - 1)
}

/// Splits `delta` into commands of at most [`MAX_MOTION`] per axis.
pub(crate) fn motion_chunks(delta: Point) -> Vec<Point> {
    let span = delta.x.unsigned_abs().max(delta.y.unsigned_abs());
    let count = span.div_ceil(MAX_MOTION as u32).max(1) as i32;
    (1..=count)
        .map(|i| Point {
            x: delta.x * i / count - delta.x * (i - 1) / count,
            y: delta.y * i / count - delta.y * (i - 1) / count,
        })
        .filter(|chunk| *chunk != Point { x: 0, y: 0 })
        .collect()
}

impl Builder {
    fn await_line(&mut self, text: &'static str) {
        self.steps.push(ScriptStep::AwaitLine(text));
    }

    fn move_by(&mut self, delta: Point) {
        for chunk in motion_chunks(delta) {
            let mut actions = Vec::new();
            if chunk.x != 0 {
                actions.push(InputAction::Rel {
                    axis: Axis::X,
                    value: chunk.x,
                });
            }
            if chunk.y != 0 {
                actions.push(InputAction::Rel {
                    axis: Axis::Y,
                    value: chunk.y,
                });
            }
            self.steps.push(ScriptStep::Input(actions));
            self.pointer = Point {
                x: clamp_axis(self.pointer.x + chunk.x, OUTPUT.width),
                y: clamp_axis(self.pointer.y + chunk.y, OUTPUT.height),
            };
        }
    }

    fn move_to(&mut self, to: Point) {
        self.move_by(Point {
            x: to.x - self.pointer.x,
            y: to.y - self.pointer.y,
        });
    }

    /// Drives the pointer into the bottom-right corner so its position is known whatever the
    /// compositor's start position.
    fn home(&mut self) {
        self.move_by(Point {
            x: 2 * OUTPUT.width as i32,
            y: 2 * OUTPUT.height as i32,
        });
        self.pointer = Point {
            x: OUTPUT.width as i32 - 1,
            y: OUTPUT.height as i32 - 1,
        };
    }

    fn button(&mut self, down: bool) {
        self.steps.push(ScriptStep::Input(vec![InputAction::Button {
            button: MouseButton::Left,
            down,
        }]));
    }

    fn click_at(&mut self, at: Point) {
        self.move_to(at);
        self.button(true);
        self.button(false);
    }

    fn tap(&mut self, qcode: QCode) {
        self.steps
            .push(ScriptStep::Input(InputAction::tap(qcode).to_vec()));
    }

    fn capture(&mut self, name: &'static str, window: Option<Point>) {
        self.await_line(IDLE);
        self.steps.push(ScriptStep::Screendump {
            name,
            check: check_output_size,
        });
        self.captures.push(PlannedCapture {
            name,
            scene: Scene {
                tier: self.tier,
                window,
                pointer: self.pointer,
            },
        });
    }
}

fn check_output_size(shot: &Screenshot) -> Result<(), String> {
    if (shot.width(), shot.height()) == (OUTPUT.width, OUTPUT.height) {
        Ok(())
    } else {
        Err(format!(
            "desktop screendump is {}x{}, expected {}x{}",
            shot.width(),
            shot.height(),
            OUTPUT.width,
            OUTPUT.height
        ))
    }
}

pub(crate) fn plan(tier: QualityTier) -> Plan {
    let mut b = Builder {
        tier,
        steps: Vec::new(),
        captures: Vec::new(),
        pointer: Point {
            x: OUTPUT.width as i32 / 2,
            y: OUTPUT.height as i32 / 2,
        },
    };
    let first = window_origin(tier, 0);
    let layout = panel(tier);
    let chrome = chrome(tier);

    b.await_line(APP_READY);
    b.await_line(IDLE);
    b.home();
    b.capture("desktop", Some(first));

    b.click_at(center(translate(layout.increment, first)));
    b.await_line("clicks=1 magenta=0 presses=0");
    b.click_at(center(translate(layout.toggle, first)));
    b.await_line("clicks=1 magenta=1 presses=0");
    b.click_at(BACKGROUND_POINT);
    b.tap(QCode::A);
    b.await_line("clicks=1 magenta=1 presses=1 text=a");
    b.capture("input", Some(first));

    let grip = center(chrome.title_bar_rect(frame_rect(tier, first)));
    b.move_to(grip);
    b.button(true);
    b.move_by(DRAG);
    b.button(false);
    let dragged = Point {
        x: first.x + DRAG.x,
        y: first.y + DRAG.y,
    };
    b.capture("dragged", Some(dragged));

    let close = chrome.control_rect(frame_rect(tier, dragged), ChromeControl::Close);
    b.click_at(center(close));
    b.await_line("[RSRC] compare after=app-exit");
    b.await_line(APP_READY);
    let second = window_origin(tier, 1);
    b.capture("relaunched", Some(second));

    b.tap(QCode::F12);
    b.await_line("[RSRC] compare after=app-exit");
    b.await_line(APP_READY);
    let third = window_origin(tier, 2);
    b.capture("recovered", Some(third));

    b.tap(QCode::F11);
    b.await_line("[RSRC] compare after=compositor-restart");
    b.await_line(APP_READY);
    b.pointer = Point {
        x: OUTPUT.width as i32 / 2,
        y: OUTPUT.height as i32 / 2,
    };
    b.capture("restarted", Some(first));

    Plan {
        steps: b.steps,
        captures: b.captures,
        created: [first, second, third, first],
        dragged,
    }
}

fn fields(line: &str) -> impl Iterator<Item = (&str, &str)> {
    line.split_whitespace().filter_map(|t| t.split_once('='))
}

fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    fields(line).find(|(k, _)| *k == name).map(|(_, v)| v)
}

fn num(line: &str, name: &str) -> Result<i64, String> {
    field(line, name)
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| format!("no numeric {name}= in {line:?}"))
}

/// Lines from the first occurrence of `prefix`, trimmed to start at it.
fn lines_with<'a>(serial: &'a str, prefix: &str) -> Vec<&'a str> {
    serial
        .lines()
        .filter_map(|line| line.find(prefix).map(|at| line[at..].trim_end()))
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Launch<'a> {
    role: &'a str,
    pid: i64,
    generation: i64,
}

/// Serial-only checks of one run; `Err` names the first violated expectation.
pub(crate) fn validate_serial(serial: &str, run: &DesktopRun, plan: &Plan) -> Result<(), String> {
    for forbidden in [
        "[FAIL]",
        "[DESK] launch failed",
        "[DESK] wiring failed",
        "budget exhausted",
        "baseline=mismatch",
    ] {
        if let Some(line) = serial.lines().find(|line| line.contains(forbidden)) {
            return Err(format!("forbidden line: {}", line.trim_end()));
        }
    }

    let backend = format!("[DISP] backend={} ", run.backend);
    if !serial.contains(&backend) {
        return Err(format!("missing `{}`", backend.trim_end()));
    }
    if serial.contains(&format!("[DISP] backend={} ", run.other_backend)) {
        return Err(format!("unexpected `[DISP] backend={}`", run.other_backend));
    }

    let tier = run.tier_name();
    let comp_started = lines_with(serial, "[COMP] started");
    let comp_expected = format!("[COMP] started output=1280x800 tier={tier}");
    if comp_started.len() != 2 || comp_started.iter().any(|l| *l != comp_expected) {
        return Err(format!(
            "expected two `{comp_expected}`, got {comp_started:?}"
        ));
    }
    let shell_ready = lines_with(serial, "[SHELL] ready");
    let shell_expected = format!("[SHELL] ready rail=88x800 surfaces=2 dock=none tier={tier}");
    if shell_ready.len() != 2 || shell_ready.iter().any(|l| *l != shell_expected) {
        return Err(format!(
            "expected two `{shell_expected}`, got {shell_ready:?}"
        ));
    }
    let app_ready = lines_with(serial, APP_READY);
    let app_expected = format!("[APP ] ready size=520x360 tier={tier}");
    if app_ready.len() != 4 || app_ready.iter().any(|l| *l != app_expected) {
        return Err(format!("expected four `{app_expected}`, got {app_ready:?}"));
    }
    let authority = lines_with(serial, "[APP ] authority");
    if authority.len() != 4
        || authority
            .iter()
            .any(|l| *l != "[APP ] authority display=denied input=denied")
    {
        return Err(format!(
            "every app must be denied display and input authority: {authority:?}"
        ));
    }

    let launches = lines_with(serial, "[DESK] launch role=")
        .into_iter()
        .map(|line| {
            Ok(Launch {
                role: field(line, "role").unwrap_or(""),
                pid: num(line, "pid")?,
                generation: num(line, "gen")?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let roles: Vec<&str> = launches.iter().map(|l| l.role).collect();
    let expected_roles = [
        "compositor",
        "shell",
        "app",
        "app",
        "app",
        "compositor",
        "shell",
        "app",
    ];
    if roles != expected_roles {
        return Err(format!(
            "launch order {roles:?}, expected {expected_roles:?}"
        ));
    }
    let mut pids: Vec<i64> = launches.iter().map(|l| l.pid).collect();
    pids.sort_unstable();
    pids.dedup();
    if pids.len() != launches.len() {
        return Err(format!("launched pids are not distinct: {launches:?}"));
    }
    let (comp1, shell1, app1, app2, app3, comp2, app4) = (
        launches[0],
        launches[1],
        launches[2],
        launches[3],
        launches[4],
        launches[5],
        launches[7],
    );
    if comp1.generation == comp2.generation {
        return Err(format!(
            "restarted compositor reuses generation {}",
            comp1.generation
        ));
    }

    let exits: Vec<(String, i64, String, i64)> = lines_with(serial, "[DESK] exit role=")
        .into_iter()
        .map(|line| {
            Ok((
                field(line, "role").unwrap_or("").to_owned(),
                num(line, "pid")?,
                field(line, "reason").unwrap_or("").to_owned(),
                num(line, "vector")?,
            ))
        })
        .collect::<Result<_, String>>()?;
    let expected_exits = vec![
        ("app".to_owned(), app1.pid, "exit".to_owned(), 0x80),
        ("app".to_owned(), app2.pid, "crash".to_owned(), 6),
        ("compositor".to_owned(), comp1.pid, "crash".to_owned(), 6),
    ];
    if exits != expected_exits {
        return Err(format!("exits {exits:?}, expected {expected_exits:?}"));
    }
    if !serial.contains("[APP ] exit reason=closed") {
        return Err("app 1 did not log `[APP ] exit reason=closed`".into());
    }

    let mut reaped: Vec<(String, i64)> = Vec::new();
    for line in lines_with(serial, "[RSRC] reaped") {
        if num(line, "residue")? != 0 {
            return Err(format!("reaped process left resources: {line}"));
        }
        reaped.push((
            field(line, "role").unwrap_or("").to_owned(),
            num(line, "pid")?,
        ));
    }
    reaped.sort();
    let mut expected_reaped = vec![
        ("app".to_owned(), app1.pid),
        ("app".to_owned(), app2.pid),
        ("app".to_owned(), app3.pid),
        ("compositor".to_owned(), comp1.pid),
        ("shell".to_owned(), shell1.pid),
    ];
    expected_reaped.sort();
    if reaped != expected_reaped {
        return Err(format!("reaped {reaped:?}, expected {expected_reaped:?}"));
    }

    let stale = lines_with(serial, "[RSRC] stale handle");
    let stale_pids = stale
        .iter()
        .map(|line| {
            if field(line, "rejected") != Some("1") {
                return Err(format!("a predecessor's handle was accepted: {line}"));
            }
            num(line, "pid")
        })
        .collect::<Result<Vec<_>, String>>()?;
    if stale_pids != [app2.pid, app3.pid, app4.pid] {
        return Err(format!(
            "stale-handle probes for pids {stale_pids:?}, expected {:?}",
            [app2.pid, app3.pid, app4.pid]
        ));
    }

    validate_snapshots(serial)?;
    validate_idle(serial)?;
    validate_windows(serial, plan)?;
    validate_rows(serial)?;

    let inputs: Vec<&str> = lines_with(serial, INPUT_PREFIX)
        .into_iter()
        .map(|line| &line[INPUT_PREFIX.len()..])
        .collect();
    if inputs != EXPECTED_INPUT {
        return Err(format!(
            "app input changes {inputs:?}, expected exactly {EXPECTED_INPUT:?}"
        ));
    }
    let focused = lines_with(serial, "[APP ] focus active=1 keyboard=1").len();
    if focused < 4 {
        return Err(format!(
            "only {focused} app focus grants; every app instance needs one"
        ));
    }
    Ok(())
}

/// Each `[RSRC] compare` must match, and the snapshot logged just before it must equal the
/// baseline field by field (so a mismatch names the leaking counter).
fn validate_snapshots(serial: &str) -> Result<(), String> {
    let rsrc = lines_with(serial, "[RSRC] ");
    let baseline = rsrc
        .iter()
        .find(|l| l.starts_with("[RSRC] baseline "))
        .ok_or("no `[RSRC] baseline` line")?;
    let base: Vec<(&str, &str)> = fields(baseline).collect();
    if base.len() != 16 {
        return Err(format!("baseline has {} counters: {baseline}", base.len()));
    }
    let mut compares = Vec::new();
    for (at, line) in rsrc.iter().enumerate() {
        let Some(rest) = line.strip_prefix("[RSRC] compare ") else {
            continue;
        };
        compares.push(field(rest, "after").unwrap_or("").to_owned());
        if field(rest, "baseline") != Some("match") {
            return Err(format!("resources differ from baseline: {line}"));
        }
        let snapshot = rsrc[..at]
            .iter()
            .rev()
            .find(|l| l.starts_with("[RSRC] snapshot "))
            .ok_or_else(|| format!("no snapshot before `{line}`"))?;
        let differing: Vec<String> = fields(snapshot)
            .zip(&base)
            .filter(|(got, want)| got != *want)
            .map(|((k, got), (_, want))| format!("{k}={got} (baseline {want})"))
            .collect();
        if !differing.is_empty() {
            return Err(format!(
                "snapshot before `{line}` differs: {}",
                differing.join(", ")
            ));
        }
    }
    let expected = ["app-exit", "app-exit", "compositor-restart"];
    if compares != expected {
        return Err(format!(
            "resource compares {compares:?}, expected {expected:?}"
        ));
    }
    Ok(())
}

/// Every quiet stretch presented nothing and lasted the proof window.
fn validate_idle(serial: &str) -> Result<(), String> {
    let idle = lines_with(serial, IDLE);
    if idle.len() < 7 {
        return Err(format!("only {} `{IDLE}` lines", idle.len()));
    }
    for line in idle {
        if num(line, "presents")? != 0 {
            return Err(format!("the compositor presented while idle: {line}"));
        }
        if num(line, "ms")? < 500 {
            return Err(format!("idle stretch shorter than 500 ms: {line}"));
        }
    }
    Ok(())
}

fn point_of(line: &str) -> Result<Point, String> {
    Ok(Point {
        x: num(line, "x")? as i32,
        y: num(line, "y")? as i32,
    })
}

/// Windows open at the cascade origins and the drag ends where the pointer moved it.
fn validate_windows(serial: &str, plan: &Plan) -> Result<(), String> {
    let created = lines_with(serial, "[WIN ] created")
        .into_iter()
        .map(point_of)
        .collect::<Result<Vec<_>, String>>()?;
    if created != plan.created {
        return Err(format!(
            "windows created at {created:?}, expected {:?}",
            plan.created
        ));
    }
    let moved = lines_with(serial, "[WIN ] moved");
    let last = moved
        .last()
        .ok_or("the title-bar drag never moved the window")?;
    if point_of(last)? != plan.dragged {
        return Err(format!("drag ended at {last}, expected {:?}", plan.dragged));
    }
    let closed = lines_with(serial, "[WIN ] closed").len();
    if closed < 2 {
        return Err(format!("only {closed} `[WIN ] closed` lines"));
    }
    Ok(())
}

/// Before every app relaunch the compositor is back to the shell-only rows.
fn validate_rows(serial: &str) -> Result<(), String> {
    const SHELL_ONLY: &str = "[COMP] rows clients=1 surfaces=2 windows=0";
    let mut last_rows: Option<&str> = None;
    let mut app_launches = 0;
    for line in serial.lines() {
        if let Some(at) = line.find("[COMP] rows ") {
            last_rows = Some(line[at..].trim_end());
        }
        if line.contains("[DESK] launch role=compositor") {
            last_rows = None;
        }
        if line.contains("[DESK] launch role=app") {
            app_launches += 1;
            if app_launches > 1 && last_rows != Some(SHELL_ONLY) {
                return Err(format!(
                    "app launch {app_launches}: compositor rows {last_rows:?}, expected `{SHELL_ONLY}`"
                ));
            }
        }
    }
    Ok(())
}

/// Structural checks of every capture, plus the client content changing where the input went.
pub(crate) fn validate_captures(captures: &[Capture], plan: &Plan) -> Result<(), String> {
    for planned in &plan.captures {
        let capture = captures
            .iter()
            .find(|c| c.name == planned.name)
            .ok_or_else(|| format!("no `{}` screendump", planned.name))?;
        check_scene(&capture.screenshot, &planned.scene)
            .map_err(|reason| format!("{} ({}): {reason}", planned.name, capture.png.display()))?;
    }
    let shot = |name: &str| {
        captures
            .iter()
            .find(|c| c.name == name)
            .map(|c| &c.screenshot)
            .ok_or_else(|| format!("no `{name}` screendump"))
    };
    let (before, after) = (shot("desktop")?, shot("input")?);
    let first = plan.captures[0].scene;
    let origin = first.window.ok_or("first capture has no window")?;
    let layout = panel(first.tier);
    let cursors = [
        crate::m10_desktop_visual::cursor(first.pointer),
        crate::m10_desktop_visual::cursor(plan.captures[1].scene.pointer),
    ];
    for (what, rect) in [
        ("counter", layout.counter),
        ("toggle", layout.toggle),
        ("key indicator", layout.keycap),
        ("text line", layout.text_line),
    ] {
        if !region_changed(before, after, translate(rect, origin), &cursors) {
            return Err(format!(
                "the playground's {what} looks the same before and after input"
            ));
        }
    }
    Ok(())
}

/// `cargo xtask run-m10-desktop [--framebuffer]`: one of the lane's two machines, without the
/// self-test fault keys, for a person at a QEMU window.
pub(crate) fn interactive(
    framebuffer: bool,
) -> (&'static [&'static str], VmLaunchConfig, Vec<String>) {
    let run = RUNS[usize::from(framebuffer)];
    let features: &'static [&'static str] = if framebuffer {
        &["m10-desktop", "m10-desktop-q0"]
    } else {
        &["m10-desktop"]
    };
    (features, run.config(), run.extra_args())
}

pub(crate) fn run() -> Result<(), XtaskError> {
    crate::run_cargo_package_tests("clean-slate-desktop-shell", &[])?;
    crate::build_desktop_self_test_userspace()?;
    for desktop in RUNS {
        let plan = plan(desktop.tier);
        let run = run_kernel_lane_capturing(
            KernelLane {
                lane: desktop.lane,
                features: desktop.features,
                markers: MarkerSet::Steps(&MARKERS),
                timeout: TIMEOUT,
                config: desktop.config(),
                extra_args: desktop.extra_args(),
            },
            plan.steps,
        )?;
        let plan = Plan {
            steps: Vec::new(),
            ..plan
        };
        validate_serial(&run.output, &desktop, &plan)
            .map_err(|reason| XtaskError::Validation(format!("{}: {reason}", desktop.lane)))?;
        validate_captures(&run.captures, &plan)
            .map_err(|reason| XtaskError::Validation(format!("{}: {reason}", desktop.lane)))?;
        println!(
            "[M10.desktop] {} backend={} tier={} host validated {} captures",
            desktop.lane,
            desktop.backend,
            desktop.tier_name(),
            plan.captures.len()
        );
    }
    println!("[M10.9] PASS");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m10_desktop_visual::{content_rect, rail, DOCK_BAND_ROWS};
    use crate::marker_spec::MarkerTracker;
    use clean_slate_graphics::Rect;
    use clean_slate_ui::layout::RectExt;

    const SNAPSHOT: &str = "procs=3 caps=9 ws=0 ports=1 conns=1 qreq=0 qev=0 xfer=0 bufs=3 pages=750 maps=3 presenter=1 wake=1 consumer=1 scanout=2 gpu=2";

    /// A transcript a passing run would print (interleaved with unrelated kernel lines).
    fn transcript(run: &DesktopRun, plan: &Plan) -> String {
        let tier = run.tier_name();
        let [o1, o2, o3, o4] = plan.created;
        let comp = format!("[COMP] started output=1280x800 tier={tier}");
        let shell = format!("[SHELL] ready rail=88x800 surfaces=2 dock=none tier={tier}");
        let ready = format!("[APP ] ready size=520x360 tier={tier}");
        let auth = "[APP ] authority display=denied input=denied";
        let focus = "[APP ] focus active=1 keyboard=1";
        let rows = "[COMP] rows clients=1 surfaces=2 windows=0";
        let idle = "[IDLE ] quiet ms=500 presents=0 seq=7";
        let app = |pid: u32, gen: u32, at: Point, stale: Option<&str>| {
            let mut lines = vec![format!("[DESK] launch role=app pid={pid} gen={gen}")];
            if let Some(handle) = stale {
                lines.push(format!(
                    "[RSRC] stale handle pid={pid} handle={handle} rejected=1"
                ));
            }
            lines.extend([
                auth.to_owned(),
                ready.clone(),
                "[COMP] rows clients=2 surfaces=3 windows=1".to_owned(),
                format!("[WIN ] created x={} y={} windows=1", at.x, at.y),
                format!("[INPT] focus window x={} y={}", at.x, at.y),
                focus.to_owned(),
                idle.to_owned(),
            ]);
            lines
        };
        let mut lines: Vec<String> = vec![
            "[BOOT] clean-slate".into(),
            format!("[DISP] backend={} output=0 epoch=1", run.backend),
            "[DESK] launch role=compositor pid=10 gen=1".into(),
            "[DESK] launch role=shell pid=11 gen=1".into(),
            comp.clone(),
            shell.clone(),
            rows.into(),
            format!("[RSRC] baseline {SNAPSHOT}"),
        ];
        lines.extend(app(12, 1, o1, None));
        lines.extend([
            idle.into(),
            format!("{INPUT_PREFIX}{}", EXPECTED_INPUT[0]),
            format!("{INPUT_PREFIX}{}", EXPECTED_INPUT[1]),
            format!("{INPUT_PREFIX}{}", EXPECTED_INPUT[2]),
            idle.into(),
            "[WIN ] moved x=1 y=1".into(),
            format!("[WIN ] moved x={} y={}", plan.dragged.x, plan.dragged.y),
            idle.into(),
            "[APP ] exit reason=closed".into(),
            "[WIN ] closed windows=0".into(),
            "[DESK] exit role=app pid=12 reason=exit vector=128".into(),
            rows.into(),
            format!("[RSRC] snapshot {SNAPSHOT}"),
            "[RSRC] compare after=app-exit baseline=match".into(),
            "[RSRC] reaped role=app pid=12 residue=0".into(),
        ]);
        lines.extend(app(13, 1, o2, Some("0x10002")));
        lines.extend([
            "[DESK] exit role=app pid=13 reason=crash vector=6".into(),
            "[WIN ] closed windows=0".into(),
            rows.into(),
            format!("[RSRC] snapshot {SNAPSHOT}"),
            "[RSRC] compare after=app-exit baseline=match".into(),
            "[RSRC] reaped role=app pid=13 residue=0".into(),
        ]);
        lines.extend(app(14, 1, o3, Some("0x20002")));
        lines.extend([
            "[DESK] exit role=compositor pid=10 reason=crash vector=6".into(),
            "[DESK] launch role=compositor pid=15 gen=2".into(),
            "[DESK] launch role=shell pid=16 gen=2".into(),
            comp,
            shell,
            rows.into(),
            format!("[RSRC] snapshot {SNAPSHOT}"),
            "[RSRC] compare after=compositor-restart baseline=match".into(),
            "[RSRC] reaped role=compositor pid=10 residue=0".into(),
            "[RSRC] reaped role=app pid=14 residue=0".into(),
            "[RSRC] reaped role=shell pid=11 residue=0".into(),
        ]);
        lines.extend(app(17, 1, o4, Some("0x30002")));
        lines.join("\n") + "\n"
    }

    fn mutated(serial: &str, from: &str, to: &str) -> String {
        assert!(serial.contains(from), "{from:?}");
        serial.replacen(from, to, 1)
    }

    #[test]
    fn motion_is_chunked_within_the_ps2_range_and_sums_to_the_delta() {
        for delta in [
            Point { x: 2560, y: 1600 },
            Point { x: -341, y: 7 },
            Point { x: 200, y: -16 },
            Point { x: 0, y: -121 },
        ] {
            let chunks = motion_chunks(delta);
            assert!(chunks
                .iter()
                .all(|c| c.x.abs() <= MAX_MOTION && c.y.abs() <= MAX_MOTION));
            let sum = chunks.iter().fold(Point { x: 0, y: 0 }, |a, c| Point {
                x: a.x + c.x,
                y: a.y + c.y,
            });
            assert_eq!(sum, delta);
        }
        assert!(motion_chunks(Point { x: 0, y: 0 }).is_empty());
    }

    #[test]
    fn every_input_command_is_one_button_edge_or_bounded_motion() {
        for tier in [QualityTier::Q0, QualityTier::Q1] {
            for step in plan(tier).steps {
                let ScriptStep::Input(actions) = step else {
                    continue;
                };
                let buttons = actions
                    .iter()
                    .filter(|a| matches!(a, InputAction::Button { .. }))
                    .count();
                let motion = actions.iter().any(|a| matches!(a, InputAction::Rel { .. }));
                assert!(buttons <= 1 && !(buttons == 1 && motion), "{actions:?}");
                for action in &actions {
                    if let InputAction::Rel { value, .. } = action {
                        assert!(value.abs() <= MAX_MOTION, "{actions:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn the_script_ends_on_an_idle_await_then_the_last_capture() {
        let plan = plan(QualityTier::Q1);
        let names: Vec<&str> = plan.captures.iter().map(|c| c.name).collect();
        assert_eq!(
            names,
            [
                "desktop",
                "input",
                "dragged",
                "relaunched",
                "recovered",
                "restarted"
            ]
        );
        let n = plan.steps.len();
        assert!(matches!(
            plan.steps[n - 1],
            ScriptStep::Screendump {
                name: "restarted",
                ..
            }
        ));
        assert!(matches!(plan.steps[n - 2], ScriptStep::AwaitLine(IDLE)));
        let idle_awaits = plan
            .steps
            .iter()
            .filter(|s| matches!(s, ScriptStep::AwaitLine(IDLE)))
            .count();
        assert_eq!(idle_awaits, 7);
    }

    #[test]
    fn targets_land_on_their_controls_and_the_background_point_on_nothing() {
        for tier in [QualityTier::Q0, QualityTier::Q1] {
            let origin = window_origin(tier, 0);
            let layout = panel(tier);
            let content = content_rect(origin);
            for rect in [layout.increment, layout.toggle] {
                let target = center(translate(rect, origin));
                assert!(content.contains(target), "{tier:?} {rect:?}");
            }
            let chrome = chrome(tier);
            let frame = frame_rect(tier, origin);
            let grip = center(chrome.title_bar_rect(frame));
            assert!(ChromeControl::ALL
                .iter()
                .all(|c| !chrome.control_rect(frame, *c).contains(grip)));
            let plan = plan(tier);
            let dragged = frame_rect(tier, plan.dragged);
            let close = center(chrome.control_rect(dragged, ChromeControl::Close));
            assert!(chrome.visual_rect(dragged).contains(close));
            assert!(dragged.y >= 0, "the drag keeps the title bar on screen");
            for step in 0..3 {
                let visual = chrome.visual_rect(frame_rect(tier, window_origin(tier, step)));
                assert!(!visual.contains(BACKGROUND_POINT), "{tier:?} step {step}");
            }
            assert!(!rail(tier).contains(BACKGROUND_POINT));
            assert!(BACKGROUND_POINT.y < (OUTPUT.height - DOCK_BAND_ROWS) as i32);
        }
    }

    #[test]
    fn the_planned_pointer_tracks_the_moves() {
        let plan = plan(QualityTier::Q1);
        let origin = plan.created[0];
        assert_eq!(plan.captures[0].scene.pointer, Point { x: 1279, y: 799 });
        assert_eq!(plan.captures[1].scene.pointer, BACKGROUND_POINT);
        let grip =
            center(chrome(QualityTier::Q1).title_bar_rect(frame_rect(QualityTier::Q1, origin)));
        assert_eq!(
            plan.captures[2].scene.pointer,
            Point {
                x: grip.x + DRAG.x,
                y: grip.y + DRAG.y
            }
        );
        assert_eq!(plan.captures[5].scene.pointer, Point { x: 640, y: 400 });
    }

    #[test]
    fn a_passing_transcript_satisfies_markers_and_validation() {
        for run in RUNS {
            let plan = plan(run.tier);
            let serial = transcript(&run, &plan);
            assert!(
                MarkerTracker::from_steps(&MARKERS).consume(&serial),
                "{}",
                run.lane
            );
            assert_eq!(
                validate_serial(&serial, &run, &plan),
                Ok(()),
                "{}",
                run.lane
            );
        }
    }

    #[test]
    fn each_broken_expectation_is_reported() {
        let run = RUNS[0];
        let plan = plan(run.tier);
        let good = transcript(&run, &plan);
        let snapshot_line = format!("[RSRC] snapshot {SNAPSHOT}");
        let cases: Vec<(String, &str)> = vec![
            (good.replace("backend=virtio-gpu", "backend=gop"), "backend"),
            (format!("{good}[FAIL] something\n"), "forbidden"),
            (
                mutated(&good, "rejected=1", "rejected=0"),
                "predecessor's handle",
            ),
            (
                mutated(&good, "presents=0", "presents=2"),
                "presented while idle",
            ),
            (
                mutated(&good, "pid=12 residue=0", "pid=12 residue=3"),
                "left resources",
            ),
            (
                mutated(
                    &good,
                    &snapshot_line,
                    &snapshot_line.replace("maps=3", "maps=4"),
                ),
                "maps=4 (baseline 3)",
            ),
            (
                mutated(&good, "display=denied input=denied", "display=granted input=denied"),
                "authority",
            ),
            (
                good.replacen(
                    "[DESK] exit role=app pid=13",
                    &format!("{INPUT_PREFIX}clicks=2 magenta=1 presses=1 text=a\n[DESK] exit role=app pid=13"),
                    1,
                ),
                "app input changes",
            ),
            (
                mutated(&good, "reason=exit vector=128", "reason=crash vector=13"),
                "exits",
            ),
            (
                mutated(&good, "dock=none tier=Q1", "dock=bottom tier=Q1"),
                "SHELL",
            ),
            (
                good.replacen(
                    "[RSRC] snapshot",
                    "[COMP] rows clients=2 surfaces=3 windows=0\n[RSRC] snapshot",
                    1,
                ),
                "compositor rows",
            ),
            (
                mutated(
                    &good,
                    &format!("[WIN ] moved x={} y={}", plan.dragged.x, plan.dragged.y),
                    "[WIN ] moved x=5 y=5",
                ),
                "drag ended",
            ),
        ];
        for (serial, expected) in cases {
            let err = validate_serial(&serial, &run, &plan).unwrap_err();
            assert!(err.contains(expected), "expected `{expected}` in `{err}`");
        }
    }

    fn capture(name: &'static str, shot: Screenshot) -> Capture {
        Capture {
            name,
            png: std::path::PathBuf::from(format!("{name}.png")),
            screenshot: shot,
        }
    }

    /// The host render with client content filled in; `stamp` marks the panel's state rects.
    fn shot(scene: &Scene, stamp: bool) -> Screenshot {
        use crate::m10_desktop_visual::{render_rgb, Layers};
        let mut rgb = render_rgb(scene, Layers::Desktop { focused: true });
        let fill = |rgb: &mut Vec<u8>, rect: Rect, color: [u8; 3]| {
            for y in rect.y.max(0)..rect.bottom().min(OUTPUT.height as i32) {
                for x in rect.x.max(0)..rect.right().min(OUTPUT.width as i32) {
                    let p = Point { x, y };
                    if crate::m10_desktop_visual::cursor(scene.pointer).contains(p) {
                        continue;
                    }
                    let at = (y as usize * OUTPUT.width as usize + x as usize) * 3;
                    rgb[at..at + 3].copy_from_slice(&color);
                }
            }
        };
        if let Some(origin) = scene.window {
            fill(&mut rgb, content_rect(origin), [0x18, 0x1c, 0x24]);
            if stamp {
                let layout = panel(scene.tier);
                for rect in [
                    layout.counter,
                    layout.toggle,
                    layout.keycap,
                    layout.text_line,
                ] {
                    fill(&mut rgb, translate(rect, origin), [0xee, 0x22, 0xee]);
                }
            }
        }
        Screenshot::new(OUTPUT.width, OUTPUT.height, rgb).unwrap()
    }

    #[test]
    fn captures_pass_when_structure_matches_and_input_changed_the_panel() {
        let plan = plan(QualityTier::Q0);
        let captures: Vec<Capture> = plan
            .captures
            .iter()
            .map(|p| capture(p.name, shot(&p.scene, p.name != "desktop")))
            .collect();
        assert_eq!(validate_captures(&captures, &plan), Ok(()));

        let unchanged: Vec<Capture> = plan
            .captures
            .iter()
            .map(|p| capture(p.name, shot(&p.scene, false)))
            .collect();
        let err = validate_captures(&unchanged, &plan).unwrap_err();
        assert!(err.contains("counter"), "{err}");

        let mut misplaced = captures;
        let relaunched = plan.captures[3].scene;
        misplaced[3] = capture(
            "relaunched",
            shot(
                &Scene {
                    window: Some(plan.created[0]),
                    ..relaunched
                },
                true,
            ),
        );
        let err = validate_captures(&misplaced, &plan).unwrap_err();
        assert!(err.starts_with("relaunched"), "{err}");
    }
}
