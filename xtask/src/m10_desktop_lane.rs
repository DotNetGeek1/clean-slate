//! M10 #118/#119 desktop lane (`cargo xtask test-m10-desktop`), on the system image since #218
//! S6f.
//!
//! Boots the system image's hooks build twice with the desktop boot option: `q1` on a
//! modern-only VirtIO-GPU, and `q0` on the `-vga std` GOP framebuffer. Init launches the
//! compositor, the desktop shell and the app from its manifest rows; the kernel has no desktop
//! launch policy of its own. Each boot runs `test-system-desktop`'s closed-loop driver
//! ([`crate::system_desktop_lane`]): the click, key, drag and close script, the app, desktop
//! shell and compositor faults, resource baselines, quiet stretches without presents and
//! screendumps checked against a host render ([`crate::m10_desktop_visual`]).
//!
//! This module keeps the M10 script's shared pieces: its targets, the input the first app must
//! log, motion chunking and the screendump checks.

use clean_slate_graphics::Point;

use crate::m10_desktop_visual::{check_scene, panel, region_changed, translate, Scene};
use crate::qmp::lane::Capture;
use crate::system_desktop::{FRAMEBUFFER_Q0, VIRTIO_GPU_Q1};
use crate::system_desktop_lane::{run_each, LaneRun};
use crate::XtaskError;

/// Largest per-axis motion in one `input-send-event`; QEMU's PS/2 mouse saturates at ±127.
pub(crate) const MAX_MOTION: i32 = 120;

/// A workspace point left of and below the first window, away from every control.
pub(crate) const BACKGROUND_POINT: Point = Point { x: 400, y: 650 };

/// Title-bar drag offset.
pub(crate) const DRAG: Point = Point { x: 200, y: -16 };

/// The three state changes app 1 must log, in order; no other app instance logs any. The
/// background click and the key typed with the pointer off the window prove delivery follows
/// focus, not the pointer.
pub(crate) const EXPECTED_INPUT: [&str; 3] = [
    "clicks=1 magenta=0 presses=0 text=",
    "clicks=1 magenta=1 presses=0 text=",
    "clicks=1 magenta=1 presses=1 text=a",
];

/// #309: after `a`, the lane holds `s` for [`HELD_KEY_HOLD`]. The press logs `text=as` with
/// `presses=2`, and every compositor repeat adds an `s` without a press, so each repeat logs one
/// more line. The 64-byte console line cuts the text after `ass`, so the lane counts lines
/// rather than reading the run; printing coalesces a burst, so the count is a lower bound.
pub(crate) const HELD_KEY_INPUT: &str = "clicks=1 magenta=1 presses=2 text=a";
/// How long the lane holds `s`: twice the compositor's 500 ms repeat delay.
pub(crate) const HELD_KEY_HOLD: std::time::Duration = std::time::Duration::from_millis(1_000);
/// Repeats the hold must produce at least (about 15 are due at 30 per second).
pub(crate) const HELD_KEY_MIN_REPEATS: usize = 3;

/// True for an app input line logged while `s` was held (its text may be cut short).
pub(crate) fn is_held_key_line(line: &str) -> bool {
    line.strip_prefix(HELD_KEY_INPUT)
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b == b's'))
}

/// The app 1 lines after [`EXPECTED_INPUT`]: the press (`text=as`), then at least
/// [`HELD_KEY_MIN_REPEATS`] repeat lines, and nothing else.
pub(crate) fn check_held_key(lines: &[&str]) -> Result<(), String> {
    let press = format!("{HELD_KEY_INPUT}s");
    match lines.first() {
        Some(first) if *first == press => {}
        other => {
            return Err(format!(
                "the press of `s` should log {press:?} first, got {other:?}"
            ))
        }
    }
    if let Some(line) = lines.iter().find(|line| !is_held_key_line(line)) {
        return Err(format!(
            "{line:?} is not a held-`s` line ({HELD_KEY_INPUT}s...)"
        ));
    }
    let repeats = lines.len() - 1;
    if repeats < HELD_KEY_MIN_REPEATS {
        return Err(format!(
            "holding `s` for {HELD_KEY_HOLD:?} logged {repeats} repeats, expected at least \
             {HELD_KEY_MIN_REPEATS}: {lines:?}"
        ));
    }
    Ok(())
}

/// The lane's two machines.
const RUNS: [LaneRun; 2] = [
    LaneRun {
        machine: VIRTIO_GPU_Q1,
        artifacts: "m10-desktop-virtio-gpu",
        serial_log: "m10-desktop-virtio-gpu/serial.log",
    },
    LaneRun {
        machine: FRAMEBUFFER_Q0,
        artifacts: "m10-desktop-framebuffer",
        serial_log: "m10-desktop-framebuffer/serial.log",
    },
];

/// What the script expects each named capture to show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PlannedCapture {
    pub(crate) name: &'static str,
    pub(crate) scene: Scene,
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

/// Structural checks of every capture against its `planned` scene, plus the client content
/// changing where the input went (`planned` starts with `desktop` and `input`).
pub(crate) fn validate_captures(
    captures: &[Capture],
    planned: &[PlannedCapture],
) -> Result<(), String> {
    for expected in planned {
        let capture = captures
            .iter()
            .find(|c| c.name == expected.name)
            .ok_or_else(|| format!("no `{}` screendump", expected.name))?;
        check_scene(&capture.screenshot, &expected.scene)
            .map_err(|reason| format!("{} ({}): {reason}", expected.name, capture.png.display()))?;
    }
    let shot = |name: &str| {
        captures
            .iter()
            .find(|c| c.name == name)
            .map(|c| &c.screenshot)
            .ok_or_else(|| format!("no `{name}` screendump"))
    };
    let (before, after) = (shot("desktop")?, shot("input")?);
    let [first, second, ..] = planned else {
        return Err("fewer than two planned captures".to_owned());
    };
    let origin = first.scene.window.ok_or("first capture has no window")?;
    let layout = panel(first.scene.tier);
    let cursors = [
        crate::m10_desktop_visual::cursor(first.scene.pointer),
        crate::m10_desktop_visual::cursor(second.scene.pointer),
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

pub(crate) fn run() -> Result<(), XtaskError> {
    crate::run_cargo_package_tests("clean-slate-desktop-shell", &[])?;
    run_each(&RUNS)?;
    println!("[M10.9] PASS");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m10_desktop_visual::{
        center, chrome, content_rect, frame_rect, rail, window_origin, DOCK_BAND_ROWS, OUTPUT,
    };
    use crate::qmp::image::Screenshot;
    use clean_slate_graphics::Rect;
    use clean_slate_ui::layout::RectExt;
    use clean_slate_ui::{ChromeControl, ChromeStyle, QualityTier};

    #[test]
    fn held_key_lines_are_the_press_then_enough_repeats() {
        let line = |n: usize| format!("{HELD_KEY_INPUT}{}", "s".repeat(n));
        // What the console shows: the text is cut after `ass`.
        let owned = [line(1), line(2), line(2), line(2)];
        let good: Vec<&str> = owned.iter().map(String::as_str).collect();
        assert_eq!(check_held_key(&good), Ok(()));
        assert!(check_held_key(&good[..3]).is_err(), "too few repeats");
        assert!(check_held_key(&good[1..]).is_err(), "no press line");
        let other = [
            line(1),
            line(2),
            line(2),
            "clicks=2 magenta=1 presses=2 text=as".to_owned(),
        ];
        let other: Vec<&str> = other.iter().map(String::as_str).collect();
        assert!(check_held_key(&other).is_err());
        assert!(check_held_key(&[]).is_err(), "the hold must be logged");
        assert!(is_held_key_line(&line(2)));
        assert!(!is_held_key_line(HELD_KEY_INPUT));
    }

    fn dragged(tier: QualityTier) -> Point {
        let first = window_origin(tier, 0);
        Point {
            x: first.x + DRAG.x,
            y: first.y + DRAG.y,
        }
    }

    /// The captures the driver takes, in order, with the pointer parked on the background.
    fn plan(tier: QualityTier) -> Vec<PlannedCapture> {
        [
            ("desktop", window_origin(tier, 0)),
            ("input", window_origin(tier, 0)),
            ("dragged", dragged(tier)),
            ("relaunched", window_origin(tier, 1)),
            ("recovered", window_origin(tier, 2)),
            ("restarted", window_origin(tier, 0)),
        ]
        .map(|(name, window)| PlannedCapture {
            name,
            scene: Scene {
                tier,
                window: Some(window),
                pointer: BACKGROUND_POINT,
            },
        })
        .to_vec()
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
            let dragged = frame_rect(tier, dragged(tier));
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
    fn captures_pass_when_structure_matches_and_input_changed_the_panel() {
        for tier in [QualityTier::Q0, QualityTier::Q1] {
            let plan = plan(tier);
            let captures: Vec<Capture> = plan
                .iter()
                .map(|p| capture(p.name, shot(&p.scene, p.name != "desktop")))
                .collect();
            assert_eq!(validate_captures(&captures, &plan), Ok(()), "{tier:?}");

            let unchanged: Vec<Capture> = plan
                .iter()
                .map(|p| capture(p.name, shot(&p.scene, false)))
                .collect();
            let err = validate_captures(&unchanged, &plan).unwrap_err();
            assert!(err.contains("counter"), "{err}");

            let mut misplaced = captures;
            let relaunched = plan[3].scene;
            misplaced[3] = capture(
                "relaunched",
                shot(
                    &Scene {
                        window: Some(window_origin(tier, 0)),
                        ..relaunched
                    },
                    true,
                ),
            );
            let err = validate_captures(&misplaced, &plan).unwrap_err();
            assert!(err.starts_with("relaunched"), "{err}");
        }
    }

    #[test]
    fn the_lane_boots_both_machines_at_their_tiers() {
        assert_eq!(RUNS.map(|run| run.machine), [VIRTIO_GPU_Q1, FRAMEBUFFER_Q0]);
        assert_eq!(VIRTIO_GPU_Q1.tier_name(), "Q1");
        assert_eq!(FRAMEBUFFER_Q0.tier_name(), "Q0");
        assert_eq!(RUNS.map(|run| run.machine.framebuffer), [false, true]);
    }
}
