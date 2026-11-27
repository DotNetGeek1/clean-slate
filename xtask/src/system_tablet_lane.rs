//! `cargo xtask test-system-tablet` (#313): the system image's desktop with a virtio keyboard
//! and tablet beside the PS/2 controller, driven over QMP on the hooks build with
//! `opt/clean-slate/desktop=q1-bare` (the desktop without the terminal) on a modern-only VirtIO-GPU.
//!
//! QMP input goes to QEMU's active handlers, and a virtio input device becomes the active one
//! for its event types once the guest sets it running, ahead of the PS/2 devices. So an
//! `abs` move, the buttons and the keys all reach the virtio devices with no `device` routing.
//!
//! 1. **Boot**: init's eight-row settle line and `test-system`'s eight-row checks, and the
//!    kernel's `[INPT] virtio keyboard=keyboard pointer=tablet`: both slots went to virtio.
//! 2. **Absolute clicks**: each move is one absolute `input-send-event` to the tablet. The
//!    compositor must report the pointer settled exactly at the target (no corrections, unlike
//!    the PS/2 lanes), and each button edge at that position with the expected hit. Increment,
//!    toggle and a background click, as in `test-system-desktop`.
//! 3. **Keyboard**: `a` through the virtio keyboard reaches the focused app.
//! 4. **Edges**: the tablet's corners land on the output's first and last pixels.
//! 5. **Whole transcript**: no row restarted.

use std::time::Duration;

use clean_slate_graphics::raw_input::{scale_abs_to_output, ABS_POINTER_MAX};
use clean_slate_graphics::Point;

use crate::m10_desktop_lane::{BACKGROUND_POINT, EXPECTED_INPUT};
use crate::m10_desktop_visual::{center, panel, translate, window_origin, OUTPUT};
use crate::qmp::input::QEMU_ABS_MAX;
use crate::qmp::{InputAction, MouseButton, QCode};
use crate::system_boot::{
    ensure_data_disk, field, number, start_shell_fixture_peer, virtio_input_qemu_args,
};
use crate::system_desktop::{
    check_baseline_boot, whole_line, Desktop, GIVE_UP_LINES, SETTLED_DESKTOP, VIRTIO_GPU_Q1,
};
use crate::system_desktop_faults::{desktop_config, Session};
use crate::system_shell::lines;
use crate::{workspace_root, VmLaunchConfig, XtaskError};

const HOOKS_FEATURE: &str = "system-test-hooks";
const LANE_TIMEOUT: Duration = Duration::from_secs(600);
const STEP_TIMEOUT: Duration = Duration::from_secs(60);
const SETTLE_WAIT: Duration = Duration::from_secs(20);
const EDGE_WAIT: Duration = Duration::from_secs(30);
const ARTIFACTS: &str = "system-tablet";
const SERIAL_LOG: &str = "system-tablet/serial.log";
const FORBIDDEN: [&str; 2] = [GIVE_UP_LINES[0], GIVE_UP_LINES[1]];
const VIRTIO_SEAT: &str = "[INPT] virtio keyboard=keyboard pointer=tablet";
const SETTLED: &str = "[INPT] pointer settled ";
const APP_INPUT: &str = "[APP ] input state=changed ";
/// Where a starting compositor puts the pointer.
const START: Point = Point {
    x: OUTPUT.width as i32 / 2,
    y: OUTPUT.height as i32 / 2,
};

/// The kernel's normalisation of a QEMU tablet value (`0..=QEMU_ABS_MAX`) to raw input's
/// `0..=ABS_POINTER_MAX`, as `virtio_input::AbsRange::normalise` does it.
fn kernel_normalise(value: i32) -> u32 {
    let span = i64::from(QEMU_ABS_MAX);
    let offset = i64::from(value.clamp(0, QEMU_ABS_MAX));
    ((offset * i64::from(ABS_POINTER_MAX) + span / 2) / span) as u32
}

/// Where the compositor puts the pointer for tablet value `value` on an `extent`-pixel axis.
fn guest_pixel(value: i32, extent: u32) -> i32 {
    scale_abs_to_output(kernel_normalise(value), extent)
}

/// The QEMU tablet value that lands on pixel `px`.
fn tablet_value(px: i32, extent: u32) -> Option<i32> {
    let estimate = (i64::from(px) * i64::from(QEMU_ABS_MAX) / i64::from(extent - 1)) as i32;
    (estimate - 4..=estimate + 4)
        .filter(|value| (0..=QEMU_ABS_MAX).contains(value))
        .find(|value| guest_pixel(*value, extent) == px)
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

/// The first complete `[INPT] button left <edge>` line in `segment`: its position and hit.
fn button_edge(segment: &str, edge: &str) -> Option<(Point, String)> {
    let (_, rest) = whole_line(segment, &format!("[INPT] button left {edge} "))?;
    let rest = format!(" {rest}");
    Some((
        Point {
            x: number(&rest, "x").ok()? as i32,
            y: number(&rest, "y").ok()? as i32,
        },
        field(&rest, "hit")?.to_owned(),
    ))
}

/// The system desktop boot, with both virtio devices claimed by the kernel.
fn check_boot(segment: &str) -> Result<Desktop, String> {
    if !lines(segment).any(|line| line.contains(SETTLED_DESKTOP)) {
        return Err(format!("init has not settled: no {SETTLED_DESKTOP:?}"));
    }
    if !lines(segment).any(|line| line.contains(VIRTIO_SEAT)) {
        return Err(format!(
            "no {VIRTIO_SEAT:?}: the virtio keyboard and tablet were not both brought up"
        ));
    }
    check_baseline_boot(segment, &VIRTIO_GPU_Q1)
}

struct Lane {
    session: Session,
    desktop: Desktop,
    pointer: Point,
}

impl Lane {
    fn fail<T>(&self, message: String) -> Result<T, XtaskError> {
        self.session.fail(message)
    }

    /// One absolute move to `target`, which the compositor must report settled exactly there.
    fn move_to(&mut self, what: &str, target: Point) -> Result<(), XtaskError> {
        let (Some(x), Some(y)) = (
            tablet_value(target.x, OUTPUT.width),
            tablet_value(target.y, OUTPUT.height),
        ) else {
            return self.fail(format!("{what}: no tablet value lands on {target:?}"));
        };
        self.move_abs(what, x, y, target)
    }

    fn move_abs(&mut self, what: &str, x: i32, y: i32, at: Point) -> Result<(), XtaskError> {
        if at == self.pointer {
            return Ok(());
        }
        self.session.mark();
        self.session.input(what, &InputAction::move_abs(x, y))?;
        let polled = self.session.poll(
            &format!("{what}: pointer settled at x={} y={}", at.x, at.y),
            SETTLE_WAIT,
            &mut |segment| match last_settled(segment) {
                Some(settled) if settled == at => Ok(()),
                Some(settled) => Err(format!(
                    "the pointer settled at x={} y={}",
                    settled.x, settled.y
                )),
                None => Err("no [INPT] pointer settled line since the move".to_owned()),
            },
        )?;
        if let Err(reason) = polled {
            return self.fail(format!(
                "{what}: one absolute move to tablet x={x} y={y} must settle at x={} y={}: {reason}",
                at.x, at.y
            ));
        }
        self.pointer = at;
        Ok(())
    }

    fn button(&mut self, what: &str, down: bool, hits: &[&str]) -> Result<(), XtaskError> {
        let edge = if down { "down" } else { "up" };
        self.session.mark();
        self.session.input(
            what,
            &[InputAction::Button {
                button: MouseButton::Left,
                down,
            }],
        )?;
        let (at, hit) = self.session.wait(
            &format!("{what}: button {edge}"),
            EDGE_WAIT,
            &mut |segment| {
                button_edge(segment, edge)
                    .ok_or_else(|| format!("no [INPT] button left {edge} line"))
            },
        )?;
        if at != self.pointer || !hits.contains(&hit.as_str()) {
            return self.fail(format!(
                "{what}: the left button {edge} landed at x={} y={} hit={hit}, expected x={} y={} hit={}",
                at.x,
                at.y,
                self.pointer.x,
                self.pointer.y,
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

    fn await_app_input(&mut self, what: &str, state: &str) -> Result<(), XtaskError> {
        let line = format!(
            "[IPC ] console pid={}: {APP_INPUT}{state}",
            self.desktop.rows[2].pid
        );
        self.session.wait(what, STEP_TIMEOUT, &mut |segment| {
            if lines(segment).any(|l| l == line) {
                Ok(())
            } else {
                Err(format!("no {line:?}"))
            }
        })
    }
}

fn config(disk: &std::path::Path, fixture_port: u16) -> VmLaunchConfig {
    let mut config = desktop_config(disk, fixture_port, &VIRTIO_GPU_Q1);
    config.extra_args.extend(virtio_input_qemu_args());
    config
}

fn run_on(disk: &std::path::Path, fixture_port: u16) -> Result<(), XtaskError> {
    let mut session = Session::start(
        &[HOOKS_FEATURE],
        config(disk, fixture_port),
        true,
        &FORBIDDEN,
        LANE_TIMEOUT,
        SERIAL_LOG,
    )?;
    println!("[STB ] step: boot");
    let desktop = session.wait("boot", STEP_TIMEOUT * 3, &mut check_boot)?;
    let mut lane = Lane {
        session,
        desktop,
        pointer: START,
    };

    println!("\n[STB ] step: absolute clicks");
    let tier = VIRTIO_GPU_Q1.tier;
    let first = window_origin(tier, 0);
    let layout = panel(tier);
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

    println!("\n[STB ] step: keyboard");
    lane.session.mark();
    lane.session.input("key a", &InputAction::tap(QCode::A))?;
    lane.await_app_input("key a", EXPECTED_INPUT[2])?;

    println!("\n[STB ] step: edges");
    let far = Point {
        x: OUTPUT.width as i32 - 1,
        y: OUTPUT.height as i32 - 1,
    };
    lane.move_abs("far corner", QEMU_ABS_MAX, QEMU_ABS_MAX, far)?;
    lane.move_abs("near corner", 0, 0, Point { x: 0, y: 0 })?;

    let transcript = lane.session.transcript();
    if let Some(line) = lines(&transcript).find(|line| line.contains("[SUP ] restart service=")) {
        return lane.fail(format!("a row restarted: {line:?}"));
    }
    lane.session.finish()?;
    Ok(())
}

/// `cargo xtask test-system-tablet`, on a fresh lane-owned disk.
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
    println!("[STB ] test-system-tablet PASS");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_output_pixel_has_a_tablet_value() {
        for extent in [OUTPUT.width, OUTPUT.height] {
            for px in 0..extent as i32 {
                let value = tablet_value(px, extent)
                    .unwrap_or_else(|| panic!("pixel {px} of {extent} is unreachable"));
                assert_eq!(guest_pixel(value, extent), px);
            }
        }
        assert_eq!(
            guest_pixel(QEMU_ABS_MAX, OUTPUT.width),
            OUTPUT.width as i32 - 1
        );
        assert_eq!(guest_pixel(0, OUTPUT.height), 0);
    }

    #[test]
    fn button_lines_parse_position_and_hit() {
        let segment = "[IPC ] console pid=4: [INPT] button left down x=12 y=34 hit=content\n";
        assert_eq!(
            button_edge(segment, "down"),
            Some((Point { x: 12, y: 34 }, "content".to_owned()))
        );
        assert_eq!(button_edge(segment, "up"), None);
        assert_eq!(
            last_settled("[INPT] pointer settled x=1 y=2\n[INPT] pointer settled x=3 y=4"),
            Some(Point { x: 1, y: 2 }),
            "a line still being printed is not read"
        );
    }

    #[test]
    fn a_boot_without_both_virtio_devices_fails_by_name() {
        let error = check_boot(&format!("{SETTLED_DESKTOP}\n")).unwrap_err();
        assert!(error.contains("virtio keyboard"), "{error}");
        let lane = config(std::path::Path::new("DISK.img"), 4000);
        assert!(lane
            .extra_args
            .windows(2)
            .any(|pair| pair == ["-device", "virtio-keyboard-pci,id=cs-keyboard"]));
    }
}
