//! `cargo xtask test-system-display` (#314): the system image's desktop at a size other than the
//! reference mode, on the hooks build with `opt/clean-slate/display=1024x768`, a virtio tablet
//! (so the lane can put the pointer where the screen check expects it) and the desktop without
//! the terminal.
//!
//! 1. **GOP** (`-vga std`, `q0-bare`): the firmware sets the configured mode before
//!    `ExitBootServices`, so the compositor starts at 1024×768 and never changes mode. The boot
//!    passes `test-system`'s eight-row checks at that size, the app's window is placed by the
//!    cascade in the 1024×768 window area, and a capture matches the host render at 1024×768.
//! 2. **VirtIO-GPU** (`q1-bare`): the device starts at the reference mode and offers the
//!    configured size as preferred, so the compositor asks for 1024×768 at start (the change can
//!    land before or after its `started` line). Once the output runs 1024×768 a capture is
//!    checked. Then the kernel hook byte Ctrl-V (`0x16`) asks the display for its smallest other
//!    mode (640×480) behind the compositor's back: the compositor must report the output changed,
//!    the app's whole frame must be inside the smaller output where the compositor moved it, the
//!    shell's rail must be laid out again for 480 rows, and a capture must match the host render
//!    at 640×480.
//! 3. **Whole transcript**: no row restarted, nothing gave up.
//!
//! Where the app's window is comes from the compositor's `[WIN ] created` line and each later
//! `[COMP] output changed`, replayed through the compositor's own `wm::fit_inside`. The pointer
//! is moved to the 1024×768 output's far corner with one absolute tablet move; after the change
//! the lane expects it clamped to the 640×480 corner without moving it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use clean_slate_compositor::wm::fit_inside;
use clean_slate_graphics::{Point, Size};

use crate::m10_desktop_visual::{check_scene, frame_rect, window_origin_at, Scene, OUTPUT};
use crate::qmp::input::QEMU_ABS_MAX;
use crate::qmp::InputAction;
use crate::system_boot::{
    ensure_data_disk, number, start_shell_fixture_peer, virtio_input_qemu_args,
};
use crate::system_desktop::{
    check_baseline_boot_at, DesktopMachine, FRAMEBUFFER_Q0, GIVE_UP_LINES, SETTLED_DESKTOP,
    VIRTIO_GPU_Q1,
};
use crate::system_desktop_faults::{desktop_config, Session};
use crate::system_shell::lines;
use crate::system_tablet_lane::last_settled;
use crate::{workspace_root, xtask_artifact_root, VmLaunchConfig, XtaskError};

const HOOKS_FEATURE: &str = "system-test-hooks";
const LANE_TIMEOUT: Duration = Duration::from_secs(600);
const STEP_TIMEOUT: Duration = Duration::from_secs(60);
const SETTLE_WAIT: Duration = Duration::from_secs(20);
const FORBIDDEN: [&str; 2] = [GIVE_UP_LINES[0], GIVE_UP_LINES[1]];
const VIRTIO_SEAT: &str = "[INPT] virtio keyboard=keyboard pointer=tablet";
/// The hooks build's quiet proof: nothing ran for half a second and nothing was presented.
const QUIET: &str = "[IDLE ] quiet ";
const STARTED: &str = "[COMP] started output=";
const CHANGED: &str = "[COMP] output changed output=";
const CREATED: &str = "[WIN ] created ";
/// The configured size, a standard mode both OVMF's QEMU video driver and the VirtIO-GPU offer.
const CONFIGURED: Size = Size {
    width: 1024,
    height: 768,
};
const DISPLAY_OPTION: &str = "name=opt/clean-slate/display,string=1024x768";
/// The VirtIO-GPU's smallest standard mode: what the Ctrl-V hook asks for.
const SMALLEST: Size = Size {
    width: 640,
    height: 480,
};
/// `kernel/src/service/system_test_hooks.rs` `DISPLAY_MODE_BYTE`.
const DISPLAY_MODE_BYTE: &[u8] = b"\x16";
const HOOK_SET: &str = "[HOOK] display mode 640x480 requested status=ok";

/// One boot of the lane.
#[derive(Clone, Copy, Debug)]
struct Run {
    machine: DesktopMachine,
    artifacts: &'static str,
    serial_log: &'static str,
    /// Sizes the compositor may report at start: on VirtIO-GPU the device's boot mode too.
    started: &'static [Size],
}

const GOP_RUN: Run = Run {
    machine: FRAMEBUFFER_Q0,
    artifacts: "system-display/framebuffer",
    serial_log: "system-display/framebuffer/serial.log",
    started: &[CONFIGURED],
};

const VIRTIO_RUN: Run = Run {
    machine: VIRTIO_GPU_Q1,
    artifacts: "system-display/virtio-gpu",
    serial_log: "system-display/virtio-gpu/serial.log",
    started: &[OUTPUT, CONFIGURED],
};

fn parse_size(text: &str) -> Option<Size> {
    let (width, height) = text.split_once('x')?;
    Some(Size {
        width: width.parse().ok()?,
        height: height.trim_end().parse().ok()?,
    })
}

/// What the compositor's lines say about the output and its one window, in transcript order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Replay {
    output: Size,
    /// Content origin of the window, once created.
    window: Option<Point>,
    /// `[COMP] output changed` lines seen.
    changes: usize,
}

/// Replays the compositor's complete lines in `transcript`: `[COMP] started`, each
/// `[COMP] output changed` (moving the window as `fit_windows` does) and `[WIN ] created`.
fn replay(transcript: &str, machine: &DesktopMachine) -> Result<Replay, String> {
    let complete = transcript.rfind('\n').map_or("", |end| &transcript[..=end]);
    let mut state: Option<Replay> = None;
    for line in lines(complete) {
        if let Some(at) = line.find(STARTED) {
            let rest = &line[at + STARTED.len()..];
            let size = rest
                .split_whitespace()
                .next()
                .and_then(parse_size)
                .ok_or_else(|| format!("unreadable {line:?}"))?;
            if state.is_some() {
                return Err(format!("the compositor started twice: {line:?}"));
            }
            state = Some(Replay {
                output: size,
                window: None,
                changes: 0,
            });
        } else if let Some(at) = line.find(CHANGED) {
            let size = parse_size(&line[at + CHANGED.len()..])
                .ok_or_else(|| format!("unreadable {line:?}"))?;
            let now = state
                .as_mut()
                .ok_or_else(|| format!("{line:?} before the compositor started"))?;
            now.output = size;
            now.changes += 1;
            if let Some(origin) = now.window {
                let frame = frame_rect(machine.tier, origin);
                let offset = Point {
                    x: frame.x - origin.x,
                    y: frame.y - origin.y,
                };
                let frame_size = Size {
                    width: frame.width,
                    height: frame.height,
                };
                now.window = Some(fit_inside(offset, frame_size, origin, size));
            }
        } else if let Some(at) = line.find(CREATED) {
            let rest = format!(" {}", &line[at + CREATED.len()..]);
            let origin = Point {
                x: number(&rest, "x")? as i32,
                y: number(&rest, "y")? as i32,
            };
            let now = state
                .as_mut()
                .ok_or_else(|| format!("{line:?} before the compositor started"))?;
            if now.window.is_some() {
                return Err(format!("a second window was created: {line:?}"));
            }
            now.window = Some(origin);
        }
    }
    state.ok_or_else(|| format!("no {STARTED:?} line"))
}

/// The replayed state once the output runs `output` and the window exists.
fn settled_at(transcript: &str, run: &Run, output: Size) -> Result<Replay, String> {
    let state = replay(transcript, &run.machine)?;
    if state.output != output {
        return Err(format!(
            "the output runs {}x{}, waiting for {}x{}",
            state.output.width, state.output.height, output.width, output.height
        ));
    }
    if state.window.is_none() {
        return Err(format!("no {CREATED:?} line yet"));
    }
    Ok(state)
}

/// `true` when the window's whole frame (`content` at `origin` plus the chrome) is on `output`.
fn frame_inside(run: &Run, origin: Point, output: Size) -> bool {
    let frame = frame_rect(run.machine.tier, origin);
    frame.x >= 0
        && frame.y >= 0
        && i64::from(frame.x) + i64::from(frame.width) <= i64::from(output.width)
        && i64::from(frame.y) + i64::from(frame.height) <= i64::from(output.height)
}

fn check_boot(segment: &str, run: &Run) -> Result<(), String> {
    if !lines(segment).any(|line| line.contains(SETTLED_DESKTOP)) {
        return Err(format!("init has not settled: no {SETTLED_DESKTOP:?}"));
    }
    if !lines(segment).any(|line| line.contains(VIRTIO_SEAT)) {
        return Err(format!(
            "no {VIRTIO_SEAT:?}: the virtio keyboard and tablet were not both brought up"
        ));
    }
    check_baseline_boot_at(segment, &run.machine, run.started).map(|_| ())
}

fn config(disk: &Path, fixture_port: u16, run: &Run) -> VmLaunchConfig {
    let mut config = desktop_config(disk, fixture_port, &run.machine);
    config.extra_args.extend(virtio_input_qemu_args());
    config
        .extra_args
        .extend(["-fw_cfg".to_owned(), DISPLAY_OPTION.to_owned()]);
    config
}

struct Lane {
    run: Run,
    session: Session,
    run_dir: PathBuf,
    /// Where the lane last put the pointer.
    pointer: Option<Point>,
}

/// The far corner of `output`.
fn corner(output: Size) -> Point {
    Point {
        x: output.width as i32 - 1,
        y: output.height as i32 - 1,
    }
}

/// Where the compositor's `Seat::warp` puts a pointer at `at` when the output becomes `output`.
fn clamped(at: Point, output: Size) -> Point {
    let far = corner(output);
    Point {
        x: at.x.clamp(0, far.x),
        y: at.y.clamp(0, far.y),
    }
}

impl Lane {
    fn fail<T>(&self, message: String) -> Result<T, XtaskError> {
        self.session.fail(message)
    }

    /// Waits until the replayed output is `output` with the window placed.
    fn await_output(&mut self, what: &str, output: Size) -> Result<Replay, XtaskError> {
        let resume = self.session.offset();
        self.session.mark_at(0);
        let run = self.run;
        let state = self.session.wait(what, STEP_TIMEOUT, &mut |segment| {
            settled_at(segment, &run, output)
        });
        self.session.mark_at(resume);
        state
    }

    /// One absolute tablet move to the far corner of `output`, settled there. A pointer the
    /// lane left at the corner of a larger output is already there: the compositor clamped it
    /// onto the smaller one, and a move to where it is reports nothing.
    fn pointer_to_corner(&mut self, what: &str, output: Size) -> Result<Point, XtaskError> {
        let corner = corner(output);
        if self.pointer.map(|at| clamped(at, output)) == Some(corner) {
            self.pointer = Some(corner);
            return Ok(corner);
        }
        self.session.mark();
        self.session
            .input(what, &InputAction::move_abs(QEMU_ABS_MAX, QEMU_ABS_MAX))?;
        let polled = self.session.poll(
            &format!("{what}: pointer settled at the corner"),
            SETTLE_WAIT,
            &mut |segment| match last_settled(segment) {
                Some(settled) if settled == corner => Ok(()),
                Some(settled) => Err(format!(
                    "the pointer settled at x={} y={}",
                    settled.x, settled.y
                )),
                None => Err("no [INPT] pointer settled line since the move".to_owned()),
            },
        )?;
        if let Err(reason) = polled {
            return self.fail(format!(
                "{what}: a tablet move to its maximum must settle at x={} y={}: {reason}",
                corner.x, corner.y
            ));
        }
        self.pointer = Some(corner);
        Ok(corner)
    }

    /// A quiet, stable screendump of `scene`, checked against the host render.
    fn capture(&mut self, name: &str, scene: Scene) -> Result<(), XtaskError> {
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
        let png = self.run_dir.join(format!("{name}.png"));
        last.write_png(&png)?;
        println!("\n[SDP ] captured `{name}` -> {}", png.display());
        if !stable {
            return self.fail(format!(
                "screendump `{name}`: the frame never stopped changing"
            ));
        }
        if let Err(reason) = check_scene(&last, &scene) {
            return self.fail(format!("screendump `{name}` ({scene:?}): {reason}"));
        }
        Ok(())
    }

    /// The pointer to the corner, then a capture of the desktop at `state`.
    fn check_desktop(&mut self, name: &str, state: Replay) -> Result<(), XtaskError> {
        let Some(window) = state.window else {
            return self.fail(format!("{name}: no window"));
        };
        if !frame_inside(&self.run, window, state.output) {
            return self.fail(format!(
                "{name}: the window's frame {:?} is not inside the {}x{} output",
                frame_rect(self.run.machine.tier, window),
                state.output.width,
                state.output.height
            ));
        }
        let pointer = self.pointer_to_corner(name, state.output)?;
        self.session.mark();
        self.capture(
            name,
            Scene {
                tier: self.run.machine.tier,
                window: Some(window),
                minimized: false,
                pointer,
                output: state.output,
            },
        )
    }
}

fn run_on(run: Run, disk: &Path, fixture_port: u16) -> Result<(), XtaskError> {
    let run_dir = xtask_artifact_root().join(run.artifacts);
    std::fs::create_dir_all(&run_dir)?;
    let session = Session::start(
        &[HOOKS_FEATURE],
        config(disk, fixture_port, &run),
        true,
        &FORBIDDEN,
        LANE_TIMEOUT,
        run.serial_log,
    )?;
    let mut lane = Lane {
        run,
        session,
        run_dir,
        pointer: None,
    };
    let name = run.machine.name;
    println!("[SDP ] {name}: boot at 1024x768");
    lane.session
        .wait("boot", STEP_TIMEOUT * 3, &mut |segment| {
            check_boot(segment, &run)
        })?;
    let state = lane.await_output("the configured output", CONFIGURED)?;
    if run.machine.framebuffer {
        // GOP set the mode before the kernel ran: nothing changes it afterwards, and the window
        // is where the cascade puts it on a 1024x768 desktop.
        if state.changes != 0 {
            return lane.fail("the GOP output changed mode after boot".to_owned());
        }
        let placed = window_origin_at(run.machine.tier, CONFIGURED, 0);
        if state.window != Some(placed) {
            return lane.fail(format!(
                "the window was created at {:?}, expected {placed:?} on a 1024x768 desktop",
                state.window
            ));
        }
    }
    lane.check_desktop("configured", state)?;

    if !run.machine.framebuffer {
        println!("\n[SDP ] {name}: runtime mode change to 640x480");
        lane.session.type_serial(DISPLAY_MODE_BYTE)?;
        lane.session
            .wait("display mode hook", STEP_TIMEOUT, &mut |segment| {
                if lines(segment).any(|line| line.contains(HOOK_SET)) {
                    Ok(())
                } else {
                    Err(format!("no {HOOK_SET:?}"))
                }
            })?;
        let before = state.changes;
        let state = lane.await_output("the 640x480 output", SMALLEST)?;
        if state.changes != before + 1 {
            return lane.fail(format!(
                "{} output changes after the hook, expected one",
                state.changes - before
            ));
        }
        lane.check_desktop("smallest", state)?;
    }

    let transcript = lane.session.transcript();
    if let Some(line) = lines(&transcript).find(|line| line.contains("[SUP ] restart service=")) {
        return lane.fail(format!("a row restarted: {line:?}"));
    }
    lane.session.finish()?;
    Ok(())
}

/// `cargo xtask test-system-display`: the GOP boot, then the VirtIO-GPU boot, each on a fresh
/// lane-owned disk.
pub(crate) fn run() -> Result<(), XtaskError> {
    for run in [GOP_RUN, VIRTIO_RUN] {
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
    println!("[SDP ] test-system-display PASS");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m10_desktop_visual::passing_capture;

    fn compositor(line: &str) -> String {
        format!("[IPC ] console pid=5: {line}\n")
    }

    #[test]
    fn the_replay_follows_start_creation_and_each_change() {
        let created = window_origin_at(VIRTIO_GPU_Q1.tier, OUTPUT, 0);
        let mut transcript = compositor("[COMP] started output=1280x800 tier=Q1");
        transcript += &compositor(&format!(
            "[WIN ] created x={} y={} windows=1",
            created.x, created.y
        ));
        let state = replay(&transcript, &VIRTIO_GPU_Q1).unwrap();
        assert_eq!(state.output, OUTPUT);
        assert_eq!(state.window, Some(created));
        assert!(settled_at(&transcript, &VIRTIO_RUN, CONFIGURED).is_err());

        transcript += &compositor("[COMP] output changed output=1024x768");
        let state = settled_at(&transcript, &VIRTIO_RUN, CONFIGURED).unwrap();
        assert_eq!(state.changes, 1);
        // The cascade's first window fits 1024x768 where it is.
        assert_eq!(state.window, Some(created));

        transcript += &compositor("[COMP] output changed output=640x480");
        let state = settled_at(&transcript, &VIRTIO_RUN, SMALLEST).unwrap();
        assert_eq!(state.changes, 2);
        let window = state.window.unwrap();
        assert!(frame_inside(&VIRTIO_RUN, window, SMALLEST), "{window:?}");
        assert!(!frame_inside(&VIRTIO_RUN, created, SMALLEST), "{created:?}");
        assert_eq!(window.y, created.y, "only the overhanging axis moves");

        // A line still being printed is not read.
        let partial = format!("{transcript}[IPC ] console pid=5: [COMP] output changed output=10");
        assert_eq!(replay(&partial, &VIRTIO_GPU_Q1).unwrap(), state);
    }

    #[test]
    fn a_corner_pointer_stays_in_the_corner_of_a_smaller_output() {
        assert_eq!(clamped(corner(CONFIGURED), SMALLEST), corner(SMALLEST));
        assert_eq!(clamped(corner(OUTPUT), CONFIGURED), corner(CONFIGURED));
        assert_eq!(
            clamped(Point { x: 512, y: 384 }, SMALLEST),
            Point { x: 512, y: 384 }
        );
    }

    #[test]
    fn the_replay_rejects_a_second_window_or_start() {
        let mut transcript = compositor("[COMP] started output=1024x768 tier=Q0");
        transcript += &compositor("[WIN ] created x=1 y=2 windows=1");
        transcript += &compositor("[WIN ] created x=3 y=4 windows=2");
        assert!(replay(&transcript, &FRAMEBUFFER_Q0)
            .unwrap_err()
            .contains("second window"));
        let twice = compositor("[COMP] started output=1024x768 tier=Q0").repeat(2);
        assert!(replay(&twice, &FRAMEBUFFER_Q0)
            .unwrap_err()
            .contains("started twice"));
        assert!(replay("", &FRAMEBUFFER_Q0).is_err());
    }

    /// The captures each boot checks pass against a host render of the same scene.
    #[test]
    fn the_lane_scenes_pass_their_own_render() {
        for (run, output) in [
            (GOP_RUN, CONFIGURED),
            (VIRTIO_RUN, CONFIGURED),
            (VIRTIO_RUN, SMALLEST),
        ] {
            let created = window_origin_at(run.machine.tier, OUTPUT, 0);
            let mut transcript = compositor("[COMP] started output=1280x800 tier=Q1");
            transcript += &compositor(&format!(
                "[WIN ] created x={} y={} windows=1",
                created.x, created.y
            ));
            transcript += &compositor(&format!(
                "[COMP] output changed output={}x{}",
                output.width, output.height
            ));
            let state = settled_at(&transcript, &run, output).unwrap();
            let scene = Scene {
                tier: run.machine.tier,
                window: state.window,
                minimized: false,
                pointer: Point {
                    x: output.width as i32 - 1,
                    y: output.height as i32 - 1,
                },
                output,
            };
            check_scene(&passing_capture(&scene), &scene)
                .unwrap_or_else(|e| panic!("{run:?} at {output:?}: {e}"));
            // The reference-size render does not pass at another size.
            let reference = Scene {
                output: OUTPUT,
                ..scene
            };
            assert!(check_scene(&passing_capture(&reference), &scene).is_err());
        }
    }

    #[test]
    fn both_boots_configure_the_display_and_a_tablet() {
        for run in [GOP_RUN, VIRTIO_RUN] {
            let config = config(Path::new("DISK.img"), 4000, &run);
            assert!(config
                .extra_args
                .windows(2)
                .any(|pair| pair == ["-fw_cfg", DISPLAY_OPTION]));
            assert!(config
                .extra_args
                .windows(2)
                .any(|pair| pair == ["-device", "virtio-tablet-pci,id=cs-tablet"]));
            assert_eq!(config.vga, run.machine.framebuffer.then_some("std"));
        }
        assert_eq!(
            parse_size("1024x768"),
            Some(CONFIGURED),
            "{DISPLAY_OPTION} names the configured size"
        );
        assert!(check_boot(&format!("{SETTLED_DESKTOP}\n"), &GOP_RUN)
            .unwrap_err()
            .contains("virtio keyboard"));
    }
}
