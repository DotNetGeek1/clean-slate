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

use std::time::Duration;

use clean_slate_graphics::{Point, Rect};
use clean_slate_ui::QualityTier;

use crate::m10_desktop_lane::motion_chunks;
use crate::m10_desktop_visual::{center, cursor, region_changed, sized_window_origin, OUTPUT};
use crate::qmp::image::Screenshot;
use crate::qmp::{InputAction, MouseButton, QCode};
use crate::system_boot::{
    desktop_qemu_args_with, ensure_data_disk, field, number, start_shell_fixture_peer,
    system_vm_config,
};
use crate::system_desktop::{whole_line, GIVE_UP_LINES, SHELL_ANSWER};
use crate::system_desktop_faults::Session;
use crate::system_shell::{console_text, lines};
use crate::{workspace_root, xtask_artifact_root, VmLaunchConfig, XtaskError};

const HOOKS_FEATURE: &str = "system-test-hooks";
const LANE_TIMEOUT: Duration = Duration::from_secs(600);
const STEP_TIMEOUT: Duration = Duration::from_secs(60);
const ARTIFACTS: &str = "system-terminal";
const SERIAL_LOG: &str = "system-terminal/serial.log";
const FORBIDDEN: [&str; 3] = [GIVE_UP_LINES[0], GIVE_UP_LINES[1], "[TERM] exit"];

const TERMINAL: u32 = 0x5303;
const TERMINAL_SHELL: u32 = 0x5401;
const CONSOLE: u32 = 0x5600;
pub(crate) const SETTLED_TERMINAL_DESKTOP: &str =
    "[INIT] boot settled running=10 down=0; waiting, no deadline";
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

/// `echo hello`, then Enter.
const TYPED: [QCode; 11] = [
    QCode::E,
    QCode::C,
    QCode::H,
    QCode::O,
    QCode::SPC,
    QCode::H,
    QCode::E,
    QCode::L,
    QCode::L,
    QCode::O,
    QCode::RET,
];
const ANSWER: &str = "hello";

/// What the boot showed about the two terminal rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Terminal {
    terminal_pid: u64,
    shell_pid: u64,
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
    }
    for line in ["[TERM] attached", "[TERM] ready text=on"] {
        let want = format!("[IPC ] console pid={terminal_pid}: {line}");
        if !lines(segment).any(|l| l.starts_with(&want)) {
            return Err(format!("no {want:?}"));
        }
    }
    for service in [TERMINAL, TERMINAL_SHELL] {
        let prefix = format!("[SVC ] authority service={service} ");
        let (_, rest) = whole_line(segment, &prefix).ok_or_else(|| format!("no {prefix:?}"))?;
        if !rest.ends_with("matches-manifest=1") {
            return Err(format!("service {service} launch audit {rest:?}"));
        }
    }
    Ok(Terminal {
        terminal_pid,
        shell_pid,
    })
}

/// The answer to `echo hello`, through the session and logged on serial: from the terminal's
/// shell, or from a process it forked while the line ran (this BusyBox runs `echo` as a child,
/// which inherits the shell's session record).
fn answered(segment: &str, shell_pid: u64) -> Result<(), String> {
    let forked = |pid: u64| {
        pid == shell_pid
            || lines(segment).any(|line| {
                line.contains("[LNX ] personality=") && line.ends_with(&format!(" pid={pid}"))
            })
    };
    let found = lines(segment)
        .filter_map(|line| {
            line.find("[CON ] pid=")
                .map(|at| &line[at + "[CON ] pid=".len()..])
        })
        .filter_map(|rest| {
            let (pid, text) = rest.split_once(": ")?;
            Some((pid.parse::<u64>().ok()?, text.trim_end()))
        })
        .any(|(pid, text)| {
            (text == ANSWER || text.ends_with(&format!(" {ANSWER}"))) && forked(pid)
        });
    if found {
        Ok(())
    } else {
        Err(format!(
            "no [CON ] {ANSWER:?} line from the terminal's shell (pid={shell_pid}) or a process it forked"
        ))
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

    fn button(&mut self, down: bool) -> Result<(), XtaskError> {
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
        if field(&rest, "hit") != Some("content") {
            return self.session.fail(format!(
                "the click on the terminal landed elsewhere: {rest:?}"
            ));
        }
        Ok(())
    }

    /// Sleeps `wait` on the guest's output without expecting anything.
    fn pace(&mut self, wait: Duration) -> Result<(), XtaskError> {
        let _ = self
            .session
            .poll("pace", wait, &mut |_| Err::<(), _>(String::new()))?;
        Ok(())
    }

    fn screendump(&mut self, name: &str) -> Result<Screenshot, XtaskError> {
        let dir = xtask_artifact_root().join(ARTIFACTS);
        std::fs::create_dir_all(&dir)?;
        self.session
            .screendump(name, &dir.join(format!("{name}.ppm")))
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
    let rows = lane
        .session
        .wait("boot", STEP_TIMEOUT * 3, &mut check_boot)?;
    println!(
        "\n[STT ] terminal pid={} attached; its shell pid={}",
        rows.terminal_pid, rows.shell_pid
    );

    println!("\n[STT ] step: focus");
    let size = clean_slate_terminal::render::WINDOW_SIZE;
    let origin = sized_window_origin(QualityTier::Q1, size, 1);
    let content = Rect {
        x: origin.x,
        y: origin.y,
        width: size.width,
        height: size.height,
    };
    // A window that maps while another has focus opens behind it (no focus stealing), so the
    // click goes to the terminal's right-hand part, clear of the playground's window.
    let target = Point {
        x: origin.x + size.width as i32 - 80,
        y: center(content).y,
    };
    lane.move_to(target)?;
    lane.button(true)?;
    lane.button(false)?;
    lane.pace(Duration::from_millis(500))?;
    let before = lane.screendump("before-typing")?;

    println!("\n[STT ] step: type `echo hello`");
    lane.session.mark();
    let mark = lane.session.offset();
    for key in TYPED {
        lane.session.input("type", &InputAction::tap(key))?;
        lane.pace(KEY_PACE)?;
    }
    lane.session.mark_at(mark);
    let shell_pid = rows.shell_pid;
    lane.session
        .wait("the shell's answer", STEP_TIMEOUT, &mut |segment| {
            answered(segment, shell_pid)
        })?;
    lane.pace(Duration::from_millis(500))?;
    let after = lane.screendump("after-typing")?;
    if !region_changed(&before, &after, content, &[cursor(lane.pointer)]) {
        return lane
            .session
            .fail("the terminal's window did not change after the shell answered".to_owned());
    }

    println!("\n[STT ] step: serial shell");
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
    let transcript = lane.session.transcript();
    if let Some(line) = lines(&transcript).find(|line| line.contains("[SUP ] restart service=")) {
        return lane.session.fail(format!("a row restarted: {line:?}"));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn boot() -> String {
        "[IPC ] console pid=1: [INIT] boot profile=desktop tier=Q1 terminal=on\n\
         [CONS] authority granted pid=9 port=22016:3 rights=connect|session\n\
         [SVC ] authority service=21505 pid=9 counts matches-manifest=1\n\
         [SVC ] launch service=21505 pid=9 gen=1\n\
         [CONS] authority granted pid=10 port=22016:3 rights=connect|attach\n\
         [SVC ] authority service=21251 pid=10 counts matches-manifest=1\n\
         [SVC ] launch service=21251 pid=10 gen=1\n\
         [IPC ] console pid=10: [TERM] attached as the console session front end\n\
         [IPC ] console pid=10: [TERM] ready text=on\n\
         [IPC ] console pid=1: [INIT] boot settled running=10 down=0; waiting, no deadline\n"
            .to_owned()
    }

    #[test]
    fn a_good_terminal_boot_names_both_pids() {
        assert_eq!(
            check_boot(&boot()),
            Ok(Terminal {
                terminal_pid: 10,
                shell_pid: 9
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
    }

    #[test]
    fn the_answer_must_come_from_the_terminal_shell() {
        assert!(answered("[CON ] pid=9: hello\n", 9).is_ok());
        assert!(answered("[CON ] pid=9: ~ # hello\n", 9).is_ok());
        assert!(answered("[CON ] pid=8: hello\n", 9).is_err());
        assert!(answered("[CON ] pid=9: hellooo\n", 9).is_err());
        let forked = "[LNX ] personality=x86_64 pid=12\n[CON ] pid=12: hello\n";
        assert!(answered(forked, 9).is_ok());
    }

    #[test]
    fn the_typed_keys_spell_echo_hello() {
        let names: String = TYPED[..10]
            .iter()
            .map(|key| match key.name() {
                "spc" => ' ',
                name => name.chars().next().unwrap(),
            })
            .collect();
        assert_eq!(names, "echo hello");
        assert_eq!(TYPED[10], QCode::RET);
    }
}
