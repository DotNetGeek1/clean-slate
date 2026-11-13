//! `test-m10-input-smoke` (#113): the kernel's controller-stimulus boot phase and CPL3 checks,
//! then host injection of keyboard and relative pointer events through QEMU's PS/2 devices
//! over the lane's private QMP socket.
//!
//! [`QMP_STIMULI`] is the oracle: the kernel logs every record it reads as
//! `[M10.input] qmp rec <n> <record>`, and the host requires exactly those lines, in order.
//! #119 can reuse the same injection inside its own script with [`qmp_injection_steps`] and
//! [`validate_qmp_output`].

use std::time::Duration;

use crate::marker_spec::MarkerSet;
use crate::qmp::inject::{check_stimuli, injection_steps, validate_exact_sequence, InputStimulus};
use crate::qmp::lane::{input_lane_config, run_kernel_lane, KernelLane};
use crate::qmp::{InputAction, MouseButton, QCode, ScriptStep};
use crate::XtaskError;

pub(crate) const LANE: &str = "m10-input";
pub(crate) const FEATURES: &[&str] = &["m10-input-self-test"];
/// Printed by the bound consumer just before it first blocks in `WORK_SET` `WAIT`.
pub(crate) const QMP_READY: &str = "[M10.input] qmp ready";
pub(crate) const QMP_RECORD_PREFIX: &str = "[M10.input] qmp rec ";
const QMP_DONE_PREFIX: &str = "[M10.input] qmp done ";
const TIMEOUT: Duration = Duration::from_secs(90);

const fn key(qcode: QCode, down: bool) -> InputAction {
    InputAction::Key { qcode, down }
}

const fn button(button: MouseButton, down: bool) -> InputAction {
    InputAction::Button { button, down }
}

/// Keys (plain, modifier-wrapped, extended), motion in both signs, a drag, every standard
/// button, both wheel directions, then the Escape tap that ends the kernel's phase. Button
/// presses and releases are separate commands: the PS/2 mouse reports the button state at
/// the end of each command.
pub(crate) const QMP_STIMULI: &[InputStimulus] = &[
    InputStimulus {
        actions: &InputAction::tap(QCode::A),
        expect: &[
            "[M10.input] qmp rec 1 kbd key=0x04 down",
            "[M10.input] qmp rec 2 kbd key=0x04 up",
        ],
    },
    InputStimulus {
        actions: &[
            key(QCode::SHIFT, true),
            key(QCode::S, true),
            key(QCode::S, false),
            key(QCode::SHIFT, false),
        ],
        expect: &[
            "[M10.input] qmp rec 3 kbd key=0xe1 down",
            "[M10.input] qmp rec 4 kbd key=0x16 down",
            "[M10.input] qmp rec 5 kbd key=0x16 up",
            "[M10.input] qmp rec 6 kbd key=0xe1 up",
        ],
    },
    InputStimulus {
        actions: &InputAction::tap(QCode::RIGHT),
        expect: &[
            "[M10.input] qmp rec 7 kbd key=0x4f down",
            "[M10.input] qmp rec 8 kbd key=0x4f up",
        ],
    },
    InputStimulus {
        actions: &InputAction::tap(QCode::RET),
        expect: &[
            "[M10.input] qmp rec 9 kbd key=0x28 down",
            "[M10.input] qmp rec 10 kbd key=0x28 up",
        ],
    },
    InputStimulus {
        actions: &InputAction::move_rel(10, 5),
        expect: &["[M10.input] qmp rec 11 mouse motion dx=10 dy=5"],
    },
    InputStimulus {
        actions: &InputAction::move_rel(-3, -7),
        expect: &["[M10.input] qmp rec 12 mouse motion dx=-3 dy=-7"],
    },
    InputStimulus {
        actions: &[button(MouseButton::Left, true)],
        expect: &["[M10.input] qmp rec 13 mouse button=1 down"],
    },
    InputStimulus {
        actions: &InputAction::move_rel(4, 0),
        expect: &["[M10.input] qmp rec 14 mouse motion dx=4 dy=0"],
    },
    InputStimulus {
        actions: &[button(MouseButton::Left, false)],
        expect: &["[M10.input] qmp rec 15 mouse button=1 up"],
    },
    InputStimulus {
        actions: &[button(MouseButton::Right, true)],
        expect: &["[M10.input] qmp rec 16 mouse button=2 down"],
    },
    InputStimulus {
        actions: &[button(MouseButton::Right, false)],
        expect: &["[M10.input] qmp rec 17 mouse button=2 up"],
    },
    InputStimulus {
        actions: &[button(MouseButton::Middle, true)],
        expect: &["[M10.input] qmp rec 18 mouse button=3 down"],
    },
    InputStimulus {
        actions: &[button(MouseButton::Middle, false)],
        expect: &["[M10.input] qmp rec 19 mouse button=3 up"],
    },
    InputStimulus {
        actions: &InputAction::scroll(MouseButton::WheelDown),
        expect: &["[M10.input] qmp rec 20 mouse wheel v=120 h=0"],
    },
    InputStimulus {
        actions: &InputAction::scroll(MouseButton::WheelUp),
        expect: &["[M10.input] qmp rec 21 mouse wheel v=-120 h=0"],
    },
    InputStimulus {
        actions: &InputAction::tap(QCode::ESC),
        expect: &[
            "[M10.input] qmp rec 22 kbd key=0x29 down",
            "[M10.input] qmp rec 23 kbd key=0x29 up",
        ],
    },
];

/// Awaits [`QMP_READY`], then injects [`QMP_STIMULI`] one command at a time.
pub(crate) fn qmp_injection_steps() -> Vec<ScriptStep> {
    injection_steps(QMP_READY, QMP_STIMULI)
}

fn expected_records() -> u64 {
    QMP_STIMULI
        .iter()
        .map(|stimulus| stimulus.expect.len() as u64)
        .sum()
}

/// The exact record sequence, then the kernel's summary: it read exactly those records, woke
/// at least once, never more often than it read records, and only on a signal.
pub(crate) fn validate_qmp_output(output: &str) -> Result<(), XtaskError> {
    validate_exact_sequence(output, QMP_RECORD_PREFIX, QMP_STIMULI)
        .map_err(|reason| XtaskError::Validation(format!("m10 input QMP sequence: {reason}")))?;
    let done = output
        .lines()
        .find_map(|line| line.find(QMP_DONE_PREFIX).map(|at| line[at..].trim_end()))
        .ok_or_else(|| XtaskError::MissingMarker(QMP_DONE_PREFIX.to_owned()))?;
    let field = |name: &str| {
        done.split_whitespace()
            .find_map(|token| token.strip_prefix(name))
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| XtaskError::Validation(format!("m10 input: no {name} in {done:?}")))
    };
    let records = field("records=")?;
    let wakes = field("wakes=")?;
    let signals = field("signals=")?;
    let fail = |what: &str| {
        Err(XtaskError::Validation(format!(
            "m10 input QMP: {what}: {done:?}"
        )))
    };
    if records != expected_records() {
        return fail("record count differs from the injected events");
    }
    if wakes == 0 || wakes > records {
        return fail("consumer wakes outside 1..=records");
    }
    if signals < wakes || signals > records {
        return fail("wake signals outside wakes..=records");
    }
    Ok(())
}

pub(crate) fn run() -> Result<(), XtaskError> {
    check_stimuli(QMP_RECORD_PREFIX, QMP_STIMULI)
        .map_err(|reason| XtaskError::Validation(format!("m10 input stimuli: {reason}")))?;
    let output = run_kernel_lane(
        KernelLane {
            lane: LANE,
            features: FEATURES,
            markers: MarkerSet::Ordered(&crate::M10_INPUT_SMOKE_ACCEPTANCE_MARKERS),
            timeout: TIMEOUT,
            config: input_lane_config(),
            extra_args: Vec::new(),
        },
        qmp_injection_steps(),
    )?;
    validate_qmp_output(&output)?;
    println!(
        "[M10.input] host validated {} QMP-injected events in order",
        expected_records()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qmp::input::Axis;

    /// HID page 0x07 usage the kernel's set 2 table gives QEMU's scancode for each qcode.
    fn usage(qcode: QCode) -> u8 {
        match qcode.name() {
            "a" => 0x04,
            "s" => 0x16,
            "shift" => 0xE1,
            "ret" => 0x28,
            "right" => 0x4F,
            "esc" => 0x29,
            "f11" => 0x44,
            "f12" => 0x45,
            other => panic!("no usage for qcode `{other}`"),
        }
    }

    fn state(down: bool) -> &'static str {
        if down {
            "down"
        } else {
            "up"
        }
    }

    /// What the kernel should log for one command, derived independently of the table:
    /// keys one record per event, a command's X and Y motion one record, buttons one record
    /// per state change, and one wheel record per detent.
    fn derive(actions: &[InputAction], held: &mut [bool; 3]) -> Vec<String> {
        let mut records = Vec::new();
        let (mut dx, mut dy) = (0, 0);
        let mut wheel = 0;
        let mut pressed = *held;
        for action in actions {
            match *action {
                InputAction::Key { qcode, down } => {
                    records.push(format!("kbd key=0x{:02x} {}", usage(qcode), state(down)));
                }
                InputAction::Rel {
                    axis: Axis::X,
                    value,
                } => dx += value,
                InputAction::Rel {
                    axis: Axis::Y,
                    value,
                } => dy += value,
                InputAction::Button { button, down } => match button {
                    MouseButton::Left => pressed[0] = down,
                    MouseButton::Right => pressed[1] = down,
                    MouseButton::Middle => pressed[2] = down,
                    MouseButton::WheelDown if down => wheel += 120,
                    MouseButton::WheelUp if down => wheel -= 120,
                    MouseButton::WheelDown | MouseButton::WheelUp => {}
                },
            }
        }
        if dx != 0 || dy != 0 {
            records.push(format!("mouse motion dx={dx} dy={dy}"));
        }
        for (index, (was, now)) in held.iter().zip(pressed).enumerate() {
            if *was != now {
                records.push(format!("mouse button={} {}", index + 1, state(now)));
            }
        }
        *held = pressed;
        if wheel != 0 {
            records.push(format!("mouse wheel v={wheel} h=0"));
        }
        records
    }

    #[test]
    fn table_matches_the_records_derived_from_its_actions() {
        let mut held = [false; 3];
        let mut index = 0;
        for (number, stimulus) in QMP_STIMULI.iter().enumerate() {
            let derived: Vec<String> = derive(stimulus.actions, &mut held)
                .into_iter()
                .map(|body| {
                    index += 1;
                    format!("{QMP_RECORD_PREFIX}{index} {body}")
                })
                .collect();
            assert_eq!(derived, stimulus.expect, "stimulus {}", number + 1);
        }
        assert_eq!(held, [false; 3], "every button is released by the end");
    }

    #[test]
    fn table_is_paceable_and_ends_with_the_only_escape_release() {
        assert_eq!(check_stimuli(QMP_RECORD_PREFIX, QMP_STIMULI), Ok(()));
        let lines: Vec<&str> = crate::qmp::inject::expected_lines(QMP_STIMULI).collect();
        let escape_release = "kbd key=0x29 up";
        assert!(lines.last().unwrap().ends_with(escape_release));
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.ends_with(escape_release))
                .count(),
            1,
            "the kernel stops at the first Escape release"
        );
        assert_eq!(expected_records(), lines.len() as u64);
    }

    #[test]
    fn every_qcode_and_mouse_button_is_exercised() {
        let used = |wanted: &InputAction| {
            QMP_STIMULI
                .iter()
                .any(|stimulus| stimulus.actions.contains(wanted))
        };
        for qcode in QCode::ALL {
            usage(*qcode);
        }
        for qcode in [
            QCode::A,
            QCode::S,
            QCode::SHIFT,
            QCode::RET,
            QCode::RIGHT,
            QCode::ESC,
        ] {
            assert!(
                used(&key(qcode, true)) && used(&key(qcode, false)),
                "{qcode:?}"
            );
        }
        for mouse_button in [
            MouseButton::Left,
            MouseButton::Right,
            MouseButton::Middle,
            MouseButton::WheelUp,
            MouseButton::WheelDown,
        ] {
            assert!(used(&button(mouse_button, true)), "{mouse_button:?}");
        }
    }

    #[test]
    fn steps_await_ready_and_pace_every_stimulus() {
        let steps = qmp_injection_steps();
        assert!(matches!(
            steps.first(),
            Some(ScriptStep::AwaitLine(QMP_READY))
        ));
        assert_eq!(steps.len(), 1 + 2 * QMP_STIMULI.len());
        assert!(matches!(
            steps.last(),
            Some(ScriptStep::AwaitLine(line)) if line.ends_with("kbd key=0x29 up")
        ));
    }

    fn passing_output() -> String {
        let mut output = String::from("[M10.input] qmp ready\r\n");
        for line in crate::qmp::inject::expected_lines(QMP_STIMULI) {
            output.push_str(line);
            output.push_str("\r\n");
        }
        output.push_str("[M10.input] qmp done records=23 wakes=17 empty_wakes=1 signals=19\r\n");
        output.push_str("[M10.input] PASS\r\n");
        output
    }

    #[test]
    fn qmp_output_passes_with_the_exact_sequence_and_a_sane_summary() {
        validate_qmp_output(&passing_output()).unwrap();
    }

    #[test]
    fn qmp_output_rejects_a_bad_sequence_or_summary() {
        let good = passing_output();
        let bad = [
            good.replace("dx=10 dy=5", "dx=10 dy=-5"),
            good.replace("[M10.input] qmp rec 15 mouse button=1 up\r\n", ""),
            good.replace("records=23", "records=22"),
            good.replace("wakes=17", "wakes=0"),
            good.replace("wakes=17", "wakes=24"),
            good.replace("signals=19", "signals=16"),
            good.replace("signals=19", "signals=24"),
            good.replace(
                "[M10.input] qmp done records=23 wakes=17 empty_wakes=1 signals=19\r\n",
                "",
            ),
        ];
        for output in bad {
            assert!(validate_qmp_output(&output).is_err(), "{output}");
        }
    }
}
