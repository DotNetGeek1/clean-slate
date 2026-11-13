//! Deterministic keyboard and pointer injection for kernel lanes (#113, reused by #119).
//!
//! A lane describes its stimulus as a table of [`InputStimulus`]: one `input-send-event` each,
//! plus the exact serial lines the guest must log for it, in order. From that one table,
//! [`injection_steps`] builds the paced QMP script (each stimulus waits for the previous one's
//! last line, so QEMU's small PS/2 queues never back up) and [`validate_exact_sequence`] checks
//! the whole run's output line for line, so a dropped, duplicated, reordered or coalesced
//! event fails the lane.
//!
//! Everything goes through QEMU's own PS/2 keyboard and mouse over the lane's private QMP
//! socket; QEMU stays `-display none`, so no window is ever opened.

use super::input::MAX_EVENTS_PER_COMMAND;
use super::{InputAction, ScriptStep};

/// One `input-send-event` and the guest lines it must produce.
#[derive(Clone, Copy, Debug)]
pub(crate) struct InputStimulus {
    pub(crate) actions: &'static [InputAction],
    /// Full serial lines (from the lane's record prefix on), in order. The last one paces the
    /// next stimulus, so it must be the last line the guest prints for this stimulus.
    pub(crate) expect: &'static [&'static str],
}

/// Rejects tables the pacing cannot drive: a stimulus with no events, more than one command's
/// worth, no expected line (nothing to pace on), or a line outside `prefix`.
pub(crate) fn check_stimuli(prefix: &str, stimuli: &[InputStimulus]) -> Result<(), String> {
    if stimuli.is_empty() {
        return Err("no input stimuli".to_owned());
    }
    for (index, stimulus) in stimuli.iter().enumerate() {
        let number = index + 1;
        if stimulus.actions.is_empty() || stimulus.actions.len() > MAX_EVENTS_PER_COMMAND {
            return Err(format!(
                "stimulus {number} has {} events, expected 1..={MAX_EVENTS_PER_COMMAND}",
                stimulus.actions.len()
            ));
        }
        if stimulus.expect.is_empty() {
            return Err(format!(
                "stimulus {number} expects no guest line to pace on"
            ));
        }
        if let Some(line) = stimulus
            .expect
            .iter()
            .find(|line| !line.starts_with(prefix))
        {
            return Err(format!(
                "stimulus {number} expects `{line}`, which lacks the prefix `{prefix}`"
            ));
        }
    }
    Ok(())
}

/// `ready`, then for each stimulus its `Input` step and an await on its last expected line.
/// Splice the result into a longer script (screendumps, other markers) as needed.
pub(crate) fn injection_steps(
    ready: &'static str,
    stimuli: &'static [InputStimulus],
) -> Vec<ScriptStep> {
    let mut steps = Vec::with_capacity(1 + 2 * stimuli.len());
    steps.push(ScriptStep::AwaitLine(ready));
    for stimulus in stimuli {
        steps.push(ScriptStep::Input(stimulus.actions.to_vec()));
        if let Some(last) = stimulus.expect.last() {
            steps.push(ScriptStep::AwaitLine(last));
        }
    }
    steps
}

/// Every expected line, in order.
pub(crate) fn expected_lines(stimuli: &[InputStimulus]) -> impl Iterator<Item = &'static str> + '_ {
    stimuli
        .iter()
        .flat_map(|stimulus| stimulus.expect.iter().copied())
}

/// The lines of `output` that contain `prefix` (from the prefix on, without trailing
/// whitespace) must be exactly the expected lines: same count, same order, same text.
pub(crate) fn validate_exact_sequence(
    output: &str,
    prefix: &str,
    stimuli: &[InputStimulus],
) -> Result<(), String> {
    let mut got = output
        .lines()
        .filter_map(|line| line.find(prefix).map(|at| line[at..].trim_end()));
    for (index, expected) in expected_lines(stimuli).enumerate() {
        match got.next() {
            Some(line) if line == expected => {}
            Some(line) => {
                return Err(format!(
                    "event {}: expected `{expected}`, guest logged `{line}`",
                    index + 1
                ))
            }
            None => {
                return Err(format!(
                    "event {}: expected `{expected}`, guest logged nothing more",
                    index + 1
                ))
            }
        }
    }
    match got.next() {
        Some(extra) => Err(format!("unexpected extra event `{extra}`")),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{MouseButton, QCode};
    use super::*;

    const PREFIX: &str = "[T] rec ";

    const STIMULI: &[InputStimulus] = &[
        InputStimulus {
            actions: &InputAction::tap(QCode::A),
            expect: &["[T] rec 1 kbd key=0x04 down", "[T] rec 2 kbd key=0x04 up"],
        },
        InputStimulus {
            actions: &InputAction::scroll(MouseButton::WheelDown),
            expect: &["[T] rec 3 mouse wheel v=120 h=0"],
        },
    ];

    const OUTPUT: &str = "[T] ready\r\n\
        noise [T] rec 1 kbd key=0x04 down\r\n\
        [T] other\n\
        [T] rec 2 kbd key=0x04 up\n\
        [T] rec 3 mouse wheel v=120 h=0   \n\
        [T] done\n";

    #[test]
    fn steps_await_ready_then_pace_each_input_on_its_last_line() {
        let steps = injection_steps("[T] ready", STIMULI);
        let described: Vec<String> = steps
            .iter()
            .map(|step| match step {
                ScriptStep::AwaitLine(text) => format!("await {text}"),
                ScriptStep::Input(actions) => format!("input {}", actions.len()),
                _ => "other".to_owned(),
            })
            .collect();
        assert_eq!(
            described,
            [
                "await [T] ready",
                "input 2",
                "await [T] rec 2 kbd key=0x04 up",
                "input 2",
                "await [T] rec 3 mouse wheel v=120 h=0",
            ]
        );
    }

    #[test]
    fn exact_sequence_accepts_the_expected_lines_amid_other_output() {
        assert_eq!(validate_exact_sequence(OUTPUT, PREFIX, STIMULI), Ok(()));
        assert_eq!(
            expected_lines(STIMULI).count(),
            3,
            "lines flatten in stimulus order"
        );
    }

    #[test]
    fn exact_sequence_rejects_drops_duplicates_reorders_and_edits() {
        let drop = OUTPUT.replace("[T] rec 2 kbd key=0x04 up\n", "");
        let dup = OUTPUT.replace(
            "[T] rec 2 kbd key=0x04 up\n",
            "[T] rec 2 kbd key=0x04 up\n[T] rec 2 kbd key=0x04 up\n",
        );
        let reorder = "[T] rec 2 kbd key=0x04 up\n[T] rec 1 kbd key=0x04 down\n\
            [T] rec 3 mouse wheel v=120 h=0\n"
            .to_owned();
        let edit = OUTPUT.replace("v=120", "v=240");
        let extra = format!("{OUTPUT}[T] rec 4 mouse motion dx=1 dy=0\n");
        for (name, output) in [
            ("drop", drop),
            ("dup", dup),
            ("reorder", reorder),
            ("edit", edit),
            ("extra", extra),
        ] {
            assert!(
                validate_exact_sequence(&output, PREFIX, STIMULI).is_err(),
                "{name}"
            );
        }
        assert!(validate_exact_sequence("", PREFIX, STIMULI)
            .unwrap_err()
            .contains("event 1"));
    }

    #[test]
    fn check_stimuli_rejects_unpaceable_tables() {
        assert_eq!(check_stimuli(PREFIX, STIMULI), Ok(()));
        assert!(check_stimuli(PREFIX, &[]).is_err());
        let no_events = [InputStimulus {
            actions: &[],
            expect: &["[T] rec 1 x"],
        }];
        assert!(check_stimuli(PREFIX, &no_events).is_err());
        let too_many = [InputStimulus {
            actions: &[InputAction::Key {
                qcode: QCode::A,
                down: true,
            }; MAX_EVENTS_PER_COMMAND + 1],
            expect: &["[T] rec 1 x"],
        }];
        assert!(check_stimuli(PREFIX, &too_many).is_err());
        const UNPACED: [InputStimulus; 1] = [InputStimulus {
            actions: &InputAction::tap(QCode::A),
            expect: &[],
        }];
        assert!(check_stimuli(PREFIX, &UNPACED).is_err());
        const FOREIGN: [InputStimulus; 1] = [InputStimulus {
            actions: &InputAction::tap(QCode::A),
            expect: &["[U] rec 1 kbd key=0x04 down"],
        }];
        assert!(check_stimuli(PREFIX, &FOREIGN)
            .unwrap_err()
            .contains("prefix"));
    }
}
