//! `input-send-event` stimuli: keys, relative motion and buttons.
//!
//! QEMU queues the resulting PS/2 bytes and returns before the guest reads
//! them, and its device queues are small, so scripts pace each stimulus on a
//! serial marker and batches stay at [`MAX_EVENTS_PER_COMMAND`] or fewer.
//! The PS/2 mouse emits one packet per command with the button state at the
//! end of the command, which is why a press and its release must be two
//! commands.

use std::time::Duration;

use super::json::JsonValue;
use super::{QmpClient, QmpError};

pub(crate) const MAX_EVENTS_PER_COMMAND: usize = 8;

/// A QEMU `QKeyCode` name. Only the named constants exist, so a typo is a
/// compile error rather than a QMP `GenericError` mid-run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QCode(&'static str);

// The key and button sets are the vocabulary for input lanes; each lane
// uses a subset.
macro_rules! qcodes {
    ($($constant:ident => $name:literal),+ $(,)?) => {
        #[allow(dead_code)]
        impl QCode {
            $(pub(crate) const $constant: QCode = QCode($name);)+
            #[cfg(test)]
            pub(crate) const ALL: &'static [QCode] = &[$(QCode::$constant),+];
        }
    };
}

qcodes! {
    A => "a", B => "b", C => "c", D => "d", E => "e", F => "f", G => "g",
    H => "h", I => "i", J => "j", K => "k", L => "l", M => "m", N => "n",
    O => "o", P => "p", Q => "q", R => "r", S => "s", T => "t", U => "u",
    V => "v", W => "w", X => "x", Y => "y", Z => "z",
    DIGIT_0 => "0", DIGIT_1 => "1", DIGIT_2 => "2", DIGIT_3 => "3", DIGIT_4 => "4",
    DIGIT_5 => "5", DIGIT_6 => "6", DIGIT_7 => "7", DIGIT_8 => "8", DIGIT_9 => "9",
    SHIFT => "shift", SHIFT_R => "shift_r", CTRL => "ctrl", CTRL_R => "ctrl_r",
    ALT => "alt", ALT_R => "alt_r", META_L => "meta_l", META_R => "meta_r",
    RET => "ret", ESC => "esc", SPC => "spc", TAB => "tab", BACKSPACE => "backspace",
    UP => "up", DOWN => "down", LEFT => "left", RIGHT => "right",
    KP_ENTER => "kp_enter", PRINT => "print", PAUSE => "pause",
    F1 => "f1", F2 => "f2", F3 => "f3", F4 => "f4", F5 => "f5", F6 => "f6",
    F7 => "f7", F8 => "f8", F9 => "f9", F10 => "f10", F11 => "f11", F12 => "f12",
}

impl QCode {
    pub(crate) fn name(self) -> &'static str {
        self.0
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MouseButton {
    Left,
    Middle,
    Right,
    WheelUp,
    WheelDown,
}

impl MouseButton {
    fn name(self) -> &'static str {
        match self {
            MouseButton::Left => "left",
            MouseButton::Middle => "middle",
            MouseButton::Right => "right",
            MouseButton::WheelUp => "wheel-up",
            MouseButton::WheelDown => "wheel-down",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Axis {
    X,
    Y,
}

/// One `InputEvent`. `Rel` follows QEMU's screen convention: positive `X` is
/// right and positive `Y` is down (PS/2 reports Y up, so the guest sees the
/// sign flipped).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InputAction {
    Key { qcode: QCode, down: bool },
    Button { button: MouseButton, down: bool },
    Rel { axis: Axis, value: i32 },
}

impl InputAction {
    /// Key down then up, in one command; the keyboard queues a scancode per
    /// event so nothing collapses.
    pub(crate) fn tap(qcode: QCode) -> [InputAction; 2] {
        [
            InputAction::Key { qcode, down: true },
            InputAction::Key { qcode, down: false },
        ]
    }

    pub(crate) fn move_rel(dx: i32, dy: i32) -> [InputAction; 2] {
        [
            InputAction::Rel {
                axis: Axis::X,
                value: dx,
            },
            InputAction::Rel {
                axis: Axis::Y,
                value: dy,
            },
        ]
    }

    fn to_json(self) -> JsonValue {
        let (kind, data) = match self {
            InputAction::Key { qcode, down } => (
                "key",
                JsonValue::object([
                    ("down", JsonValue::Bool(down)),
                    (
                        "key",
                        JsonValue::object([
                            ("type", JsonValue::str("qcode")),
                            ("data", JsonValue::str(qcode.name())),
                        ]),
                    ),
                ]),
            ),
            InputAction::Button { button, down } => (
                "btn",
                JsonValue::object([
                    ("down", JsonValue::Bool(down)),
                    ("button", JsonValue::str(button.name())),
                ]),
            ),
            InputAction::Rel { axis, value } => (
                "rel",
                JsonValue::object([
                    (
                        "axis",
                        JsonValue::str(match axis {
                            Axis::X => "x",
                            Axis::Y => "y",
                        }),
                    ),
                    ("value", JsonValue::int(i64::from(value))),
                ]),
            ),
        };
        JsonValue::object([("type", JsonValue::str(kind)), ("data", data)])
    }
}

impl QmpClient {
    /// Sends 1..=[`MAX_EVENTS_PER_COMMAND`] events as one `input-send-event`
    /// to the active handlers (no `device`/`head`).
    pub(crate) fn send_input(
        &mut self,
        actions: &[InputAction],
        timeout: Duration,
    ) -> Result<(), QmpError> {
        if actions.is_empty() || actions.len() > MAX_EVENTS_PER_COMMAND {
            return Err(QmpError::InvalidRequest {
                detail: format!(
                    "input-send-event takes 1..={MAX_EVENTS_PER_COMMAND} events, got {}",
                    actions.len()
                ),
            });
        }
        let events = actions.iter().map(|action| action.to_json()).collect();
        let reply = self.execute(
            "input-send-event",
            Some(JsonValue::object([("events", JsonValue::Array(events))])),
            timeout,
        )?;
        if reply != JsonValue::Object(Vec::new()) {
            return Err(QmpError::Protocol {
                context: "input-send-event".to_owned(),
                detail: format!("unexpected return {}", reply.to_json()),
            });
        }
        Ok(())
    }
}
