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

// Every constant must have a live user; an input lane appends the keys it
// sends.
macro_rules! qcodes {
    ($($constant:ident => $name:literal),+ $(,)?) => {
        impl QCode {
            $(pub(crate) const $constant: QCode = QCode($name);)+
            #[cfg(test)]
            pub(crate) const ALL: &'static [QCode] = &[$(QCode::$constant),+];
        }
    };
}

qcodes! {
    A => "a", S => "s", SHIFT => "shift", RET => "ret", RIGHT => "right", ESC => "esc",
    F11 => "f11", F12 => "f12",
}

impl QCode {
    pub(crate) fn name(self) -> &'static str {
        self.0
    }
}

/// A QEMU `InputButton`. The wheel "buttons" are detents: QEMU's PS/2 mouse counts one per
/// press and ignores the release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MouseButton {
    Left,
    Middle,
    Right,
    WheelUp,
    WheelDown,
}

impl MouseButton {
    pub(crate) fn name(self) -> &'static str {
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
    pub(crate) const fn tap(qcode: QCode) -> [InputAction; 2] {
        [
            InputAction::Key { qcode, down: true },
            InputAction::Key { qcode, down: false },
        ]
    }

    /// One wheel detent in one command, so the PS/2 mouse sends one packet.
    pub(crate) const fn scroll(button: MouseButton) -> [InputAction; 2] {
        [
            InputAction::Button { button, down: true },
            InputAction::Button {
                button,
                down: false,
            },
        ]
    }

    pub(crate) const fn move_rel(dx: i32, dy: i32) -> [InputAction; 2] {
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
