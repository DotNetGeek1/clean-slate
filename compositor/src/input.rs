//! Seat state folded from raw input, and input-region hit testing.
//!
//! #112 drains the raw queue (so input never wakes the loop forever), keeps pointer, button and
//! modifier state, and resolves the surface under the pointer against each surface's committed
//! input region. Focus and event delivery to clients are window-manager behaviour (#115,
//! [`crate::wm`]).

use clean_slate_graphics::geometry::{Point, Size};
use clean_slate_graphics::input::{
    reset_seat, AxisValue120, ButtonTracker, KeyState, KeyUsage, ModifierTracker, Modifiers,
    PointerButton,
};
use clean_slate_graphics::raw_input::{RawInputKind, RawInputRecord};

use crate::scene::SurfaceKey;

/// One normalised seat event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeatEvent {
    Key {
        time_ns: u64,
        usage: KeyUsage,
        state: KeyState,
        modifiers: Modifiers,
    },
    ModifiersChanged {
        modifiers: Modifiers,
    },
    PointerMotion {
        time_ns: u64,
        position: Point,
    },
    PointerButton {
        time_ns: u64,
        button: PointerButton,
        state: KeyState,
        position: Point,
    },
    PointerAxis {
        time_ns: u64,
        vertical: AxisValue120,
        horizontal: AxisValue120,
    },
    /// Raw input was lost; every held key and button is released.
    Reset {
        modifiers: Modifiers,
    },
}

/// The surface under the pointer and the pointer position in its surface-local space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hit {
    pub key: SurfaceKey,
    pub local: Point,
}

/// Seat 0: pointer position clamped to the output, held buttons and modifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seat {
    pointer: Point,
    modifiers: ModifierTracker,
    buttons: ButtonTracker,
}

impl Default for Seat {
    fn default() -> Self {
        Self::new()
    }
}

impl Seat {
    pub const fn new() -> Self {
        Self {
            pointer: Point { x: 0, y: 0 },
            modifiers: ModifierTracker::new(),
            buttons: ButtonTracker::new(),
        }
    }

    pub fn pointer(&self) -> Point {
        self.pointer
    }

    pub fn modifiers(&self) -> Modifiers {
        self.modifiers.modifiers()
    }

    pub fn any_button_pressed(&self) -> bool {
        self.buttons.any_pressed()
    }

    /// Places the pointer at `to`, clamped to `output` (start-up placement only; input moves
    /// it relatively).
    pub fn warp(&mut self, to: Point, output: Size) {
        let clamp =
            |v: i32, extent: u32| v.clamp(0, extent.saturating_sub(1).min(i32::MAX as u32) as i32);
        self.pointer = Point {
            x: clamp(to.x, output.width),
            y: clamp(to.y, output.height),
        };
    }

    /// Folds one raw record; returns the seat events it produced (at most two).
    pub fn fold(
        &mut self,
        record: &RawInputRecord,
        output: Size,
    ) -> ([Option<SeatEvent>; 2], usize) {
        let mut out = [None; 2];
        let time_ns = record.time_ns;
        match record.kind {
            RawInputKind::Key { usage, state } => {
                let changed = self.modifiers.fold(usage, state);
                out[0] = Some(SeatEvent::Key {
                    time_ns,
                    usage,
                    state,
                    modifiers: self.modifiers.modifiers(),
                });
                if let Some(modifiers) = changed {
                    out[1] = Some(SeatEvent::ModifiersChanged { modifiers });
                    return (out, 2);
                }
                (out, 1)
            }
            RawInputKind::RelMotion { dx, dy } => {
                let clamp = |v: i32, d: i32, extent: u32| -> i32 {
                    let max = i64::from(extent.saturating_sub(1).min(i32::MAX as u32));
                    (i64::from(v) + i64::from(d)).clamp(0, max) as i32
                };
                let next = Point {
                    x: clamp(self.pointer.x, dx, output.width),
                    y: clamp(self.pointer.y, dy, output.height),
                };
                if next == self.pointer {
                    return (out, 0);
                }
                self.pointer = next;
                out[0] = Some(SeatEvent::PointerMotion {
                    time_ns,
                    position: next,
                });
                (out, 1)
            }
            RawInputKind::Button { button, state } => {
                if !self.buttons.fold(button, state) {
                    return (out, 0);
                }
                out[0] = Some(SeatEvent::PointerButton {
                    time_ns,
                    button,
                    state,
                    position: self.pointer,
                });
                (out, 1)
            }
            RawInputKind::Wheel {
                vertical,
                horizontal,
            } => {
                out[0] = Some(SeatEvent::PointerAxis {
                    time_ns,
                    vertical,
                    horizontal,
                });
                (out, 1)
            }
            RawInputKind::Overflow { .. } => {
                let _ = reset_seat(&mut self.modifiers, &mut self.buttons);
                out[0] = Some(SeatEvent::Reset {
                    modifiers: self.modifiers.modifiers(),
                });
                (out, 1)
            }
        }
    }
}
