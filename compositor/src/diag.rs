//! Serial diagnostics of the compositor (#118): window lifecycle, focus and the compositor's own
//! surface/window rows, as console lines the desktop lane matches.
//!
//! [`DiagTracker::observe`] diffs the window-manager and scene state after an iteration, so a
//! line is produced only when something it reports changed: an idle compositor prints nothing.

use clean_slate_graphics::geometry::Point;
use clean_slate_graphics::input::PointerButton;
use clean_slate_graphics::limits::MAX_WINDOWS;
use clean_slate_graphics::role::SurfaceRole;
use clean_slate_native_abi::desktop::ConsoleLine;

use crate::compositor::Compositor;
use crate::scene::SurfaceKey;
use crate::trace::{InputTrace, TraceEvent};
use crate::wm::WindowPolicy;

/// Compositor-owned rows the desktop lane compares against its baseline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rows {
    pub clients: usize,
    pub surfaces: usize,
    pub windows: usize,
}

/// A mapped window as last reported: where it is and whether it is minimised (#357).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Reported {
    key: SurfaceKey,
    origin: Point,
    minimized: bool,
}

/// Remembers what was last reported.
pub struct DiagTracker {
    windows: [Option<Reported>; MAX_WINDOWS],
    focus: Option<SurfaceKey>,
    rows: Option<Rows>,
    output_changes: u64,
}

impl Default for DiagTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// `[COMP] started output=1280x800 tier=Q1`.
pub fn started_line(width: u32, height: u32, opaque: bool) -> ConsoleLine {
    ConsoleLine::format(format_args!(
        "[COMP] started output={width}x{height} tier={}",
        if opaque { "Q0" } else { "Q1" }
    ))
}

/// `[COMP] output changed output=1024x768`: the output now runs another size (#314) and the
/// shell and windows were re-laid out for it.
pub fn output_line(width: u32, height: u32) -> ConsoleLine {
    ConsoleLine::format(format_args!(
        "[COMP] output changed output={width}x{height}"
    ))
}

/// `[COMP] exit reason=<reason>`.
pub fn exit_line(reason: &str) -> ConsoleLine {
    ConsoleLine::format(format_args!("[COMP] exit reason={reason}"))
}

/// A line that reports one pointer or focus change. Printed on serial only when the launch
/// page has [`clean_slate_native_abi::desktop::LAUNCH_FLAG_INPUT_TRACE`]. Lifecycle lines
/// (`started`, `exit`, `[WIN ] created` / `closed` / `minimized` / `restored`, `[COMP] rows`)
/// are not in this set.
pub fn is_per_input_line(line: &str) -> bool {
    [
        "[WIN ] moved",
        "[INPT] focus",
        "[INPT] pointer",
        "[INPT] button",
        "[INPT] trace",
    ]
    .iter()
    .any(|prefix| line.starts_with(prefix))
}

/// `[INPT] button left down x= y= hit=`, `[INPT] pointer settled x= y=`, in the order the seat
/// saw them, then `[INPT] trace dropped=` if some did not fit.
pub fn input_trace_lines(trace: &InputTrace, emit: &mut dyn FnMut(ConsoleLine)) {
    for event in trace.events() {
        emit(match *event {
            TraceEvent::Button {
                button,
                pressed,
                at,
                hit,
            } => ConsoleLine::format(format_args!(
                "[INPT] button {} {} x={} y={} hit={}",
                match button {
                    PointerButton::Left => "left",
                    PointerButton::Right => "right",
                    PointerButton::Middle => "middle",
                    PointerButton::Back => "back",
                    PointerButton::Forward => "forward",
                },
                if pressed { "down" } else { "up" },
                at.x,
                at.y,
                hit.name()
            )),
            TraceEvent::Settled { at } => {
                ConsoleLine::format(format_args!("[INPT] pointer settled x={} y={}", at.x, at.y))
            }
        });
    }
    if trace.dropped() > 0 {
        emit(ConsoleLine::format(format_args!(
            "[INPT] trace dropped={}",
            trace.dropped()
        )));
    }
}

impl DiagTracker {
    pub const fn new() -> Self {
        Self {
            windows: [None; MAX_WINDOWS],
            focus: None,
            rows: None,
            output_changes: 0,
        }
    }

    /// The compositor's rows now.
    pub fn rows<P: WindowPolicy>(compositor: &Compositor<P>) -> Rows {
        Rows {
            clients: compositor.client_count(),
            surfaces: compositor.scene().len(),
            windows: compositor.wm().mapped.iter().flatten().count(),
        }
    }

    /// Emits a line for every change since the last call.
    pub fn observe<P: WindowPolicy>(
        &mut self,
        compositor: &Compositor<P>,
        emit: &mut dyn FnMut(ConsoleLine),
    ) {
        let changes = compositor.stats().output_changes;
        if changes != self.output_changes {
            self.output_changes = changes;
            if let Some(present) = compositor.present() {
                let size = present.size();
                emit(output_line(size.width, size.height));
            }
        }
        let wm = compositor.wm();
        let scene = compositor.scene();
        let toplevel_origin = |key: SurfaceKey| {
            scene
                .entry(key)
                .filter(|e| e.role == Some(SurfaceRole::Toplevel))
                .and_then(|e| e.origin)
        };

        for slot in &mut self.windows {
            let Some(Reported { key, .. }) = *slot else {
                continue;
            };
            if !wm.mapped.iter().flatten().any(|k| *k == key) {
                *slot = None;
                let count = wm.mapped.iter().flatten().count();
                emit(ConsoleLine::format(format_args!(
                    "[WIN ] closed windows={count}"
                )));
            }
        }
        for key in wm.mapped.iter().flatten().copied() {
            let Some(origin) = toplevel_origin(key) else {
                continue;
            };
            let minimized = compositor.is_minimized(key);
            match self.windows.iter_mut().flatten().find(|r| r.key == key) {
                Some(last) => {
                    if last.origin != origin {
                        last.origin = origin;
                        emit(ConsoleLine::format(format_args!(
                            "[WIN ] moved x={} y={}",
                            origin.x, origin.y
                        )));
                    }
                    if last.minimized != minimized {
                        last.minimized = minimized;
                        emit(ConsoleLine::format(format_args!(
                            "[WIN ] {} x={} y={}",
                            if minimized { "minimized" } else { "restored" },
                            origin.x,
                            origin.y
                        )));
                    }
                }
                None => {
                    if let Some(slot) = self.windows.iter_mut().find(|s| s.is_none()) {
                        *slot = Some(Reported {
                            key,
                            origin,
                            minimized,
                        });
                    }
                    let count = wm.mapped.iter().flatten().count();
                    emit(ConsoleLine::format(format_args!(
                        "[WIN ] created x={} y={} windows={count}",
                        origin.x, origin.y
                    )));
                }
            }
        }
        if wm.focus != self.focus {
            self.focus = wm.focus;
            let line = match wm.focus.and_then(toplevel_origin) {
                Some(origin) => ConsoleLine::format(format_args!(
                    "[INPT] focus window x={} y={}",
                    origin.x, origin.y
                )),
                None => ConsoleLine::format(format_args!("[INPT] focus none")),
            };
            emit(line);
        }
        let rows = Self::rows(compositor);
        if self.rows != Some(rows) {
            self.rows = Some(rows);
            emit(ConsoleLine::format(format_args!(
                "[COMP] rows clients={} surfaces={} windows={}",
                rows.clients, rows.surfaces, rows.windows
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::is_per_input_line;

    #[test]
    fn only_pointer_and_focus_lines_are_per_input() {
        let per_input = [
            "[WIN ] moved x=1 y=2",
            "[INPT] focus window x=8 y=9",
            "[INPT] focus none",
            "[INPT] pointer settled x=3 y=4",
            "[INPT] button left down x=3 y=4 hit=close",
            "[INPT] trace dropped=2",
        ];
        let lifecycle = [
            "[COMP] started output=1280x800 tier=Q1",
            "[COMP] exit reason=service-error",
            "[WIN ] created x=1 y=2 windows=1",
            "[WIN ] closed windows=0",
            "[WIN ] minimized x=1 y=2",
            "[WIN ] restored x=1 y=2",
            "[COMP] rows clients=1 surfaces=2 windows=1",
            "[COMP] output changed output=1024x768",
        ];
        for line in per_input {
            assert!(is_per_input_line(line), "{line}");
        }
        for line in lifecycle {
            assert!(!is_per_input_line(line), "{line}");
        }
    }
}
