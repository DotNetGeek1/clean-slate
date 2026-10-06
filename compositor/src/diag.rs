//! Serial diagnostics of the compositor (#118): window lifecycle, focus and the compositor's own
//! surface/window rows, as console lines the desktop lane matches.
//!
//! [`DiagTracker::observe`] diffs the window-manager and scene state after an iteration, so a
//! line is produced only when something it reports changed: an idle compositor prints nothing.

use clean_slate_graphics::geometry::Point;
use clean_slate_graphics::limits::MAX_WINDOWS;
use clean_slate_graphics::role::SurfaceRole;
use clean_slate_native_abi::desktop::ConsoleLine;

use crate::compositor::Compositor;
use crate::scene::SurfaceKey;
use crate::wm::WindowPolicy;

/// Compositor-owned rows the desktop lane compares against its baseline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rows {
    pub clients: usize,
    pub surfaces: usize,
    pub windows: usize,
}

/// Remembers what was last reported.
pub struct DiagTracker {
    windows: [Option<(SurfaceKey, Point)>; MAX_WINDOWS],
    focus: Option<SurfaceKey>,
    rows: Option<Rows>,
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

/// `[COMP] exit reason=<reason>`.
pub fn exit_line(reason: &str) -> ConsoleLine {
    ConsoleLine::format(format_args!("[COMP] exit reason={reason}"))
}

impl DiagTracker {
    pub const fn new() -> Self {
        Self {
            windows: [None; MAX_WINDOWS],
            focus: None,
            rows: None,
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
        let wm = compositor.wm();
        let scene = compositor.scene();
        let toplevel_origin = |key: SurfaceKey| {
            scene
                .entry(key)
                .filter(|e| e.role == Some(SurfaceRole::Toplevel))
                .and_then(|e| e.origin)
        };

        for slot in &mut self.windows {
            let Some((key, _)) = *slot else {
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
            match self.windows.iter_mut().flatten().find(|(k, _)| *k == key) {
                Some((_, last)) if *last != origin => {
                    *last = origin;
                    emit(ConsoleLine::format(format_args!(
                        "[WIN ] moved x={} y={}",
                        origin.x, origin.y
                    )));
                }
                Some(_) => {}
                None => {
                    if let Some(slot) = self.windows.iter_mut().find(|s| s.is_none()) {
                        *slot = Some((key, origin));
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
