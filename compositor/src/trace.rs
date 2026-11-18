//! What the seat did with raw input, for the closed-loop desktop lanes (#218 S6e, #240).
//!
//! The compositor records each pointer button edge with what was under the pointer, and a
//! *settled* mark when an input drain that moved the pointer ended with the kernel's queue empty.
//! The service loop turns them into `[INPT] button` and `[INPT] pointer settled` lines, printed
//! only under `LAUNCH_FLAG_INPUT_TRACE`. Settling rides on the drain that consumed the motion:
//! there is no timer and no extra wake, so an idle desktop still costs nothing.

use clean_slate_graphics::geometry::Point;
use clean_slate_graphics::input::PointerButton;
use clean_slate_ui::chrome::ChromeControl;

use crate::wm::Target;

/// Records kept between two [`InputTrace::take`] calls; later ones are counted, not kept.
pub const TRACE_CAPACITY: usize = 16;

/// What a button edge landed on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ButtonHit {
    /// No surface and no decoration.
    Nothing,
    /// A surface that is not part of a window (the desktop shell's panel or background).
    Surface,
    /// Parts of a window.
    Content,
    Title,
    Control(ChromeControl),
    Resize,
}

impl ButtonHit {
    pub(crate) fn of(target: Option<(Target, bool)>) -> Self {
        match target {
            None => Self::Nothing,
            Some((Target::Content { .. }, false)) => Self::Surface,
            Some((Target::Content { .. }, true)) => Self::Content,
            Some((Target::TitleBar, _)) => Self::Title,
            Some((Target::Control(control), _)) => Self::Control(control),
            Some((Target::Resize(_), _)) => Self::Resize,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Nothing => "none",
            Self::Surface => "surface",
            Self::Content => "content",
            Self::Title => "title",
            Self::Control(ChromeControl::Close) => "close",
            Self::Control(ChromeControl::Minimize) => "minimize",
            Self::Control(ChromeControl::Maximize) => "maximize",
            Self::Resize => "resize",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceEvent {
    Button {
        button: PointerButton,
        pressed: bool,
        at: Point,
        hit: ButtonHit,
    },
    /// The pointer's position once a drain that moved it left nothing queued.
    Settled { at: Point },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputTrace {
    events: [Option<TraceEvent>; TRACE_CAPACITY],
    len: usize,
    dropped: u32,
    moved: bool,
}

impl Default for InputTrace {
    fn default() -> Self {
        Self::new()
    }
}

impl InputTrace {
    pub const fn new() -> Self {
        Self {
            events: [None; TRACE_CAPACITY],
            len: 0,
            dropped: 0,
            moved: false,
        }
    }

    fn push(&mut self, event: TraceEvent) {
        match self.events.get_mut(self.len) {
            Some(slot) => {
                *slot = Some(event);
                self.len += 1;
            }
            None => self.dropped = self.dropped.saturating_add(1),
        }
    }

    pub(crate) fn moved(&mut self) {
        self.moved = true;
    }

    pub(crate) fn button(
        &mut self,
        button: PointerButton,
        pressed: bool,
        at: Point,
        hit: ButtonHit,
    ) {
        self.push(TraceEvent::Button {
            button,
            pressed,
            at,
            hit,
        });
    }

    /// An input drain finished with the pointer at `at`; `backlog` means records were left.
    pub(crate) fn drained(&mut self, at: Point, backlog: bool) {
        if self.moved && !backlog {
            self.moved = false;
            self.push(TraceEvent::Settled { at });
        }
    }

    /// The records since the last call, which are then forgotten.
    pub fn take(&mut self) -> Self {
        let moved = self.moved;
        let taken = core::mem::take(self);
        self.moved = moved;
        taken
    }

    pub fn events(&self) -> impl Iterator<Item = &TraceEvent> {
        self.events.iter().take(self.len).flatten()
    }

    /// Records that did not fit.
    pub fn dropped(&self) -> u32 {
        self.dropped
    }
}
