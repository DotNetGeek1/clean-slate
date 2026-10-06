//! Present scheduling: one present in flight, never blocking on the display.

use clean_slate_graphics::abi::display::{
    DisplayError, DisplayModeInfo, PresentState, PresentStatus,
};
use clean_slate_graphics::geometry::Size;
use clean_slate_graphics::limits::{DISPLAY_COMMAND_TIMEOUT_NS, SCANOUT_BUFFER_COUNT};
use clean_slate_graphics::mode::OutputInfo;

/// Display condition as seen by the compositor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayHealth {
    Ready,
    /// The backend timed out and must reset; presents fail with `ResetRequired` meanwhile.
    Resetting,
    /// The backend cannot recover; the compositor keeps serving clients without output.
    Poisoned,
}

/// The present currently owned by the display.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InFlight {
    pub seq: u64,
    pub index: u8,
    pub submitted_ns: u64,
}

/// Mode, health, the in-flight present and the next scanout buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PresentTracker {
    info: DisplayModeInfo,
    health: DisplayHealth,
    in_flight: Option<InFlight>,
    next_index: u8,
    completed_seq: u64,
}

/// What [`PresentTracker::observe`] learned from one `PRESENT_STATUS`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Observation {
    /// Presents up to this sequence completed (successfully or by timeout): fire `FrameDone`.
    pub completed: Option<(u64, u64)>,
    /// Scanout contents are unknown (reset, epoch change): repaint the whole output.
    pub full_damage: bool,
    /// The output id changed: re-query the mode.
    pub requery: bool,
}

impl PresentTracker {
    pub const fn new(info: DisplayModeInfo) -> Self {
        Self {
            info,
            health: DisplayHealth::Ready,
            in_flight: None,
            next_index: 0,
            completed_seq: 0,
        }
    }

    pub fn info(&self) -> DisplayModeInfo {
        self.info
    }

    pub fn output_info(&self) -> OutputInfo {
        OutputInfo {
            id: self.info.output,
            mode: self.info.mode,
            logical_size: self.size(),
        }
    }

    pub fn size(&self) -> Size {
        Size {
            width: self.info.mode.width_px,
            height: self.info.mode.height_px,
        }
    }

    pub fn health(&self) -> DisplayHealth {
        self.health
    }

    pub fn in_flight(&self) -> Option<InFlight> {
        self.in_flight
    }

    pub fn completed_seq(&self) -> u64 {
        self.completed_seq
    }

    /// `true` iff a new frame may be composed and presented now.
    pub fn can_present(&self) -> bool {
        self.health == DisplayHealth::Ready && self.in_flight.is_none()
    }

    /// Scanout buffer for the next frame. With copy-at-completion presents only the damaged
    /// rects of the chosen buffer must be current, so alternating needs no buffer-age tracking.
    pub fn next_index(&self) -> u8 {
        self.next_index
    }

    /// When the loop must look at the display even without a display wake.
    ///
    /// `display_wakes` is `false` when syscall 18 `BIND_WAKE` failed; completion is then
    /// observed by a bounded poll that runs only while a present is in flight or a reset is
    /// pending, never on an idle desktop. With wakes the in-flight deadline is only a backstop,
    /// and it is never earlier than one poll interval from now: a present learned from
    /// `PRESENT_STATUS` has no local submit time, and a backstop in the past would busy-poll.
    pub fn deadline(&self, now_ns: u64, display_wakes: bool, poll_ns: u64) -> Option<u64> {
        let poll = now_ns.saturating_add(poll_ns);
        match (self.health, self.in_flight) {
            (DisplayHealth::Poisoned, _) => None,
            (DisplayHealth::Resetting, _) => Some(poll),
            (DisplayHealth::Ready, Some(flight)) => Some(if display_wakes {
                flight
                    .submitted_ns
                    .saturating_add(DISPLAY_COMMAND_TIMEOUT_NS.saturating_mul(2))
                    .max(poll)
            } else {
                poll
            }),
            (DisplayHealth::Ready, None) => None,
        }
    }

    /// A `PRESENT` succeeded.
    pub fn submitted(&mut self, seq: u64, index: u8, now_ns: u64) {
        self.in_flight = Some(InFlight {
            seq,
            index,
            submitted_ns: now_ns,
        });
        self.next_index = (index + 1) % SCANOUT_BUFFER_COUNT as u8;
    }

    /// A `PRESENT` failed; returns `true` if the whole output must be repainted later.
    pub fn present_failed(&mut self, error: DisplayError) -> bool {
        match error {
            DisplayError::ResetRequired | DisplayError::DeviceTimeout => {
                self.health = DisplayHealth::Resetting;
                true
            }
            DisplayError::Poisoned => {
                self.health = DisplayHealth::Poisoned;
                false
            }
            DisplayError::StaleEpoch => true,
            _ => false,
        }
    }

    /// Folds one `PRESENT_STATUS`.
    pub fn observe(&mut self, status: PresentStatus) -> Observation {
        let mut observation = Observation::default();
        if status.output != self.info.output {
            observation.requery = true;
            observation.full_damage = true;
        }
        if status.completed_seq > self.completed_seq {
            self.completed_seq = status.completed_seq;
            observation.completed = Some((status.completed_seq, status.completed_ns));
        }
        if matches!(self.in_flight, Some(flight) if status.completed_seq >= flight.seq) {
            self.in_flight = None;
        }
        match status.state {
            PresentState::Poisoned => self.health = DisplayHealth::Poisoned,
            PresentState::ResetRequired => {
                if self.health != DisplayHealth::Resetting {
                    observation.full_damage = true;
                }
                self.health = DisplayHealth::Resetting;
            }
            PresentState::Idle | PresentState::InFlight => {
                if self.health == DisplayHealth::Resetting {
                    observation.full_damage = true;
                    observation.requery = true;
                    self.health = DisplayHealth::Ready;
                }
                if status.state == PresentState::InFlight && self.in_flight.is_none() {
                    if let Some(index) = status.in_flight_index {
                        self.in_flight = Some(InFlight {
                            seq: status.submitted_seq,
                            index,
                            submitted_ns: 0,
                        });
                    }
                }
            }
        }
        observation
    }

    /// A fresh `QUERY_MODE` after an epoch change or reset.
    pub fn requeried(&mut self, info: DisplayModeInfo) {
        self.info = info;
    }
}
