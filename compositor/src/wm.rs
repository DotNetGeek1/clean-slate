//! Window-manager policy hooks (#115 builds window lifecycle, z-order and focus here).
//!
//! The compositor owns mechanism: surface tables, damage, composition and presentation. Every
//! policy decision it needs is asked of a [`WindowPolicy`]: where a surface first appears,
//! whether an interactive move or resize may start, and what to do with seat input. #115
//! replaces [`DefaultPolicy`]; window movement itself is a compositor operation
//! ([`crate::Compositor::move_surface`]) that never asks the client to repaint.

use clean_slate_graphics::geometry::{Point, Size};
use clean_slate_graphics::role::{Layer, SurfaceRole};

use crate::input::{Hit, SeatEvent};
use crate::scene::SurfaceKey;

/// Facts available when a surface maps for the first time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlaceRequest {
    pub key: SurfaceKey,
    pub role: SurfaceRole,
    pub layer: Layer,
    pub size: Size,
    pub output: Size,
    /// Global origin of a popup's parent, if it is placed.
    pub parent_origin: Option<Point>,
}

/// Which interactive operation a client asked for with a valid press serial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interactive {
    Move,
    Resize { edges: u8 },
}

/// Policy consulted by the compositor core.
pub trait WindowPolicy {
    /// Global origin of a surface on its first map.
    fn place(&mut self, request: PlaceRequest) -> Point;

    /// `BeginMove` / `BeginResize` passed the serial check. Returning `false` ignores it.
    fn begin_interactive(&mut self, _key: SurfaceKey, _op: Interactive) -> bool {
        false
    }

    /// One normalised seat event and the surface under the pointer (input-region aware).
    fn on_seat_event(&mut self, _event: SeatEvent, _hit: Option<Hit>) {}
}

/// M10 bootstrap placement: shell surfaces at the origin, toplevels cascaded, popups at their
/// parent's origin. No focus or input routing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DefaultPolicy {
    placed_toplevels: u32,
}

/// Cascade step between successive toplevels.
pub const CASCADE_STEP: i32 = 32;
/// Cascade wraps after this many steps.
pub const CASCADE_WRAP: u32 = 8;

impl DefaultPolicy {
    pub const fn new() -> Self {
        Self {
            placed_toplevels: 0,
        }
    }
}

impl WindowPolicy for DefaultPolicy {
    fn place(&mut self, request: PlaceRequest) -> Point {
        match request.role {
            SurfaceRole::Toplevel => {
                let step = (self.placed_toplevels % CASCADE_WRAP) as i32;
                self.placed_toplevels = self.placed_toplevels.wrapping_add(1);
                Point {
                    x: CASCADE_STEP * (step + 1),
                    y: CASCADE_STEP * (step + 1),
                }
            }
            SurfaceRole::Popup => request.parent_origin.unwrap_or(Point { x: 0, y: 0 }),
            _ => Point { x: 0, y: 0 },
        }
    }
}
