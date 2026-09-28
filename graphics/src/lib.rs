//! Shared M10 graphics contract: geometry, pixels, identities, and protocol limits.
//!
//! **Authority split.** Applications render into shared buffers they own. The compositor
//! consumes pixel data only through capability-controlled read mappings of buffers
//! registered on the connection. A privileged display backend owned by the kernel performs
//! scanout; clients and the compositor never see aperture addresses, BARs, or queue rings.
//!
//! Surfaces, windows and client buffer handles are compositor-minted, connection-scoped
//! protocol objects. Kernel capabilities cover shared buffers, the compositor port,
//! display present, and raw input consumption only.
//!
//! This crate is `no_std`, dependency-free, and host-tested so every lane shares one
//! definition of limits, coordinates, blending, and generational ids.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod abi;
pub mod connection;
pub mod error;
pub mod geometry;
pub mod ids;
pub mod input;
pub mod limits;
pub mod mode;
pub mod objects;
pub mod pixel;
pub mod protocol;
pub mod raw_input;
pub mod surface;
pub mod role;
pub mod window;

pub use abi::{display, input as input_abi, status as abi_status};
pub use error::{GeometryError, LimitError, LookupError};
pub use geometry::{BufferRect, Fixed24_8, Point, Rect, RectSet, Scale120, Size};
pub use ids::{
    ClientBufferId, GenSlotTable, InputDeviceId, ObjectId, OutputId, Serial, SurfaceId, WindowId,
    KEYBOARD_INDEX, MOUSE_INDEX,
};
pub use input::{
    AxisValue120, KeyState, KeyUsage, Modifiers, PointerButton, KEY_A, KEY_CAPS_LOCK, KEY_ENTER,
    KEY_ESCAPE, KEY_LEFT_ALT, KEY_LEFT_CTRL, KEY_LEFT_GUI, KEY_LEFT_SHIFT, KEY_NUM_LOCK,
    KEY_RIGHT_ALT, KEY_RIGHT_CTRL, KEY_RIGHT_GUI, KEY_RIGHT_SHIFT,
};
pub use limits::{
    CLIENT_EVENT_QUEUE_DEPTH, DISPLAY_COMMAND_TIMEOUT_NS, MAX_BUFFERS_PER_CLIENT, MAX_BUFFER_BYTES,
    MAX_CLIENTS, MAX_CLIENT_STALL_ITERATIONS, MAX_DAMAGE_RECTS_PER_COMMIT,
    MAX_IN_FLIGHT_BUFFERS_PER_SURFACE, MAX_OUTPUTS, MAX_OUTSTANDING_REQUESTS_PER_CLIENT,
    MAX_PRESENT_DAMAGE_RECTS, MAX_REGION_RECTS, MAX_REGISTERED_BUFFERS, MAX_STRIDE_BYTES,
    MAX_SURFACES, MAX_SURFACES_PER_CLIENT, MAX_SURFACE_EXTENT, MAX_TITLE_BYTES, MAX_WINDOWS,
    MAX_WINDOWS_PER_CLIENT, RAW_INPUT_COALESCE_HIGH_WATER, RAW_INPUT_QUEUE_DEPTH,
    SCANOUT_BUFFER_COUNT, SERVER_REQUEST_QUEUE_DEPTH,
};
pub use mode::{DisplayMode, OutputInfo, REFERENCE_FRAME_BYTES, REFERENCE_MODE};
pub use pixel::{div255, over, BufferLayout, ColorSpace, PixelFormat};
pub use protocol::{
    negotiate, DecodeError, DisconnectReason, Event, Features, FrameHeader, ProtocolError,
    ProtocolVersion, Request, Tagged, BODY_BYTES, BODY_OFFSET, FRAME_BYTES, HEADER_BYTES,
    M10_SERVER_FEATURES, PROTOCOL_MAJOR, PROTOCOL_MINOR, SERVER_VERSION,
};
pub use raw_input::{RawInputDecodeError, RawInputKind, RawInputRecord, RAW_INPUT_RECORD_BYTES};
pub use role::{Layer, SurfaceRole};
pub use window::{DecorationMode, ResizeEdges, WindowStates, WindowTitle};

#[cfg(test)]
mod integration_tests {
    use super::geometry::Rect;
    use super::limits::MAX_SURFACE_EXTENT;

    #[test]
    fn rect_intersect_at_i32_bounds() {
        let a = Rect {
            x: i32::MIN,
            y: 0,
            width: 1,
            height: 1,
        };
        let b = Rect {
            x: i32::MIN,
            y: 0,
            width: 1,
            height: 1,
        };
        assert_eq!(a.intersect(b), Ok(Some(a)));
    }

    #[test]
    fn rect_union_overflow_returns_error() {
        let a = Rect {
            x: i32::MAX - 1,
            y: 0,
            width: 2,
            height: 1,
        };
        assert!(a.union_bounds(a).is_err());
    }

    #[test]
    fn max_extent_matches_buffer_rect() {
        assert!(MAX_SURFACE_EXTENT <= u16::MAX as u32);
    }
}
