//! Destination: `graphics/src/connection/tests.rs`, included from `graphics/src/connection.rs`
//! with `#[cfg(test)] mod tests;`.
//!
//! Stage D contract: connection sequencing (wire §4, C9) and error routing (SPEC §7).

use crate::connection::{Admission, ConnectionPhase, RequestError};
use crate::geometry::{BufferRect, Rect, Scale120, Size};
use crate::ids::{ClientBufferId, ObjectId, Serial, SurfaceId, WindowId};
use crate::pixel::{BufferLayout, ColorSpace, PixelFormat};
use crate::protocol::{
    DisconnectReason, Event, Features, ProtocolError, ProtocolVersion, Request, Tagged,
    FRAME_BYTES, OP_CREATE_SURFACE, OP_DESTROY_SURFACE, OP_HELLO,
};
use crate::role::SurfaceRole;
use crate::window::{ResizeEdges, WindowTitle};

fn version(major: u16, minor: u16) -> ProtocolVersion {
    ProtocolVersion { major, minor }
}

fn hello_frame(major: u16, minor: u16, features: u64, tag: u32) -> [u8; FRAME_BYTES] {
    Request::Hello {
        version: version(major, minor),
        features: Features(features),
    }
    .encode(tag)
    .unwrap()
}

fn frame(request: Request, tag: u32) -> [u8; FRAME_BYTES] {
    request.encode(tag).unwrap()
}

fn surface(slot: u8) -> SurfaceId {
    SurfaceId(ObjectId::new(slot, 3).unwrap())
}

fn window(slot: u8) -> WindowId {
    WindowId(ObjectId::new(slot, 4).unwrap())
}

fn buffer(slot: u8) -> ClientBufferId {
    ClientBufferId(ObjectId::new(slot, 5).unwrap())
}

fn established() -> ConnectionPhase {
    let mut phase = ConnectionPhase::new();
    assert!(matches!(
        phase.admit(&hello_frame(1, 0, 0, 1)),
        Admission::Welcome { .. }
    ));
    phase
}

fn fatal(tag: u32, object: u32, opcode: u16, code: ProtocolError) -> Admission {
    Admission::Disconnect {
        error: RequestError {
            tag,
            object,
            opcode,
            code,
        },
        reason: DisconnectReason::ProtocolViolation(code),
    }
}

/// One canonical value of every non-Hello request variant (19).
fn all_non_hello_requests() -> Vec<Request> {
    let zero_rect = Rect {
        x: 0,
        y: 0,
        width: 0,
        height: 0,
    };
    let zero_brect = BufferRect {
        x: 0,
        y: 0,
        width: 0,
        height: 0,
    };
    vec![
        Request::RegisterBuffer {
            layout: BufferLayout::packed(16, 16, PixelFormat::Xrgb8888).unwrap(),
        },
        Request::UnregisterBuffer { buffer: buffer(1) },
        Request::CreateSurface,
        Request::DestroySurface {
            surface: surface(1),
        },
        Request::AssignRole {
            surface: surface(1),
            role: SurfaceRole::Toplevel,
            parent: None,
        },
        Request::Attach {
            surface: surface(1),
            buffer: Some(buffer(2)),
            buffer_scale: Scale120::ONE,
        },
        Request::Damage {
            surface: surface(1),
            rects: [zero_brect; 5],
            count: 0,
        },
        Request::SetOpaqueRegion {
            surface: surface(1),
            rects: [zero_rect; 3],
            count: 0,
            replace: true,
        },
        Request::SetInputRegion {
            surface: surface(1),
            rects: [zero_rect; 3],
            count: 0,
            replace: false,
        },
        Request::Commit {
            surface: surface(1),
            request_frame: true,
            color_space: ColorSpace::Srgb,
            ack: Some(Serial(9)),
        },
        Request::CreateWindow {
            surface: surface(1),
        },
        Request::DestroyWindow { window: window(2) },
        Request::SetTitle {
            window: window(2),
            title: WindowTitle::from_str_truncating("title"),
        },
        Request::SetSizeLimits {
            window: window(2),
            min: Size {
                width: 10,
                height: 10,
            },
            max: Size {
                width: 0,
                height: 0,
            },
        },
        Request::Show { window: window(2) },
        Request::Hide { window: window(2) },
        Request::BeginMove {
            window: window(2),
            serial: Serial(3),
        },
        Request::BeginResize {
            window: window(2),
            serial: Serial(3),
            edges: ResizeEdges::from_u8(ResizeEdges::BOTTOM | ResizeEdges::RIGHT).unwrap(),
        },
        Request::AckConfigure {
            window: window(2),
            serial: Serial(4),
        },
    ]
}

#[test]
fn new_connection_awaits_hello() {
    let phase = ConnectionPhase::new();
    assert_eq!(phase, ConnectionPhase::AwaitingHello);
    assert_eq!(ConnectionPhase::default(), phase);
    assert_eq!(phase.negotiated(), None);
    assert!(!phase.is_closed());
}

#[test]
fn hello_establishes_and_welcomes_with_negotiated_version_and_features() {
    let mut phase = ConnectionPhase::new();
    assert_eq!(
        phase.admit(&hello_frame(1, 7, 0x3F, 0xA5A5_0001)),
        Admission::Welcome {
            tag: 0xA5A5_0001,
            version: version(1, 0),
            features: Features(0),
        }
    );
    assert_eq!(
        phase,
        ConnectionPhase::Established {
            version: version(1, 0),
            features: Features(0),
        }
    );
    assert_eq!(phase.negotiated(), Some((version(1, 0), Features(0))));
}

#[test]
fn requests_after_hello_are_dispatched_with_tag_and_raw_object() {
    let mut phase = established();
    assert_eq!(
        phase.admit(&frame(Request::CreateSurface, 9)),
        Admission::Dispatch {
            tag: 9,
            object: 0,
            request: Request::CreateSurface,
        }
    );
    let destroy = Request::DestroySurface {
        surface: surface(4),
    };
    assert_eq!(
        phase.admit(&frame(destroy, 10)),
        Admission::Dispatch {
            tag: 10,
            object: surface(4).0.encode(),
            request: destroy,
        }
    );
    for request in all_non_hello_requests() {
        match phase.admit(&frame(request, 77)) {
            Admission::Dispatch {
                tag,
                request: got,
                object,
            } => {
                assert_eq!(tag, 77);
                assert_eq!(got, request);
                let bytes = frame(request, 77);
                assert_eq!(
                    object,
                    u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]])
                );
            }
            other => panic!("{request:?} -> {other:?}"),
        }
    }
    assert!(!phase.is_closed());
}

#[test]
fn first_request_other_than_hello_is_fatal_unsupported_version() {
    let mut phase = ConnectionPhase::new();
    assert_eq!(
        phase.admit(&frame(Request::CreateSurface, 5)),
        fatal(5, 0, OP_CREATE_SURFACE, ProtocolError::UnsupportedVersion)
    );
    assert!(phase.is_closed());
}

#[test]
fn every_non_hello_request_before_hello_is_fatal_and_echoes_its_header() {
    for request in all_non_hello_requests() {
        let mut phase = ConnectionPhase::new();
        let bytes = frame(request, 0x1234);
        let object = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        assert_eq!(
            phase.admit(&bytes),
            fatal(
                0x1234,
                object,
                request.opcode(),
                ProtocolError::UnsupportedVersion
            ),
            "{request:?}"
        );
        assert!(phase.is_closed());
    }
}

#[test]
fn second_hello_is_fatal_unsupported_version() {
    let mut phase = established();
    assert_eq!(
        phase.admit(&hello_frame(1, 0, 0, 2)),
        fatal(2, 0, OP_HELLO, ProtocolError::UnsupportedVersion)
    );
    assert!(phase.is_closed());
}

#[test]
fn failed_negotiation_is_fatal_with_hello_tag_and_no_welcome() {
    for (major, minor) in [(0, 0), (0, 9), (2, 0), (u16::MAX, 0)] {
        let mut phase = ConnectionPhase::new();
        assert_eq!(
            phase.admit(&hello_frame(major, minor, 0, 42)),
            fatal(42, 0, OP_HELLO, ProtocolError::UnsupportedVersion),
            "version {major}.{minor}"
        );
        assert!(phase.is_closed());
        assert_eq!(phase.negotiated(), None);
    }
}

#[test]
fn closed_connection_discards_every_frame() {
    let mut phase = ConnectionPhase::new();
    let _ = phase.admit(&frame(Request::CreateSurface, 1));
    assert!(phase.is_closed());
    assert_eq!(phase.admit(&hello_frame(1, 0, 0, 2)), Admission::Discard);
    assert_eq!(
        phase.admit(&frame(Request::CreateSurface, 3)),
        Admission::Discard
    );
    assert_eq!(phase.admit(&[0u8; 3]), Admission::Discard);
    assert_eq!(phase.admit(&[0xFFu8; FRAME_BYTES]), Admission::Discard);
}

#[test]
fn pre_hello_recoverable_decode_error_escalates_to_unsupported_version() {
    let mut bytes = [0u8; FRAME_BYTES];
    bytes[0..2].copy_from_slice(&0x0002u16.to_le_bytes());
    bytes[4..8].copy_from_slice(&7u32.to_le_bytes());
    let mut phase = ConnectionPhase::new();
    assert_eq!(
        phase.admit(&bytes),
        fatal(7, 0, 0x0002, ProtocolError::UnsupportedVersion)
    );
    assert!(phase.is_closed());

    let mut phase = ConnectionPhase::new();
    let mut stale_object = frame(
        Request::DestroySurface {
            surface: surface(1),
        },
        8,
    );
    stale_object[8..12].copy_from_slice(&0x0000_0003u32.to_le_bytes());
    assert_eq!(
        phase.admit(&stale_object),
        fatal(8, 3, OP_DESTROY_SURFACE, ProtocolError::UnsupportedVersion)
    );
}

#[test]
fn pre_hello_fatal_decode_error_keeps_its_own_code() {
    let mut flagged = hello_frame(1, 0, 0, 11);
    flagged[2] = 1;
    let mut phase = ConnectionPhase::new();
    assert_eq!(
        phase.admit(&flagged),
        fatal(11, 0, OP_HELLO, ProtocolError::ReservedBitsSet)
    );
    assert!(phase.is_closed());

    let short = hello_frame(1, 0, 0, 12);
    let mut phase = ConnectionPhase::new();
    assert_eq!(
        phase.admit(&short[..63]),
        fatal(12, 0, OP_HELLO, ProtocolError::MalformedFrame)
    );

    let mut phase = ConnectionPhase::new();
    assert_eq!(
        phase.admit(&short[..5]),
        fatal(0, 0, 0, ProtocolError::MalformedFrame)
    );
}

#[test]
fn established_recoverable_decode_error_is_rejected_and_connection_stays_open() {
    let mut phase = established();
    let mut bytes = [0u8; FRAME_BYTES];
    bytes[0..2].copy_from_slice(&0x0100u16.to_le_bytes());
    bytes[4..8].copy_from_slice(&21u32.to_le_bytes());
    assert_eq!(
        phase.admit(&bytes),
        Admission::Reject(RequestError {
            tag: 21,
            object: 0,
            opcode: 0x0100,
            code: ProtocolError::UnknownOpcode,
        })
    );
    assert!(!phase.is_closed());
    assert!(matches!(
        phase.admit(&frame(Request::CreateSurface, 22)),
        Admission::Dispatch { tag: 22, .. }
    ));
}

#[test]
fn established_fatal_decode_error_disconnects() {
    let mut phase = established();
    let mut bytes = frame(Request::CreateSurface, 30);
    bytes[3] = 1;
    assert_eq!(
        phase.admit(&bytes),
        fatal(30, 0, OP_CREATE_SURFACE, ProtocolError::ReservedBitsSet)
    );
    assert!(phase.is_closed());
}

#[test]
fn handler_errors_route_by_fatality() {
    let mut phase = established();
    let recoverable = RequestError {
        tag: 1,
        object: 0x0105,
        opcode: OP_DESTROY_SURFACE,
        code: ProtocolError::StaleObject,
    };
    assert_eq!(phase.fail(recoverable), Admission::Reject(recoverable));
    assert!(!phase.is_closed());

    let fatal_error = RequestError {
        code: ProtocolError::MalformedFrame,
        ..recoverable
    };
    assert_eq!(
        phase.fail(fatal_error),
        Admission::Disconnect {
            error: fatal_error,
            reason: DisconnectReason::ProtocolViolation(ProtocolError::MalformedFrame),
        }
    );
    assert!(phase.is_closed());
    assert_eq!(phase.fail(recoverable), Admission::Discard);
}

#[test]
fn close_marks_the_connection_closed() {
    let mut phase = established();
    phase.close();
    assert!(phase.is_closed());
    assert_eq!(phase.negotiated(), None);
    assert_eq!(
        phase.admit(&frame(Request::CreateSurface, 1)),
        Admission::Discard
    );
}

#[test]
fn request_error_event_echoes_tag_raw_object_and_opcode() {
    let error = RequestError {
        tag: 5,
        object: 0xFFFF_FFFF,
        opcode: 0x7ABC,
        code: ProtocolError::UnknownOpcode,
    };
    let event = error.event();
    assert_eq!(
        event,
        Tagged {
            tag: 5,
            message: Event::Error {
                object: 0xFFFF_FFFF,
                request_opcode: 0x7ABC,
                code: ProtocolError::UnknownOpcode,
            },
        }
    );
    let bytes = event.message.encode(event.tag).unwrap();
    assert_eq!(Event::decode(&bytes), Ok(event));
}

#[test]
fn every_disconnect_reason_is_wire_encodable() {
    let mut cases = Vec::new();
    let mut phase = ConnectionPhase::new();
    cases.push(phase.admit(&frame(Request::CreateSurface, 1)));
    let mut phase = established();
    cases.push(phase.admit(&hello_frame(1, 0, 0, 2)));
    let mut phase = established();
    let mut bad = frame(Request::CreateSurface, 3);
    bad[2] = 0x80;
    cases.push(phase.admit(&bad));
    for admission in cases {
        match admission {
            Admission::Disconnect { error, reason } => {
                let raw = reason.encode();
                assert_eq!(raw, 0x0001_0000 | u32::from(error.code.code()));
                assert_eq!(DisconnectReason::decode(raw), Some(reason));
            }
            other => panic!("expected disconnect, got {other:?}"),
        }
    }
}
