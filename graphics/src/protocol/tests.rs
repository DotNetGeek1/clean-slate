//! Stage C-1 protocol tests (§10.1–10.4).

use super::error::ProtocolError;
use super::event::Event;
use super::request::{Request, DAMAGE_RECTS_PER_FRAME, REGION_RECTS_PER_FRAME};
use super::*;
use crate::geometry::{BufferRect, Fixed24_8, Rect, Scale120, Size};
use crate::ids::{ClientBufferId, ObjectId, OutputId, Serial, SurfaceId, WindowId};
use crate::input::{AxisValue120, KeyState, KeyUsage, Modifiers, PointerButton, KEY_A};
use crate::limits::MAX_TITLE_BYTES;
use crate::mode::{OutputInfo, REFERENCE_MODE};
use crate::pixel::{BufferLayout, ColorSpace, PixelFormat};
use crate::role::SurfaceRole;
use crate::window::{DecorationMode, ResizeEdges, WindowStates, WindowTitle};

const TAG: u32 = 0xA5A5_0001;

fn surf(gen: u32) -> SurfaceId {
    SurfaceId(ObjectId::new(1, gen).unwrap())
}
fn win(gen: u32) -> WindowId {
    WindowId(ObjectId::new(2, gen).unwrap())
}
fn buf(gen: u32) -> ClientBufferId {
    ClientBufferId(ObjectId::new(3, gen).unwrap())
}

fn round_trip_request(r: Request) {
    let bytes = r.encode(TAG).unwrap();
    assert_eq!(read_u16_le(&bytes, 0), r.opcode());
    let decoded = Request::decode(&bytes).unwrap();
    assert_eq!(decoded.tag, TAG);
    assert_eq!(decoded.message, r);
}

fn round_trip_event(e: Event) {
    let bytes = e.encode(TAG).unwrap();
    assert_eq!(read_u16_le(&bytes, 0), e.opcode());
    let decoded = Event::decode(&bytes).unwrap();
    assert_eq!(decoded.tag, TAG);
    assert_eq!(decoded.message, e);
}

fn mutate_decode_request(mut frame: [u8; FRAME_BYTES], off: usize, val: u8, code: ProtocolError) {
    frame[off] = val;
    let err = Request::decode(&frame).unwrap_err();
    assert_eq!(err.code, code);
}

// §10.1 frame-related asserts (C-1 subset)
const _: () = assert!(FRAME_BYTES == 64);
const _: () = assert!(HEADER_BYTES + BODY_BYTES == FRAME_BYTES);
const _: () = assert!(16 + DAMAGE_RECTS_PER_FRAME * 8 <= 64);
const _: () = assert!(16 + REGION_RECTS_PER_FRAME * 16 == 64);
const _: () = assert!(13 + MAX_TITLE_BYTES <= 64);
const _: () = assert!(Features::KNOWN == 0x3F);
const _: () = assert!(WindowStates::ALL == 0x1F);
const _: () = assert!(Modifiers::ALL == 0x3F);

#[test]
fn frame_layout_assertions() {
    assert_eq!(BODY_BYTES, 52);
}

#[test]
fn all_requests_round_trip() {
    let layout = BufferLayout::packed(64, 64, PixelFormat::Xrgb8888).unwrap();
    round_trip_request(Request::Hello {
        version: ProtocolVersion { major: 1, minor: 0 },
        features: Features(0),
    });
    round_trip_request(Request::RegisterBuffer { layout });
    round_trip_request(Request::UnregisterBuffer { buffer: buf(1) });
    round_trip_request(Request::CreateSurface);
    round_trip_request(Request::DestroySurface { surface: surf(1) });
    round_trip_request(Request::AssignRole {
        surface: surf(1),
        role: SurfaceRole::Toplevel,
        parent: None,
    });
    round_trip_request(Request::AssignRole {
        surface: surf(1),
        role: SurfaceRole::Subsurface,
        parent: Some(surf(2)),
    });
    round_trip_request(Request::Attach {
        surface: surf(1),
        buffer: None,
        buffer_scale: Scale120::ONE,
    });
    round_trip_request(Request::Attach {
        surface: surf(1),
        buffer: Some(buf(1)),
        buffer_scale: Scale120(240),
    });
    round_trip_request(Request::Damage {
        surface: surf(1),
        count: 0,
        rects: [BufferRect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        }; DAMAGE_RECTS_PER_FRAME],
    });
    round_trip_request(Request::Damage {
        surface: surf(1),
        count: 5,
        rects: [
            BufferRect {
                x: 1,
                y: 2,
                width: 3,
                height: 4,
            },
            BufferRect {
                x: 5,
                y: 6,
                width: 7,
                height: 8,
            },
            BufferRect {
                x: 9,
                y: 10,
                width: 11,
                height: 12,
            },
            BufferRect {
                x: 13,
                y: 14,
                width: 15,
                height: 16,
            },
            BufferRect {
                x: 17,
                y: 18,
                width: 19,
                height: 20,
            },
        ],
    });
    round_trip_request(Request::SetOpaqueRegion {
        surface: surf(1),
        count: 3,
        replace: true,
        rects: [
            Rect {
                x: 0,
                y: 0,
                width: 10,
                height: 10,
            },
            Rect {
                x: 1,
                y: 1,
                width: 2,
                height: 2,
            },
            Rect {
                x: i32::MIN,
                y: 0,
                width: 1,
                height: 1,
            },
        ],
    });
    round_trip_request(Request::SetInputRegion {
        surface: surf(1),
        count: 0,
        replace: false,
        rects: [Rect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        }; REGION_RECTS_PER_FRAME],
    });
    round_trip_request(Request::Commit {
        surface: surf(1),
        request_frame: true,
        color_space: ColorSpace::Srgb,
        ack: None,
    });
    round_trip_request(Request::Commit {
        surface: surf(1),
        request_frame: false,
        color_space: ColorSpace::Srgb,
        ack: Some(Serial(9)),
    });
    round_trip_request(Request::CreateWindow { surface: surf(1) });
    round_trip_request(Request::DestroyWindow { window: win(1) });
    round_trip_request(Request::SetTitle {
        window: win(1),
        title: WindowTitle::from_str_truncating("hi"),
    });
    round_trip_request(Request::SetSizeLimits {
        window: win(1),
        min: Size {
            width: 0,
            height: 0,
        },
        max: Size {
            width: 0,
            height: 0,
        },
    });
    round_trip_request(Request::Show { window: win(1) });
    round_trip_request(Request::Hide { window: win(1) });
    round_trip_request(Request::BeginMove {
        window: win(1),
        serial: Serial(1),
    });
    round_trip_request(Request::BeginResize {
        window: win(1),
        serial: Serial(2),
        edges: ResizeEdges::from_u8(5).unwrap(),
    });
    round_trip_request(Request::AckConfigure {
        window: win(1),
        serial: Serial(3),
    });
}

#[test]
fn all_events_round_trip() {
    let output = OutputInfo {
        id: OutputId::new(0, 1).unwrap(),
        mode: REFERENCE_MODE,
        logical_size: Size {
            width: 1280,
            height: 800,
        },
    };
    round_trip_event(Event::Welcome {
        version: SERVER_VERSION,
        features: Features(0),
        output,
    });
    round_trip_event(Event::Error {
        object: 0xFFFF_FFFF,
        request_opcode: 0x7ABC,
        code: ProtocolError::InvalidObject,
    });
    round_trip_event(Event::BufferRegistered { buffer: buf(1) });
    round_trip_event(Event::BufferReleased { buffer: buf(1) });
    round_trip_event(Event::BufferUnregistered { buffer: buf(1) });
    round_trip_event(Event::SurfaceCreated { surface: surf(1) });
    round_trip_event(Event::FrameDone {
        surface: surf(1),
        presented_ns: 1,
        output_seq: 2,
    });
    round_trip_event(Event::WindowCreated { window: win(1) });
    round_trip_event(Event::Configure {
        window: win(1),
        serial: Serial(4),
        size: Size {
            width: 100,
            height: 200,
        },
        scale: Scale120::ONE,
        decoration: DecorationMode::Server,
        states: WindowStates::from_bits(WindowStates::ACTIVATED).unwrap(),
        bounds: Size {
            width: 0,
            height: 0,
        },
    });
    round_trip_event(Event::CloseRequested { window: win(1) });
    round_trip_event(Event::KeyboardFocus { surface: None });
    round_trip_event(Event::KeyboardFocus {
        surface: Some(surf(1)),
    });
    round_trip_event(Event::Key {
        serial: Serial(5),
        time_ns: 6,
        usage: KeyUsage(0x04),
        state: KeyState::Pressed,
        modifiers: Modifiers::from_bits(Modifiers::SHIFT).unwrap(),
    });
    round_trip_event(Event::ModifiersChanged {
        modifiers: Modifiers::from_bits(0).unwrap(),
    });
    round_trip_event(Event::PointerEnter {
        serial: Serial(7),
        surface: surf(1),
        x: Fixed24_8(i32::MIN),
        y: Fixed24_8(i32::MAX),
    });
    round_trip_event(Event::PointerLeave {
        serial: Serial(8),
        surface: surf(1),
    });
    round_trip_event(Event::PointerMotion {
        time_ns: 9,
        x: Fixed24_8(0),
        y: Fixed24_8(0),
    });
    round_trip_event(Event::PointerButton {
        serial: Serial(10),
        time_ns: 11,
        button: PointerButton::Left,
        state: KeyState::Released,
    });
    round_trip_event(Event::PointerAxis {
        time_ns: 12,
        vertical: AxisValue120(i32::MIN),
        horizontal: AxisValue120(i32::MAX),
    });
    round_trip_event(Event::InputReset);
}

#[test]
fn golden_frames() {
    let hello = Request::Hello {
        version: ProtocolVersion { major: 1, minor: 0 },
        features: Features(0),
    }
    .encode(TAG)
    .unwrap();
    let mut expected = [0u8; 64];
    expected[0] = 0x01;
    expected[4..8].copy_from_slice(&TAG.to_le_bytes());
    expected[12] = 0x01;
    assert_eq!(hello, expected);

    let attach = Request::Attach {
        surface: surf(1),
        buffer: None,
        buffer_scale: Scale120::ONE,
    }
    .encode(TAG)
    .unwrap();
    assert_eq!(read_u16_le(&attach, 0), OP_ATTACH);
    assert_eq!(read_u16_le(&attach, 16), 120);
    assert_eq!(attach[4..8], TAG.to_le_bytes());

    let region = Request::SetOpaqueRegion {
        surface: surf(1),
        count: 3,
        replace: true,
        rects: [
            Rect {
                x: 1,
                y: 2,
                width: 3,
                height: 4,
            },
            Rect {
                x: 5,
                y: 6,
                width: 7,
                height: 8,
            },
            Rect {
                x: 9,
                y: 10,
                width: 11,
                height: 12,
            },
        ],
    }
    .encode(TAG)
    .unwrap();
    assert_eq!(region[12], 3);
    assert_eq!(region[13], 1);

    let configure = Event::Configure {
        window: win(1),
        serial: Serial(99),
        size: Size {
            width: 640,
            height: 480,
        },
        scale: Scale120::ONE,
        decoration: DecorationMode::Server,
        states: WindowStates::EMPTY,
        bounds: Size {
            width: 0,
            height: 0,
        },
    }
    .encode(0)
    .unwrap();
    assert_eq!(read_u32_le(&configure, 12), 99);

    let key = Event::Key {
        serial: Serial(42),
        time_ns: 100,
        usage: KEY_A,
        state: KeyState::Pressed,
        modifiers: Modifiers::from_bits(0).unwrap(),
    }
    .encode(0)
    .unwrap();
    assert_eq!(read_u32_le(&key, 12), 42);
    assert_eq!(read_u16_le(&key, 24), 0x04);
}

#[test]
fn window_title_cases() {
    assert_eq!(WindowTitle::from_str_truncating("").as_str(), "");
    assert_eq!(WindowTitle::from_str_truncating(&"x".repeat(40)).len(), 40);
    assert_eq!(WindowTitle::from_str_truncating(&"x".repeat(41)).len(), 40);
    let t = WindowTitle::from_str_truncating(&format!("{}é", "a".repeat(39)));
    assert_eq!(t.len(), 39);
    let t2 = WindowTitle::from_str_truncating(&format!("{}€", "a".repeat(38)));
    assert_eq!(t2.len(), 38);
    let t3 = WindowTitle::from_str_truncating(&format!("{}𐍈", "a".repeat(37)));
    assert_eq!(t3.len(), 37);
    let s = "hello";
    assert_eq!(WindowTitle::from_str_truncating(s).as_str(), s);
}

#[test]
fn protocol_error_and_disconnect() {
    let codes = [
        ProtocolError::UnsupportedVersion,
        ProtocolError::UnknownOpcode,
        ProtocolError::MalformedFrame,
        ProtocolError::ReservedBitsSet,
        ProtocolError::InvalidObject,
        ProtocolError::StaleObject,
        ProtocolError::WrongObjectKind,
        ProtocolError::LimitExceeded,
        ProtocolError::RoleForbidden,
        ProtocolError::RoleAlreadyAssigned,
        ProtocolError::InvalidParent,
        ProtocolError::InvalidFormat,
        ProtocolError::InvalidScale,
        ProtocolError::InvalidLayout,
        ProtocolError::BufferTooSmall,
        ProtocolError::BufferBusy,
        ProtocolError::TransferMissing,
        ProtocolError::TransferWrongClass,
        ProtocolError::InvalidDamage,
        ProtocolError::InvalidRegion,
        ProtocolError::NotConfigured,
        ProtocolError::SerialMismatch,
        ProtocolError::UnsupportedFeature,
        ProtocolError::NotPermitted,
    ];
    assert_eq!(codes.len(), 24);
    for e in codes {
        assert_eq!(ProtocolError::from_u16(e.code()), Some(e));
    }
    for bad in [0u16, 5, 9, 14, 23, 29, 37, 44, 52, u16::MAX] {
        assert!(ProtocolError::from_u16(bad).is_none());
    }
    for e in [
        ProtocolError::UnsupportedVersion,
        ProtocolError::MalformedFrame,
        ProtocolError::ReservedBitsSet,
    ] {
        assert!(e.is_fatal());
    }
    assert!(!ProtocolError::UnknownOpcode.is_fatal());

    for (reason, wire) in [
        (DisconnectReason::ClientExit, 1u32),
        (DisconnectReason::ServerExit, 2),
        (DisconnectReason::QueueOverflow, 3),
        (DisconnectReason::Revoked, 4),
        (
            DisconnectReason::ProtocolViolation(ProtocolError::MalformedFrame),
            0x0001_0000 | 3,
        ),
    ] {
        assert_eq!(reason.encode(), wire);
        assert_eq!(DisconnectReason::decode(wire), Some(reason));
    }
    assert!(DisconnectReason::decode(
        DisconnectReason::ProtocolViolation(ProtocolError::InvalidObject).encode()
    )
    .is_none());
}

#[test]
fn negotiate_matrix() {
    let s = SERVER_VERSION;
    let z = Features(0);
    assert_eq!(
        negotiate(ProtocolVersion { major: 1, minor: 0 }, z, s, z),
        Ok((ProtocolVersion { major: 1, minor: 0 }, z))
    );
    assert_eq!(
        negotiate(ProtocolVersion { major: 1, minor: 7 }, z, s, z)
            .unwrap()
            .0
            .minor,
        0
    );
    assert_eq!(
        negotiate(
            ProtocolVersion { major: 1, minor: 0 },
            z,
            ProtocolVersion { major: 1, minor: 3 },
            z
        )
        .unwrap()
        .0
        .minor,
        0
    );
    assert_eq!(
        negotiate(
            ProtocolVersion { major: 1, minor: 2 },
            z,
            ProtocolVersion { major: 1, minor: 5 },
            z
        )
        .unwrap()
        .0
        .minor,
        2
    );
    assert_eq!(
        negotiate(ProtocolVersion { major: 1, minor: 0 }, Features(0x3F), s, z)
            .unwrap()
            .1
            .bits(),
        0
    );
    assert_eq!(
        negotiate(
            ProtocolVersion { major: 1, minor: 0 },
            Features(u64::MAX),
            s,
            z
        )
        .unwrap()
        .1
        .bits(),
        0
    );
    assert_eq!(
        negotiate(
            ProtocolVersion { major: 1, minor: 0 },
            Features(0x105),
            s,
            Features(0x3F)
        )
        .unwrap()
        .1
        .bits(),
        0x05
    );
    assert_eq!(
        negotiate(
            ProtocolVersion { major: 1, minor: 0 },
            Features(u64::MAX),
            s,
            Features(u64::MAX)
        )
        .unwrap()
        .1
        .bits(),
        0x3F
    );
    assert!(negotiate(ProtocolVersion { major: 0, minor: 0 }, z, s, z).is_err());
    assert!(negotiate(ProtocolVersion { major: 2, minor: 0 }, z, s, z).is_err());
}

#[test]
fn malformed_length_and_header() {
    let full = Request::Hello {
        version: ProtocolVersion { major: 1, minor: 0 },
        features: Features(0),
    }
    .encode(TAG)
    .unwrap();
    for len in [0usize, 11, 12, 63] {
        let err = Request::decode(&full[..len]).unwrap_err();
        assert_eq!(err.code, ProtocolError::MalformedFrame);
        if len >= 12 {
            assert_eq!(err.tag, TAG);
        } else {
            assert_eq!(err.tag, 0);
        }
    }
    let mut long = [0u8; 65];
    long[..64].copy_from_slice(&full);
    assert_eq!(
        Request::decode(&long).unwrap_err().code,
        ProtocolError::MalformedFrame
    );
    let mut f = full;
    f[2] = 1;
    assert_eq!(
        Request::decode(&f).unwrap_err().code,
        ProtocolError::ReservedBitsSet
    );
    f = full;
    f[3] = 1;
    assert_eq!(
        Request::decode(&f).unwrap_err().code,
        ProtocolError::ReservedBitsSet
    );
}

#[test]
fn unknown_opcodes() {
    let mut f = [0u8; 64];
    for op in [0x0000u16, 0x0002, 0x0100, 0x7FFF, 0x8001] {
        write_u16_le(&mut f, 0, op);
        assert_eq!(
            Request::decode(&f).unwrap_err().code,
            ProtocolError::UnknownOpcode
        );
    }
    write_u16_le(&mut f, 0, 0x0001);
    assert_eq!(
        Event::decode(&f).unwrap_err().code,
        ProtocolError::UnknownOpcode
    );
    write_u16_le(&mut f, 0, 0x8000);
    assert_eq!(
        Event::decode(&f).unwrap_err().code,
        ProtocolError::UnknownOpcode
    );
    write_u16_le(&mut f, 0, 0x0001);
    assert_eq!(
        Event::decode(&f).unwrap_err().code,
        ProtocolError::UnknownOpcode
    );
    assert_eq!(
        Request::decode(&[0u8; 64]).unwrap_err().code,
        ProtocolError::UnknownOpcode
    );
}

#[test]
fn request_object_rules() {
    let hello = Request::Hello {
        version: ProtocolVersion { major: 1, minor: 0 },
        features: Features(0),
    }
    .encode(TAG)
    .unwrap();
    let mut h = hello;
    h[8] = 1;
    assert_eq!(
        Request::decode(&h).unwrap_err().code,
        ProtocolError::ReservedBitsSet
    );

    let destroy = Request::DestroySurface { surface: surf(1) }
        .encode(TAG)
        .unwrap();
    let mut d = destroy;
    write_u32_le(&mut d, 8, 0);
    assert_eq!(
        Request::decode(&d).unwrap_err().code,
        ProtocolError::InvalidObject
    );
    write_u32_le(&mut d, 8, 0x0000_0003);
    assert_eq!(
        Request::decode(&d).unwrap_err().code,
        ProtocolError::InvalidObject
    );
}

#[test]
fn request_pad_bytes_table() {
    const PADS: &[(u16, &[(usize, usize)])] = &[
        (OP_HELLO, &[(24, 64)]),
        (OP_REGISTER_BUFFER, &[(25, 64)]),
        (OP_UNREGISTER_BUFFER, &[(12, 64)]),
        (OP_CREATE_SURFACE, &[(12, 64)]),
        (OP_DESTROY_SURFACE, &[(12, 64)]),
        (OP_ASSIGN_ROLE, &[(13, 16), (20, 64)]),
        (OP_ATTACH, &[(18, 64)]),
        (OP_DAMAGE, &[(13, 16), (56, 64)]),
        (OP_SET_OPAQUE_REGION, &[(14, 16)]),
        (OP_COMMIT, &[(14, 16), (20, 64)]),
        (OP_CREATE_WINDOW, &[(12, 64)]),
        (OP_DESTROY_WINDOW, &[(12, 64)]),
        (OP_SET_TITLE, &[(53, 64)]),
        (OP_SET_SIZE_LIMITS, &[(28, 64)]),
        (OP_SHOW, &[(12, 64)]),
        (OP_HIDE, &[(12, 64)]),
        (OP_BEGIN_MOVE, &[(16, 64)]),
        (OP_BEGIN_RESIZE, &[(17, 64)]),
        (OP_ACK_CONFIGURE, &[(16, 64)]),
    ];
    for (op, ranges) in PADS {
        let frame = canonical_request_for_opcode(*op);
        for &(start, end) in *ranges {
            for off in start..end {
                mutate_decode_request(frame, off, 1, ProtocolError::ReservedBitsSet);
            }
        }
    }
}

fn canonical_request_for_opcode(op: u16) -> [u8; FRAME_BYTES] {
    let req = match op {
        OP_HELLO => Request::Hello {
            version: ProtocolVersion { major: 1, minor: 0 },
            features: Features(0),
        },
        OP_REGISTER_BUFFER => Request::RegisterBuffer {
            layout: BufferLayout::packed(4, 4, PixelFormat::Xrgb8888).unwrap(),
        },
        OP_UNREGISTER_BUFFER => Request::UnregisterBuffer { buffer: buf(1) },
        OP_CREATE_SURFACE => Request::CreateSurface,
        OP_DESTROY_SURFACE => Request::DestroySurface { surface: surf(1) },
        OP_ASSIGN_ROLE => Request::AssignRole {
            surface: surf(1),
            role: SurfaceRole::Toplevel,
            parent: None,
        },
        OP_ATTACH => Request::Attach {
            surface: surf(1),
            buffer: None,
            buffer_scale: Scale120::ONE,
        },
        OP_DAMAGE => Request::Damage {
            surface: surf(1),
            count: 1,
            rects: [BufferRect {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            }; DAMAGE_RECTS_PER_FRAME],
        },
        OP_SET_OPAQUE_REGION => Request::SetOpaqueRegion {
            surface: surf(1),
            count: 1,
            replace: false,
            rects: [Rect {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            }; REGION_RECTS_PER_FRAME],
        },
        OP_SET_INPUT_REGION => Request::SetInputRegion {
            surface: surf(1),
            count: 1,
            replace: false,
            rects: [Rect {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            }; REGION_RECTS_PER_FRAME],
        },
        OP_COMMIT => Request::Commit {
            surface: surf(1),
            request_frame: false,
            color_space: ColorSpace::Srgb,
            ack: None,
        },
        OP_CREATE_WINDOW => Request::CreateWindow { surface: surf(1) },
        OP_DESTROY_WINDOW => Request::DestroyWindow { window: win(1) },
        OP_SET_TITLE => Request::SetTitle {
            window: win(1),
            title: WindowTitle::from_str_truncating("t"),
        },
        OP_SET_SIZE_LIMITS => Request::SetSizeLimits {
            window: win(1),
            min: Size {
                width: 0,
                height: 0,
            },
            max: Size {
                width: 0,
                height: 0,
            },
        },
        OP_SHOW => Request::Show { window: win(1) },
        OP_HIDE => Request::Hide { window: win(1) },
        OP_BEGIN_MOVE => Request::BeginMove {
            window: win(1),
            serial: Serial(1),
        },
        OP_BEGIN_RESIZE => Request::BeginResize {
            window: win(1),
            serial: Serial(1),
            edges: ResizeEdges::from_u8(1).unwrap(),
        },
        OP_ACK_CONFIGURE => Request::AckConfigure {
            window: win(1),
            serial: Serial(1),
        },
        _ => panic!("opcode"),
    };
    req.encode(TAG).unwrap()
}

#[test]
fn damage_and_region_errors() {
    let base = Request::Damage {
        surface: surf(1),
        count: 2,
        rects: [
            BufferRect {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            },
            BufferRect {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            },
            BufferRect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            },
            BufferRect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            },
            BufferRect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            },
        ],
    }
    .encode(TAG)
    .unwrap();
    mutate_decode_request(base, 12, 6, ProtocolError::InvalidDamage);
    let mut d = base;
    d[12] = 6;
    d[48] = 1;
    assert_eq!(
        Request::decode(&d).unwrap_err().code,
        ProtocolError::InvalidDamage
    );
    let mut d6 = base;
    d6[12] = 6;
    d6[56] = 1;
    assert_eq!(
        Request::decode(&d6).unwrap_err().code,
        ProtocolError::ReservedBitsSet
    );

    let reg = Request::SetOpaqueRegion {
        surface: surf(1),
        count: 1,
        replace: false,
        rects: [
            Rect {
                x: 0,
                y: 0,
                width: 1,
                height: 1,
            },
            Rect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            },
            Rect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            },
        ],
    }
    .encode(TAG)
    .unwrap();
    mutate_decode_request(reg, 12, 4, ProtocolError::InvalidRegion);
    let mut bad_rect = reg;
    write_u32_le(&mut bad_rect, 16 + 8, 0x8000_0000);
    assert_eq!(
        Request::decode(&bad_rect).unwrap_err().code,
        ProtocolError::InvalidRegion
    );
}

#[test]
fn decode_order_flags_before_opcode() {
    let mut f = [0u8; 64];
    f[2] = 1;
    write_u16_le(&mut f, 0, 0x9999);
    assert_eq!(
        Request::decode(&f).unwrap_err().code,
        ProtocolError::ReservedBitsSet
    );
    f[2] = 0;
    write_u16_le(&mut f, 0, 0x0002);
    f[24] = 1;
    assert_eq!(
        Request::decode(&f).unwrap_err().code,
        ProtocolError::UnknownOpcode
    );
}

#[test]
fn encode_parity_invalid_values() {
    assert_eq!(
        Request::Damage {
            surface: surf(1),
            count: 6,
            rects: [BufferRect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            }; DAMAGE_RECTS_PER_FRAME],
        }
        .encode(TAG)
        .unwrap_err(),
        ProtocolError::InvalidDamage
    );
    assert_eq!(
        Request::BeginMove {
            window: win(1),
            serial: Serial(0),
        }
        .encode(TAG)
        .unwrap_err(),
        ProtocolError::SerialMismatch
    );
    assert_eq!(
        Request::Attach {
            surface: surf(1),
            buffer: None,
            buffer_scale: Scale120(0),
        }
        .encode(TAG)
        .unwrap_err(),
        ProtocolError::InvalidScale
    );
}

#[test]
fn resize_edges_all_valid() {
    for v in [1u8, 2, 4, 8, 5, 6, 9, 10] {
        let r = Request::BeginResize {
            window: win(1),
            serial: Serial(1),
            edges: ResizeEdges::from_u8(v).unwrap(),
        };
        round_trip_request(r);
    }
}

#[test]
fn key_usage_boundaries() {
    assert!(!KeyUsage(0x03).is_valid());
    assert!(KeyUsage(0x04).is_valid());
    assert!(KeyUsage(0xA4).is_valid());
    assert!(!KeyUsage(0xA5).is_valid());
    assert!(!KeyUsage(0xAF).is_valid());
    assert!(KeyUsage(0xB0).is_valid());
    assert!(KeyUsage(0xDD).is_valid());
    assert!(!KeyUsage(0xDE).is_valid());
    assert!(!KeyUsage(0xDF).is_valid());
    assert!(KeyUsage(0xE0).is_valid());
    assert!(KeyUsage(0xE7).is_valid());
    assert!(!KeyUsage(0xE8).is_valid());
}
