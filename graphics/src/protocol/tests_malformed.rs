//! Additional §10.3 malformed-matrix cases.

use super::error::ProtocolError;
use super::event::Event;
use super::request::Request;
use super::*;
use crate::geometry::{Scale120, Size};
use crate::ids::{ObjectId, OutputId, Serial, SurfaceId, WindowId};
use crate::input::{KeyState, KeyUsage, Modifiers};
use crate::pixel::{BufferLayout, ColorSpace, PixelFormat};
use crate::role::SurfaceRole;
use crate::window::{DecorationMode, ResizeEdges, WindowTitle};

const TAG: u32 = 0xA5A5_0001;

fn surf(g: u32) -> SurfaceId {
    SurfaceId(ObjectId::new(1, g).unwrap())
}
fn win(g: u32) -> WindowId {
    WindowId(ObjectId::new(2, g).unwrap())
}

#[test]
fn request_field_malformed_matrix() {
    let attach = Request::AssignRole {
        surface: surf(1),
        role: SurfaceRole::Toplevel,
        parent: None,
    }
    .encode(TAG)
    .unwrap();
    let mut a = attach;
    write_u32_le(&mut a, 16, 0x0000_0005);
    assert_eq!(
        Request::decode(&a).unwrap_err().code,
        ProtocolError::InvalidObject
    );

    let mut att = Request::Attach {
        surface: surf(1),
        buffer: None,
        buffer_scale: Scale120::ONE,
    }
    .encode(TAG)
    .unwrap();
    write_u32_le(&mut att, 12, 0x0000_00FF);
    assert_eq!(
        Request::decode(&att).unwrap_err().code,
        ProtocolError::InvalidObject
    );

    let mut role = Request::AssignRole {
        surface: surf(1),
        role: SurfaceRole::Toplevel,
        parent: None,
    }
    .encode(TAG)
    .unwrap();
    for bad in [0u8, 8, 255] {
        role[12] = bad;
        assert_eq!(
            Request::decode(&role).unwrap_err().code,
            ProtocolError::MalformedFrame
        );
    }

    let mut reg = Request::RegisterBuffer {
        layout: BufferLayout::packed(4, 4, PixelFormat::Xrgb8888).unwrap(),
    }
    .encode(TAG)
    .unwrap();
    reg[24] = 0;
    assert_eq!(
        Request::decode(&reg).unwrap_err().code,
        ProtocolError::InvalidFormat
    );
    reg[24] = 3;
    assert_eq!(
        Request::decode(&reg).unwrap_err().code,
        ProtocolError::InvalidFormat
    );

    let mut reg2 = Request::RegisterBuffer {
        layout: BufferLayout::packed(4, 4, PixelFormat::Xrgb8888).unwrap(),
    }
    .encode(TAG)
    .unwrap();
    write_u32_le(&mut reg2, 12, 0);
    assert_eq!(
        Request::decode(&reg2).unwrap_err().code,
        ProtocolError::InvalidLayout
    );
    let mut stride_bad = Request::RegisterBuffer {
        layout: BufferLayout::packed(4, 4, PixelFormat::Xrgb8888).unwrap(),
    }
    .encode(TAG)
    .unwrap();
    write_u32_le(&mut stride_bad, 20, 5);
    assert_eq!(
        Request::decode(&stride_bad).unwrap_err().code,
        ProtocolError::InvalidLayout
    );
    let mut stride_small = Request::RegisterBuffer {
        layout: BufferLayout::packed(4, 4, PixelFormat::Xrgb8888).unwrap(),
    }
    .encode(TAG)
    .unwrap();
    write_u32_le(&mut stride_small, 20, 8);
    assert_eq!(
        Request::decode(&stride_small).unwrap_err().code,
        ProtocolError::InvalidLayout
    );
    let mut huge = Request::RegisterBuffer {
        layout: BufferLayout::packed(4, 4, PixelFormat::Xrgb8888).unwrap(),
    }
    .encode(TAG)
    .unwrap();
    write_u32_le(&mut huge, 12, 16_384);
    write_u32_le(&mut huge, 16, 16_384);
    write_u32_le(&mut huge, 20, 16_384 * 4);
    assert_eq!(
        Request::decode(&huge).unwrap_err().code,
        ProtocolError::InvalidLayout
    );

    let mut commit = Request::Commit {
        surface: surf(1),
        request_frame: false,
        color_space: ColorSpace::Srgb,
        ack: None,
    }
    .encode(TAG)
    .unwrap();
    commit[13] = 1;
    assert_eq!(
        Request::decode(&commit).unwrap_err().code,
        ProtocolError::InvalidFormat
    );
    commit[12] = 2;
    commit[13] = 0;
    assert_eq!(
        Request::decode(&commit).unwrap_err().code,
        ProtocolError::MalformedFrame
    );

    let mut title = Request::SetTitle {
        window: win(1),
        title: WindowTitle::from_str_truncating("abc"),
    }
    .encode(TAG)
    .unwrap();
    title[12] = 41;
    assert_eq!(
        Request::decode(&title).unwrap_err().code,
        ProtocolError::MalformedFrame
    );
    title[12] = 3;
    title[16] = 1;
    assert_eq!(
        Request::decode(&title).unwrap_err().code,
        ProtocolError::ReservedBitsSet
    );
    title[16] = 0;
    title[13] = 0xC3;
    title[14] = 0x28;
    assert_eq!(
        Request::decode(&title).unwrap_err().code,
        ProtocolError::MalformedFrame
    );

    let mut limits = Request::SetSizeLimits {
        window: win(1),
        min: Size {
            width: 10,
            height: 10,
        },
        max: Size {
            width: 100,
            height: 100,
        },
    }
    .encode(TAG)
    .unwrap();
    write_u32_le(&mut limits, 12, 100);
    write_u32_le(&mut limits, 20, 50);
    assert_eq!(
        Request::decode(&limits).unwrap_err().code,
        ProtocolError::InvalidLayout
    );
    write_u32_le(&mut limits, 12, 4097);
    write_u32_le(&mut limits, 16, 0);
    write_u32_le(&mut limits, 20, 0);
    write_u32_le(&mut limits, 24, 0);
    assert_eq!(
        Request::decode(&limits).unwrap_err().code,
        ProtocolError::InvalidLayout
    );
    let ok_limits = Request::SetSizeLimits {
        window: win(1),
        min: Size {
            width: 100,
            height: 0,
        },
        max: Size {
            width: 0,
            height: 0,
        },
    }
    .encode(TAG)
    .unwrap();
    assert!(Request::decode(&ok_limits).is_ok());

    let mut resize = Request::BeginResize {
        window: win(1),
        serial: Serial(1),
        edges: ResizeEdges::from_u8(1).unwrap(),
    }
    .encode(TAG)
    .unwrap();
    for bad in [0u8, 3, 12, 15, 16] {
        resize[16] = bad;
        assert_eq!(
            Request::decode(&resize).unwrap_err().code,
            ProtocolError::MalformedFrame
        );
    }
    let mut mv = Request::BeginMove {
        window: win(1),
        serial: Serial(1),
    }
    .encode(TAG)
    .unwrap();
    write_u32_le(&mut mv, 12, 0);
    assert_eq!(
        Request::decode(&mv).unwrap_err().code,
        ProtocolError::SerialMismatch
    );
}

#[test]
fn event_malformed_matrix() {
    let mut key = Event::Key {
        serial: Serial(1),
        time_ns: 0,
        usage: KeyUsage(0x04),
        state: KeyState::Pressed,
        modifiers: Modifiers::from_bits(0).unwrap(),
    }
    .encode(0)
    .unwrap();
    write_u32_le(&mut key, 12, 0);
    assert_eq!(
        Event::decode(&key).unwrap_err().code,
        ProtocolError::MalformedFrame
    );
    for bad in [0x00u16, 0x03, 0xA5, 0xE8] {
        write_u16_le(&mut key, 24, bad);
        write_u32_le(&mut key, 12, 1);
        assert_eq!(
            Event::decode(&key).unwrap_err().code,
            ProtocolError::MalformedFrame
        );
    }
    key[26] = 2;
    write_u16_le(&mut key, 24, 0x04);
    assert_eq!(
        Event::decode(&key).unwrap_err().code,
        ProtocolError::MalformedFrame
    );
    write_u16_le(&mut key, 28, 1 << 6);
    key[26] = 1;
    assert_eq!(
        Event::decode(&key).unwrap_err().code,
        ProtocolError::ReservedBitsSet
    );

    let mut cfg = Event::Configure {
        window: win(1),
        serial: Serial(1),
        size: Size {
            width: 100,
            height: 100,
        },
        scale: Scale120::ONE,
        decoration: DecorationMode::Server,
        states: crate::window::WindowStates::from_bits(0).unwrap(),
        bounds: Size {
            width: 0,
            height: 0,
        },
    }
    .encode(0)
    .unwrap();
    write_u32_le(&mut cfg, 16, 4097);
    assert_eq!(
        Event::decode(&cfg).unwrap_err().code,
        ProtocolError::MalformedFrame
    );
    write_u32_le(&mut cfg, 28, 1 << 5);
    write_u32_le(&mut cfg, 16, 100);
    assert_eq!(
        Event::decode(&cfg).unwrap_err().code,
        ProtocolError::ReservedBitsSet
    );

    let mut err = Event::Error {
        object: 0,
        request_opcode: 0,
        code: ProtocolError::InvalidObject,
    }
    .encode(0)
    .unwrap();
    write_u16_le(&mut err, 12, 5);
    assert_eq!(
        Event::decode(&err).unwrap_err().code,
        ProtocolError::MalformedFrame
    );

    let mut welcome = Event::Welcome {
        version: SERVER_VERSION,
        features: Features(0),
        output: crate::mode::OutputInfo {
            id: OutputId::new(0, 1).unwrap(),
            mode: crate::mode::REFERENCE_MODE,
            logical_size: Size {
                width: 1280,
                height: 800,
            },
        },
    }
    .encode(0)
    .unwrap();
    write_u32_le(&mut welcome, 24, 0x03);
    assert_eq!(
        Event::decode(&welcome).unwrap_err().code,
        ProtocolError::MalformedFrame
    );
    welcome[41] = 1;
    write_u32_le(&mut welcome, 24, OutputId::new(0, 1).unwrap().encode());
    assert_eq!(
        Event::decode(&welcome).unwrap_err().code,
        ProtocolError::ReservedBitsSet
    );

    let mut btn = Event::PointerButton {
        serial: Serial(1),
        time_ns: 0,
        button: crate::input::PointerButton::Left,
        state: KeyState::Pressed,
    }
    .encode(0)
    .unwrap();
    write_u16_le(&mut btn, 24, 0);
    assert_eq!(
        Event::decode(&btn).unwrap_err().code,
        ProtocolError::MalformedFrame
    );
    write_u16_le(&mut btn, 24, 6);
    assert_eq!(
        Event::decode(&btn).unwrap_err().code,
        ProtocolError::MalformedFrame
    );
    let mut dec = Event::Configure {
        window: win(1),
        serial: Serial(1),
        size: Size {
            width: 1,
            height: 1,
        },
        scale: Scale120::ONE,
        decoration: DecorationMode::Server,
        states: crate::window::WindowStates::from_bits(0).unwrap(),
        bounds: Size {
            width: 0,
            height: 0,
        },
    }
    .encode(0)
    .unwrap();
    dec[26] = 0;
    assert_eq!(
        Event::decode(&dec).unwrap_err().code,
        ProtocolError::MalformedFrame
    );
    dec[26] = 3;
    assert_eq!(
        Event::decode(&dec).unwrap_err().code,
        ProtocolError::MalformedFrame
    );
}
