//! Window list feature (#237) wire tests: `ActivateWindow` and the four list events.

use super::event::Event;
use super::request::Request;
use super::*;
use crate::window::{WindowHandle, WindowTitle};

fn event_code(frame: &[u8; FRAME_BYTES]) -> ProtocolError {
    Event::decode(frame).unwrap_err().code
}

#[test]
fn activate_window_carries_the_handle_at_12_with_object_zero() {
    let f = Request::ActivateWindow {
        window: WindowHandle(0x0102_0304),
    }
    .encode(5)
    .unwrap();
    assert_eq!(read_u16_le(&f, 0), OP_ACTIVATE_WINDOW);
    assert_eq!(read_u32_le(&f, 8), 0);
    assert_eq!(read_u32_le(&f, 12), 0x0102_0304);
    assert!(f[16..].iter().all(|&b| b == 0));

    let mut zero = f;
    write_u32_le(&mut zero, 12, 0);
    assert_eq!(
        Request::decode(&zero).unwrap_err().code,
        ProtocolError::InvalidObject
    );
    assert_eq!(
        Request::ActivateWindow {
            window: WindowHandle(0)
        }
        .encode(1)
        .unwrap_err(),
        ProtocolError::InvalidObject
    );
    let mut object = f;
    write_u32_le(&mut object, 8, 0x0101);
    assert_eq!(
        Request::decode(&object).unwrap_err().code,
        ProtocolError::ReservedBitsSet
    );
}

#[test]
fn window_added_is_handle_then_pid() {
    let f = Event::WindowAdded {
        window: WindowHandle(9),
        pid: 0x0A0B_0C0D_0E0F_1011,
    }
    .encode(0)
    .unwrap();
    assert_eq!(read_u16_le(&f, 0), OP_WINDOW_ADDED);
    assert_eq!(read_u32_le(&f, 12), 9);
    assert_eq!(read_u64_le(&f, 16), 0x0A0B_0C0D_0E0F_1011);
    let mut zero = f;
    write_u32_le(&mut zero, 12, 0);
    assert_eq!(event_code(&zero), ProtocolError::InvalidObject);
}

#[test]
fn window_title_is_handle_len_then_forty_bytes() {
    let f = Event::WindowTitle {
        window: WindowHandle(3),
        title: WindowTitle::from_str_truncating("Terminal"),
    }
    .encode(0)
    .unwrap();
    assert_eq!(read_u16_le(&f, 0), OP_WINDOW_TITLE);
    assert_eq!(read_u32_le(&f, 12), 3);
    assert_eq!(f[16], 8);
    assert_eq!(&f[24..32], b"Terminal");
    assert!(f[32..].iter().all(|&b| b == 0));

    let mut past_len = f;
    past_len[32] = b'x';
    assert_eq!(event_code(&past_len), ProtocolError::ReservedBitsSet);
    let mut too_long = f;
    too_long[16] = 41;
    assert_eq!(event_code(&too_long), ProtocolError::MalformedFrame);
    let mut bad_utf8 = f;
    bad_utf8[24] = 0xFF;
    assert_eq!(event_code(&bad_utf8), ProtocolError::MalformedFrame);
}

#[test]
fn window_focused_zero_means_none() {
    let none = Event::WindowFocused { window: None }.encode(0).unwrap();
    assert_eq!(read_u16_le(&none, 0), OP_WINDOW_FOCUSED);
    assert_eq!(read_u32_le(&none, 12), 0);
    assert_eq!(
        Event::decode(&none).unwrap().message,
        Event::WindowFocused { window: None }
    );
    let removed = Event::WindowRemoved {
        window: WindowHandle(4),
    }
    .encode(0)
    .unwrap();
    let mut zero = removed;
    write_u32_le(&mut zero, 12, 0);
    assert_eq!(event_code(&zero), ProtocolError::InvalidObject);
}

#[test]
fn only_an_offered_window_list_is_negotiated() {
    use crate::connection::{Admission, ConnectionPhase};
    let hello = Request::Hello {
        version: SERVER_VERSION,
        features: Features(Features::KNOWN),
    }
    .encode(1)
    .unwrap();
    let features = |offered| match ConnectionPhase::new().admit_offering(&hello, offered) {
        Admission::Welcome { features, .. } => features,
        other => panic!("{other:?}"),
    };
    assert_eq!(features(M10_SERVER_FEATURES), M10_SERVER_FEATURES);
    assert!(features(SHELL_SERVER_FEATURES).contains(Features(Features::WINDOW_LIST)));
    let Admission::Welcome { features, .. } = ConnectionPhase::new().admit(&hello) else {
        panic!("welcome");
    };
    assert!(!features.contains(Features(Features::WINDOW_LIST)));
}
