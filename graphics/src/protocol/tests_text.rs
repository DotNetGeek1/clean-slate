//! `Text` and `KeyRepeat` (text input feature, #309) wire tests.

use super::event::Event;
use super::*;
use crate::ids::Serial;
use crate::input::{KeyUsage, Modifiers, TextRun, TEXT_RUN_MAX_BYTES};

fn text(s: &str) -> [u8; FRAME_BYTES] {
    Event::Text {
        serial: Serial(3),
        time_ns: 0x0102_0304_0506_0708,
        text: TextRun::new(s).unwrap(),
    }
    .encode(9)
    .unwrap()
}

fn code(frame: &[u8; FRAME_BYTES]) -> ProtocolError {
    Event::decode(frame).unwrap_err().code
}

#[test]
fn text_layout_is_serial_time_len_then_utf8() {
    let f = text("ß!");
    assert_eq!(read_u16_le(&f, 0), OP_TEXT);
    assert_eq!(read_u32_le(&f, 8), 0, "object is 0");
    assert_eq!(read_u32_le(&f, 12), 3);
    assert_eq!(read_u64_le(&f, 16), 0x0102_0304_0506_0708);
    assert_eq!(f[24], 3);
    assert_eq!(&f[28..31], "ß!".as_bytes());
    assert!(f[31..].iter().all(|&b| b == 0));
}

#[test]
fn text_run_bounds() {
    assert!(TextRun::new("").is_none());
    assert!(TextRun::new(&"x".repeat(TEXT_RUN_MAX_BYTES)).is_some());
    assert!(TextRun::new(&"x".repeat(TEXT_RUN_MAX_BYTES + 1)).is_none());
    for control in ["\r", "\n", "\t", "\u{8}", "\u{1b}", "\u{7f}", "a\u{0}"] {
        assert!(TextRun::new(control).is_none(), "{control:?}");
    }
    assert_eq!(TextRun::from_char('q').unwrap().as_str(), "q");
    assert!(TextRun::from_char('\r').is_none());
    let full = text(&"y".repeat(TEXT_RUN_MAX_BYTES));
    match Event::decode(&full).unwrap().message {
        Event::Text { text, .. } => assert_eq!(text.len(), TEXT_RUN_MAX_BYTES),
        other => panic!("{other:?}"),
    }
}

#[test]
fn text_rejects_bad_lengths_padding_and_utf8() {
    let mut f = text("a");
    f[24] = 0;
    assert_eq!(code(&f), ProtocolError::MalformedFrame);
    f[24] = (TEXT_RUN_MAX_BYTES + 1) as u8;
    assert_eq!(code(&f), ProtocolError::MalformedFrame);

    let mut f = text("a");
    f[29] = b'b';
    assert_eq!(code(&f), ProtocolError::ReservedBitsSet, "byte past len");
    let mut f = text("a");
    f[26] = 1;
    assert_eq!(code(&f), ProtocolError::ReservedBitsSet, "static pad");

    let mut f = text("ab");
    f[28] = 0xC3;
    f[29] = 0x28;
    assert_eq!(code(&f), ProtocolError::MalformedFrame, "invalid UTF-8");
    let mut f = text("ab");
    f[29] = b'\n';
    assert_eq!(code(&f), ProtocolError::MalformedFrame, "control character");

    let mut f = text("a");
    write_u32_le(&mut f, 12, 0);
    assert_eq!(code(&f), ProtocolError::MalformedFrame, "serial 0");
    let mut f = text("a");
    write_u32_le(&mut f, 8, 1);
    assert_eq!(code(&f), ProtocolError::ReservedBitsSet, "object must be 0");
}

#[test]
fn key_repeat_shares_key_offsets() {
    let repeat = Event::KeyRepeat {
        serial: Serial(4),
        time_ns: 77,
        usage: KeyUsage(0x2A),
        modifiers: Modifiers::from_bits(Modifiers::SHIFT).unwrap(),
    };
    let f = repeat.encode(1).unwrap();
    assert_eq!(read_u16_le(&f, 0), OP_KEY_REPEAT);
    assert_eq!(read_u32_le(&f, 12), 4);
    assert_eq!(read_u64_le(&f, 16), 77);
    assert_eq!(read_u16_le(&f, 24), 0x2A);
    assert_eq!(f[26], 0, "no state byte");
    assert_eq!(read_u16_le(&f, 28), Modifiers::SHIFT);

    let mut bad = f;
    write_u16_le(&mut bad, 24, 0x03);
    assert_eq!(code(&bad), ProtocolError::MalformedFrame);
    let mut bad = f;
    write_u16_le(&mut bad, 28, 1 << 6);
    assert_eq!(code(&bad), ProtocolError::ReservedBitsSet);
    let mut bad = f;
    bad[26] = 1;
    assert_eq!(code(&bad), ProtocolError::ReservedBitsSet);
}

#[test]
fn preedit_opcode_is_reserved_not_decoded() {
    let mut f = text("a");
    write_u16_le(&mut f, 0, OP_TEXT_PREEDIT_RESERVED);
    assert_eq!(code(&f), ProtocolError::UnknownOpcode);
}
