use super::{RawInputDecodeError, RawInputKind, RawInputRecord};
use crate::ids::InputDeviceId;
use crate::input::{AxisValue120, KeyState, PointerButton, KEY_A};

fn kb() -> InputDeviceId {
    InputDeviceId::new(0, 1).unwrap()
}

fn mouse() -> InputDeviceId {
    InputDeviceId::new(1, 1).unwrap()
}

fn canonical_key() -> RawInputRecord {
    RawInputRecord {
        seq: 42,
        time_ns: 100,
        device: kb(),
        kind: RawInputKind::Key {
            usage: KEY_A,
            state: KeyState::Pressed,
        },
    }
}

const GOLDEN_RAW_KEY: [u8; 32] = [
    0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[test]
fn raw_input_round_trips_all_kinds() {
    let cases = [
        RawInputRecord {
            seq: 1,
            time_ns: 0,
            device: kb(),
            kind: RawInputKind::Key {
                usage: KEY_A,
                state: KeyState::Released,
            },
        },
        RawInputRecord {
            seq: 2,
            time_ns: 1,
            device: mouse(),
            kind: RawInputKind::RelMotion {
                dx: i32::MIN,
                dy: i32::MAX,
            },
        },
        RawInputRecord {
            seq: 3,
            time_ns: 2,
            device: mouse(),
            kind: RawInputKind::Button {
                button: PointerButton::Right,
                state: KeyState::Pressed,
            },
        },
        RawInputRecord {
            seq: 4,
            time_ns: 3,
            device: mouse(),
            kind: RawInputKind::Wheel {
                vertical: AxisValue120(-120),
                horizontal: AxisValue120(240),
            },
        },
        RawInputRecord {
            seq: 5,
            time_ns: 4,
            device: kb(),
            kind: RawInputKind::Overflow { dropped: u32::MAX },
        },
    ];
    for record in cases {
        let bytes = record.encode();
        assert_eq!(RawInputRecord::decode(&bytes).unwrap(), record);
    }
}

#[test]
fn golden_raw_key_record() {
    assert_eq!(canonical_key().encode(), GOLDEN_RAW_KEY);
    assert_eq!(
        RawInputRecord::decode(&GOLDEN_RAW_KEY).unwrap(),
        canonical_key()
    );
}

#[test]
fn raw_input_decode_matrix() {
    let ok = canonical_key().encode();

    assert_eq!(
        RawInputRecord::decode(&ok[..31]),
        Err(RawInputDecodeError::Truncated)
    );
    assert_eq!(
        RawInputRecord::decode(&[0u8; 33]),
        Err(RawInputDecodeError::Truncated)
    );

    let mut seq0 = ok;
    seq0[0] = 0;
    assert_eq!(
        RawInputRecord::decode(&seq0),
        Err(RawInputDecodeError::InvalidField)
    );

    let mut dev0 = ok;
    dev0[16] = 0;
    dev0[17] = 0;
    dev0[18] = 0;
    dev0[19] = 0;
    assert_eq!(
        RawInputRecord::decode(&dev0),
        Err(RawInputDecodeError::InvalidField)
    );

    let mut dev_gen0 = ok;
    dev_gen0[16] = 0x05;
    dev_gen0[17] = 0;
    dev_gen0[18] = 0;
    dev_gen0[19] = 0;
    assert_eq!(
        RawInputRecord::decode(&dev_gen0),
        Err(RawInputDecodeError::InvalidField)
    );

    let mut kind0 = ok;
    kind0[20] = 0;
    assert_eq!(
        RawInputRecord::decode(&kind0),
        Err(RawInputDecodeError::UnknownKind)
    );
    let mut kind6 = ok;
    kind6[20] = 6;
    assert_eq!(
        RawInputRecord::decode(&kind6),
        Err(RawInputDecodeError::UnknownKind)
    );

    let mut pad21 = ok;
    pad21[21] = 1;
    assert_eq!(
        RawInputRecord::decode(&pad21),
        Err(RawInputDecodeError::ReservedBitsSet)
    );

    let mut usage_bad = ok;
    usage_bad[24] = 0x02;
    assert_eq!(
        RawInputRecord::decode(&usage_bad),
        Err(RawInputDecodeError::InvalidField)
    );
    let mut usage_e8 = ok;
    usage_e8[24] = 0xE8;
    assert_eq!(
        RawInputRecord::decode(&usage_e8),
        Err(RawInputDecodeError::InvalidField)
    );

    let mut state2 = ok;
    state2[26] = 2;
    assert_eq!(
        RawInputRecord::decode(&state2),
        Err(RawInputDecodeError::InvalidField)
    );

    let mut pad27 = ok;
    pad27[27] = 1;
    assert_eq!(
        RawInputRecord::decode(&pad27),
        Err(RawInputDecodeError::ReservedBitsSet)
    );

    let btn_ok = RawInputRecord {
        seq: 1,
        time_ns: 0,
        device: mouse(),
        kind: RawInputKind::Button {
            button: PointerButton::Left,
            state: KeyState::Pressed,
        },
    }
    .encode();

    let mut btn0 = btn_ok;
    btn0[24] = 0;
    btn0[25] = 0;
    assert_eq!(
        RawInputRecord::decode(&btn0),
        Err(RawInputDecodeError::InvalidField)
    );
    let mut btn6 = btn_ok;
    btn6[24] = 6;
    assert_eq!(
        RawInputRecord::decode(&btn6),
        Err(RawInputDecodeError::InvalidField)
    );

    let overflow_ok = RawInputRecord {
        seq: 1,
        time_ns: 0,
        device: kb(),
        kind: RawInputKind::Overflow { dropped: 1 },
    }
    .encode();
    let mut drop0 = overflow_ok;
    drop0[24] = 0;
    assert_eq!(
        RawInputRecord::decode(&drop0),
        Err(RawInputDecodeError::InvalidField)
    );
    let mut opad = overflow_ok;
    opad[28] = 1;
    assert_eq!(
        RawInputRecord::decode(&opad),
        Err(RawInputDecodeError::ReservedBitsSet)
    );
}
