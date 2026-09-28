use super::display::{
    DisplayError, DisplayModeInfo, DisplayWireError, PresentRequest, PresentState, PresentStatus,
    ScanoutMapping, DISPLAY_MODE_INFO_BYTES, PRESENT_REQUEST_BYTES, PRESENT_STATUS_BYTES,
    SCANOUT_MAPPING_BYTES,
};
use super::input::{InputDeviceInfo, InputWireError, INPUT_DEVICE_INFO_BYTES};
use super::status::{
    STATUS_EACCES, STATUS_EAGAIN, STATUS_EBADF, STATUS_EINVAL, STATUS_EIO, STATUS_ENODEV,
    STATUS_ENOSPC, STATUS_ENOSYS, STATUS_ENOTRECOVERABLE, STATUS_ERANGE, STATUS_ESTALE,
    STATUS_ETIMEDOUT, STATUS_RANGE_START,
};
use crate::geometry::BufferRect;
use crate::ids::{InputDeviceId, OutputId};
use crate::limits::{MAX_PRESENT_DAMAGE_RECTS, SCANOUT_BUFFER_COUNT};
use crate::mode::REFERENCE_MODE;
const NETWORK_STATUS_PENDING: u64 = u64::MAX - 15;

#[test]
fn abi_size_assertions() {
    const _: () = assert!(PRESENT_REQUEST_BYTES == 8 + MAX_PRESENT_DAMAGE_RECTS * 8);
    const _: () = assert!(PRESENT_REQUEST_BYTES == 136);
    const _: () = assert!(DISPLAY_MODE_INFO_BYTES == 32);
    const _: () = assert!(SCANOUT_MAPPING_BYTES == 32);
    const _: () = assert!(PRESENT_STATUS_BYTES == 40);
    const _: () = assert!(INPUT_DEVICE_INFO_BYTES == 16);
    const _: () = assert!(MAX_PRESENT_DAMAGE_RECTS <= u8::MAX as usize);
    const _: () = assert!(SCANOUT_BUFFER_COUNT < 0xFF);
}

#[test]
fn status_range_and_distinctness() {
    let all = [
        STATUS_EACCES,
        STATUS_EINVAL,
        STATUS_ENOSPC,
        STATUS_ENOSYS,
        STATUS_ESTALE,
        STATUS_EBADF,
        STATUS_EIO,
        STATUS_EAGAIN,
        STATUS_ENODEV,
        STATUS_ERANGE,
        STATUS_ETIMEDOUT,
        STATUS_ENOTRECOVERABLE,
    ];
    for s in all {
        assert!(s >= STATUS_RANGE_START);
    }
    for (i, a) in all.iter().enumerate() {
        for b in all.iter().skip(i + 1) {
            assert_ne!(a, b);
        }
    }
    assert_ne!(STATUS_EAGAIN, NETWORK_STATUS_PENDING);
}

fn current_output() -> OutputId {
    OutputId::new(0, 1).unwrap()
}

fn sample_mode_info() -> DisplayModeInfo {
    DisplayModeInfo {
        output: current_output(),
        mode: REFERENCE_MODE,
        scanout_buffer_count: SCANOUT_BUFFER_COUNT as u8,
        max_present_damage_rects: MAX_PRESENT_DAMAGE_RECTS as u8,
    }
}

#[test]
fn display_abi_round_trips() {
    let mode = sample_mode_info();
    assert_eq!(DisplayModeInfo::decode(&mode.encode()).unwrap(), mode);

    let map = ScanoutMapping {
        output: current_output(),
        buffer_index: 0,
        user_va: 0x1000,
        byte_len: 4_096_000,
        stride_bytes: 5120,
    };
    assert_eq!(ScanoutMapping::decode(&map.encode()).unwrap(), map);

    let one_rect = PresentRequest {
        output: current_output(),
        buffer_index: 0,
        damage_count: 1,
        rects: {
            let mut r = [BufferRect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            }; MAX_PRESENT_DAMAGE_RECTS];
            r[0] = BufferRect {
                x: 0,
                y: 0,
                width: 1280,
                height: 800,
            };
            r
        },
    };
    assert_eq!(
        PresentRequest::decode(&one_rect.encode()).unwrap(),
        one_rect
    );

    let mut sixteen = one_rect;
    sixteen.damage_count = 16;
    for i in 0..16 {
        sixteen.rects[i] = BufferRect {
            x: i as u16,
            y: 0,
            width: 1,
            height: 1,
        };
    }
    assert_eq!(PresentRequest::decode(&sixteen.encode()).unwrap(), sixteen);

    let status = PresentStatus {
        output: current_output(),
        state: PresentState::InFlight,
        in_flight_index: Some(0),
        last_error: None,
        submitted_seq: 3,
        completed_seq: 2,
        completed_ns: 99,
    };
    assert_eq!(PresentStatus::decode(&status.encode()).unwrap(), status);

    let devices = InputDeviceInfo {
        keyboard: Some(InputDeviceId::new(0, 1).unwrap()),
        mouse: Some(InputDeviceId::new(1, 1).unwrap()),
        queue_depth: 128,
        record_bytes: 32,
    };
    assert_eq!(InputDeviceInfo::decode(&devices.encode()).unwrap(), devices);
}

#[test]
fn display_error_round_trips() {
    for code in 1..=9u16 {
        let err = DisplayError::from_code(code).unwrap();
        assert_eq!(err.code(), code);
        assert_eq!(DisplayError::from_code(err.code()), Some(err));
        assert_eq!(DisplayError::from_status(err.status()), Some(err));
    }
}

#[test]
fn present_request_decode_matrix() {
    let ok = PresentRequest {
        output: current_output(),
        buffer_index: 0,
        damage_count: 1,
        rects: [BufferRect {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
        }; MAX_PRESENT_DAMAGE_RECTS],
    }
    .encode();

    assert!(PresentRequest::decode(&ok[..135]).is_err());
    assert!(PresentRequest::decode(&[0u8; 137]).is_err());

    let mut reserved = ok;
    reserved[6] = 1;
    assert_eq!(
        PresentRequest::decode(&reserved),
        Err(DisplayWireError::Malformed)
    );

    let mut slot1 = ok;
    slot1[5] = 1;
    slot1[16] = 1;
    assert_eq!(
        PresentRequest::decode(&slot1),
        Err(DisplayWireError::Malformed)
    );

    let mut epoch0 = ok;
    epoch0[0] = 0;
    epoch0[1] = 0;
    epoch0[2] = 0;
    epoch0[3] = 0;
    assert_eq!(
        PresentRequest::decode(&epoch0),
        Err(DisplayWireError::Malformed)
    );

    let mut count20 = ok;
    count20[5] = 20;
    for i in 0..16 {
        let base = 8 + 8 * i;
        count20[base + 4] = 1;
        count20[base + 6] = 1;
    }
    let decoded = PresentRequest::decode(&count20).unwrap();
    assert_eq!(decoded.damage_count, 20);
    assert_eq!(
        decoded.validate(current_output(), &REFERENCE_MODE),
        Err(DisplayError::InvalidDamage)
    );
}

#[test]
fn present_request_validate_matrix() {
    let current = current_output();
    let mut base = PresentRequest {
        output: current,
        buffer_index: 0,
        damage_count: 1,
        rects: [BufferRect {
            x: 0,
            y: 0,
            width: 1280,
            height: 800,
        }; MAX_PRESENT_DAMAGE_RECTS],
    };

    let stale = PresentRequest {
        output: OutputId::new(0, 2).unwrap(),
        ..base
    };
    assert_eq!(
        stale.validate(current, &REFERENCE_MODE),
        Err(DisplayError::StaleEpoch)
    );

    base.buffer_index = 2;
    assert_eq!(
        base.validate(current, &REFERENCE_MODE),
        Err(DisplayError::InvalidBuffer)
    );
    base.buffer_index = 0;

    base.damage_count = 0;
    assert_eq!(
        base.validate(current, &REFERENCE_MODE),
        Err(DisplayError::InvalidDamage)
    );
    base.damage_count = 17;
    assert_eq!(
        base.validate(current, &REFERENCE_MODE),
        Err(DisplayError::InvalidDamage)
    );
    base.damage_count = 1;

    base.rects[0].width = 0;
    assert_eq!(
        base.validate(current, &REFERENCE_MODE),
        Err(DisplayError::InvalidDamage)
    );
    base.rects[0] = BufferRect {
        x: 1279,
        y: 0,
        width: 2,
        height: 1,
    };
    assert_eq!(
        base.validate(current, &REFERENCE_MODE),
        Err(DisplayError::InvalidDamage)
    );
    base.rects[0] = BufferRect {
        x: 0,
        y: 0,
        width: 1280,
        height: 800,
    };
    assert!(base.validate(current, &REFERENCE_MODE).is_ok());

    let stale_and_bad = PresentRequest {
        output: OutputId::new(0, 2).unwrap(),
        buffer_index: 9,
        ..base
    };
    assert_eq!(
        stale_and_bad.validate(current, &REFERENCE_MODE),
        Err(DisplayError::StaleEpoch)
    );
}

#[test]
fn present_status_decode_matrix() {
    let ok = PresentStatus {
        output: current_output(),
        state: PresentState::Idle,
        in_flight_index: None,
        last_error: None,
        submitted_seq: 1,
        completed_seq: 1,
        completed_ns: 50,
    }
    .encode();

    let mut state4 = ok;
    state4[4] = 4;
    assert_eq!(
        PresentStatus::decode(&state4),
        Err(DisplayWireError::Malformed)
    );

    let mut inflight_none = ok;
    inflight_none[4] = 1;
    inflight_none[5] = 0xFF;
    assert_eq!(
        PresentStatus::decode(&inflight_none),
        Err(DisplayWireError::Malformed)
    );

    let mut idle_idx = ok;
    idle_idx[5] = 0;
    assert_eq!(
        PresentStatus::decode(&idle_idx),
        Err(DisplayWireError::Malformed)
    );

    let mut err10 = ok;
    err10[6] = 10;
    assert_eq!(
        PresentStatus::decode(&err10),
        Err(DisplayWireError::Malformed)
    );

    let mut completed_high = ok;
    completed_high[16] = 2;
    assert_eq!(
        PresentStatus::decode(&completed_high),
        Err(DisplayWireError::Malformed)
    );

    let mut ns_without_completed = ok;
    ns_without_completed[16] = 0;
    ns_without_completed[24] = 1;
    assert_eq!(
        PresentStatus::decode(&ns_without_completed),
        Err(DisplayWireError::Malformed)
    );

    let mut reserved = ok;
    reserved[32] = 1;
    assert_eq!(
        PresentStatus::decode(&reserved),
        Err(DisplayWireError::Malformed)
    );
}

#[test]
fn input_device_info_decode_matrix() {
    let absent = InputDeviceInfo {
        keyboard: None,
        mouse: None,
        queue_depth: 128,
        record_bytes: 32,
    };
    assert_eq!(InputDeviceInfo::decode(&absent.encode()).unwrap(), absent);

    let mut gen0 = absent.encode();
    gen0[0] = 0x01;
    assert_eq!(
        InputDeviceInfo::decode(&gen0),
        Err(InputWireError::Malformed)
    );

    let mut pad = absent.encode();
    pad[12] = 1;
    assert_eq!(
        InputDeviceInfo::decode(&pad),
        Err(InputWireError::Malformed)
    );
}
