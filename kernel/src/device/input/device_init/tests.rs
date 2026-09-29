use super::*;
use std::collections::VecDeque;
use std::vec::Vec;

/// Runs `init` against a device model until it settles, returning every byte sent and the
/// final status. The model maps each received byte to its reply bytes.
fn run(init: &mut DeviceInit, mut device: impl FnMut(u8) -> Vec<u8>) -> (Vec<u8>, InitStatus) {
    let mut sent = Vec::new();
    let mut replies = VecDeque::new();
    let mut step = init.start();
    loop {
        if let Some(byte) = step.send {
            sent.push(byte);
            replies.extend(device(byte));
        }
        if step.status != InitStatus::Pending {
            return (sent, step.status);
        }
        let Some(reply) = replies.pop_front() else {
            return (sent, step.status);
        };
        step = init.on_byte(reply);
    }
}

fn keyboard_model(set: u8) -> impl FnMut(u8) -> Vec<u8> {
    let mut last = None;
    move |byte| {
        let reply = match (last, byte) {
            (_, DEVICE_RESET) => vec![DEVICE_ACK, DEVICE_BAT_PASSED],
            (Some(KEYBOARD_SCANCODE_SET), KEYBOARD_QUERY_SET) => vec![DEVICE_ACK, set],
            _ => vec![DEVICE_ACK],
        };
        last = Some(byte);
        reply
    }
}

/// An IntelliMouse that reports `max_id` once the matching knock has been sent.
fn mouse_model(max_id: u8) -> impl FnMut(u8) -> Vec<u8> {
    let mut rates = Vec::new();
    let mut id = 0;
    let mut rate_next = false;
    move |byte| {
        if rate_next {
            rate_next = false;
            rates.push(byte);
            let tail = &rates[rates.len().saturating_sub(3)..];
            if tail == [200, 100, 80] && max_id >= 3 {
                id = 3;
            } else if tail == [200, 200, 80] && id == 3 && max_id >= 4 {
                id = 4;
            }
            return vec![DEVICE_ACK];
        }
        match byte {
            DEVICE_RESET => {
                id = 0;
                vec![DEVICE_ACK, DEVICE_BAT_PASSED, 0x00]
            }
            MOUSE_SAMPLE_RATE => {
                rate_next = true;
                vec![DEVICE_ACK]
            }
            MOUSE_GET_ID => vec![DEVICE_ACK, id],
            _ => vec![DEVICE_ACK],
        }
    }
}

const KEYBOARD_SENDS: [u8; 9] = [0xFF, 0xF5, 0xF0, 0x02, 0xF0, 0x00, 0xF3, 0x7F, 0xF4];

#[test]
fn keyboard_program_selects_and_verifies_set_2_then_enables_scanning() {
    let mut init = DeviceInit::keyboard();
    let (sent, status) = run(&mut init, keyboard_model(KEYBOARD_SET_2));
    assert_eq!(sent, KEYBOARD_SENDS);
    assert_eq!(status, InitStatus::Ready);
}

#[test]
fn mouse_protocol_follows_the_id_after_each_knock() {
    let wheel_knock = [0xF3, 200, 0xF3, 100, 0xF3, 80, 0xF2];
    let explorer_knock = [0xF3, 200, 0xF3, 200, 0xF3, 80, 0xF2];
    for (max_id, protocol, knocks) in [
        (0, MouseProtocol::Standard, 1),
        (3, MouseProtocol::Wheel, 2),
        (4, MouseProtocol::Explorer, 2),
    ] {
        let mut init = DeviceInit::mouse();
        let (sent, status) = run(&mut init, mouse_model(max_id));
        let mut expected = vec![0xFF];
        expected.extend(wheel_knock);
        if knocks == 2 {
            expected.extend(explorer_knock);
        }
        expected.push(0xF4);
        assert_eq!(sent, expected, "max_id {max_id}");
        assert_eq!(status, InitStatus::Ready);
        assert_eq!(init.protocol(), protocol);
    }
}

#[test]
fn every_awaited_response_arms_a_fresh_epoch_and_ready_cancels() {
    let mut init = DeviceInit::keyboard();
    let mut model = keyboard_model(KEYBOARD_SET_2);
    let mut replies = VecDeque::new();
    let mut step = init.start();
    let mut last_epoch = 0;
    let mut arms = 0;
    loop {
        match step.timer {
            TimerAction::Arm { wait_ns, epoch } => {
                assert!(epoch > last_epoch);
                last_epoch = epoch;
                arms += 1;
                assert!(wait_ns == RESPONSE_TIMEOUT_NS || wait_ns == BAT_TIMEOUT_NS);
            }
            TimerAction::Cancel => break,
            TimerAction::Keep => panic!("clean responses never keep the timer"),
        }
        if let Some(byte) = step.send {
            replies.extend(model(byte));
        }
        step = init.on_byte(replies.pop_front().expect("model replied"));
    }
    assert_eq!(step.status, InitStatus::Ready);
    // Nine sends plus the BAT and the scan-set answer.
    assert_eq!(arms, 11);
}

#[test]
fn bat_wait_uses_the_long_timeout() {
    let mut init = DeviceInit::keyboard();
    init.start();
    let step = init.on_byte(DEVICE_ACK);
    assert_eq!(step.send, None);
    assert!(matches!(
        step.timer,
        TimerAction::Arm {
            wait_ns: BAT_TIMEOUT_NS,
            ..
        }
    ));
}

#[test]
fn resend_repeats_the_same_byte_up_to_the_attempt_limit() {
    let mut init = DeviceInit::keyboard();
    assert_eq!(init.start().send, Some(DEVICE_RESET));
    for _ in 1..SEND_ATTEMPTS {
        let step = init.on_byte(DEVICE_RESEND);
        assert_eq!(step.send, Some(DEVICE_RESET));
        assert!(matches!(step.timer, TimerAction::Arm { .. }));
    }
    let step = init.on_byte(DEVICE_RESEND);
    assert_eq!(step.send, None);
    assert_eq!(step.timer, TimerAction::Cancel);
    assert_eq!(
        step.status,
        InitStatus::Failed(InitFailure::ResendExhausted)
    );
}

#[test]
fn attempts_reset_for_each_new_byte() {
    let mut init = DeviceInit::keyboard();
    init.start();
    init.on_byte(DEVICE_RESEND);
    init.on_byte(DEVICE_RESEND);
    init.on_byte(DEVICE_ACK);
    init.on_byte(DEVICE_BAT_PASSED);
    for _ in 1..SEND_ATTEMPTS {
        assert_eq!(
            init.on_byte(DEVICE_RESEND).send,
            Some(DEVICE_DISABLE_SCANNING)
        );
    }
    assert_eq!(init.status(), InitStatus::Pending);
}

#[test]
fn typematic_refused_is_skipped_and_scanning_still_enabled() {
    let mut init = DeviceInit::keyboard();
    let mut last = None;
    let (sent, status) = run(&mut init, |byte| {
        let reply = match (last, byte) {
            (_, DEVICE_RESET) => vec![DEVICE_ACK, DEVICE_BAT_PASSED],
            (Some(KEYBOARD_SCANCODE_SET), KEYBOARD_QUERY_SET) => vec![DEVICE_ACK, KEYBOARD_SET_2],
            (_, KEYBOARD_TYPEMATIC) => vec![DEVICE_RESEND],
            _ => vec![DEVICE_ACK],
        };
        last = Some(byte);
        reply
    });
    assert_eq!(status, InitStatus::Ready);
    assert_eq!(
        sent,
        [0xFF, 0xF5, 0xF0, 0x02, 0xF0, 0x00, 0xF3, 0xF3, 0xF3, 0xF4]
    );
}

#[test]
fn failed_bat_fails_the_device() {
    for code in DEVICE_BAT_FAILED {
        let mut init = DeviceInit::keyboard();
        init.start();
        init.on_byte(DEVICE_ACK);
        let step = init.on_byte(code);
        assert_eq!(step.status, InitStatus::Failed(InitFailure::BatFailed));
        assert_eq!(step.timer, TimerAction::Cancel);
    }
}

#[test]
fn keyboard_that_reports_another_set_is_rejected() {
    for set in KEYBOARD_OTHER_SETS {
        let mut init = DeviceInit::keyboard();
        let (_, status) = run(&mut init, keyboard_model(set));
        assert_eq!(status, InitStatus::Failed(InitFailure::ScanSetRejected));
    }
}

#[test]
fn scancodes_typed_during_boot_are_noise_and_keep_the_timer() {
    let mut init = DeviceInit::keyboard();
    init.start();
    init.on_byte(DEVICE_ACK);
    // Held keys before BAT and before F5 is acknowledged.
    for byte in [0x1C, 0xF0, 0x1C] {
        let step = init.on_byte(byte);
        assert!(step.noise);
        assert_eq!(step.timer, TimerAction::Keep);
        assert_eq!(step.send, None);
    }
    assert_eq!(init.on_byte(DEVICE_BAT_PASSED).send, Some(0xF5));
    let step = init.on_byte(0x1C);
    assert!(step.noise);
    assert_eq!(init.on_byte(DEVICE_ACK).send, Some(0xF0));
    assert_eq!(init.status(), InitStatus::Pending);
}

#[test]
fn timeout_with_the_current_epoch_fails_the_device() {
    let mut init = DeviceInit::mouse();
    let TimerAction::Arm { epoch, .. } = init.start().timer else {
        panic!("start arms a timeout");
    };
    assert!(init.on_timeout(epoch));
    assert_eq!(init.status(), InitStatus::Failed(InitFailure::Timeout));
    assert!(!init.on_timeout(epoch), "expiry is decided once");
}

#[test]
fn stale_timeout_after_the_response_is_ignored() {
    let mut init = DeviceInit::keyboard();
    let TimerAction::Arm { epoch: first, .. } = init.start().timer else {
        panic!("start arms a timeout");
    };
    let TimerAction::Arm { epoch: second, .. } = init.on_byte(DEVICE_ACK).timer else {
        panic!("ACK arms the BAT timeout");
    };
    assert_ne!(first, second);
    assert!(!init.on_timeout(first));
    assert_eq!(init.status(), InitStatus::Pending);
    assert!(init.on_timeout(second));
}

#[test]
fn resend_rearms_under_a_new_epoch() {
    let mut init = DeviceInit::keyboard();
    let TimerAction::Arm { epoch: first, .. } = init.start().timer else {
        panic!("start arms a timeout");
    };
    let TimerAction::Arm { epoch: resent, .. } = init.on_byte(DEVICE_RESEND).timer else {
        panic!("resend arms a timeout");
    };
    assert!(!init.on_timeout(first));
    assert!(init.on_timeout(resent));
}

#[test]
fn settled_devices_ignore_timeouts_and_bytes() {
    let mut init = DeviceInit::keyboard();
    run(&mut init, keyboard_model(KEYBOARD_SET_2));
    assert!(!init.on_timeout(init.epoch));
    let step = init.on_byte(DEVICE_ACK);
    assert!(step.noise);
    assert_eq!(init.status(), InitStatus::Ready);

    let mut idle = DeviceInit::mouse();
    assert_eq!(idle.status(), InitStatus::Idle);
    assert!(idle.on_byte(DEVICE_ACK).noise);
    assert!(!idle.on_timeout(0));
    assert_eq!(idle.status(), InitStatus::Idle);
}

#[test]
fn silent_device_stays_pending_until_its_timeout() {
    let mut init = DeviceInit::keyboard();
    let (sent, status) = run(&mut init, |_| Vec::new());
    assert_eq!(sent, [DEVICE_RESET]);
    assert_eq!(status, InitStatus::Pending);
    assert!(init.on_timeout(init.epoch));
}

#[test]
fn driver_failure_cancels_the_timer() {
    let mut init = DeviceInit::mouse();
    init.start();
    let step = init.fail(InitFailure::ControllerTimeout);
    assert_eq!(step.timer, TimerAction::Cancel);
    assert_eq!(
        init.status(),
        InitStatus::Failed(InitFailure::ControllerTimeout)
    );
}

#[test]
fn restart_runs_the_program_again_from_reset() {
    let mut init = DeviceInit::mouse();
    run(&mut init, mouse_model(4));
    assert_eq!(init.protocol(), MouseProtocol::Explorer);
    let (sent, status) = run(&mut init, mouse_model(0));
    assert_eq!(sent.first(), Some(&DEVICE_RESET));
    assert_eq!(status, InitStatus::Ready);
    assert_eq!(init.protocol(), MouseProtocol::Standard);
}
