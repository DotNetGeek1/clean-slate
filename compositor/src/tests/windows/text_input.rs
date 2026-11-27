//! #309 text input: `Text` after key presses, compositor key repeat against the fake clock,
//! and no repeat after focus moves.

use super::*;
use clean_slate_graphics::input::{KEY_ENTER, KEY_ESCAPE, KEY_LEFT_CTRL};
use clean_slate_graphics::protocol::Features;

const MS: u64 = 1_000_000;
const KEY_B: KeyUsage = KeyUsage(0x05);
const KEY_BACKSPACE: KeyUsage = KeyUsage(0x2A);
const KEY_C: KeyUsage = KeyUsage(0x06);

const TEXT: Features = Features(Features::TEXT_INPUT);

fn typing_client(h: &mut Harness, holder: u64, features: Features) -> Client {
    let mut c = h.connect(holder);
    h.hello_with(&mut c, features);
    c
}

/// Client A (focused) and client B, both with `features`.
fn typing_pair(features: Features) -> Pair {
    let mut h = Harness::decorated();
    let mut a = typing_client(&mut h, 2, features);
    let mut b = typing_client(&mut h, 3, features);
    let ba = h.buffer(&mut a, SIDE, SIDE, RED);
    let bb = h.buffer(&mut b, SIDE, SIDE, BLUE);
    let (sa, wa, _) = map(&mut h, &mut a, ba, A_AT);
    let (sb, wb, _) = map(&mut h, &mut b, bb, B_AT);
    h.drain(&a);
    h.drain(&b);
    Pair {
        h,
        a,
        b,
        sa,
        wa,
        sb,
        wb,
    }
}

/// Input events in order, as short strings: `K+a`, `K-a`, `R a`, `T "a"`.
fn typed(inbox: &Inbox) -> Vec<String> {
    inbox
        .events
        .iter()
        .filter_map(|(_, e)| match e {
            Event::Key { usage, state, .. } => Some(format!(
                "K{}{:02x}",
                if *state == KeyState::Pressed {
                    '+'
                } else {
                    '-'
                },
                usage.0
            )),
            Event::KeyRepeat { usage, .. } => Some(format!("R{:02x}", usage.0)),
            Event::Text { text, .. } => Some(format!("T{:?}", text.as_str())),
            _ => None,
        })
        .collect()
}

#[test]
fn welcome_offers_text_input_when_asked() {
    let mut h = Harness::new();
    let mut c = h.connect(2);
    let inbox = h.roundtrip(
        &mut c,
        Request::Hello {
            version: ProtocolVersion {
                major: PROTOCOL_MAJOR,
                minor: PROTOCOL_MINOR,
            },
            features: Features(Features::KNOWN),
        },
    );
    assert!(
        matches!(
            inbox.events.as_slice(),
            [(_, Event::Welcome { features, .. })]
                if *features == Features(TEXT.0 | Features::OUTPUT_EVENTS)
        ),
        "{inbox:?}"
    );
}

#[test]
fn a_press_sends_text_with_the_key_serial() {
    let Pair { mut h, a, .. } = typing_pair(TEXT);
    key(&mut h, KEY_A, KeyState::Pressed);
    key(&mut h, KEY_A, KeyState::Released);
    let inbox = h.drain(&a);
    assert_eq!(typed(&inbox), ["K+04", "T\"a\"", "K-04"]);
    let serials: Vec<Serial> = inbox
        .events
        .iter()
        .filter_map(|(_, e)| match e {
            Event::Key {
                serial,
                state: KeyState::Pressed,
                ..
            }
            | Event::Text { serial, .. } => Some(*serial),
            _ => None,
        })
        .collect();
    assert_eq!(serials.len(), 2);
    assert_eq!(serials[0], serials[1], "Text quotes its Key's serial");

    key(&mut h, KEY_LEFT_SHIFT, KeyState::Pressed);
    key(&mut h, KEY_A, KeyState::Pressed);
    key(&mut h, KEY_A, KeyState::Released);
    key(&mut h, KEY_LEFT_SHIFT, KeyState::Released);
    assert_eq!(
        typed(&h.drain(&a)),
        ["K+e1", "K+04", "T\"A\"", "K-04", "K-e1"]
    );
}

#[test]
fn control_keys_and_ctrl_combos_send_no_text() {
    let Pair { mut h, a, .. } = typing_pair(TEXT);
    for usage in [KEY_ENTER, KEY_BACKSPACE, KEY_ESCAPE, KeyUsage(0x52)] {
        key(&mut h, usage, KeyState::Pressed);
        key(&mut h, usage, KeyState::Released);
    }
    key(&mut h, KEY_LEFT_CTRL, KeyState::Pressed);
    key(&mut h, KEY_C, KeyState::Pressed);
    key(&mut h, KEY_C, KeyState::Released);
    key(&mut h, KEY_LEFT_CTRL, KeyState::Released);
    let inbox = h.drain(&a);
    assert_eq!(count(&inbox, |e| matches!(e, Event::Text { .. })), 0);
    assert_eq!(count(&inbox, |e| matches!(e, Event::Key { .. })), 12);
}

#[test]
fn clients_without_text_input_get_raw_keys_only() {
    let Pair { mut h, a, .. } = typing_pair(Features(0));
    let t0 = h.waiter.now_ns;
    key(&mut h, KEY_A, KeyState::Pressed);
    assert_eq!(h.comp.repeater().deadline(), None, "nothing armed");
    h.advance_to(t0 + 2_000 * MS);
    key(&mut h, KEY_A, KeyState::Released);
    assert_eq!(typed(&h.drain(&a)), ["K+04", "K-04"]);
}

#[test]
fn a_held_key_repeats_after_the_delay_at_the_rate_until_released() {
    let Pair { mut h, a, .. } = typing_pair(TEXT);
    let repeat = h.comp.config().repeat;
    let t0 = h.waiter.now_ns;
    key(&mut h, KEY_A, KeyState::Pressed);
    assert_eq!(h.comp.repeater().deadline(), Some(t0 + repeat.delay_ns));
    assert_eq!(
        h.comp.plan_wait(t0),
        WaitPlan::Block(Some(t0 + repeat.delay_ns)),
        "the loop wakes for the repeat"
    );
    assert_eq!(typed(&h.drain(&a)), ["K+04", "T\"a\""]);

    h.advance_to(t0 + repeat.delay_ns - 1);
    assert!(h.drain(&a).events.is_empty(), "nothing before the delay");

    h.advance_to(t0 + repeat.delay_ns + 3 * repeat.interval_ns);
    let inbox = h.drain(&a);
    assert_eq!(
        typed(&inbox),
        ["R04", "T\"a\"", "R04", "T\"a\"", "R04", "T\"a\"", "R04", "T\"a\""]
    );
    let times: Vec<u64> = inbox
        .events
        .iter()
        .filter_map(|(_, e)| match e {
            Event::KeyRepeat { time_ns, .. } => Some(*time_ns),
            _ => None,
        })
        .collect();
    let first = t0 + repeat.delay_ns;
    assert_eq!(
        times,
        (0..4)
            .map(|i| first + i * repeat.interval_ns)
            .collect::<Vec<_>>()
    );

    key(&mut h, KEY_A, KeyState::Released);
    assert_eq!(h.comp.repeater().deadline(), None);
    h.advance_to(t0 + 5_000 * MS);
    assert_eq!(typed(&h.drain(&a)), ["K-04"]);
    assert_eq!(h.comp.plan_wait(h.waiter.now_ns), WaitPlan::Block(None));
}

#[test]
fn held_backspace_repeats_without_text_and_shift_changes_repeated_text() {
    let Pair { mut h, a, .. } = typing_pair(TEXT);
    let repeat = h.comp.config().repeat;
    let t0 = h.waiter.now_ns;
    key(&mut h, KEY_BACKSPACE, KeyState::Pressed);
    h.advance_to(t0 + repeat.delay_ns + repeat.interval_ns);
    key(&mut h, KEY_BACKSPACE, KeyState::Released);
    assert_eq!(typed(&h.drain(&a)), ["K+2a", "R2a", "R2a", "K-2a"]);

    let t1 = h.waiter.now_ns;
    key(&mut h, KEY_B, KeyState::Pressed);
    h.advance_to(t1 + repeat.delay_ns);
    key(&mut h, KEY_LEFT_SHIFT, KeyState::Pressed);
    let t2 = h.waiter.now_ns;
    h.advance_to(t2 + repeat.interval_ns);
    assert_eq!(
        typed(&h.drain(&a)),
        ["K+05", "T\"b\"", "R05", "T\"b\"", "K+e1", "R05", "T\"B\""]
    );
}

#[test]
fn a_newer_press_takes_over_the_repeat() {
    let Pair { mut h, a, .. } = typing_pair(TEXT);
    let repeat = h.comp.config().repeat;
    let t0 = h.waiter.now_ns;
    key(&mut h, KEY_A, KeyState::Pressed);
    h.advance_to(t0 + repeat.delay_ns);
    key(&mut h, KEY_B, KeyState::Pressed);
    key(&mut h, KEY_A, KeyState::Released);
    let t1 = h.waiter.now_ns;
    h.advance_to(t1 + repeat.delay_ns);
    assert_eq!(
        typed(&h.drain(&a)),
        ["K+04", "T\"a\"", "R04", "T\"a\"", "K+05", "T\"b\"", "K-04", "R05", "T\"b\""]
    );
}

#[test]
fn no_repeat_after_focus_moves() {
    let Pair {
        mut h, a, b, sb, ..
    } = typing_pair(TEXT);
    let repeat = h.comp.config().repeat;
    let t0 = h.waiter.now_ns;
    key(&mut h, KEY_A, KeyState::Pressed);
    h.drain(&a);
    click(&mut h, B_ONLY);
    assert_eq!(h.comp.wm().focus.map(|k| k.surface), Some(sb));
    assert_eq!(h.comp.repeater().deadline(), None, "focus change disarms");
    h.advance_to(t0 + 3 * repeat.delay_ns);
    for client in [&a, &b] {
        let inbox = h.drain(client);
        assert_eq!(
            count(&inbox, |e| matches!(
                e,
                Event::KeyRepeat { .. } | Event::Text { .. }
            )),
            0,
            "{inbox:?}"
        );
    }
    key(&mut h, KEY_A, KeyState::Released);
    assert_eq!(typed(&h.drain(&b)), ["K-04"], "the release follows focus");
}

#[test]
fn input_reset_stops_the_repeat() {
    let Pair { mut h, a, .. } = typing_pair(TEXT);
    let repeat = h.comp.config().repeat;
    let t0 = h.waiter.now_ns;
    key(&mut h, KEY_A, KeyState::Pressed);
    feed(
        &mut h,
        KEYBOARD_INDEX,
        &[RawInputKind::Overflow { dropped: 1 }],
    );
    assert_eq!(h.comp.repeater().deadline(), None);
    h.advance_to(t0 + 3 * repeat.delay_ns);
    assert_eq!(
        count(&h.drain(&a), |e| matches!(e, Event::KeyRepeat { .. })),
        0
    );
}
