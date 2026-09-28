//! Destination: `graphics/src/input/tests.rs`, included from `graphics/src/input.rs` with
//! `#[cfg(test)] mod tests;`.
//!
//! Stage D contract: `ModifierTracker` exactly per wire §6.4, button state, and the
//! `InputReset` path (SPEC §6).

use crate::input::{
    reset_seat, ButtonTracker, KeyState, KeyUsage, ModifierTracker, Modifiers, PointerButton,
    KEY_A, KEY_CAPS_LOCK, KEY_ENTER, KEY_ESCAPE, KEY_LEFT_ALT, KEY_LEFT_CTRL, KEY_LEFT_GUI,
    KEY_LEFT_SHIFT, KEY_NUM_LOCK, KEY_RIGHT_ALT, KEY_RIGHT_CTRL, KEY_RIGHT_GUI, KEY_RIGHT_SHIFT,
};
use crate::protocol::{Event, Tagged};

const P: KeyState = KeyState::Pressed;
const R: KeyState = KeyState::Released;

fn m(bits: u16) -> Modifiers {
    Modifiers::from_bits(bits).unwrap()
}

const NONE: u16 = 0;

const BUTTONS: [PointerButton; 5] = [
    PointerButton::Left,
    PointerButton::Right,
    PointerButton::Middle,
    PointerButton::Back,
    PointerButton::Forward,
];

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

// --- ModifierTracker ----------------------------------------------------------------------

#[test]
fn new_tracker_reports_no_modifiers() {
    assert_eq!(ModifierTracker::new().modifiers(), m(NONE));
    assert_eq!(ModifierTracker::default(), ModifierTracker::new());
}

#[test]
fn each_held_modifier_key_sets_exactly_its_bit() {
    let table = [
        (KEY_LEFT_CTRL, Modifiers::CTRL),
        (KEY_LEFT_SHIFT, Modifiers::SHIFT),
        (KEY_LEFT_ALT, Modifiers::ALT),
        (KEY_LEFT_GUI, Modifiers::SUPER),
        (KEY_RIGHT_CTRL, Modifiers::CTRL),
        (KEY_RIGHT_SHIFT, Modifiers::SHIFT),
        (KEY_RIGHT_ALT, Modifiers::ALT),
        (KEY_RIGHT_GUI, Modifiers::SUPER),
    ];
    for (usage, bit) in table {
        let mut t = ModifierTracker::new();
        assert_eq!(t.fold(usage, P), Some(m(bit)), "usage {usage:?}");
        assert_eq!(t.modifiers(), m(bit));
        assert_eq!(t.fold(usage, R), Some(m(NONE)), "usage {usage:?}");
    }
}

#[test]
fn pair_modifier_stays_set_until_both_keys_are_released() {
    let mut t = ModifierTracker::new();
    assert_eq!(t.fold(KEY_LEFT_SHIFT, P), Some(m(Modifiers::SHIFT)));
    assert_eq!(t.fold(KEY_RIGHT_SHIFT, P), None);
    assert_eq!(t.fold(KEY_LEFT_SHIFT, R), None);
    assert_eq!(t.modifiers(), m(Modifiers::SHIFT));
    assert_eq!(t.fold(KEY_RIGHT_SHIFT, R), Some(m(NONE)));
}

#[test]
fn combined_modifiers_accumulate() {
    let mut t = ModifierTracker::new();
    assert_eq!(t.fold(KEY_LEFT_CTRL, P), Some(m(Modifiers::CTRL)));
    assert_eq!(
        t.fold(KEY_RIGHT_ALT, P),
        Some(m(Modifiers::CTRL | Modifiers::ALT))
    );
    assert_eq!(
        t.fold(KEY_LEFT_GUI, P),
        Some(m(Modifiers::CTRL | Modifiers::ALT | Modifiers::SUPER))
    );
    assert_eq!(
        t.fold(KEY_LEFT_CTRL, R),
        Some(m(Modifiers::ALT | Modifiers::SUPER))
    );
}

#[test]
fn duplicate_transitions_of_held_keys_report_no_change() {
    let mut t = ModifierTracker::new();
    assert!(t.fold(KEY_LEFT_CTRL, P).is_some());
    assert_eq!(t.fold(KEY_LEFT_CTRL, P), None);
    assert!(t.fold(KEY_LEFT_CTRL, R).is_some());
    assert_eq!(t.fold(KEY_LEFT_CTRL, R), None);
    assert_eq!(t.fold(KEY_RIGHT_GUI, R), None);
}

#[test]
fn caps_lock_toggles_only_on_released_to_pressed_transition() {
    let mut t = ModifierTracker::new();
    assert_eq!(t.fold(KEY_CAPS_LOCK, P), Some(m(Modifiers::CAPS_LOCK)));
    assert_eq!(
        t.fold(KEY_CAPS_LOCK, P),
        None,
        "duplicate press must not toggle"
    );
    assert_eq!(t.fold(KEY_CAPS_LOCK, R), None, "release must not toggle");
    assert_eq!(t.modifiers(), m(Modifiers::CAPS_LOCK));
    assert_eq!(t.fold(KEY_CAPS_LOCK, P), Some(m(NONE)));
    assert_eq!(t.fold(KEY_CAPS_LOCK, R), None);
    assert_eq!(t.modifiers(), m(NONE));
}

#[test]
fn num_lock_toggles_independently_of_caps_lock() {
    let mut t = ModifierTracker::new();
    assert_eq!(t.fold(KEY_NUM_LOCK, P), Some(m(Modifiers::NUM_LOCK)));
    assert_eq!(
        t.fold(KEY_CAPS_LOCK, P),
        Some(m(Modifiers::NUM_LOCK | Modifiers::CAPS_LOCK))
    );
    assert_eq!(t.fold(KEY_NUM_LOCK, R), None);
    assert_eq!(t.fold(KEY_NUM_LOCK, P), Some(m(Modifiers::CAPS_LOCK)));
}

#[test]
fn lock_release_without_prior_press_does_not_toggle() {
    let mut t = ModifierTracker::new();
    assert_eq!(t.fold(KEY_CAPS_LOCK, R), None);
    assert_eq!(t.fold(KEY_NUM_LOCK, R), None);
    assert_eq!(t.modifiers(), m(NONE));
}

#[test]
fn locks_combine_with_held_modifiers() {
    let mut t = ModifierTracker::new();
    let _ = t.fold(KEY_CAPS_LOCK, P);
    assert_eq!(
        t.fold(KEY_LEFT_SHIFT, P),
        Some(m(Modifiers::CAPS_LOCK | Modifiers::SHIFT))
    );
}

#[test]
fn every_other_usage_leaves_modifiers_unchanged() {
    let mut t = ModifierTracker::new();
    let _ = t.fold(KEY_CAPS_LOCK, P);
    let _ = t.fold(KEY_LEFT_SHIFT, P);
    let before = t;
    for raw in 0u16..=0xFFFF {
        if (0xE0..=0xE7).contains(&raw) || raw == 0x39 || raw == 0x53 {
            continue;
        }
        for state in [P, R] {
            assert_eq!(t.fold(KeyUsage(raw), state), None, "usage {raw:#x}");
        }
    }
    assert_eq!(t, before);
    for usage in [KEY_A, KEY_ENTER, KEY_ESCAPE] {
        assert_eq!(t.fold(usage, P), None);
    }
}

#[test]
fn reset_clears_held_keys_and_keeps_lock_bits() {
    let mut t = ModifierTracker::new();
    let _ = t.fold(KEY_CAPS_LOCK, P);
    let _ = t.fold(KEY_CAPS_LOCK, R);
    let _ = t.fold(KEY_LEFT_SHIFT, P);
    let _ = t.fold(KEY_RIGHT_CTRL, P);
    assert_eq!(
        t.modifiers(),
        m(Modifiers::CAPS_LOCK | Modifiers::SHIFT | Modifiers::CTRL)
    );
    assert_eq!(t.reset(), Some(m(Modifiers::CAPS_LOCK)));
    assert_eq!(t.modifiers(), m(Modifiers::CAPS_LOCK));
    assert_eq!(
        t.fold(KEY_LEFT_SHIFT, R),
        None,
        "shift was forgotten by reset"
    );
}

#[test]
fn reset_with_nothing_held_reports_no_change() {
    let mut t = ModifierTracker::new();
    let _ = t.fold(KEY_NUM_LOCK, P);
    let _ = t.fold(KEY_NUM_LOCK, R);
    assert_eq!(t.reset(), None);
    assert_eq!(t.modifiers(), m(Modifiers::NUM_LOCK));
    assert_eq!(ModifierTracker::new().reset(), None);
}

#[test]
fn reset_forgets_a_held_lock_key_so_the_next_press_toggles() {
    let mut t = ModifierTracker::new();
    assert_eq!(t.fold(KEY_CAPS_LOCK, P), Some(m(Modifiers::CAPS_LOCK)));
    assert_eq!(t.reset(), None);
    assert_eq!(t.fold(KEY_CAPS_LOCK, P), Some(m(NONE)));
}

/// Reference model written straight from wire §6.4.
#[derive(Default)]
struct Model {
    held: [bool; 8],
    caps_down: bool,
    num_down: bool,
    caps: bool,
    num: bool,
}

impl Model {
    fn value(&self) -> u16 {
        let pair = |a: usize, b: usize| self.held[a] || self.held[b];
        let mut bits = 0;
        if pair(1, 5) {
            bits |= Modifiers::SHIFT;
        }
        if pair(0, 4) {
            bits |= Modifiers::CTRL;
        }
        if pair(2, 6) {
            bits |= Modifiers::ALT;
        }
        if pair(3, 7) {
            bits |= Modifiers::SUPER;
        }
        if self.caps {
            bits |= Modifiers::CAPS_LOCK;
        }
        if self.num {
            bits |= Modifiers::NUM_LOCK;
        }
        bits
    }

    fn apply(&mut self, usage: u16, pressed: bool) {
        match usage {
            0xE0..=0xE7 => self.held[usize::from(usage - 0xE0)] = pressed,
            0x39 => {
                if pressed && !self.caps_down {
                    self.caps = !self.caps;
                }
                self.caps_down = pressed;
            }
            0x53 => {
                if pressed && !self.num_down {
                    self.num = !self.num;
                }
                self.num_down = pressed;
            }
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.held = [false; 8];
        self.caps_down = false;
        self.num_down = false;
    }
}

#[test]
fn property_fold_and_reset_match_reference_model() {
    let usages: [u16; 11] = [
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0x39, 0x53, 0x04,
    ];
    let mut rng = XorShift(0xD1B5_4A32_D192_ED03);
    let mut t = ModifierTracker::new();
    let mut model = Model::default();
    for _ in 0..20_000 {
        let before = model.value();
        let result = if rng.below(50) == 0 {
            model.reset();
            t.reset()
        } else {
            let usage = usages[rng.below(usages.len() as u64) as usize];
            let pressed = rng.below(2) == 0;
            model.apply(usage, pressed);
            t.fold(KeyUsage(usage), if pressed { P } else { R })
        };
        let after = model.value();
        assert_eq!(t.modifiers(), m(after));
        if after == before {
            assert_eq!(result, None);
        } else {
            assert_eq!(result, Some(m(after)));
        }
    }
}

// --- ButtonTracker ------------------------------------------------------------------------

#[test]
fn button_press_and_release_are_transitions() {
    let mut b = ButtonTracker::new();
    assert!(!b.any_pressed());
    assert!(b.fold(PointerButton::Left, P));
    assert!(b.is_pressed(PointerButton::Left));
    assert!(b.any_pressed());
    assert!(b.fold(PointerButton::Left, R));
    assert!(!b.is_pressed(PointerButton::Left));
    assert!(!b.any_pressed());
}

#[test]
fn duplicate_button_transitions_are_reported_as_no_transition() {
    let mut b = ButtonTracker::new();
    assert!(!b.fold(PointerButton::Right, R));
    assert!(b.fold(PointerButton::Right, P));
    assert!(!b.fold(PointerButton::Right, P));
    assert!(b.is_pressed(PointerButton::Right));
}

#[test]
fn buttons_are_tracked_independently() {
    let mut b = ButtonTracker::new();
    for button in BUTTONS {
        assert!(b.fold(button, P));
    }
    assert!(b.fold(PointerButton::Middle, R));
    for button in BUTTONS {
        assert_eq!(b.is_pressed(button), button != PointerButton::Middle);
    }
}

#[test]
fn button_reset_releases_all_and_reports_whether_any_was_pressed() {
    let mut b = ButtonTracker::new();
    assert!(!b.reset());
    let _ = b.fold(PointerButton::Back, P);
    let _ = b.fold(PointerButton::Forward, P);
    assert!(b.reset());
    assert!(!b.any_pressed());
    for button in BUTTONS {
        assert!(!b.is_pressed(button));
    }
    assert!(!b.reset());
    assert_eq!(b, ButtonTracker::default());
}

// --- InputReset path ----------------------------------------------------------------------

#[test]
fn reset_seat_emits_input_reset_then_modifiers_changed_and_clears_trackers() {
    let mut mods = ModifierTracker::new();
    let mut buttons = ButtonTracker::new();
    let _ = mods.fold(KEY_CAPS_LOCK, P);
    let _ = mods.fold(KEY_LEFT_SHIFT, P);
    let _ = buttons.fold(PointerButton::Left, P);
    let events = reset_seat(&mut mods, &mut buttons);
    assert_eq!(
        events,
        [
            Event::InputReset,
            Event::ModifiersChanged {
                modifiers: m(Modifiers::CAPS_LOCK)
            },
        ]
    );
    assert_eq!(mods.modifiers(), m(Modifiers::CAPS_LOCK));
    assert!(!buttons.any_pressed());
    assert!(
        buttons.fold(PointerButton::Left, P),
        "left press after reset is a transition"
    );
}

#[test]
fn reset_seat_always_emits_modifiers_changed_even_when_nothing_changed() {
    let mut mods = ModifierTracker::new();
    let mut buttons = ButtonTracker::new();
    let events = reset_seat(&mut mods, &mut buttons);
    assert_eq!(
        events,
        [
            Event::InputReset,
            Event::ModifiersChanged { modifiers: m(NONE) },
        ]
    );
}

#[test]
fn reset_seat_events_are_valid_unsolicited_frames() {
    let mut mods = ModifierTracker::new();
    let mut buttons = ButtonTracker::new();
    let _ = mods.fold(KEY_NUM_LOCK, P);
    for event in reset_seat(&mut mods, &mut buttons) {
        let bytes = event.encode(0).unwrap();
        assert_eq!(
            Event::decode(&bytes),
            Ok(Tagged {
                tag: 0,
                message: event
            })
        );
    }
}
