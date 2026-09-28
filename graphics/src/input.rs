//! Input wire types (client events and raw-input payloads in Stage C-2).

/// USB HID keyboard/page-0x07 usage id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyUsage(pub u16);

impl KeyUsage {
    pub const fn is_valid(self) -> bool {
        let v = self.0;
        (v >= 0x04 && v <= 0xA4) || (v >= 0xB0 && v <= 0xDD) || (v >= 0xE0 && v <= 0xE7)
    }
}

pub const KEY_A: KeyUsage = KeyUsage(0x04);
pub const KEY_ENTER: KeyUsage = KeyUsage(0x28);
pub const KEY_ESCAPE: KeyUsage = KeyUsage(0x29);
pub const KEY_CAPS_LOCK: KeyUsage = KeyUsage(0x39);
pub const KEY_NUM_LOCK: KeyUsage = KeyUsage(0x53);
pub const KEY_LEFT_CTRL: KeyUsage = KeyUsage(0xE0);
pub const KEY_LEFT_SHIFT: KeyUsage = KeyUsage(0xE1);
pub const KEY_LEFT_ALT: KeyUsage = KeyUsage(0xE2);
pub const KEY_LEFT_GUI: KeyUsage = KeyUsage(0xE3);
pub const KEY_RIGHT_CTRL: KeyUsage = KeyUsage(0xE4);
pub const KEY_RIGHT_SHIFT: KeyUsage = KeyUsage(0xE5);
pub const KEY_RIGHT_ALT: KeyUsage = KeyUsage(0xE6);
pub const KEY_RIGHT_GUI: KeyUsage = KeyUsage(0xE7);

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyState {
    Released = 0,
    Pressed = 1,
}

impl KeyState {
    pub fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Released),
            1 => Some(Self::Pressed),
            _ => None,
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointerButton {
    Left = 1,
    Right = 2,
    Middle = 3,
    Back = 4,
    Forward = 5,
}

impl PointerButton {
    pub fn from_u16(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::Left),
            2 => Some(Self::Right),
            3 => Some(Self::Middle),
            4 => Some(Self::Back),
            5 => Some(Self::Forward),
            _ => None,
        }
    }

    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Modifier bitset on key and pointer events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Modifiers(u16);

impl Modifiers {
    pub const SHIFT: u16 = 1 << 0;
    pub const CTRL: u16 = 1 << 1;
    pub const ALT: u16 = 1 << 2;
    pub const SUPER: u16 = 1 << 3;
    pub const CAPS_LOCK: u16 = 1 << 4;
    pub const NUM_LOCK: u16 = 1 << 5;
    pub const ALL: u16 = 0x3F;

    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !Self::ALL != 0 {
            None
        } else {
            Some(Self(bits))
        }
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn contains(self, mask: u16) -> bool {
        (self.0 & mask) == mask
    }
}

/// Wheel delta in 1/120 detent units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AxisValue120(pub i32);

/// Pure modifier state machine (wire §6.4, frozen).
///
/// Held set: usages `0xE0..=0xE7`, tracked individually. Lock set: `0x39` → `CAPS_LOCK`,
/// `0x53` → `NUM_LOCK`, toggled only on a released→pressed transition of the lock key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ModifierTracker {
    /// Bit `i` set iff usage `0xE0 + i` is held.
    held: u8,
    /// Bit 0: Caps Lock key held; bit 1: Num Lock key held.
    lock_keys_down: u8,
    /// `Modifiers::CAPS_LOCK | Modifiers::NUM_LOCK` subset.
    locks: u16,
}

const LOCK_KEY_CAPS: u8 = 1 << 0;
const LOCK_KEY_NUM: u8 = 1 << 1;

impl ModifierTracker {
    pub const fn new() -> Self {
        Self {
            held: 0,
            lock_keys_down: 0,
            locks: 0,
        }
    }

    pub const fn modifiers(&self) -> Modifiers {
        let held = self.held;
        let mut bits = self.locks;
        if held & ((1 << 1) | (1 << 5)) != 0 {
            bits |= Modifiers::SHIFT;
        }
        if held & ((1 << 0) | (1 << 4)) != 0 {
            bits |= Modifiers::CTRL;
        }
        if held & ((1 << 2) | (1 << 6)) != 0 {
            bits |= Modifiers::ALT;
        }
        if held & ((1 << 3) | (1 << 7)) != 0 {
            bits |= Modifiers::SUPER;
        }
        Modifiers(bits)
    }

    /// Applies one key transition; `Some(new)` only if the modifier value changed.
    pub fn fold(&mut self, usage: KeyUsage, state: KeyState) -> Option<Modifiers> {
        let before = self.modifiers();
        match usage.0 {
            0xE0..=0xE7 => {
                let bit = 1u8 << (usage.0 - 0xE0);
                match state {
                    KeyState::Pressed => self.held |= bit,
                    KeyState::Released => self.held &= !bit,
                }
            }
            0x39 => self.fold_lock(LOCK_KEY_CAPS, Modifiers::CAPS_LOCK, state),
            0x53 => self.fold_lock(LOCK_KEY_NUM, Modifiers::NUM_LOCK, state),
            _ => return None,
        }
        let after = self.modifiers();
        (after != before).then_some(after)
    }

    fn fold_lock(&mut self, key: u8, lock: u16, state: KeyState) {
        match state {
            KeyState::Pressed => {
                if self.lock_keys_down & key == 0 {
                    self.lock_keys_down |= key;
                    self.locks ^= lock;
                }
            }
            KeyState::Released => self.lock_keys_down &= !key,
        }
    }

    /// Clears every held key (including the lock keys' held state) and keeps lock bits.
    /// `Some(new)` only if the modifier value changed.
    pub fn reset(&mut self) -> Option<Modifiers> {
        let before = self.modifiers();
        self.held = 0;
        self.lock_keys_down = 0;
        let after = self.modifiers();
        (after != before).then_some(after)
    }
}

/// Pressed pointer buttons (seat 0).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ButtonTracker {
    /// Bit `button - 1` set iff pressed.
    pressed: u8,
}

impl ButtonTracker {
    pub const fn new() -> Self {
        Self { pressed: 0 }
    }

    /// `true` iff `state` is a transition (a duplicate press or release returns `false`).
    pub fn fold(&mut self, button: PointerButton, state: KeyState) -> bool {
        let bit = 1u8 << (button.as_u16() - 1);
        let was_pressed = self.pressed & bit != 0;
        match state {
            KeyState::Pressed => self.pressed |= bit,
            KeyState::Released => self.pressed &= !bit,
        }
        was_pressed != (state == KeyState::Pressed)
    }

    pub const fn is_pressed(&self, button: PointerButton) -> bool {
        self.pressed & (1u8 << (button.as_u16() - 1)) != 0
    }

    pub const fn any_pressed(&self) -> bool {
        self.pressed != 0
    }

    /// Releases every button; `true` iff any was pressed.
    pub fn reset(&mut self) -> bool {
        let any = self.pressed != 0;
        self.pressed = 0;
        any
    }
}

/// Raw `Overflow` / input-lost path: resets both trackers and returns the events to post to
/// the focused client, in order: `InputReset`, then `ModifiersChanged` carrying the post-reset
/// modifiers (always sent, so the client never has to guess the lock state).
pub fn reset_seat(
    modifiers: &mut ModifierTracker,
    buttons: &mut ButtonTracker,
) -> [crate::protocol::Event; 2] {
    let _ = modifiers.reset();
    let _ = buttons.reset();
    [
        crate::protocol::Event::InputReset,
        crate::protocol::Event::ModifiersChanged {
            modifiers: modifiers.modifiers(),
        },
    ]
}

#[cfg(test)]
mod tests;
