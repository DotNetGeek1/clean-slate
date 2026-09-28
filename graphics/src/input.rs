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
