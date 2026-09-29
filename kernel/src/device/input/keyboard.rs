//! PS/2 scancode set 2 decoding and typematic suppression.

use clean_slate_graphics::input::{KeyState, KeyUsage};

const fn set2_usage_table() -> [u8; 256] {
    let mut t = [0u8; 256];
    t[0x01] = 0x42;
    t[0x03] = 0x3E;
    t[0x04] = 0x3C;
    t[0x05] = 0x3A;
    t[0x06] = 0x3B;
    t[0x07] = 0x45;
    t[0x09] = 0x43;
    t[0x0A] = 0x41;
    t[0x0B] = 0x3F;
    t[0x0C] = 0x3D;
    t[0x0D] = 0x2B;
    t[0x0E] = 0x35;
    t[0x11] = 0xE2;
    t[0x12] = 0xE1;
    t[0x14] = 0xE0;
    t[0x15] = 0x14;
    t[0x16] = 0x1E;
    t[0x1A] = 0x1D;
    t[0x1B] = 0x16;
    t[0x1C] = 0x04;
    t[0x1D] = 0x1A;
    t[0x1E] = 0x1F;
    t[0x21] = 0x06;
    t[0x22] = 0x1B;
    t[0x23] = 0x07;
    t[0x24] = 0x08;
    t[0x25] = 0x21;
    t[0x26] = 0x20;
    t[0x29] = 0x2C;
    t[0x2A] = 0x19;
    t[0x2B] = 0x09;
    t[0x2C] = 0x17;
    t[0x2D] = 0x15;
    t[0x2E] = 0x22;
    t[0x31] = 0x11;
    t[0x32] = 0x05;
    t[0x33] = 0x0B;
    t[0x34] = 0x0A;
    t[0x35] = 0x1C;
    t[0x36] = 0x23;
    t[0x3A] = 0x10;
    t[0x3B] = 0x0D;
    t[0x3C] = 0x18;
    t[0x3D] = 0x24;
    t[0x3E] = 0x25;
    t[0x41] = 0x36;
    t[0x42] = 0x0E;
    t[0x43] = 0x0C;
    t[0x44] = 0x12;
    t[0x45] = 0x27;
    t[0x46] = 0x26;
    t[0x49] = 0x37;
    t[0x4A] = 0x38;
    t[0x4B] = 0x0F;
    t[0x4C] = 0x33;
    t[0x4D] = 0x13;
    t[0x4E] = 0x2D;
    t[0x52] = 0x34;
    t[0x54] = 0x2F;
    t[0x55] = 0x2E;
    t[0x58] = 0x39;
    t[0x59] = 0xE5;
    t[0x5A] = 0x28;
    t[0x5B] = 0x30;
    t[0x5D] = 0x31;
    t[0x61] = 0x64;
    t[0x66] = 0x2A;
    t[0x69] = 0x59;
    t[0x6B] = 0x5C;
    t[0x6C] = 0x5F;
    t[0x70] = 0x62;
    t[0x71] = 0x63;
    t[0x72] = 0x5A;
    t[0x73] = 0x5D;
    t[0x74] = 0x5E;
    t[0x75] = 0x60;
    t[0x76] = 0x29;
    t[0x77] = 0x53;
    t[0x78] = 0x44;
    t[0x79] = 0x57;
    t[0x7A] = 0x5B;
    t[0x7B] = 0x56;
    t[0x7C] = 0x55;
    t[0x7D] = 0x61;
    t[0x7E] = 0x47;
    t[0x83] = 0x40;
    // Alt+PrintScreen (SysRq); the #110 contract has no separate SysRq usage.
    t[0x84] = 0x46;
    t
}

const fn set2_extended_usage_table() -> [u8; 256] {
    let mut t = [0u8; 256];
    t[0x11] = 0xE6;
    t[0x14] = 0xE4;
    t[0x1F] = 0xE3;
    t[0x27] = 0xE7;
    t[0x2F] = 0x65;
    t[0x4A] = 0x54;
    t[0x5A] = 0x58;
    t[0x69] = 0x4D;
    t[0x6B] = 0x50;
    t[0x6C] = 0x4A;
    t[0x70] = 0x49;
    t[0x71] = 0x4C;
    t[0x72] = 0x51;
    t[0x74] = 0x4F;
    t[0x75] = 0x52;
    t[0x7A] = 0x4E;
    t[0x7C] = 0x46;
    t[0x7D] = 0x4B;
    t[0x7E] = 0x48;
    t
}

static SET2_USAGE: [u8; 256] = set2_usage_table();
static SET2_EXTENDED_USAGE: [u8; 256] = set2_extended_usage_table();

pub(crate) fn set2_usage(extended: bool, code: u8) -> Option<KeyUsage> {
    let raw = if extended {
        SET2_EXTENDED_USAGE[code as usize]
    } else {
        SET2_USAGE[code as usize]
    };
    if raw == 0 {
        return None;
    }
    let usage = KeyUsage(u16::from(raw));
    if usage.is_valid() {
        Some(usage)
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Set2Event {
    None,
    Key(KeyUsage, KeyState),
    PausePressedReleased,
    Unmapped,
    Ignored,
    DeviceReset,
    Overrun,
    ControllerReply,
    /// A byte that does not continue the Pause sequence: the sequence is lost and the byte must
    /// be fed again from idle.
    PauseBroken(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Set2State {
    Idle,
    E0,
    Break,
    E0Break,
    Pause(u8),
}

const PAUSE_SEQUENCE: [u8; 8] = [0xE1, 0x14, 0x77, 0xE1, 0xF0, 0x14, 0xF0, 0x77];

pub(crate) const PAUSE_USAGE: KeyUsage = KeyUsage(0x48);

pub(crate) struct Set2Decoder {
    state: Set2State,
}

impl Set2Decoder {
    pub(crate) const fn new() -> Self {
        Self {
            state: Set2State::Idle,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.state = Set2State::Idle;
    }

    pub(crate) fn feed(&mut self, byte: u8) -> Set2Event {
        // An overrun can land mid-sequence; it is a loss wherever it arrives.
        if matches!(byte, 0x00 | 0xFF) {
            self.state = Set2State::Idle;
            return Set2Event::Overrun;
        }
        // No set-2 sequence contains 0xAA, so it is the keyboard's BAT after a self-reset
        // wherever it arrives.
        if byte == 0xAA {
            self.state = Set2State::Idle;
            return Set2Event::DeviceReset;
        }
        match self.state {
            Set2State::Idle => match byte {
                0xE0 => {
                    self.state = Set2State::E0;
                    Set2Event::None
                }
                0xF0 => {
                    self.state = Set2State::Break;
                    Set2Event::None
                }
                0xE1 => {
                    self.state = Set2State::Pause(1);
                    Set2Event::None
                }
                0xFA | 0xFE | 0xEE => Set2Event::ControllerReply,
                code => match set2_usage(false, code) {
                    Some(usage) => Set2Event::Key(usage, KeyState::Pressed),
                    None => Set2Event::Unmapped,
                },
            },
            Set2State::E0 => match byte {
                0xF0 => {
                    self.state = Set2State::E0Break;
                    Set2Event::None
                }
                0x12 | 0x59 => {
                    self.state = Set2State::Idle;
                    Set2Event::Ignored
                }
                code => {
                    self.state = Set2State::Idle;
                    match set2_usage(true, code) {
                        Some(usage) => Set2Event::Key(usage, KeyState::Pressed),
                        None => Set2Event::Unmapped,
                    }
                }
            },
            Set2State::Break => {
                self.state = Set2State::Idle;
                match set2_usage(false, byte) {
                    Some(usage) => Set2Event::Key(usage, KeyState::Released),
                    None => Set2Event::Unmapped,
                }
            }
            Set2State::E0Break => match byte {
                0x12 | 0x59 => {
                    self.state = Set2State::Idle;
                    Set2Event::Ignored
                }
                code => {
                    self.state = Set2State::Idle;
                    match set2_usage(true, code) {
                        Some(usage) => Set2Event::Key(usage, KeyState::Released),
                        None => Set2Event::Unmapped,
                    }
                }
            },
            Set2State::Pause(n) => {
                if byte == PAUSE_SEQUENCE[n as usize] {
                    let next = n + 1;
                    if next == 8 {
                        self.state = Set2State::Idle;
                        Set2Event::PausePressedReleased
                    } else {
                        self.state = Set2State::Pause(next);
                        Set2Event::None
                    }
                } else {
                    self.state = Set2State::Idle;
                    Set2Event::PauseBroken(byte)
                }
            }
        }
    }
}

pub(crate) struct PressedKeys([u64; 4]);

impl PressedKeys {
    pub(crate) const fn new() -> Self {
        Self([0; 4])
    }

    pub(crate) fn clear(&mut self) {
        self.0 = [0; 4];
    }

    pub(crate) fn filter(&mut self, usage: KeyUsage, state: KeyState) -> bool {
        let idx = usage.0;
        if idx >= 0x100 {
            return false;
        }
        let idx = idx as u8;
        let word = (idx / 64) as usize;
        let bit = 1u64 << (idx % 64);
        match state {
            KeyState::Pressed => {
                if self.0[word] & bit != 0 {
                    false
                } else {
                    self.0[word] |= bit;
                    true
                }
            }
            KeyState::Released => {
                if self.0[word] & bit != 0 {
                    self.0[word] &= !bit;
                    true
                } else {
                    false
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect_keys(decoder: &mut Set2Decoder, bytes: &[u8]) -> Vec<Set2Event> {
        bytes
            .iter()
            .map(|&b| decoder.feed(b))
            .filter(|e| *e != Set2Event::None)
            .collect()
    }

    #[test]
    fn table_entries_are_valid_hid_usages() {
        for table in [&SET2_USAGE, &SET2_EXTENDED_USAGE] {
            for &raw in table.iter().filter(|&&v| v != 0) {
                assert!(KeyUsage(u16::from(raw)).is_valid());
            }
        }
    }

    #[test]
    fn table_mappings_are_injective_apart_from_sysrq() {
        const ALT_SYSRQ: usize = 0x84;
        let mut seen = [false; 256];
        for (table, alias) in [(&SET2_USAGE, Some(ALT_SYSRQ)), (&SET2_EXTENDED_USAGE, None)] {
            let codes = table
                .iter()
                .enumerate()
                .filter(|&(code, &v)| v != 0 && Some(code) != alias);
            for (_, &raw) in codes {
                assert!(!seen[raw as usize], "duplicate usage {raw:#04x}");
                seen[raw as usize] = true;
            }
        }
    }

    #[test]
    fn spot_check_letter_digit_control_mappings() {
        assert_eq!(set2_usage(false, 0x1C), Some(KeyUsage(0x04)));
        assert_eq!(set2_usage(false, 0x16), Some(KeyUsage(0x1E)));
        assert_eq!(set2_usage(false, 0x5A), Some(KeyUsage(0x28)));
        assert_eq!(set2_usage(false, 0x4E), Some(KeyUsage(0x2D)));
        assert_eq!(set2_usage(false, 0x05), Some(KeyUsage(0x3A)));
        assert_eq!(set2_usage(false, 0x7C), Some(KeyUsage(0x55)));
        assert_eq!(set2_usage(false, 0x14), Some(KeyUsage(0xE0)));
        assert_eq!(set2_usage(true, 0x74), Some(KeyUsage(0x4F)));
    }

    #[test]
    fn extended_fake_shifts_and_zero_are_unmapped() {
        assert_eq!(set2_usage(true, 0x12), None);
        assert_eq!(set2_usage(true, 0x59), None);
        assert_eq!(set2_usage(false, 0x00), None);
    }

    #[test]
    fn make_break_basic_key() {
        let mut dec = Set2Decoder::new();
        let events = collect_keys(&mut dec, &[0x1C, 0xF0, 0x1C]);
        assert_eq!(
            events,
            [
                Set2Event::Key(KeyUsage(0x04), KeyState::Pressed),
                Set2Event::Key(KeyUsage(0x04), KeyState::Released),
            ]
        );
    }

    #[test]
    fn extended_arrow_right_make_break() {
        let mut dec = Set2Decoder::new();
        let events = collect_keys(&mut dec, &[0xE0, 0x74, 0xE0, 0xF0, 0x74]);
        assert_eq!(
            events,
            [
                Set2Event::Key(KeyUsage(0x4F), KeyState::Pressed),
                Set2Event::Key(KeyUsage(0x4F), KeyState::Released),
            ]
        );
    }

    #[test]
    fn print_screen_sequence() {
        let mut dec = Set2Decoder::new();
        let bytes = [0xE0, 0x12, 0xE0, 0x7C, 0xE0, 0xF0, 0x7C, 0xE0, 0xF0, 0x12];
        let events = collect_keys(&mut dec, &bytes);
        let keys: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                Set2Event::Key(u, s) => Some((*u, *s)),
                _ => None,
            })
            .collect();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], (KeyUsage(0x46), KeyState::Pressed));
        assert_eq!(keys[1], (KeyUsage(0x46), KeyState::Released));
        assert_eq!(
            events.iter().filter(|e| **e == Set2Event::Ignored).count(),
            2
        );
    }

    #[test]
    fn pause_sequence_full() {
        let mut dec = Set2Decoder::new();
        let events = collect_keys(&mut dec, &PAUSE_SEQUENCE);
        assert_eq!(events, [Set2Event::PausePressedReleased]);
    }

    #[test]
    fn pause_corruption_hands_back_the_breaking_byte_from_idle() {
        let mut dec = Set2Decoder::new();
        let events = collect_keys(&mut dec, &[0xE1, 0x14, 0x33]);
        assert_eq!(events, [Set2Event::PauseBroken(0x33)]);
        assert_eq!(
            dec.feed(0x33),
            Set2Event::Key(KeyUsage(0x0B), KeyState::Pressed)
        );
    }

    #[test]
    fn bat_mid_sequence_is_a_device_reset() {
        let mut dec = Set2Decoder::new();
        for prefix in [&[0xE0][..], &[0xF0], &[0xE0, 0xF0], &[0xE1, 0x14]] {
            assert!(collect_keys(&mut dec, prefix).is_empty());
            assert_eq!(dec.feed(0xAA), Set2Event::DeviceReset);
            assert_eq!(
                dec.feed(0x1C),
                Set2Event::Key(KeyUsage(0x04), KeyState::Pressed)
            );
        }
    }

    #[test]
    fn alt_sysrq_reports_print_screen() {
        let mut dec = Set2Decoder::new();
        assert_eq!(
            collect_keys(&mut dec, &[0x84, 0xF0, 0x84]),
            [
                Set2Event::Key(KeyUsage(0x46), KeyState::Pressed),
                Set2Event::Key(KeyUsage(0x46), KeyState::Released),
            ]
        );
    }

    #[test]
    fn controller_special_bytes() {
        let mut dec = Set2Decoder::new();
        assert_eq!(dec.feed(0xAA), Set2Event::DeviceReset);
        dec.reset();
        assert_eq!(dec.feed(0x00), Set2Event::Overrun);
        dec.reset();
        assert_eq!(dec.feed(0xFF), Set2Event::Overrun);
        dec.reset();
        assert_eq!(dec.feed(0xFA), Set2Event::ControllerReply);
    }

    #[test]
    fn overrun_mid_sequence_is_reported_and_resets_the_decoder() {
        let mut dec = Set2Decoder::new();
        for prefix in [&[0xE0][..], &[0xF0], &[0xE0, 0xF0], &[0xE1, 0x14]] {
            assert!(collect_keys(&mut dec, prefix).is_empty());
            assert_eq!(dec.feed(0x00), Set2Event::Overrun);
            assert_eq!(
                dec.feed(0x1C),
                Set2Event::Key(KeyUsage(0x04), KeyState::Pressed)
            );
            assert_eq!(collect_keys(&mut dec, &[0xF0, 0x1C]).len(), 1);
        }
    }

    #[test]
    fn unmapped_make_and_break() {
        let mut dec = Set2Decoder::new();
        assert_eq!(dec.feed(0x02), Set2Event::Unmapped);
        assert_eq!(dec.feed(0xF0), Set2Event::None);
        assert_eq!(dec.feed(0x02), Set2Event::Unmapped);
    }

    #[test]
    fn pressed_keys_repeat_filter() {
        let usage = KeyUsage(0x04);
        let mut keys = PressedKeys::new();
        assert!(keys.filter(usage, KeyState::Pressed));
        assert!(!keys.filter(usage, KeyState::Pressed));
        assert!(keys.filter(usage, KeyState::Released));
        assert!(!keys.filter(usage, KeyState::Released));
        keys.clear();
        assert!(keys.filter(usage, KeyState::Pressed));

        let mut fresh = PressedKeys::new();
        assert!(!fresh.filter(usage, KeyState::Released));
    }
}
