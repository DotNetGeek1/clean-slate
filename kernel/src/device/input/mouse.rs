//! PS/2 mouse packet decoding.

use clean_slate_graphics::input::{AxisValue120, KeyState, PointerButton};
use clean_slate_graphics::raw_input::RawInputKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MouseProtocol {
    Standard,
    Wheel,
    Explorer,
}

impl MouseProtocol {
    pub(crate) const fn packet_len(self) -> usize {
        match self {
            Self::Standard => 3,
            Self::Wheel | Self::Explorer => 4,
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Wheel => "wheel",
            Self::Explorer => "explorer",
        }
    }

    pub(crate) const fn device_id(self) -> u8 {
        match self {
            Self::Standard => 0,
            Self::Wheel => 3,
            Self::Explorer => 4,
        }
    }
}

pub(crate) struct MouseEvents {
    events: [Option<RawInputKind>; 7],
    len: usize,
}

impl MouseEvents {
    pub(crate) fn iter(&self) -> impl Iterator<Item = RawInputKind> + '_ {
        self.events[..self.len].iter().flatten().copied()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    fn push(&mut self, kind: RawInputKind) {
        self.events[self.len] = Some(kind);
        self.len += 1;
    }
}

pub(crate) enum MouseFeed {
    Pending,
    Resync,
    Packet {
        events: MouseEvents,
        axis_overflow: bool,
    },
}

pub(crate) struct MousePacketDecoder {
    protocol: MouseProtocol,
    buf: [u8; 4],
    len: usize,
    buttons: u8,
}

impl MousePacketDecoder {
    pub(crate) const fn new(protocol: MouseProtocol) -> Self {
        Self {
            protocol,
            buf: [0; 4],
            len: 0,
            buttons: 0,
        }
    }

    pub(crate) fn feed(&mut self, byte: u8) -> MouseFeed {
        if self.len == 0 && byte & 0x08 == 0 {
            return MouseFeed::Resync;
        }

        self.buf[self.len] = byte;
        self.len += 1;

        let need = self.protocol.packet_len();
        if self.len < need {
            return MouseFeed::Pending;
        }

        let b0 = self.buf[0];
        let b1 = self.buf[1];
        let b2 = self.buf[2];
        let b3 = if need >= 4 { self.buf[3] } else { 0 };

        self.len = 0;

        let mut axis_overflow = false;
        let mut dx = i32::from(b1) - ((i32::from(b0 & 0x10)) << 4);
        let mut dy_ps2 = i32::from(b2) - ((i32::from(b0 & 0x20)) << 3);
        if b0 & 0x40 != 0 {
            dx = 0;
            axis_overflow = true;
        }
        if b0 & 0x80 != 0 {
            dy_ps2 = 0;
            axis_overflow = true;
        }
        let dy = -dy_ps2;

        let z = match self.protocol {
            MouseProtocol::Standard => 0i8,
            MouseProtocol::Wheel => b3 as i8,
            MouseProtocol::Explorer => ((b3 << 4) as i8) >> 4,
        };

        let mut mask = b0 & 0x07;
        if self.protocol == MouseProtocol::Explorer {
            if b3 & 0x10 != 0 {
                mask |= 1 << 3;
            }
            if b3 & 0x20 != 0 {
                mask |= 1 << 4;
            }
        }

        let mut out = MouseEvents {
            events: [None; 7],
            len: 0,
        };

        if dx != 0 || dy != 0 {
            out.push(RawInputKind::RelMotion { dx, dy });
        }

        const ORDER: [PointerButton; 5] = [
            PointerButton::Left,
            PointerButton::Right,
            PointerButton::Middle,
            PointerButton::Back,
            PointerButton::Forward,
        ];

        for button in ORDER {
            if self.protocol != MouseProtocol::Explorer && button as u16 > 3 {
                continue;
            }
            let bit = 1u8 << ((button as u8) - 1);
            let was = self.buttons & bit != 0;
            let now = mask & bit != 0;
            if was == now {
                continue;
            }
            out.push(RawInputKind::Button {
                button,
                state: if now {
                    KeyState::Pressed
                } else {
                    KeyState::Released
                },
            });
        }

        if z != 0 {
            out.push(RawInputKind::Wheel {
                vertical: AxisValue120(i32::from(z) * 120),
                horizontal: AxisValue120(0),
            });
        }

        self.buttons = mask;

        MouseFeed::Packet {
            events: out,
            axis_overflow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet_events(decoder: &mut MousePacketDecoder, bytes: &[u8]) -> Vec<RawInputKind> {
        let mut out = Vec::new();
        for &b in bytes {
            match decoder.feed(b) {
                MouseFeed::Packet { events, .. } => out.extend(events.iter()),
                MouseFeed::Pending | MouseFeed::Resync => {}
            }
        }
        out
    }

    fn feed_packet(decoder: &mut MousePacketDecoder, bytes: &[u8]) -> MouseFeed {
        let mut last = MouseFeed::Pending;
        for &b in bytes {
            last = decoder.feed(b);
        }
        last
    }

    #[test]
    fn standard_motion_sign_flip() {
        let mut dec = MousePacketDecoder::new(MouseProtocol::Standard);
        let b0 = 0x08 | 0x20;
        let events = packet_events(&mut dec, &[b0, 10, 0xFB]);
        assert_eq!(events, [RawInputKind::RelMotion { dx: 10, dy: 5 }]);
    }

    #[test]
    fn negative_dx_nine_bit() {
        let mut dec = MousePacketDecoder::new(MouseProtocol::Standard);
        let events = packet_events(&mut dec, &[0x18, 0xF6, 0x00]);
        assert_eq!(events, [RawInputKind::RelMotion { dx: -10, dy: 0 }]);
    }

    #[test]
    fn x_overflow_zeros_dx_preserves_dy() {
        let mut dec = MousePacketDecoder::new(MouseProtocol::Standard);
        let feed = feed_packet(&mut dec, &[0x68, 5, 0xFB]);
        match feed {
            MouseFeed::Packet {
                events,
                axis_overflow,
            } => {
                assert!(axis_overflow);
                assert_eq!(
                    events.iter().collect::<Vec<_>>(),
                    [RawInputKind::RelMotion { dx: 0, dy: 5 }]
                );
            }
            _ => panic!("expected packet"),
        }
    }

    #[test]
    fn y_overflow_zeros_dy_preserves_dx() {
        let mut dec = MousePacketDecoder::new(MouseProtocol::Standard);
        let feed = feed_packet(&mut dec, &[0x88, 5, 0xFB]);
        match feed {
            MouseFeed::Packet {
                events,
                axis_overflow,
            } => {
                assert!(axis_overflow);
                assert_eq!(
                    events.iter().collect::<Vec<_>>(),
                    [RawInputKind::RelMotion { dx: 5, dy: 0 }]
                );
            }
            _ => panic!("expected packet"),
        }
    }

    #[test]
    fn resync_then_decode() {
        let mut dec = MousePacketDecoder::new(MouseProtocol::Standard);
        assert!(matches!(dec.feed(0x01), MouseFeed::Resync));
        let events = packet_events(&mut dec, &[0x08, 1, 0]);
        assert_eq!(events, [RawInputKind::RelMotion { dx: 1, dy: 0 }]);
    }

    #[test]
    fn button_press_release_order() {
        let mut dec = MousePacketDecoder::new(MouseProtocol::Standard);
        let press = packet_events(&mut dec, &[0x09, 0, 0]);
        assert_eq!(
            press,
            [RawInputKind::Button {
                button: PointerButton::Left,
                state: KeyState::Pressed,
            }]
        );
        let release = packet_events(&mut dec, &[0x08, 0, 0]);
        assert_eq!(
            release,
            [RawInputKind::Button {
                button: PointerButton::Left,
                state: KeyState::Released,
            }]
        );
    }

    #[test]
    fn simultaneous_left_right_press_order() {
        let mut dec = MousePacketDecoder::new(MouseProtocol::Standard);
        let events = packet_events(&mut dec, &[0x0B, 0, 0]);
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0],
            RawInputKind::Button {
                button: PointerButton::Left,
                state: KeyState::Pressed,
            }
        );
        assert_eq!(
            events[1],
            RawInputKind::Button {
                button: PointerButton::Right,
                state: KeyState::Pressed,
            }
        );
    }

    #[test]
    fn wheel_protocol_detents() {
        let mut dec = MousePacketDecoder::new(MouseProtocol::Wheel);
        let up = packet_events(&mut dec, &[0x08, 0, 0, 1]);
        assert_eq!(
            up,
            [RawInputKind::Wheel {
                vertical: AxisValue120(120),
                horizontal: AxisValue120(0),
            }]
        );
        let down = packet_events(&mut dec, &[0x08, 0, 0, 0xFF]);
        assert_eq!(
            down,
            [RawInputKind::Wheel {
                vertical: AxisValue120(-120),
                horizontal: AxisValue120(0),
            }]
        );
    }

    #[test]
    fn explorer_wheel_and_side_buttons() {
        let neg = packet_events(
            &mut MousePacketDecoder::new(MouseProtocol::Explorer),
            &[0x08, 0, 0, 0x0F],
        );
        assert_eq!(
            neg,
            [RawInputKind::Wheel {
                vertical: AxisValue120(-120),
                horizontal: AxisValue120(0),
            }]
        );
        let back = packet_events(
            &mut MousePacketDecoder::new(MouseProtocol::Explorer),
            &[0x08, 0, 0, 0x10],
        );
        assert_eq!(
            back,
            [RawInputKind::Button {
                button: PointerButton::Back,
                state: KeyState::Pressed,
            }]
        );
        let fwd = packet_events(
            &mut MousePacketDecoder::new(MouseProtocol::Explorer),
            &[0x08, 0, 0, 0x20],
        );
        assert_eq!(
            fwd,
            [RawInputKind::Button {
                button: PointerButton::Forward,
                state: KeyState::Pressed,
            }]
        );
        let seven = packet_events(
            &mut MousePacketDecoder::new(MouseProtocol::Explorer),
            &[0x08, 0, 0, 0x07],
        );
        assert_eq!(
            seven,
            [RawInputKind::Wheel {
                vertical: AxisValue120(840),
                horizontal: AxisValue120(0),
            }]
        );
    }

    #[test]
    fn explorer_combined_event_order() {
        let mut dec = MousePacketDecoder::new(MouseProtocol::Explorer);
        let events = packet_events(&mut dec, &[0x09, 2, 0xFE, 1]);
        assert_eq!(events.len(), 3);
        assert!(matches!(events[0], RawInputKind::RelMotion { .. }));
        assert_eq!(
            events[1],
            RawInputKind::Button {
                button: PointerButton::Left,
                state: KeyState::Pressed,
            }
        );
        assert!(matches!(events[2], RawInputKind::Wheel { .. }));
    }

    #[test]
    fn idle_packet_zero_events() {
        let mut dec = MousePacketDecoder::new(MouseProtocol::Standard);
        match feed_packet(&mut dec, &[0x08, 0, 0]) {
            MouseFeed::Packet { events, .. } => assert_eq!(events.len(), 0),
            _ => panic!("expected empty packet"),
        }
    }
}
