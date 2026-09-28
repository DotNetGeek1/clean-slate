//! Compositor → client events (§3).

use crate::geometry::{Fixed24_8, Scale120, Size};
use crate::ids::{ClientBufferId, ObjectId, OutputId, Serial, SurfaceId, WindowId};
use crate::input::{AxisValue120, KeyState, KeyUsage, Modifiers, PointerButton};
use crate::mode::{DisplayMode, OutputInfo};
use crate::pixel::PixelFormat;
use crate::window::{DecorationMode, WindowStates};

use super::*;

/// Compositor event (§3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// `Welcome` (0x8001): negotiation success and primary output.
    Welcome {
        version: ProtocolVersion,
        features: Features,
        output: OutputInfo,
    },
    /// `Error` (0x8002): request failure echo.
    Error {
        object: u32,
        request_opcode: u16,
        code: ProtocolError,
    },
    /// `BufferRegistered` (0x8010): buffer handle minted.
    BufferRegistered { buffer: ClientBufferId },
    /// `BufferReleased` (0x8011): buffer released from surface use.
    BufferReleased { buffer: ClientBufferId },
    /// `BufferUnregistered` (0x8012): buffer unregistered.
    BufferUnregistered { buffer: ClientBufferId },
    /// `SurfaceCreated` (0x8020): surface minted.
    SurfaceCreated { surface: SurfaceId },
    /// `FrameDone` (0x8021): present completed.
    FrameDone {
        surface: SurfaceId,
        presented_ns: u64,
        output_seq: u64,
    },
    /// `WindowCreated` (0x8030): window minted.
    WindowCreated { window: WindowId },
    /// `Configure` (0x8031): window geometry and state.
    Configure {
        window: WindowId,
        serial: Serial,
        size: Size,
        scale: Scale120,
        decoration: DecorationMode,
        states: WindowStates,
        bounds: Size,
    },
    /// `CloseRequested` (0x8032): user requested close.
    CloseRequested { window: WindowId },
    /// `KeyboardFocus` (0x8040): keyboard focus surface.
    KeyboardFocus { surface: Option<SurfaceId> },
    /// `Key` (0x8041): key transition.
    Key {
        serial: Serial,
        time_ns: u64,
        usage: KeyUsage,
        state: KeyState,
        modifiers: Modifiers,
    },
    /// `ModifiersChanged` (0x8042): modifier state only.
    ModifiersChanged { modifiers: Modifiers },
    /// `PointerEnter` (0x8050): pointer entered surface.
    PointerEnter {
        serial: Serial,
        surface: SurfaceId,
        x: Fixed24_8,
        y: Fixed24_8,
    },
    /// `PointerLeave` (0x8051): pointer left surface.
    PointerLeave { serial: Serial, surface: SurfaceId },
    /// `PointerMotion` (0x8052): pointer moved on focus surface.
    PointerMotion {
        time_ns: u64,
        x: Fixed24_8,
        y: Fixed24_8,
    },
    /// `PointerButton` (0x8053): pointer button transition.
    PointerButton {
        serial: Serial,
        time_ns: u64,
        button: PointerButton,
        state: KeyState,
    },
    /// `PointerAxis` (0x8054): scroll axes.
    PointerAxis {
        time_ns: u64,
        vertical: AxisValue120,
        horizontal: AxisValue120,
    },
    /// `InputReset` (0x8060): reset input state.
    InputReset,
}

impl Event {
    pub fn opcode(&self) -> u16 {
        match self {
            Self::Welcome { .. } => OP_WELCOME,
            Self::Error { .. } => OP_ERROR,
            Self::BufferRegistered { .. } => OP_BUFFER_REGISTERED,
            Self::BufferReleased { .. } => OP_BUFFER_RELEASED,
            Self::BufferUnregistered { .. } => OP_BUFFER_UNREGISTERED,
            Self::SurfaceCreated { .. } => OP_SURFACE_CREATED,
            Self::FrameDone { .. } => OP_FRAME_DONE,
            Self::WindowCreated { .. } => OP_WINDOW_CREATED,
            Self::Configure { .. } => OP_CONFIGURE,
            Self::CloseRequested { .. } => OP_CLOSE_REQUESTED,
            Self::KeyboardFocus { .. } => OP_KEYBOARD_FOCUS,
            Self::Key { .. } => OP_KEY,
            Self::ModifiersChanged { .. } => OP_MODIFIERS_CHANGED,
            Self::PointerEnter { .. } => OP_POINTER_ENTER,
            Self::PointerLeave { .. } => OP_POINTER_LEAVE,
            Self::PointerMotion { .. } => OP_POINTER_MOTION,
            Self::PointerButton { .. } => OP_POINTER_BUTTON,
            Self::PointerAxis { .. } => OP_POINTER_AXIS,
            Self::InputReset => OP_INPUT_RESET,
        }
    }

    pub fn encode(&self, tag: u32) -> Result<[u8; FRAME_BYTES], ProtocolError> {
        let mut out = [0u8; FRAME_BYTES];
        write_u16_le(&mut out, 0, self.opcode());
        write_u32_le(&mut out, 4, tag);
        match *self {
            Self::Welcome {
                version,
                features,
                output,
            } => {
                Self::encode_welcome_body(&mut out, version, features, output)?;
            }
            Self::Error {
                object,
                request_opcode,
                code,
            } => {
                write_u32_le(&mut out, 8, object);
                write_u16_le(&mut out, 12, code.code());
                write_u16_le(&mut out, 14, request_opcode);
            }
            Self::BufferRegistered { buffer } => {
                write_u32_le(&mut out, 8, buffer.0.encode());
            }
            Self::BufferReleased { buffer } => {
                write_u32_le(&mut out, 8, buffer.0.encode());
            }
            Self::BufferUnregistered { buffer } => {
                write_u32_le(&mut out, 8, buffer.0.encode());
            }
            Self::SurfaceCreated { surface } => {
                write_u32_le(&mut out, 8, surface.0.encode());
            }
            Self::FrameDone {
                surface,
                presented_ns,
                output_seq,
            } => {
                write_u32_le(&mut out, 8, surface.0.encode());
                write_u64_le(&mut out, 12, presented_ns);
                write_u64_le(&mut out, 20, output_seq);
            }
            Self::WindowCreated { window } => {
                write_u32_le(&mut out, 8, window.0.encode());
            }
            Self::Configure {
                window,
                serial,
                size,
                scale,
                decoration,
                states,
                bounds,
            } => {
                write_u32_le(&mut out, 8, window.0.encode());
                Self::encode_configure_body(
                    &mut out, serial, size, scale, decoration, states, bounds,
                )?;
            }
            Self::CloseRequested { window } => {
                write_u32_le(&mut out, 8, window.0.encode());
            }
            Self::KeyboardFocus { surface } => {
                let raw = surface.map(|s| s.0.encode()).unwrap_or(0);
                if raw != 0 {
                    decode_object_required(raw)?;
                }
                write_u32_le(&mut out, 8, raw);
            }
            Self::Key {
                serial,
                time_ns,
                usage,
                state,
                modifiers,
            } => {
                Self::encode_key_body(&mut out, serial, time_ns, usage, state, modifiers)?;
            }
            Self::ModifiersChanged { modifiers } => {
                Self::encode_modifiers_body(&mut out, modifiers)?;
            }
            Self::PointerEnter {
                serial,
                surface,
                x,
                y,
            } => {
                write_u32_le(&mut out, 8, surface.0.encode());
                serial_required_event(serial.0)?;
                write_u32_le(&mut out, 12, serial.0);
                write_i32_le(&mut out, 16, x.0);
                write_i32_le(&mut out, 20, y.0);
            }
            Self::PointerLeave { serial, surface } => {
                write_u32_le(&mut out, 8, surface.0.encode());
                serial_required_event(serial.0)?;
                write_u32_le(&mut out, 12, serial.0);
            }
            Self::PointerMotion { time_ns, x, y } => {
                write_u64_le(&mut out, 12, time_ns);
                write_i32_le(&mut out, 20, x.0);
                write_i32_le(&mut out, 24, y.0);
            }
            Self::PointerButton {
                serial,
                time_ns,
                button,
                state,
            } => {
                serial_required_event(serial.0)?;
                write_u32_le(&mut out, 12, serial.0);
                write_u64_le(&mut out, 16, time_ns);
                write_u16_le(&mut out, 24, button.as_u16());
                out[26] = state.as_u8();
            }
            Self::PointerAxis {
                time_ns,
                vertical,
                horizontal,
            } => {
                write_u64_le(&mut out, 12, time_ns);
                write_i32_le(&mut out, 20, vertical.0);
                write_i32_le(&mut out, 24, horizontal.0);
            }
            Self::InputReset => {}
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Tagged<Self>, DecodeError> {
        check_frame_len(bytes)?;
        check_header_reserved(bytes)?;
        let opcode = read_u16_le(bytes, 0);
        let tag = read_u32_le(bytes, 4);
        let object = read_u32_le(bytes, 8);
        run_decode_prelude(bytes, EVENT_SPECS, opcode, object)
            .map_err(|c| decode_error(c, bytes))?;
        let message = match opcode {
            OP_WELCOME => Self::decode_welcome_body(bytes).map_err(|c| decode_error(c, bytes))?,
            OP_ERROR => {
                let code_raw = read_u16_le(bytes, 12);
                let code = ProtocolError::from_u16(code_raw)
                    .ok_or(ProtocolError::MalformedFrame)
                    .map_err(|c| decode_error(c, bytes))?;
                Self::Error {
                    object,
                    request_opcode: read_u16_le(bytes, 14),
                    code,
                }
            }
            OP_BUFFER_REGISTERED => Self::BufferRegistered {
                buffer: ClientBufferId(required_id(object).map_err(|c| decode_error(c, bytes))?),
            },
            OP_BUFFER_RELEASED => Self::BufferReleased {
                buffer: ClientBufferId(required_id(object).map_err(|c| decode_error(c, bytes))?),
            },
            OP_BUFFER_UNREGISTERED => Self::BufferUnregistered {
                buffer: ClientBufferId(required_id(object).map_err(|c| decode_error(c, bytes))?),
            },
            OP_SURFACE_CREATED => Self::SurfaceCreated {
                surface: SurfaceId(required_id(object).map_err(|c| decode_error(c, bytes))?),
            },
            OP_FRAME_DONE => Self::FrameDone {
                surface: SurfaceId(required_id(object).map_err(|c| decode_error(c, bytes))?),
                presented_ns: read_u64_le(bytes, 12),
                output_seq: read_u64_le(bytes, 20),
            },
            OP_WINDOW_CREATED => Self::WindowCreated {
                window: WindowId(required_id(object).map_err(|c| decode_error(c, bytes))?),
            },
            OP_CONFIGURE => Self::decode_configure_body(
                bytes,
                WindowId(required_id(object).map_err(|c| decode_error(c, bytes))?),
            )
            .map_err(|c| decode_error(c, bytes))?,
            OP_CLOSE_REQUESTED => Self::CloseRequested {
                window: WindowId(required_id(object).map_err(|c| decode_error(c, bytes))?),
            },
            OP_KEYBOARD_FOCUS => Self::KeyboardFocus {
                surface: decode_object_optional(object)
                    .map_err(|c| decode_error(c, bytes))?
                    .map(SurfaceId),
            },
            OP_KEY => Self::decode_key_body(bytes).map_err(|c| decode_error(c, bytes))?,
            OP_MODIFIERS_CHANGED => {
                Self::decode_modifiers_body(bytes).map_err(|c| decode_error(c, bytes))?
            }
            OP_POINTER_ENTER => Self::PointerEnter {
                serial: serial_required_event(read_u32_le(bytes, 12))
                    .map_err(|c| decode_error(c, bytes))?,
                surface: SurfaceId(required_id(object).map_err(|c| decode_error(c, bytes))?),
                x: Fixed24_8(read_i32_le(bytes, 16)),
                y: Fixed24_8(read_i32_le(bytes, 20)),
            },
            OP_POINTER_LEAVE => Self::PointerLeave {
                serial: serial_required_event(read_u32_le(bytes, 12))
                    .map_err(|c| decode_error(c, bytes))?,
                surface: SurfaceId(required_id(object).map_err(|c| decode_error(c, bytes))?),
            },
            OP_POINTER_MOTION => Self::PointerMotion {
                time_ns: read_u64_le(bytes, 12),
                x: Fixed24_8(read_i32_le(bytes, 20)),
                y: Fixed24_8(read_i32_le(bytes, 24)),
            },
            OP_POINTER_BUTTON => Self::PointerButton {
                serial: serial_required_event(read_u32_le(bytes, 12))
                    .map_err(|c| decode_error(c, bytes))?,
                time_ns: read_u64_le(bytes, 16),
                button: PointerButton::from_u16(read_u16_le(bytes, 24))
                    .ok_or(ProtocolError::MalformedFrame)
                    .map_err(|c| decode_error(c, bytes))?,
                state: KeyState::from_u8(bytes[26])
                    .ok_or(ProtocolError::MalformedFrame)
                    .map_err(|c| decode_error(c, bytes))?,
            },
            OP_POINTER_AXIS => Self::PointerAxis {
                time_ns: read_u64_le(bytes, 12),
                vertical: AxisValue120(read_i32_le(bytes, 20)),
                horizontal: AxisValue120(read_i32_le(bytes, 24)),
            },
            OP_INPUT_RESET => Self::InputReset,
            _ => return Err(decode_error(ProtocolError::UnknownOpcode, bytes)),
        };
        Ok(Tagged { tag, message })
    }

    fn encode_welcome_body(
        out: &mut [u8; FRAME_BYTES],
        version: ProtocolVersion,
        features: Features,
        output: OutputInfo,
    ) -> Result<(), ProtocolError> {
        write_u16_le(out, 12, version.major);
        write_u16_le(out, 14, version.minor);
        write_u64_le(out, 16, features.bits());
        write_u32_le(out, 24, output.id.encode());
        write_u32_le(out, 28, output.mode.width_px);
        write_u32_le(out, 32, output.mode.height_px);
        write_u32_le(out, 36, output.mode.stride_bytes);
        out[40] = output.mode.format as u8;
        write_u16_le(out, 42, output.mode.scale.0);
        if output.mode.scale.0 == 0 {
            return Err(ProtocolError::InvalidScale);
        }
        write_u32_le(out, 44, output.mode.refresh_mhz);
        write_u32_le(out, 48, output.logical_size.width);
        write_u32_le(out, 52, output.logical_size.height);
        Ok(())
    }

    fn decode_welcome_body(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let output_id =
            OutputId::decode(read_u32_le(bytes, 24)).map_err(|_| ProtocolError::MalformedFrame)?;
        let format = PixelFormat::from_u8(bytes[40]).ok_or(ProtocolError::InvalidFormat)?;
        let scale_raw = read_u16_le(bytes, 42);
        if scale_raw == 0 {
            return Err(ProtocolError::InvalidScale);
        }
        let mode = DisplayMode {
            width_px: read_u32_le(bytes, 28),
            height_px: read_u32_le(bytes, 32),
            stride_bytes: read_u32_le(bytes, 36),
            format,
            scale: Scale120(scale_raw),
            refresh_mhz: read_u32_le(bytes, 44),
        };
        Ok(Self::Welcome {
            version: ProtocolVersion {
                major: read_u16_le(bytes, 12),
                minor: read_u16_le(bytes, 14),
            },
            features: Features(read_u64_le(bytes, 16)),
            output: OutputInfo {
                id: output_id,
                mode,
                logical_size: Size {
                    width: read_u32_le(bytes, 48),
                    height: read_u32_le(bytes, 52),
                },
            },
        })
    }

    fn encode_configure_body(
        out: &mut [u8; FRAME_BYTES],
        serial: Serial,
        size: Size,
        scale: Scale120,
        decoration: DecorationMode,
        states: WindowStates,
        bounds: Size,
    ) -> Result<(), ProtocolError> {
        use crate::limits::MAX_SURFACE_EXTENT;
        serial_required_event(serial.0)?;
        if size.width > MAX_SURFACE_EXTENT || size.height > MAX_SURFACE_EXTENT {
            return Err(ProtocolError::MalformedFrame);
        }
        if bounds.width > MAX_SURFACE_EXTENT || bounds.height > MAX_SURFACE_EXTENT {
            return Err(ProtocolError::MalformedFrame);
        }
        if scale.0 == 0 {
            return Err(ProtocolError::InvalidScale);
        }
        WindowStates::from_bits(states.bits()).ok_or(ProtocolError::ReservedBitsSet)?;
        write_u32_le(out, 12, serial.0);
        write_u32_le(out, 16, size.width);
        write_u32_le(out, 20, size.height);
        write_u16_le(out, 24, scale.0);
        out[26] = decoration.as_u8();
        write_u32_le(out, 28, states.bits());
        write_u32_le(out, 32, bounds.width);
        write_u32_le(out, 36, bounds.height);
        Ok(())
    }

    fn decode_configure_body(bytes: &[u8], window: WindowId) -> Result<Self, ProtocolError> {
        use crate::limits::MAX_SURFACE_EXTENT;
        let serial = serial_required_event(read_u32_le(bytes, 12))?;
        let size = Size {
            width: read_u32_le(bytes, 16),
            height: read_u32_le(bytes, 20),
        };
        if size.width > MAX_SURFACE_EXTENT || size.height > MAX_SURFACE_EXTENT {
            return Err(ProtocolError::MalformedFrame);
        }
        let scale_raw = read_u16_le(bytes, 24);
        if scale_raw == 0 {
            return Err(ProtocolError::InvalidScale);
        }
        let decoration = DecorationMode::from_u8(bytes[26]).ok_or(ProtocolError::MalformedFrame)?;
        let states = WindowStates::from_bits(read_u32_le(bytes, 28))
            .ok_or(ProtocolError::ReservedBitsSet)?;
        let bounds = Size {
            width: read_u32_le(bytes, 32),
            height: read_u32_le(bytes, 36),
        };
        if bounds.width > MAX_SURFACE_EXTENT || bounds.height > MAX_SURFACE_EXTENT {
            return Err(ProtocolError::MalformedFrame);
        }
        Ok(Self::Configure {
            window,
            serial,
            size,
            scale: Scale120(scale_raw),
            decoration,
            states,
            bounds,
        })
    }

    fn encode_key_body(
        out: &mut [u8; FRAME_BYTES],
        serial: Serial,
        time_ns: u64,
        usage: KeyUsage,
        state: KeyState,
        modifiers: Modifiers,
    ) -> Result<(), ProtocolError> {
        serial_required_event(serial.0)?;
        if !usage.is_valid() {
            return Err(ProtocolError::MalformedFrame);
        }
        Modifiers::from_bits(modifiers.bits()).ok_or(ProtocolError::ReservedBitsSet)?;
        write_u32_le(out, 12, serial.0);
        write_u64_le(out, 16, time_ns);
        write_u16_le(out, 24, usage.0);
        out[26] = state.as_u8();
        write_u16_le(out, 28, modifiers.bits());
        Ok(())
    }

    fn decode_key_body(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let serial = serial_required_event(read_u32_le(bytes, 12))?;
        let usage = KeyUsage(read_u16_le(bytes, 24));
        if !usage.is_valid() {
            return Err(ProtocolError::MalformedFrame);
        }
        let state = KeyState::from_u8(bytes[26]).ok_or(ProtocolError::MalformedFrame)?;
        let modifiers =
            Modifiers::from_bits(read_u16_le(bytes, 28)).ok_or(ProtocolError::ReservedBitsSet)?;
        Ok(Self::Key {
            serial,
            time_ns: read_u64_le(bytes, 16),
            usage,
            state,
            modifiers,
        })
    }

    fn encode_modifiers_body(
        out: &mut [u8; FRAME_BYTES],
        modifiers: Modifiers,
    ) -> Result<(), ProtocolError> {
        Modifiers::from_bits(modifiers.bits()).ok_or(ProtocolError::ReservedBitsSet)?;
        write_u16_le(out, 12, modifiers.bits());
        Ok(())
    }

    fn decode_modifiers_body(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let modifiers =
            Modifiers::from_bits(read_u16_le(bytes, 12)).ok_or(ProtocolError::ReservedBitsSet)?;
        Ok(Self::ModifiersChanged { modifiers })
    }
}

fn required_id(raw: u32) -> Result<ObjectId, ProtocolError> {
    decode_object_required(raw)
}
