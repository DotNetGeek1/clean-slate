//! Client → compositor requests (§2).

use crate::geometry::{BufferRect, Rect, Scale120, Size};
use crate::ids::{ClientBufferId, Serial, SurfaceId, WindowId};
use crate::pixel::{BufferLayout, ColorSpace, PixelFormat};
use crate::role::SurfaceRole;
use crate::window::{ResizeEdges, WindowTitle};

use super::*;

/// Maximum damage rects per frame (§2.2).
pub const DAMAGE_RECTS_PER_FRAME: usize = 5;
/// Maximum region rects per frame (§2.2).
pub const REGION_RECTS_PER_FRAME: usize = 3;

/// Client request (§2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    /// `Hello` (0x0001): negotiate protocol version and features.
    Hello {
        version: ProtocolVersion,
        features: Features,
    },
    /// `RegisterBuffer` (0x0010): register shared buffer layout.
    RegisterBuffer { layout: BufferLayout },
    /// `UnregisterBuffer` (0x0011): drop a client buffer handle.
    UnregisterBuffer { buffer: ClientBufferId },
    /// `CreateSurface` (0x0020): mint a surface.
    CreateSurface,
    /// `DestroySurface` (0x0021): destroy a surface.
    DestroySurface { surface: SurfaceId },
    /// `AssignRole` (0x0022): assign surface role and optional parent.
    AssignRole {
        surface: SurfaceId,
        role: SurfaceRole,
        parent: Option<SurfaceId>,
    },
    /// `Attach` (0x0023): attach or detach buffer to surface.
    Attach {
        surface: SurfaceId,
        buffer: Option<ClientBufferId>,
        buffer_scale: Scale120,
    },
    /// `Damage` (0x0024): buffer-space damage rects.
    Damage {
        surface: SurfaceId,
        rects: [BufferRect; DAMAGE_RECTS_PER_FRAME],
        count: u8,
    },
    /// `SetOpaqueRegion` (0x0025): opaque region in surface space.
    SetOpaqueRegion {
        surface: SurfaceId,
        rects: [Rect; REGION_RECTS_PER_FRAME],
        count: u8,
        replace: bool,
    },
    /// `SetInputRegion` (0x0026): input region in surface space.
    SetInputRegion {
        surface: SurfaceId,
        rects: [Rect; REGION_RECTS_PER_FRAME],
        count: u8,
        replace: bool,
    },
    /// `Commit` (0x0027): present surface state.
    Commit {
        surface: SurfaceId,
        request_frame: bool,
        color_space: ColorSpace,
        ack: Option<Serial>,
    },
    /// `CreateWindow` (0x0030): create window for surface.
    CreateWindow { surface: SurfaceId },
    /// `DestroyWindow` (0x0031): destroy window.
    DestroyWindow { window: WindowId },
    /// `SetTitle` (0x0032): set window title.
    SetTitle {
        window: WindowId,
        title: WindowTitle,
    },
    /// `SetSizeLimits` (0x0033): min/max window size.
    SetSizeLimits {
        window: WindowId,
        min: Size,
        max: Size,
    },
    /// `Show` (0x0034): show window.
    Show { window: WindowId },
    /// `Hide` (0x0035): hide window.
    Hide { window: WindowId },
    /// `BeginMove` (0x0036): start interactive move.
    BeginMove { window: WindowId, serial: Serial },
    /// `BeginResize` (0x0037): start interactive resize.
    BeginResize {
        window: WindowId,
        serial: Serial,
        edges: ResizeEdges,
    },
    /// `AckConfigure` (0x0038): acknowledge configure serial.
    AckConfigure { window: WindowId, serial: Serial },
}

impl Request {
    pub fn opcode(&self) -> u16 {
        match self {
            Self::Hello { .. } => OP_HELLO,
            Self::RegisterBuffer { .. } => OP_REGISTER_BUFFER,
            Self::UnregisterBuffer { .. } => OP_UNREGISTER_BUFFER,
            Self::CreateSurface => OP_CREATE_SURFACE,
            Self::DestroySurface { .. } => OP_DESTROY_SURFACE,
            Self::AssignRole { .. } => OP_ASSIGN_ROLE,
            Self::Attach { .. } => OP_ATTACH,
            Self::Damage { .. } => OP_DAMAGE,
            Self::SetOpaqueRegion { .. } => OP_SET_OPAQUE_REGION,
            Self::SetInputRegion { .. } => OP_SET_INPUT_REGION,
            Self::Commit { .. } => OP_COMMIT,
            Self::CreateWindow { .. } => OP_CREATE_WINDOW,
            Self::DestroyWindow { .. } => OP_DESTROY_WINDOW,
            Self::SetTitle { .. } => OP_SET_TITLE,
            Self::SetSizeLimits { .. } => OP_SET_SIZE_LIMITS,
            Self::Show { .. } => OP_SHOW,
            Self::Hide { .. } => OP_HIDE,
            Self::BeginMove { .. } => OP_BEGIN_MOVE,
            Self::BeginResize { .. } => OP_BEGIN_RESIZE,
            Self::AckConfigure { .. } => OP_ACK_CONFIGURE,
        }
    }

    pub fn encode(&self, tag: u32) -> Result<[u8; FRAME_BYTES], ProtocolError> {
        let mut out = [0u8; FRAME_BYTES];
        let op = self.opcode();
        write_u16_le(&mut out, 0, op);
        write_u32_le(&mut out, 4, tag);
        match *self {
            Self::Hello { version, features } => {
                object_must_be_zero(0)?;
                Self::encode_hello_body(&mut out, version, features)?;
            }
            Self::RegisterBuffer { layout } => {
                object_must_be_zero(0)?;
                Self::encode_register_buffer_body(&mut out, layout)?;
            }
            Self::UnregisterBuffer { buffer } => {
                write_u32_le(&mut out, 8, buffer.0.encode());
            }
            Self::CreateSurface => {
                object_must_be_zero(0)?;
            }
            Self::DestroySurface { surface } => {
                write_u32_le(&mut out, 8, surface.0.encode());
            }
            Self::AssignRole {
                surface,
                role,
                parent,
            } => {
                write_u32_le(&mut out, 8, surface.0.encode());
                Self::encode_assign_role_body(&mut out, role, parent)?;
            }
            Self::Attach {
                surface,
                buffer,
                buffer_scale,
            } => {
                write_u32_le(&mut out, 8, surface.0.encode());
                Self::encode_attach_body(&mut out, buffer, buffer_scale)?;
            }
            Self::Damage {
                surface,
                rects,
                count,
            } => {
                write_u32_le(&mut out, 8, surface.0.encode());
                Self::encode_damage_body(&mut out, rects, count)?;
            }
            Self::SetOpaqueRegion {
                surface,
                rects,
                count,
                replace,
            } => {
                write_u32_le(&mut out, 8, surface.0.encode());
                Self::encode_region_body(&mut out, rects, count, replace)?;
            }
            Self::SetInputRegion {
                surface,
                rects,
                count,
                replace,
            } => {
                write_u32_le(&mut out, 8, surface.0.encode());
                Self::encode_region_body(&mut out, rects, count, replace)?;
            }
            Self::Commit {
                surface,
                request_frame,
                color_space,
                ack,
            } => {
                write_u32_le(&mut out, 8, surface.0.encode());
                Self::encode_commit_body(&mut out, request_frame, color_space, ack)?;
            }
            Self::CreateWindow { surface } => {
                write_u32_le(&mut out, 8, surface.0.encode());
            }
            Self::DestroyWindow { window } => {
                write_u32_le(&mut out, 8, window.0.encode());
            }
            Self::SetTitle { window, title } => {
                write_u32_le(&mut out, 8, window.0.encode());
                Self::encode_set_title_body(&mut out, title)?;
            }
            Self::SetSizeLimits { window, min, max } => {
                write_u32_le(&mut out, 8, window.0.encode());
                Self::encode_set_size_limits_body(&mut out, min, max)?;
            }
            Self::Show { window } => {
                write_u32_le(&mut out, 8, window.0.encode());
            }
            Self::Hide { window } => {
                write_u32_le(&mut out, 8, window.0.encode());
            }
            Self::BeginMove { window, serial } => {
                write_u32_le(&mut out, 8, window.0.encode());
                serial_required_request(serial.0)?;
                write_u32_le(&mut out, 12, serial.0);
            }
            Self::BeginResize {
                window,
                serial,
                edges,
            } => {
                write_u32_le(&mut out, 8, window.0.encode());
                serial_required_request(serial.0)?;
                write_u32_le(&mut out, 12, serial.0);
                if ResizeEdges::from_u8(edges.bits()).is_none() {
                    return Err(ProtocolError::MalformedFrame);
                }
                out[16] = edges.bits();
            }
            Self::AckConfigure { window, serial } => {
                write_u32_le(&mut out, 8, window.0.encode());
                serial_required_request(serial.0)?;
                write_u32_le(&mut out, 12, serial.0);
            }
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Tagged<Self>, DecodeError> {
        check_frame_len(bytes)?;
        check_header_reserved(bytes)?;
        let opcode = read_u16_le(bytes, 0);
        let tag = read_u32_le(bytes, 4);
        let object = read_u32_le(bytes, 8);
        if !is_request_opcode(opcode) {
            return Err(decode_error(ProtocolError::UnknownOpcode, bytes));
        }
        let message = match opcode {
            OP_HELLO => {
                object_must_be_zero(object).map_err(|c| decode_error(c, bytes))?;
                check_range_zero(bytes, 24, 64).map_err(|c| decode_error(c, bytes))?;
                Self::decode_hello_body(bytes).map_err(|c| decode_error(c, bytes))?
            }
            OP_REGISTER_BUFFER => {
                object_must_be_zero(object).map_err(|c| decode_error(c, bytes))?;
                check_range_zero(bytes, 25, 64).map_err(|c| decode_error(c, bytes))?;
                Self::decode_register_buffer_body(bytes).map_err(|c| decode_error(c, bytes))?
            }
            OP_UNREGISTER_BUFFER => {
                check_range_zero(bytes, 12, 64).map_err(|c| decode_error(c, bytes))?;
                let id = decode_object_required(object).map_err(|c| decode_error(c, bytes))?;
                Self::UnregisterBuffer {
                    buffer: ClientBufferId(id),
                }
            }
            OP_CREATE_SURFACE => {
                object_must_be_zero(object).map_err(|c| decode_error(c, bytes))?;
                check_range_zero(bytes, 12, 64).map_err(|c| decode_error(c, bytes))?;
                Self::CreateSurface
            }
            OP_DESTROY_SURFACE => {
                check_range_zero(bytes, 12, 64).map_err(|c| decode_error(c, bytes))?;
                let id = decode_object_required(object).map_err(|c| decode_error(c, bytes))?;
                Self::DestroySurface {
                    surface: SurfaceId(id),
                }
            }
            OP_ASSIGN_ROLE => {
                let surface = decode_object_required(object).map_err(|c| decode_error(c, bytes))?;
                check_range_zero(bytes, 13, 16).map_err(|c| decode_error(c, bytes))?;
                check_range_zero(bytes, 20, 64).map_err(|c| decode_error(c, bytes))?;
                Self::decode_assign_role_body(bytes, SurfaceId(surface))
                    .map_err(|c| decode_error(c, bytes))?
            }
            OP_ATTACH => {
                let surface = decode_object_required(object).map_err(|c| decode_error(c, bytes))?;
                check_range_zero(bytes, 18, 64).map_err(|c| decode_error(c, bytes))?;
                Self::decode_attach_body(bytes, SurfaceId(surface))
                    .map_err(|c| decode_error(c, bytes))?
            }
            OP_DAMAGE => {
                let surface = decode_object_required(object).map_err(|c| decode_error(c, bytes))?;
                check_range_zero(bytes, 13, 16).map_err(|c| decode_error(c, bytes))?;
                check_range_zero(bytes, 56, 64).map_err(|c| decode_error(c, bytes))?;
                Self::decode_damage_body(bytes, SurfaceId(surface))
                    .map_err(|c| decode_error(c, bytes))?
            }
            OP_SET_OPAQUE_REGION | OP_SET_INPUT_REGION => {
                let surface = decode_object_required(object).map_err(|c| decode_error(c, bytes))?;
                Self::decode_region_body(bytes, SurfaceId(surface), opcode == OP_SET_OPAQUE_REGION)
                    .map_err(|c| decode_error(c, bytes))?
            }
            OP_COMMIT => {
                let surface = decode_object_required(object).map_err(|c| decode_error(c, bytes))?;
                check_range_zero(bytes, 14, 16).map_err(|c| decode_error(c, bytes))?;
                check_range_zero(bytes, 20, 64).map_err(|c| decode_error(c, bytes))?;
                Self::decode_commit_body(bytes, SurfaceId(surface))
                    .map_err(|c| decode_error(c, bytes))?
            }
            OP_CREATE_WINDOW => {
                check_range_zero(bytes, 12, 64).map_err(|c| decode_error(c, bytes))?;
                let id = decode_object_required(object).map_err(|c| decode_error(c, bytes))?;
                Self::CreateWindow {
                    surface: SurfaceId(id),
                }
            }
            OP_DESTROY_WINDOW => {
                check_range_zero(bytes, 12, 64).map_err(|c| decode_error(c, bytes))?;
                let id = decode_object_required(object).map_err(|c| decode_error(c, bytes))?;
                Self::DestroyWindow {
                    window: WindowId(id),
                }
            }
            OP_SET_TITLE => {
                let window = decode_object_required(object).map_err(|c| decode_error(c, bytes))?;
                check_range_zero(bytes, 53, 64).map_err(|c| decode_error(c, bytes))?;
                Self::decode_set_title_body(bytes, WindowId(window))
                    .map_err(|c| decode_error(c, bytes))?
            }
            OP_SET_SIZE_LIMITS => {
                let window = decode_object_required(object).map_err(|c| decode_error(c, bytes))?;
                check_range_zero(bytes, 28, 64).map_err(|c| decode_error(c, bytes))?;
                Self::decode_set_size_limits_body(bytes, WindowId(window))
                    .map_err(|c| decode_error(c, bytes))?
            }
            OP_SHOW => {
                check_range_zero(bytes, 12, 64).map_err(|c| decode_error(c, bytes))?;
                let id = decode_object_required(object).map_err(|c| decode_error(c, bytes))?;
                Self::Show {
                    window: WindowId(id),
                }
            }
            OP_HIDE => {
                check_range_zero(bytes, 12, 64).map_err(|c| decode_error(c, bytes))?;
                let id = decode_object_required(object).map_err(|c| decode_error(c, bytes))?;
                Self::Hide {
                    window: WindowId(id),
                }
            }
            OP_BEGIN_MOVE => {
                let window = decode_object_required(object).map_err(|c| decode_error(c, bytes))?;
                check_range_zero(bytes, 16, 64).map_err(|c| decode_error(c, bytes))?;
                let serial = serial_required_request(read_u32_le(bytes, 12))
                    .map_err(|c| decode_error(c, bytes))?;
                Self::BeginMove {
                    window: WindowId(window),
                    serial,
                }
            }
            OP_BEGIN_RESIZE => {
                let window = decode_object_required(object).map_err(|c| decode_error(c, bytes))?;
                check_range_zero(bytes, 17, 64).map_err(|c| decode_error(c, bytes))?;
                let serial = serial_required_request(read_u32_le(bytes, 12))
                    .map_err(|c| decode_error(c, bytes))?;
                let edges = ResizeEdges::from_u8(bytes[16])
                    .ok_or(ProtocolError::MalformedFrame)
                    .map_err(|c| decode_error(c, bytes))?;
                Self::BeginResize {
                    window: WindowId(window),
                    serial,
                    edges,
                }
            }
            OP_ACK_CONFIGURE => {
                let window = decode_object_required(object).map_err(|c| decode_error(c, bytes))?;
                check_range_zero(bytes, 16, 64).map_err(|c| decode_error(c, bytes))?;
                let serial = serial_required_request(read_u32_le(bytes, 12))
                    .map_err(|c| decode_error(c, bytes))?;
                Self::AckConfigure {
                    window: WindowId(window),
                    serial,
                }
            }
            _ => return Err(decode_error(ProtocolError::UnknownOpcode, bytes)),
        };
        Ok(Tagged { tag, message })
    }

    fn encode_hello_body(
        out: &mut [u8; FRAME_BYTES],
        version: ProtocolVersion,
        features: Features,
    ) -> Result<(), ProtocolError> {
        write_u16_le(out, 12, version.major);
        write_u16_le(out, 14, version.minor);
        write_u64_le(out, 16, features.bits());
        Ok(())
    }

    fn decode_hello_body(bytes: &[u8]) -> Result<Self, ProtocolError> {
        Ok(Self::Hello {
            version: ProtocolVersion {
                major: read_u16_le(bytes, 12),
                minor: read_u16_le(bytes, 14),
            },
            features: Features(read_u64_le(bytes, 16)),
        })
    }

    fn encode_register_buffer_body(
        out: &mut [u8; FRAME_BYTES],
        layout: BufferLayout,
    ) -> Result<(), ProtocolError> {
        let format = layout.format();
        let width = layout.width();
        let height = layout.height();
        let stride = layout.stride_bytes();
        PixelFormat::from_u8(format as u8).ok_or(ProtocolError::InvalidFormat)?;
        BufferLayout::new(width, height, stride, format)
            .map_err(|_| ProtocolError::InvalidLayout)?;
        write_u32_le(out, 12, width);
        write_u32_le(out, 16, height);
        write_u32_le(out, 20, stride);
        out[24] = format as u8;
        Ok(())
    }

    fn decode_register_buffer_body(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let width = read_u32_le(bytes, 12);
        let height = read_u32_le(bytes, 16);
        let stride = read_u32_le(bytes, 20);
        let format_raw = bytes[24];
        let format = PixelFormat::from_u8(format_raw).ok_or(ProtocolError::InvalidFormat)?;
        let layout = BufferLayout::new(width, height, stride, format)
            .map_err(|_| ProtocolError::InvalidLayout)?;
        Ok(Self::RegisterBuffer { layout })
    }

    fn encode_assign_role_body(
        out: &mut [u8; FRAME_BYTES],
        role: SurfaceRole,
        parent: Option<SurfaceId>,
    ) -> Result<(), ProtocolError> {
        if SurfaceRole::from_u8(role.as_u8()).is_none() {
            return Err(ProtocolError::MalformedFrame);
        }
        out[12] = role.as_u8();
        let parent_raw = parent.map(|p| p.0.encode()).unwrap_or(0);
        if parent_raw != 0 {
            decode_object_required(parent_raw)?;
        }
        write_u32_le(out, 16, parent_raw);
        Ok(())
    }

    fn decode_assign_role_body(bytes: &[u8], surface: SurfaceId) -> Result<Self, ProtocolError> {
        let role = SurfaceRole::from_u8(bytes[12]).ok_or(ProtocolError::MalformedFrame)?;
        let parent_raw = read_u32_le(bytes, 16);
        let parent = decode_object_optional(parent_raw)?;
        Ok(Self::AssignRole {
            surface,
            role,
            parent: parent.map(SurfaceId),
        })
    }

    fn encode_attach_body(
        out: &mut [u8; FRAME_BYTES],
        buffer: Option<ClientBufferId>,
        buffer_scale: Scale120,
    ) -> Result<(), ProtocolError> {
        let raw = buffer.map(|b| b.0.encode()).unwrap_or(0);
        if raw != 0 {
            decode_object_required(raw)?;
        }
        if buffer_scale.0 == 0 {
            return Err(ProtocolError::InvalidScale);
        }
        write_u32_le(out, 12, raw);
        write_u16_le(out, 16, buffer_scale.0);
        Ok(())
    }

    fn decode_attach_body(bytes: &[u8], surface: SurfaceId) -> Result<Self, ProtocolError> {
        let buf_raw = read_u32_le(bytes, 12);
        let buffer = decode_object_optional(buf_raw)?.map(ClientBufferId);
        let scale_raw = read_u16_le(bytes, 16);
        if scale_raw == 0 {
            return Err(ProtocolError::InvalidScale);
        }
        Ok(Self::Attach {
            surface,
            buffer,
            buffer_scale: Scale120(scale_raw),
        })
    }

    fn encode_damage_body(
        out: &mut [u8; FRAME_BYTES],
        rects: [BufferRect; DAMAGE_RECTS_PER_FRAME],
        count: u8,
    ) -> Result<(), ProtocolError> {
        if count as usize > DAMAGE_RECTS_PER_FRAME {
            return Err(ProtocolError::InvalidDamage);
        }
        out[12] = count;
        for (i, r) in rects.iter().enumerate().take(DAMAGE_RECTS_PER_FRAME) {
            if i < count as usize {
                let base = 16 + 8 * i;
                write_u16_le(out, base, r.x);
                write_u16_le(out, base + 2, r.y);
                write_u16_le(out, base + 4, r.width);
                write_u16_le(out, base + 6, r.height);
            }
        }
        Ok(())
    }

    fn decode_damage_body(bytes: &[u8], surface: SurfaceId) -> Result<Self, ProtocolError> {
        let count = bytes[12];
        if count as usize > DAMAGE_RECTS_PER_FRAME {
            return Err(ProtocolError::InvalidDamage);
        }
        let mut rects = [BufferRect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        }; DAMAGE_RECTS_PER_FRAME];
        for (i, slot) in rects.iter_mut().enumerate().take(DAMAGE_RECTS_PER_FRAME) {
            let base = 16 + 8 * i;
            let slice = &bytes[base..base + 8];
            if i < count as usize {
                *slot = BufferRect {
                    x: read_u16_le(bytes, base),
                    y: read_u16_le(bytes, base + 2),
                    width: read_u16_le(bytes, base + 4),
                    height: read_u16_le(bytes, base + 6),
                };
            } else if slice.iter().any(|&b| b != 0) {
                return Err(ProtocolError::ReservedBitsSet);
            }
        }
        Ok(Self::Damage {
            surface,
            rects,
            count,
        })
    }

    fn encode_region_body(
        out: &mut [u8; FRAME_BYTES],
        rects: [Rect; REGION_RECTS_PER_FRAME],
        count: u8,
        replace: bool,
    ) -> Result<(), ProtocolError> {
        if count as usize > REGION_RECTS_PER_FRAME {
            return Err(ProtocolError::InvalidRegion);
        }
        out[12] = count;
        out[13] = u8::from(replace);
        for (i, r) in rects.iter().enumerate().take(REGION_RECTS_PER_FRAME) {
            if i < count as usize {
                r.validate().map_err(|_| ProtocolError::InvalidRegion)?;
                write_rect(out, 16 + 16 * i, *r);
            }
        }
        Ok(())
    }

    fn decode_region_body(
        bytes: &[u8],
        surface: SurfaceId,
        opaque: bool,
    ) -> Result<Self, ProtocolError> {
        let count = bytes[12];
        if count as usize > REGION_RECTS_PER_FRAME {
            return Err(ProtocolError::InvalidRegion);
        }
        let replace = decode_bool(bytes[13])?;
        check_range_zero(bytes, 14, 16)?;
        let mut rects = [Rect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        }; REGION_RECTS_PER_FRAME];
        for (i, slot) in rects.iter_mut().enumerate().take(REGION_RECTS_PER_FRAME) {
            let base = 16 + 16 * i;
            if i < count as usize {
                let r = read_rect(bytes, base)?;
                r.validate().map_err(|_| ProtocolError::InvalidRegion)?;
                *slot = r;
            } else if bytes[base..base + 16].iter().any(|&b| b != 0) {
                return Err(ProtocolError::ReservedBitsSet);
            }
        }
        if opaque {
            Ok(Self::SetOpaqueRegion {
                surface,
                rects,
                count,
                replace,
            })
        } else {
            Ok(Self::SetInputRegion {
                surface,
                rects,
                count,
                replace,
            })
        }
    }

    fn encode_commit_body(
        out: &mut [u8; FRAME_BYTES],
        request_frame: bool,
        color_space: ColorSpace,
        ack: Option<Serial>,
    ) -> Result<(), ProtocolError> {
        out[12] = u8::from(request_frame);
        match color_space {
            ColorSpace::Srgb => out[13] = 0,
        }
        write_u32_le(out, 16, ack.map(|s| s.0).unwrap_or(0));
        Ok(())
    }

    fn decode_commit_body(bytes: &[u8], surface: SurfaceId) -> Result<Self, ProtocolError> {
        let request_frame = decode_bool(bytes[12])?;
        let cs = match bytes[13] {
            0 => ColorSpace::Srgb,
            _ => return Err(ProtocolError::InvalidFormat),
        };
        let ack = serial_optional(read_u32_le(bytes, 16));
        Ok(Self::Commit {
            surface,
            request_frame,
            color_space: cs,
            ack,
        })
    }

    fn encode_set_title_body(
        out: &mut [u8; FRAME_BYTES],
        title: WindowTitle,
    ) -> Result<(), ProtocolError> {
        let (bytes, len) = title.wire_bytes();
        out[12] = len;
        out[13..13 + crate::limits::MAX_TITLE_BYTES].copy_from_slice(&bytes);
        Ok(())
    }

    fn decode_set_title_body(bytes: &[u8], window: WindowId) -> Result<Self, ProtocolError> {
        let len = bytes[12];
        if len as usize > crate::limits::MAX_TITLE_BYTES {
            return Err(ProtocolError::MalformedFrame);
        }
        let mut title_bytes = [0u8; crate::limits::MAX_TITLE_BYTES];
        title_bytes.copy_from_slice(&bytes[13..13 + crate::limits::MAX_TITLE_BYTES]);
        let title = WindowTitle::from_wire(len, &title_bytes)?;
        Ok(Self::SetTitle { window, title })
    }

    fn encode_set_size_limits_body(
        out: &mut [u8; FRAME_BYTES],
        min: Size,
        max: Size,
    ) -> Result<(), ProtocolError> {
        validate_size_limits(min, max)?;
        write_u32_le(out, 12, min.width);
        write_u32_le(out, 16, min.height);
        write_u32_le(out, 20, max.width);
        write_u32_le(out, 24, max.height);
        Ok(())
    }

    fn decode_set_size_limits_body(bytes: &[u8], window: WindowId) -> Result<Self, ProtocolError> {
        let min = Size {
            width: read_u32_le(bytes, 12),
            height: read_u32_le(bytes, 16),
        };
        let max = Size {
            width: read_u32_le(bytes, 20),
            height: read_u32_le(bytes, 24),
        };
        validate_size_limits(min, max)?;
        Ok(Self::SetSizeLimits { window, min, max })
    }
}

fn validate_size_limits(min: Size, max: Size) -> Result<(), ProtocolError> {
    use crate::limits::MAX_SURFACE_EXTENT;
    if min.width > MAX_SURFACE_EXTENT || min.height > MAX_SURFACE_EXTENT {
        return Err(ProtocolError::InvalidLayout);
    }
    if max.width > MAX_SURFACE_EXTENT || max.height > MAX_SURFACE_EXTENT {
        return Err(ProtocolError::InvalidLayout);
    }
    if max.width != 0 && min.width > max.width {
        return Err(ProtocolError::InvalidLayout);
    }
    if max.height != 0 && min.height > max.height {
        return Err(ProtocolError::InvalidLayout);
    }
    Ok(())
}

fn write_rect(out: &mut [u8], base: usize, r: Rect) {
    write_i32_le(out, base, r.x);
    write_i32_le(out, base + 4, r.y);
    write_u32_le(out, base + 8, r.width);
    write_u32_le(out, base + 12, r.height);
}

fn read_rect(bytes: &[u8], base: usize) -> Result<Rect, ProtocolError> {
    Ok(Rect {
        x: read_i32_le(bytes, base),
        y: read_i32_le(bytes, base + 4),
        width: read_u32_le(bytes, base + 8),
        height: read_u32_le(bytes, base + 12),
    })
}
