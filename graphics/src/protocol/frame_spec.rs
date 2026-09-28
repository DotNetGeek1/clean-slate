//! Per-opcode wire layout descriptors for decode steps 4–6 (§1.5).

use super::ProtocolError;

/// Header `object` rule (§1.5 step 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectRule {
    /// Nonzero → `ReservedBitsSet`.
    MustBeZero,
    /// Zero → `InvalidObject`; nonzero must decode as [`ObjectId`](crate::ids::ObjectId).
    Required,
    /// Zero = none; nonzero must decode optionally.
    Optional,
    /// No validation (`Error` echo).
    RawEcho,
}

/// Static padding ranges: half-open `[start, end)` absolute frame offsets (§1.5 step 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpcodeSpec {
    pub opcode: u16,
    pub object: ObjectRule,
    pub pads: &'static [(u8, u8)],
}

pub(crate) fn lookup_spec<'a>(specs: &'static [OpcodeSpec], opcode: u16) -> Option<&'a OpcodeSpec> {
    specs.iter().find(|s| s.opcode == opcode)
}

pub(crate) fn apply_object_rule(rule: ObjectRule, object: u32) -> Result<(), ProtocolError> {
    use super::{decode_object_optional, decode_object_required, object_must_be_zero};
    match rule {
        ObjectRule::MustBeZero => object_must_be_zero(object),
        ObjectRule::Required => {
            decode_object_required(object)?;
            Ok(())
        }
        ObjectRule::Optional => {
            decode_object_optional(object)?;
            Ok(())
        }
        ObjectRule::RawEcho => Ok(()),
    }
}

/// Request opcode layout (§2.3). Field bytes are decoded in step 7 only.
pub static REQUEST_SPECS: &[OpcodeSpec] = &[
    OpcodeSpec {
        opcode: super::OP_HELLO,
        object: ObjectRule::MustBeZero,
        pads: &[(24, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_REGISTER_BUFFER,
        object: ObjectRule::MustBeZero,
        pads: &[(25, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_UNREGISTER_BUFFER,
        object: ObjectRule::Required,
        pads: &[(12, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_CREATE_SURFACE,
        object: ObjectRule::MustBeZero,
        pads: &[(12, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_DESTROY_SURFACE,
        object: ObjectRule::Required,
        pads: &[(12, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_ASSIGN_ROLE,
        object: ObjectRule::Required,
        pads: &[(13, 16), (20, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_ATTACH,
        object: ObjectRule::Required,
        pads: &[(18, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_DAMAGE,
        object: ObjectRule::Required,
        pads: &[(13, 16), (56, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_SET_OPAQUE_REGION,
        object: ObjectRule::Required,
        pads: &[(14, 16)],
    },
    OpcodeSpec {
        opcode: super::OP_SET_INPUT_REGION,
        object: ObjectRule::Required,
        pads: &[(14, 16)],
    },
    OpcodeSpec {
        opcode: super::OP_COMMIT,
        object: ObjectRule::Required,
        pads: &[(14, 16), (20, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_CREATE_WINDOW,
        object: ObjectRule::Required,
        pads: &[(12, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_DESTROY_WINDOW,
        object: ObjectRule::Required,
        pads: &[(12, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_SET_TITLE,
        object: ObjectRule::Required,
        pads: &[(53, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_SET_SIZE_LIMITS,
        object: ObjectRule::Required,
        pads: &[(28, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_SHOW,
        object: ObjectRule::Required,
        pads: &[(12, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_HIDE,
        object: ObjectRule::Required,
        pads: &[(12, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_BEGIN_MOVE,
        object: ObjectRule::Required,
        pads: &[(16, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_BEGIN_RESIZE,
        object: ObjectRule::Required,
        pads: &[(17, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_ACK_CONFIGURE,
        object: ObjectRule::Required,
        pads: &[(16, 64)],
    },
];

/// Event opcode layout (§3.3).
pub static EVENT_SPECS: &[OpcodeSpec] = &[
    OpcodeSpec {
        opcode: super::OP_WELCOME,
        object: ObjectRule::MustBeZero,
        pads: &[(41, 42), (56, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_ERROR,
        object: ObjectRule::RawEcho,
        pads: &[(16, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_BUFFER_REGISTERED,
        object: ObjectRule::Required,
        pads: &[(12, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_BUFFER_RELEASED,
        object: ObjectRule::Required,
        pads: &[(12, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_BUFFER_UNREGISTERED,
        object: ObjectRule::Required,
        pads: &[(12, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_SURFACE_CREATED,
        object: ObjectRule::Required,
        pads: &[(12, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_FRAME_DONE,
        object: ObjectRule::Required,
        pads: &[(28, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_WINDOW_CREATED,
        object: ObjectRule::Required,
        pads: &[(12, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_CONFIGURE,
        object: ObjectRule::Required,
        pads: &[(27, 28), (40, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_CLOSE_REQUESTED,
        object: ObjectRule::Required,
        pads: &[(12, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_KEYBOARD_FOCUS,
        object: ObjectRule::Optional,
        pads: &[(12, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_KEY,
        object: ObjectRule::MustBeZero,
        pads: &[(27, 28), (30, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_MODIFIERS_CHANGED,
        object: ObjectRule::MustBeZero,
        pads: &[(14, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_POINTER_ENTER,
        object: ObjectRule::Required,
        pads: &[(24, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_POINTER_LEAVE,
        object: ObjectRule::Required,
        pads: &[(16, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_POINTER_MOTION,
        object: ObjectRule::MustBeZero,
        pads: &[(28, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_POINTER_BUTTON,
        object: ObjectRule::MustBeZero,
        pads: &[(27, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_POINTER_AXIS,
        object: ObjectRule::MustBeZero,
        pads: &[(28, 64)],
    },
    OpcodeSpec {
        opcode: super::OP_INPUT_RESET,
        object: ObjectRule::MustBeZero,
        pads: &[(12, 64)],
    },
];

pub(crate) fn run_decode_prelude(
    bytes: &[u8],
    specs: &'static [OpcodeSpec],
    opcode: u16,
    object: u32,
) -> Result<(), ProtocolError> {
    let spec = lookup_spec(specs, opcode).ok_or(ProtocolError::UnknownOpcode)?;
    apply_object_rule(spec.object, object)?;
    for &(start, end) in spec.pads {
        super::check_range_zero(bytes, start as usize, end as usize)?;
    }
    Ok(())
}
