//! Supervisor → kernel/service control requests (no embedded restart policy).

use crate::identity::ServiceId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ControlRequestKind {
    Start = 1,
    Stop = 2,
    Terminate = 3,
    Restart = 4,
}

impl ControlRequestKind {
    pub const fn from_repr(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Start),
            2 => Some(Self::Stop),
            3 => Some(Self::Terminate),
            4 => Some(Self::Restart),
            _ => None,
        }
    }
}

/// Explicit lifecycle control envelope (policy-free).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlRequest {
    pub service: ServiceId,
    pub kind: ControlRequestKind,
}

impl ControlRequest {
    pub const fn new(service: ServiceId, kind: ControlRequestKind) -> Self {
        Self { service, kind }
    }
}
