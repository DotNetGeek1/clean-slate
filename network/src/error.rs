//! Network error taxonomy and stable diagnostic codes.

use crate::device::NetworkDeviceError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenialReason {
    /// No capability was presented for the operation.
    NoCapability,
    /// A capability was presented but lacks the required right bit.
    MissingRight,
    /// Session or service instance generation does not match the live service.
    StaleGeneration,
    /// Capability was revoked.
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkError {
    InvalidRequest,
    Denied(DenialReason),
    Unreachable,
    Timeout,
    Reset,
    Protocol,
    Transport(NetworkDeviceError),
    QueueFull,
    SessionExhausted,
    NotFound,
    Closed,
}

impl NetworkError {
    /// Stable wire/diagnostic code (unique per variant).
    pub const fn code(self) -> u16 {
        match self {
            Self::InvalidRequest => 1,
            Self::Denied(DenialReason::NoCapability) => 2,
            Self::Denied(DenialReason::MissingRight) => 3,
            Self::Denied(DenialReason::StaleGeneration) => 4,
            Self::Denied(DenialReason::Revoked) => 5,
            Self::Unreachable => 6,
            Self::Timeout => 7,
            Self::Reset => 8,
            Self::Protocol => 9,
            Self::Transport(_) => 10,
            Self::QueueFull => 11,
            Self::SessionExhausted => 12,
            Self::NotFound => 13,
            Self::Closed => 14,
        }
    }
}
