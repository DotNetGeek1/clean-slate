//! Health/liveness report envelope (detection policy lives in M4.4).

use crate::identity::{InstanceGeneration, ServiceId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HealthStatus {
    Unknown = 0,
    Ok = 1,
    Degraded = 2,
    Unhealthy = 3,
}

impl HealthStatus {
    pub const fn from_repr(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Unknown),
            1 => Some(Self::Ok),
            2 => Some(Self::Degraded),
            3 => Some(Self::Unhealthy),
            _ => None,
        }
    }
}

/// Bounded health report tied to logical service + instance generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HealthReport {
    pub service: ServiceId,
    pub generation: InstanceGeneration,
    pub status: HealthStatus,
    /// Reserved for future structured detail (M4.4); must be zero in v1 wire.
    pub detail_reserved: u32,
}

impl HealthReport {
    pub const fn new(
        service: ServiceId,
        generation: InstanceGeneration,
        status: HealthStatus,
    ) -> Self {
        Self {
            service,
            generation,
            status,
            detail_reserved: 0,
        }
    }
}
