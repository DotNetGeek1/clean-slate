//! Explicit launch metadata for fault-injection fixtures (no hidden globals).

use crate::CRASH_SERVICE_ID;
use clean_slate_service_lifecycle::{InstanceGeneration, ServiceId};

pub const CRASH_SERVICE_LAUNCH_MAGIC: u32 = 0x4353_4631; // "CSF1"
pub const CRASH_SERVICE_LAUNCH_VERSION: u16 = 1;
pub const UNRELATED_WORKLOAD_LAUNCH_MAGIC: u32 = 0x5557_4C31; // "UWL1"
pub const UNRELATED_WORKLOAD_LAUNCH_VERSION: u16 = 1;

pub const CRASH_SERVICE_LAUNCH_CONFIG_BYTES: usize = 40;
pub const UNRELATED_WORKLOAD_LAUNCH_CONFIG_BYTES: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CrashServiceMode {
    /// Remain healthy until an explicit inject command (host harness or future supervisor).
    HealthyUntilInject = 0,
    /// Fault once `heartbeat` reaches `crash_at_heartbeat` (deterministic run count).
    CrashAtHeartbeat = 1,
}

impl CrashServiceMode {
    pub const fn from_repr(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::HealthyUntilInject),
            1 => Some(Self::CrashAtHeartbeat),
            _ => None,
        }
    }
}

/// Fixed-size launch block copied into a userspace data page by the kernel or supervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrashServiceLaunchConfig {
    pub service: ServiceId,
    pub generation: InstanceGeneration,
    pub mode: CrashServiceMode,
    /// Userspace heartbeat ticks before a contained fault (only for `CrashAtHeartbeat`).
    pub crash_at_heartbeat: u32,
    /// Proves a replacement instance did not inherit stale user state.
    pub stack_evidence: u64,
    /// Canonical userspace probe for a contained page fault.
    pub fault_probe_address: u64,
}

impl CrashServiceLaunchConfig {
    pub const fn healthy_instance(
        generation: InstanceGeneration,
        stack_evidence: u64,
        fault_probe_address: u64,
    ) -> Self {
        Self {
            service: CRASH_SERVICE_ID,
            generation,
            mode: CrashServiceMode::HealthyUntilInject,
            crash_at_heartbeat: 0,
            stack_evidence,
            fault_probe_address,
        }
    }

    pub const fn crash_after_heartbeats(
        generation: InstanceGeneration,
        crash_at_heartbeat: u32,
        stack_evidence: u64,
        fault_probe_address: u64,
    ) -> Self {
        Self {
            service: CRASH_SERVICE_ID,
            generation,
            mode: CrashServiceMode::CrashAtHeartbeat,
            crash_at_heartbeat,
            stack_evidence,
            fault_probe_address,
        }
    }

    pub fn encode(&self) -> Result<[u8; CRASH_SERVICE_LAUNCH_CONFIG_BYTES], ConfigEncodeError> {
        self.validate()?;
        let mut out = [0u8; CRASH_SERVICE_LAUNCH_CONFIG_BYTES];
        out[0..4].copy_from_slice(&CRASH_SERVICE_LAUNCH_MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&CRASH_SERVICE_LAUNCH_VERSION.to_le_bytes());
        out[6..10].copy_from_slice(&self.service.0.to_le_bytes());
        out[10..14].copy_from_slice(&self.generation.0.to_le_bytes());
        out[14] = self.mode as u8;
        out[15..19].copy_from_slice(&self.crash_at_heartbeat.to_le_bytes());
        out[19..27].copy_from_slice(&self.stack_evidence.to_le_bytes());
        out[27..35].copy_from_slice(&self.fault_probe_address.to_le_bytes());
        Ok(out)
    }

    pub fn decode(
        bytes: &[u8; CRASH_SERVICE_LAUNCH_CONFIG_BYTES],
    ) -> Result<Self, ConfigDecodeError> {
        let magic = u32::from_le_bytes(bytes[0..4].try_into().expect("slice"));
        if magic != CRASH_SERVICE_LAUNCH_MAGIC {
            return Err(ConfigDecodeError::BadMagic);
        }
        let version = u16::from_le_bytes(bytes[4..6].try_into().expect("slice"));
        if version != CRASH_SERVICE_LAUNCH_VERSION {
            return Err(ConfigDecodeError::UnsupportedVersion(version));
        }
        let service = ServiceId(u32::from_le_bytes(bytes[6..10].try_into().expect("slice")));
        let generation =
            InstanceGeneration(u32::from_le_bytes(bytes[10..14].try_into().expect("slice")));
        let mode = CrashServiceMode::from_repr(bytes[14]).ok_or(ConfigDecodeError::InvalidMode)?;
        let crash_at_heartbeat = u32::from_le_bytes(bytes[15..19].try_into().expect("slice"));
        let stack_evidence = u64::from_le_bytes(bytes[19..27].try_into().expect("slice"));
        let fault_probe_address = u64::from_le_bytes(bytes[27..35].try_into().expect("slice"));
        let config = Self {
            service,
            generation,
            mode,
            crash_at_heartbeat,
            stack_evidence,
            fault_probe_address,
        };
        config.validate().map_err(ConfigDecodeError::Invalid)?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigEncodeError> {
        if self.service != CRASH_SERVICE_ID {
            return Err(ConfigEncodeError::UnexpectedService);
        }
        if self.fault_probe_address == 0 {
            return Err(ConfigEncodeError::InvalidProbeAddress);
        }
        match self.mode {
            CrashServiceMode::HealthyUntilInject => Ok(()),
            CrashServiceMode::CrashAtHeartbeat if self.crash_at_heartbeat == 0 => {
                Err(ConfigEncodeError::InvalidHeartbeat)
            }
            CrashServiceMode::CrashAtHeartbeat => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnrelatedWorkloadLaunchConfig {
    pub service: ServiceId,
    pub progress_token: u64,
}

impl UnrelatedWorkloadLaunchConfig {
    pub const fn new(service: ServiceId, progress_token: u64) -> Self {
        Self {
            service,
            progress_token,
        }
    }

    pub fn encode(
        &self,
    ) -> Result<[u8; UNRELATED_WORKLOAD_LAUNCH_CONFIG_BYTES], ConfigEncodeError> {
        let mut out = [0u8; UNRELATED_WORKLOAD_LAUNCH_CONFIG_BYTES];
        out[0..4].copy_from_slice(&UNRELATED_WORKLOAD_LAUNCH_MAGIC.to_le_bytes());
        out[4..6].copy_from_slice(&UNRELATED_WORKLOAD_LAUNCH_VERSION.to_le_bytes());
        out[6..10].copy_from_slice(&self.service.0.to_le_bytes());
        out[10..18].copy_from_slice(&self.progress_token.to_le_bytes());
        Ok(out)
    }

    pub fn decode(
        bytes: &[u8; UNRELATED_WORKLOAD_LAUNCH_CONFIG_BYTES],
    ) -> Result<Self, ConfigDecodeError> {
        let magic = u32::from_le_bytes(bytes[0..4].try_into().expect("slice"));
        if magic != UNRELATED_WORKLOAD_LAUNCH_MAGIC {
            return Err(ConfigDecodeError::BadMagic);
        }
        let version = u16::from_le_bytes(bytes[4..6].try_into().expect("slice"));
        if version != UNRELATED_WORKLOAD_LAUNCH_VERSION {
            return Err(ConfigDecodeError::UnsupportedVersion(version));
        }
        let service = ServiceId(u32::from_le_bytes(bytes[6..10].try_into().expect("slice")));
        let progress_token = u64::from_le_bytes(bytes[10..18].try_into().expect("slice"));
        Ok(Self {
            service,
            progress_token,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigEncodeError {
    UnexpectedService,
    InvalidProbeAddress,
    InvalidHeartbeat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigDecodeError {
    BadMagic,
    UnsupportedVersion(u16),
    InvalidMode,
    Invalid(ConfigEncodeError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crash_service_config_round_trips() {
        let config = CrashServiceLaunchConfig::crash_after_heartbeats(
            InstanceGeneration(2),
            3,
            0xDEAD_BEEF_CAFE_0002,
            0x0000_4000_0000_1000,
        );
        let bytes = config.encode().expect("encode");
        let decoded = CrashServiceLaunchConfig::decode(&bytes).expect("decode");
        assert_eq!(decoded, config);
    }

    #[test]
    fn crash_service_rejects_wrong_service_id() {
        let mut config =
            CrashServiceLaunchConfig::healthy_instance(InstanceGeneration(1), 1, 0x1000);
        config.service = ServiceId(99);
        assert_eq!(
            config.encode().unwrap_err(),
            ConfigEncodeError::UnexpectedService
        );
    }

    #[test]
    fn unrelated_workload_config_round_trips() {
        let config = UnrelatedWorkloadLaunchConfig::new(ServiceId(0x7777), 0x42);
        let bytes = config.encode().expect("encode");
        let decoded = UnrelatedWorkloadLaunchConfig::decode(&bytes).expect("decode");
        assert_eq!(decoded, config);
    }
}
