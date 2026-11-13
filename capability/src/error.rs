//! Deterministic capability errors and syscall status mapping.

/// Authorization and wire-format failures (stable `repr(u8)` for audit).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityError {
    InvalidHandle = 0,
    StaleHandle = 1,
    Revoked = 2,
    UnauthorizedHolder = 3,
    WrongResource = 4,
    MissingRight = 5,
    InvalidRights = 6,
    RightsWidening = 7,
    DelegationDepthExceeded = 8,
    CapacityExhausted = 9,
    GenerationExhausted = 10,
    /// Parent lacks `DELEGATE`, or requested rights include [`crate::rights::Rights::root_only_for`]
    /// bits that must not be delegated.
    NotDelegable = 11,
}

impl CapabilityError {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::InvalidHandle),
            1 => Some(Self::StaleHandle),
            2 => Some(Self::Revoked),
            3 => Some(Self::UnauthorizedHolder),
            4 => Some(Self::WrongResource),
            5 => Some(Self::MissingRight),
            6 => Some(Self::InvalidRights),
            7 => Some(Self::RightsWidening),
            8 => Some(Self::DelegationDepthExceeded),
            9 => Some(Self::CapacityExhausted),
            10 => Some(Self::GenerationExhausted),
            11 => Some(Self::NotDelegable),
            _ => None,
        }
    }

    /// Stable marker for audit / protocol surfaces.
    pub const fn error_name(self) -> &'static str {
        match self {
            Self::InvalidHandle => "invalid-handle",
            Self::StaleHandle => "stale",
            Self::Revoked => "revoked",
            Self::UnauthorizedHolder => "wrong-holder",
            Self::WrongResource => "wrong-resource",
            Self::MissingRight => "missing-right",
            Self::InvalidRights => "invalid-rights",
            Self::RightsWidening => "rights-widening",
            Self::DelegationDepthExceeded => "depth-exceeded",
            Self::CapacityExhausted => "capacity",
            Self::GenerationExhausted => "generation-exhausted",
            Self::NotDelegable => "not-delegable",
        }
    }

    pub fn syscall_status(self) -> u64 {
        use syscall_abi::{SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_ENOSPC, SYSCALL_ESTALE};
        match self {
            Self::InvalidHandle | Self::InvalidRights => SYSCALL_EINVAL,
            Self::StaleHandle | Self::Revoked => SYSCALL_ESTALE,
            Self::UnauthorizedHolder
            | Self::WrongResource
            | Self::MissingRight
            | Self::RightsWidening
            | Self::NotDelegable => SYSCALL_EACCES,
            Self::CapacityExhausted | Self::GenerationExhausted | Self::DelegationDepthExceeded => {
                SYSCALL_ENOSPC
            }
        }
    }
}

/// Syscall ABI constants shared with the kernel (M6 lanes).
pub mod syscall_abi {
    use super::CapabilityError;

    pub const SYSCALL_EACCES: u64 = u64::MAX - 12;
    pub const SYSCALL_EINVAL: u64 = u64::MAX - 21;
    pub const SYSCALL_ENOSPC: u64 = u64::MAX - 28;
    pub const SYSCALL_ESTALE: u64 = u64::MAX - 116;
    pub const SYSCALL_ENOSYS: u64 = u64::MAX - 37;

    /// Reserved M6 syscall numbers (implementations live in later milestones).
    pub const SYSCALL_NR_CAP_OBJECT: u64 = 8;
    pub const SYSCALL_NR_CAP_PROCESS_CONTROL: u64 = 9;
    pub const SYSCALL_NR_CAP_DELEGATE: u64 = 10;
    pub const SYSCALL_NR_CAP_REVOKE: u64 = 11;
    pub const SYSCALL_NR_CAP_AUDIT_READ: u64 = 12;
    pub const SYSCALL_NR_CAP_GRANT: u64 = 13;

    /// `SYSCALL_NR_CAP_REVOKE` ops (`rdi`); `rsi` is the capability handle. Ops 3 and 4 are
    /// reserved for the M6.6 self-test kernel.
    pub const CAP_REVOKE_OP_REVOKE: u64 = 1;
    pub const CAP_REVOKE_OP_PROBE: u64 = 2;
    /// Drops the caller's own handle and frees its slot; never touches another record.
    pub const CAP_REVOKE_OP_DROP: u64 = 5;
    pub const SYSCALL_NR_NETWORK_CAPABILITY: u64 = 14;
    pub const SYSCALL_NR_NETWORK_REQUEST: u64 = 15;

    /// Reserved by #110 for M10; the kernel dispatcher returns `SYSCALL_ENOSYS` until the owning
    /// issue implements each number (#195, service-port issue, #111/#114, #113, service-port issue).
    pub const SYSCALL_NR_SHARED_BUFFER: u64 = 16;
    pub const SYSCALL_NR_SERVICE_PORT: u64 = 17;
    pub const SYSCALL_NR_DISPLAY: u64 = 18;
    pub const SYSCALL_NR_INPUT: u64 = 19;
    pub const SYSCALL_NR_WORK_SET: u64 = 20;

    /// Best-effort inverse of `CapabilityError::syscall_status` (lossy: many errors share a status).
    pub fn error_from_status(status: u64) -> Option<CapabilityError> {
        if status == SYSCALL_EINVAL {
            Some(CapabilityError::InvalidHandle)
        } else if status == SYSCALL_ESTALE {
            Some(CapabilityError::StaleHandle)
        } else if status == SYSCALL_EACCES {
            Some(CapabilityError::UnauthorizedHolder)
        } else if status == SYSCALL_ENOSPC {
            Some(CapabilityError::CapacityExhausted)
        } else {
            None
        }
    }
}
