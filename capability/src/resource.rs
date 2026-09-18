//! Stable resource identity (separate from capability handles).

/// Kind of protected resource referenced by a capability.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResourceClass {
    PersistentObject = 1,
    ProcessControl = 2,
    IpcEndpoint = 3,
    BlockDevice = 4,
    LifecycleControl = 5,
    Audit = 6,
    Network = 7,
}

impl ResourceClass {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::PersistentObject),
            2 => Some(Self::ProcessControl),
            3 => Some(Self::IpcEndpoint),
            4 => Some(Self::BlockDevice),
            5 => Some(Self::LifecycleControl),
            6 => Some(Self::Audit),
            7 => Some(Self::Network),
            _ => None,
        }
    }
}

/// Stable resource key bound by a capability (independent of handle slot/generation).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResourceRef {
    pub class: ResourceClass,
    pub id: u64,
    /// `0` for classes without instances; process/service generation for `ProcessControl`.
    pub instance_generation: u64,
}

impl ResourceRef {
    pub const fn object(id: u64) -> Self {
        Self {
            class: ResourceClass::PersistentObject,
            id,
            instance_generation: 0,
        }
    }

    pub const fn process(pid: u64, instance_generation: u64) -> Self {
        Self {
            class: ResourceClass::ProcessControl,
            id: pid,
            instance_generation,
        }
    }

    pub const fn network(service_id: u64, instance_generation: u64) -> Self {
        Self {
            class: ResourceClass::Network,
            id: service_id,
            instance_generation,
        }
    }

    /// Per-session network resource: `id` is the session index within `session_generation`.
    pub const fn network_session(session_generation: u64, session_index: u32) -> Self {
        Self {
            class: ResourceClass::Network,
            id: session_index as u64,
            instance_generation: session_generation,
        }
    }
}
