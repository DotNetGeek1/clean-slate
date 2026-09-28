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
    SharedBuffer = 8,
    Graphics = 9,
    Display = 10,
    Input = 11,
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
            8 => Some(Self::SharedBuffer),
            9 => Some(Self::Graphics),
            10 => Some(Self::Display),
            11 => Some(Self::Input),
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

    pub const fn ipc_endpoint(endpoint_slot: u64) -> Self {
        Self {
            class: ResourceClass::IpcEndpoint,
            id: endpoint_slot,
            instance_generation: 0,
        }
    }

    /// `id` is the full [`SharedBufferId`] wire encoding (slot and generation in `id` because
    /// `revoke_resource_id` matches class+id and ignores `instance_generation`).
    pub const fn shared_buffer(shared_buffer_id_raw: u64) -> Self {
        Self {
            class: ResourceClass::SharedBuffer,
            id: shared_buffer_id_raw,
            instance_generation: 0,
        }
    }

    /// Compositor port resource: `id` is the service id; `instance_generation` is the live
    /// compositor instance (stale after restart, mirroring [`Self::network`]).
    pub const fn graphics(service_id: u64, instance_generation: u64) -> Self {
        Self {
            class: ResourceClass::Graphics,
            id: service_id,
            instance_generation,
        }
    }

    /// `id` is the packed `clean_slate_graphics::OutputId` encoding (index bits 0..8, backend
    /// epoch bits 8..32), validated by the caller; epoch lives in `id` because
    /// `revoke_resource_id` ignores `instance_generation`.
    pub const fn display(output_id_raw: u32) -> Self {
        Self {
            class: ResourceClass::Display,
            id: output_id_raw as u64,
            instance_generation: 0,
        }
    }

    /// Input seat resource: `id` is the seat index; `instance_generation` is always `0`.
    pub const fn input(seat: u64) -> Self {
        Self {
            class: ResourceClass::Input,
            id: seat,
            instance_generation: 0,
        }
    }
}
