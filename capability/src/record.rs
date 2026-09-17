//! Canonical capability table record (pure data).

use crate::holder::HolderId;
use crate::provenance::Provenance;
use crate::resource::{ResourceClass, ResourceRef};
use crate::rights::Rights;
use crate::state::CapabilityState;

/// One slot in the M6.2 capability table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityRecord {
    pub state: CapabilityState,
    pub holder: HolderId,
    pub resource: ResourceRef,
    pub rights: Rights,
    pub provenance: Provenance,
    pub generation: u32,
}

impl CapabilityRecord {
    pub const EMPTY: Self = Self {
        state: CapabilityState::Empty,
        holder: HolderId(0),
        resource: ResourceRef {
            class: ResourceClass::PersistentObject,
            id: 0,
            instance_generation: 0,
        },
        rights: Rights::empty(),
        provenance: Provenance {
            parent: None,
            depth: 0,
            root_holder: HolderId(0),
        },
        generation: 0,
    };
}
