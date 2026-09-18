//! Delegation provenance for subtree revocation.

use crate::error::CapabilityError;
use crate::handle::{CapabilityHandle, MAX_DELEGATION_DEPTH};
use crate::holder::HolderId;

/// Delegation chain metadata stored in each live capability record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Provenance {
    pub parent: Option<CapabilityHandle>,
    /// `0` for the root grant; increases by one per delegation hop.
    pub depth: u8,
    pub root_holder: HolderId,
}

impl Provenance {
    pub const fn root(holder: HolderId) -> Self {
        Self {
            parent: None,
            depth: 0,
            root_holder: holder,
        }
    }

    pub fn child_of(
        parent_handle: CapabilityHandle,
        parent_provenance: &Provenance,
    ) -> Result<Self, CapabilityError> {
        let new_depth = parent_provenance
            .depth
            .checked_add(1)
            .ok_or(CapabilityError::DelegationDepthExceeded)?;
        if new_depth > MAX_DELEGATION_DEPTH {
            return Err(CapabilityError::DelegationDepthExceeded);
        }
        Ok(Self {
            parent: Some(parent_handle),
            depth: new_depth,
            root_holder: parent_provenance.root_holder,
        })
    }
}
