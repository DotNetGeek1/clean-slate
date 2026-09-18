//! Pure authorization checks (no table mutation).

use crate::error::CapabilityError;
use crate::handle::CapabilityHandle;
use crate::holder::HolderId;
use crate::record::CapabilityRecord;
use crate::resource::ResourceRef;
use crate::rights::Rights;
use crate::state::CapabilityState;

/// Authorizes an operation against a single capability record.
///
/// Check order (first failure wins):
/// 1. `Empty` → `InvalidHandle`
/// 2. `Retired` → `StaleHandle`
/// 3. handle generation mismatch → `StaleHandle`
/// 4. `Revoked` → `Revoked`
/// 5. holder mismatch → `UnauthorizedHolder`
/// 6. resource mismatch (class, id, or instance_generation) → `WrongResource`
/// 7. missing required rights → `MissingRight`
pub fn authorize(
    record: &CapabilityRecord,
    handle: CapabilityHandle,
    holder: HolderId,
    resource: ResourceRef,
    required: Rights,
) -> Result<(), CapabilityError> {
    if record.state == CapabilityState::Empty {
        return Err(CapabilityError::InvalidHandle);
    }
    if record.state == CapabilityState::Retired {
        return Err(CapabilityError::StaleHandle);
    }
    if record.generation != handle.generation {
        return Err(CapabilityError::StaleHandle);
    }
    if record.state == CapabilityState::Revoked {
        return Err(CapabilityError::Revoked);
    }
    if record.holder != holder {
        return Err(CapabilityError::UnauthorizedHolder);
    }
    if record.resource != resource {
        return Err(CapabilityError::WrongResource);
    }
    if !record.rights.contains(required) {
        return Err(CapabilityError::MissingRight);
    }
    Ok(())
}

/// Validates a delegation request against a parent capability.
///
/// Authorizes the parent for [`Rights::DELEGATE`] first (same precedence as [`authorize`]).
/// Then rejects rights widening and class-invalid bits. Returns the effective child rights
/// (the requested subset).
///
/// When the parent lacks `DELEGATE`, this returns [`CapabilityError::MissingRight`].
/// [`CapabilityError::NotDelegable`] is the documented protocol alias for the same condition
/// in higher-level messages; new kernel code should prefer `MissingRight` from this function.
pub fn validate_delegation(
    parent: &CapabilityRecord,
    parent_handle: CapabilityHandle,
    source_holder: HolderId,
    requested: Rights,
) -> Result<Rights, CapabilityError> {
    authorize(
        parent,
        parent_handle,
        source_holder,
        parent.resource,
        Rights::DELEGATE,
    )?;
    if !requested.is_subset_of(parent.rights) {
        return Err(CapabilityError::RightsWidening);
    }
    if !requested.is_subset_of(Rights::valid_for(parent.resource.class)) {
        return Err(CapabilityError::InvalidRights);
    }
    Ok(requested)
}
