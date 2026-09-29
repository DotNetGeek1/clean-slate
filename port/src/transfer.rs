//! P2: capability transfer on send (T1–T7).
//!
//! Validation is pure. Installing the child is the last fallible step of a SEND, and the only
//! table effect a failed SEND can have is T6 reclamation of `Revoked` slots.

use clean_slate_capability::{
    release_revoked, validate_delegation, CapabilityError, CapabilityHandle, CapabilityRecord,
    CapabilityState, CapabilityTable, HolderId, Provenance, ResourceClass, Rights,
};
use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_EINVAL, STATUS_ENOSPC};
use clean_slate_native_abi::{SharedBufferId, TransferredCap};

use crate::effects::Effects;
use crate::PortError;

/// A capability offered with a SEND, and the verdict of the shared-buffer attestation (M10 W6,
/// `shared_buffer::attest_for_transfer(holder, handle)`, owned by #195).
///
/// The attestation reads the capability table itself, so the caller evaluates it before lending
/// the table to the engine. It is pure; the engine applies it at T4, after T1–T3, so the check
/// order does not depend on when it ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub handle: CapabilityHandle,
    /// `(id, byte_len)` of the live buffer, or a native status.
    pub attestation: Result<(SharedBufferId, u64), u64>,
}

/// Children never carry `WRITE` or `DELEGATE`.
pub(crate) const TRANSFER_CHILD_RIGHTS: Rights = Rights::READ;

#[derive(Clone, Copy, Debug)]
pub(crate) struct ValidatedTransfer {
    parent: CapabilityRecord,
    provenance: Provenance,
    buffer: SharedBufferId,
    byte_len: u64,
}

pub(crate) fn capability_error(error: CapabilityError) -> PortError {
    match error {
        CapabilityError::InvalidHandle | CapabilityError::InvalidRights => PortError::Invalid,
        CapabilityError::StaleHandle | CapabilityError::Revoked => PortError::Stale,
        CapabilityError::UnauthorizedHolder
        | CapabilityError::WrongResource
        | CapabilityError::MissingRight
        | CapabilityError::RightsWidening
        | CapabilityError::NotDelegable => PortError::Denied,
        CapabilityError::DelegationDepthExceeded
        | CapabilityError::CapacityExhausted
        | CapabilityError::GenerationExhausted => PortError::NoSpace,
    }
}

fn attestation_error(status: u64) -> PortError {
    match status {
        STATUS_EINVAL => PortError::Invalid,
        STATUS_EACCES => PortError::Denied,
        STATUS_ENOSPC => PortError::NoSpace,
        _ => PortError::Stale,
    }
}

/// T1–T5; mutates nothing.
pub(crate) fn validate<const N: usize>(
    table: &CapabilityTable<N>,
    sender: HolderId,
    transfer: &Transfer,
) -> Result<ValidatedTransfer, PortError> {
    let handle = transfer.handle;
    let parent = table.record(handle).map_err(capability_error)?;
    if parent.holder != sender || parent.resource.class != ResourceClass::SharedBuffer {
        return Err(PortError::Denied);
    }
    validate_delegation(&parent, handle, sender, TRANSFER_CHILD_RIGHTS)
        .map_err(capability_error)?;
    let buffer = SharedBufferId::decode(parent.resource.id).map_err(|_| PortError::Invalid)?;
    let (attested, byte_len) = transfer.attestation.map_err(attestation_error)?;
    if attested != buffer {
        return Err(PortError::Stale);
    }
    let provenance = Provenance::child_of(handle, &parent.provenance).map_err(capability_error)?;
    Ok(ValidatedTransfer {
        parent,
        provenance,
        buffer,
        byte_len,
    })
}

/// A slot `install` can use without retiring anything.
pub(crate) fn has_installable_slot<const N: usize>(table: &CapabilityTable<N>) -> bool {
    (0..N).any(|slot| {
        table.state_at(slot) == CapabilityState::Empty
            && table.record_at(slot).generation != u32::MAX
    })
}

/// T6 and T7: reclaims `Revoked` slots only if the table is full, then installs the child.
pub(crate) fn install_child<const N: usize>(
    table: &mut CapabilityTable<N>,
    server: HolderId,
    transfer: &ValidatedTransfer,
) -> Result<TransferredCap, PortError> {
    if !has_installable_slot(table) {
        release_revoked(table);
        if !has_installable_slot(table) {
            return Err(PortError::NoSpace);
        }
    }
    let child = table
        .install(CapabilityRecord {
            state: CapabilityState::Live,
            holder: server,
            resource: transfer.parent.resource,
            rights: TRANSFER_CHILD_RIGHTS,
            provenance: transfer.provenance,
            generation: 0,
        })
        .map_err(capability_error)?;
    Ok(TransferredCap {
        handle: child.encode(),
        buffer_id: transfer.buffer.encode(),
        byte_len: transfer.byte_len,
        rights: TRANSFER_CHILD_RIGHTS.bits(),
        class: ResourceClass::SharedBuffer.as_u8(),
    })
}

/// Revokes and releases an undelivered child, but only if the slot still holds that child,
/// and notes its resource in `effects` so the caller reconciles mappings made through it.
pub(crate) fn release_child<const N: usize, B: Copy + PartialEq>(
    table: &mut CapabilityTable<N>,
    child: &TransferredCap,
    effects: &mut Effects<B>,
) {
    let Ok(handle) = CapabilityHandle::decode(child.handle) else {
        return;
    };
    let Ok(record) = table.record(handle) else {
        return;
    };
    let slot = usize::from(handle.slot);
    table.revoke_slot(slot);
    table.release_slot(slot);
    effects.note_revoked(record.resource);
}
