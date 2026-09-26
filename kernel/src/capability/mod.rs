//! M6.2 production capability-space substrate (global table + trusted identity helpers).
//!
//! Lane-owned submodules (one per M6 issue; each owns exactly its file):
//! `object` (M6.3), `process_control` (M6.4), `delegation` (M6.5), `revocation` (M6.6),
//! `audit` (M6.7). Syscall dispatch arms for them live in `syscall/mod.rs`.

pub(crate) mod audit;
pub(crate) mod bootstrap_grant;
pub(crate) mod delegation;
pub(crate) mod network;
pub(crate) mod object;
pub(crate) mod process_control;
pub(crate) mod revocation;

use core::fmt::{self, Write};

use clean_slate_capability::{
    list_holder, release_revoked, revoke_holder_tree, revoke_resource_tree, CapabilityError,
    CapabilityHandle, CapabilityRecord, CapabilityTable, HolderId, Provenance, ResourceClass,
    ResourceRef, Rights, MAX_SLOTS,
};

use crate::process::current_process_id;
use crate::sync::global_cell::GlobalCell;

/// Scratch buffer for formatting `Rights` name lists into serial logs.
pub(super) struct RightsNameBuf {
    bytes: [u8; 64],
    len: usize,
}

impl RightsNameBuf {
    pub(super) fn format_rights(&mut self, rights: Rights) {
        self.bytes = [0; 64];
        self.len = 0;
        let _ = rights.write_names(self);
    }
}

impl Write for RightsNameBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > self.bytes.len() {
            return Err(fmt::Error);
        }
        self.bytes[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

static CAPABILITY_SPACE: GlobalCell<CapabilityTable<MAX_SLOTS>> =
    GlobalCell::new(CapabilityTable::new());

/// Returns the global capability table for call sites that hold the reference across other calls.
///
/// # Safety
/// The caller must ensure no other live reference to the capability table exists for the
/// lifetime of the returned borrow.
pub(crate) unsafe fn capability_space_mut() -> &'static mut CapabilityTable<MAX_SLOTS> {
    unsafe { &mut *CAPABILITY_SPACE.get() }
}

pub(crate) fn with_capability_space<R>(f: impl FnOnce(&CapabilityTable<MAX_SLOTS>) -> R) -> R {
    f(unsafe { &*CAPABILITY_SPACE.get() })
}

pub(crate) fn current_holder() -> Result<HolderId, &'static str> {
    current_process_id().map(HolderId)
}

fn authorize_decoded<const N: usize>(
    table: &CapabilityTable<N>,
    holder: HolderId,
    raw_handle: u64,
    resource: ResourceRef,
    required: Rights,
) -> Result<CapabilityRecord, CapabilityError> {
    let handle = CapabilityHandle::decode(raw_handle)?;
    table.authorize(holder, handle, resource, required)
}

fn authorize_decoded_class<const N: usize>(
    table: &CapabilityTable<N>,
    holder: HolderId,
    raw_handle: u64,
    class: ResourceClass,
    required: Rights,
) -> Result<CapabilityRecord, CapabilityError> {
    let handle = CapabilityHandle::decode(raw_handle)?;
    table.authorize_class(holder, handle, class, required)
}

/// Authorizes using the current userspace holder and a wire-encoded handle.
#[allow(dead_code)] // M6 syscall and adapter lanes (M6.3+).
pub(crate) fn authorize_current(
    raw_handle: u64,
    resource: ResourceRef,
    required: Rights,
) -> Result<CapabilityRecord, CapabilityError> {
    let holder = match current_holder() {
        Ok(holder) => holder,
        // No trusted actor — skip audit (nothing to attribute).
        Err(_) => return Err(CapabilityError::UnauthorizedHolder),
    };
    let handle = CapabilityHandle::decode(raw_handle).unwrap_or(CapabilityHandle::INVALID);
    let result = with_capability_space(|table| {
        authorize_decoded(table, holder, raw_handle, resource, required)
    });
    let (audit_resource, depth) = match &result {
        Ok(record) => (record.resource, record.provenance.depth),
        Err(_) => (resource, 0),
    };
    audit::record_decision(
        holder,
        audit_resource,
        required,
        handle,
        depth,
        result.map(|_| ()),
    );
    result
}

/// Authorizes a handle against its record resource class and the current holder.
#[allow(dead_code)] // M6 syscall and adapter lanes (M6.3+).
pub(crate) fn authorize_current_class(
    raw_handle: u64,
    class: ResourceClass,
    required: Rights,
) -> Result<CapabilityRecord, CapabilityError> {
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(_) => return Err(CapabilityError::UnauthorizedHolder),
    };
    let handle = CapabilityHandle::decode(raw_handle).unwrap_or(CapabilityHandle::INVALID);
    let result = with_capability_space(|table| {
        authorize_decoded_class(table, holder, raw_handle, class, required)
    });
    let (audit_resource, depth) = match &result {
        Ok(record) => (record.resource, record.provenance.depth),
        Err(_) => (
            ResourceRef {
                class,
                id: 0,
                instance_generation: 0,
            },
            0,
        ),
    };
    audit::record_decision(
        holder,
        audit_resource,
        required,
        handle,
        depth,
        result.map(|_| ()),
    );
    result
}

/// Installs a kernel root grant into the global capability table.
#[allow(dead_code)] // M6 syscall and adapter lanes (M6.3+).
pub(crate) fn grant_root(
    holder: HolderId,
    resource: ResourceRef,
    rights: Rights,
) -> Result<CapabilityHandle, CapabilityError> {
    let table = unsafe { capability_space_mut() };
    let provenance = Provenance::root(holder);
    match table.grant(holder, resource, rights, provenance) {
        Ok(handle) => Ok(handle),
        Err(CapabilityError::CapacityExhausted) => {
            let _ = release_revoked(table);
            table.grant(holder, resource, rights, provenance)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn revoke_for_holder(holder: HolderId) -> usize {
    revoke_holder_tree(unsafe { capability_space_mut() }, holder)
}

/// Duplicates every live capability held by `parent` onto `child` for Linux `fork(2)`.
///
/// Unlike userspace [`clean_slate_capability::delegate`], this kernel-only path does not
/// require `Rights::DELEGATE` on the parent caps — fork is not a delegation syscall.
/// Returns whether `holder` holds any live capability for `resource` with `required` rights.
pub(crate) fn holder_has_resource_rights(
    holder: HolderId,
    resource: ResourceRef,
    required: Rights,
) -> bool {
    with_capability_space(|table| {
        let mut cursor = 0usize;
        loop {
            let Some((next_cursor, handle, _record)) = list_holder(table, holder, cursor) else {
                return false;
            };
            cursor = next_cursor;
            if table.authorize(holder, handle, resource, required).is_ok() {
                return true;
            }
        }
    })
}

#[cfg(feature = "m8-linux-image")]
pub(crate) fn inherit_capabilities_for_fork(
    parent: HolderId,
    child: HolderId,
) -> Result<(), CapabilityError> {
    let mut cursor = 0usize;
    let mut installed = [None; MAX_SLOTS];
    let mut count = 0usize;
    loop {
        let table = unsafe { capability_space_mut() };
        let Some((next_cursor, handle, record)) = list_holder(table, parent, cursor) else {
            break;
        };
        cursor = next_cursor;
        let provenance = Provenance::child_of(handle, &record.provenance)?;
        let child_record = CapabilityRecord {
            state: clean_slate_capability::CapabilityState::Live,
            holder: child,
            resource: record.resource,
            rights: record.rights,
            provenance,
            generation: 0,
        };
        if count >= MAX_SLOTS {
            rollback_fork_inherited(&installed[..count]);
            return Err(CapabilityError::CapacityExhausted);
        }
        match table.install(child_record) {
            Ok(child_handle) => {
                installed[count] = Some(child_handle);
                count += 1;
            }
            Err(error) => {
                rollback_fork_inherited(&installed[..count]);
                return Err(error);
            }
        }
    }
    Ok(())
}

#[cfg(feature = "m8-linux-image")]
fn rollback_fork_inherited(handles: &[Option<CapabilityHandle>]) {
    let table = unsafe { capability_space_mut() };
    for handle in handles.iter().flatten() {
        let _ = table.revoke(*handle);
    }
}

#[allow(dead_code)] // M6 adapters revoke exact ResourceRef (M6.3+).
pub(crate) fn revoke_for_resource(resource: ResourceRef) -> usize {
    revoke_resource_tree(
        unsafe { capability_space_mut() },
        resource.class,
        resource.id,
    )
}

pub(crate) fn revoke_for_process_resource(process_id: u64) -> usize {
    revoke_resource_tree(
        unsafe { capability_space_mut() },
        ResourceClass::ProcessControl,
        process_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_capability::CapabilityTable;

    #[test]
    fn authorize_decoded_maps_decode_and_authorize_errors() {
        let mut table = CapabilityTable::<4>::new();
        let holder = HolderId(5);
        let resource = ResourceRef::object(1);
        let handle = table
            .grant(holder, resource, Rights::READ, Provenance::root(holder))
            .expect("grant");

        assert_eq!(
            authorize_decoded(&table, holder, handle.encode(), resource, Rights::READ)
                .expect("ok")
                .holder,
            holder
        );
        assert_eq!(
            authorize_decoded(
                &table,
                holder,
                0xffff_0000_0000_0001,
                resource,
                Rights::READ
            ),
            Err(CapabilityError::InvalidHandle)
        );
        assert_eq!(
            authorize_decoded(
                &table,
                HolderId(99),
                handle.encode(),
                resource,
                Rights::READ,
            ),
            Err(CapabilityError::UnauthorizedHolder)
        );
        assert_eq!(
            authorize_decoded_class(
                &table,
                holder,
                handle.encode(),
                ResourceClass::BlockDevice,
                Rights::READ,
            ),
            Err(CapabilityError::WrongResource)
        );
    }
}
