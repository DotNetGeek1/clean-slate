//! M6.2 production capability-space substrate (global table + trusted identity helpers).
//!
//! Lane-owned submodules (one per M6 issue; each owns exactly its file):
//! `object` (M6.3), `process_control` (M6.4), `delegation` (M6.5), `revocation` (M6.6),
//! `audit` (M6.7). Syscall dispatch arms for them live in `syscall/mod.rs`.

pub(crate) mod audit;
#[cfg(test)]
mod audit_coverage;
pub(crate) mod bootstrap_grant;
pub(crate) mod delegation;
pub(crate) mod display;
#[cfg(any(test, clean_slate_desktop))]
pub(crate) mod graphics;
#[cfg(any(test, feature = "m10-input-self-test", clean_slate_desktop))]
pub(crate) mod input;
pub(crate) mod network;
pub(crate) mod object;
pub(crate) mod process_control;
pub(crate) mod revocation;

use core::fmt::{self, Write};

use clean_slate_capability::{
    list_holder, release_revoked, revoke_holder_tree_visiting, revoke_resource_tree, AuditEvent,
    AuditKind, CapabilityError, CapabilityHandle, CapabilityRecord, CapabilityTable, HolderId,
    Provenance, ResourceClass, ResourceRef, Rights, MAX_SLOTS,
};

use crate::mm::shared_buffer::{reconcile_resource, RevokedBuffers};
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

/// Live capability records across all holders.
#[cfg(any(
    feature = "m9-userspace-self-test",
    feature = "m10-port-self-test",
    feature = "m10-shared-buffer-self-test",
    clean_slate_desktop_snapshot
))]
pub(crate) fn live_capability_count() -> usize {
    with_capability_space(|table| {
        (0..table.capacity())
            .filter(|slot| table.state_at(*slot) == clean_slate_capability::CapabilityState::Live)
            .count()
    })
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
    let result = match table.grant(holder, resource, rights, provenance) {
        Ok(handle) => Ok(handle),
        Err(CapabilityError::CapacityExhausted) => {
            let _ = release_revoked(table);
            table.grant(holder, resource, rights, provenance)
        }
        Err(error) => Err(error),
    };
    audit::record(
        AuditEvent::new(AuditKind::Grant, HolderId::KERNEL, resource, rights)
            .with_subject(holder)
            .with_handle(*result.as_ref().unwrap_or(&CapabilityHandle::INVALID))
            .with_result(result.map(|_| ())),
    );
    result
}

pub(crate) fn revoke_for_holder(holder: HolderId) -> usize {
    let mut revoked_buffers = RevokedBuffers::default();
    let revoked =
        revoke_holder_tree_visiting(unsafe { capability_space_mut() }, holder, |resource| {
            revoked_buffers.note(resource)
        });
    revoked_buffers.reconcile();
    unsafe { capability_space_mut() }.clear_slot_allowance(holder);
    if revoked > 0 {
        // Names the process whose whole capability tree went, not one of its resources.
        audit::record_kernel_revoke(holder, ResourceRef::process(holder.0, 0), revoked);
    }
    revoked
}

/// Gives the instance `holder` of a manifest row the row's slot allowance. Only the service
/// launch path calls this, before the row's grants; [`revoke_for_holder`] (teardown) clears it.
pub(crate) fn set_slot_allowance(
    holder: HolderId,
    allowance: usize,
) -> Result<(), CapabilityError> {
    unsafe { capability_space_mut() }.set_slot_allowance(holder, allowance)
}

/// Returns whether `holder` holds any live capability for `resource` with `required` rights.
pub(crate) fn holder_has_resource_rights(
    holder: HolderId,
    resource: ResourceRef,
    required: Rights,
) -> bool {
    let found = with_capability_space(|table| {
        let mut cursor = 0usize;
        loop {
            let (next_cursor, handle, record) = list_holder(table, holder, cursor)?;
            cursor = next_cursor;
            if table.authorize(holder, handle, resource, required).is_ok() {
                return Some((handle, record.provenance.depth));
            }
        }
    });
    let (handle, depth) = found.unwrap_or((CapabilityHandle::INVALID, 0));
    audit::record_decision(
        holder,
        resource,
        required,
        handle,
        depth,
        found.map(|_| ()).ok_or(CapabilityError::MissingRight),
    );
    found.is_some()
}

/// Duplicates every live capability held by `parent` onto `child` for Linux `fork(2)`.
///
/// Unlike userspace [`clean_slate_capability::delegate`], this kernel-only path does not
/// require `Rights::DELEGATE` on the parent caps — fork is not a delegation syscall. A record
/// with root-only rights ([`clean_slate_capability::fork_inheritable`]) is withheld, with a
/// `NotDelegable` record per withheld capability.
#[cfg(clean_slate_linux_proc)]
pub(crate) fn inherit_capabilities_for_fork(
    parent: HolderId,
    child: HolderId,
) -> Result<(), CapabilityError> {
    let result = copy_capabilities_for_fork(parent, child);
    let inherited = result.as_ref().copied().unwrap_or_default();
    let result = result.map(|_| ());
    audit::record(
        AuditEvent::new(
            AuditKind::Inherit,
            parent,
            ResourceRef::process(child.0, 0),
            Rights::empty(),
        )
        .with_subject(child)
        .with_count(inherited)
        .with_result(result),
    );
    result
}

/// Returns how many capabilities `child` received; on error none remain installed.
#[cfg(clean_slate_linux_proc)]
fn copy_capabilities_for_fork(parent: HolderId, child: HolderId) -> Result<usize, CapabilityError> {
    let mut cursor = 0usize;
    let mut installed = [None; MAX_SLOTS];
    let mut count = 0usize;
    loop {
        let table = unsafe { capability_space_mut() };
        let Some((next_cursor, handle, record)) = list_holder(table, parent, cursor) else {
            break;
        };
        cursor = next_cursor;
        if !clean_slate_capability::fork_inheritable(&record) {
            audit::record(
                AuditEvent::new(AuditKind::Inherit, parent, record.resource, record.rights)
                    .with_subject(child)
                    .with_handle(handle)
                    .with_result(Err(CapabilityError::NotDelegable)),
            );
            continue;
        }
        let provenance = match Provenance::child_of(handle, &record.provenance) {
            Ok(provenance) => provenance,
            Err(error) => {
                rollback_fork_inherited(&installed[..count]);
                return Err(error);
            }
        };
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
    Ok(count)
}

/// Revokes and releases the copies a failed fork installed, so the table and the child's
/// quota charge are as they were before the fork (#212).
#[cfg(clean_slate_linux_proc)]
fn rollback_fork_inherited(handles: &[Option<CapabilityHandle>]) {
    let table = unsafe { capability_space_mut() };
    for handle in handles.iter().flatten() {
        if table.revoke(*handle).is_ok() {
            table.release_slot(usize::from(handle.slot));
        }
    }
}

pub(crate) fn revoke_for_resource(resource: ResourceRef) -> usize {
    let revoked = revoke_resource_tree(
        unsafe { capability_space_mut() },
        resource.class,
        resource.id,
    );
    reconcile_resource(resource);
    if revoked > 0 {
        audit::record_kernel_revoke(HolderId::KERNEL, resource, revoked);
    }
    revoked
}

/// Revokes `ProcessControl` capabilities only, which never name a shared buffer, so
/// there is nothing to reconcile.
pub(crate) fn revoke_for_process_resource(process_id: u64) -> usize {
    let revoked = revoke_resource_tree(
        unsafe { capability_space_mut() },
        ResourceClass::ProcessControl,
        process_id,
    );
    if revoked > 0 {
        audit::record_kernel_revoke(
            HolderId::KERNEL,
            ResourceRef::process(process_id, 0),
            revoked,
        );
    }
    revoked
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_capability::{CapabilityTable, HOLDER_SLOT_QUOTA};

    #[cfg(clean_slate_linux_proc)]
    fn grant_objects(holder: HolderId, first_id: u64, count: u64) {
        for id in first_id..first_id + count {
            grant_root(holder, ResourceRef::object(id), Rights::READ).expect("grant");
        }
    }

    #[cfg(clean_slate_linux_proc)]
    fn charge_of(holder: HolderId) -> (usize, usize) {
        with_capability_space(|table| (table.charged_to(holder), table.revoked_held_by(holder)))
    }

    #[cfg(clean_slate_linux_proc)]
    #[test]
    fn a_fork_child_is_charged_for_what_it_inherits() {
        let (parent, child) = (HolderId(0x7a01), HolderId(0x7a02));
        grant_objects(parent, 0x7a00, 10);
        assert_eq!(inherit_capabilities_for_fork(parent, child), Ok(()));
        assert_eq!(charge_of(child), (10, 0));
        assert_eq!(charge_of(parent), (10, 0));
        revoke_for_holder(parent);
        revoke_for_holder(child);
        assert_eq!((charge_of(parent), charge_of(child)), ((0, 0), (0, 0)));
    }

    #[cfg(clean_slate_linux_proc)]
    #[test]
    fn a_fork_over_the_child_quota_is_refused_and_releases_what_it_installed() {
        let (parent, child) = (HolderId(0x7b01), HolderId(0x7b02));
        grant_objects(parent, 0x7b00, 10);
        grant_objects(child, 0x7c00, 10);
        assert_eq!(
            inherit_capabilities_for_fork(parent, child),
            Err(CapabilityError::QuotaExceeded)
        );
        assert_eq!(
            charge_of(child),
            (10, 0),
            "the six copies installed before the refusal must be released, not only revoked"
        );
        revoke_for_holder(parent);
        revoke_for_holder(child);
    }

    #[test]
    fn one_holder_cannot_take_more_than_its_quota_of_the_global_table() {
        let holder = HolderId(0x7d01);
        let mut granted = 0;
        let refusal = loop {
            match grant_root(holder, ResourceRef::object(0x7d00), Rights::READ) {
                Ok(_) => granted += 1,
                Err(error) => break error,
            }
        };
        assert_eq!(
            (granted, refusal),
            (HOLDER_SLOT_QUOTA, CapabilityError::QuotaExceeded)
        );
        assert_eq!(revoke_for_holder(holder), HOLDER_SLOT_QUOTA);
    }

    #[test]
    fn a_slot_allowance_lasts_until_teardown() {
        let holder = HolderId(0x7e01);
        assert_eq!(set_slot_allowance(holder, 24), Ok(()));
        let mut granted = 0;
        while grant_root(holder, ResourceRef::object(0x7e00), Rights::READ).is_ok() {
            granted += 1;
        }
        assert_eq!(granted, 24);
        assert_eq!(revoke_for_holder(holder), 24);
        assert_eq!(
            with_capability_space(|table| table.slot_allowance(holder)),
            None,
            "teardown returns the pid to the default quota"
        );
        assert_eq!(
            set_slot_allowance(holder, clean_slate_capability::MAX_SLOT_ALLOWANCE + 1),
            Err(CapabilityError::QuotaExceeded)
        );
    }

    #[cfg(clean_slate_linux_proc)]
    #[test]
    fn a_fork_child_does_not_inherit_its_parents_slot_allowance() {
        let (parent, child) = (HolderId(0x7f01), HolderId(0x7f02));
        assert_eq!(set_slot_allowance(parent, 24), Ok(()));
        grant_objects(parent, 0x7f00, 20);
        assert_eq!(
            inherit_capabilities_for_fork(parent, child),
            Err(CapabilityError::QuotaExceeded)
        );
        assert_eq!(charge_of(child), (0, 0));
        assert_eq!(
            with_capability_space(|table| table.slot_allowance(child)),
            None
        );
        revoke_for_holder(parent);
        revoke_for_holder(child);
    }

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
