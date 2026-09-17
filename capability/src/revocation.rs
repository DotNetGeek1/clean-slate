//! M6.6 subtree/holder/resource revocation over `CapabilityTable` (host-testable).

use crate::error::CapabilityError;
use crate::handle::{CapabilityHandle, MAX_DELEGATION_DEPTH};
use crate::holder::HolderId;
use crate::resource::ResourceClass;
use crate::state::CapabilityState;
use crate::table::CapabilityTable;

/// Revokes `handle` and every descendant (records whose provenance.parent chain reaches
/// `handle`). Returns number of records newly revoked (0 if already revoked -> idempotent).
/// Err(InvalidHandle|StaleHandle) if handle does not resolve. Does NOT release slots (so old
/// handles report `Revoked`); call `release_revoked` to reclaim capacity.
#[allow(clippy::needless_range_loop)] // slot indices align with table slots and `in_set`.
pub fn revoke_subtree<const N: usize>(
    table: &mut CapabilityTable<N>,
    handle: CapabilityHandle,
) -> Result<usize, CapabilityError> {
    let root_slot = slot_for_handle(table, handle)?;
    let mut in_set = [false; N];
    in_set[root_slot] = true;

    let max_passes = usize::from(MAX_DELEGATION_DEPTH) + 1;
    for _ in 0..max_passes {
        let mut added = false;
        for slot in 0..N {
            if in_set[slot] {
                continue;
            }
            let record = table.record_at(slot);
            if record.state != CapabilityState::Live {
                continue;
            }
            let parent_handle = match record.provenance.parent {
                Some(parent_handle) => parent_handle,
                None => continue,
            };
            let parent_slot = slot_for_handle(table, parent_handle)?;
            if in_set[parent_slot] {
                in_set[slot] = true;
                added = true;
            }
        }
        if !added {
            break;
        }
    }

    let mut count = 0usize;
    for slot in 0..N {
        if in_set[slot] && table.revoke_slot(slot) {
            count += 1;
        }
    }
    Ok(count)
}

/// Revokes every live capability held by `holder` together with each one's subtree (descendants
/// may be held by OTHER holders), then releases all slots that were held by `holder` (the holder
/// is gone; nobody can legitimately present them). Descendant slots held by other holders stay
/// `Revoked` (not released) so their holders observe `Revoked`. Returns total newly revoked.
pub fn revoke_holder_tree<const N: usize>(
    table: &mut CapabilityTable<N>,
    holder: HolderId,
) -> usize {
    let mut revoked = 0usize;
    for slot in 0..N {
        let record = table.record_at(slot);
        if record.state != CapabilityState::Live || record.holder != holder {
            continue;
        }
        let handle = table.handle_at(slot).expect("live slot must have a handle");
        revoked += revoke_subtree(table, handle).unwrap_or(0);
    }
    for slot in 0..N {
        let record = table.record_at(slot);
        if record.holder == holder && record.state == CapabilityState::Revoked {
            table.release_slot(slot);
        }
    }
    revoked
}

/// Revokes + releases every capability whose resource matches (class,id) regardless of
/// instance_generation, plus subtrees (descendants share the resource anyway). Returns newly
/// revoked count.
pub fn revoke_resource_tree<const N: usize>(
    table: &mut CapabilityTable<N>,
    class: ResourceClass,
    id: u64,
) -> usize {
    let mut revoked = 0usize;
    for slot in 0..N {
        let record = table.record_at(slot);
        if record.state != CapabilityState::Live {
            continue;
        }
        if record.resource.class != class || record.resource.id != id {
            continue;
        }
        let handle = table.handle_at(slot).expect("live slot must have a handle");
        revoked += revoke_subtree(table, handle).unwrap_or(0);
    }
    for slot in 0..N {
        let record = table.record_at(slot);
        if record.state == CapabilityState::Revoked
            && record.resource.class == class
            && record.resource.id == id
        {
            table.release_slot(slot);
        }
    }
    revoked
}

/// Releases every `Revoked` slot back to the pool. Returns count released.
pub fn release_revoked<const N: usize>(table: &mut CapabilityTable<N>) -> usize {
    let mut count = 0usize;
    for slot in 0..N {
        if table.release_slot(slot) {
            count += 1;
        }
    }
    count
}

/// Whether `actor` may revoke `handle`: actor holds the record itself, OR actor holds an
/// ancestor (walk provenance.parent up to MAX_DELEGATION_DEPTH steps via table.record; a
/// non-resolving ancestor terminates the walk). Err(UnauthorizedHolder) otherwise;
/// Err(InvalidHandle|StaleHandle) if handle does not resolve.
pub fn authorize_revoke<const N: usize>(
    table: &CapabilityTable<N>,
    actor: HolderId,
    handle: CapabilityHandle,
) -> Result<(), CapabilityError> {
    let record = table.record(handle)?;
    if record.holder == actor {
        return Ok(());
    }
    let mut current_parent = record.provenance.parent;
    for _ in 0..MAX_DELEGATION_DEPTH {
        match current_parent {
            None => break,
            Some(parent_handle) => {
                let parent_record = match table.record(parent_handle) {
                    Ok(record) => record,
                    Err(_) => break,
                };
                if parent_record.holder == actor {
                    return Ok(());
                }
                current_parent = parent_record.provenance.parent;
            }
        }
    }
    Err(CapabilityError::UnauthorizedHolder)
}

fn slot_for_handle<const N: usize>(
    table: &CapabilityTable<N>,
    handle: CapabilityHandle,
) -> Result<usize, CapabilityError> {
    let _ = table.record(handle)?;
    Ok(usize::from(handle.slot))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::Provenance;
    use crate::record::CapabilityRecord;
    use crate::resource::ResourceRef;
    use crate::rights::Rights;

    const OWNER: HolderId = HolderId(1);
    const READER: HolderId = HolderId(2);
    const READER2: HolderId = HolderId(3);
    const SIBLING_HOLDER: HolderId = HolderId(4);
    const OTHER: HolderId = HolderId(99);
    const OBJ: ResourceRef = ResourceRef::object(42);
    const OBJ_OTHER: ResourceRef = ResourceRef::object(99);

    fn grant_root<const N: usize>(
        table: &mut CapabilityTable<N>,
        holder: HolderId,
        resource: ResourceRef,
        rights: Rights,
    ) -> CapabilityHandle {
        table
            .grant(holder, resource, rights, Provenance::root(holder))
            .expect("grant")
    }

    fn install_child<const N: usize>(
        table: &mut CapabilityTable<N>,
        parent: CapabilityHandle,
        holder: HolderId,
        rights: Rights,
    ) -> CapabilityHandle {
        let parent_record = table.record(parent).expect("parent");
        let provenance =
            Provenance::child_of(parent, &parent_record.provenance).expect("child provenance");
        let record = CapabilityRecord {
            state: CapabilityState::Live,
            holder,
            resource: parent_record.resource,
            rights,
            provenance,
            generation: 0,
        };
        table.install(record).expect("install")
    }

    #[test]
    fn revoke_subtree_nested_tree() {
        let mut table = CapabilityTable::<8>::new();
        let root = grant_root(&mut table, OWNER, OBJ, Rights::READ.union(Rights::DELEGATE));
        let a = install_child(&mut table, root, READER, Rights::READ);
        let b = install_child(&mut table, a, READER, Rights::READ);
        let c = install_child(&mut table, b, READER2, Rights::READ);
        let s = install_child(&mut table, root, SIBLING_HOLDER, Rights::READ);

        assert_eq!(revoke_subtree(&mut table, a).expect("revoke a"), 3);
        assert_eq!(
            table.state_at(usize::from(a.slot)),
            CapabilityState::Revoked
        );
        assert_eq!(
            table.state_at(usize::from(b.slot)),
            CapabilityState::Revoked
        );
        assert_eq!(
            table.state_at(usize::from(c.slot)),
            CapabilityState::Revoked
        );
        assert_eq!(
            table.state_at(usize::from(root.slot)),
            CapabilityState::Live
        );
        assert_eq!(table.state_at(usize::from(s.slot)), CapabilityState::Live);

        assert!(table.authorize(OWNER, root, OBJ, Rights::READ).is_ok());
        assert!(table
            .authorize(SIBLING_HOLDER, s, OBJ, Rights::READ)
            .is_ok());
        assert_eq!(
            table.authorize(READER, b, OBJ, Rights::READ),
            Err(CapabilityError::Revoked)
        );

        assert_eq!(revoke_subtree(&mut table, a).expect("idempotent"), 0);

        assert_eq!(release_revoked(&mut table), 3);
        assert_eq!(
            table.authorize(READER, b, OBJ, Rights::READ),
            Err(CapabilityError::StaleHandle)
        );

        let new_b = grant_root(&mut table, OTHER, OBJ, Rights::READ);
        assert_eq!(
            table.authorize(READER, b, OBJ, Rights::READ),
            Err(CapabilityError::StaleHandle)
        );
        assert!(table.authorize(OTHER, new_b, OBJ, Rights::READ).is_ok());
    }

    #[test]
    fn revoke_subtree_capacity_restored() {
        let mut table = CapabilityTable::<8>::new();
        let root = grant_root(&mut table, OWNER, OBJ, Rights::READ.union(Rights::DELEGATE));
        let child = install_child(&mut table, root, READER, Rights::READ);
        assert_eq!(table.live_count(), 2);
        assert_eq!(revoke_subtree(&mut table, child).expect("revoke"), 1);
        assert_eq!(table.live_count(), 1);
        assert_eq!(release_revoked(&mut table), 1);
        assert_eq!(table.live_count(), 1);
        let _ = grant_root(&mut table, READER, OBJ_OTHER, Rights::READ);
        assert_eq!(table.live_count(), 2);
        let empty_slots = table.capacity() - table.live_count();
        assert_eq!(empty_slots, table.capacity() - 2);
    }

    #[test]
    fn revoke_holder_tree_cross_holder_subtree() {
        let mut table = CapabilityTable::<16>::new();
        let root = grant_root(&mut table, OWNER, OBJ, Rights::READ.union(Rights::DELEGATE));
        let a = install_child(&mut table, root, READER, Rights::READ);
        let b = install_child(&mut table, a, OTHER, Rights::READ);
        let _c = install_child(&mut table, b, READER2, Rights::READ);
        let s = install_child(&mut table, root, SIBLING_HOLDER, Rights::READ);

        let count = revoke_holder_tree(&mut table, READER);
        assert_eq!(count, 3);
        assert_eq!(table.state_at(usize::from(a.slot)), CapabilityState::Empty);
        assert_eq!(
            table.state_at(usize::from(b.slot)),
            CapabilityState::Revoked
        );
        assert_eq!(
            table.state_at(usize::from(root.slot)),
            CapabilityState::Live
        );
        assert_eq!(table.state_at(usize::from(s.slot)), CapabilityState::Live);
        assert_eq!(
            table.authorize(OTHER, b, OBJ, Rights::READ),
            Err(CapabilityError::Revoked)
        );
    }

    #[test]
    fn revoke_resource_tree_all_instance_generations() {
        let mut table = CapabilityTable::<8>::new();
        let r1 = ResourceRef::process(7, 1);
        let r2 = ResourceRef::process(7, 2);
        let h1 = table
            .grant(OWNER, r1, Rights::OBSERVE, Provenance::root(OWNER))
            .unwrap();
        let h2 = table
            .grant(READER, r2, Rights::OBSERVE, Provenance::root(READER))
            .unwrap();
        let other = grant_root(&mut table, OTHER, OBJ_OTHER, Rights::READ);
        assert_eq!(
            revoke_resource_tree(&mut table, ResourceClass::ProcessControl, 7),
            2
        );
        assert_eq!(table.state_at(usize::from(h1.slot)), CapabilityState::Empty);
        assert_eq!(table.state_at(usize::from(h2.slot)), CapabilityState::Empty);
        assert_eq!(
            table.state_at(usize::from(other.slot)),
            CapabilityState::Live
        );
    }

    #[test]
    fn generation_exhaustion_on_release() {
        let mut table = CapabilityTable::<8>::new();
        let granted = grant_root(&mut table, OWNER, OBJ, Rights::READ);
        let slot = usize::from(granted.slot);
        table.set_generation_for_test(slot, u32::MAX);
        let handle = CapabilityHandle::new(granted.slot, u32::MAX);
        assert_eq!(revoke_subtree(&mut table, handle).expect("revoke"), 1);
        assert!(release_revoked(&mut table) >= 1);
        assert_eq!(table.state_at(slot), CapabilityState::Retired);
        assert_eq!(
            table.authorize(OWNER, handle, OBJ, Rights::READ),
            Err(CapabilityError::StaleHandle)
        );
        assert_eq!(table.state_at(slot), CapabilityState::Retired);
    }

    #[test]
    fn authorize_revoke_cases() {
        let mut table = CapabilityTable::<8>::new();
        let root = grant_root(&mut table, OWNER, OBJ, Rights::READ.union(Rights::DELEGATE));
        let a = install_child(&mut table, root, READER, Rights::READ);
        let b = install_child(&mut table, a, READER2, Rights::READ);
        let s = install_child(&mut table, root, SIBLING_HOLDER, Rights::READ);

        assert!(authorize_revoke(&table, READER, a).is_ok());
        assert!(authorize_revoke(&table, OWNER, a).is_ok());
        assert!(authorize_revoke(&table, OWNER, b).is_ok());
        assert_eq!(
            authorize_revoke(&table, OTHER, b),
            Err(CapabilityError::UnauthorizedHolder)
        );
        assert_eq!(
            authorize_revoke(&table, SIBLING_HOLDER, a),
            Err(CapabilityError::UnauthorizedHolder)
        );
        assert!(authorize_revoke(&table, READER2, b).is_ok());
        assert!(authorize_revoke(&table, OWNER, root).is_ok());
        assert!(authorize_revoke(&table, SIBLING_HOLDER, s).is_ok());
    }

    #[test]
    fn revoke_subtree_stale_and_invalid() {
        let mut table = CapabilityTable::<8>::new();
        let handle = grant_root(&mut table, OWNER, OBJ, Rights::READ);
        assert!(table.revoke(handle).expect("revoke"));
        assert!(table.release_slot(usize::from(handle.slot)));
        assert_eq!(
            revoke_subtree(&mut table, handle),
            Err(CapabilityError::StaleHandle)
        );
        assert_eq!(
            revoke_subtree(&mut table, CapabilityHandle::new(9, 1)),
            Err(CapabilityError::InvalidHandle)
        );
    }
}
