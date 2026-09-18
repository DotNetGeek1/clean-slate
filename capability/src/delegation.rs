//! M6.5 generic delegation and attenuation over [`CapabilityTable`].

use crate::authorize::validate_delegation;
use crate::error::CapabilityError;
use crate::handle::CapabilityHandle;
use crate::holder::HolderId;
use crate::provenance::Provenance;
use crate::record::CapabilityRecord;
use crate::rights::Rights;
use crate::state::CapabilityState;
use crate::table::CapabilityTable;

/// Delegates an attenuated child of `parent` (held by `source`) to `target`.
///
/// Every check precedes the single mutating [`CapabilityTable::install`] call.
pub fn delegate<const N: usize>(
    table: &mut CapabilityTable<N>,
    source: HolderId,
    parent: CapabilityHandle,
    target: HolderId,
    rights: Rights,
) -> Result<CapabilityHandle, CapabilityError> {
    let record = table.record(parent)?;
    let rights = validate_delegation(&record, parent, source, rights)?;
    if target == HolderId::KERNEL {
        return Err(CapabilityError::InvalidRights);
    }
    let provenance = Provenance::child_of(parent, &record.provenance)?;
    let child = CapabilityRecord {
        state: CapabilityState::Live,
        holder: target,
        resource: record.resource,
        rights,
        provenance,
        generation: 0,
    };
    table.install(child)
}

/// Cursor-based listing of live capabilities held by `holder` (slot order).
pub fn list_holder<const N: usize>(
    table: &CapabilityTable<N>,
    holder: HolderId,
    cursor: usize,
) -> Option<(usize, CapabilityHandle, CapabilityRecord)> {
    if cursor >= N {
        return None;
    }
    for slot in cursor..N {
        let record = table.record_at(slot);
        if record.state != CapabilityState::Live || record.holder != holder {
            continue;
        }
        let handle = table
            .handle_at(slot)
            .expect("live slot must expose a handle");
        return Some((slot + 1, handle, *record));
    }
    None
}

/// Delegation chain depth for `handle` (`0` = root grant).
pub fn delegation_depth<const N: usize>(
    table: &CapabilityTable<N>,
    handle: CapabilityHandle,
) -> Result<u8, CapabilityError> {
    Ok(table.record(handle)?.provenance.depth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::ResourceRef;

    const SOURCE: HolderId = HolderId(10);
    const TARGET: HolderId = HolderId(20);
    const OTHER: HolderId = HolderId(30);
    const OBJ: ResourceRef = ResourceRef::object(42);

    fn grant_delegate(
        table: &mut CapabilityTable<8>,
        holder: HolderId,
        rights: Rights,
    ) -> CapabilityHandle {
        table
            .grant(holder, OBJ, rights, Provenance::root(holder))
            .expect("grant")
    }

    #[test]
    fn attenuation_succeeds_and_child_authorizes_read_not_write() {
        let mut table = CapabilityTable::<8>::new();
        let parent = grant_delegate(
            &mut table,
            SOURCE,
            Rights::READ.union(Rights::WRITE).union(Rights::DELEGATE),
        );
        let child =
            delegate(&mut table, SOURCE, parent, TARGET, Rights::READ).expect("delegate read");
        assert_eq!(table.live_count(), 2);
        assert!(table.authorize(TARGET, child, OBJ, Rights::READ).is_ok());
        assert_eq!(
            table.authorize(TARGET, child, OBJ, Rights::WRITE),
            Err(CapabilityError::MissingRight)
        );
    }

    #[test]
    fn widening_rejected_without_table_growth() {
        let mut table = CapabilityTable::<8>::new();
        let parent = grant_delegate(&mut table, SOURCE, Rights::READ.union(Rights::DELEGATE));
        assert_eq!(
            delegate(&mut table, SOURCE, parent, TARGET, Rights::WRITE),
            Err(CapabilityError::RightsWidening)
        );
        assert_eq!(table.live_count(), 1);
    }

    #[test]
    fn depth_exceeded_at_fifth_hop_exactly() {
        let mut table = CapabilityTable::<8>::new();
        let mut holder = SOURCE;
        let mut parent = grant_delegate(&mut table, holder, Rights::READ.union(Rights::DELEGATE));
        let mut depth_errors = 0usize;
        for hop in 1usize..=5usize {
            let next = HolderId(holder.0 + hop as u64);
            match delegate(
                &mut table,
                holder,
                parent,
                next,
                Rights::READ.union(Rights::DELEGATE),
            ) {
                Ok(child) => {
                    assert_eq!(hop, usize::from(delegation_depth(&table, child).unwrap()));
                    holder = next;
                    parent = child;
                }
                Err(CapabilityError::DelegationDepthExceeded) => {
                    depth_errors += 1;
                    assert_eq!(hop, 5);
                }
                other => panic!("unexpected result at hop {hop}: {other:?}"),
            }
        }
        assert_eq!(depth_errors, 1);
        assert_eq!(table.live_count(), 5);
    }

    #[test]
    fn stale_revoked_wrong_holder_and_kernel_target_cases() {
        let mut table = CapabilityTable::<8>::new();
        let parent = grant_delegate(&mut table, SOURCE, Rights::READ.union(Rights::DELEGATE));
        assert_eq!(
            delegate(&mut table, OTHER, parent, TARGET, Rights::READ),
            Err(CapabilityError::UnauthorizedHolder)
        );
        assert!(table.revoke(parent).expect("revoke"));
        assert_eq!(
            delegate(&mut table, SOURCE, parent, TARGET, Rights::READ),
            Err(CapabilityError::Revoked)
        );
        assert!(table.release_slot(usize::from(parent.slot)));
        assert_eq!(
            delegate(&mut table, SOURCE, parent, TARGET, Rights::READ),
            Err(CapabilityError::StaleHandle)
        );

        let parent = grant_delegate(&mut table, SOURCE, Rights::READ.union(Rights::DELEGATE));
        let child = delegate(&mut table, SOURCE, parent, TARGET, Rights::READ).expect("child");
        assert_eq!(
            delegate(&mut table, TARGET, child, OTHER, Rights::READ),
            Err(CapabilityError::MissingRight)
        );
        assert_eq!(
            delegate(&mut table, SOURCE, parent, HolderId::KERNEL, Rights::READ),
            Err(CapabilityError::InvalidRights)
        );
        assert_eq!(
            delegate(&mut table, SOURCE, parent, OTHER, Rights::empty()),
            Err(CapabilityError::InvalidRights)
        );
    }

    #[test]
    fn capacity_exhausted_does_not_partially_install() {
        let mut table = CapabilityTable::<8>::new();
        let parent = grant_delegate(&mut table, SOURCE, Rights::READ.union(Rights::DELEGATE));
        for slot in 1..8 {
            grant_delegate(&mut table, HolderId(100 + slot as u64), Rights::READ);
        }
        assert_eq!(table.live_count(), 8);
        assert_eq!(
            delegate(&mut table, SOURCE, parent, TARGET, Rights::READ),
            Err(CapabilityError::CapacityExhausted)
        );
        assert_eq!(table.live_count(), 8);
    }

    #[test]
    fn child_provenance_parent_unchanged_and_distinct_handle() {
        let mut table = CapabilityTable::<8>::new();
        let parent = grant_delegate(
            &mut table,
            SOURCE,
            Rights::READ.union(Rights::WRITE).union(Rights::DELEGATE),
        );
        let before = table.record(parent).expect("parent");
        let child = delegate(
            &mut table,
            SOURCE,
            parent,
            TARGET,
            Rights::READ.union(Rights::DELEGATE),
        )
        .expect("child");
        let after = table.record(parent).expect("parent after");
        assert_eq!(before, after);
        let child_record = table.record(child).expect("child record");
        assert_eq!(child_record.holder, TARGET);
        assert_eq!(child_record.provenance.parent, Some(parent));
        assert_eq!(child_record.provenance.depth, 1);
        assert_eq!(child_record.provenance.root_holder, SOURCE);
        assert_eq!(
            table.authorize(SOURCE, child, OBJ, Rights::READ),
            Err(CapabilityError::UnauthorizedHolder)
        );
    }

    #[test]
    fn list_holder_iterates_live_caps_in_slot_order() {
        let mut table = CapabilityTable::<8>::new();
        let h0 = grant_delegate(&mut table, SOURCE, Rights::READ);
        let h1 = grant_delegate(&mut table, SOURCE, Rights::WRITE);
        grant_delegate(&mut table, TARGET, Rights::READ);
        let mut cursor = 0;
        let mut seen = Vec::new();
        while let Some((next, handle, _record)) = list_holder(&table, SOURCE, cursor) {
            seen.push(handle);
            cursor = next;
        }
        assert_eq!(seen, vec![h0, h1]);
        assert!(list_holder(&table, SOURCE, cursor).is_none());
        assert!(list_holder(&table, SOURCE, 8).is_none());
    }
}
