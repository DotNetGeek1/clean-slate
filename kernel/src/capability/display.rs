//! Display capability authorization for syscall 18 (#111, S10).
//!
//! `ResourceRef::display(index)` names the physical output; the backend epoch is checked only on
//! wire `OutputId` values, never here.

use clean_slate_capability::{
    CapabilityError, CapabilityHandle, CapabilityRecord, CapabilityState, CapabilityTable,
    HolderId, ResourceRef, Rights,
};

use super::audit::record_decision;
use super::with_capability_space;

/// `QUERY_MODE` and `PRESENT_STATUS` accept either right (docs/GRAPHICS.md, syscall 18).
pub(crate) const DISPLAY_QUERY_RIGHTS: Rights = Rights::INSPECT.union(Rights::DISPLAY_PRESENT);

/// First live display capability `holder` owns for `output_index`, whatever its rights.
pub(crate) fn find_display_handle_in<const N: usize>(
    table: &CapabilityTable<N>,
    holder: HolderId,
    output_index: u8,
) -> Option<u64> {
    let resource = ResourceRef::display(output_index);
    (0..table.capacity()).find_map(|slot| {
        if table.state_at(slot) != CapabilityState::Live {
            return None;
        }
        let record = table.record_at(slot);
        if record.holder != holder || record.resource != resource {
            return None;
        }
        table.handle_at(slot).map(CapabilityHandle::encode)
    })
}

pub(crate) fn authorize_display_query_in<const N: usize>(
    table: &CapabilityTable<N>,
    holder: HolderId,
    raw_handle: u64,
    output_index: u8,
) -> Result<CapabilityRecord, CapabilityError> {
    let handle = CapabilityHandle::decode(raw_handle)?;
    let record = table.authorize(
        holder,
        handle,
        ResourceRef::display(output_index),
        Rights::empty(),
    )?;
    if !record.rights.intersects(DISPLAY_QUERY_RIGHTS) {
        return Err(CapabilityError::MissingRight);
    }
    Ok(record)
}

/// `MAP_SCANOUT`, `PRESENT` and `BIND_WAKE` require `DISPLAY_PRESENT`; `INSPECT` alone is refused.
pub(crate) fn authorize_display_present_in<const N: usize>(
    table: &CapabilityTable<N>,
    holder: HolderId,
    raw_handle: u64,
    output_index: u8,
) -> Result<CapabilityRecord, CapabilityError> {
    let handle = CapabilityHandle::decode(raw_handle)?;
    table.authorize(
        holder,
        handle,
        ResourceRef::display(output_index),
        Rights::DISPLAY_PRESENT,
    )
}

pub(crate) fn find_display_handle(holder: HolderId, output_index: u8) -> Option<u64> {
    with_capability_space(|table| find_display_handle_in(table, holder, output_index))
}

/// Audited [`authorize_display_query_in`] against the global table.
pub(crate) fn authorize_display_query(
    holder: HolderId,
    raw_handle: u64,
    output_index: u8,
) -> Result<CapabilityRecord, CapabilityError> {
    let result = with_capability_space(|table| {
        authorize_display_query_in(table, holder, raw_handle, output_index)
    });
    let depth = result.as_ref().map_or(0, |record| record.provenance.depth);
    record_decision(
        holder,
        ResourceRef::display(output_index),
        DISPLAY_QUERY_RIGHTS,
        CapabilityHandle::decode(raw_handle).unwrap_or(CapabilityHandle::INVALID),
        depth,
        result.map(|_| ()),
    );
    result
}

/// Audited [`authorize_display_present_in`] against the global table.
pub(crate) fn authorize_display_present(
    holder: HolderId,
    raw_handle: u64,
    output_index: u8,
) -> Result<CapabilityRecord, CapabilityError> {
    let result = with_capability_space(|table| {
        authorize_display_present_in(table, holder, raw_handle, output_index)
    });
    let depth = result.as_ref().map_or(0, |record| record.provenance.depth);
    record_decision(
        holder,
        ResourceRef::display(output_index),
        Rights::DISPLAY_PRESENT,
        CapabilityHandle::decode(raw_handle).unwrap_or(CapabilityHandle::INVALID),
        depth,
        result.map(|_| ()),
    );
    result
}

#[cfg(test)]
mod tests {
    use clean_slate_capability::{
        CapabilityError, CapabilityHandle, CapabilityTable, HolderId, Provenance, ResourceClass,
        ResourceRef, Rights,
    };

    use super::{authorize_display_present_in, authorize_display_query_in, find_display_handle_in};

    const OWNER: HolderId = HolderId(7);
    const OTHER: HolderId = HolderId(8);

    fn grant(
        table: &mut CapabilityTable<8>,
        holder: HolderId,
        resource: ResourceRef,
        rights: Rights,
    ) -> u64 {
        table
            .grant(holder, resource, rights, Provenance::root(holder))
            .expect("grant")
            .encode()
    }

    #[test]
    fn find_returns_the_holders_live_handle_for_that_output_only() {
        let mut table = CapabilityTable::<8>::new();
        grant(&mut table, OTHER, ResourceRef::display(0), Rights::INSPECT);
        grant(&mut table, OWNER, ResourceRef::display(1), Rights::INSPECT);
        grant(
            &mut table,
            OWNER,
            ResourceRef::network(3, 1),
            Rights::valid_for(ResourceClass::Network),
        );
        assert_eq!(find_display_handle_in(&table, OWNER, 0), None);

        let handle = grant(
            &mut table,
            OWNER,
            ResourceRef::display(0),
            Rights::DISPLAY_PRESENT,
        );
        assert_eq!(find_display_handle_in(&table, OWNER, 0), Some(handle));

        table
            .revoke(CapabilityHandle::decode(handle).expect("handle"))
            .expect("revoke");
        assert_eq!(find_display_handle_in(&table, OWNER, 0), None);
    }

    #[test]
    fn either_query_right_authorizes() {
        let mut table = CapabilityTable::<8>::new();
        for rights in [
            Rights::INSPECT,
            Rights::DISPLAY_PRESENT,
            Rights::INSPECT.union(Rights::DISPLAY_PRESENT),
        ] {
            let handle = grant(&mut table, OWNER, ResourceRef::display(0), rights);
            let record = authorize_display_query_in(&table, OWNER, handle, 0).expect("authorized");
            assert_eq!(record.rights, rights);
        }
    }

    #[test]
    fn present_authority_needs_the_present_right() {
        let mut table = CapabilityTable::<8>::new();
        let inspect = grant(&mut table, OWNER, ResourceRef::display(0), Rights::INSPECT);
        let present = grant(
            &mut table,
            OWNER,
            ResourceRef::display(0),
            Rights::DISPLAY_PRESENT,
        );
        assert_eq!(
            authorize_display_present_in(&table, OWNER, inspect, 0).map(|_| ()),
            Err(CapabilityError::MissingRight)
        );
        assert!(authorize_display_present_in(&table, OWNER, present, 0).is_ok());
        assert_eq!(
            authorize_display_present_in(&table, OTHER, present, 0).map(|_| ()),
            Err(CapabilityError::UnauthorizedHolder)
        );
        assert_eq!(
            authorize_display_present_in(&table, OWNER, present, 1).map(|_| ()),
            Err(CapabilityError::WrongResource)
        );
    }

    #[test]
    fn wrong_holder_output_class_or_stale_handle_is_refused() {
        let mut table = CapabilityTable::<8>::new();
        let display = grant(&mut table, OWNER, ResourceRef::display(0), Rights::INSPECT);
        let network = grant(
            &mut table,
            OWNER,
            ResourceRef::network(3, 1),
            Rights::valid_for(ResourceClass::Network),
        );

        assert_eq!(
            authorize_display_query_in(&table, OTHER, display, 0).map(|_| ()),
            Err(CapabilityError::UnauthorizedHolder)
        );
        assert_eq!(
            authorize_display_query_in(&table, OWNER, display, 1).map(|_| ()),
            Err(CapabilityError::WrongResource)
        );
        assert_eq!(
            authorize_display_query_in(&table, OWNER, network, 0).map(|_| ()),
            Err(CapabilityError::WrongResource)
        );
        assert_eq!(
            authorize_display_query_in(&table, OWNER, u64::MAX, 0).map(|_| ()),
            Err(CapabilityError::InvalidHandle)
        );
        table
            .revoke(CapabilityHandle::decode(display).expect("handle"))
            .expect("revoke");
        assert!(matches!(
            authorize_display_query_in(&table, OWNER, display, 0),
            Err(CapabilityError::StaleHandle | CapabilityError::Revoked)
        ));
    }
}
