//! Host-testable generic capability slot table (M6.2).

use crate::authorize;
use crate::error::CapabilityError;
use crate::handle::{CapabilityHandle, Generation};
use crate::holder::HolderId;
use crate::provenance::Provenance;
use crate::record::CapabilityRecord;
use crate::resource::{ResourceClass, ResourceRef};
use crate::rights::Rights;
use crate::state::CapabilityState;

/// Fixed-size capability table with per-slot generation bookkeeping.
pub struct CapabilityTable<const N: usize> {
    slots: [CapabilityRecord; N],
    live_count: usize,
}

impl<const N: usize> Default for CapabilityTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> CapabilityTable<N> {
    pub const fn new() -> Self {
        Self {
            slots: [CapabilityRecord::EMPTY; N],
            live_count: 0,
        }
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    pub fn live_count(&self) -> usize {
        self.live_count
    }

    pub fn grant(
        &mut self,
        holder: HolderId,
        resource: ResourceRef,
        rights: Rights,
        provenance: Provenance,
    ) -> Result<CapabilityHandle, CapabilityError> {
        validate_rights(resource.class, rights)?;
        let (slot, generation) = self.pick_empty_slot()?;
        let record = CapabilityRecord {
            state: CapabilityState::Live,
            holder,
            resource,
            rights,
            provenance,
            generation,
        };
        self.slots[slot] = record;
        self.live_count += 1;
        Ok(CapabilityHandle::new(slot_as_u16(slot)?, generation))
    }

    pub fn install(
        &mut self,
        record: CapabilityRecord,
    ) -> Result<CapabilityHandle, CapabilityError> {
        validate_rights(record.resource.class, record.rights)?;
        let (slot, generation) = self.pick_empty_slot()?;
        let installed = CapabilityRecord {
            state: CapabilityState::Live,
            holder: record.holder,
            resource: record.resource,
            rights: record.rights,
            provenance: record.provenance,
            generation,
        };
        self.slots[slot] = installed;
        self.live_count += 1;
        Ok(CapabilityHandle::new(slot_as_u16(slot)?, generation))
    }

    pub fn authorize(
        &self,
        holder: HolderId,
        handle: CapabilityHandle,
        resource: ResourceRef,
        required: Rights,
    ) -> Result<CapabilityRecord, CapabilityError> {
        let record = self.record(handle)?;
        authorize(&record, handle, holder, resource, required)?;
        Ok(record)
    }

    pub fn authorize_class(
        &self,
        holder: HolderId,
        handle: CapabilityHandle,
        class: ResourceClass,
        required: Rights,
    ) -> Result<CapabilityRecord, CapabilityError> {
        let record = self.record(handle)?;
        if record.resource.class != class {
            return Err(CapabilityError::WrongResource);
        }
        authorize(&record, handle, holder, record.resource, required)?;
        Ok(record)
    }

    pub fn record(&self, handle: CapabilityHandle) -> Result<CapabilityRecord, CapabilityError> {
        let slot = slot_index::<N>(handle)?;
        let record = &self.slots[slot];
        if record.state == CapabilityState::Empty {
            // A never-used slot has generation 0; a released slot keeps a nonzero bumped
            // generation so handles from a previous occupant are reported as stale.
            return Err(if record.generation == 0 {
                CapabilityError::InvalidHandle
            } else {
                CapabilityError::StaleHandle
            });
        }
        if record.state == CapabilityState::Retired {
            return Err(CapabilityError::StaleHandle);
        }
        if record.generation != handle.generation {
            return Err(CapabilityError::StaleHandle);
        }
        Ok(*record)
    }

    pub fn handle_at(&self, slot: usize) -> Option<CapabilityHandle> {
        if slot >= N {
            return None;
        }
        let record = &self.slots[slot];
        if record.state == CapabilityState::Empty {
            return None;
        }
        Some(CapabilityHandle::new(
            slot_as_u16(slot).unwrap_or(0),
            record.generation,
        ))
    }

    pub fn record_at(&self, slot: usize) -> &CapabilityRecord {
        &self.slots[slot]
    }

    pub fn revoke(&mut self, handle: CapabilityHandle) -> Result<bool, CapabilityError> {
        let slot = slot_index::<N>(handle)?;
        let record = &self.slots[slot];
        if record.state == CapabilityState::Empty && record.generation == 0 {
            return Ok(false);
        }
        if record.generation != handle.generation || record.state == CapabilityState::Empty {
            return Err(CapabilityError::StaleHandle);
        }
        Ok(self.revoke_slot(slot))
    }

    /// Revokes a `Live` slot in place: state becomes `Revoked`, rights are cleared, but the
    /// generation, holder, resource, and provenance are kept so the original handle still
    /// resolves through [`Self::record`] (yielding `CapabilityError::Revoked` on authorize)
    /// and so revocation code can walk descendants whose `provenance.parent` names it.
    /// The generation is bumped when the slot is released via [`Self::release_slot`].
    pub fn revoke_slot(&mut self, slot: usize) -> bool {
        if slot >= N {
            return false;
        }
        let record = &mut self.slots[slot];
        match record.state {
            CapabilityState::Live => {
                record.state = CapabilityState::Revoked;
                record.rights = Rights::empty();
                self.live_count -= 1;
                true
            }
            CapabilityState::Revoked | CapabilityState::Retired | CapabilityState::Empty => false,
        }
    }

    /// Returns a `Revoked` slot to `Empty`, bumping its generation so every handle issued for
    /// the previous occupant stays stale even if the slot is reused. If the generation is
    /// exhausted the slot becomes `Retired` instead and is never reused.
    pub fn release_slot(&mut self, slot: usize) -> bool {
        if slot >= N {
            return false;
        }
        let record = &mut self.slots[slot];
        if record.state != CapabilityState::Revoked {
            return false;
        }
        let generation = record.generation;
        *record = CapabilityRecord::EMPTY;
        match Generation::next(generation) {
            Some(next) => record.generation = next,
            None => {
                record.generation = generation;
                record.state = CapabilityState::Retired;
            }
        }
        true
    }

    pub fn revoke_holder(&mut self, holder: HolderId) -> usize {
        let mut count = 0;
        for slot in 0..N {
            if self.slots[slot].state == CapabilityState::Live
                && self.slots[slot].holder == holder
                && self.revoke_slot(slot)
            {
                self.release_slot(slot);
                count += 1;
            }
        }
        count
    }

    pub fn revoke_resource(&mut self, resource: ResourceRef) -> usize {
        let mut count = 0;
        for slot in 0..N {
            if self.slots[slot].state == CapabilityState::Live
                && self.slots[slot].resource == resource
                && self.revoke_slot(slot)
            {
                self.release_slot(slot);
                count += 1;
            }
        }
        count
    }

    pub fn revoke_resource_id(&mut self, class: ResourceClass, id: u64) -> usize {
        let mut count = 0;
        for slot in 0..N {
            if self.slots[slot].state == CapabilityState::Live
                && self.slots[slot].resource.class == class
                && self.slots[slot].resource.id == id
                && self.revoke_slot(slot)
            {
                self.release_slot(slot);
                count += 1;
            }
        }
        count
    }

    pub fn state_at(&self, slot: usize) -> CapabilityState {
        if slot >= N {
            CapabilityState::Empty
        } else {
            self.slots[slot].state
        }
    }

    fn pick_empty_slot(&mut self) -> Result<(usize, u32), CapabilityError> {
        for slot in 0..N {
            if self.slots[slot].state != CapabilityState::Empty {
                continue;
            }
            let current = self.slots[slot].generation;
            match Generation::next(current) {
                Some(next) => return Ok((slot, next)),
                None => {
                    self.slots[slot].state = CapabilityState::Retired;
                }
            }
        }
        Err(CapabilityError::CapacityExhausted)
    }

    #[cfg(test)]
    pub fn set_generation_for_test(&mut self, slot: usize, generation: u32) {
        if slot < N {
            self.slots[slot].generation = generation;
        }
    }
}

fn validate_rights(class: ResourceClass, rights: Rights) -> Result<(), CapabilityError> {
    if rights == Rights::empty() {
        return Err(CapabilityError::InvalidRights);
    }
    if !rights.is_subset_of(Rights::valid_for(class)) {
        return Err(CapabilityError::InvalidRights);
    }
    Ok(())
}

fn slot_index<const N: usize>(handle: CapabilityHandle) -> Result<usize, CapabilityError> {
    let slot = usize::from(handle.slot);
    if slot >= N {
        return Err(CapabilityError::InvalidHandle);
    }
    Ok(slot)
}

fn slot_as_u16(slot: usize) -> Result<u16, CapabilityError> {
    u16::try_from(slot).map_err(|_| CapabilityError::CapacityExhausted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Provenance;

    const H1: HolderId = HolderId(10);
    const H2: HolderId = HolderId(20);
    const OBJ: ResourceRef = ResourceRef::object(42);

    fn grant_read(table: &mut CapabilityTable<4>, holder: HolderId) -> CapabilityHandle {
        table
            .grant(holder, OBJ, Rights::READ, Provenance::root(holder))
            .expect("grant")
    }

    #[test]
    fn grant_authorize_happy_path() {
        let mut table = CapabilityTable::<4>::new();
        let handle = grant_read(&mut table, H1);
        assert_eq!(table.live_count(), 1);
        let record = table
            .authorize(H1, handle, OBJ, Rights::READ)
            .expect("authorize");
        assert_eq!(record.state, CapabilityState::Live);
    }

    #[test]
    fn authorize_rejects_wrong_holder_resource_and_rights() {
        let mut table = CapabilityTable::<4>::new();
        let handle = grant_read(&mut table, H1);
        assert_eq!(
            table.authorize(H2, handle, OBJ, Rights::READ),
            Err(CapabilityError::UnauthorizedHolder)
        );
        let other = ResourceRef::object(99);
        assert_eq!(
            table.authorize(H1, handle, other, Rights::READ),
            Err(CapabilityError::WrongResource)
        );
        assert_eq!(
            table.authorize(H1, handle, OBJ, Rights::WRITE),
            Err(CapabilityError::MissingRight)
        );
        assert_eq!(
            table.authorize(H1, CapabilityHandle::new(9, 1), OBJ, Rights::READ),
            Err(CapabilityError::InvalidHandle)
        );
    }

    #[test]
    fn stale_after_revoke_and_revoked_before_release() {
        let mut table = CapabilityTable::<4>::new();
        let handle = grant_read(&mut table, H1);
        assert!(table.revoke(handle).expect("revoke"));
        assert_eq!(table.state_at(0), CapabilityState::Revoked);
        // The original handle still resolves so callers see the distinct `Revoked` outcome
        // and revocation code can inspect provenance/resource of the revoked record.
        let record = table.record(handle).expect("revoked record resolves");
        assert_eq!(record.state, CapabilityState::Revoked);
        assert_eq!(record.resource, OBJ);
        assert_eq!(record.holder, H1);
        assert_eq!(table.handle_at(0), Some(handle));
        assert_eq!(
            table.authorize(H1, handle, OBJ, Rights::READ),
            Err(CapabilityError::Revoked)
        );
        // Once released the slot is empty with a bumped generation: old handle is stale.
        assert!(table.release_slot(0));
        assert_eq!(table.state_at(0), CapabilityState::Empty);
        assert_eq!(
            table.authorize(H1, handle, OBJ, Rights::READ),
            Err(CapabilityError::StaleHandle)
        );
        assert_eq!(
            table.record(CapabilityHandle::new(1, 1)),
            Err(CapabilityError::InvalidHandle)
        );
    }

    #[test]
    fn slot_reuse_keeps_old_handle_stale() {
        let mut table = CapabilityTable::<4>::new();
        let old = grant_read(&mut table, H1);
        assert!(table.revoke(old).expect("revoke"));
        assert!(table.release_slot(0));
        let new = grant_read(&mut table, H2);
        assert_ne!(old.generation, new.generation);
        assert_eq!(
            table.authorize(H1, old, OBJ, Rights::READ),
            Err(CapabilityError::StaleHandle)
        );
        assert!(table.authorize(H2, new, OBJ, Rights::READ).is_ok());
    }

    #[test]
    fn capacity_exhausted_does_not_corrupt_live() {
        let mut table = CapabilityTable::<4>::new();
        let mut handles = Vec::new();
        for holder in [H1, H2, HolderId(30), HolderId(40)] {
            handles.push(grant_read(&mut table, holder));
        }
        assert_eq!(table.live_count(), 4);
        assert_eq!(
            table.grant(H1, OBJ, Rights::READ, Provenance::root(H1)),
            Err(CapabilityError::CapacityExhausted)
        );
        for (holder, handle) in [
            (H1, handles[0]),
            (H2, handles[1]),
            (HolderId(30), handles[2]),
            (HolderId(40), handles[3]),
        ] {
            assert!(table.authorize(holder, handle, OBJ, Rights::READ).is_ok());
        }
    }

    #[test]
    fn generation_exhaustion_retires_slot() {
        let mut table = CapabilityTable::<4>::new();
        table.set_generation_for_test(0, u32::MAX);
        let handle = grant_read(&mut table, H1);
        assert_ne!(handle.slot, 0);
        assert_eq!(table.state_at(0), CapabilityState::Retired);

        let live_slot = usize::from(handle.slot);
        table.set_generation_for_test(live_slot, u32::MAX);
        assert!(table.revoke_slot(live_slot));
        assert_eq!(table.state_at(live_slot), CapabilityState::Revoked);
        assert!(table.release_slot(live_slot));
        assert_eq!(table.state_at(live_slot), CapabilityState::Retired);
        assert!(!table.release_slot(live_slot));

        assert_eq!(table.live_count(), 0);
        let mut granted = 0;
        while table
            .grant(H1, OBJ, Rights::READ, Provenance::root(H1))
            .is_ok()
        {
            granted += 1;
        }
        assert_eq!(granted, 2);
        assert_eq!(
            table.grant(H1, OBJ, Rights::READ, Provenance::root(H1)),
            Err(CapabilityError::CapacityExhausted)
        );
        assert_eq!(
            table.authorize(H1, handle, OBJ, Rights::READ),
            Err(CapabilityError::StaleHandle)
        );
    }

    #[test]
    fn install_rejects_invalid_rights_transactionally() {
        let mut table = CapabilityTable::<4>::new();
        let record = CapabilityRecord {
            state: CapabilityState::Live,
            holder: H1,
            resource: OBJ,
            rights: Rights::TERMINATE,
            provenance: Provenance::root(H1),
            generation: 99,
        };
        assert_eq!(table.install(record), Err(CapabilityError::InvalidRights));
        assert_eq!(table.live_count(), 0);
    }

    #[test]
    fn revoke_idempotent() {
        let mut table = CapabilityTable::<4>::new();
        let handle = grant_read(&mut table, H1);
        assert!(table.revoke(handle).expect("first"));
        assert!(!table.revoke(handle).expect("second"));
        assert!(!table.revoke_slot(0));
        assert!(table.release_slot(0));
        assert_eq!(table.revoke(handle), Err(CapabilityError::StaleHandle));
        assert_eq!(
            table.revoke(CapabilityHandle::new(4, 1)),
            Err(CapabilityError::InvalidHandle)
        );
    }

    #[test]
    fn revoke_holder_and_resource_counts() {
        let mut table = CapabilityTable::<4>::new();
        let r1 = ResourceRef::object(1);
        let r2 = ResourceRef::object(2);
        table
            .grant(H1, r1, Rights::READ, Provenance::root(H1))
            .unwrap();
        table
            .grant(H1, r2, Rights::READ, Provenance::root(H1))
            .unwrap();
        table
            .grant(H2, r1, Rights::READ, Provenance::root(H2))
            .unwrap();
        assert_eq!(table.revoke_holder(H1), 2);
        assert_eq!(table.live_count(), 1);
        assert_eq!(table.revoke_resource(r1), 1);
        assert_eq!(table.live_count(), 0);
    }

    #[test]
    fn revoke_resource_id_matches_any_instance_generation() {
        let mut table = CapabilityTable::<4>::new();
        let pid = 7_u64;
        let r_gen1 = ResourceRef::process(pid, 1);
        let r_gen2 = ResourceRef::process(pid, 2);
        table
            .grant(H1, r_gen1, Rights::OBSERVE, Provenance::root(H1))
            .unwrap();
        table
            .grant(H2, r_gen2, Rights::OBSERVE, Provenance::root(H2))
            .unwrap();
        assert_eq!(
            table.revoke_resource_id(ResourceClass::ProcessControl, pid),
            2
        );
    }

    #[test]
    fn authorize_class_wrong_class() {
        let mut table = CapabilityTable::<4>::new();
        let handle = grant_read(&mut table, H1);
        assert_eq!(
            table.authorize_class(H1, handle, ResourceClass::BlockDevice, Rights::READ),
            Err(CapabilityError::WrongResource)
        );
        assert!(table
            .authorize_class(H1, handle, ResourceClass::PersistentObject, Rights::READ)
            .is_ok());
    }

    #[test]
    fn handle_slot_out_of_range_invalid() {
        let table = CapabilityTable::<4>::new();
        assert_eq!(
            table.record(CapabilityHandle::new(4, 1)),
            Err(CapabilityError::InvalidHandle)
        );
    }
}
