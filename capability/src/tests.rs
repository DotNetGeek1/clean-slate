extern crate alloc;

use crate::error::syscall_abi::{
    self, SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_ENOSPC, SYSCALL_ESTALE,
};
use crate::{
    authorize, authorize_audited, validate_delegation, AuditEvent, AuditOutcome, AuditSink,
    CapabilityError, CapabilityHandle, CapabilityRecord, CapabilityState, Generation, HolderId,
    Provenance, ResourceClass, ResourceRef, Rights, AUDIT_EVENT_SIZE_BYTES, MAX_DELEGATION_DEPTH,
};

struct VecSink {
    events: alloc::vec::Vec<AuditEvent>,
}

impl AuditSink for VecSink {
    fn record(&mut self, event: AuditEvent) {
        self.events.push(event);
    }
}

fn live_record(
    holder: HolderId,
    resource: ResourceRef,
    rights: Rights,
    generation: u32,
) -> CapabilityRecord {
    CapabilityRecord {
        state: CapabilityState::Live,
        holder,
        resource,
        rights,
        provenance: Provenance::root(holder),
        generation,
    }
}

#[test]
fn handle_roundtrip_and_rejections() {
    let h = CapabilityHandle::new(3, 42);
    let raw = h.encode();
    assert_eq!(CapabilityHandle::decode(raw).unwrap(), h);
    assert_eq!(
        CapabilityHandle::decode(raw | 0xffff_0000_0000_0000),
        Err(CapabilityError::InvalidHandle)
    );
    assert_eq!(
        CapabilityHandle::decode(0x0001_0000_0000_0000),
        Err(CapabilityError::InvalidHandle)
    );
}

#[test]
fn generation_next_stops_at_max() {
    assert_eq!(Generation::next(1), Some(2));
    assert_eq!(Generation::next(u32::MAX), None);
}

#[test]
fn rights_subset_and_names() {
    let full = Rights::READ.union(Rights::WRITE).union(Rights::DELEGATE);
    assert!(full.contains(Rights::READ));
    assert!(Rights::READ.is_subset_of(full));
    assert_eq!(full.attenuate(Rights::READ), Rights::READ);
    assert!(!Rights::WRITE.is_subset_of(Rights::READ));
    assert_eq!(Rights::from_bits(1 << 14), None);
    let mut buf = alloc::string::String::new();
    full.write_names(&mut buf).unwrap();
    assert_eq!(buf, "read|write|delegate");
}

#[test]
fn valid_for_masks() {
    assert_eq!(
        Rights::valid_for(ResourceClass::PersistentObject),
        Rights::READ
            .union(Rights::WRITE)
            .union(Rights::INSPECT)
            .union(Rights::DELEGATE)
            .union(Rights::REVOKE)
    );
    assert_eq!(
        Rights::valid_for(ResourceClass::Audit),
        Rights::AUDIT_READ.union(Rights::DELEGATE)
    );
    assert_eq!(
        Rights::valid_for(ResourceClass::Network),
        Rights::NET_RESOLVE
            .union(Rights::NET_CONNECT)
            .union(Rights::NET_SEND)
            .union(Rights::NET_RECEIVE)
            .union(Rights::NET_RAW_DEVICE)
            .union(Rights::DELEGATE)
            .union(Rights::REVOKE)
    );
}

#[test]
fn error_names_and_syscall_status_distinct() {
    let variants = [
        CapabilityError::InvalidHandle,
        CapabilityError::StaleHandle,
        CapabilityError::Revoked,
        CapabilityError::UnauthorizedHolder,
        CapabilityError::WrongResource,
        CapabilityError::MissingRight,
        CapabilityError::InvalidRights,
        CapabilityError::RightsWidening,
        CapabilityError::DelegationDepthExceeded,
        CapabilityError::CapacityExhausted,
        CapabilityError::GenerationExhausted,
        CapabilityError::NotDelegable,
    ];
    let mut names = alloc::collections::BTreeSet::new();
    for error in variants {
        assert!(names.insert(error.error_name()));
        match error {
            CapabilityError::InvalidHandle | CapabilityError::InvalidRights => {
                assert_eq!(error.syscall_status(), SYSCALL_EINVAL)
            }
            CapabilityError::StaleHandle | CapabilityError::Revoked => {
                assert_eq!(error.syscall_status(), SYSCALL_ESTALE)
            }
            CapabilityError::UnauthorizedHolder
            | CapabilityError::WrongResource
            | CapabilityError::MissingRight
            | CapabilityError::RightsWidening
            | CapabilityError::NotDelegable => assert_eq!(error.syscall_status(), SYSCALL_EACCES),
            CapabilityError::CapacityExhausted
            | CapabilityError::GenerationExhausted
            | CapabilityError::DelegationDepthExceeded => {
                assert_eq!(error.syscall_status(), SYSCALL_ENOSPC)
            }
        }
    }
    assert_eq!(
        syscall_abi::error_from_status(SYSCALL_EINVAL),
        Some(CapabilityError::InvalidHandle)
    );
}

#[test]
fn authorize_precedence() {
    let holder = HolderId(10);
    let resource = ResourceRef::object(7);
    let handle = CapabilityHandle::new(1, 5);
    let required = Rights::READ;

    let mut record = CapabilityRecord::EMPTY;
    assert_eq!(
        authorize(&record, handle, holder, resource, required),
        Err(CapabilityError::InvalidHandle)
    );

    record.state = CapabilityState::Retired;
    record.generation = 5;
    assert_eq!(
        authorize(&record, handle, holder, resource, required),
        Err(CapabilityError::StaleHandle)
    );

    record.state = CapabilityState::Live;
    record.generation = 4;
    assert_eq!(
        authorize(&record, handle, holder, resource, required),
        Err(CapabilityError::StaleHandle)
    );

    record.generation = 5;
    record.state = CapabilityState::Revoked;
    assert_eq!(
        authorize(&record, handle, holder, resource, required),
        Err(CapabilityError::Revoked)
    );

    record.state = CapabilityState::Live;
    record.holder = HolderId(99);
    assert_eq!(
        authorize(&record, handle, holder, resource, required),
        Err(CapabilityError::UnauthorizedHolder)
    );

    record.holder = holder;
    record.resource = ResourceRef::object(8);
    assert_eq!(
        authorize(&record, handle, holder, resource, required),
        Err(CapabilityError::WrongResource)
    );

    record.resource = resource;
    record.rights = Rights::empty();
    assert_eq!(
        authorize(&record, handle, holder, resource, required),
        Err(CapabilityError::MissingRight)
    );

    record.rights = Rights::READ;
    assert!(authorize(&record, handle, holder, resource, required).is_ok());
}

#[test]
fn validate_delegation_cases() {
    let holder = HolderId(1);
    let resource = ResourceRef::object(1);
    let handle = CapabilityHandle::new(0, 2);
    let parent = live_record(holder, resource, Rights::READ.union(Rights::DELEGATE), 2);

    assert_eq!(
        validate_delegation(&parent, handle, holder, Rights::READ.union(Rights::WRITE)),
        Err(CapabilityError::RightsWidening)
    );

    let no_delegate = live_record(holder, resource, Rights::READ, 2);
    assert_eq!(
        validate_delegation(&no_delegate, handle, holder, Rights::READ),
        Err(CapabilityError::MissingRight)
    );

    let mut stale = parent;
    stale.state = CapabilityState::Revoked;
    assert_eq!(
        validate_delegation(&stale, handle, holder, Rights::READ),
        Err(CapabilityError::Revoked)
    );

    let audit_parent = live_record(
        holder,
        ResourceRef {
            class: ResourceClass::Audit,
            id: 0,
            instance_generation: 0,
        },
        Rights::AUDIT_READ
            .union(Rights::DELEGATE)
            .union(Rights::READ),
        2,
    );
    assert_eq!(
        validate_delegation(&audit_parent, handle, holder, Rights::READ),
        Err(CapabilityError::InvalidRights)
    );
}

#[test]
fn provenance_depth_limit() {
    let root = Provenance::root(HolderId(1));
    let h = CapabilityHandle::new(0, 1);
    let mut prov = root;
    for _ in 0..MAX_DELEGATION_DEPTH {
        prov = Provenance::child_of(h, &prov).unwrap();
    }
    assert_eq!(
        Provenance::child_of(h, &prov),
        Err(CapabilityError::DelegationDepthExceeded)
    );
}

#[test]
fn audit_event_size() {
    assert_eq!(AUDIT_EVENT_SIZE_BYTES, 64);
    assert_eq!(core::mem::size_of::<AuditEvent>(), 64);
}

#[test]
fn authorize_audited_matches_authorize() {
    let holder = HolderId(5);
    let resource = ResourceRef::process(9, 1);
    let handle = CapabilityHandle::new(2, 3);
    let record = live_record(holder, resource, Rights::OBSERVE, 3);
    let mut sink = VecSink {
        events: alloc::vec::Vec::new(),
    };

    assert_eq!(
        authorize_audited(
            &mut sink,
            1,
            &record,
            handle,
            holder,
            resource,
            Rights::OBSERVE
        ),
        authorize(&record, handle, holder, resource, Rights::OBSERVE)
    );
    assert_eq!(sink.events.len(), 1);
    assert_eq!(sink.events[0].outcome.tag, AuditOutcome::TAG_ALLOWED);

    assert_eq!(
        authorize_audited(
            &mut sink,
            2,
            &record,
            handle,
            holder,
            resource,
            Rights::TERMINATE
        ),
        Err(CapabilityError::MissingRight)
    );
    assert_eq!(sink.events.len(), 2);
    assert_eq!(sink.events[1].outcome.tag, AuditOutcome::TAG_DENIED);
    assert_eq!(
        CapabilityError::from_u8(sink.events[1].outcome.error_code),
        Some(CapabilityError::MissingRight)
    );
}

#[test]
fn network_rights_mask_and_authorization() {
    let holder = HolderId(77);
    let resource = ResourceRef {
        class: ResourceClass::Network,
        id: 1,
        instance_generation: 0,
    };
    let handle = CapabilityHandle::new(0, 1);
    let valid = Rights::valid_for(ResourceClass::Network);
    assert!(valid.contains(Rights::NET_SEND));
    assert_eq!(Rights::from_bits(valid.bits() | (1 << 14)), None);
    assert!(!Rights::NET_SEND.is_subset_of(Rights::valid_for(ResourceClass::BlockDevice)));

    let parent = live_record(holder, resource, valid, 1);
    let child_rights = Rights::NET_SEND.union(Rights::NET_RECEIVE);
    assert_eq!(
        validate_delegation(&parent, handle, holder, child_rights),
        Ok(child_rights)
    );
    let invalid_parent = live_record(holder, resource, valid.union(Rights::READ), 1);
    assert_eq!(
        validate_delegation(&invalid_parent, handle, holder, Rights::READ),
        Err(CapabilityError::InvalidRights)
    );

    let bad_object = live_record(
        holder,
        ResourceRef::object(1),
        Rights::READ
            .union(Rights::DELEGATE)
            .union(Rights::NET_RESOLVE),
        1,
    );
    assert_eq!(
        validate_delegation(&bad_object, handle, holder, Rights::NET_RESOLVE),
        Err(CapabilityError::InvalidRights)
    );

    let send_only = live_record(
        holder,
        resource,
        Rights::NET_SEND.union(Rights::DELEGATE),
        1,
    );
    assert_eq!(
        authorize(&send_only, handle, holder, resource, Rights::NET_SEND),
        Ok(())
    );
    assert_eq!(
        authorize(&send_only, handle, holder, resource, Rights::NET_RECEIVE),
        Err(CapabilityError::MissingRight)
    );

    assert_eq!(
        validate_delegation(
            &send_only,
            handle,
            holder,
            Rights::NET_SEND.union(Rights::NET_RECEIVE)
        ),
        Err(CapabilityError::RightsWidening)
    );
}

#[test]
fn network_resource_ref_constructors() {
    let service = ResourceRef::network(0x5200, 3);
    assert_eq!(service.class, ResourceClass::Network);
    assert_eq!(service.id, 0x5200);
    assert_eq!(service.instance_generation, 3);
    let session = ResourceRef::network_session(2, 7);
    assert_eq!(session.instance_generation, 2);
    assert_eq!(session.id, 7);
    let stale = ResourceRef::network(0x5200, 1);
    let live = ResourceRef::network(0x5200, 2);
    assert_ne!(stale, live);
}
