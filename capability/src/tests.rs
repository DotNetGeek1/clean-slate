extern crate alloc;

use crate::error::syscall_abi::{
    self, SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_ENOSPC, SYSCALL_ESTALE,
};
use crate::{
    authorize, authorize_audited, fork_inheritable, validate_delegation, AuditEvent, AuditKind,
    AuditOutcome, AuditSink, CapabilityError, CapabilityHandle, CapabilityRecord, CapabilityState,
    CapabilityTable, Generation, HolderId, Provenance, ResourceClass, ResourceRef, Rights,
    AUDIT_EVENT_SIZE_BYTES, MAX_DELEGATION_DEPTH,
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
    assert_eq!(Rights::from_bits(1 << 27), None);
    assert_eq!(Rights::from_bits(1 << 26), Some(Rights::DIRECTORY));
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
            .union(Rights::DIRECTORY)
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
        CapabilityError::QuotaExceeded,
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
            | CapabilityError::DelegationDepthExceeded
            | CapabilityError::QuotaExceeded => {
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
fn audit_kind_and_resource_class_bytes_round_trip() {
    for raw in 0..=u8::MAX {
        if let Some(kind) = AuditKind::from_u8(raw) {
            assert_eq!(kind as u8, raw);
        }
        if let Some(class) = ResourceClass::from_u8(raw) {
            assert_eq!(class.as_u8(), raw);
            assert!(!class.name().is_empty());
        }
    }
    assert_eq!(AuditKind::from_u8(6), Some(AuditKind::Lost));
    assert_eq!(AuditKind::from_u8(7), None);
    assert_eq!(ResourceClass::Audit.name(), "audit");
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
    assert_eq!(Rights::from_bits(valid.bits() | (1 << 27)), None);
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

fn shared_buffer_id_raw(slot: u16, generation: u32) -> u64 {
    u64::from(slot) | (u64::from(generation) << 16)
}

#[test]
fn resource_class_from_u8_includes_m10_classes() {
    for raw in 1u8..=13 {
        assert_eq!(ResourceClass::from_u8(raw).map(|c| c.as_u8()), Some(raw));
    }
    assert_eq!(ResourceClass::from_u8(0), None);
    assert_eq!(ResourceClass::from_u8(14), None);
}

#[test]
fn m10_valid_for_masks_exact() {
    assert_eq!(
        Rights::valid_for(ResourceClass::SharedBuffer),
        Rights::READ
            .union(Rights::WRITE)
            .union(Rights::DELEGATE)
            .union(Rights::REVOKE)
    );
    assert_eq!(
        Rights::valid_for(ResourceClass::Graphics),
        Rights::GFX_CONNECT
            .union(Rights::GFX_SHELL)
            .union(Rights::GFX_OVERLAY)
            .union(Rights::GFX_SERVE)
            .union(Rights::DELEGATE)
            .union(Rights::REVOKE)
    );
    assert_eq!(
        Rights::valid_for(ResourceClass::Display),
        Rights::DISPLAY_PRESENT.union(Rights::INSPECT)
    );
    assert_eq!(
        Rights::valid_for(ResourceClass::Input),
        Rights::INPUT_CONSUME.union(Rights::INSPECT)
    );
    assert_eq!(
        Rights::root_only_for(ResourceClass::PersistentObject),
        Rights::empty()
    );
}

#[test]
fn launcher_rights_keep_serving_at_the_root() {
    assert_eq!(
        Rights::valid_for(ResourceClass::Launcher),
        Rights::LAUNCH_CONNECT
            .union(Rights::LAUNCH_SERVE)
            .union(Rights::DELEGATE)
            .union(Rights::REVOKE)
    );
    assert_eq!(
        Rights::root_only_for(ResourceClass::Launcher),
        Rights::LAUNCH_SERVE
    );
    assert_eq!(ResourceClass::Launcher.name(), "launcher");
    assert_eq!(ResourceClass::from_u8(13), Some(ResourceClass::Launcher));
    assert_eq!(
        ResourceRef::launcher_port(),
        ResourceRef {
            class: ResourceClass::Launcher,
            id: crate::LAUNCHER_PORT_ID,
            instance_generation: 0,
        }
    );
    let mut names = alloc::string::String::new();
    Rights::LAUNCH_CONNECT
        .union(Rights::LAUNCH_SERVE)
        .write_names(&mut names)
        .unwrap();
    assert_eq!(names, "launch_connect|launch_serve");
}

#[test]
fn console_rights_keep_serving_and_the_device_at_the_root() {
    let valid = Rights::valid_for(ResourceClass::Console);
    assert_eq!(
        valid,
        Rights::CONSOLE_CONNECT
            .union(Rights::CONSOLE_SERVE)
            .union(Rights::CONSOLE_ATTACH)
            .union(Rights::CONSOLE_SESSION)
            .union(Rights::READ)
            .union(Rights::WRITE)
            .union(Rights::DELEGATE)
            .union(Rights::REVOKE)
    );
    let root_only = Rights::root_only_for(ResourceClass::Console);
    assert!(!root_only.contains(Rights::DELEGATE));
    assert!(!root_only.contains(Rights::CONSOLE_CONNECT));
    assert!(root_only.contains(Rights::CONSOLE_SERVE));
    assert!(root_only.contains(Rights::WRITE));
    assert!(root_only.contains(Rights::CONSOLE_ATTACH));
    assert!(
        !root_only.contains(Rights::CONSOLE_SESSION),
        "forks inherit membership"
    );
    assert_eq!(ResourceClass::Console.name(), "console");
    let mut names = alloc::string::String::new();
    Rights::CONSOLE_CONNECT
        .union(Rights::CONSOLE_SERVE)
        .union(Rights::CONSOLE_ATTACH)
        .union(Rights::CONSOLE_SESSION)
        .write_names(&mut names)
        .unwrap();
    assert_eq!(
        names,
        "console_connect|console_serve|console_attach|console_session"
    );
}

#[test]
fn display_and_input_grant_reject_delegate_via_valid_for() {
    let mut table = CapabilityTable::<4>::new();
    let holder = HolderId(1);
    let prov = Provenance::root(holder);
    let display = ResourceRef::display(1);
    let input = ResourceRef::input(0);
    assert_eq!(
        table.grant(
            holder,
            display,
            Rights::DISPLAY_PRESENT.union(Rights::DELEGATE),
            prov
        ),
        Err(CapabilityError::InvalidRights)
    );
    assert_eq!(
        table.grant(
            holder,
            input,
            Rights::INPUT_CONSUME.union(Rights::DELEGATE),
            prov
        ),
        Err(CapabilityError::InvalidRights)
    );
    assert!(table
        .grant(holder, display, Rights::DISPLAY_PRESENT, prov)
        .is_ok());
    assert!(table
        .grant(holder, input, Rights::INPUT_CONSUME, prov)
        .is_ok());
}

#[test]
fn graphics_delegation_refuses_root_only_rights() {
    let holder = HolderId(2);
    let resource = ResourceRef::graphics(0x5300, 1);
    let handle = CapabilityHandle::new(0, 1);
    let parent = live_record(
        holder,
        resource,
        Rights::GFX_CONNECT
            .union(Rights::GFX_SHELL)
            .union(Rights::GFX_OVERLAY)
            .union(Rights::GFX_SERVE)
            .union(Rights::DELEGATE),
        1,
    );
    assert_eq!(
        validate_delegation(&parent, handle, holder, Rights::GFX_CONNECT),
        Ok(Rights::GFX_CONNECT)
    );
    assert_eq!(
        validate_delegation(&parent, handle, holder, Rights::GFX_SHELL),
        Err(CapabilityError::NotDelegable)
    );
    assert_eq!(
        validate_delegation(
            &parent,
            handle,
            holder,
            Rights::GFX_CONNECT.union(Rights::GFX_SERVE)
        ),
        Err(CapabilityError::NotDelegable)
    );
}

#[test]
fn shared_buffer_delegation_allows_only_read_children() {
    let holder = HolderId(2);
    let resource = ResourceRef::shared_buffer(shared_buffer_id_raw(3, 1));
    let handle = CapabilityHandle::new(0, 1);
    let parent = live_record(
        holder,
        resource,
        Rights::valid_for(ResourceClass::SharedBuffer),
        1,
    );
    assert_eq!(
        validate_delegation(&parent, handle, holder, Rights::READ),
        Ok(Rights::READ)
    );
    for right in [Rights::WRITE, Rights::DELEGATE, Rights::REVOKE] {
        assert_eq!(
            validate_delegation(&parent, handle, holder, Rights::READ.union(right)),
            Err(CapabilityError::NotDelegable)
        );
    }
}

#[test]
fn network_raw_device_is_not_delegable() {
    let holder = HolderId(2);
    let handle = CapabilityHandle::new(0, 1);
    let parent = live_record(
        holder,
        ResourceRef::network(0x5200, 1),
        Rights::valid_for(ResourceClass::Network),
        1,
    );
    assert_eq!(
        validate_delegation(&parent, handle, holder, Rights::NET_RAW_DEVICE),
        Err(CapabilityError::NotDelegable)
    );
    assert_eq!(
        validate_delegation(
            &parent,
            handle,
            holder,
            Rights::NET_CONNECT.union(Rights::NET_RAW_DEVICE)
        ),
        Err(CapabilityError::NotDelegable)
    );
    assert_eq!(
        validate_delegation(&parent, handle, holder, Rights::NET_CONNECT),
        Ok(Rights::NET_CONNECT)
    );

    let mut table = CapabilityTable::<4>::new();
    let parent_handle = table
        .grant(
            holder,
            ResourceRef::network(0x5200, 1),
            Rights::NET_RAW_DEVICE.union(Rights::DELEGATE),
            Provenance::root(holder),
        )
        .unwrap();
    assert_eq!(
        crate::delegate(
            &mut table,
            holder,
            parent_handle,
            HolderId(3),
            Rights::NET_RAW_DEVICE
        ),
        Err(CapabilityError::NotDelegable)
    );
}

#[test]
fn fork_withholds_records_with_root_only_rights() {
    let holder = HolderId(4);
    let graphics = ResourceRef::graphics(0x5300, 1);
    let shared_buffer = ResourceRef::shared_buffer(shared_buffer_id_raw(3, 1));
    let network = ResourceRef::network(0x5200, 1);
    let withheld = [
        (graphics, Rights::GFX_CONNECT.union(Rights::GFX_SERVE)),
        (graphics, Rights::GFX_SHELL),
        (graphics, Rights::GFX_OVERLAY),
        (
            shared_buffer,
            Rights::valid_for(ResourceClass::SharedBuffer),
        ),
        (shared_buffer, Rights::READ.union(Rights::WRITE)),
        (network, Rights::valid_for(ResourceClass::Network)),
    ];
    for (resource, rights) in withheld {
        assert!(
            !fork_inheritable(&live_record(holder, resource, rights, 1)),
            "{resource:?} {rights:?} must not be inherited"
        );
    }
    let inherited = [
        (graphics, Rights::GFX_CONNECT.union(Rights::DELEGATE)),
        (shared_buffer, Rights::READ),
        (network, Rights::NET_CONNECT.union(Rights::NET_SEND)),
        // Fork needs no DELEGATE, and classes without root-only rights are unaffected.
        (ResourceRef::object(9), Rights::READ.union(Rights::WRITE)),
        (ResourceRef::process(5, 1), Rights::OBSERVE),
    ];
    for (resource, rights) in inherited {
        assert!(
            fork_inheritable(&live_record(holder, resource, rights, 1)),
            "{resource:?} {rights:?} must be inherited"
        );
    }
}

#[test]
fn existing_class_delegation_unaffected_by_root_only_mask() {
    let holder = HolderId(3);
    let resource = ResourceRef::object(9);
    let handle = CapabilityHandle::new(1, 1);
    let parent = live_record(
        holder,
        resource,
        Rights::READ.union(Rights::WRITE).union(Rights::DELEGATE),
        1,
    );
    assert_eq!(
        validate_delegation(&parent, handle, holder, Rights::READ),
        Ok(Rights::READ)
    );
}

#[test]
fn m10_rights_write_names() {
    let rights = Rights::GFX_CONNECT
        .union(Rights::GFX_SHELL)
        .union(Rights::GFX_OVERLAY)
        .union(Rights::GFX_SERVE)
        .union(Rights::DISPLAY_PRESENT)
        .union(Rights::INPUT_CONSUME);
    let mut buf = alloc::string::String::new();
    rights.write_names(&mut buf).unwrap();
    assert_eq!(
        buf,
        "gfx_connect|gfx_shell|gfx_overlay|gfx_serve|display_present|input_consume"
    );
}

#[test]
fn shared_buffer_resource_ref_and_revoke_by_full_id() {
    let raw_gen1 = shared_buffer_id_raw(1, 1);
    let raw_gen2 = shared_buffer_id_raw(1, 2);
    let r1 = ResourceRef::shared_buffer(raw_gen1);
    assert_eq!(r1.id, raw_gen1);
    assert_eq!(r1.instance_generation, 0);

    let mut table = CapabilityTable::<4>::new();
    let h1 = HolderId(10);
    let h2 = HolderId(11);
    table
        .grant(h1, r1, Rights::READ, Provenance::root(h1))
        .unwrap();
    table
        .grant(
            h2,
            ResourceRef::shared_buffer(raw_gen2),
            Rights::READ,
            Provenance::root(h2),
        )
        .unwrap();
    assert_eq!(
        table.revoke_resource_id(ResourceClass::SharedBuffer, raw_gen1),
        1
    );
    assert_eq!(table.live_count(), 1);
}

#[test]
fn display_resource_ref_names_output_index_only() {
    for index in 0u8..=255 {
        let resource = ResourceRef::display(index);
        assert_eq!(resource.class, ResourceClass::Display);
        assert_eq!(resource.id, u64::from(index));
        assert_eq!(resource.instance_generation, 0);
    }
}

#[test]
fn display_resource_ref_revoke_is_per_output_index() {
    let mut table = CapabilityTable::<4>::new();
    let h1 = HolderId(20);
    let h2 = HolderId(21);
    table
        .grant(
            h1,
            ResourceRef::display(1),
            Rights::DISPLAY_PRESENT,
            Provenance::root(h1),
        )
        .unwrap();
    table
        .grant(
            h2,
            ResourceRef::display(2),
            Rights::DISPLAY_PRESENT,
            Provenance::root(h2),
        )
        .unwrap();
    assert_eq!(table.revoke_resource_id(ResourceClass::Display, 1), 1);
    assert_eq!(table.live_count(), 1);
}

#[test]
fn m10_resource_ref_constructors() {
    let gfx = ResourceRef::graphics(0x5300, 4);
    assert_eq!(gfx.class, ResourceClass::Graphics);
    assert_eq!(gfx.id, 0x5300);
    assert_eq!(gfx.instance_generation, 4);
    let disp = ResourceRef::display(3);
    assert_eq!(disp.id, 3);
    let inp = ResourceRef::input(0);
    assert_eq!(inp.id, 0);
    assert_eq!(inp.instance_generation, 0);
}

#[test]
fn a_refused_network_destination_round_trips_and_prints_its_address() {
    use crate::{NetDestination, NetTransport, PolicyRefusal};
    let destination = NetDestination {
        transport: NetTransport::Udp,
        addr: [10, 77, 0, 50],
        port: 53,
    };
    assert_eq!(
        NetDestination::decode(destination.encode()),
        Some(destination)
    );
    assert_eq!(
        NetDestination::decode(NetDestination::RESOLVE.encode()),
        Some(NetDestination::RESOLVE)
    );
    assert_eq!(NetDestination::decode(3 << 48), None, "unknown transport");
    assert_eq!(
        NetDestination::decode(1 << 56),
        None,
        "bits above the transport"
    );
    let event = crate::AuditEvent::new(
        crate::AuditKind::Authorize,
        crate::HolderId(12),
        ResourceRef {
            class: ResourceClass::Network,
            id: destination.encode(),
            instance_generation: 0,
        },
        Rights::NET_CONNECT,
    )
    .refused(PolicyRefusal::DestinationDenied);
    assert_eq!(NetDestination::of_refusal(&event), Some(destination));
    let mut line = std::string::String::new();
    crate::format_audit_line(&event, &mut line).unwrap();
    assert!(
        line.contains(" to=10.77.0.50:53/udp op=net_connect outcome=destination-denied "),
        "{line}"
    );
    let allowed = event.with_result(Ok(()));
    assert_eq!(NetDestination::of_refusal(&allowed), None);
}
