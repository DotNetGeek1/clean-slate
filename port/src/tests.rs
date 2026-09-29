use clean_slate_capability::{
    revoke_holder_tree, validate_delegation, CapabilityError, CapabilityHandle, CapabilityRecord,
    CapabilityState, CapabilityTable, HolderId, Provenance, ResourceClass, ResourceRef, Rights,
};
use clean_slate_native_abi::port::{
    PORT_MAX_CONNECTIONS, PORT_MAX_EVENT_QUEUE_DEPTH, PORT_MAX_OUTSTANDING_PER_CONNECTION,
    PORT_MAX_REQUEST_QUEUE_DEPTH, PORT_ROLE_CONNECT, PORT_ROLE_SERVE,
};
use clean_slate_native_abi::status::{
    STATUS_EACCES, STATUS_EAGAIN, STATUS_ECONNREFUSED, STATUS_EINVAL, STATUS_ENOSPC, STATUS_EPIPE,
    STATUS_ESTALE,
};
use clean_slate_native_abi::{
    port_rights_for, ConnectionId, EventKind, PortEventRecord, PortParamError, PortParams,
    PortRecvRecord, RecvKind, SharedBufferId,
};

use crate::{
    Caller, Effect, Effects, PortCore, PortCounts, PortError, PortKey, RegistrationError, Transfer,
};

type Core = PortCore<2, 8, u32>;
const CAPS: usize = 24;

const SERVICE: u64 = 7;
const INSTANCE: u64 = 3;
const RESOURCE: ResourceRef = ResourceRef::graphics(SERVICE, INSTANCE);
const GRAPHICS: u64 = ResourceClass::Graphics as u64;
const WORK_SET: u32 = 0x5a;
const REQUEST_BIT: u32 = 0;
const NOTICE_BIT: u32 = 1;

const fn caller(pid: u64, generation: u64) -> Caller {
    Caller {
        holder: HolderId(pid),
        generation,
        domain: pid,
    }
}

const SERVER: Caller = caller(1, 11);
const A: Caller = caller(2, 22);
const B: Caller = caller(3, 33);
const C: Caller = caller(4, 44);
const IMPOSTOR: Caller = caller(9, 99);

const fn params(
    max_connections: u16,
    max_connections_per_holder: u16,
    request_depth: u16,
    max_outstanding: u16,
    event_depth: u16,
) -> PortParams {
    PortParams {
        event_depth,
        request_depth,
        max_connections,
        max_outstanding,
        max_connections_per_holder,
    }
}

/// The lane's small parameters: connections 3, per-holder 1, requests 4, outstanding 2, events 2.
const SMALL: PortParams = params(3, 1, 4, 2, 2);

fn frame(byte: u8) -> [u8; 64] {
    [byte; 64]
}

fn snapshot<const N: usize>(table: &CapabilityTable<N>) -> (Vec<CapabilityRecord>, usize) {
    (
        (0..N).map(|slot| *table.record_at(slot)).collect(),
        table.live_count(),
    )
}

struct World {
    core: Box<Core>,
    table: CapabilityTable<CAPS>,
    effects: Effects<u32>,
    key: PortKey,
    serve: u64,
}

impl World {
    fn new(params: PortParams) -> Self {
        let mut core = Box::new(Core::new());
        let key = core
            .register(RESOURCE, SERVER.holder, SERVER.generation, params)
            .expect("register");
        let mut world = Self {
            core,
            table: CapabilityTable::new(),
            effects: Effects::new(),
            key,
            serve: 0,
        };
        world.serve = world.grant(SERVER.holder, RESOURCE, Rights::GFX_SERVE);
        world
    }

    fn grant(&mut self, holder: HolderId, resource: ResourceRef, rights: Rights) -> u64 {
        self.table
            .grant(holder, resource, rights, Provenance::root(holder))
            .expect("grant")
            .encode()
    }

    fn client_cap(&mut self, who: Caller) -> u64 {
        self.grant(who.holder, RESOURCE, Rights::GFX_CONNECT)
    }

    fn connect_with(&mut self, who: Caller, cap: u64) -> Result<ConnectionId, PortError> {
        self.core.connect(&self.table, who, cap, GRAPHICS, SERVICE)
    }

    fn connect(&mut self, who: Caller) -> ConnectionId {
        let cap = self.client_cap(who);
        self.connect_with(who, cap).expect("connect")
    }

    fn send(&mut self, who: Caller, conn: ConnectionId, byte: u8) -> Result<(), PortError> {
        self.core.send(
            &mut self.table,
            who,
            conn.encode(),
            &frame(byte),
            None,
            &mut self.effects,
        )
    }

    fn send_transfer(
        &mut self,
        who: Caller,
        conn: ConnectionId,
        transfer: Transfer,
    ) -> Result<(), PortError> {
        self.core.send(
            &mut self.table,
            who,
            conn.encode(),
            &frame(0xee),
            Some(transfer),
            &mut self.effects,
        )
    }

    fn recv(&mut self) -> Result<PortRecvRecord, PortError> {
        self.core
            .recv(&self.table, SERVER, self.serve, &mut self.effects)
    }

    fn post(&mut self, conn: ConnectionId, byte: u8) -> Result<(), PortError> {
        self.core.post(
            &self.table,
            SERVER,
            self.serve,
            conn.encode(),
            &frame(byte),
            &mut self.effects,
        )
    }

    fn disconnect(&mut self, conn: ConnectionId, reason: u32) -> Result<(), PortError> {
        self.core.disconnect(
            &mut self.table,
            SERVER,
            self.serve,
            conn.encode(),
            reason,
            &mut self.effects,
        )
    }

    fn event(&mut self, who: Caller, conn: ConnectionId) -> Result<PortEventRecord, PortError> {
        self.core
            .recv_event(&mut self.table, who, conn.encode(), &mut self.effects)
    }

    fn close(&mut self, who: Caller, conn: ConnectionId, reason: u32) -> Result<(), PortError> {
        self.core.close(
            &mut self.table,
            who,
            conn.encode(),
            reason,
            &mut self.effects,
        )
    }

    fn bind(&mut self) {
        self.core
            .bind_wake(
                &self.table,
                SERVER,
                self.serve,
                WORK_SET,
                REQUEST_BIT,
                NOTICE_BIT,
                &mut self.effects,
            )
            .expect("bind");
        self.take_effects();
    }

    fn exit(&mut self, who: Caller) -> crate::PortReleaseCounts {
        self.core.on_holder_exit(
            &mut self.table,
            who.holder,
            who.generation,
            &mut self.effects,
        )
    }

    fn take_effects(&mut self) -> Vec<Effect<u32>> {
        assert!(!self.effects.overflowed());
        let effects = self.effects.iter().collect();
        self.effects.clear();
        effects
    }

    /// A root `READ|WRITE|DELEGATE` shared-buffer capability and its attested transfer.
    fn buffer(&mut self, who: Caller, slot: u16, byte_len: u64) -> Transfer {
        let id = SharedBufferId::new(slot, 1).unwrap();
        let raw = self.grant(
            who.holder,
            ResourceRef::shared_buffer(id.encode()),
            Rights::READ.union(Rights::WRITE).union(Rights::DELEGATE),
        );
        Transfer {
            handle: CapabilityHandle::decode(raw).unwrap(),
            attestation: Ok((id, byte_len)),
        }
    }
}

// ---- registration ----

#[test]
fn registration_rejects_no_port_class_bad_params_duplicates_and_non_processes() {
    let mut core = Core::new();
    let ok = SMALL;
    assert_eq!(
        core.register(ResourceRef::shared_buffer(1 << 16), SERVER.holder, 11, ok),
        Err(RegistrationError::ClassHasNoPort)
    );
    let over = |field: &dyn Fn(&mut PortParams)| {
        let mut p = params(
            PORT_MAX_CONNECTIONS as u16,
            PORT_MAX_CONNECTIONS as u16,
            PORT_MAX_REQUEST_QUEUE_DEPTH as u16,
            PORT_MAX_OUTSTANDING_PER_CONNECTION as u16,
            PORT_MAX_EVENT_QUEUE_DEPTH as u16,
        );
        field(&mut p);
        p
    };
    for (bad, error) in [
        (over(&|p| p.event_depth += 1), PortParamError::EventDepth),
        (
            over(&|p| p.request_depth += 1),
            PortParamError::RequestDepth,
        ),
        (
            over(&|p| p.max_connections += 1),
            PortParamError::Connections,
        ),
        (
            over(&|p| p.max_outstanding += 1),
            PortParamError::Outstanding,
        ),
        (
            over(&|p| p.max_connections_per_holder += 1),
            PortParamError::PerHolder,
        ),
        (params(3, 1, 2, 3, 2), PortParamError::Inconsistent),
        (params(3, 4, 4, 2, 2), PortParamError::Inconsistent),
        (params(0, 1, 4, 2, 2), PortParamError::Connections),
    ] {
        assert_eq!(
            core.register(RESOURCE, SERVER.holder, 11, bad),
            Err(RegistrationError::Params(error))
        );
    }
    assert!(core
        .register(RESOURCE, SERVER.holder, 11, over(&|_| {}))
        .is_ok());
    assert_eq!(
        core.register(ResourceRef::graphics(SERVICE, 9), SERVER.holder, 11, ok),
        Err(RegistrationError::AlreadyRegistered)
    );
    assert_eq!(
        core.register(ResourceRef::graphics(8, 1), HolderId::KERNEL, 11, ok),
        Err(RegistrationError::ServerNotLive)
    );
    assert_eq!(
        core.register(ResourceRef::graphics(8, 1), SERVER.holder, 0, ok),
        Err(RegistrationError::ServerNotLive)
    );
    assert!(core
        .register(ResourceRef::graphics(8, 1), SERVER.holder, 11, ok)
        .is_ok());
    assert_eq!(
        core.register(ResourceRef::graphics(9, 1), SERVER.holder, 11, ok),
        Err(RegistrationError::RegistryFull)
    );
}

#[test]
fn port_rights_table_keeps_serve_root_only_and_disjoint_from_connect() {
    for raw in 0..=u8::MAX {
        let Some(class) = ResourceClass::from_u8(raw) else {
            continue;
        };
        let Some(rights) = port_rights_for(class) else {
            continue;
        };
        assert!(rights.serve.is_subset_of(Rights::root_only_for(class)));
        assert!(!rights.connect.intersects(rights.serve));
        assert!(rights.connect.is_subset_of(Rights::valid_for(class)));
        assert!(rights.serve.is_subset_of(Rights::valid_for(class)));
        let mut table = CapabilityTable::<4>::new();
        let handle = table
            .grant(
                SERVER.holder,
                ResourceRef {
                    class,
                    id: 1,
                    instance_generation: 1,
                },
                rights.serve.union(Rights::DELEGATE),
                Provenance::root(SERVER.holder),
            )
            .unwrap();
        let record = table.record(handle).unwrap();
        assert_eq!(
            validate_delegation(&record, handle, SERVER.holder, rights.serve),
            Err(CapabilityError::NotDelegable)
        );
    }
}

#[test]
fn port_retires_its_slot_at_the_last_generation() {
    let mut core = PortCore::<1, 1, u32>::new();
    let mut table = CapabilityTable::<4>::new();
    let mut effects = Effects::new();
    core.set_port_generation_for_test(0, u32::MAX - 1);
    let key = core.register(RESOURCE, SERVER.holder, 11, SMALL).unwrap();
    assert_eq!(key.generation(), u32::MAX);
    assert!(core.unregister(&mut table, key, &mut effects));
    assert!(!core.unregister(&mut table, key, &mut effects));
    assert_eq!(
        core.register(RESOURCE, SERVER.holder, 11, SMALL),
        Err(RegistrationError::RegistryFull)
    );
}

#[test]
fn statuses_map_one_to_one() {
    let all = [
        (PortError::Invalid, STATUS_EINVAL),
        (PortError::Denied, STATUS_EACCES),
        (PortError::Stale, STATUS_ESTALE),
        (PortError::NoSpace, STATUS_ENOSPC),
        (PortError::WouldBlock, STATUS_EAGAIN),
        (PortError::PeerClosed, STATUS_EPIPE),
        (PortError::Refused, STATUS_ECONNREFUSED),
    ];
    for (i, (error, status)) in all.iter().enumerate() {
        assert_eq!(error.status(), *status);
        for (other, _) in &all[i + 1..] {
            assert_ne!(error.status(), other.status());
        }
    }
}

// ---- CONNECT and FIND_HANDLE ----

#[test]
fn connect_check_order_reports_the_first_failing_step() {
    let mut w = World::new(SMALL);
    let a_cap = w.client_cap(A);
    let conn = |w: &mut World, who: Caller, cap: u64, class: u64, id: u64| {
        w.core.connect(&w.table, who, cap, class, id)
    };

    // 1. class
    for class in [0, 200, 1 << 8, ResourceClass::SharedBuffer as u64] {
        assert_eq!(
            conn(&mut w, A, a_cap, class, SERVICE),
            Err(PortError::Invalid)
        );
    }
    // 2. caller, handle encoding
    assert_eq!(
        conn(&mut w, caller(0, 5), a_cap, GRAPHICS, SERVICE),
        Err(PortError::Denied)
    );
    assert_eq!(
        conn(&mut w, caller(2, 0), a_cap, GRAPHICS, SERVICE),
        Err(PortError::Denied)
    );
    assert_eq!(
        conn(&mut w, A, 0, GRAPHICS, SERVICE),
        Err(PortError::Invalid)
    );
    // 3. record
    let never_used = CapabilityHandle::new(15, 1).encode();
    assert_eq!(
        conn(&mut w, A, never_used, GRAPHICS, SERVICE),
        Err(PortError::Invalid)
    );
    let released = w.client_cap(A);
    let released_handle = CapabilityHandle::decode(released).unwrap();
    w.table.revoke(released_handle).unwrap();
    w.table.release_slot(usize::from(released_handle.slot));
    assert_eq!(
        conn(&mut w, A, released, GRAPHICS, SERVICE),
        Err(PortError::Stale)
    );
    // 4. port
    assert_eq!(
        conn(&mut w, A, a_cap, GRAPHICS, 99),
        Err(PortError::Refused)
    );
    // 5. different resource
    let other_id = w.grant(
        A.holder,
        ResourceRef::graphics(8, INSTANCE),
        Rights::GFX_CONNECT,
    );
    assert_eq!(
        conn(&mut w, A, other_id, GRAPHICS, SERVICE),
        Err(PortError::Denied)
    );
    let buffer = w.grant(
        A.holder,
        ResourceRef::shared_buffer(SERVICE),
        Rights::READ.union(Rights::DELEGATE),
    );
    assert_eq!(
        conn(&mut w, A, buffer, GRAPHICS, SERVICE),
        Err(PortError::Denied)
    );
    // 6. old instance
    let old = w.grant(
        A.holder,
        ResourceRef::graphics(SERVICE, INSTANCE - 1),
        Rights::GFX_CONNECT,
    );
    assert_eq!(
        conn(&mut w, A, old, GRAPHICS, SERVICE),
        Err(PortError::Stale)
    );
    // 7. authorise
    let revoked = w.client_cap(A);
    w.table
        .revoke(CapabilityHandle::decode(revoked).unwrap())
        .unwrap();
    assert_eq!(
        conn(&mut w, A, revoked, GRAPHICS, SERVICE),
        Err(PortError::Stale)
    );
    let b_cap = w.client_cap(B);
    assert_eq!(
        conn(&mut w, A, b_cap, GRAPHICS, SERVICE),
        Err(PortError::Denied)
    );
    let shell_only = w.grant(A.holder, RESOURCE, Rights::GFX_SHELL);
    assert_eq!(
        conn(&mut w, A, shell_only, GRAPHICS, SERVICE),
        Err(PortError::Denied)
    );
    assert_eq!(
        w.core.global_counts(),
        PortCounts {
            ports: 1,
            ..PortCounts::default()
        }
    );
    // 8. per holder
    let first = conn(&mut w, A, a_cap, GRAPHICS, SERVICE).unwrap();
    assert_eq!(
        conn(&mut w, A, a_cap, GRAPHICS, SERVICE),
        Err(PortError::NoSpace)
    );
    // 9. port limit (3)
    w.connect(B);
    w.connect(C);
    let d = caller(5, 55);
    let d_cap = w.client_cap(d);
    assert_eq!(
        conn(&mut w, d, d_cap, GRAPHICS, SERVICE),
        Err(PortError::NoSpace)
    );
    // Recovery: the slot frees only once the server has received the close notice.
    w.close(A, first, 0).unwrap();
    assert_eq!(
        conn(&mut w, d, d_cap, GRAPHICS, SERVICE),
        Err(PortError::NoSpace)
    );
    assert_eq!(w.recv().unwrap().kind, RecvKind::ClientClosed);
    assert!(conn(&mut w, d, d_cap, GRAPHICS, SERVICE).is_ok());
}

#[test]
fn connect_fails_closed_when_the_shared_pool_is_exhausted() {
    let mut w = World::new(params(8, 8, 4, 2, 2));
    let other = ResourceRef::graphics(8, 1);
    w.core
        .register(other, C.holder, C.generation, params(8, 8, 4, 2, 2))
        .unwrap();
    for _ in 0..8 {
        w.connect(A);
    }
    let cap = w.grant(B.holder, other, Rights::GFX_CONNECT);
    assert_eq!(
        w.core.connect(&w.table, B, cap, GRAPHICS, 8),
        Err(PortError::NoSpace)
    );
}

#[test]
fn find_handle_returns_the_callers_live_role_handle() {
    let mut w = World::new(SMALL);
    let find = |w: &World, who: Caller, class: u64, id: u64, role: u64| {
        w.core.find_handle(&w.table, who, class, id, role)
    };
    assert_eq!(
        find(&w, A, GRAPHICS, SERVICE, PORT_ROLE_CONNECT),
        Err(PortError::Denied)
    );
    let a_cap = w.client_cap(A);
    assert_eq!(find(&w, A, GRAPHICS, SERVICE, PORT_ROLE_CONNECT), Ok(a_cap));
    assert_eq!(
        find(&w, A, GRAPHICS, SERVICE, PORT_ROLE_SERVE),
        Err(PortError::Denied)
    );
    assert_eq!(
        find(&w, SERVER, GRAPHICS, SERVICE, PORT_ROLE_SERVE),
        Ok(w.serve)
    );
    assert_eq!(find(&w, A, GRAPHICS, SERVICE, 3), Err(PortError::Invalid));
    assert_eq!(
        find(&w, A, 8, SERVICE, PORT_ROLE_CONNECT),
        Err(PortError::Invalid)
    );
    assert_eq!(
        find(&w, A, GRAPHICS, 99, PORT_ROLE_CONNECT),
        Err(PortError::Refused)
    );
    assert_eq!(
        find(&w, caller(0, 1), GRAPHICS, SERVICE, PORT_ROLE_CONNECT),
        Err(PortError::Denied)
    );
    w.table
        .revoke(CapabilityHandle::decode(a_cap).unwrap())
        .unwrap();
    assert_eq!(
        find(&w, A, GRAPHICS, SERVICE, PORT_ROLE_CONNECT),
        Err(PortError::Denied)
    );
}

// ---- serve authorisation ----

#[test]
fn serve_check_order_for_every_server_operation() {
    let mut w = World::new(SMALL);
    let conn = w.connect(A);
    let impostor_serve = w.grant(IMPOSTOR.holder, RESOURCE, Rights::GFX_SERVE);
    let connect_only = w.grant(SERVER.holder, RESOURCE, Rights::GFX_CONNECT);
    let no_port = w.grant(
        SERVER.holder,
        ResourceRef::graphics(99, 1),
        Rights::GFX_SERVE,
    );
    let old_instance = w.grant(
        SERVER.holder,
        ResourceRef::graphics(SERVICE, INSTANCE - 1),
        Rights::GFX_SERVE,
    );
    let restarted_pid = caller(SERVER.holder.0, SERVER.generation + 1);
    let cases = [
        (SERVER, 0, PortError::Invalid),
        (
            SERVER,
            CapabilityHandle::new(15, 1).encode(),
            PortError::Invalid,
        ),
        (SERVER, no_port, PortError::Denied),
        (SERVER, old_instance, PortError::Stale),
        (IMPOSTOR, impostor_serve, PortError::Denied),
        (restarted_pid, w.serve, PortError::Denied),
        (SERVER, connect_only, PortError::Denied),
    ];
    for (who, serve, expected) in cases {
        let t = &mut w.table;
        let e = &mut w.effects;
        assert_eq!(w.core.recv(t, who, serve, e).err(), Some(expected));
        assert_eq!(
            w.core.post(t, who, serve, conn.encode(), &frame(1), e),
            Err(expected)
        );
        assert_eq!(
            w.core.disconnect(t, who, serve, conn.encode(), 0, e),
            Err(expected)
        );
        assert_eq!(
            w.core.bind_wake(t, who, serve, WORK_SET, 0, 1, e),
            Err(expected)
        );
        assert_eq!(w.core.serve_port_key(t, who, serve), Err(expected));
    }
    assert!(w.take_effects().is_empty());
    assert_eq!(w.event(A, conn), Err(PortError::WouldBlock));

    // The server revoking its own serve capability.
    w.table
        .revoke(CapabilityHandle::decode(w.serve).unwrap())
        .unwrap();
    assert_eq!(w.recv().err(), Some(PortError::Stale));
}

// ---- SEND ----

#[test]
fn send_check_order_and_states() {
    let mut w = World::new(SMALL);
    let a = w.connect(A);
    let b = w.connect(B);
    let raw = |w: &mut World, who: Caller, conn: u64| {
        w.core
            .send(&mut w.table, who, conn, &frame(1), None, &mut w.effects)
    };
    assert_eq!(
        raw(&mut w, caller(0, 1), a.encode()),
        Err(PortError::Denied)
    );
    assert_eq!(raw(&mut w, A, 0), Err(PortError::Invalid));
    assert_eq!(
        raw(&mut w, A, a.encode() | 1 << 48),
        Err(PortError::Invalid)
    );
    assert_eq!(
        raw(&mut w, A, ConnectionId::new(7, 1).unwrap().encode()),
        Err(PortError::Stale)
    );
    assert_eq!(
        raw(&mut w, A, ConnectionId::new(99, 1).unwrap().encode()),
        Err(PortError::Stale)
    );
    assert_eq!(
        raw(
            &mut w,
            A,
            ConnectionId::new(a.slot(), a.generation() + 1)
                .unwrap()
                .encode()
        ),
        Err(PortError::Stale)
    );
    assert_eq!(w.send(A, b, 1), Err(PortError::Denied));
    assert_eq!(w.send(caller(2, 23), a, 1), Err(PortError::Stale));
    assert!(w.take_effects().is_empty());

    w.disconnect(b, 5).unwrap();
    assert_eq!(w.send(B, b, 1), Err(PortError::PeerClosed));
    w.close(A, a, 0).unwrap();
    assert_eq!(w.send(A, a, 1), Err(PortError::Stale));
    w.exit(SERVER);
    assert_eq!(w.send(B, b, 1), Err(PortError::Stale), "ServerGone");
}

#[test]
fn revoked_client_capability_closes_the_connection_with_a_notice() {
    let mut w = World::new(SMALL);
    w.bind();
    let cap = w.client_cap(A);
    let a = w.connect_with(A, cap).unwrap();
    w.send(A, a, 1).unwrap();
    w.take_effects();
    w.table
        .revoke(CapabilityHandle::decode(cap).unwrap())
        .unwrap();
    assert_eq!(w.send(A, a, 2), Err(PortError::Stale));
    let effects = w.take_effects();
    assert!(effects.contains(&Effect::WakeServer(w.key)));
    assert!(effects.contains(&Effect::Signal(WORK_SET, NOTICE_BIT)));
    let notice = w.recv().unwrap();
    assert_eq!(notice.kind, RecvKind::ClientRevoked);
    assert_eq!(notice.envelope.connection, a);
    assert_eq!(notice.envelope.pid, A.holder.0);
    assert_eq!(
        w.recv().err(),
        Some(PortError::WouldBlock),
        "request purged"
    );
    assert_eq!(w.event(A, a), Err(PortError::Stale));

    let cap = w.client_cap(B);
    let b = w.connect_with(B, cap).unwrap();
    w.table
        .revoke(CapabilityHandle::decode(cap).unwrap())
        .unwrap();
    assert_eq!(w.event(B, b), Err(PortError::Stale));
    assert_eq!(w.recv().unwrap().kind, RecvKind::ClientRevoked);
}

#[test]
fn envelope_is_kernel_stamped_and_frames_are_opaque() {
    let mut w = World::new(SMALL);
    let a_cap = w.grant(
        A.holder,
        RESOURCE,
        Rights::GFX_CONNECT.union(Rights::GFX_SHELL),
    );
    let a = w.connect_with(A, a_cap).unwrap();
    let b = w.connect(B);
    let mut forged = [0u8; 64];
    forged[0..8].copy_from_slice(&b.encode().to_le_bytes());
    forged[8..16].copy_from_slice(&B.holder.0.to_le_bytes());
    forged[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
    forged[44] = 1;
    w.core
        .send(&mut w.table, A, a.encode(), &forged, None, &mut w.effects)
        .unwrap();
    w.send(B, b, 2).unwrap();
    let first = w.recv().unwrap();
    assert_eq!(first.kind, RecvKind::Request);
    assert_eq!(first.frame, forged);
    assert_eq!(first.envelope.connection, a);
    assert_eq!(first.envelope.pid, A.holder.0);
    assert_eq!(first.envelope.domain, A.domain);
    assert_eq!(first.envelope.instance_generation, A.generation);
    assert_eq!(
        first.envelope.rights,
        (Rights::GFX_CONNECT.union(Rights::GFX_SHELL)).bits()
    );
    assert_eq!(first.envelope.transfer, None);
    let second = w.recv().unwrap();
    assert_eq!(second.envelope.pid, B.holder.0);
    assert_eq!(second.envelope.rights, Rights::GFX_CONNECT.bits());
    assert!(second.envelope.kernel_seq > first.envelope.kernel_seq);
    let encoded = PortRecvRecord::decode(&first.encode()).unwrap();
    assert_eq!(encoded, first);
}

#[test]
fn requests_are_fifo_across_connections_and_notices_come_first() {
    let mut w = World::new(params(3, 1, 4, 2, 2));
    let a = w.connect(A);
    let b = w.connect(B);
    let c = w.connect(C);
    w.send(A, a, 1).unwrap();
    w.send(B, b, 2).unwrap();
    w.send(A, a, 3).unwrap();
    w.send(C, c, 4).unwrap();
    w.close(C, c, 70).unwrap();
    w.close(B, b, 71).unwrap();
    let kinds: Vec<(RecvKind, u32, u8)> = (0..4)
        .map(|_| {
            let record = w.recv().unwrap();
            (record.kind, record.reason, record.frame[0])
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            (RecvKind::ClientClosed, 70, 0),
            (RecvKind::ClientClosed, 71, 0),
            (RecvKind::Request, 0, 1),
            (RecvKind::Request, 0, 3),
        ]
    );
    assert_eq!(w.recv().err(), Some(PortError::WouldBlock));
}

#[test]
fn capacity_limits_refuse_deterministically_and_recover() {
    let mut w = World::new(SMALL);
    let a = w.connect(A);
    let b = w.connect(B);
    // Outstanding (2).
    w.send(A, a, 1).unwrap();
    w.send(A, a, 2).unwrap();
    assert_eq!(w.send(A, a, 3), Err(PortError::WouldBlock));
    w.recv().unwrap();
    assert!(w.take_effects().contains(&Effect::WakeSendSpace(w.key)));
    w.send(A, a, 3).unwrap();
    // Request pool (4).
    w.send(B, b, 4).unwrap();
    w.send(B, b, 5).unwrap();
    assert_eq!(w.core.global_counts().queued_requests, 4);
    let c = w.connect(C);
    assert_eq!(w.send(C, c, 6), Err(PortError::WouldBlock));
    w.recv().unwrap();
    w.send(C, c, 6).unwrap();
    // Event ring (2).
    w.post(b, 1).unwrap();
    w.post(b, 2).unwrap();
    assert_eq!(w.post(b, 3), Err(PortError::WouldBlock));
    assert_eq!(w.event(B, b).unwrap().frame[0], 1);
    w.post(b, 3).unwrap();
    assert_eq!(w.event(B, b).unwrap().frame[0], 2);
    assert_eq!(w.event(B, b).unwrap().frame[0], 3);
    assert_eq!(w.event(B, b), Err(PortError::WouldBlock));
}

#[test]
fn effects_address_only_the_target_connection() {
    let mut w = World::new(SMALL);
    w.bind();
    let a = w.connect(A);
    let b = w.connect(B);
    w.post(a, 9).unwrap();
    assert_eq!(w.take_effects(), vec![Effect::WakeConnection(a)]);
    assert_eq!(w.event(B, b), Err(PortError::WouldBlock));
    assert_eq!(w.event(A, a).unwrap().frame, frame(9));
    w.send(B, b, 1).unwrap();
    assert_eq!(
        w.take_effects(),
        vec![
            Effect::WakeServer(w.key),
            Effect::Signal(WORK_SET, REQUEST_BIT)
        ]
    );
    w.recv().unwrap();
    assert_eq!(w.take_effects(), vec![Effect::WakeSendSpace(w.key)]);
    w.disconnect(b, 3).unwrap();
    assert_eq!(
        w.take_effects(),
        vec![Effect::WakeConnection(b), Effect::WakeSendSpace(w.key)]
    );
    w.close(A, a, 0).unwrap();
    assert_eq!(
        w.take_effects(),
        vec![
            Effect::WakeServer(w.key),
            Effect::Signal(WORK_SET, NOTICE_BIT),
            Effect::WakeSendSpace(w.key),
            Effect::WakeConnection(a),
        ]
    );
}

#[test]
fn bind_wake_validates_bits_replaces_and_signals_pending_sources() {
    let mut w = World::new(SMALL);
    let a = w.connect(A);
    let b = w.connect(B);
    let bind = |w: &mut World, target: u32, request_bit: u32, notice_bit: u32| {
        w.core.bind_wake(
            &w.table,
            SERVER,
            w.serve,
            target,
            request_bit,
            notice_bit,
            &mut w.effects,
        )
    };
    assert_eq!(bind(&mut w, 1, 32, 0), Err(PortError::Invalid));
    assert_eq!(bind(&mut w, 1, 0, 32), Err(PortError::Invalid));
    bind(&mut w, 1, 0, 1).unwrap();
    assert!(w.take_effects().is_empty(), "nothing pending");
    w.send(A, a, 1).unwrap();
    w.close(B, b, 0).unwrap();
    w.take_effects();
    bind(&mut w, 2, 5, 6).unwrap();
    assert_eq!(
        w.take_effects(),
        vec![Effect::Signal(2, 5), Effect::Signal(2, 6)]
    );
    let c = w.connect(C);
    w.send(C, c, 1).unwrap();
    assert!(w.take_effects().contains(&Effect::Signal(2, 5)));
}

// ---- DISCONNECT, CLOSE and RECV_EVENT transitions ----

#[test]
fn disconnect_purges_requests_keeps_events_then_delivers_the_reason() {
    let mut w = World::new(SMALL);
    let a = w.connect(A);
    w.send(A, a, 1).unwrap();
    w.post(a, 4).unwrap();
    w.disconnect(a, 77).unwrap();
    assert_eq!(w.core.global_counts().queued_requests, 0);
    assert_eq!(w.recv().err(), Some(PortError::WouldBlock));
    assert_eq!(w.post(a, 5), Err(PortError::Stale));
    assert_eq!(w.disconnect(a, 1), Err(PortError::Stale));
    assert_eq!(w.send(A, a, 2), Err(PortError::PeerClosed));
    assert!(w.core.event_ready(a.encode()));
    assert_eq!(w.event(A, a).unwrap().frame[0], 4);
    let last = w.event(A, a).unwrap();
    assert_eq!((last.kind, last.reason), (EventKind::Disconnected, 77));
    assert_eq!(w.event(A, a), Err(PortError::Stale));
    assert_eq!(w.core.global_counts().connections, 0);
}

#[test]
fn client_close_is_a_notice_and_server_ops_on_it_are_peer_closed() {
    let mut w = World::new(SMALL);
    let a = w.connect(A);
    w.post(a, 1).unwrap();
    w.close(A, a, 12).unwrap();
    assert_eq!(w.close(A, a, 12), Err(PortError::Stale));
    assert_eq!(w.event(A, a), Err(PortError::Stale));
    assert_eq!(w.post(a, 2), Err(PortError::PeerClosed));
    assert_eq!(w.disconnect(a, 0), Err(PortError::PeerClosed));
    assert_eq!(w.core.global_counts().queued_events, 0, "events discarded");
    let notice = w.recv().unwrap();
    assert_eq!((notice.kind, notice.reason), (RecvKind::ClientClosed, 12));
    assert_eq!(notice.envelope.rights, 0);
    assert_eq!(w.post(a, 2), Err(PortError::Stale), "slot freed");

    let b = w.connect(B);
    w.disconnect(b, 0).unwrap();
    w.close(B, b, 0).unwrap();
    assert_eq!(w.core.global_counts().connections, 0, "ServerClosed → Free");
}

#[test]
fn server_exit_makes_connections_server_gone_and_frees_notices() {
    let mut w = World::new(SMALL);
    let a = w.connect(A);
    let b = w.connect(B);
    let c = w.connect(C);
    w.send(A, a, 1).unwrap();
    w.post(a, 2).unwrap();
    w.disconnect(b, 3).unwrap();
    w.close(C, c, 0).unwrap();
    w.take_effects();
    let counts = w.exit(SERVER);
    assert_eq!(counts.served_ports, 1);
    let effects = w.take_effects();
    for expected in [
        Effect::WakeConnection(a),
        Effect::WakeConnection(b),
        Effect::WakeSendSpace(w.key),
        Effect::WakeServer(w.key),
    ] {
        assert!(effects.contains(&expected), "{expected:?}");
    }
    assert!(!effects.contains(&Effect::WakeConnection(c)));
    assert_eq!(
        w.core.global_counts(),
        PortCounts {
            connections: 2,
            ..PortCounts::default()
        }
    );
    let gone = w.event(A, a).unwrap();
    assert_eq!(gone.kind, EventKind::ServerGone, "queued event discarded");
    assert_eq!(w.event(B, b).unwrap().kind, EventKind::ServerGone);
    assert_eq!(w.event(A, a), Err(PortError::Stale));
    assert_eq!(w.core.global_counts(), PortCounts::default());
    let cap = w.client_cap(A);
    assert_eq!(w.connect_with(A, cap), Err(PortError::Refused));
}

#[test]
fn client_exit_leaves_notices_and_frees_terminal_connections() {
    let mut w = World::new(params(3, 2, 4, 2, 2));
    let a1 = w.connect(A);
    let a2 = w.connect(A);
    w.send(A, a1, 1).unwrap();
    w.disconnect(a2, 0).unwrap();
    assert_eq!(w.core.counts_for(A.holder).port_connections, 2);
    let counts = w.exit(A);
    assert_eq!(counts.client_connections, 2);
    assert_eq!(counts.served_ports, 0);
    assert_eq!(w.core.counts_for(A.holder), Default::default());
    let notice = w.recv().unwrap();
    assert_eq!(notice.kind, RecvKind::ClientExited);
    assert_eq!(notice.envelope.connection, a1);
    assert_eq!(w.recv().err(), Some(PortError::WouldBlock));
    assert_eq!(
        w.core.global_counts(),
        PortCounts {
            ports: 1,
            ..PortCounts::default()
        }
    );
}

#[test]
fn holder_exit_releases_only_the_exiting_instance_generation() {
    let mut w = World::new(SMALL);
    w.connect(A);
    let stale_client = Caller {
        generation: A.generation + 1,
        ..A
    };
    let stale_server = Caller {
        generation: SERVER.generation + 1,
        ..SERVER
    };
    assert_eq!(w.exit(stale_client), Default::default());
    assert_eq!(w.exit(stale_server), Default::default());
    assert_eq!(w.core.counts_for(A.holder).port_connections, 1);
    assert_eq!(w.core.global_counts().ports, 1);
    assert_eq!(w.exit(A).client_connections, 1);
    assert_eq!(w.exit(SERVER).served_ports, 1);
}

#[test]
fn reconnect_and_reregistration_leave_old_ids_stale() {
    let mut w = World::new(SMALL);
    let a_cap = w.client_cap(A);
    let old = w.connect_with(A, a_cap).unwrap();
    w.close(A, old, 0).unwrap();
    w.recv().unwrap();
    let new = w.connect_with(A, a_cap).unwrap();
    assert_eq!(new.slot(), old.slot());
    assert_ne!(new, old);
    assert_eq!(w.send(A, old, 1), Err(PortError::Stale));
    assert_eq!(w.event(A, old), Err(PortError::Stale));

    w.exit(SERVER);
    let restarted = ResourceRef::graphics(SERVICE, INSTANCE + 1);
    let key = w
        .core
        .register(restarted, SERVER.holder, SERVER.generation + 1, SMALL)
        .unwrap();
    assert_ne!(key, w.key);
    assert_eq!(key.slot(), w.key.slot());
    assert_eq!(w.event(A, new).unwrap().kind, EventKind::ServerGone);
    assert_eq!(w.send(A, new, 1), Err(PortError::Stale));
    assert_eq!(
        w.connect_with(A, a_cap),
        Err(PortError::Stale),
        "old instance cap"
    );
    let fresh = w.grant(A.holder, restarted, Rights::GFX_CONNECT);
    assert!(w.connect_with(A, fresh).is_ok());
}

#[test]
fn connection_slot_retires_at_the_last_generation() {
    let mut core = PortCore::<1, 1, u32>::new();
    let mut table = CapabilityTable::<4>::new();
    let mut effects = Effects::new();
    core.register(RESOURCE, SERVER.holder, SERVER.generation, SMALL)
        .unwrap();
    let cap = table
        .grant(
            A.holder,
            RESOURCE,
            Rights::GFX_CONNECT,
            Provenance::root(A.holder),
        )
        .unwrap()
        .encode();
    core.set_connection_generation_for_test(0, u32::MAX - 1);
    let last = core.connect(&table, A, cap, GRAPHICS, SERVICE).unwrap();
    assert_eq!(last.generation(), u32::MAX);
    core.on_holder_exit(&mut table, A.holder, A.generation, &mut effects);
    let serve = table
        .grant(
            SERVER.holder,
            RESOURCE,
            Rights::GFX_SERVE,
            Provenance::root(SERVER.holder),
        )
        .unwrap()
        .encode();
    core.recv(&table, SERVER, serve, &mut effects).unwrap();
    assert_eq!(
        core.connect(&table, A, cap, GRAPHICS, SERVICE),
        Err(PortError::NoSpace)
    );
}

// ---- P2 transfer ----

#[test]
fn transfer_installs_a_read_only_child_held_by_the_server() {
    let mut w = World::new(SMALL);
    let a = w.connect(A);
    let transfer = w.buffer(A, 3, 4096);
    let live_before = w.table.live_count();
    w.send_transfer(A, a, transfer).unwrap();
    assert_eq!(w.table.live_count(), live_before + 1);
    assert_eq!(w.core.global_counts().undelivered_transfers, 1);
    let record = w.recv().unwrap();
    let cap = record.envelope.transfer.expect("transfer present");
    assert_eq!(cap.buffer_id, SharedBufferId::new(3, 1).unwrap().encode());
    assert_eq!(cap.byte_len, 4096);
    assert_eq!(cap.rights, Rights::READ.bits());
    assert_eq!(cap.class, ResourceClass::SharedBuffer as u8);
    let child = CapabilityHandle::decode(cap.handle).unwrap();
    let child_record = w.table.record(child).unwrap();
    assert_eq!(child_record.holder, SERVER.holder);
    assert_eq!(child_record.rights, Rights::READ);
    assert_eq!(child_record.provenance.parent, Some(transfer.handle));
    let resource = child_record.resource;
    assert!(w
        .table
        .authorize(SERVER.holder, child, resource, Rights::READ)
        .is_ok());
    for right in [Rights::WRITE, Rights::DELEGATE] {
        assert_eq!(
            w.table.authorize(SERVER.holder, child, resource, right),
            Err(CapabilityError::MissingRight)
        );
    }
    assert_eq!(w.core.global_counts().undelivered_transfers, 0);
    let encoded = PortRecvRecord::decode(&record.encode()).unwrap();
    assert_eq!(encoded.envelope.transfer, Some(cap));
}

#[test]
fn transfer_validation_denies_and_leaves_the_table_untouched() {
    let mut w = World::new(SMALL);
    let a = w.connect(A);
    let good = w.buffer(A, 1, 64);
    let b_buffer = w.buffer(B, 2, 64);
    let a_connect = w.client_cap(A);
    let no_delegate = w.grant(
        A.holder,
        ResourceRef::shared_buffer(SharedBufferId::new(4, 1).unwrap().encode()),
        Rights::READ.union(Rights::WRITE),
    );
    let bad_id = w.grant(
        A.holder,
        ResourceRef::shared_buffer(0),
        Rights::READ.union(Rights::DELEGATE),
    );
    let revoked = w.buffer(A, 5, 64);
    w.table.revoke(revoked.handle).unwrap();
    let released = w.buffer(A, 6, 64);
    w.table.revoke(released.handle).unwrap();
    w.table.release_slot(usize::from(released.handle.slot));
    let with = |handle: u64, attestation| Transfer {
        handle: CapabilityHandle::decode(handle).unwrap(),
        attestation,
    };
    let cases = [
        (b_buffer, PortError::Denied),
        (with(a_connect, good.attestation), PortError::Denied),
        (with(no_delegate, good.attestation), PortError::Denied),
        (with(bad_id, good.attestation), PortError::Invalid),
        (revoked, PortError::Stale),
        (released, PortError::Stale),
        (
            Transfer {
                attestation: Err(STATUS_ESTALE),
                ..good
            },
            PortError::Stale,
        ),
        (
            Transfer {
                attestation: Ok((SharedBufferId::new(1, 2).unwrap(), 64)),
                ..good
            },
            PortError::Stale,
        ),
    ];
    for (transfer, expected) in cases {
        let before = snapshot(&w.table);
        assert_eq!(
            w.send_transfer(A, a, transfer),
            Err(expected),
            "{transfer:?}"
        );
        assert_eq!(snapshot(&w.table), before, "{transfer:?}");
        assert_eq!(w.core.global_counts().queued_requests, 0);
        assert!(w.take_effects().is_empty());
    }
    w.send_transfer(A, a, good).unwrap();
}

#[test]
fn transfer_beyond_the_delegation_depth_is_no_space() {
    let mut w = World::new(SMALL);
    let a = w.connect(A);
    let root = w.buffer(A, 1, 64);
    let mut parent = root.handle;
    for _ in 0..clean_slate_capability::MAX_DELEGATION_DEPTH {
        parent = clean_slate_capability::delegate(
            &mut w.table,
            A.holder,
            parent,
            A.holder,
            Rights::READ.union(Rights::DELEGATE),
        )
        .unwrap();
    }
    let before = snapshot(&w.table);
    assert_eq!(
        w.send_transfer(
            A,
            a,
            Transfer {
                handle: parent,
                ..root
            }
        ),
        Err(PortError::NoSpace)
    );
    assert_eq!(snapshot(&w.table), before);
}

#[test]
fn transfer_in_flight_limits_per_connection_and_per_port() {
    let mut w = World::new(params(6, 1, 16, 4, 2));
    let a = w.connect(A);
    let first = w.buffer(A, 1, 64);
    let second = w.buffer(A, 2, 64);
    w.send_transfer(A, a, first).unwrap();
    let before = snapshot(&w.table);
    assert_eq!(w.send_transfer(A, a, second), Err(PortError::WouldBlock));
    assert_eq!(snapshot(&w.table), before);
    w.send(A, a, 1).unwrap();

    let clients = [B, C, caller(5, 55), caller(6, 66)];
    for (i, who) in clients.iter().enumerate() {
        let conn = w.connect(*who);
        let transfer = w.buffer(*who, 10 + i as u16, 64);
        let result = w.send_transfer(*who, conn, transfer);
        if i < 3 {
            result.unwrap();
        } else {
            assert_eq!(result, Err(PortError::WouldBlock), "port cap of 4");
            w.recv().unwrap();
            w.send_transfer(*who, conn, transfer).unwrap();
        }
    }
    assert_eq!(w.core.global_counts().undelivered_transfers, 4);
    w.core.check_invariants().unwrap();
}

#[test]
fn every_failing_send_with_a_transfer_leaves_the_table_byte_identical() {
    let mut w = World::new(SMALL);
    let a = w.connect(A);
    let b = w.connect(B);
    let c = w.connect(C);
    let transfer = w.buffer(A, 1, 64);
    let check = |w: &mut World, conn: ConnectionId, expected: PortError| {
        let before = snapshot(&w.table);
        let requests = w.core.global_counts();
        assert_eq!(w.send_transfer(A, conn, transfer), Err(expected));
        assert_eq!(snapshot(&w.table), before);
        assert_eq!(w.core.global_counts(), requests);
    };
    // Outstanding full.
    w.send(A, a, 1).unwrap();
    w.send(A, a, 2).unwrap();
    check(&mut w, a, PortError::WouldBlock);
    // Pool full (depth 4).
    w.recv().unwrap();
    w.send(B, b, 3).unwrap();
    w.send(C, c, 4).unwrap();
    w.send(C, c, 5).unwrap();
    check(&mut w, a, PortError::WouldBlock);
    // Stale and foreign ids, ServerClosed.
    check(
        &mut w,
        ConnectionId::new(a.slot(), a.generation() + 1).unwrap(),
        PortError::Stale,
    );
    check(&mut w, b, PortError::Denied);
    w.disconnect(a, 0).unwrap();
    check(&mut w, a, PortError::PeerClosed);
}

#[test]
fn a_full_table_reclaims_revoked_slots_and_otherwise_fails_exactly() {
    let mut w = World::new(SMALL);
    let a = w.connect(A);
    let transfer = w.buffer(A, 1, 64);
    let mut fillers = Vec::new();
    while w.table.live_count() < CAPS {
        fillers.push(w.grant(
            C.holder,
            ResourceRef::object(fillers.len() as u64),
            Rights::READ,
        ));
    }
    let before = snapshot(&w.table);
    assert_eq!(w.send_transfer(A, a, transfer), Err(PortError::NoSpace));
    assert_eq!(snapshot(&w.table), before, "nothing revoked to reclaim");
    assert_eq!(w.core.global_counts().queued_requests, 0);

    // T6: the only table effect of a failed or successful SEND is Revoked → Empty.
    let victim = CapabilityHandle::decode(fillers[0]).unwrap();
    w.table.revoke(victim).unwrap();
    assert_eq!(
        w.table.state_at(usize::from(victim.slot)),
        CapabilityState::Revoked
    );
    w.send_transfer(A, a, transfer).unwrap();
    assert_eq!(w.table.record(victim), Err(CapabilityError::StaleHandle));
}

#[test]
fn purge_releases_undelivered_children_but_never_a_reused_slot() {
    let mut w = World::new(SMALL);
    let a = w.connect(A);
    let first = w.buffer(A, 1, 64);
    let baseline = w.table.live_count();
    w.send_transfer(A, a, first).unwrap();
    let child = w.core.undelivered_children_for_test()[0];
    w.close(A, a, 0).unwrap();
    assert_eq!(w.table.record(child), Err(CapabilityError::StaleHandle));
    assert_eq!(w.table.live_count(), baseline);
    w.recv().unwrap();

    // Parent revocation left the child Revoked; purge still releases it.
    let b = w.connect(B);
    let second = w.buffer(B, 2, 64);
    w.send_transfer(B, b, second).unwrap();
    let child = w.core.undelivered_children_for_test()[0];
    clean_slate_capability::revoke_subtree(&mut w.table, second.handle).unwrap();
    assert_eq!(
        w.table.record(child).unwrap().state,
        CapabilityState::Revoked
    );
    w.exit(B);
    assert_eq!(w.table.record(child), Err(CapabilityError::StaleHandle));
    w.recv().unwrap();

    // The child slot was reclaimed and reused before the purge: the new occupant survives.
    let c = w.connect(C);
    let third = w.buffer(C, 3, 64);
    w.send_transfer(C, c, third).unwrap();
    let child = w.core.undelivered_children_for_test()[0];
    w.table.revoke(child).unwrap();
    w.table.release_slot(usize::from(child.slot));
    let occupant = (0..CAPS)
        .map(|_| w.grant(A.holder, ResourceRef::object(1), Rights::READ))
        .find(|&raw| CapabilityHandle::decode(raw).unwrap().slot == child.slot)
        .expect("the reclaimed child slot is reused");
    w.close(C, c, 0).unwrap();
    assert_eq!(
        w.table
            .record(CapabilityHandle::decode(occupant).unwrap())
            .unwrap()
            .state,
        CapabilityState::Live
    );
}

#[test]
fn delivered_children_outlive_the_connection_until_the_sender_is_revoked() {
    let mut w = World::new(SMALL);
    let a = w.connect(A);
    let transfer = w.buffer(A, 1, 64);
    w.send_transfer(A, a, transfer).unwrap();
    let child =
        CapabilityHandle::decode(w.recv().unwrap().envelope.transfer.unwrap().handle).unwrap();
    w.exit(A);
    assert_eq!(w.table.record(child).unwrap().state, CapabilityState::Live);
    revoke_holder_tree(&mut w.table, A.holder);
    assert_eq!(
        w.table.record(child).unwrap().state,
        CapabilityState::Revoked
    );
}

// ---- readiness and accounting ----

#[test]
fn readiness_queries_match_the_operations() {
    let mut w = World::new(SMALL);
    let a = w.connect(A);
    assert!(!w.core.event_ready(a.encode()));
    assert_eq!(w.core.connection_port_key(a.encode()), Ok(w.key));
    w.post(a, 1).unwrap();
    assert!(w.core.event_ready(a.encode()));
    assert!(w.core.event_ready(0), "invalid ids complete at once");
    assert_eq!(w.core.connection_port_key(0), Err(PortError::Invalid));
    assert_eq!(w.core.serve_port_key(&w.table, SERVER, w.serve), Ok(w.key));
}

#[test]
fn counts_return_to_zero_after_every_role_exits() {
    let mut w = World::new(SMALL);
    let a = w.connect(A);
    let b = w.connect(B);
    let transfer = w.buffer(A, 1, 64);
    let baseline = w.table.live_count();
    w.send_transfer(A, a, transfer).unwrap();
    w.post(b, 1).unwrap();
    assert_eq!(
        w.core.counts_for(SERVER.holder),
        crate::HolderPortCounts {
            ports_served: 1,
            port_connections: 0
        }
    );
    w.exit(A);
    w.exit(SERVER);
    w.exit(B);
    assert_eq!(w.core.global_counts(), PortCounts::default());
    assert_eq!(w.table.live_count(), baseline);
    for who in [A, B, SERVER] {
        assert_eq!(w.core.counts_for(who.holder), Default::default());
    }
    w.core.check_invariants().unwrap();
}

#[test]
fn engine_state_is_statically_bounded() {
    assert!(core::mem::size_of::<PortCore<4, 16, u64>>() <= 128 * 1024);
    assert!(core::mem::size_of::<Effects<u64>>() <= 2 * 1024);
}

#[test]
fn engine_has_no_graphics_dependency() {
    let manifest = include_str!("../Cargo.toml");
    assert!(!manifest.contains("graphics"));
    for source in [
        include_str!("lib.rs"),
        include_str!("engine.rs"),
        include_str!("transfer.rs"),
        include_str!("effects.rs"),
    ] {
        assert!(!source.contains("clean_slate_graphics"));
    }
}

// ---- property test ----

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn random_operation_sequences_keep_every_invariant() {
    for seed in [1, 7, 42, 1234, 0xdead_beef] {
        run_property(seed, 3000);
    }
}

fn run_property(seed: u64, steps: usize) {
    let mut rng = Lcg(seed);
    let mut w = World::new(params(4, 2, 6, 3, 3));
    w.bind();
    let mut clients = [A, B, C];
    let mut conns: Vec<Vec<ConnectionId>> = vec![Vec::new(); 3];
    let mut issued: Vec<ConnectionId> = Vec::new();
    let mut delivered: Vec<(CapabilityHandle, HolderId)> = Vec::new();
    let mut buffers = 0u16;

    for step in 0..steps {
        let who = rng.below(3);
        let client = clients[who];
        let pick = |rng: &mut Lcg, list: &[ConnectionId]| -> Option<ConnectionId> {
            (!list.is_empty()).then(|| list[rng.below(list.len())])
        };
        match rng.below(10) {
            0 => {
                let cap = w.client_cap(client);
                if let Ok(id) = w.connect_with(client, cap) {
                    conns[who].push(id);
                    issued.push(id);
                }
            }
            1 | 2 => {
                if let Some(id) = pick(&mut rng, &conns[who]) {
                    let transfer =
                        (rng.below(3) == 0 && w.table.live_count() < CAPS - 2).then(|| {
                            buffers += 1;
                            w.buffer(client, buffers, 64)
                        });
                    let _ = w.core.send(
                        &mut w.table,
                        client,
                        id.encode(),
                        &frame(step as u8),
                        transfer,
                        &mut w.effects,
                    );
                }
            }
            3 | 4 => {
                if let Ok(record) = w.recv() {
                    let child = record
                        .envelope
                        .transfer
                        .map(|cap| CapabilityHandle::decode(cap.handle).unwrap())
                        .filter(|&child| {
                            w.table
                                .record(child)
                                .is_ok_and(|r| r.state == CapabilityState::Live)
                        });
                    if let Some(child) = child {
                        delivered.push((child, HolderId(record.envelope.pid)));
                    }
                }
            }
            5 => {
                if let Some(id) = pick(&mut rng, &conns[who]) {
                    let _ = w.post(id, step as u8);
                }
            }
            6 => {
                if let Some(id) = pick(&mut rng, &conns[who]) {
                    if let Ok(event) = w.event(client, id) {
                        if event.kind != EventKind::Frame {
                            conns[who].retain(|c| *c != id);
                        }
                    }
                }
            }
            7 => {
                if let Some(id) = pick(&mut rng, &conns[who]) {
                    if w.close(client, id, 0).is_ok() {
                        conns[who].retain(|c| *c != id);
                    }
                }
            }
            8 => {
                if let Some(id) = pick(&mut rng, &conns[who]) {
                    let _ = w.disconnect(id, step as u32);
                }
            }
            _ => {
                if rng.below(4) == 0 {
                    w.exit(client);
                    revoke_holder_tree(&mut w.table, client.holder);
                    delivered.retain(|(_, sender)| *sender != client.holder);
                    clients[who] = caller(client.holder.0, client.generation + 100);
                    conns[who].clear();
                } else if let Some((child, _)) = delivered.pop() {
                    w.table.revoke(child).unwrap();
                    w.table.release_slot(usize::from(child.slot));
                }
            }
        }
        w.take_effects();
        w.core
            .check_invariants()
            .unwrap_or_else(|e| panic!("seed {seed} step {step}: {e}"));
        // Only the newest id per slot may resolve.
        let mut newest = std::collections::BTreeMap::new();
        for id in &issued {
            let entry = newest.entry(id.slot()).or_insert(id.generation());
            *entry = (*entry).max(id.generation());
        }
        for id in &issued {
            if id.generation() != newest[&id.slot()] {
                assert_eq!(
                    w.core.connection_port_key(id.encode()),
                    Err(PortError::Stale),
                    "seed {seed} step {step}: stale id resolved"
                );
            }
        }
        let undelivered = w.core.undelivered_children_for_test();
        assert_eq!(
            undelivered.len(),
            w.core.global_counts().undelivered_transfers
        );
        assert_no_untracked_children(&w, &undelivered, &delivered, seed, step);
        // Keep the table from filling with dead client and buffer roots.
        if w.table.live_count() > CAPS - 4 {
            for slot in 0..CAPS {
                let record = *w.table.record_at(slot);
                let handle = w.table.handle_at(slot);
                if record.state == CapabilityState::Live
                    && record.provenance.parent.is_none()
                    && record.holder != SERVER.holder
                {
                    let handle = handle.unwrap();
                    clean_slate_capability::revoke_subtree(&mut w.table, handle).unwrap();
                    delivered.retain(|(child, _)| {
                        w.table
                            .record(*child)
                            .is_ok_and(|r| r.state == CapabilityState::Live)
                    });
                }
            }
            clean_slate_capability::release_revoked(&mut w.table);
        }
    }

    for who in clients.into_iter().chain([SERVER]) {
        w.exit(who);
        revoke_holder_tree(&mut w.table, who.holder);
    }
    w.core.check_invariants().unwrap();
    assert_eq!(w.core.global_counts(), PortCounts::default(), "seed {seed}");
    assert_no_untracked_children(&w, &[], &[], seed, steps);
}

/// Every live child in the table was minted by a transfer the engine still queues or the
/// harness saw delivered.
fn assert_no_untracked_children(
    w: &World,
    undelivered: &[CapabilityHandle],
    delivered: &[(CapabilityHandle, HolderId)],
    seed: u64,
    step: usize,
) {
    for slot in 0..CAPS {
        let record = w.table.record_at(slot);
        if record.state != CapabilityState::Live || record.provenance.parent.is_none() {
            continue;
        }
        let handle = w.table.handle_at(slot).unwrap();
        assert!(
            undelivered.contains(&handle) || delivered.iter().any(|(child, _)| *child == handle),
            "seed {seed} step {step}: child in slot {slot} leaked"
        );
    }
}
