use clean_slate_capability::{
    delegate, revoke_subtree, syscall_abi, CapabilityError, CapabilityHandle, HolderId,
    ResourceRef, Rights,
};
use clean_slate_native_abi::{SharedBufferAccess, SharedBufferId, STATUS_EACCES, STATUS_ESTALE};

use super::kernel_owned::{
    allocate_kernel_owned, extents, map_kernel_owned_into_root, pin, release_kernel_owned,
    unmap_kernel_grants_for, unpin, with_kernel_bytes_mut,
};
use super::table::test_support::ArenaFrames;
use super::table::BufferState;
use super::transfer::attest_for_transfer;
use super::window::{MappingAuthority, RowState};
use super::*;
use crate::capability::{capability_space_mut, revoke_for_holder, revoke_for_resource};
use crate::mm::paging::page_table_mut;
use crate::mm::PAGE_SIZE;

const OWNER: u64 = 41;
const READER: u64 = 42;

struct Harness {
    frames: ArenaFrames,
    owner_root: u64,
    reader_root: u64,
    zero_frame: u64,
    baseline: usize,
}

impl Harness {
    fn new() -> Self {
        let mut frames = ArenaFrames::new(256);
        let mut table = || {
            let (frame, _) = frames.allocate_run(1).unwrap();
            zero_page(frame);
            frame
        };
        let owner_root = table();
        let reader_root = table();
        let zero_frame = table();
        let zero_pt = table();
        fill_zero_table(zero_pt, zero_frame);
        state().zero = Some(ZeroPages { zero_pt });
        let baseline = frames.live_frames();
        Self {
            frames,
            owner_root,
            reader_root,
            zero_frame,
            baseline,
        }
    }

    fn allocate(&mut self, pages: u64) -> (SharedBufferId, CapabilityHandle) {
        allocate_client(OWNER, pages * PAGE_SIZE, &mut self.frames).unwrap()
    }

    fn delegate_read(&self, root: CapabilityHandle) -> CapabilityHandle {
        delegate(
            unsafe { capability_space_mut() },
            HolderId(OWNER),
            root,
            HolderId(READER),
            Rights::READ,
        )
        .unwrap()
    }

    fn map(
        &mut self,
        pid: u64,
        id: SharedBufferId,
        access: SharedBufferAccess,
        handle: CapabilityHandle,
    ) -> Result<u64, ShareError> {
        let root = if pid == OWNER {
            self.owner_root
        } else {
            self.reader_root
        };
        map_into_root(
            pid,
            root,
            id,
            access,
            MappingAuthority::Capability(handle),
            &mut self.frames,
        )
    }

    fn leaf(&self, pid: u64, va: u64) -> u64 {
        let root = if pid == OWNER {
            self.owner_root
        } else {
            self.reader_root
        };
        let va = x86_64::VirtAddr::new(va);
        let mut frame = root;
        for index in [va.p4_index(), va.p3_index(), va.p2_index(), va.p1_index()] {
            let table = unsafe { page_table_mut(frame) };
            frame = table[index].addr().as_u64();
        }
        frame
    }

    fn row_state(&self, pid: u64, id: SharedBufferId) -> Option<RowState> {
        row_for(pid, id).map(|(_, state, _)| state)
    }

    fn teardown_both(&mut self) {
        revoke_for_holder(HolderId(OWNER));
        revoke_for_holder(HolderId(READER));
        teardown_process(OWNER, &mut self.frames);
        teardown_process(READER, &mut self.frames);
        for root in [self.owner_root, self.reader_root] {
            assert!(unsafe { page_table_mut(root) }[WINDOW_PML4_INDEX].is_unused());
        }
        assert_eq!(
            self.frames.live_frames(),
            self.baseline,
            "every frame returned"
        );
        assert_eq!(state().table.stats().live_buffers, 0);
        assert_eq!(state().table.stats().dying_buffers, 0);
    }
}

fn buffer_state(id: SharedBufferId) -> Option<BufferState> {
    let record = state().table.record_at(usize::from(id.slot()));
    (record.generation == id.generation()).then_some(record.state)
}

#[test]
fn shared_buffer_cross_process_map_shares_frames_and_reader_is_read_only() {
    let mut harness = Harness::new();
    let (id, root) = harness.allocate(2);
    let child = harness.delegate_read(root);
    let owner_va = harness
        .map(OWNER, id, SharedBufferAccess::ReadWrite, root)
        .unwrap();
    let reader_va = harness
        .map(READER, id, SharedBufferAccess::Read, child)
        .unwrap();
    for page in 0..2 {
        let offset = page * PAGE_SIZE;
        assert_eq!(
            harness.leaf(OWNER, owner_va + offset),
            harness.leaf(READER, reader_va + offset),
            "both processes map the same frame"
        );
    }
    assert_eq!(
        harness.map(READER, id, SharedBufferAccess::Read, child),
        Err(ShareError::Busy),
        "one row per process and buffer"
    );
    harness.teardown_both();
}

#[test]
fn shared_buffer_owner_exit_orphans_reader_to_zero_page_and_reclaims_once() {
    let mut harness = Harness::new();
    let (id, root) = harness.allocate(3);
    let child = harness.delegate_read(root);
    harness
        .map(OWNER, id, SharedBufferAccess::ReadWrite, root)
        .unwrap();
    let reader_va = harness
        .map(READER, id, SharedBufferAccess::Read, child)
        .unwrap();

    revoke_for_holder(HolderId(OWNER));
    for pid in [OWNER, READER] {
        assert_eq!(harness.row_state(pid, id), Some(RowState::Orphaned));
    }
    assert_eq!(harness.leaf(READER, reader_va), harness.zero_frame);
    drain_pending(&mut harness.frames);
    assert_eq!(buffer_state(id), Some(BufferState::Free));
    assert_eq!(state().table.stats().reclaimed_buffers, 1);

    harness.teardown_both();
    assert_eq!(
        state().table.stats().reclaimed_buffers,
        1,
        "reclaimed exactly once"
    );
}

#[test]
fn shared_buffer_reader_exit_leaves_owner_mapping_live() {
    let mut harness = Harness::new();
    let (id, root) = harness.allocate(1);
    let child = harness.delegate_read(root);
    harness
        .map(OWNER, id, SharedBufferAccess::ReadWrite, root)
        .unwrap();
    harness
        .map(READER, id, SharedBufferAccess::Read, child)
        .unwrap();

    revoke_for_holder(HolderId(READER));
    teardown_process(READER, &mut harness.frames);
    assert_eq!(harness.row_state(READER, id), None);
    assert_eq!(harness.row_state(OWNER, id), Some(RowState::Live));
    assert_eq!(buffer_state(id), Some(BufferState::Live));
    assert_eq!(
        state()
            .table
            .record_at(usize::from(id.slot()))
            .mapping_count(),
        1
    );
    harness.teardown_both();
}

#[test]
fn shared_buffer_child_revoke_orphans_only_the_reader() {
    let mut harness = Harness::new();
    let (id, root) = harness.allocate(1);
    let child = harness.delegate_read(root);
    harness
        .map(OWNER, id, SharedBufferAccess::ReadWrite, root)
        .unwrap();
    harness
        .map(READER, id, SharedBufferAccess::Read, child)
        .unwrap();

    revoke_subtree(unsafe { capability_space_mut() }, child).unwrap();
    reconcile_resource(id.resource_ref());
    assert_eq!(harness.row_state(READER, id), Some(RowState::Orphaned));
    assert_eq!(harness.row_state(OWNER, id), Some(RowState::Live));
    assert_eq!(buffer_state(id), Some(BufferState::Live));
    harness.teardown_both();
}

/// How a port operation purges the undelivered transfer in [`purged_transfer_case`].
#[derive(Clone, Copy)]
enum Purge {
    ClientClose,
    ServerExit,
}

/// OWNER sends its root over a port READER serves. Before any `RECV`, READER finds the
/// undelivered child in its own capabilities and maps it; the purge must then treat that row
/// like a CAP_REVOKE of the child: orphaned onto the zero page, owner and buffer untouched.
fn purged_transfer_case(purge: Purge) {
    use crate::service::port::with_ports_for_test;
    use clean_slate_capability::{list_holder, ResourceClass};
    use clean_slate_native_abi::PortParams;
    use clean_slate_port::{Caller, Transfer};

    const SERVICE: u64 = 0x195;
    let resource = ResourceRef::graphics(SERVICE, 1);
    let client = Caller {
        holder: HolderId(OWNER),
        generation: 1,
        domain: OWNER,
    };
    let server = Caller {
        holder: HolderId(READER),
        generation: 1,
        domain: READER,
    };
    let params = PortParams {
        event_depth: 2,
        request_depth: 2,
        max_connections: 1,
        max_outstanding: 1,
        max_connections_per_holder: 1,
    };

    let mut harness = Harness::new();
    let (id, root) = harness.allocate(1);
    let owner_va = harness
        .map(OWNER, id, SharedBufferAccess::ReadWrite, root)
        .unwrap();
    let grant = |holder: u64, rights: Rights| {
        crate::capability::grant_root(HolderId(holder), resource, rights).unwrap()
    };
    grant(READER, Rights::GFX_SERVE);
    let connect_cap = grant(OWNER, Rights::GFX_CONNECT);
    let attestation = attest_for_transfer(HolderId(OWNER), root);
    let connection = with_ports_for_test(|core, table, effects| {
        core.register(resource, server.holder, server.generation, params)
            .unwrap();
        let connection = core
            .connect(
                table,
                client,
                connect_cap.encode(),
                u64::from(ResourceClass::Graphics.as_u8()),
                SERVICE,
            )
            .unwrap();
        let transfer = Transfer {
            handle: root,
            attestation,
        };
        core.send(
            table,
            client,
            connection.encode(),
            &[0; 64],
            Some(transfer),
            effects,
        )
        .unwrap();
        connection
    });

    let child = {
        let table = unsafe { capability_space_mut() };
        let mut cursor = 0;
        loop {
            let (next, handle, record) =
                list_holder(table, server.holder, cursor).expect("the undelivered child");
            if record.resource == id.resource_ref() {
                break handle;
            }
            cursor = next;
        }
    };
    let reader_va = harness
        .map(READER, id, SharedBufferAccess::Read, child)
        .unwrap();
    assert_eq!(
        harness.leaf(READER, reader_va),
        harness.leaf(OWNER, owner_va),
        "the guessed child maps the buffer"
    );

    with_ports_for_test(|core, table, effects| match purge {
        Purge::ClientClose => core
            .close(table, client, connection.encode(), 0, effects)
            .unwrap(),
        Purge::ServerExit => {
            core.on_holder_exit(table, server.holder, server.generation, effects);
        }
    });

    assert!(!capability_is_live(child), "the purge revoked the child");
    assert_eq!(harness.row_state(READER, id), Some(RowState::Orphaned));
    assert_eq!(harness.leaf(READER, reader_va), harness.zero_frame);
    assert_eq!(harness.row_state(OWNER, id), Some(RowState::Live));
    assert_ne!(harness.leaf(OWNER, owner_va), harness.zero_frame);
    assert_eq!(buffer_state(id), Some(BufferState::Live));
    assert_eq!(
        state()
            .table
            .record_at(usize::from(id.slot()))
            .mapping_count(),
        1,
        "only the owner stays attached"
    );
    with_ports_for_test(|core, table, effects| {
        core.on_holder_exit(table, client.holder, client.generation, effects);
        core.on_holder_exit(table, server.holder, server.generation, effects);
        assert_eq!(core.global_counts().undelivered_transfers, 0);
    });
    harness.teardown_both();
}

#[test]
fn shared_buffer_port_close_purge_orphans_a_mapped_undelivered_child() {
    purged_transfer_case(Purge::ClientClose);
}

#[test]
fn shared_buffer_port_server_exit_purge_orphans_a_mapped_undelivered_child() {
    purged_transfer_case(Purge::ServerExit);
}

#[test]
fn shared_buffer_release_by_resource_orphans_every_row_and_goes_stale() {
    let mut harness = Harness::new();
    let (id, root) = harness.allocate(1);
    let child = harness.delegate_read(root);
    harness
        .map(READER, id, SharedBufferAccess::Read, child)
        .unwrap();

    revoke_for_resource(id.resource_ref());
    assert_eq!(harness.row_state(READER, id), Some(RowState::Orphaned));
    assert_eq!(buffer_state(id), Some(BufferState::Free));
    assert_eq!(state().table.live(id).map(|_| ()), Err(ShareError::Stale));
    assert_eq!(
        harness.map(OWNER, id, SharedBufferAccess::Read, root),
        Err(ShareError::Stale)
    );
    harness.teardown_both();
}

#[test]
fn shared_buffer_third_mapping_is_refused_with_no_space() {
    let mut harness = Harness::new();
    let (id, root) = harness.allocate(1);
    let child = harness.delegate_read(root);
    harness
        .map(OWNER, id, SharedBufferAccess::ReadWrite, root)
        .unwrap();
    harness
        .map(READER, id, SharedBufferAccess::Read, child)
        .unwrap();
    let third_root = harness.frames.allocate_run(1).unwrap().0;
    zero_page(third_root);
    assert_eq!(
        map_into_root(
            43,
            third_root,
            id,
            SharedBufferAccess::Read,
            MappingAuthority::KernelGrant,
            &mut harness.frames,
        ),
        Err(ShareError::NoSpace)
    );
    assert!(unsafe { page_table_mut(third_root) }[WINDOW_PML4_INDEX].is_unused());
    harness.frames.free_run(third_root, 1).unwrap();
    harness.teardown_both();
}

#[test]
fn shared_buffer_reconcile_ignores_other_resource_classes() {
    let mut harness = Harness::new();
    let (id, root) = harness.allocate(1);
    harness
        .map(OWNER, id, SharedBufferAccess::ReadWrite, root)
        .unwrap();
    let mut revoked = RevokedBuffers::default();
    revoked.note(ResourceRef::object(id.resource_ref().id));
    assert_eq!(revoked.slots, 0);
    revoked.reconcile();
    assert_eq!(harness.row_state(OWNER, id), Some(RowState::Live));
    harness.teardown_both();
}

#[test]
fn shared_buffer_transfer_attests_only_a_delegable_live_capability() {
    let mut harness = Harness::new();
    let (id, root) = harness.allocate(2);
    let child = harness.delegate_read(root);
    assert_eq!(
        attest_for_transfer(HolderId(OWNER), root),
        Ok((id, 2 * PAGE_SIZE))
    );
    assert_eq!(
        attest_for_transfer(HolderId(READER), child),
        Err(STATUS_EACCES),
        "a read-only child cannot be passed on"
    );
    assert_eq!(
        attest_for_transfer(HolderId(READER), root),
        Err(syscall_abi::SYSCALL_EACCES),
        "only the holder may transfer"
    );
    revoke_for_resource(id.resource_ref());
    assert_eq!(
        attest_for_transfer(HolderId(OWNER), root),
        Err(STATUS_ESTALE)
    );
    harness.teardown_both();
}

#[test]
fn shared_buffer_owner_cannot_delegate_more_than_read() {
    let mut harness = Harness::new();
    let (_, root) = harness.allocate(1);
    for right in [Rights::WRITE, Rights::DELEGATE, Rights::REVOKE] {
        assert_eq!(
            delegate(
                unsafe { capability_space_mut() },
                HolderId(OWNER),
                root,
                HolderId(READER),
                Rights::READ.union(right),
            ),
            Err(CapabilityError::NotDelegable)
        );
    }
    harness.teardown_both();
}

#[test]
fn shared_buffer_kernel_owned_pin_holds_frames_past_release() {
    let mut harness = Harness::new();
    let id = allocate_kernel_owned(2 * PAGE_SIZE, &mut harness.frames).unwrap();
    let token = pin(id).unwrap();
    with_kernel_bytes_mut(&token, PAGE_SIZE - 2, 4, |offset, bytes| {
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = 0x40 + offset as u8 + index as u8;
        }
    })
    .unwrap();
    let pinned = extents(&token);
    let second_page = pinned.frame_at(1).unwrap();
    assert_eq!(unsafe { *(second_page as *const u8) }, 0x42);
    assert_eq!(
        with_kernel_bytes_mut(&token, 2 * PAGE_SIZE - 1, 2, |_, _| {}),
        Err(ShareError::Invalid)
    );

    release_kernel_owned(id, &mut harness.frames).unwrap();
    assert_eq!(
        buffer_state(id),
        Some(BufferState::Dying),
        "pinned frames stay"
    );
    assert_eq!(pin(id), Err(ShareError::Stale));
    unpin(token, &mut harness.frames);
    assert_eq!(buffer_state(id), Some(BufferState::Free));
    assert_eq!(harness.frames.live_frames(), harness.baseline);
}

#[test]
fn shared_buffer_kernel_grant_is_idempotent_and_unmapped_on_role_exit() {
    let mut harness = Harness::new();
    let id = allocate_kernel_owned(PAGE_SIZE, &mut harness.frames).unwrap();
    let root = harness.reader_root;
    let va = map_kernel_owned_into_root(
        id,
        READER,
        root,
        SharedBufferAccess::Read,
        &mut harness.frames,
    )
    .unwrap();
    assert_eq!(
        map_kernel_owned_into_root(
            id,
            READER,
            root,
            SharedBufferAccess::Read,
            &mut harness.frames
        ),
        Ok(va)
    );
    assert_eq!(
        map_kernel_owned_into_root(
            id,
            READER,
            root,
            SharedBufferAccess::ReadWrite,
            &mut harness.frames
        ),
        Err(ShareError::Busy)
    );
    let (client, client_root) = harness.allocate(1);
    let child = harness.delegate_read(client_root);
    harness
        .map(READER, client, SharedBufferAccess::Read, child)
        .unwrap();

    assert_eq!(unmap_kernel_grants_for(READER, &mut harness.frames), 1);
    assert_eq!(harness.row_state(READER, id), None);
    assert_eq!(harness.row_state(READER, client), Some(RowState::Live));
    assert_eq!(buffer_state(id), Some(BufferState::Live));
    release_kernel_owned(id, &mut harness.frames).unwrap();
    harness.teardown_both();
}

#[test]
fn shared_buffer_kernel_owned_buffers_refuse_client_pins() {
    let mut harness = Harness::new();
    let (id, _) = harness.allocate(1);
    assert_eq!(pin(id), Err(ShareError::Denied));
    harness.teardown_both();
}
