//! Kernel instance of the service-port engine (syscall 17 `SERVICE_PORT`, #200).
//!
//! One [`PortCore`] for the whole kernel. Every entry runs the engine with interrupts disabled
//! against the global capability table, then applies the returned effects, so state always
//! changes before any waiter or work set observes it. Single CPU: the core needs no lock; SMP
//! would need one, taken before the work-set and wait tables and released before the
//! shared-buffer state is touched (transfer-purge reconcile), like the capability table.
//!
//! The syscall layer (`port_syscall.rs`) and the in-kernel client entries share these functions,
//! so a CPL3 client and the M11 Linux-personality shim take one code path.

use clean_slate_capability::{
    AuditEvent, AuditKind, CapabilityError, CapabilityHandle, CapabilityTable, HolderId,
    ResourceClass, ResourceRef, Rights, MAX_SLOTS,
};
use clean_slate_native_abi::port::{PORT_MAX_CONNECTIONS, PORT_MAX_TRANSFERS_IN_FLIGHT};
#[cfg(any(
    feature = "m10-port-self-test",
    feature = "m10-shared-buffer-self-test",
    clean_slate_desktop
))]
use clean_slate_native_abi::PortParams;
use clean_slate_native_abi::{ConnectionId, PortEventRecord, PortRecvRecord, SharedBufferId};
#[cfg(any(
    feature = "m10-port-self-test",
    feature = "m10-shared-buffer-self-test",
    clean_slate_desktop_snapshot
))]
use clean_slate_port::PortCounts;
#[cfg(any(
    feature = "m10-port-self-test",
    feature = "m10-shared-buffer-self-test",
    clean_slate_desktop
))]
use clean_slate_port::RegistrationError;
use clean_slate_port::{
    Caller, Effect, Effects, HolderPortCounts, PortCore, PortError, PortKey, PortReleaseCounts,
    Transfer, REVOKED_TRANSFERS_CAPACITY,
};
use clean_slate_service_lifecycle::InstanceGeneration;

use crate::arch::x86_64::cpu::without_interrupts;
use crate::capability::audit::{self, record_kernel_revoke};
use crate::capability::{capability_space_mut, with_capability_space};
use crate::mm::shared_buffer::reconcile_resource;
use crate::sched::wait::{wake_all_registered, WaitKey};
use crate::sched::work_set::{self, WorkSetBinding};
use crate::service::instance_generation::live_instance_generation_for_pid;
use crate::sync::global_cell::GlobalCell;

pub(crate) const PORT_REGISTRY_CAPACITY: usize = 4;

pub(crate) type KernelPortCore =
    PortCore<PORT_REGISTRY_CAPACITY, PORT_MAX_CONNECTIONS, WorkSetBinding>;

const _: () =
    assert!(PORT_REGISTRY_CAPACITY * PORT_MAX_TRANSFERS_IN_FLIGHT <= REVOKED_TRANSFERS_CAPACITY);

static PORTS: GlobalCell<KernelPortCore> = GlobalCell::new(PortCore::new());

const SERVER_WAIT_KEY_TAG: u64 = 0x57 << 56;
const CONNECTION_WAIT_KEY_TAG: u64 = 0x58 << 56;
const SEND_SPACE_WAIT_KEY_TAG: u64 = 0x59 << 56;

/// The one key `RECV` blocks on and every request or notice producer wakes.
pub(crate) fn server_wait_key(key: PortKey) -> WaitKey {
    WaitKey(SERVER_WAIT_KEY_TAG | key.raw())
}

/// The one key `SEND WAIT` blocks on and every queue-space producer wakes.
pub(crate) fn send_space_wait_key(key: PortKey) -> WaitKey {
    WaitKey(SEND_SPACE_WAIT_KEY_TAG | key.raw())
}

/// The one key `RECV_EVENT` blocks on and every event or close producer wakes.
pub(crate) fn connection_wait_key(connection: ConnectionId) -> WaitKey {
    WaitKey(CONNECTION_WAIT_KEY_TAG | connection.encode())
}

/// Runs `operation` on the port core and the capability table with interrupts disabled, then
/// applies its effects. No other reference to either may be live.
///
/// An operation that purges undelivered transfers has revoked their children in the table, so
/// mappings a server made through a child (it may map one before `RECV`) must go too. As at
/// every other revocation site, the table borrow ends before `reconcile_resource` reads it and
/// edits the shared-buffer windows; that runs before the wakes, still with interrupts disabled,
/// so no woken waiter or preempting thread can reach a row whose authority is gone.
fn with_ports<R>(
    operation: impl FnOnce(
        &mut KernelPortCore,
        &mut CapabilityTable<MAX_SLOTS>,
        &mut Effects<WorkSetBinding>,
    ) -> R,
) -> R {
    without_interrupts(|| {
        let mut effects = Effects::new();
        let result = {
            let core = unsafe { &mut *PORTS.get() };
            let table = unsafe { capability_space_mut() };
            operation(core, table, &mut effects)
        };
        // `PortCore::new` bounds one operation's effects and revoked transfers.
        if effects.overflowed() {
            crate::diagnostics::qemu::fatal_kernel_error("service port effects overflowed");
        }
        for resource in effects.revoked_transfers() {
            record_kernel_revoke(HolderId::KERNEL, resource, 1);
            reconcile_resource(resource);
        }
        apply(&effects);
        result
    })
}

/// The capability error an engine refusal stands for; `None` for outcomes that are not
/// authority decisions (would block, peer closed).
fn port_denial(error: PortError) -> Option<Result<(), CapabilityError>> {
    match error {
        PortError::Invalid => Some(Err(CapabilityError::InvalidHandle)),
        PortError::Denied => Some(Err(CapabilityError::MissingRight)),
        PortError::Stale => Some(Err(CapabilityError::StaleHandle)),
        PortError::NoSpace => Some(Err(CapabilityError::CapacityExhausted)),
        PortError::Refused => Some(Err(CapabilityError::WrongResource)),
        PortError::WouldBlock | PortError::PeerClosed => None,
    }
}

/// Records a port decision. A use of an established connection or serve handle
/// (`record_allowed == false`) records refusals only: the connect or grant that conferred it
/// was recorded, and those calls run once per message.
fn record_port_decision<T>(
    event: AuditEvent,
    record_allowed: bool,
    result: Result<T, PortError>,
) -> Result<T, PortError> {
    let outcome = match &result {
        Ok(_) if record_allowed => Some(Ok(())),
        Ok(_) => None,
        Err(error) => port_denial(*error),
    };
    if let Some(outcome) = outcome {
        audit::record(event.with_result(outcome));
    }
    result
}

fn serve_event(holder: HolderId, serve: u64) -> AuditEvent {
    let resource = CapabilityHandle::decode(serve)
        .and_then(|handle| with_capability_space(|table| table.record(handle)))
        .map_or(ResourceRef::process(holder.0, 0), |record| record.resource);
    AuditEvent::new(AuditKind::Authorize, holder, resource, Rights::empty())
        .with_handle(CapabilityHandle::decode(serve).unwrap_or(CapabilityHandle::INVALID))
}

/// Connection ids are not capabilities; the record names the calling process.
fn connection_event(holder: HolderId) -> AuditEvent {
    AuditEvent::new(
        AuditKind::Authorize,
        holder,
        ResourceRef::process(holder.0, 0),
        Rights::empty(),
    )
}

/// Host tests have no live process registry, so they drive the core with explicit callers.
#[cfg(test)]
pub(crate) fn with_ports_for_test<R>(
    operation: impl FnOnce(
        &mut KernelPortCore,
        &mut CapabilityTable<MAX_SLOTS>,
        &mut Effects<WorkSetBinding>,
    ) -> R,
) -> R {
    with_ports(operation)
}

fn apply(effects: &Effects<WorkSetBinding>) {
    for effect in effects.iter() {
        match effect {
            Effect::WakeServer(key) => {
                wake_all_registered(server_wait_key(key));
            }
            Effect::WakeSendSpace(key) => {
                wake_all_registered(send_space_wait_key(key));
            }
            Effect::WakeConnection(connection) => {
                wake_all_registered(connection_wait_key(connection));
            }
            Effect::Signal(binding, bit) => work_set::signal(binding, bit),
        }
    }
}

/// Trusted identity of a live process. The kernel only ever acts on behalf of one.
fn caller_for(holder: HolderId) -> Result<Caller, PortError> {
    if holder == HolderId::KERNEL {
        return Err(PortError::Denied);
    }
    let generation = live_instance_generation_for_pid(holder.0).ok_or(PortError::Denied)?;
    Ok(Caller {
        holder,
        generation: u64::from(generation.0),
        domain: holder.0,
    })
}

// ---- launch policy ----

/// Only launch policy (or a row's `Grant::GraphicsPort`) registers a port: after spawning
/// `server` and before it runs.
#[cfg(any(
    feature = "m10-port-self-test",
    feature = "m10-shared-buffer-self-test",
    clean_slate_desktop
))]
pub(crate) fn register_port(
    resource: ResourceRef,
    server: HolderId,
    server_generation: InstanceGeneration,
    params: PortParams,
) -> Result<PortKey, RegistrationError> {
    without_interrupts(|| {
        let is_live = server != HolderId::KERNEL
            && live_instance_generation_for_pid(server.0) == Some(server_generation);
        // Generation 0 is never live, so the engine keeps its check order and reports it last.
        let generation = if is_live {
            u64::from(server_generation.0)
        } else {
            0
        };
        let core = unsafe { &mut *PORTS.get() };
        core.register(resource, server, generation, params)
    })
}

// ---- W6: shared-buffer attestation (owned by #195) ----

/// `shared_buffer::attest_for_transfer` per wave-1 decision W6: a Live `SharedBuffer`
/// capability with `DELEGATE` naming a Live buffer, or `ESTALE`/`EACCES`. The M10 port
/// self-test attests from a fixture table instead, so its buffers need no backing frames.
#[cfg(not(feature = "m10-port-self-test"))]
fn attest_for_transfer(
    holder: HolderId,
    handle: CapabilityHandle,
) -> Result<(SharedBufferId, u64), u64> {
    crate::mm::shared_buffer::transfer::attest_for_transfer(holder, handle)
}

#[cfg(feature = "m10-port-self-test")]
fn attest_for_transfer(
    holder: HolderId,
    handle: CapabilityHandle,
) -> Result<(SharedBufferId, u64), u64> {
    attestation_fixture::attest(holder, handle)
}

#[cfg(feature = "m10-port-self-test")]
pub(crate) mod attestation_fixture {
    use clean_slate_capability::{CapabilityHandle, HolderId, ResourceClass};
    use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_ENOSPC, STATUS_ESTALE};
    use clean_slate_native_abi::SharedBufferId;

    use crate::capability::with_capability_space;
    use crate::sync::global_cell::GlobalCell;

    const FIXTURE_CAPACITY: usize = 8;

    static FIXTURES: GlobalCell<[Option<(SharedBufferId, u64)>; FIXTURE_CAPACITY]> =
        GlobalCell::new([None; FIXTURE_CAPACITY]);

    /// Declares `id` a live buffer of `byte_len` bytes, as #195's table would.
    pub(crate) fn insert(id: SharedBufferId, byte_len: u64) -> Result<(), u64> {
        let fixtures = unsafe { &mut *FIXTURES.get() };
        let entry = fixtures
            .iter_mut()
            .find(|entry| entry.is_none_or(|(existing, _)| existing == id))
            .ok_or(STATUS_ENOSPC)?;
        *entry = Some((id, byte_len));
        Ok(())
    }

    /// Destroys `id`: later attestations of any capability on it are stale.
    pub(crate) fn remove(id: SharedBufferId) {
        let fixtures = unsafe { &mut *FIXTURES.get() };
        for entry in fixtures.iter_mut() {
            if entry.is_some_and(|(existing, _)| existing == id) {
                *entry = None;
            }
        }
    }

    pub(super) fn attest(
        holder: HolderId,
        handle: CapabilityHandle,
    ) -> Result<(SharedBufferId, u64), u64> {
        let record =
            with_capability_space(|table| table.record(handle)).map_err(|_| STATUS_ESTALE)?;
        if record.holder != holder || record.resource.class != ResourceClass::SharedBuffer {
            return Err(STATUS_EACCES);
        }
        let id = SharedBufferId::decode(record.resource.id).map_err(|_| STATUS_ESTALE)?;
        let fixtures = unsafe { &*FIXTURES.get() };
        fixtures
            .iter()
            .flatten()
            .find(|(existing, _)| *existing == id)
            .copied()
            .ok_or(STATUS_ESTALE)
    }
}

// ---- client entries (CPL3 syscalls and the in-kernel shim) ----

pub(crate) fn kernel_client_connect(
    holder: HolderId,
    cap: CapabilityHandle,
    class: ResourceClass,
    id: u64,
) -> Result<ConnectionId, PortError> {
    let result = caller_for(holder).and_then(|caller| {
        with_ports(|core, table, _| {
            core.connect(table, caller, cap.encode(), u64::from(class.as_u8()), id)
        })
    });
    let resource = ResourceRef {
        class,
        id,
        instance_generation: 0,
    };
    record_port_decision(
        AuditEvent::new(AuditKind::Authorize, holder, resource, Rights::empty()).with_handle(cap),
        true,
        result,
    )
}

/// The attestation runs before the engine borrows the capability table (#195 reads it too), in
/// the same interrupts-disabled section as the send.
pub(crate) fn kernel_client_send(
    holder: HolderId,
    connection: ConnectionId,
    frame: &[u8; 64],
    transfer: Option<CapabilityHandle>,
) -> Result<(), PortError> {
    let transfer_resource = transfer.and_then(|handle| {
        with_capability_space(|table| table.record(handle))
            .ok()
            .map(|record| record.resource)
    });
    let result = caller_for(holder).and_then(|caller| {
        without_interrupts(|| {
            let transfer = transfer.map(|handle| Transfer {
                handle,
                attestation: attest_for_transfer(holder, handle),
            });
            with_ports(|core, table, effects| {
                core.send(table, caller, connection.encode(), frame, transfer, effects)
            })
        })
    });
    match transfer {
        // The child lands with the port's server; the engine does not report which holder.
        Some(handle) => record_port_decision(
            AuditEvent::new(
                AuditKind::Delegate,
                holder,
                transfer_resource.unwrap_or(ResourceRef::process(holder.0, 0)),
                Rights::READ,
            )
            .with_handle(handle),
            true,
            result,
        ),
        None => record_port_decision(connection_event(holder), false, result),
    }
}

/// `WouldBlock` when nothing is pending; the caller decides whether to block.
pub(crate) fn kernel_client_try_recv_event(
    holder: HolderId,
    connection: ConnectionId,
) -> Result<PortEventRecord, PortError> {
    let result = caller_for(holder).and_then(|caller| {
        with_ports(|core, table, effects| {
            core.recv_event(table, caller, connection.encode(), effects)
        })
    });
    record_port_decision(connection_event(holder), false, result)
}

pub(crate) fn kernel_client_close(
    holder: HolderId,
    connection: ConnectionId,
    reason: u32,
) -> Result<(), PortError> {
    let result = caller_for(holder).and_then(|caller| {
        with_ports(|core, table, effects| {
            core.close(table, caller, connection.encode(), reason, effects)
        })
    });
    record_port_decision(connection_event(holder), false, result)
}

pub(crate) fn connection_port_key(connection: ConnectionId) -> Result<PortKey, PortError> {
    with_ports(|core, _, _| core.connection_port_key(connection.encode()))
}

pub(crate) fn find_handle(
    holder: HolderId,
    class: u64,
    id: u64,
    role: u64,
) -> Result<u64, PortError> {
    let result = caller_for(holder).and_then(|caller| {
        with_ports(|core, table, _| core.find_handle(table, caller, class, id, role))
    });
    let resource =
        ResourceClass::from_u8(class as u8).map_or(ResourceRef::process(holder.0, 0), |class| {
            ResourceRef {
                class,
                id,
                instance_generation: 0,
            }
        });
    let event = AuditEvent::new(AuditKind::Authorize, holder, resource, Rights::empty())
        .with_handle(
            result
                .ok()
                .and_then(|raw| CapabilityHandle::decode(raw).ok())
                .unwrap_or(CapabilityHandle::INVALID),
        );
    record_port_decision(event, true, result)
}

// ---- server entries ----

pub(crate) fn serve_port_key(holder: HolderId, serve: u64) -> Result<PortKey, PortError> {
    let result = caller_for(holder)
        .and_then(|caller| with_ports(|core, table, _| core.serve_port_key(table, caller, serve)));
    record_port_decision(serve_event(holder, serve), false, result)
}

pub(crate) fn server_recv(holder: HolderId, serve: u64) -> Result<PortRecvRecord, PortError> {
    let result = caller_for(holder).and_then(|caller| {
        with_ports(|core, table, effects| core.recv(table, caller, serve, effects))
    });
    record_port_decision(serve_event(holder, serve), false, result)
}

pub(crate) fn server_post(
    holder: HolderId,
    serve: u64,
    connection: ConnectionId,
    frame: &[u8; 64],
) -> Result<(), PortError> {
    let result = caller_for(holder).and_then(|caller| {
        with_ports(|core, table, effects| {
            core.post(table, caller, serve, connection.encode(), frame, effects)
        })
    });
    record_port_decision(serve_event(holder, serve), false, result)
}

pub(crate) fn server_disconnect(
    holder: HolderId,
    serve: u64,
    connection: ConnectionId,
    reason: u32,
) -> Result<(), PortError> {
    let result = caller_for(holder).and_then(|caller| {
        with_ports(|core, table, effects| {
            core.disconnect(table, caller, serve, connection.encode(), reason, effects)
        })
    });
    record_port_decision(serve_event(holder, serve), false, result)
}

pub(crate) fn server_bind_wake(
    holder: HolderId,
    serve: u64,
    target: WorkSetBinding,
    request_bit: u32,
    notice_bit: u32,
) -> Result<(), PortError> {
    let result = caller_for(holder).and_then(|caller| {
        with_ports(|core, table, effects| {
            core.bind_wake(
                table,
                caller,
                serve,
                target,
                request_bit,
                notice_bit,
                effects,
            )
        })
    });
    record_port_decision(serve_event(holder, serve), false, result)
}

// ---- P4 teardown and accounting ----

/// The W5 `Port` teardown slot: ports `holder` serves go away (`ServerGone`), then its client
/// connections become exit notices or are freed. Undelivered transfer children are released
/// here, before the holder's capabilities are revoked.
pub(crate) fn on_holder_exit(
    holder: HolderId,
    generation: InstanceGeneration,
) -> PortReleaseCounts {
    with_ports(|core, table, effects| {
        core.on_holder_exit(table, holder, u64::from(generation.0), effects)
    })
}

pub(crate) fn counts_for(holder: HolderId) -> HolderPortCounts {
    with_ports(|core, _, _| core.counts_for(holder))
}

#[cfg(any(
    feature = "m10-port-self-test",
    feature = "m10-shared-buffer-self-test",
    clean_slate_desktop_snapshot
))]
pub(crate) fn global_counts() -> PortCounts {
    with_ports(|core, _, _| core.global_counts())
}

#[cfg(feature = "m10-port-self-test")]
pub(crate) fn limit_rejections() -> clean_slate_port::LimitRejections {
    with_ports(|core, _, _| core.limit_rejections())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_capability::ResourceRef;
    use clean_slate_native_abi::PortParams;

    #[test]
    fn wait_keys_are_disjoint_per_role_and_per_port() {
        let params = PortParams {
            event_depth: 1,
            request_depth: 1,
            max_connections: 1,
            max_outstanding: 1,
            max_connections_per_holder: 1,
        };
        let mut core: Box<PortCore<2, 1, u32>> = Box::new(PortCore::new());
        let first = core
            .register(ResourceRef::graphics(1, 1), HolderId(7), 1, params)
            .unwrap();
        let second = core
            .register(ResourceRef::graphics(2, 1), HolderId(7), 1, params)
            .unwrap();
        let connection = ConnectionId::new(0, 1).unwrap();
        let keys = [
            server_wait_key(first),
            send_space_wait_key(first),
            server_wait_key(second),
            send_space_wait_key(second),
            connection_wait_key(connection),
            work_set::wait_key(clean_slate_native_abi::WorkSetId::new(0, 1).unwrap()),
        ];
        for (index, key) in keys.iter().enumerate() {
            for other in &keys[index + 1..] {
                assert_ne!(key, other);
            }
        }
    }

    #[test]
    fn kernel_callers_are_refused() {
        assert_eq!(caller_for(HolderId::KERNEL), Err(PortError::Denied));
        assert_eq!(
            kernel_client_close(HolderId::KERNEL, ConnectionId::new(0, 1).unwrap(), 0),
            Err(PortError::Denied)
        );
    }

    #[test]
    fn port_glue_never_records_a_pending_wake() {
        let sources = [include_str!("port.rs"), include_str!("port_syscall.rs")];
        for source in sources {
            let code = source.split("#[cfg(test)]").next().unwrap();
            for banned in ["wake_all(", "wake_one(", "block_current_thread("] {
                assert!(!code.contains(banned), "port glue must not call {banned}");
            }
        }
    }
}
