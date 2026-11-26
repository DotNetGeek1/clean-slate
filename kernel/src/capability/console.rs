//! Console grants (#310): the only root grants of `Console` authority.
//!
//! The live console service alone serves the console port and holds the serial console device;
//! a client connects with `CONSOLE_CONNECT` and nothing else. Every grant is a root record for
//! exactly one holder, so process teardown (`revoke_for_holder`) removes it.

use clean_slate_capability::{
    revoke_subtree, CapabilityError, CapabilityRecord, CapabilityState, CapabilityTable, HolderId,
    Provenance, ResourceRef, Rights,
};
use clean_slate_native_abi::PortParams;

use super::audit::{self, record_kernel_revoke};
use super::grant_root;

/// The console port's limits: a stream per connection, so at most one per client process, and
/// a small request queue whose bound is a writer's back-pressure. One event is in flight per
/// stream (the answer to its `READ`), so a short event queue suffices.
pub(crate) const CONSOLE_PORT_PARAMS: PortParams = PortParams {
    event_depth: 4,
    request_depth: 32,
    max_connections: 16,
    max_outstanding: 8,
    max_connections_per_holder: 1,
};

const _: () = assert!(CONSOLE_PORT_PARAMS.validate().is_ok());

/// The console service's port authority.
pub(crate) const CONSOLE_SERVICE_PORT_RIGHTS: Rights = Rights::CONSOLE_SERVE;
/// The console service's authority over the serial device: it writes the console's lines and
/// reads the input the kernel's line discipline committed.
pub(crate) const CONSOLE_SERVICE_DEVICE_RIGHTS: Rights = Rights::READ.union(Rights::WRITE);
pub(crate) const CONSOLE_CLIENT_RIGHTS: Rights = Rights::CONSOLE_CONNECT;
/// A member of the console session (#311): the terminal's shell, and its forks by inheritance.
pub(crate) const CONSOLE_SESSION_CLIENT_RIGHTS: Rights =
    Rights::CONSOLE_CONNECT.union(Rights::CONSOLE_SESSION);
/// The console session's front end (#311): the terminal window.
pub(crate) const CONSOLE_FRONT_END_RIGHTS: Rights =
    Rights::CONSOLE_CONNECT.union(Rights::CONSOLE_ATTACH);

/// The rights a reissued client gets: what it connected with, a session member staying one.
const fn reissued_rights(stale: Rights) -> Rights {
    if stale.contains(Rights::CONSOLE_SESSION) {
        CONSOLE_SESSION_CLIENT_RIGHTS
    } else {
        CONSOLE_CLIENT_RIGHTS
    }
}

/// Root `rights` on the console port `port` (one console service generation).
pub(crate) fn grant_console_port(
    holder: HolderId,
    port: ResourceRef,
    rights: Rights,
) -> Result<(), CapabilityError> {
    grant_root(holder, port, rights).map(|_| ())
}

/// Root `READ` and `WRITE` on the serial console device.
pub(crate) fn grant_serial_console_device(holder: HolderId) -> Result<(), CapabilityError> {
    grant_root(
        holder,
        ResourceRef::serial_console_device(),
        CONSOLE_SERVICE_DEVICE_RIGHTS,
    )
    .map(|_| ())
}

/// Whether `record` is a client's `CONSOLE_CONNECT` on a console port of service `service`
/// other than generation `generation`: a port that instance's restart left behind.
// The caller, the console service's port grant, exists only where the desktop rows do.
#[cfg_attr(not(clean_slate_desktop), allow(dead_code))]
fn is_stale_client(record: &CapabilityRecord, service: u64, generation: u64) -> bool {
    record.state == CapabilityState::Live
        && record.resource != ResourceRef::serial_console_device()
        && record.resource.class == clean_slate_capability::ResourceClass::Console
        && record.resource.id == service
        && record.resource.instance_generation != generation
        && record.rights.contains(Rights::CONSOLE_CONNECT)
}

/// A console service instance registered `port`: every holder that `kernel_client` accepts
/// and that holds `CONSOLE_CONNECT` on an earlier instance's port gets it on `port` instead.
/// The kernel is the console client of those holders (a Linux process's console fds,
/// `service::console_stream`), so the new record needs no handle handed to anyone. Calls
/// `reissued` with each holder and the result; returns how many holders were reissued.
// The caller, the console service's port grant, exists only where the desktop rows do.
#[cfg_attr(not(clean_slate_desktop), allow(dead_code))]
fn reissue_clients_in<const N: usize>(
    table: &mut CapabilityTable<N>,
    port: ResourceRef,
    kernel_client: impl Fn(HolderId) -> bool,
    mut reissued: impl FnMut(HolderId, Result<(), CapabilityError>),
) -> usize {
    // Holders first: revoking one holder's record also revokes the copies its forks made.
    let mut holders = [(HolderId(0), CONSOLE_CLIENT_RIGHTS); N];
    let mut count = 0usize;
    for slot in 0..N {
        let record = table.record_at(slot);
        if is_stale_client(record, port.id, port.instance_generation)
            && !holders[..count].iter().any(|(h, _)| *h == record.holder)
            && kernel_client(record.holder)
        {
            holders[count] = (record.holder, reissued_rights(record.rights));
            count += 1;
        }
    }
    for &(holder, rights) in &holders[..count] {
        let mut revoked = 0usize;
        for slot in 0..N {
            let record = table.record_at(slot);
            if record.holder == holder && is_stale_client(record, port.id, port.instance_generation)
            {
                if let Some(handle) = table.handle_at(slot) {
                    revoked += revoke_subtree(table, handle).unwrap_or(0);
                }
            }
        }
        if revoked > 0 {
            record_kernel_revoke(holder, ResourceRef::console_port(port.id, 0), revoked);
        }
        let provenance = Provenance::root(holder);
        let result = match table.grant(holder, port, rights, provenance) {
            Err(CapabilityError::CapacityExhausted) => {
                let _ = clean_slate_capability::release_revoked(table);
                table.grant(holder, port, rights, provenance)
            }
            other => other,
        };
        audit::record(
            clean_slate_capability::AuditEvent::new(
                clean_slate_capability::AuditKind::Grant,
                HolderId::KERNEL,
                port,
                rights,
            )
            .with_subject(holder)
            .with_handle(
                *result
                    .as_ref()
                    .unwrap_or(&clean_slate_capability::CapabilityHandle::INVALID),
            )
            .with_result(result.map(|_| ())),
        );
        reissued(holder, result.map(|_| ()));
    }
    count
}

/// [`reissue_clients_in`] on the kernel's capability space, for the Linux processes, whose
/// console streams the kernel connects.
// The caller, the console service's port grant, exists only where the desktop rows do.
#[cfg_attr(not(clean_slate_desktop), allow(dead_code))]
pub(crate) fn reissue_kernel_console_clients(port: ResourceRef) {
    use crate::process::personality::{execution_personality_for_pid, ExecutionPersonality};
    let table = unsafe { super::capability_space_mut() };
    reissue_clients_in(
        table,
        port,
        |holder| {
            matches!(
                execution_personality_for_pid(holder.0),
                Ok(ExecutionPersonality::LinuxX86_64)
            )
        },
        |holder, result| match result {
            Ok(()) => crate::diagnostics::log::kernel_log_fmt(format_args!(
                "[CONS] client reissued holder={} port={}:{}\n",
                holder.0, port.id, port.instance_generation
            )),
            Err(error) => crate::diagnostics::log::kernel_log_fmt(format_args!(
                "[FAIL] console client reissue failed holder={} port={}:{} err={:?}\n",
                holder.0, port.id, port.instance_generation, error
            )),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{holder_has_resource_rights, revoke_for_holder};
    use clean_slate_capability::ResourceClass;

    #[test]
    fn a_client_can_connect_and_nothing_more() {
        assert_eq!(CONSOLE_CLIENT_RIGHTS, Rights::CONSOLE_CONNECT);
        for rights in [
            CONSOLE_SERVICE_PORT_RIGHTS,
            CONSOLE_SERVICE_DEVICE_RIGHTS,
            CONSOLE_CLIENT_RIGHTS,
        ] {
            assert!(rights.is_subset_of(Rights::valid_for(ResourceClass::Console)));
            assert!(!rights.contains(Rights::DELEGATE));
        }
        assert!(!CONSOLE_CLIENT_RIGHTS.intersects(Rights::root_only_for(ResourceClass::Console)));
        // A session member's forks inherit it; the front end's attach stays at the root.
        assert!(!CONSOLE_SESSION_CLIENT_RIGHTS
            .intersects(Rights::root_only_for(ResourceClass::Console)));
        assert!(CONSOLE_FRONT_END_RIGHTS.intersects(Rights::root_only_for(ResourceClass::Console)));
    }

    #[test]
    fn a_session_member_is_reissued_as_one() {
        let old = ResourceRef::console_port(0x5600, 1);
        let new = ResourceRef::console_port(0x5600, 2);
        let mut table = CapabilityTable::<16>::new();
        for (holder, rights) in [
            (6, CONSOLE_CLIENT_RIGHTS),
            (7, CONSOLE_SESSION_CLIENT_RIGHTS),
        ] {
            table
                .grant(
                    HolderId(holder),
                    old,
                    rights,
                    Provenance::root(HolderId(holder)),
                )
                .unwrap();
        }
        assert_eq!(reissue_clients_in(&mut table, new, |_| true, |_, _| {}), 2);
        let rights_of = |holder: u64| {
            (0..16)
                .map(|slot| table.record_at(slot))
                .find(|r| {
                    r.state == CapabilityState::Live
                        && r.holder == HolderId(holder)
                        && r.resource == new
                })
                .map(|r| r.rights)
        };
        assert_eq!(rights_of(6), Some(CONSOLE_CLIENT_RIGHTS));
        assert_eq!(rights_of(7), Some(CONSOLE_SESSION_CLIENT_RIGHTS));
    }

    fn holds(table: &CapabilityTable<16>, holder: u64, port: ResourceRef) -> bool {
        (0..16).any(|slot| {
            let record = table.record_at(slot);
            record.state == CapabilityState::Live
                && record.holder == HolderId(holder)
                && record.resource == port
                && record.rights == CONSOLE_CLIENT_RIGHTS
        })
    }

    #[test]
    fn a_restarted_service_reissues_only_kernel_clients_on_earlier_ports() {
        let old = ResourceRef::console_port(0x5600, 1);
        let new = ResourceRef::console_port(0x5600, 2);
        let mut table = CapabilityTable::<16>::new();
        let mut grant = |holder: u64, resource: ResourceRef, rights: Rights| {
            table
                .grant(
                    HolderId(holder),
                    resource,
                    rights,
                    Provenance::root(HolderId(holder)),
                )
                .unwrap();
        };
        // The shell and its fork, a native client, the new service, and a client already on
        // the new port.
        grant(6, old, CONSOLE_CLIENT_RIGHTS);
        grant(8, old, CONSOLE_CLIENT_RIGHTS);
        grant(5, old, CONSOLE_CLIENT_RIGHTS);
        grant(9, new, CONSOLE_SERVICE_PORT_RIGHTS);
        grant(
            9,
            ResourceRef::serial_console_device(),
            CONSOLE_SERVICE_DEVICE_RIGHTS,
        );
        grant(10, new, CONSOLE_CLIENT_RIGHTS);
        let mut seen = [0u64; 4];
        let mut count = 0;
        let reissued = reissue_clients_in(
            &mut table,
            new,
            |holder| holder != HolderId(5),
            |holder, result| {
                result.unwrap();
                seen[count] = holder.0;
                count += 1;
            },
        );
        assert_eq!(reissued, 2);
        assert_eq!(&seen[..count], [6, 8]);
        for pid in [6, 8, 10] {
            assert!(holds(&table, pid, new), "{pid}");
            assert!(!holds(&table, pid, old), "{pid}");
        }
        assert!(holds(&table, 5, old), "a native client keeps its record");
        assert!(!holds(&table, 5, new));
        // Nothing is left to reissue.
        assert_eq!(reissue_clients_in(&mut table, new, |_| true, |_, _| {}), 1);
        assert!(holds(&table, 5, new));
    }

    #[test]
    fn the_service_grants_end_with_the_holder() {
        let service = HolderId(0x5600_0001);
        let port = ResourceRef::console_port(0x5600, 3);
        grant_console_port(service, port, CONSOLE_SERVICE_PORT_RIGHTS).unwrap();
        grant_serial_console_device(service).unwrap();
        assert!(holder_has_resource_rights(
            service,
            port,
            Rights::CONSOLE_SERVE
        ));
        assert!(holder_has_resource_rights(
            service,
            ResourceRef::serial_console_device(),
            Rights::READ.union(Rights::WRITE)
        ));
        assert_eq!(revoke_for_holder(service), 2);
        assert!(!holder_has_resource_rights(
            service,
            ResourceRef::serial_console_device(),
            Rights::WRITE
        ));
    }
}
