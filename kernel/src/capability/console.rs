//! Console grants (#310): the only root grants of `Console` authority.
//!
//! The live console service alone serves the console port and holds the serial console device;
//! a client connects with `CONSOLE_CONNECT` and nothing else. Every grant is a root record for
//! exactly one holder, so process teardown (`revoke_for_holder`) removes it.

use clean_slate_capability::{CapabilityError, HolderId, ResourceRef, Rights};
use clean_slate_native_abi::PortParams;

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
