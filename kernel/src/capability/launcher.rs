//! Launcher grants (#237): the only root grants of `Launcher` authority.
//!
//! The kernel registers the one launcher port for init when it launches init and grants init
//! `LAUNCH_SERVE` on it; a row with `Grant::LauncherClient` gets `LAUNCH_CONNECT` and nothing
//! else. Init's death is fatal, so the port is never served by anyone else and has no
//! instance generation. Every grant is a root record for exactly one holder, so process
//! teardown (`revoke_for_holder`) removes it.

use clean_slate_capability::{CapabilityError, HolderId, ResourceRef, Rights};
use clean_slate_native_abi::PortParams;

use super::grant_root;

/// The launcher port's limits. Requests are rare and answered at once, but a `LIST` answer is
/// one event per listed row plus its end, and each state change of a listed row posts one
/// more, so the event queue holds a full answer and the changes of a busy boot.
pub(crate) const LAUNCHER_PORT_PARAMS: PortParams = PortParams {
    event_depth: 32,
    request_depth: 16,
    max_connections: 4,
    max_outstanding: 4,
    max_connections_per_holder: 1,
};

const _: () = assert!(LAUNCHER_PORT_PARAMS.validate().is_ok());

pub(crate) const LAUNCHER_SERVE_RIGHTS: Rights = Rights::LAUNCH_SERVE;
pub(crate) const LAUNCHER_CLIENT_RIGHTS: Rights = Rights::LAUNCH_CONNECT;

/// Root `rights` on the launcher port; returns the handle.
pub(crate) fn grant_launcher_port(
    holder: HolderId,
    rights: Rights,
) -> Result<u64, CapabilityError> {
    grant_root(holder, ResourceRef::launcher_port(), rights).map(|handle| handle.encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_capability::ResourceClass;
    use clean_slate_native_abi::port_rights_for;

    #[test]
    fn init_serves_and_clients_only_connect() {
        let rights = port_rights_for(ResourceClass::Launcher).unwrap();
        assert_eq!(LAUNCHER_SERVE_RIGHTS, rights.serve);
        assert_eq!(LAUNCHER_CLIENT_RIGHTS, rights.connect);
        assert!(!LAUNCHER_CLIENT_RIGHTS.intersects(Rights::root_only_for(ResourceClass::Launcher)));
    }

    #[test]
    fn a_list_answer_fits_the_event_queue() {
        let listed_rows_bound = 12;
        assert!(usize::from(LAUNCHER_PORT_PARAMS.event_depth) > listed_rows_bound + 1);
    }
}
