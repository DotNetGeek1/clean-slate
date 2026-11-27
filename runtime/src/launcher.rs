//! A launcher client (#237): asks init, over its launcher port, to start a manifest row by name
//! and lists the rows it may start. The wire format is `clean_slate_native_abi::launcher`.

use clean_slate_capability::{ResourceClass, LAUNCHER_PORT_ID};
use clean_slate_native_abi::launcher::{AppName, LauncherEvent, LauncherRequest};
use clean_slate_native_abi::status::STATUS_EINVAL;

use crate::port::{Connection, Deadline, Wait};
use crate::{Error, Syscalls};

/// The client end of the caller's connection to the launcher port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Launcher {
    connection: Connection,
}

impl Launcher {
    /// Connects with the caller's `LAUNCH_CONNECT` capability on the launcher port.
    pub fn connect<S: Syscalls>(sys: &mut S) -> Result<Self, Error> {
        Connection::connect(sys, ResourceClass::Launcher, LAUNCHER_PORT_ID)
            .map(Self::from_connection)
    }

    pub const fn from_connection(connection: Connection) -> Self {
        Self { connection }
    }

    pub const fn connection(self) -> Connection {
        self.connection
    }

    /// Asks for the listed rows: one [`LauncherEvent::Entry`] each, then a
    /// [`LauncherEvent::ListEnd`].
    pub fn request_list<S: Syscalls>(self, sys: &mut S) -> Result<(), Error> {
        self.connection
            .send(sys, &LauncherRequest::List.encode(), None, Deadline::NEVER)
    }

    /// Asks init to start the row named `name`; the answer is a [`LauncherEvent::StartResult`].
    pub fn request_start<S: Syscalls>(self, sys: &mut S, name: &str) -> Result<(), Error> {
        let name = AppName::new(name.as_bytes()).ok_or(Error::Failed(STATUS_EINVAL))?;
        self.connection.send(
            sys,
            &LauncherRequest::Start(name).encode(),
            None,
            Deadline::NEVER,
        )
    }

    /// The next event from init. Init ending the connection is [`Error::Gone`].
    pub fn next_event<S: Syscalls>(self, sys: &mut S, wait: Wait) -> Result<LauncherEvent, Error> {
        let frame = self.connection.recv_frame(sys, wait)?;
        LauncherEvent::decode(&frame).map_err(|_| Error::Failed(STATUS_EINVAL))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeKernel;
    use clean_slate_native_abi::launcher::{AppEntry, AppState, StartResult};

    /// The fake kernel's one port stands in for the launcher port.
    fn launcher(sys: &mut FakeKernel) -> Launcher {
        let id = sys.resource_id();
        Launcher::from_connection(
            Connection::connect(sys, ResourceClass::Graphics, id).expect("connect"),
        )
    }

    #[test]
    fn requests_are_one_frame_each() {
        let mut sys = FakeKernel::new();
        let launcher = launcher(&mut sys);
        launcher.request_list(&mut sys).expect("list");
        launcher.request_start(&mut sys, "terminal").expect("start");
        assert_eq!(
            LauncherRequest::decode(&sys.server_recv_frame().unwrap()),
            Ok(LauncherRequest::List)
        );
        assert_eq!(
            LauncherRequest::decode(&sys.server_recv_frame().unwrap()),
            Ok(LauncherRequest::Start(AppName::new(b"terminal").unwrap()))
        );
        assert_eq!(
            launcher.request_start(&mut sys, "two words"),
            Err(Error::Failed(STATUS_EINVAL))
        );
        assert_eq!(sys.server_recv_frame(), None);
    }

    #[test]
    fn events_decode_and_an_ended_connection_is_gone() {
        let mut sys = FakeKernel::new();
        let launcher = launcher(&mut sys);
        let entry = AppEntry {
            service: 0x5700,
            state: AppState::Running,
            generation: 1,
            pid: 9,
            name: AppName::new(b"terminal").unwrap(),
        };
        sys.server_post(&LauncherEvent::Changed(entry).encode());
        sys.server_post(
            &LauncherEvent::StartResult {
                result: StartResult::Started,
                service: 0x5700,
            }
            .encode(),
        );
        assert_eq!(
            launcher.next_event(&mut sys, Wait::No),
            Ok(LauncherEvent::Changed(entry))
        );
        assert_eq!(
            launcher.next_event(&mut sys, Wait::No),
            Ok(LauncherEvent::StartResult {
                result: StartResult::Started,
                service: 0x5700
            })
        );
        assert_eq!(
            launcher.next_event(&mut sys, Wait::No),
            Err(Error::WouldBlock)
        );
        sys.server_post(&[0xee; 64]);
        assert_eq!(
            launcher.next_event(&mut sys, Wait::No),
            Err(Error::Failed(STATUS_EINVAL))
        );
        sys.server_disconnect(1);
        assert_eq!(launcher.next_event(&mut sys, Wait::No), Err(Error::Gone));
    }
}
