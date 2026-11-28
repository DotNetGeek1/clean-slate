//! #237 init's side of the launcher port: answers `LIST` and `START` from [`SystemInit`] and
//! tells every connected client when a listed row's state or instance changes. #373: a
//! `SYSTEM_STOP` from a connection whose capability holds `LAUNCH_POWER` (the kernel's trusted
//! envelope says which rights it holds) starts init's system stop.
//!
//! Host-testable: the port is behind [`LauncherPort`]; `bin/init.rs` implements it with
//! syscall 17 `POST` and `DISCONNECT` on init's `LAUNCH_SERVE` handle.

use clean_slate_capability::Rights;
use clean_slate_native_abi::launcher::{AppEntry, LauncherEvent, LauncherRequest, StopResult};
use clean_slate_native_abi::port::PORT_FRAME_BYTES;
use clean_slate_native_abi::RecvKind;
use clean_slate_service_lifecycle::MonotonicTicks;

use crate::control::LifecycleControl;
use crate::runtime::DiagnosticSink;
use crate::system_init::SystemInit;

type Frame = [u8; PORT_FRAME_BYTES];

/// Clients the launcher tracks at once: the kernel's `max_connections` for the port.
pub const LAUNCHER_CLIENTS: usize = 4;

/// Listed rows whose last reported entry the launcher remembers.
const LISTED_ROWS: usize = 12;

/// A refused post: the client's event queue is full, or it is gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostRefused;

/// The serving side of the launcher port.
pub trait LauncherPort {
    fn post(&mut self, connection: u64, frame: &Frame) -> Result<(), PostRefused>;
    fn disconnect(&mut self, connection: u64);
}

pub struct Launcher {
    clients: [Option<u64>; LAUNCHER_CLIENTS],
    reported: [Option<AppEntry>; LISTED_ROWS],
}

impl Default for Launcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Launcher {
    pub const fn new() -> Self {
        Self {
            clients: [None; LAUNCHER_CLIENTS],
            reported: [None; LISTED_ROWS],
        }
    }

    /// Clients currently tracked.
    pub fn client_count(&self) -> usize {
        self.clients.iter().flatten().count()
    }

    /// One received record. A request from a connection not seen before adds it; a malformed
    /// request, or one the launcher cannot answer in full, ends that connection. `rights` are
    /// the bits of the client's capability from the record's trusted envelope.
    #[allow(clippy::too_many_arguments)]
    pub fn on_record<C, D, P, const N: usize>(
        &mut self,
        init: &mut SystemInit<C, D, N>,
        port: &mut P,
        now: MonotonicTicks,
        kind: RecvKind,
        connection: u64,
        rights: u32,
        frame: &Frame,
    ) where
        C: LifecycleControl,
        D: DiagnosticSink,
        P: LauncherPort,
    {
        match kind {
            RecvKind::Request => {}
            RecvKind::ClientClosed | RecvKind::ClientExited | RecvKind::ClientRevoked => {
                self.forget(connection);
                return;
            }
        }
        if !self.track(connection) {
            port.disconnect(connection);
            return;
        }
        let answered = match LauncherRequest::decode(frame) {
            Ok(LauncherRequest::List) => {
                let mut count = 0u8;
                let mut posted = Ok(());
                for entry in init.launch_entries() {
                    count = count.saturating_add(1);
                    posted =
                        posted.and(port.post(connection, &LauncherEvent::Entry(entry).encode()));
                }
                posted.and(port.post(connection, &LauncherEvent::ListEnd { count }.encode()))
            }
            Ok(LauncherRequest::SystemStop) => {
                let result = if rights & Rights::LAUNCH_POWER.bits() != 0 {
                    init.request_system_stop(now)
                } else {
                    init.refuse_system_stop();
                    StopResult::Refused
                };
                port.post(connection, &LauncherEvent::StopResult(result).encode())
            }
            Ok(LauncherRequest::Start(name)) => {
                let (result, service) = init.launch(now, name.as_bytes());
                port.post(
                    connection,
                    &LauncherEvent::StartResult { result, service }.encode(),
                )
            }
            Err(_) => Err(PostRefused),
        };
        if answered.is_err() {
            self.forget(connection);
            port.disconnect(connection);
        }
    }

    /// After every wake: one `CHANGED` to each client for each listed row whose entry differs
    /// from the one last published. The first call only records the entries, since no client
    /// can have listed before it.
    pub fn publish_changes<C, D, P, const N: usize>(
        &mut self,
        init: &SystemInit<C, D, N>,
        port: &mut P,
    ) where
        C: LifecycleControl,
        D: DiagnosticSink,
        P: LauncherPort,
    {
        for (index, entry) in init.launch_entries().take(LISTED_ROWS).enumerate() {
            let previous = self.reported[index].replace(entry);
            if previous.is_none_or(|previous| previous == entry) {
                continue;
            }
            let frame = LauncherEvent::Changed(entry).encode();
            for slot in 0..LAUNCHER_CLIENTS {
                let Some(connection) = self.clients[slot] else {
                    continue;
                };
                if port.post(connection, &frame).is_err() {
                    // A client that does not drain its events cannot be kept current.
                    self.clients[slot] = None;
                    port.disconnect(connection);
                }
            }
        }
    }

    fn track(&mut self, connection: u64) -> bool {
        if self.clients.contains(&Some(connection)) {
            return true;
        }
        match self.clients.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some(connection);
                true
            }
            None => false,
        }
    }

    fn forget(&mut self, connection: u64) {
        for slot in &mut self.clients {
            if *slot == Some(connection) {
                *slot = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_init::tests::Harness;
    use clean_slate_native_abi::launcher::{AppName, AppState, StartResult};
    use clean_slate_service_fixtures::manifest::{
        RestartSpec, ServiceSpec, Start, CONSOLE_SERVICE_SPEC, PLAYGROUND_SERVICE_SPEC,
        SYSTEM_MANIFEST,
    };
    use clean_slate_service_fixtures::{CONSOLE_SERVICE_ID, PLAYGROUND_SERVICE_ID};
    use clean_slate_service_lifecycle::LifecycleEventKind;
    use std::vec::Vec;

    #[derive(Default)]
    struct Port {
        posted: Vec<(u64, LauncherEvent)>,
        disconnected: Vec<u64>,
        full: Vec<u64>,
    }

    impl LauncherPort for Port {
        fn post(&mut self, connection: u64, frame: &Frame) -> Result<(), PostRefused> {
            if self.full.contains(&connection) {
                return Err(PostRefused);
            }
            self.posted
                .push((connection, LauncherEvent::decode(frame).unwrap()));
            Ok(())
        }

        fn disconnect(&mut self, connection: u64) {
            self.disconnected.push(connection);
        }
    }

    /// The console row and a playground that starts only on request.
    static ON_REQUEST: &[ServiceSpec] = &[
        CONSOLE_SERVICE_SPEC,
        ServiceSpec {
            depends_on: &[CONSOLE_SERVICE_ID],
            grants: &[],
            restart: RestartSpec::Never,
            start: Start::OnRequest,
            ..PLAYGROUND_SERVICE_SPEC
        },
    ];

    struct Rig {
        harness: Harness,
        launcher: Launcher,
        port: Port,
    }

    impl Rig {
        fn new(manifest: &'static [ServiceSpec]) -> Self {
            let mut rig = Self {
                harness: Harness::boot_manifest_unready(manifest),
                launcher: Launcher::new(),
                port: Port::default(),
            };
            rig.publish();
            rig
        }

        fn request(&mut self, connection: u64, request: LauncherRequest) {
            self.launcher.on_record(
                &mut self.harness.init,
                &mut self.port,
                1,
                RecvKind::Request,
                connection,
                Rights::LAUNCH_CONNECT.bits(),
                &request.encode(),
            );
        }

        fn publish(&mut self) {
            self.launcher
                .publish_changes(&self.harness.init, &mut self.port);
        }

        fn report(&mut self, service: ServiceId, kind: LifecycleEventKind) {
            self.harness.report(1, service, kind);
            self.publish();
        }

        fn last(&mut self) -> LauncherEvent {
            self.port.posted.pop().expect("an event").1
        }

        fn changes(&mut self) -> Vec<(u64, AppState, u64)> {
            let changes = self
                .port
                .posted
                .iter()
                .filter_map(|(connection, event)| match event {
                    LauncherEvent::Changed(entry) => Some((*connection, entry.state, entry.pid)),
                    _ => None,
                })
                .collect();
            self.port.posted.clear();
            changes
        }
    }

    use clean_slate_service_lifecycle::ServiceId;

    fn start(name: &str) -> LauncherRequest {
        LauncherRequest::Start(AppName::new(name.as_bytes()).unwrap())
    }

    fn result(result: StartResult) -> LauncherEvent {
        LauncherEvent::StartResult {
            result,
            service: PLAYGROUND_SERVICE_ID.0,
        }
    }

    #[test]
    fn list_answers_every_listed_row_then_the_end() {
        let mut rig = Rig::new(ON_REQUEST);
        rig.request(7, LauncherRequest::List);
        assert_eq!(rig.port.posted.len(), 2);
        let LauncherEvent::Entry(entry) = rig.port.posted[0].1 else {
            panic!("{:?}", rig.port.posted)
        };
        assert_eq!(entry.service, PLAYGROUND_SERVICE_ID.0);
        assert_eq!(entry.state, AppState::Idle);
        assert_eq!(entry.pid, 0);
        assert_eq!(entry.name.as_str(), "playground");
        assert_eq!(rig.port.posted[1], (7, LauncherEvent::ListEnd { count: 1 }));
        assert_eq!(rig.launcher.client_count(), 1);
    }

    #[test]
    fn an_on_request_row_starts_only_when_asked_and_once_its_dependencies_run() {
        let mut rig = Rig::new(ON_REQUEST);
        assert_eq!(
            rig.harness.starts_of(PLAYGROUND_SERVICE_ID),
            0,
            "not at boot"
        );
        rig.request(7, start("playground"));
        assert_eq!(
            rig.last(),
            result(StartResult::Busy),
            "the console is not running yet"
        );
        rig.report(CONSOLE_SERVICE_ID, LifecycleEventKind::Ready);
        rig.request(7, start("playground"));
        assert_eq!(rig.last(), result(StartResult::Started));
        assert_eq!(rig.harness.starts_of(PLAYGROUND_SERVICE_ID), 1);
        rig.request(7, start("playground"));
        assert_eq!(rig.last(), result(StartResult::AlreadyRunning));
        rig.request(7, start("nothing"));
        assert_eq!(
            rig.last(),
            LauncherEvent::StartResult {
                result: StartResult::UnknownName,
                service: 0
            }
        );
        assert_eq!(rig.harness.starts_of(PLAYGROUND_SERVICE_ID), 1);
        assert_eq!(
            rig.harness
                .lines_with("[INIT] launch name=playground service=21250 result=started")
                .len(),
            1
        );
    }

    #[test]
    fn changes_reach_every_client_and_an_exit_makes_the_row_idle_again() {
        let mut rig = Rig::new(ON_REQUEST);
        rig.report(CONSOLE_SERVICE_ID, LifecycleEventKind::Ready);
        rig.request(7, LauncherRequest::List);
        rig.request(8, LauncherRequest::List);
        rig.port.posted.clear();
        rig.request(7, start("playground"));
        rig.publish();
        assert_eq!(
            rig.changes(),
            [(7, AppState::Starting, 102), (8, AppState::Starting, 102)]
        );
        rig.report(PLAYGROUND_SERVICE_ID, LifecycleEventKind::Ready);
        assert_eq!(
            rig.changes(),
            [(7, AppState::Running, 102), (8, AppState::Running, 102)]
        );
        rig.report(PLAYGROUND_SERVICE_ID, LifecycleEventKind::Exited);
        assert_eq!(
            rig.changes(),
            [(7, AppState::Idle, 0), (8, AppState::Idle, 0)]
        );
        assert_eq!(
            rig.harness
                .lines_with("[INIT] service=21250 exited; starts again on request")
                .len(),
            1
        );
        rig.publish();
        assert!(rig.changes().is_empty(), "nothing changed since");
        rig.request(7, start("playground"));
        assert_eq!(
            rig.last(),
            result(StartResult::Started),
            "an idle row starts again on request"
        );
        assert_eq!(rig.harness.starts_of(PLAYGROUND_SERVICE_ID), 2);
    }

    #[test]
    fn a_fault_also_leaves_the_row_idle_and_boot_settles_with_it_idle() {
        let mut rig = Rig::new(ON_REQUEST);
        rig.report(CONSOLE_SERVICE_ID, LifecycleEventKind::Ready);
        assert_eq!(
            rig.harness
                .lines_with("[INIT] boot settled running=1 down=0 idle=1; waiting, no deadline")
                .len(),
            1
        );
        rig.request(7, start("playground"));
        rig.report(PLAYGROUND_SERVICE_ID, LifecycleEventKind::Faulted);
        assert_eq!(
            rig.harness
                .lines_with("[INIT] service=21250 faulted; starts again on request")
                .len(),
            1
        );
        assert_eq!(
            rig.harness.init.launch_entries().next().unwrap().state,
            AppState::Idle
        );
        assert_eq!(
            rig.harness.init.next_deadline(),
            None,
            "no retry is scheduled"
        );
    }

    #[test]
    fn the_base_manifest_lists_nothing() {
        let mut rig = Rig::new(SYSTEM_MANIFEST);
        rig.request(7, LauncherRequest::List);
        assert_eq!(rig.port.posted, [(7, LauncherEvent::ListEnd { count: 0 })]);
    }

    #[test]
    fn malformed_requests_full_queues_and_a_fifth_client_end_the_connection() {
        let mut rig = Rig::new(ON_REQUEST);
        let mut bad = LauncherRequest::List.encode();
        bad[0] = 99;
        rig.launcher.on_record(
            &mut rig.harness.init,
            &mut rig.port,
            1,
            RecvKind::Request,
            7,
            Rights::LAUNCH_CONNECT.bits(),
            &bad,
        );
        assert_eq!(rig.port.disconnected, [7]);
        assert_eq!(rig.launcher.client_count(), 0);
        rig.port.full.push(8);
        rig.request(8, LauncherRequest::List);
        assert_eq!(rig.port.disconnected, [7, 8]);
        for connection in 10..14 {
            rig.request(connection, LauncherRequest::List);
        }
        assert_eq!(rig.launcher.client_count(), LAUNCHER_CLIENTS);
        rig.request(14, LauncherRequest::List);
        assert_eq!(rig.port.disconnected, [7, 8, 14]);
        rig.launcher.on_record(
            &mut rig.harness.init,
            &mut rig.port,
            1,
            RecvKind::ClientClosed,
            10,
            0,
            &[0; PORT_FRAME_BYTES],
        );
        assert_eq!(rig.launcher.client_count(), LAUNCHER_CLIENTS - 1);
    }

    #[test]
    fn a_client_whose_queue_is_full_is_dropped_on_a_change() {
        let mut rig = Rig::new(ON_REQUEST);
        rig.report(CONSOLE_SERVICE_ID, LifecycleEventKind::Ready);
        rig.request(7, LauncherRequest::List);
        rig.port.full.push(7);
        rig.request(8, start("playground"));
        rig.publish();
        assert_eq!(rig.port.disconnected, [7]);
        assert_eq!(rig.changes(), [(8, AppState::Starting, 102)]);
    }

    #[test]
    fn a_system_stop_needs_launch_power() {
        let mut rig = Rig::new(ON_REQUEST);
        rig.request(7, LauncherRequest::SystemStop);
        assert_eq!(
            rig.port.posted,
            [(7, LauncherEvent::StopResult(StopResult::Refused))]
        );
        assert!(!rig.harness.init.system_stopping());
        assert!(rig.port.disconnected.is_empty());
        assert_eq!(
            rig.harness
                .lines_with("[INIT] system stop refused: the client does not hold launch_power")
                .len(),
            1
        );
        rig.port.posted.clear();
        let power = Rights::LAUNCH_CONNECT.union(Rights::LAUNCH_POWER).bits();
        for expected in [StopResult::Accepted, StopResult::AlreadyStopping] {
            rig.launcher.on_record(
                &mut rig.harness.init,
                &mut rig.port,
                1,
                RecvKind::Request,
                8,
                power,
                &LauncherRequest::SystemStop.encode(),
            );
            assert_eq!(rig.last(), LauncherEvent::StopResult(expected));
        }
        assert!(rig.harness.init.system_stopping());
    }
}
