//! #218: applies the launch grants of a service's manifest row.
//!
//! Which grants a service receives comes only from the active manifest
//! ([`super::control::ServiceLifecycleController::launch_grants`]); the kernel calls behind each
//! grant sit behind traits so host tests can see which call every grant kind reaches.

use clean_slate_service_fixtures::manifest::Grant;
use clean_slate_service_lifecycle::InstanceGeneration;

/// Grants whose handle the image reads from its bootstrap page, so they are applied while the
/// image's address space is being built.
pub(crate) trait BootstrapGrantAuthority {
    /// Returns the encoded object-service role handle.
    fn grant_object_service_role(&mut self, pid: u64) -> Result<u64, &'static str>;
    /// Returns the encoded `AUDIT_READ` handle on the audit log.
    fn grant_audit_reader(&mut self, pid: u64) -> Result<u64, &'static str>;
    /// Returns the encoded `READ | WRITE | DIRECTORY` handle on the audit store (#219).
    fn grant_audit_store(&mut self, pid: u64) -> Result<u64, &'static str>;
    /// Returns the console IPC send handle.
    fn grant_console(&mut self, pid: u64) -> Result<u64, &'static str>;
}

/// Which client role a graphics role grant gives on the live compositor's port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GraphicsRole {
    /// `Grant::GraphicsShellRole`: `GFX_CONNECT | GFX_SHELL`.
    Shell,
    /// `Grant::GraphicsAppRole`: `GFX_CONNECT`.
    App,
}

/// Grants applied to a spawned instance before it is recorded live.
pub(crate) trait InstanceGrantAuthority {
    fn grant_block_device(&mut self, pid: u64) -> Result<(), &'static str>;
    fn grant_network_service(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
    ) -> Result<(), &'static str>;
    /// Registers the instance's graphics port and grants it `GFX_SERVE` there.
    fn grant_graphics_port(&mut self, pid: u64) -> Result<(), &'static str>;
    fn grant_display_presenter(&mut self, pid: u64) -> Result<(), &'static str>;
    fn grant_input_seat(&mut self, pid: u64) -> Result<(), &'static str>;
    /// `role` on the port of the live `Grant::GraphicsPort` instance; fails when there is none.
    fn grant_graphics_role(&mut self, pid: u64, role: GraphicsRole) -> Result<(), &'static str>;
    /// Registers the instance's console port, grants it `CONSOLE_SERVE` there and `WRITE` on
    /// the serial console device.
    fn grant_console_service(&mut self, pid: u64) -> Result<(), &'static str>;
    /// `CONSOLE_CONNECT`, with `role`'s extra right, on the port of the live
    /// `Grant::ConsoleService` instance; fails when there is none.
    fn grant_console_client(
        &mut self,
        pid: u64,
        role: ConsoleClientRole,
    ) -> Result<(), &'static str>;
    /// `LAUNCH_CONNECT` on init's launcher port (#237).
    fn grant_launcher_client(&mut self, pid: u64) -> Result<(), &'static str>;
    /// The network client entitlement and, when a network instance is live, a client
    /// capability bound to it; the instance is attributed to its row for the per-app network
    /// policy (#353). With `stats` (the row also holds `Grant::NetworkStats`, #378) both carry
    /// `NET_STATS`.
    fn grant_native_network_client(&mut self, pid: u64, stats: bool) -> Result<(), &'static str>;
    /// `OBSERVE` on the system usage view (#379): every row of the resource snapshot.
    fn grant_system_observer(&mut self, pid: u64) -> Result<(), &'static str>;
}

/// Which console port client a row is (#310, #311).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConsoleClientRole {
    /// `Grant::ConsoleClient`: its streams are framed on serial.
    Plain,
    /// `Grant::ConsoleSession`: its streams, and its forks', belong to the console session.
    Session,
    /// `Grant::ConsoleFrontEnd`: it may attach as the session's front end.
    FrontEnd,
}

#[cfg(test)]
impl ConsoleClientRole {
    pub(crate) const fn grant(self) -> Grant {
        match self {
            Self::Plain => Grant::ConsoleClient,
            Self::Session => Grant::ConsoleSession,
            Self::FrontEnd => Grant::ConsoleFrontEnd,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct BootstrapGrantHandles {
    pub(crate) object_service_role: Option<u64>,
    pub(crate) audit_reader: Option<u64>,
    pub(crate) audit_store: Option<u64>,
    pub(crate) console: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GrantFailure {
    pub(crate) grant: Grant,
    pub(crate) message: &'static str,
}

/// Only native images with a bootstrap page call this. Linux rows and desktop rows apply
/// `Console` on their own launch paths.
pub(crate) fn apply_bootstrap_grants<A: BootstrapGrantAuthority>(
    grants: &[Grant],
    pid: u64,
    authority: &mut A,
) -> Result<BootstrapGrantHandles, &'static str> {
    let mut handles = BootstrapGrantHandles::default();
    for grant in grants {
        match grant {
            Grant::ObjectServiceRole => {
                handles.object_service_role = Some(authority.grant_object_service_role(pid)?);
            }
            Grant::AuditReader => {
                handles.audit_reader = Some(authority.grant_audit_reader(pid)?);
            }
            Grant::AuditStore => {
                handles.audit_store = Some(authority.grant_audit_store(pid)?);
            }
            Grant::Console => {
                handles.console = Some(authority.grant_console(pid)?);
            }
            Grant::BlockDevice
            | Grant::NetworkService
            | Grant::GraphicsPort
            | Grant::DisplayPresenter
            | Grant::InputSeat
            | Grant::GraphicsShellRole
            | Grant::GraphicsAppRole
            | Grant::ConsoleService
            | Grant::ConsoleClient
            | Grant::ConsoleSession
            | Grant::ConsoleFrontEnd
            | Grant::LauncherClient
            | Grant::NativeNetworkClient
            | Grant::NetworkStats
            | Grant::SystemObserver => {}
            // Applied by the Linux launch path while it builds the process.
            Grant::ConsoleInput | Grant::TmpObjects | Grant::NetworkClient => {}
        }
    }
    Ok(handles)
}

pub(crate) fn apply_instance_grants<A: InstanceGrantAuthority>(
    grants: &[Grant],
    pid: u64,
    generation: InstanceGeneration,
    authority: &mut A,
) -> Result<(), GrantFailure> {
    for &grant in grants {
        let result = match grant {
            Grant::BlockDevice => authority.grant_block_device(pid),
            Grant::NetworkService => authority.grant_network_service(pid, generation),
            Grant::GraphicsPort => authority.grant_graphics_port(pid),
            Grant::DisplayPresenter => authority.grant_display_presenter(pid),
            Grant::InputSeat => authority.grant_input_seat(pid),
            Grant::GraphicsShellRole => authority.grant_graphics_role(pid, GraphicsRole::Shell),
            Grant::GraphicsAppRole => authority.grant_graphics_role(pid, GraphicsRole::App),
            Grant::ConsoleService => authority.grant_console_service(pid),
            Grant::ConsoleClient => authority.grant_console_client(pid, ConsoleClientRole::Plain),
            Grant::ConsoleSession => {
                authority.grant_console_client(pid, ConsoleClientRole::Session)
            }
            Grant::ConsoleFrontEnd => {
                authority.grant_console_client(pid, ConsoleClientRole::FrontEnd)
            }
            Grant::LauncherClient => authority.grant_launcher_client(pid),
            Grant::NativeNetworkClient => {
                authority.grant_native_network_client(pid, grants.contains(&Grant::NetworkStats))
            }
            // Carried by the `NativeNetworkClient` grant, which manifest validation puts first.
            Grant::NetworkStats => Ok(()),
            Grant::SystemObserver => authority.grant_system_observer(pid),
            Grant::ObjectServiceRole
            | Grant::AuditReader
            | Grant::AuditStore
            | Grant::Console
            | Grant::ConsoleInput
            | Grant::TmpObjects
            | Grant::NetworkClient => Ok(()),
        };
        result.map_err(|message| GrantFailure { grant, message })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_service_fixtures::manifest::{grants_for, SYSTEM_MANIFEST};
    use clean_slate_service_fixtures::{
        NETWORK_SERVICE_ID, STORAGE_SERVICE_ID, STORAGE_UNAUTHORIZED_SERVICE_ID,
        SYSTEM_SHELL_SERVICE_ID,
    };

    #[derive(Debug, PartialEq, Eq)]
    enum Call {
        ObjectServiceRole(u64),
        AuditReader(u64),
        AuditStore(u64),
        Console(u64),
        BlockDevice(u64),
        NetworkService(u64, InstanceGeneration),
        GraphicsPort(u64),
        DisplayPresenter(u64),
        InputSeat(u64),
        GraphicsRole(u64, GraphicsRole),
        ConsoleService(u64),
        ConsoleClient(u64, ConsoleClientRole),
        LauncherClient(u64),
        NativeNetworkClient(u64, bool),
        SystemObserver(u64),
    }

    #[derive(Default)]
    struct Recorder {
        calls: Vec<Call>,
        fail: Option<Grant>,
    }

    impl Recorder {
        fn outcome(&self, grant: Grant) -> Result<(), &'static str> {
            if self.fail == Some(grant) {
                Err("injected failure")
            } else {
                Ok(())
            }
        }
    }

    impl BootstrapGrantAuthority for Recorder {
        fn grant_object_service_role(&mut self, pid: u64) -> Result<u64, &'static str> {
            self.calls.push(Call::ObjectServiceRole(pid));
            self.outcome(Grant::ObjectServiceRole).map(|()| 0xa0b0)
        }

        fn grant_audit_reader(&mut self, pid: u64) -> Result<u64, &'static str> {
            self.calls.push(Call::AuditReader(pid));
            self.outcome(Grant::AuditReader).map(|()| 0xad17)
        }

        fn grant_audit_store(&mut self, pid: u64) -> Result<u64, &'static str> {
            self.calls.push(Call::AuditStore(pid));
            self.outcome(Grant::AuditStore).map(|()| 0xad57)
        }

        fn grant_console(&mut self, pid: u64) -> Result<u64, &'static str> {
            self.calls.push(Call::Console(pid));
            self.outcome(Grant::Console).map(|()| 0xc0e5)
        }
    }

    impl InstanceGrantAuthority for Recorder {
        fn grant_block_device(&mut self, pid: u64) -> Result<(), &'static str> {
            self.calls.push(Call::BlockDevice(pid));
            self.outcome(Grant::BlockDevice)
        }

        fn grant_network_service(
            &mut self,
            pid: u64,
            generation: InstanceGeneration,
        ) -> Result<(), &'static str> {
            self.calls.push(Call::NetworkService(pid, generation));
            self.outcome(Grant::NetworkService)
        }

        fn grant_graphics_port(&mut self, pid: u64) -> Result<(), &'static str> {
            self.calls.push(Call::GraphicsPort(pid));
            self.outcome(Grant::GraphicsPort)
        }

        fn grant_display_presenter(&mut self, pid: u64) -> Result<(), &'static str> {
            self.calls.push(Call::DisplayPresenter(pid));
            self.outcome(Grant::DisplayPresenter)
        }

        fn grant_input_seat(&mut self, pid: u64) -> Result<(), &'static str> {
            self.calls.push(Call::InputSeat(pid));
            self.outcome(Grant::InputSeat)
        }

        fn grant_graphics_role(
            &mut self,
            pid: u64,
            role: GraphicsRole,
        ) -> Result<(), &'static str> {
            self.calls.push(Call::GraphicsRole(pid, role));
            self.outcome(match role {
                GraphicsRole::Shell => Grant::GraphicsShellRole,
                GraphicsRole::App => Grant::GraphicsAppRole,
            })
        }

        fn grant_console_service(&mut self, pid: u64) -> Result<(), &'static str> {
            self.calls.push(Call::ConsoleService(pid));
            self.outcome(Grant::ConsoleService)
        }

        fn grant_console_client(
            &mut self,
            pid: u64,
            role: ConsoleClientRole,
        ) -> Result<(), &'static str> {
            self.calls.push(Call::ConsoleClient(pid, role));
            self.outcome(role.grant())
        }

        fn grant_launcher_client(&mut self, pid: u64) -> Result<(), &'static str> {
            self.calls.push(Call::LauncherClient(pid));
            self.outcome(Grant::LauncherClient)
        }

        fn grant_native_network_client(
            &mut self,
            pid: u64,
            stats: bool,
        ) -> Result<(), &'static str> {
            self.calls.push(Call::NativeNetworkClient(pid, stats));
            self.outcome(Grant::NativeNetworkClient)
        }

        fn grant_system_observer(&mut self, pid: u64) -> Result<(), &'static str> {
            self.calls.push(Call::SystemObserver(pid));
            self.outcome(Grant::SystemObserver)
        }
    }

    fn apply_both(grants: &[Grant], recorder: &mut Recorder) -> BootstrapGrantHandles {
        let handles = apply_bootstrap_grants(grants, 7, recorder).unwrap();
        apply_instance_grants(grants, 7, InstanceGeneration(3), recorder).unwrap();
        handles
    }

    #[test]
    fn unknown_service_reaches_no_grant_call() {
        let mut recorder = Recorder::default();
        let handles = apply_both(
            grants_for(SYSTEM_MANIFEST, STORAGE_UNAUTHORIZED_SERVICE_ID),
            &mut recorder,
        );
        assert!(recorder.calls.is_empty());
        assert_eq!(handles, BootstrapGrantHandles::default());
    }

    #[test]
    fn row_without_grants_reaches_no_grant_call() {
        let mut recorder = Recorder::default();
        apply_both(&[], &mut recorder);
        assert!(recorder.calls.is_empty());
    }

    #[test]
    fn block_device_grant_reaches_block_call_only() {
        let mut recorder = Recorder::default();
        apply_both(&[Grant::BlockDevice], &mut recorder);
        assert_eq!(recorder.calls, [Call::BlockDevice(7)]);
    }

    #[test]
    fn network_service_grant_reaches_network_call_with_generation() {
        let mut recorder = Recorder::default();
        apply_both(&[Grant::NetworkService], &mut recorder);
        assert_eq!(
            recorder.calls,
            [Call::NetworkService(7, InstanceGeneration(3))]
        );
    }

    #[test]
    fn object_service_role_is_granted_once_at_bootstrap() {
        let mut recorder = Recorder::default();
        let handles = apply_both(&[Grant::ObjectServiceRole], &mut recorder);
        assert_eq!(recorder.calls, [Call::ObjectServiceRole(7)]);
        assert_eq!(handles.object_service_role, Some(0xa0b0));
    }

    #[test]
    fn system_rows_reach_the_calls_lanes_rely_on() {
        let mut storage = Recorder::default();
        apply_both(
            grants_for(SYSTEM_MANIFEST, STORAGE_SERVICE_ID),
            &mut storage,
        );
        assert_eq!(
            storage.calls,
            [Call::ObjectServiceRole(7), Call::BlockDevice(7)]
        );

        let mut network = Recorder::default();
        apply_both(
            grants_for(SYSTEM_MANIFEST, NETWORK_SERVICE_ID),
            &mut network,
        );
        assert_eq!(
            network.calls,
            [Call::NetworkService(7, InstanceGeneration(3))]
        );
    }

    /// The Linux launch path applies its own grants and never builds a native bootstrap page.
    /// The one post-spawn grant the shell row takes is the console port's client capability,
    /// which routes its console fds through the console service (#310).
    #[test]
    fn linux_process_grants_reach_only_the_console_client_grant_call() {
        let mut recorder = Recorder::default();
        apply_instance_grants(
            grants_for(SYSTEM_MANIFEST, SYSTEM_SHELL_SERVICE_ID),
            7,
            InstanceGeneration(3),
            &mut recorder,
        )
        .unwrap();
        assert_eq!(
            recorder.calls,
            [Call::ConsoleClient(7, ConsoleClientRole::Plain)]
        );
    }

    #[test]
    fn the_audit_row_is_given_its_reader_console_and_store_handles_at_bootstrap() {
        use clean_slate_service_fixtures::AUDIT_SERVICE_ID;
        let mut recorder = Recorder::default();
        let handles = apply_both(grants_for(SYSTEM_MANIFEST, AUDIT_SERVICE_ID), &mut recorder);
        assert_eq!(
            recorder.calls,
            [Call::AuditReader(7), Call::Console(7), Call::AuditStore(7)]
        );
        assert_eq!(
            handles,
            BootstrapGrantHandles {
                object_service_role: None,
                audit_reader: Some(0xad17),
                audit_store: Some(0xad57),
                console: Some(0xc0e5),
            }
        );
    }

    #[test]
    fn instance_grant_failure_names_the_grant() {
        let mut recorder = Recorder {
            fail: Some(Grant::NetworkService),
            ..Recorder::default()
        };
        let failure = apply_instance_grants(
            &[Grant::NetworkService],
            7,
            InstanceGeneration(1),
            &mut recorder,
        )
        .unwrap_err();
        assert_eq!(
            failure,
            GrantFailure {
                grant: Grant::NetworkService,
                message: "injected failure",
            }
        );
    }

    #[test]
    fn desktop_rows_reach_one_call_per_grant_in_row_order() {
        use clean_slate_service_fixtures::manifest::SYSTEM_DESKTOP_MANIFEST;
        use clean_slate_service_fixtures::{
            COMPOSITOR_SERVICE_ID, DESKTOP_SHELL_SERVICE_ID, PLAYGROUND_SERVICE_ID,
        };

        // Desktop images get their console handle in their launch page, not a bootstrap page.
        let calls = |id| {
            let mut recorder = Recorder::default();
            apply_instance_grants(
                grants_for(SYSTEM_DESKTOP_MANIFEST, id),
                7,
                InstanceGeneration(3),
                &mut recorder,
            )
            .unwrap();
            recorder.calls
        };
        assert_eq!(
            calls(COMPOSITOR_SERVICE_ID),
            [
                Call::GraphicsPort(7),
                Call::DisplayPresenter(7),
                Call::InputSeat(7)
            ]
        );
        assert_eq!(
            calls(DESKTOP_SHELL_SERVICE_ID),
            [
                Call::GraphicsRole(7, GraphicsRole::Shell),
                Call::LauncherClient(7)
            ]
        );
        assert_eq!(
            calls(PLAYGROUND_SERVICE_ID),
            [
                Call::GraphicsRole(7, GraphicsRole::App),
                Call::ConsoleClient(7, ConsoleClientRole::Plain)
            ]
        );
    }

    #[test]
    fn the_console_row_registers_its_port_and_gets_its_console_at_bootstrap() {
        use clean_slate_service_fixtures::CONSOLE_SERVICE_ID;
        let mut recorder = Recorder::default();
        let handles = apply_both(
            grants_for(SYSTEM_MANIFEST, CONSOLE_SERVICE_ID),
            &mut recorder,
        );
        assert_eq!(
            recorder.calls,
            [Call::Console(7), Call::ConsoleService(7)],
            "bootstrap grants first, then the instance grants"
        );
        assert_eq!(handles.console, Some(0xc0e5));
    }

    /// The first failing grant stops the row and is named, so the caller rolls the whole
    /// instance back (teardown revokes the grants before it and unregisters the port).
    #[test]
    fn a_failing_desktop_grant_stops_the_row_and_is_named() {
        use clean_slate_service_fixtures::manifest::COMPOSITOR_SERVICE_SPEC;
        for (fail, applied) in [
            (Grant::GraphicsPort, 1),
            (Grant::DisplayPresenter, 2),
            (Grant::InputSeat, 3),
        ] {
            let mut recorder = Recorder {
                fail: Some(fail),
                ..Recorder::default()
            };
            let failure = apply_instance_grants(
                COMPOSITOR_SERVICE_SPEC.grants,
                7,
                InstanceGeneration(1),
                &mut recorder,
            )
            .unwrap_err();
            assert_eq!(failure.grant, fail);
            assert_eq!(recorder.calls.len(), applied, "{fail:?}");
        }
        let mut recorder = Recorder {
            fail: Some(Grant::GraphicsAppRole),
            ..Recorder::default()
        };
        assert_eq!(
            apply_instance_grants(
                &[Grant::Console, Grant::GraphicsAppRole],
                7,
                InstanceGeneration(1),
                &mut recorder,
            )
            .unwrap_err()
            .grant,
            Grant::GraphicsAppRole
        );
    }

    /// A native network client gets its authority after the spawn, like the other native
    /// instance grants; nothing goes in its bootstrap page.
    #[test]
    fn a_native_network_client_reaches_its_one_call_after_the_spawn() {
        let mut recorder = Recorder::default();
        let handles = apply_both(&[Grant::Console, Grant::NativeNetworkClient], &mut recorder);
        assert_eq!(
            recorder.calls,
            [Call::Console(7), Call::NativeNetworkClient(7, false)]
        );
        assert_eq!(handles.console, Some(0xc0e5));
    }

    /// #378: `NetworkStats` adds no call of its own; it rides on the client grant.
    #[test]
    fn network_stats_rides_on_the_native_client_grant() {
        let mut recorder = Recorder::default();
        apply_both(
            &[Grant::NativeNetworkClient, Grant::NetworkStats],
            &mut recorder,
        );
        assert_eq!(recorder.calls, [Call::NativeNetworkClient(7, true)]);
    }

    /// #379: the system observer grant is one instance grant call, after launch.
    #[test]
    fn system_observer_is_one_instance_grant() {
        let mut recorder = Recorder::default();
        let handles = apply_both(&[Grant::SystemObserver], &mut recorder);
        assert_eq!(handles, BootstrapGrantHandles::default());
        assert_eq!(recorder.calls, [Call::SystemObserver(7)]);
    }

    #[test]
    fn bootstrap_grant_failure_is_returned() {
        let mut recorder = Recorder {
            fail: Some(Grant::ObjectServiceRole),
            ..Recorder::default()
        };
        assert_eq!(
            apply_bootstrap_grants(&[Grant::ObjectServiceRole], 7, &mut recorder),
            Err("injected failure")
        );
    }
}
