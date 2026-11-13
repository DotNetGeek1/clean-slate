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
}

/// Grants applied to a spawned instance before it is recorded live.
pub(crate) trait InstanceGrantAuthority {
    fn grant_block_device(&mut self, pid: u64) -> Result<(), &'static str>;
    fn grant_network_service(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
    ) -> Result<(), &'static str>;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct BootstrapGrantHandles {
    pub(crate) object_service_role: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GrantFailure {
    pub(crate) grant: Grant,
    pub(crate) message: &'static str,
}

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
            Grant::BlockDevice | Grant::NetworkService => {}
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
            Grant::ObjectServiceRole => Ok(()),
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
    };

    #[derive(Debug, PartialEq, Eq)]
    enum Call {
        ObjectServiceRole(u64),
        BlockDevice(u64),
        NetworkService(u64, InstanceGeneration),
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
