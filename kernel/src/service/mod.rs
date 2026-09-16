#![cfg_attr(
    not(any(
        feature = "m4-service-lifecycle-self-test",
        feature = "m4-recovery-self-test"
    )),
    allow(dead_code)
)]

pub(crate) mod block_bridge;
pub(crate) mod capability;
pub(crate) mod control;
pub(crate) mod spawn;

#[cfg(feature = "m4-recovery-self-test")]
pub(crate) mod recovery_launch;

pub(crate) use control::service_lifecycle_controller_mut;
pub(crate) use control::LifecycleControlError;
