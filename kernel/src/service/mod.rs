#![cfg_attr(not(feature = "m4-service-lifecycle-self-test"), allow(dead_code))]

pub(crate) mod capability;
pub(crate) mod control;
pub(crate) mod spawn;

pub(crate) use control::LifecycleControlError;
#[cfg(feature = "m4-service-lifecycle-self-test")]
pub(crate) use control::service_lifecycle_controller_mut;
