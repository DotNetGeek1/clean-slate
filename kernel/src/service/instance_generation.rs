//! Live `InstanceGeneration` lookup for M6 `ResourceRef` and `TrustedCaller` attribution.

use clean_slate_service_lifecycle::{InstanceGeneration, ServiceId, ServiceInstanceId};

use super::control::service_lifecycle_controller_mut;
use crate::capability::network::NETWORK_SERVICE_ID;

/// Logical network service identity used in `ResourceClass::Network` capability records.
pub(crate) const NETWORK_LOGICAL_SERVICE: ServiceId = NETWORK_SERVICE_ID;

/// Authoritative generation for a declared logical service (replacement counter).
#[allow(dead_code)]
pub(crate) fn live_instance_generation(service: ServiceId) -> Option<InstanceGeneration> {
    live_instance_generation_for_service(service)
}

/// Authoritative generation for a declared logical service (replacement counter).
pub(crate) fn live_instance_generation_for_service(
    service: ServiceId,
) -> Option<InstanceGeneration> {
    unsafe { service_lifecycle_controller_mut().authoritative_generation(service) }
}

/// Generation bound to a live supervised service instance for `pid`, when registered.
pub(crate) fn live_instance_generation_for_pid(pid: u64) -> Option<InstanceGeneration> {
    unsafe { service_lifecycle_controller_mut().authoritative_generation_for_live_pid(pid) }
}

/// Convenience for network broker paths: live generation of the network service resource.
pub(crate) fn live_network_service_generation() -> Option<InstanceGeneration> {
    live_instance_generation_for_service(NETWORK_LOGICAL_SERVICE)
}

/// Builds a [`ServiceInstanceId`] view when the pid is the live instance of `service`.
#[allow(dead_code)]
pub(crate) fn live_service_instance_id(service: ServiceId) -> Option<ServiceInstanceId> {
    unsafe { service_lifecycle_controller_mut().live_service_instance_id(service) }
}
