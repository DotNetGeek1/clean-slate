//! Explicit supervisor lifecycle-control capability handles (separate from IPC send caps).

use clean_slate_capability::{
    AuditEvent, AuditKind, CapabilityError, HolderId, ResourceClass, ResourceRef, Rights,
};

use clean_slate_service_lifecycle::ServiceId;

use crate::capability::audit::{self, record_kernel_revoke};
use crate::limits::SERVICE_REGISTRY_CAPACITY;
use crate::sync::global_cell::GlobalCell;

const LIFECYCLE_CONTROL_RESOURCE: ResourceRef = ResourceRef {
    class: ResourceClass::LifecycleControl,
    id: 0,
    instance_generation: 0,
};

const fn block_device_resource(device_id: u64) -> ResourceRef {
    ResourceRef {
        class: ResourceClass::BlockDevice,
        id: device_id,
        instance_generation: 0,
    }
}

/// These tables keep their own handle encoding, so the record carries the raw handle.
fn record_lifecycle_decision(
    kind: AuditKind,
    actor: HolderId,
    subject_pid: u64,
    resource: ResourceRef,
    raw_handle: u64,
    result: Result<(), CapabilityError>,
) {
    let mut event = AuditEvent::new(kind, actor, resource, Rights::empty())
        .with_subject(HolderId(subject_pid))
        .with_result(result);
    event.handle = raw_handle;
    audit::record(event);
}

const LIFECYCLE_CONTROL_CAPABILITY_CAPACITY: usize = 4;
const BLOCK_DEVICE_CAPABILITY_CAPACITY: usize = 4;

const fn lifecycle_control_resource(service: Option<ServiceId>) -> ResourceRef {
    match service {
        Some(service) => ResourceRef {
            class: ResourceClass::LifecycleControl,
            id: service.0 as u64,
            instance_generation: 0,
        },
        None => LIFECYCLE_CONTROL_RESOURCE,
    }
}

/// The services one lifecycle-control capability may start, stop, restart and poll.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LifecycleScope {
    services: [ServiceId; SERVICE_REGISTRY_CAPACITY],
    len: usize,
}

impl LifecycleScope {
    pub(crate) const EMPTY: Self = Self {
        services: [ServiceId(0); SERVICE_REGISTRY_CAPACITY],
        len: 0,
    };

    /// No more services than the registry can declare; duplicates are kept once.
    pub(crate) fn of<'a>(
        services: impl IntoIterator<Item = &'a ServiceId>,
    ) -> Result<Self, &'static str> {
        let mut scope = Self::EMPTY;
        for &service in services {
            if scope.covers(service) {
                continue;
            }
            if scope.len == SERVICE_REGISTRY_CAPACITY {
                return Err("lifecycle control scope exceeds the service registry");
            }
            scope.services[scope.len] = service;
            scope.len += 1;
        }
        Ok(scope)
    }

    pub(crate) fn covers(&self, service: ServiceId) -> bool {
        self.services().contains(&service)
    }

    pub(crate) fn services(&self) -> &[ServiceId] {
        &self.services[..self.len]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LifecycleControlCapability {
    holder_pid: u64,
    generation: u16,
    active: bool,
    retired: bool,
    scope: LifecycleScope,
}

impl LifecycleControlCapability {
    const EMPTY: Self = Self {
        holder_pid: 0,
        generation: 0,
        active: false,
        retired: false,
        scope: LifecycleScope::EMPTY,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LifecycleControlHandleParts {
    pub(crate) capability_slot: u16,
    pub(crate) capability_generation: u16,
}

impl LifecycleControlHandleParts {
    pub(crate) fn encode(self) -> u64 {
        u64::from(self.capability_slot) | (u64::from(self.capability_generation) << 16)
    }

    pub(crate) fn decode(raw: u64) -> Self {
        Self {
            capability_slot: raw as u16,
            capability_generation: (raw >> 16) as u16,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LifecycleControlCapabilityError {
    InvalidHandle,
    StaleHandle,
    Unauthorized,
    /// The handle is valid but names a service outside its scope.
    OutOfScope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LifecycleControlCapabilityTable {
    capabilities: [LifecycleControlCapability; LIFECYCLE_CONTROL_CAPABILITY_CAPACITY],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BlockDeviceCapability {
    holder_pid: u64,
    device_id: u64,
    generation: u16,
    active: bool,
    retired: bool,
}

impl BlockDeviceCapability {
    const EMPTY: Self = Self {
        holder_pid: 0,
        device_id: 0,
        generation: 0,
        active: false,
        retired: false,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BlockDeviceHandleParts {
    pub(crate) capability_slot: u16,
    pub(crate) capability_generation: u16,
}

impl BlockDeviceHandleParts {
    pub(crate) fn encode(self) -> u64 {
        u64::from(self.capability_slot) | (u64::from(self.capability_generation) << 16)
    }

    pub(crate) fn decode(raw: u64) -> Self {
        Self {
            capability_slot: raw as u16,
            capability_generation: (raw >> 16) as u16,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlockDeviceCapabilityError {
    InvalidHandle,
    StaleHandle,
    Unauthorized,
    WrongDevice,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BlockDeviceCapabilityTable {
    capabilities: [BlockDeviceCapability; BLOCK_DEVICE_CAPABILITY_CAPACITY],
}

impl BlockDeviceCapabilityTable {
    pub(crate) const fn new() -> Self {
        Self {
            capabilities: [BlockDeviceCapability::EMPTY; BLOCK_DEVICE_CAPABILITY_CAPACITY],
        }
    }

    pub(crate) fn clear(&mut self) {
        *self = Self::new();
    }

    fn retire_capability(capability: &mut BlockDeviceCapability) {
        capability.active = false;
        capability.holder_pid = 0;
        capability.device_id = 0;
        if let Some(next_generation) =
            LifecycleControlCapabilityTable::next_generation(capability.generation)
        {
            capability.generation = next_generation;
        } else {
            capability.retired = true;
        }
    }

    pub(crate) fn grant_block_device_capability(
        &mut self,
        holder_pid: u64,
        device_id: u64,
    ) -> Result<u64, &'static str> {
        let result = self.install_block_device_capability(holder_pid, device_id);
        record_lifecycle_decision(
            AuditKind::Grant,
            HolderId::KERNEL,
            holder_pid,
            block_device_resource(device_id),
            *result.as_ref().unwrap_or(&0),
            result
                .map(|_| ())
                .map_err(|_| CapabilityError::CapacityExhausted),
        );
        result
    }

    fn install_block_device_capability(
        &mut self,
        holder_pid: u64,
        device_id: u64,
    ) -> Result<u64, &'static str> {
        for (slot, capability) in self.capabilities.iter_mut().enumerate() {
            if capability.active || capability.retired {
                continue;
            }
            let next_generation =
                match LifecycleControlCapabilityTable::next_generation(capability.generation) {
                    Some(next_generation) => next_generation,
                    None => {
                        capability.retired = true;
                        continue;
                    }
                };
            capability.holder_pid = holder_pid;
            capability.device_id = device_id;
            capability.generation = next_generation;
            capability.active = true;
            return Ok(BlockDeviceHandleParts {
                capability_slot: u16::try_from(slot)
                    .map_err(|_| "block capability slot exceeded u16 handle field")?,
                capability_generation: capability.generation,
            }
            .encode());
        }
        Err("block capability table capacity exceeded or generation exhausted")
    }

    pub(crate) fn block_device_handle_for(
        &self,
        holder_pid: u64,
        device_id: u64,
    ) -> Result<u64, BlockDeviceCapabilityError> {
        for (slot, capability) in self.capabilities.iter().enumerate() {
            if !capability.active {
                continue;
            }
            if capability.holder_pid != holder_pid {
                continue;
            }
            if capability.device_id != device_id {
                continue;
            }
            return Ok(BlockDeviceHandleParts {
                capability_slot: u16::try_from(slot)
                    .map_err(|_| BlockDeviceCapabilityError::InvalidHandle)?,
                capability_generation: capability.generation,
            }
            .encode());
        }
        Err(BlockDeviceCapabilityError::Unauthorized)
    }

    pub(crate) fn authorize_block_device_access(
        &self,
        holder_pid: u64,
        raw_handle: u64,
        device_id: u64,
    ) -> Result<(), BlockDeviceCapabilityError> {
        let result = self.check_block_device_access(holder_pid, raw_handle, device_id);
        record_lifecycle_decision(
            AuditKind::Authorize,
            HolderId(holder_pid),
            holder_pid,
            block_device_resource(device_id),
            raw_handle,
            result.map_err(|error| match error {
                BlockDeviceCapabilityError::InvalidHandle => CapabilityError::InvalidHandle,
                BlockDeviceCapabilityError::StaleHandle => CapabilityError::StaleHandle,
                BlockDeviceCapabilityError::Unauthorized => CapabilityError::UnauthorizedHolder,
                BlockDeviceCapabilityError::WrongDevice => CapabilityError::WrongResource,
            }),
        );
        result
    }

    fn check_block_device_access(
        &self,
        holder_pid: u64,
        raw_handle: u64,
        device_id: u64,
    ) -> Result<(), BlockDeviceCapabilityError> {
        let handle = BlockDeviceHandleParts::decode(raw_handle);
        let capability = match self.capabilities.get(handle.capability_slot as usize) {
            Some(capability) => capability,
            None => return Err(BlockDeviceCapabilityError::InvalidHandle),
        };
        if capability.generation == 0 {
            return Err(BlockDeviceCapabilityError::InvalidHandle);
        }
        if capability.generation != handle.capability_generation {
            return Err(BlockDeviceCapabilityError::StaleHandle);
        }
        if !capability.active {
            return Err(BlockDeviceCapabilityError::StaleHandle);
        }
        if capability.holder_pid != holder_pid {
            return Err(BlockDeviceCapabilityError::Unauthorized);
        }
        if capability.device_id != device_id {
            return Err(BlockDeviceCapabilityError::WrongDevice);
        }
        Ok(())
    }

    /// Retires every capability `pid` holds; returns how many.
    pub(crate) fn revoke_capabilities_for_pid(&mut self, pid: u64) -> usize {
        let mut revoked = 0;
        for capability in &mut self.capabilities {
            if capability.active && capability.holder_pid == pid {
                Self::retire_capability(capability);
                revoked += 1;
            }
        }
        revoked
    }

    /// Active block-device capabilities `pid` holds, on any device.
    pub(crate) fn held_by(&self, pid: u64) -> usize {
        self.capabilities
            .iter()
            .filter(|capability| capability.active && capability.holder_pid == pid)
            .count()
    }
}

impl LifecycleControlCapabilityTable {
    /// Active lifecycle-control capabilities `pid` holds.
    pub(crate) fn held_by(&self, pid: u64) -> usize {
        self.capabilities
            .iter()
            .filter(|capability| capability.active && capability.holder_pid == pid)
            .count()
    }

    pub(crate) const fn new() -> Self {
        Self {
            capabilities: [LifecycleControlCapability::EMPTY;
                LIFECYCLE_CONTROL_CAPABILITY_CAPACITY],
        }
    }

    pub(crate) fn clear(&mut self) {
        *self = Self::new();
    }

    fn next_generation(current: u16) -> Option<u16> {
        if current == u16::MAX {
            None
        } else {
            Some(current + 1)
        }
    }

    fn retire_capability(capability: &mut LifecycleControlCapability) {
        capability.active = false;
        capability.holder_pid = 0;
        capability.scope = LifecycleScope::EMPTY;
        if let Some(next_generation) = Self::next_generation(capability.generation) {
            capability.generation = next_generation;
        } else {
            capability.retired = true;
        }
    }

    /// Grants `holder_pid` control of the services in `scope`, and of no other.
    pub(crate) fn grant_lifecycle_control_capability(
        &mut self,
        holder_pid: u64,
        scope: LifecycleScope,
    ) -> Result<u64, &'static str> {
        let result = self.install_lifecycle_control_capability(holder_pid, scope);
        record_lifecycle_decision(
            AuditKind::Grant,
            HolderId::KERNEL,
            holder_pid,
            LIFECYCLE_CONTROL_RESOURCE,
            *result.as_ref().unwrap_or(&0),
            result
                .map(|_| ())
                .map_err(|_| CapabilityError::CapacityExhausted),
        );
        result
    }

    fn install_lifecycle_control_capability(
        &mut self,
        holder_pid: u64,
        scope: LifecycleScope,
    ) -> Result<u64, &'static str> {
        for (slot, capability) in self.capabilities.iter_mut().enumerate() {
            if capability.active || capability.retired {
                continue;
            }
            let next_generation = match Self::next_generation(capability.generation) {
                Some(next_generation) => next_generation,
                None => {
                    capability.retired = true;
                    continue;
                }
            };
            capability.holder_pid = holder_pid;
            capability.generation = next_generation;
            capability.active = true;
            capability.scope = scope;
            return Ok(LifecycleControlHandleParts {
                capability_slot: u16::try_from(slot)
                    .map_err(|_| "lifecycle control capability slot exceeded u16 handle field")?,
                capability_generation: capability.generation,
            }
            .encode());
        }
        Err("lifecycle control capability table capacity exceeded or generation exhausted")
    }

    /// Authorizes `raw_handle` for `service`, or, with `None`, for whichever services its scope
    /// covers (the pending-event peek). Returns the scope.
    pub(crate) fn authorize_lifecycle_control(
        &self,
        holder_pid: u64,
        raw_handle: u64,
        service: Option<ServiceId>,
    ) -> Result<LifecycleScope, LifecycleControlCapabilityError> {
        let result = self.check_lifecycle_control(holder_pid, raw_handle, service);
        record_lifecycle_decision(
            AuditKind::Authorize,
            HolderId(holder_pid),
            holder_pid,
            lifecycle_control_resource(service),
            raw_handle,
            result.map(|_| ()).map_err(|error| match error {
                LifecycleControlCapabilityError::InvalidHandle => CapabilityError::InvalidHandle,
                LifecycleControlCapabilityError::StaleHandle => CapabilityError::StaleHandle,
                LifecycleControlCapabilityError::Unauthorized => {
                    CapabilityError::UnauthorizedHolder
                }
                LifecycleControlCapabilityError::OutOfScope => CapabilityError::WrongResource,
            }),
        );
        result
    }

    fn check_lifecycle_control(
        &self,
        holder_pid: u64,
        raw_handle: u64,
        service: Option<ServiceId>,
    ) -> Result<LifecycleScope, LifecycleControlCapabilityError> {
        let handle = LifecycleControlHandleParts::decode(raw_handle);
        let capability = match self.capabilities.get(handle.capability_slot as usize) {
            Some(capability) => capability,
            None => return Err(LifecycleControlCapabilityError::InvalidHandle),
        };
        if capability.generation == 0 {
            return Err(LifecycleControlCapabilityError::InvalidHandle);
        }
        if capability.generation != handle.capability_generation {
            return Err(LifecycleControlCapabilityError::StaleHandle);
        }
        if !capability.active {
            return Err(LifecycleControlCapabilityError::StaleHandle);
        }
        if capability.holder_pid != holder_pid {
            return Err(LifecycleControlCapabilityError::Unauthorized);
        }
        if service.is_some_and(|service| !capability.scope.covers(service)) {
            return Err(LifecycleControlCapabilityError::OutOfScope);
        }
        Ok(capability.scope)
    }

    /// The scope of the first active lifecycle-control capability `pid` holds.
    #[cfg(clean_slate_system_init)]
    pub(crate) fn scope_of(&self, pid: u64) -> Option<LifecycleScope> {
        self.capabilities
            .iter()
            .find(|capability| capability.active && capability.holder_pid == pid)
            .map(|capability| capability.scope)
    }

    /// Retires every capability `pid` holds; returns how many.
    pub(crate) fn revoke_capabilities_for_pid(&mut self, pid: u64) -> usize {
        let mut revoked = 0;
        for capability in &mut self.capabilities {
            if capability.active && capability.holder_pid == pid {
                Self::retire_capability(capability);
                revoked += 1;
            }
        }
        revoked
    }
}

/// The lifecycle controller's per-pid authority. It lives outside the controller because
/// process teardown releases it, and a controller method that tears an instance down holds
/// the controller while the teardown hooks run.
pub(crate) struct LifecycleCapabilities {
    pub(crate) lifecycle_control: LifecycleControlCapabilityTable,
    pub(crate) block_device: BlockDeviceCapabilityTable,
}

impl LifecycleCapabilities {
    const fn new() -> Self {
        Self {
            lifecycle_control: LifecycleControlCapabilityTable::new(),
            block_device: BlockDeviceCapabilityTable::new(),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.lifecycle_control.clear();
        self.block_device.clear();
    }

    /// Lifecycle-control and block-device capabilities `pid` holds, in that order.
    pub(crate) fn held_by(&self, pid: u64) -> (usize, usize) {
        (
            self.lifecycle_control.held_by(pid),
            self.block_device.held_by(pid),
        )
    }

    /// Active capabilities in both tables, over every holder.
    #[cfg(clean_slate_desktop_snapshot)]
    pub(crate) fn live_count(&self) -> usize {
        self.lifecycle_control
            .capabilities
            .iter()
            .filter(|capability| capability.active)
            .count()
            + self
                .block_device
                .capabilities
                .iter()
                .filter(|capability| capability.active)
                .count()
    }

    /// Revokes every lifecycle-control and block-device capability `pid` holds; returns how
    /// many.
    pub(crate) fn revoke_for_pid(&mut self, pid: u64) -> usize {
        let lifecycle_control = self.lifecycle_control.revoke_capabilities_for_pid(pid);
        if lifecycle_control > 0 {
            record_kernel_revoke(HolderId(pid), LIFECYCLE_CONTROL_RESOURCE, lifecycle_control);
        }
        let block_device = self.block_device.revoke_capabilities_for_pid(pid);
        if block_device > 0 {
            record_kernel_revoke(HolderId(pid), block_device_resource(0), block_device);
        }
        lifecycle_control + block_device
    }
}

static LIFECYCLE_CAPABILITIES: GlobalCell<LifecycleCapabilities> =
    GlobalCell::new(LifecycleCapabilities::new());

/// Returns the lifecycle-control and block-device capability tables.
///
/// # Safety
/// The caller must ensure no other live reference to the tables exists for the lifetime of the
/// returned reference.
pub(crate) unsafe fn lifecycle_capabilities_mut() -> &'static mut LifecycleCapabilities {
    unsafe { &mut *LIFECYCLE_CAPABILITIES.get() }
}

/// Teardown: revokes everything `pid` holds in the lifecycle capability tables.
pub(crate) fn on_holder_exit(pid: u64) -> usize {
    unsafe { lifecycle_capabilities_mut() }.revoke_for_pid(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holder_exit_revokes_both_tables_and_only_that_pid() {
        let tables = unsafe { lifecycle_capabilities_mut() };
        tables.clear();
        let lifecycle = tables
            .lifecycle_control
            .grant_lifecycle_control_capability(7, scope(&[SERVICE_A]))
            .expect("grant lifecycle control");
        let block = tables
            .block_device
            .grant_block_device_capability(7, 1)
            .expect("grant block device");
        tables
            .block_device
            .grant_block_device_capability(8, 1)
            .expect("grant another holder");
        assert_eq!(tables.held_by(7), (1, 1));

        assert_eq!(on_holder_exit(7), 2);
        let tables = unsafe { lifecycle_capabilities_mut() };
        assert_eq!(tables.held_by(7), (0, 0));
        assert_eq!(tables.held_by(8), (0, 1));
        assert_eq!(
            tables
                .lifecycle_control
                .authorize_lifecycle_control(7, lifecycle, None),
            Err(LifecycleControlCapabilityError::StaleHandle)
        );
        assert_eq!(
            tables
                .block_device
                .authorize_block_device_access(7, block, 1),
            Err(BlockDeviceCapabilityError::StaleHandle)
        );
        assert_eq!(on_holder_exit(7), 0, "a second release finds nothing");
    }

    const SERVICE_A: ServiceId = ServiceId(0x5100);
    const SERVICE_B: ServiceId = ServiceId(0x5200);

    fn scope(services: &[ServiceId]) -> LifecycleScope {
        LifecycleScope::of(services).expect("scope")
    }

    #[test]
    fn lifecycle_control_capability_authorizes_only_granted_process() {
        let mut table = LifecycleControlCapabilityTable::new();
        let handle = table
            .grant_lifecycle_control_capability(10, scope(&[SERVICE_A]))
            .expect("grant capability");
        assert!(table
            .authorize_lifecycle_control(10, handle, Some(SERVICE_A))
            .is_ok());
        assert_eq!(
            table.authorize_lifecycle_control(11, handle, Some(SERVICE_A)),
            Err(LifecycleControlCapabilityError::Unauthorized)
        );
    }

    #[test]
    fn lifecycle_control_for_service_a_is_refused_for_service_b() {
        let mut table = LifecycleControlCapabilityTable::new();
        let handle = table
            .grant_lifecycle_control_capability(10, scope(&[SERVICE_A]))
            .expect("grant capability");
        assert_eq!(
            table.authorize_lifecycle_control(10, handle, Some(SERVICE_B)),
            Err(LifecycleControlCapabilityError::OutOfScope)
        );
        assert_eq!(
            table.authorize_lifecycle_control(10, handle, None),
            Ok(scope(&[SERVICE_A]))
        );
        let both = table
            .grant_lifecycle_control_capability(12, scope(&[SERVICE_A, SERVICE_B]))
            .expect("grant capability");
        for service in [SERVICE_A, SERVICE_B] {
            assert!(table
                .authorize_lifecycle_control(12, both, Some(service))
                .is_ok());
        }
        let empty = table
            .grant_lifecycle_control_capability(13, LifecycleScope::EMPTY)
            .expect("grant capability");
        assert_eq!(
            table.authorize_lifecycle_control(13, empty, Some(SERVICE_A)),
            Err(LifecycleControlCapabilityError::OutOfScope)
        );
    }

    #[test]
    fn lifecycle_scope_is_bounded_by_the_service_registry_and_deduplicated() {
        let mut services = [ServiceId(0); SERVICE_REGISTRY_CAPACITY + 1];
        for (index, service) in services.iter_mut().enumerate() {
            *service = ServiceId(index as u32 + 1);
        }
        assert!(LifecycleScope::of(&services).is_err());
        assert!(LifecycleScope::of(&services[..SERVICE_REGISTRY_CAPACITY]).is_ok());
        assert_eq!(
            scope(&[SERVICE_A, SERVICE_A, SERVICE_B]).services(),
            &[SERVICE_A, SERVICE_B]
        );
    }

    #[test]
    fn lifecycle_control_stale_handle_fails_after_revoke() {
        let mut table = LifecycleControlCapabilityTable::new();
        let handle = table
            .grant_lifecycle_control_capability(3, scope(&[SERVICE_A]))
            .expect("grant capability");
        table.revoke_capabilities_for_pid(3);
        assert_eq!(
            table.authorize_lifecycle_control(3, handle, Some(SERVICE_A)),
            Err(LifecycleControlCapabilityError::StaleHandle)
        );
        let reissued = table
            .grant_lifecycle_control_capability(4, scope(&[SERVICE_B]))
            .expect("grant capability");
        assert_eq!(
            table.authorize_lifecycle_control(4, reissued, Some(SERVICE_A)),
            Err(LifecycleControlCapabilityError::OutOfScope),
            "a reused slot does not keep the previous holder's scope"
        );
    }

    #[test]
    fn block_capability_authorizes_only_granted_process() {
        let mut table = BlockDeviceCapabilityTable::new();
        let handle = table
            .grant_block_device_capability(10, 1)
            .expect("grant capability");
        assert!(table.authorize_block_device_access(10, handle, 1).is_ok());
        assert_eq!(
            table.authorize_block_device_access(11, handle, 1),
            Err(BlockDeviceCapabilityError::Unauthorized)
        );
    }

    #[test]
    fn block_capability_rejects_wrong_device_and_stale_handle() {
        let mut table = BlockDeviceCapabilityTable::new();
        let handle = table
            .grant_block_device_capability(3, 1)
            .expect("grant capability");
        assert_eq!(
            table.authorize_block_device_access(3, handle, 2),
            Err(BlockDeviceCapabilityError::WrongDevice)
        );
        table.revoke_capabilities_for_pid(3);
        assert_eq!(
            table.authorize_block_device_access(3, handle, 1),
            Err(BlockDeviceCapabilityError::StaleHandle)
        );
    }
}
