//! Endpoint-based IPC: endpoint slots, send capabilities with generation
//! checks, and the endpoint table. Owns `IPC_ENDPOINT_TABLE`.

use crate::sync::global_cell::GlobalCell;

pub(super) const IPC_MAX_MESSAGE_BYTES: usize = 64;
const IPC_ENDPOINT_CAPACITY: usize = 4;
const IPC_CAPABILITY_CAPACITY: usize = 8;
#[cfg(any(feature = "m3-ipc-self-test", test))]
pub(super) const USERSPACE_IPC_TEST_PID: u64 = 1;
#[cfg(any(feature = "m3-ipc-self-test", test))]
pub(super) const USERSPACE_IPC_UNAUTHORIZED_TEST_PID: u64 = 2;
#[cfg(any(
    feature = "m4-supervisor-self-test",
    feature = "m4-recovery-self-test",
    test
))]
#[allow(dead_code)]
pub(crate) const USERSPACE_SUPERVISOR_TEST_PID: u64 = 1;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IpcEndpointState {
    Vacant,
    Active,
    Retired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IpcEndpointKind {
    Mailbox,
    ConsoleSink,
    LifecycleControl,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IpcEndpoint {
    owner_pid: u64,
    generation: u16,
    state: IpcEndpointState,
    kind: IpcEndpointKind,
    last_message_len: u16,
    last_message: [u8; IPC_MAX_MESSAGE_BYTES],
}

impl IpcEndpoint {
    const EMPTY: Self = Self {
        owner_pid: 0,
        generation: 0,
        state: IpcEndpointState::Vacant,
        kind: IpcEndpointKind::Mailbox,
        last_message_len: 0,
        last_message: [0; IPC_MAX_MESSAGE_BYTES],
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EndpointCapability {
    holder_pid: u64,
    generation: u16,
    endpoint_slot: u16,
    endpoint_generation: u16,
    active: bool,
    retired: bool,
}

impl EndpointCapability {
    const EMPTY: Self = Self {
        holder_pid: 0,
        generation: 0,
        endpoint_slot: 0,
        endpoint_generation: 0,
        active: false,
        retired: false,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EndpointCapabilityHandleParts {
    capability_slot: u16,
    capability_generation: u16,
    endpoint_slot: u16,
    endpoint_generation: u16,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct IpcProcessResources {
    pub(crate) owned_endpoints: usize,
    pub(crate) held_capabilities: usize,
}

#[allow(dead_code)]
impl EndpointCapabilityHandleParts {
    fn encode(self) -> u64 {
        u64::from(self.capability_slot)
            | (u64::from(self.capability_generation) << 16)
            | (u64::from(self.endpoint_slot) << 32)
            | (u64::from(self.endpoint_generation) << 48)
    }

    fn decode(raw: u64) -> Self {
        Self {
            capability_slot: raw as u16,
            capability_generation: (raw >> 16) as u16,
            endpoint_slot: (raw >> 32) as u16,
            endpoint_generation: (raw >> 48) as u16,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IpcSendError {
    InvalidCapability,
    Unauthorized,
    StaleCapability,
    InvalidMessageLength,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IpcSendResult {
    pub(crate) bytes_sent: usize,
    pub(crate) endpoint_kind: IpcEndpointKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IpcEndpointTable {
    endpoints: [IpcEndpoint; IPC_ENDPOINT_CAPACITY],
    capabilities: [EndpointCapability; IPC_CAPABILITY_CAPACITY],
}

#[allow(dead_code)]
impl IpcEndpointTable {
    pub(super) const fn new() -> Self {
        Self {
            endpoints: [IpcEndpoint::EMPTY; IPC_ENDPOINT_CAPACITY],
            capabilities: [EndpointCapability::EMPTY; IPC_CAPABILITY_CAPACITY],
        }
    }

    pub(super) fn clear(&mut self) {
        *self = Self::new();
    }

    fn next_generation(current: u16) -> Option<u16> {
        if current == u16::MAX {
            None
        } else {
            Some(current + 1)
        }
    }

    pub(super) fn create_endpoint(&mut self, owner_pid: u64) -> Result<usize, &'static str> {
        self.create_endpoint_with_kind(owner_pid, IpcEndpointKind::Mailbox)
    }

    pub(super) fn create_console_sink(&mut self, owner_pid: u64) -> Result<usize, &'static str> {
        self.create_endpoint_with_kind(owner_pid, IpcEndpointKind::ConsoleSink)
    }

    pub(super) fn create_lifecycle_control_endpoint(
        &mut self,
        owner_pid: u64,
    ) -> Result<usize, &'static str> {
        self.create_endpoint_with_kind(owner_pid, IpcEndpointKind::LifecycleControl)
    }

    fn create_endpoint_with_kind(
        &mut self,
        owner_pid: u64,
        kind: IpcEndpointKind,
    ) -> Result<usize, &'static str> {
        for (slot, endpoint) in self.endpoints.iter_mut().enumerate() {
            if endpoint.state != IpcEndpointState::Vacant {
                continue;
            }
            endpoint.owner_pid = owner_pid;
            if endpoint.generation == 0 {
                endpoint.generation = 1;
            }
            endpoint.state = IpcEndpointState::Active;
            endpoint.kind = kind;
            endpoint.last_message_len = 0;
            endpoint.last_message = [0; IPC_MAX_MESSAGE_BYTES];
            return Ok(slot);
        }
        Err("ipc endpoint table capacity exceeded or generation exhausted")
    }

    fn endpoint_generation(&self, endpoint_slot: usize) -> Result<u16, &'static str> {
        let endpoint = self
            .endpoints
            .get(endpoint_slot)
            .ok_or("ipc endpoint slot was out of range")?;
        if endpoint.state != IpcEndpointState::Active {
            return Err("ipc endpoint was not active");
        }
        Ok(endpoint.generation)
    }

    fn retire_capability(capability: &mut EndpointCapability) {
        capability.active = false;
        capability.holder_pid = 0;
        if let Some(next_generation) = Self::next_generation(capability.generation) {
            capability.generation = next_generation;
        } else {
            capability.retired = true;
        }
    }

    pub(super) fn grant_send_capability(
        &mut self,
        holder_pid: u64,
        endpoint_slot: usize,
    ) -> Result<u64, &'static str> {
        let endpoint_generation = self.endpoint_generation(endpoint_slot)?;
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
            capability.endpoint_slot = u16::try_from(endpoint_slot)
                .map_err(|_| "ipc endpoint slot exceeded u16 handle field")?;
            capability.endpoint_generation = endpoint_generation;
            capability.active = true;
            return Ok(EndpointCapabilityHandleParts {
                capability_slot: u16::try_from(slot)
                    .map_err(|_| "ipc capability slot exceeded u16 handle field")?,
                capability_generation: capability.generation,
                endpoint_slot: capability.endpoint_slot,
                endpoint_generation,
            }
            .encode());
        }
        Err("ipc capability table capacity exceeded or generation exhausted")
    }

    fn lookup_send_capability(
        &self,
        sender_pid: u64,
        raw_handle: u64,
    ) -> Result<usize, IpcSendError> {
        let handle = EndpointCapabilityHandleParts::decode(raw_handle);
        let capability = match self.capabilities.get(handle.capability_slot as usize) {
            Some(capability) => capability,
            None => return Err(IpcSendError::InvalidCapability),
        };
        if capability.generation == 0 {
            return Err(IpcSendError::InvalidCapability);
        }
        if capability.generation != handle.capability_generation {
            return Err(IpcSendError::StaleCapability);
        }
        if !capability.active {
            return Err(IpcSendError::StaleCapability);
        }
        if capability.holder_pid != sender_pid {
            return Err(IpcSendError::Unauthorized);
        }
        if capability.endpoint_slot != handle.endpoint_slot
            || capability.endpoint_generation != handle.endpoint_generation
        {
            return Err(IpcSendError::StaleCapability);
        }
        let endpoint = match self.endpoints.get(capability.endpoint_slot as usize) {
            Some(endpoint) => endpoint,
            None => return Err(IpcSendError::StaleCapability),
        };
        if endpoint.state != IpcEndpointState::Active
            || endpoint.generation != capability.endpoint_generation
        {
            return Err(IpcSendError::StaleCapability);
        }
        Ok(capability.endpoint_slot as usize)
    }

    pub(super) fn send_message(
        &mut self,
        sender_pid: u64,
        raw_handle: u64,
        message: &[u8],
    ) -> Result<IpcSendResult, IpcSendError> {
        if message.is_empty() || message.len() > IPC_MAX_MESSAGE_BYTES {
            return Err(IpcSendError::InvalidMessageLength);
        }
        let endpoint_slot = self.lookup_send_capability(sender_pid, raw_handle)?;
        let endpoint = self
            .endpoints
            .get_mut(endpoint_slot)
            .ok_or(IpcSendError::StaleCapability)?;
        endpoint.last_message = [0; IPC_MAX_MESSAGE_BYTES];
        endpoint.last_message[..message.len()].copy_from_slice(message);
        endpoint.last_message_len = message.len() as u16;
        Ok(IpcSendResult {
            bytes_sent: message.len(),
            endpoint_kind: endpoint.kind,
        })
    }

    pub(crate) fn resources_for_pid(&self, pid: u64) -> IpcProcessResources {
        let owned_endpoints = self
            .endpoints
            .iter()
            .filter(|endpoint| {
                endpoint.state == IpcEndpointState::Active && endpoint.owner_pid == pid
            })
            .count();
        let held_capabilities = self
            .capabilities
            .iter()
            .filter(|capability| capability.active && capability.holder_pid == pid)
            .count();
        IpcProcessResources {
            owned_endpoints,
            held_capabilities,
        }
    }

    pub(crate) fn active_resources(&self) -> IpcProcessResources {
        IpcProcessResources {
            owned_endpoints: self
                .endpoints
                .iter()
                .filter(|endpoint| endpoint.state == IpcEndpointState::Active)
                .count(),
            held_capabilities: self
                .capabilities
                .iter()
                .filter(|capability| capability.active)
                .count(),
        }
    }

    pub(crate) fn revoke_capabilities_held_by(&mut self, holder_pid: u64) -> usize {
        let mut revoked = 0;
        for capability in &mut self.capabilities {
            if capability.active && capability.holder_pid == holder_pid {
                Self::retire_capability(capability);
                revoked += 1;
            }
        }
        revoked
    }

    pub(crate) fn teardown_resources_for_pid(
        &mut self,
        pid: u64,
    ) -> Result<IpcProcessResources, &'static str> {
        let revoked = self.revoke_capabilities_held_by(pid);
        let mut owned_slots = [usize::MAX; IPC_ENDPOINT_CAPACITY];
        let mut owned_count = 0;
        for (slot, endpoint) in self.endpoints.iter().enumerate() {
            if endpoint.state == IpcEndpointState::Active && endpoint.owner_pid == pid {
                owned_slots[owned_count] = slot;
                owned_count += 1;
            }
        }
        for slot in owned_slots.into_iter().take(owned_count) {
            self.teardown_endpoint(slot)?;
        }
        Ok(IpcProcessResources {
            owned_endpoints: owned_count,
            held_capabilities: revoked,
        })
    }

    pub(super) fn teardown_endpoint(&mut self, endpoint_slot: usize) -> Result<(), &'static str> {
        let endpoint = self
            .endpoints
            .get_mut(endpoint_slot)
            .ok_or("ipc endpoint slot was out of range during teardown")?;
        if endpoint.state != IpcEndpointState::Active {
            return Err("ipc endpoint was not active during teardown");
        }
        let retired_generation = endpoint.generation;
        endpoint.state = match Self::next_generation(endpoint.generation) {
            Some(next_generation) => {
                endpoint.generation = next_generation;
                IpcEndpointState::Vacant
            }
            None => IpcEndpointState::Retired,
        };
        endpoint.owner_pid = 0;
        endpoint.kind = IpcEndpointKind::Mailbox;
        endpoint.last_message_len = 0;
        endpoint.last_message = [0; IPC_MAX_MESSAGE_BYTES];
        let endpoint_slot_u16 = u16::try_from(endpoint_slot)
            .map_err(|_| "ipc endpoint slot exceeded u16 handle field")?;
        for capability in &mut self.capabilities {
            if capability.active
                && capability.endpoint_slot == endpoint_slot_u16
                && capability.endpoint_generation == retired_generation
            {
                Self::retire_capability(capability);
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn endpoint_message(&self, endpoint_slot: usize) -> Option<&[u8]> {
        let endpoint = self.endpoints.get(endpoint_slot)?;
        if endpoint.state != IpcEndpointState::Active {
            return None;
        }
        Some(&endpoint.last_message[..usize::from(endpoint.last_message_len)])
    }
}

static IPC_ENDPOINT_TABLE: GlobalCell<IpcEndpointTable> = GlobalCell::new(IpcEndpointTable::new());

/// Returns the IPC endpoint table for call sites that hold the reference across other calls.
///
/// # Safety
/// The caller must ensure no other live reference to the IPC endpoint table exists for the
/// lifetime of the returned borrow.
pub(crate) unsafe fn endpoint_table_mut() -> &'static mut IpcEndpointTable {
    unsafe { &mut *IPC_ENDPOINT_TABLE.get() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::KERNEL_PROCESS_ID;

    #[test]
    fn ipc_capability_authorizes_only_granted_process() {
        let mut table = IpcEndpointTable::new();
        let endpoint_slot = table
            .create_endpoint(KERNEL_PROCESS_ID)
            .expect("create endpoint");
        let handle = table
            .grant_send_capability(USERSPACE_IPC_TEST_PID, endpoint_slot)
            .expect("grant capability");

        assert_eq!(
            table
                .send_message(USERSPACE_IPC_TEST_PID, handle, b"hi")
                .expect("authorized send"),
            IpcSendResult {
                bytes_sent: 2,
                endpoint_kind: IpcEndpointKind::Mailbox,
            }
        );
        assert_eq!(table.endpoint_message(endpoint_slot), Some(&b"hi"[..]));
        assert_eq!(
            table.send_message(USERSPACE_IPC_UNAUTHORIZED_TEST_PID, handle, b"hi"),
            Err(IpcSendError::Unauthorized)
        );
    }

    #[test]
    fn ipc_console_sink_reports_console_delivery_for_authorized_process() {
        let mut table = IpcEndpointTable::new();
        let endpoint_slot = table
            .create_console_sink(KERNEL_PROCESS_ID)
            .expect("create console sink");
        let handle = table
            .grant_send_capability(USERSPACE_IPC_TEST_PID, endpoint_slot)
            .expect("grant capability");

        assert_eq!(
            table
                .send_message(USERSPACE_IPC_TEST_PID, handle, b"hello from pid 1")
                .expect("authorized console send"),
            IpcSendResult {
                bytes_sent: 16,
                endpoint_kind: IpcEndpointKind::ConsoleSink,
            }
        );
        assert_eq!(
            table.endpoint_message(endpoint_slot),
            Some(&b"hello from pid 1"[..])
        );
    }

    #[test]
    fn ipc_console_sink_denies_process_without_capability() {
        let mut table = IpcEndpointTable::new();
        let endpoint_slot = table
            .create_console_sink(KERNEL_PROCESS_ID)
            .expect("create console sink");
        let handle = table
            .grant_send_capability(USERSPACE_IPC_TEST_PID, endpoint_slot)
            .expect("grant capability");

        assert_eq!(
            table.send_message(USERSPACE_IPC_UNAUTHORIZED_TEST_PID, handle, b"hello"),
            Err(IpcSendError::Unauthorized)
        );
        assert_eq!(table.endpoint_message(endpoint_slot), Some(&b""[..]));
    }

    #[test]
    fn ipc_lookup_rejects_invalid_capability_handle() {
        let mut table = IpcEndpointTable::new();
        let endpoint_slot = table
            .create_endpoint(KERNEL_PROCESS_ID)
            .expect("create endpoint");
        let _handle = table
            .grant_send_capability(USERSPACE_IPC_TEST_PID, endpoint_slot)
            .expect("grant capability");
        let invalid_handle = EndpointCapabilityHandleParts {
            capability_slot: IPC_CAPABILITY_CAPACITY as u16,
            capability_generation: 1,
            endpoint_slot: 0,
            endpoint_generation: 1,
        }
        .encode();

        assert_eq!(
            table.send_message(USERSPACE_IPC_TEST_PID, invalid_handle, b"x"),
            Err(IpcSendError::InvalidCapability)
        );
    }

    #[test]
    fn ipc_teardown_makes_stale_handles_fail_after_slot_reuse() {
        let mut table = IpcEndpointTable::new();
        let endpoint_slot = table
            .create_endpoint(KERNEL_PROCESS_ID)
            .expect("create endpoint");
        let stale_handle = table
            .grant_send_capability(USERSPACE_IPC_TEST_PID, endpoint_slot)
            .expect("grant capability");
        table
            .teardown_endpoint(endpoint_slot)
            .expect("teardown endpoint");
        assert_eq!(
            table.send_message(USERSPACE_IPC_TEST_PID, stale_handle, b"x"),
            Err(IpcSendError::StaleCapability)
        );

        let reused_slot = table
            .create_endpoint(KERNEL_PROCESS_ID)
            .expect("reuse endpoint slot");
        assert_eq!(reused_slot, endpoint_slot);
        assert_eq!(
            table.send_message(USERSPACE_IPC_TEST_PID, stale_handle, b"x"),
            Err(IpcSendError::StaleCapability)
        );
    }

    #[test]
    fn ipc_send_rejects_empty_or_oversized_messages() {
        let mut table = IpcEndpointTable::new();
        let endpoint_slot = table
            .create_endpoint(KERNEL_PROCESS_ID)
            .expect("create endpoint");
        let handle = table
            .grant_send_capability(USERSPACE_IPC_TEST_PID, endpoint_slot)
            .expect("grant capability");

        assert_eq!(
            table.send_message(USERSPACE_IPC_TEST_PID, handle, b""),
            Err(IpcSendError::InvalidMessageLength)
        );
        let oversized = [0u8; IPC_MAX_MESSAGE_BYTES + 1];
        assert_eq!(
            table.send_message(USERSPACE_IPC_TEST_PID, handle, &oversized),
            Err(IpcSendError::InvalidMessageLength)
        );
    }

    #[test]
    fn ipc_endpoint_generation_near_wrap_never_aliases_stale_handles() {
        let mut table = IpcEndpointTable::new();
        let endpoint_slot = table
            .create_endpoint(KERNEL_PROCESS_ID)
            .expect("create endpoint");
        table.endpoints[endpoint_slot].generation = u16::MAX - 1;
        let stale_handle = table
            .grant_send_capability(USERSPACE_IPC_TEST_PID, endpoint_slot)
            .expect("grant near-wrap capability");

        table
            .teardown_endpoint(endpoint_slot)
            .expect("teardown at max-1");
        let reused_slot = table
            .create_endpoint(KERNEL_PROCESS_ID)
            .expect("reuse endpoint slot at max generation");
        assert_eq!(reused_slot, endpoint_slot);
        assert_eq!(
            table.send_message(USERSPACE_IPC_TEST_PID, stale_handle, b"x"),
            Err(IpcSendError::StaleCapability)
        );

        table
            .teardown_endpoint(endpoint_slot)
            .expect("teardown at max generation retires slot");
        assert_eq!(
            table.endpoints[endpoint_slot].state,
            IpcEndpointState::Retired
        );
    }

    #[test]
    fn ipc_capability_generation_exhaustion_retires_slot() {
        let mut table = IpcEndpointTable::new();
        let endpoint_slot = table
            .create_endpoint(KERNEL_PROCESS_ID)
            .expect("create endpoint");
        table.capabilities[0].generation = u16::MAX;
        for capability in table.capabilities.iter_mut().skip(1) {
            capability.retired = true;
        }

        assert!(table
            .grant_send_capability(USERSPACE_IPC_TEST_PID, endpoint_slot)
            .is_err());
        assert!(table.capabilities[0].retired);
    }

    #[test]
    fn ipc_process_helpers_count_and_revoke_owned_resources() {
        let mut table = IpcEndpointTable::new();
        let endpoint_slot = table
            .create_endpoint(USERSPACE_IPC_TEST_PID)
            .expect("create endpoint");
        let handle = table
            .grant_send_capability(USERSPACE_IPC_TEST_PID, endpoint_slot)
            .expect("grant capability");
        let other_handle = table
            .grant_send_capability(USERSPACE_IPC_UNAUTHORIZED_TEST_PID, endpoint_slot)
            .expect("grant other capability");

        assert_eq!(
            table.resources_for_pid(USERSPACE_IPC_TEST_PID),
            IpcProcessResources {
                owned_endpoints: 1,
                held_capabilities: 1,
            }
        );
        assert_eq!(table.revoke_capabilities_held_by(USERSPACE_IPC_TEST_PID), 1);
        assert_eq!(
            table.send_message(USERSPACE_IPC_TEST_PID, handle, b"x"),
            Err(IpcSendError::StaleCapability)
        );
        assert_eq!(
            table
                .teardown_resources_for_pid(USERSPACE_IPC_TEST_PID)
                .expect("teardown pid resources"),
            IpcProcessResources {
                owned_endpoints: 1,
                held_capabilities: 0,
            }
        );
        assert_eq!(
            table.send_message(USERSPACE_IPC_UNAUTHORIZED_TEST_PID, other_handle, b"x"),
            Err(IpcSendError::StaleCapability)
        );
    }
}
