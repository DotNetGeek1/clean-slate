//! Explicit supervisor lifecycle-control capability handles (separate from IPC send caps).

const LIFECYCLE_CONTROL_CAPABILITY_CAPACITY: usize = 4;
const BLOCK_DEVICE_CAPABILITY_CAPACITY: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LifecycleControlCapability {
    holder_pid: u64,
    generation: u16,
    active: bool,
    retired: bool,
}

impl LifecycleControlCapability {
    const EMPTY: Self = Self {
        holder_pid: 0,
        generation: 0,
        active: false,
        retired: false,
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

    pub(crate) fn revoke_capabilities_for_pid(&mut self, pid: u64) {
        for capability in &mut self.capabilities {
            if capability.active && capability.holder_pid == pid {
                Self::retire_capability(capability);
            }
        }
    }
}

impl LifecycleControlCapabilityTable {
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

    #[allow(dead_code)]
    fn retire_capability(capability: &mut LifecycleControlCapability) {
        capability.active = false;
        capability.holder_pid = 0;
        if let Some(next_generation) = Self::next_generation(capability.generation) {
            capability.generation = next_generation;
        } else {
            capability.retired = true;
        }
    }

    pub(crate) fn grant_lifecycle_control_capability(
        &mut self,
        holder_pid: u64,
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
            return Ok(LifecycleControlHandleParts {
                capability_slot: u16::try_from(slot)
                    .map_err(|_| "lifecycle control capability slot exceeded u16 handle field")?,
                capability_generation: capability.generation,
            }
            .encode());
        }
        Err("lifecycle control capability table capacity exceeded or generation exhausted")
    }

    pub(crate) fn authorize_lifecycle_control(
        &self,
        holder_pid: u64,
        raw_handle: u64,
    ) -> Result<(), LifecycleControlCapabilityError> {
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
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn revoke_capabilities_for_pid(&mut self, pid: u64) {
        for capability in &mut self.capabilities {
            if capability.active && capability.holder_pid == pid {
                Self::retire_capability(capability);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_control_capability_authorizes_only_granted_process() {
        let mut table = LifecycleControlCapabilityTable::new();
        let handle = table
            .grant_lifecycle_control_capability(10)
            .expect("grant capability");
        assert!(table.authorize_lifecycle_control(10, handle).is_ok());
        assert_eq!(
            table.authorize_lifecycle_control(11, handle),
            Err(LifecycleControlCapabilityError::Unauthorized)
        );
    }

    #[test]
    fn lifecycle_control_stale_handle_fails_after_revoke() {
        let mut table = LifecycleControlCapabilityTable::new();
        let handle = table
            .grant_lifecycle_control_capability(3)
            .expect("grant capability");
        table.revoke_capabilities_for_pid(3);
        assert_eq!(
            table.authorize_lifecycle_control(3, handle),
            Err(LifecycleControlCapabilityError::StaleHandle)
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
