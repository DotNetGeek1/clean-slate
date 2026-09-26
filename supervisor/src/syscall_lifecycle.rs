//! Kernel lifecycle control via syscall 4 (M4.2 / #36).

use clean_slate_service_lifecycle::{
    ControlRequest, LifecycleEvent, LifecycleMessage, ServiceId, LIFECYCLE_WIRE_MAX_BYTES,
};

use crate::control::{LifecycleControl, LifecycleControlError};

const SYSCALL_NR_LIFECYCLE_CONTROL: u64 = 4;
const SYSCALL_NR_LIFECYCLE_POLL: u64 = 5;
const SYSCALL_ESTALE: u64 = u64::MAX - 116;

/// Userspace transport for capability-gated lifecycle control.
pub struct SyscallLifecycleControl<const MAX_EVENTS: usize = 16> {
    capability: u64,
    pending: [Option<LifecycleEvent>; MAX_EVENTS],
    pending_count: usize,
}

impl<const MAX_EVENTS: usize> SyscallLifecycleControl<MAX_EVENTS> {
    pub const fn new(capability: u64) -> Self {
        Self {
            capability,
            pending: [None; MAX_EVENTS],
            pending_count: 0,
        }
    }

    fn push_pending(&mut self, event: LifecycleEvent) -> Result<(), LifecycleControlError> {
        if self.pending_count >= MAX_EVENTS {
            return Err(LifecycleControlError::TransportFailed);
        }
        let slot = self
            .pending
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(LifecycleControlError::TransportFailed)?;
        *slot = Some(event);
        self.pending_count += 1;
        Ok(())
    }

    fn syscall_lifecycle(
        &mut self,
        request: ControlRequest,
    ) -> Result<Option<LifecycleEvent>, LifecycleControlError> {
        let wire = LifecycleMessage::ControlRequest(request);
        let encoded = wire.encode();
        let mut reply = [0u8; LIFECYCLE_WIRE_MAX_BYTES];
        let result: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                in("rax") SYSCALL_NR_LIFECYCLE_CONTROL,
                in("rdi") self.capability,
                in("rsi") encoded.as_ptr(),
                in("rdx") encoded.len(),
                in("r8") reply.len(),
                in("r10") reply.as_mut_ptr(),
                lateout("rax") result,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        if result == SYSCALL_ESTALE {
            return Err(LifecycleControlError::TransportFailed);
        }
        if result == 0 {
            return Ok(None);
        }
        if result > reply.len() as u64 {
            return Err(LifecycleControlError::TransportFailed);
        }
        let (decoded, _) = LifecycleMessage::decode(&reply[..result as usize])
            .map_err(|_| LifecycleControlError::TransportFailed)?;
        match decoded {
            LifecycleMessage::LifecycleEvent(event) => Ok(Some(event)),
            _ => Err(LifecycleControlError::TransportFailed),
        }
    }

    fn syscall_poll(
        &mut self,
        service: ServiceId,
    ) -> Result<Option<LifecycleEvent>, LifecycleControlError> {
        let mut reply = [0u8; LIFECYCLE_WIRE_MAX_BYTES];
        let result: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                in("rax") SYSCALL_NR_LIFECYCLE_POLL,
                in("rdi") service.0,
                in("rsi") self.capability,
                in("r8") reply.len(),
                in("r10") reply.as_mut_ptr(),
                lateout("rax") result,
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        if result == 0 {
            return Ok(None);
        }
        if result > reply.len() as u64 {
            return Err(LifecycleControlError::TransportFailed);
        }
        let (decoded, _) = LifecycleMessage::decode(&reply[..result as usize])
            .map_err(|_| LifecycleControlError::TransportFailed)?;
        match decoded {
            LifecycleMessage::LifecycleEvent(event) => Ok(Some(event)),
            _ => Err(LifecycleControlError::TransportFailed),
        }
    }
}

impl<const MAX_EVENTS: usize> LifecycleControl for SyscallLifecycleControl<MAX_EVENTS> {
    fn issue_control(&mut self, request: ControlRequest) -> Result<(), LifecycleControlError> {
        match self.syscall_lifecycle(request)? {
            Some(event) => self.push_pending(event),
            None => Ok(()),
        }
    }

    fn poll_event(
        &mut self,
        service: ServiceId,
    ) -> Result<Option<LifecycleEvent>, LifecycleControlError> {
        for entry in &mut self.pending {
            let Some(event) = *entry else {
                continue;
            };
            if event.instance.service == service {
                *entry = None;
                self.pending_count = self.pending_count.saturating_sub(1);
                return Ok(Some(event));
            }
        }
        self.syscall_poll(service)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_control_struct_compiles() {
        let _ = SyscallLifecycleControl::<4>::new(1);
    }
}
