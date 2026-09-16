//! Narrow lifecycle-control transport (real IPC in #36; fakes for host/userspace tests).

use clean_slate_service_lifecycle::{ControlRequest, LifecycleEvent, ServiceId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleControlError {
    TransportFailed,
    Unsupported,
}

/// Issues control requests and receives lifecycle events from the kernel launch path.
pub trait LifecycleControl {
    fn issue_control(&mut self, request: ControlRequest) -> Result<(), LifecycleControlError>;

    /// Poll or dequeue the next lifecycle event for `service`, if any.
    fn poll_event(
        &mut self,
        service: ServiceId,
    ) -> Result<Option<LifecycleEvent>, LifecycleControlError>;
}

/// Host-test backend that records control requests and serves scripted events.
pub struct FakeLifecycleControl<const MAX_EVENTS: usize = 16> {
    issued: [Option<ControlRequest>; MAX_EVENTS],
    issued_len: usize,
    pending: [Option<LifecycleEvent>; MAX_EVENTS],
    pending_count: usize,
}

impl<const MAX_EVENTS: usize> Default for FakeLifecycleControl<MAX_EVENTS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_EVENTS: usize> FakeLifecycleControl<MAX_EVENTS> {
    pub const fn new() -> Self {
        Self {
            issued: [None; MAX_EVENTS],
            issued_len: 0,
            pending: [None; MAX_EVENTS],
            pending_count: 0,
        }
    }

    pub fn push_pending(&mut self, event: LifecycleEvent) -> Result<(), LifecycleControlError> {
        if self.pending_count >= MAX_EVENTS {
            return Err(LifecycleControlError::TransportFailed);
        }
        if let Some(slot) = self.pending.iter_mut().find(|entry| entry.is_none()) {
            *slot = Some(event);
            self.pending_count += 1;
            return Ok(());
        }
        Err(LifecycleControlError::TransportFailed)
    }

    pub fn issued_requests(&self) -> impl Iterator<Item = ControlRequest> + '_ {
        self.issued[..self.issued_len]
            .iter()
            .filter_map(|entry| *entry)
    }
}

impl<const MAX_EVENTS: usize> LifecycleControl for FakeLifecycleControl<MAX_EVENTS> {
    fn issue_control(&mut self, request: ControlRequest) -> Result<(), LifecycleControlError> {
        if self.issued_len >= MAX_EVENTS {
            return Err(LifecycleControlError::TransportFailed);
        }
        self.issued[self.issued_len] = Some(request);
        self.issued_len += 1;
        Ok(())
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
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_service_lifecycle::ControlRequestKind;

    #[test]
    fn fake_records_control_requests() {
        let mut fake = FakeLifecycleControl::<4>::new();
        let service = ServiceId(7);
        fake.issue_control(ControlRequest::new(service, ControlRequestKind::Start))
            .expect("issue");
        let issued: Vec<_> = fake.issued_requests().collect();
        assert_eq!(issued.len(), 1);
        assert_eq!(issued[0].service, service);
    }
}
