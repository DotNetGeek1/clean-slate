//! Capability-gated lifecycle control dispatch and service registry.

use crate::diagnostics::log::kernel_log_fmt;
use crate::mm::frame_allocator::PageAllocator;
use crate::process::domain::teardown_process_by_id;
use crate::process::process_registry_mut;
use crate::service::capability::LifecycleControlCapabilityError;
use crate::service::spawn::launch_builtin_service;
use crate::sync::global_cell::GlobalCell;
use clean_slate_service_lifecycle::apply_transition;
use clean_slate_service_lifecycle::ControlRequest;
use clean_slate_service_lifecycle::ControlRequestKind;
use clean_slate_service_lifecycle::DecodeError;
use clean_slate_service_lifecycle::DomainId;
use clean_slate_service_lifecycle::InstanceGeneration;
use clean_slate_service_lifecycle::LifecycleEvent;
use clean_slate_service_lifecycle::LifecycleEventKind;
use clean_slate_service_lifecycle::LifecycleMessage;
use clean_slate_service_lifecycle::ProcessId;
use clean_slate_service_lifecycle::ServiceId;
use clean_slate_service_lifecycle::ServiceInstanceId;
use clean_slate_service_lifecycle::ServiceLifecycleState;
use clean_slate_service_lifecycle::TransitionError;
use clean_slate_service_lifecycle::TransitionInput;

const SERVICE_REGISTRY_CAPACITY: usize = 4;
const SERVICE_TERMINATE_STATUS: u64 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LiveServiceInstance {
    pid: u64,
    tid: u64,
    domain_id: u64,
    generation: InstanceGeneration,
    scheduler_slot: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ServiceRecord {
    service: ServiceId,
    state: ServiceLifecycleState,
    authoritative_generation: InstanceGeneration,
    live: Option<LiveServiceInstance>,
}

impl ServiceRecord {
    const fn empty() -> Self {
        Self {
            service: ServiceId(0),
            state: ServiceLifecycleState::Declared,
            authoritative_generation: InstanceGeneration(0),
            live: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LifecycleControlError {
    Unauthorized,
    StaleHandle,
    InvalidHandle,
    InvalidMessage(DecodeError),
    InvalidTransition(TransitionError),
    UnknownService,
    ServiceAlreadyLive,
    ServiceNotLive,
    StaleInstance(ServiceInstanceId),
    SpawnFailed(&'static str),
    TeardownFailed(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LifecycleControlResult {
    pub(crate) event: LifecycleEvent,
}

pub(crate) struct ServiceLifecycleController {
    capabilities: super::capability::LifecycleControlCapabilityTable,
    services: [ServiceRecord; SERVICE_REGISTRY_CAPACITY],
    next_scheduler_slot: usize,
    kernel_root_frame: u64,
    kernel_stack_top: u64,
}

impl ServiceLifecycleController {
    const fn new() -> Self {
        Self {
            capabilities: super::capability::LifecycleControlCapabilityTable::new(),
            services: [ServiceRecord::empty(); SERVICE_REGISTRY_CAPACITY],
            next_scheduler_slot: 2,
            kernel_root_frame: 0,
            kernel_stack_top: 0,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.capabilities.clear();
        self.services = [ServiceRecord::empty(); SERVICE_REGISTRY_CAPACITY];
        self.next_scheduler_slot = 2;
    }

    pub(crate) fn configure_launch_context(
        &mut self,
        kernel_root_frame: u64,
        kernel_stack_top: u64,
    ) {
        self.kernel_root_frame = kernel_root_frame;
        self.kernel_stack_top = kernel_stack_top;
    }

    pub(crate) fn declare_service(&mut self, service: ServiceId) -> Result<(), &'static str> {
        if self.find_service(service).is_some() {
            return Err("service was already declared");
        }
        let slot = self
            .services
            .iter_mut()
            .find(|entry| entry.service.0 == 0)
            .ok_or("service registry capacity exceeded")?;
        *slot = ServiceRecord {
            service,
            state: ServiceLifecycleState::Declared,
            authoritative_generation: InstanceGeneration(0),
            live: None,
        };
        kernel_log_fmt(format_args!("[SVC ] declared service={}\n", service.0));
        Ok(())
    }

    pub(crate) fn grant_lifecycle_control_capability(
        &mut self,
        holder_pid: u64,
    ) -> Result<u64, &'static str> {
        self.capabilities
            .grant_lifecycle_control_capability(holder_pid)
    }

    fn find_service(&self, service: ServiceId) -> Option<&ServiceRecord> {
        self.services
            .iter()
            .find(|entry| entry.service == service && entry.service.0 != 0)
    }

    fn find_service_mut(&mut self, service: ServiceId) -> Option<&mut ServiceRecord> {
        self.services
            .iter_mut()
            .find(|entry| entry.service == service && entry.service.0 != 0)
    }

    fn allocate_scheduler_slot(&mut self) -> Result<usize, &'static str> {
        let slot = self.next_scheduler_slot;
        self.next_scheduler_slot = self
            .next_scheduler_slot
            .checked_add(1)
            .ok_or("supervised service scheduler slot space exhausted")?;
        Ok(slot)
    }

    fn service_index(&self, service_id: ServiceId) -> Option<usize> {
        self.services
            .iter()
            .position(|entry| entry.service == service_id && entry.service.0 != 0)
    }

    fn start_service(
        &mut self,
        allocator: &mut PageAllocator,
        service_id: ServiceId,
    ) -> Result<LifecycleControlResult, LifecycleControlError> {
        let service_index = self
            .service_index(service_id)
            .ok_or(LifecycleControlError::UnknownService)?;
        if self.services[service_index].live.is_some() {
            return Err(LifecycleControlError::ServiceAlreadyLive);
        }
        if self.kernel_stack_top == 0 {
            return Err(LifecycleControlError::SpawnFailed(
                "service launch context was not configured",
            ));
        }
        let kernel_stack_top = self.kernel_stack_top;
        let scheduler_slot = self
            .allocate_scheduler_slot()
            .map_err(LifecycleControlError::SpawnFailed)?;
        let generation = self.services[service_index].authoritative_generation;
        let spawned =
            launch_builtin_service(allocator, kernel_stack_top, scheduler_slot, service_id)
                .map_err(LifecycleControlError::SpawnFailed)?;
        let instance = ServiceInstanceId::new(
            service_id,
            generation,
            ProcessId(spawned.pid),
            DomainId(spawned.domain_id),
        );
        self.services[service_index].live = Some(LiveServiceInstance {
            pid: spawned.pid,
            tid: spawned.tid,
            domain_id: spawned.domain_id,
            generation,
            scheduler_slot,
        });
        self.log_launch(instance);
        Ok(LifecycleControlResult {
            event: LifecycleEvent::new(instance, LifecycleEventKind::InstanceSpawned),
        })
    }

    fn terminate_service(
        &mut self,
        allocator: &mut PageAllocator,
        service_id: ServiceId,
    ) -> Result<LifecycleControlResult, LifecycleControlError> {
        let service_index = self
            .service_index(service_id)
            .ok_or(LifecycleControlError::UnknownService)?;
        let live = self.services[service_index]
            .live
            .take()
            .ok_or(LifecycleControlError::ServiceNotLive)?;
        self.log_terminate(service_id, live.pid);
        teardown_process_by_id(
            allocator,
            self.kernel_root_frame,
            live.pid,
            SERVICE_TERMINATE_STATUS,
            false,
        )
        .map_err(LifecycleControlError::TeardownFailed)?;
        self.log_reaped(service_id, live.pid);
        if unsafe { process_registry_mut().get(live.pid) }.is_some() {
            return Err(LifecycleControlError::TeardownFailed(
                "process registry retained a reaped supervised service",
            ));
        }
        self.services[service_index].state = ServiceLifecycleState::Exited;
        let instance = ServiceInstanceId::new(
            service_id,
            live.generation,
            ProcessId(live.pid),
            DomainId(live.domain_id),
        );
        Ok(LifecycleControlResult {
            event: LifecycleEvent::new(instance, LifecycleEventKind::Exited),
        })
    }

    fn log_launch(&self, instance: ServiceInstanceId) {
        kernel_log_fmt(format_args!(
            "[SVC ] launch service={} pid={} gen={}\n",
            instance.service.0, instance.pid.0, instance.generation.0
        ));
    }

    fn log_terminate(&self, service: ServiceId, pid: u64) {
        kernel_log_fmt(format_args!(
            "[SVC ] terminate service={} pid={}\n",
            service.0, pid
        ));
    }

    fn log_reaped(&self, service: ServiceId, pid: u64) {
        kernel_log_fmt(format_args!(
            "[SVC ] reaped service={} pid={}\n",
            service.0, pid
        ));
    }

    pub(crate) fn handle_control_message(
        &mut self,
        allocator: &mut PageAllocator,
        supervisor_pid: u64,
        capability_handle: u64,
        message: &[u8],
    ) -> Result<LifecycleControlResult, LifecycleControlError> {
        self.capabilities
            .authorize_lifecycle_control(supervisor_pid, capability_handle)
            .map_err(|error| match error {
                LifecycleControlCapabilityError::Unauthorized => {
                    LifecycleControlError::Unauthorized
                }
                LifecycleControlCapabilityError::StaleHandle => LifecycleControlError::StaleHandle,
                LifecycleControlCapabilityError::InvalidHandle => {
                    LifecycleControlError::InvalidHandle
                }
            })?;
        let (decoded, _) =
            LifecycleMessage::decode(message).map_err(LifecycleControlError::InvalidMessage)?;
        let LifecycleMessage::ControlRequest(request) = decoded else {
            return Err(LifecycleControlError::InvalidMessage(
                DecodeError::UnknownMessageKind(0),
            ));
        };
        self.handle_control_request(allocator, supervisor_pid, request)
    }

    pub(crate) fn handle_control_request(
        &mut self,
        allocator: &mut PageAllocator,
        _supervisor_pid: u64,
        request: ControlRequest,
    ) -> Result<LifecycleControlResult, LifecycleControlError> {
        let service_id = request.service;
        let kind = request.kind;
        let record = self
            .find_service_mut(service_id)
            .ok_or(LifecycleControlError::UnknownService)?;
        if kind != ControlRequestKind::Restart {
            let (next_state, next_generation) = apply_transition(
                record.state,
                record.authoritative_generation,
                TransitionInput::Control(kind),
                None,
            )
            .map_err(LifecycleControlError::InvalidTransition)?;
            record.state = next_state;
            record.authoritative_generation = next_generation;
        } else {
            let (next_state, next_generation) = apply_transition(
                record.state,
                record.authoritative_generation,
                TransitionInput::Control(ControlRequestKind::Restart),
                None,
            )
            .map_err(LifecycleControlError::InvalidTransition)?;
            record.state = next_state;
            record.authoritative_generation = next_generation;
        }

        match kind {
            ControlRequestKind::Start => self.start_service(allocator, service_id),
            ControlRequestKind::Terminate | ControlRequestKind::Stop => {
                self.terminate_service(allocator, service_id)
            }
            ControlRequestKind::Restart => {
                if self
                    .find_service(service_id)
                    .and_then(|record| record.live)
                    .is_some()
                {
                    self.terminate_service(allocator, service_id)?;
                }
                let record = self
                    .find_service_mut(service_id)
                    .ok_or(LifecycleControlError::UnknownService)?;
                let (next_state, next_generation) = apply_transition(
                    record.state,
                    record.authoritative_generation,
                    TransitionInput::Control(ControlRequestKind::Start),
                    None,
                )
                .map_err(LifecycleControlError::InvalidTransition)?;
                record.state = next_state;
                record.authoritative_generation = next_generation;
                self.start_service(allocator, service_id)
            }
        }
    }

    pub(crate) fn validate_instance_handle(
        &self,
        instance: ServiceInstanceId,
    ) -> Result<(), LifecycleControlError> {
        let record = self
            .find_service(instance.service)
            .ok_or(LifecycleControlError::UnknownService)?;
        if instance.generation != record.authoritative_generation {
            return Err(LifecycleControlError::StaleInstance(instance));
        }
        let Some(live) = record.live else {
            return Err(LifecycleControlError::StaleInstance(instance));
        };
        if live.pid != instance.pid.0 || live.domain_id != instance.domain.0 {
            return Err(LifecycleControlError::StaleInstance(instance));
        }
        Ok(())
    }
}

static SERVICE_LIFECYCLE_CONTROLLER: GlobalCell<ServiceLifecycleController> =
    GlobalCell::new(ServiceLifecycleController::new());

/// Returns the service lifecycle controller for call sites that hold the reference across other calls.
///
/// # Safety
/// The caller must ensure no other live reference to the controller exists for the lifetime of the
/// returned borrow.
pub(crate) unsafe fn service_lifecycle_controller_mut() -> &'static mut ServiceLifecycleController {
    unsafe { &mut *SERVICE_LIFECYCLE_CONTROLLER.get() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mm::frame_allocator::PageAllocator;

    #[test]
    fn unauthorized_supervisor_cannot_control_services() {
        use crate::boot::uefi::normalize_memory_map;
        use uefi::mem::memory_map::{MemoryAttribute, MemoryDescriptor, MemoryType};

        let mut controller = ServiceLifecycleController::new();
        controller
            .declare_service(ServiceId(7))
            .expect("declare service");
        let capability = controller
            .grant_lifecycle_control_capability(100)
            .expect("grant capability");
        #[repr(align(4096))]
        struct AlignedPages([u8; crate::mm::PAGE_SIZE as usize * 4]);
        let mut pages = AlignedPages([0; crate::mm::PAGE_SIZE as usize * 4]);
        let base = pages.0.as_mut_ptr() as u64;
        let descriptors = [MemoryDescriptor {
            ty: MemoryType::CONVENTIONAL,
            phys_start: base,
            virt_start: 0,
            page_count: 4,
            att: MemoryAttribute::empty(),
        }];
        let map = normalize_memory_map(descriptors.iter(), &[]).expect("normalize map");
        let mut allocator = PageAllocator::new(&map).expect("allocator");
        controller.configure_launch_context(0x1000, 0x2000);
        let request = ControlRequest::new(ServiceId(7), ControlRequestKind::Start);
        let message = LifecycleMessage::ControlRequest(request).encode();
        let err = controller
            .handle_control_message(&mut allocator, 101, capability, &message)
            .unwrap_err();
        assert_eq!(err, LifecycleControlError::Unauthorized);
    }

    #[test]
    fn stale_instance_handle_fails_after_restart() {
        let mut controller = ServiceLifecycleController::new();
        controller.services[0] = ServiceRecord {
            service: ServiceId(1),
            state: ServiceLifecycleState::Running,
            authoritative_generation: InstanceGeneration(2),
            live: Some(LiveServiceInstance {
                pid: 42,
                tid: 7,
                domain_id: 42,
                generation: InstanceGeneration(2),
                scheduler_slot: 3,
            }),
        };
        let stale = ServiceInstanceId::new(
            ServiceId(1),
            InstanceGeneration(1),
            ProcessId(10),
            DomainId(10),
        );
        assert_eq!(
            controller.validate_instance_handle(stale),
            Err(LifecycleControlError::StaleInstance(stale))
        );
    }

    #[test]
    fn restart_transition_bumps_generation_before_spawn() {
        let mut controller = ServiceLifecycleController::new();
        controller.services[0] = ServiceRecord {
            service: ServiceId(4),
            state: ServiceLifecycleState::Running,
            authoritative_generation: InstanceGeneration(3),
            live: None,
        };
        let (next_state, next_generation) = apply_transition(
            ServiceLifecycleState::Running,
            InstanceGeneration(3),
            TransitionInput::Control(ControlRequestKind::Restart),
            None,
        )
        .expect("restart transition");
        assert_eq!(next_state, ServiceLifecycleState::RestartPending);
        assert_eq!(next_generation, InstanceGeneration(3));
        let (starting, bumped) = apply_transition(
            ServiceLifecycleState::Exited,
            InstanceGeneration(3),
            TransitionInput::Control(ControlRequestKind::Start),
            None,
        )
        .expect("start after exit");
        assert_eq!(starting, ServiceLifecycleState::Starting);
        assert_eq!(bumped, InstanceGeneration(4));
        let _ = &mut controller;
    }
}
