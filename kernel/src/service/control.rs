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
const SERVICE_PENDING_EVENTS: usize = 16;
const SERVICE_TERMINATE_STATUS: u64 = 0;
#[cfg(feature = "m4-recovery-self-test")]
const SERVICE_SCHEDULER_SLOT_START: usize = 2;
#[cfg(not(feature = "m4-recovery-self-test"))]
const SERVICE_SCHEDULER_SLOT_START: usize = 0;

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
    pub(crate) event: Option<LifecycleEvent>,
}

pub(crate) struct ServiceLifecycleController {
    capabilities: super::capability::LifecycleControlCapabilityTable,
    services: [ServiceRecord; SERVICE_REGISTRY_CAPACITY],
    pending: [Option<LifecycleEvent>; SERVICE_PENDING_EVENTS],
    pending_count: usize,
    next_scheduler_slot: usize,
    kernel_root_frame: u64,
    kernel_stack_top: u64,
}

impl ServiceLifecycleController {
    const fn new() -> Self {
        Self {
            capabilities: super::capability::LifecycleControlCapabilityTable::new(),
            services: [ServiceRecord::empty(); SERVICE_REGISTRY_CAPACITY],
            pending: [None; SERVICE_PENDING_EVENTS],
            pending_count: 0,
            next_scheduler_slot: SERVICE_SCHEDULER_SLOT_START,
            kernel_root_frame: 0,
            kernel_stack_top: 0,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.capabilities.clear();
        self.services = [ServiceRecord::empty(); SERVICE_REGISTRY_CAPACITY];
        self.pending = [None; SERVICE_PENDING_EVENTS];
        self.pending_count = 0;
        self.next_scheduler_slot = SERVICE_SCHEDULER_SLOT_START;
    }

    #[allow(dead_code)]
    fn push_pending(&mut self, event: LifecycleEvent) -> Result<(), LifecycleControlError> {
        if self.pending_count >= SERVICE_PENDING_EVENTS {
            return Err(Self::event_queue_full_error());
        }
        let slot = self
            .pending
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(Self::event_queue_full_error())?;
        *slot = Some(event);
        self.pending_count += 1;
        Ok(())
    }

    fn push_terminal_pending(
        &mut self,
        event: LifecycleEvent,
    ) -> Result<(), LifecycleControlError> {
        debug_assert!(matches!(
            event.kind,
            LifecycleEventKind::Faulted | LifecycleEventKind::Exited
        ));
        if self.push_pending(event).is_ok() {
            return Ok(());
        }
        for pending in &mut self.pending {
            let Some(queued) = *pending else {
                continue;
            };
            if queued.instance.service == event.instance.service
                || !matches!(
                    queued.kind,
                    LifecycleEventKind::Faulted | LifecycleEventKind::Exited
                )
            {
                *pending = Some(event);
                return Ok(());
            }
        }
        if let Some(slot) = self.pending.iter_mut().find(|entry| entry.is_none()) {
            *slot = Some(event);
            self.pending_count = self.pending_count.saturating_add(1);
            return Ok(());
        }
        if let Some(slot) = self.pending.first_mut() {
            *slot = Some(event);
            self.pending_count = SERVICE_PENDING_EVENTS;
            return Ok(());
        }
        Ok(())
    }

    const fn event_queue_full_error() -> LifecycleControlError {
        LifecycleControlError::InvalidMessage(
            clean_slate_service_lifecycle::DecodeError::BufferTooShort {
                actual: 0,
                required: 1,
            },
        )
    }

    #[allow(dead_code)]
    pub(crate) fn replay_pending_lifecycle_event(
        &mut self,
        event: LifecycleEvent,
    ) -> Result<(), LifecycleControlError> {
        self.push_pending(event)
    }

    pub(crate) fn poll_pending_event(
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

    pub(crate) fn poll_pending_event_authorized(
        &mut self,
        supervisor_pid: u64,
        capability_handle: u64,
        service: ServiceId,
    ) -> Result<Option<LifecycleEvent>, LifecycleControlError> {
        self.authorize_lifecycle_control(supervisor_pid, capability_handle)?;
        self.poll_pending_event(service)
    }

    #[allow(dead_code)]
    pub(crate) fn notify_instance_ready(
        &mut self,
        service_id: ServiceId,
    ) -> Result<(), LifecycleControlError> {
        let service_index = self
            .service_index(service_id)
            .ok_or(LifecycleControlError::UnknownService)?;
        let record = self.services[service_index];
        let live = record.live.ok_or(LifecycleControlError::ServiceNotLive)?;
        let instance = ServiceInstanceId::new(
            service_id,
            live.generation,
            ProcessId(live.pid),
            DomainId(live.domain_id),
        );
        let (next_state, _) = apply_transition(
            record.state,
            record.authoritative_generation,
            TransitionInput::Event(LifecycleEventKind::Ready),
            Some(instance),
        )
        .map_err(LifecycleControlError::InvalidTransition)?;
        self.push_pending(LifecycleEvent::new(instance, LifecycleEventKind::Ready))?;
        self.services[service_index].state = next_state;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn notify_instance_faulted(
        &mut self,
        service_id: ServiceId,
        pid: u64,
    ) -> Result<LifecycleEvent, LifecycleControlError> {
        self.notify_instance_faulted_with_status(service_id, pid, 0)
    }

    pub(crate) fn notify_faulted_live_process(
        &mut self,
        pid: u64,
        status_code: u32,
    ) -> Result<Option<LifecycleEvent>, LifecycleControlError> {
        let Some(service_index) = self
            .services
            .iter()
            .position(|entry| entry.live.is_some_and(|live| live.pid == pid))
        else {
            return Ok(None);
        };
        let service_id = self.services[service_index].service;
        let event = self.notify_instance_faulted_with_status(service_id, pid, status_code)?;
        Ok(Some(event))
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

    #[allow(dead_code)]
    pub(crate) fn authoritative_generation(
        &self,
        service: ServiceId,
    ) -> Option<InstanceGeneration> {
        self.find_service(service)
            .map(|record| record.authoritative_generation)
    }

    #[allow(dead_code)]
    pub(crate) fn live_pid(&self, service: ServiceId) -> Option<u64> {
        self.find_service(service)
            .and_then(|record| record.live.map(|live| live.pid))
    }

    fn find_service(&self, service: ServiceId) -> Option<&ServiceRecord> {
        self.services
            .iter()
            .find(|entry| entry.service == service && entry.service.0 != 0)
    }

    fn allocate_scheduler_slot(&mut self) -> Result<usize, &'static str> {
        let scheduler = unsafe { crate::sched::scheduler_mut() };
        let slot = scheduler
            .first_empty_slot_from(self.next_scheduler_slot)
            .ok_or("thread slot exceeded fixed scheduler capacity")?;
        self.next_scheduler_slot = (slot + 1) % scheduler.thread_capacity();
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
        generation: InstanceGeneration,
    ) -> Result<LifecycleControlResult, LifecycleControlError> {
        let service_index = self
            .service_index(service_id)
            .ok_or(LifecycleControlError::UnknownService)?;
        if self.services[service_index].live.is_some() {
            return Err(LifecycleControlError::ServiceAlreadyLive);
        }
        let scheduler_slot = self
            .allocate_scheduler_slot()
            .map_err(LifecycleControlError::SpawnFailed)?;
        let kernel_stack_top = {
            #[cfg(feature = "m4-recovery-self-test")]
            {
                use crate::arch::x86_64::context_switch::task_stack_top;
                use crate::sched::task_stacks_mut;
                let stacks = unsafe { task_stacks_mut() };
                if scheduler_slot >= stacks.len() {
                    return Err(LifecycleControlError::SpawnFailed(
                        "recovery scheduler slot exceeds task stack table",
                    ));
                }
                task_stack_top(&stacks[scheduler_slot])
            }
            #[cfg(not(feature = "m4-recovery-self-test"))]
            {
                if self.kernel_stack_top == 0 {
                    return Err(LifecycleControlError::SpawnFailed(
                        "service launch context was not configured",
                    ));
                }
                self.kernel_stack_top
            }
        };
        let spawned = if service_id.0 == 0x0000_4100 {
            #[cfg(feature = "m4-recovery-self-test")]
            {
                super::recovery_launch::spawn_crash_service(
                    allocator,
                    kernel_stack_top,
                    scheduler_slot,
                    service_id,
                    generation,
                )
                .map_err(LifecycleControlError::SpawnFailed)?
            }
            #[cfg(not(feature = "m4-recovery-self-test"))]
            {
                return Err(LifecycleControlError::SpawnFailed(
                    "crash service launch requires m4-recovery-self-test",
                ));
            }
        } else {
            launch_builtin_service(allocator, kernel_stack_top, scheduler_slot, service_id)
                .map_err(|message| {
                    kernel_log_fmt(format_args!(
                        "[FAIL] builtin service spawn service={} slot={} err={message}\n",
                        service_id.0, scheduler_slot
                    ));
                    LifecycleControlError::SpawnFailed(message)
                })?
        };
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
            event: Some(LifecycleEvent::new(
                instance,
                LifecycleEventKind::InstanceSpawned,
            )),
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
        self.services[service_index].live = None;
        self.services[service_index].state = ServiceLifecycleState::Exited;
        let instance = ServiceInstanceId::new(
            service_id,
            live.generation,
            ProcessId(live.pid),
            DomainId(live.domain_id),
        );
        Ok(LifecycleControlResult {
            event: Some(LifecycleEvent::new(instance, LifecycleEventKind::Exited)),
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

    fn authorize_lifecycle_control(
        &self,
        supervisor_pid: u64,
        capability_handle: u64,
    ) -> Result<(), LifecycleControlError> {
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
            })
    }

    pub(crate) fn handle_control_message(
        &mut self,
        allocator: &mut PageAllocator,
        supervisor_pid: u64,
        capability_handle: u64,
        message: &[u8],
    ) -> Result<LifecycleControlResult, LifecycleControlError> {
        self.authorize_lifecycle_control(supervisor_pid, capability_handle)?;
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
        let service_index = self
            .service_index(service_id)
            .ok_or(LifecycleControlError::UnknownService)?;
        let record = self.services[service_index];
        let (next_state, next_generation) = apply_transition(
            record.state,
            record.authoritative_generation,
            TransitionInput::Control(kind),
            None,
        )
        .map_err(LifecycleControlError::InvalidTransition)?;

        match kind {
            ControlRequestKind::Start => {
                let result = self.start_service(allocator, service_id, next_generation)?;
                self.services[service_index].state = next_state;
                self.services[service_index].authoritative_generation = next_generation;
                Ok(result)
            }
            ControlRequestKind::Terminate | ControlRequestKind::Stop => {
                let result = self.terminate_service(allocator, service_id)?;
                self.services[service_index].authoritative_generation = next_generation;
                Ok(result)
            }
            ControlRequestKind::Restart => {
                let live_instance = self.services[service_index].live;
                if let Some(live) = live_instance {
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
                }
                self.services[service_index].state = next_state;
                self.services[service_index].authoritative_generation = next_generation;
                self.services[service_index].live = None;
                Ok(LifecycleControlResult { event: None })
            }
        }
    }

    #[allow(dead_code)]
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

    fn notify_instance_faulted_with_status(
        &mut self,
        service_id: ServiceId,
        pid: u64,
        status_code: u32,
    ) -> Result<LifecycleEvent, LifecycleControlError> {
        let service_index = self
            .service_index(service_id)
            .ok_or(LifecycleControlError::UnknownService)?;
        let record = self.services[service_index];
        let live = record.live.ok_or(LifecycleControlError::ServiceNotLive)?;
        if live.pid != pid {
            return Err(LifecycleControlError::StaleInstance(
                ServiceInstanceId::new(
                    service_id,
                    live.generation,
                    ProcessId(pid),
                    DomainId(live.domain_id),
                ),
            ));
        }
        let instance = ServiceInstanceId::new(
            service_id,
            live.generation,
            ProcessId(live.pid),
            DomainId(live.domain_id),
        );
        let (next_state, _) = apply_transition(
            record.state,
            record.authoritative_generation,
            TransitionInput::Event(LifecycleEventKind::Faulted),
            Some(instance),
        )
        .map_err(LifecycleControlError::InvalidTransition)?;
        let mut event = LifecycleEvent::new(instance, LifecycleEventKind::Faulted);
        event.status_code = status_code;
        self.push_terminal_pending(event)?;
        self.services[service_index].state = next_state;
        self.services[service_index].live = None;
        Ok(event)
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
    use crate::sched::ThreadKind;

    fn test_allocator() -> PageAllocator {
        use crate::boot::uefi::normalize_memory_map;
        use uefi::mem::memory_map::{MemoryAttribute, MemoryDescriptor, MemoryType};

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
        PageAllocator::new(&map).expect("allocator")
    }

    #[test]
    fn unauthorized_supervisor_cannot_control_services() {
        let mut controller = ServiceLifecycleController::new();
        controller
            .declare_service(ServiceId(7))
            .expect("declare service");
        let capability = controller
            .grant_lifecycle_control_capability(100)
            .expect("grant capability");
        let mut allocator = test_allocator();
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

    #[cfg(not(feature = "m4-recovery-self-test"))]
    #[test]
    fn allocate_scheduler_slot_wraps_and_finds_empty_slot() {
        unsafe {
            *crate::sched::scheduler_mut() = crate::sched::Scheduler::new();
            crate::sched::scheduler_mut()
                .configure_thread(0, 1, 1, ThreadKind::User, 0x1000, 0x1000, 0x1000)
                .expect("occupy slot zero");
        }

        let mut controller = ServiceLifecycleController::new();
        controller.next_scheduler_slot = 2;
        assert_eq!(controller.allocate_scheduler_slot().expect("allocate"), 1);
    }

    #[test]
    fn start_failure_rolls_back_transition_and_generation() {
        let mut controller = ServiceLifecycleController::new();
        controller
            .declare_service(ServiceId(2))
            .expect("declare service");
        let mut allocator = test_allocator();
        let err = controller
            .handle_control_request(
                &mut allocator,
                0,
                ControlRequest::new(ServiceId(2), ControlRequestKind::Start),
            )
            .unwrap_err();
        assert!(matches!(err, LifecycleControlError::SpawnFailed(_)));
        let record = controller.find_service(ServiceId(2)).expect("record");
        assert_eq!(record.state, ServiceLifecycleState::Declared);
        assert_eq!(record.authoritative_generation, InstanceGeneration(0));
        assert!(record.live.is_none());
    }

    #[test]
    fn terminate_failure_preserves_live_instance() {
        let mut controller = ServiceLifecycleController::new();
        controller.services[0] = ServiceRecord {
            service: ServiceId(9),
            state: ServiceLifecycleState::Running,
            authoritative_generation: InstanceGeneration(1),
            live: Some(LiveServiceInstance {
                pid: 0,
                tid: 7,
                domain_id: 0,
                generation: InstanceGeneration(1),
                scheduler_slot: 1,
            }),
        };
        let mut allocator = test_allocator();
        let err = controller
            .handle_control_request(
                &mut allocator,
                0,
                ControlRequest::new(ServiceId(9), ControlRequestKind::Terminate),
            )
            .unwrap_err();
        assert!(matches!(err, LifecycleControlError::TeardownFailed(_)));
        let record = controller.find_service(ServiceId(9)).expect("record");
        assert_eq!(record.state, ServiceLifecycleState::Running);
        assert_eq!(record.live.expect("live").pid, 0);
    }

    #[test]
    fn restart_failure_preserves_live_instance_and_state() {
        let mut controller = ServiceLifecycleController::new();
        controller.services[0] = ServiceRecord {
            service: ServiceId(10),
            state: ServiceLifecycleState::Running,
            authoritative_generation: InstanceGeneration(2),
            live: Some(LiveServiceInstance {
                pid: 0,
                tid: 7,
                domain_id: 0,
                generation: InstanceGeneration(2),
                scheduler_slot: 2,
            }),
        };
        let mut allocator = test_allocator();
        let err = controller
            .handle_control_request(
                &mut allocator,
                0,
                ControlRequest::new(ServiceId(10), ControlRequestKind::Restart),
            )
            .unwrap_err();
        assert!(matches!(err, LifecycleControlError::TeardownFailed(_)));
        let record = controller.find_service(ServiceId(10)).expect("record");
        assert_eq!(record.state, ServiceLifecycleState::Running);
        assert_eq!(record.live.expect("live").pid, 0);
    }

    #[test]
    fn ready_notification_queue_failure_does_not_commit_state() {
        let mut controller = ServiceLifecycleController::new();
        controller.services[0] = ServiceRecord {
            service: ServiceId(11),
            state: ServiceLifecycleState::Starting,
            authoritative_generation: InstanceGeneration(1),
            live: Some(LiveServiceInstance {
                pid: 44,
                tid: 5,
                domain_id: 44,
                generation: InstanceGeneration(1),
                scheduler_slot: 0,
            }),
        };
        let full_event = LifecycleEvent::new(
            ServiceInstanceId::new(
                ServiceId(11),
                InstanceGeneration(1),
                ProcessId(44),
                DomainId(44),
            ),
            LifecycleEventKind::Ready,
        );
        controller.pending = [Some(full_event); SERVICE_PENDING_EVENTS];
        controller.pending_count = SERVICE_PENDING_EVENTS;

        let err = controller.notify_instance_ready(ServiceId(11)).unwrap_err();
        assert!(matches!(err, LifecycleControlError::InvalidMessage(_)));
        let record = controller.find_service(ServiceId(11)).expect("record");
        assert_eq!(record.state, ServiceLifecycleState::Starting);
    }

    #[test]
    fn stale_pid_fault_notification_cannot_clear_live_instance() {
        let mut controller = ServiceLifecycleController::new();
        controller.services[0] = ServiceRecord {
            service: ServiceId(12),
            state: ServiceLifecycleState::Running,
            authoritative_generation: InstanceGeneration(4),
            live: Some(LiveServiceInstance {
                pid: 123,
                tid: 9,
                domain_id: 123,
                generation: InstanceGeneration(4),
                scheduler_slot: 2,
            }),
        };

        let err = controller
            .notify_instance_faulted(ServiceId(12), 777)
            .unwrap_err();
        assert!(matches!(err, LifecycleControlError::StaleInstance(_)));
        let record = controller.find_service(ServiceId(12)).expect("record");
        assert_eq!(record.state, ServiceLifecycleState::Running);
        assert_eq!(record.live.expect("live").pid, 123);
    }

    #[test]
    fn fault_notification_queue_full_still_commits_terminal_fault_event() {
        let mut controller = ServiceLifecycleController::new();
        controller.services[0] = ServiceRecord {
            service: ServiceId(13),
            state: ServiceLifecycleState::Running,
            authoritative_generation: InstanceGeneration(1),
            live: Some(LiveServiceInstance {
                pid: 55,
                tid: 5,
                domain_id: 55,
                generation: InstanceGeneration(1),
                scheduler_slot: 0,
            }),
        };
        let full_event = LifecycleEvent::new(
            ServiceInstanceId::new(
                ServiceId(13),
                InstanceGeneration(1),
                ProcessId(55),
                DomainId(55),
            ),
            LifecycleEventKind::Ready,
        );
        controller.pending = [Some(full_event); SERVICE_PENDING_EVENTS];
        controller.pending_count = SERVICE_PENDING_EVENTS;

        let event = controller
            .notify_instance_faulted(ServiceId(13), 55)
            .expect("faulted event");
        assert_eq!(event.kind, LifecycleEventKind::Faulted);
        assert_eq!(event.instance.pid.0, 55);
        let record = controller.find_service(ServiceId(13)).expect("record");
        assert_eq!(record.state, ServiceLifecycleState::Faulted);
        assert!(record.live.is_none());
        assert!(controller.pending.iter().flatten().any(|queued| queued.kind
            == LifecycleEventKind::Faulted
            && queued.instance.pid.0 == 55));
    }

    #[test]
    fn faulting_live_process_lookup_returns_supervised_fault_event() {
        let mut controller = ServiceLifecycleController::new();
        controller.services[0] = ServiceRecord {
            service: ServiceId(14),
            state: ServiceLifecycleState::Running,
            authoritative_generation: InstanceGeneration(3),
            live: Some(LiveServiceInstance {
                pid: 300,
                tid: 1,
                domain_id: 300,
                generation: InstanceGeneration(3),
                scheduler_slot: 0,
            }),
        };
        let event = controller
            .notify_faulted_live_process(300, 17)
            .expect("notify")
            .expect("event");
        assert_eq!(event.kind, LifecycleEventKind::Faulted);
        assert_eq!(event.status_code, 17);
        assert_eq!(controller.live_pid(ServiceId(14)), None);
    }
}
