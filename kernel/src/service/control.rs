//! Capability-gated lifecycle control dispatch and service registry.

use crate::diagnostics::log::kernel_log_fmt;
use crate::mm::frame_allocator::PageAllocator;
use crate::process::domain::teardown_process_by_id;
use crate::process::process_registry_mut;
use crate::service::capability::{lifecycle_capabilities_mut, BlockDeviceCapabilityError};
use crate::service::capability::{LifecycleControlCapabilityError, LifecycleScope};
use crate::service::grants::{apply_instance_grants, GraphicsRole, InstanceGrantAuthority};
use crate::service::lifecycle_wait::wake_lifecycle_waiters;
use crate::service::spawn::{launch_builtin_service, LaunchContext};
use crate::sync::global_cell::GlobalCell;
#[cfg(clean_slate_desktop)]
use clean_slate_service_fixtures::manifest::graphics_port_row;
use clean_slate_service_fixtures::manifest::{
    find_service, Grant, ServiceSpec, SYSTEM_DESKTOP_MANIFEST, SYSTEM_MANIFEST,
    SYSTEM_TERMINAL_DESKTOP_MANIFEST,
};
use clean_slate_service_fixtures::{
    NETWORK_DEVICE_ID, NETWORK_SERVICE_ID, STORAGE_BLOCK_DEVICE_ID,
};
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

use crate::limits::SERVICE_REGISTRY_CAPACITY;

const SERVICE_PENDING_EVENTS: usize = 16;
const SERVICE_TERMINATE_STATUS: u64 = 0;

// Init declares every system service, so the registry must hold the whole manifest.
const _: () = assert!(SYSTEM_MANIFEST.len() <= SERVICE_REGISTRY_CAPACITY);
const _: () = assert!(SYSTEM_DESKTOP_MANIFEST.len() <= SERVICE_REGISTRY_CAPACITY);
const _: () = assert!(SYSTEM_TERMINAL_DESKTOP_MANIFEST.len() <= SERVICE_REGISTRY_CAPACITY);

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

/// Why a `SERVICE_READY` report was refused. A refusal changes nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ServiceReadyRefusal {
    /// The caller is not the live instance of a declared service.
    NotAServiceInstance,
    /// The caller's instance is no longer starting.
    NotStarting,
}

pub(crate) struct ServiceLifecycleController {
    services: [ServiceRecord; SERVICE_REGISTRY_CAPACITY],
    pending: [Option<LifecycleEvent>; SERVICE_PENDING_EVENTS],
    pending_count: usize,
    /// One `SERVICE_READY` message per service, indexed like `services` and kept out of
    /// `pending` so an accepted report never depends on queue space. A newer instance's
    /// report replaces an older one still unpolled.
    ready_pending: [Option<LifecycleEvent>; SERVICE_REGISTRY_CAPACITY],
    next_scheduler_slot: usize,
    kernel_root_frame: u64,
    /// Rows that decide each started service's bootstrap mode and launch grants.
    manifest: &'static [ServiceSpec],
    /// Handle a restarted scenario instance resumes from; init will own this state (#218 S3).
    scenario_previous_handle: u64,
}

impl ServiceLifecycleController {
    const fn new() -> Self {
        Self {
            services: [ServiceRecord::empty(); SERVICE_REGISTRY_CAPACITY],
            pending: [None; SERVICE_PENDING_EVENTS],
            pending_count: 0,
            ready_pending: [None; SERVICE_REGISTRY_CAPACITY],
            next_scheduler_slot: 0,
            kernel_root_frame: 0,
            manifest: SYSTEM_MANIFEST,
            scenario_previous_handle: 0,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.manifest = SYSTEM_MANIFEST;
        self.scenario_previous_handle = 0;
        unsafe { lifecycle_capabilities_mut() }.clear();
        self.services = [ServiceRecord::empty(); SERVICE_REGISTRY_CAPACITY];
        self.pending = [None; SERVICE_PENDING_EVENTS];
        self.pending_count = 0;
        self.ready_pending = [None; SERVICE_REGISTRY_CAPACITY];
        self.next_scheduler_slot = 0;
    }

    /// First scheduler slot a later service launch may take. Recovery occupies
    /// slots 0 and 1 itself and sets this to 2 after [`Self::clear`].
    #[cfg(feature = "m4-recovery-self-test")]
    pub(crate) fn set_scheduler_slot_start(&mut self, slot: usize) {
        self.next_scheduler_slot = slot;
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
        wake_lifecycle_waiters();
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
                wake_lifecycle_waiters();
                return Ok(());
            }
        }
        if let Some(slot) = self.pending.iter_mut().find(|entry| entry.is_none()) {
            *slot = Some(event);
            self.pending_count = self.pending_count.saturating_add(1);
            wake_lifecycle_waiters();
            return Ok(());
        }
        if let Some(slot) = self.pending.first_mut() {
            *slot = Some(event);
            self.pending_count = SERVICE_PENDING_EVENTS;
            wake_lifecycle_waiters();
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

    /// The next message for `service`: its queued event or its ready message, whichever names
    /// the older instance. For the same instance the ready message goes first, since an
    /// instance reports ready before it can exit or fault.
    pub(crate) fn poll_pending_event(
        &mut self,
        service: ServiceId,
    ) -> Result<Option<LifecycleEvent>, LifecycleControlError> {
        let queued = self
            .pending
            .iter()
            .position(|entry| entry.is_some_and(|event| event.instance.service == service));
        let ready = self
            .service_index(service)
            .filter(|&index| self.ready_pending[index].is_some());
        let take_ready = match (queued, ready) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(queued), Some(ready)) => {
                let queued_generation = self.pending[queued].map(|event| event.instance.generation);
                let ready_generation =
                    self.ready_pending[ready].map(|event| event.instance.generation);
                ready_generation <= queued_generation
            }
        };
        if take_ready {
            return Ok(ready.and_then(|index| self.ready_pending[index].take()));
        }
        let Some(queued) = queued else {
            return Ok(None);
        };
        self.pending_count = self.pending_count.saturating_sub(1);
        Ok(self.pending[queued].take())
    }

    pub(crate) fn poll_pending_event_authorized(
        &mut self,
        supervisor_pid: u64,
        capability_handle: u64,
        service: ServiceId,
    ) -> Result<Option<LifecycleEvent>, LifecycleControlError> {
        self.authorize_lifecycle_control(supervisor_pid, capability_handle, Some(service))?;
        let event = self.poll_pending_event(service)?;
        #[cfg(feature = "m4-recovery-self-test")]
        if let Some(event) = event {
            crate::selftest::m4_recovery::observe_recovery_lifecycle_delivery(
                supervisor_pid,
                event,
            );
        }
        Ok(event)
    }

    /// The service of some pending message within the capability's scope, left queued for
    /// [`Self::poll_pending_event`]. Messages for services outside the scope are not seen.
    pub(crate) fn pending_service_authorized(
        &self,
        supervisor_pid: u64,
        capability_handle: u64,
    ) -> Result<Option<ServiceId>, LifecycleControlError> {
        let scope = self.authorize_lifecycle_control(supervisor_pid, capability_handle, None)?;
        Ok(self
            .pending
            .iter()
            .chain(self.ready_pending.iter())
            .flatten()
            .map(|event| event.instance.service)
            .find(|service| service.0 != 0 && scope.covers(*service)))
    }

    /// `SERVICE_READY` from `pid`. Accepted only from the live instance of a declared service
    /// that is still starting: the service moves to running, its ready message is stored and lifecycle waiters are woken.
    /// A refusal (no live instance, as with init's own probe, or an instance that has left
    /// starting) changes nothing and wakes nobody.
    pub(crate) fn report_ready_from_pid(
        &mut self,
        pid: u64,
    ) -> Result<ServiceInstanceId, ServiceReadyRefusal> {
        let service_index = self
            .services
            .iter()
            .position(|entry| {
                entry.service.0 != 0 && entry.live.is_some_and(|live| live.pid == pid)
            })
            .ok_or(ServiceReadyRefusal::NotAServiceInstance)?;
        let record = self.services[service_index];
        let live = record
            .live
            .ok_or(ServiceReadyRefusal::NotAServiceInstance)?;
        if record.state != ServiceLifecycleState::Starting {
            return Err(ServiceReadyRefusal::NotStarting);
        }
        let instance = ServiceInstanceId::new(
            record.service,
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
        .map_err(|_| ServiceReadyRefusal::NotStarting)?;
        self.services[service_index].state = next_state;
        self.ready_pending[service_index] =
            Some(LifecycleEvent::new(instance, LifecycleEventKind::Ready));
        wake_lifecycle_waiters();
        Ok(instance)
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

    #[cfg(any(
        feature = "m5-storage-self-test",
        feature = "m5-persistence-self-test",
        feature = "m5-crash-early-self-test",
        feature = "m5-crash-late-self-test",
        feature = "m5-crash-recovery-self-test",
        feature = "m6-object-self-test",
        feature = "m6-process-control-self-test",
        feature = "m6-delegation-self-test",
        feature = "m7-net-caps-self-test",
        feature = "m10-port-self-test",
        feature = "m10-shared-buffer-self-test",
        feature = "m6-revocation-self-test",
        feature = "m6-audit-self-test",
        feature = "m6-capabilities-self-test",
        feature = "m6-fixture-smoke-self-test",
        feature = "m10-native-memory-self-test",
        feature = "m10-clock-self-test",
        feature = "m7-net-service-self-test",
        feature = "m8-linux-hello",
        clean_slate_system_init
    ))]
    pub(crate) fn notify_exited_live_process(
        &mut self,
        pid: u64,
    ) -> Result<Option<LifecycleEvent>, LifecycleControlError> {
        let Some(service_index) = self
            .services
            .iter()
            .position(|entry| entry.live.is_some_and(|live| live.pid == pid))
        else {
            return Ok(None);
        };
        let record = self.services[service_index];
        let live = record.live.ok_or(LifecycleControlError::ServiceNotLive)?;
        let instance = ServiceInstanceId::new(
            record.service,
            live.generation,
            ProcessId(live.pid),
            DomainId(live.domain_id),
        );
        let (next_state, _) = apply_transition(
            record.state,
            record.authoritative_generation,
            TransitionInput::Event(LifecycleEventKind::Exited),
            Some(instance),
        )
        .map_err(LifecycleControlError::InvalidTransition)?;
        let event = LifecycleEvent::new(instance, LifecycleEventKind::Exited);
        self.push_terminal_pending(event)?;
        self.services[service_index].state = next_state;
        self.services[service_index].live = None;
        Ok(Some(event))
    }

    pub(crate) fn configure_launch_context(&mut self, kernel_root_frame: u64) {
        self.kernel_root_frame = kernel_root_frame;
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

    /// Grants `holder_pid` lifecycle control of `services` and of no other service.
    pub(crate) fn grant_lifecycle_control_capability<'a>(
        &mut self,
        holder_pid: u64,
        services: impl IntoIterator<Item = &'a ServiceId>,
    ) -> Result<u64, &'static str> {
        let scope = LifecycleScope::of(services)?;
        unsafe { lifecycle_capabilities_mut() }
            .lifecycle_control
            .grant_lifecycle_control_capability(holder_pid, scope)
    }

    /// A capability of another kind for the lifecycle-wait refusal check.
    #[cfg(feature = "m4-service-lifecycle-self-test")]
    pub(crate) fn grant_block_device_capability_for_self_test(
        &mut self,
        holder_pid: u64,
    ) -> Result<u64, &'static str> {
        unsafe { lifecycle_capabilities_mut() }
            .block_device
            .grant_block_device_capability(holder_pid, STORAGE_BLOCK_DEVICE_ID)
    }

    pub(crate) fn acquire_block_device_capability(
        &self,
        holder_pid: u64,
        device_id: u64,
    ) -> Result<u64, LifecycleControlError> {
        unsafe { lifecycle_capabilities_mut() }
            .block_device
            .block_device_handle_for(holder_pid, device_id)
            .map_err(|error| match error {
                BlockDeviceCapabilityError::Unauthorized => LifecycleControlError::Unauthorized,
                BlockDeviceCapabilityError::InvalidHandle => LifecycleControlError::InvalidHandle,
                BlockDeviceCapabilityError::StaleHandle => LifecycleControlError::StaleHandle,
                BlockDeviceCapabilityError::WrongDevice => LifecycleControlError::InvalidHandle,
            })
    }

    pub(crate) fn authorize_block_device_request(
        &self,
        holder_pid: u64,
        capability_handle: u64,
        device_id: u64,
    ) -> Result<(), LifecycleControlError> {
        unsafe { lifecycle_capabilities_mut() }
            .block_device
            .authorize_block_device_access(holder_pid, capability_handle, device_id)
            .map_err(|error| match error {
                BlockDeviceCapabilityError::Unauthorized => LifecycleControlError::Unauthorized,
                BlockDeviceCapabilityError::StaleHandle => LifecycleControlError::StaleHandle,
                BlockDeviceCapabilityError::InvalidHandle
                | BlockDeviceCapabilityError::WrongDevice => LifecycleControlError::InvalidHandle,
            })
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

    #[cfg(feature = "m8-linux-hello")]
    pub(crate) fn live_service_id_for_pid(&self, pid: u64) -> Option<ServiceId> {
        self.services.iter().find_map(|entry| {
            if entry.service.0 != 0 && entry.live.is_some_and(|live| live.pid == pid) {
                Some(entry.service)
            } else {
                None
            }
        })
    }

    #[cfg(feature = "m7-net-caps-self-test")]
    pub(crate) fn test_advance_authoritative_generation(
        &mut self,
        service: ServiceId,
    ) -> Result<InstanceGeneration, &'static str> {
        let index = self
            .service_index(service)
            .ok_or("unknown service for generation bump")?;
        let next = InstanceGeneration(self.services[index].authoritative_generation.0 + 1);
        self.services[index].authoritative_generation = next;
        Ok(next)
    }

    #[allow(dead_code)]
    pub(crate) fn live_service_instance_id(&self, service: ServiceId) -> Option<ServiceInstanceId> {
        let record = self.find_service(service)?;
        let live = record.live?;
        Some(ServiceInstanceId::new(
            service,
            record.authoritative_generation,
            ProcessId(live.pid),
            DomainId(live.domain_id),
        ))
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

    /// Every service thread runs on its own scheduler slot's task stack: dispatch loads
    /// `Thread::kernel_stack_top` into the TSS and SYSCALL stack on each switch, and
    /// `Scheduler::configure_thread` rejects a user thread bound to any other stack.
    fn resolve_kernel_stack_top(scheduler_slot: usize) -> Result<u64, LifecycleControlError> {
        use crate::arch::x86_64::context_switch::task_stack_top;
        use crate::sched::task_stacks_mut;
        let stacks = unsafe { task_stacks_mut() };
        if scheduler_slot >= stacks.len() {
            return Err(LifecycleControlError::SpawnFailed(
                "service scheduler slot exceeds task stack table",
            ));
        }
        Ok(task_stack_top(&stacks[scheduler_slot]))
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
        if self.kernel_root_frame == 0 {
            return Err(LifecycleControlError::SpawnFailed(
                "service launch context was not configured",
            ));
        }
        let scheduler_slot = self
            .allocate_scheduler_slot()
            .map_err(LifecycleControlError::SpawnFailed)?;
        let kernel_stack_top = Self::resolve_kernel_stack_top(scheduler_slot)?;
        let context = self.launch_context(service_id, generation);
        let grants = context.grants();
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
            launch_builtin_service(
                allocator,
                kernel_stack_top,
                scheduler_slot,
                service_id,
                context,
            )
            .map_err(|message| {
                #[cfg(feature = "m8-linux-hello")]
                if service_id == crate::service::linux_launch::LINUX_HELLO_SERVICE_ID {
                    // `launch_linux_hello` already logged `[LNX ] load failed: â€¦`.
                    return LifecycleControlError::SpawnFailed(message);
                }
                kernel_log_fmt(format_args!(
                    "[SVC ] builtin service spawn failed service={} slot={} err={message}\n",
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
        let kernel_root_frame = self.kernel_root_frame;
        if let Some(allowance) = context.spec.and_then(|spec| spec.slot_allowance) {
            let holder = clean_slate_capability::HolderId(spawned.pid);
            if crate::capability::set_slot_allowance(holder, allowance).is_err() {
                kernel_log_fmt(format_args!(
                    "[FAIL] service={} pid={} slot allowance={allowance} refused\n",
                    service_id.0, spawned.pid
                ));
                teardown_process_by_id(
                    allocator,
                    kernel_root_frame,
                    spawned.pid,
                    SERVICE_TERMINATE_STATUS,
                    false,
                )
                .map_err(LifecycleControlError::SpawnFailed)?;
                return Err(LifecycleControlError::SpawnFailed(
                    "service slot allowance refused",
                ));
            }
        }
        let memory_pages = context.spec.map_or(0, |spec| spec.memory_pages);
        if memory_pages != 0 {
            // The record is keyed by the process's own instance generation, which syscall 23
            // and teardown look up; the service generation above is a different counter.
            let budget = crate::process::live_instance_generation(spawned.pid)
                .ok_or("native memory budget: process has no instance generation")
                .and_then(|process_generation| {
                    crate::process::native_mem::set_budget(
                        spawned.pid,
                        process_generation,
                        memory_pages,
                    )
                });
            if let Err(message) = budget {
                kernel_log_fmt(format_args!(
                    "[FAIL] service={} pid={} memory budget={memory_pages} refused\n",
                    service_id.0, spawned.pid
                ));
                teardown_process_by_id(
                    allocator,
                    kernel_root_frame,
                    spawned.pid,
                    SERVICE_TERMINATE_STATUS,
                    false,
                )
                .map_err(LifecycleControlError::SpawnFailed)?;
                return Err(LifecycleControlError::SpawnFailed(message));
            }
        }
        self.apply_instance_grants_with_rollback(
            spawned.pid,
            service_id,
            grants,
            generation,
            |pid| {
                teardown_process_by_id(
                    allocator,
                    kernel_root_frame,
                    pid,
                    SERVICE_TERMINATE_STATUS,
                    false,
                )
                .map(|_| ())
            },
        )?;
        #[cfg(clean_slate_system_init)]
        if let Err(message) =
            super::system_init::audit_service_authority(service_id, spawned.pid, context.spec)
        {
            teardown_process_by_id(
                allocator,
                kernel_root_frame,
                spawned.pid,
                SERVICE_TERMINATE_STATUS,
                false,
            )
            .map_err(LifecycleControlError::SpawnFailed)?;
            return Err(LifecycleControlError::SpawnFailed(message));
        }
        self.services[service_index].live = Some(LiveServiceInstance {
            pid: spawned.pid,
            tid: spawned.tid,
            domain_id: spawned.domain_id,
            generation,
            scheduler_slot,
        });
        if service_id == NETWORK_SERVICE_ID {
            crate::capability::network::on_network_instance_registered(u64::from(generation.0));
        }
        self.log_launch(instance);
        #[cfg(feature = "system-test-hooks")]
        super::system_test_hooks::on_service_launched(service_id, spawned.pid);
        Ok(LifecycleControlResult {
            event: Some(LifecycleEvent::new(
                instance,
                LifecycleEventKind::InstanceSpawned,
            )),
        })
    }

    /// Applies the post-spawn grants of `service_id`'s manifest row. A failed grant tears the
    /// spawned instance down so the controller never records a live instance missing authority.
    fn apply_instance_grants_with_rollback<F>(
        &mut self,
        pid: u64,
        service_id: ServiceId,
        grants: &[Grant],
        instance_generation: InstanceGeneration,
        mut rollback_spawn: F,
    ) -> Result<(), LifecycleControlError>
    where
        F: FnMut(u64) -> Result<(), &'static str>,
    {
        #[cfg(clean_slate_desktop)]
        let live_graphics_port = self.live_graphics_port();
        #[cfg(clean_slate_desktop)]
        let live_console_port = self.live_console_port();
        let mut authority = KernelInstanceGrants {
            service_id,
            #[cfg(clean_slate_desktop)]
            live_graphics_port,
            #[cfg(clean_slate_desktop)]
            live_console_port,
        };
        if let Err(failure) =
            apply_instance_grants(grants, pid, instance_generation, &mut authority)
        {
            rollback_spawn(pid).map_err(|_| {
                LifecycleControlError::SpawnFailed(rollback_failure_message(failure.grant))
            })?;
            return Err(LifecycleControlError::SpawnFailed(failure.message));
        }
        Ok(())
    }

    /// The graphics port of the live instance of the active manifest's `Grant::GraphicsPort`
    /// row, when that instance has registered one: what the graphics role grants name.
    #[cfg(clean_slate_desktop)]
    fn live_graphics_port(&self) -> Option<LiveGraphicsPort> {
        let row = graphics_port_row(self.manifest)?;
        let pid = self.live_pid(row.id)?;
        let generation = crate::process::live_instance_generation(pid)?;
        let port = crate::service::port::counts_for(clean_slate_capability::HolderId(pid));
        (port.ports_served > 0).then_some(LiveGraphicsPort {
            service: row.id,
            generation,
        })
    }

    /// The console port of the live instance of the active manifest's `Grant::ConsoleService`
    /// row, when that instance has registered one: what the console client grants name.
    #[cfg(clean_slate_desktop)]
    fn live_console_port(&self) -> Option<LiveGraphicsPort> {
        let row = clean_slate_service_fixtures::manifest::console_service_row(self.manifest)?;
        let pid = self.live_pid(row.id)?;
        let generation = crate::process::live_instance_generation(pid)?;
        let port = crate::service::port::counts_for(clean_slate_capability::HolderId(pid));
        (port.ports_served > 0).then_some(LiveGraphicsPort {
            service: row.id,
            generation,
        })
    }

    /// Replaces the system manifest until the next [`Self::clear`]. Self-tests whose services need
    /// rows different from [`SYSTEM_MANIFEST`] install their scenario here. The build that
    /// launches init installs the manifest its boot option selects.
    #[cfg_attr(
        not(any(
            test,
            clean_slate_system_init,
            feature = "m5-storage-self-test",
            feature = "m5-persistence-self-test",
            feature = "m5-crash-early-self-test",
            feature = "m5-crash-late-self-test",
            feature = "m5-crash-recovery-self-test"
        )),
        allow(dead_code)
    )]
    pub(crate) fn use_scenario_manifest(&mut self, manifest: &'static [ServiceSpec]) {
        self.manifest = manifest;
    }

    /// Sets the handle the next started storage instance resumes from, until the next
    /// [`Self::clear`]. Only the M5 integration restart phase needs one.
    #[cfg_attr(
        not(any(
            test,
            feature = "m5-storage-self-test",
            feature = "m5-persistence-self-test",
            feature = "m5-crash-early-self-test",
            feature = "m5-crash-late-self-test",
            feature = "m5-crash-recovery-self-test"
        )),
        allow(dead_code)
    )]
    pub(crate) fn set_scenario_previous_handle(&mut self, handle: u64) {
        self.scenario_previous_handle = handle;
    }

    /// The active manifest row and scenario state an instance of `service_id` launches with.
    fn launch_context(
        &self,
        service_id: ServiceId,
        generation: InstanceGeneration,
    ) -> LaunchContext {
        LaunchContext {
            spec: find_service(self.manifest, service_id),
            generation,
            previous_handle: self.scenario_previous_handle,
        }
    }

    #[cfg(test)]
    pub(crate) fn launch_grants(&self, service_id: ServiceId) -> &'static [Grant] {
        self.launch_context(service_id, InstanceGeneration(0))
            .grants()
    }

    #[cfg(feature = "m7-net-service-self-test")]
    pub(crate) fn grant_network_client_capability(
        &mut self,
        pid: u64,
    ) -> Result<u64, &'static str> {
        use crate::capability::network::{
            grant_network_authority, revoke_network_capabilities_for_holder, NetworkGrantPolicy,
        };
        use clean_slate_capability::{HolderId, Rights};
        revoke_network_capabilities_for_holder(HolderId(pid));
        let rights = Rights::NET_RESOLVE
            .union(Rights::NET_CONNECT)
            .union(Rights::NET_SEND)
            .union(Rights::NET_RECEIVE);
        let handle =
            grant_network_authority(HolderId(pid), rights, NetworkGrantPolicy::Application, None)
                .map_err(|_| "network client capability grant failed")?;
        Ok(handle.encode())
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
        if service_id == NETWORK_SERVICE_ID {
            let _ = crate::service::net_bridge::shutdown_net_service_instance();
        }
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
        #[cfg(feature = "m8-linux-hello")]
        if service_id == crate::service::linux_launch::LINUX_HELLO_SERVICE_ID {
            crate::service::linux_launch::clear_linux_hello_live_for_pid(live.pid);
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

    /// `residue` is what `remaining_owned_resource_count` still attributes to the pid after
    /// teardown, which must be 0.
    pub(crate) fn log_reaped(&self, service: ServiceId, pid: u64) {
        kernel_log_fmt(format_args!(
            "[SVC ] reaped service={} pid={} residue={}\n",
            service.0,
            pid,
            crate::process::domain::remaining_owned_resource_count(pid)
        ));
    }

    fn authorize_lifecycle_control(
        &self,
        supervisor_pid: u64,
        capability_handle: u64,
        service: Option<ServiceId>,
    ) -> Result<LifecycleScope, LifecycleControlError> {
        unsafe { lifecycle_capabilities_mut() }
            .lifecycle_control
            .authorize_lifecycle_control(supervisor_pid, capability_handle, service)
            .map_err(|error| match error {
                LifecycleControlCapabilityError::Unauthorized
                | LifecycleControlCapabilityError::OutOfScope => {
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
        let decoded = LifecycleMessage::decode(message);
        let service = match &decoded {
            Ok((LifecycleMessage::ControlRequest(request), _)) => Some(request.service),
            _ => None,
        };
        self.authorize_lifecycle_control(supervisor_pid, capability_handle, service)?;
        let (decoded, _) = decoded.map_err(LifecycleControlError::InvalidMessage)?;
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
                self.services[service_index].authoritative_generation = next_generation;
                self.services[service_index].state = next_state;
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
                    #[cfg(feature = "m8-linux-hello")]
                    if service_id == crate::service::linux_launch::LINUX_HELLO_SERVICE_ID {
                        crate::service::linux_launch::clear_linux_hello_live_for_pid(live.pid);
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

/// The graphics port `graphics(service, generation)` of a live compositor instance.
#[cfg(clean_slate_desktop)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LiveGraphicsPort {
    service: ServiceId,
    generation: InstanceGeneration,
}

struct KernelInstanceGrants {
    service_id: ServiceId,
    #[cfg(clean_slate_desktop)]
    live_graphics_port: Option<LiveGraphicsPort>,
    /// The console port of the live `Grant::ConsoleService` instance, as for graphics.
    #[cfg(clean_slate_desktop)]
    live_console_port: Option<LiveGraphicsPort>,
}

impl KernelInstanceGrants {
    fn grant_failed(&self, pid: u64, what: &str, message: &'static str) -> &'static str {
        kernel_log_fmt(format_args!(
            "[SVC ] {what} grant failed pid={pid} service={} err={message}\n",
            self.service_id.0
        ));
        message
    }
}

impl InstanceGrantAuthority for KernelInstanceGrants {
    fn grant_block_device(&mut self, pid: u64) -> Result<(), &'static str> {
        if let Err(message) = unsafe { lifecycle_capabilities_mut() }
            .block_device
            .grant_block_device_capability(pid, STORAGE_BLOCK_DEVICE_ID)
        {
            kernel_log_fmt(format_args!(
                "[BLK ] block capability grant failed pid={} service={} err={message}\n",
                pid, self.service_id.0
            ));
            return Err(message);
        }
        kernel_log_fmt(format_args!(
            "[BLK ] authority granted pid={} device={}\n",
            pid, STORAGE_BLOCK_DEVICE_ID
        ));
        Ok(())
    }

    fn grant_network_service(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
    ) -> Result<(), &'static str> {
        use crate::capability::network::{grant_network_authority, NetworkGrantPolicy};
        use clean_slate_capability::{HolderId, ResourceClass, Rights};
        let rights = Rights::valid_for(ResourceClass::Network);
        if grant_network_authority(
            HolderId(pid),
            rights,
            NetworkGrantPolicy::NetworkService,
            Some(u64::from(generation.0)),
        )
        .is_err()
        {
            kernel_log_fmt(format_args!(
                "[NET ] network capability grant failed pid={} service={}\n",
                pid, self.service_id.0
            ));
            return Err("network service capability grant failed");
        }
        crate::service::net_bridge::net_bridge_mut().register_service_instance(
            pid,
            pid,
            u64::from(generation.0),
        );
        kernel_log_fmt(format_args!(
            "[NET ] authority granted pid={} device={}\n",
            pid, NETWORK_DEVICE_ID
        ));
        Ok(())
    }

    /// `graphics(service id, process instance generation)`: the generation `register_port`
    /// checks is the process registry's.
    #[cfg(clean_slate_desktop)]
    fn grant_graphics_port(&mut self, pid: u64) -> Result<(), &'static str> {
        use super::desktop_image::COMPOSITOR_PORT_PARAMS;
        use crate::capability::graphics::{grant_graphics, COMPOSITOR_GRAPHICS_RIGHTS};
        use clean_slate_capability::{HolderId, ResourceRef};

        let Some(generation) = crate::process::live_instance_generation(pid) else {
            return Err(self.grant_failed(pid, "graphics port", "instance has no generation"));
        };
        let resource = ResourceRef::graphics(u64::from(self.service_id.0), u64::from(generation.0));
        if crate::service::port::register_port(
            resource,
            HolderId(pid),
            generation,
            COMPOSITOR_PORT_PARAMS,
        )
        .is_err()
        {
            return Err(self.grant_failed(pid, "graphics port", "port registration refused"));
        }
        // From here a failure leaves the port registered; the caller's rollback teardown
        // unregisters it with the process.
        grant_graphics(HolderId(pid), resource, COMPOSITOR_GRAPHICS_RIGHTS)
            .map_err(|_| self.grant_failed(pid, "graphics port", "serve capability refused"))?;
        kernel_log_fmt(format_args!(
            "[GFX ] authority granted pid={pid} port={}:{} rights=serve registered=1\n",
            self.service_id.0, generation.0
        ));
        Ok(())
    }

    #[cfg(clean_slate_desktop)]
    fn grant_display_presenter(&mut self, pid: u64) -> Result<(), &'static str> {
        crate::capability::graphics::grant_display_presenter(clean_slate_capability::HolderId(pid))
            .map_err(|_| self.grant_failed(pid, "display presenter", "capability refused"))?;
        kernel_log_fmt(format_args!(
            "[DISP] authority granted pid={pid} output=0 rights=present,inspect\n"
        ));
        Ok(())
    }

    #[cfg(clean_slate_desktop)]
    fn grant_input_seat(&mut self, pid: u64) -> Result<(), &'static str> {
        crate::capability::graphics::grant_input_seat(clean_slate_capability::HolderId(pid))
            .map_err(|_| self.grant_failed(pid, "input seat", "capability refused"))?;
        kernel_log_fmt(format_args!(
            "[SEAT] authority granted pid={pid} seat=0 rights=consume,inspect\n"
        ));
        Ok(())
    }

    #[cfg(clean_slate_desktop)]
    fn grant_graphics_role(&mut self, pid: u64, role: GraphicsRole) -> Result<(), &'static str> {
        use crate::capability::graphics::{
            grant_graphics, APP_GRAPHICS_RIGHTS, SHELL_GRAPHICS_RIGHTS,
        };
        use clean_slate_capability::{HolderId, ResourceRef};

        let Some(port) = self.live_graphics_port else {
            return Err(self.grant_failed(pid, "graphics role", "no live graphics port"));
        };
        let (rights, names) = match role {
            GraphicsRole::Shell => (SHELL_GRAPHICS_RIGHTS, "connect,shell"),
            GraphicsRole::App => (APP_GRAPHICS_RIGHTS, "connect"),
        };
        let resource =
            ResourceRef::graphics(u64::from(port.service.0), u64::from(port.generation.0));
        grant_graphics(HolderId(pid), resource, rights)
            .map_err(|_| self.grant_failed(pid, "graphics role", "capability refused"))?;
        kernel_log_fmt(format_args!(
            "[GFX ] authority granted pid={pid} port={}:{} rights={names}\n",
            port.service.0, port.generation.0
        ));
        Ok(())
    }

    /// `console_port(service id, process instance generation)`, as the graphics port.
    #[cfg(clean_slate_desktop)]
    fn grant_console_service(&mut self, pid: u64) -> Result<(), &'static str> {
        use crate::capability::console::{
            grant_console_port, grant_serial_console_device, CONSOLE_PORT_PARAMS,
            CONSOLE_SERVICE_PORT_RIGHTS,
        };
        use clean_slate_capability::{HolderId, ResourceRef};

        let Some(generation) = crate::process::live_instance_generation(pid) else {
            return Err(self.grant_failed(pid, "console port", "instance has no generation"));
        };
        let resource =
            ResourceRef::console_port(u64::from(self.service_id.0), u64::from(generation.0));
        if crate::service::port::register_port(
            resource,
            HolderId(pid),
            generation,
            CONSOLE_PORT_PARAMS,
        )
        .is_err()
        {
            return Err(self.grant_failed(pid, "console port", "port registration refused"));
        }
        // From here a failure leaves the port registered; the caller's rollback teardown
        // unregisters it with the process.
        grant_console_port(HolderId(pid), resource, CONSOLE_SERVICE_PORT_RIGHTS)
            .map_err(|_| self.grant_failed(pid, "console port", "serve capability refused"))?;
        grant_serial_console_device(HolderId(pid))
            .map_err(|_| self.grant_failed(pid, "console device", "capability refused"))?;
        kernel_log_fmt(format_args!(
            "[CONS] authority granted pid={pid} port={}:{} rights=serve registered=1 device=read|write\n",
            self.service_id.0, generation.0
        ));
        // A restart: the Linux processes whose console the kernel connects move to this port.
        crate::capability::console::reissue_kernel_console_clients(resource);
        Ok(())
    }

    #[cfg(clean_slate_desktop)]
    fn grant_console_client(
        &mut self,
        pid: u64,
        role: super::grants::ConsoleClientRole,
    ) -> Result<(), &'static str> {
        use super::grants::ConsoleClientRole;
        use crate::capability::console::{
            grant_console_port, CONSOLE_CLIENT_RIGHTS, CONSOLE_FRONT_END_RIGHTS,
            CONSOLE_SESSION_CLIENT_RIGHTS,
        };
        use clean_slate_capability::{HolderId, ResourceRef};

        let (rights, label) = match role {
            ConsoleClientRole::Plain => (CONSOLE_CLIENT_RIGHTS, "connect"),
            ConsoleClientRole::Session => (CONSOLE_SESSION_CLIENT_RIGHTS, "connect|session"),
            ConsoleClientRole::FrontEnd => (CONSOLE_FRONT_END_RIGHTS, "connect|attach"),
        };

        let Some(port) = self.live_console_port else {
            return Err(self.grant_failed(pid, "console client", "no live console port"));
        };
        let resource =
            ResourceRef::console_port(u64::from(port.service.0), u64::from(port.generation.0));
        grant_console_port(HolderId(pid), resource, rights)
            .map_err(|_| self.grant_failed(pid, "console client", "capability refused"))?;
        kernel_log_fmt(format_args!(
            "[CONS] authority granted pid={pid} port={}:{} rights={label}\n",
            port.service.0, port.generation.0
        ));
        Ok(())
    }

    /// Init serves the launcher port from boot on and never restarts, so there is no live
    /// instance to look up.
    #[cfg(clean_slate_desktop)]
    fn grant_launcher_client(&mut self, pid: u64) -> Result<(), &'static str> {
        use crate::capability::launcher::{grant_launcher_port, LAUNCHER_CLIENT_RIGHTS};
        use clean_slate_capability::HolderId;

        grant_launcher_port(HolderId(pid), LAUNCHER_CLIENT_RIGHTS)
            .map_err(|_| self.grant_failed(pid, "launcher client", "capability refused"))?;
        kernel_log_fmt(format_args!(
            "[KERN] launcher authority granted pid={pid} rights=connect\n"
        ));
        Ok(())
    }

    #[cfg(not(clean_slate_desktop))]
    fn grant_launcher_client(&mut self, pid: u64) -> Result<(), &'static str> {
        Err(self.grant_failed(pid, "launcher client", DESKTOP_NOT_COMPILED))
    }

    #[cfg(not(clean_slate_desktop))]
    fn grant_console_service(&mut self, pid: u64) -> Result<(), &'static str> {
        Err(self.grant_failed(pid, "console port", DESKTOP_NOT_COMPILED))
    }

    #[cfg(not(clean_slate_desktop))]
    fn grant_console_client(
        &mut self,
        pid: u64,
        _role: super::grants::ConsoleClientRole,
    ) -> Result<(), &'static str> {
        Err(self.grant_failed(pid, "console client", DESKTOP_NOT_COMPILED))
    }

    #[cfg(not(clean_slate_desktop))]
    fn grant_graphics_port(&mut self, pid: u64) -> Result<(), &'static str> {
        Err(self.grant_failed(pid, "graphics port", DESKTOP_NOT_COMPILED))
    }

    #[cfg(not(clean_slate_desktop))]
    fn grant_display_presenter(&mut self, pid: u64) -> Result<(), &'static str> {
        Err(self.grant_failed(pid, "display presenter", DESKTOP_NOT_COMPILED))
    }

    #[cfg(not(clean_slate_desktop))]
    fn grant_input_seat(&mut self, pid: u64) -> Result<(), &'static str> {
        Err(self.grant_failed(pid, "input seat", DESKTOP_NOT_COMPILED))
    }

    #[cfg(not(clean_slate_desktop))]
    fn grant_graphics_role(&mut self, pid: u64, _role: GraphicsRole) -> Result<(), &'static str> {
        Err(self.grant_failed(pid, "graphics role", DESKTOP_NOT_COMPILED))
    }
}

#[cfg(not(clean_slate_desktop))]
const DESKTOP_NOT_COMPILED: &str = "desktop grants are not compiled into this kernel";

const fn rollback_failure_message(grant: Grant) -> &'static str {
    match grant {
        Grant::BlockDevice => "storage service block-capability rollback teardown failed",
        Grant::NetworkService => "network service capability rollback teardown failed",
        Grant::ObjectServiceRole => "object service role rollback teardown failed",
        Grant::AuditReader => "audit reader rollback teardown failed",
        Grant::AuditStore => "audit store rollback teardown failed",
        Grant::Console | Grant::ConsoleInput | Grant::TmpObjects | Grant::NetworkClient => {
            "linux process grant rollback teardown failed"
        }
        Grant::GraphicsPort
        | Grant::DisplayPresenter
        | Grant::InputSeat
        | Grant::GraphicsShellRole
        | Grant::GraphicsAppRole => "desktop grant rollback teardown failed",
        Grant::ConsoleService
        | Grant::ConsoleClient
        | Grant::ConsoleSession
        | Grant::ConsoleFrontEnd => "console grant rollback teardown failed",
        Grant::LauncherClient => "launcher grant rollback teardown failed",
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
    use clean_slate_service_fixtures::{STORAGE_SERVICE_ID, STORAGE_UNAUTHORIZED_SERVICE_ID};

    fn test_allocator() -> PageAllocator {
        use crate::boot::uefi::normalize_memory_map_boxed;
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
        let map = normalize_memory_map_boxed(descriptors.iter(), &[]).expect("normalize map");
        PageAllocator::new(&map).expect("allocator")
    }

    #[test]
    fn unauthorized_supervisor_cannot_control_services() {
        let mut controller = ServiceLifecycleController::new();
        controller
            .declare_service(ServiceId(7))
            .expect("declare service");
        let capability = controller
            .grant_lifecycle_control_capability(100, &[ServiceId(7)])
            .expect("grant capability");
        let mut allocator = test_allocator();
        controller.configure_launch_context(0x1000);
        let request = ControlRequest::new(ServiceId(7), ControlRequestKind::Start);
        let message = LifecycleMessage::ControlRequest(request).encode();
        let err = controller
            .handle_control_message(&mut allocator, 101, capability, &message)
            .unwrap_err();
        assert_eq!(err, LifecycleControlError::Unauthorized);
    }

    /// #220: a lifecycle-control capability for service A starts, stops, polls and peeks at A
    /// only. Requests for B, declared and live-able, are refused and change nothing.
    #[test]
    fn lifecycle_control_for_one_service_is_refused_for_another() {
        const SERVICE_A: ServiceId = ServiceId(7);
        const SERVICE_B: ServiceId = ServiceId(8);
        let mut controller = ServiceLifecycleController::new();
        controller.declare_service(SERVICE_A).expect("declare A");
        controller.declare_service(SERVICE_B).expect("declare B");
        let capability = controller
            .grant_lifecycle_control_capability(100, &[SERVICE_A])
            .expect("grant capability");
        let mut allocator = test_allocator();
        controller.configure_launch_context(0x1000);
        let services_before = controller.services;
        for kind in [
            ControlRequestKind::Start,
            ControlRequestKind::Stop,
            ControlRequestKind::Terminate,
            ControlRequestKind::Restart,
        ] {
            let message =
                LifecycleMessage::ControlRequest(ControlRequest::new(SERVICE_B, kind)).encode();
            assert_eq!(
                controller
                    .handle_control_message(&mut allocator, 100, capability, &message)
                    .unwrap_err(),
                LifecycleControlError::Unauthorized,
                "{kind:?}"
            );
        }
        assert_eq!(controller.services, services_before);

        controller
            .replay_pending_lifecycle_event(event_for(SERVICE_B, 66, LifecycleEventKind::Exited))
            .unwrap();
        assert_eq!(
            controller.pending_service_authorized(100, capability),
            Ok(None),
            "the peek does not see an out-of-scope service's message"
        );
        assert_eq!(
            controller.poll_pending_event_authorized(100, capability, SERVICE_B),
            Err(LifecycleControlError::Unauthorized)
        );
        controller
            .replay_pending_lifecycle_event(event_for(SERVICE_A, 65, LifecycleEventKind::Exited))
            .unwrap();
        assert_eq!(
            controller.pending_service_authorized(100, capability),
            Ok(Some(SERVICE_A))
        );
        assert_eq!(
            controller
                .poll_pending_event_authorized(100, capability, SERVICE_A)
                .expect("poll A")
                .map(|event| event.instance.service),
            Some(SERVICE_A)
        );
    }

    /// Init holds the lifecycle-control capability for its manifest rows. A control request
    /// names a service and an action only, so the grants of a started instance are the
    /// manifest row's; and a request for an id outside the manifest changes nothing.
    #[test]
    fn init_cannot_start_an_undeclared_service_or_choose_its_grants() {
        use clean_slate_service_fixtures::manifest::SYSTEM_MANIFEST;
        const INIT_PID: u64 = 1;

        let mut controller = ServiceLifecycleController::new();
        for spec in SYSTEM_MANIFEST {
            controller.declare_service(spec.id).expect("declare row");
        }
        let capability = controller
            .grant_lifecycle_control_capability(
                INIT_PID,
                SYSTEM_MANIFEST.iter().map(|spec| &spec.id),
            )
            .expect("grant capability");
        let mut allocator = test_allocator();
        controller.configure_launch_context(0x1000);
        let services_before = controller.services;
        for undeclared in [ServiceId(0x5300), ServiceId(0), ServiceId(u32::MAX)] {
            for kind in [
                ControlRequestKind::Start,
                ControlRequestKind::Stop,
                ControlRequestKind::Terminate,
                ControlRequestKind::Restart,
            ] {
                let message =
                    LifecycleMessage::ControlRequest(ControlRequest::new(undeclared, kind))
                        .encode();
                assert_eq!(
                    controller
                        .handle_control_message(&mut allocator, INIT_PID, capability, &message)
                        .unwrap_err(),
                    LifecycleControlError::Unauthorized,
                    "{undeclared:?} {kind:?}"
                );
            }
        }
        assert_eq!(controller.services, services_before);
        assert_eq!(controller.pending_count, 0);
        assert!(controller.ready_pending.iter().all(Option::is_none));
        for spec in SYSTEM_MANIFEST {
            assert_eq!(
                controller.launch_grants(spec.id),
                spec.grants,
                "{:?}",
                spec.id
            );
        }
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
        use crate::sched::ThreadKind;
        unsafe {
            *crate::sched::scheduler_mut() = crate::sched::Scheduler::new();
            crate::sched::scheduler_mut()
                .configure_thread(
                    0,
                    1,
                    1,
                    ThreadKind::User,
                    crate::sched::Scheduler::user_kernel_stack_top(0),
                    0x1000,
                    0x1000,
                )
                .expect("occupy slot zero");
            // Occupy every slot from 2 up so the search from
            // next_scheduler_slot=2 must wrap to empty slot 1.
            let capacity = crate::sched::scheduler_mut().thread_capacity();
            for slot in 2..capacity {
                let id = slot as u64 + 1;
                crate::sched::scheduler_mut()
                    .configure_thread(
                        slot,
                        id,
                        id,
                        ThreadKind::User,
                        crate::sched::Scheduler::user_kernel_stack_top(slot),
                        id * 0x1000,
                        id * 0x1000,
                    )
                    .expect("occupy slots from two");
            }
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

    #[cfg(not(feature = "m4-recovery-self-test"))]
    #[test]
    fn storage_grant_capacity_failure_rolls_back_spawned_instance() {
        let mut controller = ServiceLifecycleController::new();
        let mut pid = 100_u64;
        loop {
            if unsafe { lifecycle_capabilities_mut() }
                .block_device
                .grant_block_device_capability(pid, STORAGE_BLOCK_DEVICE_ID)
                .is_err()
            {
                break;
            }
            pid += 1;
        }

        let mut rollback_pid = 0_u64;
        let grants = controller.launch_grants(STORAGE_SERVICE_ID);
        let err = controller
            .apply_instance_grants_with_rollback(
                77,
                STORAGE_SERVICE_ID,
                grants,
                InstanceGeneration(1),
                |pid| {
                    rollback_pid = pid;
                    Ok(())
                },
            )
            .unwrap_err();
        assert!(matches!(err, LifecycleControlError::SpawnFailed(_)));
        assert_eq!(rollback_pid, 77);
    }

    #[cfg(not(feature = "m4-recovery-self-test"))]
    #[test]
    fn storage_grant_rollback_error_is_reported() {
        let mut controller = ServiceLifecycleController::new();
        let mut pid = 100_u64;
        loop {
            if unsafe { lifecycle_capabilities_mut() }
                .block_device
                .grant_block_device_capability(pid, STORAGE_BLOCK_DEVICE_ID)
                .is_err()
            {
                break;
            }
            pid += 1;
        }

        let grants = controller.launch_grants(STORAGE_SERVICE_ID);
        let err = controller
            .apply_instance_grants_with_rollback(
                77,
                STORAGE_SERVICE_ID,
                grants,
                InstanceGeneration(1),
                |_| Err("teardown failed"),
            )
            .unwrap_err();
        assert_eq!(
            err,
            LifecycleControlError::SpawnFailed(
                "storage service block-capability rollback teardown failed"
            )
        );
    }

    #[test]
    fn launch_grants_come_from_the_active_manifest() {
        use clean_slate_service_fixtures::manifest::{RestartSpec, ServiceImage, Start};
        static SCENARIO: &[ServiceSpec] = &[ServiceSpec {
            id: STORAGE_SERVICE_ID,
            image: ServiceImage::Storage,
            mode: 0,
            grants: &[Grant::BlockDevice],
            restart: RestartSpec::Never,
            depends_on: &[],
            slot_allowance: None,
            memory_pages: 0,
            launch_name: None,
            start: Start::AtBoot,
        }];

        let mut controller = ServiceLifecycleController::new();
        assert_eq!(
            controller.launch_grants(STORAGE_SERVICE_ID),
            [Grant::BlockDevice, Grant::ObjectServiceRole]
        );
        assert_eq!(
            controller.launch_grants(NETWORK_SERVICE_ID),
            [Grant::NetworkService]
        );
        assert!(controller
            .launch_grants(STORAGE_UNAUTHORIZED_SERVICE_ID)
            .is_empty());

        controller.use_scenario_manifest(SCENARIO);
        assert_eq!(
            controller.launch_grants(STORAGE_SERVICE_ID),
            [Grant::BlockDevice]
        );
        assert!(controller.launch_grants(NETWORK_SERVICE_ID).is_empty());

        controller.clear();
        assert_eq!(
            controller.launch_grants(NETWORK_SERVICE_ID),
            [Grant::NetworkService]
        );
    }

    #[test]
    fn launch_context_carries_the_row_generation_and_scenario_handle() {
        use clean_slate_service_fixtures::manifest::STORAGE_SERVICE_SPEC;
        use clean_slate_service_fixtures::STORAGE_SERVICE_MODE_OBJECT_SERVICE;

        let mut controller = ServiceLifecycleController::new();
        let context = controller.launch_context(STORAGE_SERVICE_ID, InstanceGeneration(3));
        assert_eq!(context.spec, Some(&STORAGE_SERVICE_SPEC));
        assert_eq!(
            context.spec.map(|spec| spec.mode),
            Some(STORAGE_SERVICE_MODE_OBJECT_SERVICE)
        );
        assert_eq!(context.generation, InstanceGeneration(3));
        assert_eq!(context.previous_handle, 0);
        assert_eq!(
            controller
                .launch_context(STORAGE_UNAUTHORIZED_SERVICE_ID, InstanceGeneration(1))
                .spec,
            None
        );

        controller.set_scenario_previous_handle(0x55);
        assert_eq!(
            controller
                .launch_context(STORAGE_SERVICE_ID, InstanceGeneration(2))
                .previous_handle,
            0x55
        );
        controller.clear();
        assert_eq!(
            controller
                .launch_context(STORAGE_SERVICE_ID, InstanceGeneration(2))
                .previous_handle,
            0
        );
    }

    #[test]
    fn rows_without_post_spawn_grants_succeed_without_rollback() {
        let mut controller = ServiceLifecycleController::new();
        let mut rolled_back = false;
        for grants in [&[][..], &[Grant::ObjectServiceRole][..]] {
            controller
                .apply_instance_grants_with_rollback(
                    77,
                    STORAGE_UNAUTHORIZED_SERVICE_ID,
                    grants,
                    InstanceGeneration(1),
                    |_| {
                        rolled_back = true;
                        Ok(())
                    },
                )
                .unwrap();
        }
        assert!(!rolled_back);
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

    /// The fault notice only retires the live record; the teardown that follows it revokes.
    #[test]
    fn block_capability_is_revoked_by_the_teardown_after_a_fault() {
        let mut controller = ServiceLifecycleController::new();
        controller.services[0] = ServiceRecord {
            service: STORAGE_SERVICE_ID,
            state: ServiceLifecycleState::Running,
            authoritative_generation: InstanceGeneration(1),
            live: Some(LiveServiceInstance {
                pid: 77,
                tid: 1,
                domain_id: 77,
                generation: InstanceGeneration(1),
                scheduler_slot: 0,
            }),
        };
        unsafe { lifecycle_capabilities_mut() }
            .block_device
            .grant_block_device_capability(77, STORAGE_BLOCK_DEVICE_ID)
            .expect("grant");
        let handle = controller
            .acquire_block_device_capability(77, STORAGE_BLOCK_DEVICE_ID)
            .expect("acquire");
        controller
            .notify_faulted_live_process(77, 0)
            .expect("faulted lookup")
            .expect("event");
        assert_eq!(
            controller.authorize_block_device_request(77, handle, STORAGE_BLOCK_DEVICE_ID),
            Ok(())
        );
        assert_eq!(crate::service::capability::on_holder_exit(77), 1);
        assert_eq!(
            controller.authorize_block_device_request(77, handle, STORAGE_BLOCK_DEVICE_ID),
            Err(LifecycleControlError::StaleHandle)
        );
    }

    #[test]
    fn registry_holds_twelve_services_and_refuses_the_thirteenth() {
        assert_eq!(SERVICE_REGISTRY_CAPACITY, 12);
        let mut controller = ServiceLifecycleController::new();
        for id in 1..=12 {
            controller
                .declare_service(ServiceId(id))
                .expect("declare within capacity");
        }
        assert_eq!(
            controller.declare_service(ServiceId(13)),
            Err("service registry capacity exceeded")
        );
        assert!(controller.find_service(ServiceId(13)).is_none());
        for id in 1..=12 {
            assert!(controller.find_service(ServiceId(id)).is_some());
        }
        assert_eq!(
            controller.declare_service(ServiceId(8)),
            Err("service was already declared")
        );
    }

    fn live_record(service: ServiceId, pid: u64) -> ServiceRecord {
        ServiceRecord {
            service,
            state: ServiceLifecycleState::Running,
            authoritative_generation: InstanceGeneration(1),
            live: Some(LiveServiceInstance {
                pid,
                tid: 1,
                domain_id: pid,
                generation: InstanceGeneration(1),
                scheduler_slot: 0,
            }),
        }
    }

    fn event_for(service: ServiceId, pid: u64, kind: LifecycleEventKind) -> LifecycleEvent {
        LifecycleEvent::new(
            ServiceInstanceId::new(
                service,
                InstanceGeneration(1),
                ProcessId(pid),
                DomainId(pid),
            ),
            kind,
        )
    }

    /// Runs `queue` and returns how many lifecycle wakes it requested.
    fn wakes_during(queue: impl FnOnce()) -> u64 {
        let before = crate::service::lifecycle_wait::test_wake_count();
        queue();
        crate::service::lifecycle_wait::test_wake_count() - before
    }

    #[test]
    fn every_queued_message_wakes_lifecycle_waiters() {
        let mut controller = ServiceLifecycleController::new();
        controller.services[0] = ServiceRecord {
            state: ServiceLifecycleState::Starting,
            ..live_record(ServiceId(20), 60)
        };
        assert_eq!(
            wakes_during(|| controller.notify_instance_ready(ServiceId(20)).unwrap()),
            1
        );
        assert_eq!(
            wakes_during(|| controller
                .replay_pending_lifecycle_event(event_for(
                    ServiceId(21),
                    61,
                    LifecycleEventKind::Ready
                ))
                .unwrap()),
            1
        );
        assert_eq!(
            wakes_during(|| {
                controller.notify_faulted_live_process(60, 3).unwrap();
            }),
            1
        );
    }

    #[test]
    fn a_full_queue_wakes_only_when_a_message_is_stored() {
        // Full of non-terminal events: a ready notification is refused and wakes nobody.
        let mut controller = ServiceLifecycleController::new();
        controller.services[0] = ServiceRecord {
            state: ServiceLifecycleState::Starting,
            ..live_record(ServiceId(22), 62)
        };
        controller.pending =
            [Some(event_for(ServiceId(30), 1, LifecycleEventKind::Ready)); SERVICE_PENDING_EVENTS];
        controller.pending_count = SERVICE_PENDING_EVENTS;
        assert_eq!(
            wakes_during(|| {
                controller.notify_instance_ready(ServiceId(22)).unwrap_err();
            }),
            0
        );
        // A terminal event replaces a non-terminal one.
        controller.services[0].state = ServiceLifecycleState::Running;
        assert_eq!(
            wakes_during(|| {
                controller.notify_faulted_live_process(62, 0).unwrap();
            }),
            1
        );

        // Full of other services' terminal events: the first slot is overwritten.
        let mut controller = ServiceLifecycleController::new();
        controller.services[0] = live_record(ServiceId(23), 63);
        controller.pending =
            [Some(event_for(ServiceId(31), 2, LifecycleEventKind::Exited)); SERVICE_PENDING_EVENTS];
        controller.pending_count = SERVICE_PENDING_EVENTS;
        assert_eq!(
            wakes_during(|| {
                controller.notify_faulted_live_process(63, 0).unwrap();
            }),
            1
        );
        assert_eq!(
            controller.pending[0].map(|event| event.instance.service),
            Some(ServiceId(23))
        );

        // A count that says full over an empty slot still stores and wakes.
        let mut controller = ServiceLifecycleController::new();
        controller.services[0] = live_record(ServiceId(24), 64);
        controller.pending_count = SERVICE_PENDING_EVENTS;
        assert_eq!(
            wakes_during(|| {
                controller.notify_faulted_live_process(64, 0).unwrap();
            }),
            1
        );
    }

    #[test]
    fn pending_service_peek_is_authorized_like_a_poll_and_consumes_nothing() {
        let mut controller = ServiceLifecycleController::new();
        let capability = controller
            .grant_lifecycle_control_capability(100, &[ServiceId(25)])
            .expect("grant capability");
        assert_eq!(
            controller.pending_service_authorized(100, capability),
            Ok(None)
        );

        controller
            .replay_pending_lifecycle_event(event_for(
                ServiceId(25),
                65,
                LifecycleEventKind::Exited,
            ))
            .unwrap();
        assert_eq!(
            controller.pending_service_authorized(100, capability),
            Ok(Some(ServiceId(25)))
        );
        assert_eq!(
            controller.pending_service_authorized(100, capability),
            Ok(Some(ServiceId(25)))
        );

        // Another process holding the same handle value, a handle of the wrong slot or
        // generation, and a revoked capability are all refused.
        assert_eq!(
            controller.pending_service_authorized(101, capability),
            Err(LifecycleControlError::Unauthorized)
        );
        use crate::service::capability::LifecycleControlHandleParts;
        let parts = LifecycleControlHandleParts::decode(capability).expect("lifecycle handle");
        let wrong_generation = LifecycleControlHandleParts {
            capability_generation: parts.capability_generation + 1,
            ..parts
        }
        .encode();
        assert_eq!(
            controller.pending_service_authorized(100, wrong_generation),
            Err(LifecycleControlError::StaleHandle)
        );
        assert_eq!(
            controller.pending_service_authorized(100, 0xffff),
            Err(LifecycleControlError::InvalidHandle)
        );
        let block_handle = unsafe { lifecycle_capabilities_mut() }
            .block_device
            .grant_block_device_capability(101, STORAGE_BLOCK_DEVICE_ID)
            .expect("grant block capability");
        assert_eq!(
            controller.pending_service_authorized(101, block_handle),
            Err(LifecycleControlError::InvalidHandle),
            "a block-device handle is not a lifecycle handle, whoever holds it (#288)"
        );
        let holder_block_handle = unsafe { lifecycle_capabilities_mut() }
            .block_device
            .grant_block_device_capability(100, STORAGE_BLOCK_DEVICE_ID)
            .expect("grant block capability to the lifecycle holder");
        assert_eq!(
            controller.pending_service_authorized(100, holder_block_handle),
            Err(LifecycleControlError::InvalidHandle),
            "the lifecycle holder's own block-device handle does not alias its lifecycle handle"
        );
        assert_eq!(
            controller.pending_service_authorized(100, capability & 0xffff_ffff),
            Err(LifecycleControlError::InvalidHandle),
            "the lifecycle handle without its family tag is refused"
        );
        assert_eq!(
            controller.pending_service_authorized(100, capability | (1 << 40)),
            Err(LifecycleControlError::InvalidHandle),
            "a reserved bit set on the lifecycle handle is refused"
        );

        let event = controller
            .poll_pending_event_authorized(100, capability, ServiceId(25))
            .expect("poll")
            .expect("event");
        assert_eq!(event.instance.service, ServiceId(25));
        assert_eq!(
            controller.pending_service_authorized(100, capability),
            Ok(None)
        );

        unsafe { lifecycle_capabilities_mut() }
            .lifecycle_control
            .revoke_capabilities_for_pid(100);
        assert_eq!(
            controller.pending_service_authorized(100, capability),
            Err(LifecycleControlError::StaleHandle)
        );
    }

    fn starting_record(service: ServiceId, pid: u64, generation: u32) -> ServiceRecord {
        ServiceRecord {
            state: ServiceLifecycleState::Starting,
            authoritative_generation: InstanceGeneration(generation),
            live: Some(LiveServiceInstance {
                generation: InstanceGeneration(generation),
                ..live_record(service, pid).live.expect("live")
            }),
            ..live_record(service, pid)
        }
    }

    type ReadyObservable = (
        [ServiceRecord; SERVICE_REGISTRY_CAPACITY],
        [Option<LifecycleEvent>; SERVICE_PENDING_EVENTS],
        usize,
        [Option<LifecycleEvent>; SERVICE_REGISTRY_CAPACITY],
    );

    /// Everything a `SERVICE_READY` report may change.
    fn ready_observable(controller: &ServiceLifecycleController) -> ReadyObservable {
        (
            controller.services,
            controller.pending,
            controller.pending_count,
            controller.ready_pending,
        )
    }

    #[test]
    fn service_ready_from_a_starting_desktop_service_is_accepted() {
        // The report keys only on the live Starting instance of 0x5300, 0x5301 or 0x5302, so it
        // is accepted. Terminate from the resulting Running state is the path that stops a client
        // when the compositor exits, and it stays valid.
        for (id, pid) in [(0x5300u32, 80u64), (0x5301, 81), (0x5302, 82)] {
            let mut controller = ServiceLifecycleController::new();
            controller.services[0] = starting_record(ServiceId(id), pid, 1);
            let before_pending = controller.pending_count;
            let instance = controller
                .report_ready_from_pid(pid)
                .expect("desktop service ready is accepted");
            assert_eq!(instance.service, ServiceId(id));
            assert_eq!(controller.services[0].state, ServiceLifecycleState::Running);
            assert_eq!(controller.pending_count, before_pending);
            assert!(controller.ready_pending[0].is_some());
            let (next, generation) = apply_transition(
                ServiceLifecycleState::Running,
                InstanceGeneration(1),
                TransitionInput::Control(ControlRequestKind::Terminate),
                None,
            )
            .expect("terminate from running");
            assert_eq!(next, ServiceLifecycleState::Stopping);
            assert_eq!(generation, InstanceGeneration(1));
            let (faulted, _) = apply_transition(
                ServiceLifecycleState::Running,
                InstanceGeneration(1),
                TransitionInput::Event(LifecycleEventKind::Faulted),
                Some(instance),
            )
            .expect("fault from running");
            assert_eq!(faulted, ServiceLifecycleState::Faulted);
        }
    }

    #[test]
    fn service_ready_from_the_starting_live_instance_is_accepted_once() {
        let mut controller = ServiceLifecycleController::new();
        controller.services[1] = starting_record(STORAGE_SERVICE_ID, 70, 1);
        let mut accepted = None;
        assert_eq!(
            wakes_during(|| accepted = Some(controller.report_ready_from_pid(70))),
            1
        );
        let instance = accepted.unwrap().expect("accepted");
        assert_eq!(instance.service, STORAGE_SERVICE_ID);
        assert_eq!(instance.pid, ProcessId(70));
        assert_eq!(instance.generation, InstanceGeneration(1));
        assert_eq!(controller.services[1].state, ServiceLifecycleState::Running);
        assert_eq!(controller.pending_count, 0, "the shared queue is not used");

        // The same instance again, before and after its message is polled: refused, inert.
        for poll_first in [false, true] {
            if poll_first {
                let event = controller
                    .poll_pending_event(STORAGE_SERVICE_ID)
                    .unwrap()
                    .expect("ready message");
                assert_eq!(event.kind, LifecycleEventKind::Ready);
                assert_eq!(event.instance, instance);
                assert_eq!(controller.poll_pending_event(STORAGE_SERVICE_ID), Ok(None));
            }
            let before = ready_observable(&controller);
            let mut result = None;
            assert_eq!(
                wakes_during(|| result = Some(controller.report_ready_from_pid(70))),
                0
            );
            assert_eq!(result.unwrap(), Err(ServiceReadyRefusal::NotStarting));
            assert_eq!(ready_observable(&controller), before);
        }
    }

    #[test]
    fn service_ready_from_anything_but_a_live_service_instance_is_refused_inertly() {
        let mut controller = ServiceLifecycleController::new();
        controller.services[0] = starting_record(STORAGE_SERVICE_ID, 70, 1);
        // A lifecycle-control holder (init), and pids with no live instance at all.
        controller
            .grant_lifecycle_control_capability(100, &[STORAGE_SERVICE_ID])
            .expect("grant capability");
        // A faulted instance keeps its record but has no live pid.
        controller.services[1] = ServiceRecord {
            state: ServiceLifecycleState::Faulted,
            live: None,
            ..live_record(NETWORK_SERVICE_ID, 71)
        };
        for pid in [100, 71, 0, 9999] {
            let before = ready_observable(&controller);
            let mut result = None;
            assert_eq!(
                wakes_during(|| result = Some(controller.report_ready_from_pid(pid))),
                0
            );
            assert_eq!(
                result.unwrap(),
                Err(ServiceReadyRefusal::NotAServiceInstance),
                "pid {pid}"
            );
            assert_eq!(ready_observable(&controller), before);
        }
    }

    #[test]
    fn service_ready_outside_starting_is_refused_inertly() {
        for state in [
            ServiceLifecycleState::Running,
            ServiceLifecycleState::Stopping,
        ] {
            let mut controller = ServiceLifecycleController::new();
            controller.services[0] = ServiceRecord {
                state,
                ..starting_record(STORAGE_SERVICE_ID, 70, 1)
            };
            let before = ready_observable(&controller);
            let mut result = None;
            assert_eq!(
                wakes_during(|| result = Some(controller.report_ready_from_pid(70))),
                0
            );
            assert_eq!(result.unwrap(), Err(ServiceReadyRefusal::NotStarting));
            assert_eq!(ready_observable(&controller), before);
        }
    }

    #[test]
    fn service_ready_is_accepted_with_the_shared_queue_full() {
        let mut controller = ServiceLifecycleController::new();
        controller.services[0] = starting_record(NETWORK_SERVICE_ID, 72, 1);
        let full =
            [Some(event_for(ServiceId(30), 1, LifecycleEventKind::Exited)); SERVICE_PENDING_EVENTS];
        controller.pending = full;
        controller.pending_count = SERVICE_PENDING_EVENTS;
        assert_eq!(
            wakes_during(|| {
                controller.report_ready_from_pid(72).expect("accepted");
            }),
            1
        );
        assert_eq!(controller.services[0].state, ServiceLifecycleState::Running);
        assert_eq!(controller.pending, full, "queued messages are untouched");
        assert_eq!(controller.pending_count, SERVICE_PENDING_EVENTS);
        assert_eq!(
            controller
                .poll_pending_event(NETWORK_SERVICE_ID)
                .unwrap()
                .map(|event| event.kind),
            Some(LifecycleEventKind::Ready)
        );
    }

    #[test]
    fn at_most_one_ready_message_is_held_per_service_and_the_newest_wins() {
        let mut controller = ServiceLifecycleController::new();
        controller.services[0] = starting_record(STORAGE_SERVICE_ID, 70, 1);
        controller.report_ready_from_pid(70).expect("gen 1");
        // Replaced before anyone polled gen 1's message.
        controller.services[0] = starting_record(STORAGE_SERVICE_ID, 80, 2);
        controller.report_ready_from_pid(80).expect("gen 2");
        assert_eq!(
            controller.ready_pending.iter().flatten().count(),
            1,
            "one slot per service"
        );
        let event = controller
            .poll_pending_event(STORAGE_SERVICE_ID)
            .unwrap()
            .expect("ready");
        assert_eq!(event.instance.generation, InstanceGeneration(2));
        assert_eq!(event.instance.pid, ProcessId(80));
        assert_eq!(controller.poll_pending_event(STORAGE_SERVICE_ID), Ok(None));
    }

    #[test]
    fn ready_and_queued_messages_are_delivered_oldest_instance_first() {
        // Same instance: ready before its fault.
        let mut controller = ServiceLifecycleController::new();
        controller.services[0] = starting_record(STORAGE_SERVICE_ID, 70, 1);
        controller.report_ready_from_pid(70).expect("ready");
        controller
            .notify_faulted_live_process(70, 3)
            .expect("fault")
            .expect("event");
        let kinds: Vec<_> = core::iter::from_fn(|| {
            controller
                .poll_pending_event(STORAGE_SERVICE_ID)
                .unwrap()
                .map(|event| event.kind)
        })
        .collect();
        assert_eq!(
            kinds,
            [LifecycleEventKind::Ready, LifecycleEventKind::Faulted]
        );

        // An older instance's unpolled fault goes before the replacement's ready.
        let mut controller = ServiceLifecycleController::new();
        controller.services[0] = starting_record(STORAGE_SERVICE_ID, 70, 1);
        controller
            .notify_faulted_live_process(70, 3)
            .expect("fault")
            .expect("event");
        controller.services[0] = starting_record(STORAGE_SERVICE_ID, 80, 2);
        controller.report_ready_from_pid(80).expect("ready");
        let order: Vec<_> = core::iter::from_fn(|| {
            controller
                .poll_pending_event(STORAGE_SERVICE_ID)
                .unwrap()
                .map(|event| (event.kind, event.instance.generation.0))
        })
        .collect();
        assert_eq!(
            order,
            [
                (LifecycleEventKind::Faulted, 1),
                (LifecycleEventKind::Ready, 2)
            ]
        );
        assert_eq!(controller.pending_count, 0);
    }

    #[test]
    fn a_pending_ready_message_is_visible_to_an_authorized_peek_and_cleared_with_the_registry() {
        let mut controller = ServiceLifecycleController::new();
        let capability = controller
            .grant_lifecycle_control_capability(100, &[NETWORK_SERVICE_ID])
            .expect("grant capability");
        controller.services[2] = starting_record(NETWORK_SERVICE_ID, 72, 1);
        controller.report_ready_from_pid(72).expect("ready");
        assert_eq!(
            controller.pending_service_authorized(100, capability),
            Ok(Some(NETWORK_SERVICE_ID))
        );
        assert_eq!(
            controller.pending_service_authorized(101, capability),
            Err(LifecycleControlError::Unauthorized)
        );
        controller.clear();
        assert!(controller.ready_pending.iter().all(Option::is_none));
    }

    #[test]
    fn block_capability_does_not_transfer_to_replacement_instance() {
        let mut controller = ServiceLifecycleController::new();
        controller.services[0] = ServiceRecord {
            service: STORAGE_SERVICE_ID,
            state: ServiceLifecycleState::Running,
            authoritative_generation: InstanceGeneration(2),
            live: Some(LiveServiceInstance {
                pid: 80,
                tid: 1,
                domain_id: 80,
                generation: InstanceGeneration(2),
                scheduler_slot: 0,
            }),
        };
        let handle = unsafe { lifecycle_capabilities_mut() }
            .block_device
            .grant_block_device_capability(80, STORAGE_BLOCK_DEVICE_ID)
            .expect("grant");
        unsafe { lifecycle_capabilities_mut() }
            .block_device
            .revoke_capabilities_for_pid(80);
        controller.services[0].live = Some(LiveServiceInstance {
            pid: 81,
            tid: 2,
            domain_id: 81,
            generation: InstanceGeneration(3),
            scheduler_slot: 1,
        });
        unsafe { lifecycle_capabilities_mut() }
            .block_device
            .grant_block_device_capability(81, STORAGE_BLOCK_DEVICE_ID)
            .expect("grant replacement");
        assert_eq!(
            controller.authorize_block_device_request(81, handle, STORAGE_BLOCK_DEVICE_ID),
            Err(LifecycleControlError::StaleHandle)
        );
    }
}
