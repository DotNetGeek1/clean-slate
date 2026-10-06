use super::begin_thread_exit;
use super::finalize_process_exit;
use super::linux_fd;
use super::process_registry_mut;
use super::reap_process_record;
use super::ProcessState;
use super::KERNEL_PROCESS_ID;
use crate::arch::x86_64::cpu::without_interrupts;
use clean_slate_capability::HolderId;
use clean_slate_service_lifecycle::InstanceGeneration;

use crate::capability::bootstrap_grant::discard_bootstrap_grants_for_holder;
use crate::capability::object::{
    reclaim_object_requests_for_holder, recover_object_queue_for_service_holder_exit,
};
use crate::capability::{revoke_for_holder, revoke_for_process_resource};
use crate::device::input;
use crate::ipc::endpoint_table_mut;
use crate::ipc::IpcProcessResources;
use crate::mm::address_space::activate_address_space_root;
use crate::mm::address_space::destroy_process_address_space;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
use crate::sched::dispatch::prepare_current_scheduler_thread_dispatch;
use crate::sched::scheduler_mut;
use crate::sched::with_scheduler;
use crate::sched::work_set;
use crate::sched::ThreadKind;
use crate::sched::ThreadProcessResources;
use crate::service::net_bridge::{
    notify_holder_exit_for_process, reclaim_net_requests_for_holder,
    recover_net_queue_for_service_holder_exit,
};
use crate::service::port;

// Process teardown and resource accounting are only exercised end-to-end by
// the M3 self-test features today; the normal boot path picks them up later.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ResourceSnapshot {
    pub(crate) user_pages: usize,
    pub(crate) page_table_frames: usize,
    pub(crate) kernel_stacks: usize,
    pub(crate) ipc_endpoints: usize,
    pub(crate) ipc_handles: usize,
    pub(crate) threads: usize,
    pub(crate) runnable_threads: usize,
    pub(crate) work_sets: usize,
    pub(crate) ports_served: usize,
    pub(crate) port_connections: usize,
    /// #195 shared-window rows (Live or orphaned): presenter release removes its scanout
    /// kernel-grant rows and teardown step 5 every other one.
    pub(crate) shared_mappings: usize,
}

/// What the M10 teardown slots released; both exit paths compare it with the snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct HolderReleaseCounts {
    work_sets: usize,
    ports: clean_slate_port::PortReleaseCounts,
    /// Scanout kernel-grant rows the presenter slot unmapped; step 5 removes the rest.
    presenter_grant_rows: usize,
    shared_mappings: usize,
}

impl HolderReleaseCounts {
    fn matches(self, snapshot: &ResourceSnapshot) -> Result<(), &'static str> {
        if self.work_sets != snapshot.work_sets {
            return Err("work-set teardown count diverged from the recorded process snapshot");
        }
        if self.ports.served_ports != snapshot.ports_served
            || self.ports.client_connections != snapshot.port_connections
        {
            return Err("port teardown count diverged from the recorded process snapshot");
        }
        if self
            .presenter_grant_rows
            .saturating_add(self.shared_mappings)
            != snapshot.shared_mappings
        {
            return Err(
                "shared-mapping teardown count diverged from the recorded process snapshot",
            );
        }
        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DomainTeardownResult {
    pub(crate) process_id: u64,
    pub(crate) exit_status: u64,
    pub(crate) released_resources: ResourceSnapshot,
    pub(crate) next_stack_pointer: Option<u64>,
}

#[allow(dead_code)]
/// Counts scheduler/IPC ownership still attributed to `process_id` after teardown.
pub(crate) fn remaining_owned_resource_count(process_id: u64) -> usize {
    if unsafe { process_registry_mut().get(process_id) }.is_some() {
        return usize::MAX;
    }
    let thread_resources =
        without_interrupts(|| unsafe { scheduler_mut().resources_for_process(process_id) });
    let ipc_resources = unsafe { endpoint_table_mut().resources_for_pid(process_id) };
    thread_resources.threads
        + thread_resources.kernel_stacks
        + thread_resources.runnable_threads
        + ipc_resources.owned_endpoints
        + ipc_resources.held_capabilities
        + work_set::count_for(HolderId(process_id))
        + port_resource_count(HolderId(process_id))
        + crate::mm::shared_buffer::mapping_count(process_id)
}

fn port_resource_count(holder: HolderId) -> usize {
    let counts = port::counts_for(holder);
    counts.ports_served + counts.port_connections
}

pub(crate) fn resource_snapshot(process_id: u64) -> Result<ResourceSnapshot, &'static str> {
    let address_space = unsafe {
        process_registry_mut()
            .get(process_id)
            .ok_or("resource snapshot process was not registered")?
            .resource_domain
            .address_space_resource_counts()
    };
    let thread_resources =
        without_interrupts(|| unsafe { scheduler_mut().resources_for_process(process_id) });
    let ipc_resources = unsafe { endpoint_table_mut().resources_for_pid(process_id) };
    let ports = port::counts_for(HolderId(process_id));
    Ok(ResourceSnapshot {
        user_pages: address_space.user_pages,
        page_table_frames: address_space.page_table_frames,
        kernel_stacks: thread_resources.kernel_stacks,
        ipc_endpoints: ipc_resources.owned_endpoints,
        ipc_handles: ipc_resources.held_capabilities,
        threads: thread_resources.threads,
        runnable_threads: thread_resources.runnable_threads,
        work_sets: work_set::count_for(HolderId(process_id)),
        ports_served: ports.ports_served,
        port_connections: ports.port_connections,
        shared_mappings: crate::mm::shared_buffer::mapping_count(process_id),
    })
}

const TEARDOWN_HOOK_COUNT: usize = 15;

/// One step of the teardown sequence shared by every path that dismantles a
/// registered process, declared in execution order. The port through address
/// space steps follow the kernel ordering (P4) in `docs/GRAPHICS.md`.
///
/// The discriminants end at `u8::MAX`, so a new variant overflows them until
/// `TEARDOWN_HOOK_COUNT` grows, and the assertion below then fails the build
/// until [`TEARDOWN_HOOK_ORDER`] lists the variant at its declared position.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TeardownHook {
    IpcEndpoints = (u8::MAX as usize + 1 - TEARDOWN_HOOK_COUNT) as u8,
    ObjectQueues,
    NetQueues,
    NetworkCapabilities,
    NetHolderExitNotice,
    /// P4 step 1: service ports the holder serves or is connected to.
    Port,
    /// P4 step 2: the display presenter binding.
    DisplayPresenter,
    /// P4 step 3: the raw-input consumer binding.
    InputConsumer,
    /// The holder's work set; after every wake source is unbound.
    WorkSet,
    /// P4 step 4.
    RevokeHolderCapabilities,
    RevokeProcessResource,
    DiscardBootstrapGrants,
    /// P4 step 5: shared-buffer mappings.
    SharedMappings,
    ThreadReap,
    /// P4 step 6: the private address space and the process record.
    AddressSpace,
}

pub(crate) const TEARDOWN_HOOK_ORDER: [TeardownHook; TEARDOWN_HOOK_COUNT] = [
    TeardownHook::IpcEndpoints,
    TeardownHook::ObjectQueues,
    TeardownHook::NetQueues,
    TeardownHook::NetworkCapabilities,
    TeardownHook::NetHolderExitNotice,
    TeardownHook::Port,
    TeardownHook::DisplayPresenter,
    TeardownHook::InputConsumer,
    TeardownHook::WorkSet,
    TeardownHook::RevokeHolderCapabilities,
    TeardownHook::RevokeProcessResource,
    TeardownHook::DiscardBootstrapGrants,
    TeardownHook::SharedMappings,
    TeardownHook::ThreadReap,
    TeardownHook::AddressSpace,
];

const _: () = {
    let mut slot = 0;
    while slot < TEARDOWN_HOOK_COUNT {
        assert!(
            TEARDOWN_HOOK_ORDER[slot] as usize == TeardownHook::IpcEndpoints as usize + slot,
            "TEARDOWN_HOOK_ORDER must list every TeardownHook once, in declaration order"
        );
        slot += 1;
    }
    assert!((TeardownHook::Port as u8) < (TeardownHook::DisplayPresenter as u8));
    assert!((TeardownHook::DisplayPresenter as u8) < (TeardownHook::InputConsumer as u8));
    assert!((TeardownHook::InputConsumer as u8) < (TeardownHook::WorkSet as u8));
    assert!((TeardownHook::WorkSet as u8) < (TeardownHook::RevokeHolderCapabilities as u8));
    assert!((TeardownHook::RevokeHolderCapabilities as u8) < (TeardownHook::SharedMappings as u8));
    assert!((TeardownHook::ThreadReap as u8) < (TeardownHook::AddressSpace as u8));
    assert!(
        TeardownHook::AddressSpace as u8 == u8::MAX,
        "the address-space step frees the root every earlier hook borrows, so it runs last"
    );
};

/// What every teardown hook receives. Hooks borrow the private address space
/// through `address_space_root`; only the last hook takes and frees it.
pub(crate) struct TeardownContext<'a> {
    pub(crate) process_id: u64,
    pub(crate) instance_generation: InstanceGeneration,
    pub(crate) address_space_root: u64,
    pub(crate) allocator: &'a mut PageAllocator,
}

impl<'a> TeardownContext<'a> {
    fn for_registered(process_id: u64, allocator: &'a mut PageAllocator) -> Option<Self> {
        let process = unsafe { process_registry_mut().get(process_id)? };
        Some(Self {
            process_id,
            instance_generation: process.instance_generation,
            address_space_root: process.resource_domain.dispatch_root_frame(),
            allocator,
        })
    }
}

/// How one dismantle runs the shared hooks.
struct TeardownPath {
    /// The process has been dispatched, so the holder-exit bookkeeping hooks apply.
    process_ran: bool,
    revokes_capabilities: bool,
    /// Keep running after a failed hook and report the first failure.
    best_effort: bool,
    record_missing: &'static str,
    address_space_missing: &'static str,
}

/// `teardown_current_process`: the exiting thread is the caller.
const CURRENT_TEARDOWN: TeardownPath = TeardownPath {
    process_ran: true,
    revokes_capabilities: true,
    best_effort: false,
    record_missing: "process missing from registry during resource teardown",
    address_space_missing: "process address space was missing during teardown",
};

/// `teardown_process_by_id`: supervisor-initiated, target is not running.
const EXTERNAL_TEARDOWN: TeardownPath = TeardownPath {
    process_ran: true,
    revokes_capabilities: true,
    best_effort: false,
    record_missing: "process missing from registry during external resource teardown",
    address_space_missing: "process address space was missing during external teardown",
};

impl TeardownPath {
    const fn runs(&self, hook: TeardownHook) -> bool {
        match hook {
            TeardownHook::IpcEndpoints
            | TeardownHook::ObjectQueues
            | TeardownHook::NetQueues
            | TeardownHook::NetworkCapabilities
            | TeardownHook::NetHolderExitNotice
            | TeardownHook::RevokeProcessResource
            | TeardownHook::DiscardBootstrapGrants
            | TeardownHook::ThreadReap => self.process_ran,
            TeardownHook::RevokeHolderCapabilities => self.revokes_capabilities,
            TeardownHook::Port
            | TeardownHook::DisplayPresenter
            | TeardownHook::InputConsumer
            | TeardownHook::WorkSet
            | TeardownHook::SharedMappings
            | TeardownHook::AddressSpace => true,
        }
    }
}

/// Runs every hook `path` applies, in [`TEARDOWN_HOOK_ORDER`]. The dying
/// process's root must not be the active one.
fn run_teardown_hooks(
    ctx: &mut TeardownContext<'_>,
    path: &TeardownPath,
    mut run_hook: impl FnMut(TeardownHook, &mut TeardownContext<'_>) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let mut first_failure = None;
    for hook in TEARDOWN_HOOK_ORDER {
        if !path.runs(hook) {
            continue;
        }
        if let Err(message) = run_hook(hook, ctx) {
            if !path.best_effort {
                return Err(message);
            }
            first_failure.get_or_insert(message);
        }
    }
    first_failure.map_or(Ok(()), Err)
}

#[derive(Default)]
struct ReleasedResources {
    ipc: Option<IpcProcessResources>,
    threads: Option<ThreadProcessResources>,
    holder: HolderReleaseCounts,
}

fn run_teardown_hook(
    hook: TeardownHook,
    ctx: &mut TeardownContext<'_>,
    path: &TeardownPath,
    released: &mut ReleasedResources,
) -> Result<(), &'static str> {
    let holder = HolderId(ctx.process_id);
    #[cfg(feature = "m10-port-self-test")]
    crate::selftest::m10_port::trace_teardown_hook(holder, hook);
    match hook {
        TeardownHook::IpcEndpoints => {
            released.ipc =
                Some(unsafe { endpoint_table_mut().teardown_resources_for_pid(ctx.process_id)? });
        }
        TeardownHook::ObjectQueues => {
            recover_object_queue_for_service_holder_exit(holder);
            reclaim_object_requests_for_holder(holder);
        }
        TeardownHook::NetQueues => {
            recover_net_queue_for_service_holder_exit(holder.0);
            reclaim_net_requests_for_holder(holder.0);
        }
        TeardownHook::NetworkCapabilities => {
            crate::capability::network::on_holder_exit(holder);
        }
        TeardownHook::NetHolderExitNotice => {
            notify_holder_exit_for_process(holder.0);
        }
        TeardownHook::Port => released.holder.ports = release_ports(ctx),
        TeardownHook::DisplayPresenter => {
            released.holder.presenter_grant_rows = release_display_presenter(ctx);
        }
        TeardownHook::InputConsumer => release_input_consumer(ctx),
        TeardownHook::WorkSet => released.holder.work_sets = release_work_set(ctx),
        TeardownHook::RevokeHolderCapabilities => {
            revoke_for_holder(holder);
        }
        TeardownHook::RevokeProcessResource => {
            revoke_for_process_resource(ctx.process_id);
        }
        TeardownHook::DiscardBootstrapGrants => {
            discard_bootstrap_grants_for_holder(holder);
        }
        TeardownHook::SharedMappings => {
            released.holder.shared_mappings = release_shared_mappings(ctx)?;
        }
        TeardownHook::ThreadReap => {
            released.threads = Some(without_interrupts(|| unsafe {
                let scheduler = scheduler_mut();
                let resources = scheduler.resources_for_process(ctx.process_id);
                let reaped = scheduler.reap_threads_for_process(ctx.process_id)?;
                if reaped != resources.threads {
                    return Err("scheduler thread cleanup count diverged from teardown snapshot");
                }
                Ok::<ThreadProcessResources, &'static str>(resources)
            })?);
        }
        TeardownHook::AddressSpace => release_address_space(ctx, path)?,
    }
    Ok(())
}

fn release_ports(ctx: &mut TeardownContext<'_>) -> clean_slate_port::PortReleaseCounts {
    port::on_holder_exit(HolderId(ctx.process_id), ctx.instance_generation)
}

fn release_display_presenter(ctx: &mut TeardownContext<'_>) -> usize {
    crate::device::display::release_presenter_for_holder(HolderId(ctx.process_id), ctx.allocator)
}

fn release_input_consumer(ctx: &mut TeardownContext<'_>) {
    input::release_consumer_for_holder(HolderId(ctx.process_id));
}

fn release_work_set(ctx: &mut TeardownContext<'_>) -> usize {
    work_set::on_holder_exit(HolderId(ctx.process_id))
}

fn release_shared_mappings(ctx: &mut TeardownContext<'_>) -> Result<usize, &'static str> {
    debug_assert!(
        crate::mm::shared_buffer::window_root(ctx.process_id)
            .is_none_or(|root| root == ctx.address_space_root),
        "shared window was built in a different root than the one being torn down"
    );
    let removed = crate::mm::shared_buffer::teardown_process(ctx.process_id, ctx.allocator);
    if crate::mm::shared_buffer::mapping_count(ctx.process_id) != 0 {
        return Err("shared-mapping teardown left rows for the exiting process");
    }
    Ok(removed)
}

fn release_address_space(
    ctx: &mut TeardownContext<'_>,
    path: &TeardownPath,
) -> Result<(), &'static str> {
    let process_record = unsafe {
        process_registry_mut()
            .get_mut(ctx.process_id)
            .ok_or(path.record_missing)?
    };
    if process_record.resource_domain.dispatch_root_frame() != ctx.address_space_root {
        return Err("process address space was replaced while teardown hooks held its root");
    }
    if current_root_frame_address() == ctx.address_space_root {
        return Err("teardown would free the active address-space root");
    }
    let destroyed = match process_record.resource_domain.take_address_space() {
        Some(address_space) => destroy_process_address_space(&address_space, ctx.allocator),
        None => Err(path.address_space_missing),
    };
    if !path.best_effort {
        destroyed?;
    }
    if !path.process_ran {
        process_record.live_threads = 0;
    }
    let reaped = reap_process_record(process_record);
    destroyed.and(reaped)
}

fn run_exit_teardown_hooks(
    ctx: &mut TeardownContext<'_>,
    path: &TeardownPath,
) -> Result<
    (
        IpcProcessResources,
        ThreadProcessResources,
        HolderReleaseCounts,
    ),
    &'static str,
> {
    let mut released = ReleasedResources::default();
    run_teardown_hooks(ctx, path, |hook, ctx| {
        run_teardown_hook(hook, ctx, path, &mut released)
    })?;
    Ok((
        released
            .ipc
            .ok_or("teardown hook order omitted IPC endpoint release")?,
        released
            .threads
            .ok_or("teardown hook order omitted thread reap")?,
        released.holder,
    ))
}

/// How [`rollback_registered_process`] dismantles a process whose record was
/// inserted but which was never dispatched.
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
pub(crate) struct RegistrationRollback {
    pub(crate) revokes_capabilities: bool,
    /// Run every step and report the first failure instead of stopping at it.
    pub(crate) best_effort: bool,
    pub(crate) process_missing: &'static str,
    pub(crate) address_space_missing: &'static str,
}

/// Dismantles a registered, never-dispatched process through the shared hooks,
/// then releases its registry slot. Holder-exit bookkeeping hooks are skipped
/// because the process never ran; the caller discards any scheduler thread.
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
pub(crate) fn rollback_registered_process(
    process_id: u64,
    allocator: &mut PageAllocator,
    rollback: RegistrationRollback,
) -> Result<(), &'static str> {
    let path = TeardownPath {
        process_ran: false,
        revokes_capabilities: rollback.revokes_capabilities,
        best_effort: rollback.best_effort,
        record_missing: rollback.process_missing,
        address_space_missing: rollback.address_space_missing,
    };
    let mut ctx =
        TeardownContext::for_registered(process_id, allocator).ok_or(rollback.process_missing)?;
    let mut released = ReleasedResources::default();
    let hooks = run_teardown_hooks(&mut ctx, &path, |hook, ctx| {
        run_teardown_hook(hook, ctx, &path, &mut released)
    });
    if !rollback.best_effort {
        hooks?;
    }
    let slot_released = unsafe { process_registry_mut().release_reaped(process_id) };
    hooks.and(slot_released)
}

#[allow(dead_code)]
pub(crate) fn teardown_current_process(
    allocator: &mut PageAllocator,
    kernel_root_frame: u64,
    status: u64,
    faulted: bool,
) -> Result<DomainTeardownResult, &'static str> {
    let (process_id, instance_generation) = without_interrupts(|| unsafe {
        let scheduler = scheduler_mut();
        let current_index = scheduler
            .current_thread
            .ok_or("process teardown required a current scheduler thread")?;
        let current = *scheduler
            .threads
            .get(current_index)
            .ok_or("scheduler current thread slot exceeded fixed scheduler capacity")?;
        if current.kind != ThreadKind::User {
            return Err("process teardown required a userspace current thread");
        }
        let retired_siblings =
            scheduler.retire_sibling_threads_for_process(current.owner_process_id, current.id);
        let process_record = process_registry_mut()
            .get_mut(current.owner_process_id)
            .ok_or("teardown process was missing from registry")?;
        let instance_generation = process_record.instance_generation;
        let current_thread = scheduler
            .threads
            .get_mut(current_index)
            .ok_or("scheduler current thread slot exceeded fixed scheduler capacity")?;
        let should_destroy = begin_thread_exit(process_record, current_thread, status, faulted)?;
        let retired_siblings_u16 = u16::try_from(retired_siblings)
            .map_err(|_| "retired sibling thread count overflowed process accounting")?;
        if process_record.live_threads < retired_siblings_u16 {
            return Err("process thread accounting underflow during teardown");
        }
        process_record.live_threads -= retired_siblings_u16;
        if process_record.live_threads == 0 && !should_destroy {
            finalize_process_exit(process_record, status)?;
        }
        if process_record.live_threads != 0 {
            return Err("process teardown left live threads after sibling retirement");
        }
        Ok::<(u64, InstanceGeneration), &'static str>((
            current.owner_process_id,
            instance_generation,
        ))
    })?;

    let next_stack_pointer =
        without_interrupts(|| with_scheduler(|scheduler| scheduler.finish_current_thread()))?;
    let released_resources = resource_snapshot(process_id)?;
    activate_address_space_root(kernel_root_frame);
    // Drop Linux fd projections before IPC capability teardown so a replacement
    // process (same pid, new generation) cannot observe a stale table (#95).
    linux_fd::release_for_process(process_id, instance_generation);
    #[cfg(feature = "m9-linux-trace")]
    crate::syscall::linux::trace::release_process(process_id, instance_generation);
    #[cfg(not(any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test"
    )))]
    {
        crate::process::linux_mem::release_for_process(process_id, instance_generation, allocator);
        crate::process::linux_signal::release_for_process(process_id, instance_generation);
    }
    #[cfg(not(any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test"
    )))]
    crate::syscall::linux::poll::clear_poll_interest_for_pid(process_id);
    linux_fd::release_for_process_by_pid(process_id);
    let registry_live = |check_pid: u64| unsafe { process_registry_mut().get(check_pid).is_some() };
    linux_fd::release_stale_registry_slots(&registry_live);
    #[cfg(feature = "m8-linux-image")]
    crate::process::linux_proc::table::table_mut().retire_stale_live_slots(&registry_live);
    let mut ctx = TeardownContext::for_registered(process_id, allocator)
        .ok_or(CURRENT_TEARDOWN.record_missing)?;
    let (released_ipc, reaped_threads, released_holder) =
        run_exit_teardown_hooks(&mut ctx, &CURRENT_TEARDOWN)?;
    if next_stack_pointer.is_some() {
        prepare_current_scheduler_thread_dispatch()?;
    }
    unsafe { process_registry_mut().release_reaped(process_id)? };
    if released_ipc.owned_endpoints != released_resources.ipc_endpoints
        || released_ipc.held_capabilities != released_resources.ipc_handles
    {
        return Err("IPC teardown counts diverged from the recorded process snapshot");
    }
    if reaped_threads.threads != released_resources.threads
        || reaped_threads.kernel_stacks != released_resources.kernel_stacks
    {
        return Err("scheduler teardown counts diverged from the recorded process snapshot");
    }
    released_holder.matches(&released_resources)?;
    Ok(DomainTeardownResult {
        process_id,
        exit_status: status,
        released_resources,
        next_stack_pointer,
    })
}

#[allow(dead_code)]
pub(crate) fn teardown_process_by_id(
    allocator: &mut PageAllocator,
    kernel_root_frame: u64,
    process_id: u64,
    status: u64,
    faulted: bool,
) -> Result<DomainTeardownResult, &'static str> {
    if process_id == KERNEL_PROCESS_ID {
        return Err("kernel process cannot be torn down through lifecycle control");
    }
    if faulted {
        return Err("supervisor-initiated teardown does not model faulted exit yet");
    }

    without_interrupts(|| unsafe {
        let scheduler = scheduler_mut();
        let current_process = match scheduler.current_userspace_process_id() {
            Ok(pid) => Some(pid),
            Err("scheduler had no current thread") | Err("current thread was not userspace") => {
                None
            }
            Err(message) => return Err(message),
        };
        if current_process == Some(process_id) {
            return Err("cannot externally teardown the currently running userspace process");
        }
        let process_record = process_registry_mut()
            .get_mut(process_id)
            .ok_or("teardown target process was missing from registry")?;
        if !matches!(
            process_record.state,
            ProcessState::Ready
                | ProcessState::Running
                | ProcessState::Faulted
                | ProcessState::Exiting
        ) {
            return Err("teardown target process was not live");
        }
        let exited_threads = scheduler.force_exit_all_threads_for_process(process_id)?;
        if process_record.live_threads
            < u16::try_from(exited_threads)
                .map_err(|_| "force-exit thread count overflowed process live thread accounting")?
        {
            return Err("process thread accounting underflow during external teardown");
        }
        process_record.live_threads -= u16::try_from(exited_threads)
            .map_err(|_| "force-exit thread count overflowed process live thread accounting")?;
        if process_record.live_threads != 0 {
            return Err("external teardown left live threads after force-exit");
        }
        finalize_process_exit(process_record, status)?;
        Ok::<(), &'static str>(())
    })?;

    let caller_root = current_root_frame_address();
    let released_resources = resource_snapshot(process_id)?;
    let mut ctx = TeardownContext::for_registered(process_id, allocator)
        .ok_or(EXTERNAL_TEARDOWN.record_missing)?;
    activate_address_space_root(kernel_root_frame);
    linux_fd::release_for_process(process_id, ctx.instance_generation);
    let teardown_result = run_exit_teardown_hooks(&mut ctx, &EXTERNAL_TEARDOWN);
    activate_address_space_root(caller_root);
    let (released_ipc, reaped_threads, released_holder) = teardown_result?;
    unsafe { process_registry_mut().release_reaped(process_id)? };
    if released_ipc.owned_endpoints != released_resources.ipc_endpoints
        || released_ipc.held_capabilities != released_resources.ipc_handles
    {
        return Err("IPC teardown counts diverged from the recorded external teardown snapshot");
    }
    if reaped_threads.threads != released_resources.threads
        || reaped_threads.kernel_stacks != released_resources.kernel_stacks
    {
        return Err(
            "scheduler teardown counts diverged from the recorded external teardown snapshot",
        );
    }
    released_holder.matches(&released_resources)?;
    Ok(DomainTeardownResult {
        process_id,
        exit_status: status,
        released_resources,
        next_stack_pointer: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::Path;
    use std::string::{String, ToString};
    use std::vec::Vec;

    fn test_allocator() -> PageAllocator {
        use crate::boot::uefi::normalize_memory_map_boxed;
        use uefi::mem::memory_map::{MemoryAttribute, MemoryDescriptor, MemoryType};

        let descriptors = [MemoryDescriptor {
            ty: MemoryType::CONVENTIONAL,
            phys_start: 0x10_0000,
            virt_start: 0,
            page_count: 1,
            att: MemoryAttribute::empty(),
        }];
        let map = normalize_memory_map_boxed(descriptors.iter(), &[]).expect("normalize map");
        PageAllocator::new(&map).expect("allocator")
    }

    /// Runs `path` against a recording hook that fails at each hook in `failing`.
    fn hooks_run_by(
        path: &TeardownPath,
        failing: &[TeardownHook],
    ) -> (Vec<TeardownHook>, Result<(), &'static str>) {
        let mut allocator = test_allocator();
        let mut ctx = TeardownContext {
            process_id: 41,
            instance_generation: InstanceGeneration(7),
            address_space_root: 0x20_0000,
            allocator: &mut allocator,
        };
        let mut ran = Vec::new();
        let result = run_teardown_hooks(&mut ctx, path, |hook, ctx| {
            assert_eq!(
                (
                    ctx.process_id,
                    ctx.instance_generation,
                    ctx.address_space_root
                ),
                (41, InstanceGeneration(7), 0x20_0000),
                "{hook:?} did not receive the teardown context"
            );
            ran.push(hook);
            if failing.contains(&hook) {
                Err(hook_failure(hook))
            } else {
                Ok(())
            }
        });
        (ran, result)
    }

    fn hook_failure(hook: TeardownHook) -> &'static str {
        match hook {
            TeardownHook::Port => "port hook failed",
            TeardownHook::SharedMappings => "shared-mapping hook failed",
            _ => "hook failed",
        }
    }

    fn assert_runs_once_each_in_order(ran: &[TeardownHook]) {
        for pair in ran.windows(2) {
            assert!(
                (pair[0] as u8) < (pair[1] as u8),
                "{:?} ran before {:?}, or twice",
                pair[0],
                pair[1]
            );
        }
    }

    #[cfg(not(any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test"
    )))]
    fn rollback_path(revokes_capabilities: bool, best_effort: bool) -> TeardownPath {
        TeardownPath {
            process_ran: false,
            revokes_capabilities,
            best_effort,
            record_missing: "rollback record missing",
            address_space_missing: "rollback address space missing",
        }
    }

    #[test]
    fn exit_teardown_runs_every_hook_once_in_order() {
        for path in [&CURRENT_TEARDOWN, &EXTERNAL_TEARDOWN] {
            let (ran, result) = hooks_run_by(path, &[]);
            assert_eq!(result, Ok(()));
            assert_eq!(ran.len(), TEARDOWN_HOOK_COUNT);
            assert_runs_once_each_in_order(&ran);
        }
        assert_eq!(
            hooks_run_by(&CURRENT_TEARDOWN, &[]).0,
            hooks_run_by(&EXTERNAL_TEARDOWN, &[]).0
        );
    }

    #[test]
    fn exit_teardown_stops_at_the_first_failed_hook() {
        let (ran, result) = hooks_run_by(
            &CURRENT_TEARDOWN,
            &[TeardownHook::Port, TeardownHook::SharedMappings],
        );
        assert_eq!(result, Err("port hook failed"));
        assert_eq!(ran.last(), Some(&TeardownHook::Port));
        assert!(!ran.contains(&TeardownHook::RevokeHolderCapabilities));
        assert!(!ran.contains(&TeardownHook::AddressSpace));
    }

    #[cfg(not(any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test"
    )))]
    #[test]
    fn rollback_runs_only_the_p4_hooks_once_in_order() {
        let (ran, result) = hooks_run_by(&rollback_path(true, false), &[]);
        assert_eq!(result, Ok(()));
        assert_runs_once_each_in_order(&ran);
        assert_eq!(
            ran,
            [
                TeardownHook::Port,
                TeardownHook::DisplayPresenter,
                TeardownHook::InputConsumer,
                TeardownHook::WorkSet,
                TeardownHook::RevokeHolderCapabilities,
                TeardownHook::SharedMappings,
                TeardownHook::AddressSpace,
            ]
        );

        let (without_capabilities, _) = hooks_run_by(&rollback_path(false, false), &[]);
        assert_eq!(
            without_capabilities,
            ran.iter()
                .copied()
                .filter(|hook| *hook != TeardownHook::RevokeHolderCapabilities)
                .collect::<Vec<_>>()
        );
    }

    #[cfg(not(any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test"
    )))]
    #[test]
    fn best_effort_rollback_runs_every_hook_and_reports_the_first_failure() {
        let (all, _) = hooks_run_by(&rollback_path(true, true), &[]);
        let (ran, result) = hooks_run_by(
            &rollback_path(true, true),
            &[TeardownHook::Port, TeardownHook::SharedMappings],
        );
        assert_eq!(result, Err("port hook failed"));
        assert_eq!(ran, all);

        let (stopped, result) = hooks_run_by(
            &rollback_path(true, false),
            &[TeardownHook::Port, TeardownHook::SharedMappings],
        );
        assert_eq!(result, Err("port hook failed"));
        assert_eq!(stopped, [TeardownHook::Port]);
    }

    #[test]
    fn input_consumer_hook_hands_the_seat_to_the_next_holder() {
        let exiting = HolderId(0x113);
        let next = HolderId(0x114);
        assert_eq!(input::bind_consumer(exiting), Ok(()));
        assert!(input::bind_consumer(next).is_err());

        let mut allocator = test_allocator();
        let mut ctx = TeardownContext {
            process_id: exiting.0,
            instance_generation: InstanceGeneration(1),
            address_space_root: 0x20_0000,
            allocator: &mut allocator,
        };
        // The slot functions, not `run_teardown_hook`: the port lane's hook trace requires every
        // teardown to start at the first hook.
        for _ in 0..2 {
            release_input_consumer(&mut ctx);
            assert_eq!(release_shared_mappings(&mut ctx), Ok(0));
            assert_eq!(input::consumer_bindings_for(exiting), 0);
        }
        assert_eq!(input::bind_consumer(next), Ok(()));
        assert_eq!(input::release_consumer_for_holder(next), 1);
    }

    #[test]
    fn shared_mapping_release_accounts_for_every_snapshot_row() {
        let snapshot = ResourceSnapshot {
            shared_mappings: 3,
            ..ResourceSnapshot::default()
        };
        let released = |presenter_grant_rows, shared_mappings| HolderReleaseCounts {
            presenter_grant_rows,
            shared_mappings,
            ..HolderReleaseCounts::default()
        };
        assert_eq!(released(0, 3).matches(&snapshot), Ok(()));
        assert_eq!(
            released(2, 1).matches(&snapshot),
            Ok(()),
            "presenter release unmaps its scanout grant rows before step 5"
        );
        assert!(
            released(0, 2).matches(&snapshot).is_err(),
            "a row unaccounted for"
        );
        assert!(
            released(2, 2).matches(&snapshot).is_err(),
            "a row created during teardown"
        );
    }

    /// Calls that dismantle part of a registered process. Outside the teardown
    /// block they are allowed only where no registered process is dismantled.
    const DIRECT_TEARDOWN_CALLS: [&str; 6] = [
        concat!("revoke_for_holder", "("),
        concat!("revoke_holder_tree", "("),
        concat!("revoke_holder_tree_visiting", "("),
        concat!("take_address_space", "("),
        concat!("destroy_process_address_space", "("),
        concat!("run_teardown_hooks", "("),
    ];

    /// `(file under kernel/src, enclosing function, call)`.
    const DIRECT_TEARDOWN_ALLOWLIST: &[(&str, &str, &str)] = &[
        // The shared teardown block and its entry points.
        (
            "process/domain.rs",
            "run_teardown_hook",
            "revoke_for_holder",
        ),
        (
            "process/domain.rs",
            "release_address_space",
            "take_address_space",
        ),
        (
            "process/domain.rs",
            "release_address_space",
            "destroy_process_address_space",
        ),
        (
            "process/domain.rs",
            "run_exit_teardown_hooks",
            "run_teardown_hooks",
        ),
        (
            "process/domain.rs",
            "rollback_registered_process",
            "run_teardown_hooks",
        ),
        ("process/domain.rs", "hooks_run_by", "run_teardown_hooks"),
        (
            "capability/mod.rs",
            "revoke_for_holder",
            "revoke_holder_tree_visiting",
        ),
        // Address spaces built before any process record exists.
        (
            "mm/fork_clone.rs",
            "fork_child_address_space",
            "destroy_process_address_space",
        ),
        (
            "process/linux_proc/fork.rs",
            "linux_fork",
            "destroy_process_address_space",
        ),
        (
            "process/linux_image.rs",
            "discard_address_space",
            "destroy_process_address_space",
        ),
        (
            "service/spawn.rs",
            "discard_address_space",
            "destroy_process_address_space",
        ),
        (
            "mm/address_space.rs",
            "verify_carve_out_attach_at_boot",
            "destroy_process_address_space",
        ),
        (
            "selftest/m10_nxe.rs",
            "launch_nx_fetch_probe",
            "destroy_process_address_space",
        ),
        (
            "selftest/m8_linux_hello.rs",
            "launch_native_sibling",
            "destroy_process_address_space",
        ),
        (
            "selftest/m8_linux_image.rs",
            "launch_native_sibling",
            "destroy_process_address_space",
        ),
        (
            "selftest/m9_linux_exec.rs",
            "maybe_finish",
            "destroy_process_address_space",
        ),
        (
            "selftest/m9_linux_exec.rs",
            "start_m9_linux_exec_self_test",
            "destroy_process_address_space",
        ),
        (
            "selftest/m9_low_va.rs",
            "launch_native_sibling",
            "destroy_process_address_space",
        ),
        (
            "selftest/m9_low_va.rs",
            "launch_fault_probe",
            "destroy_process_address_space",
        ),
        (
            "selftest/m9_low_va.rs",
            "maybe_finish",
            "destroy_process_address_space",
        ),
        (
            "selftest/m9_low_va.rs",
            "prove_two_low_roots",
            "destroy_process_address_space",
        ),
        (
            "selftest/m9_low_va.rs",
            "start_m9_low_va_self_test",
            "destroy_process_address_space",
        ),
        // Exec frees the image it replaced; the process stays registered.
        (
            "process/linux_exec.rs",
            "destroy_old_exec_address_space",
            "destroy_process_address_space",
        ),
        // Capability-table host tests; no process exists.
        (
            "capability/object.rs",
            "pending_bootstrap_grant_rolls_back_when_bootstrap_table_is_full",
            "revoke_for_holder",
        ),
        (
            "capability/input.rs",
            "root_grant_carries_exactly_the_requested_seat_zero_rights",
            "revoke_for_holder",
        ),
        // Shared-buffer host tests replay step 4 on a bare capability table.
        (
            "mm/shared_buffer/tests.rs",
            "teardown_both",
            "revoke_for_holder",
        ),
        (
            "mm/shared_buffer/tests.rs",
            "shared_buffer_owner_exit_orphans_reader_to_zero_page_and_reclaims_once",
            "revoke_for_holder",
        ),
        (
            "mm/shared_buffer/tests.rs",
            "shared_buffer_reader_exit_leaves_owner_mapping_live",
            "revoke_for_holder",
        ),
    ];

    fn is_identifier_byte(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'_'
    }

    /// The function a `fn` item on `line` declares, if any.
    fn declared_function(line: &str) -> Option<&str> {
        let bytes = line.as_bytes();
        let mut search_from = 0;
        while let Some(offset) = line[search_from..].find("fn ") {
            let start = search_from + offset;
            search_from = start + 3;
            if start > 0 && is_identifier_byte(bytes[start - 1]) {
                continue;
            }
            let name = &line[start + 3..];
            let len = name
                .bytes()
                .take_while(|byte| is_identifier_byte(*byte))
                .count();
            if len > 0 && matches!(name.as_bytes().get(len), Some(b'(' | b'<')) {
                return Some(&name[..len]);
            }
        }
        None
    }

    /// Every `(file, enclosing function, call)` for the calls in `DIRECT_TEARDOWN_CALLS`,
    /// with the `file:line` of each.
    fn direct_teardown_calls(root: &Path) -> Vec<((String, String, String), String)> {
        let mut files = Vec::new();
        let mut directories = std::vec![root.to_path_buf()];
        while let Some(directory) = directories.pop() {
            for entry in std::fs::read_dir(&directory).expect("read kernel source directory") {
                let path = entry.expect("kernel source entry").path();
                if path.is_dir() {
                    directories.push(path);
                } else if path.extension().is_some_and(|extension| extension == "rs") {
                    files.push(path);
                }
            }
        }
        files.sort();

        let mut calls = Vec::new();
        for file in files {
            let relative = file
                .strip_prefix(root)
                .expect("source file under kernel/src")
                .to_string_lossy()
                .replace('\\', "/");
            let source = std::fs::read_to_string(&file).expect("read kernel source file");
            let mut function = String::from("<module>");
            for (index, line) in source.lines().enumerate() {
                let code = line.split("//").next().unwrap_or_default();
                if let Some(name) = declared_function(code) {
                    function = name.to_string();
                }
                for call in DIRECT_TEARDOWN_CALLS {
                    let name = &call[..call.len() - 1];
                    for (offset, _) in code.match_indices(call) {
                        let prefix = code[..offset].trim_end();
                        let starts_identifier =
                            offset == 0 || !is_identifier_byte(code.as_bytes()[offset - 1]);
                        if starts_identifier && !prefix.ends_with("fn") {
                            calls.push((
                                (relative.clone(), function.clone(), name.to_string()),
                                std::format!("{relative}:{}", index + 1),
                            ));
                        }
                    }
                }
            }
        }
        calls
    }

    #[test]
    fn only_the_teardown_block_dismantles_registered_processes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let calls = direct_teardown_calls(&root);
        let allowed: BTreeSet<(String, String, String)> = DIRECT_TEARDOWN_ALLOWLIST
            .iter()
            .map(|(file, function, call)| {
                (file.to_string(), function.to_string(), call.to_string())
            })
            .collect();
        let found: BTreeSet<(String, String, String)> =
            calls.iter().map(|(site, _)| site.clone()).collect();

        let unexpected: Vec<String> = calls
            .iter()
            .filter(|(site, _)| !allowed.contains(site))
            .map(|((_, function, call), location)| {
                std::format!("{location}: `{call}` in `{function}`")
            })
            .collect();
        assert!(
            unexpected.is_empty(),
            "direct teardown calls outside the shared hook block:\n  {}\nDismantle a registered \
             process with `domain::rollback_registered_process` or a teardown path. Only a path \
             that never registered a process may call these directly; name it in \
             DIRECT_TEARDOWN_ALLOWLIST.",
            unexpected.join("\n  ")
        );
        let stale: Vec<String> = allowed
            .difference(&found)
            .map(|(file, function, call)| std::format!("{file}: `{call}` in `{function}`"))
            .collect();
        assert!(
            stale.is_empty(),
            "DIRECT_TEARDOWN_ALLOWLIST names calls that no longer exist:\n  {}",
            stale.join("\n  ")
        );
    }
}
