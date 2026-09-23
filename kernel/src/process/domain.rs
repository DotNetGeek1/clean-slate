use super::begin_thread_exit;
use super::finalize_process_exit;
use super::linux_fd;
use super::live_instance_generation;
use super::process_registry_mut;
use super::reap_process_record;
use super::ProcessState;
use super::KERNEL_PROCESS_ID;
use crate::arch::x86_64::cpu::without_interrupts;
use clean_slate_capability::HolderId;

use crate::capability::bootstrap_grant::discard_bootstrap_grants_for_holder;
use crate::capability::object::{
    reclaim_object_requests_for_holder, recover_object_queue_for_service_holder_exit,
};
use crate::capability::{revoke_for_holder, revoke_for_process_resource};
use crate::ipc::endpoint_table_mut;
use crate::ipc::IpcProcessResources;
use crate::mm::address_space::activate_address_space_root;
use crate::mm::address_space::destroy_process_address_space;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
use crate::sched::dispatch::prepare_current_scheduler_thread_dispatch;
use crate::sched::scheduler_mut;
use crate::sched::with_scheduler;
use crate::sched::ThreadKind;
use crate::sched::ThreadProcessResources;
use crate::service::instance_generation::live_instance_generation_for_pid;
use crate::service::net_bridge::{
    notify_holder_exit_for_process, reclaim_net_requests_for_holder,
    recover_net_queue_for_service_holder_exit,
};

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
    Ok(ResourceSnapshot {
        user_pages: address_space.user_pages,
        page_table_frames: address_space.page_table_frames,
        kernel_stacks: thread_resources.kernel_stacks,
        ipc_endpoints: ipc_resources.owned_endpoints,
        ipc_handles: ipc_resources.held_capabilities,
        threads: thread_resources.threads,
        runnable_threads: thread_resources.runnable_threads,
    })
}

#[allow(dead_code)]
pub(crate) fn teardown_current_process(
    allocator: &mut PageAllocator,
    kernel_root_frame: u64,
    status: u64,
    faulted: bool,
) -> Result<DomainTeardownResult, &'static str> {
    let process_id = without_interrupts(|| unsafe {
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
        Ok::<u64, &'static str>(current.owner_process_id)
    })?;

    let next_stack_pointer =
        without_interrupts(|| with_scheduler(|scheduler| scheduler.finish_current_thread()))?;
    let released_resources = resource_snapshot(process_id)?;
    activate_address_space_root(kernel_root_frame);
    // Drop Linux fd projections before IPC capability teardown so a replacement
    // process (same pid, new generation) cannot observe a stale table (#95).
    if let Some(generation) = live_instance_generation(process_id) {
        linux_fd::release_for_process(process_id, generation);
        #[cfg(not(any(
            feature = "m1-self-test",
            feature = "m2-double-fault-self-test",
            feature = "m2-timer-self-test"
        )))]
        {
            crate::process::linux_mem::release_for_process(process_id, generation);
            crate::process::linux_signal::release_for_process(process_id, generation);
        }
        #[cfg(not(any(
            feature = "m1-self-test",
            feature = "m2-double-fault-self-test",
            feature = "m2-timer-self-test"
        )))]
        crate::syscall::linux::poll::clear_poll_interest_for_pid(process_id);
    }
    linux_fd::release_for_process_by_pid(process_id);
    let registry_live = |check_pid: u64| unsafe { process_registry_mut().get(check_pid).is_some() };
    linux_fd::release_stale_registry_slots(&registry_live);
    #[cfg(feature = "m8-linux-image")]
    crate::process::linux_proc::table::table_mut().retire_stale_live_slots(&registry_live);
    let released_ipc: IpcProcessResources =
        unsafe { endpoint_table_mut().teardown_resources_for_pid(process_id)? };
    let holder = HolderId(process_id);
    let holder_generation = live_instance_generation_for_pid(holder.0).map(|g| u64::from(g.0));
    recover_object_queue_for_service_holder_exit(holder);
    reclaim_object_requests_for_holder(holder);
    recover_net_queue_for_service_holder_exit(holder.0);
    let net_reclaimed = reclaim_net_requests_for_holder(holder.0);
    let sessions_cleared = crate::capability::network::on_holder_exit(holder);
    if net_reclaimed == 0 && sessions_cleared > 0 {
        if let Some(generation) = holder_generation {
            notify_holder_exit_for_process(holder.0, generation);
        }
    }
    revoke_for_holder(holder);
    revoke_for_process_resource(process_id);
    discard_bootstrap_grants_for_holder(holder);
    let reaped_threads: ThreadProcessResources = without_interrupts(|| unsafe {
        let scheduler = scheduler_mut();
        let resources = scheduler.resources_for_process(process_id);
        let reaped_threads = scheduler.reap_threads_for_process(process_id)?;
        if reaped_threads != resources.threads {
            return Err("scheduler thread cleanup count diverged from teardown snapshot");
        }
        Ok::<ThreadProcessResources, &'static str>(resources)
    })?;
    {
        let process_record = unsafe {
            process_registry_mut()
                .get_mut(process_id)
                .ok_or("process missing from registry during resource teardown")?
        };
        let address_space = process_record
            .resource_domain
            .take_address_space()
            .ok_or("process address space was missing during teardown")?;
        destroy_process_address_space(&address_space, allocator)?;
        reap_process_record(process_record)?;
    }
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
    activate_address_space_root(kernel_root_frame);
    let teardown_result = (|| {
        if let Some(generation) = live_instance_generation(process_id) {
            linux_fd::release_for_process(process_id, generation);
        }
        let released_ipc: IpcProcessResources =
            unsafe { endpoint_table_mut().teardown_resources_for_pid(process_id)? };
        let holder = HolderId(process_id);
        let holder_generation = live_instance_generation_for_pid(holder.0).map(|g| u64::from(g.0));
        recover_object_queue_for_service_holder_exit(holder);
        reclaim_object_requests_for_holder(holder);
        recover_net_queue_for_service_holder_exit(holder.0);
        let net_reclaimed = reclaim_net_requests_for_holder(holder.0);
        let sessions_cleared = crate::capability::network::on_holder_exit(holder);
        if net_reclaimed == 0 && sessions_cleared > 0 {
            if let Some(generation) = holder_generation {
                notify_holder_exit_for_process(holder.0, generation);
            }
        }
        revoke_for_holder(holder);
        revoke_for_process_resource(process_id);
        discard_bootstrap_grants_for_holder(holder);
        let reaped_threads: ThreadProcessResources = without_interrupts(|| unsafe {
            let scheduler = scheduler_mut();
            let resources = scheduler.resources_for_process(process_id);
            let reaped_threads = scheduler.reap_threads_for_process(process_id)?;
            if reaped_threads != resources.threads {
                return Err(
                    "scheduler thread cleanup count diverged from external teardown snapshot",
                );
            }
            Ok::<ThreadProcessResources, &'static str>(resources)
        })?;
        {
            let process_record = unsafe {
                process_registry_mut()
                    .get_mut(process_id)
                    .ok_or("process missing from registry during external resource teardown")?
            };
            let address_space = process_record
                .resource_domain
                .take_address_space()
                .ok_or("process address space was missing during external teardown")?;
            destroy_process_address_space(&address_space, allocator)?;
            reap_process_record(process_record)?;
        }
        Ok::<(IpcProcessResources, ThreadProcessResources), &'static str>((
            released_ipc,
            reaped_threads,
        ))
    })();
    activate_address_space_root(caller_root);
    let (released_ipc, reaped_threads) = teardown_result?;
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
    Ok(DomainTeardownResult {
        process_id,
        exit_status: status,
        released_resources,
        next_stack_pointer: None,
    })
}
