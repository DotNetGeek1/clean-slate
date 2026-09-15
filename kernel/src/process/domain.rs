use super::begin_thread_exit;
use super::finalize_process_exit;
use super::process_registry_mut;
use super::reap_process_record;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::ipc::endpoint_table_mut;
use crate::ipc::IpcProcessResources;
use crate::mm::address_space::activate_address_space_root;
use crate::mm::address_space::destroy_process_address_space;
use crate::mm::frame_allocator::PageAllocator;
use crate::sched::dispatch::prepare_current_scheduler_thread_dispatch;
use crate::sched::scheduler_mut;
use crate::sched::with_scheduler;
use crate::sched::ThreadKind;
use crate::sched::ThreadProcessResources;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DomainTeardownResult {
    pub(crate) process_id: u64,
    pub(crate) exit_status: u64,
    pub(crate) released_resources: ResourceSnapshot,
    pub(crate) next_stack_pointer: Option<u64>,
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
        let current = scheduler.threads[current_index];
        if current.kind != ThreadKind::User {
            return Err("process teardown required a userspace current thread");
        }
        let retired_siblings =
            scheduler.retire_sibling_threads_for_process(current.owner_process_id, current.id);
        let process_record = process_registry_mut()
            .get_mut(current.owner_process_id)
            .ok_or("teardown process was missing from registry")?;
        let current_thread = &mut scheduler.threads[current_index];
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
    let released_ipc: IpcProcessResources =
        unsafe { endpoint_table_mut().teardown_resources_for_pid(process_id)? };
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
