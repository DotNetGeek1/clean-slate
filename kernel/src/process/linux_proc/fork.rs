//! Linux `fork` — bounded eager address-space copy (#102).

#![cfg_attr(not(feature = "m9-linux-proc-self-test"), allow(dead_code))]

use super::table::{table, table_mut, ProcId, LINUX_MAX_PROC_ENTRIES};
use crate::arch::x86_64::context_switch::build_fork_child_userspace_frame;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::capability::capability_space_mut;
use crate::mm::address_space::destroy_process_address_space;
use crate::mm::fork_clone::{fork_child_address_space, LINUX_FORK_MAX_PAGES};
use crate::mm::frame_allocator::PageAllocator;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::linux_fd;
use crate::process::linux_image::LINUX_USER_WINDOW_BASE;
use crate::process::linux_mem;
use crate::process::linux_signal;
use crate::process::{
    personality::ExecutionPersonality, process_registry_mut, reap_process_record, Process,
    ProcessState, ResourceDomain,
};
use crate::sched::{scheduler_mut, Thread, ThreadKind, ThreadState};
use clean_slate_capability::CapabilityHandle;
use clean_slate_capability::{delegate, list_holder, HolderId, MAX_SLOTS};
use clean_slate_linux_abi::{EAGAIN, ENOMEM, ESRCH};
use clean_slate_service_lifecycle::InstanceGeneration;
use x86_64::VirtAddr;

pub(crate) fn linux_fork(
    parent_pid: u64,
    parent_gen: InstanceGeneration,
    parent_frame: &SyscallContext,
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
) -> Result<u64, clean_slate_linux_abi::LinuxErrno> {
    if table().occupied() >= LINUX_MAX_PROC_ENTRIES {
        return Err(EAGAIN);
    }
    let child_space = without_interrupts(|| unsafe {
        let parent = process_registry_mut().get(parent_pid).ok_or(ESRCH)?;
        let parent_space = parent
            .resource_domain
            .address_space()
            .ok_or(clean_slate_linux_abi::EINVAL)?;
        fork_child_address_space(
            parent_space,
            allocator,
            VirtAddr::new(LINUX_USER_WINDOW_BASE),
            LINUX_FORK_MAX_PAGES,
        )
        .map_err(|_| ENOMEM)
    })?;

    let (child_pid, child_tid) = without_interrupts(|| -> Result<(u64, u64), &'static str> {
        let ids = unsafe { id_allocator_mut() };
        Ok((ids.allocate_pid()?, ids.allocate_tid()?))
    })
    .map_err(|_| EAGAIN)?;

    let child_frame_ptr =
        build_fork_child_userspace_frame(kernel_stack_top, parent_frame).map_err(|_| EAGAIN)?;

    let child_gen = match without_interrupts(|| -> Result<InstanceGeneration, &'static str> {
        unsafe {
            if scheduler_slot >= scheduler_mut().thread_capacity() {
                let _ = destroy_process_address_space(&child_space, allocator);
                return Err("fork scheduler slot");
            }
            if scheduler_mut().threads[scheduler_slot].state != ThreadState::Empty {
                let _ = destroy_process_address_space(&child_space, allocator);
                return Err("fork scheduler slot occupied");
            }
            let process = Process {
                id: child_pid,
                instance_generation: InstanceGeneration(0),
                state: ProcessState::Ready,
                resource_domain: ResourceDomain::with_address_space(child_pid, child_space),
                live_threads: 1,
                exit_status: None,
                execution_personality: ExecutionPersonality::LinuxX86_64,
            };
            if let Err(message) = process_registry_mut().insert(process) {
                let _ = message;
                let _ =
                    crate::process::linux_image::rollback_registered_process(child_pid, allocator);
                return Err("fork registry");
            }
            let generation = process_registry_mut()
                .instance_generation(child_pid)
                .ok_or("fork generation")?;
            if scheduler_mut()
                .configure_thread(
                    scheduler_slot,
                    child_tid,
                    child_pid,
                    ThreadKind::User,
                    kernel_stack_top,
                    child_frame_ptr,
                    parent_frame.user_rip,
                )
                .is_err()
            {
                let _ =
                    crate::process::linux_image::rollback_registered_process(child_pid, allocator);
                return Err("fork configure");
            }
            Ok(generation)
        }
    }) {
        Ok(gen) => gen,
        Err(_) => return Err(EAGAIN),
    };

    if linux_fd::inherit_for_child(parent_pid, parent_gen, child_pid, child_gen).is_err()
        || delegate_all_caps(parent_pid, child_pid).is_err()
        || table_mut()
            .register(
                ProcId {
                    pid: child_pid,
                    generation: child_gen,
                },
                ProcId {
                    pid: parent_pid,
                    generation: parent_gen,
                },
            )
            .is_err()
    {
        abort_fork_child(child_pid, allocator);
        return Err(EAGAIN);
    }

    let runtime_state = linux_mem::clone_for_fork(parent_pid, parent_gen, child_pid, child_gen)
        .and_then(|()| linux_signal::clone_for_fork(parent_pid, parent_gen, child_pid, child_gen));
    if let Err(errno) = runtime_state {
        linux_mem::release_for_process(child_pid, child_gen, allocator);
        linux_signal::release_for_process(child_pid, child_gen);
        linux_fd::release_for_process(child_pid, child_gen);
        abort_fork_child(child_pid, allocator);
        return Err(errno);
    }

    Ok(child_pid)
}

fn abort_fork_child(child_pid: u64, allocator: &mut PageAllocator) {
    without_interrupts(|| {
        let registry = unsafe { process_registry_mut() };
        if let Some(record) = registry.get_mut(child_pid) {
            if let Some(space) = record.resource_domain.take_address_space() {
                let _ = destroy_process_address_space(&space, allocator);
            }
            record.live_threads = 0;
            let _ = reap_process_record(record);
            let _ = registry.release_reaped(child_pid);
        }
        for thread in unsafe { scheduler_mut() }.threads.iter_mut() {
            if thread.owner_process_id == child_pid {
                *thread = Thread::EMPTY;
            }
        }
    });
}

fn delegate_all_caps(parent_pid: u64, child_pid: u64) -> Result<(), ()> {
    let parent = HolderId(parent_pid);
    let child = HolderId(child_pid);
    let mut cursor = 0usize;
    let mut installed = [None; MAX_SLOTS];
    let mut count = 0usize;
    loop {
        let table = unsafe { capability_space_mut() };
        let Some((next_cursor, handle, record)) = list_holder(table, parent, cursor) else {
            break;
        };
        cursor = next_cursor + 1;
        if count >= MAX_SLOTS {
            rollback_delegated(&installed[..count]);
            return Err(());
        }
        match delegate(table, parent, handle, child, record.rights) {
            Ok(child_handle) => {
                installed[count] = Some(child_handle);
                count += 1;
            }
            Err(_) => {
                rollback_delegated(&installed[..count]);
                return Err(());
            }
        }
    }
    Ok(())
}

fn rollback_delegated(handles: &[Option<CapabilityHandle>]) {
    let table = unsafe { capability_space_mut() };
    for handle in handles.iter().flatten() {
        let _ = table.revoke(*handle);
    }
}
