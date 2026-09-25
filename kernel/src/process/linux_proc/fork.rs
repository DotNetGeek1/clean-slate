//! Linux `fork` — bounded eager address-space copy (#102).

#![cfg_attr(not(feature = "m9-linux-proc-self-test"), allow(dead_code))]

use super::table::{table, table_mut, ProcId, LINUX_MAX_PROC_ENTRIES};
use crate::arch::x86_64::context_switch::build_fork_child_userspace_frame;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::capability::inherit_capabilities_for_fork;
use crate::capability::revoke_for_holder;
use crate::mm::address_space::destroy_process_address_space;
use crate::mm::fork_clone::{fork_child_address_space, LINUX_FORK_MAX_PAGES};
use crate::mm::frame_allocator::PageAllocator;
use crate::process::id_allocator::id_allocator_mut;
use crate::ipc::endpoint_table_mut;
use crate::process::linux_fd;
use crate::process::linux_image::LINUX_USER_WINDOW_BASE;
use crate::process::linux_mem;
use crate::process::linux_signal;
use crate::process::{
    personality::ExecutionPersonality, process_registry_mut, reap_process_record, Process,
    ProcessState, ResourceDomain,
};
use crate::sched::{scheduler_mut, Thread, ThreadKind, ThreadState, TASK_COUNT};
use clean_slate_capability::HolderId;
use clean_slate_linux_abi::{EAGAIN, ENOMEM, ESRCH};
use clean_slate_service_lifecycle::InstanceGeneration;
use x86_64::VirtAddr;
#[cfg(feature = "m9-userspace-self-test")]
use core::sync::atomic::{AtomicUsize, Ordering};

#[cfg(feature = "m9-userspace-self-test")]
const FORK_DIAG_LIMIT: usize = 8;
#[cfg(feature = "m9-userspace-self-test")]
static FORK_DIAG_COUNT: AtomicUsize = AtomicUsize::new(0);

struct ForkChildCleanup {
    child_gen: InstanceGeneration,
    registry_committed: bool,
    proc_registered: bool,
    caps_inherited: bool,
    fd_inherited: bool,
}

pub(crate) fn linux_fork(
    parent_pid: u64,
    parent_gen: InstanceGeneration,
    parent_frame: &SyscallContext,
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
) -> Result<u64, clean_slate_linux_abi::LinuxErrno> {
    if table().occupied() >= LINUX_MAX_PROC_ENTRIES {
        #[cfg(feature = "m9-userspace-self-test")]
        fork_diag("proc-table-full", 0);
        return Err(EAGAIN);
    }
    let child_space = match without_interrupts(|| unsafe {
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
    }) {
        Ok(space) => space,
        Err(ESRCH) => return Err(ESRCH),
        Err(ENOMEM) => {
            #[cfg(feature = "m9-userspace-self-test")]
            fork_diag("clone-as-ENOMEM", 0);
            return Err(ENOMEM);
        }
        Err(_) => {
            #[cfg(feature = "m9-userspace-self-test")]
            fork_diag("clone-as", 0);
            return Err(EAGAIN);
        }
    };

    let (child_pid, child_tid) = match without_interrupts(|| -> Result<(u64, u64), &'static str> {
        let ids = unsafe { id_allocator_mut() };
        Ok((ids.allocate_pid()?, ids.allocate_tid()?))
    }) {
        Ok(ids) => ids,
        Err(_) => {
            let _ = destroy_process_address_space(&child_space, allocator);
            #[cfg(feature = "m9-userspace-self-test")]
            fork_diag("id-alloc", 0);
            return Err(EAGAIN);
        }
    };

    let child_frame_ptr = match build_fork_child_userspace_frame(kernel_stack_top, parent_frame) {
        Ok(ptr) => ptr,
        Err(_) => {
            let _ = destroy_process_address_space(&child_space, allocator);
            #[cfg(feature = "m9-userspace-self-test")]
            fork_diag("child-frame", child_pid);
            return Err(EAGAIN);
        }
    };

    let child_gen = match without_interrupts(|| -> Result<InstanceGeneration, &'static str> {
        unsafe {
            if scheduler_slot >= scheduler_mut().thread_capacity() {
                let _ = destroy_process_address_space(&child_space, allocator);
                return Err("scheduler-slot-range");
            }
            if scheduler_mut().threads[scheduler_slot].state != ThreadState::Empty {
                let _ = destroy_process_address_space(&child_space, allocator);
                return Err("scheduler-slot-occupied");
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
            if let Err(_message) = process_registry_mut().insert(process) {
                let _ =
                    crate::process::linux_image::rollback_registered_process(child_pid, allocator);
                return Err("registry-insert");
            }
            let generation = process_registry_mut()
                .instance_generation(child_pid)
                .ok_or("registry-generation")?;
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
                return Err("scheduler-configure");
            }
            Ok(generation)
        }
    }) {
        Ok(gen) => gen,
        Err(reason) => {
            #[cfg(feature = "m9-userspace-self-test")]
            fork_diag(reason, child_pid);
            return Err(EAGAIN);
        }
    };

    let mut cleanup = ForkChildCleanup {
        child_gen,
        registry_committed: true,
        proc_registered: false,
        caps_inherited: false,
        fd_inherited: false,
    };

    if linux_fd::inherit_for_child(parent_pid, parent_gen, child_pid, child_gen).is_err() {
        abort_fork_child(child_pid, &cleanup, allocator);
        #[cfg(feature = "m9-userspace-self-test")]
        fork_diag("inherit-fd", child_pid);
        return Err(EAGAIN);
    }
    cleanup.fd_inherited = true;

    if inherit_capabilities_for_fork(HolderId(parent_pid), HolderId(child_pid)).is_err() {
        abort_fork_child(child_pid, &cleanup, allocator);
        #[cfg(feature = "m9-userspace-self-test")]
        fork_diag("inherit-caps", child_pid);
        return Err(EAGAIN);
    }
    cleanup.caps_inherited = true;

    if without_interrupts(|| -> Result<(), clean_slate_linux_abi::LinuxErrno> {
        let handle = unsafe { endpoint_table_mut() }
            .grant_console_capability_for_pid(child_pid)
            .map_err(|_| EAGAIN)?;
        linux_fd::rebind_forked_console_stdio(child_pid, child_gen, handle, handle)
    })
    .is_err()
    {
        abort_fork_child(child_pid, &cleanup, allocator);
        #[cfg(feature = "m9-userspace-self-test")]
        fork_diag("rebind-stdio", child_pid);
        return Err(EAGAIN);
    }

    if table_mut()
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
        abort_fork_child(child_pid, &cleanup, allocator);
        #[cfg(feature = "m9-userspace-self-test")]
        fork_diag("proc-register", child_pid);
        return Err(EAGAIN);
    }
    cleanup.proc_registered = true;
    let runtime_state = linux_mem::clone_for_fork(parent_pid, parent_gen, child_pid, child_gen)
        .and_then(|()| linux_signal::clone_for_fork(parent_pid, parent_gen, child_pid, child_gen));
    if let Err(errno) = runtime_state {
        linux_mem::release_for_process(child_pid, child_gen, allocator);
        linux_signal::release_for_process(child_pid, child_gen);
        abort_fork_child(child_pid, &cleanup, allocator);
        #[cfg(feature = "m9-userspace-self-test")]
        fork_diag("runtime-clone", child_pid);
        return Err(errno);
    }

    Ok(child_pid)
}

fn abort_fork_child(
    child_pid: u64,
    cleanup: &ForkChildCleanup,
    allocator: &mut PageAllocator,
) {
    if cleanup.fd_inherited {
        linux_fd::release_for_process(child_pid, cleanup.child_gen);
    }
    if cleanup.caps_inherited {
        revoke_for_holder(HolderId(child_pid));
    }
    if cleanup.proc_registered {
        table_mut().reap_zombie(ProcId {
            pid: child_pid,
            generation: cleanup.child_gen,
        });
    }
    if cleanup.registry_committed {
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
}

#[cfg(feature = "m9-userspace-self-test")]
fn fork_diag(reason: &str, child_pid: u64) {
    if FORK_DIAG_COUNT.fetch_add(1, Ordering::Relaxed) >= FORK_DIAG_LIMIT {
        return;
    }
    use crate::capability::with_capability_space;
    use crate::diagnostics::log::kernel_log_fmt;
    let (proc_live, sched_occ, reg_occ, cap_live, fd_pool) = without_interrupts(|| unsafe {
        (
            table().occupied(),
            scheduler_mut().occupied_thread_slots(),
            process_registry_mut().occupied_slots(),
            with_capability_space(|t| t.live_count()),
            linux_fd::open_description_pool_live_count(),
        )
    });
    kernel_log_fmt(format_args!(
        "[M9  ] fork fail reason={reason} child={child_pid} proc={proc_live}/{LINUX_MAX_PROC_ENTRIES} sched={sched_occ}/{TASK_COUNT} reg={reg_occ} caps={cap_live} fd_pool={fd_pool}\n"
    ));
    without_interrupts(|| unsafe {
        let scheduler = scheduler_mut();
        for slot in 0..TASK_COUNT {
            let thread = &scheduler.threads[slot];
            if thread.state == ThreadState::Empty {
                continue;
            }
            kernel_log_fmt(format_args!(
                "[M9  ] fork slot={slot} pid={} state={:?}\n",
                thread.owner_process_id, thread.state
            ));
        }
    });
}

