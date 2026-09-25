//! Linux process/pipe syscall family (#102).

use super::table::LinuxSyscallHandler;

/// Handlers owned by the process family, or `None` if `nr` is not ours.
pub(crate) fn lookup_handler(nr: u64) -> Option<LinuxSyscallHandler> {
    #[cfg(feature = "m8-linux-image")]
    {
        return enabled::lookup(nr);
    }
    #[allow(unreachable_code)]
    {
        let _ = nr;
        None
    }
}

#[cfg(feature = "m8-linux-image")]
mod enabled {
    use super::super::exit::{exit_status_from_linux, switch_after_exit};
    use super::super::table::LinuxSyscallContext;
    use crate::arch::x86_64::context_switch::task_stack_top;
    use crate::arch::x86_64::cpu::without_interrupts;
    use crate::diagnostics::log::kernel_log_fmt;
    use crate::diagnostics::qemu::fatal_kernel_error;
    use crate::mm::address_space::kernel_root_frame;
    use crate::mm::user_mapping::{
        validate_user_pointer_range, validate_user_writable_pointer_range,
    };
    use crate::process::domain::teardown_current_process;
    use crate::process::linux_exec::{
        commit_exec, linux_errno_for_exec_error, prepare_linux_image, LinuxExecSpec,
        LINUX_EXEC_MAX_ARGS, LINUX_EXEC_MAX_ARG_BYTES, LINUX_EXEC_MAX_ENVS,
    };
    use crate::process::linux_fd;
    use crate::process::linux_image::{LINUX_CONVENTIONAL_LOAD_POLICY, LINUX_STACK_PAGES};
    use crate::process::linux_proc::exec_resolve::resolve_executable;
    use crate::process::linux_proc::{
        fork::linux_fork,
        pipe::{open_pipe_refs, pool_mut, wait_key_for_parent},
        table::{exit_status_word, table_mut, ProcId},
        wait::linux_wait4,
    };
    use crate::sched::wait::wake_all;
    use crate::sched::{scheduler_mut, task_stacks_mut, ThreadState};
    #[cfg(feature = "m9-linux-exec-self-test")]
    use crate::selftest::m9_linux_exec::handle_execve_selftest;
    use crate::sync::global_cell::GlobalCell;
    use crate::syscall::service_lifecycle_syscall_allocator_mut;
    use clean_slate_linux_abi::{
        LinuxSyscallRequest, LinuxSyscallResult, E2BIG, EFAULT, EINVAL, ENOMEM, SYS_EXECVE,
        SYS_EXIT_GROUP, SYS_FORK, SYS_GETPPID, SYS_PIPE, SYS_WAIT4,
    };

    pub(super) fn lookup(nr: u64) -> Option<super::LinuxSyscallHandler> {
        match nr {
            SYS_PIPE => Some(handle_sys_pipe),
            SYS_FORK => Some(handle_sys_fork),
            SYS_WAIT4 => Some(handle_sys_wait4),
            SYS_GETPPID => Some(handle_sys_getppid),
            SYS_EXIT_GROUP => Some(handle_sys_exit_group),
            SYS_EXECVE => Some(handle_sys_execve),
            _ => None,
        }
    }

    struct ExecCopyScratch {
        busy: bool,
        path: [u8; 256],
        path_len: usize,
        argv: [[u8; 128]; 16],
        argv_len: [usize; 16],
        argv_count: usize,
        envp: [[u8; 128]; 16],
        envp_len: [usize; 16],
        envp_count: usize,
    }

    static EXEC_SCRATCH: GlobalCell<ExecCopyScratch> = GlobalCell::new(ExecCopyScratch {
        busy: false,
        path: [0; 256],
        path_len: 0,
        argv: [[0; 128]; 16],
        argv_len: [0; 16],
        argv_count: 0,
        envp: [[0; 128]; 16],
        envp_len: [0; 16],
        envp_count: 0,
    });

    pub(crate) fn handle_sys_pipe(
        request: &LinuxSyscallRequest,
        ctx: &mut LinuxSyscallContext<'_>,
    ) -> LinuxSyscallResult {
        table_mut().ensure_proc_slot(ProcId {
            pid: ctx.pid,
            generation: ctx.instance_generation,
        })?;
        let user_ptr = request.args[0];
        if user_ptr == 0 {
            return Err(EFAULT);
        }
        validate_user_writable_pointer_range(user_ptr, 8).map_err(|_| EFAULT)?;
        let (read_ref, write_ref) = open_pipe_refs(pool_mut())?;
        let read_fd = linux_fd::alloc_pipe_end(ctx.pid, ctx.instance_generation, read_ref)?;
        let write_fd = linux_fd::alloc_pipe_end(ctx.pid, ctx.instance_generation, write_ref)?;
        let pair = [read_fd as u32, write_fd as u32];
        unsafe {
            core::ptr::copy_nonoverlapping(pair.as_ptr(), user_ptr as *mut u32, 2);
        }
        Ok(0)
    }

    pub(crate) fn handle_sys_fork(
        _request: &LinuxSyscallRequest,
        ctx: &mut LinuxSyscallContext<'_>,
    ) -> LinuxSyscallResult {
        table_mut().ensure_proc_slot(ProcId {
            pid: ctx.pid,
            generation: ctx.instance_generation,
        })?;
        let allocator = service_lifecycle_syscall_allocator_mut()
            .as_mut()
            .ok_or(ENOMEM)?;
        let slot = find_empty_scheduler_slot()?;
        let stacks = unsafe { task_stacks_mut() };
        let stack_top = task_stack_top(&stacks[slot]);
        let child_pid = linux_fork(
            ctx.pid,
            ctx.instance_generation,
            ctx.frame,
            allocator,
            stack_top,
            slot,
        )?;
        Ok(child_pid)
    }

    pub(crate) fn handle_sys_wait4(
        request: &LinuxSyscallRequest,
        ctx: &mut LinuxSyscallContext<'_>,
    ) -> LinuxSyscallResult {
        table_mut().ensure_proc_slot(ProcId {
            pid: ctx.pid,
            generation: ctx.instance_generation,
        })?;
        linux_wait4(request, ctx)
    }

    pub(crate) fn handle_sys_getppid(
        _request: &LinuxSyscallRequest,
        ctx: &mut LinuxSyscallContext<'_>,
    ) -> LinuxSyscallResult {
        let id = ProcId {
            pid: ctx.pid,
            generation: ctx.instance_generation,
        };
        Ok(table_mut().getppid(id))
    }

    pub(crate) fn handle_sys_exit_group(
        request: &LinuxSyscallRequest,
        ctx: &mut LinuxSyscallContext<'_>,
    ) -> LinuxSyscallResult {
        let status = exit_status_from_linux(request.args[0]);
        let pid = ctx.pid;
        let id = ProcId {
            pid,
            generation: ctx.instance_generation,
        };
        let _ = table_mut().ensure_proc_slot(id);
        let parent_pid = table_mut().parent_of(id).map_or(pid, |p| p.pid);
        table_mut().publish_exit(id, exit_status_word(status as u32, None));
        table_mut().finalize_children_on_parent_exit(id);
        table_mut().retire_slot(id);
        wake_all(wait_key_for_parent(parent_pid));
        kernel_log_fmt(format_args!("[LNX ] exit pid={pid} status={status}\n"));
        let allocator = service_lifecycle_syscall_allocator_mut()
            .as_mut()
            .unwrap_or_else(|| fatal_kernel_error("linux exit_group: allocator missing"));
        let teardown = teardown_current_process(allocator, kernel_root_frame(), status, false)
            .unwrap_or_else(|message| fatal_kernel_error(message));
        #[cfg(feature = "m9-linux-proc-self-test")]
        if let Some(next_frame) = crate::selftest::m9_linux_proc::after_probe_exit_group(
            pid,
            ctx.instance_generation,
            status,
            &teardown,
            allocator,
        ) {
            switch_after_exit(Some(next_frame));
        }
        #[cfg(feature = "m9-linux-trace-self-test")]
        if let Some(next_frame) = crate::selftest::m9_linux_trace::after_probe_exit_group(
            pid,
            ctx.instance_generation,
            status,
            &teardown,
            allocator,
        ) {
            switch_after_exit(Some(next_frame));
        }
        switch_after_exit(teardown.next_stack_pointer)
    }

    pub(crate) fn handle_sys_execve(
        request: &LinuxSyscallRequest,
        ctx: &mut LinuxSyscallContext<'_>,
    ) -> LinuxSyscallResult {
        #[cfg(feature = "m9-linux-exec-self-test")]
        if crate::selftest::m9_linux_exec::should_use_exec_selftest(ctx.pid) {
            return handle_execve_selftest(ctx);
        }
        let scratch = unsafe { &mut *EXEC_SCRATCH.get() };
        if scratch.busy {
            return Err(ENOMEM);
        }
        scratch.busy = true;
        let result = execve_inner(request, ctx, scratch);
        scratch.busy = false;
        result
    }

    fn execve_inner(
        request: &LinuxSyscallRequest,
        ctx: &mut LinuxSyscallContext<'_>,
        scratch: &mut ExecCopyScratch,
    ) -> LinuxSyscallResult {
        let path_ptr = request.args[0];
        let argv_ptr = request.args[1];
        let envp_ptr = request.args[2];
        scratch.path_len = copy_user_cstring(path_ptr, &mut scratch.path)?;
        let path = &scratch.path[..scratch.path_len];
        scratch.argv_count = copy_user_string_array(
            argv_ptr,
            &mut scratch.argv,
            &mut scratch.argv_len,
            LINUX_EXEC_MAX_ARGS,
            true,
        )?;
        scratch.envp_count = if envp_ptr == 0 {
            0
        } else {
            copy_user_string_array(
                envp_ptr,
                &mut scratch.envp,
                &mut scratch.envp_len,
                LINUX_EXEC_MAX_ENVS,
                false,
            )?
        };
        let mut total = scratch.path_len;
        for i in 0..scratch.argv_count {
            total += scratch.argv_len[i] + 1;
        }
        for i in 0..scratch.envp_count {
            total += scratch.envp_len[i] + 1;
        }
        if total > LINUX_EXEC_MAX_ARG_BYTES {
            return Err(E2BIG);
        }
        let mut resolved = [0u8; crate::process::linux_proc::exec_resolve::LINUX_PATH_MAX];
        let exec_ref = resolve_executable(ctx.pid, ctx.instance_generation, path, &mut resolved)?;
        let argv_storage: [&[u8]; 16] = core::array::from_fn(|index| {
            if index < scratch.argv_count {
                &scratch.argv[index][..scratch.argv_len[index]]
            } else {
                &[]
            }
        });
        let envp_storage: [&[u8]; 16] = core::array::from_fn(|index| {
            if index < scratch.envp_count {
                &scratch.envp[index][..scratch.envp_len[index]]
            } else {
                &[]
            }
        });
        let spec = LinuxExecSpec {
            image: exec_ref.image,
            argv: &argv_storage[..scratch.argv_count],
            envp: &envp_storage[..scratch.envp_count],
            exec_filename: path,
            stack_pages: LINUX_STACK_PAGES,
            policy: &LINUX_CONVENTIONAL_LOAD_POLICY,
        };
        let allocator = service_lifecycle_syscall_allocator_mut()
            .as_mut()
            .ok_or(ENOMEM)?;
        let prepared = prepare_linux_image(allocator, &spec).map_err(linux_errno_for_exec_error)?;
        commit_exec(
            ctx.frame,
            allocator,
            ctx.pid,
            ctx.instance_generation,
            prepared,
        )
        .map_err(linux_errno_for_exec_error)?;
        Ok(0)
    }

    fn find_empty_scheduler_slot() -> Result<usize, clean_slate_linux_abi::LinuxErrno> {
        without_interrupts(|| {
            let scheduler = unsafe { scheduler_mut() };
            scheduler
                .threads
                .iter()
                .position(|thread| thread.state == ThreadState::Empty)
                .ok_or(ENOMEM)
        })
    }

    fn copy_user_cstring(
        ptr: u64,
        out: &mut [u8],
    ) -> Result<usize, clean_slate_linux_abi::LinuxErrno> {
        if ptr == 0 {
            return Err(EFAULT);
        }
        for (index, slot) in out.iter_mut().enumerate() {
            validate_user_pointer_range(ptr + index as u64, 1).map_err(|_| EFAULT)?;
            let byte = unsafe { *((ptr + index as u64) as *const u8) };
            if byte == 0 {
                if index == 0 {
                    return Err(EINVAL);
                }
                return Ok(index);
            }
            *slot = byte;
        }
        Err(E2BIG)
    }

    fn copy_user_string_array(
        ptr: u64,
        storage: &mut [[u8; 128]],
        lengths: &mut [usize],
        max_entries: usize,
        require_non_empty: bool,
    ) -> Result<usize, clean_slate_linux_abi::LinuxErrno> {
        if ptr == 0 {
            return if require_non_empty {
                Err(EFAULT)
            } else {
                Ok(0)
            };
        }
        let mut count = 0usize;
        while count < max_entries {
            validate_user_pointer_range(ptr + count as u64 * 8, 8).map_err(|_| EFAULT)?;
            let entry_ptr = unsafe { *((ptr + count as u64 * 8) as *const u64) };
            if entry_ptr == 0 {
                break;
            }
            lengths[count] = copy_user_cstring(entry_ptr, &mut storage[count])?;
            count += 1;
        }
        if count == 0 && require_non_empty {
            return Err(EINVAL);
        }
        Ok(count)
    }
}
