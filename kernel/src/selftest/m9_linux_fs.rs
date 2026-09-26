//! M9 #101 Linux filesystem/path projection acceptance (storage + probe + fd cycles).

use crate::arch::x86_64::context_switch::{restore_task_context, task_stack_top};
use crate::diagnostics::log::{kernel_log_fmt, kernel_log_line};
use crate::diagnostics::qemu::{fatal_kernel_error, qemu_exit, QEMU_EXIT_SUCCESS};
use crate::interrupt::timer::initialize_timer;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
use crate::mm::PAGE_SIZE;
use crate::process::domain::DomainTeardownResult;
use crate::process::id_allocator::{id_allocator_mut, IdAllocator};
use crate::process::linux_exec::{launch_linux_process_from_spec, LinuxExecSpec};
use crate::process::linux_fd;
use crate::process::linux_fs::table;
use crate::process::linux_image::{LINUX_CONVENTIONAL_LOAD_POLICY, LINUX_STACK_PAGES};
use crate::process::linux_rootfs;
use crate::process::live_instance_generation;
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::{scheduler_mut, task_stacks_mut, Scheduler, ThreadState};
use crate::selftest::userspace_process::{
    configure_scheduler_thread_slot, spawn_linux_userspace_process_with_code,
};
use crate::selftest::{USER_TEST_CODE_ADDRESS, USER_TEST_PROCESS_STACK_ADDRESS};
use crate::service::control::ServiceLifecycleController;
use crate::service::service_lifecycle_controller_mut;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use clean_slate_service_fixtures::{
    StorageServiceBootstrap, STORAGE_SERVICE_ID, STORAGE_SERVICE_MODE_OBJECT_SERVICE,
};
use clean_slate_service_lifecycle::{
    ControlRequest, ControlRequestKind, InstanceGeneration, LifecycleMessage, ServiceId,
};
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};

const SUPERVISOR_TEST_PID: u64 = 70;
const LINUX_SLOT: usize = 1;
const CYCLE_SLOT: usize = 2;
const FS_CYCLES: u32 = 8;
const PASS_MARKER: &str = "[M9.H] PASS";

const PROBE_FIXTURE: &[u8] =
    include_bytes!("../../../fixtures/linux-fs-probe/linux-fs-probe-x86_64");

static M9_MAIN_PROBE_PID: AtomicU64 = AtomicU64::new(0);
static M9_CYCLE_PID: AtomicU64 = AtomicU64::new(0);
static M9_CYCLE: AtomicU32 = AtomicU32::new(0);
static M9_BASELINE_POOL: AtomicU16 = AtomicU16::new(0);
static M9_BASELINE_NODES: AtomicU16 = AtomicU16::new(0);
static M9_POOL_AT_CYCLE: AtomicU16 = AtomicU16::new(0);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    MainProbe,
    Cycles,
}

static mut M9_PHASE: Phase = Phase::MainProbe;

pub(crate) fn storage_service_bootstrap(
    service: ServiceId,
) -> Result<StorageServiceBootstrap, &'static str> {
    if service != STORAGE_SERVICE_ID {
        return Err("unexpected storage bootstrap service for m9 linux fs test");
    }
    Ok(StorageServiceBootstrap::new(
        STORAGE_SERVICE_MODE_OBJECT_SERVICE,
        0,
    ))
}

pub(crate) fn start_m9_linux_fs_self_test(page_allocator: PageAllocator) -> ! {
    kernel_log_line("[M9.H] creating");

    install_service_lifecycle_syscall_allocator(page_allocator);
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m9 linux fs allocator missing"));

    let img = linux_rootfs::image().expect("m9 linux fs rootfs");
    linux_rootfs::ensure_rootfs_integrity_logged().expect("rootfs integrity");
    crate::process::linux_fs::init_namespace(&img).expect("namespace init");

    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    linux_fd::reset_registry_for_selftest();

    let kernel_root = current_root_frame_address();
    let lifecycle_capability = {
        let controller = unsafe { service_lifecycle_controller_mut() };
        controller.clear();
        controller.configure_launch_context(kernel_root);
        controller
            .declare_service(STORAGE_SERVICE_ID)
            .unwrap_or_else(|message| fatal_kernel_error(message));
        controller
            .grant_lifecycle_control_capability(SUPERVISOR_TEST_PID)
            .unwrap_or_else(|message| fatal_kernel_error(message))
    };
    launch_storage_service(
        unsafe { service_lifecycle_controller_mut() },
        allocator,
        lifecycle_capability,
    );

    let baseline_pool = linux_fd::open_description_pool_live_count();
    let baseline_nodes = table().live_count();
    M9_BASELINE_POOL.store(baseline_pool, Ordering::Relaxed);
    M9_BASELINE_NODES.store(baseline_nodes, Ordering::Relaxed);
    kernel_log_fmt(format_args!(
        "[M9.H] fd pool baseline={baseline_pool} nodes={baseline_nodes}\n"
    ));

    initialize_timer();

    let spec = LinuxExecSpec {
        image: PROBE_FIXTURE,
        argv: &[b"linux-fs-probe"],
        envp: &[],
        exec_filename: b"/linux-fs-probe",
        stack_pages: LINUX_STACK_PAGES,
        policy: &LINUX_CONVENTIONAL_LOAD_POLICY,
    };
    let stacks = unsafe { &*task_stacks_mut() };
    let linux = launch_linux_process_from_spec(
        allocator,
        task_stack_top(&stacks[LINUX_SLOT]),
        LINUX_SLOT,
        &spec,
    )
    .unwrap_or_else(|_| fatal_kernel_error("m9 linux fs probe launch failed"));
    M9_MAIN_PROBE_PID.store(linux.pid, Ordering::Relaxed);

    linux_fd::grant_console_stdio_for_process(linux.pid, linux.instance_generation)
        .unwrap_or_else(|_| fatal_kernel_error("stdio install"));

    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}

fn launch_storage_service(
    controller: &mut ServiceLifecycleController,
    allocator: &mut PageAllocator,
    lifecycle_capability: u64,
) {
    let result = controller
        .handle_control_message(
            allocator,
            SUPERVISOR_TEST_PID,
            lifecycle_capability,
            &LifecycleMessage::ControlRequest(ControlRequest::new(
                STORAGE_SERVICE_ID,
                ControlRequestKind::Start,
            ))
            .encode(),
        )
        .unwrap_or_else(|_| fatal_kernel_error("m9 linux fs storage launch failed"));
    let pid = result
        .event
        .map(|event| event.instance.pid.0)
        .unwrap_or_else(|| fatal_kernel_error("storage pid missing"));
    kernel_log_fmt(format_args!("[STOR] object-service started pid={pid}\n"));
}

fn log_cycle_pool(cycle: u32, label: &str) {
    let pool = linux_fd::open_description_pool_live_count();
    let nodes = table().live_count();
    kernel_log_fmt(format_args!(
        "[M9.H] {label} pool={pool} nodes={nodes} cycle={cycle}\n"
    ));
}

fn build_cycle_code(out: &mut [u8; PAGE_SIZE as usize]) -> Result<usize, &'static str> {
    const PATH_OFF: usize = 160;
    const PATH: &[u8] = b"/etc/hostname\0";
    let path_abs = USER_TEST_CODE_ADDRESS + PATH_OFF as u64;
    let mut len = 0usize;
    let mut emit = |b: &[u8]| -> Result<(), &'static str> {
        if len + b.len() > out.len() {
            return Err("cycle code overflow");
        }
        out[len..len + b.len()].copy_from_slice(b);
        len += b.len();
        Ok(())
    };
    // mov rax, 2  (open)
    emit(&[0x48, 0xC7, 0xC0, 0x02, 0x00, 0x00, 0x00])?;
    // mov rdi, path_abs
    emit(&[0x48, 0xBF])?;
    emit(&path_abs.to_le_bytes())?;
    // mov rsi, 0 (O_RDONLY)
    emit(&[0x48, 0xC7, 0xC6, 0x00, 0x00, 0x00, 0x00])?;
    emit(&[0x0F, 0x05])?; // syscall
                          // mov rbx, rax
    emit(&[0x48, 0x89, 0xC3])?;
    // read(rbx, buf, 8) — buf at PATH_OFF+32
    let buf_abs = USER_TEST_CODE_ADDRESS + (PATH_OFF + 32) as u64;
    emit(&[0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00])?;
    emit(&[0x48, 0x89, 0xDF])?;
    emit(&[0x48, 0xBE])?;
    emit(&buf_abs.to_le_bytes())?;
    emit(&[0x48, 0xC7, 0xC2, 0x08, 0x00, 0x00, 0x00])?;
    emit(&[0x0F, 0x05])?;
    // close(rbx)
    emit(&[0x48, 0xC7, 0xC0, 0x03, 0x00, 0x00, 0x00])?;
    emit(&[0x48, 0x89, 0xDF])?;
    emit(&[0x0F, 0x05])?;
    // exit(0)
    emit(&[0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00])?;
    emit(&[0x48, 0x31, 0xFF])?;
    emit(&[0x0F, 0x05])?;
    if PATH_OFF + PATH.len() > out.len() {
        return Err("cycle path placement");
    }
    out[PATH_OFF..PATH_OFF + PATH.len()].copy_from_slice(PATH);
    Ok(len.max(PATH_OFF + PATH.len()))
}

fn launch_fs_cycle(allocator: &mut PageAllocator, cycle: u32) -> Result<(), &'static str> {
    log_cycle_pool(cycle, "pool_before");
    M9_POOL_AT_CYCLE.store(
        linux_fd::open_description_pool_live_count(),
        Ordering::Relaxed,
    );

    let mut code = [0u8; PAGE_SIZE as usize];
    let code_len = build_cycle_code(&mut code)?;
    let stacks = unsafe { &*task_stacks_mut() };
    let spawned = spawn_linux_userspace_process_with_code(
        allocator,
        task_stack_top(&stacks[CYCLE_SLOT]),
        &code[..code_len],
        USER_TEST_PROCESS_STACK_ADDRESS,
    )?;
    let generation = live_instance_generation(spawned.process_id)
        .ok_or("m9 linux fs cycle missing generation")?;
    crate::process::linux_fs::grant_linux_tmp_object_capabilities(spawned.process_id)
        .map_err(|_| "tmp grant failed")?;
    configure_scheduler_thread_slot(CYCLE_SLOT, &spawned.thread)?;
    let scheduler = unsafe { scheduler_mut() };
    scheduler.current_thread = Some(CYCLE_SLOT);
    scheduler.threads[CYCLE_SLOT].started = false;
    scheduler.threads[CYCLE_SLOT].state = ThreadState::Ready;
    M9_CYCLE_PID.store(spawned.process_id, Ordering::Relaxed);
    let _ = generation;
    Ok(())
}

fn finish_cycles_or_continue(allocator: &mut PageAllocator) -> Option<u64> {
    let cycle = M9_CYCLE.load(Ordering::Relaxed);
    log_cycle_pool(cycle, "pool_after");
    let before = M9_POOL_AT_CYCLE.load(Ordering::Relaxed);
    let after = linux_fd::open_description_pool_live_count();
    if before != after {
        fatal_kernel_error("m9 linux fs fd pool changed across cycle");
    }
    let baseline_pool = M9_BASELINE_POOL.load(Ordering::Relaxed);
    let baseline_nodes = M9_BASELINE_NODES.load(Ordering::Relaxed);
    if after != baseline_pool || table().live_count() != baseline_nodes {
        fatal_kernel_error("m9 linux fs baseline occupancy drift");
    }

    let next = cycle + 1;
    if next >= FS_CYCLES {
        kernel_log_fmt(format_args!(
            "[M9.H] fd pool after={after} nodes={}\n",
            table().live_count()
        ));
        kernel_log_line(PASS_MARKER);
        qemu_exit(QEMU_EXIT_SUCCESS);
    }
    M9_CYCLE.store(next, Ordering::Relaxed);
    launch_fs_cycle(allocator, next).unwrap_or_else(|_| fatal_kernel_error("cycle launch"));
    Some(start_current_scheduler_thread().unwrap_or_else(|m| fatal_kernel_error(m)))
}

/// After production teardown of the main probe or a cycle stub.
pub(crate) fn after_linux_exit(
    pid: u64,
    _generation: InstanceGeneration,
    teardown: &DomainTeardownResult,
    allocator: &mut PageAllocator,
) -> Option<u64> {
    match unsafe { M9_PHASE } {
        Phase::MainProbe if pid == M9_MAIN_PROBE_PID.load(Ordering::Relaxed) => {
            if teardown.exit_status != 0 {
                kernel_log_fmt(format_args!(
                    "[M9.H] probe exit status={}\n",
                    teardown.exit_status
                ));
                fatal_kernel_error("m9 linux fs probe non-zero exit");
            }
            // The namespace keeps `/tmp` entries and resolved rootfs nodes after the probe
            // exits, so cycles are measured against the post-probe node table.
            let probe_nodes = table().live_count();
            M9_BASELINE_NODES.store(probe_nodes, Ordering::Relaxed);
            kernel_log_fmt(format_args!(
                "[M9.H] node baseline after probe={probe_nodes}\n"
            ));
            unsafe {
                M9_PHASE = Phase::Cycles;
            }
            M9_CYCLE.store(0, Ordering::Relaxed);
            launch_fs_cycle(allocator, 0).unwrap_or_else(|_| fatal_kernel_error("cycle 0"));
            Some(start_current_scheduler_thread().unwrap_or_else(|m| fatal_kernel_error(m)))
        }
        Phase::Cycles if pid == M9_CYCLE_PID.load(Ordering::Relaxed) => {
            if teardown.exit_status != 0 {
                fatal_kernel_error("m9 linux fs cycle non-zero exit");
            }
            finish_cycles_or_continue(allocator)
        }
        _ => None,
    }
}
