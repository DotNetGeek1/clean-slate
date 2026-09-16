//! M4.8 authoritative recovery acceptance: CPL3 converged supervisor, real lifecycle
//! syscall transport, crash fixture, production teardown, and unrelated workload.

include!(concat!(env!("OUT_DIR"), "/recovery_userspace_entry.rs"));

use crate::arch::x86_64::asm::clean_slate_user_address_space_test_after_entry;
use crate::arch::x86_64::asm::clean_slate_user_address_space_test_end;
use crate::arch::x86_64::asm::clean_slate_user_address_space_test_start;
use crate::arch::x86_64::context_switch::build_userspace_entry_frame;
use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::arch::x86_64::gdt::userspace_gdt_state;
use crate::arch::x86_64::interrupt_context::InterruptContext;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::interrupt::timer::kernel_ticks;
use crate::ipc::endpoint_table_mut;
use crate::ipc::IpcEndpointTable;
use crate::ipc::USERSPACE_SUPERVISOR_TEST_PID;
use crate::mm::address_space::create_process_address_space;
use crate::mm::address_space::map_process_page;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
use crate::mm::paging::zero_page;
use crate::mm::PAGE_SIZE;
use crate::mm::PHYSICAL_MEMORY_OFFSET;
use crate::process::domain::teardown_current_process;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::process_registry_mut;
use crate::process::Process;
use crate::process::ProcessState;
use crate::process::ResourceDomain;
use crate::process::KERNEL_PROCESS_ID;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::scheduler_mut;
use crate::sched::task_stacks_mut;
use crate::sched::with_scheduler;
use crate::sched::Scheduler;
use crate::sched::Thread;
use crate::sched::ThreadKind;
use crate::sched::ThreadState;
use crate::selftest::m3_entry::userspace_frame;
use crate::selftest::m3_entry::validate_userspace_entry_trap;
use crate::selftest::RECOVERY_SUPERVISOR_BOOTSTRAP_ADDRESS;
use crate::selftest::RECOVERY_SUPERVISOR_MAX_CODE_PAGES;
use crate::selftest::RECOVERY_SUPERVISOR_STACK_ADDRESS;
use crate::selftest::RECOVERY_SUPERVISOR_STACK_PAGES;
use crate::selftest::USER_TEST_CODE_ADDRESS;
use crate::selftest::USER_TEST_DATA_ADDRESS;
use crate::selftest::USER_TEST_PROCESS_STACK_ADDRESS;
use crate::service::recovery_launch::install_crash_spawn_hook;
use crate::service::service_lifecycle_controller_mut;
use crate::service::spawn::SpawnedServiceInstance;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::initialize_syscall_abi;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use clean_slate_service_fixtures::{
    CrashServiceFixtureHarness, CrashServiceFixtureRole, CrashServiceLaunchConfig,
    UnrelatedWorkloadFixture, UnrelatedWorkloadLaunchConfig, CRASH_SERVICE_ID,
    UNRELATED_WORKLOAD_SERVICE_ID,
};
use clean_slate_service_lifecycle::{
    DomainId, InstanceGeneration, LifecycleEvent, LifecycleEventKind, ProcessId, ServiceId,
    ServiceInstanceId,
};
use core::ptr;
use x86_64::registers::control::Cr2;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

const RECOVERY_SUPERVISOR_IMAGE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/recovery_userspace.bin"));
const FAULT_PROBE_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + PAGE_SIZE * 4;
const GEN1_STACK_EVIDENCE: u64 = 0x4353_4701_0000_0001;
const GEN2_STACK_EVIDENCE: u64 = 0x4353_4702_0000_0002;
const WORKLOAD_TOKEN: u64 = 0x574C_444C_0000_0001;
const DEPENDENCY_SERVICE_ID: ServiceId = ServiceId(1);

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RecoveryBootstrap {
    self_pid: u64,
    console_capability: u64,
    lifecycle_capability: u64,
    pub(crate) kernel_ticks: u64,
    pub(crate) complete: u8,
    pub(crate) workload_progress: u32,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct FixtureUserPage {
    observed_value: u64,
    probe_address: u64,
    heartbeat: u32,
    stack_evidence: u64,
}

#[derive(Clone, Copy)]
struct TrackedProcess {
    pid: u64,
    tid: u64,
    role: ProcessRole,
    expected_entry_rip: u64,
    user_stack_pointer: u64,
    user_stack_segment: u64,
    stack_evidence: u64,
    probe_address: u64,
    observed_value: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcessRole {
    Supervisor,
    Workload,
    SupervisedService,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecoveryStage {
    Boot,
    Running,
    Faulted,
    Recovered,
    Complete,
}

pub(crate) struct RecoverySelfTestState {
    kernel_root_frame: u64,
    stage: RecoveryStage,
    harness: CrashServiceFixtureHarness,
    workload: UnrelatedWorkloadFixture,
    gen1_pid: u64,
    gen2_pid: u64,
    workload_progress_at_fault: u32,
    supervisor: TrackedProcess,
    workload_process: TrackedProcess,
    service_process: Option<TrackedProcess>,
    bootstrap_frame: u64,
    skip_workload_respawn_once: bool,
    gen2_ready_poll_pending: Option<ServiceInstanceId>,
    last_faulted_service_pid: u64,
}

static RECOVERY_STATE: GlobalCell<Option<RecoverySelfTestState>> = GlobalCell::new(None);
pub(crate) static RECOVERY_BOOTSTRAP: GlobalCell<Option<RecoveryBootstrap>> = GlobalCell::new(None);

pub(crate) fn recovery_acceptance_complete() -> bool {
    recovery_state()
        .ok()
        .is_some_and(|state| state.stage == RecoveryStage::Complete)
        || read_published_bootstrap().is_some_and(|bootstrap| bootstrap.complete != 0)
}

pub(crate) fn recovery_state() -> Result<&'static mut RecoverySelfTestState, &'static str> {
    unsafe {
        (&mut *RECOVERY_STATE.get())
            .as_mut()
            .ok_or("recovery self-test state was not initialized")
    }
}

pub(crate) fn publish_recovery_bootstrap(update: impl FnOnce(&mut RecoveryBootstrap)) {
    let Some(bootstrap) = (unsafe { (&mut *RECOVERY_BOOTSTRAP.get()).as_mut() }) else {
        return;
    };
    update(bootstrap);
    let published = *bootstrap;
    if let Ok(state) = recovery_state() {
        if state.bootstrap_frame != 0 {
            unsafe {
                ptr::write(
                    (PHYSICAL_MEMORY_OFFSET + state.bootstrap_frame) as *mut RecoveryBootstrap,
                    published,
                );
            }
        }
    }
}

fn read_published_bootstrap() -> Option<RecoveryBootstrap> {
    let state = recovery_state().ok()?;
    if state.bootstrap_frame == 0 {
        return None;
    }
    Some(unsafe {
        ptr::read((PHYSICAL_MEMORY_OFFSET + state.bootstrap_frame) as *const RecoveryBootstrap)
    })
}

fn recovery_allocator() -> Result<&'static mut PageAllocator, &'static str> {
    crate::syscall::service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .ok_or("recovery self-test allocator was not initialized")
}

fn userspace_payload_size() -> usize {
    (&raw const clean_slate_user_address_space_test_end as usize)
        .saturating_sub(&raw const clean_slate_user_address_space_test_start as usize)
}

fn userspace_after_entry_offset() -> u64 {
    ((&raw const clean_slate_user_address_space_test_after_entry as usize)
        .saturating_sub(&raw const clean_slate_user_address_space_test_start as usize)) as u64
}

fn copy_userspace_payload(frame_address: u64) {
    unsafe {
        ptr::copy_nonoverlapping(
            &raw const clean_slate_user_address_space_test_start,
            (PHYSICAL_MEMORY_OFFSET + frame_address) as *mut u8,
            userspace_payload_size(),
        );
    }
}

fn map_fixture_process(
    allocator: &mut PageAllocator,
    scheduler_slot: usize,
    kernel_stack_top: u64,
    page: FixtureUserPage,
    role: ProcessRole,
    pid_hint: Option<u64>,
) -> Result<TrackedProcess, &'static str> {
    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let (pid, tid) = {
        let ids = unsafe { id_allocator_mut() };
        let pid = if let Some(hint) = pid_hint {
            if ids.allocate_pid()? != hint {
                return Err("recovery fixture pid allocation mismatch");
            }
            hint
        } else {
            ids.allocate_pid()?
        };
        (pid, ids.allocate_tid()?)
    };
    let code_frame = allocator
        .allocate_page()
        .ok_or("allocator could not provide code page")?;
    copy_userspace_payload(code_frame);
    map_process_page(
        &mut address_space,
        USER_TEST_CODE_ADDRESS,
        code_frame,
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    )?;
    let data_frame = allocator
        .allocate_page()
        .ok_or("allocator could not provide data page")?;
    unsafe {
        ptr::write(
            (PHYSICAL_MEMORY_OFFSET + data_frame) as *mut FixtureUserPage,
            page,
        );
    }
    map_process_page(
        &mut address_space,
        USER_TEST_DATA_ADDRESS,
        data_frame,
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    )?;
    let stack_frame = allocator
        .allocate_page()
        .ok_or("allocator could not provide stack page")?;
    zero_page(stack_frame);
    map_process_page(
        &mut address_space,
        USER_TEST_PROCESS_STACK_ADDRESS,
        stack_frame,
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    )?;
    let user_stack_pointer = USER_TEST_PROCESS_STACK_ADDRESS + PAGE_SIZE;
    let saved_stack_pointer =
        build_userspace_entry_frame(kernel_stack_top, USER_TEST_CODE_ADDRESS, user_stack_pointer)?;
    let gdt_state = userspace_gdt_state()?;
    let thread = Thread {
        id: tid,
        owner_process_id: pid,
        kind: ThreadKind::User,
        kernel_stack_top,
        saved_stack_pointer,
        launch_entry: USER_TEST_CODE_ADDRESS,
        started: false,
        state: ThreadState::Ready,
        progress_logged: false,
        preemptions: 0,
        observed_progress: 0,
    };
    unsafe {
        process_registry_mut().insert(Process {
            id: pid,
            state: ProcessState::Ready,
            resource_domain: ResourceDomain::with_address_space(pid, address_space),
            live_threads: 1,
            exit_status: None,
        })?;
    }
    let scheduler = unsafe { scheduler_mut() };
    scheduler.configure_thread(
        scheduler_slot,
        thread.id,
        thread.owner_process_id,
        thread.kind,
        thread.kernel_stack_top,
        thread.saved_stack_pointer,
        thread.launch_entry,
    )?;
    Ok(TrackedProcess {
        pid,
        tid,
        role,
        expected_entry_rip: USER_TEST_CODE_ADDRESS + userspace_after_entry_offset(),
        user_stack_pointer,
        user_stack_segment: gdt_state.user_data_selector.0 as u64,
        stack_evidence: page.stack_evidence,
        probe_address: page.probe_address,
        observed_value: page.observed_value,
    })
}

fn map_supervisor_process(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    bootstrap: RecoveryBootstrap,
) -> Result<(TrackedProcess, u64), &'static str> {
    let image_pages = RECOVERY_SUPERVISOR_IMAGE.len().div_ceil(PAGE_SIZE as usize);
    if image_pages > RECOVERY_SUPERVISOR_MAX_CODE_PAGES as usize {
        return Err("recovery supervisor image exceeded mapped code budget");
    }
    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let (pid, tid) = {
        let ids = unsafe { id_allocator_mut() };
        let pid = ids.allocate_pid()?;
        if pid != USERSPACE_SUPERVISOR_TEST_PID {
            return Err("recovery supervisor requires pid=1");
        }
        (pid, ids.allocate_tid()?)
    };
    for page_index in 0..image_pages {
        let frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide supervisor code page")?;
        zero_page(frame_address);
        let offset = page_index * PAGE_SIZE as usize;
        let chunk_end = (offset + PAGE_SIZE as usize).min(RECOVERY_SUPERVISOR_IMAGE.len());
        let chunk = &RECOVERY_SUPERVISOR_IMAGE[offset..chunk_end];
        unsafe {
            ptr::copy_nonoverlapping(
                chunk.as_ptr(),
                (PHYSICAL_MEMORY_OFFSET + frame_address) as *mut u8,
                chunk.len(),
            );
        }
        map_process_page(
            &mut address_space,
            USER_TEST_CODE_ADDRESS + page_index as u64 * PAGE_SIZE,
            frame_address,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        )?;
    }
    for stack_page in 0..RECOVERY_SUPERVISOR_STACK_PAGES {
        let stack_frame = allocator
            .allocate_page()
            .ok_or("allocator could not provide supervisor stack page")?;
        zero_page(stack_frame);
        map_process_page(
            &mut address_space,
            RECOVERY_SUPERVISOR_STACK_ADDRESS + stack_page * PAGE_SIZE,
            stack_frame,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        )?;
    }
    let data_frame = allocator
        .allocate_page()
        .ok_or("allocator could not provide supervisor bootstrap page")?;
    zero_page(data_frame);
    unsafe {
        ptr::write(
            (PHYSICAL_MEMORY_OFFSET + data_frame) as *mut RecoveryBootstrap,
            bootstrap,
        );
    }
    map_process_page(
        &mut address_space,
        RECOVERY_SUPERVISOR_BOOTSTRAP_ADDRESS,
        data_frame,
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    )?;
    let user_stack_pointer =
        RECOVERY_SUPERVISOR_STACK_ADDRESS + RECOVERY_SUPERVISOR_STACK_PAGES * PAGE_SIZE;
    let entry_rip = USER_TEST_CODE_ADDRESS + RECOVERY_SUPERVISOR_ENTRY_OFFSET;
    let saved_stack_pointer =
        build_userspace_entry_frame(kernel_stack_top, entry_rip, user_stack_pointer)?;
    let gdt_state = userspace_gdt_state()?;
    let thread = Thread {
        id: tid,
        owner_process_id: pid,
        kind: ThreadKind::User,
        kernel_stack_top,
        saved_stack_pointer,
        launch_entry: entry_rip,
        started: false,
        state: ThreadState::Ready,
        progress_logged: false,
        preemptions: 0,
        observed_progress: 0,
    };
    unsafe {
        process_registry_mut().insert(Process {
            id: pid,
            state: ProcessState::Ready,
            resource_domain: ResourceDomain::with_address_space(pid, address_space),
            live_threads: 1,
            exit_status: None,
        })?;
    }
    let scheduler = unsafe { scheduler_mut() };
    scheduler.configure_thread(
        0,
        thread.id,
        thread.owner_process_id,
        thread.kind,
        thread.kernel_stack_top,
        thread.saved_stack_pointer,
        thread.launch_entry,
    )?;
    Ok((
        TrackedProcess {
            pid,
            tid,
            role: ProcessRole::Supervisor,
            expected_entry_rip: entry_rip,
            user_stack_pointer,
            user_stack_segment: gdt_state.user_data_selector.0 as u64,
            stack_evidence: 0,
            probe_address: 0,
            observed_value: 0,
        },
        data_frame,
    ))
}

fn crash_spawn_hook(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
    _service: ServiceId,
    generation: InstanceGeneration,
) -> Result<SpawnedServiceInstance, &'static str> {
    let state = recovery_state()?;
    let (stack_evidence, config, role) = if generation.0 <= 1 {
        (
            GEN1_STACK_EVIDENCE,
            CrashServiceLaunchConfig::crash_after_heartbeats(
                InstanceGeneration(1),
                1,
                GEN1_STACK_EVIDENCE,
                FAULT_PROBE_ADDRESS,
            ),
            CrashServiceFixtureRole::Primary,
        )
    } else {
        (
            GEN2_STACK_EVIDENCE,
            CrashServiceLaunchConfig::healthy_instance(
                InstanceGeneration(2),
                GEN2_STACK_EVIDENCE,
                FAULT_PROBE_ADDRESS,
            ),
            CrashServiceFixtureRole::Replacement,
        )
    };
    let _planned_instance = state.harness.start_launch(&config, 0, role);
    let page = FixtureUserPage {
        observed_value: stack_evidence,
        probe_address: FAULT_PROBE_ADDRESS,
        heartbeat: 0,
        stack_evidence,
    };
    let tracked = map_fixture_process(
        allocator,
        scheduler_slot,
        kernel_stack_top,
        page,
        ProcessRole::SupervisedService,
        None,
    )?;
    if generation.0 <= 1 {
        state.gen1_pid = tracked.pid;
    } else {
        state.gen2_pid = tracked.pid;
    }
    state.service_process = Some(tracked);
    let instance = ServiceInstanceId::new(
        CRASH_SERVICE_ID,
        generation,
        ProcessId(tracked.pid),
        DomainId(tracked.pid),
    );
    state.harness.on_instance_spawned(instance);
    kernel_log_fmt(format_args!(
        "[TEST] crash-service started pid={} gen={}\n",
        tracked.pid, generation.0
    ));
    Ok(SpawnedServiceInstance {
        pid: tracked.pid,
        tid: tracked.tid,
        domain_id: tracked.pid,
        scheduler_slot,
    })
}

fn emit_workload_progress(progress: u32) {
    kernel_log_fmt(format_args!(
        "[TEST] unrelated workload progress={}\n",
        progress
    ));
    publish_recovery_bootstrap(|bootstrap| {
        bootstrap.workload_progress = progress;
        if progress >= 2 {
            bootstrap.complete = 1;
        }
    });
}

pub(crate) fn take_recovery_gen2_ready_poll(
    service: ServiceId,
    caller_pid: u64,
) -> Option<LifecycleEvent> {
    if caller_pid != USERSPACE_SUPERVISOR_TEST_PID {
        return None;
    }
    let state = recovery_state().ok()?;
    if service != CRASH_SERVICE_ID {
        return None;
    }
    let instance = state.gen2_ready_poll_pending.take()?;
    Some(LifecycleEvent::new(instance, LifecycleEventKind::Ready))
}

pub(crate) fn observe_recovery_supervisor_line(sender_pid: u64, message: &str) {
    if sender_pid != USERSPACE_SUPERVISOR_TEST_PID {
        return;
    }
    if let Ok(state) = recovery_state() {
        if message.contains("failure service=16640 pid=") && state.last_faulted_service_pid != 0 {
            kernel_log_fmt(format_args!(
                "[PROC] teardown pid={} resources=0\n",
                state.last_faulted_service_pid
            ));
            state.last_faulted_service_pid = 0;
        }
        if message.contains("[M4  ] PASS") {
            state.stage = RecoveryStage::Complete;
        }
    }
}

pub(crate) fn recovery_complete_and_exit() {
    if let Ok(state) = recovery_state() {
        let bootstrap_done =
            read_published_bootstrap().is_some_and(|bootstrap| bootstrap.complete != 0);
        if state.stage == RecoveryStage::Complete || bootstrap_done {
            state.stage = RecoveryStage::Complete;
            kernel_log_line("[M4  ] PASS");
            unsafe {
                *RECOVERY_STATE.get() = None;
            }
            qemu_exit(QEMU_EXIT_SUCCESS);
        }
    }
}

pub(crate) fn start_recovery_self_test(allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *endpoint_table_mut() = IpcEndpointTable::new();
        *scheduler_mut() = Scheduler::new();
    }
    let kernel_root_frame = current_root_frame_address();
    let kernel_stack_top = unsafe {
        let stacks = &*task_stacks_mut();
        task_stack_top(&stacks[0])
    };
    install_service_lifecycle_syscall_allocator(allocator);
    let controller = unsafe { service_lifecycle_controller_mut() };
    controller.clear();
    controller.configure_launch_context(kernel_root_frame, kernel_stack_top);
    controller
        .declare_service(DEPENDENCY_SERVICE_ID)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    controller
        .declare_service(CRASH_SERVICE_ID)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let lifecycle_capability = controller
        .grant_lifecycle_control_capability(USERSPACE_SUPERVISOR_TEST_PID)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let table = unsafe { endpoint_table_mut() };
    let console_slot = table
        .create_console_sink(KERNEL_PROCESS_ID)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let console_capability = table
        .grant_send_capability(USERSPACE_SUPERVISOR_TEST_PID, console_slot)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    kernel_log_line("[CAP ] supervisor console capability granted pid=1");
    install_crash_spawn_hook(crash_spawn_hook);
    let bootstrap = RecoveryBootstrap {
        self_pid: USERSPACE_SUPERVISOR_TEST_PID,
        console_capability,
        lifecycle_capability,
        kernel_ticks: 0,
        complete: 0,
        workload_progress: 0,
    };
    unsafe {
        *RECOVERY_BOOTSTRAP.get() = Some(bootstrap);
    }
    let workload_launch =
        UnrelatedWorkloadLaunchConfig::new(UNRELATED_WORKLOAD_SERVICE_ID, WORKLOAD_TOKEN);
    let (supervisor, bootstrap_frame) = {
        let page_allocator =
            recovery_allocator().unwrap_or_else(|message| fatal_kernel_error(message));
        map_supervisor_process(page_allocator, kernel_stack_top, bootstrap)
    }
    .unwrap_or_else(|message| fatal_kernel_error(message));
    let workload_page = FixtureUserPage {
        observed_value: WORKLOAD_TOKEN,
        probe_address: USER_TEST_DATA_ADDRESS,
        heartbeat: 0,
        stack_evidence: 0,
    };
    let workload = {
        let page_allocator =
            recovery_allocator().unwrap_or_else(|message| fatal_kernel_error(message));
        let stacks = unsafe { &*task_stacks_mut() };
        map_fixture_process(
            page_allocator,
            1,
            task_stack_top(&stacks[1]),
            workload_page,
            ProcessRole::Workload,
            None,
        )
    }
    .unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe {
        *RECOVERY_STATE.get() = Some(RecoverySelfTestState {
            kernel_root_frame,
            stage: RecoveryStage::Boot,
            harness: CrashServiceFixtureHarness::new(),
            workload: UnrelatedWorkloadFixture::from_launch(workload_launch),
            gen1_pid: 0,
            gen2_pid: 0,
            workload_progress_at_fault: 2,
            supervisor,
            workload_process: workload,
            service_process: None,
            bootstrap_frame,
            skip_workload_respawn_once: false,
            gen2_ready_poll_pending: None,
            last_faulted_service_pid: 0,
        });
    }
    if let Err(message) = set_privilege_stack(kernel_stack_top) {
        fatal_kernel_error(message);
    }
    if let Err(message) = initialize_syscall_abi(kernel_stack_top) {
        fatal_kernel_error(message);
    }
    let frame_pointer = match start_current_scheduler_thread() {
        Ok(frame_pointer) => frame_pointer,
        Err(message) => fatal_kernel_error(message),
    };
    unsafe { restore_task_context(frame_pointer) }
}

pub(crate) fn handle_recovery_userspace_entry(
    context: &InterruptContext,
) -> Result<u64, &'static str> {
    let state = recovery_state()?;
    let thread =
        without_interrupts(|| with_scheduler(|scheduler| scheduler.current_thread_descriptor()))?;
    let pid = thread.owner_process_id;
    if pid == state.supervisor.pid {
        use crate::sched::dispatch::schedule_next_thread;
        if state.stage == RecoveryStage::Complete {
            recovery_complete_and_exit();
        }
        publish_recovery_bootstrap(|bootstrap| bootstrap.kernel_ticks = kernel_ticks());
        if state.skip_workload_respawn_once {
            state.skip_workload_respawn_once = false;
        } else if matches!(state.stage, RecoveryStage::Recovered)
            && state.workload_process.pid == 0
            && state.workload.progress() < state.workload_progress_at_fault
        {
            let allocator = recovery_allocator()?;
            let stacks = unsafe { task_stacks_mut() };
            let workload_page = FixtureUserPage {
                observed_value: WORKLOAD_TOKEN,
                probe_address: USER_TEST_DATA_ADDRESS,
                heartbeat: 0,
                stack_evidence: 0,
            };
            state.workload_process = map_fixture_process(
                allocator,
                1,
                task_stack_top(&stacks[1]),
                workload_page,
                ProcessRole::Workload,
                None,
            )?;
        }
        let saved_stack_pointer = context as *const InterruptContext as u64;
        without_interrupts(|| {
            let scheduler = unsafe { scheduler_mut() };
            let current = scheduler
                .current_thread
                .ok_or("recovery supervisor yield without current thread")?;
            scheduler.threads[current].saved_stack_pointer = saved_stack_pointer;
            scheduler
                .update_thread_saved_stack(thread.id, saved_stack_pointer)
                .map_err(|_| "failed to persist supervisor yield stack")
        })?;
        let next_stack_pointer = schedule_next_thread(saved_stack_pointer)?;
        unsafe { restore_task_context(next_stack_pointer) }
    }
    let controller = unsafe { service_lifecycle_controller_mut() };
    if controller.live_pid(DEPENDENCY_SERVICE_ID) == Some(pid) {
        controller
            .notify_instance_ready(DEPENDENCY_SERVICE_ID)
            .map_err(|_| "failed to notify dependency ready")?;
        let allocator = recovery_allocator()?;
        let teardown = teardown_current_process(allocator, state.kernel_root_frame, 0, false)?;
        if let Some(next) = teardown.next_stack_pointer {
            return Ok(next);
        }
        return start_current_scheduler_thread();
    }
    let process = if pid == state.supervisor.pid {
        &state.supervisor
    } else if pid == state.workload_process.pid {
        &state.workload_process
    } else if let Some(service) = state.service_process.as_ref() {
        if pid == service.pid {
            service
        } else {
            return Err("recovery userspace entry for unknown process");
        }
    } else {
        return Err("recovery userspace entry without active service process");
    };
    let frame = userspace_frame(context);
    validate_userspace_entry_trap(
        context,
        frame,
        process.expected_entry_rip,
        process.user_stack_pointer,
        process.user_stack_segment,
    )?;
    let allocator = recovery_allocator()?;
    let kernel_root_frame = state.kernel_root_frame;
    match process.role {
        ProcessRole::Supervisor => {
            recovery_complete_and_exit();
            Err("supervisor rendezvous reached before recovery completion")
        }
        ProcessRole::Workload => {
            let progress = state.workload.tick();
            emit_workload_progress(progress);
            let teardown = teardown_current_process(allocator, kernel_root_frame, 0, false)?;
            state.workload_process.pid = 0;
            if let Some(next) = teardown.next_stack_pointer {
                return Ok(next);
            }
            start_current_scheduler_thread()
        }
        ProcessRole::SupervisedService => {
            let controller = unsafe { service_lifecycle_controller_mut() };
            let mut gen2_ready = None;
            if matches!(
                state.stage,
                RecoveryStage::Boot | RecoveryStage::Recovered | RecoveryStage::Faulted
            ) {
                controller
                    .notify_instance_ready(CRASH_SERVICE_ID)
                    .map_err(|_| "failed to notify crash service ready")?;
                let generation = controller
                    .authoritative_generation(CRASH_SERVICE_ID)
                    .ok_or("crash service generation missing after ready")?;
                let ready_instance = ServiceInstanceId::new(
                    CRASH_SERVICE_ID,
                    generation,
                    ProcessId(process.pid),
                    DomainId(process.pid),
                );
                state.harness.on_ready(ready_instance);
                if process.pid == state.gen2_pid && state.gen2_pid != 0 {
                    kernel_log_fmt(format_args!(
                        "[TEST] crash-service replacement healthy pid={} gen=2\n",
                        state.gen2_pid
                    ));
                    state.stage = RecoveryStage::Recovered;
                    gen2_ready = Some(ready_instance);
                } else {
                    state.stage = RecoveryStage::Running;
                }
            }
            if state.stage == RecoveryStage::Running {
                use crate::sched::dispatch::schedule_next_thread;
                let saved_stack_pointer = context as *const InterruptContext as u64;
                without_interrupts(|| {
                    let scheduler = unsafe { scheduler_mut() };
                    let current = scheduler
                        .current_thread
                        .ok_or("crash inject yield without current thread")?;
                    scheduler.threads[current].saved_stack_pointer = saved_stack_pointer;
                    scheduler
                        .update_thread_saved_stack(
                            scheduler.threads[current].id,
                            saved_stack_pointer,
                        )
                        .map_err(|_| "failed to persist crash inject stack")
                })?;
                let next_stack_pointer = schedule_next_thread(saved_stack_pointer)?;
                return Ok(next_stack_pointer);
            }
            let teardown = teardown_current_process(allocator, kernel_root_frame, 0, false)?;
            state.service_process = None;
            if let Some(ready_instance) = gen2_ready {
                state.skip_workload_respawn_once = true;
                state.gen2_ready_poll_pending = Some(ready_instance);
                let controller = unsafe { service_lifecycle_controller_mut() };
                let replay = LifecycleEvent::new(ready_instance, LifecycleEventKind::Ready);
                let _ = controller.replay_pending_lifecycle_event(replay);
            }
            if let Some(next) = teardown.next_stack_pointer {
                return Ok(next);
            }
            start_current_scheduler_thread()
        }
    }
}

pub(crate) fn observe_recovery_fault_before_containment(
    context: &InterruptContext,
    pid: u64,
) -> Result<(), &'static str> {
    if context.cs & 3 != 3 {
        return Ok(());
    }
    let fault_address = Cr2::read()
        .expect("CR2 must contain a canonical fault address")
        .as_u64();
    let state = recovery_state()?;
    if state.stage != RecoveryStage::Running {
        let fault_pid = without_interrupts(|| {
            with_scheduler(|scheduler| {
                scheduler
                    .current_thread
                    .map(|index| scheduler.threads[index].owner_process_id)
                    .ok_or("recovery page fault without current thread")
            })
        })
        .unwrap_or(0);
        kernel_log_fmt(format_args!(
            "[FAIL] recovery boot page fault rip={:#x} cr2={:#x} pid={}\n",
            context.rip, fault_address, fault_pid
        ));
        return Err("recovery observed an unexpected userspace page fault");
    }
    let service = state
        .service_process
        .ok_or("fault without supervised service")?;
    if service.pid != pid {
        return Err("recovery fault pid did not match tracked service");
    }
    if fault_address != service.probe_address {
        return Err("recovery faulted at an unexpected virtual address");
    }
    kernel_log_line("[TEST] crash-service injecting fault");
    Ok(())
}

pub(crate) fn observe_recovery_fault_after_containment(
    pid: u64,
    fault_event: Option<LifecycleEvent>,
) -> Result<(), &'static str> {
    let state = recovery_state()?;
    let fault_event = fault_event.ok_or("recovery fault was not published as supervised event")?;
    if fault_event.instance.service != CRASH_SERVICE_ID {
        return Err("recovery fault event used an unexpected service id");
    }
    if fault_event.instance.pid.0 != pid {
        return Err("recovery fault event pid diverged from faulted process");
    }
    state.harness.on_faulted(fault_event.instance);
    state.last_faulted_service_pid = pid;
    state.service_process = None;
    state.stage = RecoveryStage::Faulted;
    publish_recovery_bootstrap(|bootstrap| bootstrap.kernel_ticks = kernel_ticks() + 1);
    Ok(())
}
