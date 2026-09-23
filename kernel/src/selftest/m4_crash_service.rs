//! M4.7 crash-service fixture: production userspace teardown, lifecycle events,
//! deterministic fault injection, and unrelated workload progress (no reboot).

use crate::arch::x86_64::asm::clean_slate_user_address_space_test_after_entry;
use crate::arch::x86_64::asm::clean_slate_user_address_space_test_end;
use crate::arch::x86_64::asm::clean_slate_user_address_space_test_start;
use crate::arch::x86_64::context_switch::build_userspace_entry_frame;
use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::gdt::userspace_gdt_state;
use crate::arch::x86_64::interrupt_context::InterruptContext;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::ipc::endpoint_table_mut;
use crate::ipc::IpcEndpointTable;
use crate::ipc::IpcProcessResources;
use crate::ipc::IpcSendError;
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
use crate::run;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::scheduler_mut;
use crate::sched::task_stacks_mut;
use crate::sched::with_scheduler;
use crate::sched::Scheduler;
use crate::sched::Thread;
use crate::sched::ThreadKind;
use crate::sched::ThreadProcessResources;
use crate::sched::ThreadState;
use crate::selftest::m3_entry::userspace_frame;
use crate::selftest::m3_entry::validate_userspace_entry_trap;
use crate::selftest::USER_TEST_CODE_ADDRESS;
use crate::selftest::USER_TEST_DATA_ADDRESS;
use crate::selftest::USER_TEST_PROCESS_STACK_ADDRESS;
use crate::sync::global_cell::GlobalCell;
use clean_slate_service_fixtures::{
    CrashServiceFixtureHarness, CrashServiceFixtureRole, CrashServiceLaunchConfig,
    UnrelatedWorkloadFixture, UnrelatedWorkloadLaunchConfig, CRASH_SERVICE_ID,
    UNRELATED_WORKLOAD_SERVICE_ID,
};
use clean_slate_service_lifecycle::{
    format_declared_line, format_instance_line, DomainId, InstanceGeneration, ProcessId,
    ServiceInstanceId, ServiceLifecycleState,
};
use core::fmt::Write;
use core::ptr;
use x86_64::registers::control::Cr2;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

const FAULT_PROBE_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + PAGE_SIZE * 4;
const GEN1_STACK_EVIDENCE: u64 = 0x4353_4701_0000_0001;
const GEN2_STACK_EVIDENCE: u64 = 0x4353_4702_0000_0002;
const WORKLOAD_TOKEN: u64 = 0x574C_444C_0000_0001;

#[derive(Clone, Copy)]
#[repr(C)]
struct CrashServiceUserPage {
    observed_value: u64,
    probe_address: u64,
    heartbeat: u32,
    stack_evidence: u64,
}

#[derive(Clone, Copy)]
struct UserspaceFixtureProcess {
    process_id: u64,
    thread_id: u64,
    observed_value: u64,
    expected_probe_address: u64,
    expected_entry_rip: u64,
    user_stack_pointer: u64,
    user_stack_segment: u64,
    stack_evidence: u64,
    self_capability: u64,
    kernel_probe_capability: u64,
}

impl UserspaceFixtureProcess {
    const EMPTY: Self = Self {
        process_id: 0,
        thread_id: 0,
        observed_value: 0,
        expected_probe_address: 0,
        expected_entry_rip: 0,
        user_stack_pointer: 0,
        user_stack_segment: 0,
        stack_evidence: 0,
        self_capability: 0,
        kernel_probe_capability: 0,
    };
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CrashServiceStage {
    WarmupWorkload,
    DualRunning,
    CrashFaultResume,
    WorkloadAfterFault,
    ReplacementHealthy,
    FinalWorkload,
    Complete,
}

struct CrashServiceSelfTestState {
    kernel_root_frame: u64,
    stage: CrashServiceStage,
    harness: CrashServiceFixtureHarness,
    workload: UnrelatedWorkloadFixture,
    workload_progress_before_fault: u32,
    gen1_instance: Option<ServiceInstanceId>,
    gen1_pid: u64,
    gen2_pid: u64,
    processes: [UserspaceFixtureProcess; 2],
}

static CRASH_SERVICE_ALLOCATOR: GlobalCell<Option<PageAllocator>> = GlobalCell::new(None);
static CRASH_SERVICE_STATE: GlobalCell<Option<CrashServiceSelfTestState>> = GlobalCell::new(None);

fn userspace_payload_size() -> usize {
    (&raw const clean_slate_user_address_space_test_end as usize)
        .saturating_sub(&raw const clean_slate_user_address_space_test_start as usize)
}

fn userspace_after_entry_offset() -> u64 {
    ((&raw const clean_slate_user_address_space_test_after_entry as usize)
        .saturating_sub(&raw const clean_slate_user_address_space_test_start as usize)) as u64
}

fn crash_service_state() -> Result<&'static mut CrashServiceSelfTestState, &'static str> {
    unsafe {
        (&mut *CRASH_SERVICE_STATE.get())
            .as_mut()
            .ok_or("crash-service self-test state was not initialized")
    }
}

fn crash_service_allocator() -> Result<&'static mut PageAllocator, &'static str> {
    unsafe {
        (&mut *CRASH_SERVICE_ALLOCATOR.get())
            .as_mut()
            .ok_or("crash-service self-test allocator was not initialized")
    }
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

fn initialize_crash_service_page(frame_address: u64, config: &CrashServiceLaunchConfig) {
    zero_page(frame_address);
    let page = CrashServiceUserPage {
        observed_value: config.stack_evidence,
        probe_address: config.fault_probe_address,
        heartbeat: 0,
        stack_evidence: config.stack_evidence,
    };
    unsafe {
        ptr::write(
            (PHYSICAL_MEMORY_OFFSET + frame_address) as *mut CrashServiceUserPage,
            page,
        );
    }
}

fn initialize_workload_page(frame_address: u64, token: u64, probe_address: u64) {
    zero_page(frame_address);
    let page = CrashServiceUserPage {
        observed_value: token,
        probe_address,
        heartbeat: 0,
        stack_evidence: 0,
    };
    unsafe {
        ptr::write(
            (PHYSICAL_MEMORY_OFFSET + frame_address) as *mut CrashServiceUserPage,
            page,
        );
    }
}

fn create_userspace_process(
    allocator: &mut PageAllocator,
    scheduler_slot: usize,
    kernel_stack_top: u64,
    data_page: CrashServiceUserPage,
) -> Result<UserspaceFixtureProcess, &'static str> {
    if userspace_payload_size() > PAGE_SIZE as usize {
        return Err("crash-service userspace payload exceeded one page");
    }
    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let (pid, tid) = {
        let ids = unsafe { id_allocator_mut() };
        (ids.allocate_pid()?, ids.allocate_tid()?)
    };

    let code_frame = allocator
        .allocate_page()
        .ok_or("allocator could not provide a code page")?;
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
        .ok_or("allocator could not provide a data page")?;
    unsafe {
        ptr::write(
            (PHYSICAL_MEMORY_OFFSET + data_frame) as *mut CrashServiceUserPage,
            data_page,
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
        .ok_or("allocator could not provide a stack page")?;
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

    let self_capability;
    let kernel_probe_capability;
    {
        let table = unsafe { endpoint_table_mut() };
        let endpoint_slot = table.create_endpoint(pid)?;
        self_capability = table.grant_send_capability(pid, endpoint_slot)?;
        kernel_probe_capability = table.grant_send_capability(KERNEL_PROCESS_ID, endpoint_slot)?;
    }

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
        blocked_syscall_frame: 0,
        wait_resume_outcome: crate::sched::wait::WaitOutcome::Woken,
    };
    let process = Process {
        id: pid,
        instance_generation: clean_slate_service_lifecycle::InstanceGeneration(0),
        state: ProcessState::Ready,
        resource_domain: ResourceDomain::with_address_space(pid, address_space),
        live_threads: 1,
        exit_status: None,
        execution_personality: crate::process::personality::ExecutionPersonality::Native,
    };
    unsafe { process_registry_mut().insert(process)? };
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
    Ok(UserspaceFixtureProcess {
        process_id: pid,
        thread_id: tid,
        observed_value: data_page.observed_value,
        expected_probe_address: data_page.probe_address,
        expected_entry_rip: USER_TEST_CODE_ADDRESS + userspace_after_entry_offset(),
        user_stack_pointer,
        user_stack_segment: gdt_state.user_data_selector.0 as u64,
        stack_evidence: data_page.stack_evidence,
        self_capability,
        kernel_probe_capability,
    })
}

fn verify_process_cleanup(process: UserspaceFixtureProcess) -> Result<(), &'static str> {
    if unsafe { process_registry_mut().get(process.process_id) }.is_some() {
        return Err("process registry still retained a crash-service fixture process");
    }
    let thread_resources: ThreadProcessResources =
        without_interrupts(|| unsafe { scheduler_mut().resources_for_process(process.process_id) });
    if thread_resources != ThreadProcessResources::default() {
        return Err("scheduler still retained fixture thread ownership after teardown");
    }
    let ipc_resources: IpcProcessResources =
        unsafe { endpoint_table_mut().resources_for_pid(process.process_id) };
    if ipc_resources != IpcProcessResources::default() {
        return Err("IPC table still retained fixture ownership after teardown");
    }
    let table = unsafe { endpoint_table_mut() };
    if table.send_message(process.process_id, process.self_capability, b"x")
        != Err(IpcSendError::StaleCapability)
    {
        return Err("revoked self capability did not fail after teardown");
    }
    if table.send_message(KERNEL_PROCESS_ID, process.kernel_probe_capability, b"x")
        != Err(IpcSendError::StaleCapability)
    {
        return Err("owned endpoint teardown did not invalidate external capability");
    }
    kernel_log_fmt(format_args!(
        "[PROC] teardown pid={} resources=0\n",
        process.process_id
    ));
    Ok(())
}

fn current_process_index(state: &CrashServiceSelfTestState) -> Result<usize, &'static str> {
    let thread =
        without_interrupts(|| with_scheduler(|scheduler| scheduler.current_thread_descriptor()))?;
    state
        .processes
        .iter()
        .position(|process| process.process_id != 0 && process.thread_id == thread.id)
        .ok_or("current scheduler thread did not map to a crash-service fixture process")
}

struct SerialLineBuffer {
    bytes: [u8; 96],
    len: usize,
}

impl SerialLineBuffer {
    const fn new() -> Self {
        Self {
            bytes: [0; 96],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }
}

impl Write for SerialLineBuffer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for byte in s.bytes() {
            if self.len >= self.bytes.len() {
                return Err(core::fmt::Error);
            }
            self.bytes[self.len] = byte;
            self.len += 1;
        }
        Ok(())
    }
}

fn emit_declared_service() {
    let mut buffer = SerialLineBuffer::new();
    let _ = format_declared_line(&mut buffer, CRASH_SERVICE_ID);
    kernel_log_line(buffer.as_str());
}

fn emit_instance_line(instance: ServiceInstanceId) {
    let mut buffer = SerialLineBuffer::new();
    let _ = format_instance_line(&mut buffer, instance);
    kernel_log_line(buffer.as_str());
}

fn emit_started(pid: u64, generation: u32) {
    kernel_log_fmt(format_args!(
        "[TEST] crash-service started pid={} gen={}\n",
        pid, generation
    ));
}

fn emit_injecting_fault() {
    kernel_log_line("[TEST] crash-service injecting fault");
}

fn emit_replacement_healthy(pid: u64, generation: u32) {
    kernel_log_fmt(format_args!(
        "[TEST] crash-service replacement healthy pid={} gen={}\n",
        pid, generation
    ));
}

fn emit_workload_progress(progress: u32) {
    kernel_log_fmt(format_args!(
        "[TEST] unrelated workload progress={}\n",
        progress
    ));
}

fn apply_lifecycle_fault_event(state: &mut CrashServiceSelfTestState, instance: ServiceInstanceId) {
    state.harness.on_faulted(instance);
    kernel_log_fmt(format_args!(
        "[SVC ] lifecycle fault service={} gen={} pid={}\n",
        instance.service.0, instance.generation.0, instance.pid.0
    ));
}

fn launch_warmup_workload() -> Result<u64, &'static str> {
    let allocator = crash_service_allocator()?;
    let state = crash_service_state()?;
    let stacks = unsafe { &*task_stacks_mut() };
    let scheduler = unsafe { scheduler_mut() };
    *scheduler = Scheduler::new();
    let probe = VirtAddr::from_ptr(run as *const ()).as_u64();
    let page = CrashServiceUserPage {
        observed_value: WORKLOAD_TOKEN,
        probe_address: probe,
        heartbeat: 0,
        stack_evidence: 0,
    };
    let process = create_userspace_process(allocator, 0, task_stack_top(&stacks[0]), page)?;
    state.processes = [process, UserspaceFixtureProcess::EMPTY];
    start_current_scheduler_thread()
}

fn launch_dual_processes(state: &mut CrashServiceSelfTestState) -> Result<u64, &'static str> {
    let allocator = crash_service_allocator()?;
    let stacks = unsafe { &*task_stacks_mut() };
    let scheduler = unsafe { scheduler_mut() };
    *scheduler = Scheduler::new();

    let gen1_config = CrashServiceLaunchConfig::crash_after_heartbeats(
        InstanceGeneration(1),
        1,
        GEN1_STACK_EVIDENCE,
        FAULT_PROBE_ADDRESS,
    );
    let _instance = state
        .harness
        .start_launch(&gen1_config, 0, CrashServiceFixtureRole::Primary);

    let crash_page = CrashServiceUserPage {
        observed_value: GEN1_STACK_EVIDENCE,
        probe_address: FAULT_PROBE_ADDRESS,
        heartbeat: 0,
        stack_evidence: GEN1_STACK_EVIDENCE,
    };
    let crash_process =
        create_userspace_process(allocator, 0, task_stack_top(&stacks[0]), crash_page)?;
    let actual_instance = ServiceInstanceId::new(
        CRASH_SERVICE_ID,
        InstanceGeneration(1),
        ProcessId(crash_process.process_id),
        DomainId(crash_process.process_id),
    );
    state.harness.on_instance_spawned(actual_instance);
    state.gen1_instance = Some(actual_instance);
    state.gen1_pid = crash_process.process_id;
    emit_instance_line(actual_instance);
    emit_started(crash_process.process_id, 1);
    let _ = state.harness.report_health(InstanceGeneration(1));
    state.harness.on_ready(actual_instance);

    let workload_page = CrashServiceUserPage {
        observed_value: WORKLOAD_TOKEN,
        probe_address: VirtAddr::from_ptr(run as *const ()).as_u64(),
        heartbeat: 0,
        stack_evidence: 0,
    };
    let workload_process =
        create_userspace_process(allocator, 1, task_stack_top(&stacks[1]), workload_page)?;
    state.processes = [crash_process, workload_process];
    state.stage = CrashServiceStage::DualRunning;
    start_current_scheduler_thread()
}

fn launch_replacement_instance() -> Result<u64, &'static str> {
    let allocator = crash_service_allocator()?;
    let state = crash_service_state()?;
    let stacks = unsafe { &*task_stacks_mut() };
    let scheduler = unsafe { scheduler_mut() };
    *scheduler = Scheduler::new();

    let gen2_config = CrashServiceLaunchConfig::healthy_instance(
        InstanceGeneration(2),
        GEN2_STACK_EVIDENCE,
        FAULT_PROBE_ADDRESS,
    );
    let _replacement =
        state
            .harness
            .start_launch(&gen2_config, 0, CrashServiceFixtureRole::Replacement);
    let crash_page = CrashServiceUserPage {
        observed_value: GEN2_STACK_EVIDENCE,
        probe_address: FAULT_PROBE_ADDRESS,
        heartbeat: 0,
        stack_evidence: GEN2_STACK_EVIDENCE,
    };
    let crash_process =
        create_userspace_process(allocator, 0, task_stack_top(&stacks[0]), crash_page)?;
    if crash_process.process_id == state.gen1_pid {
        return Err("replacement crash-service reused the failed instance pid");
    }
    if crash_process.stack_evidence != GEN2_STACK_EVIDENCE {
        return Err("replacement crash-service did not receive fresh stack evidence");
    }
    state.gen2_pid = crash_process.process_id;
    let instance = ServiceInstanceId::new(
        CRASH_SERVICE_ID,
        InstanceGeneration(2),
        ProcessId(crash_process.process_id),
        DomainId(crash_process.process_id),
    );
    state.harness.on_instance_spawned(instance);
    state.harness.on_ready(instance);
    emit_replacement_healthy(crash_process.process_id, 2);
    state.stage = CrashServiceStage::ReplacementHealthy;
    state.processes = [crash_process, UserspaceFixtureProcess::EMPTY];
    start_current_scheduler_thread()
}

fn launch_final_workload() -> Result<u64, &'static str> {
    let allocator = crash_service_allocator()?;
    let state = crash_service_state()?;
    let stacks = unsafe { &*task_stacks_mut() };
    let scheduler = unsafe { scheduler_mut() };
    *scheduler = Scheduler::new();
    let page = CrashServiceUserPage {
        observed_value: WORKLOAD_TOKEN,
        probe_address: VirtAddr::from_ptr(run as *const ()).as_u64(),
        heartbeat: 0,
        stack_evidence: 0,
    };
    let process = create_userspace_process(allocator, 0, task_stack_top(&stacks[0]), page)?;
    state.processes = [process, UserspaceFixtureProcess::EMPTY];
    start_current_scheduler_thread()
}

fn finish_self_test() -> Result<u64, &'static str> {
    let state = crash_service_state()?;
    if state.harness.state() != ServiceLifecycleState::Running {
        return Err("crash-service fixture did not end in a healthy running state");
    }
    if state.workload.progress() < state.workload_progress_before_fault + 2 {
        return Err("unrelated workload did not continue after replacement");
    }
    if state.gen2_pid == 0 || state.gen2_pid == state.gen1_pid {
        return Err("replacement instance pid evidence missing");
    }
    unsafe {
        *CRASH_SERVICE_STATE.get() = None;
        *CRASH_SERVICE_ALLOCATOR.get() = None;
    }
    kernel_log_line("[M4.7] PASS");
    qemu_exit(QEMU_EXIT_SUCCESS)
}

fn launch_next_stage() -> Result<u64, &'static str> {
    let state = crash_service_state()?;
    match state.stage {
        CrashServiceStage::WarmupWorkload => launch_warmup_workload(),
        CrashServiceStage::DualRunning => launch_dual_processes(state),
        CrashServiceStage::ReplacementHealthy => launch_replacement_instance(),
        CrashServiceStage::FinalWorkload => launch_final_workload(),
        CrashServiceStage::Complete => finish_self_test(),
        _ => Err("crash-service self-test reached launch_next_stage in an invalid stage"),
    }
}

pub(crate) fn start_crash_service_self_test(allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *endpoint_table_mut() = IpcEndpointTable::new();
        *scheduler_mut() = Scheduler::new();
    }
    let workload_launch =
        UnrelatedWorkloadLaunchConfig::new(UNRELATED_WORKLOAD_SERVICE_ID, WORKLOAD_TOKEN);
    let kernel_root_frame = current_root_frame_address();
    emit_declared_service();
    unsafe {
        *CRASH_SERVICE_ALLOCATOR.get() = Some(allocator);
        *CRASH_SERVICE_STATE.get() = Some(CrashServiceSelfTestState {
            kernel_root_frame,
            stage: CrashServiceStage::WarmupWorkload,
            harness: CrashServiceFixtureHarness::new(),
            workload: UnrelatedWorkloadFixture::from_launch(workload_launch),
            workload_progress_before_fault: 2,
            gen1_instance: None,
            gen1_pid: 0,
            gen2_pid: 0,
            processes: [UserspaceFixtureProcess::EMPTY; 2],
        });
    }
    let frame_pointer = match launch_next_stage() {
        Ok(frame_pointer) => frame_pointer,
        Err(message) => fatal_kernel_error(message),
    };
    unsafe { restore_task_context(frame_pointer) }
}

pub(crate) fn handle_crash_service_userspace_entry(
    context: &InterruptContext,
) -> Result<u64, &'static str> {
    let frame = userspace_frame(context);
    let state = crash_service_state()?;
    let process_index = current_process_index(state)?;
    let process = state.processes[process_index];
    validate_userspace_entry_trap(
        context,
        frame,
        process.expected_entry_rip,
        process.user_stack_pointer,
        process.user_stack_segment,
    )?;
    if context.rdi != process.observed_value {
        return Err("crash-service fixture observed an unexpected payload value");
    }

    let allocator = crash_service_allocator()?;
    let kernel_root_frame = state.kernel_root_frame;

    match state.stage {
        CrashServiceStage::WarmupWorkload => {
            let progress = state.workload.tick();
            emit_workload_progress(progress);
            let teardown = teardown_current_process(allocator, kernel_root_frame, 0, false)?;
            verify_process_cleanup(process)?;
            state.processes = [UserspaceFixtureProcess::EMPTY; 2];
            if progress >= state.workload_progress_before_fault {
                state.stage = CrashServiceStage::DualRunning;
            }
            if let Some(next) = teardown.next_stack_pointer {
                return Ok(next);
            }
            launch_next_stage()
        }
        CrashServiceStage::DualRunning if process_index == 1 => {
            let progress = state.workload.tick();
            emit_workload_progress(progress);
            let teardown = teardown_current_process(allocator, kernel_root_frame, 0, false)?;
            verify_process_cleanup(process)?;
            state.processes[1] = UserspaceFixtureProcess::EMPTY;
            if let Some(next) = teardown.next_stack_pointer {
                return Ok(next);
            }
            launch_next_stage()
        }
        CrashServiceStage::DualRunning if process_index == 0 => {
            let gen1_config = CrashServiceLaunchConfig::crash_after_heartbeats(
                InstanceGeneration(1),
                1,
                GEN1_STACK_EVIDENCE,
                FAULT_PROBE_ADDRESS,
            );
            let heartbeat = 1u32;
            if state.harness.should_inject_fault(&gen1_config, heartbeat) {
                emit_injecting_fault();
                state.stage = CrashServiceStage::CrashFaultResume;
                return Ok(context as *const InterruptContext as u64);
            }
            Err("crash-service did not reach inject stage on schedule")
        }
        CrashServiceStage::WorkloadAfterFault if process_index == 1 => {
            let progress = state.workload.tick();
            emit_workload_progress(progress);
            let teardown = teardown_current_process(allocator, kernel_root_frame, 0, false)?;
            verify_process_cleanup(process)?;
            state.processes[1] = UserspaceFixtureProcess::EMPTY;
            state.stage = CrashServiceStage::ReplacementHealthy;
            if let Some(next) = teardown.next_stack_pointer {
                return Ok(next);
            }
            launch_next_stage()
        }
        CrashServiceStage::FinalWorkload if process_index == 0 => {
            if process.stack_evidence == GEN1_STACK_EVIDENCE {
                return Err("final workload observed stale gen1 stack evidence");
            }
            let progress = state.workload.tick();
            emit_workload_progress(progress);
            let teardown = teardown_current_process(allocator, kernel_root_frame, 0, false)?;
            verify_process_cleanup(process)?;
            state.processes[0] = UserspaceFixtureProcess::EMPTY;
            state.stage = CrashServiceStage::Complete;
            if let Some(next) = teardown.next_stack_pointer {
                return Ok(next);
            }
            launch_next_stage()
        }
        CrashServiceStage::ReplacementHealthy if process_index == 0 => {
            if process.stack_evidence != GEN2_STACK_EVIDENCE {
                return Err("replacement instance resumed stale user stack evidence");
            }
            let teardown = teardown_current_process(allocator, kernel_root_frame, 0, false)?;
            verify_process_cleanup(process)?;
            state.processes[0] = UserspaceFixtureProcess::EMPTY;
            state.stage = CrashServiceStage::FinalWorkload;
            if let Some(next) = teardown.next_stack_pointer {
                return Ok(next);
            }
            launch_next_stage()
        }
        _ => Err("crash-service userspace entry in unexpected stage"),
    }
}

pub(crate) fn handle_crash_service_page_fault(context: &InterruptContext) -> ! {
    if context.cs & 3 != 3 {
        fatal_kernel_error("crash-service page fault did not originate from CPL3");
    }
    let fault_address = Cr2::read()
        .expect("CR2 must contain a canonical fault address")
        .as_u64();
    let state = match crash_service_state() {
        Ok(state) => state,
        Err(message) => fatal_kernel_error(message),
    };
    if state.stage != CrashServiceStage::CrashFaultResume {
        fatal_kernel_error("crash-service observed an unexpected userspace page fault");
    }
    let process_index = match current_process_index(state) {
        Ok(index) => index,
        Err(message) => fatal_kernel_error(message),
    };
    if process_index != 0 {
        fatal_kernel_error("crash-service fault was not attributed to the crash target");
    }
    let process = state.processes[0];
    if fault_address != process.expected_probe_address {
        fatal_kernel_error("crash-service faulted at an unexpected virtual address");
    }

    let allocator = match crash_service_allocator() {
        Ok(allocator) => allocator,
        Err(message) => fatal_kernel_error(message),
    };
    kernel_log_fmt(format_args!("[PROC] fault pid={}\n", process.process_id));
    let instance = state.gen1_instance.expect("gen1 instance");
    apply_lifecycle_fault_event(state, instance);
    let teardown = match teardown_current_process(allocator, state.kernel_root_frame, 1, true) {
        Ok(teardown) => teardown,
        Err(message) => fatal_kernel_error(message),
    };
    if teardown.next_stack_pointer.is_none() {
        fatal_kernel_error("crash-service fault teardown lost the unrelated workload");
    }
    if let Err(message) = verify_process_cleanup(process) {
        fatal_kernel_error(message);
    }
    state.processes[0] = UserspaceFixtureProcess::EMPTY;
    state.stage = CrashServiceStage::WorkloadAfterFault;
    unsafe { restore_task_context(teardown.next_stack_pointer.expect("checked above")) }
}
