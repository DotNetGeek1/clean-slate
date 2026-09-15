//! Milestone 3.6 resource-accounting self-test: repeatedly creates bounded
//! userspace domains, emits live resource snapshots, tears them down through the
//! production coordinator, and proves registry-slot reuse beyond fixed capacity.

#[cfg(feature = "m3-resources-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_address_space_test_after_entry;
#[cfg(feature = "m3-resources-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_address_space_test_end;
use crate::arch::x86_64::asm::clean_slate_user_address_space_test_start;
use crate::arch::x86_64::context_switch::build_userspace_entry_frame;
use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::gdt::selector_rpl;
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
use crate::process::domain::resource_snapshot;
use crate::process::domain::teardown_current_process;
use crate::process::domain::ResourceSnapshot;
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
use core::ptr;
use x86_64::registers::control::Cr2;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

const NORMAL_RESOURCE_CYCLES: usize = 8;
const TOTAL_EXPECTED_PROCESS_CREATIONS: u64 = 10;
const LIVE_RESOURCE_MARKER: &str = "[RES ] pid=";

#[derive(Clone, Copy)]
struct UserspaceResourceTestPage {
    observed_value: u64,
    probe_address: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SystemResourceSnapshot {
    allocated_pages: u64,
    process_slots: usize,
    thread_slots: usize,
    ipc_endpoints: usize,
    ipc_handles: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ResourceScenarioStage {
    NormalExit,
    FaultResume,
    FaultCompanionExit,
}

#[derive(Clone, Copy)]
struct UserspaceResourceProcess {
    process_id: u64,
    thread_id: u64,
    observed_value: u64,
    expected_probe_address: u64,
    expected_entry_rip: u64,
    user_stack_pointer: u64,
    user_stack_segment: u64,
    self_capability: u64,
    kernel_probe_capability: u64,
}

impl UserspaceResourceProcess {
    const EMPTY: Self = Self {
        process_id: 0,
        thread_id: 0,
        observed_value: 0,
        expected_probe_address: 0,
        expected_entry_rip: 0,
        user_stack_pointer: 0,
        user_stack_segment: 0,
        self_capability: 0,
        kernel_probe_capability: 0,
    };
}

struct UserspaceResourcesState {
    kernel_root_frame: u64,
    baseline: SystemResourceSnapshot,
    normal_cycles_completed: usize,
    fault_cycle_started: bool,
    total_created_processes: u64,
    first_pid: u64,
    first_tid: u64,
    last_pid: u64,
    last_tid: u64,
    stage: ResourceScenarioStage,
    processes: [UserspaceResourceProcess; 2],
}

static USERSPACE_RESOURCES_ALLOCATOR: GlobalCell<Option<PageAllocator>> = GlobalCell::new(None);
static USERSPACE_RESOURCES_STATE: GlobalCell<Option<UserspaceResourcesState>> =
    GlobalCell::new(None);

fn userspace_resources_test_size() -> usize {
    (&raw const clean_slate_user_address_space_test_end as usize)
        .saturating_sub(&raw const clean_slate_user_address_space_test_start as usize)
}

fn userspace_resources_after_entry_offset() -> u64 {
    ((&raw const clean_slate_user_address_space_test_after_entry as usize)
        .saturating_sub(&raw const clean_slate_user_address_space_test_start as usize)) as u64
}

fn userspace_resources_state() -> Result<&'static mut UserspaceResourcesState, &'static str> {
    unsafe {
        (&mut *USERSPACE_RESOURCES_STATE.get())
            .as_mut()
            .ok_or("userspace resources self-test state was not initialized")
    }
}

fn userspace_resources_allocator() -> Result<&'static mut PageAllocator, &'static str> {
    unsafe {
        (&mut *USERSPACE_RESOURCES_ALLOCATOR.get())
            .as_mut()
            .ok_or("userspace resources self-test allocator was not initialized")
    }
}

fn initialize_userspace_resource_page(frame_address: u64, observed_value: u64, probe_address: u64) {
    zero_page(frame_address);
    unsafe {
        ptr::write(
            (PHYSICAL_MEMORY_OFFSET + frame_address) as *mut UserspaceResourceTestPage,
            UserspaceResourceTestPage {
                observed_value,
                probe_address,
            },
        );
    }
}

fn copy_userspace_resource_payload(frame_address: u64) {
    unsafe {
        ptr::copy_nonoverlapping(
            &raw const clean_slate_user_address_space_test_start,
            (PHYSICAL_MEMORY_OFFSET + frame_address) as *mut u8,
            userspace_resources_test_size(),
        );
    }
}

fn create_resource_process(
    allocator: &mut PageAllocator,
    scheduler_slot: usize,
    kernel_stack_top: u64,
    observed_value: u64,
    probe_address: u64,
) -> Result<UserspaceResourceProcess, &'static str> {
    if userspace_resources_test_size() > PAGE_SIZE as usize {
        return Err("userspace resources test payload exceeded one page");
    }
    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let (pid, tid) = {
        let ids = unsafe { id_allocator_mut() };
        (ids.allocate_pid()?, ids.allocate_tid()?)
    };

    let code_frame_address = allocator
        .allocate_page()
        .ok_or("allocator could not provide a code page for a resources test process")?;
    zero_page(code_frame_address);
    copy_userspace_resource_payload(code_frame_address);
    map_process_page(
        &mut address_space,
        USER_TEST_CODE_ADDRESS,
        code_frame_address,
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    )?;

    let data_frame_address = allocator
        .allocate_page()
        .ok_or("allocator could not provide a data page for a resources test process")?;
    initialize_userspace_resource_page(data_frame_address, observed_value, probe_address);
    map_process_page(
        &mut address_space,
        USER_TEST_DATA_ADDRESS,
        data_frame_address,
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    )?;

    let stack_frame_address = allocator
        .allocate_page()
        .ok_or("allocator could not provide a stack page for a resources test process")?;
    zero_page(stack_frame_address);
    map_process_page(
        &mut address_space,
        USER_TEST_PROCESS_STACK_ADDRESS,
        stack_frame_address,
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
    };
    let process = Process {
        id: pid,
        state: ProcessState::Ready,
        resource_domain: ResourceDomain::with_address_space(pid, address_space),
        live_threads: 1,
        exit_status: None,
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
    Ok(UserspaceResourceProcess {
        process_id: pid,
        thread_id: tid,
        observed_value,
        expected_probe_address: probe_address,
        expected_entry_rip: USER_TEST_CODE_ADDRESS + userspace_resources_after_entry_offset(),
        user_stack_pointer,
        user_stack_segment: gdt_state.user_data_selector.0 as u64,
        self_capability,
        kernel_probe_capability,
    })
}

fn capture_system_snapshot(allocator: &PageAllocator) -> SystemResourceSnapshot {
    let ipc_resources = unsafe { endpoint_table_mut().active_resources() };
    let process_slots = unsafe { process_registry_mut().occupied_slots() };
    let thread_slots = without_interrupts(|| unsafe { scheduler_mut().occupied_thread_slots() });
    SystemResourceSnapshot {
        allocated_pages: allocator.stats().allocated_pages,
        process_slots,
        thread_slots,
        ipc_endpoints: ipc_resources.owned_endpoints,
        ipc_handles: ipc_resources.held_capabilities,
    }
}

fn log_baseline(snapshot: SystemResourceSnapshot) {
    kernel_log_fmt(format_args!(
        "[RES ] baseline pages={} handles={} threads={}\n",
        snapshot.allocated_pages, snapshot.ipc_handles, snapshot.thread_slots
    ));
}

fn log_resource_snapshot(process_id: u64, snapshot: ResourceSnapshot) {
    kernel_log_fmt(format_args!(
        "{LIVE_RESOURCE_MARKER}{} pages={} tables={} endpoints={} handles={} threads={} runnable={} stacks={}\n",
        process_id,
        snapshot.user_pages,
        snapshot.page_table_frames,
        snapshot.ipc_endpoints,
        snapshot.ipc_handles,
        snapshot.threads,
        snapshot.runnable_threads,
        snapshot.kernel_stacks
    ));
}

fn verify_process_cleanup(process: UserspaceResourceProcess) -> Result<(), &'static str> {
    if unsafe { process_registry_mut().get(process.process_id) }.is_some() {
        return Err("process registry still retained a released resources-test process");
    }
    let thread_resources: ThreadProcessResources =
        without_interrupts(|| unsafe { scheduler_mut().resources_for_process(process.process_id) });
    if thread_resources != ThreadProcessResources::default() {
        return Err("scheduler still retained resources-test thread ownership after teardown");
    }
    let ipc_resources: IpcProcessResources =
        unsafe { endpoint_table_mut().resources_for_pid(process.process_id) };
    if ipc_resources != IpcProcessResources::default() {
        return Err("IPC table still retained resources-test ownership after teardown");
    }
    let table = unsafe { endpoint_table_mut() };
    if table.send_message(process.process_id, process.self_capability, b"x")
        != Err(IpcSendError::StaleCapability)
    {
        return Err("revoked self capability did not fail deterministically after teardown");
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

fn verify_baseline_restored(
    allocator: &PageAllocator,
    baseline: SystemResourceSnapshot,
) -> Result<(), &'static str> {
    let current = capture_system_snapshot(allocator);
    if current != baseline {
        return Err("resource accounting did not return to the recorded baseline");
    }
    Ok(())
}

fn current_process_index(state: &UserspaceResourcesState) -> Result<usize, &'static str> {
    let thread =
        without_interrupts(|| with_scheduler(|scheduler| scheduler.current_thread_descriptor()))?;
    state
        .processes
        .iter()
        .position(|process| process.process_id != 0 && process.thread_id == thread.id)
        .ok_or("current scheduler thread did not map to a resources-test process")
}

fn launch_next_scenario() -> Result<u64, &'static str> {
    let allocator = userspace_resources_allocator()?;
    let state = userspace_resources_state()?;
    let stacks = unsafe { &*task_stacks_mut() };
    let scheduler = unsafe { scheduler_mut() };
    *scheduler = Scheduler::new();

    if state.normal_cycles_completed < NORMAL_RESOURCE_CYCLES {
        let observed_value = (state.normal_cycles_completed as u64) + 1;
        let process = create_resource_process(
            allocator,
            0,
            task_stack_top(&stacks[0]),
            observed_value,
            VirtAddr::from_ptr(run as *const ()).as_u64(),
        )?;
        state.total_created_processes += 1;
        if state.first_pid == 0 {
            state.first_pid = process.process_id;
            state.first_tid = process.thread_id;
        }
        state.last_pid = process.process_id;
        state.last_tid = process.thread_id;
        state.stage = ResourceScenarioStage::NormalExit;
        state.processes = [process, UserspaceResourceProcess::EMPTY];
        kernel_log_fmt(format_args!(
            "[PROC] created pid={} tid={}\n",
            process.process_id, process.thread_id
        ));
        return start_current_scheduler_thread();
    }

    if !state.fault_cycle_started {
        let fault_process = create_resource_process(
            allocator,
            0,
            task_stack_top(&stacks[0]),
            0x4641_554c_545f_0001,
            VirtAddr::from_ptr(run as *const ()).as_u64(),
        )?;
        let companion_process = create_resource_process(
            allocator,
            1,
            task_stack_top(&stacks[1]),
            0x4641_554c_545f_0002,
            VirtAddr::from_ptr(run as *const ()).as_u64(),
        )?;
        state.total_created_processes += 2;
        if state.first_pid == 0 {
            state.first_pid = fault_process.process_id;
            state.first_tid = fault_process.thread_id;
        }
        state.last_pid = companion_process.process_id;
        state.last_tid = companion_process.thread_id;
        state.fault_cycle_started = true;
        state.stage = ResourceScenarioStage::FaultResume;
        state.processes = [fault_process, companion_process];
        kernel_log_fmt(format_args!(
            "[PROC] created pid={} tid={}\n",
            fault_process.process_id, fault_process.thread_id
        ));
        kernel_log_fmt(format_args!(
            "[PROC] created pid={} tid={}\n",
            companion_process.process_id, companion_process.thread_id
        ));
        return start_current_scheduler_thread();
    }

    if state.total_created_processes != TOTAL_EXPECTED_PROCESS_CREATIONS
        || state
            .last_pid
            .saturating_sub(state.first_pid)
            .saturating_add(1)
            != TOTAL_EXPECTED_PROCESS_CREATIONS
        || state
            .last_tid
            .saturating_sub(state.first_tid)
            .saturating_add(1)
            != TOTAL_EXPECTED_PROCESS_CREATIONS
    {
        return Err("resources test did not complete the required monotonic create/reap cycles");
    }
    verify_baseline_restored(allocator, state.baseline)?;
    unsafe {
        *USERSPACE_RESOURCES_STATE.get() = None;
        *USERSPACE_RESOURCES_ALLOCATOR.get() = None;
    }
    kernel_log_line("[M3.6] PASS");
    qemu_exit(QEMU_EXIT_SUCCESS)
}

pub(crate) fn start_userspace_resources_self_test(allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *endpoint_table_mut() = IpcEndpointTable::new();
        *scheduler_mut() = Scheduler::new();
    }
    let baseline = capture_system_snapshot(&allocator);
    log_baseline(baseline);
    let kernel_root_frame = current_root_frame_address();
    unsafe {
        *USERSPACE_RESOURCES_ALLOCATOR.get() = Some(allocator);
        *USERSPACE_RESOURCES_STATE.get() = Some(UserspaceResourcesState {
            kernel_root_frame,
            baseline,
            normal_cycles_completed: 0,
            fault_cycle_started: false,
            total_created_processes: 0,
            first_pid: 0,
            first_tid: 0,
            last_pid: 0,
            last_tid: 0,
            stage: ResourceScenarioStage::NormalExit,
            processes: [UserspaceResourceProcess::EMPTY; 2],
        });
    }
    let frame_pointer = match launch_next_scenario() {
        Ok(frame_pointer) => frame_pointer,
        Err(message) => fatal_kernel_error(message),
    };
    unsafe { restore_task_context(frame_pointer) }
}

pub(crate) fn handle_userspace_resource_entry(
    context: &InterruptContext,
) -> Result<u64, &'static str> {
    let frame = userspace_frame(context);
    let state = userspace_resources_state()?;
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
        return Err("resources-test process observed an unexpected payload value");
    }

    let snapshot = resource_snapshot(process.process_id)?;
    if snapshot.user_pages == 0
        || snapshot.page_table_frames == 0
        || snapshot.ipc_endpoints == 0
        || snapshot.ipc_handles == 0
        || snapshot.threads == 0
        || snapshot.kernel_stacks == 0
    {
        return Err("resources-test live snapshot missed owned resources");
    }
    log_resource_snapshot(process.process_id, snapshot);

    match state.stage {
        ResourceScenarioStage::NormalExit => {
            let allocator = userspace_resources_allocator()?;
            let baseline = state.baseline;
            let kernel_root_frame = state.kernel_root_frame;
            let teardown = teardown_current_process(allocator, kernel_root_frame, 0, false)?;
            if resource_snapshot(teardown.process_id).is_ok() {
                return Err("released process unexpectedly remained snapshot-visible");
            }
            verify_process_cleanup(process)?;
            verify_baseline_restored(allocator, baseline)?;
            state.normal_cycles_completed += 1;
            state.processes = [UserspaceResourceProcess::EMPTY; 2];
            if let Some(next_stack_pointer) = teardown.next_stack_pointer {
                return Ok(next_stack_pointer);
            }
            launch_next_scenario()
        }
        ResourceScenarioStage::FaultResume if process_index == 0 => {
            Ok(context as *const InterruptContext as u64)
        }
        ResourceScenarioStage::FaultCompanionExit if process_index == 1 => {
            let allocator = userspace_resources_allocator()?;
            let baseline = state.baseline;
            let kernel_root_frame = state.kernel_root_frame;
            let teardown = teardown_current_process(allocator, kernel_root_frame, 0, false)?;
            if teardown.next_stack_pointer.is_some() {
                return Err("final companion exit unexpectedly left runnable work");
            }
            verify_process_cleanup(process)?;
            verify_baseline_restored(allocator, baseline)?;
            state.processes = [UserspaceResourceProcess::EMPTY; 2];
            launch_next_scenario()
        }
        _ => Err("resources-test reached an unexpected userspace rendezvous stage"),
    }
}

pub(crate) fn handle_userspace_resource_page_fault(context: &InterruptContext) -> ! {
    if selector_rpl(context.cs) != 3 {
        fatal_kernel_error("resources-test page fault did not originate from CPL3");
    }
    let fault_address = Cr2::read()
        .expect("CR2 must contain a canonical fault address")
        .as_u64();
    let state = match userspace_resources_state() {
        Ok(state) => state,
        Err(message) => fatal_kernel_error(message),
    };
    let process_index = match current_process_index(state) {
        Ok(index) => index,
        Err(message) => fatal_kernel_error(message),
    };
    let process = state.processes[process_index];
    if state.stage != ResourceScenarioStage::FaultResume || process_index != 0 {
        fatal_kernel_error("resources-test observed an unexpected userspace page fault");
    }
    if fault_address != process.expected_probe_address {
        fatal_kernel_error("resources-test process faulted at an unexpected virtual address");
    }

    let allocator = match userspace_resources_allocator() {
        Ok(allocator) => allocator,
        Err(message) => fatal_kernel_error(message),
    };
    kernel_log_fmt(format_args!("[PROC] fault pid={}\n", process.process_id));
    let teardown = match teardown_current_process(allocator, state.kernel_root_frame, 1, true) {
        Ok(teardown) => teardown,
        Err(message) => fatal_kernel_error(message),
    };
    if teardown.next_stack_pointer.is_none() {
        fatal_kernel_error("fault teardown lost the remaining runnable companion process");
    }
    if teardown.exit_status != 1 {
        fatal_kernel_error("fault teardown reported an unexpected exit status");
    }
    if teardown.released_resources.ipc_endpoints == 0 || teardown.released_resources.threads == 0 {
        fatal_kernel_error("fault teardown released an incomplete resource snapshot");
    }
    if let Err(message) = verify_process_cleanup(process) {
        fatal_kernel_error(message);
    }
    state.processes[0] = UserspaceResourceProcess::EMPTY;
    state.stage = ResourceScenarioStage::FaultCompanionExit;
    unsafe { restore_task_context(teardown.next_stack_pointer.expect("checked above")) }
}
