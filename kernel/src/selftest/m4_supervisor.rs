//! Milestone 4 supervisor/recovery self-test: launches a userspace supervisor
//! and a crash-once service, tears down the failed service through the M3
//! lifecycle path, and proves the supervisor restarts the logical service
//! through an explicit restart capability.

use crate::arch::x86_64::asm::clean_slate_user_service_test_after_entry;
use crate::arch::x86_64::asm::clean_slate_user_service_test_end;
use crate::arch::x86_64::asm::clean_slate_user_service_test_start;
use crate::arch::x86_64::asm::clean_slate_user_supervisor_test_end;
use crate::arch::x86_64::asm::clean_slate_user_supervisor_test_start;
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
use crate::interrupt::timer::kernel_ticks;
use crate::mm::address_space::create_process_address_space;
use crate::mm::address_space::map_process_page;
use crate::mm::frame_allocator::free_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
use crate::mm::paging::zero_page;
use crate::mm::PAGE_SIZE;
use crate::mm::PHYSICAL_MEMORY_OFFSET;
use crate::process::domain::resource_snapshot;
use crate::process::domain::teardown_current_process;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::process_registry_mut;
use crate::process::Process;
use crate::process::ProcessState;
use crate::process::ResourceDomain;
use crate::run;
use crate::sched::dispatch::schedule_next_thread;
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
use crate::selftest::USER_TEST_CODE_ADDRESS;
use crate::selftest::USER_TEST_DATA_ADDRESS;
use crate::selftest::USER_TEST_PROCESS_STACK_ADDRESS;
use crate::sync::global_cell::GlobalCell;
use core::ptr;
use x86_64::registers::control::Cr2;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

const LOGICAL_SERVICE_ID: u64 = 1;
const SERVICE_NAME: &str = "crash-once";
const SUPERVISOR_RESTART_LIMIT: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ServiceLifecycleState {
    Empty = 0,
    Starting = 1,
    Running = 2,
    Failed = 3,
    Restarting = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RestartCapabilityHandleParts {
    slot: u16,
    generation: u16,
}

impl RestartCapabilityHandleParts {
    fn encode(self) -> u64 {
        u64::from(self.slot) | (u64::from(self.generation) << 16)
    }

    fn decode(raw: u64) -> Self {
        Self {
            slot: raw as u16,
            generation: (raw >> 16) as u16,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RestartCapability {
    holder_pid: u64,
    generation: u16,
    service_id: u64,
    active: bool,
}

impl RestartCapability {
    const EMPTY: Self = Self {
        holder_pid: 0,
        generation: 0,
        service_id: 0,
        active: false,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RestartCapabilityTable {
    entries: [RestartCapability; 1],
}

impl RestartCapabilityTable {
    const fn new() -> Self {
        Self {
            entries: [RestartCapability::EMPTY; 1],
        }
    }

    fn clear(&mut self) {
        *self = Self::new();
    }

    fn grant(&mut self, holder_pid: u64, service_id: u64) -> Result<u64, &'static str> {
        let capability = self
            .entries
            .get_mut(0)
            .ok_or("restart capability slot was missing")?;
        capability.holder_pid = holder_pid;
        capability.service_id = service_id;
        capability.generation = capability
            .generation
            .checked_add(1)
            .ok_or("restart capability generation exhausted")?;
        capability.active = true;
        Ok(RestartCapabilityHandleParts {
            slot: 0,
            generation: capability.generation,
        }
        .encode())
    }

    fn validate(&self, holder_pid: u64, raw: u64, service_id: u64) -> Result<(), &'static str> {
        let handle = RestartCapabilityHandleParts::decode(raw);
        let capability = self
            .entries
            .get(handle.slot as usize)
            .ok_or("restart capability slot was out of range")?;
        if !capability.active {
            return Err("restart capability was not active");
        }
        if capability.generation != handle.generation {
            return Err("restart capability was stale");
        }
        if capability.holder_pid != holder_pid {
            return Err("restart capability holder was unauthorized");
        }
        if capability.service_id != service_id {
            return Err("restart capability did not match the logical service");
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct UserspaceServicePayloadData {
    service_id: u64,
    should_crash: u64,
    fault_address: u64,
}

#[derive(Clone, Copy)]
struct UserspaceSupervisorPayloadData {
    restart_capability: u64,
    service_id: u64,
    failed_pid: u64,
    restarted_pid: u64,
}

#[derive(Clone, Copy)]
struct M4Process {
    process_id: u64,
    thread_id: u64,
    thread: Thread,
    expected_entry_rip: u64,
    user_stack_pointer: u64,
    user_stack_segment: u64,
}

#[derive(Clone, Copy)]
struct ServiceRecord {
    logical_id: u64,
    generation: u8,
    state: ServiceLifecycleState,
    current_pid: u64,
    last_failed_pid: u64,
    last_exit_status: u64,
    restart_budget_remaining: u8,
}

struct M4SupervisorState {
    kernel_root_frame: u64,
    ticks_at_start: u64,
    ticks_at_fault: u64,
    supervisor: M4Process,
    service: M4Process,
    service_record: ServiceRecord,
    restart_capabilities: RestartCapabilityTable,
}

static USERSPACE_M4_ALLOCATOR: GlobalCell<Option<PageAllocator>> = GlobalCell::new(None);
static USERSPACE_M4_STATE: GlobalCell<Option<M4SupervisorState>> = GlobalCell::new(None);

fn service_test_size() -> usize {
    (&raw const clean_slate_user_service_test_end as usize)
        .saturating_sub(&raw const clean_slate_user_service_test_start as usize)
}

fn service_test_after_entry_offset() -> u64 {
    ((&raw const clean_slate_user_service_test_after_entry as usize)
        .saturating_sub(&raw const clean_slate_user_service_test_start as usize)) as u64
}

fn supervisor_test_size() -> usize {
    (&raw const clean_slate_user_supervisor_test_end as usize)
        .saturating_sub(&raw const clean_slate_user_supervisor_test_start as usize)
}

fn m4_state() -> Result<&'static mut M4SupervisorState, &'static str> {
    unsafe {
        (&mut *USERSPACE_M4_STATE.get())
            .as_mut()
            .ok_or("M4 supervisor state was not initialized")
    }
}

fn m4_allocator() -> Result<&'static mut PageAllocator, &'static str> {
    unsafe {
        (&mut *USERSPACE_M4_ALLOCATOR.get())
            .as_mut()
            .ok_or("M4 supervisor allocator was not initialized")
    }
}

fn encode_service_status(record: ServiceRecord) -> u64 {
    u64::from(record.state as u8) | (u64::from(record.generation) << 8) | (record.current_pid << 16)
}

fn copy_payload(frame_address: u64, start: *const u8, size: usize) {
    unsafe {
        ptr::copy_nonoverlapping(
            start,
            (PHYSICAL_MEMORY_OFFSET + frame_address) as *mut u8,
            size,
        );
    }
}

fn create_process_with_payload<T: Copy>(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    payload_start: *const u8,
    payload_size: usize,
    after_entry_offset: u64,
    data: T,
) -> Result<M4Process, &'static str> {
    if payload_size > PAGE_SIZE as usize {
        return Err("M4 userspace payload exceeded one page");
    }
    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let (pid, tid) = {
        let ids = unsafe { id_allocator_mut() };
        (ids.allocate_pid()?, ids.allocate_tid()?)
    };
    let code_frame_address = allocator
        .allocate_page()
        .ok_or("allocator could not provide an M4 code page")?;
    zero_page(code_frame_address);
    copy_payload(code_frame_address, payload_start, payload_size);
    map_process_page(
        &mut address_space,
        USER_TEST_CODE_ADDRESS,
        code_frame_address,
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    )?;

    let data_frame_address = allocator
        .allocate_page()
        .ok_or("allocator could not provide an M4 data page")?;
    zero_page(data_frame_address);
    unsafe {
        ptr::write(
            (PHYSICAL_MEMORY_OFFSET + data_frame_address) as *mut T,
            data,
        );
    }
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
        .ok_or("allocator could not provide an M4 stack page")?;
    zero_page(stack_frame_address);
    if let Err(message) = map_process_page(
        &mut address_space,
        USER_TEST_PROCESS_STACK_ADDRESS,
        stack_frame_address,
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    ) {
        unsafe {
            free_frame(allocator, stack_frame_address)?;
            free_frame(allocator, data_frame_address)?;
            free_frame(allocator, code_frame_address)?;
        }
        return Err(message);
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
    unsafe {
        process_registry_mut().insert(Process {
            id: pid,
            state: ProcessState::Ready,
            resource_domain: ResourceDomain::with_address_space(pid, address_space),
            live_threads: 1,
            exit_status: None,
        })?
    };
    Ok(M4Process {
        process_id: pid,
        thread_id: tid,
        thread,
        expected_entry_rip: USER_TEST_CODE_ADDRESS + after_entry_offset,
        user_stack_pointer,
        user_stack_segment: gdt_state.user_data_selector.0 as u64,
    })
}

fn create_supervisor_process(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    restart_capability: u64,
) -> Result<M4Process, &'static str> {
    create_process_with_payload(
        allocator,
        kernel_stack_top,
        &raw const clean_slate_user_supervisor_test_start,
        supervisor_test_size(),
        0,
        UserspaceSupervisorPayloadData {
            restart_capability,
            service_id: LOGICAL_SERVICE_ID,
            failed_pid: 0,
            restarted_pid: 0,
        },
    )
}

fn create_service_process(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    should_crash: bool,
) -> Result<M4Process, &'static str> {
    create_process_with_payload(
        allocator,
        kernel_stack_top,
        &raw const clean_slate_user_service_test_start,
        service_test_size(),
        service_test_after_entry_offset(),
        UserspaceServicePayloadData {
            service_id: LOGICAL_SERVICE_ID,
            should_crash: u64::from(should_crash),
            fault_address: VirtAddr::from_ptr(run as *const ()).as_u64(),
        },
    )
}

fn current_process_index(state: &M4SupervisorState) -> Result<usize, &'static str> {
    let thread =
        without_interrupts(|| with_scheduler(|scheduler| scheduler.current_thread_descriptor()))?;
    if thread.id == state.supervisor.thread_id {
        return Ok(0);
    }
    if thread.id == state.service.thread_id {
        return Ok(1);
    }
    Err("current scheduler thread did not map to an M4 process")
}

fn persist_saved_stack(process: M4Process, saved_stack_pointer: u64) -> Result<(), &'static str> {
    without_interrupts(|| unsafe {
        scheduler_mut().update_thread_saved_stack(process.thread_id, saved_stack_pointer)
    })
}

fn launch_replacement_service(state: &mut M4SupervisorState) -> Result<u64, &'static str> {
    let allocator = m4_allocator()?;
    let stacks = unsafe { &*task_stacks_mut() };
    let replacement = create_service_process(allocator, task_stack_top(&stacks[1]), false)?;
    state.service = replacement;
    state.service_record.generation = state.service_record.generation.saturating_add(1);
    state.service_record.state = ServiceLifecycleState::Restarting;
    state.service_record.current_pid = replacement.process_id;
    let scheduler = unsafe { scheduler_mut() };
    scheduler.configure_thread(
        1,
        replacement.thread.id,
        replacement.thread.owner_process_id,
        replacement.thread.kind,
        replacement.thread.kernel_stack_top,
        replacement.thread.saved_stack_pointer,
        replacement.thread.launch_entry,
    )?;
    Ok(replacement.process_id)
}

pub(crate) fn start_userspace_supervisor_self_test(allocator: PageAllocator) -> ! {
    if service_test_size() > PAGE_SIZE as usize || supervisor_test_size() > PAGE_SIZE as usize {
        fatal_kernel_error("M4 payload exceeded one page");
    }

    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    let stacks = unsafe { &*task_stacks_mut() };
    let mut restart_capabilities = RestartCapabilityTable::new();
    restart_capabilities.clear();
    let restart_capability = restart_capabilities
        .grant(1, LOGICAL_SERVICE_ID)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let mut allocator = allocator;
    let supervisor = create_supervisor_process(
        &mut allocator,
        task_stack_top(&stacks[0]),
        restart_capability,
    )
    .unwrap_or_else(|message| fatal_kernel_error(message));
    let service = create_service_process(&mut allocator, task_stack_top(&stacks[1]), true)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let scheduler = unsafe { scheduler_mut() };
    *scheduler = Scheduler::new();
    scheduler
        .configure_thread(
            0,
            supervisor.thread.id,
            supervisor.thread.owner_process_id,
            supervisor.thread.kind,
            supervisor.thread.kernel_stack_top,
            supervisor.thread.saved_stack_pointer,
            supervisor.thread.launch_entry,
        )
        .unwrap_or_else(|message| fatal_kernel_error(message));
    scheduler
        .configure_thread(
            1,
            service.thread.id,
            service.thread.owner_process_id,
            service.thread.kind,
            service.thread.kernel_stack_top,
            service.thread.saved_stack_pointer,
            service.thread.launch_entry,
        )
        .unwrap_or_else(|message| fatal_kernel_error(message));

    unsafe {
        *USERSPACE_M4_ALLOCATOR.get() = Some(allocator);
        *USERSPACE_M4_STATE.get() = Some(M4SupervisorState {
            kernel_root_frame: current_root_frame_address(),
            ticks_at_start: kernel_ticks(),
            ticks_at_fault: 0,
            supervisor,
            service,
            service_record: ServiceRecord {
                logical_id: LOGICAL_SERVICE_ID,
                generation: 1,
                state: ServiceLifecycleState::Starting,
                current_pid: service.process_id,
                last_failed_pid: 0,
                last_exit_status: 0,
                restart_budget_remaining: SUPERVISOR_RESTART_LIMIT,
            },
            restart_capabilities,
        });
    }
    kernel_log_fmt(format_args!(
        "[M4  ] supervisor started pid={}\n",
        supervisor.process_id
    ));
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}

pub(crate) fn handle_userspace_supervisor_entry(
    context: &InterruptContext,
) -> Result<u64, &'static str> {
    let state = m4_state()?;
    let process_index = current_process_index(state)?;
    let saved_stack_pointer = context as *const InterruptContext as u64;
    match process_index {
        0 => {
            state.supervisor.thread.saved_stack_pointer = saved_stack_pointer;
            persist_saved_stack(state.supervisor, saved_stack_pointer)?;
            if context.rdi == 1 {
                if state.service_record.state != ServiceLifecycleState::Running {
                    return Err("supervisor completed before service reached running state");
                }
                if state.service_record.current_pid == state.service_record.last_failed_pid {
                    return Err("replacement service reused the failed instance identity");
                }
                if kernel_ticks() <= state.ticks_at_fault {
                    return Err("unrelated timer work did not continue across restart");
                }
                kernel_log_fmt(format_args!(
                    "[M4  ] unrelated ticks advanced={} service={} old-pid={} new-pid={}\n",
                    kernel_ticks().saturating_sub(state.ticks_at_start),
                    SERVICE_NAME,
                    state.service_record.last_failed_pid,
                    state.service_record.current_pid
                ));
                unsafe {
                    *USERSPACE_M4_STATE.get() = None;
                    *USERSPACE_M4_ALLOCATOR.get() = None;
                }
                kernel_log_line("[M4  ] PASS");
                qemu_exit(QEMU_EXIT_SUCCESS)
            }
            schedule_next_thread(saved_stack_pointer)
        }
        1 => {
            let process = state.service;
            let frame = userspace_frame(context);
            validate_userspace_entry_trap(
                context,
                frame,
                process.expected_entry_rip,
                process.user_stack_pointer,
                process.user_stack_segment,
            )?;
            state.service.thread.saved_stack_pointer = saved_stack_pointer;
            persist_saved_stack(process, saved_stack_pointer)?;
            let was_restart = state.service_record.generation > 1;
            state.service_record.state = ServiceLifecycleState::Running;
            state.service_record.current_pid = process.process_id;
            if was_restart {
                kernel_log_fmt(format_args!(
                    "[M4  ] service restarted logical={} pid={} generation={}\n",
                    state.service_record.logical_id,
                    process.process_id,
                    state.service_record.generation
                ));
            } else {
                kernel_log_fmt(format_args!(
                    "[M4  ] service started logical={} pid={} generation={}\n",
                    state.service_record.logical_id,
                    process.process_id,
                    state.service_record.generation
                ));
            }
            Ok(saved_stack_pointer)
        }
        _ => Err("M4 supervisor entry reached an unknown process"),
    }
}

pub(crate) fn handle_userspace_supervisor_page_fault(context: &InterruptContext) -> ! {
    if selector_rpl(context.cs) != 3 {
        fatal_kernel_error("M4 userspace page fault did not originate from CPL3");
    }
    let fault_address = Cr2::read()
        .expect("CR2 must contain a canonical fault address")
        .as_u64();
    let state = match m4_state() {
        Ok(state) => state,
        Err(message) => fatal_kernel_error(message),
    };
    let process_index = match current_process_index(state) {
        Ok(index) => index,
        Err(message) => fatal_kernel_error(message),
    };
    if process_index != 1 {
        fatal_kernel_error("M4 supervisor faulted unexpectedly");
    }
    if fault_address != VirtAddr::from_ptr(run as *const ()).as_u64() {
        fatal_kernel_error("M4 service faulted at an unexpected address");
    }
    kernel_log_fmt(format_args!(
        "[M4  ] service deliberately crashed pid={}\n",
        state.service.process_id
    ));
    kernel_log_fmt(format_args!(
        "[PROC] fault pid={}\n",
        state.service.process_id
    ));
    state.ticks_at_fault = kernel_ticks();
    state.service_record.state = ServiceLifecycleState::Failed;
    state.service_record.last_failed_pid = state.service.process_id;
    state.service_record.last_exit_status = 1;
    let allocator = match m4_allocator() {
        Ok(allocator) => allocator,
        Err(message) => fatal_kernel_error(message),
    };
    let teardown = match teardown_current_process(allocator, state.kernel_root_frame, 1, true) {
        Ok(teardown) => teardown,
        Err(message) => fatal_kernel_error(message),
    };
    if teardown.next_stack_pointer.is_none() {
        fatal_kernel_error("M4 teardown lost the supervisor runnable thread");
    }
    if resource_snapshot(teardown.process_id).is_ok() {
        fatal_kernel_error("M4 service remained snapshot-visible after teardown");
    }
    kernel_log_fmt(format_args!(
        "[M4  ] resources reclaimed old-pid={} threads={} user-pages={}\n",
        teardown.process_id,
        teardown.released_resources.threads,
        teardown.released_resources.user_pages
    ));
    unsafe { restore_task_context(teardown.next_stack_pointer.expect("checked above")) }
}

pub(crate) fn supervisor_wait_fault_event(service_id: u64) -> Result<u64, &'static str> {
    let state = m4_state()?;
    if state.service_record.logical_id != service_id {
        return Err("M4 wait fault event used an unknown logical service id");
    }
    if state.service_record.state == ServiceLifecycleState::Failed
        && state.service_record.last_failed_pid != 0
    {
        kernel_log_fmt(format_args!(
            "[M4  ] supervisor detected failure logical={} pid={}\n",
            service_id, state.service_record.last_failed_pid
        ));
        Ok(state.service_record.last_failed_pid)
    } else {
        Ok(0)
    }
}

pub(crate) fn supervisor_restart_service(
    holder_pid: u64,
    restart_capability: u64,
    service_id: u64,
    failed_pid: u64,
) -> Result<u64, &'static str> {
    let state = m4_state()?;
    state
        .restart_capabilities
        .validate(holder_pid, restart_capability, service_id)?;
    if state.service_record.logical_id != service_id {
        return Err("restart targeted an unknown logical service");
    }
    if state.service_record.state != ServiceLifecycleState::Failed {
        return Err("restart requested while the service was not failed");
    }
    if state.service_record.last_failed_pid != failed_pid {
        return Err("restart request used a stale failed service identity");
    }
    if state.service_record.restart_budget_remaining == 0 {
        return Err("restart budget exhausted");
    }
    state.service_record.restart_budget_remaining -= 1;
    let new_pid = launch_replacement_service(state)?;
    kernel_log_fmt(format_args!(
        "[M4  ] supervisor requested restart logical={} old-pid={} new-pid={} budget-remaining={}\n",
        service_id,
        failed_pid,
        new_pid,
        state.service_record.restart_budget_remaining
    ));
    Ok(new_pid)
}

pub(crate) fn query_service_status(service_id: u64) -> Result<u64, &'static str> {
    let state = m4_state()?;
    if state.service_record.logical_id != service_id {
        return Err("queried an unknown logical service");
    }
    Ok(encode_service_status(state.service_record))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_status_encoding_keeps_state_generation_and_pid_distinct() {
        let encoded = encode_service_status(ServiceRecord {
            logical_id: 1,
            generation: 2,
            state: ServiceLifecycleState::Running,
            current_pid: 7,
            last_failed_pid: 6,
            last_exit_status: 1,
            restart_budget_remaining: 0,
        });
        assert_eq!(encoded & 0xff, ServiceLifecycleState::Running as u64);
        assert_eq!((encoded >> 8) & 0xff, 2);
        assert_eq!(encoded >> 16, 7);
    }

    #[test]
    fn restart_capability_handle_round_trips() {
        let raw = RestartCapabilityHandleParts {
            slot: 3,
            generation: 9,
        }
        .encode();
        let decoded = RestartCapabilityHandleParts::decode(raw);
        assert_eq!(decoded.slot, 3);
        assert_eq!(decoded.generation, 9);
    }
}
