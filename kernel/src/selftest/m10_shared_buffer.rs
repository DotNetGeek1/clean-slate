//! M10 #195 S2: scripted fixture lane for bounded shared user buffers (phase `nx` first).

use crate::arch::x86_64::context_switch::{restore_task_context, task_stack_top};
use crate::arch::x86_64::gdt::selector_rpl;
use crate::arch::x86_64::interrupt_context::InterruptContext;
use crate::capability::live_capability_count;
use crate::diagnostics::log::{kernel_log_fmt, kernel_log_line};
use crate::diagnostics::qemu::{fatal_kernel_error, qemu_exit, QEMU_EXIT_SUCCESS};
use crate::interrupt::timer::initialize_timer;
use crate::mm::frame_allocator::PageAllocator;
use crate::process::id_allocator::{id_allocator_mut, IdAllocator};
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::idle::idle_handoff_while_threads_blocked;
use crate::sched::{scheduler_mut, task_stacks_mut, Scheduler, ThreadState};
use crate::selftest::m6_fixture::{
    fixture_service, lane_check_step, set_all_exited_handler, set_lane_check_handler,
    set_report_handler, spawn_fixture, wait_exit_step, FixtureReportAction,
};
use crate::sync::global_cell::GlobalCell;
use crate::syscall::{
    install_service_lifecycle_syscall_allocator, service_lifecycle_syscall_allocator_mut,
};
use clean_slate_capability::syscall_abi::SYSCALL_EINVAL;
use clean_slate_service_fixtures::m6_fixture::{
    M6FixtureBootstrap, M6FixtureStep, FIXTURE_STATUS_MISMATCH, M6_FIXTURE_BOOTSTRAP_ADDRESS,
};
use x86_64::registers::control::Cr2;

const CHECK_PHASE_DONE: u64 = 0;
const CHECK_NX: u64 = 1;

const SLOTS_PER_BANK: usize = 3;
const BANK_BASE: [usize; 2] = [1, 1 + SLOTS_PER_BANK];
const _: () =
    assert!(BANK_BASE.len() * SLOTS_PER_BANK <= crate::process::PROCESS_REGISTRY_CAPACITY);

const NX_EXEC_OFFSET: u64 = 0x800;
const NX_TARGET: u64 = M6_FIXTURE_BOOTSTRAP_ADDRESS + NX_EXEC_OFFSET;
const EXPECTED_NX_FETCH_ERROR: u64 = 0x15;

const FIXTURE_NX_EXEC: u64 = 0;
const FIXTURE_NX_OBSERVER: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PhaseId {
    Nx = 0,
}

struct FaultObservation {
    pid: u64,
    error_code: u64,
    cr2: u64,
    rip: u64,
}

#[derive(Clone, Copy)]
struct Baseline {
    allocated_pages: u64,
    free_pages: u64,
    capabilities: usize,
}

struct LaneState {
    baseline: Baseline,
    phase_index: usize,
    nx_exec_pid: u64,
    latest_fault: Option<FaultObservation>,
}

static LANE_STATE: GlobalCell<Option<LaneState>> = GlobalCell::new(None);

fn state_mut() -> &'static mut LaneState {
    unsafe {
        (*LANE_STATE.get())
            .as_mut()
            .unwrap_or_else(|| fatal_kernel_error("[M10.SB] state missing"))
    }
}

fn allocator() -> &'static mut PageAllocator {
    service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("[M10.SB] allocator missing"))
}

fn scheduler_slot_for(phase_index: usize, fixture_index: usize) -> usize {
    let bank = phase_index % BANK_BASE.len();
    BANK_BASE[bank] + fixture_index
}

fn assert_scheduler_slot_free(slot: usize) {
    let scheduler = unsafe { scheduler_mut() };
    if slot >= scheduler.thread_capacity() {
        fatal_kernel_error("[M10.SB] scheduler slot out of range");
    }
    if scheduler.threads[slot].state != ThreadState::Empty {
        fatal_kernel_error("[M10.SB] scheduler slot was not empty");
    }
}

fn build_nx_exec_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    program
        .push(M6FixtureStep::exec(NX_TARGET))
        .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] nx exec program overflow"));
    program
}

fn build_nx_observer_program(exec_pid: u64) -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    program
        .push(wait_exit_step(exec_pid))
        .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] nx observer wait overflow"));
    program
        .push(lane_check_step(CHECK_NX, 0))
        .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] nx observer check overflow"));
    program
        .push(lane_check_step(CHECK_PHASE_DONE, PhaseId::Nx as u64))
        .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] nx observer done overflow"));
    program
        .push(M6FixtureStep::report())
        .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] nx observer report overflow"));
    program
}

fn spawn_nx_fixtures(allocator: &mut PageAllocator, phase_index: usize) {
    kernel_log_line("[M10.SB] phase nx start");
    let stacks = unsafe { &*task_stacks_mut() };

    let slot_a = scheduler_slot_for(phase_index, 0);
    assert_scheduler_slot_free(slot_a);
    let exec_spawned = spawn_fixture(
        allocator,
        task_stack_top(&stacks[slot_a]),
        slot_a,
        fixture_service(FIXTURE_NX_EXEC),
        &build_nx_exec_program(),
    )
    .unwrap_or_else(|message| fatal_kernel_error(message));
    state_mut().nx_exec_pid = exec_spawned.pid;

    let slot_b = scheduler_slot_for(phase_index, 1);
    assert_scheduler_slot_free(slot_b);
    spawn_fixture(
        allocator,
        task_stack_top(&stacks[slot_b]),
        slot_b,
        fixture_service(FIXTURE_NX_OBSERVER),
        &build_nx_observer_program(exec_spawned.pid),
    )
    .unwrap_or_else(|message| fatal_kernel_error(message));
}

fn start_phase(phase: PhaseId) {
    let phase_index = state_mut().phase_index;
    match phase {
        PhaseId::Nx => spawn_nx_fixtures(allocator(), phase_index),
    }
}

fn lane_check_handler(_pid: u64, check: u64, arg: u64) -> u64 {
    match check {
        CHECK_NX => {
            let state = state_mut();
            let observation = state
                .latest_fault
                .as_ref()
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] nx check without fault"));
            if observation.pid != state.nx_exec_pid {
                fatal_kernel_error("[M10.SB] nx fault pid mismatch");
            }
            if observation.error_code != EXPECTED_NX_FETCH_ERROR {
                fatal_kernel_error("[M10.SB] nx fault error code mismatch");
            }
            if observation.cr2 != NX_TARGET || observation.rip != NX_TARGET {
                fatal_kernel_error("[M10.SB] nx fault address mismatch");
            }
            kernel_log_line("[M10.SB] nx exec fault err=0x15 OK");
            0
        }
        CHECK_PHASE_DONE => {
            let state = state_mut();
            if arg != state.phase_index as u64 {
                fatal_kernel_error("[M10.SB] phase done index mismatch");
            }
            match state.phase_index {
                0 => {
                    kernel_log_line("[M10.SB] phase nx done");
                    state.phase_index = 1;
                }
                _ => fatal_kernel_error("[M10.SB] unknown phase done"),
            }
            0
        }
        _ => SYSCALL_EINVAL,
    }
}

fn report_handler(pid: u64, report: &M6FixtureBootstrap) -> FixtureReportAction {
    if report.status == FIXTURE_STATUS_MISMATCH {
        kernel_log_fmt(format_args!(
            "[M10.SB] mismatch pid={} failed_step={}\n",
            pid, report.failed_step
        ));
        return FixtureReportAction::Fail("[M10.SB] fixture mismatch");
    }
    FixtureReportAction::Continue
}

fn finish_all_exited() -> ! {
    let baseline = state_mut().baseline;
    let stats = allocator().stats();
    let caps = live_capability_count();
    let registry_slots = unsafe { process_registry_mut().occupied_slots() };
    if stats.allocated_pages != baseline.allocated_pages
        || stats.free_pages != baseline.free_pages
        || caps != baseline.capabilities
        || registry_slots != 0
    {
        kernel_log_fmt(format_args!(
            "[M10.SB] baseline mismatch alloc {}->{} free {}->{} caps {}->{} registry={}\n",
            baseline.allocated_pages,
            stats.allocated_pages,
            baseline.free_pages,
            stats.free_pages,
            baseline.capabilities,
            caps,
            registry_slots
        ));
        fatal_kernel_error("[M10.SB] baseline mismatch");
    }
    kernel_log_line("[M10.SB] baseline OK");
    kernel_log_line("[M10.SB] PASS");
    qemu_exit(QEMU_EXIT_SUCCESS)
}

/// Records a CPL3 fixture page fault; the production fault path then tears it down.
pub(crate) fn record_page_fault(context: &InterruptContext) {
    if selector_rpl(context.cs) != 3 {
        return;
    }
    let pid = crate::process::current_process_id().unwrap_or(0);
    if !crate::selftest::m6_fixture::is_fixture_pid(pid) {
        return;
    }
    let cr2 = Cr2::read()
        .expect("CR2 must contain a canonical fault address")
        .as_u64();
    state_mut().latest_fault = Some(FaultObservation {
        pid,
        error_code: context.error_code,
        cr2,
        rip: context.rip,
    });
}

pub(crate) fn maybe_continue_after_fixture_fault(_pid: u64) -> ! {
    match idle_handoff_while_threads_blocked() {
        Ok(Some(next_stack_pointer)) => unsafe { restore_task_context(next_stack_pointer) },
        Ok(None) => finish_all_exited(),
        Err(message) => fatal_kernel_error(message),
    }
}

pub(crate) fn start_m10_shared_buffer_self_test(page_allocator: PageAllocator) -> ! {
    kernel_log_line("[M10.SB] creating");
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    install_service_lifecycle_syscall_allocator(page_allocator);
    let alloc = allocator();
    let stats = alloc.stats();
    let baseline = Baseline {
        allocated_pages: stats.allocated_pages,
        free_pages: stats.free_pages,
        capabilities: live_capability_count(),
    };
    unsafe {
        *LANE_STATE.get() = Some(LaneState {
            baseline,
            phase_index: 0,
            nx_exec_pid: 0,
            latest_fault: None,
        });
    }
    set_report_handler(report_handler);
    set_lane_check_handler(lane_check_handler);
    set_all_exited_handler(finish_all_exited);

    start_phase(PhaseId::Nx);

    initialize_timer();
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}
