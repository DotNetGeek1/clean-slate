//! #306 native memory lane: one scripted fixture with a 48-page budget maps up to the budget,
//! is refused one page past it, unmaps part of a run and maps into the hole, checks the zeroed
//! and preserved contents, protects a page read-only, and ends by writing to that page. The
//! write faults, the fault path tears the fixture down with 48 pages still mapped, and the lane
//! passes only if the allocator and the native memory records are back where they were before
//! the spawn.

use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::mm::frame_allocator::PageAllocator;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::live_instance_generation;
use crate::process::native_mem;
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::scheduler_mut;
use crate::sched::task_stacks_mut;
use crate::sched::Scheduler;
use crate::selftest::m6_fixture::{
    fixture_service, lane_check_step, set_lane_check_handler, set_report_handler, spawn_fixture,
    FixtureReportAction,
};
use crate::sync::global_cell::GlobalCell;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use clean_slate_native_abi::memory::{
    MemoryUsage, MEMORY_ACCESS_READ, MEMORY_MAP_FIXED, MEMORY_PAGE_BYTES, MEMORY_SUBOP_MAP,
    MEMORY_SUBOP_PROTECT, MEMORY_SUBOP_QUERY, MEMORY_SUBOP_UNMAP, NATIVE_MEMORY_WINDOW_BASE,
    SYSCALL_NR_MEMORY,
};
use clean_slate_native_abi::status::{STATUS_EEXIST, STATUS_EINVAL, STATUS_ENOSPC};
use clean_slate_service_fixtures::m6_fixture::{
    M6FixtureBootstrap, M6FixtureStep, PATTERN_CONSTANT, PATTERN_INCREMENTING,
};

const BUDGET: u64 = 48;
const BASE: u64 = NATIVE_MEMORY_WINDOW_BASE;
const PAGE: u64 = MEMORY_PAGE_BYTES;
const SEED: u64 = 7;

/// Lane check: the fixture is at its budget and about to write to its read-only page.
const CHECK_AT_BUDGET: u64 = 1;

struct LaneState {
    pid: u64,
    free_pages: u64,
    allocated_pages: u64,
    records: usize,
    at_budget: bool,
}

static LANE_STATE: GlobalCell<Option<LaneState>> = GlobalCell::new(None);

fn state() -> &'static mut LaneState {
    unsafe {
        (*LANE_STATE.get())
            .as_mut()
            .unwrap_or_else(|| fatal_kernel_error("[M10.mem] lane state missing"))
    }
}

fn allocator() -> &'static mut PageAllocator {
    service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("[M10.mem] allocator missing"))
}

fn memory(subop: u64, rsi: u64, rdx: u64, r10: u64) -> M6FixtureStep {
    M6FixtureStep::syscall(SYSCALL_NR_MEMORY, [subop, rsi, rdx, r10, 0, 0])
}

fn map(hint: u64, pages: u64, flags: u64) -> M6FixtureStep {
    memory(MEMORY_SUBOP_MAP, hint, pages * PAGE, flags)
}

fn unmap(start: u64, pages: u64) -> M6FixtureStep {
    memory(MEMORY_SUBOP_UNMAP, start, pages * PAGE, 0)
}

fn query(used: u32) -> M6FixtureStep {
    memory(MEMORY_SUBOP_QUERY, 0, 0, 0).expect_eq(
        MemoryUsage {
            used_pages: used,
            budget_pages: BUDGET as u32,
        }
        .encode(),
    )
}

const fn page(index: u64) -> u64 {
    BASE + index * PAGE
}

fn build_program() -> M6FixtureBootstrap {
    let steps = [
        query(0),
        map(0, 0, 0).expect_eq(STATUS_EINVAL),
        map(0, 32, 0).expect_eq(page(0)),
        map(0, 16, 0).expect_eq(page(32)),
        M6FixtureStep::fill(page(0), BUDGET * PAGE, SEED, PATTERN_INCREMENTING),
        M6FixtureStep::verify(page(0), BUDGET * PAGE, SEED, PATTERN_INCREMENTING),
        // One page past the budget, wherever it would go.
        map(0, 1, 0).expect_eq(STATUS_ENOSPC),
        map(page(100), 1, MEMORY_MAP_FIXED).expect_eq(STATUS_ENOSPC),
        query(BUDGET as u32),
        // A partial unmap splits the run; the hole is mapped again, zeroed.
        unmap(page(8), 8).expect_eq(8),
        query(40),
        map(0, 8, 0).expect_eq(page(8)),
        M6FixtureStep::verify(page(8), 8 * PAGE, 0, PATTERN_CONSTANT),
        M6FixtureStep::verify(page(0), 8 * PAGE, SEED, PATTERN_INCREMENTING),
        // Under the budget again, a fixed map over a mapped page is refused, never replaced.
        unmap(page(47), 1).expect_eq(1),
        map(page(0), 1, MEMORY_MAP_FIXED).expect_eq(STATUS_EEXIST),
        map(page(47), 1, MEMORY_MAP_FIXED).expect_eq(page(47)),
        M6FixtureStep::verify(page(47), PAGE, 0, PATTERN_CONSTANT),
        // Unmapping nothing frees nothing.
        unmap(page(200), 4).expect_eq(0),
        memory(MEMORY_SUBOP_PROTECT, page(0), PAGE, MEMORY_ACCESS_READ).expect_eq(0),
        memory(MEMORY_SUBOP_PROTECT, page(1), PAGE, 2).expect_eq(STATUS_EINVAL),
        memory(MEMORY_SUBOP_PROTECT, page(200), PAGE, MEMORY_ACCESS_READ).expect_eq(STATUS_EINVAL),
        M6FixtureStep::verify(page(0), PAGE, SEED, PATTERN_INCREMENTING),
        query(BUDGET as u32),
        lane_check_step(CHECK_AT_BUDGET, 0),
        // The write to the read-only page faults; the fixture dies holding its whole budget.
        M6FixtureStep::fault_at(page(0)),
    ];
    let mut program = M6FixtureBootstrap::new();
    for step in steps {
        program
            .push(step)
            .unwrap_or_else(|_| fatal_kernel_error("[M10.mem] program too long"));
    }
    program
}

fn report_handler(pid: u64, report: &M6FixtureBootstrap) -> FixtureReportAction {
    kernel_log_fmt(format_args!(
        "[M10.mem] unexpected report pid={pid} status={} failed_step={}\n",
        report.status, report.failed_step
    ));
    FixtureReportAction::Fail("[M10.mem] fixture reported instead of faulting")
}

fn lane_check_handler(pid: u64, check: u64, _arg: u64) -> u64 {
    let state = state();
    if pid != state.pid || check != CHECK_AT_BUDGET {
        return STATUS_EINVAL;
    }
    let Some(generation) = live_instance_generation(pid) else {
        return STATUS_EINVAL;
    };
    let usage = native_mem::usage(pid, generation);
    kernel_log_fmt(format_args!(
        "[M10.mem] at budget used={} budget={}\n",
        usage.used_pages, usage.budget_pages
    ));
    if u64::from(usage.used_pages) != BUDGET || u64::from(usage.budget_pages) != BUDGET {
        return STATUS_EINVAL;
    }
    state.at_budget = true;
    0
}

/// The fault path calls this once the faulting fixture has been torn down.
pub(crate) fn finish_after_fixture_fault(pid: u64) -> ! {
    let state = state();
    if pid != state.pid || !state.at_budget {
        fatal_kernel_error("[M10.mem] fixture faulted before it reached its budget");
    }
    kernel_log_fmt(format_args!(
        "[M10.mem] read-only write faulted pid={pid}\n"
    ));
    let stats = allocator().stats();
    let records = native_mem::live_records();
    let registry_slots = unsafe { process_registry_mut().occupied_slots() };
    if stats.free_pages != state.free_pages
        || stats.allocated_pages != state.allocated_pages
        || records != state.records
        || registry_slots != 0
    {
        kernel_log_fmt(format_args!(
            "[M10.mem] baseline mismatch free {}->{} allocated {}->{} records {}->{} registry={}\n",
            state.free_pages,
            stats.free_pages,
            state.allocated_pages,
            stats.allocated_pages,
            state.records,
            records,
            registry_slots
        ));
        fatal_kernel_error("[M10.mem] baseline mismatch");
    }
    kernel_log_fmt(format_args!(
        "[M10.mem] baseline restored free_pages={} records={records}\n",
        stats.free_pages
    ));
    kernel_log_line("[M10.mem] PASS");
    qemu_exit(QEMU_EXIT_SUCCESS)
}

pub(crate) fn start_m10_native_memory_self_test(page_allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    install_service_lifecycle_syscall_allocator(page_allocator);
    set_report_handler(report_handler);
    set_lane_check_handler(lane_check_handler);
    let stats = allocator().stats();
    unsafe {
        *LANE_STATE.get() = Some(LaneState {
            pid: 0,
            free_pages: stats.free_pages,
            allocated_pages: stats.allocated_pages,
            records: native_mem::live_records(),
            at_budget: false,
        });
    }
    let stacks = unsafe { &*task_stacks_mut() };
    let program = build_program();
    let spawned = spawn_fixture(
        allocator(),
        task_stack_top(&stacks[0]),
        0,
        fixture_service(0),
        &program,
    )
    .unwrap_or_else(|message| fatal_kernel_error(message));
    let generation = live_instance_generation(spawned.pid)
        .unwrap_or_else(|| fatal_kernel_error("[M10.mem] fixture has no generation"));
    native_mem::set_budget(spawned.pid, generation, BUDGET)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    state().pid = spawned.pid;
    kernel_log_fmt(format_args!(
        "[M10.mem] fixture spawned pid={} budget={BUDGET}\n",
        spawned.pid
    ));
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}
