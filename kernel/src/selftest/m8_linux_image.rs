//! M8.2 (#92) self-test: the frozen Linux fixture is constructed through
//! `process::linux_image::launch_linux_process` and ENTERED through the
//! production userspace path.
//!
//! Proof of entry does not depend on the Linux syscall surface (#93/#94):
//! the first syscall the Linux-tagged pid makes (nr 999, the fixture's probe)
//! is observed at the syscall entry with the trusted pid, `user_rip` inside the
//! fixture's RX PT_LOAD page and `user_rsp == launch RSP` (the fixture pushes
//! nothing before its first syscall). The process is then torn down through
//! the production teardown path and frame / registry accounting must return to
//! the baseline captured before launch. A native sibling process makes
//! progress concurrently (its own syscalls are counted) and keeps running
//! after the Linux teardown so the scheduler always has a runnable thread.
//!
//! Marker: `[M8.2] PASS`. Every unexpected observation is fatal (fail closed);
//! a Linux process that never reaches its first syscall is caught by the
//! native-progress bound below and, independently, by the xtask timeout.

use crate::arch::x86_64::context_switch::{
    build_userspace_entry_frame, restore_task_context, task_stack_top,
};
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::{kernel_log_fmt, kernel_log_line};
use crate::diagnostics::qemu::{fatal_kernel_error, qemu_exit, QEMU_EXIT_SUCCESS};
use crate::interrupt::timer::initialize_timer;
use crate::mm::address_space::{
    create_process_address_space, destroy_process_address_space, kernel_root_frame,
    map_process_page,
};
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::zero_page;
use crate::mm::{phys_to_virt, PAGE_SIZE};
use crate::process::domain::teardown_current_process;
use crate::process::id_allocator::{id_allocator_mut, IdAllocator};
use crate::process::linux_image::{
    launch_linux_process, LaunchedLinuxProcess, LINUX_M8_FIXTURE, LINUX_STACK_BASE,
    LINUX_STACK_PAGES, LINUX_STACK_TOP,
};
use crate::process::personality::ExecutionPersonality;
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::{scheduler_mut, task_stacks_mut, Scheduler};
use crate::selftest::{USER_TEST_CODE_ADDRESS, USER_TEST_STACK_ADDRESS};
use crate::service::spawn::register_spawned_process_checked;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::{
    current_syscall_caller_pid, install_service_lifecycle_syscall_allocator,
    service_lifecycle_syscall_allocator_mut,
};
use core::ptr;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

const PASS_MARKER: &str = "[M8.2] PASS";

/// The fixture's first syscall number (`hello.S`: unsupported-syscall probe).
const FIXTURE_FIRST_SYSCALL_NR: u64 = 999;

/// Native sibling syscall number: native `SYSCALL_NR_VERSION` (0), which the
/// native dispatcher answers unconditionally, so the sibling loops forever
/// without depending on any other kernel service.
const NATIVE_VERSION_SYSCALL_NR: u64 = 0;

/// Native sibling progress the test waits for after the Linux teardown (or
/// before it, depending on scheduling order). Small: one syscall per timer
/// slice is enough to prove concurrent progress.
const NATIVE_REQUIRED_PROGRESS: u64 = 3;

/// Fail-closed bound: if the native sibling makes this many syscalls before the
/// Linux pid has been observed, the Linux process never reached `e_entry`
/// (timer preemption guarantees it is scheduled in between). Generous so a slow
/// CI host cannot trip it spuriously; the xtask timeout is the outer bound.
const NATIVE_PROGRESS_BOUND_WITHOUT_LINUX: u64 = 1_000_000;

/// Native sibling code: `xor eax, eax; syscall; jmp <xor>` — a version-syscall
/// loop that touches no memory beyond its own page. Byte-exact so the test does
/// not depend on an assembler payload symbol.
const NATIVE_SIBLING_CODE: [u8; 6] = [
    0x31, 0xC0, // xor eax, eax
    0x0F, 0x05, // syscall
    0xEB, 0xFA, // jmp -6 (back to xor)
];

/// Scheduler slots: Linux first so `scheduler.start()` dispatches it first and
/// the native sibling proves preemption rather than only running after teardown.
const LINUX_SCHEDULER_SLOT: usize = 0;
const NATIVE_SCHEDULER_SLOT: usize = 1;

struct TestState {
    linux: LaunchedLinuxProcess,
    native_pid: u64,
    /// Allocator free-page count and registry occupancy before the Linux launch.
    baseline_free_pages: u64,
    baseline_registry_slots: usize,
    /// Frames the Linux launch consumed (user pages + page-table frames).
    linux_frames: u64,
    linux_observed: bool,
    linux_torn_down: bool,
    native_progress: u64,
}

static TEST_STATE: GlobalCell<Option<TestState>> = GlobalCell::new(None);

fn test_state() -> &'static mut TestState {
    unsafe {
        (*TEST_STATE.get())
            .as_mut()
            .unwrap_or_else(|| fatal_kernel_error("m8 linux image state was not initialized"))
    }
}

/// User pages the Linux launch maps: PT_LOAD pages plus the fixed stack pages
/// (the guard page is never mapped).
fn linux_user_pages(linux: &LaunchedLinuxProcess) -> usize {
    linux.image_pages + LINUX_STACK_PAGES as usize
}

fn allocator() -> &'static mut PageAllocator {
    service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m8 linux image allocator missing"))
}

/// Launch the native sibling (an RX code page plus one NX stack page) through
/// the production address-space and registration path.
#[inline(never)]
fn launch_native_sibling(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
) -> Result<u64, &'static str> {
    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let result = (|| -> Result<(), &'static str> {
        let code_frame = allocator
            .allocate_page()
            .ok_or("allocator could not provide the native sibling code page")?;
        zero_page(code_frame);
        unsafe {
            ptr::copy_nonoverlapping(
                NATIVE_SIBLING_CODE.as_ptr(),
                (phys_to_virt(code_frame)) as *mut u8,
                NATIVE_SIBLING_CODE.len(),
            );
        }
        map_process_page(
            &mut address_space,
            USER_TEST_CODE_ADDRESS,
            code_frame,
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        )?;
        let stack_frame = allocator
            .allocate_page()
            .ok_or("allocator could not provide the native sibling stack page")?;
        zero_page(stack_frame);
        map_process_page(
            &mut address_space,
            USER_TEST_STACK_ADDRESS,
            stack_frame,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        )
    })();
    if let Err(message) = result {
        destroy_process_address_space(&address_space, allocator)?;
        return Err(message);
    }
    let (pid, tid) = {
        let ids = unsafe { id_allocator_mut() };
        (ids.allocate_pid()?, ids.allocate_tid()?)
    };
    let saved_stack_pointer = build_userspace_entry_frame(
        kernel_stack_top,
        USER_TEST_CODE_ADDRESS,
        USER_TEST_STACK_ADDRESS + PAGE_SIZE,
    )?;
    let spawned = register_spawned_process_checked(
        allocator,
        address_space,
        pid,
        tid,
        kernel_stack_top,
        saved_stack_pointer,
        USER_TEST_CODE_ADDRESS,
        scheduler_slot,
    )?;
    Ok(spawned.pid)
}

pub(crate) fn start_m8_linux_image_self_test(allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    install_service_lifecycle_syscall_allocator(allocator);
    let allocator = self::allocator();
    let stacks = unsafe { &*task_stacks_mut() };

    let native_pid = launch_native_sibling(
        allocator,
        task_stack_top(&stacks[NATIVE_SCHEDULER_SLOT]),
        NATIVE_SCHEDULER_SLOT,
    )
    .unwrap_or_else(|message| fatal_kernel_error(message));
    kernel_log_fmt(format_args!(
        "[M8.2] native sibling pid={} slot={}\n",
        native_pid, NATIVE_SCHEDULER_SLOT
    ));

    // Baseline captured after the sibling, immediately before the Linux launch.
    let baseline_free_pages = allocator.stats().free_pages;
    let baseline_registry_slots = unsafe { process_registry_mut().occupied_slots() };

    let linux = launch_linux_process(
        allocator,
        task_stack_top(&stacks[LINUX_SCHEDULER_SLOT]),
        LINUX_SCHEDULER_SLOT,
        LINUX_M8_FIXTURE,
    )
    .unwrap_or_else(|error| {
        kernel_log_fmt(format_args!(
            "[M8.2] launch failed: {}\n",
            error.description()
        ));
        fatal_kernel_error("linux image launch failed")
    });
    kernel_log_fmt(format_args!(
        "[M8.2] linux launched pid={} tid={} gen={} entry={:#018x} rsp={:#018x} image_pages={} pt_frames={}\n",
        linux.pid,
        linux.tid,
        linux.instance_generation.0,
        linux.entry,
        linux.launch_rsp,
        linux.image_pages,
        linux.page_table_frames
    ));

    // Construction accounting: exactly the planned frames were consumed and the
    // registry gained one Linux-tagged slot.
    let after_free_pages = allocator.stats().free_pages;
    let linux_frames = baseline_free_pages
        .checked_sub(after_free_pages)
        .unwrap_or_else(|| fatal_kernel_error("allocator free count grew across linux launch"));
    let expected_frames = (linux_user_pages(&linux) + linux.page_table_frames) as u64;
    if linux_frames != expected_frames {
        kernel_log_fmt(format_args!(
            "[M8.2] frame accounting mismatch consumed={} expected={}\n",
            linux_frames, expected_frames
        ));
        fatal_kernel_error("linux launch consumed an unexpected number of frames");
    }
    let registry = unsafe { &*process_registry_mut() };
    if registry.occupied_slots() != baseline_registry_slots + 1 {
        fatal_kernel_error("linux launch did not occupy exactly one registry slot");
    }
    let process = registry
        .get(linux.pid)
        .unwrap_or_else(|| fatal_kernel_error("launched linux process missing from registry"));
    if process.execution_personality != ExecutionPersonality::LinuxX86_64 {
        fatal_kernel_error("launched linux process was not tagged LinuxX86_64");
    }
    if linux.launch_rsp % 16 != 0
        || !(LINUX_STACK_BASE..LINUX_STACK_TOP).contains(&linux.launch_rsp)
    {
        fatal_kernel_error("linux launch RSP violated the initial-stack contract");
    }

    unsafe {
        *TEST_STATE.get() = Some(TestState {
            linux,
            native_pid,
            baseline_free_pages,
            baseline_registry_slots,
            linux_frames,
            linux_observed: false,
            linux_torn_down: false,
            native_progress: 0,
        });
    }

    initialize_timer();
    kernel_log_line("[TIME] timer initialized");
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}

/// Syscall-entry observer (called from `clean_slate_syscall_dispatch` after the
/// canonical return-state check). Returns for the native sibling; never returns
/// for the Linux pid, whose first syscall ends the process.
pub(crate) fn observe_syscall(frame: &SyscallContext) {
    let pid = current_syscall_caller_pid().unwrap_or_else(|message| fatal_kernel_error(message));
    let state = test_state();
    if pid == state.linux.pid {
        observe_linux_first_syscall(state, frame)
    }
    if pid != state.native_pid {
        fatal_kernel_error("syscall from an unexpected pid during the m8 linux image test");
    }
    if frame.rax != NATIVE_VERSION_SYSCALL_NR {
        fatal_kernel_error("native sibling issued an unexpected syscall number");
    }
    state.native_progress = state
        .native_progress
        .checked_add(1)
        .unwrap_or_else(|| fatal_kernel_error("native progress counter overflow"));
    if !state.linux_observed && state.native_progress >= NATIVE_PROGRESS_BOUND_WITHOUT_LINUX {
        fatal_kernel_error("linux process never reached its first syscall");
    }
    maybe_pass(state);
}

fn maybe_pass(state: &TestState) {
    if state.linux_torn_down && state.native_progress >= NATIVE_REQUIRED_PROGRESS {
        kernel_log_fmt(format_args!(
            "[M8.2] native progress={} after linux teardown\n",
            state.native_progress
        ));
        kernel_log_line(PASS_MARKER);
        qemu_exit(QEMU_EXIT_SUCCESS)
    }
}

fn observe_linux_first_syscall(state: &mut TestState, frame: &SyscallContext) -> ! {
    if state.linux_observed {
        fatal_kernel_error("linux process made a second syscall after its teardown began");
    }
    state.linux_observed = true;
    kernel_log_fmt(format_args!(
        "[M8.2] linux entry observed pid={} rax={} rip={:#018x} rsp={:#018x}\n",
        state.linux.pid, frame.rax, frame.user_rip, frame.user_rsp
    ));
    if frame.rax != FIXTURE_FIRST_SYSCALL_NR {
        fatal_kernel_error("linux first syscall number was not the fixture probe");
    }
    // The fixture's only PT_LOAD is one RX page starting at the image base.
    let rx_page = state.linux.entry & !(PAGE_SIZE - 1);
    if !(rx_page..rx_page + PAGE_SIZE).contains(&frame.user_rip) {
        fatal_kernel_error("linux first syscall RIP was outside the fixture RX page");
    }
    if frame.user_rip <= state.linux.entry {
        fatal_kernel_error("linux first syscall RIP did not advance past e_entry");
    }
    if frame.user_rsp != state.linux.launch_rsp {
        fatal_kernel_error("linux first syscall RSP diverged from the launch RSP");
    }
    if !(LINUX_STACK_BASE..LINUX_STACK_TOP).contains(&frame.user_rsp) {
        fatal_kernel_error("linux first syscall RSP was outside the Linux stack");
    }

    // Production teardown path (same call the fault handler uses).
    let allocator = allocator();
    let teardown = teardown_current_process(allocator, kernel_root_frame(), 0, false)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    if teardown.process_id != state.linux.pid {
        fatal_kernel_error("teardown reported a different pid than the linux process");
    }
    let released = teardown.released_resources;
    if released.user_pages != linux_user_pages(&state.linux)
        || released.page_table_frames != state.linux.page_table_frames
        || released.threads != 1
    {
        kernel_log_fmt(format_args!(
            "[M8.2] teardown snapshot user_pages={} pt_frames={} threads={}\n",
            released.user_pages, released.page_table_frames, released.threads
        ));
        fatal_kernel_error("linux teardown released an unexpected resource set");
    }
    let free_pages = allocator.stats().free_pages;
    if free_pages != state.baseline_free_pages {
        kernel_log_fmt(format_args!(
            "[M8.2] free pages after teardown={} baseline={} launch consumed={}\n",
            free_pages, state.baseline_free_pages, state.linux_frames
        ));
        fatal_kernel_error("linux teardown did not return the allocator to baseline");
    }
    let registry = unsafe { &*process_registry_mut() };
    if registry.get(state.linux.pid).is_some()
        || registry.occupied_slots() != state.baseline_registry_slots
    {
        fatal_kernel_error("linux teardown did not release the registry slot");
    }
    kernel_log_fmt(format_args!(
        "[M8.2] linux torn down pid={} frames_reclaimed={} registry_slots={}\n",
        state.linux.pid,
        state.linux_frames,
        registry.occupied_slots()
    ));
    state.linux_torn_down = true;
    maybe_pass(state);

    // Continue on the native sibling (the dying thread's kernel stack is abandoned).
    let next_stack_pointer = teardown
        .next_stack_pointer
        .unwrap_or_else(|| fatal_kernel_error("no runnable native sibling after linux teardown"));
    unsafe { restore_task_context(next_stack_pointer) }
}
