//! M8.7 (#97) observer self-test for the production Linux hello launch path.
//!
//! This module does **not** tag personality, grant console capabilities, install
//! stdio, or drive relaunch. Boot calls
//! [`crate::service::linux_launch::start_linux_hello_service`]; the lifecycle
//! controller owns generation and restart. The observer watches registry / fd /
//! serial / delivered-byte effects and emits `[M8.7] PASS`.

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
use crate::process::id_allocator::{id_allocator_mut, IdAllocator};
use crate::process::linux_fd::{
    self, console_sink_render_style, ConsoleSinkRenderStyle, LINUX_STDOUT_FD,
};
use crate::process::linux_image::LinuxImageError;
use crate::process::personality::ExecutionPersonality;
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::{scheduler_mut, task_stacks_mut, Scheduler};
use crate::selftest::{USER_TEST_CODE_ADDRESS, USER_TEST_STACK_ADDRESS};
use crate::service::control::service_lifecycle_controller_mut;
use crate::service::linux_launch::{
    launch_linux_hello, linux_hello_completed_exits, linux_hello_delivered_bytes,
    linux_hello_first_exited, linux_hello_last_exited, linux_hello_live, start_linux_hello_service,
};
use crate::service::spawn::register_spawned_process_checked;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::{
    current_syscall_caller_pid, install_service_lifecycle_syscall_allocator,
    service_lifecycle_syscall_allocator_mut,
};
use clean_slate_linux_abi::EBADF;
use clean_slate_service_lifecycle::InstanceGeneration;
use core::ptr;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

const PASS_MARKER: &str = "[M8.7] PASS";

/// Native sibling: `xor eax,eax; syscall; jmp` — version-syscall progress loop.
const NATIVE_SIBLING_CODE: [u8; 6] = [
    0x31, 0xC0, // xor eax, eax
    0x0F, 0x05, // syscall
    0xEB, 0xFA, // jmp -6
];

const NATIVE_VERSION_SYSCALL_NR: u64 = 0;
const NATIVE_REQUIRED_PROGRESS: u64 = 3;
/// Native progress required *after* the malformed-load proof before PASS.
const NATIVE_PROGRESS_AFTER_MALFORMED: u64 = 2;
const NATIVE_PROGRESS_BOUND_WITHOUT_FIRST_EXIT: u64 = 1_000_000;

const NATIVE_SCHEDULER_SLOT: usize = 1;
/// Fixture hello line is exactly 18 bytes including the trailing newline.
const HELLO_DELIVERED_BYTES: u64 = 18;
/// Initial + one controller-owned relaunch.
const LINUX_REMAINING_RESTARTS: u8 = 1;

/// Malformed corpus image used only by this self-test to prove fail-closed load.
const MALFORMED_BAD_MAGIC: &[u8] =
    include_bytes!("../../../fixtures/linux-hello/malformed/bad-magic.elf");

struct ObserverState {
    native_pid: u64,
    first_pid: u64,
    first_generation: u32,
    first_exit_seen: bool,
    relaunch_seen: bool,
    relaunch_pid: u64,
    relaunch_generation: u32,
    second_exit_seen: bool,
    malformed_proven: bool,
    native_progress: u64,
    /// Native progress snapshot taken when malformed load was proven.
    native_progress_at_malformed: Option<u64>,
    /// Harness-visible `[M8.7] * observed` lines (after both Linux exits).
    observer_markers_emitted: bool,
}

static OBSERVER: GlobalCell<Option<ObserverState>> = GlobalCell::new(None);

fn observer() -> &'static mut ObserverState {
    unsafe {
        (*OBSERVER.get())
            .as_mut()
            .unwrap_or_else(|| fatal_kernel_error("m8.7 observer state missing"))
    }
}

fn allocator() -> &'static mut PageAllocator {
    service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m8.7 allocator missing"))
}

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

fn prove_malformed_load(allocator: &mut PageAllocator, state: &mut ObserverState) {
    if state.malformed_proven {
        return;
    }
    let stacks = unsafe { &*task_stacks_mut() };
    // Use an empty slot so we do not clobber the native sibling. After the
    // second Linux exit the controller-allocated Linux slot(s) are Empty again
    // (first launch typically slot 0; relaunch may use another empty slot).
    const MALFORMED_SLOT: usize = 0;
    let free_before = allocator.stats().free_pages;
    let occupied_before = unsafe { process_registry_mut().occupied_slots() };

    let err = match launch_linux_hello(
        allocator,
        task_stack_top(&stacks[MALFORMED_SLOT]),
        MALFORMED_SLOT,
        MALFORMED_BAD_MAGIC,
    ) {
        Ok(_) => {
            fatal_kernel_error("m8.7 malformed ELF launch unexpectedly succeeded");
        }
        Err(message) => message,
    };
    if err != LinuxImageError::LoadPlan(clean_slate_elf::LoadPlanError::BadMagic).description() {
        kernel_log_fmt(format_args!("[M8.7] unexpected malformed error: {err}\n"));
        fatal_kernel_error("m8.7 malformed ELF did not report the expected description");
    }
    if allocator.stats().free_pages != free_before {
        fatal_kernel_error("m8.7 malformed ELF launch leaked allocator frames");
    }
    if unsafe { process_registry_mut().occupied_slots() } != occupied_before {
        fatal_kernel_error("m8.7 malformed ELF launch created a process");
    }
    state.malformed_proven = true;
    state.native_progress_at_malformed = Some(state.native_progress);
    kernel_log_line("[M8.7] malformed ELF rejected fail-closed");
}

fn emit_observer_markers_once(state: &mut ObserverState) {
    if state.observer_markers_emitted {
        return;
    }
    let Some((exited_pid, gen, status)) = linux_hello_first_exited() else {
        fatal_kernel_error("m8.7 first exit missing first_exited");
    };
    kernel_log_fmt(format_args!(
        "[M8.7] first exit observed pid={} gen={} status={}\n",
        exited_pid, gen.0, status
    ));
    kernel_log_fmt(format_args!(
        "[M8.7] relaunch observed pid={} gen={}\n",
        state.relaunch_pid, state.relaunch_generation
    ));
    kernel_log_line("[M8.7] second exit observed");
    state.observer_markers_emitted = true;
}

fn maybe_pass(state: &ObserverState) {
    let Some(at_malformed) = state.native_progress_at_malformed else {
        return;
    };
    let after_malformed = state.native_progress.saturating_sub(at_malformed);
    if state.first_exit_seen
        && state.relaunch_seen
        && state.second_exit_seen
        && state.malformed_proven
        && state.native_progress >= NATIVE_REQUIRED_PROGRESS
        && after_malformed >= NATIVE_PROGRESS_AFTER_MALFORMED
    {
        kernel_log_fmt(format_args!(
            "[M8.7] native progress={} (+{} after malformed) delivered_bytes={}\n",
            state.native_progress,
            after_malformed,
            linux_hello_delivered_bytes()
        ));
        kernel_log_line(PASS_MARKER);
        qemu_exit(QEMU_EXIT_SUCCESS)
    }
}

/// Syscall-entry observer: native sibling watches production lifecycle effects.
pub(crate) fn observe_syscall(frame: &SyscallContext) {
    let pid = current_syscall_caller_pid().unwrap_or_else(|message| fatal_kernel_error(message));
    let state = observer();
    if pid != state.native_pid {
        return;
    }
    if frame.rax != NATIVE_VERSION_SYSCALL_NR {
        fatal_kernel_error("m8.7 native sibling issued an unexpected syscall number");
    }
    state.native_progress = state
        .native_progress
        .checked_add(1)
        .unwrap_or_else(|| fatal_kernel_error("m8.7 native progress overflow"));

    if !state.first_exit_seen {
        if linux_hello_completed_exits() >= 1 {
            let Some((exited_pid, _gen, status)) = linux_hello_first_exited() else {
                fatal_kernel_error("m8.7 first exit missing first_exited");
            };
            if exited_pid != state.first_pid {
                fatal_kernel_error("m8.7 first exit identity mismatched the armed session");
            }
            if status != 0 {
                fatal_kernel_error("m8.7 first exit status was not 0");
            }
            let armed_gen = InstanceGeneration(state.first_generation);
            if linux_fd::projection_for(exited_pid, armed_gen, LINUX_STDOUT_FD) != Err(EBADF) {
                fatal_kernel_error("m8.7 first-exit fd table did not fail closed");
            }
            if linux_hello_delivered_bytes() < HELLO_DELIVERED_BYTES {
                fatal_kernel_error("m8.7 first launch did not deliver the hello byte count");
            }
            if console_sink_render_style(ExecutionPersonality::LinuxX86_64)
                != ConsoleSinkRenderStyle::Verbatim
            {
                fatal_kernel_error("m8.7 Linux console sink was not Verbatim");
            }
            state.first_exit_seen = true;
        } else if state.native_progress >= NATIVE_PROGRESS_BOUND_WITHOUT_FIRST_EXIT {
            fatal_kernel_error("m8.7 Linux hello never exited");
        }
    }

    if state.first_exit_seen && !state.relaunch_seen {
        if let Some(launched) = linux_hello_live() {
            let Some((old_pid, old_gen, _)) = linux_hello_last_exited() else {
                fatal_kernel_error("m8.7 relaunch missing last_exited snapshot");
            };
            if launched.pid == old_pid && launched.instance_generation.0 <= old_gen.0 {
                fatal_kernel_error("m8.7 relaunch did not advance pid/generation");
            }
            if linux_fd::projection_for(old_pid, old_gen, LINUX_STDOUT_FD) != Err(EBADF) {
                fatal_kernel_error("m8.7 stale (pid, generation) fd lookup did not fail closed");
            }
            if linux_fd::projection_for(launched.pid, launched.instance_generation, LINUX_STDOUT_FD)
                .is_err()
            {
                fatal_kernel_error("m8.7 relaunched process had no fresh stdout projection");
            }
            state.relaunch_seen = true;
            state.relaunch_pid = launched.pid;
            state.relaunch_generation = launched.instance_generation.0;
        } else if linux_hello_completed_exits() >= 2 {
            let Some((exited_pid, gen, _)) = linux_hello_last_exited() else {
                fatal_kernel_error("m8.7 relaunch missing last_exited snapshot");
            };
            if exited_pid == state.first_pid && gen.0 <= state.first_generation {
                fatal_kernel_error("m8.7 relaunch did not advance pid/generation");
            }
            state.relaunch_seen = true;
            state.relaunch_pid = exited_pid;
            state.relaunch_generation = gen.0;
        }
    }

    if state.relaunch_seen && !state.second_exit_seen && linux_hello_completed_exits() >= 2 {
        let Some((_, _, status)) = linux_hello_last_exited() else {
            fatal_kernel_error("m8.7 second exit missing last_exited");
        };
        if status != 0 {
            fatal_kernel_error("m8.7 second exit status was not 0");
        }
        if linux_hello_live().is_some() {
            fatal_kernel_error("m8.7 second exit still showed a live session process");
        }
        if linux_hello_delivered_bytes() < HELLO_DELIVERED_BYTES.saturating_mul(2) {
            fatal_kernel_error("m8.7 two launches did not deliver 2× hello bytes");
        }
        state.second_exit_seen = true;
        emit_observer_markers_once(state);
        prove_malformed_load(allocator(), state);
    }

    maybe_pass(state);
}

pub(crate) fn start_m8_linux_hello_self_test(allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    install_service_lifecycle_syscall_allocator(allocator);
    let allocator = self::allocator();
    let stacks = unsafe { &*task_stacks_mut() };

    let controller = unsafe { service_lifecycle_controller_mut() };
    controller.clear();
    controller.configure_launch_context(kernel_root_frame(), 0);

    let native_pid = launch_native_sibling(
        allocator,
        task_stack_top(&stacks[NATIVE_SCHEDULER_SLOT]),
        NATIVE_SCHEDULER_SLOT,
    )
    .unwrap_or_else(|message| fatal_kernel_error(message));
    kernel_log_fmt(format_args!(
        "[M8.7] native sibling pid={} slot={}\n",
        native_pid, NATIVE_SCHEDULER_SLOT
    ));

    // Controller Start allocates the first empty slot (0) for Linux hello and
    // owns generation + the single automatic relaunch (budget=1).
    let first =
        start_linux_hello_service(allocator, LINUX_REMAINING_RESTARTS).unwrap_or_else(|message| {
            kernel_log_fmt(format_args!("[M8.7] arm failed: {message}\n"));
            fatal_kernel_error("m8.7 production linux hello Start failed")
        });

    unsafe {
        *OBSERVER.get() = Some(ObserverState {
            native_pid,
            first_pid: first.pid,
            first_generation: first.instance_generation.0,
            first_exit_seen: false,
            relaunch_seen: false,
            relaunch_pid: 0,
            relaunch_generation: 0,
            second_exit_seen: false,
            malformed_proven: false,
            native_progress: 0,
            native_progress_at_malformed: None,
            observer_markers_emitted: false,
        });
    }

    initialize_timer();
    kernel_log_line("[TIME] timer initialized");
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}
