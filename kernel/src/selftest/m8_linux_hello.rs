//! M8.7 (#97) observer self-test for the production Linux hello launch path.
//!
//! This module does **not** tag personality, grant console capabilities, or
//! install stdio itself. Boot/session bring-up calls
//! [`crate::service::linux_launch::arm_linux_hello_session`]; relaunch goes
//! through [`crate::service::linux_launch::poll_linux_hello_relaunch`]. The
//! observer watches registry / fd / serial effects and emits `[M8.7] PASS`.

use crate::arch::x86_64::context_switch::{
    build_userspace_entry_frame, restore_task_context, task_stack_top,
};
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::{kernel_log_fmt, kernel_log_line};
use crate::diagnostics::qemu::{fatal_kernel_error, qemu_exit, QEMU_EXIT_SUCCESS};
use crate::interrupt::timer::initialize_timer;
use crate::mm::address_space::{
    create_process_address_space, destroy_process_address_space, map_process_page,
};
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::zero_page;
use crate::mm::{PAGE_SIZE, PHYSICAL_MEMORY_OFFSET};
use crate::process::id_allocator::{id_allocator_mut, IdAllocator};
use crate::process::linux_fd::{self, LINUX_STDOUT_FD};
use crate::process::linux_image::LinuxImageError;
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::{scheduler_mut, task_stacks_mut, Scheduler};
use crate::selftest::{USER_TEST_CODE_ADDRESS, USER_TEST_STACK_ADDRESS};
use crate::service::linux_launch::{
    arm_linux_hello_session, launch_linux_hello, linux_hello_completed_exits,
    linux_hello_last_exited, linux_hello_live, poll_linux_hello_relaunch,
};
use crate::service::spawn::register_spawned_process_checked;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::{
    current_syscall_caller_pid, install_service_lifecycle_syscall_allocator,
    service_lifecycle_syscall_allocator_mut,
};
use clean_slate_linux_abi::EBADF;
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
const NATIVE_PROGRESS_BOUND_WITHOUT_FIRST_EXIT: u64 = 1_000_000;

const LINUX_SCHEDULER_SLOT: usize = 0;
const NATIVE_SCHEDULER_SLOT: usize = 1;
/// Initial + one relaunch through the production session.
const LINUX_TARGET_LAUNCHES: u8 = 2;

/// Malformed corpus image used only by this self-test to prove fail-closed load.
const MALFORMED_BAD_MAGIC: &[u8] =
    include_bytes!("../../../fixtures/linux-hello/malformed/bad-magic.elf");

struct ObserverState {
    native_pid: u64,
    first_pid: u64,
    first_generation: u32,
    first_exit_seen: bool,
    relaunch_seen: bool,
    second_exit_seen: bool,
    malformed_proven: bool,
    native_progress: u64,
    /// Allocator free pages captured immediately before the malformed proof.
    pre_malformed_free_pages: Option<u64>,
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
                (PHYSICAL_MEMORY_OFFSET + code_frame) as *mut u8,
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
    let free_before = allocator.stats().free_pages;
    state.pre_malformed_free_pages = Some(free_before);
    let occupied_before = unsafe { process_registry_mut().occupied_slots() };

    let err = match launch_linux_hello(
        allocator,
        task_stack_top(&stacks[LINUX_SCHEDULER_SLOT]),
        LINUX_SCHEDULER_SLOT,
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
    kernel_log_line("[M8.7] malformed ELF rejected fail-closed");
}

fn maybe_pass(state: &ObserverState) {
    if state.first_exit_seen
        && state.relaunch_seen
        && state.second_exit_seen
        && state.malformed_proven
        && state.native_progress >= NATIVE_REQUIRED_PROGRESS
    {
        kernel_log_fmt(format_args!(
            "[M8.7] native progress={} after linux hello session\n",
            state.native_progress
        ));
        kernel_log_line(PASS_MARKER);
        qemu_exit(QEMU_EXIT_SUCCESS)
    }
}

/// Syscall-entry observer: native sibling drives relaunch poll + completion.
pub(crate) fn observe_syscall(frame: &SyscallContext) {
    let pid = current_syscall_caller_pid().unwrap_or_else(|message| fatal_kernel_error(message));
    let state = observer();
    if pid != state.native_pid {
        // Linux personality syscalls are handled by the production path; the
        // observer only watches their effects via the session snapshot below.
        return;
    }
    if frame.rax != NATIVE_VERSION_SYSCALL_NR {
        fatal_kernel_error("m8.7 native sibling issued an unexpected syscall number");
    }
    state.native_progress = state
        .native_progress
        .checked_add(1)
        .unwrap_or_else(|| fatal_kernel_error("m8.7 native progress overflow"));

    // Production relaunch poll (stdio/personality wiring stays inside linux_launch).
    // `poll_linux_hello_relaunch` records an exit and may start the next instance
    // in the same call, so update exit observation from the session snapshot first.
    let relaunch = match poll_linux_hello_relaunch(allocator()) {
        Ok(launched) => launched,
        Err(message) => {
            kernel_log_fmt(format_args!("[M8.7] relaunch failed: {message}\n"));
            fatal_kernel_error("m8.7 production relaunch failed");
        }
    };

    if !state.first_exit_seen {
        if linux_hello_completed_exits() >= 1 {
            let Some((exited_pid, gen)) = linux_hello_last_exited() else {
                fatal_kernel_error("m8.7 first exit missing last_exited");
            };
            if exited_pid != state.first_pid || gen.0 != state.first_generation {
                fatal_kernel_error("m8.7 first exit identity mismatched the armed session");
            }
            if linux_fd::projection_for(exited_pid, gen, LINUX_STDOUT_FD) != Err(EBADF) {
                fatal_kernel_error("m8.7 first-exit fd table did not fail closed");
            }
            state.first_exit_seen = true;
            kernel_log_fmt(format_args!(
                "[M8.7] first exit observed pid={} gen={}\n",
                exited_pid, gen.0
            ));
        } else if state.native_progress >= NATIVE_PROGRESS_BOUND_WITHOUT_FIRST_EXIT {
            fatal_kernel_error("m8.7 Linux hello never exited");
        }
    }

    if let Some(launched) = relaunch {
        if !state.first_exit_seen {
            fatal_kernel_error("m8.7 relaunch before the first Linux exit");
        }
        let Some((old_pid, old_gen)) = linux_hello_last_exited() else {
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
        kernel_log_fmt(format_args!(
            "[M8.7] relaunch observed pid={} gen={}\n",
            launched.pid, launched.instance_generation.0
        ));
    }

    if state.relaunch_seen && !state.second_exit_seen && linux_hello_completed_exits() >= 2 {
        if linux_hello_live().is_some() {
            fatal_kernel_error("m8.7 second exit still showed a live session process");
        }
        state.second_exit_seen = true;
        kernel_log_line("[M8.7] second exit observed");
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

    let first = arm_linux_hello_session(
        allocator,
        task_stack_top(&stacks[LINUX_SCHEDULER_SLOT]),
        LINUX_SCHEDULER_SLOT,
        LINUX_TARGET_LAUNCHES,
    )
    .unwrap_or_else(|message| {
        kernel_log_fmt(format_args!("[M8.7] arm failed: {message}\n"));
        fatal_kernel_error("m8.7 production linux hello arm failed")
    });

    unsafe {
        *OBSERVER.get() = Some(ObserverState {
            native_pid,
            first_pid: first.pid,
            first_generation: first.instance_generation.0,
            first_exit_seen: false,
            relaunch_seen: false,
            second_exit_seen: false,
            malformed_proven: false,
            native_progress: 0,
            pre_malformed_free_pages: None,
        });
    }

    initialize_timer();
    kernel_log_line("[TIME] timer initialized");
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}
