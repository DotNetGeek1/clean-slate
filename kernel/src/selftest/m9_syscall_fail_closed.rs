//! M9 #143: unresolved syscall caller must fail closed (no native/Linux dispatch).
//!
//! #215: the same boot also runs two hostile offenders. A native process issues
//! `syscall` with a non-canonical RSP; a Linux process checks that
//! `arch_prctl(ARCH_SET_FS, 1 << 63)` returns `-EPERM` and then does the same.
//! Both must be terminated through the CPL3 fault path while the native sibling
//! keeps running; any `[FAIL]` or halt fails the lane.

use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::diagnostics::serial::serial_write_line;
use crate::interrupt::timer::initialize_timer;
use crate::mm::frame_allocator::PageAllocator;
use crate::process::live_instance_generation;
use crate::process::process_registry_mut;
use crate::process::spoof_registered_address_space_root_for_self_test;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::scheduler_mut;
use crate::sched::task_stacks_mut;
use crate::sched::ThreadKind;
use crate::selftest::userspace_process::configure_scheduler_thread_slot;
use crate::selftest::userspace_process::reset_process_scheduler_world;
use crate::selftest::userspace_process::spawn_linux_userspace_process_with_code;
use crate::selftest::userspace_process::spawn_native_userspace_process_with_code;
use crate::selftest::USER_TEST_PROCESS_STACK_ADDRESS;
use crate::syscall::initialize_syscall_abi;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

pub(crate) const M9_SYSCALL_FAIL_CLOSED_PASS_MARKER: &str = "[M9.C] PASS";
pub(crate) const M9_NONCANONICAL_NATIVE_MARKER: &str =
    "[M9.C] non-canonical syscall rsp terminated native offender OK";
pub(crate) const M9_ARCH_SET_FS_EPERM_MARKER: &str =
    "[M9.C] arch_prctl(ARCH_SET_FS, non-canonical) returned EPERM OK";
pub(crate) const M9_NONCANONICAL_LINUX_MARKER: &str =
    "[M9.C] non-canonical syscall rsp terminated linux offender OK";

/// Registry poison value for the offender; must not be `0` (a transient CR3 of zero
/// would match and let native dispatch loop instead of fail-closed).
const M9_ROOT_SPOOF_SENTINEL: u64 = 0x0000_0000_DEAD_BEEF;

/// Offender: `syscall` with `rax=0` (native VERSION); loops if it ever returned.
const OFFENDER_SYSCALL_CODE: [u8; 7] = [
    0x48, 0x31, 0xC0, // xor rax, rax
    0x0F, 0x05, // syscall
    0xEB, 0xFE, // jmp $-2
];

/// Native sibling: version syscall loop (same as M8.3 dispatch proof).
const NATIVE_PROGRESS_CODE: [u8; 7] = [
    0x48, 0x31, 0xC0, // xor rax, rax
    0x0F, 0x05, // syscall
    0xEB, 0xF9, // jmp loop
];

/// Native hostile offender: VERSION syscall with RSP = 1 << 63.
const NATIVE_NONCANONICAL_RSP_CODE: [u8; 17] = [
    0x48, 0xBC, 0, 0, 0, 0, 0, 0, 0, 0x80, // movabs rsp, 0x8000_0000_0000_0000
    0x48, 0x31, 0xC0, // xor rax, rax
    0x0F, 0x05, // syscall
    0x0F, 0x0B, // ud2
];

/// Linux hostile offender. `arch_prctl(ARCH_SET_FS, 1 << 63)` must return
/// `-EPERM` (else `exit(1)`); then `getpid` with RSP = 1 << 63.
const LINUX_HOSTILE_CODE: [u8; 61] = [
    0xB8, 0x9E, 0x00, 0x00, 0x00, // mov eax, 158 (arch_prctl)
    0xBF, 0x02, 0x10, 0x00, 0x00, // mov edi, 0x1002 (ARCH_SET_FS)
    0x48, 0xBE, 0, 0, 0, 0, 0, 0, 0, 0x80, // movabs rsi, 0x8000_0000_0000_0000
    0x0F, 0x05, // syscall
    0x48, 0x83, 0xF8, 0xFF, // cmp rax, -1 (-EPERM)
    0x75, 0x13, // jne fail (+19)
    0x48, 0xBC, 0, 0, 0, 0, 0, 0, 0, 0x80, // movabs rsp, 0x8000_0000_0000_0000
    0xB8, 0x27, 0x00, 0x00, 0x00, // mov eax, 39 (getpid)
    0x0F, 0x05, // syscall
    0x0F, 0x0B, // ud2
    // fail:
    0xB8, 0x3C, 0x00, 0x00, 0x00, // mov eax, 60 (exit)
    0xBF, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
    0x0F, 0x05, // syscall
    0x0F, 0x0B, // ud2
];

static M9_OFFENDER_PID: AtomicU64 = AtomicU64::new(0);
static M9_MISMATCH_ARMED: AtomicBool = AtomicBool::new(false);
static M9_MISMATCH_APPLIED: AtomicBool = AtomicBool::new(false);
static M9_FAIL_CLOSED_OBSERVED: AtomicBool = AtomicBool::new(false);
static M9_SIBLING_PROGRESS: AtomicUsize = AtomicUsize::new(0);
static M9_NATIVE_HOSTILE_PID: AtomicU64 = AtomicU64::new(0);
static M9_LINUX_HOSTILE_PID: AtomicU64 = AtomicU64::new(0);
static M9_NATIVE_HOSTILE_CONTAINED: AtomicBool = AtomicBool::new(false);
static M9_LINUX_HOSTILE_CONTAINED: AtomicBool = AtomicBool::new(false);

fn install_payload(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    reset_process_scheduler_world();
    M9_OFFENDER_PID.store(0, Ordering::Relaxed);
    M9_MISMATCH_ARMED.store(false, Ordering::Relaxed);
    M9_MISMATCH_APPLIED.store(false, Ordering::Relaxed);
    M9_FAIL_CLOSED_OBSERVED.store(false, Ordering::Relaxed);
    M9_SIBLING_PROGRESS.store(0, Ordering::Relaxed);
    M9_NATIVE_HOSTILE_PID.store(0, Ordering::Relaxed);
    M9_LINUX_HOSTILE_PID.store(0, Ordering::Relaxed);
    M9_NATIVE_HOSTILE_CONTAINED.store(false, Ordering::Relaxed);
    M9_LINUX_HOSTILE_CONTAINED.store(false, Ordering::Relaxed);

    let stacks = unsafe { &*task_stacks_mut() };
    let offender = spawn_native_userspace_process_with_code(
        allocator,
        task_stack_top(&stacks[0]),
        &OFFENDER_SYSCALL_CODE,
        USER_TEST_PROCESS_STACK_ADDRESS,
    )?;
    M9_OFFENDER_PID.store(offender.process_id, Ordering::Relaxed);
    M9_MISMATCH_ARMED.store(true, Ordering::Relaxed);

    let sibling = spawn_native_userspace_process_with_code(
        allocator,
        task_stack_top(&stacks[1]),
        &NATIVE_PROGRESS_CODE,
        USER_TEST_PROCESS_STACK_ADDRESS,
    )?;

    let native_hostile = spawn_native_userspace_process_with_code(
        allocator,
        task_stack_top(&stacks[2]),
        &NATIVE_NONCANONICAL_RSP_CODE,
        USER_TEST_PROCESS_STACK_ADDRESS,
    )?;
    M9_NATIVE_HOSTILE_PID.store(native_hostile.process_id, Ordering::Relaxed);

    let linux_hostile = spawn_linux_userspace_process_with_code(
        allocator,
        task_stack_top(&stacks[3]),
        &LINUX_HOSTILE_CODE,
        USER_TEST_PROCESS_STACK_ADDRESS,
    )?;
    M9_LINUX_HOSTILE_PID.store(linux_hostile.process_id, Ordering::Relaxed);

    configure_scheduler_thread_slot(0, &offender.thread)?;
    configure_scheduler_thread_slot(1, &sibling.thread)?;
    configure_scheduler_thread_slot(2, &native_hostile.thread)?;
    configure_scheduler_thread_slot(3, &linux_hostile.thread)?;
    Ok(())
}

/// Poison registry metadata on the offender's first syscall only (not the sibling).
pub(crate) fn arm_caller_resolution_mismatch_if_pending() {
    if !M9_MISMATCH_ARMED.load(Ordering::Relaxed) || M9_MISMATCH_APPLIED.load(Ordering::Relaxed) {
        return;
    }
    let offender = M9_OFFENDER_PID.load(Ordering::Relaxed);
    if offender == 0 {
        return;
    }
    let scheduler = unsafe { scheduler_mut() };
    let index = match scheduler.current_thread {
        Some(index) => index,
        None => return,
    };
    let thread = scheduler.threads[index];
    if thread.kind != ThreadKind::User || thread.owner_process_id != offender {
        return;
    }
    if spoof_registered_address_space_root_for_self_test(offender, M9_ROOT_SPOOF_SENTINEL).is_err()
    {
        return;
    }
    M9_MISMATCH_APPLIED.store(true, Ordering::Relaxed);
}

pub(crate) fn start_m9_syscall_fail_closed_self_test(allocator: PageAllocator) -> ! {
    install_service_lifecycle_syscall_allocator(allocator);
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m9 fail-closed allocator missing"));
    if let Err(message) = install_payload(allocator) {
        fatal_kernel_error(message);
    }

    let kernel_stack_top = unsafe {
        let stacks = &*task_stacks_mut();
        task_stack_top(&stacks[0])
    };
    if let Err(message) = set_privilege_stack(kernel_stack_top) {
        fatal_kernel_error(message);
    }
    if let Err(message) = initialize_syscall_abi(kernel_stack_top) {
        fatal_kernel_error(message);
    }
    initialize_timer();
    serial_write_line("[TIME] timer initialized");

    let frame_pointer = match start_current_scheduler_thread() {
        Ok(frame_pointer) => frame_pointer,
        Err(message) => fatal_kernel_error(message),
    };
    unsafe { restore_task_context(frame_pointer) }
}

pub(crate) fn observe_syscall_fail_closed(reason: &'static str, torn_down_pid: u64) {
    let offender = M9_OFFENDER_PID.load(Ordering::Relaxed);
    if torn_down_pid != offender {
        fatal_kernel_error("m9 fail-closed tore down an unexpected process");
    }
    if reason != "syscall caller process did not match active address space" {
        fatal_kernel_error("m9 fail-closed diagnostic reason mismatch");
    }
    M9_FAIL_CLOSED_OBSERVED.store(true, Ordering::Relaxed);
}

/// Called from the syscall entry containment path before the caller is torn down.
pub(crate) fn observe_noncanonical_containment() {
    let scheduler = unsafe { scheduler_mut() };
    let Some(index) = scheduler.current_thread else {
        fatal_kernel_error("m9 non-canonical containment had no current thread");
    };
    let pid = scheduler.threads[index].owner_process_id;
    if pid == M9_NATIVE_HOSTILE_PID.load(Ordering::Relaxed) {
        M9_NATIVE_HOSTILE_CONTAINED.store(true, Ordering::Relaxed);
    } else if pid == M9_LINUX_HOSTILE_PID.load(Ordering::Relaxed) {
        let generation = live_instance_generation(pid)
            .unwrap_or_else(|| fatal_kernel_error("m9 linux offender had no generation"));
        if crate::process::linux_mem::saved_fs_base(pid, generation) != 0 {
            fatal_kernel_error("m9 rejected ARCH_SET_FS still stored the fs base");
        }
        M9_LINUX_HOSTILE_CONTAINED.store(true, Ordering::Relaxed);
    } else {
        fatal_kernel_error("m9 non-canonical containment hit an unexpected process");
    }
}

fn is_registered(pid: u64) -> bool {
    unsafe { process_registry_mut().get(pid) }.is_some()
}

pub(crate) fn observe_native_sibling_progress() {
    if !M9_FAIL_CLOSED_OBSERVED.load(Ordering::Relaxed) {
        return;
    }
    let linux_hostile = M9_LINUX_HOSTILE_PID.load(Ordering::Relaxed);
    let linux_contained = M9_LINUX_HOSTILE_CONTAINED.load(Ordering::Relaxed);
    if !linux_contained && !is_registered(linux_hostile) {
        fatal_kernel_error("m9 linux offender exited without containment (arch_prctl not EPERM?)");
    }
    if !M9_NATIVE_HOSTILE_CONTAINED.load(Ordering::Relaxed) || !linux_contained {
        return;
    }
    for pid in [
        M9_OFFENDER_PID.load(Ordering::Relaxed),
        M9_NATIVE_HOSTILE_PID.load(Ordering::Relaxed),
        linux_hostile,
    ] {
        if is_registered(pid) {
            fatal_kernel_error("m9 offender remained in the process registry");
        }
    }
    M9_SIBLING_PROGRESS.fetch_add(1, Ordering::Relaxed);
    kernel_log_line(M9_NONCANONICAL_NATIVE_MARKER);
    kernel_log_line(M9_ARCH_SET_FS_EPERM_MARKER);
    kernel_log_line(M9_NONCANONICAL_LINUX_MARKER);
    kernel_log_line(M9_SYSCALL_FAIL_CLOSED_PASS_MARKER);
    qemu_exit(QEMU_EXIT_SUCCESS);
}
