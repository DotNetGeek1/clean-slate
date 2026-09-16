//! SYSCALL ABI: numbers, error codes, MSR setup and the Rust-side dispatcher
//! entered from `clean_slate_syscall_entry` in `arch/x86_64/asm.rs`.

pub(crate) mod validation;
use crate::arch::x86_64::asm::clean_slate_syscall_entry;
use crate::arch::x86_64::asm::SYSCALL_SCRATCH_USER_RSP;
#[cfg(feature = "m3-syscall-self-test")]
use crate::arch::x86_64::context_switch::USER_TEST_RFLAGS;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::gdt::set_syscall_kernel_stack;
use crate::arch::x86_64::gdt::userspace_gdt_state;
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::arch::x86_64::msr::read_msr;
use crate::arch::x86_64::msr::write_msr;
use crate::arch::x86_64::IA32_EFER_MSR;
use crate::arch::x86_64::IA32_EFER_SCE;
use crate::arch::x86_64::IA32_FMASK_MSR;
use crate::arch::x86_64::IA32_LSTAR_MSR;
use crate::arch::x86_64::IA32_STAR_MSR;
use crate::arch::x86_64::RFLAGS_ALIGNMENT_CHECK_BIT;
use crate::arch::x86_64::RFLAGS_DIRECTION_FLAG_BIT;
use crate::arch::x86_64::RFLAGS_INTERRUPT_ENABLE_BIT;
use crate::arch::x86_64::RFLAGS_IOPL_SHIFT;
use crate::arch::x86_64::RFLAGS_NESTED_TASK_BIT;
use crate::arch::x86_64::RFLAGS_RESUME_FLAG_BIT;
use crate::arch::x86_64::RFLAGS_TRAP_FLAG_BIT;
use crate::diagnostics::log::kernel_log_fmt;
#[cfg(feature = "m3-syscall-self-test")]
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
#[cfg(feature = "m3-syscall-self-test")]
use crate::diagnostics::qemu::qemu_exit;
#[cfg(feature = "m3-syscall-self-test")]
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
#[cfg(feature = "m3-syscall-self-test")]
use crate::interrupt::timer::kernel_ticks;
#[cfg(feature = "m4-recovery-self-test")]
use crate::interrupt::timer::kernel_ticks;
use crate::ipc::endpoint_table_mut;
use crate::ipc::IpcEndpointKind;
use crate::ipc::IpcSendError;
use crate::ipc::IPC_MAX_MESSAGE_BYTES;
#[cfg(feature = "m3-ipc-self-test")]
use crate::ipc::USERSPACE_IPC_TEST_PID;
#[cfg(feature = "m3-ipc-self-test")]
use crate::ipc::USERSPACE_IPC_UNAUTHORIZED_TEST_PID;
#[cfg(any(feature = "m4-supervisor-self-test", feature = "m4-recovery-self-test"))]
use crate::ipc::USERSPACE_SUPERVISOR_TEST_PID;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
use crate::mm::user_mapping::validate_user_pointer_range;
use crate::mm::user_mapping::validate_user_writable_pointer_range;
#[cfg(feature = "m3-syscall-self-test")]
use crate::mm::PAGE_SIZE;
use crate::process::process_registry_mut;
use crate::process::KERNEL_PROCESS_ID;
use crate::sched::with_scheduler;
use crate::sched::ThreadKind;
#[cfg(feature = "m3-syscall-self-test")]
use crate::sched::TASK_REQUIRED_PREEMPTIONS;
#[cfg(feature = "m3-ipc-self-test")]
use crate::selftest::m3_ipc::IPC_SEND_PASS_MARKER;
#[cfg(feature = "m3-ipc-self-test")]
use crate::selftest::m3_ipc::USERSPACE_IPC_TEST_STATE;
#[cfg(feature = "m3-syscall-self-test")]
use crate::selftest::m3_syscall::userspace_syscall_test_state;
#[cfg(feature = "m3-syscall-self-test")]
use crate::selftest::m3_syscall::SYSCALL_CALL_COUNT;
#[cfg(feature = "m3-syscall-self-test")]
use crate::selftest::m3_syscall::SYSCALL_DF_SANITIZED_OBSERVED;
#[cfg(feature = "m3-syscall-self-test")]
use crate::selftest::m3_syscall::SYSCALL_PASS_MARKER;
#[cfg(feature = "m3-syscall-self-test")]
use crate::selftest::m3_syscall::SYSCALL_TEST_REQUIRED_CALLS;
#[cfg(feature = "m4-recovery-self-test")]
use crate::selftest::m4_recovery::observe_recovery_supervisor_line;
#[cfg(feature = "m4-recovery-self-test")]
use crate::selftest::m4_recovery::recovery_complete_and_exit;
#[cfg(feature = "m4-supervisor-self-test")]
use crate::selftest::m4_supervisor::observe_supervisor_console_line;
#[cfg(feature = "m3-syscall-self-test")]
use crate::selftest::USER_TEST_CODE_ADDRESS;
use crate::service::service_lifecycle_controller_mut;
use crate::service::LifecycleControlError;
use crate::sync::global_cell::GlobalCell;
#[cfg(feature = "m3-syscall-self-test")]
use crate::syscall::validation::maybe_validate_syscall_entry_flags;
#[cfg(feature = "m3-syscall-self-test")]
use crate::syscall::validation::syscall_return_rflags_match;
use crate::syscall::validation::validate_canonical_user_return_state;
use crate::syscall::validation::validate_sysret_selector_triplet;
use clean_slate_service_lifecycle::LifecycleMessage;
use clean_slate_service_lifecycle::ServiceId;
use clean_slate_service_lifecycle::LIFECYCLE_WIRE_MAX_BYTES;
use core::ptr;
#[cfg(feature = "m3-syscall-self-test")]
use core::sync::atomic::Ordering;

const SYSCALL_ENTRY_RFLAGS_MASK: u64 = (1u64 << RFLAGS_TRAP_FLAG_BIT)
    | (1u64 << RFLAGS_INTERRUPT_ENABLE_BIT)
    | (1u64 << RFLAGS_DIRECTION_FLAG_BIT)
    | (0b11u64 << RFLAGS_IOPL_SHIFT)
    | (1u64 << RFLAGS_NESTED_TASK_BIT)
    | (1u64 << RFLAGS_RESUME_FLAG_BIT)
    | (1u64 << RFLAGS_ALIGNMENT_CHECK_BIT);

const SYSCALL_ABI_VERSION: u64 = 1;
const SYSCALL_NR_VERSION: u64 = 0;
const SYSCALL_NR_READ_U64: u64 = 1;
const SYSCALL_NR_FINISH: u64 = 2;
const SYSCALL_NR_IPC_SEND: u64 = 3;
const SYSCALL_NR_LIFECYCLE_CONTROL: u64 = 4;
const SYSCALL_NR_LIFECYCLE_POLL: u64 = 5;
const SYSCALL_ENOSYS: u64 = u64::MAX - 37;
pub(super) const SYSCALL_EACCES: u64 = u64::MAX - 12;
const SYSCALL_EINVAL: u64 = u64::MAX - 21;
const SYSCALL_ESTALE: u64 = u64::MAX - 116;

pub(super) fn initialize_syscall_abi(kernel_stack_top: u64) -> Result<(), &'static str> {
    if kernel_stack_top % 16 != 0 {
        return Err("syscall kernel stack top must be 16-byte aligned");
    }

    let gdt_state = userspace_gdt_state()?;
    validate_sysret_selector_triplet(
        gdt_state.user_sysret_selector_base,
        gdt_state.user_data_selector,
        gdt_state.user_code_selector,
    )?;
    let star = ((gdt_state.user_sysret_selector_base.0 as u64) << 48)
        | ((gdt_state.code_selector.0 as u64) << 32);
    set_syscall_kernel_stack(kernel_stack_top)?;
    unsafe {
        SYSCALL_SCRATCH_USER_RSP = 0;
    }
    write_msr(IA32_STAR_MSR, star);
    write_msr(IA32_LSTAR_MSR, clean_slate_syscall_entry as usize as u64);
    write_msr(IA32_FMASK_MSR, SYSCALL_ENTRY_RFLAGS_MASK);
    write_msr(IA32_EFER_MSR, read_msr(IA32_EFER_MSR) | IA32_EFER_SCE);
    Ok(())
}

#[cfg(feature = "m3-syscall-self-test")]
fn handle_syscall_read_u64(frame: &mut SyscallContext) {
    if frame.rsi != size_of::<u64>() as u64 {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    if validate_user_pointer_range(frame.rdi, frame.rsi).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    frame.rax = unsafe { ptr::read_unaligned(frame.rdi as *const u64) };
    SYSCALL_CALL_COUNT.fetch_add(1, Ordering::Relaxed);
}

fn handle_syscall_ipc_send(frame: &mut SyscallContext) {
    let length = match usize::try_from(frame.rdx) {
        Ok(length) => length,
        Err(_) => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    if length == 0 || length > IPC_MAX_MESSAGE_BYTES {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    if validate_user_pointer_range(frame.rsi, frame.rdx).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let mut copied = [0u8; IPC_MAX_MESSAGE_BYTES];
    unsafe {
        ptr::copy_nonoverlapping(frame.rsi as *const u8, copied.as_mut_ptr(), length);
    }
    let sender_pid = match current_syscall_caller_pid() {
        Ok(sender_pid) => sender_pid,
        Err(_) => {
            frame.rax = SYSCALL_EACCES;
            return;
        }
    };
    let table = unsafe { endpoint_table_mut() };
    match table.send_message(sender_pid, frame.rdi, &copied[..length]) {
        Ok(result) => {
            if result.endpoint_kind == IpcEndpointKind::ConsoleSink {
                let message = core::str::from_utf8(&copied[..length]).unwrap_or("<non-utf8>");
                kernel_log_fmt(format_args!("[IPC ] console pid={sender_pid}: {message}\n"));
                #[cfg(feature = "m4-supervisor-self-test")]
                if sender_pid == USERSPACE_SUPERVISOR_TEST_PID {
                    observe_supervisor_console_line(sender_pid, message.trim_end());
                }
                #[cfg(feature = "m4-recovery-self-test")]
                if sender_pid == USERSPACE_SUPERVISOR_TEST_PID {
                    observe_recovery_supervisor_line(sender_pid, message.trim_end());
                }
            }
            #[cfg(feature = "m3-ipc-self-test")]
            if let Some(state) = unsafe { (&mut *USERSPACE_IPC_TEST_STATE.get()).as_mut() } {
                if sender_pid == USERSPACE_IPC_TEST_PID && !state.send_ok_observed {
                    kernel_log_fmt(format_args!(
                        "{IPC_SEND_PASS_MARKER}{}\n",
                        result.bytes_sent
                    ));
                    state.send_ok_observed = true;
                }
            }
            frame.rax = result.bytes_sent as u64;
        }
        Err(IpcSendError::Unauthorized) => {
            #[cfg(feature = "m3-ipc-self-test")]
            if let Some(state) = unsafe { (&mut *USERSPACE_IPC_TEST_STATE.get()).as_mut() } {
                if sender_pid == USERSPACE_IPC_UNAUTHORIZED_TEST_PID {
                    state.unauthorized_syscall_observed = true;
                }
            }
            frame.rax = SYSCALL_EACCES;
        }
        Err(IpcSendError::InvalidCapability) => {
            #[cfg(feature = "m3-ipc-self-test")]
            if let Some(state) = unsafe { (&mut *USERSPACE_IPC_TEST_STATE.get()).as_mut() } {
                if sender_pid == USERSPACE_IPC_UNAUTHORIZED_TEST_PID {
                    state.unauthorized_syscall_observed = true;
                }
            }
            frame.rax = SYSCALL_EACCES;
        }
        Err(IpcSendError::StaleCapability) => frame.rax = SYSCALL_ESTALE,
        Err(IpcSendError::InvalidMessageLength) => frame.rax = SYSCALL_EINVAL,
    }
}

static SERVICE_LIFECYCLE_SYSCALL_ALLOCATOR: GlobalCell<Option<PageAllocator>> =
    GlobalCell::new(None);

#[allow(dead_code)]
pub(super) fn service_lifecycle_syscall_allocator_mut() -> &'static mut Option<PageAllocator> {
    unsafe { &mut *SERVICE_LIFECYCLE_SYSCALL_ALLOCATOR.get() }
}

#[allow(dead_code)]
pub(super) fn install_service_lifecycle_syscall_allocator(allocator: PageAllocator) {
    *service_lifecycle_syscall_allocator_mut() = Some(allocator);
}

#[allow(dead_code)]
fn lifecycle_control_syscall_error(error: LifecycleControlError) -> u64 {
    match error {
        LifecycleControlError::Unauthorized => SYSCALL_EACCES,
        LifecycleControlError::StaleHandle | LifecycleControlError::StaleInstance(_) => {
            SYSCALL_ESTALE
        }
        LifecycleControlError::InvalidHandle
        | LifecycleControlError::InvalidMessage(_)
        | LifecycleControlError::InvalidTransition(_)
        | LifecycleControlError::UnknownService
        | LifecycleControlError::ServiceAlreadyLive
        | LifecycleControlError::ServiceNotLive
        | LifecycleControlError::SpawnFailed(_)
        | LifecycleControlError::TeardownFailed(_) => SYSCALL_EINVAL,
    }
}

fn copy_lifecycle_reply_to_user(frame: &mut SyscallContext, event: LifecycleMessage) -> bool {
    let encoded = event.encode();
    if encoded.len() > LIFECYCLE_WIRE_MAX_BYTES {
        frame.rax = SYSCALL_EINVAL;
        return false;
    }
    unsafe {
        ptr::copy_nonoverlapping(encoded.as_ptr(), frame.r10 as *mut u8, encoded.len());
    }
    frame.rax = encoded.len() as u64;
    true
}

fn lifecycle_reply_capacity_is_valid(reply_capacity: usize) -> bool {
    reply_capacity >= LIFECYCLE_WIRE_MAX_BYTES
}

#[allow(dead_code)]
fn handle_syscall_lifecycle_control(frame: &mut SyscallContext) {
    let message_length = match usize::try_from(frame.rdx) {
        Ok(length) => length,
        Err(_) => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    if message_length == 0 || message_length > LIFECYCLE_WIRE_MAX_BYTES {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    if validate_user_pointer_range(frame.rsi, frame.rdx).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let reply_capacity = match usize::try_from(frame.r8) {
        Ok(length) => length,
        Err(_) => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    if !lifecycle_reply_capacity_is_valid(reply_capacity) {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    if validate_user_writable_pointer_range(frame.r10, frame.r8).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let sender_pid = match current_syscall_caller_pid() {
        Ok(sender_pid) => sender_pid,
        Err(_) => {
            frame.rax = SYSCALL_EACCES;
            return;
        }
    };
    let mut message = [0u8; LIFECYCLE_WIRE_MAX_BYTES];
    unsafe {
        ptr::copy_nonoverlapping(frame.rsi as *const u8, message.as_mut_ptr(), message_length);
    }
    let allocator = unsafe { (&mut *SERVICE_LIFECYCLE_SYSCALL_ALLOCATOR.get()).as_mut() };
    let Some(allocator) = allocator else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    let controller = unsafe { service_lifecycle_controller_mut() };
    match controller.handle_control_message(
        allocator,
        sender_pid,
        frame.rdi,
        &message[..message_length],
    ) {
        Ok(result) => match result.event {
            Some(event) => {
                let _ =
                    copy_lifecycle_reply_to_user(frame, LifecycleMessage::LifecycleEvent(event));
            }
            None => frame.rax = 0,
        },
        Err(error) => frame.rax = lifecycle_control_syscall_error(error),
    }
}

fn handle_syscall_lifecycle_poll(frame: &mut SyscallContext) {
    let service = ServiceId(frame.rdi as u32);
    let reply_capacity = match usize::try_from(frame.r8) {
        Ok(length) => length,
        Err(_) => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    if validate_user_writable_pointer_range(frame.r10, frame.r8).is_err()
        || !lifecycle_reply_capacity_is_valid(reply_capacity)
    {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let caller_pid = match current_syscall_caller_pid() {
        Ok(pid) => pid,
        Err(_) => {
            frame.rax = SYSCALL_EACCES;
            return;
        }
    };
    #[cfg(feature = "m4-recovery-self-test")]
    {
        use crate::selftest::m4_recovery::take_recovery_gen2_ready_poll;
        if let Some(event) = take_recovery_gen2_ready_poll(service, caller_pid) {
            let _ = copy_lifecycle_reply_to_user(frame, LifecycleMessage::LifecycleEvent(event));
            return;
        }
    }
    let controller = unsafe { service_lifecycle_controller_mut() };
    let event = match controller.poll_pending_event_authorized(caller_pid, frame.rsi, service) {
        Ok(Some(event)) => Some(event),
        Ok(None) => None,
        Err(error) => {
            frame.rax = lifecycle_control_syscall_error(error);
            return;
        }
    };
    match event {
        Some(event) => {
            let _ = copy_lifecycle_reply_to_user(frame, LifecycleMessage::LifecycleEvent(event));
        }
        None => frame.rax = 0,
    }
}

// Consumed by arch/x86_64/asm.rs (clean_slate_syscall_entry calls this with the saved frame).
#[unsafe(no_mangle)]
extern "C" fn clean_slate_syscall_dispatch(context: *mut SyscallContext) -> u64 {
    let frame = unsafe { &mut *context };
    if let Err(message) = validate_canonical_user_return_state(frame) {
        fatal_kernel_error(message);
    }

    match frame.rax {
        SYSCALL_NR_VERSION => {
            #[cfg(feature = "m3-syscall-self-test")]
            maybe_validate_syscall_entry_flags(frame);
            frame.rax = SYSCALL_ABI_VERSION;
        }
        #[cfg(feature = "m3-syscall-self-test")]
        SYSCALL_NR_READ_U64 => handle_syscall_read_u64(frame),
        #[cfg(not(feature = "m3-syscall-self-test"))]
        SYSCALL_NR_READ_U64 => frame.rax = SYSCALL_ENOSYS,
        #[cfg(feature = "m3-syscall-self-test")]
        SYSCALL_NR_FINISH => {
            let state = match userspace_syscall_test_state() {
                Ok(state) => state,
                Err(message) => fatal_kernel_error(message),
            };
            if frame.user_rsp != state.user_stack_pointer
                || !syscall_return_rflags_match(frame.user_rflags, USER_TEST_RFLAGS)
            {
                fatal_kernel_error("syscall return frame contained unexpected userspace state");
            }
            if frame.user_rip < USER_TEST_CODE_ADDRESS
                || frame.user_rip >= USER_TEST_CODE_ADDRESS + PAGE_SIZE
            {
                fatal_kernel_error("syscall return RIP escaped the userspace code page");
            }
            let call_count = SYSCALL_CALL_COUNT.load(Ordering::Relaxed);
            let ticks = kernel_ticks();
            if call_count >= SYSCALL_TEST_REQUIRED_CALLS
                && ticks >= TASK_REQUIRED_PREEMPTIONS
                && SYSCALL_DF_SANITIZED_OBSERVED.load(Ordering::Relaxed)
            {
                kernel_log_line(SYSCALL_PASS_MARKER);
                qemu_exit(QEMU_EXIT_SUCCESS)
            }
            frame.rax = 0;
        }
        #[cfg(all(
            not(feature = "m3-syscall-self-test"),
            not(feature = "m4-recovery-self-test")
        ))]
        SYSCALL_NR_FINISH => frame.rax = SYSCALL_ENOSYS,
        #[cfg(feature = "m4-recovery-self-test")]
        SYSCALL_NR_FINISH => {
            use crate::selftest::m4_recovery::publish_recovery_bootstrap;
            publish_recovery_bootstrap(|bootstrap| bootstrap.kernel_ticks = kernel_ticks());
            use crate::selftest::m4_recovery::recovery_acceptance_complete;
            if recovery_acceptance_complete() {
                recovery_complete_and_exit();
            }
            frame.rax = 0;
        }
        SYSCALL_NR_IPC_SEND => handle_syscall_ipc_send(frame),
        SYSCALL_NR_LIFECYCLE_CONTROL => handle_syscall_lifecycle_control(frame),
        SYSCALL_NR_LIFECYCLE_POLL => handle_syscall_lifecycle_poll(frame),
        _ => frame.rax = SYSCALL_ENOSYS,
    }

    frame as *mut SyscallContext as u64
}

fn current_syscall_caller_pid() -> Result<u64, &'static str> {
    let thread =
        without_interrupts(|| with_scheduler(|scheduler| scheduler.current_thread_descriptor()))?;
    if thread.kind != ThreadKind::User {
        return Err("syscall caller thread was not userspace");
    }
    if thread.owner_process_id == KERNEL_PROCESS_ID {
        return Err("syscall caller process id was invalid");
    }
    let registry = unsafe { &*process_registry_mut() };
    let process = registry
        .get(thread.owner_process_id)
        .ok_or("syscall caller process was not present in registry")?;
    let active_root = current_root_frame_address();
    if process.address_space_root() != active_root {
        return Err("syscall caller process did not match active address space");
    }
    let process_for_root = registry
        .find_by_address_space_root(active_root)
        .ok_or("active address space did not map to a registered process")?;
    if process_for_root.id != process.id {
        return Err("syscall caller thread process did not match active owner root");
    }
    Ok(process.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_reply_capacity_rejects_short_buffers() {
        assert!(!lifecycle_reply_capacity_is_valid(33));
        assert!(!lifecycle_reply_capacity_is_valid(
            LIFECYCLE_WIRE_MAX_BYTES - 1
        ));
    }

    #[test]
    fn lifecycle_reply_capacity_accepts_wire_max_buffer() {
        assert!(lifecycle_reply_capacity_is_valid(LIFECYCLE_WIRE_MAX_BYTES));
    }
}
