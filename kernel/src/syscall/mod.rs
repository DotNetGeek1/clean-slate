//! SYSCALL ABI: numbers, error codes, MSR setup and the Rust-side dispatcher
//! entered from `clean_slate_syscall_entry` in `arch/x86_64/asm.rs`.

pub(crate) mod linux;
pub(crate) mod validation;
use crate::arch::x86_64::asm::clean_slate_syscall_entry;
use crate::arch::x86_64::asm::SYSCALL_SCRATCH_USER_RSP;
use crate::arch::x86_64::context_switch::resume_after_scheduler_handoff;
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
use crate::mm::address_space::kernel_root_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
use crate::mm::user_mapping::validate_user_pointer_range;
use crate::mm::user_mapping::validate_user_writable_pointer_range;
#[cfg(feature = "m3-syscall-self-test")]
use crate::mm::PAGE_SIZE;
use crate::process::domain::teardown_current_process;
use crate::process::live_instance_generation;
use crate::process::personality::dispatch_target_for;
use crate::process::personality::execution_personality_for_pid;
use crate::process::personality::ExecutionPersonality;
use crate::process::personality::SyscallDispatchTarget;
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
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test"
))]
use crate::selftest::m5_storage::observe_userspace_block_operation;
#[cfg(feature = "m3-syscall-self-test")]
use crate::selftest::USER_TEST_CODE_ADDRESS;
use crate::service::block_bridge::handle_kernel_block_request;
use crate::service::service_lifecycle_controller_mut;
use crate::service::LifecycleControlError;
use crate::sync::global_cell::GlobalCell;
#[cfg(feature = "m3-syscall-self-test")]
use crate::syscall::validation::maybe_validate_syscall_entry_flags;
#[cfg(feature = "m3-syscall-self-test")]
use crate::syscall::validation::syscall_return_rflags_match;
use crate::syscall::validation::validate_canonical_user_return_state;
use crate::syscall::validation::validate_sysret_selector_triplet;
use clean_slate_capability::syscall_abi as cap_abi;
use clean_slate_service_fixtures::{
    BlockTransportOp, BlockTransportRequest, BlockTransportResponse, BlockTransportStatus,
    BLOCK_TRANSPORT_MAX_PAYLOAD_BYTES, BLOCK_TRANSPORT_REQUEST_BYTES,
    BLOCK_TRANSPORT_RESPONSE_BYTES, BLOCK_TRANSPORT_VERSION,
};
use clean_slate_service_lifecycle::InstanceGeneration;
use clean_slate_service_lifecycle::LifecycleMessage;
use clean_slate_service_lifecycle::ServiceId;
use clean_slate_service_lifecycle::LIFECYCLE_WIRE_MAX_BYTES;
use core::ptr;
use core::sync::atomic::AtomicU64;
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
const SYSCALL_NR_BLOCK_CAPABILITY: u64 = 6;
const SYSCALL_NR_BLOCK_REQUEST: u64 = 7;
#[cfg(feature = "m9-block-wake-self-test")]
const SYSCALL_NR_WAIT_BLOCK: u64 = 100;
#[cfg(feature = "m9-block-wake-self-test")]
const SYSCALL_NR_WAIT_WAKE: u64 = 101;
#[cfg(feature = "m9-block-wake-self-test")]
const SYSCALL_NR_WAIT_PROGRESS: u64 = 102;
#[cfg(feature = "m9-block-wake-self-test")]
const SYSCALL_NR_WAIT_YIELD: u64 = 103;
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
    crate::sched::fpu::enable_user_fpu_state();
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
pub(crate) fn service_lifecycle_syscall_allocator_mut() -> &'static mut Option<PageAllocator> {
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

fn handle_syscall_block_capability(frame: &mut SyscallContext) {
    if frame.rsi != u64::from(BLOCK_TRANSPORT_VERSION) {
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
    let controller = unsafe { service_lifecycle_controller_mut() };
    match controller.acquire_block_device_capability(caller_pid, frame.rdi) {
        Ok(handle) => frame.rax = handle,
        Err(LifecycleControlError::Unauthorized) => frame.rax = SYSCALL_EACCES,
        Err(LifecycleControlError::StaleHandle | LifecycleControlError::StaleInstance(_)) => {
            frame.rax = SYSCALL_ESTALE
        }
        Err(_) => frame.rax = SYSCALL_EINVAL,
    }
}

fn handle_syscall_block_request(frame: &mut SyscallContext) {
    if frame.rdx != BLOCK_TRANSPORT_REQUEST_BYTES as u64 {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    if validate_user_pointer_range(frame.rsi, frame.rdx).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    if validate_user_writable_pointer_range(frame.r10, BLOCK_TRANSPORT_RESPONSE_BYTES as u64)
        .is_err()
    {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let payload_len = match usize::try_from(frame.r9) {
        Ok(len) => len,
        Err(_) => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    if payload_len > BLOCK_TRANSPORT_MAX_PAYLOAD_BYTES {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let mut request_bytes = [0u8; BLOCK_TRANSPORT_REQUEST_BYTES];
    unsafe {
        ptr::copy_nonoverlapping(
            frame.rsi as *const u8,
            request_bytes.as_mut_ptr(),
            request_bytes.len(),
        );
    }
    let request = match BlockTransportRequest::decode(&request_bytes) {
        Ok(request) => request,
        Err(_) => {
            let response = BlockTransportResponse {
                request_id: 0,
                device_id: 0,
                operation: BlockTransportOp::Geometry,
                status: BlockTransportStatus::InvalidProtocol,
                logical_block_size: 0,
                block_count: 0,
                max_transfer_blocks: 0,
            }
            .encode();
            unsafe {
                ptr::copy_nonoverlapping(response.as_ptr(), frame.r10 as *mut u8, response.len());
            }
            frame.rax = BLOCK_TRANSPORT_RESPONSE_BYTES as u64;
            return;
        }
    };

    if u64::from(request.buffer_len) != frame.r9 {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    match request.operation {
        BlockTransportOp::Geometry | BlockTransportOp::Flush => {
            if payload_len != 0 {
                frame.rax = SYSCALL_EINVAL;
                return;
            }
        }
        BlockTransportOp::Read => {
            if payload_len > 0 && validate_user_writable_pointer_range(frame.r8, frame.r9).is_err()
            {
                frame.rax = SYSCALL_EINVAL;
                return;
            }
        }
        BlockTransportOp::Write => {
            if payload_len > 0 && validate_user_pointer_range(frame.r8, frame.r9).is_err() {
                frame.rax = SYSCALL_EINVAL;
                return;
            }
        }
    }
    let caller_pid = match current_syscall_caller_pid() {
        Ok(pid) => pid,
        Err(_) => {
            frame.rax = SYSCALL_EACCES;
            return;
        }
    };
    let controller = unsafe { service_lifecycle_controller_mut() };
    match controller.authorize_block_device_request(caller_pid, frame.rdi, request.device_id) {
        Ok(()) => {}
        Err(LifecycleControlError::Unauthorized) => {
            frame.rax = SYSCALL_EACCES;
            return;
        }
        Err(LifecycleControlError::StaleHandle | LifecycleControlError::StaleInstance(_)) => {
            frame.rax = SYSCALL_ESTALE;
            return;
        }
        Err(_) => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    }
    let mut payload = [0u8; BLOCK_TRANSPORT_MAX_PAYLOAD_BYTES];
    if matches!(request.operation, BlockTransportOp::Write) && payload_len > 0 {
        unsafe {
            ptr::copy_nonoverlapping(frame.r8 as *const u8, payload.as_mut_ptr(), payload_len);
        }
    }
    kernel_log_fmt(format_args!(
        "[BLK ] request op={} id={}\n",
        block_op_name(request.operation),
        request.request_id
    ));
    let response_bytes = handle_kernel_block_request(&request_bytes, &mut payload[..payload_len]);
    let (response, response_wire) = match BlockTransportResponse::decode(&response_bytes) {
        Ok(decoded) => (decoded, response_bytes),
        Err(_) => {
            let fallback = BlockTransportResponse {
                request_id: request.request_id,
                device_id: request.device_id,
                operation: request.operation,
                status: BlockTransportStatus::InvalidProtocol,
                logical_block_size: 0,
                block_count: 0,
                max_transfer_blocks: 0,
            };
            (fallback, fallback.encode())
        }
    };
    if matches!(request.operation, BlockTransportOp::Read)
        && matches!(response.status, BlockTransportStatus::Ok)
        && payload_len > 0
    {
        unsafe {
            ptr::copy_nonoverlapping(payload.as_ptr(), frame.r8 as *mut u8, payload_len);
        }
    }
    unsafe {
        ptr::copy_nonoverlapping(
            response_wire.as_ptr(),
            frame.r10 as *mut u8,
            response_wire.len(),
        );
    }
    kernel_log_fmt(format_args!(
        "[BLK ] completion id={} status={}\n",
        request.request_id,
        block_status_name(response.status as u8)
    ));
    #[cfg(any(
        feature = "m5-storage-self-test",
        feature = "m5-persistence-self-test",
        feature = "m5-crash-early-self-test",
        feature = "m5-crash-late-self-test",
        feature = "m5-crash-recovery-self-test"
    ))]
    if matches!(response.status, BlockTransportStatus::Ok) {
        observe_userspace_block_operation(request.operation);
    }
    frame.rax = BLOCK_TRANSPORT_RESPONSE_BYTES as u64;
}

fn block_op_name(op: BlockTransportOp) -> &'static str {
    match op {
        BlockTransportOp::Geometry => "geometry",
        BlockTransportOp::Read => "read",
        BlockTransportOp::Write => "write",
        BlockTransportOp::Flush => "flush",
    }
}

fn block_status_name(raw: u8) -> &'static str {
    match raw {
        0 => "ok",
        1 => "invalid-protocol",
        2 => "invalid-request",
        3 => "unsupported",
        4 => "device-fault",
        5 => "timeout",
        6 => "reset-required",
        _ => "unknown",
    }
}

// Consumed by arch/x86_64/asm.rs (clean_slate_syscall_entry calls this with the saved frame).
// Personality is resolved from trusted process metadata before interpreting RAX
// so native vs Linux number spaces cannot collide.
fn sync_syscall_kernel_stack_from_current_thread() {
    let _ = crate::arch::x86_64::cpu::without_interrupts(|| {
        let scheduler = unsafe { crate::sched::scheduler_mut() };
        let index = scheduler
            .current_thread
            .ok_or("syscall entry required a current thread")?;
        let top = scheduler.threads[index].kernel_stack_top;
        crate::arch::x86_64::gdt::set_syscall_kernel_stack(top)
    });
}

#[unsafe(no_mangle)]
extern "C" fn clean_slate_syscall_dispatch(context: *mut SyscallContext) -> u64 {
    sync_syscall_kernel_stack_from_current_thread();
    crate::sched::check_task_stack_guard(context as u64);
    let frame = unsafe { &mut *context };
    if let Err(message) = validate_canonical_user_return_state(frame) {
        fatal_kernel_error(message);
    }
    // M8.2 (#92) self-test: observe the first syscall of the launched Linux
    // image (entry proof) and the native sibling's progress. Test-only hook.
    #[cfg(feature = "m8-linux-image-self-test")]
    crate::selftest::m8_linux_image::observe_syscall(frame);
    #[cfg(feature = "m8-linux-hello-self-test")]
    crate::selftest::m8_linux_hello::observe_syscall(frame);
    #[cfg(feature = "m9-low-va-self-test")]
    crate::selftest::m9_low_va::observe_syscall(frame);
    #[cfg(feature = "m9-linux-exec-self-test")]
    crate::selftest::m9_linux_exec::observe_syscall(frame);
    #[cfg(feature = "m9-linux-proc-self-test")]
    crate::selftest::m9_linux_proc::observe_syscall(frame);
    #[cfg(feature = "m9-linux-socket-self-test")]
    crate::selftest::m9_linux_socket::observe_syscall(frame);

    #[cfg(feature = "m9-syscall-fail-closed-self-test")]
    crate::selftest::m9_syscall_fail_closed::arm_caller_resolution_mismatch_if_pending();

    match route_syscall(resolve_syscall_caller()) {
        SyscallRoute::Native { pid } => {
            let _ = pid;
            dispatch_native(frame);
        }
        SyscallRoute::Linux { pid, generation } => {
            linux::dispatch(frame, pid, generation);
            #[cfg(feature = "m8-linux-dispatch-self-test")]
            crate::selftest::m8_linux_dispatch::maybe_complete_m8_linux_dispatch();
        }
        SyscallRoute::LinuxRejectMissingGeneration { pid } => {
            linux::reject_missing_generation(frame, pid);
        }
        SyscallRoute::FailClosed { reason } => fail_closed_unresolved_syscall_caller(reason),
    }

    frame as *mut SyscallContext as u64
}

/// Trusted caller identity resolved once per SYSCALL entry.
pub(crate) struct ResolvedSyscallCaller {
    pub(crate) pid: u64,
    pub(crate) personality: ExecutionPersonality,
}

/// Pure routing decision for host tests and production dispatch (#143).
pub(crate) enum SyscallRoute {
    Native {
        pid: u64,
    },
    Linux {
        pid: u64,
        generation: InstanceGeneration,
    },
    LinuxRejectMissingGeneration {
        pid: u64,
    },
    FailClosed {
        reason: &'static str,
    },
}

/// Map trusted caller resolution to a dispatch target without touching user registers.
pub(crate) fn route_syscall(
    resolution: Result<ResolvedSyscallCaller, &'static str>,
) -> SyscallRoute {
    match resolution {
        Ok(caller) => match dispatch_target_for(caller.personality) {
            SyscallDispatchTarget::Native => SyscallRoute::Native { pid: caller.pid },
            SyscallDispatchTarget::LinuxX86_64 => match live_instance_generation(caller.pid) {
                Some(generation) if generation.0 != 0 => SyscallRoute::Linux {
                    pid: caller.pid,
                    generation,
                },
                _ => SyscallRoute::LinuxRejectMissingGeneration { pid: caller.pid },
            },
        },
        Err(reason) => SyscallRoute::FailClosed { reason },
    }
}

/// Resolve caller pid + personality from the trusted scheduler/CR3 path.
fn resolve_syscall_caller() -> Result<ResolvedSyscallCaller, &'static str> {
    let pid = current_syscall_caller_pid()?;
    let personality = execution_personality_for_pid(pid)?;
    Ok(ResolvedSyscallCaller { pid, personality })
}

const UNRESOLVED_CALLER_DIAG_LIMIT: u64 = 8;
static UNRESOLVED_CALLER_DIAG_COUNT: AtomicU64 = AtomicU64::new(0);

fn log_unresolved_syscall_caller(reason: &'static str) {
    let observed = UNRESOLVED_CALLER_DIAG_COUNT.fetch_add(1, Ordering::Relaxed);
    if observed < UNRESOLVED_CALLER_DIAG_LIMIT {
        kernel_log_fmt(format_args!(
            "[SYSC] unresolved caller reason={reason} fail-closed\n"
        ));
    }
}

/// Contain the current userspace execution context when caller resolution failed.
fn fail_closed_unresolved_syscall_caller(reason: &'static str) -> ! {
    log_unresolved_syscall_caller(reason);
    if matches!(
        reason,
        "scheduler had no current thread to dispatch" | "syscall caller thread was not userspace"
    ) {
        fatal_kernel_error(reason);
    }
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("service lifecycle allocator was unavailable"));
    let teardown = teardown_current_process(allocator, kernel_root_frame(), 1, true)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    #[cfg(feature = "m9-syscall-fail-closed-self-test")]
    crate::selftest::m9_syscall_fail_closed::observe_syscall_fail_closed(
        reason,
        teardown.process_id,
    );
    resume_after_syscall_containment(teardown.next_stack_pointer)
}

fn resume_after_syscall_containment(next_stack_pointer: Option<u64>) -> ! {
    resume_after_scheduler_handoff(
        next_stack_pointer,
        "no runnable thread remained after syscall fail-closed",
    )
}

/// Narrow hook for native blocking from syscall handlers (#145).
#[cfg_attr(not(feature = "m9-block-wake-self-test"), allow(dead_code))]
pub(crate) fn block_current_syscall(
    frame: &mut SyscallContext,
    key: crate::sched::wait::WaitKey,
    deadline: Option<crate::sched::wait::Deadline>,
) {
    match crate::sched::wait::block_current_thread(frame, key, deadline) {
        Ok(outcome) => {
            frame.rax = crate::sched::wait::encode_wait_outcome(outcome);
        }
        Err(message) => fatal_kernel_error(message),
    }
}

fn dispatch_native(frame: &mut SyscallContext) {
    match frame.rax {
        SYSCALL_NR_VERSION => {
            #[cfg(feature = "m3-syscall-self-test")]
            maybe_validate_syscall_entry_flags(frame);
            #[cfg(feature = "m8-linux-dispatch-self-test")]
            {
                crate::syscall::linux::M8_NATIVE_PROGRESS.fetch_add(1, Ordering::Relaxed);
                crate::selftest::m8_linux_dispatch::maybe_complete_m8_linux_dispatch();
            }
            #[cfg(feature = "m9-syscall-fail-closed-self-test")]
            crate::selftest::m9_syscall_fail_closed::observe_native_sibling_progress();
            #[cfg(feature = "m9-userspace-self-test")]
            crate::selftest::m9_userspace::observe_native_progress();
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
        SYSCALL_NR_BLOCK_CAPABILITY => handle_syscall_block_capability(frame),
        SYSCALL_NR_BLOCK_REQUEST => handle_syscall_block_request(frame),
        #[cfg(feature = "m9-block-wake-self-test")]
        SYSCALL_NR_WAIT_BLOCK => {
            crate::selftest::m9_block_wake::handle_wait_block_syscall(frame);
        }
        #[cfg(feature = "m9-block-wake-self-test")]
        SYSCALL_NR_WAIT_WAKE => {
            crate::selftest::m9_block_wake::handle_wait_wake_syscall(frame);
        }
        #[cfg(feature = "m9-block-wake-self-test")]
        SYSCALL_NR_WAIT_PROGRESS => {
            crate::selftest::m9_block_wake::handle_wait_progress_syscall(frame);
        }
        #[cfg(feature = "m9-block-wake-self-test")]
        SYSCALL_NR_WAIT_YIELD => {
            crate::selftest::m9_block_wake::handle_wait_yield_syscall(frame);
        }
        // M6 capability-controlled services: numbers reserved in clean_slate_capability.
        cap_abi::SYSCALL_NR_CAP_OBJECT => crate::capability::object::handle_syscall(frame),
        cap_abi::SYSCALL_NR_CAP_PROCESS_CONTROL => {
            crate::capability::process_control::handle_syscall(frame)
        }
        cap_abi::SYSCALL_NR_CAP_DELEGATE => crate::capability::delegation::handle_syscall(frame),
        cap_abi::SYSCALL_NR_CAP_REVOKE => crate::capability::revocation::handle_syscall(frame),
        cap_abi::SYSCALL_NR_CAP_AUDIT_READ => crate::capability::audit::handle_syscall(frame),
        cap_abi::SYSCALL_NR_CAP_GRANT => crate::capability::bootstrap_grant::handle_syscall(frame),
        cap_abi::SYSCALL_NR_NETWORK_CAPABILITY => {
            crate::service::net_syscall::handle_syscall_network_capability(frame)
        }
        cap_abi::SYSCALL_NR_NETWORK_REQUEST => {
            crate::service::net_syscall::handle_syscall_network_request(frame)
        }
        _ => frame.rax = SYSCALL_ENOSYS,
    }
}

pub(crate) fn current_syscall_caller_pid() -> Result<u64, &'static str> {
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
    if active_root == 0 {
        return Err("syscall caller active address space root was invalid");
    }
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

    #[test]
    fn dispatch_native_unknown_nr_returns_native_enosys_sentinel() {
        let mut frame = SyscallContext {
            rax: 999,
            rdx: 0,
            rbx: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            user_rip: 0,
            user_rflags: 0,
            user_rsp: 0,
        };
        dispatch_native(&mut frame);
        assert_eq!(frame.rax, SYSCALL_ENOSYS);
        // Native sentinel is not produced via Linux encode_rax in this path.
        assert_eq!(SYSCALL_ENOSYS, u64::MAX - 37);
    }

    #[test]
    fn route_syscall_trusted_native_selects_native() {
        let route = route_syscall(Ok(ResolvedSyscallCaller {
            pid: 4,
            personality: ExecutionPersonality::Native,
        }));
        assert!(matches!(route, SyscallRoute::Native { pid: 4 }));
    }

    #[test]
    fn route_syscall_trusted_linux_selects_linux() {
        let route = route_syscall(Ok(ResolvedSyscallCaller {
            pid: 5,
            personality: ExecutionPersonality::LinuxX86_64,
        }));
        assert!(matches!(
            route,
            SyscallRoute::LinuxRejectMissingGeneration { pid: 5 }
        ));
    }

    #[test]
    fn route_syscall_unresolved_fails_closed() {
        let route = route_syscall(Err(
            "syscall caller process did not match active address space",
        ));
        assert!(matches!(
            route,
            SyscallRoute::FailClosed {
                reason: "syscall caller process did not match active address space"
            }
        ));
    }

    #[test]
    fn overlapping_nr_one_unresolved_never_selects_native_route() {
        let route = route_syscall(Err(
            "active address space did not map to a registered process",
        ));
        assert!(matches!(route, SyscallRoute::FailClosed { .. }));
        assert!(!matches!(route, SyscallRoute::Native { .. }));
    }

    #[test]
    fn dispatch_native_version_returns_abi_version() {
        let mut frame = SyscallContext {
            rax: SYSCALL_NR_VERSION,
            rdx: 0,
            rbx: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            user_rip: 0,
            user_rflags: 0,
            user_rsp: 0,
        };
        dispatch_native(&mut frame);
        assert_eq!(frame.rax, SYSCALL_ABI_VERSION);
    }
}
