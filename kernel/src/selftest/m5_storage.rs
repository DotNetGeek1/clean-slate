//! M5.3 integration self-test: launch storage service through lifecycle control
//! and validate one CPL3 block request/completion round trip.

use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::scheduler_mut;
use crate::sched::task_stacks_mut;
use crate::sched::Scheduler;
use crate::service::service_lifecycle_controller_mut;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use clean_slate_service_fixtures::STORAGE_SERVICE_ID;
use clean_slate_service_lifecycle::{ControlRequest, ControlRequestKind};

const SUPERVISOR_TEST_PID: u64 = 50;

pub(crate) const M5_STORAGE_PASS_MARKER: &str = "[M5.3] PASS";

pub(crate) fn start_m5_storage_self_test(allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    let kernel_root = current_root_frame_address();
    let kernel_stack_top = unsafe {
        let stacks = &*task_stacks_mut();
        task_stack_top(&stacks[0])
    };
    install_service_lifecycle_syscall_allocator(allocator);
    let controller = unsafe { service_lifecycle_controller_mut() };
    controller.clear();
    controller.configure_launch_context(kernel_root, kernel_stack_top);
    controller
        .declare_service(STORAGE_SERVICE_ID)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let capability = controller
        .grant_lifecycle_control_capability(SUPERVISOR_TEST_PID)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let allocator = crate::syscall::service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("storage self-test allocator was missing"));
    let controller = unsafe { service_lifecycle_controller_mut() };
    controller
        .handle_control_message(
            allocator,
            SUPERVISOR_TEST_PID,
            capability,
            &clean_slate_service_lifecycle::LifecycleMessage::ControlRequest(ControlRequest::new(
                STORAGE_SERVICE_ID,
                ControlRequestKind::Start,
            ))
            .encode(),
        )
        .unwrap_or_else(|_| fatal_kernel_error("storage service launch failed"));
    if let Some(pid) = controller.live_pid(STORAGE_SERVICE_ID) {
        kernel_log_fmt(format_args!("[STOR] service started pid={pid}\n"));
    } else {
        fatal_kernel_error("storage service did not become live");
    }
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}

pub(crate) fn handle_userspace_storage_entry() -> u64 {
    kernel_log_line(M5_STORAGE_PASS_MARKER);
    qemu_exit(QEMU_EXIT_SUCCESS)
}
