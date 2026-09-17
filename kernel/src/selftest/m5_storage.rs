//! M5.3 integration self-test: launch storage + unrelated userspace processes
//! through lifecycle control and validate authorized block access plus explicit
//! unauthorized denial.

use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::mm::address_space::kernel_root_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
use crate::process::domain::teardown_current_process;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::scheduler_mut;
use crate::sched::task_stacks_mut;
use crate::sched::Scheduler;
use crate::service::service_lifecycle_controller_mut;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use clean_slate_service_fixtures::{STORAGE_SERVICE_ID, STORAGE_UNAUTHORIZED_SERVICE_ID};
use clean_slate_service_lifecycle::{
    ControlRequest, ControlRequestKind, LifecycleMessage, ServiceId,
};

const SUPERVISOR_TEST_PID: u64 = 50;
pub(crate) const M5_STORAGE_UNAUTHORIZED_DENIED_MARKER: &str = "[BLK ] unauthorized denied pid=";
pub(crate) const M5_STORAGE_PASS_MARKER: &str = "[M5.7] PASS";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct M5StorageSelfTestState {
    authorized_pid: u64,
    unauthorized_pid: u64,
    authorized_done: bool,
    unauthorized_done: bool,
}

static M5_STORAGE_SELF_TEST_STATE: GlobalCell<Option<M5StorageSelfTestState>> =
    GlobalCell::new(None);

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
    controller
        .declare_service(STORAGE_UNAUTHORIZED_SERVICE_ID)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let capability = controller
        .grant_lifecycle_control_capability(SUPERVISOR_TEST_PID)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("storage self-test allocator was missing"));
    let controller = unsafe { service_lifecycle_controller_mut() };
    start_service(controller, allocator, capability, STORAGE_SERVICE_ID);
    start_service(
        controller,
        allocator,
        capability,
        STORAGE_UNAUTHORIZED_SERVICE_ID,
    );
    let authorized_pid = controller
        .live_pid(STORAGE_SERVICE_ID)
        .unwrap_or_else(|| fatal_kernel_error("storage service did not become live"));
    let unauthorized_pid = controller
        .live_pid(STORAGE_UNAUTHORIZED_SERVICE_ID)
        .unwrap_or_else(|| fatal_kernel_error("unauthorized probe service did not become live"));
    kernel_log_fmt(format_args!(
        "[STOR] service started pid={authorized_pid}\n"
    ));
    unsafe {
        *M5_STORAGE_SELF_TEST_STATE.get() = Some(M5StorageSelfTestState {
            authorized_pid,
            unauthorized_pid,
            authorized_done: false,
            unauthorized_done: false,
        });
    }
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}

fn start_service(
    controller: &mut crate::service::control::ServiceLifecycleController,
    allocator: &mut PageAllocator,
    capability: u64,
    service: ServiceId,
) {
    controller
        .handle_control_message(
            allocator,
            SUPERVISOR_TEST_PID,
            capability,
            &LifecycleMessage::ControlRequest(ControlRequest::new(
                service,
                ControlRequestKind::Start,
            ))
            .encode(),
        )
        .unwrap_or_else(|_| fatal_kernel_error("storage self-test service launch failed"));
}

fn current_userspace_pid() -> Result<u64, &'static str> {
    without_interrupts(|| unsafe { scheduler_mut().current_userspace_process_id() })
}

pub(crate) fn handle_userspace_storage_entry() -> u64 {
    let pid = current_userspace_pid().unwrap_or_else(|message| fatal_kernel_error(message));
    let state = unsafe {
        (&mut *M5_STORAGE_SELF_TEST_STATE.get())
            .as_mut()
            .unwrap_or_else(|| fatal_kernel_error("m5 storage self-test state was not initialized"))
    };
    if pid == state.authorized_pid {
        state.authorized_done = true;
    } else if pid == state.unauthorized_pid {
        state.unauthorized_done = true;
        kernel_log_fmt(format_args!(
            "{M5_STORAGE_UNAUTHORIZED_DENIED_MARKER}{pid}\n"
        ));
    } else {
        fatal_kernel_error("unexpected process reached m5 storage entry trap");
    }
    let complete = state.authorized_done && state.unauthorized_done;
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("service lifecycle allocator was unavailable"));
    let teardown = teardown_current_process(allocator, kernel_root_frame(), 0, false)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    if complete {
        unsafe {
            *M5_STORAGE_SELF_TEST_STATE.get() = None;
        }
        kernel_log_line(M5_STORAGE_PASS_MARKER);
        qemu_exit(QEMU_EXIT_SUCCESS)
    }
    teardown
        .next_stack_pointer
        .unwrap_or_else(|| fatal_kernel_error("no runnable thread remained during m5 self-test"))
}
