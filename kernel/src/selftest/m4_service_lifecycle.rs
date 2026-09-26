//! M4.2 service lifecycle control acceptance: capability-gated launch, terminate,
//! and restart with fresh instance identity markers.

#[cfg(feature = "m4-service-lifecycle-self-test")]
use crate::diagnostics::log::kernel_log_line;
#[cfg(feature = "m4-service-lifecycle-self-test")]
use crate::diagnostics::qemu::fatal_kernel_error;
#[cfg(feature = "m4-service-lifecycle-self-test")]
use crate::diagnostics::qemu::qemu_exit;
#[cfg(feature = "m4-service-lifecycle-self-test")]
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
#[cfg(feature = "m4-service-lifecycle-self-test")]
use crate::mm::frame_allocator::PageAllocator;
#[cfg(feature = "m4-service-lifecycle-self-test")]
use crate::mm::paging::current_root_frame_address;
#[cfg(feature = "m4-service-lifecycle-self-test")]
use crate::process::id_allocator::id_allocator_mut;
#[cfg(feature = "m4-service-lifecycle-self-test")]
use crate::process::id_allocator::IdAllocator;
#[cfg(feature = "m4-service-lifecycle-self-test")]
use crate::process::process_registry_mut;
#[cfg(feature = "m4-service-lifecycle-self-test")]
use crate::sched::scheduler_mut;
#[cfg(feature = "m4-service-lifecycle-self-test")]
use crate::sched::Scheduler;
#[cfg(feature = "m4-service-lifecycle-self-test")]
use crate::service::service_lifecycle_controller_mut;
#[cfg(feature = "m4-service-lifecycle-self-test")]
use crate::service::LifecycleControlError;
#[cfg(feature = "m4-service-lifecycle-self-test")]
use crate::syscall::install_service_lifecycle_syscall_allocator;
#[cfg(feature = "m4-service-lifecycle-self-test")]
use clean_slate_service_lifecycle::ControlRequest;
#[cfg(feature = "m4-service-lifecycle-self-test")]
use clean_slate_service_lifecycle::ControlRequestKind;
#[cfg(feature = "m4-service-lifecycle-self-test")]
use clean_slate_service_lifecycle::LifecycleMessage;
#[cfg(feature = "m4-service-lifecycle-self-test")]
use clean_slate_service_lifecycle::ServiceId;

#[cfg(feature = "m4-service-lifecycle-self-test")]
pub(super) const SERVICE_LIFECYCLE_PASS_MARKER: &str = "[M4.2] PASS";

#[cfg(feature = "m4-service-lifecycle-self-test")]
pub(super) const SERVICE_LIFECYCLE_UNAUTHORIZED_MARKER: &str = "[M4.2] unauthorized denied";

#[cfg(feature = "m4-service-lifecycle-self-test")]
const SUPERVISOR_TEST_PID: u64 = 50;

#[cfg(feature = "m4-service-lifecycle-self-test")]
pub(crate) fn start_service_lifecycle_self_test(allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    let kernel_root_frame = current_root_frame_address();
    install_service_lifecycle_syscall_allocator(allocator);
    let controller = unsafe { service_lifecycle_controller_mut() };
    controller.clear();
    controller.configure_launch_context(kernel_root_frame);
    controller
        .declare_service(ServiceId(2))
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let lifecycle_capability = controller
        .grant_lifecycle_control_capability(SUPERVISOR_TEST_PID)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let allocator = match crate::syscall::service_lifecycle_syscall_allocator_mut().as_mut() {
        Some(allocator) => allocator,
        None => fatal_kernel_error("service lifecycle self-test allocator was missing"),
    };
    let controller = unsafe { service_lifecycle_controller_mut() };
    let first = controller
        .handle_control_request(
            allocator,
            SUPERVISOR_TEST_PID,
            ControlRequest::new(ServiceId(2), ControlRequestKind::Start),
        )
        .unwrap_or_else(|_| fatal_kernel_error("service lifecycle launch failed"));
    let first_event = first
        .event
        .unwrap_or_else(|| fatal_kernel_error("first launch event missing"));
    controller
        .handle_control_request(
            allocator,
            SUPERVISOR_TEST_PID,
            ControlRequest::new(ServiceId(2), ControlRequestKind::Terminate),
        )
        .unwrap_or_else(|_| fatal_kernel_error("service lifecycle terminate failed"));
    let restarted = controller
        .handle_control_request(
            allocator,
            SUPERVISOR_TEST_PID,
            ControlRequest::new(ServiceId(2), ControlRequestKind::Restart),
        )
        .unwrap_or_else(|_| fatal_kernel_error("service lifecycle restart failed"));
    if restarted.event.is_some() {
        fatal_kernel_error("restart control unexpectedly returned an immediate lifecycle event");
    }
    let replacement = controller
        .handle_control_request(
            allocator,
            SUPERVISOR_TEST_PID,
            ControlRequest::new(ServiceId(2), ControlRequestKind::Start),
        )
        .unwrap_or_else(|_| fatal_kernel_error("service lifecycle restart start failed"));
    let replacement_event = replacement
        .event
        .unwrap_or_else(|| fatal_kernel_error("restart start did not return spawn event"));
    if first_event.instance.pid == replacement_event.instance.pid {
        fatal_kernel_error("service restart reused the previous pid");
    }
    if replacement_event.instance.generation.0 <= first_event.instance.generation.0 {
        fatal_kernel_error("service restart did not advance instance generation");
    }
    if controller
        .validate_instance_handle(first_event.instance)
        .is_ok()
    {
        fatal_kernel_error("stale pre-restart instance handle remained valid");
    }
    match controller.handle_control_message(
        allocator,
        SUPERVISOR_TEST_PID + 1,
        lifecycle_capability,
        &LifecycleMessage::ControlRequest(ControlRequest::new(
            ServiceId(1),
            ControlRequestKind::Terminate,
        ))
        .encode(),
    ) {
        Err(LifecycleControlError::Unauthorized) => {}
        _ => fatal_kernel_error("unauthorized lifecycle control was accepted"),
    }
    kernel_log_line(SERVICE_LIFECYCLE_UNAUTHORIZED_MARKER);
    kernel_log_line(SERVICE_LIFECYCLE_PASS_MARKER);
    qemu_exit(QEMU_EXIT_SUCCESS)
}
