#![cfg_attr(
    not(any(
        feature = "m4-service-lifecycle-self-test",
        feature = "m4-recovery-self-test"
    )),
    allow(dead_code)
)]

pub(crate) mod block_bridge;
pub(crate) mod capability;
pub(crate) mod control;
pub(crate) mod instance_generation;
#[cfg(feature = "m8-linux-image")]
pub(crate) mod linux_launch;
pub(crate) mod net_bridge;
pub(crate) mod net_request_wake;
pub(crate) mod net_syscall;
pub(crate) mod spawn;

#[cfg(feature = "m4-recovery-self-test")]
pub(crate) mod recovery_launch;

pub(crate) use control::service_lifecycle_controller_mut;
pub(crate) use control::LifecycleControlError;

/// Notify the service layer that a supervised process exited through production
/// teardown. Dispatches restart policy by service id; the Linux `exit` syscall
/// must not name a concrete service.
#[cfg(feature = "m8-linux-hello")]
pub(crate) fn on_supervised_process_exited(
    allocator: &mut crate::mm::frame_allocator::PageAllocator,
    pid: u64,
    status: u64,
) {
    let controller = unsafe { service_lifecycle_controller_mut() };
    let Some(service_id) = controller.live_service_id_for_pid(pid) else {
        return;
    };
    if service_id == linux_launch::LINUX_HELLO_SERVICE_ID {
        linux_launch::on_linux_hello_process_exited(allocator, pid, status);
    }
}
