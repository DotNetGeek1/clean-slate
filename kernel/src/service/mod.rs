#![cfg_attr(
    not(any(
        feature = "m4-service-lifecycle-self-test",
        feature = "m4-recovery-self-test"
    )),
    allow(dead_code)
)]

pub(crate) mod block_bridge;
pub(crate) mod capability;
#[cfg(clean_slate_system_init)]
pub(crate) mod console_device;
#[cfg(clean_slate_system_init)]
pub(crate) mod console_stream;
pub(crate) mod control;
#[cfg(clean_slate_desktop)]
pub(crate) mod desktop_image;
pub(crate) mod display_syscall;
pub(crate) mod grants;
pub(crate) mod input_syscall;
pub(crate) mod instance_generation;
pub(crate) mod lifecycle_wait;
#[cfg(feature = "m8-linux-image")]
pub(crate) mod linux_launch;
pub(crate) mod net_bridge;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
pub(crate) mod net_launch;
pub(crate) mod net_request_wake;
pub(crate) mod net_syscall;
pub(crate) mod port;
pub(crate) mod port_syscall;
pub(crate) mod service_ready;
pub(crate) mod spawn;
pub(crate) mod storage_refusal;
pub(crate) mod system_init;
#[cfg(clean_slate_system_init)]
pub(crate) mod system_shell;
#[cfg(feature = "system-test-hooks")]
pub(crate) mod system_test_hooks;

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
