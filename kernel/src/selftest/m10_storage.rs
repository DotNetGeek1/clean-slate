//! #312 storage lane: the storage service, and one native app (the storage probe,
//! `clean-slate-storage-probe-userspace`) holding a directory capability and nothing else.
//!
//! Each boot the probe moves its file one stage along (`ProbeStage`): on a blank disk it
//! creates `big.bin` and writes 1 MiB into it through a shared buffer in offset writes, then
//! commits; the next boot on the same disk reads it back by name through the buffer, checks
//! every byte and truncates it to 4 KiB; the third reads the 4 KiB back and unlinks it.
//! The probe reports each step and its stage through lane checks, and the kernel ends the
//! boot at the stage report; xtask runs the three boots and checks the stages in order.

use crate::arch::x86_64::context_switch::{restore_task_context, task_stack_top};
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::qemu::{fatal_kernel_error, qemu_exit, QEMU_EXIT_SUCCESS};
use crate::interrupt::timer::initialize_timer;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
use crate::process::id_allocator::{id_allocator_mut, IdAllocator};
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::{scheduler_mut, task_stacks_mut, Scheduler};
use crate::selftest::m6_fixture::{
    register_fixture_pid, set_lane_check_handler, FIXTURE_SUBOP_LANE_CHECK,
};
use crate::service::control::ServiceLifecycleController;
use crate::service::service_lifecycle_controller_mut;
use crate::service::spawn::launch_storage_probe;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use clean_slate_native_abi::status::STATUS_EINVAL;
use clean_slate_service_fixtures::storage_probe::{
    ProbeFailure, ProbeStage, ProbeStep, STORAGE_PROBE_CHECK_FAILED,
    STORAGE_PROBE_CHECK_STAGE_DONE, STORAGE_PROBE_CHECK_STEP, STORAGE_PROBE_DIRECTORY_ID,
    STORAGE_PROBE_SUBOP_LANE_CHECK,
};
use clean_slate_service_fixtures::STORAGE_SERVICE_ID;
use clean_slate_service_lifecycle::{ControlRequest, ControlRequestKind, LifecycleMessage};
use core::sync::atomic::{AtomicU64, Ordering};

const _: () = assert!(STORAGE_PROBE_SUBOP_LANE_CHECK == FIXTURE_SUBOP_LANE_CHECK);

const SUPERVISOR_TEST_PID: u64 = 60;
/// The storage service takes slot 0.
const PROBE_SLOT: usize = 1;

static PROBE_PID: AtomicU64 = AtomicU64::new(0);

fn lane_check(pid: u64, check: u64, arg: u64) -> u64 {
    if pid == 0 || pid != PROBE_PID.load(Ordering::Relaxed) {
        return STATUS_EINVAL;
    }
    match check {
        STORAGE_PROBE_CHECK_STEP => {
            let name = ProbeStep::from_code(arg).map_or("?", ProbeStep::name);
            kernel_log_fmt(format_args!("[M10.storage] step {name}\n"));
            0
        }
        STORAGE_PROBE_CHECK_STAGE_DONE => {
            let Some(stage) = ProbeStage::from_code(arg) else {
                return STATUS_EINVAL;
            };
            kernel_log_fmt(format_args!(
                "[M10.storage] stage {} pid={pid}\n[M10.storage] boot PASS\n",
                stage.name()
            ));
            qemu_exit(QEMU_EXIT_SUCCESS)
        }
        STORAGE_PROBE_CHECK_FAILED => {
            match ProbeFailure::decode(arg) {
                Some(failure) => match failure.status_below_max() {
                    Some(below) => kernel_log_fmt(format_args!(
                        "[M10.storage] FAIL step={} status=u64::MAX-{below}\n",
                        failure.step.name()
                    )),
                    None => kernel_log_fmt(format_args!(
                        "[M10.storage] FAIL step={} detail={:#x}\n",
                        failure.step.name(),
                        failure.detail
                    )),
                },
                None => kernel_log_fmt(format_args!("[M10.storage] FAIL raw={arg:#x}\n")),
            }
            fatal_kernel_error("[M10.storage] probe failed")
        }
        _ => STATUS_EINVAL,
    }
}

fn launch_storage_service(
    controller: &mut ServiceLifecycleController,
    allocator: &mut PageAllocator,
    lifecycle_capability: u64,
) {
    let result = controller
        .handle_control_message(
            allocator,
            SUPERVISOR_TEST_PID,
            lifecycle_capability,
            &LifecycleMessage::ControlRequest(ControlRequest::new(
                STORAGE_SERVICE_ID,
                ControlRequestKind::Start,
            ))
            .encode(),
        )
        .unwrap_or_else(|_| fatal_kernel_error("[M10.storage] storage service launch failed"));
    let pid = result
        .event
        .map(|event| event.instance.pid.0)
        .unwrap_or_else(|| fatal_kernel_error("[M10.storage] storage service pid missing"));
    kernel_log_fmt(format_args!("[STOR] object-service started pid={pid}\n"));
}

pub(crate) fn start_m10_storage_self_test(page_allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    let kernel_root = current_root_frame_address();
    install_service_lifecycle_syscall_allocator(page_allocator);
    let lifecycle_capability = {
        let controller = unsafe { service_lifecycle_controller_mut() };
        controller.clear();
        controller.configure_launch_context(kernel_root);
        controller
            .declare_service(STORAGE_SERVICE_ID)
            .unwrap_or_else(|message| fatal_kernel_error(message));
        controller
            .grant_lifecycle_control_capability(SUPERVISOR_TEST_PID, &[STORAGE_SERVICE_ID])
            .unwrap_or_else(|message| fatal_kernel_error(message))
    };
    set_lane_check_handler(lane_check);
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("[M10.storage] allocator missing"));
    launch_storage_service(
        unsafe { service_lifecycle_controller_mut() },
        allocator,
        lifecycle_capability,
    );

    let stack_top = unsafe { task_stack_top(&(*task_stacks_mut())[PROBE_SLOT]) };
    let probe = launch_storage_probe(allocator, stack_top, PROBE_SLOT, STORAGE_PROBE_DIRECTORY_ID)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    register_fixture_pid(probe.pid).unwrap_or_else(|message| fatal_kernel_error(message));
    PROBE_PID.store(probe.pid, Ordering::Relaxed);
    kernel_log_fmt(format_args!(
        "[M10.storage] probe spawned pid={} directory={STORAGE_PROBE_DIRECTORY_ID:#x}\n",
        probe.pid
    ));

    initialize_timer();
    // `m3-entry-self-test` skips calibration inside `initialize_timer`; the storage
    // service's block completion waits use TSC `MonotonicNs` deadlines.
    crate::time::calibration::calibrate_apic_tick();
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}
