//! #353 native network client lane: the network service against the M7 fixture peer, and one
//! native app (the network probe, `clean-slate-net-probe-userspace`) whose row's only grant is
//! `Grant::NativeNetworkClient`.
//!
//! Both rows come from `NET_PROBE_MANIFEST` and are started through the lifecycle controller,
//! so the probe gets its client capability and its policy domain the way any native row does.
//! The probe resolves the fixture name, fetches the fixture's page over a TCP stream and over
//! TLS, makes a UDP round trip, then connects to a destination its policy does not name. That
//! connect must be refused; the kernel then checks that the refusal is in the audit log, naming
//! the probe and the destination. The probe reports each step through lane checks, and the
//! kernel ends the boot at its last report.
//!
//! With `m10-net-listen-self-test` (#359, `cargo xtask test-m10-net-listen`) the kernel answers
//! the probe's mode check with the listen mode: the probe listens on its policy's port, is
//! refused another port (the kernel checks that audit record too), and echoes the connection
//! the host makes in through QEMU's `hostfwd`. That kernel runs on QEMU's user network, with
//! the static address the lane builds it with, not on the fixture network.

use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::capability::audit::with_audit_log;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::qemu::{fatal_kernel_error, qemu_exit, QEMU_EXIT_SUCCESS};
use crate::interrupt::timer::initialize_timer;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
use crate::process::current_process_id;
use crate::process::id_allocator::{id_allocator_mut, IdAllocator};
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::{scheduler_mut, Scheduler};
use crate::service::control::ServiceLifecycleController;
use crate::service::service_lifecycle_controller_mut;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use clean_slate_capability::{HolderId, NetDestination, NetTransport};
use clean_slate_native_abi::status::STATUS_EINVAL;
use clean_slate_service_fixtures::net_probe::{
    NetProbeFailure, NetProbeStep, NET_PROBE_CHECK_DONE, NET_PROBE_CHECK_FAILED,
    NET_PROBE_CHECK_LISTENING, NET_PROBE_CHECK_LISTEN_REFUSED, NET_PROBE_CHECK_MODE,
    NET_PROBE_CHECK_REFUSED, NET_PROBE_CHECK_STEP, NET_PROBE_DENIED, NET_PROBE_LISTEN_DENIED_PORT,
    NET_PROBE_MANIFEST, NET_PROBE_MODE_LISTEN, NET_PROBE_SERVICE_ID, NET_PROBE_SUBOP_LANE_CHECK,
    NET_PROBE_WRONG_ANSWER,
};
use clean_slate_service_fixtures::NETWORK_SERVICE_ID;
use clean_slate_service_lifecycle::{
    ControlRequest, ControlRequestKind, LifecycleMessage, ServiceId,
};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const SUPERVISOR_TEST_PID: u64 = 61;

static PROBE_PID: AtomicU64 = AtomicU64::new(0);
static REFUSAL_AUDITED: AtomicBool = AtomicBool::new(false);

/// Serves the probe's lane check (`SYSCALL_NR_CAP_GRANT` sub-operation
/// [`NET_PROBE_SUBOP_LANE_CHECK`]); `false` for any other sub-operation.
pub(crate) fn handle_harness_subop(frame: &mut SyscallContext) -> bool {
    if frame.rdi != NET_PROBE_SUBOP_LANE_CHECK {
        return false;
    }
    let pid = current_process_id().unwrap_or(0);
    frame.rax = lane_check(pid, frame.rsi, frame.rdx);
    true
}

fn lane_check(pid: u64, check: u64, arg: u64) -> u64 {
    if pid == 0 || pid != PROBE_PID.load(Ordering::Relaxed) {
        return STATUS_EINVAL;
    }
    match check {
        NET_PROBE_CHECK_MODE => {
            if cfg!(feature = "m10-net-listen-self-test") {
                kernel_log_fmt(format_args!("[M10.net] mode listen\n"));
                NET_PROBE_MODE_LISTEN
            } else {
                0
            }
        }
        NET_PROBE_CHECK_LISTEN_REFUSED => {
            let port = NET_PROBE_LISTEN_DENIED_PORT;
            let denied = NetDestination {
                transport: NetTransport::TcpListen,
                addr: [0; 4],
                port,
            };
            if arg != u64::from(port) || !refusal_is_audited(pid, denied) {
                fatal_kernel_error("[M10.net] the refused listen has no audit record");
            }
            REFUSAL_AUDITED.store(true, Ordering::Relaxed);
            kernel_log_fmt(format_args!(
                "[M10.net] listen refusal audited actor={pid} dest=0.0.0.0:{port}/tcp-listen\n"
            ));
            0
        }
        NET_PROBE_CHECK_LISTENING => {
            kernel_log_fmt(format_args!("[M10.net] listening port={arg}\n"));
            0
        }
        NET_PROBE_CHECK_STEP => {
            let name = NetProbeStep::from_code(arg).map_or("?", NetProbeStep::name);
            kernel_log_fmt(format_args!("[M10.net] step {name}\n"));
            0
        }
        NET_PROBE_CHECK_REFUSED => {
            let (ip, port) = NET_PROBE_DENIED;
            let denied = NetDestination {
                transport: NetTransport::Tcp,
                addr: ip,
                port,
            };
            if !refusal_is_audited(pid, denied) {
                fatal_kernel_error("[M10.net] the refused connect has no audit record");
            }
            REFUSAL_AUDITED.store(true, Ordering::Relaxed);
            let (ip, port) = NET_PROBE_DENIED;
            kernel_log_fmt(format_args!(
                "[M10.net] refusal audited actor={pid} dest={}.{}.{}.{}:{port}/tcp\n",
                ip[0], ip[1], ip[2], ip[3]
            ));
            0
        }
        NET_PROBE_CHECK_DONE => {
            if !REFUSAL_AUDITED.load(Ordering::Relaxed) {
                fatal_kernel_error("[M10.net] probe finished without the refusal check");
            }
            kernel_log_fmt(format_args!("[M10.net] PASS pid={pid}\n"));
            qemu_exit(QEMU_EXIT_SUCCESS)
        }
        NET_PROBE_CHECK_FAILED => {
            match NetProbeFailure::decode(arg) {
                Some(failure) if failure.status == NET_PROBE_WRONG_ANSWER => kernel_log_fmt(
                    format_args!("[M10.net] FAIL step={} wrong answer\n", failure.step.name()),
                ),
                Some(failure) => kernel_log_fmt(format_args!(
                    "[M10.net] FAIL step={} status=u64::MAX-{}\n",
                    failure.step.name(),
                    u64::MAX - failure.status
                )),
                None => kernel_log_fmt(format_args!("[M10.net] FAIL raw={arg:#x}\n")),
            }
            fatal_kernel_error("[M10.net] probe failed")
        }
        _ => STATUS_EINVAL,
    }
}

/// Whether the audit log holds a refused-destination record with the probe as actor and the
/// denied destination.
fn refusal_is_audited(pid: u64, denied: NetDestination) -> bool {
    with_audit_log(|log| {
        let (Some(oldest), Some(newest)) = (log.oldest_sequence(), log.newest_sequence()) else {
            return false;
        };
        (oldest..=newest)
            .filter_map(|sequence| log.get(sequence))
            .any(|event| {
                event.actor == HolderId(pid) && NetDestination::of_refusal(&event) == Some(denied)
            })
    })
}

fn start_service(
    controller: &mut ServiceLifecycleController,
    allocator: &mut PageAllocator,
    lifecycle_capability: u64,
    service: ServiceId,
) -> u64 {
    let result = controller
        .handle_control_message(
            allocator,
            SUPERVISOR_TEST_PID,
            lifecycle_capability,
            &LifecycleMessage::ControlRequest(ControlRequest::new(
                service,
                ControlRequestKind::Start,
            ))
            .encode(),
        )
        .unwrap_or_else(|_| fatal_kernel_error("[M10.net] service launch failed"));
    result
        .event
        .map(|event| event.instance.pid.0)
        .unwrap_or_else(|| fatal_kernel_error("[M10.net] service pid missing"))
}

pub(crate) fn start_m10_net_self_test(page_allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    let kernel_root = current_root_frame_address();
    install_service_lifecycle_syscall_allocator(page_allocator);
    let services = [NETWORK_SERVICE_ID, NET_PROBE_SERVICE_ID];
    let lifecycle_capability = {
        let controller = unsafe { service_lifecycle_controller_mut() };
        controller.clear();
        controller.use_scenario_manifest(NET_PROBE_MANIFEST);
        controller.configure_launch_context(kernel_root);
        for service in services {
            controller
                .declare_service(service)
                .unwrap_or_else(|message| fatal_kernel_error(message));
        }
        controller
            .grant_lifecycle_control_capability(SUPERVISOR_TEST_PID, &services)
            .unwrap_or_else(|message| fatal_kernel_error(message))
    };
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("[M10.net] allocator missing"));
    let controller = unsafe { service_lifecycle_controller_mut() };
    // The network instance is live before the probe launches, so the probe's grant issues
    // its client capability at once; its requests wait in the bridge until the service runs.
    let network = start_service(
        controller,
        allocator,
        lifecycle_capability,
        NETWORK_SERVICE_ID,
    );
    kernel_log_fmt(format_args!("[M10.net] network service pid={network}\n"));
    let probe = start_service(
        controller,
        allocator,
        lifecycle_capability,
        NET_PROBE_SERVICE_ID,
    );
    PROBE_PID.store(probe, Ordering::Relaxed);
    kernel_log_fmt(format_args!("[M10.net] probe started pid={probe}\n"));

    initialize_timer();
    // `m3-entry-self-test` skips calibration inside `initialize_timer`; the network service's
    // waits and the probe's deadlines are TSC `MonotonicNs` times.
    crate::time::calibration::calibrate_apic_tick();
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}
