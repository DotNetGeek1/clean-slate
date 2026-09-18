//! M7.3 network service constituent self-test (CPL3 service + syscall path).

use crate::arch::x86_64::apic::reprogram_local_apic_timer;
use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::interrupt::timer::initialize_timer;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
use crate::process::domain::teardown_current_process;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::process_registry_mut;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::sched::dispatch::prepare_current_scheduler_thread_dispatch;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::scheduler_mut;
use crate::sched::ThreadState;
use crate::sched::task_stacks_mut;
use crate::sched::Scheduler;
use crate::service::control::ServiceLifecycleController;
use crate::service::service_lifecycle_controller_mut;
use crate::service::spawn::launch_network_aux_process;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use clean_slate_service_fixtures::{
    NetworkServiceBootstrap, NETWORK_SERVICE_BOOTSTRAP_ADDRESS, NETWORK_SERVICE_ID,
    NETWORK_SERVICE_MODE_ACCEPTANCE, NETWORK_SERVICE_MODE_CAPACITY_LOOP,
    NETWORK_SERVICE_MODE_CLIENT, NETWORK_SERVICE_MODE_INFLIGHT_ARM,
    NETWORK_SERVICE_MODE_STALE_CLOSE, NETWORK_SERVICE_MODE_UNAUTHORIZED_PROBE,
    NETWORK_SERVICE_RESULT_OK, NETWORK_UNAUTHORIZED_SERVICE_ID,
};
use clean_slate_service_lifecycle::{
    ControlRequest, ControlRequestKind, LifecycleMessage, ServiceId,
};

const PASS_MARKER: &str = "[M7.3] PASS";
const SUPERVISOR_TEST_PID: u64 = 70;

const CLIENT_ECHO_SLOT: usize = 1;
const UNAUTHORIZED_PROBE_SLOT: usize = 2;
const INFLIGHT_ARM_SLOT: usize = 3;
const STALE_CLOSE_SLOT: usize = 4;
const CAPACITY_LOOP_SLOT: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum M7Phase {
    AwaitClientEcho,
    AwaitUnauthorized,
    AwaitInflightArm,
    AwaitStaleClose,
    AwaitCapacityLoop,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PostTeardownLaunch {
    None,
    UnauthorizedProbe,
    InflightArm,
    StaleClose,
    CapacityLoop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct M7NetSelfTestState {
    lifecycle_capability: u64,
    phase: M7Phase,
    session_id_raw: u64,
    service_generation: u64,
}

static M7_NET_SELF_TEST_STATE: GlobalCell<Option<M7NetSelfTestState>> = GlobalCell::new(None);

fn set_state(state: Option<M7NetSelfTestState>) {
    unsafe {
        *M7_NET_SELF_TEST_STATE.get() = state;
    }
}

fn state() -> M7NetSelfTestState {
    unsafe {
        (*M7_NET_SELF_TEST_STATE.get()).expect("m7 net self-test state was not initialized")
    }
}

pub(crate) fn network_service_bootstrap(
    service: ServiceId,
) -> Result<NetworkServiceBootstrap, &'static str> {
    let test_state = state();
    match service {
        NETWORK_SERVICE_ID => Ok(NetworkServiceBootstrap::new(
            NETWORK_SERVICE_MODE_ACCEPTANCE,
            test_state.service_generation,
        )),
        NETWORK_UNAUTHORIZED_SERVICE_ID => Ok(NetworkServiceBootstrap::new(
            NETWORK_SERVICE_MODE_UNAUTHORIZED_PROBE,
            0,
        )),
        _ => Err("unexpected network bootstrap service"),
    }
}

pub(crate) fn start_m7_net_service_self_test(allocator: PageAllocator) -> ! {
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
    let lifecycle_capability = {
        let controller = unsafe { service_lifecycle_controller_mut() };
        controller.clear();
        controller.configure_launch_context(kernel_root, kernel_stack_top);
        controller
            .declare_service(NETWORK_SERVICE_ID)
            .unwrap_or_else(|message| fatal_kernel_error(message));
        controller
            .declare_service(NETWORK_UNAUTHORIZED_SERVICE_ID)
            .unwrap_or_else(|message| fatal_kernel_error(message));
        controller
            .grant_lifecycle_control_capability(SUPERVISOR_TEST_PID)
            .unwrap_or_else(|message| fatal_kernel_error(message))
    };
    set_state(Some(M7NetSelfTestState {
        lifecycle_capability,
        phase: M7Phase::AwaitClientEcho,
        session_id_raw: 0,
        service_generation: 1,
    }));
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m7 net allocator missing"));
    let controller = unsafe { service_lifecycle_controller_mut() };
    launch_network_service(controller, allocator, lifecycle_capability, NETWORK_SERVICE_ID);
    log_service_started(controller, 1);
    launch_client_echo(controller, allocator, CLIENT_ECHO_SLOT);
    initialize_timer();
    reprogram_local_apic_timer(50_000);
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}

fn log_service_started(controller: &ServiceLifecycleController, generation: u64) {
    let pid = controller.live_pid(NETWORK_SERVICE_ID).unwrap_or(0);
    kernel_log_fmt(format_args!(
        "[NET ] service started pid={pid} generation={generation}\n"
    ));
}

fn launch_network_service(
    controller: &mut ServiceLifecycleController,
    allocator: &mut PageAllocator,
    lifecycle_capability: u64,
    service: ServiceId,
) {
    let _ = controller
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
        .unwrap_or_else(|_| fatal_kernel_error("m7 network service launch failed"));
}

fn launch_client_echo(
    controller: &mut ServiceLifecycleController,
    allocator: &mut PageAllocator,
    slot: usize,
) {
    let test_state = state();
    let stack_top = unsafe { task_stack_top(&(*task_stacks_mut())[slot]) };
    let bootstrap =
        NetworkServiceBootstrap::new(NETWORK_SERVICE_MODE_CLIENT, test_state.service_generation);
    let spawned = launch_network_aux_process(allocator, stack_top, slot, bootstrap)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    controller
        .grant_network_client_capability(spawned.pid)
        .unwrap_or_else(|message| fatal_kernel_error(message));
}

fn launch_aux(
    controller: &mut ServiceLifecycleController,
    allocator: &mut PageAllocator,
    slot: usize,
    mode: u64,
    generation: u64,
    grant_client: bool,
) {
    let stack_top = unsafe { task_stack_top(&(*task_stacks_mut())[slot]) };
    let bootstrap = NetworkServiceBootstrap::new(mode, generation);
    let spawned = launch_network_aux_process(allocator, stack_top, slot, bootstrap)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    if grant_client {
        controller
            .grant_network_client_capability(spawned.pid)
            .unwrap_or_else(|message| fatal_kernel_error(message));
    }
}

fn launch_aux_with_bootstrap(
    controller: &mut ServiceLifecycleController,
    allocator: &mut PageAllocator,
    slot: usize,
    bootstrap: NetworkServiceBootstrap,
    grant_client: bool,
) {
    let stack_top = unsafe { task_stack_top(&(*task_stacks_mut())[slot]) };
    let spawned = launch_network_aux_process(allocator, stack_top, slot, bootstrap)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    if grant_client {
        controller
            .grant_network_client_capability(spawned.pid)
            .unwrap_or_else(|message| fatal_kernel_error(message));
    }
}

fn terminate_network_service(
    controller: &mut ServiceLifecycleController,
    allocator: &mut PageAllocator,
    lifecycle_capability: u64,
) {
    let _ = controller
        .handle_control_message(
            allocator,
            SUPERVISOR_TEST_PID,
            lifecycle_capability,
            &LifecycleMessage::ControlRequest(ControlRequest::new(
                NETWORK_SERVICE_ID,
                ControlRequestKind::Terminate,
            ))
            .encode(),
        )
        .unwrap_or_else(|_| fatal_kernel_error("m7 network service terminate failed"));
}

fn scheduler_slot_for_launch(post_launch: PostTeardownLaunch) -> usize {
    match post_launch {
        PostTeardownLaunch::UnauthorizedProbe => UNAUTHORIZED_PROBE_SLOT,
        PostTeardownLaunch::InflightArm => INFLIGHT_ARM_SLOT,
        PostTeardownLaunch::StaleClose => STALE_CLOSE_SLOT,
        PostTeardownLaunch::CapacityLoop => CAPACITY_LOOP_SLOT,
        PostTeardownLaunch::None => fatal_kernel_error("missing scheduler slot for post-teardown launch"),
    }
}

fn resume_scheduler_slot(slot: usize) -> u64 {
    let stack_pointer = without_interrupts(|| {
        let scheduler = unsafe { scheduler_mut() };
        if slot >= scheduler.threads.len() {
            return Err("m7 net self-test scheduler slot out of range");
        }
        scheduler.current_thread = Some(slot);
        scheduler.threads[slot].started = true;
        scheduler.threads[slot].state = ThreadState::Running;
        Ok(scheduler.threads[slot].saved_stack_pointer)
    })
    .unwrap_or_else(|message| fatal_kernel_error(message));
    prepare_current_scheduler_thread_dispatch()
        .unwrap_or_else(|message| fatal_kernel_error(message));
    stack_pointer
}

fn launch_post_teardown(
    post_launch: PostTeardownLaunch,
    controller: &mut ServiceLifecycleController,
    allocator: &mut PageAllocator,
) {
    let test_state = state();
    match post_launch {
        PostTeardownLaunch::None => {}
        PostTeardownLaunch::UnauthorizedProbe => {
            launch_aux(
                controller,
                allocator,
                UNAUTHORIZED_PROBE_SLOT,
                NETWORK_SERVICE_MODE_UNAUTHORIZED_PROBE,
                0,
                false,
            );
            kernel_log_line("[NET ] unauthorized probe launched");
        }
        PostTeardownLaunch::InflightArm => {
            let mut bootstrap = NetworkServiceBootstrap::new(
                NETWORK_SERVICE_MODE_INFLIGHT_ARM,
                test_state.service_generation,
            );
            bootstrap.session_id_raw = test_state.session_id_raw;
            launch_aux_with_bootstrap(
                controller,
                allocator,
                INFLIGHT_ARM_SLOT,
                bootstrap,
                true,
            );
        }
        PostTeardownLaunch::StaleClose => {
            let mut bootstrap =
                NetworkServiceBootstrap::new(NETWORK_SERVICE_MODE_STALE_CLOSE, 2);
            bootstrap.session_id_raw = test_state.session_id_raw;
            launch_aux_with_bootstrap(controller, allocator, STALE_CLOSE_SLOT, bootstrap, true);
        }
        PostTeardownLaunch::CapacityLoop => launch_aux(
            controller,
            allocator,
            CAPACITY_LOOP_SLOT,
            NETWORK_SERVICE_MODE_CAPACITY_LOOP,
            test_state.service_generation,
            true,
        ),
    }
}

pub(crate) fn handle_userspace_network_entry() -> u64 {
    let _pid = crate::process::current_process_id().unwrap_or_else(|message| fatal_kernel_error(message));
    let report = unsafe { &*(NETWORK_SERVICE_BOOTSTRAP_ADDRESS as *const NetworkServiceBootstrap) };
    let test_state = state();
    let mut session_id_raw = test_state.session_id_raw;
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m7 net allocator missing"));
    let controller = unsafe { service_lifecycle_controller_mut() };

    let (next_phase, post_launch) = match (test_state.phase, report.mode) {
        (M7Phase::AwaitClientEcho, NETWORK_SERVICE_MODE_CLIENT) => {
            if report.result_code != NETWORK_SERVICE_RESULT_OK {
                fatal_kernel_error("m7 client echo failed");
            }
            session_id_raw = report.session_id_raw;
            kernel_log_fmt(format_args!(
                "[NET ] session open id={}\n",
                report.session_id_raw
            ));
            kernel_log_fmt(format_args!("[NET ] echo ok len={}\n", report.echo_len));
            (
                M7Phase::AwaitUnauthorized,
                PostTeardownLaunch::UnauthorizedProbe,
            )
        }
        (M7Phase::AwaitUnauthorized, NETWORK_SERVICE_MODE_UNAUTHORIZED_PROBE) => {
            if report.result_code != NETWORK_SERVICE_RESULT_OK {
                fatal_kernel_error("m7 unauthorized probe failed");
            }
            (M7Phase::AwaitInflightArm, PostTeardownLaunch::InflightArm)
        }
        (M7Phase::AwaitInflightArm, NETWORK_SERVICE_MODE_INFLIGHT_ARM) => {
            if report.result_code != NETWORK_SERVICE_RESULT_OK {
                fatal_kernel_error("m7 inflight arm failed");
            }
            terminate_network_service(controller, allocator, test_state.lifecycle_capability);
            let mut test_state = test_state;
            test_state.service_generation = 2;
            set_state(Some(test_state));
            launch_network_service(
                controller,
                allocator,
                test_state.lifecycle_capability,
                NETWORK_SERVICE_ID,
            );
            kernel_log_fmt(format_args!(
                "[NET ] service restarted pid={} generation={}\n",
                controller.live_pid(NETWORK_SERVICE_ID).unwrap_or(0),
                test_state.service_generation
            ));
            (M7Phase::AwaitStaleClose, PostTeardownLaunch::StaleClose)
        }
        (M7Phase::AwaitStaleClose, NETWORK_SERVICE_MODE_STALE_CLOSE) => {
            if report.result_code != NETWORK_SERVICE_RESULT_OK {
                fatal_kernel_error("m7 stale close failed");
            }
            kernel_log_fmt(format_args!(
                "[NET ] stale-session denied generation={}\n",
                report.aux_status
            ));
            (M7Phase::AwaitCapacityLoop, PostTeardownLaunch::CapacityLoop)
        }
        (M7Phase::AwaitCapacityLoop, NETWORK_SERVICE_MODE_CAPACITY_LOOP) => {
            if report.result_code != NETWORK_SERVICE_RESULT_OK {
                fatal_kernel_error("m7 capacity loop failed");
            }
            kernel_log_line("[NET ] capacity baseline ok");
            (M7Phase::Complete, PostTeardownLaunch::None)
        }
        _ => fatal_kernel_error("unexpected m7 net userspace trap phase/mode"),
    };

    set_state(Some(M7NetSelfTestState {
        lifecycle_capability: test_state.lifecycle_capability,
        phase: next_phase,
        session_id_raw,
        service_generation: state().service_generation,
    }));

    let teardown = teardown_current_process(allocator, current_root_frame_address(), 0, false)
        .unwrap_or_else(|message| fatal_kernel_error(message));

    if post_launch != PostTeardownLaunch::None {
        launch_post_teardown(post_launch, controller, allocator);
        if next_phase == M7Phase::Complete {
            kernel_log_line(PASS_MARKER);
            qemu_exit(QEMU_EXIT_SUCCESS);
        }
        return resume_scheduler_slot(scheduler_slot_for_launch(post_launch));
    }

    if next_phase == M7Phase::Complete {
        kernel_log_line(PASS_MARKER);
        qemu_exit(QEMU_EXIT_SUCCESS);
    }

    teardown
        .next_stack_pointer
        .unwrap_or_else(|| fatal_kernel_error("m7 net self-test teardown found no runnable thread"))
}
