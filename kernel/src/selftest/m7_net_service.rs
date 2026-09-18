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
use crate::mm::address_space::activate_address_space_root;
use crate::mm::address_space::kernel_root_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::process::domain::teardown_current_process;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::process_registry_mut;
use crate::process::userspace_process_root_frame;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::scheduler_mut;
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

const CLIENT_SLOT: usize = 1;
const UNAUTHORIZED_SLOT: usize = 2;
const INFLIGHT_SLOT: usize = 3;
const STALE_SLOT: usize = 4;
const CAPACITY_SLOT: usize = 5;

/// `aux_status == 1` releases a pre-spawned fixture from its idle loop (M6-style RR).
const FIXTURE_PHASE_RELEASED: u64 = 1;

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
struct M7FixturePids {
    client: u64,
    unauthorized: u64,
    inflight: u64,
    stale: u64,
    capacity: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct M7NetSelfTestState {
    lifecycle_capability: u64,
    phase: M7Phase,
    session_id_raw: u64,
    service_generation: u64,
    fixtures: M7FixturePids,
}

static M7_NET_SELF_TEST_STATE: GlobalCell<Option<M7NetSelfTestState>> = GlobalCell::new(None);

fn set_state(state: Option<M7NetSelfTestState>) {
    unsafe {
        *M7_NET_SELF_TEST_STATE.get() = state;
    }
}

fn state() -> M7NetSelfTestState {
    unsafe { (*M7_NET_SELF_TEST_STATE.get()).expect("m7 net self-test state was not initialized") }
}

fn patch_fixture_bootstrap(
    pid: u64,
    kernel_root: u64,
    patch: impl FnOnce(&mut NetworkServiceBootstrap),
) {
    let root =
        userspace_process_root_frame(pid).unwrap_or_else(|message| fatal_kernel_error(message));
    activate_address_space_root(root);
    unsafe {
        let bootstrap = &mut *(NETWORK_SERVICE_BOOTSTRAP_ADDRESS as *mut NetworkServiceBootstrap);
        patch(bootstrap);
    }
    activate_address_space_root(kernel_root);
}

fn release_fixture_phase(pid: u64, kernel_root: u64) {
    patch_fixture_bootstrap(pid, kernel_root, |bootstrap| {
        bootstrap.aux_status = FIXTURE_PHASE_RELEASED;
    });
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
    let kernel_root = kernel_root_frame();
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
        fixtures: M7FixturePids {
            client: 0,
            unauthorized: 0,
            inflight: 0,
            stale: 0,
            capacity: 0,
        },
    }));
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m7 net allocator missing"));
    let controller = unsafe { service_lifecycle_controller_mut() };
    launch_network_service(
        controller,
        allocator,
        lifecycle_capability,
        NETWORK_SERVICE_ID,
    );
    log_service_started(controller, 1);
    let fixtures = spawn_all_fixtures(controller, allocator);
    set_state(Some(M7NetSelfTestState {
        lifecycle_capability,
        phase: M7Phase::AwaitClientEcho,
        session_id_raw: 0,
        service_generation: 1,
        fixtures,
    }));
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

fn spawn_all_fixtures(
    controller: &mut ServiceLifecycleController,
    allocator: &mut PageAllocator,
) -> M7FixturePids {
    let generation = 1;
    let mut client_bootstrap =
        NetworkServiceBootstrap::new(NETWORK_SERVICE_MODE_CLIENT, generation);
    client_bootstrap.aux_status = FIXTURE_PHASE_RELEASED;
    let client =
        launch_aux_with_bootstrap(controller, allocator, CLIENT_SLOT, client_bootstrap, true);
    let unauthorized = launch_aux_with_bootstrap(
        controller,
        allocator,
        UNAUTHORIZED_SLOT,
        NetworkServiceBootstrap::new(NETWORK_SERVICE_MODE_UNAUTHORIZED_PROBE, 0),
        false,
    );
    let inflight = launch_aux_with_bootstrap(
        controller,
        allocator,
        INFLIGHT_SLOT,
        NetworkServiceBootstrap::new(NETWORK_SERVICE_MODE_INFLIGHT_ARM, generation),
        true,
    );
    let stale = launch_aux_with_bootstrap(
        controller,
        allocator,
        STALE_SLOT,
        NetworkServiceBootstrap::new(NETWORK_SERVICE_MODE_STALE_CLOSE, 2),
        true,
    );
    let capacity = launch_aux_with_bootstrap(
        controller,
        allocator,
        CAPACITY_SLOT,
        NetworkServiceBootstrap::new(NETWORK_SERVICE_MODE_CAPACITY_LOOP, generation),
        true,
    );
    M7FixturePids {
        client: client.pid,
        unauthorized: unauthorized.pid,
        inflight: inflight.pid,
        stale: stale.pid,
        capacity: capacity.pid,
    }
}

fn launch_aux_with_bootstrap(
    controller: &mut ServiceLifecycleController,
    allocator: &mut PageAllocator,
    slot: usize,
    bootstrap: NetworkServiceBootstrap,
    grant_client: bool,
) -> crate::service::spawn::SpawnedServiceInstance {
    let stack_top = unsafe { task_stack_top(&(*task_stacks_mut())[slot]) };
    let spawned = launch_network_aux_process(allocator, stack_top, slot, bootstrap)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    if grant_client {
        controller
            .grant_network_client_capability(spawned.pid)
            .unwrap_or_else(|message| fatal_kernel_error(message));
    }
    spawned
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

pub(crate) fn handle_userspace_network_entry() -> u64 {
    let _pid =
        crate::process::current_process_id().unwrap_or_else(|message| fatal_kernel_error(message));
    let report = unsafe { &*(NETWORK_SERVICE_BOOTSTRAP_ADDRESS as *const NetworkServiceBootstrap) };
    let test_state = state();
    let kernel_root = kernel_root_frame();
    let mut session_id_raw = test_state.session_id_raw;
    let mut service_generation = test_state.service_generation;
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m7 net allocator missing"));
    let controller = unsafe { service_lifecycle_controller_mut() };

    let next_phase = match (test_state.phase, report.mode) {
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
            release_fixture_phase(test_state.fixtures.unauthorized, kernel_root);
            M7Phase::AwaitUnauthorized
        }
        (M7Phase::AwaitUnauthorized, NETWORK_SERVICE_MODE_UNAUTHORIZED_PROBE) => {
            if report.result_code != NETWORK_SERVICE_RESULT_OK {
                fatal_kernel_error("m7 unauthorized probe failed");
            }
            use clean_slate_network::protocol::TrustedCaller;
            crate::service::net_bridge::net_bridge_mut().push_holder_exit(TrustedCaller::new(
                test_state.fixtures.client,
                test_state.fixtures.client,
                0,
            ));
            crate::service::net_bridge::net_bridge_mut().log_m7_client_holder_exit_ack();
            patch_fixture_bootstrap(test_state.fixtures.inflight, kernel_root, |bootstrap| {
                bootstrap.session_id_raw = session_id_raw;
                bootstrap.aux_status = FIXTURE_PHASE_RELEASED;
            });
            M7Phase::AwaitInflightArm
        }
        (M7Phase::AwaitInflightArm, NETWORK_SERVICE_MODE_INFLIGHT_ARM) => {
            if report.result_code != NETWORK_SERVICE_RESULT_OK {
                fatal_kernel_error("m7 inflight arm failed");
            }
            terminate_network_service(controller, allocator, test_state.lifecycle_capability);
            let inflight_failed = crate::service::net_bridge::net_bridge_mut().inflight_failed();
            service_generation = 2;
            set_state(Some(M7NetSelfTestState {
                lifecycle_capability: test_state.lifecycle_capability,
                phase: test_state.phase,
                session_id_raw,
                service_generation,
                fixtures: test_state.fixtures,
            }));
            launch_network_service(
                controller,
                allocator,
                test_state.lifecycle_capability,
                NETWORK_SERVICE_ID,
            );
            kernel_log_fmt(format_args!(
                "[NET ] service restarted pid={} generation={}\n",
                controller.live_pid(NETWORK_SERVICE_ID).unwrap_or(0),
                service_generation
            ));
            kernel_log_fmt(format_args!(
                "[NET ] inflight failed count={inflight_failed}\n"
            ));
            for pid in [test_state.fixtures.stale, test_state.fixtures.capacity] {
                controller
                    .grant_network_client_capability(pid)
                    .unwrap_or_else(|message| fatal_kernel_error(message));
            }
            patch_fixture_bootstrap(test_state.fixtures.stale, kernel_root, |bootstrap| {
                bootstrap.session_id_raw = session_id_raw;
                bootstrap.service_generation = service_generation;
                bootstrap.aux_status = FIXTURE_PHASE_RELEASED;
            });
            patch_fixture_bootstrap(test_state.fixtures.capacity, kernel_root, |bootstrap| {
                bootstrap.service_generation = service_generation;
            });
            M7Phase::AwaitStaleClose
        }
        (M7Phase::AwaitStaleClose, NETWORK_SERVICE_MODE_STALE_CLOSE) => {
            if report.result_code != NETWORK_SERVICE_RESULT_OK {
                fatal_kernel_error("m7 stale close failed");
            }
            kernel_log_fmt(format_args!(
                "[NET ] stale-session denied generation={}\n",
                report.aux_status
            ));
            patch_fixture_bootstrap(test_state.fixtures.capacity, kernel_root, |bootstrap| {
                bootstrap.service_generation = service_generation;
                bootstrap.aux_status = FIXTURE_PHASE_RELEASED;
            });
            M7Phase::AwaitCapacityLoop
        }
        (M7Phase::AwaitCapacityLoop, NETWORK_SERVICE_MODE_CAPACITY_LOOP) => {
            if report.result_code != NETWORK_SERVICE_RESULT_OK {
                fatal_kernel_error("m7 capacity loop failed");
            }
            kernel_log_line("[NET ] capacity baseline ok");
            terminate_network_service(controller, allocator, test_state.lifecycle_capability);
            M7Phase::Complete
        }
        _ => fatal_kernel_error("unexpected m7 net userspace trap phase/mode"),
    };

    set_state(Some(M7NetSelfTestState {
        lifecycle_capability: test_state.lifecycle_capability,
        phase: next_phase,
        session_id_raw,
        service_generation,
        fixtures: test_state.fixtures,
    }));

    let teardown = teardown_current_process(allocator, kernel_root, 0, false)
        .unwrap_or_else(|message| fatal_kernel_error(message));

    if next_phase == M7Phase::Complete {
        kernel_log_line(PASS_MARKER);
        qemu_exit(QEMU_EXIT_SUCCESS);
    }

    match teardown.next_stack_pointer {
        Some(next_stack_pointer) => next_stack_pointer,
        None => fatal_kernel_error("m7 net self-test teardown found no runnable thread"),
    }
}
