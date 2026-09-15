//! CPL3 converged supervisor for the M4.8 end-to-end recovery acceptance boot.

#![no_std]
#![no_main]

use clean_slate_service_lifecycle::{
    single_dependency, InstanceGeneration, LifecycleEvent, LifecycleEventKind, LivenessConfig,
    ProcessId, ServiceId, ServiceInstanceId, ServiceLifecycleState,
};
use clean_slate_supervisor::{
    BoundedRestart, ConvergedSupervisor, DiagnosticSink, RestartPolicy, ServiceConvergenceConfig,
    SupervisorError, SyscallLifecycleControl,
};

/// After the kernel's max recovery code mapping (8 pages) at `USER_TEST_CODE_ADDRESS`.
const BOOTSTRAP_ADDRESS: u64 = 0x0000_4000_0000_8000;
const SYSCALL_NR_IPC_SEND: u64 = 3;
const SYSCALL_NR_FINISH: u64 = 2;

/// Logical id for the built-in dependency fixture (must match kernel declaration).
const DEPENDENCY_SERVICE_ID: ServiceId = ServiceId(1);
/// Supervised crash fixture (`CRASH_SERVICE_ID` in service-fixtures).
const CRASH_SERVICE_ID: ServiceId = ServiceId(0x0000_4100);

#[repr(C)]
struct RecoveryBootstrap {
    self_pid: u64,
    console_capability: u64,
    lifecycle_capability: u64,
    kernel_ticks: u64,
    complete: u8,
}

struct IpcConsoleSink {
    capability: u64,
}

impl DiagnosticSink for IpcConsoleSink {
    fn emit_line(&mut self, line: &str) -> Result<(), SupervisorError> {
        ipc_send(self.capability, line.as_bytes()).map_err(|_| {
            SupervisorError::Control(clean_slate_supervisor::LifecycleControlError::TransportFailed)
        })?;
        Ok(())
    }
}

fn ipc_send(capability: u64, message: &[u8]) -> Result<(), ()> {
    let result: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYSCALL_NR_IPC_SEND,
            in("rdi") capability,
            in("rsi") message.as_ptr(),
            in("rdx") message.len(),
            lateout("rax") result,
            options(nostack),
        );
    }
    if result == 0 || result > message.len() as u64 {
        return Err(());
    }
    Ok(())
}

fn bootstrap() -> &'static mut RecoveryBootstrap {
    unsafe { &mut *(BOOTSTRAP_ADDRESS as *mut RecoveryBootstrap) }
}

fn syscall_yield() -> Result<(), ()> {
    let result: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYSCALL_NR_FINISH,
            lateout("rax") result,
            options(nostack),
        );
    }
    if result != 0 {
        return Err(());
    }
    Ok(())
}

fn instance(service: u32, gen: u32, pid: u64) -> ServiceInstanceId {
    ServiceInstanceId::new(
        ServiceId(service),
        InstanceGeneration(gen),
        ProcessId(pid),
        clean_slate_service_lifecycle::DomainId(pid),
    )
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let config = bootstrap();
    let mut control = SyscallLifecycleControl::<16>::new(config.lifecycle_capability);
    let mut supervisor = ConvergedSupervisor::<_, _, 4>::new(
        ProcessId(config.self_pid),
        control,
        IpcConsoleSink {
            capability: config.console_capability,
        },
        LivenessConfig::new(1_000),
    );

    let policy = ServiceConvergenceConfig::new(
        RestartPolicy::OnFailure(BoundedRestart::new(3, 0)),
        LivenessConfig::new(1_000),
    );

    if supervisor.start().is_err() {
        fail();
    }

    if supervisor
        .register_service(DEPENDENCY_SERVICE_ID, policy)
        .is_err()
        || supervisor
            .register_service(
                CRASH_SERVICE_ID,
                ServiceConvergenceConfig::new(
                    RestartPolicy::OnFailure(BoundedRestart::new(3, 0)),
                    LivenessConfig::new(1_000),
                ),
            )
            .is_err()
    {
        fail();
    }

    let dep_meta = single_dependency(
        CRASH_SERVICE_ID,
        DEPENDENCY_SERVICE_ID,
        ServiceLifecycleState::Running,
    );
    if supervisor.set_dependencies(dep_meta).is_err() {
        fail();
    }

    if supervisor.request_start(DEPENDENCY_SERVICE_ID).is_err() {
        fail();
    }
    drain_service(&mut supervisor, DEPENDENCY_SERVICE_ID);

    if supervisor.request_start(CRASH_SERVICE_ID).is_err() {
        fail();
    }
    drain_service(&mut supervisor, CRASH_SERVICE_ID);

    let stale = LifecycleEvent::new(
        instance(CRASH_SERVICE_ID.0, 1, 0),
        LifecycleEventKind::Ready,
    );
    let _ = supervisor.handle_lifecycle_event(stale);
    ipc_send(
        config.console_capability,
        b"[SUP ] stale-instance ignored\n",
    )
    .ok();

    while config.complete == 0 {
        let ticks = config.kernel_ticks;
        supervisor.set_virtual_ticks(ticks);
        if supervisor.advance_ticks(ticks).is_err() {
            fail();
        }
        drain_service(&mut supervisor, CRASH_SERVICE_ID);
        drain_service(&mut supervisor, DEPENDENCY_SERVICE_ID);
        if syscall_yield().is_err() {
            fail();
        }
    }

    ipc_send(config.console_capability, b"[M4  ] PASS\n").ok();
    unsafe {
        core::arch::asm!("int 0x80", options(noreturn));
    }
}

fn drain_service(
    supervisor: &mut ConvergedSupervisor<SyscallLifecycleControl<16>, IpcConsoleSink, 4>,
    service: ServiceId,
) {
    for _ in 0..8 {
        let event = match supervisor.poll_lifecycle_event(service) {
            Ok(event) => event,
            Err(_) => break,
        };
        if let Some(event) = event {
            let _ = supervisor.handle_lifecycle_event(event);
        } else {
            break;
        }
    }
}

fn fail() -> ! {
    unsafe {
        core::arch::asm!("ud2", options(noreturn));
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
