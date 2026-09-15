//! CPL3 integration image for M4.6 restart-policy convergence self-test.

#![no_std]
#![no_main]

use clean_slate_service_lifecycle::{
    DomainId, InstanceGeneration, LifecycleEvent, LifecycleEventKind, LivenessConfig, ProcessId,
    ServiceId, ServiceInstanceId,
};
use clean_slate_supervisor::{
    BoundedRestart, ConvergedSupervisor, DiagnosticSink, FakeLifecycleControl,
    LifecycleControlError, RestartPolicy, ServiceConvergenceConfig, SupervisorError,
};

const BOOTSTRAP_ADDRESS: u64 = 0x0000_4000_0000_1000;
const SYSCALL_NR_IPC_SEND: u64 = 3;

#[repr(C)]
struct SupervisorBootstrap {
    self_pid: u64,
    console_capability: u64,
}

struct IpcConsoleSink {
    capability: u64,
}

impl DiagnosticSink for IpcConsoleSink {
    fn emit_line(&mut self, line: &str) -> Result<(), SupervisorError> {
        ipc_send(self.capability, line.as_bytes())
            .map_err(|_| SupervisorError::Control(LifecycleControlError::TransportFailed))?;
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

fn bootstrap() -> &'static SupervisorBootstrap {
    unsafe { &*(BOOTSTRAP_ADDRESS as *const SupervisorBootstrap) }
}

fn instance(service: u32, gen: u32, pid: u64) -> ServiceInstanceId {
    ServiceInstanceId::new(
        ServiceId(service),
        InstanceGeneration(gen),
        ProcessId(pid),
        DomainId(pid),
    )
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let config = bootstrap();
    let mut control = FakeLifecycleControl::<16>::new();
    let service = ServiceId(1);
    let _ = control.push_pending(LifecycleEvent::new(
        instance(1, 1, 201),
        LifecycleEventKind::InstanceSpawned,
    ));
    let _ = control.push_pending(LifecycleEvent::new(
        instance(1, 1, 201),
        LifecycleEventKind::Ready,
    ));
    let _ = control.push_pending(LifecycleEvent::new(
        instance(1, 2, 202),
        LifecycleEventKind::InstanceSpawned,
    ));
    let _ = control.push_pending(LifecycleEvent::new(
        instance(1, 2, 202),
        LifecycleEventKind::Ready,
    ));

    let mut supervisor = ConvergedSupervisor::<_, _, 4>::new(
        ProcessId(config.self_pid),
        control,
        IpcConsoleSink {
            capability: config.console_capability,
        },
        LivenessConfig::new(100),
    );

    let policy = ServiceConvergenceConfig::new(
        RestartPolicy::OnFailure(BoundedRestart::new(3, 0)),
        LivenessConfig::new(100),
    );

    if supervisor.start().is_err() || supervisor.register_service(service, policy).is_err() {
        unsafe {
            core::arch::asm!("ud2", options(noreturn));
        }
    }
    supervisor.set_virtual_ticks(0);
    if supervisor.request_start(service).is_err()
        || supervisor
            .handle_lifecycle_event(LifecycleEvent::new(
                instance(1, 1, 201),
                LifecycleEventKind::Faulted,
            ))
            .is_err()
    {
        unsafe {
            core::arch::asm!("ud2", options(noreturn));
        }
    }

    ipc_send(config.console_capability, b"[M4.6] PASS\n").ok();

    unsafe {
        core::arch::asm!("int 0x80", options(noreturn));
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
