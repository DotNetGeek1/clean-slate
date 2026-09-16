//! CPL3 supervisor image for the M4.3 QEMU integration self-test.

#![no_std]
#![no_main]

use clean_slate_service_lifecycle::{
    DomainId, InstanceGeneration, LifecycleEvent, LifecycleEventKind, ProcessId, ServiceId,
    ServiceInstanceId,
};
use clean_slate_supervisor::{
    DiagnosticSink, FakeLifecycleControl, LifecycleControlError, Supervisor, SupervisorError,
};

const BOOTSTRAP_ADDRESS: u64 = 0x0000_4000_0000_C000;
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

fn seed_control(
    control: &mut FakeLifecycleControl<8>,
    service: ServiceId,
    pid: u64,
) -> Result<(), SupervisorError> {
    let instance = ServiceInstanceId::new(
        service,
        InstanceGeneration(1),
        ProcessId(pid),
        DomainId(pid),
    );
    control
        .push_pending(LifecycleEvent::new(
            instance,
            LifecycleEventKind::InstanceSpawned,
        ))
        .map_err(|_| SupervisorError::Control(LifecycleControlError::TransportFailed))?;
    control
        .push_pending(LifecycleEvent::new(instance, LifecycleEventKind::Ready))
        .map_err(|_| SupervisorError::Control(LifecycleControlError::TransportFailed))?;
    Ok(())
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let config = bootstrap();
    let mut control = FakeLifecycleControl::<8>::new();
    let service = ServiceId(1);
    let instance_pid = 201_u64;
    if seed_control(&mut control, service, instance_pid).is_err() {
        unsafe {
            core::arch::asm!("ud2", options(noreturn));
        }
    }

    let mut supervisor = Supervisor::<_, _, 8>::new(
        ProcessId(config.self_pid),
        control,
        IpcConsoleSink {
            capability: config.console_capability,
        },
    );

    if supervisor.start().is_err()
        || supervisor.register_service(service).is_err()
        || supervisor.request_start(service).is_err()
    {
        unsafe {
            core::arch::asm!("ud2", options(noreturn));
        }
    }

    unsafe {
        core::arch::asm!("int 0x80", options(noreturn));
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
