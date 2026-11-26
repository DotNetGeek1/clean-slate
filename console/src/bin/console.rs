//! #310 console service: the CPL3 adapter around `clean_slate_console::ConsoleCore`.
//!
//! Startup reads the bootstrap page, finds its `CONSOLE_SERVE` capability on the console port
//! and its serial device capability (syscall 25 `FIND_HANDLE`), creates its work set and binds
//! the port's requests and notices to it, then reports ready. From there it sleeps in
//! `WORK_SET` `WAIT` until a request or notice arrives and drains the port. A startup step that
//! fails is a `FAIL` line and `ud2`, which init's restart policy handles like any other fault.

#![no_std]
#![no_main]

use clean_slate_capability::ResourceClass;
use clean_slate_console::{ConsoleCore, Frame, PostFailure, SerialDevice, StreamPort};
use clean_slate_native_abi::console::{
    CONSOLE_DEVICE_OP_FIND_HANDLE, CONSOLE_DEVICE_OP_WRITE, SYSCALL_NR_CONSOLE_DEVICE,
};
use clean_slate_native_abi::service_ready::ServiceReadyResult;
use clean_slate_native_abi::status::is_status;
use clean_slate_native_abi::ConnectionId;
use clean_slate_runtime::console::Console;
use clean_slate_runtime::port::{Server, Wait, WorkSet};
use clean_slate_runtime::{process, Error, Kernel, Syscalls};
use clean_slate_service_fixtures::console_service::{
    ConsoleServiceBootstrap, CONSOLE_SERVICE_BOOTSTRAP_ADDRESS,
};

const REQUEST_BIT: u32 = 0;
const NOTICE_BIT: u32 = 1;
const WAKE_MASK: u32 = (1 << REQUEST_BIT) | (1 << NOTICE_BIT);

static mut CORE: ConsoleCore = ConsoleCore::new();

struct KernelDevice {
    handle: u64,
}

impl SerialDevice for KernelDevice {
    fn write_line(&mut self, line: &[u8]) -> Result<(), u64> {
        let raw = Kernel.syscall(
            SYSCALL_NR_CONSOLE_DEVICE,
            [
                CONSOLE_DEVICE_OP_WRITE,
                self.handle,
                line.as_ptr() as u64,
                line.len() as u64,
                0,
                0,
            ],
        );
        if is_status(raw) {
            Err(raw)
        } else {
            Ok(())
        }
    }
}

struct KernelPort {
    server: Server,
}

impl StreamPort for KernelPort {
    fn post(&mut self, connection: ConnectionId, frame: &Frame) -> Result<(), PostFailure> {
        match self.server.post(&mut Kernel, connection, frame) {
            Ok(()) => Ok(()),
            Err(Error::WouldBlock) => Err(PostFailure::Full),
            Err(_) => Err(PostFailure::Gone),
        }
    }

    fn disconnect(&mut self, connection: ConnectionId, reason: u32) {
        let _ = self.server.disconnect(&mut Kernel, connection, reason);
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let bootstrap =
        unsafe { *(CONSOLE_SERVICE_BOOTSTRAP_ADDRESS as *const ConsoleServiceBootstrap) };
    let console = Console::new(bootstrap.console_capability);
    let Ok(server) = Server::find(
        &mut Kernel,
        ResourceClass::Console,
        bootstrap.port_resource_id,
    ) else {
        fail(
            console,
            b"[CONS] FAIL no serve capability on the console port",
        );
    };
    let Ok(device) = Kernel.call(
        SYSCALL_NR_CONSOLE_DEVICE,
        [CONSOLE_DEVICE_OP_FIND_HANDLE, 0, 0, 0, 0, 0],
    ) else {
        fail(console, b"[CONS] FAIL no serial console device");
    };
    let Ok(work_set) = WorkSet::create(&mut Kernel) else {
        fail(console, b"[CONS] FAIL WORK_SET CREATE refused");
    };
    if server
        .bind_wake(&mut Kernel, work_set, REQUEST_BIT, NOTICE_BIT)
        .is_err()
    {
        fail(console, b"[CONS] FAIL port BIND_WAKE refused");
    }
    let mut device = KernelDevice { handle: device };
    let mut port = KernelPort { server };
    let core = unsafe { &mut *core::ptr::addr_of_mut!(CORE) };
    if process::report_ready(&mut Kernel, 0) != ServiceReadyResult::Accepted {
        fail(console, b"[CONS] FAIL SERVICE_READY refused");
    }
    loop {
        loop {
            match server.recv(&mut Kernel) {
                Ok(Some(record)) => core.handle(&record, &mut device, &mut port),
                Ok(None) => break,
                Err(_) => fail(console, b"[CONS] FAIL port RECV refused"),
            }
        }
        // Drained: show partial lines, such as a prompt, before sleeping.
        core.idle(&mut device);
        if work_set
            .wait(&mut Kernel, WAKE_MASK, Wait::FOREVER)
            .is_err()
        {
            fail(console, b"[CONS] FAIL WORK_SET WAIT failed");
        }
    }
}

fn fail(console: Console, line: &[u8]) -> ! {
    let _ = console.send(&mut Kernel, line);
    process::abort();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    process::abort();
}
