//! #310 console service: the CPL3 adapter around `clean_slate_console::ConsoleCore`.
//!
//! Startup reads the bootstrap page, finds its `CONSOLE_SERVE` capability on the console port
//! and its serial device capability (syscall 25 `FIND_HANDLE`), creates its work set and binds
//! the port's requests and notices to it and the serial line's committed input to a third bit,
//! then reports ready. From there it sleeps in
//! `WORK_SET` `WAIT` until a request or notice arrives and drains the port. A startup step that
//! fails is a `FAIL` line and `ud2`, which init's restart policy handles like any other fault.

#![no_std]
#![no_main]

use clean_slate_capability::ResourceClass;
use clean_slate_console::{
    ConsoleCore, Frame, InputRead, InputSource, PostFailure, SerialDevice, StreamPort,
};
use clean_slate_native_abi::console::{
    CONSOLE_DEVICE_OP_BIND_INPUT, CONSOLE_DEVICE_OP_FIND_HANDLE, CONSOLE_DEVICE_OP_READ_INPUT,
    CONSOLE_DEVICE_OP_WRITE, CONSOLE_INPUT_END, SYSCALL_NR_CONSOLE_DEVICE,
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
/// Set by the kernel when the serial line's discipline commits input.
const INPUT_BIT: u32 = 2;
const WAKE_MASK: u32 = (1 << REQUEST_BIT) | (1 << NOTICE_BIT) | (1 << INPUT_BIT);

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

struct KernelInput {
    handle: u64,
}

impl InputSource for KernelInput {
    fn read_input(&mut self, out: &mut [u8]) -> InputRead {
        let raw = Kernel.syscall(
            SYSCALL_NR_CONSOLE_DEVICE,
            [
                CONSOLE_DEVICE_OP_READ_INPUT,
                self.handle,
                out.as_mut_ptr() as u64,
                out.len() as u64,
                0,
                0,
            ],
        );
        if is_status(raw) {
            // `EAGAIN`: nothing committed. Any other status is the same to the readers.
            InputRead::Nothing
        } else if raw == CONSOLE_INPUT_END {
            InputRead::End
        } else {
            InputRead::Bytes(raw as usize)
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
    if Kernel
        .call(
            SYSCALL_NR_CONSOLE_DEVICE,
            [
                CONSOLE_DEVICE_OP_BIND_INPUT,
                device,
                work_set.raw(),
                u64::from(INPUT_BIT),
                0,
                0,
            ],
        )
        .is_err()
    {
        fail(console, b"[CONS] FAIL serial input BIND_INPUT refused");
    }
    let mut input = KernelInput { handle: device };
    let mut device = KernelDevice { handle: device };
    let mut port = KernelPort { server };
    let core = unsafe { &mut *core::ptr::addr_of_mut!(CORE) };
    if process::report_ready(&mut Kernel, 0) != ServiceReadyResult::Accepted {
        fail(console, b"[CONS] FAIL SERVICE_READY refused");
    }
    let mut input_reported = false;
    loop {
        loop {
            match server.recv(&mut Kernel) {
                Ok(Some(record)) => {
                    core.handle_with_input(&record, &mut device, &mut port, &mut input)
                }
                Ok(None) => break,
                Err(_) => fail(console, b"[CONS] FAIL port RECV refused"),
            }
        }
        // Drained: hand committed serial input to the waiting reads, and show partial lines,
        // such as a prompt, before sleeping.
        core.pump_input(&mut port, &mut input);
        // Once a boot: typed input reached a reader through the service, not the kernel.
        if !input_reported && core.stats().serial_input_bytes > 0 {
            input_reported = true;
            let _ = console.send(&mut Kernel, b"[CONS] serial input answered a read");
        }
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
