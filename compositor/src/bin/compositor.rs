//! CPL3 compositor service: the thin kernel adapter around `clean_slate_compositor`.
//!
//! Every trait in `clean_slate_compositor::backend` is implemented here over the frozen native
//! ABI (syscalls 16–20); the core never issues a syscall. The adapter names no device: the
//! display is reached only through syscall 18, identical for every scanout backend.
//!
//! Startup reads [`CompositorBootstrap`] from the launch page, finds its `Graphics{GFX_SERVE}`,
//! `Display` and (optional) `Input` capabilities, creates its work set and binds every wake
//! source it can. Display completion without `BIND_WAKE` (`ENOSYS` until #111 wires it) falls
//! back to a bounded deadline while a present is in flight. Input is read only on its own wake
//! bit, so the compositor consumes input only once syscall 19 `BIND_WAKE` succeeds (it also makes
//! the compositor the seat consumer); otherwise it runs without input. Neither adds an idle poll.

#![no_std]
#![no_main]

use core::ptr::addr_of_mut;

use clean_slate_capability::syscall_abi::SYSCALL_NR_CAP_REVOKE;
use clean_slate_capability::ResourceClass;
use clean_slate_compositor::backend::{
    BufferMapping, DisplayBackend, InputFailure, InputSource, MapFailure, NoInput, PortFailure,
    PortServer, SharedBufferMapper, WaitFailure, WorkWaiter, WAKE_DISPLAY, WAKE_INPUT,
    WAKE_NOTICES, WAKE_REQUESTS,
};
use clean_slate_compositor::{Compositor, Config, DefaultPolicy, Io};
use clean_slate_graphics::abi::display::{
    DisplayError, DisplayModeInfo, PresentRequest, PresentStatus, ScanoutMapping,
    DISPLAY_ABI_VERSION, DISPLAY_MODE_INFO_BYTES, DISPLAY_SUBOP_BIND_WAKE,
    DISPLAY_SUBOP_FIND_HANDLE, DISPLAY_SUBOP_MAP_SCANOUT, DISPLAY_SUBOP_PRESENT,
    DISPLAY_SUBOP_PRESENT_STATUS, DISPLAY_SUBOP_QUERY_MODE, PRESENT_REQUEST_BYTES,
    PRESENT_STATUS_BYTES, SCANOUT_MAPPING_BYTES,
};
use clean_slate_graphics::abi::input::{
    INPUT_ABI_VERSION, INPUT_SUBOP_BIND_WAKE, INPUT_SUBOP_FIND_HANDLE, INPUT_SUBOP_READ_BATCH,
    READ_BATCH_MAX_RECORDS,
};
use clean_slate_graphics::limits::SCANOUT_BUFFER_COUNT;
use clean_slate_graphics::protocol::DisconnectReason;
use clean_slate_graphics::raw_input::{RawInputRecord, RAW_INPUT_RECORD_BYTES};
use clean_slate_native_abi::port::{
    PORT_OP_BIND_WAKE, PORT_OP_DISCONNECT, PORT_OP_FIND_HANDLE, PORT_OP_POST, PORT_OP_RECV,
    PORT_RECV_NONBLOCK, PORT_ROLE_SERVE,
};
use clean_slate_native_abi::work_set::{
    WORK_SET_OP_CREATE, WORK_SET_OP_NOW, WORK_SET_OP_WAIT, WORK_SET_WAIT_NONBLOCK,
};
use clean_slate_native_abi::{
    is_status, ConnectionId, PortRecvRecord, TransferredCap, SHARED_BUFFER_ACCESS_READ,
    SHARED_BUFFER_SUBOP_MAP, SHARED_BUFFER_SUBOP_UNMAP, STATUS_EAGAIN, STATUS_ENOSPC, STATUS_EPIPE,
    STATUS_ESTALE, STATUS_ETIMEDOUT, SYSCALL_NR_SERVICE_PORT, SYSCALL_NR_SHARED_BUFFER,
    SYSCALL_NR_WORK_SET,
};

/// Launch page shared with the supervisor images.
const BOOTSTRAP_ADDRESS: u64 = 0x0000_4000_0000_1000;
const SYSCALL_NR_DISPLAY: u64 = 18;
const SYSCALL_NR_INPUT: u64 = 19;
const CAP_REVOKE_OP_REVOKE: u64 = 1;

/// Layout the launch policy writes for the compositor (P5).
#[repr(C)]
struct CompositorBootstrap {
    self_pid: u64,
    /// Resource id of the compositor's `Graphics` port (`ResourceRef::graphics`).
    graphics_resource_id: u64,
}

static mut COMPOSITOR: Compositor<DefaultPolicy> =
    Compositor::new(DefaultPolicy::new(), Config::DEFAULT);

fn syscall(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let result: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => result,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            in("r8") a4,
            in("r9") 0u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

fn checked(raw: u64) -> Result<u64, u64> {
    if is_status(raw) {
        Err(raw)
    } else {
        Ok(raw)
    }
}

fn port_failure(status: u64) -> PortFailure {
    match status {
        STATUS_EAGAIN => PortFailure::Full,
        STATUS_EPIPE | STATUS_ESTALE => PortFailure::Gone,
        other => PortFailure::Status(other),
    }
}

fn display_failure(status: u64) -> DisplayError {
    DisplayError::from_status(status).unwrap_or(DisplayError::ModeUnavailable)
}

struct KernelPort {
    serve: u64,
}

impl PortServer for KernelPort {
    fn recv(&mut self) -> Result<Option<PortRecvRecord>, PortFailure> {
        let mut out = [0u8; PortRecvRecord::BYTES];
        let raw = syscall(
            SYSCALL_NR_SERVICE_PORT,
            PORT_OP_RECV,
            self.serve,
            out.as_mut_ptr() as u64,
            out.len() as u64,
            PORT_RECV_NONBLOCK,
        );
        match checked(raw) {
            Ok(_) => PortRecvRecord::decode(&out)
                .map(Some)
                .map_err(|_| PortFailure::Status(raw)),
            Err(STATUS_EAGAIN) => Ok(None),
            Err(status) => Err(port_failure(status)),
        }
    }

    fn post(&mut self, connection: ConnectionId, frame: &[u8; 64]) -> Result<(), PortFailure> {
        let raw = syscall(
            SYSCALL_NR_SERVICE_PORT,
            PORT_OP_POST,
            self.serve,
            connection.encode(),
            frame.as_ptr() as u64,
            0,
        );
        checked(raw).map(|_| ()).map_err(port_failure)
    }

    fn disconnect(
        &mut self,
        connection: ConnectionId,
        reason: DisconnectReason,
    ) -> Result<(), PortFailure> {
        let raw = syscall(
            SYSCALL_NR_SERVICE_PORT,
            PORT_OP_DISCONNECT,
            self.serve,
            connection.encode(),
            u64::from(reason.encode()),
            0,
        );
        checked(raw).map(|_| ()).map_err(port_failure)
    }
}

/// Read-only shared-window mappings of client buffers.
struct KernelSharedBuffers;

impl SharedBufferMapper for KernelSharedBuffers {
    fn map_read(&mut self, transfer: &TransferredCap) -> Result<BufferMapping, MapFailure> {
        let raw = syscall(
            SYSCALL_NR_SHARED_BUFFER,
            SHARED_BUFFER_SUBOP_MAP,
            transfer.handle,
            SHARED_BUFFER_ACCESS_READ,
            0,
            0,
        );
        match checked(raw) {
            Ok(va) => Ok(BufferMapping {
                handle: transfer.handle,
                buffer_id: transfer.buffer_id,
                byte_len: transfer.byte_len,
                token: va,
            }),
            Err(STATUS_ENOSPC | STATUS_EAGAIN) => Err(MapFailure::NoSpace),
            Err(_) => Err(MapFailure::Denied),
        }
    }

    fn bytes(&self, mapping: &BufferMapping) -> Option<&[u8]> {
        if mapping.token == 0 {
            return None;
        }
        // The kernel mapped at least `byte_len` readable bytes at `token` and keeps the row
        // alive until `unmap`, which takes the mapping by value.
        Some(unsafe {
            core::slice::from_raw_parts(mapping.token as *const u8, mapping.byte_len as usize)
        })
    }

    fn unmap(&mut self, mapping: BufferMapping) {
        syscall(
            SYSCALL_NR_SHARED_BUFFER,
            SHARED_BUFFER_SUBOP_UNMAP,
            0,
            mapping.token,
            0,
            0,
        );
        self.discard_handle(mapping.handle);
    }

    fn discard(&mut self, transfer: &TransferredCap) {
        self.discard_handle(transfer.handle);
    }
}

impl KernelSharedBuffers {
    /// A `READ` child cannot revoke itself, so this fails with `EACCES` until the kernel grows a
    /// holder-side drop; the child is then reclaimed at compositor teardown.
    fn discard_handle(&mut self, handle: u64) {
        syscall(SYSCALL_NR_CAP_REVOKE, CAP_REVOKE_OP_REVOKE, handle, 0, 0, 0);
    }
}

struct KernelDisplay {
    handle: u64,
    scanout: [Option<(u64, u64)>; SCANOUT_BUFFER_COUNT],
}

impl DisplayBackend for KernelDisplay {
    fn query_mode(&mut self) -> Result<DisplayModeInfo, DisplayError> {
        let mut out = [0u8; DISPLAY_MODE_INFO_BYTES];
        let raw = syscall(
            SYSCALL_NR_DISPLAY,
            DISPLAY_SUBOP_QUERY_MODE,
            self.handle,
            out.as_mut_ptr() as u64,
            out.len() as u64,
            0,
        );
        checked(raw).map_err(display_failure)?;
        DisplayModeInfo::decode(&out).map_err(|_| DisplayError::ModeUnavailable)
    }

    fn scanout(&mut self, index: u8) -> Result<&mut [u8], DisplayError> {
        let slot = self
            .scanout
            .get_mut(usize::from(index))
            .ok_or(DisplayError::InvalidBuffer)?;
        let (va, len) = match *slot {
            Some(mapped) => mapped,
            None => {
                let mut out = [0u8; SCANOUT_MAPPING_BYTES];
                let raw = syscall(
                    SYSCALL_NR_DISPLAY,
                    DISPLAY_SUBOP_MAP_SCANOUT,
                    self.handle,
                    u64::from(index),
                    out.as_mut_ptr() as u64,
                    out.len() as u64,
                );
                checked(raw).map_err(display_failure)?;
                let mapping =
                    ScanoutMapping::decode(&out).map_err(|_| DisplayError::InvalidBuffer)?;
                *slot = Some((mapping.user_va, mapping.byte_len));
                (mapping.user_va, mapping.byte_len)
            }
        };
        // Scanout mappings are user read-write, persist across epoch bumps and are released
        // only by process teardown; the core writes only the index that is not in flight.
        Ok(unsafe { core::slice::from_raw_parts_mut(va as *mut u8, len as usize) })
    }

    fn present(&mut self, request: &PresentRequest) -> Result<u64, DisplayError> {
        let bytes: [u8; PRESENT_REQUEST_BYTES] = request.encode();
        let raw = syscall(
            SYSCALL_NR_DISPLAY,
            DISPLAY_SUBOP_PRESENT,
            self.handle,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
            0,
        );
        checked(raw).map_err(display_failure)
    }

    fn status(&mut self) -> Result<PresentStatus, DisplayError> {
        let mut out = [0u8; PRESENT_STATUS_BYTES];
        let raw = syscall(
            SYSCALL_NR_DISPLAY,
            DISPLAY_SUBOP_PRESENT_STATUS,
            self.handle,
            out.as_mut_ptr() as u64,
            out.len() as u64,
            0,
        );
        checked(raw).map_err(display_failure)?;
        PresentStatus::decode(&out).map_err(|_| DisplayError::ModeUnavailable)
    }
}

struct KernelInput {
    handle: u64,
}

impl InputSource for KernelInput {
    fn read_batch(
        &mut self,
        max: usize,
        sink: &mut dyn FnMut(RawInputRecord),
    ) -> Result<usize, InputFailure> {
        let mut out = [0u8; READ_BATCH_MAX_RECORDS * RAW_INPUT_RECORD_BYTES];
        let max = max.min(READ_BATCH_MAX_RECORDS);
        let raw = syscall(
            SYSCALL_NR_INPUT,
            INPUT_SUBOP_READ_BATCH,
            self.handle,
            out.as_mut_ptr() as u64,
            max as u64,
            0,
        );
        let count = checked(raw).map_err(InputFailure)? as usize;
        let count = count.min(max);
        for chunk in out[..count * RAW_INPUT_RECORD_BYTES].chunks_exact(RAW_INPUT_RECORD_BYTES) {
            if let Ok(record) = RawInputRecord::decode(chunk) {
                sink(record);
            }
        }
        Ok(count)
    }
}

struct KernelWorkSet {
    id: u64,
    /// `WAIT` with a deadline needs a calibrated clock; without one a deadline wait degrades to
    /// a non-blocking check, which the core only plans while a present is in flight.
    has_clock: bool,
}

impl WorkWaiter for KernelWorkSet {
    fn wait(&mut self, mask: u32, deadline_ns: Option<u64>) -> Result<u32, WaitFailure> {
        let (deadline, flags) = match deadline_ns {
            Some(deadline) if self.has_clock => (deadline.max(1), 0),
            Some(_) => (0, WORK_SET_WAIT_NONBLOCK),
            None => (0, 0),
        };
        let raw = syscall(
            SYSCALL_NR_WORK_SET,
            WORK_SET_OP_WAIT,
            self.id,
            u64::from(mask),
            deadline,
            flags,
        );
        match checked(raw) {
            Ok(bits) => Ok(bits as u32),
            Err(STATUS_ETIMEDOUT | STATUS_EAGAIN) => Ok(0),
            Err(status) => Err(WaitFailure(status)),
        }
    }

    fn now_ns(&mut self) -> u64 {
        checked(syscall(SYSCALL_NR_WORK_SET, WORK_SET_OP_NOW, 0, 0, 0, 0)).unwrap_or(0)
    }
}

fn bootstrap() -> &'static CompositorBootstrap {
    unsafe { &*(BOOTSTRAP_ADDRESS as *const CompositorBootstrap) }
}

fn exit() -> ! {
    unsafe {
        core::arch::asm!("int 0x80", options(noreturn));
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let boot = bootstrap();
    let _ = boot.self_pid;
    let Ok(serve) = checked(syscall(
        SYSCALL_NR_SERVICE_PORT,
        PORT_OP_FIND_HANDLE,
        0,
        u64::from(ResourceClass::Graphics as u8),
        boot.graphics_resource_id,
        PORT_ROLE_SERVE,
    )) else {
        exit();
    };
    let Ok(display_handle) = checked(syscall(
        SYSCALL_NR_DISPLAY,
        DISPLAY_SUBOP_FIND_HANDLE,
        0,
        DISPLAY_ABI_VERSION,
        0,
        0,
    )) else {
        exit();
    };
    let input_handle = checked(syscall(
        SYSCALL_NR_INPUT,
        INPUT_SUBOP_FIND_HANDLE,
        0,
        INPUT_ABI_VERSION,
        0,
        0,
    ))
    .ok();
    let Ok(work_set) = checked(syscall(SYSCALL_NR_WORK_SET, WORK_SET_OP_CREATE, 0, 0, 0, 0)) else {
        exit();
    };
    let port_bound = checked(syscall(
        SYSCALL_NR_SERVICE_PORT,
        PORT_OP_BIND_WAKE,
        serve,
        work_set,
        u64::from(WAKE_REQUESTS.trailing_zeros()),
        u64::from(WAKE_NOTICES.trailing_zeros()),
    ));
    if port_bound.is_err() {
        exit();
    }
    let display_wakes = checked(syscall(
        SYSCALL_NR_DISPLAY,
        DISPLAY_SUBOP_BIND_WAKE,
        display_handle,
        work_set,
        u64::from(WAKE_DISPLAY.trailing_zeros()),
        0,
    ))
    .is_ok();
    let input_handle = input_handle.filter(|&handle| {
        checked(syscall(
            SYSCALL_NR_INPUT,
            INPUT_SUBOP_BIND_WAKE,
            handle,
            work_set,
            u64::from(WAKE_INPUT.trailing_zeros()),
            0,
        ))
        .is_ok()
    });

    let mut port = KernelPort { serve };
    let mut buffers = KernelSharedBuffers;
    let mut display = KernelDisplay {
        handle: display_handle,
        scanout: [None; SCANOUT_BUFFER_COUNT],
    };
    let mut kernel_input = input_handle.map(|handle| KernelInput { handle });
    let mut no_input = NoInput;
    let mut waiter = KernelWorkSet {
        id: work_set,
        has_clock: false,
    };
    waiter.has_clock = waiter.now_ns() != 0;

    let compositor = unsafe { &mut *addr_of_mut!(COMPOSITOR) };
    compositor.set_config(Config {
        display_wakes,
        ..Config::DEFAULT
    });
    if compositor.start(&mut display).is_err() {
        exit();
    }
    let input: &mut dyn InputSource = match kernel_input.as_mut() {
        Some(input) => input,
        None => &mut no_input,
    };
    let mut io = Io {
        port: &mut port,
        buffers: &mut buffers,
        display: &mut display,
        input,
        waiter: &mut waiter,
    };
    while compositor.iterate(&mut io).is_ok() {}
    exit();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    exit();
}
