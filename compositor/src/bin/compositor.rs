//! CPL3 compositor service: the thin kernel adapter around `clean_slate_compositor`.
//!
//! Every trait in `clean_slate_compositor::backend` is implemented here over the frozen native
//! ABI (syscalls 16–20); the core never issues a syscall. The adapter names no device: the
//! display is reached only through syscall 18, identical for every scanout backend.
//!
//! Startup reads the [`DesktopLaunchPage`] (resource id, console, quality tier and, in
//! `fault-keys` builds only, the self-test fault key) the #118 launch policy writes, finds its
//! `Graphics{GFX_SERVE}`,
//! `Display` and (optional) `Input` capabilities, creates its work set and binds every wake
//! source it can. Display `BIND_WAKE` follows the first `MAP_SCANOUT`, which makes the compositor
//! the presenter; if either fails, completion falls back to a bounded deadline while a present is
//! in flight, which needs a calibrated clock. With neither the display wake nor a clock the
//! compositor exits rather than spin, and every `WAIT` blocks (never `NONBLOCK`). Input is read
//! only on its own wake bit, so the compositor consumes input only once syscall 19 `BIND_WAKE`
//! succeeds (it also makes the compositor the seat consumer); otherwise it runs without input.
//! Neither adds an idle poll.
//!
//! Client pixels are copied out of the shared window with volatile loads, never referenced, and
//! each transferred child capability is released with `CAP_REVOKE` `DROP` once unmapped.

#![no_std]
#![no_main]

use core::ptr::addr_of_mut;

use clean_slate_capability::syscall_abi::{CAP_REVOKE_OP_DROP, SYSCALL_NR_CAP_REVOKE};
use clean_slate_capability::ResourceClass;
use clean_slate_compositor::backend::{
    can_observe_presents, BufferMapping, DisplayBackend, InputFailure, InputSource, MapFailure,
    NoInput, PortFailure, PortServer, SharedBufferMapper, WaitFailure, WaitRequest, WorkWaiter,
    WAKE_DISPLAY, WAKE_INPUT, WAKE_NOTICES, WAKE_REQUESTS,
};
use clean_slate_compositor::diag::{self, DiagTracker};
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
#[cfg(feature = "fault-keys")]
use clean_slate_graphics::input::{KeyState, KeyUsage};
use clean_slate_graphics::limits::SCANOUT_BUFFER_COUNT;
use clean_slate_graphics::protocol::DisconnectReason;
#[cfg(feature = "fault-keys")]
use clean_slate_graphics::raw_input::RawInputKind;
use clean_slate_graphics::raw_input::{RawInputRecord, RAW_INPUT_RECORD_BYTES};
use clean_slate_native_abi::desktop::{
    ConsoleLine, DesktopLaunchPage, DESKTOP_LAUNCH_ADDRESS, SYSCALL_NR_IPC_SEND,
};
use clean_slate_native_abi::port::{
    PORT_OP_BIND_WAKE, PORT_OP_DISCONNECT, PORT_OP_FIND_HANDLE, PORT_OP_POST, PORT_OP_RECV,
    PORT_RECV_NONBLOCK, PORT_ROLE_SERVE,
};
use clean_slate_native_abi::work_set::{WORK_SET_OP_CREATE, WORK_SET_OP_NOW, WORK_SET_OP_WAIT};
use clean_slate_native_abi::{
    is_status, ConnectionId, PortRecvRecord, TransferredCap, SHARED_BUFFER_ACCESS_READ,
    SHARED_BUFFER_SUBOP_MAP, SHARED_BUFFER_SUBOP_UNMAP, STATUS_EAGAIN, STATUS_ENOSPC, STATUS_EPIPE,
    STATUS_ESTALE, STATUS_ETIMEDOUT, SYSCALL_NR_SERVICE_PORT, SYSCALL_NR_SHARED_BUFFER,
    SYSCALL_NR_WORK_SET,
};
use clean_slate_ui::shell::ShellConfig;
use clean_slate_ui::{QualityTier, CLEAN_SLATE_DARK};

const SYSCALL_NR_DISPLAY: u64 = 18;
const SYSCALL_NR_INPUT: u64 = 19;
/// HID usage of F11, the compositor's self-test fault key.
#[cfg(feature = "fault-keys")]
const KEY_F11: u16 = 0x44;

static mut COMPOSITOR: Compositor<DefaultPolicy> =
    Compositor::new(DefaultPolicy::new(), Config::DEFAULT);
static mut DIAG: DiagTracker = DiagTracker::new();

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

    fn read(&self, mapping: &BufferMapping, offset: u64, dst: &mut [u8]) -> bool {
        let Some(end) = offset.checked_add(dst.len() as u64) else {
            return false;
        };
        let Some(start) = mapping.token.checked_add(offset) else {
            return false;
        };
        if mapping.token == 0 || end > mapping.byte_len {
            return false;
        }
        // The kernel mapped at least `byte_len` readable bytes at `token` and keeps the row (or
        // its zero-page orphan) until `unmap`, which takes the mapping by value. The client
        // writes the same frames concurrently, so they are only ever read volatilely.
        unsafe { volatile_copy(start as *const u8, dst) };
        true
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
    /// `DROP` releases only this process's child record; the client's root and mapping are
    /// untouched. Called after `UNMAP`, so the kernel's "still mapped" `EAGAIN` cannot occur, and
    /// `ESTALE` (already purged by a client revoke) needs no handling.
    fn discard_handle(&mut self, handle: u64) {
        syscall(SYSCALL_NR_CAP_REVOKE, CAP_REVOKE_OP_DROP, handle, 0, 0, 0);
    }
}

/// Copies `dst.len()` bytes from `src` with volatile loads: `u64` words over the aligned middle,
/// bytes at either end.
///
/// # Safety
///
/// `src..src + dst.len()` must stay mapped and readable for the whole call.
unsafe fn volatile_copy(src: *const u8, dst: &mut [u8]) {
    let len = dst.len();
    let head = src.align_offset(core::mem::align_of::<u64>()).min(len);
    let mut at = 0;
    while at < head {
        dst[at] = unsafe { core::ptr::read_volatile(src.add(at)) };
        at += 1;
    }
    while at + 8 <= len {
        let word = unsafe { core::ptr::read_volatile(src.add(at).cast::<u64>()) };
        dst[at..at + 8].copy_from_slice(&word.to_ne_bytes());
        at += 8;
    }
    while at < len {
        dst[at] = unsafe { core::ptr::read_volatile(src.add(at)) };
        at += 1;
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
    /// Self-test launches only: F11 makes the compositor crash (an invalid opcode) so the
    /// desktop lane can prove compositor restart.
    #[cfg(feature = "fault-keys")]
    fault_key_armed: bool,
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
                #[cfg(feature = "fault-keys")]
                if self.fault_key_armed
                    && matches!(
                        record.kind,
                        RawInputKind::Key {
                            usage: KeyUsage(KEY_F11),
                            state: KeyState::Pressed,
                        }
                    )
                {
                    unsafe { core::arch::asm!("ud2", options(noreturn)) };
                }
                sink(record);
            }
        }
        Ok(count)
    }
}

struct KernelWorkSet {
    id: u64,
    /// `WORK_SET NOW` succeeds (the TSC is calibrated). A deadline `WAIT` needs it; without it
    /// every wait blocks on wake bits alone (see [`WaitRequest::plan`]).
    has_clock: bool,
}

impl WorkWaiter for KernelWorkSet {
    fn wait(&mut self, mask: u32, deadline_ns: Option<u64>) -> Result<u32, WaitFailure> {
        let deadline = match WaitRequest::plan(deadline_ns, self.has_clock) {
            WaitRequest::Until(deadline) => deadline.max(1),
            WaitRequest::Forever => 0,
        };
        let raw = syscall(
            SYSCALL_NR_WORK_SET,
            WORK_SET_OP_WAIT,
            self.id,
            u64::from(mask),
            deadline,
            0,
        );
        match checked(raw) {
            Ok(bits) => Ok(bits as u32),
            Err(STATUS_ETIMEDOUT) => Ok(0),
            Err(status) => Err(WaitFailure(status)),
        }
    }

    fn now_ns(&mut self) -> u64 {
        checked(syscall(SYSCALL_NR_WORK_SET, WORK_SET_OP_NOW, 0, 0, 0, 0)).unwrap_or(0)
    }
}

fn console(boot: &DesktopLaunchPage, line: &ConsoleLine) {
    if let Some(handle) = boot.console() {
        let bytes = line.as_bytes();
        syscall(
            SYSCALL_NR_IPC_SEND,
            handle,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
            0,
            0,
        );
    }
}

fn exit() -> ! {
    unsafe {
        core::arch::asm!("int 0x80", options(noreturn));
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // SAFETY: the launch policy maps and fills the launch page before entry.
    let boot = unsafe { *(DESKTOP_LAUNCH_ADDRESS as *const DesktopLaunchPage) };
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
    let mut display = KernelDisplay {
        handle: display_handle,
        scanout: [None; SCANOUT_BUFFER_COUNT],
    };
    // Display `BIND_WAKE` is presenter-only, and the first `MAP_SCANOUT` binds the presenter.
    let display_wakes = display.scanout(0).is_ok()
        && checked(syscall(
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
    let mut kernel_input = input_handle.map(|handle| KernelInput {
        handle,
        #[cfg(feature = "fault-keys")]
        fault_key_armed: boot.fault_key_armed(),
    });
    let mut no_input = NoInput;
    let mut waiter = KernelWorkSet {
        id: work_set,
        has_clock: checked(syscall(SYSCALL_NR_WORK_SET, WORK_SET_OP_NOW, 0, 0, 0, 0)).is_ok(),
    };
    if !can_observe_presents(waiter.has_clock, display_wakes) {
        exit();
    }

    let compositor = unsafe { &mut *addr_of_mut!(COMPOSITOR) };
    let tier = if boot.is_opaque_tier() {
        QualityTier::Q0
    } else {
        QualityTier::Q1
    };
    *compositor.policy_mut() = DefaultPolicy::with_theme(&CLEAN_SLATE_DARK, tier, ShellConfig::M10);
    compositor.set_config(Config {
        display_wakes,
        ..Config::DEFAULT
    });
    if compositor.start(&mut display).is_err() {
        console(&boot, &diag::exit_line("start-failed"));
        exit();
    }
    if let Ok(mode) = display.query_mode() {
        console(
            &boot,
            &diag::started_line(
                mode.mode.width_px,
                mode.mode.height_px,
                boot.is_opaque_tier(),
            ),
        );
    }
    let tracker = unsafe { &mut *addr_of_mut!(DIAG) };
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
    while compositor.iterate(&mut io).is_ok() {
        tracker.observe(compositor, &mut |line| console(&boot, &line));
    }
    console(&boot, &diag::exit_line("service-error"));
    exit();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    exit();
}
