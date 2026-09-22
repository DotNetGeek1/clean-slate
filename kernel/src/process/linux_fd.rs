//! Linux stdio / file-descriptor projection onto Clean-Slate IPC capabilities (#95).
//!
//! Linux `fd` integers are compatibility-local references only. They are **not**
//! capabilities and never confer authority by themselves. Each open projection
//! stores a real `IpcEndpointTable` send-capability handle that was granted to
//! the owning pid by trusted bootstrap code. [`write_fd`] always routes through
//! [`IpcEndpointTable::send_message`] so holder, generation, and endpoint checks
//! apply.
//!
//! The table lives in a kernel-owned registry keyed by `(pid, InstanceGeneration)`,
//! not as a field on [`super::Process`], so spawn / Process-literal sites stay
//! untouched and a replacement process (same pid, new generation) cannot inherit
//! a prior instance's projections.
//!
//! Core logic is implemented on [`LinuxFdRegistry`] taking an explicit
//! `&mut IpcEndpointTable` so host tests can use local instances without
//! mutating process-global IPC / fd tables.

// #94 (`write`/`exit`) and #97 (Linux launch bootstrap) consume install/write/
// projection; production teardown already calls `release_for_process`.
#![allow(dead_code)]

use clean_slate_linux_abi::{LinuxErrno, EACCES, EBADF, EINVAL};
use clean_slate_service_lifecycle::InstanceGeneration;

use super::personality::ExecutionPersonality;
use super::process_registry_mut;
use super::KERNEL_PROCESS_ID;
use super::PROCESS_REGISTRY_CAPACITY;
use crate::diagnostics::log::kernel_log_fmt;
#[cfg(not(test))]
use crate::diagnostics::serial::serial_write_bytes;
use crate::ipc::endpoint_table_mut;
use crate::ipc::IpcEndpointKind;
use crate::ipc::IpcEndpointTable;
use crate::ipc::IpcSendError;
use crate::ipc::IPC_MAX_MESSAGE_BYTES;
use crate::sync::global_cell::GlobalCell;

/// Per-process Linux fd table size: fds `0..LINUX_FD_TABLE_CAPACITY` (stdin /
/// stdout / stderr / one spare). M8 only installs stdout/stderr; keeping the
/// table small matches the fixture contract and leaves room for a closed stdin
/// without inventing M9 filesystem breadth.
pub(crate) const LINUX_FD_TABLE_CAPACITY: usize = 4;

/// Registry slots: one optional fd table per live process registry entry.
/// Derived from [`PROCESS_REGISTRY_CAPACITY`] so the bound tracks process
/// accounting rather than inventing a separate soft limit.
const LINUX_FD_REGISTRY_CAPACITY: usize = PROCESS_REGISTRY_CAPACITY;

/// Linux stdout (fd 1).
pub(crate) const LINUX_STDOUT_FD: u64 = 1;
/// Linux stderr (fd 2).
pub(crate) const LINUX_STDERR_FD: u64 = 2;

/// Projection of a Linux fd onto Clean-Slate authority (or closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinuxFdProjection {
    /// Descriptor is not open; [`write_fd`] returns [`EBADF`].
    Closed,
    /// Send-capability handle for a granted `ConsoleSink` (or future kinds).
    /// The `u64` is an `IpcEndpointTable` capability handle, never a Linux fd.
    ConsoleEndpoint { capability_handle: u64 },
}

impl LinuxFdProjection {
    const fn closed() -> Self {
        Self::Closed
    }
}

/// How a ConsoleSink message from the Linux fd path is rendered on serial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConsoleSinkRenderStyle {
    /// Payload bytes as UTF-8 with no `[IPC ]` framing (Linux personality).
    Verbatim,
    /// Historical `[IPC ] console pid=N: <msg>\n` framing (native personality).
    NativeFramed,
}

/// Pure render-style decision from trusted personality (host-testable).
pub(crate) const fn console_sink_render_style(
    personality: ExecutionPersonality,
) -> ConsoleSinkRenderStyle {
    match personality {
        ExecutionPersonality::LinuxX86_64 => ConsoleSinkRenderStyle::Verbatim,
        ExecutionPersonality::Native => ConsoleSinkRenderStyle::NativeFramed,
    }
}

/// Bounded per-process Linux fd table (compatibility view only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LinuxFdTable {
    entries: [LinuxFdProjection; LINUX_FD_TABLE_CAPACITY],
}

impl LinuxFdTable {
    const fn empty() -> Self {
        Self {
            entries: [LinuxFdProjection::closed(); LINUX_FD_TABLE_CAPACITY],
        }
    }

    fn get(&self, fd: u64) -> Option<LinuxFdProjection> {
        let index = usize::try_from(fd).ok()?;
        self.entries.get(index).copied()
    }

    fn set(&mut self, fd: usize, projection: LinuxFdProjection) {
        if let Some(slot) = self.entries.get_mut(fd) {
            *slot = projection;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LinuxFdRegistrySlot {
    pid: u64,
    generation: InstanceGeneration,
    table: LinuxFdTable,
}

/// Kernel-owned registry of Linux fd tables keyed by `(pid, generation)`.
pub(crate) struct LinuxFdRegistry {
    slots: [Option<LinuxFdRegistrySlot>; LINUX_FD_REGISTRY_CAPACITY],
}

impl LinuxFdRegistry {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [None; LINUX_FD_REGISTRY_CAPACITY],
        }
    }

    pub(crate) fn occupied(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    fn find_slot_mut(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
    ) -> Option<&mut LinuxFdRegistrySlot> {
        self.slots.iter_mut().find_map(|slot| match slot {
            Some(entry) if entry.pid == pid && entry.generation == generation => Some(entry),
            _ => None,
        })
    }

    fn find_slot(&self, pid: u64, generation: InstanceGeneration) -> Option<&LinuxFdRegistrySlot> {
        self.slots.iter().find_map(|slot| match slot {
            Some(entry) if entry.pid == pid && entry.generation == generation => Some(entry),
            _ => None,
        })
    }

    /// Install stdout (fd 1) / stderr (fd 2) projections.
    ///
    /// Does **not** validate that `stdout_handle` / `stderr_handle` are currently
    /// held by `pid` — that check happens later in
    /// [`IpcEndpointTable::send_message`] when [`Self::write_fd`] runs. Callers
    /// may pass the same handle for both fds (M8: one shared console grant;
    /// stderr is not distinguishable on serial).
    ///
    /// Rejects [`KERNEL_PROCESS_ID`]: the kernel is not a Linux-personality
    /// process and must not own a compatibility fd table.
    pub(crate) fn install(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
        stdout_handle: u64,
        stderr_handle: u64,
    ) -> Result<(), &'static str> {
        if pid == KERNEL_PROCESS_ID {
            return Err("linux fd table cannot be installed for the kernel process");
        }
        if let Some(existing) = self.find_slot_mut(pid, generation) {
            existing.table = LinuxFdTable::empty();
            existing.table.set(
                LINUX_STDOUT_FD as usize,
                LinuxFdProjection::ConsoleEndpoint {
                    capability_handle: stdout_handle,
                },
            );
            existing.table.set(
                LINUX_STDERR_FD as usize,
                LinuxFdProjection::ConsoleEndpoint {
                    capability_handle: stderr_handle,
                },
            );
            return Ok(());
        }
        let free = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or("linux fd registry capacity exceeded")?;
        let mut table = LinuxFdTable::empty();
        table.set(
            LINUX_STDOUT_FD as usize,
            LinuxFdProjection::ConsoleEndpoint {
                capability_handle: stdout_handle,
            },
        );
        table.set(
            LINUX_STDERR_FD as usize,
            LinuxFdProjection::ConsoleEndpoint {
                capability_handle: stderr_handle,
            },
        );
        *free = Some(LinuxFdRegistrySlot {
            pid,
            generation,
            table,
        });
        Ok(())
    }

    /// Look up the projection for `fd` under `(pid, generation)`.
    pub(crate) fn projection_for(
        &self,
        pid: u64,
        generation: InstanceGeneration,
        fd: u64,
    ) -> Result<LinuxFdProjection, LinuxErrno> {
        let slot = self.find_slot(pid, generation).ok_or(EBADF)?;
        slot.table.get(fd).ok_or(EBADF)
    }

    /// Release the fd table for `(pid, generation)` if present (idempotent).
    pub(crate) fn release(&mut self, pid: u64, generation: InstanceGeneration) -> bool {
        for slot in &mut self.slots {
            if let Some(entry) = slot {
                if entry.pid == pid && entry.generation == generation {
                    *slot = None;
                    return true;
                }
            }
        }
        false
    }

    /// Write `bytes` through the capability projected by Linux `fd`.
    ///
    /// Routes through `ipc.send_message(pid, handle, …)` so ownership and
    /// generation checks apply. `personality` selects ConsoleSink serial
    /// framing ([`console_sink_render_style`]); the global wrapper resolves it
    /// from the process registry.
    pub(crate) fn write_fd(
        &mut self,
        ipc: &mut IpcEndpointTable,
        pid: u64,
        generation: InstanceGeneration,
        fd: u64,
        bytes: &[u8],
        personality: ExecutionPersonality,
    ) -> Result<usize, LinuxErrno> {
        let projection = self.projection_for(pid, generation, fd)?;
        let handle = match projection {
            LinuxFdProjection::Closed => return Err(EBADF),
            LinuxFdProjection::ConsoleEndpoint { capability_handle } => capability_handle,
        };
        if bytes.is_empty() {
            return Ok(0);
        }
        let send_len = core::cmp::min(bytes.len(), IPC_MAX_MESSAGE_BYTES);
        let payload = &bytes[..send_len];
        match ipc.send_message(pid, handle, payload) {
            Ok(result) => {
                if result.endpoint_kind == IpcEndpointKind::ConsoleSink {
                    emit_console_sink_render(console_sink_render_style(personality), pid, payload);
                }
                Ok(result.bytes_sent)
            }
            Err(error) => Err(map_ipc_send_error(error)),
        }
    }
}

static LINUX_FD_REGISTRY: GlobalCell<LinuxFdRegistry> = GlobalCell::new(LinuxFdRegistry::new());

fn registry_mut() -> &'static mut LinuxFdRegistry {
    unsafe { &mut *LINUX_FD_REGISTRY.get() }
}

/// Map an IPC send failure onto a Linux errno for the fd projection path.
///
/// | `IpcSendError`           | Linux errno | Rationale |
/// |--------------------------|-------------|-----------|
/// | `InvalidCapability`      | `EBADF`     | Handle does not name a live capability; fd projection is unusable. |
/// | `StaleCapability`        | `EBADF`     | Retired/generation-mismatched handle; treat as bad descriptor. |
/// | `Unauthorized`           | `EACCES`    | Handle exists but is not held by this pid (fd integer is not authority). |
/// | `InvalidMessageLength`   | `EINVAL`    | Should not occur after short-write truncation; fail closed. |
pub(crate) const fn map_ipc_send_error(error: IpcSendError) -> LinuxErrno {
    match error {
        IpcSendError::InvalidCapability | IpcSendError::StaleCapability => EBADF,
        IpcSendError::Unauthorized => EACCES,
        IpcSendError::InvalidMessageLength => EINVAL,
    }
}

/// Install stdout (fd 1) and stderr (fd 2) projections for a process instance.
///
/// Trusted bootstrap only. Does **not** validate that the handles are currently
/// held by `pid` — [`write_fd`] / `send_message` enforce that. M8 callers should
/// pass the **same** console capability for both fds (shared kernel ConsoleSink
/// grant); stderr is not distinguishable from stdout on serial in M8.
///
/// Rejects [`KERNEL_PROCESS_ID`]. fd 0 and fd 3 remain [`LinuxFdProjection::Closed`].
pub(crate) fn install_stdio_for_process(
    pid: u64,
    generation: InstanceGeneration,
    stdout_handle: u64,
    stderr_handle: u64,
) -> Result<(), &'static str> {
    registry_mut().install(pid, generation, stdout_handle, stderr_handle)
}

/// Look up the projection for `fd` under a trusted `(pid, generation)`.
///
/// Used by #94 (`write`/`exit`) after resolving the caller from scheduler /
/// syscall context. Stale generation or missing registry entry → [`EBADF`].
pub(crate) fn projection_for(
    pid: u64,
    generation: InstanceGeneration,
    fd: u64,
) -> Result<LinuxFdProjection, LinuxErrno> {
    registry_mut().projection_for(pid, generation, fd)
}

/// Write `bytes` through the capability projected by Linux `fd`.
///
/// - Out-of-range / closed / missing / stale `(pid, generation)` → [`EBADF`].
/// - Empty write returns `Ok(0)` without touching IPC (Linux allows a zero-length write).
/// - Writes longer than [`IPC_MAX_MESSAGE_BYTES`] (64) return a **short write**:
///   only the first 64 bytes are sent and the returned length is `64`. #94
///   decides whether the Linux `write` handler loops for the remainder.
/// - On success for a `ConsoleSink`, serial output uses
///   [`console_sink_render_style`] for the sender's trusted personality.
pub(crate) fn write_fd(
    pid: u64,
    generation: InstanceGeneration,
    fd: u64,
    bytes: &[u8],
) -> Result<usize, LinuxErrno> {
    let personality = unsafe { process_registry_mut().get(pid) }
        .map(|process| process.execution_personality)
        .unwrap_or(ExecutionPersonality::Native);
    registry_mut().write_fd(
        unsafe { endpoint_table_mut() },
        pid,
        generation,
        fd,
        bytes,
        personality,
    )
}

/// Release the fd table for `(pid, generation)` if present.
///
/// Idempotent: missing / mismatched generation is a no-op. Production teardown
/// in [`super::domain`] calls this so a replacement process with a new
/// generation starts with a fresh table.
pub(crate) fn release_for_process(pid: u64, generation: InstanceGeneration) {
    let _ = registry_mut().release(pid, generation);
}

/// Deliver Linux ConsoleSink payload bytes to the host serial device.
///
/// This is the **only** path by which Linux-personality stdio payload bytes
/// reach serial (#144 / #147 contract). Callers must pass the exact IPC chunk
/// bytes; chunking at 64 bytes is invisible to this function — each invocation
/// is rendered independently and must not reinterpret bytes as UTF-8.
pub(crate) fn console_write_bytes(bytes: &[u8]) {
    #[cfg(feature = "m8-linux-dispatch-self-test")]
    crate::selftest::m8_linux_dispatch::observe_linux_console_write_bytes(bytes);

    #[cfg(test)]
    {
        linux_console_byte_test_sink::capture(bytes);
    }

    #[cfg(not(test))]
    serial_write_bytes(bytes);
}

/// Apply ConsoleSink serial rendering for the Linux fd path.
///
/// **Decision (M8.5):** reuse `IpcEndpointKind::ConsoleSink` — no new endpoint
/// kind, no raw console syscall, no new resource class. Linux personality →
/// byte-transparent payload via [`console_write_bytes`]. Native personality on
/// this path keeps framed lines; the native `ipc_send` syscall handler is
/// unchanged.
fn emit_console_sink_render(style: ConsoleSinkRenderStyle, sender_pid: u64, payload: &[u8]) {
    match style {
        ConsoleSinkRenderStyle::Verbatim => console_write_bytes(payload),
        ConsoleSinkRenderStyle::NativeFramed => {
            let message = core::str::from_utf8(payload).unwrap_or("<non-utf8>");
            kernel_log_fmt(format_args!("[IPC ] console pid={sender_pid}: {message}\n"));
        }
    }
}

#[cfg(test)]
mod linux_console_byte_test_sink {
    use std::cell::RefCell;

    thread_local! {
        static CAPTURE: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) fn reset() {
        CAPTURE.with(|capture| capture.borrow_mut().clear());
    }

    pub(super) fn capture(bytes: &[u8]) {
        CAPTURE.with(|capture| capture.borrow_mut().extend_from_slice(bytes));
    }

    pub(super) fn take() -> Vec<u8> {
        CAPTURE.with(|capture| capture.borrow().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IPC_CAPABILITY_CAPACITY, IPC_ENDPOINT_CAPACITY};

    fn local_pair() -> (LinuxFdRegistry, IpcEndpointTable) {
        (LinuxFdRegistry::new(), IpcEndpointTable::new())
    }

    #[test]
    fn install_and_lookup_stdio_projections() {
        let (mut fds, mut ipc) = local_pair();
        let generation = InstanceGeneration(3);
        let handle = ipc
            .grant_console_capability_for_pid(10)
            .expect("shared console grant");
        // M8: stdout and stderr project the same console capability.
        fds.install(10, generation, handle, handle)
            .expect("install");

        assert_eq!(
            fds.projection_for(10, generation, LINUX_STDOUT_FD)
                .expect("stdout"),
            LinuxFdProjection::ConsoleEndpoint {
                capability_handle: handle
            }
        );
        assert_eq!(
            fds.projection_for(10, generation, LINUX_STDERR_FD)
                .expect("stderr"),
            LinuxFdProjection::ConsoleEndpoint {
                capability_handle: handle
            }
        );
        assert_eq!(
            fds.projection_for(10, generation, 0).expect("stdin closed"),
            LinuxFdProjection::Closed
        );
        assert_eq!(fds.projection_for(10, generation, 99), Err(EBADF));
    }

    #[test]
    fn install_rejects_kernel_process_id() {
        let (mut fds, _) = local_pair();
        assert!(fds
            .install(KERNEL_PROCESS_ID, InstanceGeneration(1), 1, 1)
            .is_err());
    }

    #[test]
    fn write_fd_ebadf_for_closed_and_invalid() {
        let (mut fds, mut ipc) = local_pair();
        let generation = InstanceGeneration(1);
        let handle = ipc.grant_console_capability_for_pid(11).expect("grant");
        fds.install(11, generation, handle, handle)
            .expect("install");

        assert_eq!(
            fds.write_fd(
                &mut ipc,
                11,
                generation,
                0,
                b"x",
                ExecutionPersonality::LinuxX86_64
            ),
            Err(EBADF),
            "closed stdin"
        );
        assert_eq!(
            fds.write_fd(
                &mut ipc,
                11,
                generation,
                99,
                b"x",
                ExecutionPersonality::LinuxX86_64
            ),
            Err(EBADF),
            "out of range"
        );
        assert_eq!(
            fds.write_fd(
                &mut ipc,
                11,
                InstanceGeneration(99),
                LINUX_STDOUT_FD,
                b"x",
                ExecutionPersonality::LinuxX86_64
            ),
            Err(EBADF),
            "stale generation"
        );
    }

    #[test]
    fn registry_exhaustion_is_deterministic() {
        let (mut fds, _) = local_pair();
        for i in 0..LINUX_FD_REGISTRY_CAPACITY {
            let pid = 100 + i as u64;
            fds.install(pid, InstanceGeneration(1), 1, 2)
                .expect("fill registry");
        }
        assert_eq!(fds.occupied(), LINUX_FD_REGISTRY_CAPACITY);
        assert!(fds.install(999, InstanceGeneration(1), 1, 2).is_err());
    }

    #[test]
    fn release_clears_table_and_stale_generation_fails_closed() {
        let (mut fds, mut ipc) = local_pair();
        let generation = InstanceGeneration(4);
        let handle = ipc.grant_console_capability_for_pid(12).expect("grant");
        fds.install(12, generation, handle, handle)
            .expect("install");
        fds.release(12, generation);
        assert_eq!(
            fds.projection_for(12, generation, LINUX_STDOUT_FD),
            Err(EBADF)
        );
        assert_eq!(
            fds.write_fd(
                &mut ipc,
                12,
                generation,
                LINUX_STDOUT_FD,
                b"hello",
                ExecutionPersonality::LinuxX86_64
            ),
            Err(EBADF)
        );
    }

    #[test]
    fn replacement_process_does_not_inherit_prior_table() {
        let (mut fds, mut ipc) = local_pair();
        let gen1 = InstanceGeneration(1);
        let gen2 = InstanceGeneration(2);
        let handle1 = ipc
            .grant_console_capability_for_pid(13)
            .expect("grant gen1");
        fds.install(13, gen1, handle1, handle1)
            .expect("install gen1");
        fds.release(13, gen1);
        ipc.teardown_resources_for_pid(13)
            .expect("teardown gen1 caps");

        let handle2 = ipc
            .grant_console_capability_for_pid(13)
            .expect("grant gen2");
        fds.install(13, gen2, handle2, handle2)
            .expect("install gen2");

        assert_eq!(
            fds.projection_for(13, gen1, LINUX_STDOUT_FD),
            Err(EBADF),
            "old generation must not see a table"
        );
        assert_eq!(
            fds.projection_for(13, gen2, LINUX_STDOUT_FD)
                .expect("new table"),
            LinuxFdProjection::ConsoleEndpoint {
                capability_handle: handle2
            }
        );
        assert_ne!(handle1, handle2);
    }

    #[test]
    fn naming_fd_one_without_grant_yields_no_output() {
        let (mut fds, mut ipc) = local_pair();
        let generation = InstanceGeneration(1);
        let foreign = ipc
            .grant_console_capability_for_pid(50)
            .expect("grant to other pid");
        fds.install(51, generation, foreign, foreign)
            .expect("install ungranted");

        assert_eq!(
            fds.write_fd(
                &mut ipc,
                51,
                generation,
                LINUX_STDOUT_FD,
                b"secret",
                ExecutionPersonality::LinuxX86_64
            ),
            Err(EACCES),
            "ungranted handle must be rejected by IpcEndpointTable"
        );
        assert_eq!(
            ipc.endpoint_message(0),
            Some(&b""[..]),
            "no payload delivered without a real grant to the writer pid"
        );
    }

    #[test]
    fn authorized_write_delivers_through_real_endpoint_table() {
        let (mut fds, mut ipc) = local_pair();
        let generation = InstanceGeneration(7);
        let handle = ipc.grant_console_capability_for_pid(20).expect("grant");
        fds.install(20, generation, handle, handle)
            .expect("install");

        assert_eq!(
            fds.write_fd(
                &mut ipc,
                20,
                generation,
                LINUX_STDOUT_FD,
                b"Hello from Linux.\n",
                ExecutionPersonality::LinuxX86_64
            ),
            Ok(18)
        );
        assert_eq!(ipc.endpoint_message(0), Some(&b"Hello from Linux.\n"[..]));
    }

    #[test]
    fn short_write_caps_at_ipc_max_message_bytes() {
        let (mut fds, mut ipc) = local_pair();
        let generation = InstanceGeneration(1);
        let handle = ipc.grant_console_capability_for_pid(21).expect("grant");
        fds.install(21, generation, handle, handle)
            .expect("install");

        let mut oversized = [b'a'; IPC_MAX_MESSAGE_BYTES + 8];
        oversized[0] = b'H';
        assert_eq!(
            fds.write_fd(
                &mut ipc,
                21,
                generation,
                LINUX_STDOUT_FD,
                &oversized,
                ExecutionPersonality::LinuxX86_64
            ),
            Ok(IPC_MAX_MESSAGE_BYTES)
        );
        let delivered = ipc.endpoint_message(0).expect("message");
        assert_eq!(delivered.len(), IPC_MAX_MESSAGE_BYTES);
        assert_eq!(delivered[0], b'H');
    }

    #[test]
    fn empty_write_returns_zero_without_ipc() {
        let (mut fds, mut ipc) = local_pair();
        let generation = InstanceGeneration(1);
        let handle = ipc.grant_console_capability_for_pid(22).expect("grant");
        fds.install(22, generation, handle, handle)
            .expect("install");
        assert_eq!(
            fds.write_fd(
                &mut ipc,
                22,
                generation,
                LINUX_STDOUT_FD,
                b"",
                ExecutionPersonality::LinuxX86_64
            ),
            Ok(0)
        );
    }

    #[test]
    fn shared_console_sink_survives_sequential_grant_teardown_cycles() {
        let (mut fds, mut ipc) = local_pair();
        // Exceed both endpoint and capability capacities: if each grant created
        // a new ConsoleSink, this would fail. Shared sink + cap retirement must
        // keep occupied resources flat across cycles.
        let cycles = IPC_ENDPOINT_CAPACITY.max(IPC_CAPABILITY_CAPACITY) + 4;
        let pid = 40u64;
        let mut generation = InstanceGeneration(1);

        for _ in 0..cycles {
            let handle = ipc
                .grant_console_capability_for_pid(pid)
                .expect("grant on shared sink");
            fds.install(pid, generation, handle, handle)
                .expect("install");
            assert_eq!(
                fds.write_fd(
                    &mut ipc,
                    pid,
                    generation,
                    LINUX_STDOUT_FD,
                    b"hi",
                    ExecutionPersonality::LinuxX86_64
                ),
                Ok(2)
            );
            fds.release(pid, generation);
            ipc.teardown_resources_for_pid(pid)
                .expect("release holder capabilities");

            let resources = ipc.active_resources();
            assert_eq!(
                resources.owned_endpoints, 1,
                "shared kernel ConsoleSink must remain the sole endpoint"
            );
            assert_eq!(
                resources.held_capabilities, 0,
                "holder capabilities must be reclaimed each cycle"
            );
            generation = InstanceGeneration(generation.0 + 1);
        }
    }

    #[test]
    fn teardown_stales_old_handle_and_fresh_grant_works() {
        let (mut fds, mut ipc) = local_pair();
        let gen1 = InstanceGeneration(1);
        let gen2 = InstanceGeneration(2);
        let pid = 41u64;
        let old_handle = ipc
            .grant_console_capability_for_pid(pid)
            .expect("first grant");
        fds.install(pid, gen1, old_handle, old_handle)
            .expect("install");

        fds.release(pid, gen1);
        ipc.teardown_resources_for_pid(pid).expect("teardown caps");

        assert_eq!(
            ipc.send_message(pid, old_handle, b"x"),
            Err(IpcSendError::StaleCapability)
        );
        assert_eq!(
            fds.write_fd(
                &mut ipc,
                pid,
                gen1,
                LINUX_STDOUT_FD,
                b"x",
                ExecutionPersonality::LinuxX86_64
            ),
            Err(EBADF),
            "old (pid, generation) must fail closed"
        );

        let new_handle = ipc
            .grant_console_capability_for_pid(pid)
            .expect("fresh grant");
        fds.install(pid, gen2, new_handle, new_handle)
            .expect("reinstall");
        assert_eq!(
            fds.write_fd(
                &mut ipc,
                pid,
                gen2,
                LINUX_STDOUT_FD,
                b"ok",
                ExecutionPersonality::LinuxX86_64
            ),
            Ok(2)
        );
        assert_ne!(old_handle, new_handle);
        assert_eq!(ipc.active_resources().owned_endpoints, 1);
    }

    #[test]
    fn map_ipc_send_error_documents_linux_mapping() {
        assert_eq!(map_ipc_send_error(IpcSendError::InvalidCapability), EBADF);
        assert_eq!(map_ipc_send_error(IpcSendError::StaleCapability), EBADF);
        assert_eq!(map_ipc_send_error(IpcSendError::Unauthorized), EACCES);
        assert_eq!(
            map_ipc_send_error(IpcSendError::InvalidMessageLength),
            EINVAL
        );
    }

    #[test]
    fn linux_fd_registry_capacity_tracks_process_registry() {
        assert_eq!(LINUX_FD_REGISTRY_CAPACITY, PROCESS_REGISTRY_CAPACITY);
        assert_eq!(LINUX_FD_TABLE_CAPACITY, 4);
    }

    #[test]
    fn linux_personality_renders_verbatim_native_framed() {
        assert_eq!(
            console_sink_render_style(ExecutionPersonality::LinuxX86_64),
            ConsoleSinkRenderStyle::Verbatim
        );
        assert_eq!(
            console_sink_render_style(ExecutionPersonality::Native),
            ConsoleSinkRenderStyle::NativeFramed
        );
    }

    #[test]
    fn grant_console_reuses_single_kernel_owned_sink() {
        let mut ipc = IpcEndpointTable::new();
        let _h1 = ipc
            .grant_console_capability_for_pid(1)
            .expect("first grant creates sink");
        let _h2 = ipc
            .grant_console_capability_for_pid(2)
            .expect("second grant reuses sink");
        assert_eq!(ipc.active_resources().owned_endpoints, 1);
        assert_eq!(ipc.active_resources().held_capabilities, 2);
    }

    fn capture_verbatim_write(
        fds: &mut LinuxFdRegistry,
        ipc: &mut IpcEndpointTable,
        pid: u64,
        generation: InstanceGeneration,
        bytes: &[u8],
    ) -> usize {
        linux_console_byte_test_sink::reset();
        let written = fds
            .write_fd(
                ipc,
                pid,
                generation,
                LINUX_STDOUT_FD,
                bytes,
                ExecutionPersonality::LinuxX86_64,
            )
            .expect("write");
        assert_eq!(linux_console_byte_test_sink::take(), bytes[..written]);
        written
    }

    #[test]
    fn verbatim_render_preserves_ascii_nul_and_invalid_utf8() {
        let generation = InstanceGeneration(1);
        let (mut fds, mut ipc) = local_pair();
        let handle = ipc.grant_console_capability_for_pid(30).expect("grant");
        fds.install(30, generation, handle, handle)
            .expect("install");
        let payload = b"ok\0\xff\xfe\x80";
        assert_eq!(
            capture_verbatim_write(&mut fds, &mut ipc, 30, generation, payload),
            payload.len()
        );
    }

    #[test]
    fn verbatim_render_preserves_64_byte_chunk_boundary() {
        let generation = InstanceGeneration(1);
        let (mut fds, mut ipc) = local_pair();
        let handle = ipc.grant_console_capability_for_pid(31).expect("grant");
        fds.install(31, generation, handle, handle)
            .expect("install");
        let mut payload = [0u8; IPC_MAX_MESSAGE_BYTES + 4];
        payload.fill(b'x');
        payload[IPC_MAX_MESSAGE_BYTES] = b'y';
        let written = capture_verbatim_write(&mut fds, &mut ipc, 31, generation, &payload);
        assert_eq!(written, IPC_MAX_MESSAGE_BYTES);
        assert_eq!(
            linux_console_byte_test_sink::take(),
            &payload[..IPC_MAX_MESSAGE_BYTES]
        );
    }

    #[test]
    fn verbatim_render_preserves_utf8_split_across_chunks() {
        let generation = InstanceGeneration(1);
        let (mut fds, mut ipc) = local_pair();
        let handle = ipc.grant_console_capability_for_pid(32).expect("grant");
        fds.install(32, generation, handle, handle)
            .expect("install");
        let mut payload = [0u8; IPC_MAX_MESSAGE_BYTES + 8];
        payload[..61].fill(b'a');
        payload[61..65].copy_from_slice(&[0xF0, 0x9F, 0x98, 0x80]);
        payload[65..].fill(b'b');
        linux_console_byte_test_sink::reset();
        let first = fds
            .write_fd(
                &mut ipc,
                32,
                generation,
                LINUX_STDOUT_FD,
                &payload,
                ExecutionPersonality::LinuxX86_64,
            )
            .expect("first chunk");
        assert_eq!(first, IPC_MAX_MESSAGE_BYTES);
        let first_capture = linux_console_byte_test_sink::take();
        linux_console_byte_test_sink::reset();
        let second = fds
            .write_fd(
                &mut ipc,
                32,
                generation,
                LINUX_STDOUT_FD,
                &payload[first..],
                ExecutionPersonality::LinuxX86_64,
            )
            .expect("second chunk");
        let second_capture = linux_console_byte_test_sink::take();
        let mut combined = first_capture;
        combined.extend_from_slice(&second_capture);
        assert_eq!(combined.as_slice(), &payload[..first + second]);
    }

    #[test]
    fn write_4096_plus_short_writes_exact_max_to_capture() {
        let generation = InstanceGeneration(1);
        let (mut fds, mut ipc) = local_pair();
        let handle = ipc.grant_console_capability_for_pid(34).expect("grant");
        fds.install(34, generation, handle, handle)
            .expect("install");
        let payload = [0xABu8; crate::syscall::linux::write::LINUX_WRITE_MAX_BYTES + 16];
        linux_console_byte_test_sink::reset();
        let written = crate::syscall::linux::write::write_with(
            &mut fds,
            &mut ipc,
            34,
            generation,
            LINUX_STDOUT_FD,
            &payload,
            ExecutionPersonality::LinuxX86_64,
        )
        .expect("write");
        assert_eq!(
            written,
            crate::syscall::linux::write::LINUX_WRITE_MAX_BYTES as u64
        );
        assert_eq!(
            linux_console_byte_test_sink::take(),
            &payload[..crate::syscall::linux::write::LINUX_WRITE_MAX_BYTES]
        );
    }

    #[test]
    fn repeated_verbatim_writes_concatenate_on_serial_capture() {
        let generation = InstanceGeneration(1);
        let (mut fds, mut ipc) = local_pair();
        let handle = ipc.grant_console_capability_for_pid(33).expect("grant");
        fds.install(33, generation, handle, handle)
            .expect("install");
        linux_console_byte_test_sink::reset();
        assert_eq!(
            fds.write_fd(
                &mut ipc,
                33,
                generation,
                LINUX_STDOUT_FD,
                b"ab",
                ExecutionPersonality::LinuxX86_64
            ),
            Ok(2)
        );
        assert_eq!(
            fds.write_fd(
                &mut ipc,
                33,
                generation,
                LINUX_STDOUT_FD,
                b"cd",
                ExecutionPersonality::LinuxX86_64
            ),
            Ok(2)
        );
        assert_eq!(linux_console_byte_test_sink::take(), b"abcd");
    }
}
