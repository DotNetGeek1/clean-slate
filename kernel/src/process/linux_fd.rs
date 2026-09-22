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

// #94 (`write`/`exit`) and #97 (Linux launch bootstrap) consume install/write/
// projection; production teardown already calls `release_for_process`.
#![allow(dead_code)]

use clean_slate_linux_abi::{LinuxErrno, EACCES, EBADF, EINVAL};
use clean_slate_service_lifecycle::InstanceGeneration;

use super::personality::ExecutionPersonality;
use super::process_registry_mut;
use super::PROCESS_REGISTRY_CAPACITY;
use crate::diagnostics::log::kernel_log_fmt;
use crate::ipc::endpoint_table_mut;
use crate::ipc::IpcEndpointKind;
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

    fn clear(&mut self) {
        *self = Self::new();
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

    fn install(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
        stdout_handle: u64,
        stderr_handle: u64,
    ) -> Result<(), &'static str> {
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

    fn release(&mut self, pid: u64, generation: InstanceGeneration) -> bool {
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

    fn occupied(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
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
/// Trusted bootstrap only: callers must have already granted `stdout_handle` /
/// `stderr_handle` to `pid` via [`crate::ipc::IpcEndpointTable::grant_send_capability`]
/// (or [`crate::ipc::IpcEndpointTable::grant_console_capability_for_pid`]). Naming
/// fd 1 without that grant yields no output — [`write_fd`] still goes through
/// IPC checks.
///
/// fd 0 and fd 3 remain [`LinuxFdProjection::Closed`] for M8.
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
    let slot = registry_mut().find_slot(pid, generation).ok_or(EBADF)?;
    slot.table.get(fd).ok_or(EBADF)
}

/// Write `bytes` through the capability projected by Linux `fd`.
///
/// - Out-of-range / closed / missing / stale `(pid, generation)` → [`EBADF`].
/// - Empty write returns `Ok(0)` without touching IPC (Linux allows a zero-length write).
/// - Writes longer than [`IPC_MAX_MESSAGE_BYTES`] (64) return a **short write**:
///   only the first 64 bytes are sent and the returned length is `64`. #94
///   decides whether the Linux `write` handler loops for the remainder.
/// - On success for a `ConsoleSink`, serial output is rendered per
///   [`render_console_sink_for_linux_fd`] (verbatim for Linux-personality senders).
pub(crate) fn write_fd(
    pid: u64,
    generation: InstanceGeneration,
    fd: u64,
    bytes: &[u8],
) -> Result<usize, LinuxErrno> {
    let projection = projection_for(pid, generation, fd)?;
    let handle = match projection {
        LinuxFdProjection::Closed => return Err(EBADF),
        LinuxFdProjection::ConsoleEndpoint { capability_handle } => capability_handle,
    };
    if bytes.is_empty() {
        return Ok(0);
    }
    let send_len = core::cmp::min(bytes.len(), IPC_MAX_MESSAGE_BYTES);
    let payload = &bytes[..send_len];
    let table = unsafe { endpoint_table_mut() };
    match table.send_message(pid, handle, payload) {
        Ok(result) => {
            if result.endpoint_kind == IpcEndpointKind::ConsoleSink {
                render_console_sink_for_linux_fd(pid, payload);
            }
            Ok(result.bytes_sent)
        }
        Err(error) => Err(map_ipc_send_error(error)),
    }
}

/// Release the fd table for `(pid, generation)` if present.
///
/// Idempotent: missing / mismatched generation is a no-op. Production teardown
/// in [`super::domain`] calls this so a replacement process with a new
/// generation starts with a fresh table.
pub(crate) fn release_for_process(pid: u64, generation: InstanceGeneration) {
    let _ = registry_mut().release(pid, generation);
}

/// ConsoleSink serial rendering for messages delivered via the Linux fd path.
///
/// **Decision (M8.5):** reuse `IpcEndpointKind::ConsoleSink` — no new endpoint
/// kind, no raw console syscall, no new resource class. When the sender process
/// has [`ExecutionPersonality::LinuxX86_64`], the payload is written to serial
/// **verbatim** (no `[IPC ] console pid=N:` prefix) so acceptance can extract
/// the exact bytes `Hello from Linux.\n`. Native personality senders using this
/// path (unexpected in M8) keep the historical framed line for consistency with
/// `SYSCALL_NR_IPC_SEND`. The native IPC syscall handler is unchanged and still
/// owns framing for native `ipc_send`.
fn render_console_sink_for_linux_fd(sender_pid: u64, payload: &[u8]) {
    let personality = unsafe { process_registry_mut().get(sender_pid) }
        .map(|process| process.execution_personality)
        .unwrap_or(ExecutionPersonality::Native);
    match personality {
        ExecutionPersonality::LinuxX86_64 => {
            if let Ok(text) = core::str::from_utf8(payload) {
                kernel_log_fmt(format_args!("{text}"));
            } else {
                // M8 fixture is ASCII; non-UTF8 still avoids native framing so
                // extracts stay free of `[IPC ]` prefixes.
                kernel_log_fmt(format_args!("<non-utf8>\n"));
            }
        }
        ExecutionPersonality::Native => {
            let message = core::str::from_utf8(payload).unwrap_or("<non-utf8>");
            kernel_log_fmt(format_args!("[IPC ] console pid={sender_pid}: {message}\n"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::IpcEndpointTable;

    fn reset_globals() {
        registry_mut().clear();
        unsafe {
            *endpoint_table_mut() = IpcEndpointTable::new();
        }
    }

    fn grant_console_to(pid: u64) -> u64 {
        let table = unsafe { endpoint_table_mut() };
        table
            .grant_console_capability_for_pid(pid)
            .expect("grant console capability")
    }

    #[test]
    fn install_and_lookup_stdio_projections() {
        reset_globals();
        let generation = InstanceGeneration(3);
        let stdout = grant_console_to(10);
        let stderr = grant_console_to(10);
        install_stdio_for_process(10, generation, stdout, stderr).expect("install");

        assert_eq!(
            projection_for(10, generation, LINUX_STDOUT_FD).expect("stdout"),
            LinuxFdProjection::ConsoleEndpoint {
                capability_handle: stdout
            }
        );
        assert_eq!(
            projection_for(10, generation, LINUX_STDERR_FD).expect("stderr"),
            LinuxFdProjection::ConsoleEndpoint {
                capability_handle: stderr
            }
        );
        assert_eq!(
            projection_for(10, generation, 0).expect("stdin closed"),
            LinuxFdProjection::Closed
        );
        assert_eq!(projection_for(10, generation, 99), Err(EBADF));
        reset_globals();
    }

    #[test]
    fn write_fd_ebadf_for_closed_and_invalid() {
        reset_globals();
        let generation = InstanceGeneration(1);
        let handle = grant_console_to(11);
        install_stdio_for_process(11, generation, handle, handle).expect("install");

        assert_eq!(
            write_fd(11, generation, 0, b"x"),
            Err(EBADF),
            "closed stdin"
        );
        assert_eq!(
            write_fd(11, generation, 99, b"x"),
            Err(EBADF),
            "out of range"
        );
        assert_eq!(
            write_fd(11, InstanceGeneration(99), LINUX_STDOUT_FD, b"x"),
            Err(EBADF),
            "stale generation"
        );
        reset_globals();
    }

    #[test]
    fn registry_exhaustion_is_deterministic() {
        reset_globals();
        // Install does not validate handles; use placeholders so this test is
        // independent of IPC endpoint/capability capacity.
        for i in 0..LINUX_FD_REGISTRY_CAPACITY {
            let pid = 100 + i as u64;
            install_stdio_for_process(pid, InstanceGeneration(1), 1, 2).expect("fill registry");
        }
        assert_eq!(registry_mut().occupied(), LINUX_FD_REGISTRY_CAPACITY);
        assert!(install_stdio_for_process(999, InstanceGeneration(1), 1, 2).is_err());
        reset_globals();
    }

    #[test]
    fn release_clears_table_and_stale_generation_fails_closed() {
        reset_globals();
        let generation = InstanceGeneration(4);
        let handle = grant_console_to(12);
        install_stdio_for_process(12, generation, handle, handle).expect("install");
        release_for_process(12, generation);
        assert_eq!(projection_for(12, generation, LINUX_STDOUT_FD), Err(EBADF));
        assert_eq!(
            write_fd(12, generation, LINUX_STDOUT_FD, b"hello"),
            Err(EBADF)
        );
        release_for_process(12, InstanceGeneration(1));
        reset_globals();
    }

    #[test]
    fn replacement_process_does_not_inherit_prior_table() {
        reset_globals();
        let gen1 = InstanceGeneration(1);
        let gen2 = InstanceGeneration(2);
        let handle1 = grant_console_to(13);
        install_stdio_for_process(13, gen1, handle1, handle1).expect("install gen1");
        release_for_process(13, gen1);

        let handle2 = grant_console_to(13);
        install_stdio_for_process(13, gen2, handle2, handle2).expect("install gen2");

        assert_eq!(
            projection_for(13, gen1, LINUX_STDOUT_FD),
            Err(EBADF),
            "old generation must not see a table"
        );
        assert_eq!(
            projection_for(13, gen2, LINUX_STDOUT_FD).expect("new table"),
            LinuxFdProjection::ConsoleEndpoint {
                capability_handle: handle2
            }
        );
        assert_ne!(handle1, handle2);
        reset_globals();
    }

    #[test]
    fn naming_fd_one_without_grant_yields_no_output() {
        reset_globals();
        let generation = InstanceGeneration(1);
        // Install a handle granted to another pid — fd 1 is not authority.
        let foreign = grant_console_to(50);
        install_stdio_for_process(51, generation, foreign, foreign).expect("install ungranted");

        let table = unsafe { endpoint_table_mut() };
        assert_eq!(
            write_fd(51, generation, LINUX_STDOUT_FD, b"secret"),
            Err(EACCES),
            "ungranted handle must be rejected by IpcEndpointTable"
        );
        assert_eq!(
            table.endpoint_message(0),
            Some(&b""[..]),
            "no payload delivered without a real grant to the writer pid"
        );
        reset_globals();
    }

    #[test]
    fn authorized_write_delivers_through_real_endpoint_table() {
        reset_globals();
        let generation = InstanceGeneration(7);
        let handle = grant_console_to(20);
        install_stdio_for_process(20, generation, handle, handle).expect("install");

        assert_eq!(
            write_fd(20, generation, LINUX_STDOUT_FD, b"Hello from Linux.\n"),
            Ok(18)
        );
        let table = unsafe { endpoint_table_mut() };
        assert_eq!(table.endpoint_message(0), Some(&b"Hello from Linux.\n"[..]));
        reset_globals();
    }

    #[test]
    fn short_write_caps_at_ipc_max_message_bytes() {
        reset_globals();
        let generation = InstanceGeneration(1);
        let handle = grant_console_to(21);
        install_stdio_for_process(21, generation, handle, handle).expect("install");

        let mut oversized = [b'a'; IPC_MAX_MESSAGE_BYTES + 8];
        oversized[0] = b'H';
        assert_eq!(
            write_fd(21, generation, LINUX_STDOUT_FD, &oversized),
            Ok(IPC_MAX_MESSAGE_BYTES)
        );
        let table = unsafe { endpoint_table_mut() };
        let delivered = table.endpoint_message(0).expect("message");
        assert_eq!(delivered.len(), IPC_MAX_MESSAGE_BYTES);
        assert_eq!(delivered[0], b'H');
        reset_globals();
    }

    #[test]
    fn empty_write_returns_zero_without_ipc() {
        reset_globals();
        let generation = InstanceGeneration(1);
        let handle = grant_console_to(22);
        install_stdio_for_process(22, generation, handle, handle).expect("install");
        assert_eq!(write_fd(22, generation, LINUX_STDOUT_FD, b""), Ok(0));
        reset_globals();
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
}
