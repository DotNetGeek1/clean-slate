//! Persistent writable `/home` backed by storage-service objects (#304).
//!
//! `/home` is a flat directory of up to [`super::home_table::HOME_MAX_FILES`] files that survives reboots: the
//! files a Linux Doom port writes (save games, its config, screenshots). It is not a
//! filesystem. Each file is one object, and the name table ([`HomeTable`]) is one more.
//!
//! - **Durability.** File writes and truncates go to the storage service as `WRITE_AT` and
//!   `TRUNCATE` requests, which it stages without committing. Writing the name table, with
//!   every file's current length, is a whole-object write, which commits, so the table and
//!   all staged file bytes become durable together. The table is written when a file is
//!   created, renamed or unlinked, and by `close` of a writable fd, `fsync` and `fdatasync`
//!   when anything changed since the last commit. A crash loses what was written since then,
//!   never the agreement between the table's lengths and the bytes.
//! - **Authority.** One capability, `READ`/`WRITE` on [`HOME_TABLE_OBJECT_ID`], authorises
//!   every file in `/home`: the per-holder capability quota cannot hold one per file. Bound
//!   per-file capabilities are a later stage.
//! - **Blocking.** Every request blocks the calling thread and restarts the syscall when the
//!   service completes it. A syscall that needs several requests (a long `write`, or a
//!   create that truncates the slot's object then commits) records its progress in a
//!   [`PendingOp`] keyed by the caller and its syscall, so the restarted handler resumes
//!   where it stopped.
//!
//! Known gaps: a file unlinked while open is gone at once (its open fds fail with `EBADF`);
//! a process that exits without closing a written file leaves the change staged, made
//! durable by the next commit from any process; concurrent writers to `/home` are not
//! ordered beyond the storage queue's order.

use clean_slate_capability::HolderId;
use clean_slate_linux_abi::{
    LinuxErrno, LinuxSyscallRequest, EACCES, EFAULT, EFBIG, EIO, ENOENT, ENOSPC,
};
use clean_slate_service_fixtures::{
    OBJECT_MAX_PAYLOAD_BYTES, OBJECT_OP_READ, OBJECT_OP_READ_AT, OBJECT_OP_TRUNCATE,
    OBJECT_OP_WRITE, OBJECT_OP_WRITE_AT, OBJECT_STATUS_NOT_FOUND, OBJECT_STATUS_NO_SPACE,
    OBJECT_STATUS_PENDING, OBJECT_STATUS_TOO_LARGE,
};

pub(crate) use super::home_table::{
    home_file_object_id, validate_name, HomeTable, HOME_MAX_FILE_BYTES, HOME_TABLE_BYTES,
    HOME_TABLE_OBJECT_ID,
};
use crate::capability::object::{
    authorize_holder_object_op, object_queue_poll, object_queue_submit_under,
    object_request_wait_key, SyscallQueueError,
};
use crate::mm::user_access::copy_from_user;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::linux::block::{block_linux_syscall, LinuxTimeoutResult};
use crate::syscall::linux::table::LinuxSyscallContext;

pub(crate) const LINUX_HOME_PATH: &[u8] = b"/home";

/// Syscalls in flight on `/home` at once: one per Linux process.
const PENDING_OPS: usize = crate::process::PROCESS_REGISTRY_CAPACITY;

/// How a multi-request `/home` syscall resumes after a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingOp {
    pid: u64,
    /// The syscall: number and arguments, the same on every restart of it.
    nr: u64,
    args: [u64; 6],
    /// The request in flight, 0 for none, and what it asked for: a restart that would
    /// submit something else first drains it.
    request_id: u64,
    op: u64,
    object_id: u64,
    offset: u64,
    /// The caller's own value, returned with the completion (a commit's change count).
    tag: u64,
    /// The caller's resume point: bytes done for a write, steps done for a namespace op.
    progress: u64,
}

struct HomeState {
    loaded: bool,
    /// The stored table did not decode: `/home` fails with `EIO` rather than overwrite it.
    refused: bool,
    table: HomeTable,
    /// Count of changes to file bytes or lengths, and the count the last commit covered.
    changes: u64,
    committed: u64,
    ops: [Option<PendingOp>; PENDING_OPS],
}

impl HomeState {
    const fn new() -> Self {
        Self {
            loaded: false,
            refused: false,
            table: HomeTable::empty(),
            changes: 0,
            committed: 0,
            ops: [None; PENDING_OPS],
        }
    }
}

static HOME: GlobalCell<HomeState> = GlobalCell::new(HomeState::new());

fn home() -> &'static mut HomeState {
    unsafe { &mut *HOME.get() }
}

/// What a `/home` step did: finished with a value, or blocked (return the value as is).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Flow<T> {
    Done(T),
    Restart(u64),
}

/// Returns early from the enclosing handler with the restart value of a blocked step.
macro_rules! step {
    ($flow:expr) => {
        match $flow {
            Flow::Done(value) => value,
            Flow::Restart(rax) => return Ok(Flow::Restart(rax)),
        }
    };
}
pub(crate) use step;

struct Completion {
    /// `Ok(())`, or the service's error status.
    status: Result<(), u64>,
    len: usize,
    payload: [u8; OBJECT_MAX_PAYLOAD_BYTES],
    tag: u64,
}

fn same_syscall(op: &PendingOp, pid: u64, request: &LinuxSyscallRequest) -> bool {
    op.pid == pid && op.nr == request.nr && op.args == request.args
}

fn op_index(pid: u64) -> Option<usize> {
    home()
        .ops
        .iter()
        .position(|op| op.is_some_and(|op| op.pid == pid))
}

/// The caller's progress in this syscall, 0 when it has none yet.
fn progress(pid: u64, request: &LinuxSyscallRequest) -> u64 {
    op_index(pid)
        .and_then(|index| home().ops[index])
        .filter(|op| same_syscall(op, pid, request))
        .map_or(0, |op| op.progress)
}

fn set_progress(pid: u64, request: &LinuxSyscallRequest, progress: u64) {
    if let Some(op) = op_index(pid).and_then(|index| home().ops[index].as_mut()) {
        if same_syscall(op, pid, request) {
            op.progress = progress;
        }
    }
}

/// Forgets the caller's syscall state. Every handler calls it when it returns anything but
/// a restart, so the next syscall, even one with the same arguments, starts afresh.
pub(crate) fn end_syscall(pid: u64) {
    if let Some(index) = op_index(pid) {
        let op = home().ops[index].take();
        // An abandoned request still holds a queue slot until polled; poll it once so a
        // completed one is freed. One still in service is freed by its completion.
        if let Some(op) = op.filter(|op| op.request_id != 0) {
            let mut scratch = [0u8; OBJECT_MAX_PAYLOAD_BYTES];
            let _ = object_queue_poll(HolderId(pid), op.request_id, &mut scratch);
        }
    }
}

/// Wraps a handler body: ends the syscall unless it blocked.
pub(crate) fn finish<T>(
    pid: u64,
    result: Result<Flow<T>, LinuxErrno>,
) -> Result<Flow<T>, LinuxErrno> {
    if !matches!(result, Ok(Flow::Restart(_))) {
        end_syscall(pid);
    }
    result
}

fn queue_errno(error: SyscallQueueError) -> LinuxErrno {
    match error {
        SyscallQueueError::QueueFull => ENOSPC,
        SyscallQueueError::UnauthorizedHolder => EACCES,
        _ => EIO,
    }
}

fn status_errno(status: u64) -> LinuxErrno {
    match status {
        OBJECT_STATUS_NO_SPACE => ENOSPC,
        OBJECT_STATUS_TOO_LARGE => EFBIG,
        OBJECT_STATUS_NOT_FOUND => ENOENT,
        _ => EIO,
    }
}

fn block_on(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    request_id: u64,
) -> Result<Flow<Completion>, LinuxErrno> {
    block_linux_syscall(
        request,
        ctx,
        object_request_wait_key(request_id),
        None,
        LinuxTimeoutResult::Zero,
    )
    .map(Flow::Restart)
}

/// Sends one object request for the calling syscall, or collects its completion when the
/// syscall was restarted for it. `payload` is the bytes of a write; for a `READ_AT` its
/// length is the bytes asked for. Every submission is authorised by the caller's right on
/// the `/home` table object.
fn object_request(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    op: u64,
    object_id: u64,
    offset: u64,
    payload: &[u8],
    tag: u64,
) -> Result<Flow<Completion>, LinuxErrno> {
    let pid = ctx.pid;
    let holder = HolderId(pid);
    let state = home();
    let index = match op_index(pid) {
        Some(index) => index,
        None => {
            // Between its restarts a syscall always has a request in flight, so an entry
            // without one is left over (its process exited mid-syscall) and may be reused.
            let index = state
                .ops
                .iter()
                .position(|op| op.is_none_or(|op| op.request_id == 0))
                .ok_or(ENOSPC)?;
            state.ops[index] = Some(PendingOp {
                pid,
                nr: request.nr,
                args: request.args,
                request_id: 0,
                op: 0,
                object_id: 0,
                offset: 0,
                tag: 0,
                progress: 0,
            });
            index
        }
    };
    let mut entry = state.ops[index].expect("pending op present");
    if !same_syscall(&entry, pid, request) {
        // A syscall interrupted while blocked left this behind; start this one afresh.
        entry = PendingOp {
            nr: request.nr,
            args: request.args,
            progress: 0,
            ..entry
        };
    }
    if entry.request_id != 0 {
        let mut completion = Completion {
            status: Ok(()),
            len: 0,
            payload: [0; OBJECT_MAX_PAYLOAD_BYTES],
            tag: entry.tag,
        };
        let polled = object_queue_poll(holder, entry.request_id, &mut completion.payload);
        if polled == Ok(OBJECT_STATUS_PENDING) {
            state.ops[index] = Some(entry);
            return block_on(request, ctx, entry.request_id);
        }
        let matches = entry.op == op && entry.object_id == object_id && entry.offset == offset;
        entry.request_id = 0;
        state.ops[index] = Some(entry);
        match polled {
            Ok(len) if matches => {
                completion.len = len as usize;
                return Ok(Flow::Done(completion));
            }
            Err(SyscallQueueError::CompletionStatus(status)) if matches => {
                completion.status = Err(status);
                return Ok(Flow::Done(completion));
            }
            Err(error) if matches => return Err(queue_errno(error)),
            // A request this step did not ask for: drained, now submit ours.
            _ => {}
        }
    }
    let request_id =
        object_queue_submit_under(holder, HOME_TABLE_OBJECT_ID, op, object_id, offset, payload)
            .map_err(queue_errno)?;
    entry.request_id = request_id;
    entry.op = op;
    entry.object_id = object_id;
    entry.offset = offset;
    entry.tag = tag;
    state.ops[index] = Some(entry);
    block_on(request, ctx, request_id)
}

fn authorize(pid: u64, write: bool) -> Result<(), LinuxErrno> {
    let op = if write {
        OBJECT_OP_WRITE
    } else {
        OBJECT_OP_READ
    };
    authorize_holder_object_op(HolderId(pid), HOME_TABLE_OBJECT_ID, op).map_err(|_| EACCES)
}

/// Whether `path` (normalized) is `/home` or a path inside it.
pub(crate) fn is_home_path(path: &[u8]) -> bool {
    path == LINUX_HOME_PATH
        || (path.starts_with(LINUX_HOME_PATH) && path.get(LINUX_HOME_PATH.len()) == Some(&b'/'))
}

/// The name of a file directly in `/home`, or `None` for any other path.
pub(crate) fn home_file_name(path: &[u8]) -> Option<&[u8]> {
    let name = path.strip_prefix(LINUX_HOME_PATH)?.strip_prefix(b"/")?;
    (!name.is_empty()).then_some(name)
}

/// Loads the name table on first use after boot, after checking the caller may use
/// `/home` at all (`READ`, or `WRITE` when `write`).
pub(crate) fn ensure_loaded(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    write: bool,
) -> Result<Flow<()>, LinuxErrno> {
    authorize(ctx.pid, write)?;
    let state = home();
    if state.refused {
        return Err(EIO);
    }
    if state.loaded {
        return Ok(Flow::Done(()));
    }
    let completion = step!(object_request(
        request,
        ctx,
        OBJECT_OP_READ_AT,
        HOME_TABLE_OBJECT_ID,
        0,
        &[0; HOME_TABLE_BYTES],
        0
    )?);
    if state.loaded {
        return Ok(Flow::Done(()));
    }
    match completion.status {
        Ok(()) => match HomeTable::decode(&completion.payload[..completion.len]) {
            Ok(table) => {
                state.table = table;
                state.loaded = true;
                crate::diagnostics::log::kernel_log_fmt(format_args!(
                    "[HOME] loaded files={} bytes={}\n",
                    table.live_count(),
                    table.total_bytes()
                ));
            }
            Err(_) => {
                state.refused = true;
                crate::diagnostics::log::kernel_log_line("[HOME] table refused: not a /home table");
                return Err(EIO);
            }
        },
        // A store that never had `/home`: it starts empty.
        Err(OBJECT_STATUS_NOT_FOUND) => {
            state.table = HomeTable::empty();
            state.loaded = true;
            crate::diagnostics::log::kernel_log_line("[HOME] loaded files=0 bytes=0 (new)");
        }
        Err(status) => return Err(status_errno(status)),
    }
    Ok(Flow::Done(()))
}

/// The loaded table. Callers have run [`ensure_loaded`] in this syscall.
pub(crate) fn table() -> &'static HomeTable {
    &home().table
}

pub(crate) fn is_loaded() -> bool {
    home().loaded
}

pub(crate) fn file_len(slot: usize) -> u64 {
    home()
        .table
        .entry(slot)
        .map_or(0, |entry| u64::from(entry.len))
}

fn note_change() {
    let state = home();
    state.changes = state.changes.wrapping_add(1);
}

/// Writes the table, committing it and every staged file change. `apply` runs on the
/// table once the commit is durable; the table sent is the current one with `apply` run
/// on a copy, so a restart that recomputes it sends the same bytes.
fn commit_with(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    apply: impl Fn(&mut HomeTable) -> Result<(), LinuxErrno>,
) -> Result<Flow<()>, LinuxErrno> {
    let state = home();
    let mut next = state.table;
    apply(&mut next)?;
    let changes = state.changes;
    let completion = step!(object_request(
        request,
        ctx,
        OBJECT_OP_WRITE,
        HOME_TABLE_OBJECT_ID,
        0,
        &next.encode(),
        changes
    )?);
    completion.status.map_err(status_errno)?;
    apply(&mut state.table)?;
    state.committed = completion.tag;
    crate::diagnostics::log::kernel_log_fmt(format_args!(
        "[HOME] commit files={} bytes={}\n",
        state.table.live_count(),
        state.table.total_bytes()
    ));
    Ok(Flow::Done(()))
}

/// Commits when anything changed since the last commit (`close`, `fsync`, `fdatasync`).
pub(crate) fn sync(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> Result<Flow<()>, LinuxErrno> {
    let state = home();
    if !state.loaded || state.changes == state.committed {
        return Ok(Flow::Done(()));
    }
    commit_with(request, ctx, |_| Ok(()))
}

/// Stages `slot`'s object cut or extended to `len`.
fn truncate_object(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    slot: usize,
    len: u64,
) -> Result<Flow<()>, LinuxErrno> {
    let completion = step!(object_request(
        request,
        ctx,
        OBJECT_OP_TRUNCATE,
        home_file_object_id(slot),
        len,
        &[],
        0
    )?);
    completion.status.map_err(status_errno)?;
    Ok(Flow::Done(()))
}

/// Creates `name` in `/home`, returning its slot; an existing file is returned as is.
/// The slot's object is emptied first (a crash or earlier file may have left bytes in it),
/// then the table commit makes the new name durable.
pub(crate) fn create(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    name: &[u8],
) -> Result<Flow<usize>, LinuxErrno> {
    validate_name(name)?;
    let state = home();
    // The name appears in the table only when this syscall's commit lands, so an existing
    // name here is a file that was there already.
    if let Some(slot) = state.table.find(name) {
        return Ok(Flow::Done(slot));
    }
    let slot = state.table.free_slot()?;
    if progress(ctx.pid, request) == 0 {
        step!(truncate_object(request, ctx, slot, 0)?);
        set_progress(ctx.pid, request, 1);
    }
    step!(commit_with(request, ctx, |table| table.create_at(slot, name))?);
    Ok(Flow::Done(slot))
}

/// Cuts or extends `slot` to `len` (`O_TRUNC`, `ftruncate`). Committed with the next sync.
pub(crate) fn truncate(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    slot: usize,
    len: u64,
) -> Result<Flow<()>, LinuxErrno> {
    if len > HOME_MAX_FILE_BYTES {
        return Err(EFBIG);
    }
    if home().table.entry(slot).is_none() {
        return Err(ENOENT);
    }
    step!(truncate_object(request, ctx, slot, len)?);
    if let Some(entry) = home().table.entry_mut(slot) {
        entry.len = len as u32;
    }
    note_change();
    Ok(Flow::Done(()))
}

/// Removes `name`: its object is emptied, then the table commit drops the name.
pub(crate) fn unlink(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    name: &[u8],
) -> Result<Flow<usize>, LinuxErrno> {
    let slot = home().table.find(name).ok_or(ENOENT)?;
    if progress(ctx.pid, request) == 0 {
        step!(truncate_object(request, ctx, slot, 0)?);
        set_progress(ctx.pid, request, 1);
    }
    step!(commit_with(request, ctx, |table| {
        table.remove(slot);
        Ok(())
    })?);
    Ok(Flow::Done(slot))
}

/// Renames `from` to `to`, replacing `to` if it exists. Returns `from`'s slot and the slot
/// of the file it replaced. The replaced file's object is emptied before the commit.
pub(crate) fn rename(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    from: &[u8],
    to: &[u8],
) -> Result<Flow<(usize, Option<usize>)>, LinuxErrno> {
    validate_name(to)?;
    let table = home().table;
    let slot = table.find(from).ok_or(ENOENT)?;
    let victim = table.find(to).filter(|victim| *victim != slot);
    if from == to {
        return Ok(Flow::Done((slot, None)));
    }
    if let Some(victim) = victim {
        if progress(ctx.pid, request) == 0 {
            step!(truncate_object(request, ctx, victim, 0)?);
            set_progress(ctx.pid, request, 1);
        }
    }
    step!(commit_with(request, ctx, |table| table
        .rename(slot, to)
        .map(|_| ()))?);
    Ok(Flow::Done((slot, victim)))
}

/// Reads at most one request's worth of `slot` at `offset` into `out`. A short read is
/// normal: callers that want more read again.
pub(crate) fn read(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    slot: usize,
    offset: u64,
    out: &mut [u8],
) -> Result<Flow<usize>, LinuxErrno> {
    authorize(ctx.pid, false)?;
    let len = file_len(slot);
    if offset >= len || out.is_empty() {
        return Ok(Flow::Done(0));
    }
    let want = ((len - offset) as usize)
        .min(out.len())
        .min(OBJECT_MAX_PAYLOAD_BYTES);
    let completion = step!(object_request(
        request,
        ctx,
        OBJECT_OP_READ_AT,
        home_file_object_id(slot),
        offset,
        &[0; OBJECT_MAX_PAYLOAD_BYTES][..want],
        0
    )?);
    completion.status.map_err(status_errno)?;
    let got = completion.len.min(want);
    out[..got].copy_from_slice(&completion.payload[..got]);
    Ok(Flow::Done(got))
}

/// Writes `count` bytes from user address `user_ptr` to `slot` at `offset`, in requests of
/// at most [`OBJECT_MAX_PAYLOAD_BYTES`]. Staged, not committed: [`sync`] makes it durable.
/// Returns the bytes written, fewer than `count` only when a later request failed.
pub(crate) fn write(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    slot: usize,
    offset: u64,
    user_ptr: u64,
    count: usize,
) -> Result<Flow<usize>, LinuxErrno> {
    authorize(ctx.pid, true)?;
    if home().table.entry(slot).is_none() {
        return Err(ENOENT);
    }
    let end = offset.checked_add(count as u64).ok_or(EFBIG)?;
    if end > HOME_MAX_FILE_BYTES {
        return Err(EFBIG);
    }
    let mut done = progress(ctx.pid, request) as usize;
    while done < count {
        let chunk = (count - done).min(OBJECT_MAX_PAYLOAD_BYTES);
        let mut payload = [0u8; OBJECT_MAX_PAYLOAD_BYTES];
        let source = user_ptr.checked_add(done as u64).ok_or(EFAULT)?;
        copy_from_user(&mut payload[..chunk], source).map_err(|_| EFAULT)?;
        let at = offset + done as u64;
        let completion = match object_request(
            request,
            ctx,
            OBJECT_OP_WRITE_AT,
            home_file_object_id(slot),
            at,
            &payload[..chunk],
            chunk as u64,
        ) {
            Ok(Flow::Done(completion)) => completion,
            Ok(Flow::Restart(rax)) => return Ok(Flow::Restart(rax)),
            Err(_) if done > 0 => return Ok(Flow::Done(done)),
            Err(errno) => return Err(errno),
        };
        if let Err(status) = completion.status {
            return if done > 0 {
                Ok(Flow::Done(done))
            } else {
                Err(status_errno(status))
            };
        }
        done += completion.tag as usize;
        set_progress(ctx.pid, request, done as u64);
        if let Some(entry) = home().table.entry_mut(slot) {
            entry.len = entry.len.max((offset + done as u64) as u32);
        }
        note_change();
    }
    Ok(Flow::Done(count))
}

/// `/home` state is rebuilt from the store after every boot; host tests start clean.
#[cfg(test)]
pub(crate) fn reset_home_for_host_tests() {
    *home() = HomeState::new();
}

/// Loads `table` as if read from the store (host tests of the namespace).
#[cfg(test)]
pub(crate) fn load_home_for_host_tests(table: HomeTable) {
    let state = home();
    state.table = table;
    state.loaded = true;
}
