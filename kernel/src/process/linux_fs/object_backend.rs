//! Writable `/tmp` files backed by M6.3 persistent objects (#101).

use clean_slate_capability::{HolderId, Rights};
use clean_slate_linux_abi::LinuxErrno;
use clean_slate_service_fixtures::{
    OBJECT_MAX_PAYLOAD_BYTES, OBJECT_OP_READ, OBJECT_OP_WRITE, OBJECT_STATUS_PENDING,
};

use crate::capability::object::{
    grant_object_capability, object_queue_poll, object_queue_submit, SyscallQueueError,
};
use crate::sync::global_cell::GlobalCell;
use crate::syscall::linux::block::{block_linux_syscall, LinuxTimeoutResult};
use crate::syscall::linux::table::LinuxSyscallContext;
use clean_slate_linux_abi::LinuxSyscallRequest;

pub const LINUX_TMP_OBJECT_ID_BASE: u64 = 0x004C_0000;
pub const LINUX_TMP_MAX_FILES: usize = 4;
pub const LINUX_TMP_MAX_ENTRIES: usize = 8;

#[derive(Clone, Copy)]
pub(crate) struct TmpFileState {
    pub object_id: u64,
    pub len: usize,
    pub path_len: u16,
    pub path: [u8; 128],
    pub pending_request_id: u64,
}

struct TmpStore {
    files: [Option<TmpFileState>; LINUX_TMP_MAX_FILES],
    scratch: [[u8; OBJECT_MAX_PAYLOAD_BYTES]; LINUX_TMP_MAX_FILES],
}

impl TmpStore {
    const fn new() -> Self {
        Self {
            files: [None; LINUX_TMP_MAX_FILES],
            scratch: [[0; OBJECT_MAX_PAYLOAD_BYTES]; LINUX_TMP_MAX_FILES],
        }
    }
}

static TMP_STORE: GlobalCell<TmpStore> = GlobalCell::new(TmpStore::new());

fn store_mut() -> &'static mut TmpStore {
    unsafe { &mut *TMP_STORE.get() }
}

#[cfg(all(test, feature = "m9-rootfs"))]
pub(crate) fn reset_tmp_store_for_host_tests() {
    *store_mut() = TmpStore::new();
}

pub(crate) fn grant_linux_tmp_object_capabilities(pid: u64) -> Result<(), &'static str> {
    let holder = HolderId(pid);
    for index in 0..LINUX_TMP_MAX_FILES {
        let object_id = LINUX_TMP_OBJECT_ID_BASE + index as u64;
        if grant_object_capability(holder, object_id, Rights::READ.union(Rights::WRITE)).is_err() {
            return Err("linux tmp object grant failed");
        }
    }
    Ok(())
}

/// Bootstrap a writable `/tmp` file before any Linux process runs (self-test / init).
pub(crate) fn bootstrap_tmp_file_bytes(path: &[u8], data: &[u8]) -> Result<(), LinuxErrno> {
    if data.len() > OBJECT_MAX_PAYLOAD_BYTES {
        return Err(clean_slate_linux_abi::EFBIG);
    }
    let object_id = tmp_file_create(path)?;
    let state = slot_for_object_mut(object_id).ok_or(clean_slate_linux_abi::ENOENT)?;
    state.len = data.len();
    if let Some(index) = slot_index_for_object(object_id) {
        store_mut().scratch[index][..data.len()].copy_from_slice(data);
    }
    Ok(())
}

pub(crate) fn tmp_file_create(path: &[u8]) -> Result<u64, LinuxErrno> {
    let store = store_mut();
    for index in 0..LINUX_TMP_MAX_FILES {
        if store.files[index].is_none() {
            let object_id = LINUX_TMP_OBJECT_ID_BASE + index as u64;
            let mut state = TmpFileState {
                object_id,
                len: 0,
                path_len: path.len() as u16,
                path: [0; 128],
                pending_request_id: 0,
            };
            if path.len() > state.path.len() {
                return Err(clean_slate_linux_abi::ENAMETOOLONG);
            }
            state.path[..path.len()].copy_from_slice(path);
            store.files[index] = Some(state);
            return Ok(object_id);
        }
    }
    Err(clean_slate_linux_abi::ENOSPC)
}

pub(crate) fn tmp_file_lookup_by_path(path: &[u8]) -> Option<u64> {
    let store = store_mut();
    for state in store.files.iter().flatten() {
        if state.path_len as usize == path.len() && &state.path[..path.len()] == path {
            return Some(state.object_id);
        }
    }
    None
}

/// Read bytes from the in-kernel tmp scratch (authoritative after a completed write).
pub(crate) fn tmp_file_read_local(
    object_id: u64,
    offset: usize,
    out: &mut [u8],
) -> Result<usize, LinuxErrno> {
    let state = tmp_file_by_object_id(object_id).ok_or(clean_slate_linux_abi::ENOENT)?;
    if offset >= state.len {
        return Ok(0);
    }
    let index = slot_index_for_object(object_id).ok_or(clean_slate_linux_abi::EINVAL)?;
    let take = (state.len - offset).min(out.len());
    out[..take].copy_from_slice(&store_mut().scratch[index][offset..offset + take]);
    Ok(take)
}

pub(crate) fn tmp_file_by_object_id(object_id: u64) -> Option<TmpFileState> {
    let store = store_mut();
    for state in store.files.iter().flatten() {
        if state.object_id == object_id {
            return Some(*state);
        }
    }
    None
}

fn slot_index_for_object(object_id: u64) -> Option<usize> {
    (object_id >= LINUX_TMP_OBJECT_ID_BASE)
        .then_some((object_id - LINUX_TMP_OBJECT_ID_BASE) as usize)
        .filter(|i| *i < LINUX_TMP_MAX_FILES)
}

#[allow(clippy::manual_flatten)]
fn slot_for_object_mut(object_id: u64) -> Option<&'static mut TmpFileState> {
    let store = store_mut();
    for slot in store.files.iter_mut() {
        if let Some(state) = slot {
            if state.object_id == object_id {
                return Some(state);
            }
        }
    }
    None
}

pub(crate) fn tmp_file_truncate_local(object_id: u64) -> Result<(), LinuxErrno> {
    let state = slot_for_object_mut(object_id).ok_or(clean_slate_linux_abi::ENOENT)?;
    state.len = 0;
    state.pending_request_id = 0;
    if let Some(index) = slot_index_for_object(object_id) {
        store_mut().scratch[index].fill(0);
    }
    Ok(())
}

pub(crate) fn tmp_scratch_for(
    object_id: u64,
) -> Result<&'static [u8; OBJECT_MAX_PAYLOAD_BYTES], LinuxErrno> {
    let index = slot_index_for_object(object_id).ok_or(clean_slate_linux_abi::EINVAL)?;
    Ok(&store_mut().scratch[index])
}

pub(crate) fn object_wait_key(request_id: u64) -> crate::sched::wait::WaitKey {
    crate::sched::wait::WaitKey(0x46_u64 << 56 | (request_id & 0x00FF_FFFF_FFFF_FFFF))
}

/// Result of a synchronous object queue operation (may require syscall restart).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObjectIo {
    Done(usize),
    Restart(u64),
}

fn queue_err(e: SyscallQueueError) -> LinuxErrno {
    match e {
        SyscallQueueError::QueueFull => clean_slate_linux_abi::ENOSPC,
        SyscallQueueError::CompletionStatus(_) => clean_slate_linux_abi::EIO,
        _ => clean_slate_linux_abi::EINVAL,
    }
}

pub(crate) fn object_read_sync(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    pid: u64,
    object_id: u64,
    out: &mut [u8],
) -> Result<ObjectIo, LinuxErrno> {
    let holder = HolderId(pid);
    let state = slot_for_object_mut(object_id).ok_or(clean_slate_linux_abi::ENOENT)?;
    if state.pending_request_id == 0 {
        state.pending_request_id =
            object_queue_submit(holder, OBJECT_OP_READ, object_id, &[]).map_err(queue_err)?;
    }
    let request_id = state.pending_request_id;
    let key = object_wait_key(request_id);
    let mut payload = [0u8; OBJECT_MAX_PAYLOAD_BYTES];
    match object_queue_poll(holder, request_id, &mut payload) {
        Ok(status) if status == OBJECT_STATUS_PENDING => {
            block_linux_syscall(request, ctx, key, None, LinuxTimeoutResult::Zero)
                .map(ObjectIo::Restart)
        }
        Ok(len) => {
            state.pending_request_id = 0;
            let len = len as usize;
            state.len = len;
            if let Some(index) = slot_index_for_object(object_id) {
                store_mut().scratch[index][..len].copy_from_slice(&payload[..len]);
            }
            let take = len.min(out.len());
            out[..take].copy_from_slice(&payload[..take]);
            Ok(ObjectIo::Done(take))
        }
        Err(SyscallQueueError::CompletionStatus(_)) => {
            state.pending_request_id = 0;
            Err(clean_slate_linux_abi::EIO)
        }
        Err(e) => {
            state.pending_request_id = 0;
            Err(queue_err(e))
        }
    }
}

pub(crate) fn object_write_sync(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    pid: u64,
    object_id: u64,
    payload: &[u8],
) -> Result<ObjectIo, LinuxErrno> {
    if payload.len() > OBJECT_MAX_PAYLOAD_BYTES {
        return Err(clean_slate_linux_abi::EFBIG);
    }
    let holder = HolderId(pid);
    let state = slot_for_object_mut(object_id).ok_or(clean_slate_linux_abi::ENOENT)?;
    if state.pending_request_id == 0 {
        state.pending_request_id =
            object_queue_submit(holder, OBJECT_OP_WRITE, object_id, payload).map_err(queue_err)?;
    }
    let request_id = state.pending_request_id;
    let key = object_wait_key(request_id);
    let mut scratch = [0u8; OBJECT_MAX_PAYLOAD_BYTES];
    match object_queue_poll(holder, request_id, &mut scratch) {
        Ok(status) if status == OBJECT_STATUS_PENDING => {
            block_linux_syscall(request, ctx, key, None, LinuxTimeoutResult::Zero)
                .map(ObjectIo::Restart)
        }
        Ok(_) => {
            state.pending_request_id = 0;
            state.len = payload.len();
            if let Some(index) = slot_index_for_object(object_id) {
                store_mut().scratch[index][..payload.len()].copy_from_slice(payload);
            }
            crate::diagnostics::log::kernel_log_fmt(format_args!(
                "[STOR] write object={object_id} bytes={}\n",
                payload.len()
            ));
            Ok(ObjectIo::Done(payload.len()))
        }
        Err(SyscallQueueError::CompletionStatus(_)) => {
            state.pending_request_id = 0;
            Err(clean_slate_linux_abi::EIO)
        }
        Err(e) => {
            state.pending_request_id = 0;
            Err(queue_err(e))
        }
    }
}
