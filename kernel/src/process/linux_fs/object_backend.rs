//! Writable `/tmp` files backed by M6.3 persistent objects (#101).

use clean_slate_capability::{HolderId, Rights};
use clean_slate_linux_abi::LinuxErrno;
use clean_slate_service_fixtures::OBJECT_MAX_PAYLOAD_BYTES;

use crate::capability::object::grant_object_capability;
use crate::sync::global_cell::GlobalCell;

pub const LINUX_TMP_OBJECT_ID_BASE: u64 = 0x004C_0000;
pub const LINUX_TMP_MAX_FILES: usize = 4;
pub const LINUX_TMP_MAX_ENTRIES: usize = 8;

#[derive(Clone, Copy)]
pub(crate) struct TmpFileState {
    pub object_id: u64,
    pub len: usize,
    pub path_len: u16,
    pub path: [u8; 128],
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
    for slot in store.files.iter() {
        if let Some(state) = slot {
            if state.path_len as usize == path.len() && &state.path[..path.len()] == path {
                return Some(state.object_id);
            }
        }
    }
    None
}

pub(crate) fn tmp_file_by_object_id(object_id: u64) -> Option<TmpFileState> {
    let store = store_mut();
    for slot in store.files.iter() {
        if let Some(state) = slot {
            if state.object_id == object_id {
                return Some(*state);
            }
        }
    }
    None
}

pub(crate) fn tmp_file_write_bytes(object_id: u64, bytes: &[u8]) -> Result<(), LinuxErrno> {
    if bytes.len() > OBJECT_MAX_PAYLOAD_BYTES {
        return Err(clean_slate_linux_abi::EINVAL);
    }
    let index = (object_id - LINUX_TMP_OBJECT_ID_BASE) as usize;
    if index >= LINUX_TMP_MAX_FILES {
        return Err(clean_slate_linux_abi::EINVAL);
    }
    let store = store_mut();
    for slot in store.files.iter_mut() {
        if let Some(state) = slot {
            if state.object_id == object_id {
                state.len = bytes.len();
                store.scratch[index][..bytes.len()].copy_from_slice(bytes);
                return Ok(());
            }
        }
    }
    Err(clean_slate_linux_abi::ENOENT)
}

pub(crate) fn tmp_scratch_for(
    object_id: u64,
) -> Result<&'static mut [u8; OBJECT_MAX_PAYLOAD_BYTES], LinuxErrno> {
    let index = (object_id - LINUX_TMP_OBJECT_ID_BASE) as usize;
    if index >= LINUX_TMP_MAX_FILES {
        return Err(clean_slate_linux_abi::EINVAL);
    }
    Ok(&mut store_mut().scratch[index])
}

pub(crate) fn tmp_bytes_for(object_id: u64) -> Result<&'static [u8], LinuxErrno> {
    let state = tmp_file_by_object_id(object_id).ok_or(clean_slate_linux_abi::ENOENT)?;
    let index = (object_id - LINUX_TMP_OBJECT_ID_BASE) as usize;
    let store = store_mut();
    Ok(&store.scratch[index][..state.len])
}

pub(crate) fn object_wait_key(request_id: u64) -> crate::sched::wait::WaitKey {
    crate::sched::wait::WaitKey(0x46_u64 << 56 | (request_id & 0x00FF_FFFF_FFFF_FFFF))
}
