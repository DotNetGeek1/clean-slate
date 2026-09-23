//! Linux filesystem/path projection (#101).
#![allow(dead_code)]

pub(crate) mod namespace;
pub(crate) mod object_backend;
pub(crate) mod path;

#[cfg(all(test, feature = "m9-rootfs"))]
mod host_tests;

use clean_slate_linux_abi::LinuxErrno;
use clean_slate_rootfs::Image;
use clean_slate_service_lifecycle::InstanceGeneration;
use namespace::NodeTable;
use path::LINUX_PATH_MAX;

use crate::sync::global_cell::GlobalCell;

static NODE_TABLE: GlobalCell<NodeTable> = GlobalCell::new(NodeTable::new());

pub(crate) struct ExecutableRef<'a> {
    pub image: &'a [u8],
    pub resolved_path_len: usize,
}

pub(crate) fn init_namespace(image: &Image<'_>) -> Result<(), &'static str> {
    let table = unsafe { &mut *NODE_TABLE.get() };
    table.init_rootfs(image)
}

pub(crate) fn table_mut() -> &'static mut NodeTable {
    unsafe { &mut *NODE_TABLE.get() }
}

pub(crate) fn table() -> &'static NodeTable {
    unsafe { &*NODE_TABLE.get() }
}

pub(crate) fn resolve_executable<'a>(
    _pid: u64,
    _generation: InstanceGeneration,
    path: &[u8],
    resolved_out: &mut [u8; LINUX_PATH_MAX],
    image: &'a Image<'a>,
) -> Result<ExecutableRef<'a>, LinuxErrno> {
    let mut norm = [0u8; LINUX_PATH_MAX];
    let len = path::normalize_path(path, &mut norm)?;
    resolved_out[..len].copy_from_slice(&norm[..len]);
    let bytes = namespace::resolve_executable_bytes(table_mut(), image, &norm[..len])?;
    Ok(ExecutableRef {
        image: bytes,
        resolved_path_len: len,
    })
}

pub(crate) fn grant_linux_tmp_object_capabilities(pid: u64) -> Result<(), &'static str> {
    object_backend::grant_linux_tmp_object_capabilities(pid)
}
