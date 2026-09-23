//! File-backed fd read/write/lseek helpers (#101).

use crate::process::linux_fd::open_description::DescriptorKind;
use crate::process::linux_fd;
use crate::process::linux_fs::table_mut;
use crate::process::linux_rootfs;
use clean_slate_linux_abi::{LinuxErrno, EBADF, EINVAL};
use clean_slate_service_fixtures::OBJECT_MAX_PAYLOAD_BYTES;

pub(crate) fn write_file_bytes(
    pid: u64,
    generation: clean_slate_service_lifecycle::InstanceGeneration,
    fd: u64,
    bytes: &[u8],
) -> Result<usize, LinuxErrno> {
    let open = linux_fd::open_description_id_for_fd(pid, generation, fd)?;
    let desc = linux_fd::open_description_snapshot(open)?;
    let file = match desc.kind {
        DescriptorKind::File(f) => f,
        _ => return Err(EBADF),
    };
    let table = table_mut();
    table.check_node(file.node)?;
    if let Ok(object_id) = table.object_id_for_node(file.node) {
        let scratch = crate::process::linux_fs::object_backend::tmp_scratch_for(object_id)?;
        let start = desc.offset as usize;
        if start + bytes.len() > OBJECT_MAX_PAYLOAD_BYTES {
            return Err(EINVAL);
        }
        scratch[start..start + bytes.len()].copy_from_slice(bytes);
        crate::process::linux_fs::object_backend::tmp_file_write_bytes(object_id, &scratch[..start + bytes.len()])?;
        linux_fd::set_open_description_offset(pid, generation, fd, desc.offset + bytes.len() as u64)?;
        return Ok(bytes.len());
    }
    Err(EBADF)
}

pub(crate) fn read_file_fd(
    pid: u64,
    generation: clean_slate_service_lifecycle::InstanceGeneration,
    fd: u64,
    buf: &mut [u8],
) -> Result<usize, LinuxErrno> {
    let open = linux_fd::open_description_id_for_fd(pid, generation, fd)?;
    let desc = linux_fd::open_description_snapshot(open)?;
    let file = match desc.kind {
        DescriptorKind::File(f) => f,
        _ => return Err(EBADF),
    };
    let image = linux_rootfs::image();
    let table = table_mut();
    table.check_node(file.node)?;
    if let Ok(data) = table.rootfs_entry_data(file.node, &image) {
        let start = desc.offset as usize;
        if start >= data.len() {
            return Ok(0);
        }
        let take = (data.len() - start).min(buf.len());
        buf[..take].copy_from_slice(&data[start..start + take]);
        linux_fd::set_open_description_offset(pid, generation, fd, desc.offset + take as u64)?;
        return Ok(take);
    }
    if let Ok(object_id) = table.object_id_for_node(file.node) {
        let state = crate::process::linux_fs::object_backend::tmp_file_by_object_id(object_id)
            .ok_or(EBADF)?;
        let start = desc.offset as usize;
        if start >= state.len {
            return Ok(0);
        }
        let data = crate::process::linux_fs::object_backend::tmp_bytes_for(object_id)?;
        let take = (data.len().saturating_sub(start)).min(buf.len());
        buf[..take].copy_from_slice(&data[start..start + take]);
        linux_fd::set_open_description_offset(pid, generation, fd, desc.offset + take as u64)?;
        return Ok(take);
    }
    Err(EBADF)
}

pub(crate) fn lseek_file_fd(
    pid: u64,
    generation: clean_slate_service_lifecycle::InstanceGeneration,
    fd: u64,
    offset: i64,
    whence: u32,
) -> Result<u64, LinuxErrno> {
    use clean_slate_linux_abi::{SEEK_CUR, SEEK_END, SEEK_SET};
    let open = linux_fd::open_description_id_for_fd(pid, generation, fd)?;
    let desc = linux_fd::open_description_snapshot(open)?;
    let file = match desc.kind {
        DescriptorKind::File(f) => f,
        _ => return Err(EBADF),
    };
    let image = linux_rootfs::image();
    let table = table_mut();
    table.check_node(file.node)?;
    let size = if let Ok(data) = table.rootfs_entry_data(file.node, &image) {
        data.len() as i64
    } else if let Ok(object_id) = table.object_id_for_node(file.node) {
        crate::process::linux_fs::object_backend::tmp_file_by_object_id(object_id)
            .map(|s| s.len as i64)
            .unwrap_or(0)
    } else {
        return Err(EBADF);
    };
    let new_off = match whence {
        SEEK_SET => offset,
        SEEK_CUR => desc.offset as i64 + offset,
        SEEK_END => size + offset,
        _ => return Err(EINVAL),
    };
    if new_off < 0 {
        return Err(EINVAL);
    }
    linux_fd::set_open_description_offset(pid, generation, fd, new_off as u64)?;
    Ok(new_off as u64)
}
