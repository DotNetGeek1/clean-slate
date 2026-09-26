//! File-backed fd read/write/lseek helpers (#101).

use crate::process::linux_fd;
use crate::process::linux_fd::open_description::DescriptorKind;
use crate::process::linux_fs::object_backend::{object_read_sync, object_write_sync, ObjectIo};
use crate::process::linux_fs::table_mut;
use crate::process::linux_rootfs;
use crate::syscall::linux::table::LinuxSyscallContext;
use crate::syscall::linux::user_copy::{copy_user_bytes, LINUX_USER_COPY_MAX_BYTES};
use clean_slate_linux_abi::{
    LinuxErrno, LinuxSyscallRequest, LinuxSyscallResult, EBADF, EFAULT, EFBIG, EINVAL,
};
use clean_slate_service_fixtures::OBJECT_MAX_PAYLOAD_BYTES;
use clean_slate_service_lifecycle::InstanceGeneration;

fn image() -> clean_slate_rootfs::Image<'static> {
    linux_rootfs::image().expect("m9 rootfs")
}

fn tmp_file_by_len(object_id: u64) -> usize {
    crate::process::linux_fs::object_backend::tmp_file_by_object_id(object_id)
        .map(|s| s.len)
        .unwrap_or(0)
}

pub(crate) fn read_file_fd(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    pid: u64,
    generation: InstanceGeneration,
    fd: u64,
    buf: &mut [u8],
) -> LinuxSyscallResult {
    let open = linux_fd::open_description_id_for_fd(pid, generation, fd)?;
    let desc = linux_fd::open_description_snapshot(open)?;
    let file = match desc.kind {
        DescriptorKind::File(f) => f,
        _ => return Err(EBADF),
    };
    let table = table_mut();
    table.check_node(file.node)?;
    let img = image();
    if let Ok(data) = table.rootfs_entry_data(file.node, &img) {
        let start = desc.offset as usize;
        if start >= data.len() {
            return Ok(0);
        }
        let take = (data.len() - start).min(buf.len());
        buf[..take].copy_from_slice(&data[start..start + take]);
        linux_fd::set_open_description_offset(pid, generation, fd, desc.offset + take as u64)?;
        return Ok(take as u64);
    }
    if let Ok(object_id) = table.object_id_for_node(file.node) {
        let start = desc.offset as usize;
        if let Ok(take) =
            crate::process::linux_fs::object_backend::tmp_file_read_local(object_id, start, buf)
        {
            if take > 0 || tmp_file_by_len(object_id) <= start {
                linux_fd::set_open_description_offset(
                    pid,
                    generation,
                    fd,
                    desc.offset + take as u64,
                )?;
                return Ok(take as u64);
            }
        }
        let mut payload = [0u8; OBJECT_MAX_PAYLOAD_BYTES];
        match object_read_sync(request, ctx, pid, object_id, &mut payload)? {
            ObjectIo::Restart(rax) => return Ok(rax),
            ObjectIo::Done(_) => {}
        }
        let len = tmp_file_by_len(object_id);
        let start = desc.offset as usize;
        if start >= len {
            return Ok(0);
        }
        let take = (len - start).min(buf.len());
        buf[..take].copy_from_slice(&payload[start..start + take]);
        linux_fd::set_open_description_offset(pid, generation, fd, desc.offset + take as u64)?;
        return Ok(take as u64);
    }
    Err(EBADF)
}

pub(crate) fn write_file_fd(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    pid: u64,
    generation: InstanceGeneration,
    fd: u64,
    bytes: &[u8],
) -> LinuxSyscallResult {
    let open = linux_fd::open_description_id_for_fd(pid, generation, fd)?;
    let desc = linux_fd::open_description_snapshot(open)?;
    let file = match desc.kind {
        DescriptorKind::File(f) => f,
        _ => return Err(EBADF),
    };
    let table = table_mut();
    table.check_node(file.node)?;
    if table.rootfs_entry_data(file.node, &image()).is_ok() {
        return Err(EBADF);
    }
    let object_id = table.object_id_for_node(file.node)?;
    let scratch = crate::process::linux_fs::object_backend::tmp_scratch_for(object_id)?;
    let start = desc.offset as usize;
    if start.saturating_add(bytes.len()) > OBJECT_MAX_PAYLOAD_BYTES {
        return Err(EFBIG);
    }
    scratch[start..start + bytes.len()].copy_from_slice(bytes);
    let new_len = start + bytes.len();
    match object_write_sync(request, ctx, pid, object_id, &scratch[..new_len])? {
        ObjectIo::Restart(rax) => Ok(rax),
        ObjectIo::Done(n) => {
            linux_fd::set_open_description_offset(pid, generation, fd, new_len as u64)?;
            Ok(n as u64)
        }
    }
}

/// Copy the full user buffer into the tmp object scratch, then one object write (restart-safe).
pub(crate) fn write_file_fd_user(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    pid: u64,
    generation: InstanceGeneration,
    fd: u64,
    user_ptr: u64,
    count: usize,
) -> LinuxSyscallResult {
    if count == 0 {
        return Ok(0);
    }
    let open = linux_fd::open_description_id_for_fd(pid, generation, fd)?;
    let desc = linux_fd::open_description_snapshot(open)?;
    let file = match desc.kind {
        DescriptorKind::File(f) => f,
        _ => return Err(EBADF),
    };
    let table = table_mut();
    table.check_node(file.node)?;
    if table.rootfs_entry_data(file.node, &image()).is_ok() {
        return Err(EBADF);
    }
    let start = desc.offset as usize;
    if start.saturating_add(count) > OBJECT_MAX_PAYLOAD_BYTES {
        return Err(EFBIG);
    }
    let mut payload = [0u8; OBJECT_MAX_PAYLOAD_BYTES];
    let mut copied = 0usize;
    let mut chunk = [0u8; LINUX_USER_COPY_MAX_BYTES];
    while copied < count {
        let want = (count - copied).min(LINUX_USER_COPY_MAX_BYTES);
        let chunk_ptr = user_ptr.checked_add(copied as u64).ok_or(EFAULT)?;
        copy_user_bytes(chunk_ptr, want as u64, &mut chunk)?;
        payload[copied..copied + want].copy_from_slice(&chunk[..want]);
        copied += want;
    }
    write_file_fd(request, ctx, pid, generation, fd, &payload[..count])
}

pub(crate) fn lseek_file_fd(
    pid: u64,
    generation: InstanceGeneration,
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
    let img = image();
    let table = table_mut();
    table.check_node(file.node)?;
    let size = if let Ok(data) = table.rootfs_entry_data(file.node, &img) {
        data.len() as i64
    } else if let Ok(object_id) = table.object_id_for_node(file.node) {
        tmp_file_by_len(object_id) as i64
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
