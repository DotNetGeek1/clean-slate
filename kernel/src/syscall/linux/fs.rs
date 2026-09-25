//! Linux filesystem/path syscall family (#101).

use super::table::{LinuxSyscallContext, LinuxSyscallHandler};
use super::user_copy::copy_user_path_cstring;
use crate::mm::user_mapping::validate_user_writable_pointer_range;
use crate::process::linux_fd::{
    self,
    open_description::{DescriptorKind, DirHandleRef, FileHandleRef, OpenAccess, OpenStatus},
};
use crate::process::linux_fs::namespace::{check_write_allowed, NodeId};
use crate::process::linux_fs::path::{resolve_path, LINUX_PATH_MAX};
use crate::process::linux_fs::table_mut;
use crate::process::linux_rootfs;
use clean_slate_linux_abi::{
    encode_dirent64, encode_stat144, LinuxErrno, LinuxSyscallRequest, LinuxSyscallResult, EFAULT,
    EINVAL, EISDIR, ENOTDIR, O_CREAT, O_DIRECTORY, O_RDONLY, O_TRUNC, O_WRONLY, SYS_GETCWD,
    SYS_GETDENTS64, SYS_LSTAT, SYS_MKDIR, SYS_OPEN, SYS_STAT,
};

pub(crate) fn lookup_handler(nr: u64) -> Option<LinuxSyscallHandler> {
    match nr {
        SYS_OPEN => Some(handle_sys_open),
        SYS_STAT => Some(handle_sys_stat),
        SYS_LSTAT => Some(handle_sys_lstat),
        SYS_GETCWD => Some(handle_sys_getcwd),
        SYS_MKDIR => Some(handle_sys_mkdir),
        SYS_GETDENTS64 => Some(handle_sys_getdents64),
        _ => None,
    }
}

fn image() -> clean_slate_rootfs::Image<'static> {
    linux_rootfs::image().expect("m9 rootfs embedded image")
}

fn node_from_dir_ref(r: DirHandleRef) -> NodeId {
    r.node
}

pub(crate) fn handle_sys_open(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let path_ptr = request.args[0];
    let flags = request.args[1] as u32;
    let _mode = request.args[2];
    let path = copy_path_from_user(path_ptr)?;
    check_write_allowed(path.as_bytes(), flags)?;
    let image = image();
    let table = table_mut();
    let node = if (flags & O_CREAT) != 0 && (flags & O_WRONLY) != 0 {
        table.open_create_file(path.as_bytes(), (flags & O_TRUNC) != 0, &image)?
    } else {
        let follow = (flags & O_DIRECTORY) == 0;
        table.lookup_path(path.as_bytes(), &image, follow)?
    };
    let kind = table.node_kind(node)?;
    let access = match flags & 0b11 {
        O_RDONLY => OpenAccess::ReadOnly,
        O_WRONLY => OpenAccess::WriteOnly,
        _ => OpenAccess::ReadWrite,
    };
    let status = OpenStatus {
        access,
        nonblock: false,
        append: false,
    };
    let fd = match kind {
        crate::process::linux_fs::namespace::NodeKind::Dir => {
            if (flags & O_DIRECTORY) == 0 && access != OpenAccess::ReadOnly {
                return Err(EISDIR);
            }
            linux_fd::alloc_dir_description(
                ctx.pid,
                ctx.instance_generation,
                DirHandleRef { node },
                status,
            )?
        }
        _ => {
            if (flags & O_DIRECTORY) != 0 {
                return Err(ENOTDIR);
            }
            linux_fd::alloc_file_description(
                ctx.pid,
                ctx.instance_generation,
                FileHandleRef { node },
                status,
            )?
        }
    };
    Ok(fd as u64)
}

pub(crate) fn handle_sys_stat(
    request: &LinuxSyscallRequest,
    _ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let path_ptr = request.args[0];
    let stat_ptr = request.args[1];
    let path = copy_path_from_user(path_ptr)?;
    let image = image();
    let node = table_mut().lookup_path(path.as_bytes(), &image, true)?;
    write_stat(stat_ptr, node, false)?;
    Ok(0)
}

pub(crate) fn handle_sys_lstat(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let _ = ctx;
    let path_ptr = request.args[0];
    let stat_ptr = request.args[1];
    let path = copy_path_from_user(path_ptr)?;
    let image = image();
    let node = table_mut().lookup_path(path.as_bytes(), &image, false)?;
    write_stat(stat_ptr, node, true)?;
    Ok(0)
}

pub(crate) fn handle_sys_getcwd(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let _ = ctx;
    let buf = request.args[0];
    let size = request.args[1];
    if size < 2 {
        return Err(clean_slate_linux_abi::ERANGE);
    }
    let cwd = b"/";
    if size < cwd.len() as u64 + 1 {
        return Err(clean_slate_linux_abi::ERANGE);
    }
    if validate_user_writable_pointer_range(buf, cwd.len() as u64 + 1).is_err() {
        return Err(EFAULT);
    }
    let dst = buf as *mut u8;
    unsafe {
        core::ptr::copy_nonoverlapping(cwd.as_ptr(), dst, cwd.len());
        *dst.add(cwd.len()) = 0;
    }
    Ok(buf)
}

pub(crate) fn handle_sys_mkdir(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let path_ptr = request.args[0];
    let _mode = request.args[1];
    let path = copy_path_from_user(path_ptr)?;
    let image = image();
    match table_mut().mkdir(path.as_bytes(), &image) {
        Ok(()) => Ok(0),
        Err(errno) => {
            #[cfg(feature = "m9-userspace-self-test")]
            if errno == clean_slate_linux_abi::EROFS {
                use crate::diagnostics::log::kernel_log_fmt;
                kernel_log_fmt(format_args!(
                    "[M9  ] mkdir EROFS pid={} path={:?}\n",
                    ctx.pid,
                    path.as_bytes()
                ));
            }
            Err(errno)
        }
    }
}

pub(crate) fn handle_sys_getdents64(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let fd = request.args[0];
    let buf_ptr = request.args[1];
    let count = request.args[2];
    if count == 0 {
        return Ok(0);
    }
    if validate_user_writable_pointer_range(buf_ptr, count).is_err() {
        return Err(EFAULT);
    }
    let desc = linux_fd::open_description_snapshot(linux_fd::open_description_id_for_fd(
        ctx.pid,
        ctx.instance_generation,
        fd,
    )?)?;
    let dir_node = match desc.kind {
        DescriptorKind::Dir(r) => node_from_dir_ref(r),
        _ => return Err(ENOTDIR),
    };
    let image = image();
    let mut children = [(
        NodeId {
            index: 0,
            generation: 0,
        },
        0u8,
    ); 32];
    let child_count = table_mut().list_children(dir_node, &image, &mut children)?;
    let cursor = desc.offset as usize;
    if cursor >= child_count {
        return Ok(0);
    }
    let mut wrote = 0u64;
    let mut offset = 0usize;
    let mut scratch = [0u8; 256];
    while (cursor as usize) + offset < child_count {
        let (node, dt) = children[(cursor as usize) + offset];
        let name = table_mut().dirent_name(node)?;
        let n = encode_dirent64(&mut scratch, (node.index as u64) + 1, 0, dt, name);
        if n == 0 {
            if wrote == 0 {
                return Err(EINVAL);
            }
            break;
        }
        if wrote + n as u64 > count {
            if wrote == 0 {
                return Err(EINVAL);
            }
            break;
        }
        let dst = buf_ptr + wrote;
        unsafe {
            core::ptr::copy_nonoverlapping(scratch.as_ptr(), dst as *mut u8, n);
        }
        wrote += n as u64;
        offset += 1;
    }
    linux_fd::set_open_description_offset(
        ctx.pid,
        ctx.instance_generation,
        fd,
        cursor as u64 + offset as u64,
    )?;
    Ok(wrote)
}

fn write_stat(stat_ptr: u64, node: NodeId, lstat: bool) -> Result<(), LinuxErrno> {
    if validate_user_writable_pointer_range(stat_ptr, 144).is_err() {
        return Err(EFAULT);
    }
    let image = image();
    let fields = table_mut().stat_fields(node, &image, lstat)?;
    let mut buf = [0u8; 144];
    if !encode_stat144(&mut buf, &fields) {
        return Err(EINVAL);
    }
    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr(), stat_ptr as *mut u8, 144);
    }
    Ok(())
}

struct UserPathBuf {
    storage: [u8; LINUX_PATH_MAX],
    len: usize,
}

impl UserPathBuf {
    fn as_bytes(&self) -> &[u8] {
        &self.storage[..self.len]
    }
}

fn copy_path_from_user(ptr: u64) -> Result<UserPathBuf, LinuxErrno> {
    let mut scratch = [0u8; LINUX_PATH_MAX];
    let len = copy_user_path_cstring(ptr, &mut scratch)?;
    let mut storage = [0u8; LINUX_PATH_MAX];
    let norm_len = resolve_path(b"/", &scratch[..len], &mut storage)?;
    Ok(UserPathBuf {
        storage,
        len: norm_len,
    })
}

