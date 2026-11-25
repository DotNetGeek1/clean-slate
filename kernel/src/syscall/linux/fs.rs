//! Linux filesystem/path syscall family (#101).

use super::table::{LinuxSyscallContext, LinuxSyscallHandler};
use super::user_copy::copy_user_path_cstring;
use crate::mm::user_access::copy_to_user;
use crate::mm::user_mapping::validate_user_writable_pointer_range;
use crate::process::linux_fd::{
    self,
    open_description::{DescriptorKind, DirHandleRef, FileHandleRef, OpenAccess, OpenStatus},
    FdFlags,
};
use crate::process::linux_fs::home_backend::{self as home, is_home_path, step, Flow};
use crate::process::linux_fs::namespace::{
    check_write_allowed, is_tmp_path, open_write_intent, NodeId,
};
use crate::process::linux_fs::object_backend::authorize_tmp_namespace_write;
use crate::process::linux_fs::path::{resolve_path, LINUX_PATH_MAX};
use crate::process::linux_fs::table_mut;
use crate::process::linux_rootfs;
use clean_slate_linux_abi::{
    encode_dirent64, encode_stat144, LinuxErrno, LinuxSyscallRequest, LinuxSyscallResult, EFAULT,
    EINVAL, EISDIR, ENOENT, ENOTDIR, EROFS, EXDEV, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_LARGEFILE,
    O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, SYS_FDATASYNC, SYS_FSTAT, SYS_FSYNC, SYS_FTRUNCATE,
    SYS_GETCWD, SYS_GETDENTS64, SYS_LSTAT, SYS_MKDIR, SYS_OPEN, SYS_RENAME, SYS_STAT, SYS_UNLINK,
    S_IFCHR, S_IFIFO, S_IFSOCK,
};

pub(crate) fn lookup_handler(nr: u64) -> Option<LinuxSyscallHandler> {
    match nr {
        SYS_OPEN => Some(handle_sys_open),
        SYS_STAT => Some(handle_sys_stat),
        SYS_FSTAT => Some(handle_sys_fstat),
        SYS_FSYNC | SYS_FDATASYNC => Some(handle_sys_fsync),
        SYS_FTRUNCATE => Some(handle_sys_ftruncate),
        SYS_RENAME => Some(handle_sys_rename),
        SYS_UNLINK => Some(handle_sys_unlink),
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
    let fd_flags = open_fd_flags(flags)?;
    let path = copy_path_from_user(path_ptr)?;
    // As in Linux, a missing fd fails the open before the path is resolved, so an
    // EMFILE/ENFILE open never creates or truncates a file.
    linux_fd::check_description_and_fd_available(ctx.pid, ctx.instance_generation)?;
    check_write_allowed(path.as_bytes(), flags)?;
    if is_home_path(path.as_bytes()) {
        let pid = ctx.pid;
        return flow_result(home::finish(
            pid,
            open_home(request, ctx, path.as_bytes(), flags, fd_flags),
        ));
    }
    if open_write_intent(flags) && is_tmp_path(path.as_bytes())? {
        authorize_tmp_namespace_write(ctx.pid)?;
    }
    let image = image();
    let table = table_mut();
    let access = flags & 0b11;
    let may_create = (flags & O_CREAT) != 0 && (access == O_WRONLY || access == O_RDWR);
    let node = if may_create {
        table.open_create_file(path.as_bytes(), (flags & O_TRUNC) != 0, &image)?
    } else {
        let follow = (flags & O_DIRECTORY) == 0;
        table.lookup_path(path.as_bytes(), &image, follow)?
    };
    alloc_open_fd(ctx, node, flags, fd_flags)
}

/// The value a `/home` handler returns to user space: its result, or the restart value of
/// a blocked step.
fn flow_result(result: Result<home::Flow<u64>, LinuxErrno>) -> LinuxSyscallResult {
    match result? {
        home::Flow::Done(value) | home::Flow::Restart(value) => Ok(value),
    }
}

/// `open` of `/home` or a file in it (#304): loads the table, creates or truncates through
/// the storage service, then opens the node like any other.
fn open_home(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    path: &[u8],
    flags: u32,
    fd_flags: FdFlags,
) -> Result<home::Flow<u64>, LinuxErrno> {
    let write = open_write_intent(flags);
    step!(home::ensure_loaded(request, ctx, write)?);
    let image = image();
    let access = flags & 0b11;
    let writable = access == O_WRONLY || access == O_RDWR;
    if let Some(name) = home::home_file_name(path) {
        if name.contains(&b'/') {
            return Err(ENOENT);
        }
        let slot = match home::table().find(name) {
            Some(slot) => slot,
            None if (flags & O_CREAT) != 0 && writable => step!(home::create(request, ctx, name)?),
            None => return Err(ENOENT),
        };
        if (flags & O_TRUNC) != 0 && writable && home::file_len(slot) != 0 {
            step!(home::truncate(request, ctx, slot, 0)?);
        }
    } else if write && (flags & O_DIRECTORY) == 0 {
        return Err(EISDIR);
    }
    let follow = (flags & O_DIRECTORY) == 0;
    let node = table_mut().lookup_path(path, &image, follow)?;
    alloc_open_fd(ctx, node, flags, fd_flags).map(home::Flow::Done)
}

/// Opens `node` as a new fd with `open(2)` `flags`.
fn alloc_open_fd(
    ctx: &mut LinuxSyscallContext<'_>,
    node: NodeId,
    flags: u32,
    fd_flags: FdFlags,
) -> LinuxSyscallResult {
    let table = table_mut();
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
                fd_flags,
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
                fd_flags,
            )?
        }
    };
    Ok(fd as u64)
}

const OPEN_ACCESS_MASK: u32 = 0b11;
/// `O_LARGEFILE` is accepted as a no-op (x86-64 offsets are already 64-bit). Every
/// other bit outside this set, including `O_APPEND`/`O_NONBLOCK`, is not implemented
/// for filesystem opens and is refused rather than silently ignored.
const OPEN_SUPPORTED_FLAGS: u32 =
    OPEN_ACCESS_MASK | O_CREAT | O_TRUNC | O_DIRECTORY | O_LARGEFILE | O_CLOEXEC;

/// Validates `open(2)` flags and derives the per-fd flags of the new descriptor.
/// `O_CREAT | O_DIRECTORY` is refused as in Linux 6.4+, rather than creating a
/// file and then failing with `ENOTDIR`.
fn open_fd_flags(flags: u32) -> Result<FdFlags, LinuxErrno> {
    if flags & !OPEN_SUPPORTED_FLAGS != 0
        || flags & OPEN_ACCESS_MASK == OPEN_ACCESS_MASK
        || flags & (O_CREAT | O_DIRECTORY) == O_CREAT | O_DIRECTORY
    {
        return Err(EINVAL);
    }
    Ok(FdFlags {
        cloexec: flags & O_CLOEXEC != 0,
    })
}

pub(crate) fn handle_sys_stat(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let path_ptr = request.args[0];
    let stat_ptr = request.args[1];
    let path = copy_path_from_user(path_ptr)?;
    if let Some(rax) = load_home_for_path(request, ctx, path.as_bytes())? {
        return Ok(rax);
    }
    let image = image();
    let node = table_mut().lookup_path(path.as_bytes(), &image, true)?;
    write_stat(stat_ptr, node, false)?;
    Ok(0)
}

pub(crate) fn handle_sys_lstat(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let path_ptr = request.args[0];
    let stat_ptr = request.args[1];
    let path = copy_path_from_user(path_ptr)?;
    if let Some(rax) = load_home_for_path(request, ctx, path.as_bytes())? {
        return Ok(rax);
    }
    let image = image();
    let node = table_mut().lookup_path(path.as_bytes(), &image, false)?;
    write_stat(stat_ptr, node, true)?;
    Ok(0)
}

/// Loads the `/home` table before a lookup of a path in it; `Some` is a restart value.
fn load_home_for_path(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    path: &[u8],
) -> Result<Option<u64>, LinuxErrno> {
    if !is_home_path(path) {
        return Ok(None);
    }
    let pid = ctx.pid;
    match home::finish(pid, home::ensure_loaded(request, ctx, false))? {
        home::Flow::Done(()) => Ok(None),
        home::Flow::Restart(rax) => Ok(Some(rax)),
    }
}

pub(crate) fn handle_sys_fstat(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let fd = request.args[0];
    let stat_ptr = request.args[1];
    let desc = linux_fd::open_description_snapshot(linux_fd::open_description_id_for_fd(
        ctx.pid,
        ctx.instance_generation,
        fd,
    )?)?;
    let mode = match desc.kind {
        DescriptorKind::File(file) => return write_stat(stat_ptr, file.node, false).map(|()| 0),
        DescriptorKind::Dir(dir) => return write_stat(stat_ptr, dir.node, false).map(|()| 0),
        DescriptorKind::Console(_) | DescriptorKind::ConsoleInput => S_IFCHR | 0o620,
        DescriptorKind::PipeRead(_) | DescriptorKind::PipeWrite(_) => S_IFIFO | 0o600,
        DescriptorKind::Socket(_) => S_IFSOCK | 0o777,
    };
    if validate_user_writable_pointer_range(stat_ptr, 144).is_err() {
        return Err(EFAULT);
    }
    let fields = clean_slate_linux_abi::LinuxStatFields {
        st_dev: 0,
        st_ino: fd + 1,
        st_nlink: 1,
        st_mode: mode,
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 4096,
        st_blocks: 0,
    };
    let mut buf = [0u8; 144];
    if !encode_stat144(&mut buf, &fields) {
        return Err(EINVAL);
    }
    copy_to_user(stat_ptr, &buf).map_err(|_| EFAULT)?;
    Ok(0)
}

/// The `/home` slot and access of a file fd, or `None` for any other fd.
fn home_file_fd(
    ctx: &LinuxSyscallContext<'_>,
    fd: u64,
) -> Result<Option<(usize, OpenAccess)>, LinuxErrno> {
    let desc = linux_fd::open_description_snapshot(linux_fd::open_description_id_for_fd(
        ctx.pid,
        ctx.instance_generation,
        fd,
    )?)?;
    let DescriptorKind::File(file) = desc.kind else {
        return Ok(None);
    };
    let Ok(slot) = table_mut().home_slot_for_node(file.node) else {
        return Ok(None);
    };
    let access = linux_fd::open_description_status(ctx.pid, ctx.instance_generation, fd)?.access;
    Ok(Some((slot, access)))
}

/// `fsync`/`fdatasync`: a `/home` file commits every staged change; a `/tmp` write is
/// durable when it returns and the root image never changes, so they have nothing to do.
pub(crate) fn handle_sys_fsync(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let fd = request.args[0];
    let desc = linux_fd::open_description_snapshot(linux_fd::open_description_id_for_fd(
        ctx.pid,
        ctx.instance_generation,
        fd,
    )?)?;
    match desc.kind {
        DescriptorKind::File(_) | DescriptorKind::Dir(_) => {}
        _ => return Err(EINVAL),
    }
    if home_file_fd(ctx, fd)?.is_none() {
        return Ok(0);
    }
    let pid = ctx.pid;
    flow_result(home::finish(pid, home::sync(request, ctx).map(map_unit)))
}

/// Commits `/home` before closing a writable fd on one of its files, so `close` is a
/// commit point. `Some` is a restart value; on `None` the caller closes the fd.
pub(crate) fn sync_home_before_close(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    fd: u64,
) -> Result<Option<u64>, LinuxErrno> {
    match home_file_fd(ctx, fd) {
        Ok(Some((_, access))) if access != OpenAccess::ReadOnly => {}
        _ => return Ok(None),
    }
    let pid = ctx.pid;
    match home::finish(pid, home::sync(request, ctx))? {
        home::Flow::Done(()) => Ok(None),
        home::Flow::Restart(rax) => Ok(Some(rax)),
    }
}

fn map_unit(flow: home::Flow<()>) -> home::Flow<u64> {
    match flow {
        home::Flow::Done(()) => home::Flow::Done(0),
        home::Flow::Restart(rax) => home::Flow::Restart(rax),
    }
}

pub(crate) fn handle_sys_ftruncate(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let fd = request.args[0];
    let len = request.args[1] as i64;
    if len < 0 {
        return Err(EINVAL);
    }
    let Some((slot, access)) = home_file_fd(ctx, fd)? else {
        // `/tmp` files and the root image cannot be truncated through an fd (yet).
        return Err(EINVAL);
    };
    if access == OpenAccess::ReadOnly {
        return Err(EINVAL);
    }
    let pid = ctx.pid;
    flow_result(home::finish(
        pid,
        home::truncate(request, ctx, slot, len as u64).map(map_unit),
    ))
}

/// The name of a `/home` file path, `EISDIR` for `/home` itself, and the errno for a path
/// outside it: `EPERM` in `/tmp`, which has no unlink or rename, `EROFS` elsewhere.
fn home_name_or_errno(path: &[u8]) -> Result<&[u8], LinuxErrno> {
    if path == home::LINUX_HOME_PATH {
        return Err(EISDIR);
    }
    if let Some(name) = home::home_file_name(path) {
        return if name.contains(&b'/') {
            Err(ENOENT)
        } else {
            Ok(name)
        };
    }
    if is_tmp_path(path)? {
        Err(clean_slate_linux_abi::EPERM)
    } else {
        Err(EROFS)
    }
}

pub(crate) fn handle_sys_unlink(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let path = copy_path_from_user(request.args[0])?;
    let name = home_name_or_errno(path.as_bytes())?;
    let pid = ctx.pid;
    flow_result(home::finish(pid, unlink_home(request, ctx, name)))
}

fn unlink_home(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    name: &[u8],
) -> Result<home::Flow<u64>, LinuxErrno> {
    step!(home::ensure_loaded(request, ctx, true)?);
    let slot = step!(home::unlink(request, ctx, name)?);
    table_mut().evict_home_file(slot);
    Ok(home::Flow::Done(0))
}

pub(crate) fn handle_sys_rename(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let from = copy_path_from_user(request.args[0])?;
    let to = copy_path_from_user(request.args[1])?;
    match (is_home_path(from.as_bytes()), is_home_path(to.as_bytes())) {
        (true, true) => {}
        (true, false) | (false, true) => return Err(EXDEV),
        (false, false) => {
            home_name_or_errno(from.as_bytes())?;
            return Err(EROFS);
        }
    }
    let from_name = home_name_or_errno(from.as_bytes())?;
    let to_name = home_name_or_errno(to.as_bytes())?;
    let pid = ctx.pid;
    flow_result(home::finish(
        pid,
        rename_home(request, ctx, from_name, to_name),
    ))
}

fn rename_home(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    from: &[u8],
    to: &[u8],
) -> Result<home::Flow<u64>, LinuxErrno> {
    step!(home::ensure_loaded(request, ctx, true)?);
    let (slot, victim) = step!(home::rename(request, ctx, from, to)?);
    let table = table_mut();
    if let Some(victim) = victim {
        table.evict_home_file(victim);
    }
    table.rename_home_file(slot, to);
    Ok(home::Flow::Done(0))
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
    let cwd = b"/\0";
    if size < cwd.len() as u64 {
        return Err(clean_slate_linux_abi::ERANGE);
    }
    copy_to_user(buf, cwd).map_err(|_| EFAULT)?;
    Ok(cwd.len() as u64)
}

pub(crate) fn handle_sys_mkdir(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let path_ptr = request.args[0];
    let _mode = request.args[1];
    let path = copy_path_from_user(path_ptr)?;
    if is_tmp_path(path.as_bytes())? {
        authorize_tmp_namespace_write(ctx.pid)?;
    }
    let image = image();
    table_mut().mkdir(path.as_bytes(), &image).map(|()| 0)
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
        copy_to_user(buf_ptr + wrote, &scratch[..n]).map_err(|_| EFAULT)?;
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
    copy_to_user(stat_ptr, &buf).map_err(|_| EFAULT)
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

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_linux_abi::{O_APPEND, O_NONBLOCK};

    #[test]
    fn open_cloexec_sets_fd_cloexec() {
        let frozen_file = O_RDONLY | O_LARGEFILE | O_CLOEXEC;
        let frozen_dir = O_RDONLY | O_LARGEFILE | O_CLOEXEC | O_DIRECTORY;
        assert_eq!(open_fd_flags(frozen_file), Ok(FdFlags { cloexec: true }));
        assert_eq!(open_fd_flags(frozen_dir), Ok(FdFlags { cloexec: true }));
        assert_eq!(
            open_fd_flags(O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC),
            Ok(FdFlags { cloexec: true })
        );
    }

    #[test]
    fn open_without_cloexec_leaves_fd_flags_clear() {
        for flags in [
            O_RDONLY,
            O_RDONLY | O_LARGEFILE,
            O_RDONLY | O_DIRECTORY,
            O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE,
            O_RDWR,
        ] {
            assert_eq!(open_fd_flags(flags), Ok(FdFlags { cloexec: false }));
        }
    }

    #[test]
    fn open_unsupported_flags_are_einval() {
        for flags in [
            O_RDONLY | O_APPEND,
            O_WRONLY | O_NONBLOCK,
            O_RDONLY | O_CLOEXEC | 0x4000_0000,
            OPEN_ACCESS_MASK,
            O_RDWR | O_CREAT | O_DIRECTORY,
        ] {
            assert_eq!(open_fd_flags(flags), Err(EINVAL), "flags={flags:#x}");
        }
    }
}
