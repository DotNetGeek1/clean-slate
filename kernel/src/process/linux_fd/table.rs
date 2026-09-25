//! Per-process Linux fd table (compatibility integers → open descriptions).

use super::open_description::{
    ConsoleSinkRef, DescriptorKind, OpenAccess, OpenDescriptionId, OpenDescriptionPool,
    OpenStatus,
};
use clean_slate_linux_abi::{LinuxErrno, EBADF, EMFILE};

/// Per-process fd table size (highest observed fd 11 + headroom for dup2 tests).
pub(crate) const LINUX_FD_TABLE_CAPACITY: usize = 16;

/// Linux stdout (fd 1).
pub(crate) const LINUX_STDOUT_FD: u64 = 1;
/// Linux stderr (fd 2).
pub(crate) const LINUX_STDERR_FD: u64 = 2;

/// Per-fd flags (`FD_CLOEXEC` is per integer slot, not on the open description).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct FdFlags {
    pub(crate) cloexec: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FdEntry {
    pub(crate) open: OpenDescriptionId,
    pub(crate) flags: FdFlags,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LinuxFdTable {
    pub(crate) entries: [Option<FdEntry>; LINUX_FD_TABLE_CAPACITY],
}

impl LinuxFdTable {
    pub(crate) const fn empty() -> Self {
        Self {
            entries: [None; LINUX_FD_TABLE_CAPACITY],
        }
    }

    pub(crate) fn get(&self, fd: u64) -> Option<&FdEntry> {
        let index = usize::try_from(fd).ok()?;
        self.entries.get(index).and_then(|slot| slot.as_ref())
    }

    pub(crate) fn get_mut(&mut self, fd: u64) -> Option<&mut FdEntry> {
        let index = usize::try_from(fd).ok()?;
        self.entries.get_mut(index).and_then(|slot| slot.as_mut())
    }

    pub(crate) fn clear_entry(&mut self, fd: u64) {
        if let Ok(index) = usize::try_from(fd) {
            if let Some(slot) = self.entries.get_mut(index) {
                *slot = None;
            }
        }
    }

    pub(crate) fn alloc_lowest(
        &mut self,
        pool: &mut OpenDescriptionPool,
        open: OpenDescriptionId,
        flags: FdFlags,
    ) -> Result<i32, LinuxErrno> {
        for (index, slot) in self.entries.iter_mut().enumerate() {
            if slot.is_none() {
                pool.attach_first_ref(open)?;
                *slot = Some(FdEntry { open, flags });
                return Ok(index as i32);
            }
        }
        Err(EMFILE)
    }

    pub(crate) fn set_at(
        &mut self,
        pool: &mut OpenDescriptionPool,
        fd: u64,
        open: OpenDescriptionId,
        flags: FdFlags,
    ) -> Result<(), LinuxErrno> {
        let index = usize::try_from(fd)
            .ok()
            .filter(|i| *i < LINUX_FD_TABLE_CAPACITY)
            .ok_or(EBADF)?;
        if self.entries[index].is_some() {
            return Err(EMFILE);
        }
        pool.attach_first_ref(open)?;
        self.entries[index] = Some(FdEntry { open, flags });
        Ok(())
    }
}

pub(crate) fn close_fd_entry(
    table: &mut LinuxFdTable,
    pool: &mut OpenDescriptionPool,
    fd: u64,
) -> Result<(), LinuxErrno> {
    let entry = table.get(fd).ok_or(EBADF)?;
    let open = entry.open;
    table.clear_entry(fd);
    pool.release_ref(open)?;
    Ok(())
}

pub(crate) fn dup2_fd(
    table: &mut LinuxFdTable,
    pool: &mut OpenDescriptionPool,
    old_fd: u64,
    new_fd: u64,
) -> Result<(), LinuxErrno> {
    if old_fd == new_fd {
        return table.get(old_fd).map(|_| ()).ok_or(EBADF);
    }
    let old = table.get(old_fd).ok_or(EBADF)?;
    let open = old.open;
    let flags = FdFlags { cloexec: false };
    if table.get(new_fd).is_some() {
        close_fd_entry(table, pool, new_fd)?;
    }
    let index = usize::try_from(new_fd)
        .ok()
        .filter(|i| *i < LINUX_FD_TABLE_CAPACITY)
        .ok_or(EBADF)?;
    pool.add_ref(open)?;
    table.entries[index] = Some(FdEntry { open, flags });
    Ok(())
}

pub(crate) fn inherit_table(
    parent: &LinuxFdTable,
    pool: &mut OpenDescriptionPool,
    child: &mut LinuxFdTable,
) -> Result<(), LinuxErrno> {
    *child = LinuxFdTable::empty();
    for (index, entry) in parent.entries.iter().enumerate() {
        if let Some(entry) = entry {
            pool.add_ref(entry.open)?;
            child.entries[index] = Some(*entry);
        }
    }
    Ok(())
}

pub(crate) fn close_on_exec(table: &mut LinuxFdTable, pool: &mut OpenDescriptionPool) {
    for index in 0..LINUX_FD_TABLE_CAPACITY {
        if let Some(entry) = table.entries[index] {
            if entry.flags.cloexec {
                let _ = close_fd_entry(table, pool, index as u64);
            }
        }
    }
}

pub(crate) fn release_table(
    table: &mut LinuxFdTable,
    pool: &mut OpenDescriptionPool,
) -> Result<(), LinuxErrno> {
    for index in 0..LINUX_FD_TABLE_CAPACITY {
        if table.entries[index].is_some() {
            close_fd_entry(table, pool, index as u64)?;
        }
    }
    Ok(())
}

pub(crate) fn install_stdio_entries(
    table: &mut LinuxFdTable,
    pool: &mut OpenDescriptionPool,
    pid: u64,
    stdout_handle: u64,
    stderr_handle: u64,
) -> Result<(), LinuxErrno> {
    *table = LinuxFdTable::empty();
    let write_status = OpenStatus {
        access: OpenAccess::WriteOnly,
        nonblock: false,
        append: false,
    };
    let stdout_open = pool.alloc_console(
        pid,
        ConsoleSinkRef {
            capability_handle: stdout_handle,
        },
        write_status,
    )?;
    let stderr_open = pool.alloc_console(
        pid,
        ConsoleSinkRef {
            capability_handle: stderr_handle,
        },
        write_status,
    )?;
    pool.attach_first_ref(stdout_open)?;
    pool.attach_first_ref(stderr_open)?;
    table.entries[LINUX_STDOUT_FD as usize] = Some(FdEntry {
        open: stdout_open,
        flags: FdFlags::default(),
    });
    table.entries[LINUX_STDERR_FD as usize] = Some(FdEntry {
        open: stderr_open,
        flags: FdFlags::default(),
    });
    Ok(())
}

/// After `fork(2)`, inherited stdio fds share open descriptions whose console handles
/// still name the parent holder. Replace fd 1/2 with child-local console descriptions
/// when they still point at a console backend (leave pipes/files shared as-is).
pub(crate) fn rebind_console_stdio_if_console(
    table: &mut LinuxFdTable,
    pool: &mut OpenDescriptionPool,
    owner_pid: u64,
    fd: u64,
    capability_handle: u64,
) -> Result<(), LinuxErrno> {
    let Some(entry) = table.get(fd).copied() else {
        return Ok(());
    };
    if !matches!(
        pool.get(entry.open)?.kind,
        DescriptorKind::Console(_)
    ) {
        return Ok(());
    }
    let flags = entry.flags;
    close_fd_entry(table, pool, fd)?;
    let write_status = OpenStatus {
        access: OpenAccess::WriteOnly,
        nonblock: false,
        append: false,
    };
    let open = pool.alloc_console(
        owner_pid,
        ConsoleSinkRef {
            capability_handle,
        },
        write_status,
    )?;
    pool.attach_first_ref(open)?;
    table.entries[usize::try_from(fd).map_err(|_| EBADF)?] = Some(FdEntry { open, flags });
    Ok(())
}
