//! Linux fd / open-description lifecycle (#147).

#![allow(dead_code)]

pub(crate) mod console;
pub(crate) mod open_description;
pub(crate) mod readiness;
pub(crate) mod table;

use clean_slate_linux_abi::{LinuxErrno, EBADF, EMFILE};
use clean_slate_service_lifecycle::InstanceGeneration;
use console::write_console;
use open_description::{
    DescriptorKind, OpenAccess, OpenDescriptionPool, OpenStatus, PipeRef, SocketRef,
};

/// Kind dispatch for the #147 `read(2)` front-end (`write.rs` socket path).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinuxReadKind {
    Console,
    Socket(SocketRef),
    Unsupported,
}
use table::{
    close_fd_entry, close_on_exec as close_cloexec_in_table, dup2_fd, inherit_table,
    install_stdio_entries, release_table, LinuxFdTable,
};

use super::personality::ExecutionPersonality;
use super::process_registry_mut;
use super::KERNEL_PROCESS_ID;
use super::PROCESS_REGISTRY_CAPACITY;
use crate::ipc::endpoint_table_mut;
use crate::ipc::IpcEndpointTable;
use crate::sync::global_cell::GlobalCell;

#[allow(unused_imports)]
pub(crate) use console::map_ipc_send_error;
#[allow(unused_imports)]
pub(crate) use open_description::ConsoleSinkRef;
#[allow(unused_imports)]
pub(crate) use table::{LINUX_STDERR_FD, LINUX_STDOUT_FD};

const LINUX_FD_REGISTRY_CAPACITY: usize = PROCESS_REGISTRY_CAPACITY;

/// M8-compatible projection view (write path and legacy self-tests).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinuxFdProjection {
    Closed,
    ConsoleEndpoint {
        capability_handle: u64,
    },
    /// #101: file-backed description (read/write/lseek via fs_io).
    FileBackend,
    /// #101: directory-backed description (getdents64 cursor in offset).
    DirBackend,
    /// #102: pipe read/write end (pipe syscalls; not `Closed`).
    PipeBackend,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LinuxFdRegistrySlot {
    pid: u64,
    generation: InstanceGeneration,
    table: LinuxFdTable,
}

/// Kernel-owned registry: per-process fd tables + global open-description pool.
pub(crate) struct LinuxFdRegistry {
    slots: [Option<LinuxFdRegistrySlot>; LINUX_FD_REGISTRY_CAPACITY],
    pool: OpenDescriptionPool,
}

impl LinuxFdRegistry {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [None; LINUX_FD_REGISTRY_CAPACITY],
            pool: OpenDescriptionPool::new(),
        }
    }

    pub(crate) fn occupied(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    pub(crate) fn open_description_live_count(&self) -> u16 {
        self.pool.live_count()
    }

    fn slot_index(&self, pid: u64, generation: InstanceGeneration) -> Option<usize> {
        self.slots.iter().position(|slot| {
            matches!(
                slot,
                Some(entry) if entry.pid == pid && entry.generation == generation
            )
        })
    }

    fn ensure_slot_index(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
    ) -> Result<usize, &'static str> {
        if pid == KERNEL_PROCESS_ID {
            return Err("linux fd table cannot be installed for the kernel process");
        }
        if let Some(index) = self.slot_index(pid, generation) {
            return Ok(index);
        }
        let free = self
            .slots
            .iter_mut()
            .position(|slot| slot.is_none())
            .ok_or("linux fd registry capacity exceeded")?;
        self.slots[free] = Some(LinuxFdRegistrySlot {
            pid,
            generation,
            table: LinuxFdTable::empty(),
        });
        Ok(free)
    }

    pub(crate) fn install(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
        stdout_handle: u64,
        stderr_handle: u64,
    ) -> Result<(), &'static str> {
        let index = self.ensure_slot_index(pid, generation)?;
        let table = &mut self.slots[index].as_mut().expect("slot").table;
        install_stdio_entries(table, &mut self.pool, pid, stdout_handle, stderr_handle)
            .map_err(|_| "linux fd stdio install failed")
    }

    pub(crate) fn ensure_open_fd(
        &self,
        pid: u64,
        generation: InstanceGeneration,
        fd: u64,
    ) -> Result<(), LinuxErrno> {
        match self.open_fd_entry(pid, generation, fd)? {
            Some(entry) => {
                self.pool.get(entry.open)?;
                Ok(())
            }
            None => Err(EBADF),
        }
    }

    fn open_fd_entry(
        &self,
        pid: u64,
        generation: InstanceGeneration,
        fd: u64,
    ) -> Result<Option<FdEntry>, LinuxErrno> {
        let index = usize::try_from(fd)
            .ok()
            .filter(|index| *index < LINUX_FD_TABLE_CAPACITY)
            .ok_or(EBADF)?;
        let slot = self.slot_index(pid, generation).ok_or(EBADF)?;
        Ok(self.slots[slot]
            .as_ref()
            .expect("slot")
            .table
            .entries
            .get(index)
            .and_then(|entry| *entry))
    }

    pub(crate) fn projection_for(
        &self,
        pid: u64,
        generation: InstanceGeneration,
        fd: u64,
    ) -> Result<LinuxFdProjection, LinuxErrno> {
        let entry = match self.open_fd_entry(pid, generation, fd)? {
            Some(entry) => entry,
            None => return Ok(LinuxFdProjection::Closed),
        };
        let desc = self.pool.get(entry.open)?;
        match desc.kind {
            DescriptorKind::Console(sink) => Ok(LinuxFdProjection::ConsoleEndpoint {
                capability_handle: sink.capability_handle,
            }),
            DescriptorKind::File(_) => Ok(LinuxFdProjection::FileBackend),
            DescriptorKind::Dir(_) => Ok(LinuxFdProjection::DirBackend),
            DescriptorKind::PipeRead(_) | DescriptorKind::PipeWrite(_) => {
                Ok(LinuxFdProjection::PipeBackend)
            }
            DescriptorKind::Socket(_) => Ok(LinuxFdProjection::Closed),
        }
    }

    pub(crate) fn release(&mut self, pid: u64, generation: InstanceGeneration) -> bool {
        let index = self.slots.iter().position(|slot| {
            matches!(
                slot,
                Some(entry) if entry.pid == pid && entry.generation == generation
            )
        });
        let index = index.or_else(|| {
            self.slots
                .iter()
                .position(|slot| matches!(slot, Some(entry) if entry.pid == pid))
        });
        if let Some(index) = index {
            if let Some(entry) = &mut self.slots[index] {
                let _ = release_table(&mut entry.table, &mut self.pool);
            }
            self.slots[index] = None;
            return true;
        }
        false
    }

    pub(crate) fn read_kind_for_fd(
        &self,
        pid: u64,
        generation: InstanceGeneration,
        fd: u64,
    ) -> Result<LinuxReadKind, LinuxErrno> {
        let index = self.slot_index(pid, generation).ok_or(EBADF)?;
        let open = self.slots[index]
            .as_ref()
            .expect("slot")
            .table
            .get(fd)
            .ok_or(EBADF)?
            .open;
        let desc = self.pool.get(open)?;
        Ok(match desc.kind {
            DescriptorKind::Console(_) => LinuxReadKind::Console,
            DescriptorKind::Socket(socket) => LinuxReadKind::Socket(socket),
            DescriptorKind::File(_)
            | DescriptorKind::Dir(_)
            | DescriptorKind::PipeRead(_)
            | DescriptorKind::PipeWrite(_) => LinuxReadKind::Unsupported,
        })
    }

    pub(crate) fn write_fd(
        &mut self,
        ipc: &mut IpcEndpointTable,
        pid: u64,
        generation: InstanceGeneration,
        fd: u64,
        bytes: &[u8],
        personality: ExecutionPersonality,
    ) -> Result<usize, LinuxErrno> {
        let index = self.slot_index(pid, generation).ok_or(EBADF)?;
        let open = self.slots[index]
            .as_ref()
            .expect("slot")
            .table
            .get(fd)
            .ok_or(EBADF)?
            .open;
        let desc = self.pool.get(open)?;
        match desc.kind {
            DescriptorKind::Console(sink) => write_console(ipc, pid, sink, bytes, personality),
            // #102 pipe writes use blocking path from syscall/write.rs
            DescriptorKind::PipeWrite(_) => Err(EBADF),
            // #101: file writes go through `write(2)` → `handle_sys_write` + `fs_io::write_file_fd`.
            DescriptorKind::File(_) => Err(EBADF),
            DescriptorKind::Socket(_) => Err(EBADF),
            _ => Err(EBADF),
        }
    }

    pub(crate) fn alloc_pipe_description(
        &mut self,
        owner_pid: u64,
        pipe: PipeRef,
    ) -> Result<OpenDescriptionId, LinuxErrno> {
        self.pool.alloc_pipe(owner_pid, pipe)
    }

    fn pool_mut(&mut self) -> &mut OpenDescriptionPool {
        &mut self.pool
    }

    pub(crate) fn open_description_kind(
        &self,
        pid: u64,
        generation: InstanceGeneration,
        fd: u64,
    ) -> Result<DescriptorKind, LinuxErrno> {
        let index = self.slot_index(pid, generation).ok_or(EBADF)?;
        let open = self.slots[index]
            .as_ref()
            .expect("slot")
            .table
            .get(fd)
            .ok_or(EBADF)?
            .open;
        Ok(self.pool.get(open)?.kind)
    }

    pub(crate) fn pipe_read_ref(
        &self,
        pid: u64,
        generation: InstanceGeneration,
        fd: u64,
    ) -> Option<PipeRef> {
        match self.open_description_kind(pid, generation, fd).ok()? {
            DescriptorKind::PipeRead(pipe) => Some(pipe),
            _ => None,
        }
    }

    pub(crate) fn pipe_write_ref(
        &self,
        pid: u64,
        generation: InstanceGeneration,
        fd: u64,
    ) -> Option<PipeRef> {
        match self.open_description_kind(pid, generation, fd).ok()? {
            DescriptorKind::PipeWrite(pipe) => Some(pipe),
            _ => None,
        }
    }

    pub(crate) fn close_fd(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
        fd: u64,
    ) -> Result<(), LinuxErrno> {
        let index = self.slot_index(pid, generation).ok_or(EBADF)?;
        let table = &mut self.slots[index].as_mut().expect("slot").table;
        close_fd_entry(table, &mut self.pool, fd)
    }

    pub(crate) fn dup2(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
        old_fd: u64,
        new_fd: u64,
    ) -> Result<(), LinuxErrno> {
        let index = self.slot_index(pid, generation).ok_or(EBADF)?;
        let table = &mut self.slots[index].as_mut().expect("slot").table;
        dup2_fd(table, &mut self.pool, old_fd, new_fd)
    }

    pub(crate) fn set_fd_cloexec(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
        fd: u64,
        cloexec: bool,
    ) -> Result<(), LinuxErrno> {
        let index = self.slot_index(pid, generation).ok_or(EBADF)?;
        let entry = self.slots[index]
            .as_mut()
            .expect("slot")
            .table
            .get_mut(fd)
            .ok_or(EBADF)?;
        entry.flags.cloexec = cloexec;
        Ok(())
    }

    pub(crate) fn get_fd_cloexec(
        &self,
        pid: u64,
        generation: InstanceGeneration,
        fd: u64,
    ) -> Result<bool, LinuxErrno> {
        let index = self.slot_index(pid, generation).ok_or(EBADF)?;
        let entry = self.slots[index]
            .as_ref()
            .expect("slot")
            .table
            .get(fd)
            .ok_or(EBADF)?;
        Ok(entry.flags.cloexec)
    }

    pub(crate) fn open_description_status(
        &self,
        pid: u64,
        generation: InstanceGeneration,
        fd: u64,
    ) -> Result<OpenStatus, LinuxErrno> {
        let index = self.slot_index(pid, generation).ok_or(EBADF)?;
        let open = self.slots[index]
            .as_ref()
            .expect("slot")
            .table
            .get(fd)
            .ok_or(EBADF)?
            .open;
        Ok(self.pool.get(open)?.status)
    }

    pub(crate) fn set_open_description_status(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
        fd: u64,
        status: OpenStatus,
    ) -> Result<(), LinuxErrno> {
        let index = self.slot_index(pid, generation).ok_or(EBADF)?;
        let open = self.slots[index]
            .as_ref()
            .expect("slot")
            .table
            .get(fd)
            .ok_or(EBADF)?
            .open;
        self.pool.get_mut(open)?.status = status;
        Ok(())
    }

    pub(crate) fn inherit_for_child(
        &mut self,
        parent_pid: u64,
        parent_gen: InstanceGeneration,
        child_pid: u64,
        child_gen: InstanceGeneration,
    ) -> Result<(), LinuxErrno> {
        let parent_table = self
            .slots
            .get(self.slot_index(parent_pid, parent_gen).ok_or(EBADF)?)
            .and_then(|slot| slot.as_ref())
            .ok_or(EBADF)?
            .table;
        let child_index = self
            .ensure_slot_index(child_pid, child_gen)
            .map_err(|_| EBADF)?;
        let child_table = &mut self.slots[child_index].as_mut().expect("slot").table;
        inherit_table(&parent_table, &mut self.pool, child_table)
    }

    /// When the process has no fd table slot (never opened a fd), exec is a no-op.
    pub(crate) fn close_on_exec_for_process(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
    ) -> Result<(), LinuxErrno> {
        let Some(index) = self.slot_index(pid, generation) else {
            return Ok(());
        };
        let table = &mut self.slots[index].as_mut().expect("slot").table;
        close_cloexec_in_table(table, &mut self.pool);
        Ok(())
    }

    pub(crate) fn open_description_id_for_fd(
        &self,
        pid: u64,
        generation: InstanceGeneration,
        fd: u64,
    ) -> Result<OpenDescriptionId, LinuxErrno> {
        let entry = self.open_fd_entry(pid, generation, fd)?.ok_or(EBADF)?;
        Ok(entry.open)
    }

    pub(crate) fn socket_ref_for_open(
        &self,
        open: OpenDescriptionId,
    ) -> Result<SocketRef, LinuxErrno> {
        let desc = self.pool.get(open)?;
        match desc.kind {
            DescriptorKind::Socket(socket) => Ok(socket),
            _ => Err(EBADF),
        }
    }

    pub(crate) fn ensure_fd_table(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
    ) -> Result<(), LinuxErrno> {
        self.ensure_slot_index(pid, generation).map_err(|_| EBADF)?;
        Ok(())
    }

    pub(crate) fn install_socket_description(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
        socket: SocketRef,
        nonblock: bool,
    ) -> Result<i32, LinuxErrno> {
        self.ensure_fd_table(pid, generation)?;
        let status = OpenStatus {
            access: OpenAccess::ReadWrite,
            nonblock,
            append: false,
        };
        let open = self.pool.alloc_socket(pid, socket, status)?;
        self.pool.attach_first_ref(open)?;
        self.alloc_lowest_fd(pid, generation, open, FdFlags::default())
    }

    pub(crate) fn alloc_lowest_fd(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
        open: OpenDescriptionId,
        flags: FdFlags,
    ) -> Result<i32, LinuxErrno> {
        let index = self.slot_index(pid, generation).ok_or(EBADF)?;
        let table = &mut self.slots[index].as_mut().expect("slot").table;
        table.alloc_lowest(&mut self.pool, open, flags)
    }

    pub(crate) fn dup_to_lowest_at_or_above(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
        old_fd: u64,
        min_fd: u64,
    ) -> Result<i32, LinuxErrno> {
        let index = self.slot_index(pid, generation).ok_or(EBADF)?;
        let table = &mut self.slots[index].as_mut().expect("slot").table;
        let open = table.get(old_fd).ok_or(EBADF)?.open;
        let start = usize::try_from(min_fd)
            .ok()
            .filter(|i| *i < LINUX_FD_TABLE_CAPACITY);
        for slot_index in start.unwrap_or(0)..LINUX_FD_TABLE_CAPACITY {
            if table.entries[slot_index].is_none() {
                self.pool.add_ref(open)?;
                table.entries[slot_index] = Some(FdEntry {
                    open,
                    flags: FdFlags { cloexec: true },
                });
                return Ok(slot_index as i32);
            }
        }
        Err(EMFILE)
    }

    #[cfg(any(test, feature = "m9-fd-core-self-test"))]
    pub(crate) fn alloc_self_test_placeholder_file(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
    ) -> Result<i32, LinuxErrno> {
        let index = self.ensure_slot_index(pid, generation).map_err(|_| EBADF)?;
        let open = self.pool.alloc_placeholder_file(
            pid,
            open_description::FileHandleRef {
                node: open_description::LinuxFsNodeId {
                    index: 0x147,
                    generation: 1,
                },
            },
        )?;
        let table = &mut self.slots[index].as_mut().expect("slot").table;
        table.alloc_lowest(&mut self.pool, open, FdFlags::default())
    }

    pub(crate) fn alloc_description_and_fd(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
        kind: DescriptorKind,
        status: OpenStatus,
        flags: FdFlags,
    ) -> Result<i32, LinuxErrno> {
        let slot_index = self.slot_index(pid, generation).ok_or(EBADF)?;
        let open = self.pool.alloc_file_or_dir(pid, kind, status)?;
        let table = &mut self.slots[slot_index].as_mut().expect("slot").table;
        table.alloc_lowest(&mut self.pool, open, flags)
    }

    pub(crate) fn open_description_for_fd(
        &self,
        pid: u64,
        generation: InstanceGeneration,
        fd: u64,
    ) -> Result<OpenDescriptionId, LinuxErrno> {
        let slot_index = self.slot_index(pid, generation).ok_or(EBADF)?;
        Ok(self.slots[slot_index]
            .as_ref()
            .expect("slot")
            .table
            .get(fd)
            .ok_or(EBADF)?
            .open)
    }

    pub(crate) fn open_description_view(
        &self,
        open: OpenDescriptionId,
    ) -> Result<(DescriptorKind, u64), LinuxErrno> {
        let desc = self.pool.get(open)?;
        Ok((desc.kind, desc.offset))
    }

    pub(crate) fn set_description_offset(
        &mut self,
        open: OpenDescriptionId,
        offset: u64,
    ) -> Result<(), LinuxErrno> {
        self.pool.get_mut(open)?.offset = offset;
        Ok(())
    }

    #[cfg(test)]
    fn table_get_for_test(
        &self,
        pid: u64,
        generation: InstanceGeneration,
        fd: u64,
    ) -> Option<FdEntry> {
        let index = self.slot_index(pid, generation)?;
        self.slots[index]
            .as_ref()
            .expect("slot")
            .table
            .get(fd)
            .copied()
    }
}

static LINUX_FD_REGISTRY: GlobalCell<LinuxFdRegistry> = GlobalCell::new(LinuxFdRegistry::new());

fn registry_mut() -> &'static mut LinuxFdRegistry {
    unsafe { &mut *LINUX_FD_REGISTRY.get() }
}

#[cfg(any(
    test,
    feature = "m9-linux-exec-self-test",
    feature = "m9-fd-core-self-test",
    feature = "m9-linux-socket-self-test",
    feature = "m9-linux-proc-self-test",
    feature = "m9-linux-fs-self-test"
))]
pub(crate) fn reset_registry_for_selftest() {
    unsafe { *LINUX_FD_REGISTRY.get() = LinuxFdRegistry::new() };
}

pub(crate) fn install_stdio_for_process(
    pid: u64,
    generation: InstanceGeneration,
    stdout_handle: u64,
    stderr_handle: u64,
) -> Result<(), &'static str> {
    registry_mut().install(pid, generation, stdout_handle, stderr_handle)
}

pub(crate) fn projection_for(
    pid: u64,
    generation: InstanceGeneration,
    fd: u64,
) -> Result<LinuxFdProjection, LinuxErrno> {
    registry_mut().projection_for(pid, generation, fd)
}

pub(crate) fn ensure_open_fd(
    pid: u64,
    generation: InstanceGeneration,
    fd: u64,
) -> Result<(), LinuxErrno> {
    registry_mut().ensure_open_fd(pid, generation, fd)
}

pub(crate) fn install_socket_fd(
    pid: u64,
    generation: InstanceGeneration,
    socket: SocketRef,
    nonblock: bool,
) -> Result<i32, LinuxErrno> {
    registry_mut().install_socket_description(pid, generation, socket, nonblock)
}

pub(crate) fn open_id_for_fd(
    pid: u64,
    generation: InstanceGeneration,
    fd: u64,
) -> Result<OpenDescriptionId, LinuxErrno> {
    registry_mut().open_description_id_for_fd(pid, generation, fd)
}

pub(crate) fn socket_ref_for_open(open: OpenDescriptionId) -> Result<SocketRef, LinuxErrno> {
    registry_mut().socket_ref_for_open(open)
}

pub(crate) fn read_kind_for_fd(
    pid: u64,
    generation: InstanceGeneration,
    fd: u64,
) -> Result<LinuxReadKind, LinuxErrno> {
    registry_mut().read_kind_for_fd(pid, generation, fd)
}

pub(crate) fn alloc_pipe_end(
    pid: u64,
    generation: InstanceGeneration,
    pipe: PipeRef,
) -> Result<i32, LinuxErrno> {
    let registry = registry_mut();
    let index = registry
        .ensure_slot_index(pid, generation)
        .map_err(|_| EBADF)?;
    let open = registry.alloc_pipe_description(pid, pipe)?;
    registry.slots[index]
        .as_mut()
        .expect("slot")
        .table
        .alloc_lowest(&mut registry.pool, open, FdFlags::default())
}

pub(crate) fn open_description_kind(
    pid: u64,
    generation: InstanceGeneration,
    fd: u64,
) -> Result<DescriptorKind, LinuxErrno> {
    registry_mut().open_description_kind(pid, generation, fd)
}

pub(crate) fn pipe_read_ref(pid: u64, generation: InstanceGeneration, fd: u64) -> Option<PipeRef> {
    registry_mut().pipe_read_ref(pid, generation, fd)
}

pub(crate) fn pipe_write_ref(pid: u64, generation: InstanceGeneration, fd: u64) -> Option<PipeRef> {
    registry_mut().pipe_write_ref(pid, generation, fd)
}

pub(crate) fn pipe_ref_for(pid: u64, generation: InstanceGeneration, fd: u64) -> Option<PipeRef> {
    registry_mut().pipe_read_ref(pid, generation, fd)
}

pub(crate) fn write_fd(
    pid: u64,
    generation: InstanceGeneration,
    fd: u64,
    bytes: &[u8],
) -> Result<usize, LinuxErrno> {
    let personality = unsafe { process_registry_mut().get(pid) }
        .map(|process| process.execution_personality)
        .unwrap_or(ExecutionPersonality::Native);
    registry_mut().write_fd(
        unsafe { endpoint_table_mut() },
        pid,
        generation,
        fd,
        bytes,
        personality,
    )
}

pub(crate) fn release_for_process(pid: u64, generation: InstanceGeneration) {
    let registry = registry_mut();
    if registry.release(pid, generation) {
        return;
    }
    registry.release_by_pid(pid);
}

pub(crate) fn release_for_process_by_pid(pid: u64) {
    registry_mut().release_by_pid(pid);
}

pub(crate) fn release_stale_registry_slots<F>(mut registry_live: F)
where
    F: FnMut(u64) -> bool,
{
    let registry = registry_mut();
    for index in 0..PROCESS_REGISTRY_CAPACITY {
        if let Some(entry) = &registry.slots[index] {
            if !registry_live(entry.pid) {
                registry.release_by_pid(entry.pid);
            }
        }
    }
}

impl LinuxFdRegistry {
    fn release_by_pid(&mut self, pid: u64) {
        let indices: [usize; PROCESS_REGISTRY_CAPACITY] = core::array::from_fn(|index| index);
        for index in indices {
            if matches!(
                self.slots[index],
                Some(entry) if entry.pid == pid
            ) {
                if let Some(entry) = &mut self.slots[index] {
                    let _ = release_table(&mut entry.table, &mut self.pool);
                }
                self.slots[index] = None;
            }
        }
    }
}

pub(crate) fn close_fd(
    pid: u64,
    generation: InstanceGeneration,
    fd: u64,
) -> Result<(), LinuxErrno> {
    registry_mut().close_fd(pid, generation, fd)
}

pub(crate) fn dup2(
    pid: u64,
    generation: InstanceGeneration,
    old_fd: u64,
    new_fd: u64,
) -> Result<(), LinuxErrno> {
    registry_mut().dup2(pid, generation, old_fd, new_fd)
}

pub(crate) fn inherit_for_child(
    parent_pid: u64,
    parent_gen: InstanceGeneration,
    child_pid: u64,
    child_gen: InstanceGeneration,
) -> Result<(), LinuxErrno> {
    registry_mut().inherit_for_child(parent_pid, parent_gen, child_pid, child_gen)
}

/// Clears `FD_CLOEXEC` descriptors for `pid`/`generation`. Missing fd table is OK
/// (process never used the fd layer).
pub(crate) fn close_on_exec(pid: u64, generation: InstanceGeneration) -> Result<(), LinuxErrno> {
    registry_mut().close_on_exec_for_process(pid, generation)
}

pub(crate) fn open_description_pool_live_count() -> u16 {
    registry_mut().open_description_live_count()
}

pub(crate) fn get_fd_cloexec(
    pid: u64,
    generation: InstanceGeneration,
    fd: u64,
) -> Result<bool, LinuxErrno> {
    registry_mut().get_fd_cloexec(pid, generation, fd)
}

pub(crate) fn set_fd_cloexec(
    pid: u64,
    generation: InstanceGeneration,
    fd: u64,
    cloexec: bool,
) -> Result<(), LinuxErrno> {
    registry_mut().set_fd_cloexec(pid, generation, fd, cloexec)
}

pub(crate) fn open_description_status(
    pid: u64,
    generation: InstanceGeneration,
    fd: u64,
) -> Result<OpenStatus, LinuxErrno> {
    registry_mut().open_description_status(pid, generation, fd)
}

pub(crate) fn set_open_description_status(
    pid: u64,
    generation: InstanceGeneration,
    fd: u64,
    status: OpenStatus,
) -> Result<(), LinuxErrno> {
    registry_mut().set_open_description_status(pid, generation, fd, status)
}

pub(crate) fn alloc_lowest_fd(
    pid: u64,
    generation: InstanceGeneration,
    open: OpenDescriptionId,
    flags: FdFlags,
) -> Result<i32, LinuxErrno> {
    registry_mut().alloc_lowest_fd(pid, generation, open, flags)
}

pub(crate) fn alloc_file_description(
    pid: u64,
    generation: InstanceGeneration,
    file: open_description::FileHandleRef,
    status: OpenStatus,
) -> Result<i32, LinuxErrno> {
    registry_mut().alloc_description_and_fd(
        pid,
        generation,
        DescriptorKind::File(file),
        status,
        FdFlags::default(),
    )
}

pub(crate) fn alloc_dir_description(
    pid: u64,
    generation: InstanceGeneration,
    dir: open_description::DirHandleRef,
    status: OpenStatus,
) -> Result<i32, LinuxErrno> {
    registry_mut().alloc_description_and_fd(
        pid,
        generation,
        DescriptorKind::Dir(dir),
        status,
        FdFlags::default(),
    )
}

pub(crate) fn open_description_id_for_fd(
    pid: u64,
    generation: InstanceGeneration,
    fd: u64,
) -> Result<OpenDescriptionId, LinuxErrno> {
    registry_mut().open_description_for_fd(pid, generation, fd)
}

#[derive(Clone, Copy)]
pub(crate) struct OpenDescriptionSnapshot {
    pub kind: DescriptorKind,
    pub offset: u64,
}

pub(crate) fn open_description_snapshot(
    open: OpenDescriptionId,
) -> Result<OpenDescriptionSnapshot, LinuxErrno> {
    let (kind, offset) = registry_mut().open_description_view(open)?;
    Ok(OpenDescriptionSnapshot { kind, offset })
}

pub(crate) fn set_open_description_offset(
    pid: u64,
    generation: InstanceGeneration,
    fd: u64,
    offset: u64,
) -> Result<(), LinuxErrno> {
    let open = open_description_id_for_fd(pid, generation, fd)?;
    registry_mut().set_description_offset(open, offset)
}

pub(crate) fn dup_to_lowest_at_or_above(
    pid: u64,
    generation: InstanceGeneration,
    old_fd: u64,
    min_fd: u64,
) -> Result<i32, LinuxErrno> {
    registry_mut().dup_to_lowest_at_or_above(pid, generation, old_fd, min_fd)
}

#[cfg(any(test, feature = "m9-fd-core-self-test"))]
pub(crate) fn alloc_self_test_placeholder_file(
    pid: u64,
    generation: InstanceGeneration,
) -> Result<i32, LinuxErrno> {
    registry_mut().alloc_self_test_placeholder_file(pid, generation)
}

#[allow(unused_imports)]
pub(crate) use console::{console_sink_render_style, console_write_bytes, ConsoleSinkRenderStyle};
#[allow(unused_imports)]
pub(crate) use open_description::{
    apply_linux_fl_to_status, open_status_to_linux_fl, OpenDescriptionId, OPEN_DESCRIPTION_CAPACITY,
};
#[allow(unused_imports)]
pub(crate) use table::{FdEntry, FdFlags, LINUX_FD_TABLE_CAPACITY};

#[cfg(test)]
mod tests {
    use super::*;
    fn local_pair() -> (LinuxFdRegistry, IpcEndpointTable) {
        (LinuxFdRegistry::new(), IpcEndpointTable::new())
    }

    #[test]
    fn install_and_lookup_stdio_projections() {
        let (mut fds, mut ipc) = local_pair();
        let generation = InstanceGeneration(3);
        let handle = ipc
            .grant_console_capability_for_pid(10)
            .expect("shared console grant");
        fds.install(10, generation, handle, handle)
            .expect("install");

        assert_eq!(
            fds.projection_for(10, generation, LINUX_STDOUT_FD)
                .expect("stdout"),
            LinuxFdProjection::ConsoleEndpoint {
                capability_handle: handle
            }
        );
        assert_eq!(
            fds.projection_for(10, generation, LINUX_STDERR_FD)
                .expect("stderr"),
            LinuxFdProjection::ConsoleEndpoint {
                capability_handle: handle
            }
        );
        assert_eq!(
            fds.projection_for(10, generation, 0).expect("stdin closed"),
            LinuxFdProjection::Closed
        );
        assert_eq!(fds.projection_for(10, generation, 99), Err(EBADF));
    }

    #[test]
    fn lowest_fd_allocation_and_reuse() {
        let (mut fds, mut ipc) = local_pair();
        let gen = InstanceGeneration(1);
        let handle = ipc.grant_console_capability_for_pid(1).expect("grant");
        fds.install(1, gen, handle, handle).expect("install");
        let placeholder = fds
            .alloc_self_test_placeholder_file(1, gen)
            .expect("placeholder");
        assert_eq!(placeholder, 0);
        fds.close_fd(1, gen, 0).expect("close");
        let again = fds.alloc_self_test_placeholder_file(1, gen).expect("reuse");
        assert_eq!(again, 0);
    }

    #[test]
    fn dup2_shares_open_description_independent_cloexec() {
        let (mut fds, mut ipc) = local_pair();
        let gen = InstanceGeneration(1);
        let handle = ipc.grant_console_capability_for_pid(2).expect("grant");
        fds.install(2, gen, handle, handle).expect("install");
        fds.dup2(2, gen, LINUX_STDOUT_FD, 5).expect("dup2");
        fds.set_fd_cloexec(2, gen, 5, true).expect("cloexec");
        assert!(!fds.get_fd_cloexec(2, gen, LINUX_STDOUT_FD).expect("get"));
        assert!(fds.get_fd_cloexec(2, gen, 5).expect("get dup"));
        fds.close_fd(2, gen, LINUX_STDOUT_FD).expect("close old");
        assert!(fds.table_get_for_test(2, gen, 5).is_some());
    }

    #[test]
    fn double_close_is_ebadf() {
        let (mut fds, mut ipc) = local_pair();
        let gen = InstanceGeneration(1);
        let handle = ipc.grant_console_capability_for_pid(3).expect("grant");
        fds.install(3, gen, handle, handle).expect("install");
        fds.close_fd(3, gen, LINUX_STDOUT_FD).expect("close");
        assert_eq!(fds.close_fd(3, gen, LINUX_STDOUT_FD), Err(EBADF));
    }

    #[test]
    fn close_on_exec_closes_only_flagged() {
        let (mut fds, mut ipc) = local_pair();
        let gen = InstanceGeneration(1);
        let handle = ipc.grant_console_capability_for_pid(4).expect("grant");
        fds.install(4, gen, handle, handle).expect("install");
        fds.set_fd_cloexec(4, gen, LINUX_STDERR_FD, true)
            .expect("set");
        fds.close_on_exec_for_process(4, gen).expect("exec");
        assert!(fds.table_get_for_test(4, gen, LINUX_STDOUT_FD).is_some());
        assert!(fds.table_get_for_test(4, gen, LINUX_STDERR_FD).is_none());
    }

    #[test]
    fn inheritance_bumps_refcounts() {
        let (mut fds, mut ipc) = local_pair();
        let pg = InstanceGeneration(1);
        let cg = InstanceGeneration(2);
        let handle = ipc.grant_console_capability_for_pid(5).expect("grant");
        fds.install(5, pg, handle, handle).expect("install");
        let before = fds.open_description_live_count();
        fds.inherit_for_child(5, pg, 6, cg).expect("inherit");
        assert!(fds.table_get_for_test(6, cg, LINUX_STDOUT_FD).is_some());
        assert!(fds.open_description_live_count() >= before);
        fds.release(6, cg);
        fds.release(5, pg);
        assert_eq!(fds.open_description_live_count(), 0);
    }

    #[test]
    fn stale_open_description_generation_rejected() {
        let (mut fds, mut ipc) = local_pair();
        let gen = InstanceGeneration(1);
        let handle = ipc.grant_console_capability_for_pid(7).expect("grant");
        fds.install(7, gen, handle, handle).expect("install");
        fds.close_fd(7, gen, LINUX_STDOUT_FD).expect("close");
        assert_eq!(
            fds.projection_for(7, gen, LINUX_STDOUT_FD),
            Ok(LinuxFdProjection::Closed)
        );
    }

    #[test]
    fn table_exhaustion_returns_emfile() {
        let (mut fds, mut ipc) = local_pair();
        let gen = InstanceGeneration(1);
        let handle = ipc.grant_console_capability_for_pid(8).expect("grant");
        fds.install(8, gen, handle, handle).expect("install");
        while fds.alloc_self_test_placeholder_file(8, gen).is_ok() {}
        assert_eq!(fds.alloc_self_test_placeholder_file(8, gen), Err(EMFILE));
    }

    #[test]
    fn process_teardown_releases_pool() {
        let (mut fds, mut ipc) = local_pair();
        let gen = InstanceGeneration(1);
        let handle = ipc.grant_console_capability_for_pid(9).expect("grant");
        fds.install(9, gen, handle, handle).expect("install");
        fds.alloc_self_test_placeholder_file(9, gen).expect("ph");
        assert!(fds.open_description_live_count() > 0);
        fds.release(9, gen);
        assert_eq!(fds.open_description_live_count(), 0);
    }

    #[test]
    fn linux_fd_registry_capacity_tracks_process_registry() {
        assert_eq!(LINUX_FD_REGISTRY_CAPACITY, PROCESS_REGISTRY_CAPACITY);
        assert_eq!(LINUX_FD_TABLE_CAPACITY, 16);
        assert_eq!(OPEN_DESCRIPTION_CAPACITY, 48);
    }
}
