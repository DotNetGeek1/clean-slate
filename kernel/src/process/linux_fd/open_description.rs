//! Global bounded pool of Linux open descriptions (shared offset/status + backend).

use clean_slate_linux_abi::{LinuxErrno, EBADF, ENFILE};

/// Generation-safe handle into the open-description pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpenDescriptionId {
    pub(crate) index: u16,
    pub(crate) generation: u32,
}

/// Opaque console backend reference (IPC send-capability handle).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConsoleSinkRef {
    pub(crate) capability_handle: u64,
}

/// #101: stable node identity for Linux fs projection backends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LinuxFsNodeId {
    pub(crate) index: u16,
    pub(crate) generation: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileHandleRef {
    pub(crate) node: LinuxFsNodeId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirHandleRef {
    pub(crate) node: LinuxFsNodeId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PipeId {
    pub(crate) index: u16,
    pub(crate) generation: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PipeEnd {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PipeRef {
    pub(crate) pipe: PipeId,
    pub(crate) end: PipeEnd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SocketRef {
    pub(crate) id: u32,
    pub(crate) generation: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DescriptorKind {
    Console(ConsoleSinkRef),
    File(FileHandleRef),
    Dir(DirHandleRef),
    PipeRead(PipeRef),
    PipeWrite(PipeRef),
    Socket(SocketRef),
}

/// Shared open-file status bits (Linux `fcntl` F_GETFL/F_SETFL surface).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct OpenStatus {
    pub(crate) access: OpenAccess,
    pub(crate) nonblock: bool,
    pub(crate) append: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum OpenAccess {
    #[default]
    ReadOnly,
    WriteOnly,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpenDescription {
    pub(crate) kind: DescriptorKind,
    pub(crate) status: OpenStatus,
    pub(crate) offset: u64,
    pub(crate) refcount: u16,
    pub(crate) generation: u32,
    pub(crate) owner_pid_for_audit: u64,
}

/// Global open-description slots.
///
/// Justification: at most [`super::LINUX_FD_TABLE_CAPACITY`] unique descriptions
/// per live process × [`crate::process::PROCESS_REGISTRY_CAPACITY`] processes
/// in the worst case (no sharing). 48 slots = 6× headroom over 8×16=128 upper
/// bound is intentionally tighter to keep kernel RAM fixed; exhaustion returns
/// `ENFILE` and is covered by host tests.
pub(crate) const OPEN_DESCRIPTION_CAPACITY: usize = 48;

const OPEN_DESCRIPTION_REF_MAX: u16 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PoolSlot {
    live: bool,
    generation: u32,
    description: OpenDescription,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct OpenDescriptionPool {
    slots: [PoolSlot; OPEN_DESCRIPTION_CAPACITY],
    live_count: u16,
}

const EMPTY_POOL_DESCRIPTION: OpenDescription = OpenDescription {
    kind: DescriptorKind::File(FileHandleRef {
        node: LinuxFsNodeId {
            index: 0,
            generation: 0,
        },
    }),
    status: OpenStatus {
        access: OpenAccess::ReadOnly,
        nonblock: false,
        append: false,
    },
    offset: 0,
    refcount: 0,
    generation: 0,
    owner_pid_for_audit: 0,
};

impl OpenDescriptionPool {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [PoolSlot {
                live: false,
                generation: 1,
                description: EMPTY_POOL_DESCRIPTION,
            }; OPEN_DESCRIPTION_CAPACITY],
            live_count: 0,
        }
    }

    pub(crate) fn live_count(&self) -> u16 {
        self.live_count
    }

    pub(crate) fn alloc_console(
        &mut self,
        owner_pid: u64,
        sink: ConsoleSinkRef,
        status: OpenStatus,
    ) -> Result<OpenDescriptionId, LinuxErrno> {
        let index = self.find_free_slot().ok_or(ENFILE)?;
        let slot = &mut self.slots[index];
        let generation = slot.generation;
        slot.live = true;
        slot.description = OpenDescription {
            kind: DescriptorKind::Console(sink),
            status,
            offset: 0,
            refcount: 0,
            generation,
            owner_pid_for_audit: owner_pid,
        };
        self.live_count = self.live_count.saturating_add(1);
        Ok(OpenDescriptionId {
            index: index as u16,
            generation,
        })
    }

    pub(crate) fn alloc_pipe(
        &mut self,
        owner_pid: u64,
        pipe: PipeRef,
    ) -> Result<OpenDescriptionId, LinuxErrno> {
        let index = self.find_free_slot().ok_or(ENFILE)?;
        let slot = &mut self.slots[index];
        let generation = slot.generation;
        slot.live = true;
        let kind = match pipe.end {
            PipeEnd::Read => DescriptorKind::PipeRead(pipe),
            PipeEnd::Write => DescriptorKind::PipeWrite(pipe),
        };
        slot.description = OpenDescription {
            kind,
            status: OpenStatus {
                access: OpenAccess::ReadWrite,
                nonblock: false,
                append: false,
            },
            offset: 0,
            refcount: 0,
            generation,
            owner_pid_for_audit: owner_pid,
        };
        self.live_count = self.live_count.saturating_add(1);
        Ok(OpenDescriptionId {
            index: index as u16,
            generation,
        })
    }

    pub(crate) fn alloc_file_or_dir(
        &mut self,
        owner_pid: u64,
        kind: DescriptorKind,
        status: OpenStatus,
    ) -> Result<OpenDescriptionId, LinuxErrno> {
        let index = self.find_free_slot().ok_or(ENFILE)?;
        let slot = &mut self.slots[index];
        let generation = slot.generation;
        slot.live = true;
        slot.description = OpenDescription {
            kind,
            status,
            offset: 0,
            refcount: 0,
            generation,
            owner_pid_for_audit: owner_pid,
        };
        self.live_count = self.live_count.saturating_add(1);
        Ok(OpenDescriptionId {
            index: index as u16,
            generation,
        })
    }

    pub(crate) fn alloc_placeholder_file(
        &mut self,
        owner_pid: u64,
        file: FileHandleRef,
    ) -> Result<OpenDescriptionId, LinuxErrno> {
        let index = self.find_free_slot().ok_or(ENFILE)?;
        let slot = &mut self.slots[index];
        let generation = slot.generation;
        slot.live = true;
        slot.description = OpenDescription {
            kind: DescriptorKind::File(file),
            status: OpenStatus {
                access: OpenAccess::ReadOnly,
                nonblock: false,
                append: false,
            },
            offset: 0,
            refcount: 0,
            generation,
            owner_pid_for_audit: owner_pid,
        };
        self.live_count = self.live_count.saturating_add(1);
        Ok(OpenDescriptionId {
            index: index as u16,
            generation,
        })
    }

    pub(crate) fn attach_first_ref(&mut self, id: OpenDescriptionId) -> Result<(), LinuxErrno> {
        let desc = self.get_mut(id)?;
        if desc.refcount == 0 {
            desc.refcount = 1;
            attach_pipe_open_description(&desc.kind);
            Ok(())
        } else {
            self.add_ref(id)
        }
    }

    pub(crate) fn get(&self, id: OpenDescriptionId) -> Result<&OpenDescription, LinuxErrno> {
        let slot = self
            .slots
            .get(id.index as usize)
            .filter(|slot| slot.live)
            .ok_or(EBADF)?;
        if slot.generation != id.generation || slot.description.generation != id.generation {
            return Err(EBADF);
        }
        Ok(&slot.description)
    }

    pub(crate) fn get_mut(
        &mut self,
        id: OpenDescriptionId,
    ) -> Result<&mut OpenDescription, LinuxErrno> {
        let slot = self
            .slots
            .get_mut(id.index as usize)
            .filter(|slot| slot.live)
            .ok_or(EBADF)?;
        if slot.generation != id.generation || slot.description.generation != id.generation {
            return Err(EBADF);
        }
        Ok(&mut slot.description)
    }

    pub(crate) fn add_ref(&mut self, id: OpenDescriptionId) -> Result<(), LinuxErrno> {
        let desc = self.get_mut(id)?;
        if desc.refcount >= OPEN_DESCRIPTION_REF_MAX {
            return Err(clean_slate_linux_abi::EMFILE);
        }
        desc.refcount += 1;
        Ok(())
    }

    pub(crate) fn release_ref(&mut self, id: OpenDescriptionId) -> Result<(), LinuxErrno> {
        let slot = self
            .slots
            .get_mut(id.index as usize)
            .filter(|slot| slot.live)
            .ok_or(EBADF)?;
        if slot.generation != id.generation {
            return Err(EBADF);
        }
        let desc = &mut slot.description;
        if desc.refcount == 0 {
            return Err(EBADF);
        }
        let kind = desc.kind;
        desc.refcount -= 1;
        if desc.refcount == 0 {
            detach_pipe_open_description(&kind);
            self.finalize_slot(id.index as usize);
        }
        Ok(())
    }

    fn finalize_slot(&mut self, index: usize) {
        let slot = &mut self.slots[index];
        if !slot.live {
            return;
        }
        slot.live = false;
        slot.generation = slot.generation.saturating_add(1);
        self.live_count = self.live_count.saturating_sub(1);
    }

    fn find_free_slot(&self) -> Option<usize> {
        self.slots.iter().position(|slot| !slot.live)
    }
}

#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
fn attach_pipe_open_description(kind: &DescriptorKind) {
    match kind {
        DescriptorKind::PipeRead(pipe) | DescriptorKind::PipeWrite(pipe) => {
            crate::process::linux_proc::pipe::attach_pipe_end(*pipe);
        }
        _ => {}
    }
}

#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
fn detach_pipe_open_description(kind: &DescriptorKind) {
    match kind {
        DescriptorKind::PipeRead(pipe) | DescriptorKind::PipeWrite(pipe) => {
            crate::process::linux_proc::pipe::release_pipe_end(*pipe);
        }
        _ => {}
    }
}

// M1/M2 boots exclude the Linux process substrate, so no pipe ends can exist.
#[cfg(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
))]
fn attach_pipe_open_description(_kind: &DescriptorKind) {}

#[cfg(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
))]
fn detach_pipe_open_description(_kind: &DescriptorKind) {}

pub(crate) const fn open_status_to_linux_fl(status: &OpenStatus) -> u32 {
    let mut fl = match status.access {
        OpenAccess::ReadOnly => 0,
        OpenAccess::WriteOnly => 1,
        OpenAccess::ReadWrite => 2,
    };
    if status.nonblock {
        fl |= 0x800;
    }
    if status.append {
        fl |= 0x400;
    }
    fl
}

pub(crate) fn apply_linux_fl_to_status(fl: u32, status: &mut OpenStatus) -> Result<(), LinuxErrno> {
    status.access = match fl & 3 {
        0 => OpenAccess::ReadOnly,
        1 => OpenAccess::WriteOnly,
        2 => OpenAccess::ReadWrite,
        _ => return Err(clean_slate_linux_abi::EINVAL),
    };
    status.nonblock = (fl & 0x800) != 0;
    status.append = (fl & 0x400) != 0;
    Ok(())
}
