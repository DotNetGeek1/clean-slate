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

/// Placeholder refs until #101/#102/#105 land (id + generation only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileHandleRef {
    pub(crate) id: u32,
    pub(crate) generation: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirHandleRef {
    pub(crate) id: u32,
    pub(crate) generation: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PipeRef {
    pub(crate) id: u32,
    pub(crate) generation: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SocketRef {
    pub(crate) index: u16,
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
        id: 0,
        generation: 0,
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

    pub(crate) fn alloc_socket(
        &mut self,
        owner_pid: u64,
        socket: SocketRef,
        status: OpenStatus,
    ) -> Result<OpenDescriptionId, LinuxErrno> {
        let index = self.find_free_slot().ok_or(ENFILE)?;
        let slot = &mut self.slots[index];
        let generation = slot.generation;
        slot.live = true;
        slot.description = OpenDescription {
            kind: DescriptorKind::Socket(socket),
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
        desc.refcount -= 1;
        if desc.refcount == 0 {
            self.finalize_slot(id.index as usize);
        }
        Ok(())
    }

    fn finalize_slot(&mut self, index: usize) {
        let slot = &mut self.slots[index];
        if !slot.live {
            return;
        }
        release_kind_hook(&slot.description.kind);
        slot.live = false;
        slot.generation = slot.generation.saturating_add(1);
        self.live_count = self.live_count.saturating_sub(1);
    }

    fn find_free_slot(&self) -> Option<usize> {
        self.slots.iter().position(|slot| !slot.live)
    }
}

fn release_kind_hook(kind: &DescriptorKind) {
    match kind {
        DescriptorKind::Console(_) => {}
        DescriptorKind::File(_) => {}
        DescriptorKind::Dir(_) => {}
        DescriptorKind::PipeRead(_) => {}
        DescriptorKind::PipeWrite(_) => {}
        DescriptorKind::Socket(socket) => {
            crate::process::linux_socket::release_socket(
                crate::process::linux_socket::socket_ref_to_id(*socket),
            );
        }
    }
}

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
