//! Bounded pipe ring storage (#102). Linux default 64 KiB; traces show ≤1024 bytes.

use crate::process::linux_fd::open_description::{PipeEnd, PipeId, PipeRef};
#[cfg_attr(test, allow(unused_imports))]
use crate::sched::wait::{wake_all, WaitKey};
use crate::sync::global_cell::GlobalCell;
use clean_slate_linux_abi::{LinuxErrno, EAGAIN, EBADF, EPIPE};

pub(crate) const LINUX_PIPE_MAX: usize = 8;
pub(crate) const LINUX_PIPE_CAPACITY: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PipeHandle {
    pub(crate) index: u16,
    pub(crate) generation: u32,
}

struct PipeSlot {
    live: bool,
    generation: u32,
    buffer: [u8; LINUX_PIPE_CAPACITY],
    head: usize,
    len: usize,
    readers: u16,
    writers: u16,
}

impl PipeSlot {
    const EMPTY: Self = Self {
        live: false,
        generation: 0,
        buffer: [0; LINUX_PIPE_CAPACITY],
        head: 0,
        len: 0,
        readers: 0,
        writers: 0,
    };
}

pub(crate) struct PipePool {
    slots: [PipeSlot; LINUX_PIPE_MAX],
    next_generation: u32,
}

impl PipePool {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [PipeSlot::EMPTY; LINUX_PIPE_MAX],
            next_generation: 1,
        }
    }

    pub(crate) fn alloc_pipe(&mut self) -> Result<PipeHandle, LinuxErrno> {
        let index = self.slots.iter().position(|s| !s.live).ok_or(EAGAIN)?;
        let generation = self.next_generation;
        self.next_generation = self.next_generation.saturating_add(1).max(1);
        self.slots[index] = PipeSlot {
            live: true,
            generation,
            buffer: [0; LINUX_PIPE_CAPACITY],
            head: 0,
            len: 0,
            readers: 0,
            writers: 0,
        };
        Ok(PipeHandle {
            index: index as u16,
            generation,
        })
    }

    pub(crate) fn add_reader(&mut self, handle: PipeHandle) {
        if let Some(slot) = self.slot_mut(handle) {
            slot.readers = slot.readers.saturating_add(1);
        }
    }

    pub(crate) fn add_writer(&mut self, handle: PipeHandle) {
        if let Some(slot) = self.slot_mut(handle) {
            slot.writers = slot.writers.saturating_add(1);
        }
    }

    pub(crate) fn release_end(&mut self, handle: PipeHandle, end: PipeEnd) {
        let Some(slot) = self.slot_mut(handle) else {
            return;
        };
        match end {
            PipeEnd::Read => {
                slot.readers = slot.readers.saturating_sub(1);
                if slot.readers == 0 {
                    #[cfg(not(test))]
                    wake_all(writer_wait_key(handle));
                }
            }
            PipeEnd::Write => {
                slot.writers = slot.writers.saturating_sub(1);
                #[cfg(not(test))]
                wake_all(reader_wait_key(handle));
            }
        }
        if slot.readers == 0 && slot.writers == 0 {
            slot.live = false;
        }
    }

    pub(crate) fn read_into(
        &mut self,
        handle: PipeHandle,
        out: &mut [u8],
    ) -> Result<usize, PipeReadOutcome> {
        let slot = self.slot_mut(handle).ok_or(PipeReadOutcome::Stale)?;
        if slot.len > 0 {
            let take = out.len().min(slot.len);
            for (i, byte) in out.iter_mut().take(take).enumerate() {
                *byte = slot.buffer[(slot.head + i) % LINUX_PIPE_CAPACITY];
            }
            slot.head = (slot.head + take) % LINUX_PIPE_CAPACITY;
            slot.len -= take;
            #[cfg(not(test))]
            wake_all(writer_wait_key(handle));
            return Ok(take);
        }
        if slot.writers > 0 {
            return Err(PipeReadOutcome::Block);
        }
        Ok(0)
    }

    pub(crate) fn write_from(
        &mut self,
        handle: PipeHandle,
        bytes: &[u8],
    ) -> Result<usize, PipeWriteOutcome> {
        let slot = self.slot_mut(handle).ok_or(PipeWriteOutcome::Stale)?;
        if slot.readers == 0 {
            return Err(PipeWriteOutcome::Epipe);
        }
        let space = LINUX_PIPE_CAPACITY - slot.len;
        if space == 0 {
            if slot.readers > 0 {
                return Err(PipeWriteOutcome::Block);
            }
            return Err(PipeWriteOutcome::Epipe);
        }
        let take = bytes.len().min(space);
        for (i, byte) in bytes.iter().take(take).enumerate() {
            let pos = (slot.head + slot.len + i) % LINUX_PIPE_CAPACITY;
            slot.buffer[pos] = *byte;
        }
        slot.len += take;
        #[cfg(not(test))]
        wake_all(reader_wait_key(handle));
        Ok(take)
    }

    pub(crate) fn readable(&self, handle: PipeHandle) -> bool {
        self.slot(handle)
            .map(|s| s.len > 0 || s.writers == 0)
            .unwrap_or(false)
    }

    pub(crate) fn writable(&self, handle: PipeHandle) -> bool {
        self.slot(handle)
            .map(|s| s.len < LINUX_PIPE_CAPACITY || s.readers == 0)
            .unwrap_or(false)
    }

    pub(crate) fn live_count(&self) -> usize {
        self.slots.iter().filter(|s| s.live).count()
    }

    fn slot(&self, handle: PipeHandle) -> Option<&PipeSlot> {
        let index = usize::from(handle.index);
        self.slots
            .get(index)
            .filter(|s| s.live && s.generation == handle.generation)
    }

    fn slot_mut(&mut self, handle: PipeHandle) -> Option<&mut PipeSlot> {
        let index = usize::from(handle.index);
        self.slots
            .get_mut(index)
            .filter(|s| s.live && s.generation == handle.generation)
    }
}

#[derive(Debug)]
pub(crate) enum PipeReadOutcome {
    Block,
    Stale,
}

#[derive(Debug)]
pub(crate) enum PipeWriteOutcome {
    Block,
    Epipe,
    Stale,
}

pub(crate) fn reader_wait_key(handle: PipeHandle) -> WaitKey {
    WaitKey(
        (0x50u64 << 56)
            | (0x01u64 << 48)
            | (u64::from(handle.index) << 32)
            | u64::from(handle.generation),
    )
}

pub(crate) fn writer_wait_key(handle: PipeHandle) -> WaitKey {
    WaitKey(
        (0x50u64 << 56)
            | (0x02u64 << 48)
            | (u64::from(handle.index) << 32)
            | u64::from(handle.generation),
    )
}

pub(crate) fn wait_key_for_parent(pid: u64) -> WaitKey {
    WaitKey((0x50u64 << 56) | pid)
}

static PIPE_POOL: GlobalCell<PipePool> = GlobalCell::new(PipePool::new());

pub(crate) fn pool_mut() -> &'static mut PipePool {
    unsafe { &mut *PIPE_POOL.get() }
}

pub(crate) fn pool() -> &'static PipePool {
    unsafe { &*PIPE_POOL.get() }
}

pub(crate) fn reset_for_selftest() {
    unsafe { *PIPE_POOL.get() = PipePool::new() };
}

pub(crate) fn pipe_ref_to_handle(pipe: PipeRef) -> PipeHandle {
    PipeHandle {
        index: pipe.pipe.index,
        generation: pipe.pipe.generation,
    }
}

pub(crate) fn read_pipe(pipe: PipeRef, buf: &mut [u8]) -> Result<usize, LinuxErrno> {
    match pool_mut().read_into(pipe_ref_to_handle(pipe), buf) {
        Ok(n) => Ok(n),
        Err(PipeReadOutcome::Block) => Err(EAGAIN),
        Err(PipeReadOutcome::Stale) => Err(EBADF),
    }
}

pub(crate) fn write_pipe(pipe: PipeRef, bytes: &[u8]) -> Result<usize, LinuxErrno> {
    match pool_mut().write_from(pipe_ref_to_handle(pipe), bytes) {
        Ok(n) => Ok(n),
        Err(PipeWriteOutcome::Block) => Err(EAGAIN),
        Err(PipeWriteOutcome::Epipe) => Err(EPIPE),
        Err(PipeWriteOutcome::Stale) => Err(EBADF),
    }
}

pub(crate) fn release_pipe_end(pipe: PipeRef) {
    pool_mut().release_end(pipe_ref_to_handle(pipe), pipe.end);
}

pub(crate) fn open_pipe_refs(pool: &mut PipePool) -> Result<(PipeRef, PipeRef), LinuxErrno> {
    let handle = pool.alloc_pipe()?;
    pool.add_reader(handle);
    pool.add_writer(handle);
    let read = PipeRef {
        pipe: PipeId {
            index: handle.index,
            generation: handle.generation,
        },
        end: PipeEnd::Read,
    };
    let write = PipeRef {
        pipe: PipeId {
            index: handle.index,
            generation: handle.generation,
        },
        end: PipeEnd::Write,
    };
    Ok((read, write))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_wrap_partial_write_eof_epipe() {
        reset_for_selftest();
        let pool = pool_mut();
        let handle = pool.alloc_pipe().unwrap();
        pool.add_reader(handle);
        pool.add_writer(handle);
        let mut buf = [0u8; 16];
        assert_eq!(pool.write_from(handle, &[b'h', b'i']).unwrap(), 2);
        assert_eq!(pool.read_into(handle, &mut buf).unwrap(), 2);
        pool.release_end(handle, PipeEnd::Write);
        assert_eq!(pool.read_into(handle, &mut buf).unwrap(), 0);
        pool.release_end(handle, PipeEnd::Read);
        assert!(matches!(
            pool.write_from(handle, b"x"),
            Err(PipeWriteOutcome::Epipe) | Err(PipeWriteOutcome::Stale)
        ));
    }
}
