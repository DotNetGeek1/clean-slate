//! Native storage (#312): offset reads, writes, truncates and commits on a persistent object
//! the process holds a capability to (syscall 8, `OBJECT_SUBOP_SUBMIT_AT`).
//!
//! Writes and truncates are staged, not durable: [`Object::commit`] makes every staged change
//! in the store durable at once, and a crash or a storage service restart before it forgets
//! them. A write that would take the store past its live-byte budget fails with
//! [`Error::Failed`]`(STATUS_ENOSPC)` and stages nothing; a capability bound to an object
//! that was deleted fails with [`Error::Gone`].
//!
//! [`Object::write_from`] and [`Object::read_into`] move bytes through a shared buffer the
//! process holds ([`crate::buffer::SharedBuffer`]), up to
//! [`OBJECT_MAX_BUFFER_PAYLOAD_BYTES`] per request instead of 512.

use clean_slate_native_abi::object::{
    ObjectSubmitAt, OBJECT_MAX_BUFFER_PAYLOAD_BYTES, OBJECT_MAX_PAYLOAD_BYTES, OBJECT_OP_COMMIT,
    OBJECT_OP_READ_AT, OBJECT_OP_TRUNCATE, OBJECT_OP_WRITE_AT, OBJECT_POLL_NO_DEADLINE,
    OBJECT_SUBMIT_AT_BYTES, OBJECT_SUBOP_POLL, OBJECT_SUBOP_SUBMIT_AT, SYSCALL_NR_CAP_OBJECT,
};

use clean_slate_native_abi::directory::{
    entry_object_id, validate_name, DirectoryError, DirectoryTable, DIRECTORY_MAX_ENTRY_BYTES,
    DIRECTORY_TABLE_BYTES,
};
use clean_slate_native_abi::status::{STATUS_EFBIG, STATUS_EINVAL, STATUS_EIO, STATUS_ENOENT};

use crate::{Error, Syscalls};

/// A persistent object: the capability handle that authorises it and the object's id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Object {
    handle: u64,
    id: u64,
}

impl Object {
    pub const fn new(handle: u64, id: u64) -> Self {
        Self { handle, id }
    }

    pub const fn handle(self) -> u64 {
        self.handle
    }

    pub const fn id(self) -> u64 {
        self.id
    }

    /// Reads into `out` from `offset`; returns the bytes read, fewer than `out.len()` only at
    /// the object's end.
    pub fn read_at<S: Syscalls>(
        self,
        sys: &mut S,
        offset: u64,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut done = 0;
        let total = out.len();
        while done < total {
            let chunk = &mut out[done..(done + OBJECT_MAX_PAYLOAD_BYTES).min(total)];
            let want = chunk.len();
            let read =
                self.request(sys, OBJECT_OP_READ_AT, offset + done as u64, want, 0, chunk)?;
            done += read;
            if read < want {
                break;
            }
        }
        Ok(done)
    }

    /// Stages `data` at `offset`, creating the object when it is missing and zero-filling any
    /// gap past its end.
    pub fn write_at<S: Syscalls>(self, sys: &mut S, offset: u64, data: &[u8]) -> Result<(), Error> {
        for (index, chunk) in data.chunks(OBJECT_MAX_PAYLOAD_BYTES).enumerate() {
            let at = offset + (index * OBJECT_MAX_PAYLOAD_BYTES) as u64;
            self.request(
                sys,
                OBJECT_OP_WRITE_AT,
                at,
                chunk.len(),
                chunk.as_ptr() as u64,
                &mut [],
            )?;
        }
        Ok(())
    }

    /// Stages `len` bytes from the shared buffer `buffer` (a capability handle with `READ`),
    /// starting `buffer_offset` bytes into it, at `offset` in the object.
    pub fn write_from<S: Syscalls>(
        self,
        sys: &mut S,
        offset: u64,
        buffer: u64,
        buffer_offset: u64,
        len: u64,
    ) -> Result<(), Error> {
        let mut done = 0;
        while done < len {
            let chunk = (len - done).min(OBJECT_MAX_BUFFER_PAYLOAD_BYTES as u64);
            self.submit_staged(
                sys,
                OBJECT_OP_WRITE_AT,
                offset + done,
                chunk,
                buffer,
                buffer_offset + done,
            )?;
            done += chunk;
        }
        Ok(())
    }

    /// Reads up to `len` bytes from `offset` into the shared buffer `buffer` (a capability
    /// handle with `WRITE`), starting `buffer_offset` bytes into it; returns the bytes read,
    /// fewer than `len` only at the object's end.
    pub fn read_into<S: Syscalls>(
        self,
        sys: &mut S,
        offset: u64,
        buffer: u64,
        buffer_offset: u64,
        len: u64,
    ) -> Result<u64, Error> {
        let mut done = 0;
        while done < len {
            let chunk = (len - done).min(OBJECT_MAX_BUFFER_PAYLOAD_BYTES as u64);
            let read = self.submit_staged(
                sys,
                OBJECT_OP_READ_AT,
                offset + done,
                chunk,
                buffer,
                buffer_offset + done,
            )?;
            done += read;
            if read < chunk {
                break;
            }
        }
        Ok(done)
    }

    /// Stages the object cut or zero-extended to `len` bytes.
    pub fn truncate<S: Syscalls>(self, sys: &mut S, len: u64) -> Result<(), Error> {
        self.request(sys, OBJECT_OP_TRUNCATE, len, 0, 0, &mut [])
            .map(drop)
    }

    /// Makes every staged change in the store durable.
    pub fn commit<S: Syscalls>(self, sys: &mut S) -> Result<(), Error> {
        self.request(sys, OBJECT_OP_COMMIT, 0, 0, 0, &mut [])
            .map(drop)
    }

    /// One request through a shared buffer; returns the bytes it moved.
    fn submit_staged<S: Syscalls>(
        self,
        sys: &mut S,
        op: u64,
        offset: u64,
        len: u64,
        buffer: u64,
        buffer_offset: u64,
    ) -> Result<u64, Error> {
        let descriptor = ObjectSubmitAt {
            op,
            object_id: self.id,
            offset,
            len,
            data: 0,
            buffer,
            buffer_offset,
        };
        self.submit_and_wait(sys, &descriptor, &mut [])
            .map(|moved| moved as u64)
    }

    /// One request: submit it, then wait for its completion. Returns the bytes copied to `out`.
    fn request<S: Syscalls>(
        self,
        sys: &mut S,
        op: u64,
        offset: u64,
        len: usize,
        data: u64,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let descriptor = ObjectSubmitAt {
            op,
            object_id: self.id,
            offset,
            len: len as u64,
            data,
            ..ObjectSubmitAt::default()
        };
        self.submit_and_wait(sys, &descriptor, out)
    }

    fn submit_and_wait<S: Syscalls>(
        self,
        sys: &mut S,
        descriptor: &ObjectSubmitAt,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let descriptor = descriptor.encode();
        let request_id = sys.call(
            SYSCALL_NR_CAP_OBJECT,
            [
                OBJECT_SUBOP_SUBMIT_AT,
                self.handle,
                descriptor.as_ptr() as u64,
                OBJECT_SUBMIT_AT_BYTES as u64,
                0,
                0,
            ],
        )?;
        let read = sys.call(
            SYSCALL_NR_CAP_OBJECT,
            [
                OBJECT_SUBOP_POLL,
                request_id,
                out.len() as u64,
                out.as_mut_ptr() as u64,
                OBJECT_POLL_NO_DEADLINE,
                0,
            ],
        )?;
        Ok(read as usize)
    }
}

/// A directory (#312, `clean_slate_native_abi::directory`): a name table object, and up to
/// 15 entry objects after it, all authorised by one capability with `DIRECTORY` on the
/// table. Every call reads the table afresh, so two handles on one directory see each
/// other's committed changes; concurrent writers are not ordered beyond the storage queue.
///
/// Names, lengths and entry bytes become durable together at the commit each of
/// [`create`](Self::create), [`set_len`](Self::set_len), [`rename`](Self::rename) and
/// [`unlink`](Self::unlink) ends with: write an entry's bytes through its [`Object`], then
/// record its length with `set_len`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Directory {
    table: Object,
}

/// An entry of a [`Directory`]: its slot, and its object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub slot: usize,
    pub object: Object,
    /// The length the table records, as of the last commit.
    pub len: u64,
}

impl Directory {
    /// The directory whose table is object `id`, authorised by `handle`.
    pub const fn new(handle: u64, id: u64) -> Self {
        Self {
            table: Object::new(handle, id),
        }
    }

    /// The table as last committed; a directory never written is empty. A table that does
    /// not decode is `EIO`, never overwritten.
    pub fn table<S: Syscalls>(self, sys: &mut S) -> Result<DirectoryTable, Error> {
        let mut bytes = [0u8; DIRECTORY_TABLE_BYTES];
        match self.table.read_at(sys, 0, &mut bytes) {
            Ok(DIRECTORY_TABLE_BYTES) => {
                DirectoryTable::decode(&bytes).map_err(|_| Error::Failed(STATUS_EIO))
            }
            Ok(_) => Err(Error::Failed(STATUS_EIO)),
            Err(Error::Failed(STATUS_ENOENT)) => Ok(DirectoryTable::empty()),
            Err(error) => Err(error),
        }
    }

    /// The entry named `name`; `ENOENT` when there is none.
    pub fn open<S: Syscalls>(self, sys: &mut S, name: &[u8]) -> Result<Entry, Error> {
        let table = self.table(sys)?;
        let slot = table.find(name).ok_or(Error::Failed(STATUS_ENOENT))?;
        Ok(self.entry(&table, slot))
    }

    /// The entry named `name`, created empty when there is none.
    pub fn create<S: Syscalls>(self, sys: &mut S, name: &[u8]) -> Result<Entry, Error> {
        validate_name(name).map_err(refusal)?;
        let mut table = self.table(sys)?;
        if let Some(slot) = table.find(name) {
            return Ok(self.entry(&table, slot));
        }
        let slot = table.free_slot().map_err(refusal)?;
        // The slot's object may hold an unlinked entry's bytes.
        self.entry_object(slot).truncate(sys, 0)?;
        table.create_at(slot, name).map_err(refusal)?;
        self.commit_table(sys, &table)?;
        Ok(self.entry(&table, slot))
    }

    /// Records `len` as the length of the entry in `slot` and commits the directory, with
    /// every byte staged in its entries.
    pub fn set_len<S: Syscalls>(self, sys: &mut S, slot: usize, len: u64) -> Result<(), Error> {
        if len > DIRECTORY_MAX_ENTRY_BYTES {
            return Err(Error::Failed(STATUS_EFBIG));
        }
        let mut table = self.table(sys)?;
        let entry = table.entry_mut(slot).ok_or(Error::Failed(STATUS_ENOENT))?;
        entry.len = len as u32;
        self.commit_table(sys, &table)
    }

    /// Renames `from` to `to`, replacing `to` if it exists.
    pub fn rename<S: Syscalls>(self, sys: &mut S, from: &[u8], to: &[u8]) -> Result<(), Error> {
        validate_name(to).map_err(refusal)?;
        let mut table = self.table(sys)?;
        let slot = table.find(from).ok_or(Error::Failed(STATUS_ENOENT))?;
        if from == to {
            return Ok(());
        }
        if let Some(victim) = table.find(to) {
            self.entry_object(victim).truncate(sys, 0)?;
        }
        table.rename(slot, to).map_err(refusal)?;
        self.commit_table(sys, &table)
    }

    /// Removes `name`: its object is emptied, and the commit drops the name.
    pub fn unlink<S: Syscalls>(self, sys: &mut S, name: &[u8]) -> Result<(), Error> {
        let mut table = self.table(sys)?;
        let slot = table.find(name).ok_or(Error::Failed(STATUS_ENOENT))?;
        self.entry_object(slot).truncate(sys, 0)?;
        table.remove(slot);
        self.commit_table(sys, &table)
    }

    fn entry_object(self, slot: usize) -> Object {
        Object::new(self.table.handle, entry_object_id(self.table.id, slot))
    }

    fn entry(self, table: &DirectoryTable, slot: usize) -> Entry {
        Entry {
            slot,
            object: self.entry_object(slot),
            len: table.entry(slot).map_or(0, |entry| u64::from(entry.len)),
        }
    }

    /// Stages the table, then commits it with every staged entry change: the commit point.
    fn commit_table<S: Syscalls>(self, sys: &mut S, table: &DirectoryTable) -> Result<(), Error> {
        self.table.write_at(sys, 0, &table.encode())?;
        self.table.commit(sys)
    }
}

/// The status a refused directory change fails with.
fn refusal(error: DirectoryError) -> Error {
    use clean_slate_native_abi::status::{STATUS_ENAMETOOLONG, STATUS_ENOSPC};
    Error::Failed(match error {
        DirectoryError::NameTooLong => STATUS_ENAMETOOLONG,
        DirectoryError::Full => STATUS_ENOSPC,
        _ => STATUS_EINVAL,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeKernel;
    use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_ENOENT, STATUS_ENOSPC};

    const OBJECT: Object = Object::new(0x77, 0x5100_0001);

    #[test]
    fn writes_stage_until_a_commit_and_read_back_across_chunks() {
        let mut sys = FakeKernel::new();
        sys.grant_object(OBJECT.handle(), OBJECT.id(), true);
        let data: std::vec::Vec<u8> = (0..1300u32).map(|n| n as u8).collect();
        OBJECT.write_at(&mut sys, 100, &data).unwrap();
        assert_eq!(sys.object_staged(OBJECT.id()).unwrap().len(), 1400);
        assert_eq!(sys.object_committed(OBJECT.id()), None);
        OBJECT.commit(&mut sys).unwrap();
        assert_eq!(sys.object_committed(OBJECT.id()).unwrap().len(), 1400);

        let mut out = [0xFFu8; 2048];
        assert_eq!(OBJECT.read_at(&mut sys, 0, &mut out), Ok(1400));
        assert_eq!(&out[..100], &[0; 100][..]);
        assert_eq!(&out[100..1400], &data[..]);
        // Three 512-byte reads: the third came back short at the end.
        let reads = sys
            .object_requests()
            .iter()
            .filter(|(op, ..)| *op == OBJECT_OP_READ_AT)
            .count();
        assert_eq!(reads, 3);
    }

    #[test]
    fn a_shared_buffer_moves_a_mebibyte_in_eight_requests() {
        use crate::buffer::SharedBuffer;
        const MIB: usize = 1024 * 1024;
        let mut sys = FakeKernel::new();
        sys.grant_object(OBJECT.handle(), OBJECT.id(), true);
        let mut buffer = SharedBuffer::allocate(&mut sys, MIB).unwrap();
        for (index, byte) in buffer.bytes().iter_mut().enumerate() {
            *byte = (index / 4096) as u8 ^ index as u8;
        }
        let expected = buffer.bytes().to_vec();
        OBJECT
            .write_from(&mut sys, 0, buffer.handle(), 0, MIB as u64)
            .unwrap();
        let writes = sys
            .object_requests()
            .iter()
            .filter(|(op, ..)| *op == OBJECT_OP_WRITE_AT)
            .count();
        assert_eq!(writes, MIB / OBJECT_MAX_BUFFER_PAYLOAD_BYTES);
        OBJECT.commit(&mut sys).unwrap();
        assert_eq!(sys.object_committed(OBJECT.id()), Some(&expected[..]));

        buffer.bytes().fill(0);
        assert_eq!(
            OBJECT.read_into(&mut sys, 0, buffer.handle(), 0, MIB as u64),
            Ok(MIB as u64)
        );
        assert_eq!(buffer.bytes(), &expected[..]);
        assert_eq!(
            OBJECT.read_into(&mut sys, MIB as u64 - 10, buffer.handle(), 0, 4096),
            Ok(10)
        );
        // The buffer range must fit the buffer.
        assert!(OBJECT
            .read_into(&mut sys, 0, buffer.handle(), 1, MIB as u64)
            .is_err());
    }

    const DIRECTORY: Directory = Directory::new(0x99, 0x5100_0000);

    fn directory_kernel() -> FakeKernel {
        let mut sys = FakeKernel::new();
        sys.grant_directory(0x99, 0x5100_0000);
        sys
    }

    #[test]
    fn a_named_entry_is_durable_once_its_length_is_set() {
        let mut sys = directory_kernel();
        assert_eq!(
            DIRECTORY.open(&mut sys, b"save.bin"),
            Err(Error::Failed(STATUS_ENOENT))
        );
        let entry = DIRECTORY.create(&mut sys, b"save.bin").unwrap();
        assert_eq!((entry.slot, entry.len), (0, 0));
        assert_eq!(entry.object.id(), 0x5100_0001);
        assert_eq!(DIRECTORY.create(&mut sys, b"save.bin"), Ok(entry));
        entry.object.write_at(&mut sys, 0, &[7; 1000]).unwrap();
        // Staged only: the committed table still says 0 bytes and the bytes are not durable.
        assert_eq!(sys.object_committed(0x5100_0001), Some(&[][..]));
        DIRECTORY.set_len(&mut sys, entry.slot, 1000).unwrap();
        assert_eq!(sys.object_committed(0x5100_0001), Some(&[7; 1000][..]));
        let reopened = DIRECTORY.open(&mut sys, b"save.bin").unwrap();
        assert_eq!(reopened.len, 1000);
        let table = DIRECTORY.table(&mut sys).unwrap();
        assert_eq!(table.live_count(), 1);
    }

    #[test]
    fn rename_and_unlink_change_the_names_and_empty_what_they_drop() {
        let mut sys = directory_kernel();
        let tmp = DIRECTORY.create(&mut sys, b"save.tmp").unwrap();
        let old = DIRECTORY.create(&mut sys, b"save").unwrap();
        old.object.write_at(&mut sys, 0, b"old").unwrap();
        DIRECTORY.set_len(&mut sys, old.slot, 3).unwrap();
        tmp.object.write_at(&mut sys, 0, b"newer").unwrap();
        DIRECTORY.set_len(&mut sys, tmp.slot, 5).unwrap();
        DIRECTORY.rename(&mut sys, b"save.tmp", b"save").unwrap();
        let save = DIRECTORY.open(&mut sys, b"save").unwrap();
        assert_eq!((save.slot, save.len), (tmp.slot, 5));
        assert_eq!(sys.object_committed(old.object.id()), Some(&[][..]));
        assert_eq!(
            DIRECTORY.open(&mut sys, b"save.tmp"),
            Err(Error::Failed(STATUS_ENOENT))
        );
        DIRECTORY.unlink(&mut sys, b"save").unwrap();
        assert_eq!(DIRECTORY.table(&mut sys).unwrap().live_count(), 0);
        assert_eq!(sys.object_committed(save.object.id()), Some(&[][..]));
        assert_eq!(
            DIRECTORY.unlink(&mut sys, b"save"),
            Err(Error::Failed(STATUS_ENOENT))
        );
    }

    #[test]
    fn bad_names_a_full_directory_and_a_damaged_table_are_refused() {
        use clean_slate_native_abi::directory::DIRECTORY_MAX_ENTRIES;
        use clean_slate_native_abi::status::{STATUS_ENAMETOOLONG, STATUS_ENOSPC};
        let mut sys = directory_kernel();
        assert_eq!(
            DIRECTORY.create(&mut sys, b"a/b"),
            Err(Error::Failed(STATUS_EINVAL))
        );
        assert_eq!(
            DIRECTORY.create(&mut sys, &[b'x'; 28]),
            Err(Error::Failed(STATUS_ENAMETOOLONG))
        );
        for index in 0..DIRECTORY_MAX_ENTRIES {
            DIRECTORY.create(&mut sys, &[b'a' + index as u8]).unwrap();
        }
        assert_eq!(
            DIRECTORY.create(&mut sys, b"one-more"),
            Err(Error::Failed(STATUS_ENOSPC))
        );
        assert_eq!(
            DIRECTORY.set_len(&mut sys, 0, DIRECTORY_MAX_ENTRY_BYTES + 1),
            Err(Error::Failed(STATUS_EFBIG))
        );
        Object::new(0x99, 0x5100_0000)
            .write_at(&mut sys, 0, b"garbage")
            .unwrap();
        assert_eq!(DIRECTORY.table(&mut sys), Err(Error::Failed(STATUS_EIO)));
    }

    #[test]
    fn truncate_cuts_and_extends() {
        let mut sys = FakeKernel::new();
        sys.grant_object(OBJECT.handle(), OBJECT.id(), true);
        OBJECT.write_at(&mut sys, 0, b"hello").unwrap();
        OBJECT.truncate(&mut sys, 2).unwrap();
        OBJECT.truncate(&mut sys, 4).unwrap();
        let mut out = [0xFF; 8];
        assert_eq!(OBJECT.read_at(&mut sys, 0, &mut out), Ok(4));
        assert_eq!(&out[..4], b"he\0\0");
    }

    #[test]
    fn failures_keep_their_status() {
        let mut sys = FakeKernel::new();
        let mut out = [0; 4];
        assert_eq!(
            OBJECT.read_at(&mut sys, 0, &mut out),
            Err(Error::Failed(STATUS_EACCES))
        );
        sys.grant_object(OBJECT.handle(), OBJECT.id(), false);
        assert_eq!(
            OBJECT.read_at(&mut sys, 0, &mut out),
            Err(Error::Failed(STATUS_ENOENT))
        );
        assert_eq!(
            OBJECT.write_at(&mut sys, 0, b"x"),
            Err(Error::Failed(STATUS_EACCES))
        );
        sys.grant_object(OBJECT.handle(), OBJECT.id(), true);
        sys.set_object_budget(8);
        assert_eq!(
            OBJECT.write_at(&mut sys, 0, b"too many bytes"),
            Err(Error::Failed(STATUS_ENOSPC))
        );
        assert_eq!(sys.object_staged(OBJECT.id()), None);
        sys.object_gone(OBJECT.id());
        assert_eq!(OBJECT.commit(&mut sys), Err(Error::Gone));
    }
}
