//! The persisted name table of the Linux `/home` directory (#304).
//!
//! `/home` is one flat directory of up to [`HOME_MAX_FILES`] files. File `slot` is the
//! object [`home_file_object_id`]`(slot)`; this table, the object
//! [`HOME_TABLE_OBJECT_ID`], maps each live slot to its name and length. The table is one
//! 512-byte object, so one whole-object write replaces it, and that write is the commit
//! point: the storage service commits every staged file write with it, so names, lengths and
//! file bytes become durable together.
//!
//! Layout, little-endian: an 8-byte magic, 24 reserved zero bytes, then one 32-byte entry
//! per slot: the length (`u32`), the name length (`u8`, 0 for a free slot) and the name,
//! zero-padded to [`HOME_NAME_MAX`] bytes.

use clean_slate_linux_abi::{LinuxErrno, EINVAL, ENAMETOOLONG, ENOSPC};

/// The object holding the table. Holding `READ`/`WRITE` on it is holding them on every
/// file in `/home`: it is the directory's capability.
pub const HOME_TABLE_OBJECT_ID: u64 = 0x004D_0000;
/// File objects follow the table object: slot `n` is `HOME_FILE_OBJECT_ID_BASE + n`.
pub const HOME_FILE_OBJECT_ID_BASE: u64 = HOME_TABLE_OBJECT_ID + 1;
pub const HOME_MAX_FILES: usize = 15;
pub const HOME_NAME_MAX: usize = 27;
/// Largest file `/home` takes: a vanilla save game is at most 180 KiB, and the storage
/// service's live-byte budget is under 3 MiB for the whole store.
pub const HOME_MAX_FILE_BYTES: u64 = 1024 * 1024;
pub const HOME_TABLE_BYTES: usize = 512;

const MAGIC: [u8; 8] = *b"CSHOME01";
const HEADER_BYTES: usize = 32;
const ENTRY_BYTES: usize = 32;
const _: () = assert!(HEADER_BYTES + HOME_MAX_FILES * ENTRY_BYTES == HOME_TABLE_BYTES);
const _: () = assert!(4 + 1 + HOME_NAME_MAX == ENTRY_BYTES);

pub const fn home_file_object_id(slot: usize) -> u64 {
    HOME_FILE_OBJECT_ID_BASE + slot as u64
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HomeEntry {
    name: [u8; HOME_NAME_MAX],
    name_len: u8,
    pub len: u32,
}

impl HomeEntry {
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    fn new(name: &[u8]) -> Self {
        let mut entry = Self {
            name: [0; HOME_NAME_MAX],
            name_len: name.len() as u8,
            len: 0,
        };
        entry.name[..name.len()].copy_from_slice(name);
        entry
    }
}

/// Why a stored table was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HomeTableError {
    BadLength,
    BadMagic,
    BadEntry,
    DuplicateName,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HomeTable {
    entries: [Option<HomeEntry>; HOME_MAX_FILES],
}

impl HomeTable {
    pub const fn empty() -> Self {
        Self {
            entries: [None; HOME_MAX_FILES],
        }
    }

    pub fn entry(&self, slot: usize) -> Option<&HomeEntry> {
        self.entries.get(slot).and_then(Option::as_ref)
    }

    pub fn entry_mut(&mut self, slot: usize) -> Option<&mut HomeEntry> {
        self.entries.get_mut(slot).and_then(Option::as_mut)
    }

    /// Live `(slot, entry)` pairs in slot order.
    pub fn live(&self) -> impl Iterator<Item = (usize, &HomeEntry)> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(slot, entry)| entry.as_ref().map(|entry| (slot, entry)))
    }

    pub fn live_count(&self) -> usize {
        self.live().count()
    }

    pub fn total_bytes(&self) -> u64 {
        self.live().map(|(_, entry)| u64::from(entry.len)).sum()
    }

    pub fn find(&self, name: &[u8]) -> Option<usize> {
        self.live()
            .find(|(_, entry)| entry.name() == name)
            .map(|(slot, _)| slot)
    }

    /// The slot a new file would take: the first free one.
    pub fn free_slot(&self) -> Result<usize, LinuxErrno> {
        self.entries.iter().position(Option::is_none).ok_or(ENOSPC)
    }

    /// Creates an empty file `name` in `slot`. The caller checked the name is free.
    pub fn create_at(&mut self, slot: usize, name: &[u8]) -> Result<(), LinuxErrno> {
        validate_name(name)?;
        let entry = self.entries.get_mut(slot).ok_or(EINVAL)?;
        if entry.is_some() {
            return Err(EINVAL);
        }
        *entry = Some(HomeEntry::new(name));
        Ok(())
    }

    pub fn remove(&mut self, slot: usize) {
        if let Some(entry) = self.entries.get_mut(slot) {
            *entry = None;
        }
    }

    /// Renames the file in `slot` to `name`, removing the file that had `name`, if any.
    /// Returns the slot it removed.
    pub fn rename(&mut self, slot: usize, name: &[u8]) -> Result<Option<usize>, LinuxErrno> {
        validate_name(name)?;
        if self.entry(slot).is_none() {
            return Err(EINVAL);
        }
        let victim = self.find(name).filter(|victim| *victim != slot);
        if let Some(victim) = victim {
            self.remove(victim);
        }
        let len = self.entry(slot).map_or(0, |entry| entry.len);
        let mut entry = HomeEntry::new(name);
        entry.len = len;
        self.entries[slot] = Some(entry);
        Ok(victim)
    }

    pub fn encode(&self) -> [u8; HOME_TABLE_BYTES] {
        let mut out = [0u8; HOME_TABLE_BYTES];
        out[..MAGIC.len()].copy_from_slice(&MAGIC);
        for (slot, entry) in self.live() {
            let at = HEADER_BYTES + slot * ENTRY_BYTES;
            out[at..at + 4].copy_from_slice(&entry.len.to_le_bytes());
            out[at + 4] = entry.name_len;
            out[at + 5..at + 5 + entry.name_len as usize].copy_from_slice(entry.name());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, HomeTableError> {
        if bytes.len() != HOME_TABLE_BYTES {
            return Err(HomeTableError::BadLength);
        }
        if bytes[..MAGIC.len()] != MAGIC || bytes[MAGIC.len()..HEADER_BYTES].iter().any(|b| *b != 0)
        {
            return Err(HomeTableError::BadMagic);
        }
        let mut table = Self::empty();
        for slot in 0..HOME_MAX_FILES {
            let at = HEADER_BYTES + slot * ENTRY_BYTES;
            let raw = &bytes[at..at + ENTRY_BYTES];
            let len = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let name_len = raw[4] as usize;
            if name_len == 0 {
                if raw.iter().any(|b| *b != 0) {
                    return Err(HomeTableError::BadEntry);
                }
                continue;
            }
            if name_len > HOME_NAME_MAX || raw[5 + name_len..].iter().any(|b| *b != 0) {
                return Err(HomeTableError::BadEntry);
            }
            let name = &raw[5..5 + name_len];
            if validate_name(name).is_err() || u64::from(len) > HOME_MAX_FILE_BYTES {
                return Err(HomeTableError::BadEntry);
            }
            if table.find(name).is_some() {
                return Err(HomeTableError::DuplicateName);
            }
            let mut entry = HomeEntry::new(name);
            entry.len = len;
            table.entries[slot] = Some(entry);
        }
        Ok(table)
    }
}

/// A name `/home` can hold: 1 to [`HOME_NAME_MAX`] bytes, no `/` or NUL, not `.` or `..`.
pub fn validate_name(name: &[u8]) -> Result<(), LinuxErrno> {
    if name.len() > HOME_NAME_MAX {
        return Err(ENAMETOOLONG);
    }
    if name.is_empty()
        || name == b"."
        || name == b".."
        || name.iter().any(|b| *b == b'/' || *b == 0)
    {
        return Err(EINVAL);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table_with(names: &[&[u8]]) -> HomeTable {
        let mut table = HomeTable::empty();
        for name in names {
            let slot = table.free_slot().unwrap();
            table.create_at(slot, name).unwrap();
        }
        table
    }

    #[test]
    fn an_empty_table_round_trips() {
        let table = HomeTable::empty();
        assert_eq!(HomeTable::decode(&table.encode()), Ok(table));
        assert_eq!(table.live_count(), 0);
    }

    #[test]
    fn names_and_lengths_round_trip_in_their_slots() {
        let mut table = table_with(&[b"doomsav0.dsg", b"default.cfg", b"doomsav5.dsg"]);
        table.entry_mut(0).unwrap().len = 180 * 1024;
        table.entry_mut(1).unwrap().len = 3;
        table.remove(1);
        let longest = [b'n'; HOME_NAME_MAX];
        table.create_at(1, &longest).unwrap();
        let decoded = HomeTable::decode(&table.encode()).unwrap();
        assert_eq!(decoded, table);
        assert_eq!(decoded.find(b"doomsav0.dsg"), Some(0));
        assert_eq!(decoded.find(&longest), Some(1));
        assert_eq!(decoded.find(b"default.cfg"), None);
        assert_eq!(decoded.total_bytes(), 180 * 1024);
    }

    #[test]
    fn the_table_fills_at_its_slot_count() {
        let mut table = HomeTable::empty();
        for index in 0..HOME_MAX_FILES {
            let name = [b'a' + index as u8];
            table.create_at(table.free_slot().unwrap(), &name).unwrap();
        }
        assert_eq!(table.free_slot(), Err(ENOSPC));
        table.remove(4);
        assert_eq!(table.free_slot(), Ok(4));
    }

    #[test]
    fn rename_keeps_the_slot_and_length_and_replaces_the_target() {
        let mut table = table_with(&[b"doomsav0.dsg.tmp", b"doomsav0.dsg"]);
        table.entry_mut(0).unwrap().len = 77;
        assert_eq!(table.rename(0, b"doomsav0.dsg"), Ok(Some(1)));
        assert_eq!(table.find(b"doomsav0.dsg"), Some(0));
        assert_eq!(table.entry(0).unwrap().len, 77);
        assert!(table.entry(1).is_none());
        assert_eq!(table.rename(0, b"doomsav0.dsg"), Ok(None));
        assert_eq!(table.rename(5, b"x"), Err(EINVAL));
    }

    #[test]
    fn bad_names_are_refused() {
        let mut table = HomeTable::empty();
        for name in [&b""[..], b".", b"..", b"a/b", b"a\0b"] {
            assert_eq!(table.create_at(0, name), Err(EINVAL));
        }
        assert_eq!(
            table.create_at(0, &[b'x'; HOME_NAME_MAX + 1]),
            Err(ENAMETOOLONG)
        );
    }

    #[test]
    fn damaged_tables_are_refused() {
        let good = table_with(&[b"a", b"b"]).encode();
        assert_eq!(
            HomeTable::decode(&good[..100]),
            Err(HomeTableError::BadLength)
        );
        let mut bad = good;
        bad[0] ^= 1;
        assert_eq!(HomeTable::decode(&bad), Err(HomeTableError::BadMagic));
        let mut bad = good;
        bad[HEADER_BYTES + 4] = HOME_NAME_MAX as u8 + 1;
        assert_eq!(HomeTable::decode(&bad), Err(HomeTableError::BadEntry));
        let mut bad = good;
        bad[HEADER_BYTES + ENTRY_BYTES + 5] = b'a';
        assert_eq!(HomeTable::decode(&bad), Err(HomeTableError::DuplicateName));
        let mut bad = good;
        bad[HEADER_BYTES..HEADER_BYTES + 4]
            .copy_from_slice(&(HOME_MAX_FILE_BYTES as u32 + 1).to_le_bytes());
        assert_eq!(HomeTable::decode(&bad), Err(HomeTableError::BadEntry));
        let mut bad = good;
        bad[HEADER_BYTES + 2 * ENTRY_BYTES] = 1;
        assert_eq!(HomeTable::decode(&bad), Err(HomeTableError::BadEntry));
    }

    #[test]
    fn file_object_ids_follow_the_table_object() {
        assert_eq!(home_file_object_id(0), HOME_TABLE_OBJECT_ID + 1);
        assert_eq!(
            home_file_object_id(HOME_MAX_FILES - 1),
            HOME_TABLE_OBJECT_ID + HOME_MAX_FILES as u64
        );
    }
}
