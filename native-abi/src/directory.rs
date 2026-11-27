//! The directory capability (#312): a directory is a name table object and the entry objects
//! that follow it, the model the Linux `/home` projection introduced (#304).
//!
//! Directory `D` is the table object `D`; the object of entry `slot` is
//! [`entry_object_id`]`(D, slot)`, `D + 1 + slot`. A `PersistentObject` capability on `D`
//! with `Rights::DIRECTORY` authorises its `READ` and `WRITE` on every entry object too, so
//! one capability covers the directory: the per-holder capability quota cannot hold one per
//! entry. The table maps each live slot to its name and length.
//!
//! The table is one 512-byte object, so one write replaces it, and the commit that follows
//! it is the commit point: names, lengths and the entries' staged bytes become durable
//! together. A crash loses what changed since the last commit, never the agreement between
//! the table's lengths and the bytes.
//!
//! Layout, little-endian: an 8-byte magic ([`DIRECTORY_MAGIC`], which keeps the `/home`
//! format's name), 24 reserved zero bytes, then one 32-byte entry per slot: the length
//! (`u32`), the name length (`u8`, 0 for a free slot) and the name, zero-padded to
//! [`DIRECTORY_NAME_MAX`] bytes.

pub const DIRECTORY_MAX_ENTRIES: usize = 15;
pub const DIRECTORY_NAME_MAX: usize = 27;
/// Largest entry a directory takes. The storage service's live-byte budget is under 3 MiB
/// for the whole store.
pub const DIRECTORY_MAX_ENTRY_BYTES: u64 = 1024 * 1024;
pub const DIRECTORY_TABLE_BYTES: usize = 512;
pub const DIRECTORY_MAGIC: [u8; 8] = *b"CSHOME01";

const HEADER_BYTES: usize = 32;
const ENTRY_BYTES: usize = 32;
const _: () = assert!(HEADER_BYTES + DIRECTORY_MAX_ENTRIES * ENTRY_BYTES == DIRECTORY_TABLE_BYTES);
const _: () = assert!(4 + 1 + DIRECTORY_NAME_MAX == ENTRY_BYTES);

/// The object of entry `slot` in directory `directory`.
pub const fn entry_object_id(directory: u64, slot: usize) -> u64 {
    directory + 1 + slot as u64
}

/// Whether `object` is one of directory `directory`'s entry objects.
pub const fn is_entry_of(directory: u64, object: u64) -> bool {
    object > directory && object - directory <= DIRECTORY_MAX_ENTRIES as u64
}

/// Why a directory operation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryError {
    /// An empty name, `.`, `..`, or one holding `/` or NUL.
    InvalidName,
    /// A name longer than [`DIRECTORY_NAME_MAX`].
    NameTooLong,
    /// Every slot is taken.
    Full,
    /// No entry in that slot.
    NoEntry,
    /// The slot is taken.
    SlotTaken,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryEntry {
    name: [u8; DIRECTORY_NAME_MAX],
    name_len: u8,
    pub len: u32,
}

impl DirectoryEntry {
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    fn new(name: &[u8]) -> Self {
        let mut entry = Self {
            name: [0; DIRECTORY_NAME_MAX],
            name_len: name.len() as u8,
            len: 0,
        };
        entry.name[..name.len()].copy_from_slice(name);
        entry
    }
}

/// Why a stored table was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryTableError {
    BadLength,
    BadMagic,
    BadEntry,
    DuplicateName,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryTable {
    entries: [Option<DirectoryEntry>; DIRECTORY_MAX_ENTRIES],
}

impl DirectoryTable {
    pub const fn empty() -> Self {
        Self {
            entries: [None; DIRECTORY_MAX_ENTRIES],
        }
    }

    pub fn entry(&self, slot: usize) -> Option<&DirectoryEntry> {
        self.entries.get(slot).and_then(Option::as_ref)
    }

    pub fn entry_mut(&mut self, slot: usize) -> Option<&mut DirectoryEntry> {
        self.entries.get_mut(slot).and_then(Option::as_mut)
    }

    /// Live `(slot, entry)` pairs in slot order.
    pub fn live(&self) -> impl Iterator<Item = (usize, &DirectoryEntry)> {
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

    /// The slot a new entry would take: the first free one.
    pub fn free_slot(&self) -> Result<usize, DirectoryError> {
        self.entries
            .iter()
            .position(Option::is_none)
            .ok_or(DirectoryError::Full)
    }

    /// Creates an empty entry `name` in `slot`. The caller checked the name is free.
    pub fn create_at(&mut self, slot: usize, name: &[u8]) -> Result<(), DirectoryError> {
        validate_name(name)?;
        let entry = self.entries.get_mut(slot).ok_or(DirectoryError::NoEntry)?;
        if entry.is_some() {
            return Err(DirectoryError::SlotTaken);
        }
        *entry = Some(DirectoryEntry::new(name));
        Ok(())
    }

    pub fn remove(&mut self, slot: usize) {
        if let Some(entry) = self.entries.get_mut(slot) {
            *entry = None;
        }
    }

    /// Renames the entry in `slot` to `name`, removing the entry that had `name`, if any.
    /// Returns the slot it removed.
    pub fn rename(&mut self, slot: usize, name: &[u8]) -> Result<Option<usize>, DirectoryError> {
        validate_name(name)?;
        if self.entry(slot).is_none() {
            return Err(DirectoryError::NoEntry);
        }
        let victim = self.find(name).filter(|victim| *victim != slot);
        if let Some(victim) = victim {
            self.remove(victim);
        }
        let len = self.entry(slot).map_or(0, |entry| entry.len);
        let mut entry = DirectoryEntry::new(name);
        entry.len = len;
        self.entries[slot] = Some(entry);
        Ok(victim)
    }

    pub fn encode(&self) -> [u8; DIRECTORY_TABLE_BYTES] {
        let mut out = [0u8; DIRECTORY_TABLE_BYTES];
        out[..DIRECTORY_MAGIC.len()].copy_from_slice(&DIRECTORY_MAGIC);
        for (slot, entry) in self.live() {
            let at = HEADER_BYTES + slot * ENTRY_BYTES;
            out[at..at + 4].copy_from_slice(&entry.len.to_le_bytes());
            out[at + 4] = entry.name_len;
            out[at + 5..at + 5 + entry.name_len as usize].copy_from_slice(entry.name());
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DirectoryTableError> {
        if bytes.len() != DIRECTORY_TABLE_BYTES {
            return Err(DirectoryTableError::BadLength);
        }
        if bytes[..DIRECTORY_MAGIC.len()] != DIRECTORY_MAGIC
            || bytes[DIRECTORY_MAGIC.len()..HEADER_BYTES]
                .iter()
                .any(|b| *b != 0)
        {
            return Err(DirectoryTableError::BadMagic);
        }
        let mut table = Self::empty();
        for slot in 0..DIRECTORY_MAX_ENTRIES {
            let at = HEADER_BYTES + slot * ENTRY_BYTES;
            let raw = &bytes[at..at + ENTRY_BYTES];
            let len = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let name_len = raw[4] as usize;
            if name_len == 0 {
                if raw.iter().any(|b| *b != 0) {
                    return Err(DirectoryTableError::BadEntry);
                }
                continue;
            }
            if name_len > DIRECTORY_NAME_MAX || raw[5 + name_len..].iter().any(|b| *b != 0) {
                return Err(DirectoryTableError::BadEntry);
            }
            let name = &raw[5..5 + name_len];
            if validate_name(name).is_err() || u64::from(len) > DIRECTORY_MAX_ENTRY_BYTES {
                return Err(DirectoryTableError::BadEntry);
            }
            if table.find(name).is_some() {
                return Err(DirectoryTableError::DuplicateName);
            }
            let mut entry = DirectoryEntry::new(name);
            entry.len = len;
            table.entries[slot] = Some(entry);
        }
        Ok(table)
    }
}

/// A name a directory can hold: 1 to [`DIRECTORY_NAME_MAX`] bytes, no `/` or NUL, not `.`
/// or `..`.
pub fn validate_name(name: &[u8]) -> Result<(), DirectoryError> {
    if name.len() > DIRECTORY_NAME_MAX {
        return Err(DirectoryError::NameTooLong);
    }
    if name.is_empty()
        || name == b"."
        || name == b".."
        || name.iter().any(|b| *b == b'/' || *b == 0)
    {
        return Err(DirectoryError::InvalidName);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table_with(names: &[&[u8]]) -> DirectoryTable {
        let mut table = DirectoryTable::empty();
        for name in names {
            let slot = table.free_slot().unwrap();
            table.create_at(slot, name).unwrap();
        }
        table
    }

    #[test]
    fn an_empty_table_round_trips() {
        let table = DirectoryTable::empty();
        assert_eq!(DirectoryTable::decode(&table.encode()), Ok(table));
        assert_eq!(table.live_count(), 0);
    }

    #[test]
    fn names_and_lengths_round_trip_in_their_slots() {
        let mut table = table_with(&[b"doomsav0.dsg", b"default.cfg", b"doomsav5.dsg"]);
        table.entry_mut(0).unwrap().len = 180 * 1024;
        table.entry_mut(1).unwrap().len = 3;
        table.remove(1);
        let longest = [b'n'; DIRECTORY_NAME_MAX];
        table.create_at(1, &longest).unwrap();
        let decoded = DirectoryTable::decode(&table.encode()).unwrap();
        assert_eq!(decoded, table);
        assert_eq!(decoded.find(b"doomsav0.dsg"), Some(0));
        assert_eq!(decoded.find(&longest), Some(1));
        assert_eq!(decoded.find(b"default.cfg"), None);
        assert_eq!(decoded.total_bytes(), 180 * 1024);
    }

    #[test]
    fn the_table_fills_at_its_slot_count() {
        let mut table = DirectoryTable::empty();
        for index in 0..DIRECTORY_MAX_ENTRIES {
            let name = [b'a' + index as u8];
            table.create_at(table.free_slot().unwrap(), &name).unwrap();
        }
        assert_eq!(table.free_slot(), Err(DirectoryError::Full));
        table.remove(4);
        assert_eq!(table.free_slot(), Ok(4));
        assert_eq!(table.create_at(5, b"z"), Err(DirectoryError::SlotTaken));
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
        assert_eq!(table.rename(5, b"x"), Err(DirectoryError::NoEntry));
    }

    #[test]
    fn bad_names_are_refused() {
        let mut table = DirectoryTable::empty();
        for name in [&b""[..], b".", b"..", b"a/b", b"a\0b"] {
            assert_eq!(table.create_at(0, name), Err(DirectoryError::InvalidName));
        }
        assert_eq!(
            table.create_at(0, &[b'x'; DIRECTORY_NAME_MAX + 1]),
            Err(DirectoryError::NameTooLong)
        );
    }

    #[test]
    fn damaged_tables_are_refused() {
        let good = table_with(&[b"a", b"b"]).encode();
        assert_eq!(
            DirectoryTable::decode(&good[..100]),
            Err(DirectoryTableError::BadLength)
        );
        let mut bad = good;
        bad[0] ^= 1;
        assert_eq!(
            DirectoryTable::decode(&bad),
            Err(DirectoryTableError::BadMagic)
        );
        let mut bad = good;
        bad[HEADER_BYTES + 4] = DIRECTORY_NAME_MAX as u8 + 1;
        assert_eq!(
            DirectoryTable::decode(&bad),
            Err(DirectoryTableError::BadEntry)
        );
        let mut bad = good;
        bad[HEADER_BYTES + ENTRY_BYTES + 5] = b'a';
        assert_eq!(
            DirectoryTable::decode(&bad),
            Err(DirectoryTableError::DuplicateName)
        );
        let mut bad = good;
        bad[HEADER_BYTES..HEADER_BYTES + 4]
            .copy_from_slice(&(DIRECTORY_MAX_ENTRY_BYTES as u32 + 1).to_le_bytes());
        assert_eq!(
            DirectoryTable::decode(&bad),
            Err(DirectoryTableError::BadEntry)
        );
        let mut bad = good;
        bad[HEADER_BYTES + 2 * ENTRY_BYTES] = 1;
        assert_eq!(
            DirectoryTable::decode(&bad),
            Err(DirectoryTableError::BadEntry)
        );
    }

    #[test]
    fn entry_objects_follow_the_table_object() {
        let directory = 0x004D_0000;
        assert_eq!(entry_object_id(directory, 0), directory + 1);
        assert_eq!(
            entry_object_id(directory, DIRECTORY_MAX_ENTRIES - 1),
            directory + DIRECTORY_MAX_ENTRIES as u64
        );
        assert!(!is_entry_of(directory, directory));
        assert!(is_entry_of(directory, directory + 1));
        assert!(is_entry_of(
            directory,
            directory + DIRECTORY_MAX_ENTRIES as u64
        ));
        assert!(!is_entry_of(
            directory,
            directory + DIRECTORY_MAX_ENTRIES as u64 + 1
        ));
        assert!(!is_entry_of(directory, directory - 1));
    }
}
