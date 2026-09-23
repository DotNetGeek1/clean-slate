//! Deterministic read-only rootfs image format for M9 (#104 / #101).

#![cfg_attr(not(feature = "std"), no_std)]

pub const MAGIC: &[u8; 8] = b"CSROOTFS";
pub const VERSION: u16 = 1;
pub const MAX_ENTRIES: usize = 64;
pub const MAX_PATH_BYTES: usize = 64;
pub const MAX_IMAGE_BYTES: usize = 2 * 1024 * 1024;
const HEADER_LEN: usize = 32;
const ENTRY_LEN: usize = 80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Dir = 1,
    File = 2,
    Link = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootfsError {
    TooShort,
    BadMagic,
    BadVersion,
    BadCrc,
    EntryCount,
    OutOfBounds,
    UnsortedPaths,
    DuplicatePath,
    PathTooLong,
    ImageTooLarge,
    InvalidKind,
}

pub struct Image<'a> {
    bytes: &'a [u8],
    entry_count: usize,
    entries_offset: usize,
    data_offset: usize,
}

pub struct Entry<'a> {
    pub path: &'a [u8],
    pub kind: EntryKind,
    pub writable_root: bool,
    pub data: &'a [u8],
}

impl<'a> Image<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, RootfsError> {
        if bytes.len() < HEADER_LEN {
            return Err(RootfsError::TooShort);
        }
        if &bytes[..8] != MAGIC {
            return Err(RootfsError::BadMagic);
        }
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version != VERSION {
            return Err(RootfsError::BadVersion);
        }
        let entry_count = u16::from_le_bytes([bytes[10], bytes[11]]) as usize;
        if entry_count > MAX_ENTRIES {
            return Err(RootfsError::EntryCount);
        }
        let entries_offset = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let data_offset = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) as usize;
        let data_len = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) as usize;
        let stored_crc = u32::from_le_bytes(bytes[28..32].try_into().unwrap());
        let computed = crc32(&bytes[..28]);
        if stored_crc != computed {
            return Err(RootfsError::BadCrc);
        }
        let end = data_offset.checked_add(data_len).ok_or(RootfsError::OutOfBounds)?;
        if end > bytes.len() || end > MAX_IMAGE_BYTES {
            return Err(RootfsError::OutOfBounds);
        }
        let entries_end = entries_offset
            .checked_add(entry_count.checked_mul(ENTRY_LEN).ok_or(RootfsError::OutOfBounds)?)
            .ok_or(RootfsError::OutOfBounds)?;
        if entries_end > data_offset {
            return Err(RootfsError::OutOfBounds);
        }
        let image = Self {
            bytes,
            entry_count,
            entries_offset,
            data_offset,
        };
        image.validate_entries()?;
        Ok(image)
    }

    fn validate_entries(&self) -> Result<(), RootfsError> {
        let mut prev: Option<&[u8]> = None;
        for index in 0..self.entry_count {
            let entry = self.raw_entry(index)?;
            if let Some(p) = prev {
                if entry.path <= p {
                    return if entry.path == p {
                        Err(RootfsError::DuplicatePath)
                    } else {
                        Err(RootfsError::UnsortedPaths)
                    };
                }
            }
            prev = Some(entry.path);
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    fn raw_entry(&self, index: usize) -> Result<Entry<'a>, RootfsError> {
        if index >= self.entry_count {
            return Err(RootfsError::OutOfBounds);
        }
        let base = self
            .entries_offset
            .checked_add(index * ENTRY_LEN)
            .ok_or(RootfsError::OutOfBounds)?;
        let slice = self.bytes.get(base..base + ENTRY_LEN).ok_or(RootfsError::OutOfBounds)?;
        let kind = match slice[0] {
            1 => EntryKind::Dir,
            2 => EntryKind::File,
            3 => EntryKind::Link,
            _ => return Err(RootfsError::InvalidKind),
        };
        let writable_root = (slice[1] & 1) != 0;
        let path_len = slice[2] as usize;
        if path_len > MAX_PATH_BYTES {
            return Err(RootfsError::PathTooLong);
        }
        let data_rel_off = u32::from_le_bytes(slice[4..8].try_into().unwrap()) as usize;
        let data_len2 = u32::from_le_bytes(slice[8..12].try_into().unwrap()) as usize;
        let path = &slice[12..12 + path_len];
        let abs_off = self
            .data_offset
            .checked_add(data_rel_off)
            .ok_or(RootfsError::OutOfBounds)?;
        let data_end = abs_off.checked_add(data_len2).ok_or(RootfsError::OutOfBounds)?;
        let data = self.bytes.get(abs_off..data_end).ok_or(RootfsError::OutOfBounds)?;
        Ok(Entry {
            path,
            kind,
            writable_root,
            data,
        })
    }

    pub fn entry(&self, index: usize) -> Option<Entry<'a>> {
        self.raw_entry(index).ok()
    }

    pub fn lookup(&self, path: &[u8]) -> Option<Entry<'a>> {
        let mut lo = 0usize;
        let mut hi = self.entry_count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let entry = self.raw_entry(mid).ok()?;
            if entry.path == path {
                return Some(entry);
            }
            if entry.path < path {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        None
    }

    pub fn children<'s>(&'s self, dir: &[u8]) -> ChildrenIter<'s, 'a> {
        let mut dir_buf = [0u8; MAX_PATH_BYTES];
        let len = dir.len().min(MAX_PATH_BYTES);
        dir_buf[..len].copy_from_slice(&dir[..len]);
        ChildrenIter {
            image: self,
            dir: dir_buf,
            dir_len: len,
            index: 0,
        }
    }
}

pub struct ChildrenIter<'s, 'a: 's> {
    image: &'s Image<'a>,
    dir: [u8; MAX_PATH_BYTES],
    dir_len: usize,
    index: usize,
}

impl<'s, 'a: 's> Iterator for ChildrenIter<'s, 'a> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.image.entry_count {
            let entry = self.image.raw_entry(self.index).ok();
            self.index += 1;
            if let Some(entry) = entry {
                if is_direct_child(&self.dir[..self.dir_len], entry.path) {
                    return Some(entry);
                }
            }
        }
        None
    }
}

fn is_direct_child(dir: &[u8], path: &[u8]) -> bool {
    if path.len() <= dir.len() || !path.starts_with(dir) {
        return false;
    }
    let mut rest = &path[dir.len()..];
    if rest.starts_with(b"/") {
        rest = &rest[1..];
    }
    !rest.is_empty() && !rest.contains(&b'/')
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xedb8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[cfg(feature = "std")]
pub mod pack_std {
    use super::*;
    #[derive(Clone, Debug)]
    pub struct ManifestEntry {
        pub path: Vec<u8>,
        pub kind: EntryKind,
        pub writable_root: bool,
        pub data: Vec<u8>,
    }

    #[derive(Clone, Debug, Default)]
    pub struct Manifest {
        pub entries: Vec<ManifestEntry>,
    }

    pub fn pack(manifest: &Manifest) -> Result<Vec<u8>, RootfsError> {
        let mut sorted: Vec<_> = manifest.entries.iter().cloned().collect();
        sorted.sort_by(|a, b| a.path.cmp(&b.path));
        for window in sorted.windows(2) {
            if window[0].path == window[1].path {
                return Err(RootfsError::DuplicatePath);
            }
        }
        if sorted.len() > MAX_ENTRIES {
            return Err(RootfsError::EntryCount);
        }
        let mut data_section: Vec<u8> = Vec::new();
        let mut entry_records: Vec<[u8; ENTRY_LEN]> = Vec::new();
        for entry in &sorted {
            if entry.path.len() > MAX_PATH_BYTES {
                return Err(RootfsError::PathTooLong);
            }
            let data_off = align16(data_section.len());
            while data_section.len() < data_off {
                data_section.push(0);
            }
            let rel_off = data_section.len();
            data_section.extend_from_slice(&entry.data);
            let mut rec = [0u8; ENTRY_LEN];
            rec[0] = entry.kind as u8;
            if entry.writable_root {
                rec[1] = 1;
            }
            rec[2] = entry.path.len() as u8;
            rec[4..8].copy_from_slice(&(rel_off as u32).to_le_bytes());
            rec[8..12].copy_from_slice(&(entry.data.len() as u32).to_le_bytes());
            rec[12..12 + entry.path.len()].copy_from_slice(&entry.path);
            entry_records.push(rec);
        }
        let entries_offset = HEADER_LEN;
        let data_offset = entries_offset + entry_records.len() * ENTRY_LEN;
        let total_len = data_offset + data_section.len();
        if total_len > MAX_IMAGE_BYTES {
            return Err(RootfsError::ImageTooLarge);
        }
        let mut out = vec![0u8; total_len];
        out[..8].copy_from_slice(MAGIC);
        out[8..10].copy_from_slice(&VERSION.to_le_bytes());
        out[10..12].copy_from_slice(&(sorted.len() as u16).to_le_bytes());
        out[16..20].copy_from_slice(&(entries_offset as u32).to_le_bytes());
        out[20..24].copy_from_slice(&(data_offset as u32).to_le_bytes());
        out[24..28].copy_from_slice(&(data_section.len() as u32).to_le_bytes());
        let crc = crc32(&out[..28]);
        out[28..32].copy_from_slice(&crc.to_le_bytes());
        for (i, rec) in entry_records.iter().enumerate() {
            let base = entries_offset + i * ENTRY_LEN;
            out[base..base + ENTRY_LEN].copy_from_slice(rec);
        }
        out[data_offset..].copy_from_slice(&data_section);
        Ok(out)
    }

    fn align16(n: usize) -> usize {
        (n + 15) & !15
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_minimal_tree() {
        #[cfg(feature = "std")]
        {
            use pack_std::{Manifest, ManifestEntry};
            let manifest = Manifest {
                entries: vec![
                    ManifestEntry {
                        path: b"/".to_vec(),
                        kind: EntryKind::Dir,
                        writable_root: false,
                        data: vec![],
                    },
                    ManifestEntry {
                        path: b"/bin".to_vec(),
                        kind: EntryKind::Dir,
                        writable_root: false,
                        data: vec![],
                    },
                    ManifestEntry {
                        path: b"/tmp".to_vec(),
                        kind: EntryKind::Dir,
                        writable_root: true,
                        data: vec![],
                    },
                ],
            };
            let packed = pack_std::pack(&manifest).unwrap();
            let image = Image::parse(&packed).unwrap();
            assert!(image.lookup(b"/bin").is_some());
            let kids: Vec<_> = image.children(b"/").collect();
            assert_eq!(kids.len(), 2);
        }
    }
}
