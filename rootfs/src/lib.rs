//! Deterministic read-only rootfs image format for M9 BusyBox fixtures (#104).
#![cfg_attr(not(feature = "std"), no_std)]

pub const MAGIC: &[u8; 8] = b"CSROOTFS";
pub const VERSION: u16 = 1;
pub const HEADER_SIZE: usize = 32;
pub const ENTRY_SIZE: usize = 80;
pub const MAX_ENTRIES: usize = 64;
pub const MAX_PATH_BYTES: usize = 64;
pub const MAX_IMAGE_BYTES: usize = 2 * 1024 * 1024;
pub const DATA_ALIGN: usize = 16;

pub const KIND_DIR: u8 = 1;
pub const KIND_FILE: u8 = 2;
pub const KIND_LINK: u8 = 3;
pub const FLAG_WRITABLE_ROOT: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Dir,
    File,
    Link,
}

impl EntryKind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            KIND_DIR => Some(Self::Dir),
            KIND_FILE => Some(Self::File),
            KIND_LINK => Some(Self::Link),
            _ => None,
        }
    }

}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootfsError {
    TooSmall,
    BadMagic,
    BadVersion,
    BadHeaderCrc,
    EntryCountOutOfRange,
    ImageTooLarge,
    EntriesOutOfBounds,
    DataOutOfBounds,
    UnsortedPaths,
    DuplicatePath,
    BadEntryKind,
    PathLenMismatch,
    PathTooLong,
    DataMisaligned,
    EmptyPath,
    BadPath,
}

pub struct Image<'a> {
    bytes: &'a [u8],
    entry_count: usize,
    entries_offset: usize,
    data_offset: usize,
    data_len: usize,
}

pub struct Entry<'a> {
    pub path: &'a [u8],
    pub kind: EntryKind,
    pub writable_root: bool,
    pub data: &'a [u8],
}

impl<'a> Image<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, RootfsError> {
        if bytes.len() < HEADER_SIZE {
            return Err(RootfsError::TooSmall);
        }
        if bytes.get(0..8) != Some(MAGIC.as_slice()) {
            return Err(RootfsError::BadMagic);
        }
        let version = read_u16_le(bytes, 8);
        if version != VERSION {
            return Err(RootfsError::BadVersion);
        }
        let entry_count = read_u16_le(bytes, 10) as usize;
        if entry_count > MAX_ENTRIES {
            return Err(RootfsError::EntryCountOutOfRange);
        }
        let entries_offset = read_u32_le(bytes, 16) as usize;
        let data_offset = read_u32_le(bytes, 20) as usize;
        let data_len = read_u32_le(bytes, 24) as usize;
        let stored_crc = read_u32_le(bytes, 28);
        let computed_crc = crc32(&bytes[..28]);
        if stored_crc != computed_crc {
            return Err(RootfsError::BadHeaderCrc);
        }
        if entries_offset != HEADER_SIZE {
            return Err(RootfsError::EntriesOutOfBounds);
        }
        let entries_end = entries_offset + entry_count * ENTRY_SIZE;
        if entries_end > bytes.len() || data_offset < entries_end {
            return Err(RootfsError::EntriesOutOfBounds);
        }
        let data_end = data_offset + data_len;
        if data_end > bytes.len() || data_end > MAX_IMAGE_BYTES {
            return Err(RootfsError::ImageTooLarge);
        }

        let image = Self {
            bytes,
            entry_count,
            entries_offset,
            data_offset,
            data_len,
        };
        image.validate_entries()?;
        Ok(image)
    }

    pub fn raw_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.entry_count
    }

    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    pub fn entry(&self, index: usize) -> Option<Entry<'a>> {
        if index >= self.entry_count {
            return None;
        }
        self.decode_entry(index).ok()
    }

    pub fn lookup(&self, path: &[u8]) -> Option<Entry<'a>> {
        let mut lo = 0usize;
        let mut hi = self.entry_count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let entry_path = self.entry_path(mid).ok()?;
            match entry_path.cmp(path) {
                core::cmp::Ordering::Less => lo = mid + 1,
                core::cmp::Ordering::Greater => hi = mid,
                core::cmp::Ordering::Equal => return self.entry(mid),
            }
        }
        None
    }

    pub fn children<'d>(&'a self, dir: &'d [u8]) -> ChildrenIter<'a, 'd> {
        ChildrenIter {
            image: self,
            dir,
            index: 0,
        }
    }

    fn validate_entries(&self) -> Result<(), RootfsError> {
        let mut prev: Option<&[u8]> = None;
        for i in 0..self.entry_count {
            let path = self.entry_path(i)?;
            if path.is_empty() {
                return Err(RootfsError::EmptyPath);
            }
            if !path.starts_with(b"/") {
                return Err(RootfsError::BadPath);
            }
            if let Some(p) = prev {
                if path <= p {
                    if path == p {
                        return Err(RootfsError::DuplicatePath);
                    }
                    return Err(RootfsError::UnsortedPaths);
                }
            }
            prev = Some(path);
            let entry = self.decode_entry(i)?;
            if path.len() != entry.path.len() {
                return Err(RootfsError::PathLenMismatch);
            }
            let (kind, flags, path_len, data_off, data_len) = self.raw_entry_fields(i)?;
            if path_len as usize != path.len() {
                return Err(RootfsError::PathLenMismatch);
            }
            if path.len() > MAX_PATH_BYTES {
                return Err(RootfsError::PathTooLong);
            }
            match kind {
                KIND_DIR => {
                    if data_len != 0 || data_off != 0 {
                        return Err(RootfsError::DataOutOfBounds);
                    }
                }
                KIND_FILE | KIND_LINK => {
                    if data_len == 0 && entry.kind != EntryKind::File {
                        // empty files are allowed; links need target bytes
                    }
                    if data_off as usize % DATA_ALIGN != 0 {
                        return Err(RootfsError::DataMisaligned);
                    }
                    let start = self.data_offset + data_off as usize;
                    let end = start + data_len as usize;
                    if end > self.data_offset + self.data_len {
                        return Err(RootfsError::DataOutOfBounds);
                    }
                    if entry.kind == EntryKind::Link && entry.data.is_empty() {
                        return Err(RootfsError::DataOutOfBounds);
                    }
                }
                _ => return Err(RootfsError::BadEntryKind),
            }
            if flags & !FLAG_WRITABLE_ROOT != 0 {
                return Err(RootfsError::BadEntryKind);
            }
            if flags & FLAG_WRITABLE_ROOT != 0 && path != b"/tmp" {
                return Err(RootfsError::BadPath);
            }
        }
        Ok(())
    }

    fn entry_offset(&self, index: usize) -> usize {
        self.entries_offset + index * ENTRY_SIZE
    }

    fn raw_entry_fields(&self, index: usize) -> Result<(u8, u8, u8, u32, u32), RootfsError> {
        let off = self.entry_offset(index);
        let slice = self.bytes.get(off..off + ENTRY_SIZE).ok_or(RootfsError::TooSmall)?;
        Ok((
            slice[0],
            slice[1],
            slice[2],
            read_u32_le(slice, 4),
            read_u32_le(slice, 8),
        ))
    }

    fn entry_path(&self, index: usize) -> Result<&'a [u8], RootfsError> {
        let (_, _, path_len, _, _) = self.raw_entry_fields(index)?;
        let off = self.entry_offset(index) + 12;
        let path_len = path_len as usize;
        if path_len > MAX_PATH_BYTES {
            return Err(RootfsError::PathTooLong);
        }
        let slice = self
            .bytes
            .get(off..off + path_len)
            .ok_or(RootfsError::TooSmall)?;
        Ok(slice)
    }

    fn decode_entry(&self, index: usize) -> Result<Entry<'a>, RootfsError> {
        let (kind_u8, flags, path_len, data_off, data_len) = self.raw_entry_fields(index)?;
        let kind = EntryKind::from_u8(kind_u8).ok_or(RootfsError::BadEntryKind)?;
        let path = self.entry_path(index)?;
        if path_len as usize != path.len() {
            return Err(RootfsError::PathLenMismatch);
        }
        let data = if kind == EntryKind::Dir {
            &[]
        } else {
            let start = self.data_offset + data_off as usize;
            let end = start + data_len as usize;
            self.bytes.get(start..end).ok_or(RootfsError::DataOutOfBounds)?
        };
        Ok(Entry {
            path,
            kind,
            writable_root: flags & FLAG_WRITABLE_ROOT != 0,
            data,
        })
    }
}

pub struct ChildrenIter<'a, 'd> {
    image: &'a Image<'a>,
    dir: &'d [u8],
    index: usize,
}

impl<'a, 'd> Iterator for ChildrenIter<'a, 'd> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.image.entry_count {
            let idx = self.index;
            self.index += 1;
            let entry = self.image.entry(idx)?;
            if is_direct_child(self.dir, entry.path) {
                return Some(entry);
            }
        }
        None
    }
}

fn is_direct_child(dir: &[u8], child: &[u8]) -> bool {
    if dir == b"/" {
        if !child.starts_with(b"/") || child.len() <= 1 {
            return false;
        }
        let rest = &child[1..];
        return !rest.is_empty() && !rest.contains(&b'/');
    }
    if !child.starts_with(dir) || child.len() <= dir.len() {
        return false;
    }
    if child[dir.len()] != b'/' {
        return false;
    }
    let rest = &child[dir.len() + 1..];
    !rest.is_empty() && !rest.contains(&b'/')
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32_le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(feature = "std")]
mod manifest;
#[cfg(feature = "std")]
mod pack;

#[cfg(feature = "std")]
pub use manifest::{Manifest, ManifestEntry, ManifestKind};
#[cfg(feature = "std")]
pub use pack::pack;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_empty() {
        assert_eq!(crc32(b""), 0);
    }

    #[cfg(feature = "std")]
    mod std_tests {
        use super::*;
        use std::path::Path;

        fn fixture_resolve(base: &Path, rel: &str) -> std::io::Result<Vec<u8>> {
            std::fs::read(base.join(rel))
        }

        #[test]
        fn round_trip_minimal_manifest() {
            let toml = r#"
[image]
version = 1
[[entry]]
path = "/"
kind = "dir"
[[entry]]
path = "/tmp"
kind = "dir"
writable = true
[[entry]]
path = "/etc/hostname"
kind = "file"
inline = "m9-fixture\n"
"#;
            let manifest = Manifest::parse_toml(toml).expect("parse");
            let base = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("fixtures/busybox/frozen");
            let packed = pack(
                &manifest,
                |_| Err(std::io::Error::new(std::io::ErrorKind::NotFound, "unused")),
            )
            .expect("pack");
            let image = Image::parse(&packed).expect("parse packed");
            assert!(image.lookup(b"/tmp").unwrap().writable_root);
            assert_eq!(
                image.lookup(b"/etc/hostname").unwrap().data,
                b"m9-fixture\n"
            );
        }

        #[test]
        fn deterministic_double_pack() {
            let toml = std::fs::read_to_string(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap()
                    .join("fixtures/busybox/frozen/rootfs.toml"),
            )
            .expect("rootfs.toml");
            let manifest = Manifest::parse_toml(&toml).expect("parse");
            let base = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("fixtures/busybox/frozen");
            let resolve = |p: &Path| -> std::io::Result<Vec<u8>> {
                if let Ok(rel) = p.strip_prefix(&base) {
                    return std::fs::read(base.join(rel));
                }
                let name = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "name"))?;
                if name == "busybox" {
                    return std::fs::read(base.join("busybox"));
                }
                std::fs::read(p)
            };
            let a = pack(&manifest, resolve).expect("pack a");
            let b = pack(&manifest, resolve).expect("pack b");
            assert_eq!(a, b);
        }

        #[test]
        fn children_and_lookup_misses() {
            let toml = std::fs::read_to_string(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap()
                    .join("fixtures/busybox/frozen/rootfs.toml"),
            )
            .expect("rootfs.toml");
            let manifest = Manifest::parse_toml(&toml).expect("parse");
            let base = Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("fixtures/busybox/frozen");
            let packed = pack(
                &manifest,
                |p| std::fs::read(base.join(p.file_name().unwrap())),
            )
            .expect("pack");
            let image = Image::parse(&packed).expect("parse");
            assert!(image.lookup(b"/bin/").is_none());
            assert!(image.lookup(b"//bin").is_none());
            assert!(image.lookup(b"bin").is_none());
            let root_children: Vec<_> = image.children(b"/").map(|e| e.path).collect();
            assert!(root_children.iter().any(|p| *p == b"/bin"));
            assert!(root_children.iter().any(|p| *p == b"/etc"));
            assert!(root_children.iter().any(|p| *p == b"/tmp"));
            let bin_children: Vec<_> = image.children(b"/bin").map(|e| e.path).collect();
            assert!(bin_children.iter().any(|p| *p == b"/bin/busybox"));
        }

        #[test]
        fn non_utf8_path_round_trip() {
            let toml = r#"
[image]
version = 1
[[entry]]
path = "/"
kind = "dir"
[[entry]]
path = "/\xFFoo"
kind = "file"
inline = "x"
"#;
            let manifest = Manifest::parse_toml(toml).expect("parse");
            let packed = pack(&manifest, |_| Ok(Vec::new())).expect("pack");
            let image = Image::parse(&packed).expect("parse");
            let path = &[b'/', 0xFF, b'o', b'o'];
            assert_eq!(image.lookup(path).unwrap().data, b"x");
        }

        #[test]
        fn rejects_duplicate_paths() {
            let toml = r#"
[image]
version = 1
[[entry]]
path = "/"
kind = "dir"
[[entry]]
path = "/a"
kind = "dir"
[[entry]]
path = "/a"
kind = "dir"
"#;
            let manifest = Manifest::parse_toml(toml).expect("parse");
            let err = pack(&manifest, |_| Ok(Vec::new())).unwrap_err();
            assert_eq!(err, RootfsError::DuplicatePath);
        }
    }

    #[test]
    fn malformed_header_crc() {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&0u16.to_le_bytes());
        bytes[16..20].copy_from_slice(&(HEADER_SIZE as u32).to_le_bytes());
        assert!(matches!(
            Image::parse(&bytes),
            Err(RootfsError::BadHeaderCrc)
        ));
    }
}
