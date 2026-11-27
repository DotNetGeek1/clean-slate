//! #219 stage D: the audit service's persisted log, kept in its audit store.
//!
//! The store is a native directory (#312) the audit service alone holds
//! (`Grant::AuditStore`). The log lives in the entry [`AUDIT_LOG_NAME`]: a
//! [`AUDIT_STORE_BLOCK_BYTES`]-byte [`SegmentHeader`], then one block per persisted record.
//!
//! Each record block is the 64-byte `AuditEvent` exactly as the kernel handed it, the record's
//! wall-clock time, the boot it was read in, 16 zero bytes, and its chain hash: SHA-256 of the
//! previous record's hash followed by the block's first 96 bytes. The first record of a segment
//! chains from the segment's anchor, which is the previous segment's head, or 32 zero bytes for
//! the first segment ever. The chain is unkeyed (#219 owner decision 3): it shows that the log
//! was not changed by accident or by a writer that did not recompute it, not who wrote it.
//!
//! The header carries the reader's cursor (the first kernel sequence not yet persisted this
//! boot) and the chain's head, and is rewritten by the same commit that makes new records
//! durable, so records, cursor and head always agree on disk.
//!
//! A segment holds at most [`AUDIT_SEGMENT_MAX_RECORDS`] records (256 KiB). A full segment is
//! renamed [`AUDIT_OLD_NAME`], replacing the one before it, and a new segment anchored on its
//! head takes its place, so the store keeps the newest two segments. A segment that does not
//! verify is renamed [`AUDIT_BAD_NAME`], kept for inspection rather than overwritten, and a new
//! segment starts in its place.

use clean_slate_capability::{
    AuditEvent, AuditKind, AuditOutcome, ResourceClass, Rights, AUDIT_EVENT_SIZE_BYTES,
};
use clean_slate_native_abi::directory::is_entry_of;
use clean_slate_native_abi::object::OBJECT_SERVICE_ROLE_ID;
use clean_slate_native_abi::status::STATUS_ENOENT;
use clean_slate_runtime::storage::{Directory, Entry, Object};
use clean_slate_runtime::{Error, Syscalls};
use core::mem::offset_of;
use sha2::{Digest, Sha256};

use crate::audit_reader::AUDIT_DRAIN_MAX_RECORDS;

/// The current segment of the persisted log.
pub const AUDIT_LOG_NAME: &[u8] = b"audit.log";
/// The segment before it, once one has filled.
pub const AUDIT_OLD_NAME: &[u8] = b"audit.old";
/// The last segment that did not verify.
pub const AUDIT_BAD_NAME: &[u8] = b"audit.bad";

/// The header and every record are this long.
pub const AUDIT_STORE_BLOCK_BYTES: usize = 128;
/// Records one segment holds: a segment is at most 256 KiB, header included.
pub const AUDIT_SEGMENT_MAX_RECORDS: u64 = 2047;
/// The first eight bytes of a segment.
pub const AUDIT_STORE_MAGIC: [u8; 8] = *b"CSAUDIT1";

/// The bytes of a record the chain hash covers.
const RECORD_BODY_BYTES: usize = 96;
/// Blocks read per storage request while verifying (one 512-byte request).
const VERIFY_BLOCKS: usize = 4;
/// Blocks staged per write while appending.
const WRITE_BLOCKS: usize = 8;

pub type ChainHash = [u8; 32];

/// The anchor of the first segment ever.
pub const GENESIS: ChainHash = [0; 32];

/// SHA-256 of `previous` followed by `body`.
pub fn chain_hash(previous: &ChainHash, body: &[u8]) -> ChainHash {
    let mut hasher = Sha256::new();
    hasher.update(previous);
    hasher.update(body);
    hasher.finalize().into()
}

/// A segment's header, at offset 0 of its entry.
///
/// | Offset | Field |
/// | --- | --- |
/// | 0 | magic, [`AUDIT_STORE_MAGIC`] |
/// | 8 | `boot` |
/// | 16 | `next_since` |
/// | 24 | `records` |
/// | 32 | `segment` |
/// | 40 | zero |
/// | 64 | `anchor` |
/// | 96 | `head` |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentHeader {
    /// Boots that have read the log, counting this one; 0 before the first.
    pub boot: u64,
    /// The first kernel sequence of boot `boot` not yet persisted.
    pub next_since: u64,
    /// Records in this segment.
    pub records: u64,
    /// This segment's number: 0 for the first, one more at each rotation.
    pub segment: u64,
    /// The hash the segment's first record chains from.
    pub anchor: ChainHash,
    /// The hash of the segment's last record, or `anchor` while it has none.
    pub head: ChainHash,
}

impl SegmentHeader {
    /// The first segment of an empty store.
    pub const GENESIS: Self = Self {
        boot: 0,
        next_since: 1,
        records: 0,
        segment: 0,
        anchor: GENESIS,
        head: GENESIS,
    };

    /// The segment that follows `self` once it is full.
    pub const fn successor(&self) -> Self {
        Self {
            records: 0,
            segment: self.segment + 1,
            anchor: self.head,
            ..*self
        }
    }

    /// The entry length a segment with this header has.
    pub const fn entry_len(&self) -> u64 {
        (self.records + 1) * AUDIT_STORE_BLOCK_BYTES as u64
    }

    pub fn encode(&self) -> [u8; AUDIT_STORE_BLOCK_BYTES] {
        let mut bytes = [0u8; AUDIT_STORE_BLOCK_BYTES];
        bytes[..8].copy_from_slice(&AUDIT_STORE_MAGIC);
        bytes[8..16].copy_from_slice(&self.boot.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.next_since.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.records.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.segment.to_le_bytes());
        bytes[64..96].copy_from_slice(&self.anchor);
        bytes[96..128].copy_from_slice(&self.head);
        bytes
    }

    pub fn decode(bytes: &[u8; AUDIT_STORE_BLOCK_BYTES]) -> Option<Self> {
        if bytes[..8] != AUDIT_STORE_MAGIC || bytes[40..64].iter().any(|&byte| byte != 0) {
            return None;
        }
        let mut anchor = [0u8; 32];
        let mut head = [0u8; 32];
        anchor.copy_from_slice(&bytes[64..96]);
        head.copy_from_slice(&bytes[96..128]);
        Some(Self {
            boot: word(bytes, 8),
            next_since: word(bytes, 16),
            records: word(bytes, 24),
            segment: word(bytes, 32),
            anchor,
            head,
        })
    }
}

fn word(bytes: &[u8], offset: usize) -> u64 {
    let mut le = [0u8; 8];
    le.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(le)
}

/// One persisted record, before it is chained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredRecord {
    /// The record as the kernel handed it.
    pub event: [u8; AUDIT_EVENT_SIZE_BYTES],
    /// Unix nanoseconds when the kernel recorded it, or 0 when the boot had no wall clock or
    /// the record has no time.
    pub wall_ns: u64,
    /// The boot it was read in ([`SegmentHeader::boot`]).
    pub boot: u64,
}

impl StoredRecord {
    /// The record's wall-clock time: the boot's epoch (Unix nanoseconds at monotonic 0) plus
    /// the record's monotonic timestamp. A record the kernel made before its clock ran has
    /// timestamp 0 and keeps 0.
    pub fn wall_ns_of(event: &[u8; AUDIT_EVENT_SIZE_BYTES], boot_epoch_ns: Option<u64>) -> u64 {
        let timestamp = word(event, offset_of!(AuditEvent, timestamp_ns));
        match boot_epoch_ns {
            Some(epoch) if timestamp != 0 => epoch.saturating_add(timestamp),
            _ => 0,
        }
    }

    /// The block for this record when the chain's head is `previous`, and its hash.
    pub fn chain(&self, previous: &ChainHash) -> ([u8; AUDIT_STORE_BLOCK_BYTES], ChainHash) {
        let mut block = [0u8; AUDIT_STORE_BLOCK_BYTES];
        block[..AUDIT_EVENT_SIZE_BYTES].copy_from_slice(&self.event);
        block[64..72].copy_from_slice(&self.wall_ns.to_le_bytes());
        block[72..80].copy_from_slice(&self.boot.to_le_bytes());
        let hash = chain_hash(previous, &block[..RECORD_BODY_BYTES]);
        block[RECORD_BODY_BYTES..].copy_from_slice(&hash);
        (block, hash)
    }
}

/// Whether the reader keeps `event`. Persisting a batch is itself a use of the store, and the
/// storage service serving it uses its service role and its block device, so keeping those
/// allowed uses would make every drain write the uses of the one before it, and the log would
/// never go quiet. Not kept, then: the reader's own allowed uses of the log and of its store,
/// and any holder's allowed uses of the object-service role or of a block device, which are
/// the storage service serving requests (every client's request is kept as the client's use
/// of its own object capability). Everything else is kept, every denial included.
pub fn worth_keeping(event: &[u8; AUDIT_EVENT_SIZE_BYTES], reader: u64, store: u64) -> bool {
    let outcome = offset_of!(AuditEvent, outcome) + offset_of!(AuditOutcome, tag);
    let allowed_use = event[offset_of!(AuditEvent, kind)] == AuditKind::Authorize as u8
        && event[outcome] == AuditOutcome::TAG_ALLOWED;
    if !allowed_use {
        return true;
    }
    let resource = word(event, offset_of!(AuditEvent, resource_id));
    let class = event[offset_of!(AuditEvent, class)];
    let serves_storage = class == ResourceClass::BlockDevice as u8
        || (class == ResourceClass::PersistentObject as u8 && resource == OBJECT_SERVICE_ROLE_ID);
    if serves_storage {
        return false;
    }
    if word(event, offset_of!(AuditEvent, actor)) != reader {
        return true;
    }
    let requested = offset_of!(AuditEvent, requested);
    let mut rights = [0u8; 4];
    rights.copy_from_slice(&event[requested..requested + 4]);
    let reads_log = class == ResourceClass::Audit as u8
        && u32::from_le_bytes(rights) == Rights::AUDIT_READ.bits();
    let uses_store = class == ResourceClass::PersistentObject as u8
        && (resource == store || is_entry_of(store, resource));
    !(reads_log || uses_store)
}

/// Why a segment did not verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Damage {
    /// The header is not a segment header.
    Header,
    /// The entry's length does not match the header's record count.
    Length,
    /// Record `n` (from 0) does not chain from the one before it, or, at `n` = the record
    /// count, the last record is not the header's head.
    Chain(u64),
    /// The segment does not chain from the previous segment's head.
    Link,
}

/// What [`AuditStore::open`] found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpenReport {
    /// The previous segment did not verify and was set aside as [`AUDIT_BAD_NAME`].
    pub old_damage: Option<Damage>,
    /// The current segment did not verify and was set aside as [`AUDIT_BAD_NAME`].
    pub log_damage: Option<Damage>,
    /// Records verified, in both segments.
    pub verified: u64,
    /// A new segment was started: on an empty store, after a rotation a crash interrupted,
    /// or in place of a damaged one.
    pub started_segment: bool,
}

/// The persisted log, open for appending.
#[derive(Debug)]
pub struct AuditStore {
    directory: Directory,
    slot: usize,
    object: Object,
    header: SegmentHeader,
}

impl AuditStore {
    /// Opens the log in `directory`, verifying both segments, and starts a segment if there is
    /// none. Fails only when storage does.
    pub fn open<S: Syscalls>(
        sys: &mut S,
        directory: Directory,
    ) -> Result<(Self, OpenReport), Error> {
        let mut report = OpenReport::default();
        let mut previous = None;
        if let Some(old) = nonempty(sys, directory, AUDIT_OLD_NAME)? {
            match verify(sys, &old)? {
                Ok(header) => {
                    report.verified += header.records;
                    previous = Some(header);
                }
                Err(damage) => {
                    report.old_damage = Some(damage);
                    directory.rename(sys, AUDIT_OLD_NAME, AUDIT_BAD_NAME)?;
                }
            }
        }
        if let Some(log) = nonempty(sys, directory, AUDIT_LOG_NAME)? {
            let damage = match verify(sys, &log)? {
                Ok(header) if previous.is_none_or(|old| old.head == header.anchor) => {
                    report.verified += header.records;
                    let store = Self {
                        directory,
                        slot: log.slot,
                        object: log.object,
                        header,
                    };
                    return Ok((store, report));
                }
                Ok(_) => Damage::Link,
                Err(damage) => damage,
            };
            report.log_damage = Some(damage);
            directory.rename(sys, AUDIT_LOG_NAME, AUDIT_BAD_NAME)?;
        }
        report.started_segment = true;
        let header = previous.map_or(SegmentHeader::GENESIS, |old| old.successor());
        Ok((Self::start_segment(sys, directory, header)?, report))
    }

    pub fn header(&self) -> &SegmentHeader {
        &self.header
    }

    /// Starts boot `boot + 1` with its cursor at sequence 1, durably, before anything of the
    /// boot is read: so a later instance of this boot that finds a read log (its launch
    /// cursor above 0) knows the header it finds is this boot's.
    pub fn begin_boot<S: Syscalls>(&mut self, sys: &mut S) -> Result<(), Error> {
        let mut header = self.header;
        header.boot += 1;
        header.next_since = 1;
        self.commit(sys, header)
    }

    /// Appends the `records` that `keep` keeps (at most [`AUDIT_DRAIN_MAX_RECORDS`]; each a
    /// kernel record of this boot, with its wall-clock time from `boot_epoch_ns`) and moves the
    /// cursor to `next_since`, in one commit. Nothing is written when nothing is kept: the cursor
    /// alone is not worth a write, since a restarted reader re-reads and drops the same records.
    pub fn append<S: Syscalls>(
        &mut self,
        sys: &mut S,
        records: &[[u8; AUDIT_EVENT_SIZE_BYTES]],
        keep: impl Fn(&[u8; AUDIT_EVENT_SIZE_BYTES]) -> bool,
        boot_epoch_ns: Option<u64>,
        next_since: u64,
    ) -> Result<(), Error> {
        assert!(records.len() <= AUDIT_DRAIN_MAX_RECORDS);
        let kept = records.iter().filter(|event| keep(event)).count() as u64;
        if kept == 0 {
            return Ok(());
        }
        if self.header.records + kept > AUDIT_SEGMENT_MAX_RECORDS {
            self.rotate(sys)?;
        }
        let mut header = self.header;
        let mut blocks = [0u8; WRITE_BLOCKS * AUDIT_STORE_BLOCK_BYTES];
        let mut staged = 0;
        for event in records.iter().filter(|event| keep(event)) {
            let record = StoredRecord {
                event: *event,
                wall_ns: StoredRecord::wall_ns_of(event, boot_epoch_ns),
                boot: header.boot,
            };
            let (block, hash) = record.chain(&header.head);
            blocks[staged * AUDIT_STORE_BLOCK_BYTES..][..AUDIT_STORE_BLOCK_BYTES]
                .copy_from_slice(&block);
            header.head = hash;
            staged += 1;
            if staged == WRITE_BLOCKS {
                self.object.write_at(sys, header.entry_len(), &blocks)?;
                header.records += staged as u64;
                staged = 0;
            }
        }
        if staged > 0 {
            self.object.write_at(
                sys,
                header.entry_len(),
                &blocks[..staged * AUDIT_STORE_BLOCK_BYTES],
            )?;
            header.records += staged as u64;
        }
        header.next_since = next_since;
        self.commit(sys, header)
    }

    /// Writes `header` and commits it with everything staged; the in-memory header follows
    /// only once the commit succeeded.
    fn commit<S: Syscalls>(&mut self, sys: &mut S, header: SegmentHeader) -> Result<(), Error> {
        self.object.write_at(sys, 0, &header.encode())?;
        self.directory.set_len(sys, self.slot, header.entry_len())?;
        self.header = header;
        Ok(())
    }

    /// Keeps the full segment as the old one and starts its successor.
    fn rotate<S: Syscalls>(&mut self, sys: &mut S) -> Result<(), Error> {
        self.directory.rename(sys, AUDIT_LOG_NAME, AUDIT_OLD_NAME)?;
        *self = Self::start_segment(sys, self.directory, self.header.successor())?;
        Ok(())
    }

    fn start_segment<S: Syscalls>(
        sys: &mut S,
        directory: Directory,
        header: SegmentHeader,
    ) -> Result<Self, Error> {
        let entry = directory.create(sys, AUDIT_LOG_NAME)?;
        let mut store = Self {
            directory,
            slot: entry.slot,
            object: entry.object,
            header,
        };
        store.commit(sys, header)?;
        Ok(store)
    }
}

/// The entry `name` when it exists and is not empty. An empty one is a segment whose first
/// commit never happened.
fn nonempty<S: Syscalls>(
    sys: &mut S,
    directory: Directory,
    name: &[u8],
) -> Result<Option<Entry>, Error> {
    match directory.open(sys, name) {
        Ok(entry) if entry.len > 0 => Ok(Some(entry)),
        Ok(_) | Err(Error::Failed(STATUS_ENOENT)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Reads the segment in `entry` and checks its header, its length and every record's hash.
pub fn verify<S: Syscalls>(
    sys: &mut S,
    entry: &Entry,
) -> Result<Result<SegmentHeader, Damage>, Error> {
    let mut bytes = [0u8; AUDIT_STORE_BLOCK_BYTES];
    if entry.len < AUDIT_STORE_BLOCK_BYTES as u64
        || entry.object.read_at(sys, 0, &mut bytes)? != AUDIT_STORE_BLOCK_BYTES
    {
        return Ok(Err(Damage::Length));
    }
    let Some(header) = SegmentHeader::decode(&bytes) else {
        return Ok(Err(Damage::Header));
    };
    if header.records > AUDIT_SEGMENT_MAX_RECORDS || header.entry_len() != entry.len {
        return Ok(Err(Damage::Length));
    }
    let mut head = header.anchor;
    let mut index = 0;
    let mut blocks = [0u8; VERIFY_BLOCKS * AUDIT_STORE_BLOCK_BYTES];
    while index < header.records {
        let count = (header.records - index).min(VERIFY_BLOCKS as u64) as usize;
        let want = count * AUDIT_STORE_BLOCK_BYTES;
        let offset = (index + 1) * AUDIT_STORE_BLOCK_BYTES as u64;
        if entry.object.read_at(sys, offset, &mut blocks[..want])? != want {
            return Ok(Err(Damage::Length));
        }
        for block in blocks[..want].chunks_exact(AUDIT_STORE_BLOCK_BYTES) {
            let hash = chain_hash(&head, &block[..RECORD_BODY_BYTES]);
            if block[RECORD_BODY_BYTES..] != hash {
                return Ok(Err(Damage::Chain(index)));
            }
            head = hash;
            index += 1;
        }
    }
    if head != header.head {
        return Ok(Err(Damage::Chain(header.records)));
    }
    Ok(Ok(header))
}

#[cfg(test)]
mod tests;
