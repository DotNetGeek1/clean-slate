//! Crash matrix for the `clean-slate-store` commit protocol on a faulty device.
//!
//! Seeded random workloads (create, update and delete objects, commit) run on a
//! [`FaultDevice`]. Each workload is crashed at every operation prefix, the
//! crash is resolved by fault-mode-specific crash plans, and the durable image
//! is mounted. Every case must satisfy the store's promise for devices that may
//! lie: the mount yields exactly one generation that some `commit` wrote (its
//! generation number and every object byte), or a clean `Corrupt` /
//! `Incompatible` error. Never a mix, and never data no commit wrote. An
//! unmountable image must probe as `Refused`, so the storage service leaves it
//! alone, unless both superblock slots are all zero; only then is it `Blank`.
//! `ObjectStore::open` must reach the same decision, and write nothing unless
//! it formats a blank image. A refusal must name the damage on disk: a payload
//! when some slot holds an intact superblock, an interrupted first format when
//! each slot is blank or a zero-filled byte prefix of the block `format` wrote,
//! "not a store" when neither slot holds the magic, and corrupt superblocks
//! otherwise; never another format version, since no fault here produces a
//! foreign slot with a valid checksum.
//!
//! Stronger checks where the device allows them:
//! - unless writes are misdirected, every superblock on disk sits in the slot
//!   it was written for, so the mount must be exactly the newest generation
//!   whose superblock and payload bytes are intact, or an error when none is;
//! - on an honest device (flushes kept, writes in place; pending writes may
//!   persist in any subset and order, and tear), the newest intact superblock
//!   must mount, and never one older than the last acknowledged commit;
//! - once `format` is acknowledged on a device that keeps flushes and writes
//!   in place, no crash or bit flip makes the image `Blank` again;
//! - the store's device contract is that a one-logical-block write is atomic on
//!   power loss. On an honest device that keeps it, no crash, including one
//!   during the first `format`, leaves the image refused. The honest mode
//!   never tears; the sector-atomic mode tears at logical-block boundaries,
//!   which splits multi-block payload writes but never a one-block
//!   superblock;
//! - as defence in depth, on an honest device whose writes tear at any byte,
//!   an image is refused only when the first `format` was interrupted, and
//!   then as `InterruptedFormat`. No format order avoids such refusals: the
//!   first write to make a slot non-zero can tear just after its first
//!   non-zero byte, which leaves a slot that is neither blank nor a superblock;
//! - `InterruptedFormat` never names damage to a store whose `format` was
//!   acknowledged, on a device that keeps flushes and writes in place.
//!
//! The run is bounded for `cargo test`; set `CLEAN_SLATE_STORE_FAULT_SCALE=N`
//! to run N times as many seeded workloads.

mod support;

use std::collections::BTreeMap;
use std::time::Instant;

use clean_slate_block::fake::FakeBlockDevice;
use clean_slate_block::{BlockDeviceId, BlockGeometry};
use clean_slate_store::{
    probe, ObjectStore, OpenError, Opened, Probe, Refusal, StoreError, MIN_OBJECT_LIMIT,
    STORE_MAGIC, SUPERBLOCK_SLOTS, TABLE_ENTRY_BYTES,
};
use support::fault_device::{CrashStep, FaultConfig, FaultDevice, OpKind, OpOutcome};

const SCALE_ENV: &str = "CLEAN_SLATE_STORE_FAULT_SCALE";
const BASE_SEEDS: u64 = 16;
/// Device-fault configurations (dropped flushes or a misdirected write) tried
/// per workload, each crashed at every prefix.
const FAULT_RUNS_PER_SEED: usize = 4;
const FIRST_SEED: u64 = 0x224b_0000;

const BLOCK: usize = 512;
const BLOCK_COUNT: u64 = 64;
/// Blocks in each of the two payload arenas.
const ARENA_BLOCKS: u64 = (BLOCK_COUNT - SUPERBLOCK_SLOTS) / 2;
const MAX_LIVE_OBJECTS: usize = 5;
const MAX_OBJECT_BLOCKS: usize = 4;
const _: () = assert!(MAX_LIVE_OBJECTS <= MIN_OBJECT_LIMIT);
const _: () = assert!((MAX_LIVE_OBJECTS * MAX_OBJECT_BLOCKS) as u64 <= ARENA_BLOCKS);

/// Format layout used by the intactness oracle: the superblock's generation,
/// object count and object-table extent, and in each table entry the object
/// id, start LBA and payload length.
const GENERATION_OFFSET: usize = 12;
const OBJECT_COUNT_OFFSET: usize = 36;
const TABLE_START_OFFSET: usize = 56;
const TABLE_BLOCKS_OFFSET: usize = 64;
const ENTRY_ID_OFFSET: usize = 0;
const ENTRY_START_OFFSET: usize = 16;
const ENTRY_LEN_OFFSET: usize = 24;

/// Fixed tear offsets: the checksum, generation, object-count, next-epoch and
/// table-extent fields of a superblock, the start, length and second-entry
/// fields of an object table, and the block boundary of a two-block write.
const TEAR_OFFSETS: &[usize] = &[
    1,
    4,
    8,
    12,
    16,
    20,
    24,
    36,
    48,
    56,
    64,
    68,
    72,
    144,
    BLOCK - 1,
    BLOCK,
    BLOCK + 1,
    BLOCK + 48,
];
const RANDOM_TEAR_OFFSETS: usize = 3;
/// Fixed bit flips in each superblock slot: the magic, the version field (3
/// becomes 2, 1 and 259), the checksum and the generation.
const FLIP_BITS: &[usize] = &[0, 32, 33, 40, 64, 96];
/// Pending-write counts up to this enumerate every subset; above it, sample.
const EXHAUSTIVE_SUBSET_LIMIT: usize = 6;
const SAMPLED_SUBSETS: usize = 64;

fn geometry() -> BlockGeometry {
    BlockGeometry::new(BlockDeviceId::new(224), 512, BLOCK_COUNT, 2, false).unwrap()
}

/// SplitMix64: a small seedable generator, so every case is reproducible
/// from the seed printed with a failure.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next_u64() % u64::try_from(bound).unwrap()).unwrap()
    }

    fn coin(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for index in (1..items.len()).rev() {
            items.swap(index, self.below(index + 1));
        }
    }
}

type Snapshot = BTreeMap<u64, (String, Vec<u8>)>;

enum Mutation {
    Write {
        id: u64,
        name: String,
        data: Vec<u8>,
    },
    Delete {
        id: u64,
    },
}

/// Each entry is the writes and deletes staged before one commit.
struct Workload {
    commits: Vec<Vec<Mutation>>,
}

/// Creates, updates and deletes. A create sometimes takes the name of an object deleted
/// earlier, under a new id, so a commit can drop one object and add another of the same name.
fn generate_workload(rng: &mut Rng) -> Workload {
    let mut live: Vec<(u64, String)> = Vec::new();
    let mut freed_names: Vec<String> = Vec::new();
    let mut next_index = 0u64;
    let commit_count = 3 + rng.below(4);
    let commits = (0..commit_count)
        .map(|_| {
            let mutation_count = 1 + rng.below(3);
            (0..mutation_count)
                .map(|_| {
                    if !live.is_empty() && rng.below(4) == 0 {
                        let (id, name) = live.swap_remove(rng.below(live.len()));
                        freed_names.push(name);
                        return Mutation::Delete { id };
                    }
                    let create = live.is_empty() || (live.len() < MAX_LIVE_OBJECTS && rng.coin());
                    let (id, name) = if create {
                        next_index += 1;
                        let id = 0x100 + next_index;
                        let name = if !freed_names.is_empty() && rng.coin() {
                            freed_names.swap_remove(rng.below(freed_names.len()))
                        } else {
                            format!("obj{next_index}")
                        };
                        live.push((id, name.clone()));
                        (id, name)
                    } else {
                        live[rng.below(live.len())].clone()
                    };
                    Mutation::Write {
                        id,
                        name,
                        data: payload(rng),
                    }
                })
                .collect()
        })
        .collect();
    Workload { commits }
}

/// Every full block holds the same bytes (0..=255 twice) in a fresh order, so
/// a stale full block in place of a new one never changes an additive byte
/// sum: only a real checksum tells them apart.
fn payload(rng: &mut Rng) -> Vec<u8> {
    let len = match rng.below(4) {
        0 => rng.below(65),
        1 | 2 => BLOCK * (1 + rng.below(MAX_OBJECT_BLOCKS)),
        _ => BLOCK * rng.below(MAX_OBJECT_BLOCKS) + 1 + rng.below(BLOCK - 1),
    };
    let mut data = Vec::with_capacity(len.next_multiple_of(BLOCK));
    while data.len() < len {
        let mut block = (0..BLOCK).map(|index| index as u8).collect::<Vec<_>>();
        rng.shuffle(&mut block);
        data.extend_from_slice(&block);
    }
    data.truncate(len);
    data
}

fn snapshot_of<D: clean_slate_block::BlockDevice>(store: &ObjectStore<D>) -> Snapshot {
    store
        .objects()
        .iter()
        .map(|object| {
            let data = store.read_object_by_id(object.id()).unwrap();
            (object.id(), (object.name().to_owned(), data))
        })
        .collect()
}

struct Run {
    device: FaultDevice,
    /// `snapshots[g]` is what the commit producing generation `g` wrote;
    /// generation 0 is the empty store `format` writes.
    snapshots: Vec<Snapshot>,
    last_acked: Option<u64>,
}

/// Format and run `workload`, stopping at the power loss if `faults` has one.
fn run_workload(workload: &Workload, faults: FaultConfig) -> Run {
    let device = FaultDevice::new(geometry(), faults);
    let mut run = Run {
        device: device.clone(),
        snapshots: vec![Snapshot::new()],
        last_acked: None,
    };
    let mut store = match ObjectStore::format(device) {
        Ok(store) => store,
        Err(error) => {
            assert!(run.device.is_powered_off(), "format failed: {error:?}");
            return run;
        }
    };
    run.last_acked = Some(0);
    for commit in &workload.commits {
        for mutation in commit {
            match mutation {
                Mutation::Write { id, name, data } => store
                    .write_object(*id, name, data)
                    .expect("workload stays within store limits"),
                Mutation::Delete { id } => store
                    .delete_object(*id)
                    .expect("workload deletes only live objects"),
            }
        }
        run.snapshots.push(snapshot_of(&store));
        match store.commit() {
            Ok(()) => run.last_acked = Some(store.committed_generation()),
            Err(error) => {
                assert!(run.device.is_powered_off(), "commit failed: {error:?}");
                return run;
            }
        }
    }
    run
}

fn mount(image: &[u8]) -> Result<(u64, Snapshot), StoreError> {
    let device = FakeBlockDevice::from_durable_bytes(geometry(), image).unwrap();
    let store = ObjectStore::mount(device)?;
    Ok((store.committed_generation(), snapshot_of(&store)))
}

struct SuperblockWrite {
    generation: u64,
    lba: u64,
    bytes: Vec<u8>,
    /// The object table this superblock names, as its commit wrote it: the
    /// newest write aimed at each of its blocks before the superblock write.
    table: Vec<u8>,
}

impl SuperblockWrite {
    fn table_start(&self) -> u64 {
        read_u64(&self.bytes, TABLE_START_OFFSET)
    }

    fn entries(&self) -> impl Iterator<Item = &[u8]> {
        let count = usize::try_from(read_u32(&self.bytes, OBJECT_COUNT_OFFSET)).unwrap();
        self.table[..count * TABLE_ENTRY_BYTES].chunks_exact(TABLE_ENTRY_BYTES)
    }
}

fn superblock_writes(device: &FaultDevice) -> Vec<SuperblockWrite> {
    let mut written = BTreeMap::<u64, Vec<u8>>::new();
    let mut writes = Vec::new();
    for op in device.log() {
        let OpKind::Write { lba, data, .. } = op.kind else {
            continue;
        };
        if lba < SUPERBLOCK_SLOTS {
            let table_start = read_u64(&data, TABLE_START_OFFSET);
            let table_blocks = u64::from(read_u32(&data, TABLE_BLOCKS_OFFSET));
            let table = (table_start..table_start + table_blocks)
                .flat_map(|block| written[&block].clone())
                .collect();
            writes.push(SuperblockWrite {
                generation: read_u64(&data, GENERATION_OFFSET),
                lba,
                bytes: data,
                table,
            });
        } else {
            for (index, block) in data.chunks_exact(BLOCK).enumerate() {
                written.insert(lba + u64::try_from(index).unwrap(), block.to_vec());
            }
        }
    }
    writes
}

fn stored_block(image: &[u8], lba: u64) -> &[u8] {
    let start = usize::try_from(lba).unwrap() * BLOCK;
    &image[start..start + BLOCK]
}

/// The object table and every payload byte the superblock references are on
/// disk as its commit wrote them.
fn payload_intact(image: &[u8], superblock: &SuperblockWrite, snapshot: &Snapshot) -> bool {
    let table_start = usize::try_from(superblock.table_start()).unwrap() * BLOCK;
    if image[table_start..table_start + superblock.table.len()] != superblock.table[..] {
        return false;
    }
    superblock.entries().all(|entry| {
        let len = usize::try_from(read_u32(entry, ENTRY_LEN_OFFSET)).unwrap();
        let start = usize::try_from(read_u64(entry, ENTRY_START_OFFSET)).unwrap() * BLOCK;
        let (_, data) = &snapshot[&read_u64(entry, ENTRY_ID_OFFSET)];
        image[start..start + len] == data[..]
    })
}

/// The newest generation whose superblock sits intact in the slot it was
/// written for and, with `with_payload`, whose payload is intact too.
fn newest_intact(run: &Run, image: &[u8], with_payload: bool) -> Option<u64> {
    superblock_writes(&run.device)
        .iter()
        .filter(|write| stored_block(image, write.lba) == write.bytes)
        .filter(|write| {
            let snapshot = &run.snapshots[usize::try_from(write.generation).unwrap()];
            !with_payload || payload_intact(image, write, snapshot)
        })
        .map(|write| write.generation)
        .max()
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Pending writes persist in any subset and order at the crash.
    Honest,
    /// As `Honest`, and one pending write tears at a logical-block boundary.
    SectorAtomic,
    /// As `Honest`, and one pending write tears at a byte offset.
    Torn,
    /// Flushes are acknowledged without persisting; pending writes then
    /// persist in any subset and order, or tear.
    DroppedFlush,
    /// As `Honest`, then one stored bit flips.
    BitFlip,
    /// One write lands at another LBA.
    Misdirected,
}

impl Mode {
    /// The device keeps its flush promise and stores data where it was told.
    fn is_honest(self) -> bool {
        matches!(self, Self::Honest | Self::SectorAtomic | Self::Torn)
    }

    /// Honest, and no logical block is ever left part old and part new.
    fn is_sector_atomic(self) -> bool {
        matches!(self, Self::Honest | Self::SectorAtomic)
    }

    /// What a flush acknowledged stays on disk where it was written, give or take a flipped bit.
    fn persists_acknowledged_writes(self) -> bool {
        self.is_honest() || self == Self::BitFlip
    }

    /// Every superblock on disk sits in the slot it was written for.
    fn writes_in_place(self) -> bool {
        self != Self::Misdirected
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// The commit in flight at the crash (or not acknowledged because of it).
    InFlight,
    LastAcked,
    /// A generation older than the last acknowledged commit.
    RolledBack,
    /// Unmountable, so the storage service refuses the disk and leaves it as is.
    Refused(Refusal),
    /// Refused, and `format` was never acknowledged: the crash interrupted the first format.
    RefusedBeforeFormatAck(Refusal),
    /// Unmountable with both superblock slots still all zero: no format or
    /// commit reached them, so the service formats a disk that holds nothing.
    Blank,
}

fn describe(snapshot: &Snapshot) -> String {
    let objects = snapshot
        .iter()
        .map(|(id, (name, data))| format!("{id:#x}/{name}/{}B", data.len()))
        .collect::<Vec<_>>();
    format!("[{}]", objects.join(", "))
}

fn check(mode: Mode, run: &Run, image: &[u8]) -> Result<Outcome, String> {
    let mounted = mount(image);
    let generation = match &mounted {
        Ok((generation, objects)) => {
            let Some(written) = run.snapshots.get(usize::try_from(*generation).unwrap()) else {
                return Err(format!(
                    "mounted generation {generation}, which no commit wrote"
                ));
            };
            if written != objects {
                let matching = run
                    .snapshots
                    .iter()
                    .position(|snapshot| snapshot == objects);
                return Err(format!(
                    "MIX: generation {generation} mounted {}, its commit wrote {} \
                     (matches the objects of generation {matching:?})",
                    describe(objects),
                    describe(written),
                ));
            }
            Some(*generation)
        }
        Err(StoreError::Corrupt(_) | StoreError::Incompatible(_)) => None,
        Err(error) => return Err(format!("unclean mount error {error:?}")),
    };
    let shown = match &mounted {
        Ok((generation, _)) => format!("generation {generation}"),
        Err(error) => format!("{error:?}"),
    };

    if mode.writes_in_place() {
        let expected = newest_intact(run, image, true);
        if generation != expected {
            return Err(format!(
                "mounted {shown}; newest generation intact on disk is {expected:?}"
            ));
        }
    }
    if mode.is_honest() {
        let expected = newest_intact(run, image, false);
        if generation != expected {
            return Err(format!(
                "honest device mounted {shown}; newest intact superblock is generation {expected:?}"
            ));
        }
        if generation < run.last_acked {
            return Err(format!(
                "honest device mounted {shown}, older than acknowledged generation {:?}",
                run.last_acked
            ));
        }
    }

    let mut device = FakeBlockDevice::from_durable_bytes(geometry(), image).unwrap();
    let probed = probe(&mut device).map_err(|error| format!("probe failed: {error:?}"))?;
    let blank = image[..SUPERBLOCK_SLOTS as usize * BLOCK]
        .iter()
        .all(|&byte| byte == 0);
    let decision_holds = match probed {
        Probe::Mountable => generation.is_some(),
        Probe::Blank => generation.is_none() && blank,
        Probe::Refused(_) => generation.is_none() && !blank,
    };
    if !decision_holds {
        return Err(format!(
            "mounted {shown} with superblock slots {}, but the service would decide {probed:?}",
            if blank { "all zero" } else { "not all zero" }
        ));
    }
    if probed == Probe::Blank && run.last_acked.is_some() && mode.persists_acknowledged_writes() {
        return Err(format!(
            "format was acknowledged, yet the image probes {probed:?} and would be reformatted"
        ));
    }
    if let Probe::Refused(refusal) = probed {
        if let Some(expected) = expected_refusal(run, image) {
            if refusal != expected {
                return Err(format!(
                    "refused as {refusal:?}, but the damage on disk is {expected:?}"
                ));
            }
        }
        if mode.is_sector_atomic() {
            return Err(format!(
                "a crash on an honest device with sector-atomic writes left it refused as \
                 {refusal:?}"
            ));
        }
        if mode == Mode::Torn
            && (refusal != Refusal::InterruptedFormat
                || run.last_acked.is_some()
                || !torn_first_format(run, image))
        {
            return Err(format!(
                "honest device refused as {refusal:?}, and not because a tear interrupted the \
                 first format"
            ));
        }
        if refusal == Refusal::InterruptedFormat
            && run.last_acked.is_some()
            && mode.persists_acknowledged_writes()
        {
            return Err(
                "a store whose format was acknowledged is refused as an interrupted first format"
                    .to_owned(),
            );
        }
    }
    check_open(image, probed, &mounted)?;

    Ok(match (generation, run.last_acked) {
        (None, None) => match probed {
            Probe::Refused(refusal) => Outcome::RefusedBeforeFormatAck(refusal),
            _ => Outcome::Blank,
        },
        (None, Some(_)) => match probed {
            Probe::Refused(refusal) => Outcome::Refused(refusal),
            _ => Outcome::Blank,
        },
        (Some(generation), Some(acked)) if generation < acked => Outcome::RolledBack,
        (Some(generation), Some(acked)) if generation == acked => Outcome::LastAcked,
        (Some(_), _) => Outcome::InFlight,
    })
}

/// The refusal an unmountable image must get, judged from where its slot bytes
/// came from rather than by the store's decoder. `None` when a slot holds a
/// superblock aimed at the other slot, which may or may not decode where it
/// landed.
fn expected_refusal(run: &Run, image: &[u8]) -> Option<Refusal> {
    let writes = superblock_writes(&run.device);
    let slots = (0..SUPERBLOCK_SLOTS)
        .map(|lba| (lba, stored_block(image, lba)))
        .collect::<Vec<_>>();
    if slots.iter().any(|(lba, bytes)| {
        writes
            .iter()
            .any(|write| write.lba == *lba && write.bytes == *bytes)
    }) {
        Some(Refusal::PayloadInvalid)
    } else if slots
        .iter()
        .any(|(_, bytes)| writes.iter().any(|write| write.bytes == *bytes))
    {
        None
    } else if torn_first_format(run, image) {
        Some(Refusal::InterruptedFormat)
    } else if slots
        .iter()
        .all(|(_, bytes)| bytes[..4] != STORE_MAGIC.to_le_bytes())
    {
        Some(Refusal::NotAStore)
    } else {
        Some(Refusal::SuperblocksInvalid)
    }
}

/// Each superblock slot is blank or a strict byte prefix of the block `format`
/// wrote, zero-filled after it: a sub-sector tear of the first format.
fn torn_first_format(run: &Run, image: &[u8]) -> bool {
    let Some(format_block) = superblock_writes(&run.device)
        .into_iter()
        .find(|write| write.generation == 0)
        .map(|write| write.bytes)
    else {
        return false;
    };
    (0..SUPERBLOCK_SLOTS).all(|lba| {
        let slot = stored_block(image, lba);
        let written = slot
            .iter()
            .rposition(|&byte| byte != 0)
            .map_or(0, |last| last + 1);
        slot[..written] == format_block[..written] && slot != format_block.as_slice()
    })
}

/// `open` must reach the decision `probe` made, and write nothing unless it
/// formats a blank image.
fn check_open(
    image: &[u8],
    probed: Probe,
    mounted: &Result<(u64, Snapshot), StoreError>,
) -> Result<(), String> {
    let device = FaultDevice::from_image(geometry(), image);
    let opened = ObjectStore::open(device.clone());
    let mutations = device.log().len();
    let holds = match (&opened, probed) {
        (Ok((store, Opened::Formatted)), Probe::Blank) => {
            store.committed_generation() == 0 && store.objects().is_empty()
        }
        (Ok((store, Opened::Mounted)), Probe::Mountable) => {
            mutations == 0
                && mounted.as_ref().ok()
                    == Some(&(store.committed_generation(), snapshot_of(store)))
        }
        (Err(OpenError::Refused(refusal)), Probe::Refused(probed_refusal)) => {
            mutations == 0 && *refusal == probed_refusal
        }
        _ => false,
    };
    if holds {
        Ok(())
    } else {
        Err(format!(
            "probe decided {probed:?}, but open gave {:?} after {mutations} writes and flushes",
            opened.map(|(store, how)| (how, store.committed_generation()))
        ))
    }
}

/// Device faults for one run: none, a random non-empty set of dropped
/// flushes, or one misdirected write.
fn device_faults(mode: Mode, clean: &Run, rng: &mut Rng) -> FaultConfig {
    let log = clean.device.log();
    match mode {
        Mode::Honest | Mode::SectorAtomic | Mode::Torn | Mode::BitFlip => FaultConfig::default(),
        Mode::DroppedFlush => {
            let flushes = log.iter().filter(|op| op.kind == OpKind::Flush).count();
            let mut dropped_flushes = (0..flushes).filter(|_| rng.coin()).collect::<Vec<_>>();
            if dropped_flushes.is_empty() {
                dropped_flushes.push(rng.below(flushes));
            }
            FaultConfig {
                dropped_flushes,
                ..FaultConfig::default()
            }
        }
        Mode::Misdirected => {
            let writes = log
                .iter()
                .filter_map(|op| match &op.kind {
                    OpKind::Write { lba, data, .. } => Some((*lba, data.len() / BLOCK)),
                    OpKind::Flush => None,
                })
                .collect::<Vec<_>>();
            let ordinal = rng.below(writes.len());
            let (lba, blocks) = writes[ordinal];
            FaultConfig {
                misdirected_writes: vec![(ordinal, misdirect_target(lba, blocks, rng))],
                ..FaultConfig::default()
            }
        }
    }
}

/// Another LBA for a `blocks`-block write aimed at `lba`: the other
/// superblock slot, the same place in the other arena, a neighbour, or
/// anywhere in the payload area.
fn misdirect_target(lba: u64, blocks: usize, rng: &mut Rng) -> u64 {
    let blocks = u64::try_from(blocks).unwrap();
    let fits = |target: u64| target != lba && target + blocks <= BLOCK_COUNT;
    loop {
        let target = match rng.below(4) {
            0 if blocks == 1 => u64::try_from(rng.below(2)).unwrap(),
            1 if lba >= SUPERBLOCK_SLOTS + ARENA_BLOCKS => lba - ARENA_BLOCKS,
            1 if lba >= SUPERBLOCK_SLOTS => lba + ARENA_BLOCKS,
            2 if rng.coin() && lba > 0 => lba - 1,
            2 => lba + 1,
            _ => {
                SUPERBLOCK_SLOTS
                    + u64::try_from(
                        rng.below(usize::try_from(BLOCK_COUNT - SUPERBLOCK_SLOTS).unwrap()),
                    )
                    .unwrap()
            }
        };
        if fits(target) {
            return target;
        }
    }
}

/// Persist `indices` in a random order.
fn persist_shuffled(indices: impl IntoIterator<Item = usize>, rng: &mut Rng) -> Vec<CrashStep> {
    let mut steps = indices
        .into_iter()
        .map(CrashStep::Persist)
        .collect::<Vec<_>>();
    rng.shuffle(&mut steps);
    steps
}

fn random_subset(count: usize, rng: &mut Rng) -> Vec<CrashStep> {
    let chosen = (0..count).filter(|_| rng.coin()).collect::<Vec<_>>();
    persist_shuffled(chosen, rng)
}

/// Every subset of the pending writes when there are few, else a sample.
fn subset_plans(count: usize, rng: &mut Rng) -> Vec<Vec<CrashStep>> {
    if count <= EXHAUSTIVE_SUBSET_LIMIT {
        (0..1usize << count)
            .map(|mask| persist_shuffled((0..count).filter(|index| mask & (1 << index) != 0), rng))
            .collect()
    } else {
        (0..SAMPLED_SUBSETS)
            .map(|_| random_subset(count, rng))
            .collect()
    }
}

fn tear_offsets(len: usize, rng: &mut Rng) -> Vec<usize> {
    let mut offsets = TEAR_OFFSETS
        .iter()
        .copied()
        .filter(|offset| *offset < len)
        .collect::<Vec<_>>();
    offsets.extend((0..RANDOM_TEAR_OFFSETS).map(|_| 1 + rng.below(len - 1)));
    offsets
}

/// `others` persisted (in their given order), then pending write `index` torn.
fn with_tear(mut others: Vec<CrashStep>, index: usize, bytes: usize) -> Vec<CrashStep> {
    others.retain(|step| *step != CrashStep::Persist(index));
    others.push(CrashStep::Tear { index, bytes });
    others
}

fn crash_plans(mode: Mode, device: &FaultDevice, rng: &mut Rng) -> Vec<Vec<CrashStep>> {
    let pending = device.pending();
    let count = pending.len();
    let log = device.log();
    let in_flight = pending
        .iter()
        .position(|write| log[write.op].outcome == OpOutcome::PowerLoss);
    match mode {
        Mode::Honest => subset_plans(count, rng),
        Mode::SectorAtomic => {
            let mut plans = subset_plans(count, rng);
            for (index, write) in pending.iter().enumerate() {
                for bytes in (BLOCK..write.data.len()).step_by(BLOCK) {
                    plans.push(with_tear(Vec::new(), index, bytes));
                    plans.push(with_tear(random_subset(count, rng), index, bytes));
                }
            }
            plans
        }
        Mode::Torn => {
            let mut plans = Vec::new();
            for (index, write) in pending.iter().enumerate() {
                if Some(index) == in_flight {
                    for bytes in tear_offsets(write.data.len(), rng) {
                        let all_others = persist_shuffled(0..count, rng);
                        plans.push(with_tear(Vec::new(), index, bytes));
                        plans.push(with_tear(all_others, index, bytes));
                        plans.push(with_tear(random_subset(count, rng), index, bytes));
                    }
                } else {
                    let bytes = 1 + rng.below(write.data.len() - 1);
                    plans.push(with_tear(random_subset(count, rng), index, bytes));
                }
            }
            plans
        }
        Mode::DroppedFlush => {
            let mut plans = vec![
                Vec::new(),
                (0..count).map(CrashStep::Persist).collect(),
                (0..count).rev().map(CrashStep::Persist).collect(),
            ];
            plans.extend((0..6).map(|_| random_subset(count, rng)));
            if count > 0 {
                for _ in 0..2 {
                    let index = rng.below(count);
                    let bytes = 1 + rng.below(pending[index].data.len() - 1);
                    plans.push(with_tear(random_subset(count, rng), index, bytes));
                }
            }
            plans
        }
        Mode::BitFlip => {
            let written = log
                .iter()
                .filter_map(|op| match &op.kind {
                    OpKind::Write {
                        landed_lba, data, ..
                    } => Some((*landed_lba, data.len() / BLOCK)),
                    OpKind::Flush => None,
                })
                .flat_map(|(lba, blocks)| lba..lba + u64::try_from(blocks).unwrap())
                .collect::<Vec<_>>();
            let mut plans = (0..6)
                .map(|_| {
                    let mut plan = random_subset(count, rng);
                    let lba = if written.is_empty() || rng.below(4) == 0 {
                        u64::try_from(rng.below(2)).unwrap()
                    } else {
                        written[rng.below(written.len())]
                    };
                    plan.push(CrashStep::FlipBit {
                        lba,
                        bit: rng.below(BLOCK * 8),
                    });
                    plan
                })
                .collect::<Vec<_>>();
            for lba in 0..SUPERBLOCK_SLOTS {
                for &bit in FLIP_BITS {
                    let mut plan = random_subset(count, rng);
                    plan.push(CrashStep::FlipBit { lba, bit });
                    plans.push(plan);
                }
            }
            plans
        }
        Mode::Misdirected => {
            let mut plans = vec![Vec::new(), (0..count).map(CrashStep::Persist).collect()];
            plans.extend((0..4).map(|_| random_subset(count, rng)));
            plans
        }
    }
}

#[derive(Default)]
struct Report {
    workloads: u64,
    device_configs: u64,
    crash_points: u64,
    cases: u64,
    outcomes: BTreeMap<String, u64>,
    failures: Vec<String>,
    failure_count: u64,
}

const REPORTED_FAILURES: usize = 8;

impl Report {
    fn record(&mut self, result: Result<Outcome, String>, context: impl FnOnce() -> String) {
        self.cases += 1;
        match result {
            Ok(outcome) => *self.outcomes.entry(format!("{outcome:?}")).or_default() += 1,
            Err(failure) => {
                self.failure_count += 1;
                if self.failures.len() < REPORTED_FAILURES {
                    self.failures.push(format!("{}: {failure}", context()));
                }
            }
        }
    }
}

fn scale() -> u64 {
    std::env::var(SCALE_ENV)
        .ok()
        .map(|value| value.parse::<u64>().expect("scale is a positive integer"))
        .unwrap_or(1)
        .max(1)
}

fn crash_matrix(mode: Mode) -> Report {
    let started = Instant::now();
    let mut report = Report::default();
    let configs_per_seed = if mode.is_honest() || mode == Mode::BitFlip {
        1
    } else {
        FAULT_RUNS_PER_SEED
    };
    for seed in (0..BASE_SEEDS * scale()).map(|index| FIRST_SEED + index) {
        let mut rng = Rng(seed);
        let workload = generate_workload(&mut rng);
        let clean = run_workload(&workload, FaultConfig::default());
        let op_count = clean.device.log().len();
        report.workloads += 1;
        for _ in 0..configs_per_seed {
            let faults = device_faults(mode, &clean, &mut rng);
            report.device_configs += 1;
            for prefix in 0..=op_count {
                let run = run_workload(
                    &workload,
                    FaultConfig {
                        power_loss_at_op: Some(prefix),
                        ..faults.clone()
                    },
                );
                report.crash_points += 1;
                for plan in crash_plans(mode, &run.device, &mut rng) {
                    let image = run.device.crash_image(&plan);
                    report.record(check(mode, &run, &image), || {
                        format!(
                            "{mode:?} seed {seed:#x} faults {faults:?} power loss at op \
                             {prefix}/{op_count} plan {plan:?}"
                        )
                    });
                }
            }
        }
    }
    eprintln!(
        "{mode:?}: {} workloads, {} device configs, {} crash points, {} cases, {:?}, \
         {} failures, {:.2?}",
        report.workloads,
        report.device_configs,
        report.crash_points,
        report.cases,
        report.outcomes,
        report.failure_count,
        started.elapsed(),
    );
    report
}

fn assert_holds(report: &Report) {
    assert!(report.cases > 0, "matrix ran no cases");
    assert!(
        report.failure_count == 0,
        "{} of {} cases broke the invariant; first {}:\n{}",
        report.failure_count,
        report.cases,
        report.failures.len(),
        report.failures.join("\n")
    );
}

fn has_outcome(report: &Report, prefix: &str) -> bool {
    report.outcomes.keys().any(|key| key.starts_with(prefix))
}

#[test]
fn honest_crash_at_every_prefix_mounts_newest_intact_commit() {
    let report = crash_matrix(Mode::Honest);
    assert_holds(&report);
    assert!(report.outcomes.contains_key("InFlight") && report.outcomes.contains_key("LastAcked"));
    assert!(report.outcomes.contains_key("Blank"));
}

/// The first `format` included: every crash leaves the disk blank or mountable.
#[test]
fn sector_atomic_tear_at_every_prefix_never_leaves_a_refused_disk() {
    let report = crash_matrix(Mode::SectorAtomic);
    assert_holds(&report);
    assert!(report.outcomes.contains_key("InFlight") && report.outcomes.contains_key("LastAcked"));
    assert!(report.outcomes.contains_key("Blank"));
}

/// Outside the sector-atomic contract: a sub-sector tear during the first
/// `format` can leave a disk refused as `InterruptedFormat`, and nothing else
/// is ever refused.
#[test]
fn torn_write_at_every_prefix_never_mixes_generations() {
    let report = crash_matrix(Mode::Torn);
    assert_holds(&report);
    assert!(report.outcomes.contains_key("InFlight") && report.outcomes.contains_key("LastAcked"));
    let refused = report
        .outcomes
        .keys()
        .filter(|key| key.starts_with("Refused"))
        .collect::<Vec<_>>();
    assert_eq!(refused, ["RefusedBeforeFormatAck(InterruptedFormat)"]);
}

#[test]
fn dropped_flush_at_every_prefix_never_mixes_generations() {
    let report = crash_matrix(Mode::DroppedFlush);
    assert_holds(&report);
    assert!(report.outcomes.contains_key("RolledBack") || has_outcome(&report, "Refused("));
}

#[test]
fn bit_flip_at_every_prefix_never_mixes_generations() {
    let report = crash_matrix(Mode::BitFlip);
    assert_holds(&report);
    assert!(report
        .outcomes
        .contains_key("RefusedBeforeFormatAck(SuperblocksInvalid)"));
}

/// A superblock needs a valid CRC-32C and a table inside its own slot's arena,
/// the table must match the CRC-32C the superblock gives it (bound to the
/// generation and the table's location), and each payload the CRC-32C in its
/// entry (bound to the object's id, epoch and location), so a misdirected
/// write can roll the mount back or fail it, but not mix generations.
#[test]
fn misdirected_write_at_every_prefix_never_mixes_generations() {
    let report = crash_matrix(Mode::Misdirected);
    assert_holds(&report);
}

#[test]
fn generator_is_deterministic_per_seed() {
    let first = generate_workload(&mut Rng(FIRST_SEED));
    let second = generate_workload(&mut Rng(FIRST_SEED));
    let shape = |workload: &Workload| {
        workload
            .commits
            .iter()
            .flatten()
            .map(|mutation| match mutation {
                Mutation::Write { id, data, .. } => (*id, Some(data.clone())),
                Mutation::Delete { id } => (*id, None),
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(shape(&first), shape(&second));
    assert_ne!(
        shape(&first),
        shape(&generate_workload(&mut Rng(FIRST_SEED + 1)))
    );
}

/// The crash matrix only covers deletes if the workloads hold them, including a delete and a
/// create of the same name in one commit.
#[test]
fn workloads_delete_and_reuse_names() {
    let mut deletes = 0;
    let mut same_commit_name_reuse = 0;
    for seed in FIRST_SEED..FIRST_SEED + BASE_SEEDS {
        let workload = generate_workload(&mut Rng(seed));
        let mut names: BTreeMap<u64, String> = BTreeMap::new();
        for commit in &workload.commits {
            let mut deleted_here = Vec::new();
            for mutation in commit {
                match mutation {
                    Mutation::Delete { id } => {
                        deletes += 1;
                        deleted_here.push(names[id].clone());
                    }
                    Mutation::Write { id, name, .. } => {
                        if !names.contains_key(id) && deleted_here.contains(name) {
                            same_commit_name_reuse += 1;
                        }
                        names.insert(*id, name.clone());
                    }
                }
            }
        }
    }
    assert!(deletes >= BASE_SEEDS, "only {deletes} deletes");
    assert!(
        same_commit_name_reuse > 0,
        "no commit reuses a deleted name"
    );
}

#[test]
fn full_payload_blocks_share_one_byte_sum() {
    let mut rng = Rng(FIRST_SEED);
    let payloads = (0..16).map(|_| payload(&mut rng)).collect::<Vec<_>>();
    let sums = payloads
        .iter()
        .flat_map(|data| data.chunks_exact(BLOCK))
        .map(|block| block.iter().map(|byte| u32::from(*byte)).sum::<u32>())
        .collect::<Vec<_>>();
    assert!(sums.len() > 1);
    assert!(sums.windows(2).all(|pair| pair[0] == pair[1]));
}
