//! Crash matrix for the `clean-slate-store` commit protocol on a faulty device.
//!
//! Seeded random workloads (create and update objects, commit) run on a
//! [`FaultDevice`]. Each workload is crashed at every operation prefix, the
//! crash is resolved by fault-mode-specific crash plans, and the durable image
//! is mounted. Every case must satisfy the store's promise for devices that may
//! lie: the mount yields exactly one generation that some `commit` wrote (its
//! generation number and every object byte), or a clean `Corrupt` /
//! `Incompatible` error. Never a mix, and never data no commit wrote.
//!
//! Stronger checks where the device allows them:
//! - unless writes are misdirected, every superblock on disk sits in the slot
//!   it was written for, so the mount must be exactly the newest generation
//!   whose superblock and payload bytes are intact, or an error when none is;
//! - on an honest device (flushes kept, writes in place; pending writes may
//!   persist in any subset and order, and tear), the newest intact superblock
//!   must mount, and never one older than the last acknowledged commit.
//!
//! The run is bounded for `cargo test`; set `CLEAN_SLATE_STORE_FAULT_SCALE=N`
//! to run N times as many seeded workloads.

mod support;

use std::collections::BTreeMap;
use std::time::Instant;

use clean_slate_block::fake::FakeBlockDevice;
use clean_slate_block::{BlockDeviceId, BlockGeometry};
use clean_slate_store::{
    IncompatibleFormatError, ObjectStore, StoreError, MAX_OBJECTS, SUPERBLOCK_SLOTS,
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
const _: () = assert!(MAX_LIVE_OBJECTS <= MAX_OBJECTS);
const _: () = assert!((MAX_LIVE_OBJECTS * MAX_OBJECT_BLOCKS) as u64 <= ARENA_BLOCKS);

/// Superblock layout used by the intactness oracle: the generation, then a
/// table of 64-byte entries after the 48-byte header, each holding flags,
/// payload length, start LBA and object id.
const GENERATION_OFFSET: usize = 12;
const ENTRY_TABLE_OFFSET: usize = 48;
const ENTRY_BYTES: usize = 64;
const ENTRY_PRESENT_FLAG: u8 = 0x01;

/// Fixed tear offsets: the checksum, generation, object-count and first and
/// second table-entry fields of a superblock, and the block boundary of a
/// two-block payload write.
const TEAR_OFFSETS: &[usize] = &[
    1,
    4,
    8,
    12,
    16,
    20,
    36,
    48,
    112,
    176,
    BLOCK - 1,
    BLOCK,
    BLOCK + 1,
    BLOCK + 48,
];
const RANDOM_TEAR_OFFSETS: usize = 3;
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

struct Mutation {
    id: u64,
    name: String,
    data: Vec<u8>,
}

/// Each entry is the writes staged before one commit.
struct Workload {
    commits: Vec<Vec<Mutation>>,
}

fn generate_workload(rng: &mut Rng) -> Workload {
    let mut live = Vec::new();
    let mut next_index = 0u64;
    let commit_count = 3 + rng.below(4);
    let commits = (0..commit_count)
        .map(|_| {
            let mutation_count = 1 + rng.below(3);
            (0..mutation_count)
                .map(|_| {
                    let create = live.is_empty() || (live.len() < MAX_LIVE_OBJECTS && rng.coin());
                    let index = if create {
                        next_index += 1;
                        live.push(next_index);
                        next_index
                    } else {
                        live[rng.below(live.len())]
                    };
                    Mutation {
                        id: 0x100 + index,
                        name: format!("obj{index}"),
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
            store
                .write_object(mutation.id, &mutation.name, &mutation.data)
                .expect("workload stays within store limits");
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
}

fn superblock_writes(device: &FaultDevice) -> Vec<SuperblockWrite> {
    device
        .log()
        .into_iter()
        .filter_map(|op| match op.kind {
            OpKind::Write { lba, data, .. } if lba < SUPERBLOCK_SLOTS => Some(SuperblockWrite {
                generation: read_u64(&data, GENERATION_OFFSET),
                lba,
                bytes: data,
            }),
            _ => None,
        })
        .collect()
}

fn stored_block(image: &[u8], lba: u64) -> &[u8] {
    let start = usize::try_from(lba).unwrap() * BLOCK;
    &image[start..start + BLOCK]
}

/// Every payload byte the superblock references is on disk as its commit wrote it.
fn payload_intact(image: &[u8], superblock: &SuperblockWrite, snapshot: &Snapshot) -> bool {
    (0..MAX_OBJECTS).all(|index| {
        let entry = &superblock.bytes[ENTRY_TABLE_OFFSET + index * ENTRY_BYTES..][..ENTRY_BYTES];
        if entry[0] & ENTRY_PRESENT_FLAG == 0 {
            return true;
        }
        let len = usize::try_from(read_u32(entry, 4)).unwrap();
        let start = usize::try_from(read_u64(entry, 8)).unwrap() * BLOCK;
        let (_, data) = &snapshot[&read_u64(entry, 24)];
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
        matches!(self, Self::Honest | Self::Torn)
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
    Corrupt,
    /// `Incompatible`, other than `BadMagic` after an acknowledged format.
    Incompatible,
    /// `Incompatible(BadMagic)` although `format` was acknowledged. The
    /// storage service formats a `BadMagic` device, so this outcome erases
    /// whatever survived.
    BadMagicAfterFormat,
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

    Ok(match (generation, run.last_acked) {
        (None, acked) => match &mounted {
            Err(StoreError::Incompatible(IncompatibleFormatError::BadMagic)) if acked.is_some() => {
                Outcome::BadMagicAfterFormat
            }
            Err(StoreError::Incompatible(_)) => Outcome::Incompatible,
            _ => Outcome::Corrupt,
        },
        (Some(generation), Some(acked)) if generation < acked => Outcome::RolledBack,
        (Some(generation), Some(acked)) if generation == acked => Outcome::LastAcked,
        (Some(_), _) => Outcome::InFlight,
    })
}

/// Device faults for one run: none, a random non-empty set of dropped
/// flushes, or one misdirected write.
fn device_faults(mode: Mode, clean: &Run, rng: &mut Rng) -> FaultConfig {
    let log = clean.device.log();
    match mode {
        Mode::Honest | Mode::Torn | Mode::BitFlip => FaultConfig::default(),
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
            (0..6)
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
                .collect()
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

#[test]
fn honest_crash_at_every_prefix_mounts_newest_intact_commit() {
    let report = crash_matrix(Mode::Honest);
    assert_holds(&report);
    assert!(report.outcomes.contains_key("InFlight") && report.outcomes.contains_key("LastAcked"));
}

#[test]
fn torn_write_at_every_prefix_never_mixes_generations() {
    let report = crash_matrix(Mode::Torn);
    assert_holds(&report);
    assert!(report.outcomes.contains_key("InFlight") && report.outcomes.contains_key("LastAcked"));
}

#[test]
fn dropped_flush_at_every_prefix_never_mixes_generations() {
    let report = crash_matrix(Mode::DroppedFlush);
    assert_holds(&report);
    assert!(report.outcomes.contains_key("RolledBack") || report.outcomes.contains_key("Corrupt"));
}

#[test]
fn bit_flip_at_every_prefix_never_mixes_generations() {
    let report = crash_matrix(Mode::BitFlip);
    assert_holds(&report);
}

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
            .map(|mutation| (mutation.id, mutation.data.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(shape(&first), shape(&second));
    assert_ne!(
        shape(&first),
        shape(&generate_workload(&mut Rng(FIRST_SEED + 1)))
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
