//! Destination: `graphics/src/ids/tests_capacity.rs`, included from `graphics/src/ids.rs`
//! with `#[cfg(test)] mod tests_capacity;` (next to the existing inline `mod tests`).
//!
//! Stage D contract (plan §14 S1): `GenSlotTable` capacity and retirement are strictly
//! per-table. There is no generation state shared between tables, so retiring slots in one
//! table can never exhaust another. The only addition to `ids.rs` is `MAX_OBJECT_GENERATION`.

use crate::error::{LimitError, LookupError};
use crate::ids::{GenSlotTable, ObjectId, MAX_OBJECT_GENERATION};

/// Retires every slot of a 4-slot table.
fn fully_retired() -> GenSlotTable<u8, 4> {
    let mut table = GenSlotTable::<u8, 4>::new();
    for slot in 0..4u8 {
        table.seed_vacant_generation(slot, MAX_OBJECT_GENERATION);
    }
    for _ in 0..4 {
        let id = table.insert(0).unwrap();
        table.remove(id).unwrap();
    }
    for slot in 0..4u8 {
        assert!(table.is_retired(slot));
    }
    table
}

#[test]
fn max_object_generation_is_24_bits() {
    assert_eq!(MAX_OBJECT_GENERATION, 0x00FF_FFFF);
    assert!(ObjectId::new(0, MAX_OBJECT_GENERATION).is_ok());
    assert_eq!(
        ObjectId::new(0, MAX_OBJECT_GENERATION + 1),
        Err(LookupError::Invalid)
    );
}

#[test]
fn new_table_mints_generation_one_in_every_slot() {
    let mut table = GenSlotTable::<u8, 3>::new();
    for slot in 0..3u8 {
        let id = table.insert(slot).unwrap();
        assert_eq!((id.slot(), id.generation()), (slot, 1));
    }
    assert_eq!(table.insert(9), Err(LimitError::Exhausted));
}

#[test]
fn reused_slot_generation_increments_and_old_id_is_stale() {
    let mut table = GenSlotTable::<u8, 1>::new();
    let a = table.insert(1).unwrap();
    table.remove(a).unwrap();
    let b = table.insert(2).unwrap();
    assert_eq!((b.slot(), b.generation()), (a.slot(), a.generation() + 1));
    assert_eq!(table.get(a), Err(LookupError::Stale));
    assert_eq!(table.get(b), Ok(&2));
}

#[test]
fn retired_slot_is_retired_for_every_operation_and_skipped_by_insert() {
    let mut table = GenSlotTable::<u8, 2>::new();
    table.seed_vacant_generation(0, MAX_OBJECT_GENERATION);
    let last = table.insert(1).unwrap();
    assert_eq!(last.generation(), MAX_OBJECT_GENERATION);
    table.remove(last).unwrap();
    assert!(table.is_retired(0));
    assert_eq!(table.get(last), Err(LookupError::Retired));
    assert_eq!(table.get_mut(last).err(), Some(LookupError::Retired));
    assert_eq!(table.remove(last), Err(LookupError::Retired));
    let next = table.insert(2).unwrap();
    assert_eq!(next.slot(), 1);
    assert_eq!(table.insert(3), Err(LimitError::Exhausted));
}

#[test]
fn fully_retired_table_is_exhausted() {
    let mut table = fully_retired();
    assert_eq!(table.insert(0), Err(LimitError::Exhausted));
}

#[test]
fn mix_of_retired_and_live_slots_is_exhausted_and_live_values_still_resolve() {
    let mut table = GenSlotTable::<u8, 3>::new();
    table.seed_vacant_generation(0, MAX_OBJECT_GENERATION);
    let doomed = table.insert(0).unwrap();
    table.remove(doomed).unwrap();
    let a = table.insert(1).unwrap();
    let b = table.insert(2).unwrap();
    assert_eq!(table.insert(3), Err(LimitError::Exhausted));
    assert_eq!((table.get(a), table.get(b)), (Ok(&1), Ok(&2)));
}

/// No cross-table exhaustion: a fresh table next to a fully retired one has full capacity
/// at generation 1.
#[test]
fn retirement_in_one_table_never_reaches_another() {
    let mut retired = fully_retired();
    let mut fresh = GenSlotTable::<u8, 4>::new();
    for slot in 0..4u8 {
        let id = fresh.insert(slot).unwrap();
        assert_eq!((id.slot(), id.generation()), (slot, 1));
    }
    assert_eq!(retired.insert(0), Err(LimitError::Exhausted));
}

#[test]
fn the_same_raw_id_resolves_independently_per_table() {
    let mut a = GenSlotTable::<u8, 2>::new();
    let mut b = GenSlotTable::<u8, 2>::new();
    let ia = a.insert(10).unwrap();
    let ib = b.insert(20).unwrap();
    assert_eq!(ia, ib);
    assert_eq!((a.get(ia), b.get(ia)), (Ok(&10), Ok(&20)));
    let only_b = b.insert(21).unwrap();
    assert_eq!(a.get(only_b), Err(LookupError::Invalid));
    a.remove(ia).unwrap();
    assert_eq!(a.get(ia), Err(LookupError::Stale));
    assert_eq!(b.get(ia), Ok(&20));
}
