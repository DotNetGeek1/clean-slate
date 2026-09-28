//! Destination: `graphics/src/objects/tests.rs`, included from `graphics/src/objects.rs` with
//! `#[cfg(test)] mod tests;`.
//!
//! Stage D contract: per-connection object table, compositor-wide budgets, stale / invalid /
//! wrong-kind lookups, and connection isolation (SPEC §3, plan §14 S1). There is no
//! cross-connection generation state: retirement exhausts only the retiring connection.

use crate::error::LookupError;
use crate::ids::{ClientBufferId, ObjectId, SurfaceId, WindowId, MAX_OBJECT_GENERATION};
use crate::limits::{
    MAX_BUFFERS_PER_CLIENT, MAX_OBJECTS_PER_CLIENT, MAX_REGISTERED_BUFFERS, MAX_SURFACES,
    MAX_SURFACES_PER_CLIENT, MAX_WINDOWS, MAX_WINDOWS_PER_CLIENT,
};
use crate::objects::{lookup_error_code, GlobalBudget, ObjectKind, ObjectTable};
use crate::protocol::ProtocolError;

type Table = ObjectTable<u32, u32, u32>;

const KINDS: [ObjectKind; 3] = [ObjectKind::Surface, ObjectKind::Window, ObjectKind::Buffer];

fn insert(
    table: &mut Table,
    budget: &mut GlobalBudget,
    kind: ObjectKind,
    v: u32,
) -> Result<ObjectId, ProtocolError> {
    match kind {
        ObjectKind::Surface => table.insert_surface(budget, v).map(|id| id.0),
        ObjectKind::Window => table.insert_window(budget, v).map(|id| id.0),
        ObjectKind::Buffer => table.insert_buffer(budget, v).map(|id| id.0),
    }
}

fn get(table: &Table, kind: ObjectKind, id: ObjectId) -> Result<u32, ProtocolError> {
    match kind {
        ObjectKind::Surface => table.surface(SurfaceId(id)).copied(),
        ObjectKind::Window => table.window(WindowId(id)).copied(),
        ObjectKind::Buffer => table.buffer(ClientBufferId(id)).copied(),
    }
}

fn get_mut(table: &mut Table, kind: ObjectKind, id: ObjectId) -> Result<&mut u32, ProtocolError> {
    match kind {
        ObjectKind::Surface => table.surface_mut(SurfaceId(id)),
        ObjectKind::Window => table.window_mut(WindowId(id)),
        ObjectKind::Buffer => table.buffer_mut(ClientBufferId(id)),
    }
}

fn remove(
    table: &mut Table,
    budget: &mut GlobalBudget,
    kind: ObjectKind,
    id: ObjectId,
) -> Result<u32, ProtocolError> {
    match kind {
        ObjectKind::Surface => table.remove_surface(budget, SurfaceId(id)),
        ObjectKind::Window => table.remove_window(budget, WindowId(id)),
        ObjectKind::Buffer => table.remove_buffer(budget, ClientBufferId(id)),
    }
}

/// Fills every per-kind cap of `table` and returns the ids with their kinds.
fn fill_caps(table: &mut Table, budget: &mut GlobalBudget) -> Vec<(ObjectKind, ObjectId)> {
    let mut ids = Vec::new();
    for kind in KINDS {
        for i in 0..kind.per_client_limit() {
            ids.push((kind, insert(table, budget, kind, i as u32).unwrap()));
        }
    }
    ids
}

/// Retires every slot of `table`: each slot is seeded at the last generation, filled, and the
/// object removed. Leaves the table with no live object and no insertable slot.
fn retire_every_slot(table: &mut Table, budget: &mut GlobalBudget) -> Vec<(ObjectKind, ObjectId)> {
    for slot in 0..MAX_OBJECTS_PER_CLIENT as u8 {
        table.seed_vacant_generation(slot, MAX_OBJECT_GENERATION);
    }
    let ids = fill_caps(table, budget);
    for (kind, id) in &ids {
        assert_eq!(id.generation(), MAX_OBJECT_GENERATION);
        remove(table, budget, *kind, *id).unwrap();
    }
    ids
}

#[test]
fn limits_are_the_frozen_values() {
    assert_eq!(MAX_SURFACES_PER_CLIENT, 8);
    assert_eq!(MAX_WINDOWS_PER_CLIENT, 4);
    assert_eq!(MAX_BUFFERS_PER_CLIENT, 8);
    assert_eq!(
        MAX_OBJECTS_PER_CLIENT,
        MAX_SURFACES_PER_CLIENT + MAX_WINDOWS_PER_CLIENT + MAX_BUFFERS_PER_CLIENT
    );
    assert_eq!(MAX_SURFACES, 32);
    assert_eq!(MAX_WINDOWS, 16);
    assert_eq!(MAX_REGISTERED_BUFFERS, 16);
    for kind in KINDS {
        assert!(kind.per_client_limit() <= kind.global_limit());
    }
    assert_eq!(
        ObjectKind::Surface.per_client_limit(),
        MAX_SURFACES_PER_CLIENT
    );
    assert_eq!(ObjectKind::Window.global_limit(), MAX_WINDOWS);
    assert_eq!(ObjectKind::Buffer.global_limit(), MAX_REGISTERED_BUFFERS);
}

#[test]
fn lookup_error_mapping_is_fixed() {
    assert_eq!(
        lookup_error_code(LookupError::Invalid),
        ProtocolError::InvalidObject
    );
    assert_eq!(
        lookup_error_code(LookupError::Stale),
        ProtocolError::StaleObject
    );
    assert_eq!(
        lookup_error_code(LookupError::Retired),
        ProtocolError::StaleObject
    );
}

#[test]
fn new_table_is_empty_and_default_matches_new() {
    let table = Table::new();
    let default = Table::default();
    for kind in KINDS {
        assert_eq!(table.count(kind), 0);
        assert_eq!(default.count(kind), 0);
    }
    assert_eq!(GlobalBudget::new(), GlobalBudget::default());
    for kind in KINDS {
        assert_eq!(GlobalBudget::new().used(kind), 0);
    }
}

#[test]
fn inserted_objects_resolve_and_are_mutable() {
    let mut budget = GlobalBudget::new();
    let mut table = Table::new();
    for (i, kind) in KINDS.into_iter().enumerate() {
        let id = insert(&mut table, &mut budget, kind, i as u32 * 10).unwrap();
        assert_eq!(id.generation(), 1, "fresh tables mint generation 1");
        assert_eq!(get(&table, kind, id), Ok(i as u32 * 10));
        assert_eq!(table.kind_of(id), Ok(kind));
        *get_mut(&mut table, kind, id).unwrap() += 1;
        assert_eq!(get(&table, kind, id), Ok(i as u32 * 10 + 1));
        assert_eq!(table.count(kind), 1);
        assert_eq!(budget.used(kind), 1);
    }
}

/// Architecture proof: every per-client table is bounded and exhaustion is `LimitExceeded`.
#[test]
fn per_client_caps_are_enforced_per_kind() {
    for kind in KINDS {
        let mut budget = GlobalBudget::new();
        let mut table = Table::new();
        for i in 0..kind.per_client_limit() {
            assert!(
                insert(&mut table, &mut budget, kind, i as u32).is_ok(),
                "{kind:?} #{i}"
            );
        }
        let before_budget = budget;
        assert_eq!(
            insert(&mut table, &mut budget, kind, 99),
            Err(ProtocolError::LimitExceeded),
            "{kind:?}"
        );
        assert_eq!(budget, before_budget, "failed insert consumed budget");
        assert_eq!(table.count(kind), kind.per_client_limit());
    }
}

#[test]
fn one_kind_at_cap_does_not_starve_the_others() {
    let mut budget = GlobalBudget::new();
    let mut table = Table::new();
    let ids = fill_caps(&mut table, &mut budget);
    assert_eq!(ids.len(), MAX_OBJECTS_PER_CLIENT);
    for kind in KINDS {
        assert_eq!(
            insert(&mut table, &mut budget, kind, 0),
            Err(ProtocolError::LimitExceeded)
        );
    }
    let mut raw: Vec<u32> = ids.iter().map(|(_, id)| id.encode()).collect();
    raw.sort_unstable();
    raw.dedup();
    assert_eq!(raw.len(), MAX_OBJECTS_PER_CLIENT, "ids must be unique");
    for (kind, id) in ids {
        assert_eq!(table.kind_of(id), Ok(kind));
    }
}

#[test]
fn removal_frees_capacity_and_budget() {
    let mut budget = GlobalBudget::new();
    let mut table = Table::new();
    let mut ids = Vec::new();
    for i in 0..MAX_WINDOWS_PER_CLIENT {
        ids.push(insert(&mut table, &mut budget, ObjectKind::Window, i as u32).unwrap());
    }
    assert_eq!(
        remove(&mut table, &mut budget, ObjectKind::Window, ids[1]),
        Ok(1)
    );
    assert_eq!(table.count(ObjectKind::Window), MAX_WINDOWS_PER_CLIENT - 1);
    assert_eq!(budget.used(ObjectKind::Window), MAX_WINDOWS_PER_CLIENT - 1);
    assert!(insert(&mut table, &mut budget, ObjectKind::Window, 7).is_ok());
}

/// Architecture proof: compositor-wide budgets bound every kind across connections.
#[test]
fn global_budgets_are_shared_across_connections() {
    for kind in KINDS {
        let mut budget = GlobalBudget::new();
        let mut tables: Vec<Table> = Vec::new();
        let mut inserted = 0;
        while inserted < kind.global_limit() {
            let mut table = Table::new();
            for _ in 0..kind.per_client_limit().min(kind.global_limit() - inserted) {
                insert(&mut table, &mut budget, kind, 0).unwrap();
                inserted += 1;
            }
            tables.push(table);
        }
        assert_eq!(budget.used(kind), kind.global_limit());
        let mut fresh = Table::new();
        assert_eq!(
            insert(&mut fresh, &mut budget, kind, 0),
            Err(ProtocolError::LimitExceeded),
            "{kind:?}"
        );
        assert_eq!(fresh.count(kind), 0);
        assert_eq!(budget.used(kind), kind.global_limit());
        for other in KINDS.into_iter().filter(|k| *k != kind) {
            assert!(insert(&mut fresh, &mut budget, other, 0).is_ok());
        }
        tables.pop().unwrap().close(&mut budget);
        assert!(
            insert(&mut fresh, &mut budget, kind, 0).is_ok(),
            "{kind:?} after close"
        );
    }
}

#[test]
fn close_returns_every_live_object_budget() {
    let mut budget = GlobalBudget::new();
    let mut a = Table::new();
    let mut b = Table::new();
    for kind in KINDS {
        insert(&mut a, &mut budget, kind, 0).unwrap();
        insert(&mut a, &mut budget, kind, 0).unwrap();
        insert(&mut b, &mut budget, kind, 0).unwrap();
    }
    a.close(&mut budget);
    for kind in KINDS {
        assert_eq!(budget.used(kind), 1);
    }
    b.close(&mut budget);
    assert_eq!(budget, GlobalBudget::new());
}

/// Architecture proof: stale id after destroy.
#[test]
fn destroyed_ids_are_stale_for_every_operation_and_reuse_mints_a_new_generation() {
    for kind in KINDS {
        let mut budget = GlobalBudget::new();
        let mut table = Table::new();
        let id = insert(&mut table, &mut budget, kind, 5).unwrap();
        assert_eq!(remove(&mut table, &mut budget, kind, id), Ok(5));
        assert_eq!(get(&table, kind, id), Err(ProtocolError::StaleObject));
        assert_eq!(
            get_mut(&mut table, kind, id).err(),
            Some(ProtocolError::StaleObject)
        );
        assert_eq!(table.kind_of(id), Err(ProtocolError::StaleObject));
        let budget_before = budget;
        assert_eq!(
            remove(&mut table, &mut budget, kind, id),
            Err(ProtocolError::StaleObject)
        );
        assert_eq!(budget, budget_before);

        let reused = insert(&mut table, &mut budget, kind, 6).unwrap();
        assert_eq!(reused.slot(), id.slot());
        assert!(reused.generation() > id.generation());
        assert_eq!(get(&table, kind, id), Err(ProtocolError::StaleObject));
        assert_eq!(get(&table, kind, reused), Ok(6));
    }
}

#[test]
fn never_issued_and_out_of_range_ids_are_invalid() {
    let mut budget = GlobalBudget::new();
    let mut table = Table::new();
    let _ = insert(&mut table, &mut budget, ObjectKind::Surface, 0).unwrap();
    let never_issued = ObjectId::new(5, 1).unwrap();
    let out_of_range = ObjectId::new(MAX_OBJECTS_PER_CLIENT as u8, 1).unwrap();
    let max_slot = ObjectId::new(255, 1).unwrap();
    for id in [never_issued, out_of_range, max_slot] {
        for kind in KINDS {
            assert_eq!(
                get(&table, kind, id),
                Err(ProtocolError::InvalidObject),
                "{id:?}"
            );
            assert_eq!(
                remove(&mut table, &mut budget, kind, id),
                Err(ProtocolError::InvalidObject)
            );
        }
        assert_eq!(table.kind_of(id), Err(ProtocolError::InvalidObject));
    }
}

#[test]
fn live_slot_with_other_generation_is_stale() {
    let mut budget = GlobalBudget::new();
    let mut table = Table::new();
    let id = insert(&mut table, &mut budget, ObjectKind::Buffer, 1).unwrap();
    let forged = ObjectId::new(id.slot(), id.generation() + 1).unwrap();
    assert_eq!(
        get(&table, ObjectKind::Buffer, forged),
        Err(ProtocolError::StaleObject)
    );
}

/// Architecture proof: wrong object kind, for every ordered pair, and a wrong-kind remove
/// removes nothing.
#[test]
fn wrong_kind_lookups_and_removes_fail_without_side_effects() {
    for actual in KINDS {
        for asked in KINDS.into_iter().filter(|k| *k != actual) {
            let mut budget = GlobalBudget::new();
            let mut table = Table::new();
            let id = insert(&mut table, &mut budget, actual, 42).unwrap();
            assert_eq!(
                get(&table, asked, id),
                Err(ProtocolError::WrongObjectKind),
                "{actual:?} as {asked:?}"
            );
            assert_eq!(
                get_mut(&mut table, asked, id).err(),
                Some(ProtocolError::WrongObjectKind)
            );
            let before = budget;
            assert_eq!(
                remove(&mut table, &mut budget, asked, id),
                Err(ProtocolError::WrongObjectKind)
            );
            assert_eq!(budget, before);
            assert_eq!(table.count(actual), 1);
            assert_eq!(get(&table, actual, id), Ok(42));
        }
    }
}

/// S1: a retired slot is stale on lookup (via `lookup_error_code`) and is never reissued.
#[test]
fn retired_slots_look_up_as_stale_and_are_never_reissued() {
    let mut budget = GlobalBudget::new();
    let mut table = Table::new();
    table.seed_vacant_generation(0, MAX_OBJECT_GENERATION);
    let last = insert(&mut table, &mut budget, ObjectKind::Surface, 1).unwrap();
    assert_eq!(last.slot(), 0);
    assert_eq!(last.generation(), MAX_OBJECT_GENERATION);
    remove(&mut table, &mut budget, ObjectKind::Surface, last).unwrap();
    assert_eq!(
        get(&table, ObjectKind::Surface, last),
        Err(ProtocolError::StaleObject)
    );
    assert_eq!(
        table.kind_of(last),
        Err(lookup_error_code(LookupError::Retired))
    );
    assert_eq!(
        remove(&mut table, &mut budget, ObjectKind::Surface, last),
        Err(ProtocolError::StaleObject)
    );
    for kind in KINDS {
        let next = insert(&mut table, &mut budget, kind, 2).unwrap();
        assert_ne!(next.slot(), 0, "retired slot must not be reissued");
    }
}

/// S1: a connection whose slots are all retired or live gets `LimitExceeded` on insert even
/// below its per-kind caps, and the failure consumes no budget.
#[test]
fn table_with_every_slot_retired_or_full_refuses_inserts() {
    let mut budget = GlobalBudget::new();
    let mut table = Table::new();
    for slot in 0..MAX_OBJECTS_PER_CLIENT as u8 {
        table.seed_vacant_generation(slot, MAX_OBJECT_GENERATION);
    }
    let mut live_windows = Vec::new();
    for kind in KINDS {
        for i in 0..kind.per_client_limit() {
            let id = insert(&mut table, &mut budget, kind, i as u32).unwrap();
            if kind == ObjectKind::Window {
                live_windows.push(id);
            } else {
                remove(&mut table, &mut budget, kind, id).unwrap();
            }
        }
    }
    assert_eq!(table.count(ObjectKind::Surface), 0);
    assert_eq!(table.count(ObjectKind::Buffer), 0);
    let before = budget;
    for kind in KINDS {
        assert_eq!(
            insert(&mut table, &mut budget, kind, 0),
            Err(ProtocolError::LimitExceeded),
            "{kind:?}"
        );
    }
    assert_eq!(budget, before, "refused inserts consumed budget");
    for id in live_windows {
        assert!(
            get(&table, ObjectKind::Window, id).is_ok(),
            "live objects keep working"
        );
    }
}

/// S1 (no cross-connection exhaustion): a connection that retired every slot and closed
/// returns all budget, and a fresh table for the next connection gets its full caps at
/// generation 1.
#[test]
fn retiring_connection_leaves_no_trace_for_the_next_connection() {
    let mut budget = GlobalBudget::new();
    let mut churner = Table::new();
    retire_every_slot(&mut churner, &mut budget);
    for kind in KINDS {
        assert_eq!(
            insert(&mut churner, &mut budget, kind, 0),
            Err(ProtocolError::LimitExceeded)
        );
    }
    churner.close(&mut budget);
    assert_eq!(budget, GlobalBudget::new(), "close must return all budget");

    let mut next = Table::new();
    let ids = fill_caps(&mut next, &mut budget);
    assert_eq!(ids.len(), MAX_OBJECTS_PER_CLIENT);
    for (kind, id) in ids {
        assert_eq!(
            id.generation(),
            1,
            "no generation carries over between connections"
        );
        assert_eq!(next.kind_of(id), Ok(kind));
    }
}

/// S1: retirement in one live connection never affects a concurrent connection.
#[test]
fn retirement_only_exhausts_the_retiring_connection() {
    let mut budget = GlobalBudget::new();
    let mut churner = Table::new();
    let mut neighbour = Table::new();
    retire_every_slot(&mut churner, &mut budget);
    let ids = fill_caps(&mut neighbour, &mut budget);
    assert_eq!(ids.len(), MAX_OBJECTS_PER_CLIENT);
    for (kind, id) in &ids {
        remove(&mut neighbour, &mut budget, *kind, *id).unwrap();
    }
    assert!(fill_caps(&mut neighbour, &mut budget).len() == MAX_OBJECTS_PER_CLIENT);
    assert_eq!(
        insert(&mut churner, &mut budget, ObjectKind::Surface, 0),
        Err(ProtocolError::LimitExceeded)
    );
}

/// S1: ids are meaningful only in their own table. The same raw id names each table's own
/// object, or nothing.
#[test]
fn the_same_raw_id_names_each_tables_own_object_or_nothing() {
    let mut budget = GlobalBudget::new();
    let mut a = Table::new();
    let mut b = Table::new();
    let in_a = insert(&mut a, &mut budget, ObjectKind::Surface, 100).unwrap();
    let in_b = insert(&mut b, &mut budget, ObjectKind::Surface, 200).unwrap();
    assert_eq!(in_a, in_b, "fresh tables mint identical raw ids");
    assert_eq!(get(&a, ObjectKind::Surface, in_a), Ok(100));
    assert_eq!(get(&b, ObjectKind::Surface, in_a), Ok(200));

    let only_b = insert(&mut b, &mut budget, ObjectKind::Window, 7).unwrap();
    assert_eq!(
        get(&a, ObjectKind::Window, only_b),
        Err(ProtocolError::InvalidObject)
    );
    assert_eq!(a.kind_of(only_b), Err(ProtocolError::InvalidObject));

    remove(&mut a, &mut budget, ObjectKind::Surface, in_a).unwrap();
    assert_eq!(
        get(&a, ObjectKind::Surface, in_a),
        Err(ProtocolError::StaleObject)
    );
    assert_eq!(
        get(&b, ObjectKind::Surface, in_b),
        Ok(200),
        "b is untouched by a's destroy"
    );
}

/// Stale id after "reconnect" is not a table property any more: a new connection's table
/// only ever resolves its own objects, so an id from a previous lifetime is invalid until the
/// new table issues that slot, and then names the new connection's own object.
#[test]
fn ids_from_a_closed_connection_mean_nothing_special_in_the_next_table() {
    let mut budget = GlobalBudget::new();
    let mut old = Table::new();
    let old_id = insert(&mut old, &mut budget, ObjectKind::Surface, 1).unwrap();
    old.close(&mut budget);
    let mut new = Table::new();
    assert_eq!(
        get(&new, ObjectKind::Surface, old_id),
        Err(ProtocolError::InvalidObject)
    );
    let new_id = insert(&mut new, &mut budget, ObjectKind::Surface, 2).unwrap();
    assert_eq!(new_id, old_id);
    assert_eq!(get(&new, ObjectKind::Surface, old_id), Ok(2));
}
