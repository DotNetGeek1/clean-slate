use super::*;
use clean_slate_graphics::input::{AxisValue120, KeyState, KeyUsage, PointerButton};
use clean_slate_graphics::limits::{RAW_INPUT_COALESCE_HIGH_WATER, RAW_INPUT_QUEUE_DEPTH};

type Queue = RawInputQueue<RAW_INPUT_QUEUE_DEPTH>;

fn kbd() -> InputDeviceId {
    InputDeviceId::new(0, 1).expect("keyboard id")
}

fn mouse() -> InputDeviceId {
    InputDeviceId::new(1, 1).expect("mouse id")
}

fn key() -> RawInputKind {
    RawInputKind::Key {
        usage: KeyUsage(0x04),
        state: KeyState::Pressed,
    }
}

fn motion(dx: i32, dy: i32) -> RawInputKind {
    RawInputKind::RelMotion { dx, dy }
}

fn button() -> RawInputKind {
    RawInputKind::Button {
        button: PointerButton::Left,
        state: KeyState::Pressed,
    }
}

fn wheel() -> RawInputKind {
    RawInputKind::Wheel {
        vertical: AxisValue120(120),
        horizontal: AxisValue120(0),
    }
}

fn fill_with_keys(queue: &mut Queue, count: usize) {
    for _ in 0..count {
        let outcome = queue.push(kbd(), key(), 10);
        assert!(!outcome.dropped && !outcome.coalesced);
    }
}

fn drain(queue: &mut Queue, count: usize) -> std::vec::Vec<RawInputRecord> {
    (0..count)
        .map(|_| queue.pop(10).expect("queued record"))
        .collect()
}

#[test]
fn seq_starts_at_one_and_is_contiguous_across_pops() {
    let mut queue = Queue::new();
    fill_with_keys(&mut queue, 3);
    assert_eq!(queue.pop(10).map(|r| r.seq), Some(1));
    assert_eq!(queue.pop(10).map(|r| r.seq), Some(2));
    fill_with_keys(&mut queue, 2);
    let seqs: std::vec::Vec<u64> = drain(&mut queue, 3).iter().map(|r| r.seq).collect();
    assert_eq!(seqs, [3, 4, 5]);
    assert_eq!(queue.pop(10), None);
}

#[test]
fn time_ns_is_clamped_non_decreasing() {
    let mut queue = Queue::new();
    queue.push(kbd(), key(), 100);
    queue.push(kbd(), key(), 50);
    queue.push(kbd(), key(), 150);
    let times: std::vec::Vec<u64> = drain(&mut queue, 3).iter().map(|r| r.time_ns).collect();
    assert_eq!(times, [100, 100, 150]);
    assert!(!queue.push(kbd(), key(), 20).dropped);
    assert_eq!(queue.pop(0).map(|r| r.time_ns), Some(150));
}

#[test]
fn full_queue_drops_and_overflow_follows_the_queued_records() {
    let mut queue = Queue::new();
    fill_with_keys(&mut queue, RAW_INPUT_QUEUE_DEPTH);
    let outcome = queue.push(mouse(), button(), 10);
    assert!(outcome.dropped);
    assert!(!outcome.queued_into_empty && !outcome.coalesced);
    assert_eq!(queue.len(), RAW_INPUT_QUEUE_DEPTH);
    assert_eq!(queue.pending_dropped(), 1);
    let records = drain(&mut queue, RAW_INPUT_QUEUE_DEPTH);
    assert_eq!(records.last().map(|r| r.seq), Some(128));
    let overflow = queue.pop(20).expect("overflow materialised on pop");
    assert_eq!(overflow.seq, 129);
    assert_eq!(overflow.device, mouse());
    assert_eq!(overflow.kind, RawInputKind::Overflow { dropped: 1 });
    assert_eq!(queue.pending_dropped(), 0);
    assert_eq!(queue.pop(20), None);
}

#[test]
fn overflow_carries_the_device_of_the_first_drop() {
    let mut queue = Queue::new();
    fill_with_keys(&mut queue, RAW_INPUT_QUEUE_DEPTH);
    assert!(queue.push(mouse(), motion(1, 1), 10).dropped);
    assert!(queue.push(kbd(), key(), 10).dropped);
    drain(&mut queue, RAW_INPUT_QUEUE_DEPTH);
    let overflow = queue.pop(10).expect("overflow");
    assert_eq!(overflow.device, mouse());
    assert_eq!(overflow.kind, RawInputKind::Overflow { dropped: 2 });
}

#[test]
fn overflow_is_queued_before_the_next_record_with_consecutive_seqs() {
    let mut queue = Queue::new();
    fill_with_keys(&mut queue, RAW_INPUT_QUEUE_DEPTH);
    assert!(queue.push(kbd(), key(), 10).dropped);
    drain(&mut queue, 2);
    let outcome = queue.push(mouse(), button(), 11);
    assert!(!outcome.dropped && !outcome.queued_into_empty);
    assert_eq!(queue.len(), RAW_INPUT_QUEUE_DEPTH);
    assert_eq!(queue.pending_dropped(), 0);
    let records = drain(&mut queue, RAW_INPUT_QUEUE_DEPTH);
    let overflow = records[RAW_INPUT_QUEUE_DEPTH - 2];
    let next = records[RAW_INPUT_QUEUE_DEPTH - 1];
    assert_eq!(overflow.kind, RawInputKind::Overflow { dropped: 1 });
    assert_eq!(overflow.device, kbd());
    assert_eq!(overflow.seq, 129);
    assert_eq!(next.kind, button());
    assert_eq!(next.seq, 130);
}

#[test]
fn overflow_takes_the_last_free_slot_and_the_new_record_is_dropped() {
    let mut queue = Queue::new();
    fill_with_keys(&mut queue, RAW_INPUT_QUEUE_DEPTH);
    assert!(queue.push(kbd(), key(), 10).dropped);
    drain(&mut queue, 1);
    let outcome = queue.push(mouse(), button(), 11);
    assert!(outcome.dropped);
    assert_eq!(queue.len(), RAW_INPUT_QUEUE_DEPTH);
    assert_eq!(queue.pending_dropped(), 1);
    let records = drain(&mut queue, RAW_INPUT_QUEUE_DEPTH);
    let overflow = records[RAW_INPUT_QUEUE_DEPTH - 1];
    assert_eq!(overflow.kind, RawInputKind::Overflow { dropped: 1 });
    assert_eq!(overflow.device, kbd());
    assert_eq!(overflow.seq, 129);
    let second = queue.pop(12).expect("second overflow");
    assert_eq!(second.kind, RawInputKind::Overflow { dropped: 1 });
    assert_eq!(second.device, mouse());
    assert_eq!(second.seq, 130);
}

#[test]
fn motion_below_high_water_is_never_coalesced() {
    let mut queue = Queue::new();
    fill_with_keys(&mut queue, RAW_INPUT_COALESCE_HIGH_WATER - 2);
    assert!(!queue.push(mouse(), motion(1, 2), 10).coalesced);
    assert_eq!(queue.len(), RAW_INPUT_COALESCE_HIGH_WATER - 1);
    let outcome = queue.push(mouse(), motion(3, 4), 10);
    assert!(!outcome.coalesced && !outcome.dropped);
    assert_eq!(queue.len(), RAW_INPUT_COALESCE_HIGH_WATER);
}

#[test]
fn motion_at_high_water_merges_into_same_device_tail_saturating() {
    let mut queue = Queue::new();
    fill_with_keys(&mut queue, RAW_INPUT_COALESCE_HIGH_WATER - 1);
    queue.push(mouse(), motion(i32::MAX - 1, -5), 10);
    assert_eq!(queue.len(), RAW_INPUT_COALESCE_HIGH_WATER);
    let outcome = queue.push(mouse(), motion(10, -7), 30);
    assert!(outcome.coalesced);
    assert!(!outcome.dropped && !outcome.queued_into_empty);
    assert_eq!(queue.len(), RAW_INPUT_COALESCE_HIGH_WATER);
    let outcome = queue.push(mouse(), motion(0, i32::MIN), 40);
    assert!(outcome.coalesced);
    let records = drain(&mut queue, RAW_INPUT_COALESCE_HIGH_WATER);
    let tail = records[RAW_INPUT_COALESCE_HIGH_WATER - 1];
    assert_eq!(tail.seq, RAW_INPUT_COALESCE_HIGH_WATER as u64);
    assert_eq!(tail.time_ns, 40);
    assert_eq!(
        tail.kind,
        RawInputKind::RelMotion {
            dx: i32::MAX,
            dy: i32::MIN
        }
    );
    queue.push(kbd(), key(), 50);
    assert_eq!(
        queue.pop(50).map(|r| r.seq),
        Some(RAW_INPUT_COALESCE_HIGH_WATER as u64 + 1)
    );
}

#[test]
fn motion_from_another_device_is_not_coalesced() {
    let mut queue = Queue::new();
    let other = InputDeviceId::new(1, 2).expect("regenerated mouse id");
    fill_with_keys(&mut queue, RAW_INPUT_COALESCE_HIGH_WATER);
    queue.push(mouse(), motion(1, 1), 10);
    let outcome = queue.push(other, motion(1, 1), 10);
    assert!(!outcome.coalesced && !outcome.dropped);
    assert_eq!(queue.len(), RAW_INPUT_COALESCE_HIGH_WATER + 2);
}

#[test]
fn motion_after_a_non_motion_tail_is_not_coalesced() {
    let mut queue = Queue::new();
    fill_with_keys(&mut queue, RAW_INPUT_COALESCE_HIGH_WATER);
    queue.push(mouse(), button(), 10);
    let outcome = queue.push(mouse(), motion(1, 1), 10);
    assert!(!outcome.coalesced && !outcome.dropped);
    assert_eq!(queue.len(), RAW_INPUT_COALESCE_HIGH_WATER + 2);
}

#[test]
fn keys_buttons_and_wheel_are_never_coalesced() {
    let mut queue = Queue::new();
    fill_with_keys(&mut queue, RAW_INPUT_COALESCE_HIGH_WATER);
    for (device, kind) in [
        (kbd(), key()),
        (kbd(), key()),
        (mouse(), button()),
        (mouse(), button()),
        (mouse(), wheel()),
        (mouse(), wheel()),
    ] {
        let outcome = queue.push(device, kind, 10);
        assert!(!outcome.coalesced && !outcome.dropped);
    }
    assert_eq!(queue.len(), RAW_INPUT_COALESCE_HIGH_WATER + 6);
}

#[test]
fn pending_loss_blocks_coalescing_into_the_pre_loss_tail() {
    let mut queue = Queue::new();
    fill_with_keys(&mut queue, RAW_INPUT_QUEUE_DEPTH - 1);
    queue.push(mouse(), motion(5, 5), 10);
    assert!(queue.push(mouse(), motion(1, 1), 10).coalesced);
    assert!(queue.push(kbd(), key(), 10).dropped);
    let outcome = queue.push(mouse(), motion(100, 100), 10);
    assert!(outcome.dropped && !outcome.coalesced);
    assert_eq!(queue.pending_dropped(), 2);
    drain(&mut queue, 1);
    let outcome = queue.push(mouse(), motion(7, 7), 10);
    assert!(outcome.dropped && !outcome.coalesced);
    assert_eq!(queue.pending_dropped(), 1);
    let records = drain(&mut queue, RAW_INPUT_QUEUE_DEPTH);
    assert_eq!(
        records[RAW_INPUT_QUEUE_DEPTH - 2].kind,
        RawInputKind::RelMotion { dx: 6, dy: 6 }
    );
    assert_eq!(
        records[RAW_INPUT_QUEUE_DEPTH - 1].kind,
        RawInputKind::Overflow { dropped: 2 }
    );
}

#[test]
fn queued_into_empty_marks_exactly_the_empty_to_non_empty_edge() {
    let mut queue = Queue::new();
    assert!(queue.push(kbd(), key(), 10).queued_into_empty);
    assert!(!queue.push(kbd(), key(), 10).queued_into_empty);
    drain(&mut queue, 2);
    assert!(queue.push(mouse(), motion(1, 1), 10).queued_into_empty);
    drain(&mut queue, 1);

    fill_with_keys(&mut queue, RAW_INPUT_COALESCE_HIGH_WATER);
    queue.push(mouse(), motion(1, 1), 10);
    assert!(!queue.push(mouse(), motion(1, 1), 10).queued_into_empty);
    drain(&mut queue, RAW_INPUT_COALESCE_HIGH_WATER + 1);

    fill_with_keys(&mut queue, RAW_INPUT_QUEUE_DEPTH);
    assert!(queue.push(kbd(), key(), 10).dropped);
    drain(&mut queue, RAW_INPUT_QUEUE_DEPTH);
    assert_eq!(queue.len(), 0);
    assert!(!queue.is_empty_including_pending());
    let outcome = queue.push(mouse(), button(), 10);
    assert!(
        !outcome.queued_into_empty && !outcome.dropped,
        "a pending Overflow already makes the queue non-empty for the consumer"
    );
    let records = drain(&mut queue, 2);
    assert_eq!(records[0].kind, RawInputKind::Overflow { dropped: 1 });
    assert_eq!(records[1].kind, button());
    assert!(queue.is_empty_including_pending());
}

#[test]
fn pending_dropped_saturates_at_u32_max() {
    let mut queue = Queue::new();
    fill_with_keys(&mut queue, RAW_INPUT_QUEUE_DEPTH);
    assert!(queue.push(mouse(), button(), 10).dropped);
    queue.pending_dropped = u32::MAX - 1;
    assert!(queue.push(kbd(), key(), 10).dropped);
    assert!(queue.push(kbd(), key(), 10).dropped);
    assert_eq!(queue.pending_dropped(), u32::MAX);
    drain(&mut queue, RAW_INPUT_QUEUE_DEPTH);
    let overflow = queue.pop(10).expect("overflow");
    assert_eq!(overflow.kind, RawInputKind::Overflow { dropped: u32::MAX });
    assert_eq!(overflow.device, mouse());
}

#[test]
fn every_popped_record_round_trips_through_the_wire_codec() {
    let mut queue = Queue::new();
    queue.push(kbd(), key(), 1);
    queue.push(mouse(), motion(-3, 9), 2);
    queue.push(mouse(), button(), 3);
    queue.push(mouse(), wheel(), 4);
    fill_with_keys(&mut queue, RAW_INPUT_QUEUE_DEPTH - 4);
    assert!(queue.push(kbd(), key(), 5).dropped);
    let mut records = drain(&mut queue, RAW_INPUT_QUEUE_DEPTH);
    records.push(queue.pop(6).expect("overflow"));
    for record in records {
        assert_eq!(RawInputRecord::decode(&record.encode()), Ok(record));
    }
}

#[test]
fn empty_pop_returns_none_and_consumes_no_seq() {
    let mut queue = Queue::new();
    assert_eq!(queue.pop(10), None);
    assert_eq!(queue.pop(10), None);
    assert!(queue.is_empty_including_pending());
    queue.push(kbd(), key(), 10);
    assert_eq!(queue.pop(10).map(|r| r.seq), Some(1));
}

#[test]
fn record_loss_on_an_empty_queue_is_a_wake_edge_and_pops_as_overflow() {
    let mut queue = Queue::new();
    assert!(queue.record_loss(kbd()));
    assert!(!queue.record_loss(mouse()));
    assert_eq!(queue.pending_dropped(), 2);
    let overflow = queue.pop(10).expect("overflow");
    assert_eq!(overflow.seq, 1);
    assert_eq!(overflow.device, kbd());
    assert_eq!(overflow.kind, RawInputKind::Overflow { dropped: 2 });
    queue.push(kbd(), key(), 10);
    assert!(!queue.record_loss(kbd()));
    queue.push(mouse(), button(), 10);
    let records = drain(&mut queue, 3);
    assert_eq!(records[0].kind, key());
    assert_eq!(records[1].kind, RawInputKind::Overflow { dropped: 1 });
    assert_eq!(records[2].kind, button());
    assert_eq!(
        records.iter().map(|r| r.seq).collect::<std::vec::Vec<_>>(),
        [2, 3, 4]
    );
}

#[test]
fn clear_into_loss_turns_unread_records_into_one_overflow() {
    let mut queue = Queue::new();
    queue.push(mouse(), motion(1, 1), 10);
    queue.push(kbd(), key(), 10);
    queue.pop(10);
    queue.push(kbd(), key(), 10);
    queue.clear_into_loss();
    assert_eq!(queue.len(), 0);
    assert_eq!(queue.pending_dropped(), 2);
    let overflow = queue.pop(10).expect("overflow");
    assert_eq!(overflow.kind, RawInputKind::Overflow { dropped: 2 });
    assert_eq!(overflow.device, kbd());
    assert_eq!(overflow.seq, 4);
    queue.clear_into_loss();
    assert!(queue.is_empty_including_pending());
    assert_eq!(queue.pop(10), None);
}
