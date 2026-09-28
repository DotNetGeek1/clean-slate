//! Destination: `graphics/src/surface/tests.rs`, included from `graphics/src/surface.rs` with
//! `#[cfg(test)] mod tests;`.
//!
//! Stage D contract: pending/committed surface state, atomic commit with rollback, damage and
//! region normalisation, busy-buffer handoff and at-most-once `FrameDone` (SPEC §4).

use core::cell::Cell;
use core::mem::size_of;

use crate::geometry::{BufferRect, Point, Rect, Scale120, Size};
use crate::ids::{ClientBufferId, ObjectId, Serial, SurfaceId};
use crate::limits::{
    MAX_BUFFERS_PER_CLIENT, MAX_DAMAGE_RECTS_PER_COMMIT, MAX_IN_FLIGHT_BUFFERS_PER_SURFACE,
    MAX_REGION_RECTS, MAX_SURFACE_EXTENT,
};
use crate::pixel::{BufferLayout, ColorSpace, PixelFormat};
use crate::protocol::ProtocolError;
use crate::role::{Layer, ParentRef, RoleGrant, SurfaceRole, GFX_CONNECT_BIT, GFX_SHELL_BIT};
use crate::surface::{
    AssignedRole, BufferTracker, CommitOutcome, CommitRequest, CommittedBuffer,
    CommittedInputRegion, CommittedState, ConnectionBufferTracker, DamageSet, FrameDone,
    FrameState, InputRegion, Latch, OpaqueRegion, PendingBuffer, PendingState, RegionSet,
    SurfaceState, EXTENT_RECT,
};
use crate::window::{ConfigureState, SerialMinter, WindowConfig, WindowStates};

type Tracker = BufferTracker<8>;

fn sid(slot: u8) -> SurfaceId {
    SurfaceId(ObjectId::new(slot, 1).unwrap())
}

fn bid(slot: u8) -> ClientBufferId {
    ClientBufferId(ObjectId::new(slot, 1).unwrap())
}

fn layout(width: u32, height: u32) -> BufferLayout {
    BufferLayout::packed(width, height, PixelFormat::Xrgb8888).unwrap()
}

fn rect(x: i32, y: i32, width: u32, height: u32) -> Rect {
    Rect {
        x,
        y,
        width,
        height,
    }
}

fn brect(x: u16, y: u16, width: u16, height: u16) -> BufferRect {
    BufferRect {
        x,
        y,
        width,
        height,
    }
}

fn size(width: u32, height: u32) -> Size {
    Size { width, height }
}

fn plain() -> CommitRequest {
    CommitRequest {
        request_frame: false,
        color_space: ColorSpace::Srgb,
        ack: None,
    }
}

fn with_frame() -> CommitRequest {
    CommitRequest {
        request_frame: true,
        ..plain()
    }
}

fn with_ack(serial: Serial) -> CommitRequest {
    CommitRequest {
        ack: Some(serial),
        ..plain()
    }
}

fn no_resolve(_: ClientBufferId) -> Result<BufferLayout, ProtocolError> {
    panic!("resolver must not be called")
}

fn region(rects: &[Rect]) -> RegionSet {
    let mut set = RegionSet::new();
    for r in rects {
        set.insert(*r).unwrap();
    }
    set
}

fn damage_set(rects: &[Rect]) -> DamageSet {
    let mut set = DamageSet::new();
    for r in rects {
        set.insert(*r).unwrap();
    }
    set
}

/// `n` disjoint 1×1 rects on the diagonal starting at `start`.
fn diagonal(start: i32, n: usize) -> Vec<Rect> {
    (0..n as i32)
        .map(|i| rect(start + 2 * i, start + 2 * i, 1, 1))
        .collect()
}

/// Attach `buffer` (sized `w×h`) and commit it without a window.
fn map(
    s: &mut SurfaceState,
    id: SurfaceId,
    t: &mut Tracker,
    buffer: ClientBufferId,
    w: u32,
    h: u32,
) -> CommitOutcome {
    s.attach(Some(buffer), Scale120::ONE, t).unwrap();
    s.commit(id, plain(), t, None, |_| Ok(layout(w, h)))
        .unwrap()
}

fn commit_plain(s: &mut SurfaceState, id: SurfaceId, t: &mut Tracker) -> CommitOutcome {
    s.commit(id, plain(), t, None, no_resolve).unwrap()
}

fn window_with_serial() -> (ConfigureState, Serial) {
    let mut minter = SerialMinter::new();
    let mut window = ConfigureState::new();
    let serial = window
        .send(
            &mut minter,
            WindowConfig::new(size(64, 32), WindowStates::EMPTY, size(0, 0)),
        )
        .unwrap();
    (window, serial)
}

fn connect() -> RoleGrant {
    RoleGrant::from_rights_bits(GFX_CONNECT_BIT)
}

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

// --- defaults and limits ------------------------------------------------------------------

#[test]
fn frozen_limits_and_set_capacities() {
    assert_eq!(MAX_DAMAGE_RECTS_PER_COMMIT, 16);
    assert_eq!(MAX_REGION_RECTS, 8);
    assert_eq!(MAX_IN_FLIGHT_BUFFERS_PER_SURFACE, 2);
    assert_eq!(
        EXTENT_RECT,
        rect(0, 0, MAX_SURFACE_EXTENT, MAX_SURFACE_EXTENT)
    );
    let _: ConnectionBufferTracker = BufferTracker::<MAX_BUFFERS_PER_CLIENT>::new();
}

#[test]
fn new_surface_has_documented_defaults() {
    let s = SurfaceState::new();
    assert_eq!(s, SurfaceState::default());
    assert_eq!(s.role(), None);
    assert_eq!(s.frame(), FrameState::Idle);
    assert!(s.unlatched_damage().is_empty());

    let p = s.pending();
    assert_eq!(*p, PendingState::new());
    assert_eq!(*p, PendingState::default());
    assert_eq!(p.buffer(), PendingBuffer::Unchanged);
    assert_eq!(p.scale(), Scale120::ONE);
    assert!(p.damage().is_empty());
    assert_eq!(*p.opaque(), OpaqueRegion::Rects(RegionSet::new()));
    assert_eq!(*p.input(), InputRegion::WholeSurface);

    let c = s.committed();
    assert_eq!(*c, CommittedState::new());
    assert_eq!(*c, CommittedState::default());
    assert_eq!(c.buffer(), None);
    assert!(!c.is_mapped());
    assert_eq!(c.size(), size(0, 0));
    assert_eq!(c.scale(), Scale120::ONE);
    assert_eq!(c.color_space(), ColorSpace::Srgb);
    assert!(c.opaque().is_empty());
    assert_eq!(*c.input(), CommittedInputRegion::WholeSurface);
    assert_eq!(c.commit_count(), 0);

    let t = Tracker::new();
    assert!(t.is_empty());
    assert_eq!(t, Tracker::default());
}

/// Reference implementation (x86_64): SurfaceState 1192, tracker<8> 160, CommitOutcome 20,
/// Latch 288, ConfigureState 152. Bounds leave ~10% headroom.
#[test]
fn state_sizes_stay_bounded() {
    assert!(
        size_of::<SurfaceState>() <= 1280,
        "{}",
        size_of::<SurfaceState>()
    );
    assert!(size_of::<Tracker>() <= 192, "{}", size_of::<Tracker>());
    assert!(
        size_of::<ConnectionBufferTracker>() <= 192,
        "{}",
        size_of::<ConnectionBufferTracker>()
    );
    assert!(
        size_of::<CommitOutcome>() <= 24,
        "{}",
        size_of::<CommitOutcome>()
    );
    assert!(size_of::<Latch>() <= 320, "{}", size_of::<Latch>());
    assert!(
        size_of::<ConfigureState>() <= 192,
        "{}",
        size_of::<ConfigureState>()
    );
}

// --- attach -------------------------------------------------------------------------------

#[test]
fn attach_records_pending_buffer_without_touching_committed_state() {
    let mut s = SurfaceState::new();
    let t = Tracker::new();
    s.attach(Some(bid(1)), Scale120::ONE, &t).unwrap();
    assert_eq!(s.pending().buffer(), PendingBuffer::Attach(bid(1)));
    s.attach(Some(bid(2)), Scale120::ONE, &t).unwrap();
    assert_eq!(
        s.pending().buffer(),
        PendingBuffer::Attach(bid(2)),
        "last attach wins"
    );
    s.attach(None, Scale120::ONE, &t).unwrap();
    assert_eq!(s.pending().buffer(), PendingBuffer::Detach);
    assert_eq!(*s.committed(), CommittedState::new());
}

#[test]
fn attach_rejects_non_unit_scale_first_and_leaves_pending_unchanged() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    map(&mut s, sid(1), &mut t, bid(1), 8, 8);
    let before = s;
    for scale in [Scale120(0), Scale120(119), Scale120(240)] {
        assert_eq!(
            s.attach(Some(bid(2)), scale, &t),
            Err(ProtocolError::InvalidScale)
        );
        assert_eq!(s.attach(None, scale, &t), Err(ProtocolError::InvalidScale));
        assert_eq!(
            s.attach(Some(bid(1)), scale, &t),
            Err(ProtocolError::InvalidScale),
            "InvalidScale precedes BufferBusy"
        );
    }
    assert_eq!(s, before);
}

/// Architecture proof: busy-buffer attach.
#[test]
fn attaching_a_busy_buffer_fails_on_every_surface_of_the_connection() {
    let mut a = SurfaceState::new();
    let mut b = SurfaceState::new();
    let mut t = Tracker::new();
    map(&mut a, sid(1), &mut t, bid(1), 8, 8);
    assert!(t.is_busy(bid(1)));
    let (a_before, b_before) = (a, b);
    assert_eq!(
        a.attach(Some(bid(1)), Scale120::ONE, &t),
        Err(ProtocolError::BufferBusy)
    );
    assert_eq!(
        b.attach(Some(bid(1)), Scale120::ONE, &t),
        Err(ProtocolError::BufferBusy)
    );
    assert_eq!((a, b), (a_before, b_before));
    assert!(b.attach(Some(bid(2)), Scale120::ONE, &t).is_ok());
    assert!(
        a.attach(None, Scale120::ONE, &t).is_ok(),
        "detach never conflicts"
    );
}

#[test]
fn a_released_buffer_can_be_attached_again() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    map(&mut s, id, &mut t, bid(1), 8, 8);
    s.latch(id, &mut t);
    map(&mut s, id, &mut t, bid(2), 8, 8);
    assert_eq!(s.latch(id, &mut t).released, Some(bid(1)));
    assert!(!t.is_busy(bid(1)));
    assert!(s.attach(Some(bid(1)), Scale120::ONE, &t).is_ok());
}

// --- damage -------------------------------------------------------------------------------

#[test]
fn damage_accumulates_in_pending_until_commit_clears_it() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    map(&mut s, id, &mut t, bid(1), 64, 64);
    s.damage(&[brect(0, 0, 1, 1)]).unwrap();
    s.damage(&[brect(2, 2, 1, 1), brect(4, 4, 1, 1)]).unwrap();
    assert_eq!(
        s.pending().damage().rects(),
        &[rect(0, 0, 1, 1), rect(2, 2, 1, 1), rect(4, 4, 1, 1)]
    );
    commit_plain(&mut s, id, &mut t);
    assert!(s.pending().damage().is_empty());
}

#[test]
fn damage_with_more_than_five_rects_is_invalid_and_changes_nothing() {
    let mut s = SurfaceState::new();
    s.damage(&[brect(0, 0, 1, 1)]).unwrap();
    let before = s;
    let six = [brect(1, 1, 1, 1); 6];
    assert_eq!(s.damage(&six), Err(ProtocolError::InvalidDamage));
    assert_eq!(s, before);
    assert!(s.damage(&six[..5]).is_ok());
    assert!(s.damage(&[]).is_ok());
}

#[test]
fn damage_drops_empty_and_out_of_extent_rects_and_clips_the_rest() {
    let mut s = SurfaceState::new();
    s.damage(&[
        brect(0, 0, 0, 5),
        brect(0, 0, 5, 0),
        brect(4096, 0, 10, 10),
        brect(0, 5000, 10, 10),
        brect(4090, 4000, 100, 200),
    ])
    .unwrap();
    assert_eq!(s.pending().damage().rects(), &[rect(4090, 4000, 6, 96)]);
    s.damage(&[brect(65535, 65535, 65535, 65535)]).unwrap();
    assert_eq!(s.pending().damage().len(), 1);
}

#[test]
fn damage_overflow_collapses_to_the_bounding_box_instead_of_failing() {
    let mut s = SurfaceState::new();
    let rects: Vec<BufferRect> = (0..17u16).map(|i| brect(i * 2, i * 2, 1, 1)).collect();
    for chunk in rects.chunks(5) {
        s.damage(chunk).unwrap();
    }
    let damage = s.pending().damage();
    assert!(damage.is_collapsed());
    assert_eq!(damage.rects(), &[rect(0, 0, 33, 33)]);
}

#[test]
fn first_map_damages_the_whole_buffer_regardless_of_pending_damage() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    s.damage(&[brect(1, 1, 1, 1)]).unwrap();
    let outcome = map(&mut s, id, &mut t, bid(1), 64, 32);
    assert!(outcome.schedule_composite);
    assert_eq!(s.unlatched_damage().rects(), &[rect(0, 0, 64, 32)]);
    let latch = s.latch(id, &mut t);
    assert!(latch.geometry_changed);
    assert_eq!(latch.damage, damage_set(&[rect(0, 0, 64, 32)]));
    assert!(s.unlatched_damage().is_empty());
}

#[test]
fn same_size_swap_uses_pending_damage_clipped_to_the_buffer() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    map(&mut s, id, &mut t, bid(1), 64, 32);
    s.latch(id, &mut t);
    s.damage(&[brect(60, 30, 10, 10), brect(100, 100, 5, 5)])
        .unwrap();
    let outcome = map(&mut s, id, &mut t, bid(2), 64, 32);
    assert!(outcome.schedule_composite);
    let latch = s.latch(id, &mut t);
    assert!(!latch.geometry_changed);
    assert_eq!(latch.damage.rects(), &[rect(60, 30, 4, 2)]);
}

#[test]
fn same_size_swap_without_damage_schedules_nothing() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    map(&mut s, id, &mut t, bid(1), 64, 32);
    s.latch(id, &mut t);
    let outcome = map(&mut s, id, &mut t, bid(2), 64, 32);
    assert!(!outcome.schedule_composite);
    assert!(s.unlatched_damage().is_empty());
    assert_eq!(t.latest(id), Some(bid(2)), "the swap is still tracked");
}

#[test]
fn size_change_damages_the_whole_new_buffer() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    map(&mut s, id, &mut t, bid(1), 64, 32);
    s.latch(id, &mut t);
    s.damage(&[brect(0, 0, 1, 1)]).unwrap();
    map(&mut s, id, &mut t, bid(2), 16, 128);
    let latch = s.latch(id, &mut t);
    assert!(latch.geometry_changed);
    assert_eq!(latch.damage.rects(), &[rect(0, 0, 16, 128)]);
    assert_eq!(s.committed().size(), size(16, 128));
}

#[test]
fn detach_unmaps_with_a_geometry_change_and_no_damage() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    map(&mut s, id, &mut t, bid(1), 64, 32);
    s.latch(id, &mut t);
    s.attach(None, Scale120::ONE, &t).unwrap();
    s.damage(&[brect(0, 0, 4, 4)]).unwrap();
    let outcome = commit_plain(&mut s, id, &mut t);
    assert!(outcome.schedule_composite);
    assert!(!s.committed().is_mapped());
    assert_eq!(s.committed().size(), size(0, 0));
    let latch = s.latch(id, &mut t);
    assert!(latch.geometry_changed);
    assert!(latch.damage.is_empty());
}

#[test]
fn unmapped_commit_without_a_buffer_has_no_damage_and_no_geometry_change() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    s.damage(&[brect(0, 0, 4, 4)]).unwrap();
    let outcome = commit_plain(&mut s, sid(1), &mut t);
    assert!(!outcome.schedule_composite);
    assert_eq!(s.committed().commit_count(), 1);
    let latch = s.latch(sid(1), &mut t);
    assert!(!latch.geometry_changed);
    assert!(latch.damage.is_empty());
    assert_eq!(latch.released, None);
}

#[test]
fn damage_accumulates_across_commits_until_latch() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    map(&mut s, id, &mut t, bid(1), 64, 64);
    s.latch(id, &mut t);
    s.damage(&[brect(0, 0, 2, 2)]).unwrap();
    commit_plain(&mut s, id, &mut t);
    s.damage(&[brect(10, 10, 2, 2)]).unwrap();
    commit_plain(&mut s, id, &mut t);
    assert_eq!(
        s.unlatched_damage().rects(),
        &[rect(0, 0, 2, 2), rect(10, 10, 2, 2)]
    );
    let latch = s.latch(id, &mut t);
    assert_eq!(latch.damage.len(), 2);
    assert!(!latch.geometry_changed);
    assert!(
        s.latch(id, &mut t).damage.is_empty(),
        "latch hands damage over once"
    );
}

#[test]
fn unlatched_damage_collapses_instead_of_growing() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    map(&mut s, id, &mut t, bid(1), 256, 256);
    s.latch(id, &mut t);
    for i in 0..40u16 {
        s.damage(&[brect(i * 4, i * 4, 1, 1)]).unwrap();
        commit_plain(&mut s, id, &mut t);
    }
    assert!(s.unlatched_damage().len() <= MAX_DAMAGE_RECTS_PER_COMMIT);
    let bounds = s
        .unlatched_damage()
        .rects()
        .iter()
        .fold(rect(0, 0, 0, 0), |acc, r| acc.union_bounds(*r).unwrap());
    assert_eq!(bounds, rect(0, 0, 157, 157));
}

// --- opaque region ------------------------------------------------------------------------

#[test]
fn opaque_region_replace_and_append() {
    let mut s = SurfaceState::new();
    s.set_opaque_region(&[rect(0, 0, 4, 4)], true).unwrap();
    s.set_opaque_region(&[rect(8, 8, 4, 4)], false).unwrap();
    assert_eq!(
        *s.pending().opaque(),
        OpaqueRegion::Rects(region(&[rect(0, 0, 4, 4), rect(8, 8, 4, 4)]))
    );
    s.set_opaque_region(&[rect(1, 1, 1, 1)], true).unwrap();
    assert_eq!(
        *s.pending().opaque(),
        OpaqueRegion::Rects(region(&[rect(1, 1, 1, 1)]))
    );
    s.set_opaque_region(&[], true).unwrap();
    assert_eq!(*s.pending().opaque(), OpaqueRegion::Rects(RegionSet::new()));
}

#[test]
fn opaque_overflow_degrades_to_not_opaque_and_is_sticky_until_replace() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    let rects = diagonal(0, 9);
    s.set_opaque_region(&rects[0..3], true).unwrap();
    s.set_opaque_region(&rects[3..6], false).unwrap();
    s.set_opaque_region(&rects[6..8], false).unwrap();
    assert!(matches!(s.pending().opaque(), OpaqueRegion::Rects(set) if set.len() == 8));
    s.set_opaque_region(&rects[8..9], false).unwrap();
    assert_eq!(*s.pending().opaque(), OpaqueRegion::Degraded);
    s.set_opaque_region(&[rect(0, 0, 1, 1)], false).unwrap();
    assert_eq!(
        *s.pending().opaque(),
        OpaqueRegion::Degraded,
        "appends are ignored"
    );

    map(&mut s, id, &mut t, bid(1), 64, 64);
    assert!(
        s.committed().opaque().is_empty(),
        "degraded commits as not opaque"
    );

    s.set_opaque_region(&[rect(0, 0, 2, 2)], true).unwrap();
    commit_plain(&mut s, id, &mut t);
    assert_eq!(*s.committed().opaque(), region(&[rect(0, 0, 2, 2)]));
}

// --- input region -------------------------------------------------------------------------

#[test]
fn input_region_defaults_to_whole_surface_and_empty_replace_means_no_input() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    map(&mut s, id, &mut t, bid(1), 10, 10);
    assert!(s.committed().accepts_input_at(Point { x: 0, y: 0 }));
    s.set_input_region(&[], true).unwrap();
    assert_eq!(*s.pending().input(), InputRegion::Rects(RegionSet::new()));
    commit_plain(&mut s, id, &mut t);
    assert_eq!(
        *s.committed().input(),
        CommittedInputRegion::Rects(RegionSet::new())
    );
    assert!(!s.committed().accepts_input_at(Point { x: 0, y: 0 }));
}

#[test]
fn input_append_to_whole_surface_is_a_no_op() {
    let mut s = SurfaceState::new();
    s.set_input_region(&[rect(0, 0, 1, 1)], false).unwrap();
    assert_eq!(*s.pending().input(), InputRegion::WholeSurface);
}

/// C21: any rect covering the whole extent normalises to `WholeSurface`, in append or replace
/// mode. Normalisation runs before the capacity check, so such a request never overflows.
#[test]
fn full_extent_input_rect_normalises_to_whole_surface() {
    for replace in [true, false] {
        let mut s = SurfaceState::new();
        s.set_input_region(&[rect(0, 0, 1, 1)], true).unwrap();
        s.set_input_region(&[rect(5, 5, 1, 1), EXTENT_RECT], replace)
            .unwrap();
        assert_eq!(
            *s.pending().input(),
            InputRegion::WholeSurface,
            "replace={replace}"
        );
    }
    let mut s = SurfaceState::new();
    s.set_input_region(&[rect(-100, -100, 10_000, 10_000)], true)
        .unwrap();
    assert_eq!(
        *s.pending().input(),
        InputRegion::WholeSurface,
        "clipped to the extent first"
    );

    let mut s = SurfaceState::new();
    fill_input_region(&mut s, 8);
    let extra = diagonal(100, 2);
    assert_eq!(
        s.set_input_region(&[extra[0], extra[1], EXTENT_RECT], false),
        Ok(()),
        "a full-extent rect wins over the capacity check"
    );
    assert_eq!(*s.pending().input(), InputRegion::WholeSurface);

    let mut s = SurfaceState::new();
    s.set_input_region(
        &[rect(0, 0, MAX_SURFACE_EXTENT, MAX_SURFACE_EXTENT - 1)],
        true,
    )
    .unwrap();
    assert!(matches!(s.pending().input(), InputRegion::Rects(set) if set.len() == 1));
}

/// Replaces the pending input region with `n` (≤ 8) disjoint rects, 3 per request.
fn fill_input_region(s: &mut SurfaceState, n: usize) {
    let rects = diagonal(0, n);
    for (i, chunk) in rects.chunks(3).enumerate() {
        s.set_input_region(chunk, i == 0).unwrap();
    }
    assert!(matches!(s.pending().input(), InputRegion::Rects(set) if set.len() == n));
}

/// S2: a `SetInputRegion` that would exceed `MAX_REGION_RECTS` fails atomically with
/// `InvalidRegion`; nothing of it is applied and the next commit is unaffected.
#[test]
fn input_region_overflow_fails_the_request_atomically() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    map(&mut s, id, &mut t, bid(1), 64, 64);

    fill_input_region(&mut s, 8);
    let before = s;
    assert_eq!(
        s.set_input_region(&[rect(40, 40, 1, 1)], false),
        Err(ProtocolError::InvalidRegion)
    );
    assert_eq!(s, before);

    fill_input_region(&mut s, 7);
    let before = s;
    assert_eq!(
        s.set_input_region(&[rect(40, 40, 1, 1), rect(42, 42, 1, 1)], false),
        Err(ProtocolError::InvalidRegion),
        "7 + 2 > 8: neither rect is applied"
    );
    assert_eq!(s, before);
    assert!(
        s.set_input_region(&[rect(40, 40, 1, 1)], false).is_ok(),
        "7 + 1 fits"
    );

    let outcome = s.commit(id, plain(), &mut t, None, no_resolve);
    assert!(outcome.is_ok(), "a full region never poisons the commit");
    assert!(matches!(s.committed().input(), CommittedInputRegion::Rects(set) if set.len() == 8));
}

#[test]
fn input_region_overflow_ignores_dropped_rects_and_replace_resets_capacity() {
    let mut s = SurfaceState::new();
    fill_input_region(&mut s, 8);
    assert!(
        s.set_input_region(
            &[rect(MAX_SURFACE_EXTENT as i32, 0, 1, 1), rect(0, 0, 0, 5)],
            false
        )
        .is_ok(),
        "rects dropped by clipping do not count"
    );
    s.set_input_region(&[rect(0, 0, 2, 2)], true).unwrap();
    assert_eq!(
        *s.pending().input(),
        InputRegion::Rects(region(&[rect(0, 0, 2, 2)]))
    );
}

// --- region request validation ------------------------------------------------------------

#[test]
fn region_requests_with_more_than_three_rects_fail_atomically() {
    let four = [rect(0, 0, 1, 1); 4];
    let mut s = SurfaceState::new();
    s.set_opaque_region(&[rect(9, 9, 1, 1)], true).unwrap();
    s.set_input_region(&[rect(9, 9, 1, 1)], true).unwrap();
    let before = s;
    assert_eq!(
        s.set_opaque_region(&four, true),
        Err(ProtocolError::InvalidRegion)
    );
    assert_eq!(
        s.set_input_region(&four, true),
        Err(ProtocolError::InvalidRegion)
    );
    assert_eq!(s, before);
}

#[test]
fn region_requests_with_an_overflowing_rect_fail_atomically() {
    let bad = [
        rect(i32::MAX, 0, 10, 1),
        rect(0, i32::MAX - 1, 1, 2),
        rect(0, 0, u32::MAX, 1),
        rect(0, 0, 1, i32::MAX as u32 + 1),
    ];
    for b in bad {
        let mut s = SurfaceState::new();
        s.set_opaque_region(&[rect(9, 9, 1, 1)], true).unwrap();
        s.set_input_region(&[rect(9, 9, 1, 1)], true).unwrap();
        let before = s;
        let rects = [rect(0, 0, 4, 4), b];
        assert_eq!(
            s.set_opaque_region(&rects, false),
            Err(ProtocolError::InvalidRegion),
            "{b:?}"
        );
        assert_eq!(
            s.set_input_region(&rects, false),
            Err(ProtocolError::InvalidRegion),
            "{b:?}"
        );
        assert_eq!(s, before, "the valid first rect must not be applied");
    }
}

#[test]
fn regions_are_clipped_to_the_extent_at_request_time() {
    let mut s = SurfaceState::new();
    s.set_opaque_region(
        &[
            rect(-5, -5, 10, 10),
            rect(5000, 0, 10, 10),
            rect(-20, 0, 10, 10),
        ],
        true,
    )
    .unwrap();
    assert_eq!(
        *s.pending().opaque(),
        OpaqueRegion::Rects(region(&[rect(0, 0, 5, 5)]))
    );
    s.set_input_region(&[rect(4090, 4090, 100, 100), rect(0, 0, 0, 10)], true)
        .unwrap();
    assert_eq!(
        *s.pending().input(),
        InputRegion::Rects(region(&[rect(4090, 4090, 6, 6)]))
    );
}

#[test]
fn committed_regions_are_clipped_to_the_buffer_size() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    s.set_opaque_region(&[rect(0, 0, 100, 100), rect(50, 50, 10, 10)], true)
        .unwrap();
    s.set_input_region(&[rect(10, 10, 100, 5), rect(40, 0, 1, 1)], true)
        .unwrap();
    map(&mut s, id, &mut t, bid(1), 32, 16);
    assert_eq!(*s.committed().opaque(), region(&[rect(0, 0, 32, 16)]));
    assert_eq!(
        *s.committed().input(),
        CommittedInputRegion::Rects(region(&[rect(10, 10, 22, 5)]))
    );
    assert!(
        matches!(s.pending().opaque(), OpaqueRegion::Rects(set) if set.len() == 2),
        "pending keeps the unclipped request"
    );
}

#[test]
fn regions_and_scale_persist_across_commits_while_buffer_and_damage_reset() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    s.set_opaque_region(&[rect(0, 0, 4, 4)], true).unwrap();
    s.set_input_region(&[rect(0, 0, 8, 8)], true).unwrap();
    map(&mut s, id, &mut t, bid(1), 16, 16);
    assert_eq!(s.pending().buffer(), PendingBuffer::Unchanged);
    assert!(s.pending().damage().is_empty());
    let pending_regions = (*s.pending().opaque(), *s.pending().input());
    commit_plain(&mut s, id, &mut t);
    assert_eq!(
        (*s.pending().opaque(), *s.pending().input()),
        pending_regions
    );
    assert_eq!(*s.committed().opaque(), region(&[rect(0, 0, 4, 4)]));
    assert_eq!(
        s.committed().buffer().map(|b| b.id),
        Some(bid(1)),
        "Unchanged keeps the buffer"
    );
    assert_eq!(s.committed().commit_count(), 2);
    assert_eq!(s.pending().scale(), Scale120::ONE);
}

#[test]
fn committed_state_records_buffer_layout_and_color_space() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    map(&mut s, sid(1), &mut t, bid(3), 20, 10);
    assert_eq!(
        s.committed().buffer(),
        Some(CommittedBuffer {
            id: bid(3),
            layout: layout(20, 10)
        })
    );
    assert!(s.committed().is_mapped());
    assert_eq!(s.committed().color_space(), ColorSpace::Srgb);
}

#[test]
fn accepts_input_at_is_bounded_by_surface_size_and_input_region() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    assert!(
        !s.committed().accepts_input_at(Point { x: 0, y: 0 }),
        "unmapped never accepts"
    );
    map(&mut s, id, &mut t, bid(1), 10, 5);
    let c = *s.committed();
    assert!(c.accepts_input_at(Point { x: 0, y: 0 }));
    assert!(c.accepts_input_at(Point { x: 9, y: 4 }));
    assert!(!c.accepts_input_at(Point { x: 10, y: 0 }));
    assert!(!c.accepts_input_at(Point { x: 0, y: 5 }));
    assert!(!c.accepts_input_at(Point { x: -1, y: 0 }));
    assert!(!c.accepts_input_at(Point {
        x: i32::MIN,
        y: i32::MAX
    }));

    s.set_input_region(&[rect(2, 1, 2, 2), rect(8, 0, 10, 10)], true)
        .unwrap();
    commit_plain(&mut s, id, &mut t);
    let c = *s.committed();
    assert!(c.accepts_input_at(Point { x: 2, y: 1 }));
    assert!(c.accepts_input_at(Point { x: 3, y: 2 }));
    assert!(!c.accepts_input_at(Point { x: 4, y: 2 }));
    assert!(c.accepts_input_at(Point { x: 9, y: 4 }));
    assert!(!c.accepts_input_at(Point { x: 5, y: 0 }));
}

// --- commit rollback (architecture proof) -------------------------------------------------

type Snapshot = (SurfaceState, Tracker, ConfigureState);

fn snapshot(s: &SurfaceState, t: &Tracker, w: &ConfigureState) -> Snapshot {
    (*s, *t, *w)
}

/// A windowed, configured, mapped surface with pending attach + damage + region changes, so a
/// rollback bug on any field is visible.
fn rich_fixture() -> (SurfaceState, Tracker, ConfigureState, Serial) {
    let mut minter = SerialMinter::new();
    let mut w = ConfigureState::new();
    let cfg = WindowConfig::new(size(64, 32), WindowStates::EMPTY, size(0, 0));
    let first = w.send(&mut minter, cfg).unwrap();
    w.ack(first).unwrap();
    let pending_serial = w.send(&mut minter, cfg).unwrap();
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    s.assign_role(SurfaceRole::Toplevel, connect(), ParentRef::Absent)
        .unwrap();
    s.attach(Some(bid(1)), Scale120::ONE, &t).unwrap();
    s.commit(id, with_frame(), &mut t, Some(&mut w), |_| {
        Ok(layout(64, 32))
    })
    .unwrap();
    s.attach(Some(bid(2)), Scale120::ONE, &t).unwrap();
    s.damage(&[brect(1, 1, 2, 2)]).unwrap();
    s.set_opaque_region(&[rect(0, 0, 8, 8)], true).unwrap();
    (s, t, w, pending_serial)
}

/// Commits `sid(1)` expecting `expected`, and proves pending state, committed state, the
/// tracker and the window's configure state are all bit-for-bit unchanged.
fn assert_rolls_back<const N: usize, F>(
    s: &mut SurfaceState,
    t: &mut BufferTracker<N>,
    mut w: Option<&mut ConfigureState>,
    request: CommitRequest,
    resolve: F,
    expected: ProtocolError,
) where
    F: FnOnce(ClientBufferId) -> Result<BufferLayout, ProtocolError>,
{
    let (s_before, t_before) = (*s, *t);
    let w_before = w.as_deref().copied();
    let result = s.commit(sid(1), request, t, w.as_deref_mut(), resolve);
    assert_eq!(result, Err(expected));
    assert_eq!(*s, s_before, "surface state mutated by a failed commit");
    assert_eq!(*t, t_before, "tracker mutated by a failed commit");
    assert_eq!(
        w.as_deref().copied(),
        w_before,
        "configure state mutated by a failed commit"
    );
}

#[test]
fn commit_rolls_back_when_the_attached_buffer_became_busy() {
    let (mut s, mut t, mut w, serial) = rich_fixture();
    let mut other = SurfaceState::new();
    other.attach(Some(bid(2)), Scale120::ONE, &t).unwrap();
    other
        .commit(sid(2), plain(), &mut t, None, |_| Ok(layout(8, 8)))
        .unwrap();
    assert!(t.is_busy(bid(2)));
    assert_rolls_back(
        &mut s,
        &mut t,
        Some(&mut w),
        CommitRequest {
            request_frame: true,
            ..with_ack(serial)
        },
        |_| Ok(layout(64, 32)),
        ProtocolError::BufferBusy,
    );
    assert_eq!(
        w.check_ack(serial),
        Ok(()),
        "a failed commit must not consume its ack"
    );
}

#[test]
fn commit_rolls_back_and_passes_resolver_errors_through() {
    for code in [
        ProtocolError::StaleObject,
        ProtocolError::InvalidObject,
        ProtocolError::WrongObjectKind,
        ProtocolError::InvalidLayout,
    ] {
        let (mut s, mut t, mut w, _) = rich_fixture();
        let calls = Cell::new(0);
        assert_rolls_back(
            &mut s,
            &mut t,
            Some(&mut w),
            with_frame(),
            |b| {
                assert_eq!(b, bid(2));
                calls.set(calls.get() + 1);
                Err(code)
            },
            code,
        );
        assert_eq!(calls.get(), 1);
    }
}

#[test]
fn commit_rolls_back_on_unknown_or_consumed_ack() {
    let (mut s, mut t, mut w, serial) = rich_fixture();
    assert_rolls_back(
        &mut s,
        &mut t,
        Some(&mut w),
        with_ack(Serial(serial.0 + 100)),
        no_resolve,
        ProtocolError::SerialMismatch,
    );
    assert_rolls_back(
        &mut s,
        &mut t,
        Some(&mut w),
        with_ack(Serial(1)),
        no_resolve,
        ProtocolError::SerialMismatch,
    );
}

#[test]
fn commit_ack_without_a_window_is_serial_mismatch() {
    let (mut s, mut t, _, serial) = rich_fixture();
    assert_rolls_back(
        &mut s,
        &mut t,
        None,
        with_ack(serial),
        no_resolve,
        ProtocolError::SerialMismatch,
    );
}

#[test]
fn commit_on_a_never_configured_window_is_not_configured() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let (mut w, _) = window_with_serial();
    s.attach(Some(bid(1)), Scale120::ONE, &t).unwrap();
    s.damage(&[brect(0, 0, 1, 1)]).unwrap();
    assert_rolls_back(
        &mut s,
        &mut t,
        Some(&mut w),
        with_frame(),
        no_resolve,
        ProtocolError::NotConfigured,
    );
    let mut fresh = ConfigureState::new();
    assert_rolls_back(
        &mut s,
        &mut t,
        Some(&mut fresh),
        plain(),
        no_resolve,
        ProtocolError::NotConfigured,
    );
}

/// Architecture proof: exhaustion of the busy-buffer table.
#[test]
fn commit_rolls_back_when_the_tracker_is_exhausted() {
    let mut t = BufferTracker::<1>::new();
    let mut a = SurfaceState::new();
    a.attach(Some(bid(1)), Scale120::ONE, &t).unwrap();
    a.commit(sid(2), plain(), &mut t, None, |_| Ok(layout(8, 8)))
        .unwrap();

    // `b` is sid(1): a windowed, configured surface committing with a valid ack.
    let mut minter = SerialMinter::new();
    let mut w = ConfigureState::new();
    let cfg = WindowConfig::new(size(8, 8), WindowStates::EMPTY, size(0, 0));
    let first = w.send(&mut minter, cfg).unwrap();
    w.ack(first).unwrap();
    let serial = w.send(&mut minter, cfg).unwrap();
    let mut b = SurfaceState::new();
    b.assign_role(SurfaceRole::Toplevel, connect(), ParentRef::Absent)
        .unwrap();
    b.attach(Some(bid(2)), Scale120::ONE, &t).unwrap();
    b.damage(&[brect(0, 0, 1, 1)]).unwrap();
    assert_rolls_back(
        &mut b,
        &mut t,
        Some(&mut w),
        CommitRequest {
            request_frame: true,
            ..with_ack(serial)
        },
        |_| Ok(layout(8, 8)),
        ProtocolError::LimitExceeded,
    );
    assert_eq!(w.check_ack(serial), Ok(()), "the ack survives exhaustion");

    assert_eq!(
        t.check_commit(sid(1), PendingBuffer::Attach(bid(2))),
        Err(ProtocolError::LimitExceeded)
    );
    assert_eq!(t.check_commit(sid(1), PendingBuffer::Detach), Ok(()));
    assert_eq!(
        t.check_commit(sid(2), PendingBuffer::Attach(bid(2))),
        Ok(()),
        "existing entry reused"
    );
    a.attach(Some(bid(3)), Scale120::ONE, &t).unwrap();
    assert!(a
        .commit(sid(2), plain(), &mut t, None, |_| Ok(layout(8, 8)))
        .is_ok());
}

#[test]
fn connection_tracker_never_exhausts_with_one_buffer_per_surface() {
    let mut t = ConnectionBufferTracker::new();
    let mut surfaces = [SurfaceState::new(); MAX_BUFFERS_PER_CLIENT];
    for (i, s) in surfaces.iter_mut().enumerate() {
        let slot = i as u8;
        s.attach(Some(bid(slot)), Scale120::ONE, &t).unwrap();
        assert!(s
            .commit(sid(slot), plain(), &mut t, None, |_| Ok(layout(8, 8)))
            .is_ok());
    }
    assert_eq!(t.len(), MAX_BUFFERS_PER_CLIENT);
}

/// The full validation order: each row fixes the previous failure and exposes the next one.
#[test]
fn commit_validation_order_is_ack_configured_resolve_tracker() {
    let (mut s, mut t, mut w, serial) = rich_fixture();
    // Make every check fail at once.
    let mut other = SurfaceState::new();
    other.attach(Some(bid(2)), Scale120::ONE, &t).unwrap();
    other
        .commit(sid(2), plain(), &mut t, None, |_| Ok(layout(8, 8)))
        .unwrap();
    let mut unconfigured = ConfigureState::new();
    let stale = |_: ClientBufferId| -> Result<BufferLayout, ProtocolError> {
        Err(ProtocolError::StaleObject)
    };

    assert_rolls_back(
        &mut s,
        &mut t,
        Some(&mut unconfigured),
        with_ack(Serial(999)),
        stale,
        ProtocolError::SerialMismatch,
    );
    assert_rolls_back(
        &mut s,
        &mut t,
        None,
        with_ack(serial),
        stale,
        ProtocolError::SerialMismatch,
    );
    assert_rolls_back(
        &mut s,
        &mut t,
        Some(&mut unconfigured),
        plain(),
        stale,
        ProtocolError::NotConfigured,
    );
    assert_rolls_back(
        &mut s,
        &mut t,
        Some(&mut w),
        with_ack(serial),
        stale,
        ProtocolError::StaleObject,
    );
    assert_rolls_back(
        &mut s,
        &mut t,
        Some(&mut w),
        with_ack(serial),
        |_| Ok(layout(64, 32)),
        ProtocolError::BufferBusy,
    );
    s.attach(Some(bid(3)), Scale120::ONE, &t).unwrap();
    let outcome = s
        .commit(sid(1), with_ack(serial), &mut t, Some(&mut w), |_| {
            Ok(layout(64, 32))
        })
        .unwrap();
    assert_eq!(outcome.acked, Some(serial));
}

#[test]
fn resolver_runs_only_for_attach_and_exactly_once() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    let calls = Cell::new(0);
    let counting = |_: ClientBufferId| {
        calls.set(calls.get() + 1);
        Ok(layout(8, 8))
    };
    s.commit(id, plain(), &mut t, None, counting).unwrap();
    assert_eq!(calls.get(), 0, "Unchanged");
    s.attach(Some(bid(1)), Scale120::ONE, &t).unwrap();
    s.commit(id, plain(), &mut t, None, counting).unwrap();
    assert_eq!(calls.get(), 1, "Attach");
    s.attach(None, Scale120::ONE, &t).unwrap();
    s.commit(id, plain(), &mut t, None, counting).unwrap();
    assert_eq!(calls.get(), 1, "Detach");
}

// --- configure ack via commit (C24) -------------------------------------------------------

#[test]
fn commit_ack_is_applied_atomically_with_the_commit() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let (mut w, serial) = window_with_serial();
    s.assign_role(SurfaceRole::Toplevel, connect(), ParentRef::Absent)
        .unwrap();
    s.attach(Some(bid(1)), Scale120::ONE, &t).unwrap();
    let outcome = s
        .commit(sid(1), with_ack(serial), &mut t, Some(&mut w), |_| {
            Ok(layout(64, 32))
        })
        .unwrap();
    assert_eq!(outcome.acked, Some(serial));
    assert!(w.is_configured());
    assert_eq!(w.acked().map(|(s, _)| s), Some(serial));
    assert!(s.committed().is_mapped());

    let before = snapshot(&s, &t, &w);
    assert_eq!(
        s.commit(sid(1), with_ack(serial), &mut t, Some(&mut w), no_resolve),
        Err(ProtocolError::SerialMismatch),
        "an ack is one-shot"
    );
    assert_eq!(snapshot(&s, &t, &w), before);

    let outcome = s
        .commit(sid(1), plain(), &mut t, Some(&mut w), no_resolve)
        .unwrap();
    assert_eq!(
        outcome.acked, None,
        "configured windows commit without an ack"
    );
}

#[test]
fn commit_ack_consumes_older_outstanding_serials() {
    let mut minter = SerialMinter::new();
    let mut w = ConfigureState::new();
    let cfg = WindowConfig::new(size(8, 8), WindowStates::EMPTY, size(0, 0));
    let s1 = w.send(&mut minter, cfg).unwrap();
    let s2 = w.send(&mut minter, cfg).unwrap();
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    s.commit(sid(1), with_ack(s2), &mut t, Some(&mut w), no_resolve)
        .unwrap();
    assert_eq!(w.outstanding_len(), 0);
    assert_eq!(
        s.commit(sid(1), with_ack(s1), &mut t, Some(&mut w), no_resolve),
        Err(ProtocolError::SerialMismatch)
    );
}

#[test]
fn surfaces_without_a_window_or_role_commit_freely() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    assert_eq!(s.role(), None);
    let outcome = map(&mut s, sid(1), &mut t, bid(1), 8, 8);
    assert_eq!(outcome.acked, None);
    assert!(s.committed().is_mapped());
}

// --- buffer handoff -----------------------------------------------------------------------

/// Architecture proof: supersede-release ordering.
#[test]
fn superseded_latest_is_released_at_commit_and_old_current_at_latch() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    let mut released = Vec::new();

    assert_eq!(map(&mut s, id, &mut t, bid(1), 8, 8).released, None);
    assert_eq!(t.latest(id), Some(bid(1)));
    assert_eq!(t.current(id), None);
    released.extend(s.latch(id, &mut t).released);
    assert_eq!((t.current(id), t.latest(id)), (Some(bid(1)), None));

    released.extend(map(&mut s, id, &mut t, bid(2), 8, 8).released);
    assert_eq!(t.busy_count(id), 2);
    released.extend(map(&mut s, id, &mut t, bid(3), 8, 8).released);
    assert_eq!(
        released,
        vec![bid(2)],
        "B was never composited: released at supersede"
    );
    assert!(!t.is_busy(bid(2)));
    assert_eq!((t.current(id), t.latest(id)), (Some(bid(1)), Some(bid(3))));

    released.extend(s.latch(id, &mut t).released);
    assert_eq!(released, vec![bid(2), bid(1)]);
    assert_eq!((t.current(id), t.latest(id)), (Some(bid(3)), None));

    s.attach(None, Scale120::ONE, &t).unwrap();
    released.extend(commit_plain(&mut s, id, &mut t).released);
    assert!(
        t.is_busy(bid(3)),
        "current stays busy until the unmap is composited"
    );
    released.extend(s.latch(id, &mut t).released);
    assert_eq!(released, vec![bid(2), bid(1), bid(3)]);
    assert!(t.is_empty());
}

#[test]
fn detach_before_latch_releases_latest_immediately() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    map(&mut s, id, &mut t, bid(1), 8, 8);
    s.attach(None, Scale120::ONE, &t).unwrap();
    assert_eq!(commit_plain(&mut s, id, &mut t).released, Some(bid(1)));
    assert!(t.is_empty());
    assert_eq!(s.latch(id, &mut t).released, None);

    map(&mut s, id, &mut t, bid(1), 8, 8);
    s.latch(id, &mut t);
    map(&mut s, id, &mut t, bid(2), 8, 8);
    s.attach(None, Scale120::ONE, &t).unwrap();
    assert_eq!(commit_plain(&mut s, id, &mut t).released, Some(bid(2)));
    assert_eq!((t.current(id), t.latest(id)), (Some(bid(1)), None));
    assert_eq!(s.latch(id, &mut t).released, Some(bid(1)));
    assert!(t.is_empty());
}

#[test]
fn reattach_after_detach_before_latch_keeps_current_busy() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    map(&mut s, id, &mut t, bid(1), 8, 8);
    s.latch(id, &mut t);
    s.attach(None, Scale120::ONE, &t).unwrap();
    commit_plain(&mut s, id, &mut t);
    assert_eq!(map(&mut s, id, &mut t, bid(2), 8, 8).released, None);
    assert_eq!((t.current(id), t.latest(id)), (Some(bid(1)), Some(bid(2))));
    assert_eq!(s.latch(id, &mut t).released, Some(bid(1)));
}

#[test]
fn reattaching_the_current_or_latest_buffer_is_buffer_busy() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    map(&mut s, id, &mut t, bid(1), 8, 8);
    assert_eq!(
        s.attach(Some(bid(1)), Scale120::ONE, &t),
        Err(ProtocolError::BufferBusy)
    );
    s.latch(id, &mut t);
    assert_eq!(
        s.attach(Some(bid(1)), Scale120::ONE, &t),
        Err(ProtocolError::BufferBusy),
        "single-buffered clients cannot update in M10"
    );
}

#[test]
fn latch_without_new_commit_releases_nothing() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    assert_eq!(s.latch(id, &mut t).released, None);
    map(&mut s, id, &mut t, bid(1), 8, 8);
    s.latch(id, &mut t);
    assert_eq!(s.latch(id, &mut t).released, None);
    assert_eq!(t.current(id), Some(bid(1)));
}

#[test]
fn remove_surface_releases_current_then_latest() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    assert_eq!(t.remove_surface(id), [None, None]);
    map(&mut s, id, &mut t, bid(1), 8, 8);
    s.latch(id, &mut t);
    map(&mut s, id, &mut t, bid(2), 8, 8);
    assert_eq!(t.remove_surface(id), [Some(bid(1)), Some(bid(2))]);
    assert!(t.is_empty());
    assert!(!t.is_busy(bid(1)) && !t.is_busy(bid(2)));

    let mut s = SurfaceState::new();
    map(&mut s, id, &mut t, bid(3), 8, 8);
    assert_eq!(t.remove_surface(id), [None, Some(bid(3))]);
}

#[test]
fn tracker_entries_are_per_surface_and_independent() {
    let mut a = SurfaceState::new();
    let mut b = SurfaceState::new();
    let mut t = Tracker::new();
    map(&mut a, sid(1), &mut t, bid(1), 8, 8);
    map(&mut b, sid(2), &mut t, bid(2), 8, 8);
    assert_eq!(t.len(), 2);
    assert_eq!(b.latch(sid(2), &mut t).released, None);
    assert_eq!(
        t.latest(sid(1)),
        Some(bid(1)),
        "latching B does not touch A"
    );
    assert_eq!(t.current(sid(2)), Some(bid(2)));
    assert_eq!(t.remove_surface(sid(1)), [None, Some(bid(1))]);
    assert_eq!(t.len(), 1);
}

#[test]
fn tracker_commit_rechecks_busy_and_capacity() {
    let mut t = BufferTracker::<1>::new();
    assert_eq!(t.commit(sid(1), PendingBuffer::Attach(bid(1))), Ok(None));
    assert_eq!(
        t.commit(sid(2), PendingBuffer::Attach(bid(1))),
        Err(ProtocolError::BufferBusy)
    );
    assert_eq!(
        t.commit(sid(2), PendingBuffer::Attach(bid(2))),
        Err(ProtocolError::LimitExceeded)
    );
    assert_eq!(t.commit(sid(2), PendingBuffer::Detach), Ok(None));
    assert_eq!(t.commit(sid(2), PendingBuffer::Unchanged), Ok(None));
    assert_eq!(t.composited(sid(2)), None);
    assert_eq!(t.len(), 1);
}

/// Property: random attach/commit/latch/destroy on three surfaces sharing six buffers.
/// Every busy buffer is released exactly once, busy state matches the model, no surface ever
/// holds more than `MAX_IN_FLIGHT_BUFFERS_PER_SURFACE`, and failed commits change nothing.
#[test]
fn property_buffer_handoff_conserves_buffers() {
    const SURFACES: usize = 3;
    const BUFFERS: u8 = 6;
    let mut rng = XorShift(0x5851_F42D_4C95_7F2D);
    let mut t = Tracker::new();
    let mut surfaces = [SurfaceState::new(); SURFACES];
    let mut owner: [Option<usize>; BUFFERS as usize] = [None; BUFFERS as usize];
    let mut became_busy = 0usize;
    let mut releases = 0usize;

    let mut release =
        |b: ClientBufferId, owner: &mut [Option<usize>; BUFFERS as usize], t: &Tracker| {
            let slot = usize::from(b.0.slot());
            assert!(owner[slot].is_some(), "{b:?} released while idle");
            owner[slot] = None;
            assert!(!t.is_busy(b), "{b:?} released but still busy");
            releases += 1;
        };

    for step in 0..20_000u32 {
        let si = rng.below(SURFACES as u64) as usize;
        let id = sid(si as u8);
        match rng.below(5) {
            0 => {
                let b = bid(rng.below(u64::from(BUFFERS)) as u8);
                let busy = owner[usize::from(b.0.slot())].is_some();
                let result = surfaces[si].attach(Some(b), Scale120::ONE, &t);
                assert_eq!(result.is_err(), busy, "step {step}");
            }
            1 => surfaces[si].attach(None, Scale120::ONE, &t).unwrap(),
            2 => {
                let pending = surfaces[si].pending().buffer();
                let before = (surfaces[si], t);
                let result = surfaces[si].commit(id, plain(), &mut t, None, |b| {
                    Ok(layout(8 + u32::from(b.0.slot()), 8))
                });
                match pending {
                    PendingBuffer::Attach(b) if owner[usize::from(b.0.slot())].is_some() => {
                        assert_eq!(result, Err(ProtocolError::BufferBusy));
                        assert_eq!((surfaces[si], t), before);
                    }
                    _ => {
                        let outcome = result.unwrap();
                        if let Some(r) = outcome.released {
                            release(r, &mut owner, &t);
                        }
                        if let PendingBuffer::Attach(b) = pending {
                            owner[usize::from(b.0.slot())] = Some(si);
                            became_busy += 1;
                        }
                    }
                }
            }
            3 => {
                if let Some(r) = surfaces[si].latch(id, &mut t).released {
                    release(r, &mut owner, &t);
                }
            }
            _ => {
                for r in t.remove_surface(id).into_iter().flatten() {
                    release(r, &mut owner, &t);
                }
                surfaces[si] = SurfaceState::new();
            }
        }
        for b in 0..BUFFERS {
            assert_eq!(
                t.is_busy(bid(b)),
                owner[usize::from(b)].is_some(),
                "step {step} {b}"
            );
        }
        for (i, _) in surfaces.iter().enumerate() {
            let held = owner.iter().filter(|o| **o == Some(i)).count();
            assert_eq!(t.busy_count(sid(i as u8)), held);
            assert!(held <= MAX_IN_FLIGHT_BUFFERS_PER_SURFACE);
        }
    }
    for i in 0..SURFACES {
        for r in t.remove_surface(sid(i as u8)).into_iter().flatten() {
            release(r, &mut owner, &t);
        }
    }
    assert!(t.is_empty());
    assert_eq!(
        releases, became_busy,
        "every busy buffer is released exactly once"
    );
}

// --- frame callbacks (architecture proof: FrameDone at most once) ---------------------------

#[test]
fn frame_callback_arms_once_fires_once() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    let outcome = s
        .commit(id, with_frame(), &mut t, None, no_resolve)
        .unwrap();
    assert!(outcome.frame_armed);
    assert!(
        outcome.schedule_composite,
        "a frame request alone schedules a composite"
    );
    assert_eq!(s.frame(), FrameState::Armed);

    let outcome = s
        .commit(id, with_frame(), &mut t, None, no_resolve)
        .unwrap();
    assert!(
        !outcome.frame_armed,
        "second request merges into the armed callback"
    );
    assert_eq!(s.present_completed(100, 1), None, "armed but not submitted");

    assert!(s.frame_submitted(5));
    assert_eq!(s.frame(), FrameState::AwaitingPresent { present_seq: 5 });
    assert!(!s.frame_submitted(6), "only Armed transitions");
    assert_eq!(s.frame(), FrameState::AwaitingPresent { present_seq: 5 });

    assert_eq!(s.present_completed(4, 10), None);
    assert_eq!(
        s.present_completed(5, 20),
        Some(FrameDone {
            presented_ns: 20,
            output_seq: 5
        })
    );
    assert_eq!(s.frame(), FrameState::Idle);
    assert_eq!(s.present_completed(5, 20), None);
    assert_eq!(s.present_completed(6, 30), None);
}

#[test]
fn frame_done_reports_the_observed_completion_sequence() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    s.commit(sid(1), with_frame(), &mut t, None, no_resolve)
        .unwrap();
    s.frame_submitted(3);
    assert_eq!(
        s.present_completed(7, 99),
        Some(FrameDone {
            presented_ns: 99,
            output_seq: 7
        })
    );
}

#[test]
fn frame_request_while_awaiting_present_merges_into_the_pending_callback() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    s.commit(id, with_frame(), &mut t, None, no_resolve)
        .unwrap();
    s.frame_submitted(1);
    let outcome = s
        .commit(id, with_frame(), &mut t, None, no_resolve)
        .unwrap();
    assert!(!outcome.frame_armed);
    assert_eq!(s.frame(), FrameState::AwaitingPresent { present_seq: 1 });
    assert!(s.present_completed(1, 1).is_some());
    assert_eq!(
        s.frame(),
        FrameState::Idle,
        "merged request does not re-arm"
    );
    assert!(!s.frame_submitted(2));
}

/// S3: there is no empty present and no immediate fire. A callback armed while a present is
/// already in flight rides that present's sequence; with nothing in flight it stays `Armed`
/// until the next real present.
#[test]
fn armed_callback_rides_an_in_flight_present_and_never_fires_without_one() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    s.commit(sid(1), with_frame(), &mut t, None, no_resolve)
        .unwrap();
    for seq in [0, 1, 2] {
        assert_eq!(s.present_completed(seq, 1), None);
        assert_eq!(s.frame(), FrameState::Armed, "no present, no FrameDone");
    }
    let in_flight = 41;
    assert!(s.frame_submitted(in_flight));
    assert_eq!(
        s.present_completed(in_flight, 500),
        Some(FrameDone {
            presented_ns: 500,
            output_seq: in_flight
        })
    );
}

#[test]
fn frame_submitted_while_idle_is_ignored() {
    let mut s = SurfaceState::new();
    assert!(!s.frame_submitted(1));
    assert_eq!(s.frame(), FrameState::Idle);
    assert_eq!(s.present_completed(1, 1), None);
}

#[test]
fn failed_commit_never_arms_a_frame() {
    let (mut s, mut t, mut w, _) = rich_fixture();
    assert!(s.frame_submitted(1));
    assert!(s.present_completed(1, 1).is_some());
    assert_eq!(s.frame(), FrameState::Idle);
    assert_rolls_back(
        &mut s,
        &mut t,
        Some(&mut w),
        with_ack(Serial(12345)),
        no_resolve,
        ProtocolError::SerialMismatch,
    );
    assert_eq!(s.frame(), FrameState::Idle);
}

#[test]
fn schedule_composite_reflects_geometry_damage_or_frame() {
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    assert!(
        map(&mut s, id, &mut t, bid(1), 16, 16).schedule_composite,
        "geometry"
    );
    s.latch(id, &mut t);
    assert!(
        !commit_plain(&mut s, id, &mut t).schedule_composite,
        "no-op commit"
    );
    s.damage(&[brect(0, 0, 1, 1)]).unwrap();
    assert!(
        commit_plain(&mut s, id, &mut t).schedule_composite,
        "damage"
    );
    s.damage(&[brect(100, 100, 1, 1)]).unwrap();
    assert!(
        !commit_plain(&mut s, id, &mut t).schedule_composite,
        "damage clipped away entirely"
    );
    assert!(
        s.commit(id, with_frame(), &mut t, None, no_resolve)
            .unwrap()
            .schedule_composite
    );
}

/// Property: under random commits, submissions and completions, `FrameDone` fires exactly once
/// per armed-and-submitted callback and never more often than callbacks were armed.
#[test]
fn property_frame_done_fires_at_most_once_per_armed_callback() {
    let mut rng = XorShift(0x1405_7B7E_F767_814F);
    let mut s = SurfaceState::new();
    let mut t = Tracker::new();
    let id = sid(1);
    let mut armed = 0u32;
    let mut fired = 0u32;
    let mut submitted_seq = 0u64;
    let mut completed_seq = 0u64;
    for _ in 0..20_000 {
        match rng.below(3) {
            0 => {
                let request_frame = rng.below(2) == 0;
                let was_idle = s.frame() == FrameState::Idle;
                let outcome = s
                    .commit(
                        id,
                        CommitRequest {
                            request_frame,
                            ..plain()
                        },
                        &mut t,
                        None,
                        no_resolve,
                    )
                    .unwrap();
                assert_eq!(outcome.frame_armed, request_frame && was_idle);
                armed += u32::from(outcome.frame_armed);
            }
            1 => {
                submitted_seq += 1;
                let was_armed = s.frame() == FrameState::Armed;
                assert_eq!(s.frame_submitted(submitted_seq), was_armed);
            }
            _ => {
                if completed_seq < submitted_seq {
                    completed_seq += 1 + rng.below(submitted_seq - completed_seq);
                }
                let awaiting = match s.frame() {
                    FrameState::AwaitingPresent { present_seq } => Some(present_seq),
                    _ => None,
                };
                let done = s.present_completed(completed_seq, completed_seq * 10);
                match awaiting {
                    Some(seq) if completed_seq >= seq => {
                        let done = done.expect("due callback must fire");
                        assert_eq!(done.output_seq, completed_seq);
                        assert!(done.output_seq >= seq);
                        fired += 1;
                    }
                    _ => assert_eq!(done, None),
                }
            }
        }
        assert!(fired <= armed);
        assert!(armed - fired <= 1, "at most one callback outstanding");
    }
    if s.frame() == FrameState::Armed {
        submitted_seq += 1;
        s.frame_submitted(submitted_seq);
    }
    if s.present_completed(submitted_seq, 1).is_some() {
        fired += 1;
    }
    assert_eq!(fired, armed);
}

// --- role assignment ----------------------------------------------------------------------

#[test]
fn assign_role_records_role_and_layer_and_is_one_shot() {
    let mut s = SurfaceState::new();
    assert_eq!(
        s.assign_role(SurfaceRole::Toplevel, connect(), ParentRef::Absent),
        Ok(Layer::Windows)
    );
    assert_eq!(
        s.role(),
        Some(AssignedRole {
            role: SurfaceRole::Toplevel,
            layer: Layer::Windows
        })
    );
    let before = s;
    assert_eq!(
        s.assign_role(SurfaceRole::Toplevel, connect(), ParentRef::Absent),
        Err(ProtocolError::RoleAlreadyAssigned)
    );
    assert_eq!(
        s.assign_role(
            SurfaceRole::Cursor,
            RoleGrant::from_rights_bits(0),
            ParentRef::Absent
        ),
        Err(ProtocolError::RoleAlreadyAssigned),
        "RoleAlreadyAssigned precedes every other check"
    );
    assert_eq!(s, before);
}

/// Architecture proof: unauthorised role.
#[test]
fn failed_role_assignment_leaves_the_surface_role_less() {
    let mut s = SurfaceState::new();
    assert_eq!(
        s.assign_role(SurfaceRole::Background, connect(), ParentRef::Absent),
        Err(ProtocolError::RoleForbidden)
    );
    assert_eq!(
        s.assign_role(
            SurfaceRole::Toplevel,
            RoleGrant::from_rights_bits(GFX_SHELL_BIT),
            ParentRef::Absent
        ),
        Err(ProtocolError::RoleForbidden)
    );
    assert_eq!(
        s.assign_role(SurfaceRole::Popup, connect(), ParentRef::Absent),
        Err(ProtocolError::InvalidParent)
    );
    assert_eq!(
        s.assign_role(SurfaceRole::Subsurface, connect(), ParentRef::Absent),
        Err(ProtocolError::UnsupportedFeature)
    );
    assert_eq!(s.role(), None);
    let shell = RoleGrant::from_rights_bits(GFX_CONNECT_BIT | GFX_SHELL_BIT);
    assert_eq!(
        s.assign_role(SurfaceRole::Background, shell, ParentRef::Absent),
        Ok(Layer::Background)
    );
}

#[test]
fn popup_role_checks_its_resolved_parent() {
    let mut s = SurfaceState::new();
    let parent = ParentRef::Surface {
        role: Some(SurfaceRole::Toplevel),
        is_self: false,
    };
    assert_eq!(
        s.assign_role(SurfaceRole::Popup, connect(), parent),
        Ok(Layer::Windows)
    );
    let mut s = SurfaceState::new();
    let self_parent = ParentRef::Surface {
        role: None,
        is_self: true,
    };
    assert_eq!(
        s.assign_role(SurfaceRole::Popup, connect(), self_parent),
        Err(ProtocolError::InvalidParent)
    );
}
