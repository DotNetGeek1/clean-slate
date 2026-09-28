//! Double-buffered surface state, buffer in-flight rules and frame callbacks (Stage D).

use crate::geometry::{BufferRect, Point, Rect, RectSet, Scale120, Size};
use crate::ids::{ClientBufferId, Serial, SurfaceId};
use crate::limits::{
    MAX_BUFFERS_PER_CLIENT, MAX_DAMAGE_RECTS_PER_COMMIT, MAX_IN_FLIGHT_BUFFERS_PER_SURFACE,
    MAX_REGION_RECTS, MAX_SURFACE_EXTENT,
};
use crate::pixel::{BufferLayout, ColorSpace};
use crate::protocol::request::{DAMAGE_RECTS_PER_FRAME, REGION_RECTS_PER_FRAME};
use crate::protocol::ProtocolError;
use crate::role::{validate_parent, validate_role, Layer, ParentRef, RoleGrant, SurfaceRole};
use crate::window::ConfigureState;

pub type DamageSet = RectSet<MAX_DAMAGE_RECTS_PER_COMMIT>;
pub type RegionSet = RectSet<MAX_REGION_RECTS>;

/// `[0, MAX_SURFACE_EXTENT)²`: request-time clip bound for damage and regions.
pub const EXTENT_RECT: Rect = Rect {
    x: 0,
    y: 0,
    width: MAX_SURFACE_EXTENT,
    height: MAX_SURFACE_EXTENT,
};

const EXTENT_SIZE: Size = Size {
    width: MAX_SURFACE_EXTENT,
    height: MAX_SURFACE_EXTENT,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingBuffer {
    Unchanged,
    Attach(ClientBufferId),
    Detach,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpaqueRegion {
    /// Empty set = not opaque.
    Rects(RegionSet),
    /// Overflowed: not opaque; appends ignored until `replace = true`.
    Degraded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputRegion {
    WholeSurface,
    Rects(RegionSet),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommittedInputRegion {
    WholeSurface,
    Rects(RegionSet),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingState {
    buffer: PendingBuffer,
    scale: Scale120,
    damage: DamageSet,
    opaque: OpaqueRegion,
    input: InputRegion,
}

impl Default for PendingState {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingState {
    pub const fn new() -> Self {
        Self {
            buffer: PendingBuffer::Unchanged,
            scale: Scale120::ONE,
            damage: DamageSet::new(),
            opaque: OpaqueRegion::Rects(RegionSet::new()),
            input: InputRegion::WholeSurface,
        }
    }

    pub fn buffer(&self) -> PendingBuffer {
        self.buffer
    }

    pub fn scale(&self) -> Scale120 {
        self.scale
    }

    pub fn damage(&self) -> &DamageSet {
        &self.damage
    }

    pub fn opaque(&self) -> &OpaqueRegion {
        &self.opaque
    }

    pub fn input(&self) -> &InputRegion {
        &self.input
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommittedBuffer {
    pub id: ClientBufferId,
    pub layout: BufferLayout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommittedState {
    buffer: Option<CommittedBuffer>,
    scale: Scale120,
    color_space: ColorSpace,
    opaque: RegionSet,
    input: CommittedInputRegion,
    commit_count: u64,
}

impl Default for CommittedState {
    fn default() -> Self {
        Self::new()
    }
}

impl CommittedState {
    pub const fn new() -> Self {
        Self {
            buffer: None,
            scale: Scale120::ONE,
            color_space: ColorSpace::Srgb,
            opaque: RegionSet::new(),
            input: CommittedInputRegion::WholeSurface,
            commit_count: 0,
        }
    }

    pub fn buffer(&self) -> Option<CommittedBuffer> {
        self.buffer
    }

    pub fn is_mapped(&self) -> bool {
        self.buffer.is_some()
    }

    /// Buffer extent (scale 1.0 in M10); `0×0` when unmapped.
    pub fn size(&self) -> Size {
        match self.buffer {
            Some(b) => Size {
                width: b.layout.width(),
                height: b.layout.height(),
            },
            None => Size {
                width: 0,
                height: 0,
            },
        }
    }

    pub fn scale(&self) -> Scale120 {
        self.scale
    }

    pub fn color_space(&self) -> ColorSpace {
        self.color_space
    }

    /// Surface-local, clipped to [`Self::size`]; empty = not opaque.
    pub fn opaque(&self) -> &RegionSet {
        &self.opaque
    }

    pub fn input(&self) -> &CommittedInputRegion {
        &self.input
    }

    pub fn commit_count(&self) -> u64 {
        self.commit_count
    }

    /// Surface-local hit test: inside the surface extent and the committed input region.
    pub fn accepts_input_at(&self, point: Point) -> bool {
        let size = self.size();
        let inside = |r: &Rect| {
            let x = i64::from(point.x);
            let y = i64::from(point.y);
            x >= i64::from(r.x)
                && y >= i64::from(r.y)
                && x < i64::from(r.x) + i64::from(r.width)
                && y < i64::from(r.y) + i64::from(r.height)
        };
        let surface = Rect {
            x: 0,
            y: 0,
            width: size.width,
            height: size.height,
        };
        if !inside(&surface) {
            return false;
        }
        match &self.input {
            CommittedInputRegion::WholeSurface => true,
            CommittedInputRegion::Rects(set) => set.rects().iter().any(inside),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameState {
    Idle,
    Armed,
    AwaitingPresent { present_seq: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameDone {
    pub presented_ns: u64,
    pub output_seq: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitRequest {
    pub request_frame: bool,
    pub color_space: ColorSpace,
    pub ack: Option<Serial>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitOutcome {
    /// Superseded committed-but-not-composited buffer; post `BufferReleased` now.
    pub released: Option<ClientBufferId>,
    /// Serial acknowledged atomically by `Commit.ack`.
    pub acked: Option<Serial>,
    /// This commit moved the frame callback `Idle → Armed`.
    pub frame_armed: bool,
    /// Geometry changed, damage non-empty, or a frame was requested.
    pub schedule_composite: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Latch {
    /// Previously displayed buffer, now idle; post `BufferReleased`.
    pub released: Option<ClientBufferId>,
    /// Buffer-space damage accumulated over every commit since the previous latch.
    pub damage: DamageSet,
    /// Mapping or buffer extent changed since the previous latch.
    pub geometry_changed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssignedRole {
    pub role: SurfaceRole,
    pub layer: Layer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurfaceState {
    role: Option<AssignedRole>,
    pending: PendingState,
    committed: CommittedState,
    frame: FrameState,
    unlatched_damage: DamageSet,
    unlatched_geometry: bool,
}

impl Default for SurfaceState {
    fn default() -> Self {
        Self::new()
    }
}

fn clip_region_rects(
    rects: &[Rect],
) -> Result<([Rect; REGION_RECTS_PER_FRAME], usize), ProtocolError> {
    if rects.len() > REGION_RECTS_PER_FRAME {
        return Err(ProtocolError::InvalidRegion);
    }
    let mut out = [Rect {
        x: 0,
        y: 0,
        width: 0,
        height: 0,
    }; REGION_RECTS_PER_FRAME];
    let mut n = 0;
    for r in rects {
        match r.clip_to(EXTENT_SIZE) {
            Err(_) => return Err(ProtocolError::InvalidRegion),
            Ok(None) => {}
            Ok(Some(c)) => {
                out[n] = c;
                n += 1;
            }
        }
    }
    Ok((out, n))
}

fn clip_set_to(set: &RegionSet, size: Size) -> RegionSet {
    let mut out = RegionSet::new();
    for r in set.rects() {
        if let Ok(Some(c)) = r.clip_to(size) {
            let _ = out.insert(c);
        }
    }
    out
}

impl SurfaceState {
    pub const fn new() -> Self {
        Self {
            role: None,
            pending: PendingState::new(),
            committed: CommittedState::new(),
            frame: FrameState::Idle,
            unlatched_damage: DamageSet::new(),
            unlatched_geometry: false,
        }
    }

    pub fn role(&self) -> Option<AssignedRole> {
        self.role
    }

    pub fn pending(&self) -> &PendingState {
        &self.pending
    }

    pub fn committed(&self) -> &CommittedState {
        &self.committed
    }

    pub fn frame(&self) -> FrameState {
        self.frame
    }

    /// Damage accumulated by commits since the last [`Self::latch`].
    pub fn unlatched_damage(&self) -> &DamageSet {
        &self.unlatched_damage
    }

    /// `RoleAlreadyAssigned` → `validate_role` → `validate_parent`; a failure leaves the
    /// surface role-less.
    pub fn assign_role(
        &mut self,
        role: SurfaceRole,
        grant: RoleGrant,
        parent: ParentRef,
    ) -> Result<Layer, ProtocolError> {
        if self.role.is_some() {
            return Err(ProtocolError::RoleAlreadyAssigned);
        }
        let layer = validate_role(role, grant)?;
        validate_parent(role, parent)?;
        self.role = Some(AssignedRole { role, layer });
        Ok(layer)
    }

    /// `InvalidScale` (scale ≠ 1.0) → `BufferBusy`. On error pending is unchanged.
    pub fn attach<const N: usize>(
        &mut self,
        buffer: Option<ClientBufferId>,
        scale: Scale120,
        tracker: &BufferTracker<N>,
    ) -> Result<(), ProtocolError> {
        if scale != Scale120::ONE {
            return Err(ProtocolError::InvalidScale);
        }
        if let Some(b) = buffer {
            if tracker.is_busy(b) {
                return Err(ProtocolError::BufferBusy);
            }
        }
        self.pending.buffer = match buffer {
            Some(b) => PendingBuffer::Attach(b),
            None => PendingBuffer::Detach,
        };
        self.pending.scale = scale;
        Ok(())
    }

    /// Accumulates buffer-space damage, clipped to the extent square; zero-area and fully
    /// outside rects are dropped; overflow collapses to the bounding box.
    pub fn damage(&mut self, rects: &[BufferRect]) -> Result<(), ProtocolError> {
        if rects.len() > DAMAGE_RECTS_PER_FRAME {
            return Err(ProtocolError::InvalidDamage);
        }
        let mut damage = self.pending.damage;
        for r in rects {
            if let Some(c) = r.clip_to_extent(MAX_SURFACE_EXTENT, MAX_SURFACE_EXTENT) {
                damage
                    .insert(c.to_rect())
                    .map_err(|_| ProtocolError::InvalidDamage)?;
            }
        }
        self.pending.damage = damage;
        Ok(())
    }

    pub fn set_opaque_region(
        &mut self,
        rects: &[Rect],
        replace: bool,
    ) -> Result<(), ProtocolError> {
        let (clipped, n) = clip_region_rects(rects)?;
        let base = if replace {
            OpaqueRegion::Rects(RegionSet::new())
        } else {
            self.pending.opaque
        };
        self.pending.opaque = match base {
            OpaqueRegion::Degraded => OpaqueRegion::Degraded,
            OpaqueRegion::Rects(mut set) => {
                let mut result = None;
                for r in &clipped[..n] {
                    if set.len() == MAX_REGION_RECTS {
                        result = Some(OpaqueRegion::Degraded);
                        break;
                    }
                    let _ = set.insert(*r);
                }
                result.unwrap_or(OpaqueRegion::Rects(set))
            }
        };
        Ok(())
    }

    pub fn set_input_region(&mut self, rects: &[Rect], replace: bool) -> Result<(), ProtocolError> {
        let (clipped, n) = clip_region_rects(rects)?;
        if clipped[..n].contains(&EXTENT_RECT) {
            self.pending.input = InputRegion::WholeSurface;
            return Ok(());
        }
        let base = if replace {
            InputRegion::Rects(RegionSet::new())
        } else {
            self.pending.input
        };
        self.pending.input = match base {
            InputRegion::WholeSurface => InputRegion::WholeSurface,
            InputRegion::Rects(mut set) => {
                if set.len() + n > MAX_REGION_RECTS {
                    return Err(ProtocolError::InvalidRegion);
                }
                for r in &clipped[..n] {
                    let _ = set.insert(*r);
                }
                InputRegion::Rects(set)
            }
        };
        Ok(())
    }

    /// Atomic commit. Validation order (first failure wins, nothing mutated):
    /// 1. `ack`: no window → `SerialMismatch`; `window.check_ack` → `SerialMismatch`.
    /// 2. window present, never configured, `ack` is `None` → `NotConfigured`.
    /// 3. `PendingBuffer::Attach(b)`: `resolve(b)` error passed through unchanged.
    /// 4. `tracker.check_commit`: `BufferBusy`, then `LimitExceeded`.
    pub fn commit<const N: usize, F>(
        &mut self,
        surface: SurfaceId,
        request: CommitRequest,
        tracker: &mut BufferTracker<N>,
        window: Option<&mut ConfigureState>,
        resolve: F,
    ) -> Result<CommitOutcome, ProtocolError>
    where
        F: FnOnce(ClientBufferId) -> Result<BufferLayout, ProtocolError>,
    {
        match (&window, request.ack) {
            (None, Some(_)) => return Err(ProtocolError::SerialMismatch),
            (Some(w), Some(s)) => w.check_ack(s)?,
            (Some(w), None) if !w.is_configured() => return Err(ProtocolError::NotConfigured),
            _ => {}
        }
        let new_buffer = match self.pending.buffer {
            PendingBuffer::Unchanged => self.committed.buffer,
            PendingBuffer::Detach => None,
            PendingBuffer::Attach(id) => Some(CommittedBuffer {
                id,
                layout: resolve(id)?,
            }),
        };
        tracker.check_commit(surface, self.pending.buffer)?;

        // Apply (infallible from here on).
        let acked = match (window, request.ack) {
            (Some(w), Some(s)) => w.ack(s).ok().map(|_| s),
            _ => None,
        };
        let released = tracker.commit(surface, self.pending.buffer).unwrap_or(None);

        let old_size = self
            .committed
            .buffer
            .map(|b| (b.layout.width(), b.layout.height()));
        let new_size = new_buffer.map(|b| (b.layout.width(), b.layout.height()));
        let geometry_changed = old_size != new_size;
        let size = match new_size {
            Some((width, height)) => Size { width, height },
            None => Size {
                width: 0,
                height: 0,
            },
        };

        let mut commit_damage = DamageSet::new();
        if new_size.is_some() {
            if geometry_changed {
                let _ = commit_damage.insert(Rect {
                    x: 0,
                    y: 0,
                    width: size.width,
                    height: size.height,
                });
            } else {
                for r in self.pending.damage.rects() {
                    if let Ok(Some(c)) = r.clip_to(size) {
                        let _ = commit_damage.insert(c);
                    }
                }
            }
        }
        for r in commit_damage.rects() {
            let _ = self.unlatched_damage.insert(*r);
        }
        self.unlatched_geometry |= geometry_changed;

        self.committed.buffer = new_buffer;
        self.committed.scale = self.pending.scale;
        self.committed.color_space = request.color_space;
        self.committed.opaque = match &self.pending.opaque {
            OpaqueRegion::Rects(set) => clip_set_to(set, size),
            OpaqueRegion::Degraded => RegionSet::new(),
        };
        self.committed.input = match &self.pending.input {
            InputRegion::Rects(set) => CommittedInputRegion::Rects(clip_set_to(set, size)),
            InputRegion::WholeSurface => CommittedInputRegion::WholeSurface,
        };
        self.committed.commit_count += 1;

        self.pending.buffer = PendingBuffer::Unchanged;
        self.pending.damage = DamageSet::new();

        let frame_armed = request.request_frame && self.frame == FrameState::Idle;
        if frame_armed {
            self.frame = FrameState::Armed;
        }

        Ok(CommitOutcome {
            released,
            acked,
            frame_armed,
            schedule_composite: geometry_changed
                || !commit_damage.is_empty()
                || request.request_frame,
        })
    }

    /// Start of composition: promotes the latest committed buffer, releases the previously
    /// displayed one, and hands over accumulated damage.
    pub fn latch<const N: usize>(
        &mut self,
        surface: SurfaceId,
        tracker: &mut BufferTracker<N>,
    ) -> Latch {
        let latch = Latch {
            released: tracker.composited(surface),
            damage: self.unlatched_damage,
            geometry_changed: self.unlatched_geometry,
        };
        self.unlatched_damage = DamageSet::new();
        self.unlatched_geometry = false;
        latch
    }

    /// `Armed → AwaitingPresent(present_seq)`; `true` iff it transitioned.
    pub fn frame_submitted(&mut self, present_seq: u64) -> bool {
        if self.frame == FrameState::Armed {
            self.frame = FrameState::AwaitingPresent { present_seq };
            true
        } else {
            false
        }
    }

    /// Fires `FrameDone` once `completed_seq ≥ present_seq`.
    pub fn present_completed(
        &mut self,
        completed_seq: u64,
        completed_ns: u64,
    ) -> Option<FrameDone> {
        match self.frame {
            FrameState::AwaitingPresent { present_seq } if completed_seq >= present_seq => {
                self.frame = FrameState::Idle;
                Some(FrameDone {
                    presented_ns: completed_ns,
                    output_seq: completed_seq,
                })
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Latest {
    Empty,
    Buffer(ClientBufferId),
    Detach,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Tracked {
    surface: SurfaceId,
    current: Option<ClientBufferId>,
    latest: Latest,
}

/// Connection-wide busy-buffer tracker. One entry per surface that holds at least one busy
/// buffer; `current` = composited (compositor may re-read), `latest` = committed, not yet
/// composited. Busy buffers per surface ≤ `MAX_IN_FLIGHT_BUFFERS_PER_SURFACE` by construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferTracker<const N: usize> {
    entries: [Option<Tracked>; N],
}

/// Sized so a compositor that enforces `MAX_BUFFERS_PER_CLIENT` never sees `LimitExceeded`.
pub type ConnectionBufferTracker = BufferTracker<MAX_BUFFERS_PER_CLIENT>;

impl<const N: usize> Default for BufferTracker<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> BufferTracker<N> {
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    fn find(&self, surface: SurfaceId) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| matches!(e, Some(t) if t.surface == surface))
    }

    /// Surfaces currently holding busy buffers.
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_busy(&self, buffer: ClientBufferId) -> bool {
        self.entries
            .iter()
            .flatten()
            .any(|t| t.current == Some(buffer) || t.latest == Latest::Buffer(buffer))
    }

    pub fn current(&self, surface: SurfaceId) -> Option<ClientBufferId> {
        self.find(surface)
            .and_then(|i| self.entries[i])
            .and_then(|t| t.current)
    }

    pub fn latest(&self, surface: SurfaceId) -> Option<ClientBufferId> {
        match self.find(surface).and_then(|i| self.entries[i]) {
            Some(Tracked {
                latest: Latest::Buffer(b),
                ..
            }) => Some(b),
            _ => None,
        }
    }

    pub fn busy_count(&self, surface: SurfaceId) -> usize {
        usize::from(self.current(surface).is_some()) + usize::from(self.latest(surface).is_some())
    }

    /// `Attach(b)`: `BufferBusy` if `b` is busy anywhere on the connection, then
    /// `LimitExceeded` if `surface` has no entry and all `N` are in use.
    pub fn check_commit(
        &self,
        surface: SurfaceId,
        pending: PendingBuffer,
    ) -> Result<(), ProtocolError> {
        if let PendingBuffer::Attach(b) = pending {
            if self.is_busy(b) {
                return Err(ProtocolError::BufferBusy);
            }
            if self.find(surface).is_none() && self.entries.iter().all(Option::is_some) {
                return Err(ProtocolError::LimitExceeded);
            }
        }
        Ok(())
    }

    /// Returns the superseded `latest` buffer, if any.
    pub fn commit(
        &mut self,
        surface: SurfaceId,
        pending: PendingBuffer,
    ) -> Result<Option<ClientBufferId>, ProtocolError> {
        self.check_commit(surface, pending)?;
        match pending {
            PendingBuffer::Unchanged => Ok(None),
            PendingBuffer::Attach(b) => {
                let index = match self.find(surface) {
                    Some(i) => i,
                    None => {
                        let i = self
                            .entries
                            .iter()
                            .position(Option::is_none)
                            .ok_or(ProtocolError::LimitExceeded)?;
                        self.entries[i] = Some(Tracked {
                            surface,
                            current: None,
                            latest: Latest::Empty,
                        });
                        i
                    }
                };
                let Some(t) = self.entries[index].as_mut() else {
                    return Ok(None);
                };
                let released = match t.latest {
                    Latest::Buffer(old) => Some(old),
                    _ => None,
                };
                t.latest = Latest::Buffer(b);
                Ok(released)
            }
            PendingBuffer::Detach => {
                let Some(index) = self.find(surface) else {
                    return Ok(None);
                };
                let Some(t) = self.entries[index].as_mut() else {
                    return Ok(None);
                };
                let released = match t.latest {
                    Latest::Buffer(old) => Some(old),
                    _ => None,
                };
                if t.current.is_some() {
                    t.latest = Latest::Detach;
                } else {
                    self.entries[index] = None;
                }
                Ok(released)
            }
        }
    }

    /// Latch: `latest` becomes `current`; returns the previous `current` if it changed.
    pub fn composited(&mut self, surface: SurfaceId) -> Option<ClientBufferId> {
        let index = self.find(surface)?;
        let t = self.entries[index].as_mut()?;
        match t.latest {
            Latest::Empty => None,
            Latest::Buffer(b) => {
                let released = t.current;
                t.current = Some(b);
                t.latest = Latest::Empty;
                released
            }
            Latest::Detach => {
                let released = t.current;
                self.entries[index] = None;
                released
            }
        }
    }

    /// Surface destroyed: every busy buffer becomes idle, returned as `[current, latest]`.
    pub fn remove_surface(
        &mut self,
        surface: SurfaceId,
    ) -> [Option<ClientBufferId>; MAX_IN_FLIGHT_BUFFERS_PER_SURFACE] {
        let Some(index) = self.find(surface) else {
            return [None, None];
        };
        let Some(t) = self.entries[index].take() else {
            return [None, None];
        };
        let latest = match t.latest {
            Latest::Buffer(b) => Some(b),
            _ => None,
        };
        [t.current, latest]
    }
}

#[cfg(test)]
mod tests;
