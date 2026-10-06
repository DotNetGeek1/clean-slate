//! Stacking and placement of role-assigned surfaces in global logical space.
//!
//! Entries are keyed by [`SurfaceKey`] (generation-safe connection id plus object id, S1), never
//! by object id alone. Order is explicit: `(layer, z)` ascending is bottom to top, where `layer`
//! comes from `validate_role` and `z` is the window-manager stacking counter.

use clean_slate_graphics::geometry::{Point, Rect};
use clean_slate_graphics::ids::SurfaceId;
use clean_slate_graphics::limits::MAX_SURFACES;
use clean_slate_graphics::role::{Layer, SurfaceRole};
use clean_slate_native_abi::ConnectionId;

/// Compositor-wide surface identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SurfaceKey {
    pub connection: ConnectionId,
    pub surface: SurfaceId,
}

/// One surface in the scene.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SceneEntry {
    pub key: SurfaceKey,
    /// Index of the owning client slot.
    pub client: usize,
    /// `None` until `AssignRole`; role-less surfaces are never composited.
    pub role: Option<SurfaceRole>,
    pub layer: Layer,
    pub z: u64,
    /// Global logical origin; `None` until the window manager places the surface on first map.
    pub origin: Option<Point>,
    /// Screen rect as last composited, used to expose damage on move, resize, hide or destroy.
    pub shown: Option<Rect>,
}

/// Bounded scene: at most [`MAX_SURFACES`] entries, one per live surface of any connection.
pub struct Scene {
    entries: [Option<SceneEntry>; MAX_SURFACES],
    next_z: u64,
}

/// Bottom-to-top order of live scene entries, as indices into the scene.
#[derive(Clone, Copy, Debug)]
pub struct StackOrder {
    indices: [u8; MAX_SURFACES],
    len: usize,
}

impl StackOrder {
    pub fn as_slice(&self) -> &[u8] {
        &self.indices[..self.len]
    }
}

impl Scene {
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_SURFACES],
            next_z: 1,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn take_z(&mut self) -> u64 {
        let z = self.next_z;
        self.next_z = self.next_z.saturating_add(1);
        z
    }

    /// Inserts a role-less entry. `false` if the scene is full, which cannot happen while the
    /// global surface budget is enforced.
    pub fn insert(&mut self, key: SurfaceKey, client: usize) -> bool {
        if self.find(key).is_some() {
            return true;
        }
        let z = self.take_z();
        match self.entries.iter_mut().find(|e| e.is_none()) {
            Some(slot) => {
                *slot = Some(SceneEntry {
                    key,
                    client,
                    role: None,
                    layer: Layer::Windows,
                    z,
                    origin: None,
                    shown: None,
                });
                true
            }
            None => false,
        }
    }

    /// Records the validated role and stacks the surface at the top of its layer.
    pub fn set_role(&mut self, key: SurfaceKey, role: SurfaceRole, layer: Layer) -> bool {
        let z = self.take_z();
        match self.find(key).and_then(|i| self.entries[i].as_mut()) {
            Some(entry) => {
                entry.role = Some(role);
                entry.layer = layer;
                entry.z = z;
                true
            }
            None => false,
        }
    }

    /// Live entries with their scene index, in storage (not stacking) order.
    pub fn iter(&self) -> impl Iterator<Item = (usize, &SceneEntry)> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.as_ref().map(|e| (i, e)))
    }

    pub fn find(&self, key: SurfaceKey) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| matches!(e, Some(entry) if entry.key == key))
    }

    pub fn get(&self, index: usize) -> Option<&SceneEntry> {
        self.entries.get(index).and_then(Option::as_ref)
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut SceneEntry> {
        self.entries.get_mut(index).and_then(Option::as_mut)
    }

    pub fn entry(&self, key: SurfaceKey) -> Option<&SceneEntry> {
        self.find(key).and_then(|i| self.get(i))
    }

    /// Removes `key`; returns the rect it occupied on screen, which is now exposed.
    pub fn remove(&mut self, key: SurfaceKey) -> Option<Option<Rect>> {
        let index = self.find(key)?;
        let entry = self.entries[index].take()?;
        Some(entry.shown)
    }

    /// Removes every entry of `connection`, calling `exposed` with each shown rect.
    pub fn remove_connection(&mut self, connection: ConnectionId, mut exposed: impl FnMut(Rect)) {
        for slot in &mut self.entries {
            if let Some(entry) = slot {
                if entry.key.connection == connection {
                    if let Some(rect) = entry.shown {
                        exposed(rect);
                    }
                    *slot = None;
                }
            }
        }
    }

    /// Moves `key` to the top of its layer.
    pub fn raise(&mut self, key: SurfaceKey) -> bool {
        let z = self.take_z();
        match self.find(key).and_then(|i| self.entries[i].as_mut()) {
            Some(entry) => {
                entry.z = z;
                true
            }
            None => false,
        }
    }

    pub fn set_origin(&mut self, key: SurfaceKey, origin: Point) -> bool {
        match self.find(key).and_then(|i| self.entries[i].as_mut()) {
            Some(entry) => {
                entry.origin = Some(origin);
                true
            }
            None => false,
        }
    }

    /// Live entries sorted bottom to top by `(layer, z)`.
    pub fn order(&self) -> StackOrder {
        let mut order = StackOrder {
            indices: [0; MAX_SURFACES],
            len: 0,
        };
        for (index, entry) in self.entries.iter().enumerate() {
            let Some(entry) = entry else {
                continue;
            };
            let rank = |e: &SceneEntry| (e.layer.as_u8(), e.z);
            let mut at = order.len;
            while at > 0 {
                let Some(prev) = self.entries[usize::from(order.indices[at - 1])].as_ref() else {
                    break;
                };
                if rank(prev) <= rank(entry) {
                    break;
                }
                order.indices[at] = order.indices[at - 1];
                at -= 1;
            }
            order.indices[at] = index as u8;
            order.len += 1;
        }
        order
    }
}

impl Default for Scene {
    fn default() -> Self {
        Self::new()
    }
}
