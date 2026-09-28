//! Per-connection protocol object table and compositor-wide object budgets (Stage D).
//!
//! Surfaces, windows and client buffers of one connection share a single generational id
//! space, so every id names at most one object of one kind and a wrong-kind id is detected
//! deterministically. Ids are meaningful only in their own connection's table; retirement
//! exhausts only that table, never another connection's.

use crate::error::LookupError;
use crate::ids::{ClientBufferId, GenSlotTable, ObjectId, SurfaceId, WindowId};
use crate::limits::{
    MAX_BUFFERS_PER_CLIENT, MAX_OBJECTS_PER_CLIENT, MAX_REGISTERED_BUFFERS, MAX_SURFACES,
    MAX_SURFACES_PER_CLIENT, MAX_WINDOWS, MAX_WINDOWS_PER_CLIENT,
};
use crate::protocol::ProtocolError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    Surface,
    Window,
    Buffer,
}

impl ObjectKind {
    const fn index(self) -> usize {
        match self {
            Self::Surface => 0,
            Self::Window => 1,
            Self::Buffer => 2,
        }
    }

    pub const fn per_client_limit(self) -> usize {
        match self {
            Self::Surface => MAX_SURFACES_PER_CLIENT,
            Self::Window => MAX_WINDOWS_PER_CLIENT,
            Self::Buffer => MAX_BUFFERS_PER_CLIENT,
        }
    }

    pub const fn global_limit(self) -> usize {
        match self {
            Self::Surface => MAX_SURFACES,
            Self::Window => MAX_WINDOWS,
            Self::Buffer => MAX_REGISTERED_BUFFERS,
        }
    }
}

/// `Invalid` → `InvalidObject`; `Stale` and `Retired` → `StaleObject`.
pub const fn lookup_error_code(error: LookupError) -> ProtocolError {
    match error {
        LookupError::Invalid => ProtocolError::InvalidObject,
        LookupError::Stale | LookupError::Retired => ProtocolError::StaleObject,
    }
}

/// Compositor-wide object counts (`MAX_SURFACES`, `MAX_WINDOWS`, `MAX_REGISTERED_BUFFERS`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GlobalBudget {
    used: [usize; 3],
}

impl GlobalBudget {
    pub const fn new() -> Self {
        Self { used: [0; 3] }
    }

    pub const fn used(&self, kind: ObjectKind) -> usize {
        self.used[kind.index()]
    }
}

enum Entry<S, W, B> {
    Surface(S),
    Window(W),
    Buffer(B),
}

impl<S, W, B> Entry<S, W, B> {
    const fn kind(&self) -> ObjectKind {
        match self {
            Self::Surface(_) => ObjectKind::Surface,
            Self::Window(_) => ObjectKind::Window,
            Self::Buffer(_) => ObjectKind::Buffer,
        }
    }
}

/// One connection's objects. Capacity [`MAX_OBJECTS_PER_CLIENT`] = sum of the per-kind caps,
/// so no kind can starve another.
pub struct ObjectTable<S, W, B> {
    table: GenSlotTable<Entry<S, W, B>, MAX_OBJECTS_PER_CLIENT>,
    counts: [usize; 3],
}

impl<S, W, B> Default for ObjectTable<S, W, B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S, W, B> ObjectTable<S, W, B> {
    pub const fn new() -> Self {
        Self {
            table: GenSlotTable::new(),
            counts: [0; 3],
        }
    }

    pub const fn count(&self, kind: ObjectKind) -> usize {
        self.counts[kind.index()]
    }

    fn insert(
        &mut self,
        budget: &mut GlobalBudget,
        entry: Entry<S, W, B>,
    ) -> Result<ObjectId, ProtocolError> {
        let kind = entry.kind();
        if self.counts[kind.index()] >= kind.per_client_limit()
            || budget.used[kind.index()] >= kind.global_limit()
        {
            return Err(ProtocolError::LimitExceeded);
        }
        let id = self
            .table
            .insert(entry)
            .map_err(|_| ProtocolError::LimitExceeded)?;
        self.counts[kind.index()] += 1;
        budget.used[kind.index()] += 1;
        Ok(id)
    }

    pub fn insert_surface(
        &mut self,
        budget: &mut GlobalBudget,
        value: S,
    ) -> Result<SurfaceId, ProtocolError> {
        self.insert(budget, Entry::Surface(value)).map(SurfaceId)
    }

    pub fn insert_window(
        &mut self,
        budget: &mut GlobalBudget,
        value: W,
    ) -> Result<WindowId, ProtocolError> {
        self.insert(budget, Entry::Window(value)).map(WindowId)
    }

    pub fn insert_buffer(
        &mut self,
        budget: &mut GlobalBudget,
        value: B,
    ) -> Result<ClientBufferId, ProtocolError> {
        self.insert(budget, Entry::Buffer(value))
            .map(ClientBufferId)
    }

    fn entry(&self, id: ObjectId) -> Result<&Entry<S, W, B>, ProtocolError> {
        self.table.get(id).map_err(lookup_error_code)
    }

    fn entry_mut(&mut self, id: ObjectId) -> Result<&mut Entry<S, W, B>, ProtocolError> {
        self.table.get_mut(id).map_err(lookup_error_code)
    }

    /// Kind of the live object named by `id`.
    pub fn kind_of(&self, id: ObjectId) -> Result<ObjectKind, ProtocolError> {
        self.entry(id).map(Entry::kind)
    }

    pub fn surface(&self, id: SurfaceId) -> Result<&S, ProtocolError> {
        match self.entry(id.0)? {
            Entry::Surface(v) => Ok(v),
            _ => Err(ProtocolError::WrongObjectKind),
        }
    }

    pub fn surface_mut(&mut self, id: SurfaceId) -> Result<&mut S, ProtocolError> {
        match self.entry_mut(id.0)? {
            Entry::Surface(v) => Ok(v),
            _ => Err(ProtocolError::WrongObjectKind),
        }
    }

    pub fn window(&self, id: WindowId) -> Result<&W, ProtocolError> {
        match self.entry(id.0)? {
            Entry::Window(v) => Ok(v),
            _ => Err(ProtocolError::WrongObjectKind),
        }
    }

    pub fn window_mut(&mut self, id: WindowId) -> Result<&mut W, ProtocolError> {
        match self.entry_mut(id.0)? {
            Entry::Window(v) => Ok(v),
            _ => Err(ProtocolError::WrongObjectKind),
        }
    }

    pub fn buffer(&self, id: ClientBufferId) -> Result<&B, ProtocolError> {
        match self.entry(id.0)? {
            Entry::Buffer(v) => Ok(v),
            _ => Err(ProtocolError::WrongObjectKind),
        }
    }

    pub fn buffer_mut(&mut self, id: ClientBufferId) -> Result<&mut B, ProtocolError> {
        match self.entry_mut(id.0)? {
            Entry::Buffer(v) => Ok(v),
            _ => Err(ProtocolError::WrongObjectKind),
        }
    }

    fn remove(
        &mut self,
        budget: &mut GlobalBudget,
        id: ObjectId,
        kind: ObjectKind,
    ) -> Result<Entry<S, W, B>, ProtocolError> {
        if self.kind_of(id)? != kind {
            return Err(ProtocolError::WrongObjectKind);
        }
        let entry = self.table.remove(id).map_err(lookup_error_code)?;
        self.counts[kind.index()] -= 1;
        budget.used[kind.index()] = budget.used[kind.index()].saturating_sub(1);
        Ok(entry)
    }

    pub fn remove_surface(
        &mut self,
        budget: &mut GlobalBudget,
        id: SurfaceId,
    ) -> Result<S, ProtocolError> {
        match self.remove(budget, id.0, ObjectKind::Surface)? {
            Entry::Surface(v) => Ok(v),
            _ => Err(ProtocolError::WrongObjectKind),
        }
    }

    pub fn remove_window(
        &mut self,
        budget: &mut GlobalBudget,
        id: WindowId,
    ) -> Result<W, ProtocolError> {
        match self.remove(budget, id.0, ObjectKind::Window)? {
            Entry::Window(v) => Ok(v),
            _ => Err(ProtocolError::WrongObjectKind),
        }
    }

    pub fn remove_buffer(
        &mut self,
        budget: &mut GlobalBudget,
        id: ClientBufferId,
    ) -> Result<B, ProtocolError> {
        match self.remove(budget, id.0, ObjectKind::Buffer)? {
            Entry::Buffer(v) => Ok(v),
            _ => Err(ProtocolError::WrongObjectKind),
        }
    }

    /// Connection teardown: returns every live object's budget. Retired slots die with the
    /// table; the next connection starts from a fresh [`ObjectTable::new`].
    pub fn close(self, budget: &mut GlobalBudget) {
        for (used, count) in budget.used.iter_mut().zip(self.counts) {
            *used = used.saturating_sub(count);
        }
    }

    #[cfg(test)]
    pub(crate) fn seed_vacant_generation(&mut self, slot: u8, generation: u32) {
        self.table.seed_vacant_generation(slot, generation);
    }
}

#[cfg(test)]
mod tests;
