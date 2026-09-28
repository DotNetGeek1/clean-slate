//! Connection-scoped object identities and generational slot tables.

use crate::error::{LimitError, LookupError};

const SLOT_INDEX_MASK: u32 = 0xFF;
const GENERATION_SHIFT: u32 = 8;
const MAX_PACKED_GENERATION: u32 = 0x00FF_FFFF;

/// Largest generation an [`ObjectId`] can carry; a slot retires after releasing it.
pub const MAX_OBJECT_GENERATION: u32 = MAX_PACKED_GENERATION;

fn encode_index_generation(index: u8, generation: u32) -> Result<u32, LookupError> {
    if generation == 0 || generation > MAX_PACKED_GENERATION {
        return Err(LookupError::Invalid);
    }
    Ok(u32::from(index) | (generation << GENERATION_SHIFT))
}

fn decode_index_generation(raw: u32) -> Result<(u8, u32), LookupError> {
    let generation = raw >> GENERATION_SHIFT;
    if generation == 0 || generation > MAX_PACKED_GENERATION {
        return Err(LookupError::Invalid);
    }
    Ok(((raw & SLOT_INDEX_MASK) as u8, generation))
}

/// Compositor-minted object reference: slot in bits 0..8, generation in 8..32.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ObjectId(u32);

/// Surface protocol object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SurfaceId(pub ObjectId);

/// Window protocol object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WindowId(pub ObjectId);

/// Client-registered shared buffer handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClientBufferId(pub ObjectId);

/// Physical output identity: index in 0..8, backend epoch in 8..32.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OutputId(u32);

/// Kernel input device index for the keyboard (M10 seat 0).
pub const KEYBOARD_INDEX: u8 = 0;
/// Kernel input device index for the mouse (M10 seat 0).
pub const MOUSE_INDEX: u8 = 1;

/// Kernel-minted input device identity: index in 0..8, generation in 8..32.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InputDeviceId(u32);

/// Configure or input correlation token (equality only; never ordered).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Serial(pub u32);

impl ObjectId {
    pub fn encode(self) -> u32 {
        self.0
    }

    pub fn decode(raw: u32) -> Result<Self, LookupError> {
        decode_index_generation(raw).map(|_| Self(raw))
    }

    /// Wire helper: raw `0` means no object; nonzero values use [`Self::decode`].
    pub fn decode_optional(raw: u32) -> Result<Option<Self>, LookupError> {
        if raw == 0 {
            Ok(None)
        } else {
            Self::decode(raw).map(Some)
        }
    }

    pub fn encode_optional(id: Option<ObjectId>) -> u32 {
        id.map_or(0, ObjectId::encode)
    }

    pub fn new(slot: u8, generation: u32) -> Result<Self, LookupError> {
        encode_index_generation(slot, generation).map(Self)
    }

    pub fn slot(self) -> u8 {
        (self.0 & SLOT_INDEX_MASK) as u8
    }

    pub fn generation(self) -> u32 {
        self.0 >> GENERATION_SHIFT
    }
}

impl OutputId {
    pub fn encode(self) -> u32 {
        self.0
    }

    pub fn decode(raw: u32) -> Result<Self, LookupError> {
        decode_index_generation(raw).map(|_| Self(raw))
    }

    pub fn new(index: u8, backend_epoch: u32) -> Result<Self, LookupError> {
        encode_index_generation(index, backend_epoch).map(Self)
    }

    pub fn index(self) -> u8 {
        (self.0 & SLOT_INDEX_MASK) as u8
    }

    pub fn backend_epoch(self) -> u32 {
        self.0 >> GENERATION_SHIFT
    }
}

impl InputDeviceId {
    pub fn encode(self) -> u32 {
        self.0
    }

    pub fn decode(raw: u32) -> Result<Self, LookupError> {
        decode_index_generation(raw).map(|_| Self(raw))
    }

    pub fn new(index: u8, generation: u32) -> Result<Self, LookupError> {
        encode_index_generation(index, generation).map(Self)
    }

    pub fn index(self) -> u8 {
        (self.0 & SLOT_INDEX_MASK) as u8
    }

    pub fn generation(self) -> u32 {
        self.0 >> GENERATION_SHIFT
    }
}

struct Slot<T> {
    value: Option<T>,
    /// Live generation, or next issue generation when vacant; `0` means never issued.
    generation: u32,
    retired: bool,
}

/// Fixed-size generational table; slots retire instead of wrapping generation.
///
/// Capacity `N` must be ≤ 256 so slot indices fit in bits 0..8 of [`ObjectId`].
pub struct GenSlotTable<T, const N: usize> {
    slots: [Slot<T>; N],
}

impl<T, const N: usize> Default for GenSlotTable<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> GenSlotTable<T, N> {
    const N_WITHIN_SLOT_BITS: () = assert!(N <= 256);

    pub const fn new() -> Self {
        let () = Self::N_WITHIN_SLOT_BITS;
        Self {
            slots: [const {
                Slot {
                    value: None,
                    generation: 0,
                    retired: false,
                }
            }; N],
        }
    }

    pub fn insert(&mut self, value: T) -> Result<ObjectId, LimitError> {
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if slot.retired || slot.value.is_some() {
                continue;
            }
            let slot_index = u8::try_from(index).map_err(|_| LimitError::Exhausted)?;
            let generation = if slot.generation == 0 {
                1
            } else {
                slot.generation
            };
            let Ok(id) = ObjectId::new(slot_index, generation) else {
                continue;
            };
            slot.generation = generation;
            slot.value = Some(value);
            return Ok(id);
        }
        Err(LimitError::Exhausted)
    }

    pub fn get(&self, id: ObjectId) -> Result<&T, LookupError> {
        self.lookup(id)
    }

    pub fn get_mut(&mut self, id: ObjectId) -> Result<&mut T, LookupError> {
        let slot_index = Self::slot_index(id)?;
        let slot = &mut self.slots[slot_index];
        Self::match_live(slot, id)?;
        slot.value.as_mut().ok_or(LookupError::Stale)
    }

    pub fn remove(&mut self, id: ObjectId) -> Result<T, LookupError> {
        let slot_index = Self::slot_index(id)?;
        let slot = &mut self.slots[slot_index];
        if slot.retired {
            return Err(LookupError::Retired);
        }
        if slot.value.is_none() {
            return if slot.generation == 0 {
                Err(LookupError::Invalid)
            } else {
                Err(LookupError::Stale)
            };
        }
        if slot.generation != id.generation() {
            return Err(LookupError::Stale);
        }
        let taken = slot.value.take().ok_or(LookupError::Stale)?;
        match next_generation(slot.generation) {
            Some(next) => slot.generation = next,
            None => slot.retired = true,
        }
        Ok(taken)
    }

    fn lookup(&self, id: ObjectId) -> Result<&T, LookupError> {
        let slot_index = Self::slot_index(id)?;
        let slot = &self.slots[slot_index];
        Self::match_live(slot, id)?;
        slot.value.as_ref().ok_or(LookupError::Stale)
    }

    fn slot_index(id: ObjectId) -> Result<usize, LookupError> {
        let index = usize::from(id.slot());
        if index >= N {
            return Err(LookupError::Invalid);
        }
        Ok(index)
    }

    fn match_live(slot: &Slot<T>, id: ObjectId) -> Result<(), LookupError> {
        if slot.retired {
            return Err(LookupError::Retired);
        }
        if slot.value.is_none() {
            return if slot.generation == 0 {
                Err(LookupError::Invalid)
            } else {
                Err(LookupError::Stale)
            };
        }
        if slot.generation != id.generation() {
            return Err(LookupError::Stale);
        }
        Ok(())
    }

    /// Clears every slot in place (same observable state as [`Self::new`]).
    pub fn clear_in_place(&mut self) {
        for slot in self.slots.iter_mut() {
            *slot = Slot {
                value: None,
                generation: 0,
                retired: false,
            };
        }
    }

    #[cfg(test)]
    pub(crate) fn seed_vacant_generation(&mut self, slot: u8, generation: u32) {
        let index = usize::from(slot);
        if index < N {
            self.slots[index].generation = generation;
        }
    }

    #[cfg(test)]
    pub(crate) fn is_retired(&self, slot: u8) -> bool {
        self.slots[usize::from(slot)].retired
    }
}

const fn next_generation(current: u32) -> Option<u32> {
    if current >= MAX_PACKED_GENERATION {
        None
    } else {
        Some(current + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_id_round_trip_and_generation_zero() {
        let id = ObjectId::new(3, 42).unwrap();
        assert_eq!(ObjectId::decode(id.encode()), Ok(id));
        assert_eq!(id.slot(), 3);
        assert_eq!(id.generation(), 42);
        assert_eq!(ObjectId::decode(3), Err(LookupError::Invalid));
        assert_eq!(ObjectId::new(0, 0), Err(LookupError::Invalid));
    }

    #[test]
    fn object_id_optional_wire_zero() {
        assert_eq!(ObjectId::decode_optional(0), Ok(None));
        assert_eq!(ObjectId::encode_optional(None), 0);
        let id = ObjectId::new(1, 1).unwrap();
        assert_eq!(ObjectId::decode_optional(id.encode()), Ok(Some(id)));
        assert_eq!(ObjectId::encode_optional(Some(id)), id.encode());
    }

    #[test]
    fn gen_slot_table_stale_after_remove_and_reuse() {
        let mut table = GenSlotTable::<u32, 4>::new();
        let id1 = table.insert(10).unwrap();
        assert_eq!(table.get(id1), Ok(&10));
        assert_eq!(table.remove(id1), Ok(10));
        assert_eq!(table.get(id1), Err(LookupError::Stale));

        let id2 = table.insert(20).unwrap();
        assert_eq!(id2.slot(), id1.slot());
        assert_ne!(id2.generation(), id1.generation());
        assert_eq!(table.get(id2), Ok(&20));
    }

    #[test]
    fn gen_slot_table_never_issued_invalid() {
        let table = GenSlotTable::<u32, 2>::new();
        let fake = ObjectId::new(0, 1).unwrap();
        assert_eq!(table.get(fake), Err(LookupError::Invalid));
    }

    #[test]
    fn gen_slot_table_exhausted() {
        let mut table = GenSlotTable::<u32, 1>::new();
        assert!(table.insert(1).is_ok());
        assert_eq!(table.insert(2), Err(LimitError::Exhausted));
    }

    #[test]
    fn gen_slot_table_retire_at_max_generation() {
        let mut table = GenSlotTable::<u32, 1>::new();
        table.seed_vacant_generation(0, MAX_PACKED_GENERATION);
        let id = table.insert(7).unwrap();
        assert_eq!(id.generation(), MAX_PACKED_GENERATION);
        assert_eq!(table.remove(id), Ok(7));
        assert!(table.is_retired(0));
        assert_eq!(table.insert(8), Err(LimitError::Exhausted));
        let stale = ObjectId::new(0, MAX_PACKED_GENERATION).unwrap();
        assert_eq!(table.get(stale), Err(LookupError::Retired));
    }

    #[test]
    fn gen_slot_table_slot_indices_are_not_truncated() {
        let mut table = GenSlotTable::<u32, 256>::new();
        let mut ids = [ObjectId::new(0, 1).unwrap(); 256];
        for expected in 0u8..=255 {
            let id = table.insert(u32::from(expected)).unwrap();
            assert_eq!(id.slot(), expected);
            ids[usize::from(expected)] = id;
        }
        for expected in 0u8..=255 {
            assert_eq!(
                table.get(ids[usize::from(expected)]),
                Ok(&u32::from(expected))
            );
        }
    }

    #[test]
    fn output_id_rejects_zero_epoch() {
        assert_eq!(OutputId::new(0, 0), Err(LookupError::Invalid));
        let id = OutputId::new(0, 5).unwrap();
        assert_eq!(OutputId::decode(id.encode()), Ok(id));
    }

    #[test]
    fn output_id_rejects_epoch_above_max_packed() {
        assert_eq!(
            OutputId::new(0, MAX_PACKED_GENERATION + 1),
            Err(LookupError::Invalid)
        );
        assert_eq!(OutputId::new(0, 0x0100_0000), Err(LookupError::Invalid));
    }

    #[test]
    fn input_device_id_round_trip_and_indices() {
        assert_eq!(KEYBOARD_INDEX, 0);
        assert_eq!(MOUSE_INDEX, 1);
        let kb = InputDeviceId::new(KEYBOARD_INDEX, 1).unwrap();
        let mouse = InputDeviceId::new(MOUSE_INDEX, 2).unwrap();
        assert_eq!(InputDeviceId::decode(kb.encode()), Ok(kb));
        assert_eq!(kb.index(), KEYBOARD_INDEX);
        assert_eq!(mouse.generation(), 2);
        assert_eq!(InputDeviceId::new(0, 0), Err(LookupError::Invalid));
    }
}

#[cfg(test)]
mod tests_capacity;
