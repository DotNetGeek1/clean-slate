//! Reference display mode, output metadata, and the modes an output offers (#314).

use crate::geometry::Scale120;
use crate::geometry::Size;
use crate::ids::OutputId;
use crate::limits::{MAX_BUFFER_BYTES, MAX_SURFACE_EXTENT};
use crate::pixel::PixelFormat;

/// Physical scanout parameters visible to clients after negotiation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayMode {
    pub width_px: u32,
    pub height_px: u32,
    pub stride_bytes: u32,
    pub format: PixelFormat,
    pub scale: Scale120,
    pub refresh_mhz: u32,
}

/// One physical output described to clients at connect time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputInfo {
    pub id: OutputId,
    pub mode: DisplayMode,
    pub logical_size: Size,
}

/// Frozen QEMU/OVMF reference mode: 1280×800 `Xrgb8888`, scale 1.0, stride 5120.
pub const REFERENCE_MODE: DisplayMode = DisplayMode {
    width_px: 1280,
    height_px: 800,
    stride_bytes: 5120,
    format: PixelFormat::Xrgb8888,
    scale: Scale120::ONE,
    refresh_mhz: 0,
};

/// One full reference frame (1000 × 4096-byte pages).
pub const REFERENCE_FRAME_BYTES: usize = 4_096_000;

const _: () = assert!(
    REFERENCE_FRAME_BYTES
        == REFERENCE_MODE.stride_bytes as usize * REFERENCE_MODE.height_px as usize
);
const _: () = assert!(REFERENCE_FRAME_BYTES == 1000 * 4096);
const _: () = assert!((REFERENCE_FRAME_BYTES as u64) <= MAX_BUFFER_BYTES);
const _: () = assert!(matches!(
    DisplayMode::packed(REFERENCE_MODE.width_px, REFERENCE_MODE.height_px),
    Some(mode) if mode.stride_bytes == REFERENCE_MODE.stride_bytes
));
const _: () = assert!(mode_size_in_bounds(1920, 1080));
const _: () = assert!(!mode_size_in_bounds(1920, 1200));

// ---- display modes on offer (#314) -------------------------------------------------------------

/// The largest frame a mode may need: one scanout buffer. 1920×1080 fits; 1920×1200 does not.
pub const MAX_MODE_FRAME_BYTES: u64 = MAX_BUFFER_BYTES;
/// The narrowest mode a backend offers.
pub const MIN_MODE_WIDTH: u32 = 640;
/// The shortest mode a backend offers.
pub const MIN_MODE_HEIGHT: u32 = 480;
/// Entries in one `QUERY_MODES` list.
pub const MAX_OFFERED_MODES: usize = 16;

/// Sizes a backend that can scan out any size offers up to its host's preferred size (#314).
pub const STANDARD_MODE_SIZES: [(u32, u32); 11] = [
    (640, 480),
    (800, 600),
    (1024, 768),
    (1280, 720),
    (1280, 800),
    (1280, 1024),
    (1366, 768),
    (1440, 900),
    (1600, 900),
    (1680, 1050),
    (1920, 1080),
];

/// Whether a `width`×`height` packed `Xrgb8888` mode is inside the mode bounds: each side
/// between the minimum and [`MAX_SURFACE_EXTENT`], and the frame within [`MAX_MODE_FRAME_BYTES`].
pub const fn mode_size_in_bounds(width: u32, height: u32) -> bool {
    if width < MIN_MODE_WIDTH || height < MIN_MODE_HEIGHT {
        return false;
    }
    if width > MAX_SURFACE_EXTENT || height > MAX_SURFACE_EXTENT {
        return false;
    }
    (width as u64) * 4 * (height as u64) <= MAX_MODE_FRAME_BYTES
}

impl DisplayMode {
    /// The client-visible mode for a `width`×`height` output: `Xrgb8888`, scale 1, packed
    /// stride (`width × 4`), refresh unknown. `None` outside [`mode_size_in_bounds`].
    pub const fn packed(width: u32, height: u32) -> Option<Self> {
        if !mode_size_in_bounds(width, height) {
            return None;
        }
        Some(Self {
            width_px: width,
            height_px: height,
            stride_bytes: width * 4,
            format: PixelFormat::Xrgb8888,
            scale: Scale120::ONE,
            refresh_mhz: 0,
        })
    }

    /// Bytes one frame of this mode occupies in a scanout buffer.
    pub const fn frame_bytes(&self) -> u64 {
        self.stride_bytes as u64 * self.height_px as u64
    }

    pub const fn size(&self) -> Size {
        Size {
            width: self.width_px,
            height: self.height_px,
        }
    }
}

/// What a [`ModeEntry`] is to its backend.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ModeFlags(pub u8);

impl ModeFlags {
    /// The mode the output scans out now. Exactly one entry of a list carries it.
    pub const CURRENT: Self = Self(1 << 0);
    /// The configured size (boot option `opt/clean-slate/display`), else the host's own size on
    /// a backend that reports one. At most one entry carries it.
    pub const PREFERRED: Self = Self(1 << 1);
    /// `SET_MODE` accepts it. GOP can set no mode after `ExitBootServices`, so only its current
    /// mode is settable.
    pub const SETTABLE: Self = Self(1 << 2);
    pub const KNOWN: Self = Self(0b111);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

/// One size on offer. Every offered mode is packed `Xrgb8888` at scale 1 ([`DisplayMode::packed`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModeEntry {
    pub width_px: u32,
    pub height_px: u32,
    pub flags: ModeFlags,
}

impl ModeEntry {
    pub const fn mode(&self) -> Option<DisplayMode> {
        DisplayMode::packed(self.width_px, self.height_px)
    }

    pub const fn area(&self) -> u64 {
        self.width_px as u64 * self.height_px as u64
    }

    pub const fn is(&self, flag: ModeFlags) -> bool {
        self.flags.contains(flag)
    }
}

/// Why a mode could not join a [`ModeList`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeListError {
    Full,
}

/// The modes one output offers, in insertion order, one entry per size (bounded, no allocation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModeList {
    entries: [ModeEntry; MAX_OFFERED_MODES],
    len: usize,
}

impl Default for ModeList {
    fn default() -> Self {
        Self::new()
    }
}

impl ModeList {
    const EMPTY: ModeEntry = ModeEntry {
        width_px: 0,
        height_px: 0,
        flags: ModeFlags(0),
    };

    pub const fn new() -> Self {
        Self {
            entries: [Self::EMPTY; MAX_OFFERED_MODES],
            len: 0,
        }
    }

    pub fn as_slice(&self) -> &[ModeEntry] {
        &self.entries[..self.len]
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Adds `flags` to the entry for this size, or appends one. `CURRENT` and `PREFERRED` move:
    /// the entry that had them loses them. A full list refuses a new size and changes nothing.
    pub fn offer(
        &mut self,
        width: u32,
        height: u32,
        flags: ModeFlags,
    ) -> Result<(), ModeListError> {
        let index = match self.position(width, height) {
            Some(index) => index,
            None => {
                if self.len == MAX_OFFERED_MODES {
                    return Err(ModeListError::Full);
                }
                self.entries[self.len] = ModeEntry {
                    width_px: width,
                    height_px: height,
                    flags: ModeFlags(0),
                };
                self.len += 1;
                self.len - 1
            }
        };
        for moving in [ModeFlags::CURRENT, ModeFlags::PREFERRED] {
            if flags.contains(moving) {
                for entry in &mut self.entries[..self.len] {
                    entry.flags = entry.flags.without(moving);
                }
            }
        }
        let entry = &mut self.entries[index];
        entry.flags = entry.flags.union(flags);
        Ok(())
    }

    pub fn find(&self, width: u32, height: u32) -> Option<ModeEntry> {
        self.position(width, height)
            .map(|index| self.entries[index])
    }

    fn position(&self, width: u32, height: u32) -> Option<usize> {
        self.as_slice()
            .iter()
            .position(|entry| entry.width_px == width && entry.height_px == height)
    }

    pub fn current(&self) -> Option<ModeEntry> {
        self.with(ModeFlags::CURRENT)
    }

    pub fn preferred(&self) -> Option<ModeEntry> {
        self.with(ModeFlags::PREFERRED)
    }

    fn with(&self, flag: ModeFlags) -> Option<ModeEntry> {
        self.as_slice().iter().copied().find(|entry| entry.is(flag))
    }

    /// The settable entry with the largest area; the wider one of equal areas, then the first.
    pub fn largest_settable(&self) -> Option<ModeEntry> {
        self.as_slice()
            .iter()
            .copied()
            .filter(|entry| entry.is(ModeFlags::SETTABLE))
            .fold(None, |best: Option<ModeEntry>, entry| match best {
                Some(best) if (best.area(), best.width_px) >= (entry.area(), entry.width_px) => {
                    Some(best)
                }
                _ => Some(entry),
            })
    }

    /// The largest packed frame any settable entry needs: what a scanout buffer must hold so that
    /// every settable mode fits without reallocating it.
    pub fn settable_frame_bytes(&self) -> u64 {
        self.as_slice()
            .iter()
            .filter(|entry| entry.is(ModeFlags::SETTABLE))
            .map(|entry| u64::from(entry.width_px) * 4 * u64::from(entry.height_px))
            .max()
            .unwrap_or(0)
    }

    /// The compositor's start-up choice (#314): the preferred entry if it is settable, else the
    /// largest settable entry, else the current one.
    pub fn choose(&self) -> Option<ModeEntry> {
        self.preferred()
            .filter(|entry| entry.is(ModeFlags::SETTABLE))
            .or_else(|| self.largest_settable())
            .or_else(|| self.current())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: ModeFlags = ModeFlags::SETTABLE;

    #[test]
    fn mode_bounds_cap_the_frame_at_one_scanout_buffer() {
        assert!(mode_size_in_bounds(640, 480));
        assert!(!mode_size_in_bounds(639, 480));
        assert!(!mode_size_in_bounds(640, 479));
        assert!(mode_size_in_bounds(1920, 1080));
        assert!(!mode_size_in_bounds(1920, 1200));
        assert!(!mode_size_in_bounds(2560, 1440));
        assert!(!mode_size_in_bounds(MAX_SURFACE_EXTENT + 1, 480));
        for (width, height) in STANDARD_MODE_SIZES {
            let mode = DisplayMode::packed(width, height).expect("standard size in bounds");
            assert_eq!(mode.stride_bytes, width * 4);
            assert!(mode.frame_bytes() <= MAX_MODE_FRAME_BYTES);
        }
        assert_eq!(DisplayMode::packed(1280, 800), Some(REFERENCE_MODE));
        assert_eq!(REFERENCE_MODE.frame_bytes(), REFERENCE_FRAME_BYTES as u64);
        assert_eq!(DisplayMode::packed(320, 200), None);
    }

    #[test]
    fn offer_merges_one_entry_per_size_and_moves_current_and_preferred() {
        let mut list = ModeList::new();
        list.offer(1280, 800, S.union(ModeFlags::CURRENT)).unwrap();
        list.offer(1024, 768, S).unwrap();
        list.offer(1024, 768, ModeFlags::PREFERRED).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(
            list.find(1024, 768).unwrap().flags,
            S.union(ModeFlags::PREFERRED)
        );
        list.offer(1024, 768, ModeFlags::CURRENT).unwrap();
        assert_eq!(list.current().unwrap().width_px, 1024);
        assert!(!list.find(1280, 800).unwrap().is(ModeFlags::CURRENT));
        list.offer(1280, 800, ModeFlags::PREFERRED).unwrap();
        assert_eq!(list.preferred().unwrap().width_px, 1280);
        assert!(!list.find(1024, 768).unwrap().is(ModeFlags::PREFERRED));

        let mut full = ModeList::new();
        for i in 0..MAX_OFFERED_MODES as u32 {
            full.offer(640 + i, 480, S).unwrap();
        }
        assert_eq!(full.offer(2000, 480, S), Err(ModeListError::Full));
        assert_eq!(full.offer(640, 480, ModeFlags::CURRENT), Ok(()));
        assert_eq!(full.len(), MAX_OFFERED_MODES);
    }

    #[test]
    fn choose_takes_the_settable_preferred_else_the_largest_settable() {
        let mut list = ModeList::new();
        list.offer(1280, 800, S.union(ModeFlags::CURRENT)).unwrap();
        list.offer(1920, 1080, S).unwrap();
        list.offer(1024, 768, S.union(ModeFlags::PREFERRED))
            .unwrap();
        assert_eq!(list.choose().unwrap().width_px, 1024);

        list.offer(1024, 768, ModeFlags(0)).unwrap();
        let mut unsettable = ModeList::new();
        unsettable
            .offer(1280, 800, S.union(ModeFlags::CURRENT))
            .unwrap();
        unsettable.offer(1920, 1080, S).unwrap();
        unsettable.offer(1024, 768, ModeFlags::PREFERRED).unwrap();
        assert_eq!(
            unsettable.choose().unwrap().width_px,
            1920,
            "an unsettable preferred size falls back to the largest settable"
        );

        let mut gop = ModeList::new();
        gop.offer(1024, 768, S.union(ModeFlags::CURRENT)).unwrap();
        gop.offer(1920, 1080, ModeFlags(0)).unwrap();
        assert_eq!(gop.choose().unwrap().width_px, 1024);
        assert_eq!(gop.settable_frame_bytes(), 1024 * 4 * 768);

        let mut ties = ModeList::new();
        ties.offer(1600, 900, S.union(ModeFlags::CURRENT)).unwrap();
        ties.offer(1200, 1200, S).unwrap();
        assert_eq!(ties.largest_settable().unwrap().width_px, 1600);
        assert_eq!(ModeList::new().choose(), None);
    }
}
