//! GOP framebuffer capture before `ExitBootServices` (#111).
//!
//! Capture runs on every boot and never fails it: any rejection means "no display backend"
//! (`ModeUnavailable`/`ENODEV` to callers of syscall 18). Only the reference mode is accepted
//! (`clean_slate_graphics::REFERENCE_MODE`: 1280×800, 32-bit, B,G,R,X or R,G,B,X).
//!
//! The firmware layer talks to the raw protocol: the safe `uefi` accessors panic on pixel
//! formats above 3 and on a failed pool free, and a panic here would kill every lane.

use clean_slate_graphics::{MAX_STRIDE_BYTES, REFERENCE_MODE};

use crate::mm::layout::PHYSMAP_SPAN;
use crate::mm::region::{MemoryRegion, MemoryRegionKind};
use crate::mm::PAGE_SIZE;

/// Upper bound on firmware modes inspected; more is rejected rather than truncated.
pub(crate) const MAX_GOP_MODES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GopRawFormat {
    Rgbx,
    Bgrx,
    Bitmask,
    BltOnly,
    Unknown(u32),
}

impl GopRawFormat {
    pub(crate) const fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::Rgbx,
            1 => Self::Bgrx,
            2 => Self::Bitmask,
            3 => Self::BltOnly,
            other => Self::Unknown(other),
        }
    }

    const fn order(self) -> Option<GopPixelOrder> {
        match self {
            Self::Bgrx => Some(GopPixelOrder::Bgrx),
            Self::Rgbx => Some(GopPixelOrder::Rgbx),
            Self::Bitmask | Self::BltOnly | Self::Unknown(_) => None,
        }
    }

    #[cfg(feature = "m10-framebuffer-self-test")]
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Rgbx => "rgbx",
            Self::Bgrx => "bgrx",
            Self::Bitmask => "bitmask",
            Self::BltOnly => "blt-only",
            Self::Unknown(_) => "unknown",
        }
    }
}

/// Byte order of an accepted aperture. `Bgrx` matches `PixelFormat::Xrgb8888` in memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GopPixelOrder {
    Bgrx,
    Rgbx,
}

impl GopPixelOrder {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Bgrx => "bgrx",
            Self::Rgbx => "rgbx",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GopModeCandidate {
    pub(crate) index: u32,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) stride_px: u32,
    pub(crate) format: GopRawFormat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GopRejection {
    NoGopHandle,
    MultipleGopDevices,
    OpenFailed,
    TooManyModes,
    ReferenceModeAbsent,
    UnsupportedFormat,
    SetModeFailed,
    ModeMismatchAfterSet,
    StrideInvalid,
    SizeTooSmall,
    BaseInvalid,
    RangeOverflow,
    BeyondPhysmapSpan,
    OverlapsUsableRam,
    ApertureMapFailed,
}

impl GopRejection {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::NoGopHandle => "no-gop-handle",
            Self::MultipleGopDevices => "multiple-gop-devices",
            Self::OpenFailed => "open-failed",
            Self::TooManyModes => "too-many-modes",
            Self::ReferenceModeAbsent => "reference-mode-absent",
            Self::UnsupportedFormat => "unsupported-format",
            Self::SetModeFailed => "set-mode-failed",
            Self::ModeMismatchAfterSet => "mode-mismatch-after-set",
            Self::StrideInvalid => "stride-invalid",
            Self::SizeTooSmall => "size-too-small",
            Self::BaseInvalid => "base-invalid",
            Self::RangeOverflow => "range-overflow",
            Self::BeyondPhysmapSpan => "beyond-physmap-span",
            Self::OverlapsUsableRam => "overlaps-usable-ram",
            Self::ApertureMapFailed => "aperture-map-failed",
        }
    }
}

/// Firmware state read back after `SetMode`; `size` is the firmware `frame_buffer_size`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RawFramebufferInfo {
    pub(crate) mode_index: u32,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) stride_px: u32,
    pub(crate) format: GopRawFormat,
    pub(crate) base: u64,
    pub(crate) size: u64,
}

/// A validated aperture. Only `[phys_base, phys_base + map_len)` is ever mapped, and only
/// `byte_len` bytes of it are ever written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BootFramebuffer {
    pub(crate) phys_base: u64,
    pub(crate) byte_len: u64,
    pub(crate) map_len: u64,
    pub(crate) width: u32,
    pub(crate) height: u32,
    /// Backend-private; may exceed `width * 4` and is never exposed to clients.
    pub(crate) stride_bytes: u32,
    pub(crate) order: GopPixelOrder,
    pub(crate) mode_index: u32,
}

impl BootFramebuffer {
    pub(crate) const fn page_count(&self) -> u64 {
        self.map_len / PAGE_SIZE
    }

    pub(crate) const fn phys_end(&self) -> u64 {
        self.phys_base + self.map_len
    }
}

/// Picks the reference mode, preferring B,G,R,X (no conversion at present time).
pub(crate) fn select_reference_mode(modes: &[GopModeCandidate]) -> Result<u32, GopRejection> {
    if modes.len() > MAX_GOP_MODES {
        return Err(GopRejection::TooManyModes);
    }
    let mut saw_reference_size = false;
    let mut rgbx = None;
    for mode in modes {
        if mode.width != REFERENCE_MODE.width_px || mode.height != REFERENCE_MODE.height_px {
            continue;
        }
        saw_reference_size = true;
        if mode.stride_px < mode.width {
            continue;
        }
        match mode.format.order() {
            Some(GopPixelOrder::Bgrx) => return Ok(mode.index),
            Some(GopPixelOrder::Rgbx) if rgbx.is_none() => rgbx = Some(mode.index),
            _ => {}
        }
    }
    match (rgbx, saw_reference_size) {
        (Some(index), _) => Ok(index),
        (None, true) => Err(GopRejection::UnsupportedFormat),
        (None, false) => Err(GopRejection::ReferenceModeAbsent),
    }
}

/// Validates the post-`SetMode` state in `u64` so no input can wrap.
pub(crate) fn validate_framebuffer(
    raw: RawFramebufferInfo,
) -> Result<BootFramebuffer, GopRejection> {
    if raw.width != REFERENCE_MODE.width_px || raw.height != REFERENCE_MODE.height_px {
        return Err(GopRejection::ModeMismatchAfterSet);
    }
    let order = raw.format.order().ok_or(GopRejection::UnsupportedFormat)?;
    let stride_bytes = u64::from(raw.stride_px) * 4;
    if raw.stride_px < raw.width || stride_bytes > u64::from(MAX_STRIDE_BYTES) {
        return Err(GopRejection::StrideInvalid);
    }
    let byte_len = stride_bytes
        .checked_mul(u64::from(raw.height))
        .ok_or(GopRejection::RangeOverflow)?;
    if raw.size < byte_len {
        return Err(GopRejection::SizeTooSmall);
    }
    if raw.base == 0 || raw.base % PAGE_SIZE != 0 {
        return Err(GopRejection::BaseInvalid);
    }
    let map_len = byte_len
        .checked_next_multiple_of(PAGE_SIZE)
        .ok_or(GopRejection::RangeOverflow)?;
    let end = raw
        .base
        .checked_add(map_len)
        .ok_or(GopRejection::RangeOverflow)?;
    if end > PHYSMAP_SPAN {
        return Err(GopRejection::BeyondPhysmapSpan);
    }
    Ok(BootFramebuffer {
        phys_base: raw.base,
        byte_len,
        map_len,
        width: raw.width,
        height: raw.height,
        stride_bytes: stride_bytes as u32,
        order,
        mode_index: raw.mode_index,
    })
}

/// Rejects an aperture that intersects allocator-usable RAM.
pub(crate) fn aperture_conflicts(
    regions: &[MemoryRegion],
    framebuffer: &BootFramebuffer,
) -> Result<(), GopRejection> {
    let (start, end) = (framebuffer.phys_base, framebuffer.phys_end());
    if regions.iter().any(|region| {
        region.kind == MemoryRegionKind::Usable && region.start < end && start < region.end
    }) {
        return Err(GopRejection::OverlapsUsableRam);
    }
    Ok(())
}

pub(crate) fn log_rejection(reason: GopRejection) {
    crate::diagnostics::serial::serial_write_fmt(format_args!(
        "[GOP ] unavailable reason={}\n",
        reason.name()
    ));
}

pub(crate) use firmware::capture_boot_framebuffer;

mod firmware {
    use core::mem::size_of;
    use core::ptr::{self, NonNull};

    use uefi::boot::{self, OpenProtocolParams, SearchType};
    use uefi::proto::console::gop::GraphicsOutput;
    use uefi::proto::device_path::DevicePath;
    use uefi::Handle;
    use uefi_raw::protocol::console::{GraphicsOutputModeInformation, GraphicsOutputProtocol};

    use super::{
        select_reference_mode, validate_framebuffer, BootFramebuffer, GopModeCandidate,
        GopRawFormat, GopRejection, RawFramebufferInfo, MAX_GOP_MODES,
    };
    use crate::diagnostics::serial::serial_write_fmt;

    const EMPTY_CANDIDATE: GopModeCandidate = GopModeCandidate {
        index: 0,
        width: 0,
        height: 0,
        stride_px: 0,
        format: GopRawFormat::Unknown(u32::MAX),
    };

    /// Exactly one GOP handle that also carries a device path; ConSplitter's virtual handle has
    /// none and is skipped.
    fn physical_gop_handle() -> Result<Handle, GopRejection> {
        let handles = boot::locate_handle_buffer(SearchType::from_proto::<GraphicsOutput>())
            .map_err(|_| GopRejection::NoGopHandle)?;
        let mut found = None;
        for &handle in handles.iter() {
            let params = OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            };
            if !boot::test_protocol::<DevicePath>(params).unwrap_or(false) {
                continue;
            }
            if found.replace(handle).is_some() {
                return Err(GopRejection::MultipleGopDevices);
            }
        }
        found.ok_or(GopRejection::NoGopHandle)
    }

    fn candidate(index: u32, info: &GraphicsOutputModeInformation) -> GopModeCandidate {
        GopModeCandidate {
            index,
            width: info.horizontal_resolution,
            height: info.vertical_resolution,
            stride_px: info.pixels_per_scan_line,
            format: GopRawFormat::from_raw(info.pixel_format.0),
        }
    }

    /// # Safety
    /// `gop` must point at a live, exclusively opened GOP instance.
    unsafe fn query_mode(
        gop: *mut GraphicsOutputProtocol,
        index: u32,
    ) -> Option<GraphicsOutputModeInformation> {
        let mut size = 0usize;
        let mut info: *const GraphicsOutputModeInformation = ptr::null();
        let status = unsafe { ((*gop).query_mode)(gop, index, &mut size, &mut info) };
        let pool = NonNull::new(info.cast_mut().cast::<u8>());
        let result = if status.is_success()
            && pool.is_some()
            && size >= size_of::<GraphicsOutputModeInformation>()
        {
            Some(unsafe { ptr::read_unaligned(info) })
        } else {
            None
        };
        if let Some(pool) = pool {
            let _ = unsafe { boot::free_pool(pool) };
        }
        result
    }

    pub(crate) fn capture_boot_framebuffer() -> Result<BootFramebuffer, GopRejection> {
        let handle = physical_gop_handle()?;
        let mut protocol = boot::open_protocol_exclusive::<GraphicsOutput>(handle)
            .map_err(|_| GopRejection::OpenFailed)?;
        // `GraphicsOutput` is `repr(transparent)` over the raw protocol struct.
        let gop = (&mut *protocol as *mut GraphicsOutput).cast::<GraphicsOutputProtocol>();
        if unsafe { (*gop).mode.is_null() } {
            return Err(GopRejection::OpenFailed);
        }

        let max_mode = unsafe { (*(*gop).mode).max_mode };
        if max_mode as usize > MAX_GOP_MODES {
            return Err(GopRejection::TooManyModes);
        }
        let mut modes = [EMPTY_CANDIDATE; MAX_GOP_MODES];
        let mut count = 0usize;
        for index in 0..max_mode {
            let Some(info) = (unsafe { query_mode(gop, index) }) else {
                continue;
            };
            modes[count] = candidate(index, &info);
            count += 1;
            #[cfg(feature = "m10-framebuffer-self-test")]
            {
                let mode = modes[count - 1];
                serial_write_fmt(format_args!(
                    "[GOP ] mode i={} {}x{} fmt={} stride={}\n",
                    mode.index,
                    mode.width,
                    mode.height,
                    mode.format.name(),
                    mode.stride_px
                ));
            }
        }
        serial_write_fmt(format_args!("[GOP ] modes={count}\n"));

        let selected = select_reference_mode(&modes[..count])?;
        let status = unsafe { ((*gop).set_mode)(gop, selected) };
        if !status.is_success() {
            return Err(GopRejection::SetModeFailed);
        }

        // SetMode invalidates the previous framebuffer; base and size are re-read here.
        let mode = unsafe { ptr::read_unaligned((*gop).mode) };
        if mode.info.is_null() || mode.size_of_info < size_of::<GraphicsOutputModeInformation>() {
            return Err(GopRejection::ModeMismatchAfterSet);
        }
        let info = unsafe { ptr::read_unaligned(mode.info) };
        let framebuffer = validate_framebuffer(RawFramebufferInfo {
            mode_index: mode.mode,
            width: info.horizontal_resolution,
            height: info.vertical_resolution,
            stride_px: info.pixels_per_scan_line,
            format: GopRawFormat::from_raw(info.pixel_format.0),
            base: mode.frame_buffer_base,
            size: mode.frame_buffer_size as u64,
        })?;
        serial_write_fmt(format_args!(
            "[GOP ] set-mode {}x{} fmt={} stride={}\n",
            framebuffer.width,
            framebuffer.height,
            framebuffer.order.name(),
            framebuffer.stride_bytes
        ));
        serial_write_fmt(format_args!(
            "[GOP ] captured base={:#x} len={}\n",
            framebuffer.phys_base, framebuffer.byte_len
        ));
        Ok(framebuffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn mode(index: u32, width: u32, height: u32, format: GopRawFormat) -> GopModeCandidate {
        GopModeCandidate {
            index,
            width,
            height,
            stride_px: width,
            format,
        }
    }

    fn reference_raw() -> RawFramebufferInfo {
        RawFramebufferInfo {
            mode_index: 7,
            width: 1280,
            height: 800,
            stride_px: 1280,
            format: GopRawFormat::Bgrx,
            base: 0x8000_0000,
            size: 16 * 1024 * 1024,
        }
    }

    #[test]
    fn select_reference_mode_matrix() {
        assert_eq!(
            select_reference_mode(&[]),
            Err(GopRejection::ReferenceModeAbsent)
        );
        assert_eq!(
            select_reference_mode(&[mode(0, 800, 600, GopRawFormat::Bgrx)]),
            Err(GopRejection::ReferenceModeAbsent)
        );
        for format in [
            GopRawFormat::Bitmask,
            GopRawFormat::BltOnly,
            GopRawFormat::Unknown(7),
        ] {
            assert_eq!(
                select_reference_mode(&[mode(3, 1280, 800, format)]),
                Err(GopRejection::UnsupportedFormat),
                "{format:?}"
            );
        }
        assert_eq!(
            select_reference_mode(&[
                mode(1, 1280, 800, GopRawFormat::Rgbx),
                mode(2, 1280, 800, GopRawFormat::Bgrx),
            ]),
            Ok(2),
            "Bgrx wins over an earlier Rgbx"
        );
        assert_eq!(
            select_reference_mode(&[
                mode(4, 1280, 800, GopRawFormat::Rgbx),
                mode(5, 1280, 800, GopRawFormat::Rgbx),
            ]),
            Ok(4),
            "first of duplicates"
        );
        assert_eq!(
            select_reference_mode(&[
                mode(8, 1280, 800, GopRawFormat::Bgrx),
                mode(9, 1280, 800, GopRawFormat::Bgrx),
            ]),
            Ok(8)
        );
        let mut narrow = mode(6, 1280, 800, GopRawFormat::Bgrx);
        narrow.stride_px = 1279;
        assert_eq!(
            select_reference_mode(&[narrow]),
            Err(GopRejection::UnsupportedFormat)
        );
        let too_many: Vec<_> = (0..=MAX_GOP_MODES as u32)
            .map(|index| mode(index, 1280, 800, GopRawFormat::Bgrx))
            .collect();
        assert_eq!(
            select_reference_mode(&too_many),
            Err(GopRejection::TooManyModes)
        );
        assert_eq!(select_reference_mode(&too_many[..MAX_GOP_MODES]), Ok(0));
    }

    #[test]
    fn raw_format_decode_never_panics() {
        assert_eq!(GopRawFormat::from_raw(0), GopRawFormat::Rgbx);
        assert_eq!(GopRawFormat::from_raw(1), GopRawFormat::Bgrx);
        assert_eq!(GopRawFormat::from_raw(2), GopRawFormat::Bitmask);
        assert_eq!(GopRawFormat::from_raw(3), GopRawFormat::BltOnly);
        assert_eq!(GopRawFormat::from_raw(4), GopRawFormat::Unknown(4));
        assert_eq!(
            GopRawFormat::from_raw(u32::MAX),
            GopRawFormat::Unknown(u32::MAX)
        );
    }

    #[test]
    fn validate_framebuffer_accepts_reference() {
        let fb = validate_framebuffer(reference_raw()).unwrap();
        assert_eq!(fb.phys_base, 0x8000_0000);
        assert_eq!(fb.byte_len, 4_096_000);
        assert_eq!(fb.map_len, 4_096_000);
        assert_eq!(fb.page_count(), 1000);
        assert_eq!(fb.stride_bytes, 5120);
        assert_eq!(fb.order, GopPixelOrder::Bgrx);
        assert_eq!(fb.mode_index, 7);
    }

    #[test]
    fn validate_framebuffer_uses_stride_for_length() {
        let raw = RawFramebufferInfo {
            stride_px: 1281,
            format: GopRawFormat::Rgbx,
            ..reference_raw()
        };
        let fb = validate_framebuffer(raw).unwrap();
        assert_eq!(fb.stride_bytes, 1281 * 4);
        assert_eq!(fb.byte_len, 1281 * 4 * 800);
        assert_eq!(fb.map_len, (1281 * 4 * 800_u64).next_multiple_of(PAGE_SIZE));
        assert!(fb.map_len > fb.byte_len);
        assert_eq!(fb.order, GopPixelOrder::Rgbx);
    }

    #[test]
    fn validate_framebuffer_rejection_matrix() {
        let base = reference_raw();
        let cases = [
            (
                RawFramebufferInfo {
                    width: 1024,
                    ..base
                },
                GopRejection::ModeMismatchAfterSet,
            ),
            (
                RawFramebufferInfo {
                    height: 768,
                    ..base
                },
                GopRejection::ModeMismatchAfterSet,
            ),
            (
                RawFramebufferInfo {
                    format: GopRawFormat::Bitmask,
                    ..base
                },
                GopRejection::UnsupportedFormat,
            ),
            (
                RawFramebufferInfo {
                    format: GopRawFormat::BltOnly,
                    ..base
                },
                GopRejection::UnsupportedFormat,
            ),
            (
                RawFramebufferInfo {
                    format: GopRawFormat::Unknown(9),
                    ..base
                },
                GopRejection::UnsupportedFormat,
            ),
            (
                RawFramebufferInfo {
                    stride_px: 1279,
                    ..base
                },
                GopRejection::StrideInvalid,
            ),
            (
                RawFramebufferInfo {
                    stride_px: MAX_STRIDE_BYTES / 4 + 1,
                    ..base
                },
                GopRejection::StrideInvalid,
            ),
            (
                RawFramebufferInfo {
                    stride_px: u32::MAX,
                    ..base
                },
                GopRejection::StrideInvalid,
            ),
            (
                RawFramebufferInfo {
                    size: 4_096_000 - 1,
                    ..base
                },
                GopRejection::SizeTooSmall,
            ),
            (
                RawFramebufferInfo { base: 0, ..base },
                GopRejection::BaseInvalid,
            ),
            (
                RawFramebufferInfo {
                    base: 0x8000_0010,
                    ..base
                },
                GopRejection::BaseInvalid,
            ),
            (
                RawFramebufferInfo {
                    base: u64::MAX & !(PAGE_SIZE - 1),
                    ..base
                },
                GopRejection::RangeOverflow,
            ),
            (
                RawFramebufferInfo {
                    base: PHYSMAP_SPAN - PAGE_SIZE,
                    ..base
                },
                GopRejection::BeyondPhysmapSpan,
            ),
        ];
        for (raw, expected) in cases {
            assert_eq!(validate_framebuffer(raw), Err(expected), "{raw:?}");
        }
        let at_span_end = RawFramebufferInfo {
            base: PHYSMAP_SPAN - 1000 * PAGE_SIZE,
            ..base
        };
        assert!(validate_framebuffer(at_span_end).is_ok());
    }

    #[test]
    fn aperture_conflicts_only_with_usable_ram() {
        let fb = validate_framebuffer(reference_raw()).unwrap();
        let region = |start: u64, end: u64, kind| MemoryRegion { start, end, kind };
        let usable = MemoryRegionKind::Usable;
        let reserved = MemoryRegionKind::Reserved;

        assert_eq!(aperture_conflicts(&[], &fb), Ok(()));
        assert_eq!(
            aperture_conflicts(&[region(0x1000, 0x7fff_f000, usable)], &fb),
            Ok(())
        );
        assert_eq!(
            aperture_conflicts(
                &[
                    region(0x1000, fb.phys_base, usable),
                    region(fb.phys_end(), fb.phys_end() + 0x1000, usable),
                ],
                &fb
            ),
            Ok(()),
            "touching both edges is not an overlap"
        );
        assert_eq!(
            aperture_conflicts(
                &[region(fb.phys_end() - PAGE_SIZE, fb.phys_end(), usable)],
                &fb
            ),
            Err(GopRejection::OverlapsUsableRam)
        );
        assert_eq!(
            aperture_conflicts(
                &[region(
                    fb.phys_base - PAGE_SIZE,
                    fb.phys_base + PAGE_SIZE,
                    usable
                )],
                &fb
            ),
            Err(GopRejection::OverlapsUsableRam)
        );
        assert_eq!(
            aperture_conflicts(&[region(0x7000_0000, 0x9000_0000, reserved)], &fb),
            Ok(()),
            "firmware-reserved framebuffer memory is not allocator RAM"
        );
    }
}
