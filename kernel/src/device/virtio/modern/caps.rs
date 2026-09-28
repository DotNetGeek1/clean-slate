//! VirtIO 1.x PCI vendor-capability decoding (virtio 1.2 §4.1.4): locates the
//! common, notify, ISR and device-config regions and validates each against
//! its sized BAR before any MMIO touches it.

use crate::device::pci::capabilities;
use crate::device::pci::memory_bar;
use crate::device::pci::MemoryBar;
use crate::device::pci::{PciConfigRead, PciConfigWrite, PciError};

pub(crate) const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
pub(crate) const VIRTIO_PCI_MODERN_DEVICE_BASE: u16 = 0x1040;

pub(crate) const CFG_TYPE_COMMON: u8 = 1;
pub(crate) const CFG_TYPE_NOTIFY: u8 = 2;
pub(crate) const CFG_TYPE_ISR: u8 = 3;
pub(crate) const CFG_TYPE_DEVICE: u8 = 4;

/// Through `queue_device` (0x30..0x38); the 1.2 `queue_notify_data`/`queue_reset`
/// fields are never touched.
pub(crate) const COMMON_CFG_MIN_LEN: u32 = 0x38;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CapKind {
    Common,
    Notify,
    Isr,
    Device,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CapError {
    NotModern,
    NoCapabilityList,
    ListMalformed,
    Malformed,
    Bar,
    OutOfBar,
    Misaligned,
    TooShort,
    BadMultiplier,
    Missing(CapKind),
    NotifyOutOfRange,
}

/// What a BAR index resolves to for capability validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BarKind {
    Memory(MemoryBar),
    Io,
    /// Unimplemented, unassigned, reserved type, or the upper half of a 64-bit BAR.
    Unusable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Bars(pub(crate) [BarKind; 6]);

impl Bars {
    /// Size every BAR of `cfg`. Must run before bus mastering is enabled.
    pub(crate) fn probe<C: PciConfigWrite>(cfg: &C) -> Self {
        let mut upper_half = [false; 6];
        let mut kinds = [BarKind::Unusable; 6];
        for index in 0usize..6 {
            let low = cfg.read_u32(0x10 + 4 * index as u8);
            if low & 1 == 0 && (low >> 1) & 0x3 == 2 && index + 1 < 6 {
                upper_half[index + 1] = true;
            }
        }
        for index in 0usize..6 {
            if upper_half[index] {
                kinds[index] = BarKind::Unusable;
            } else {
                kinds[index] = match memory_bar(cfg, index as u8) {
                    Ok(bar) => BarKind::Memory(bar),
                    Err(PciError::IoBar) => BarKind::Io,
                    Err(_) => BarKind::Unusable,
                };
            }
        }
        Bars(kinds)
    }
}

/// A validated region: `phys = bar.base + offset`, and `[offset, offset + length)`
/// lies inside the BAR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Region {
    pub(crate) bar: u8,
    pub(crate) offset: u32,
    pub(crate) length: u32,
    pub(crate) phys: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ModernLayout {
    pub(crate) common: Region,
    pub(crate) notify: Region,
    pub(crate) notify_off_multiplier: u32,
    pub(crate) isr: Region,
    pub(crate) device: Option<Region>,
    /// Diagnostics only: capabilities skipped by the spec's ignore rules.
    pub(crate) ignored: u8,
    /// Diagnostics only: valid capabilities after the first of their type.
    pub(crate) duplicates: u8,
}

/// Modern-only identity: vendor 0x1AF4, device `0x1040 + virtio_id`, revision >= 1.
pub(crate) fn check_device_identity(
    vendor: u16,
    device: u16,
    revision: u8,
    virtio_id: u16,
) -> Result<(), CapError> {
    if vendor != VIRTIO_PCI_VENDOR_ID {
        return Err(CapError::NotModern);
    }
    if VIRTIO_PCI_MODERN_DEVICE_BASE.checked_add(virtio_id) != Some(device) {
        return Err(CapError::NotModern);
    }
    if revision < 1 {
        return Err(CapError::NotModern);
    }
    Ok(())
}

/// Decode and validate the VirtIO vendor capabilities of `cfg`.
pub(crate) fn decode_modern_layout<C: PciConfigRead>(
    cfg: &C,
    bars: &Bars,
) -> Result<ModernLayout, CapError> {
    if cfg.read_u16(0x06) & (1 << 4) == 0 {
        return Err(CapError::NoCapabilityList);
    }

    let mut common = None;
    let mut notify = None;
    let mut notify_off_multiplier = 0u32;
    let mut isr = None;
    let mut device = None;
    let mut ignored = 0u8;
    let mut duplicates = 0u8;

    const VENDOR_CAP_ID: u8 = 0x09;

    for item in capabilities(cfg) {
        let (off, id) = item.map_err(|_| CapError::ListMalformed)?;
        if id != VENDOR_CAP_ID {
            continue;
        }

        let cap_len = cfg.read_u8(off + 2);
        if off as usize + cap_len as usize > 256 || cap_len < 16 {
            return Err(CapError::Malformed);
        }
        let cfg_type = cfg.read_u8(off + 3);
        if cfg_type == CFG_TYPE_NOTIFY && cap_len < 20 {
            return Err(CapError::Malformed);
        }

        if !matches!(
            cfg_type,
            CFG_TYPE_COMMON | CFG_TYPE_NOTIFY | CFG_TYPE_ISR | CFG_TYPE_DEVICE
        ) {
            ignored = ignored.saturating_add(1);
            continue;
        }

        let bar = cfg.read_u8(off + 4);
        if bar > 5 {
            ignored = ignored.saturating_add(1);
            continue;
        }

        let memory_bar = match bars.0[usize::from(bar)] {
            BarKind::Io => {
                ignored = ignored.saturating_add(1);
                continue;
            }
            BarKind::Unusable => return Err(CapError::Bar),
            BarKind::Memory(b) => b,
        };

        let offset = cfg.read_u32(off + 8);
        let length = cfg.read_u32(off + 12);
        let end = offset.checked_add(length);
        if end.is_none() || u64::from(end.unwrap()) > memory_bar.size {
            return Err(CapError::OutOfBar);
        }

        let aligned = match cfg_type {
            CFG_TYPE_COMMON | CFG_TYPE_DEVICE => offset.is_multiple_of(4),
            CFG_TYPE_NOTIFY => offset.is_multiple_of(2),
            CFG_TYPE_ISR => true,
            _ => true,
        };
        if !aligned {
            return Err(CapError::Misaligned);
        }

        let min_len = match cfg_type {
            CFG_TYPE_COMMON => COMMON_CFG_MIN_LEN,
            CFG_TYPE_NOTIFY => 2,
            CFG_TYPE_ISR | CFG_TYPE_DEVICE => 1,
            _ => 0,
        };
        if length < min_len {
            return Err(CapError::TooShort);
        }

        let mult = if cfg_type == CFG_TYPE_NOTIFY {
            let mult = cfg.read_u32(off + 16);
            if mult != 0 && (mult < 2 || !mult.is_power_of_two()) {
                return Err(CapError::BadMultiplier);
            }
            mult
        } else {
            0
        };

        let phys = memory_bar
            .base
            .checked_add(u64::from(offset))
            .ok_or(CapError::OutOfBar)?;
        let region = Region {
            bar,
            offset,
            length,
            phys,
        };

        match cfg_type {
            CFG_TYPE_COMMON => {
                if common.is_some() {
                    duplicates = duplicates.saturating_add(1);
                } else {
                    common = Some(region);
                }
            }
            CFG_TYPE_NOTIFY => {
                if notify.is_some() {
                    duplicates = duplicates.saturating_add(1);
                } else {
                    notify = Some(region);
                    notify_off_multiplier = mult;
                }
            }
            CFG_TYPE_ISR => {
                if isr.is_some() {
                    duplicates = duplicates.saturating_add(1);
                } else {
                    isr = Some(region);
                }
            }
            CFG_TYPE_DEVICE => {
                if device.is_some() {
                    duplicates = duplicates.saturating_add(1);
                } else {
                    device = Some(region);
                }
            }
            _ => {}
        }
    }

    let common = common.ok_or(CapError::Missing(CapKind::Common))?;
    let notify = notify.ok_or(CapError::Missing(CapKind::Notify))?;
    let isr = isr.ok_or(CapError::Missing(CapKind::Isr))?;

    Ok(ModernLayout {
        common,
        notify,
        notify_off_multiplier,
        isr,
        device,
        ignored,
        duplicates,
    })
}

/// Notify address of a queue: `notify.phys + queue_notify_off * multiplier`,
/// with the 16-bit notify write inside the notify region.
pub(crate) fn notify_address(
    notify: &Region,
    multiplier: u32,
    queue_notify_off: u16,
) -> Result<u64, CapError> {
    let _ = (notify, multiplier, queue_notify_off);
    todo!("#196 stage 3a")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::pci::FakeConfigSpace;

    const BAR4_BASE: u64 = 0x0000_0080_0000_0000;
    const BAR4_SIZE: u64 = 0x4000;
    const STATUS_OFFSET: u8 = 0x06;
    const STATUS_CAPABILITIES_LIST: u16 = 1 << 4;
    const CAP_POINTER_OFFSET: u8 = 0x34;
    const VENDOR_CAP_ID: u8 = 0x09;
    const MSIX_CAP_ID: u8 = 0x11;

    fn bar4() -> MemoryBar {
        MemoryBar {
            index: 4,
            base: BAR4_BASE,
            size: BAR4_SIZE,
            is_64: true,
            prefetchable: true,
        }
    }

    fn qemu_bars() -> Bars {
        let mut bars = [BarKind::Unusable; 6];
        bars[4] = BarKind::Memory(bar4());
        Bars(bars)
    }

    #[derive(Clone, Copy)]
    struct Cap {
        id: u8,
        cfg_type: u8,
        bar: u8,
        offset: u32,
        length: u32,
        multiplier: Option<u32>,
        cap_len: Option<u8>,
    }

    fn vendor(cfg_type: u8, bar: u8, offset: u32, length: u32) -> Cap {
        Cap {
            id: VENDOR_CAP_ID,
            cfg_type,
            bar,
            offset,
            length,
            multiplier: None,
            cap_len: None,
        }
    }

    fn notify(bar: u8, offset: u32, length: u32, multiplier: u32) -> Cap {
        Cap {
            multiplier: Some(multiplier),
            ..vendor(CFG_TYPE_NOTIFY, bar, offset, length)
        }
    }

    fn common() -> Cap {
        vendor(CFG_TYPE_COMMON, 4, 0x0000, 0x1000)
    }

    fn isr() -> Cap {
        vendor(CFG_TYPE_ISR, 4, 0x1000, 0x1000)
    }

    fn device() -> Cap {
        vendor(CFG_TYPE_DEVICE, 4, 0x2000, 0x1000)
    }

    fn qemu_notify() -> Cap {
        notify(4, 0x3000, 0x1000, 4)
    }

    fn pci_cfg() -> Cap {
        vendor(5, 0, 0, 0)
    }

    /// QEMU's modern virtio-pci order: common, ISR, device, notify, PCI_CFG.
    fn qemu_caps() -> [Cap; 5] {
        [common(), isr(), device(), qemu_notify(), pci_cfg()]
    }

    /// Config space with `caps` chained from 0x40 in order, 20 bytes apart.
    fn config_with(caps: &[Cap]) -> FakeConfigSpace {
        let cfg = FakeConfigSpace::new();
        cfg.set_u16(0x00, VIRTIO_PCI_VENDOR_ID);
        cfg.set_u16(STATUS_OFFSET, STATUS_CAPABILITIES_LIST);
        cfg.set_u8(CAP_POINTER_OFFSET, if caps.is_empty() { 0 } else { 0x40 });
        let mut offset = 0x40u8;
        for (index, cap) in caps.iter().enumerate() {
            let next = if index + 1 == caps.len() {
                0
            } else {
                offset + 20
            };
            write_cap(&cfg, offset, next, cap);
            offset += 20;
        }
        cfg
    }

    fn write_cap(cfg: &FakeConfigSpace, at: u8, next: u8, cap: &Cap) {
        let default_len = if cap.multiplier.is_some() { 20 } else { 16 };
        cfg.set_u8(at, cap.id);
        cfg.set_u8(at + 1, next);
        cfg.set_u8(at + 2, cap.cap_len.unwrap_or(default_len));
        cfg.set_u8(at + 3, cap.cfg_type);
        cfg.set_u8(at + 4, cap.bar);
        cfg.set_u32(at + 8, cap.offset);
        cfg.set_u32(at + 12, cap.length);
        if let Some(multiplier) = cap.multiplier {
            cfg.set_u32(at + 16, multiplier);
        }
    }

    fn decode(caps: &[Cap]) -> Result<ModernLayout, CapError> {
        decode_modern_layout(&config_with(caps), &qemu_bars())
    }

    fn region(offset: u32, length: u32) -> Region {
        Region {
            bar: 4,
            offset,
            length,
            phys: BAR4_BASE + u64::from(offset),
        }
    }

    #[test]
    fn qemu_layout_decodes() {
        let layout = decode(&qemu_caps()).expect("QEMU layout");
        assert_eq!(layout.common, region(0x0000, 0x1000));
        assert_eq!(layout.isr, region(0x1000, 0x1000));
        assert_eq!(layout.device, Some(region(0x2000, 0x1000)));
        assert_eq!(layout.notify, region(0x3000, 0x1000));
        assert_eq!(layout.notify_off_multiplier, 4);
        assert_eq!(layout.common.phys, 0x0000_0080_0000_0000);
        assert_eq!(layout.notify.phys, 0x0000_0080_0000_3000);
        assert_eq!(layout.ignored, 1);
        assert_eq!(layout.duplicates, 0);
    }

    #[test]
    fn non_vendor_capabilities_are_skipped() {
        let msix = Cap {
            id: MSIX_CAP_ID,
            ..vendor(0, 0, 0, 0)
        };
        let [a, b, c, d, e] = qemu_caps();
        let layout = decode(&[msix, a, b, c, d, e]).expect("layout with MSI-X");
        assert_eq!(layout.ignored, 1);
        assert_eq!(layout.common, region(0x0000, 0x1000));
    }

    #[test]
    fn pci_cfg_cap_with_unassigned_bar0_is_ignored() {
        let layout = decode(&[pci_cfg(), common(), isr(), qemu_notify()]).expect("layout");
        assert_eq!(layout.ignored, 1);
    }

    #[test]
    fn rng_like_layout_without_device_cap() {
        let layout = decode(&[common(), isr(), qemu_notify(), pci_cfg()]).expect("layout");
        assert_eq!(layout.device, None);
    }

    #[test]
    fn missing_common() {
        assert_eq!(
            decode(&[isr(), device(), qemu_notify()]),
            Err(CapError::Missing(CapKind::Common))
        );
    }

    #[test]
    fn missing_notify() {
        assert_eq!(
            decode(&[common(), isr(), device()]),
            Err(CapError::Missing(CapKind::Notify))
        );
    }

    #[test]
    fn missing_isr() {
        assert_eq!(
            decode(&[common(), device(), qemu_notify()]),
            Err(CapError::Missing(CapKind::Isr))
        );
    }

    #[test]
    fn duplicate_valid_common_first_wins() {
        let second = vendor(CFG_TYPE_COMMON, 4, 0x2000, 0x100);
        let layout = decode(&[common(), second, isr(), qemu_notify()]).expect("layout");
        assert_eq!(layout.common, region(0x0000, 0x1000));
        assert_eq!(layout.duplicates, 1);
    }

    #[test]
    fn duplicate_malformed_notify_after_valid_fails() {
        let bad = notify(4, 0x3800, 0x1000, 4);
        assert_eq!(
            decode(&[common(), isr(), qemu_notify(), bad]),
            Err(CapError::OutOfBar)
        );
    }

    #[test]
    fn notify_on_io_bar_ignored_memory_notify_used() {
        let mut bars = qemu_bars();
        bars.0[2] = BarKind::Io;
        let cfg = config_with(&[
            notify(2, 0, 0x40, 4),
            common(),
            isr(),
            qemu_notify(),
            pci_cfg(),
        ]);
        let layout = decode_modern_layout(&cfg, &bars).expect("layout");
        assert_eq!(layout.notify, region(0x3000, 0x1000));
        assert_eq!(layout.ignored, 2);
        assert_eq!(layout.duplicates, 0);
    }

    #[test]
    fn reserved_bar_index_ignored() {
        let [a, b, c, d, e] = qemu_caps();
        let layout =
            decode(&[a, b, c, d, e, vendor(CFG_TYPE_COMMON, 7, 0, 0x1000)]).expect("layout");
        assert_eq!(layout.ignored, 2);
        assert_eq!(layout.duplicates, 0);
    }

    #[test]
    fn unknown_cfg_types_ignored() {
        let mut caps = vec![common(), isr(), qemu_notify()];
        for cfg_type in [0u8, 5, 6, 8, 9, 200] {
            caps.push(vendor(cfg_type, 4, 0, 0x10));
        }
        let layout = decode(&caps).expect("layout");
        assert_eq!(layout.ignored, 6);
    }

    #[test]
    fn region_end_equals_bar_size_ok() {
        let tail = vendor(CFG_TYPE_DEVICE, 4, 0x3f00, 0x100);
        let layout = decode(&[common(), isr(), qemu_notify(), tail]).expect("layout");
        assert_eq!(layout.device, Some(region(0x3f00, 0x100)));
    }

    #[test]
    fn region_beyond_bar() {
        let past = vendor(CFG_TYPE_DEVICE, 4, 0x3f00, 0x101);
        assert_eq!(
            decode(&[common(), isr(), qemu_notify(), past]),
            Err(CapError::OutOfBar)
        );
    }

    #[test]
    fn offset_plus_length_overflows_u32() {
        let wrap = vendor(CFG_TYPE_DEVICE, 4, 0xffff_ff00, 0x200);
        assert_eq!(
            decode(&[common(), isr(), qemu_notify(), wrap]),
            Err(CapError::OutOfBar)
        );
    }

    #[test]
    fn misaligned_common() {
        let bad = vendor(CFG_TYPE_COMMON, 4, 0x2, 0x100);
        assert_eq!(
            decode(&[bad, isr(), qemu_notify()]),
            Err(CapError::Misaligned)
        );
    }

    #[test]
    fn misaligned_notify() {
        assert_eq!(
            decode(&[common(), isr(), notify(4, 0x3001, 0x100, 4)]),
            Err(CapError::Misaligned)
        );
    }

    #[test]
    fn misaligned_device() {
        let bad = vendor(CFG_TYPE_DEVICE, 4, 0x2002, 0x100);
        assert_eq!(
            decode(&[common(), isr(), qemu_notify(), bad]),
            Err(CapError::Misaligned)
        );
    }

    #[test]
    fn common_shorter_than_0x38() {
        let short = vendor(CFG_TYPE_COMMON, 4, 0, COMMON_CFG_MIN_LEN - 4);
        assert_eq!(
            decode(&[short, isr(), qemu_notify()]),
            Err(CapError::TooShort)
        );
        let exact = vendor(CFG_TYPE_COMMON, 4, 0, COMMON_CFG_MIN_LEN);
        assert!(decode(&[exact, isr(), qemu_notify()]).is_ok());
    }

    #[test]
    fn isr_zero_length() {
        let empty = vendor(CFG_TYPE_ISR, 4, 0x1000, 0);
        assert_eq!(
            decode(&[common(), empty, qemu_notify()]),
            Err(CapError::TooShort)
        );
    }

    #[test]
    fn notify_length_1() {
        assert_eq!(
            decode(&[common(), isr(), notify(4, 0x3000, 1, 4)]),
            Err(CapError::TooShort)
        );
    }

    #[test]
    fn cap_len_12() {
        let short = Cap {
            cap_len: Some(12),
            ..common()
        };
        assert_eq!(
            decode(&[short, isr(), qemu_notify()]),
            Err(CapError::Malformed)
        );
    }

    #[test]
    fn notify_cap_len_16() {
        let short = Cap {
            cap_len: Some(16),
            ..qemu_notify()
        };
        assert_eq!(decode(&[common(), isr(), short]), Err(CapError::Malformed));
    }

    #[test]
    fn cap_crosses_config_space_end() {
        let cfg = config_with(&[common(), isr(), qemu_notify()]);
        // Re-link the notify cap (third, at 0x68) to a cap at 0xf8 whose 16 bytes pass 0x100.
        cfg.set_u8(0x68 + 1, 0xf8);
        cfg.set_u8(0xf8, VENDOR_CAP_ID);
        cfg.set_u8(0xf9, 0);
        cfg.set_u8(0xfa, 16);
        cfg.set_u8(0xfb, CFG_TYPE_DEVICE);
        assert_eq!(
            decode_modern_layout(&cfg, &qemu_bars()),
            Err(CapError::Malformed)
        );
    }

    #[test]
    fn cap_list_loop() {
        let cfg = config_with(&[common(), isr(), qemu_notify()]);
        cfg.set_u8(0x68 + 1, 0x54);
        assert_eq!(
            decode_modern_layout(&cfg, &qemu_bars()),
            Err(CapError::ListMalformed)
        );
    }

    #[test]
    fn cap_ptr_below_0x40() {
        let cfg = config_with(&[common(), isr(), qemu_notify()]);
        cfg.set_u8(0x54 + 1, 0x3c);
        assert_eq!(
            decode_modern_layout(&cfg, &qemu_bars()),
            Err(CapError::ListMalformed)
        );
    }

    #[test]
    fn bar_unassigned_for_common() {
        let bad = vendor(CFG_TYPE_COMMON, 0, 0, 0x1000);
        assert_eq!(decode(&[bad, isr(), qemu_notify()]), Err(CapError::Bar));
    }

    #[test]
    fn bar_is_upper_half_of_64bit() {
        let bad = vendor(CFG_TYPE_COMMON, 5, 0, 0x1000);
        assert_eq!(decode(&[bad, isr(), qemu_notify()]), Err(CapError::Bar));
    }

    #[test]
    fn notify_multiplier_3() {
        assert_eq!(
            decode(&[common(), isr(), notify(4, 0x3000, 0x1000, 3)]),
            Err(CapError::BadMultiplier)
        );
    }

    #[test]
    fn notify_multiplier_1() {
        assert_eq!(
            decode(&[common(), isr(), notify(4, 0x3000, 0x1000, 1)]),
            Err(CapError::BadMultiplier)
        );
    }

    #[test]
    fn notify_multiplier_0() {
        let layout = decode(&[common(), isr(), notify(4, 0x3000, 0x1000, 0)]).expect("layout");
        assert_eq!(layout.notify_off_multiplier, 0);
    }

    #[test]
    fn no_capability_list_bit() {
        let cfg = config_with(&qemu_caps());
        cfg.set_u16(STATUS_OFFSET, 0);
        assert_eq!(
            decode_modern_layout(&cfg, &qemu_bars()),
            Err(CapError::NoCapabilityList)
        );
    }

    #[test]
    fn identity_transitional_id_rejected() {
        assert_eq!(
            check_device_identity(VIRTIO_PCI_VENDOR_ID, 0x1001, 1, 2),
            Err(CapError::NotModern)
        );
    }

    #[test]
    fn identity_revision_0_rejected() {
        assert_eq!(
            check_device_identity(VIRTIO_PCI_VENDOR_ID, 0x1042, 0, 2),
            Err(CapError::NotModern)
        );
    }

    #[test]
    fn identity_wrong_vendor_rejected() {
        assert_eq!(
            check_device_identity(0x8086, 0x1050, 1, 16),
            Err(CapError::NotModern)
        );
    }

    #[test]
    fn identity_modern_gpu_ok() {
        assert_eq!(
            check_device_identity(VIRTIO_PCI_VENDOR_ID, 0x1050, 1, 16),
            Ok(())
        );
        assert_eq!(
            check_device_identity(VIRTIO_PCI_VENDOR_ID, 0x1042, 1, 2),
            Ok(())
        );
    }

    #[test]
    fn identity_id_overflow_rejected() {
        assert_eq!(
            check_device_identity(VIRTIO_PCI_VENDOR_ID, 0x103f, 1, u16::MAX),
            Err(CapError::NotModern)
        );
    }

    fn qemu_notify_region() -> Region {
        region(0x3000, 0x1000)
    }

    #[test]
    fn notify_address_is_base_plus_off_times_mult() {
        assert_eq!(
            notify_address(&qemu_notify_region(), 4, 3),
            Ok(BAR4_BASE + 0x3000 + 12)
        );
    }

    #[test]
    fn notify_zero_multiplier_shares_address() {
        let notify = qemu_notify_region();
        assert_eq!(notify_address(&notify, 0, 0), Ok(notify.phys));
        assert_eq!(notify_address(&notify, 0, 7), Ok(notify.phys));
        assert_eq!(notify_address(&notify, 0, u16::MAX), Ok(notify.phys));
    }

    #[test]
    fn notify_last_valid_offset_ok() {
        let notify = qemu_notify_region();
        assert_eq!(notify_address(&notify, 4, 1023), Ok(notify.phys + 4092));
        let tight = Region {
            length: 14,
            ..notify
        };
        assert_eq!(notify_address(&tight, 4, 3), Ok(notify.phys + 12));
    }

    #[test]
    fn notify_offset_past_length_fails() {
        let notify = qemu_notify_region();
        assert_eq!(
            notify_address(&notify, 4, 1024),
            Err(CapError::NotifyOutOfRange)
        );
        let tight = Region {
            length: 13,
            ..notify
        };
        assert_eq!(
            notify_address(&tight, 4, 3),
            Err(CapError::NotifyOutOfRange)
        );
    }

    #[test]
    fn notify_u16_max_with_large_mult_fails_without_overflow() {
        assert_eq!(
            notify_address(&qemu_notify_region(), 1 << 31, u16::MAX),
            Err(CapError::NotifyOutOfRange)
        );
    }

    #[test]
    fn notify_phys_overflow_fails() {
        let notify = Region {
            bar: 4,
            offset: 0,
            length: u32::MAX,
            phys: u64::MAX - 8,
        };
        assert_eq!(
            notify_address(&notify, 4, 4),
            Err(CapError::NotifyOutOfRange)
        );
    }
}

#[cfg(test)]
mod probe_tests {
    use super::*;
    use crate::device::pci::FakeConfigSpace;

    #[test]
    fn bars_probe_classifies_qemu_layout() {
        let mut cfg = FakeConfigSpace::new();
        cfg.bar_sizes[1] = 0x1000;
        cfg.bar_sizes[4] = 0x4000;
        cfg.set_u32(0x14, 0xfebd_1000);
        cfg.set_u32(0x20, 0x0000_000c);
        cfg.set_u32(0x24, 0x0000_0080);
        cfg.set_u32(0x18, 0x0000_0001);
        let bars = Bars::probe(&cfg);
        assert!(matches!(bars.0[0], BarKind::Unusable));
        assert_eq!(
            bars.0[1],
            BarKind::Memory(MemoryBar {
                index: 1,
                base: 0xfebd_1000,
                size: 0x1000,
                is_64: false,
                prefetchable: false,
            })
        );
        assert_eq!(bars.0[2], BarKind::Io);
        assert!(matches!(bars.0[3], BarKind::Unusable));
        if let BarKind::Memory(bar) = bars.0[4] {
            assert_eq!(bar.base, 0x80_0000_0000);
            assert_eq!(bar.size, 0x4000);
            assert!(bar.is_64);
            assert!(bar.prefetchable);
        } else {
            panic!("expected memory BAR4");
        }
        assert!(matches!(bars.0[5], BarKind::Unusable));
    }

    #[test]
    fn bars_probe_marks_unassigned_64bit_upper_half_unusable() {
        let mut cfg = FakeConfigSpace::new();
        cfg.bar_sizes[4] = 0x4000;
        cfg.set_u32(0x20, 0x0000_000c);
        cfg.set_u32(0x24, 0);
        let bars = Bars::probe(&cfg);
        assert!(matches!(bars.0[5], BarKind::Unusable));
    }
}
