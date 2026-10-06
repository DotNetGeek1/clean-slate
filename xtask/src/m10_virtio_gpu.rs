//! M10 #114 VirtIO-GPU scanout lane (`cargo xtask test-m10-virtio-gpu`).
//!
//! Kernel display host tests, then one boot of the `m10-virtio-gpu-self-test` kernel against a
//! modern-only `virtio-gpu-pci` with no VGA. The guest drives create/attach/scanout/transfer/flush,
//! a buffer switch, a forced W3 timeout, reset to a new epoch and release, and prints `[VGPU]`
//! markers; the host checks their order and the figures they carry. Visual proof of the scanout is
//! #118/#119 through #197.

use crate::marker_spec::MarkerSet;
use crate::{prepare_vm, run_cargo_package_tests, run_driven_acceptance_command, NoDriver};
use crate::{VmLaunchConfig, XtaskError};
use std::time::Duration;

/// `ioeventfd=off`: a request that is never notified is never seen, so the forced timeout is
/// deterministic.
pub(crate) const GPU_DEVICE: &str =
    "virtio-gpu-pci,disable-legacy=on,xres=1280,yres=800,ioeventfd=off";
/// As the #196 lane: no 64-bit PCI aperture, so the BARs land inside the kernel identity map.
const OVMF_MMIO64: &str = "name=opt/ovmf/X-PciMmio64Mb,string=0";
const TIMEOUT: Duration = Duration::from_secs(60);

/// `REFERENCE_FRAME_BYTES` (1280 × 800 × 4).
const FRAME_BYTES: u64 = 4_096_000;
/// `REFERENCE_B_DAMAGE` areas × 4 bytes: 64×48 + 32×32 + 80×40 pixels.
const B_DAMAGE_BYTES: u64 = (64 * 48 + 32 * 32 + 80 * 40) * 4;
const _: () = assert!(B_DAMAGE_BYTES < FRAME_BYTES);

pub(crate) const MARKERS: [&str; 12] = [
    "[VIRTIO] modern id=16 slot=0 irq=msix vector=",
    "[DISP] backend=virtio-gpu output=0 epoch=1",
    "[VGPU] bring-up ok display-info=1280x800 resource=1 format=b8g8r8x8 scanout=0 completed=3",
    "[VGPU] scanout buffers mapped=2 stride=5120",
    "[VGPU] present seq=1 buffer=0 attach=1 transfers=1 flushes=1 irq-completed",
    "[VGPU] present seq=2 buffer=1 detach=1 attach=2 transfers=4 flushes=2 damage-bytes=",
    "[VGPU] readback crc32=0x20f2eec9",
    "[VGPU] timeout -> reset-required seq=3 error=device-timeout present-rejected",
    "[VGPU] reset ok epoch=2 generation=",
    "[VGPU] present seq=4 buffer=1 epoch=2 reattached",
    "[VGPU] release ok detach=1 unref=1 device-reset=1",
    "[VGPU] PASS",
];

pub(crate) fn qemu_args() -> Vec<String> {
    [
        "-vga",
        "none",
        "-device",
        GPU_DEVICE,
        "-fw_cfg",
        OVMF_MMIO64,
    ]
    .iter()
    .map(|arg| (*arg).to_string())
    .collect()
}

/// Constituent; does not print `[M10  ] PASS`.
pub(crate) fn run_acceptance() -> Result<(), XtaskError> {
    run_cargo_package_tests("clean-slate-kernel", &["device::display"])?;
    run_cargo_package_tests("clean-slate-kernel", &["device::virtio"])?;
    let mut vm = prepare_vm(
        false,
        false,
        &["m10-virtio-gpu-self-test"],
        VmLaunchConfig::default(),
    )?;
    vm.qemu.args(qemu_args());
    let output = run_driven_acceptance_command(
        &mut vm.qemu,
        MarkerSet::Ordered(&MARKERS),
        TIMEOUT,
        &mut NoDriver,
    )?;
    validate_serial(&output).map_err(XtaskError::Validation)?;
    println!("[M10.virtio-gpu] PASS");
    Ok(())
}

/// Checks the figures behind the ordered markers: the switch present moved only the damaged
/// bytes, the reset produced a new transport generation, and no other display backend or guest
/// failure appeared.
pub(crate) fn validate_serial(serial: &str) -> Result<(), String> {
    if let Some(line) = serial.lines().find(|line| line.contains("[FAIL]")) {
        return Err(format!("guest failure: {}", line.trim_end()));
    }
    if serial.contains("[DISP] backend=gop") {
        return Err("a GOP display was installed; the lane needs the VirtIO-GPU backend".into());
    }
    let damage = field(serial, "damage-bytes=")?;
    let frame = field(serial, "frame-bytes=")?;
    if frame != FRAME_BYTES {
        return Err(format!("frame-bytes={frame}, expected {FRAME_BYTES}"));
    }
    if damage != B_DAMAGE_BYTES {
        return Err(format!(
            "damage-bytes={damage}, expected {B_DAMAGE_BYTES} (damage-only transfer)"
        ));
    }
    let generation = field(serial, "[VGPU] reset ok epoch=2 generation=")?;
    if generation < 2 {
        return Err(format!("reset generation={generation}, expected a new one"));
    }
    Ok(())
}

/// The decimal value after the first `key` in `serial`.
fn field(serial: &str, key: &str) -> Result<u64, String> {
    let start = serial
        .find(key)
        .map(|at| at + key.len())
        .ok_or_else(|| format!("missing `{key}`"))?;
    let digits: String = serial[start..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits
        .parse()
        .map_err(|_| format!("`{key}` has no decimal value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "\
[VIRTIO] modern id=16 slot=0 irq=msix vector=0x0\r\n\
[DISP] backend=virtio-gpu output=0 epoch=1\r\n\
[VGPU] bring-up ok display-info=1280x800 resource=1 format=b8g8r8x8 scanout=0 completed=3\r\n\
[VGPU] scanout buffers mapped=2 stride=5120\r\n\
[VGPU] present seq=1 buffer=0 attach=1 transfers=1 flushes=1 irq-completed\r\n\
[VGPU] present seq=2 buffer=1 detach=1 attach=2 transfers=4 flushes=2 damage-bytes=29184 frame-bytes=4096000\r\n\
[VGPU] readback crc32=0x20f2eec9\r\n\
[VGPU] timeout -> reset-required seq=3 error=device-timeout present-rejected\r\n\
[VGPU] reset ok epoch=2 generation=2\r\n\
[VGPU] present seq=4 buffer=1 epoch=2 reattached\r\n\
[VGPU] release ok detach=1 unref=1 device-reset=1\r\n\
[VGPU] PASS\r\n";

    #[test]
    fn markers_are_found_in_order_in_a_passing_serial() {
        let mut rest = GOOD;
        for marker in MARKERS {
            let at = rest
                .find(marker)
                .unwrap_or_else(|| panic!("missing {marker}"));
            rest = &rest[at + marker.len()..];
        }
    }

    #[test]
    fn a_passing_serial_validates() {
        assert_eq!(validate_serial(GOOD), Ok(()));
    }

    #[test]
    fn b_damage_bytes_match_the_reference_rects() {
        assert_eq!(B_DAMAGE_BYTES, 29_184);
    }

    #[test]
    fn a_full_frame_transfer_on_the_switch_is_rejected() {
        let serial = GOOD.replace("damage-bytes=29184", "damage-bytes=4096000");
        assert!(validate_serial(&serial)
            .unwrap_err()
            .contains("damage-only"));
    }

    #[test]
    fn a_wrong_frame_size_is_rejected() {
        let serial = GOOD.replace("frame-bytes=4096000", "frame-bytes=4194304");
        assert!(validate_serial(&serial).is_err());
    }

    #[test]
    fn a_reset_that_kept_the_generation_is_rejected() {
        let serial = GOOD.replace("generation=2", "generation=1");
        assert!(validate_serial(&serial).is_err());
    }

    #[test]
    fn a_guest_failure_or_gop_backend_is_rejected() {
        let failed = format!("{GOOD}[FAIL] m10-virtio-gpu: present rejected\r\n");
        assert!(validate_serial(&failed)
            .unwrap_err()
            .contains("guest failure"));
        let gop = GOOD.replace("backend=virtio-gpu", "backend=gop");
        assert!(validate_serial(&gop).is_err());
    }

    #[test]
    fn missing_figures_are_rejected() {
        let serial = GOOD.replace("damage-bytes=29184 ", "");
        assert!(validate_serial(&serial)
            .unwrap_err()
            .contains("damage-bytes"));
    }

    #[test]
    fn qemu_args_are_modern_only_without_vga() {
        let args = qemu_args();
        assert_eq!(args[..2], ["-vga".to_string(), "none".to_string()]);
        assert!(args.contains(&GPU_DEVICE.to_string()));
        assert!(GPU_DEVICE.contains("disable-legacy=on"));
        assert!(GPU_DEVICE.contains("xres=1280,yres=800"));
        assert!(GPU_DEVICE.contains("ioeventfd=off"));
        assert!(args.contains(&OVMF_MMIO64.to_string()));
    }
}
