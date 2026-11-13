//! M10 #114 VirtIO-GPU scanout lane (`cargo xtask test-m10-virtio-gpu`).
//!
//! Kernel display host tests, then one boot of the `m10-virtio-gpu-self-test` kernel against a
//! modern-only `virtio-gpu-pci` with no VGA. The guest drives create/attach/scanout/transfer/flush,
//! a buffer switch, a forced W3 timeout, reset to a new epoch and release, and prints `[VGPU]`
//! markers; the host checks their order and the figures they carry.
//!
//! The host also checks what QEMU displays. After the first present, the buffer switch and the
//! present after the reset, the guest prints `[VGPU] hold capture=<frame>` and keeps the scanout
//! still; the lane takes a QMP screendump, compares it pixel for pixel with a host render of the
//! frame, then releases the guest with one key tap (the guest polls the i8042 for it).

use std::sync::OnceLock;
use std::time::Duration;

use clean_slate_raster::{
    draw_reference_a, draw_reference_b, draw_reference_decoy, reference_layout, Canvas,
};

use crate::m10_framebuffer_validate::{bgrx_frame_to_rgb, compare_with_render};
use crate::marker_spec::MarkerSet;
use crate::qmp::image::Screenshot;
use crate::qmp::{InputAction, QCode, QmpScriptDriver, ScriptStep};
use crate::{prepare_vm, run_cargo_package_tests, run_driven_acceptance_command};
use crate::{xtask_artifact_root, AcceptanceDriver, VmLaunchConfig, XtaskError};

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

const HOLD_A: &str = "[VGPU] hold capture=a";
const HOLD_B: &str = "[VGPU] hold capture=b";
const HOLD_C: &str = "[VGPU] hold capture=c";

pub(crate) const MARKERS: [&str; 15] = [
    "[VIRTIO] modern id=16 slot=0 irq=msix vector=",
    "[DISP] backend=virtio-gpu output=0 epoch=1",
    "[VGPU] bring-up ok display-info=1280x800 resource=1 format=b8g8r8x8 completed=2",
    "[VGPU] scanout buffers mapped=2 stride=5120",
    "[VGPU] present seq=1 buffer=0 attach=1 set-scanout=1 transfers=1 flushes=1 irq-completed",
    HOLD_A,
    "[VGPU] present seq=2 buffer=1 detach=1 attach=2 transfers=4 flushes=2 damage-bytes=",
    HOLD_B,
    "[VGPU] readback crc32=0x20f2eec9",
    "[VGPU] timeout -> reset-required seq=3 error=device-timeout present-rejected",
    "[VGPU] reset ok epoch=2 generation=",
    "[VGPU] present seq=4 buffer=1 epoch=2 reattached set-scanout",
    HOLD_C,
    "[VGPU] release ok detach=1 unref=1 device-reset=1",
    "[VGPU] PASS",
];

/// The frames the host expects QEMU to display at each hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Frame {
    /// The first present: buffer 0, pattern A, full frame.
    A,
    /// The switch to buffer 1 with B's damage only: A with B's rects (the decoy is outside them).
    B,
    /// The full-frame present of buffer 1 after the reset: A, B and the decoy, on a new resource.
    AfterReset,
}

impl Frame {
    const ALL: [Frame; 3] = [Frame::A, Frame::B, Frame::AfterReset];

    fn label(self) -> &'static str {
        match self {
            Frame::A => "frame A after the first present",
            Frame::B => "frame B after the damage-only buffer switch",
            Frame::AfterReset => "the full frame after the reset",
        }
    }

    /// The BGRX bytes the guest's scanout buffers hold, drawn as the guest draws them.
    fn render_bgrx(self) -> Vec<u8> {
        let layout = reference_layout();
        let mut bytes = vec![0u8; layout.byte_len()];
        let mut canvas = Canvas::new(&mut bytes, layout).expect("reference layout");
        draw_reference_a(&mut canvas);
        if self != Frame::A {
            draw_reference_b(&mut canvas);
        }
        if self == Frame::AfterReset {
            draw_reference_decoy(&mut canvas);
        }
        bytes
    }

    /// The render as screendump RGB. The resource is `B8G8R8X8_UNORM`, which QEMU scans out as
    /// pixman `x8r8g8b8` and writes to the screendump as R, G, B: the same reordering as the GOP
    /// framebuffer lane, with the X byte dropped.
    fn expected_rgb(self) -> &'static [u8] {
        static RENDERS: OnceLock<[Vec<u8>; 3]> = OnceLock::new();
        let renders =
            RENDERS.get_or_init(|| Frame::ALL.map(|frame| bgrx_frame_to_rgb(&frame.render_bgrx())));
        &renders[self as usize]
    }

    fn check(self, shot: &Screenshot) -> Result<(), String> {
        compare_with_render(shot, self.expected_rgb())
            .map_err(|detail| format!("{}: {detail}", self.label()))
    }

    /// The `[VGPU]` line the guest prints while it holds this frame.
    fn hold_line(self) -> &'static str {
        match self {
            Frame::A => HOLD_A,
            Frame::B => HOLD_B,
            Frame::AfterReset => HOLD_C,
        }
    }

    fn capture_name(self) -> &'static str {
        match self {
            Frame::A => "virtio-gpu-a",
            Frame::B => "virtio-gpu-b",
            Frame::AfterReset => "virtio-gpu-after-reset",
        }
    }

    fn screendump_check(self) -> fn(&Screenshot) -> Result<(), String> {
        match self {
            Frame::A => |shot| Frame::A.check(shot),
            Frame::B => |shot| Frame::B.check(shot),
            Frame::AfterReset => |shot| Frame::AfterReset.check(shot),
        }
    }
}

/// Await each hold, capture and check the display, then release the guest.
fn capture_steps() -> Vec<ScriptStep> {
    Frame::ALL
        .into_iter()
        .flat_map(|frame| {
            [
                ScriptStep::AwaitLine(frame.hold_line()),
                ScriptStep::Screendump {
                    name: frame.capture_name(),
                    check: frame.screendump_check(),
                },
                ScriptStep::Input(InputAction::tap(QCode::A).to_vec()),
            ]
        })
        .collect()
}

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

/// Constituent; does not print `[M10 ] PASS`.
pub(crate) fn run_acceptance() -> Result<(), XtaskError> {
    run_cargo_package_tests("clean-slate-kernel", &["device::display"])?;
    run_cargo_package_tests("clean-slate-kernel", &["device::virtio"])?;
    let mut vm = prepare_vm(
        false,
        false,
        &["m10-virtio-gpu-self-test"],
        VmLaunchConfig::default(),
    )?;
    let mut driver =
        QmpScriptDriver::new("m10-virtio-gpu", capture_steps(), &xtask_artifact_root())?;
    vm.qemu.args(qemu_args());
    vm.qemu.args(driver.qemu_args());
    let output = run_driven_acceptance_command(
        &mut vm.qemu,
        MarkerSet::Ordered(&MARKERS),
        TIMEOUT,
        &mut driver,
    )?;
    validate_serial(&output).map_err(XtaskError::Validation)?;
    if !driver.is_complete() || driver.captures().len() != Frame::ALL.len() {
        return Err(XtaskError::Validation(
            "m10 virtio-gpu: the host screendump stages did not all run".into(),
        ));
    }
    for capture in driver.captures() {
        println!(
            "[M10.virtio-gpu] host screenshot match {} {}x{} png={}",
            capture.name,
            capture.screenshot.width(),
            capture.screenshot.height(),
            capture.png.display()
        );
    }
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
[VGPU] bring-up ok display-info=1280x800 resource=1 format=b8g8r8x8 completed=2\r\n\
[VGPU] scanout buffers mapped=2 stride=5120\r\n\
[VGPU] present seq=1 buffer=0 attach=1 set-scanout=1 transfers=1 flushes=1 irq-completed\r\n\
[VGPU] hold capture=a\r\n\
[VGPU] present seq=2 buffer=1 detach=1 attach=2 transfers=4 flushes=2 damage-bytes=29184 frame-bytes=4096000\r\n\
[VGPU] hold capture=b\r\n\
[VGPU] readback crc32=0x20f2eec9\r\n\
[VGPU] timeout -> reset-required seq=3 error=device-timeout present-rejected\r\n\
[VGPU] reset ok epoch=2 generation=2\r\n\
[VGPU] present seq=4 buffer=1 epoch=2 reattached set-scanout\r\n\
[VGPU] hold capture=c\r\n\
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

    fn screenshot_of(frame: Frame) -> Screenshot {
        let layout = reference_layout();
        Screenshot::new(
            layout.width(),
            layout.height(),
            frame.expected_rgb().to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn each_capture_accepts_its_own_frame_only() {
        for expected in Frame::ALL {
            for shown in Frame::ALL {
                let result = (expected.screendump_check())(&screenshot_of(shown));
                assert_eq!(
                    result.is_ok(),
                    expected == shown,
                    "{expected:?} on {shown:?}"
                );
            }
        }
    }

    #[test]
    fn frame_b_is_the_framebuffer_golden() {
        let layout = reference_layout();
        let bytes = Frame::B.render_bgrx();
        assert_eq!(
            clean_slate_raster::visible_crc32(&bytes, layout),
            Some(0x20F2_EEC9)
        );
    }

    #[test]
    fn a_blank_display_fails_with_the_frame_named() {
        let layout = reference_layout();
        let blank = Screenshot::new(
            layout.width(),
            layout.height(),
            vec![0; layout.width() as usize * layout.height() as usize * 3],
        )
        .unwrap();
        let err = (Frame::A.screendump_check())(&blank).unwrap_err();
        assert!(
            err.starts_with("frame A after the first present: "),
            "{err}"
        );
        assert!(err.contains("pixels differ from the host render"), "{err}");
    }

    #[test]
    fn every_hold_is_captured_then_released_in_marker_order() {
        let steps = capture_steps();
        assert_eq!(steps.len(), 9);
        let holds: Vec<&str> = steps
            .iter()
            .filter_map(|step| match step {
                ScriptStep::AwaitLine(line) => Some(*line),
                _ => None,
            })
            .collect();
        assert_eq!(holds, [HOLD_A, HOLD_B, HOLD_C]);
        let positions: Vec<usize> = holds
            .iter()
            .map(|hold| MARKERS.iter().position(|marker| marker == hold).unwrap())
            .collect();
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        for chunk in steps.chunks(3) {
            assert!(matches!(chunk[1], ScriptStep::Screendump { .. }));
            assert!(matches!(chunk[2], ScriptStep::Input(_)));
        }
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
