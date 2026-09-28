//! `test-qmp-smoke`: proves the QMP harness against real QEMU without a
//! kernel or OVMF.
//!
//! SeaBIOS boots a 512-byte real-mode sector that paints a two-colour text
//! screen and echoes every i8042 byte to COM1 as `[QMPFIX] kbd xx` or
//! `[QMPFIX] aux xx`. The script injects keys and pointer events paced by
//! those lines, captures the screen, and quits. A second run fails its
//! screenshot check on purpose and proves the failure path leaves no QEMU
//! and no endpoint behind.

use std::fs;
use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use super::image::Screenshot;
use super::json::JsonValue;
use super::{InputAction, MouseButton, QCode, QemuVersion, QmpScriptDriver, ScriptStep};
use crate::{run_driven_acceptance_command, AcceptanceDriver, MarkerSet, XtaskError};

const LANE: &str = "qmp-smoke";
const FAILURE_LANE: &str = "qmp-smoke-failure";
const TIMEOUT: Duration = Duration::from_secs(90);
const PEER_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);
/// SeaBIOS boots through CHS; below one 16-head, 63-sector cylinder
/// (504 KiB) it computes zero cylinders and cannot read sector 0.
const DISK_IMAGE_BYTES: usize = 1024 * 1024;
const LOAD_ADDRESS: u16 = 0x7C00;
const TEXT_COLUMNS: usize = 80;
/// Text rows painted with the blue attribute; the rest are red.
const BLUE_ROWS: usize = 12;
const TEXT_ROWS: usize = 25;
/// Scanlines per text row in mode 3 (400 lines / 25 rows).
const CELL_HEIGHT: usize = 16;

const READY: &str = "[QMPFIX] ready";

/// Every `[QMPFIX]` line the fixture prints, in order. PS/2 packets are
/// `flags dx dy` with dy inverted relative to QMP, and each
/// `input-send-event` produces exactly one packet.
const SMOKE_LINES: [&str; 22] = [
    READY,
    "[QMPFIX] aux fa",
    "[QMPFIX] kbd 1e",
    "[QMPFIX] kbd 9e",
    "[QMPFIX] kbd 1c",
    "[QMPFIX] kbd 9c",
    "[QMPFIX] aux 08",
    "[QMPFIX] aux 05",
    "[QMPFIX] aux 05",
    "[QMPFIX] aux 38",
    "[QMPFIX] aux fd",
    "[QMPFIX] aux fc",
    "[QMPFIX] aux 09",
    "[QMPFIX] aux 00",
    "[QMPFIX] aux 00",
    "[QMPFIX] aux 08",
    "[QMPFIX] aux 00",
    "[QMPFIX] aux 00",
    "[QMPFIX] kbd 2a",
    "[QMPFIX] kbd 1f",
    "[QMPFIX] kbd 9f",
    "[QMPFIX] kbd aa",
];

const FAILURE_LINES: [&str; 2] = [READY, "[QMPFIX] aux fa"];

pub(crate) fn run(artifact_root: &Path) -> Result<(), XtaskError> {
    let version = run_passing_script(artifact_root)?;
    run_failing_script(artifact_root)?;
    println!("[QMP.smoke] QEMU {version}");
    println!("[QMP.smoke] PASS");
    Ok(())
}

fn run_passing_script(artifact_root: &Path) -> Result<QemuVersion, XtaskError> {
    let mut driver = QmpScriptDriver::new(LANE, smoke_steps(), artifact_root)?;
    let mut qemu = fixture_command(driver.run_dir(), &driver.qemu_args())?;
    let output = run_driven_acceptance_command(
        &mut qemu,
        MarkerSet::Ordered(&SMOKE_LINES),
        TIMEOUT,
        &mut driver,
    )?;
    let _ = fs::remove_file(driver.run_dir().join("fixture.img"));

    let lines: Vec<&str> = output
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| line.starts_with("[QMPFIX]"))
        .collect();
    if lines != SMOKE_LINES {
        return Err(XtaskError::Validation(format!(
            "{LANE} serial trace differs from the injected script:\n  expected {SMOKE_LINES:?}\n  got      {lines:?}"
        )));
    }

    let version = driver
        .version()
        .ok_or_else(|| XtaskError::Validation(format!("{LANE} never recorded a QEMU version")))?;
    if !driver.events().iter().any(|event| event.name == "SHUTDOWN") {
        return Err(XtaskError::Validation(format!(
            "{LANE} saw no SHUTDOWN event after quit"
        )));
    }

    let [capture] = driver.captures() else {
        return Err(XtaskError::Validation(format!(
            "{LANE} expected exactly one capture, got {}",
            driver.captures().len()
        )));
    };
    check_png_header(&capture.png, &capture.screenshot)?;
    expect_port_released(LANE, driver.port())?;
    println!(
        "[QMP.smoke] injected 3 keystrokes and 4 pointer packets; `{}` {}x{} at {}",
        capture.name,
        capture.screenshot.width(),
        capture.screenshot.height(),
        capture.png.display()
    );
    Ok(version)
}

fn run_failing_script(artifact_root: &Path) -> Result<(), XtaskError> {
    let mut driver = QmpScriptDriver::new(FAILURE_LANE, failing_steps(), artifact_root)?;
    driver.keep_peer_probe();
    let mut qemu = fixture_command(driver.run_dir(), &driver.qemu_args())?;
    let result = run_driven_acceptance_command(
        &mut qemu,
        MarkerSet::Ordered(&FAILURE_LINES),
        TIMEOUT,
        &mut driver,
    );
    match result {
        Err(XtaskError::DriverFailed { reason, .. }) if reason.contains("deliberate") => {}
        Err(other) => {
            return Err(XtaskError::Validation(format!(
                "{FAILURE_LANE} failed for the wrong reason: {other}"
            )))
        }
        Ok(_) => {
            return Err(XtaskError::Validation(format!(
                "{FAILURE_LANE} passed although its screenshot check always fails"
            )))
        }
    }
    let _ = fs::remove_file(driver.run_dir().join("fixture.img"));

    if !driver.peer_closed_within(PEER_CLOSE_TIMEOUT)? {
        return Err(XtaskError::Validation(format!(
            "{FAILURE_LANE}: QEMU's QMP socket stayed open {PEER_CLOSE_TIMEOUT:?} after teardown"
        )));
    }
    expect_port_released(FAILURE_LANE, driver.port())?;
    println!("[QMP.smoke] failure cleanup ok");
    Ok(())
}

fn smoke_steps() -> Vec<ScriptStep> {
    use ScriptStep::{AwaitLine, Input};
    vec![
        AwaitLine("[QMPFIX] aux fa"),
        Input(InputAction::tap(QCode::A).to_vec()),
        AwaitLine("[QMPFIX] kbd 1e"),
        AwaitLine("[QMPFIX] kbd 9e"),
        Input(InputAction::tap(QCode::RET).to_vec()),
        AwaitLine("[QMPFIX] kbd 1c"),
        AwaitLine("[QMPFIX] kbd 9c"),
        Input(InputAction::move_rel(5, -5).to_vec()),
        AwaitLine("[QMPFIX] aux 08"),
        AwaitLine("[QMPFIX] aux 05"),
        AwaitLine("[QMPFIX] aux 05"),
        Input(InputAction::move_rel(-3, 4).to_vec()),
        AwaitLine("[QMPFIX] aux 38"),
        AwaitLine("[QMPFIX] aux fd"),
        AwaitLine("[QMPFIX] aux fc"),
        Input(vec![InputAction::Button {
            button: MouseButton::Left,
            down: true,
        }]),
        AwaitLine("[QMPFIX] aux 09"),
        AwaitLine("[QMPFIX] aux 00"),
        AwaitLine("[QMPFIX] aux 00"),
        Input(vec![InputAction::Button {
            button: MouseButton::Left,
            down: false,
        }]),
        AwaitLine("[QMPFIX] aux 08"),
        AwaitLine("[QMPFIX] aux 00"),
        AwaitLine("[QMPFIX] aux 00"),
        Input(vec![
            InputAction::Key {
                qcode: QCode::SHIFT,
                down: true,
            },
            InputAction::Key {
                qcode: QCode::S,
                down: true,
            },
            InputAction::Key {
                qcode: QCode::S,
                down: false,
            },
            InputAction::Key {
                qcode: QCode::SHIFT,
                down: false,
            },
        ]),
        AwaitLine("[QMPFIX] kbd 2a"),
        AwaitLine("[QMPFIX] kbd 1f"),
        AwaitLine("[QMPFIX] kbd 9f"),
        // `kbd aa` is also the tracker's final marker: the driver sees each
        // chunk before the tracker does, so the capture and quit below run
        // before the acceptance loop can tear QEMU down.
        AwaitLine("[QMPFIX] kbd aa"),
        ScriptStep::Screendump {
            name: "frame",
            check: check_frame,
        },
        ScriptStep::CommandError {
            command: "no-such-command",
            class: "CommandNotFound",
        },
        ScriptStep::Command {
            command: "query-status",
            arguments: None,
            check: check_running,
        },
        ScriptStep::Quit,
    ]
}

fn failing_steps() -> Vec<ScriptStep> {
    vec![
        ScriptStep::AwaitLine("[QMPFIX] aux fa"),
        ScriptStep::Screendump {
            name: "forced-failure",
            check: |_| Err("deliberate failure to prove cleanup".to_owned()),
        },
    ]
}

fn check_running(reply: &JsonValue) -> Result<(), String> {
    let status = reply.get("status").and_then(JsonValue::as_str);
    let running = reply.get("running").and_then(JsonValue::as_bool);
    match (status, running) {
        (Some("running"), Some(true)) => Ok(()),
        other => Err(format!("expected a running VM, got {other:?}")),
    }
}

/// The top [`BLUE_ROWS`] text rows are blue on blue and the rest red on red,
/// so every pixel of each band equals the band's first pixel.
fn check_frame(shot: &Screenshot) -> Result<(), String> {
    let (width, height) = (shot.width() as usize, shot.height() as usize);
    if height != TEXT_ROWS * CELL_HEIGHT || !matches!(width, 640 | 720) {
        return Err(format!(
            "expected an 80x25 text frame, got {width}x{height}"
        ));
    }
    let split = BLUE_ROWS * CELL_HEIGHT;
    let blue = shot.pixel(0, 0).ok_or("empty frame")?;
    let red = shot.pixel(0, split as u32).ok_or("frame too short")?;
    if !(blue[0] == 0 && blue[1] == 0 && blue[2] >= 0x80) {
        return Err(format!("top band is {blue:02x?}, not blue"));
    }
    if !(red[0] >= 0x80 && red[1] == 0 && red[2] == 0) {
        return Err(format!("bottom band is {red:02x?}, not red"));
    }
    for (index, got) in shot.rgb().chunks_exact(3).enumerate() {
        let (x, y) = (index % width, index / width);
        let expected = if y < split { blue } else { red };
        if got != expected {
            return Err(format!(
                "pixel ({x},{y}) is {got:02x?}, expected {expected:02x?}"
            ));
        }
    }
    Ok(())
}

/// Re-reads the written PNG and checks its signature and IHDR dimensions.
fn check_png_header(png: &Path, shot: &Screenshot) -> Result<(), XtaskError> {
    let mut header = [0u8; 24];
    fs::File::open(png)?.read_exact(&mut header)?;
    let signature_ok = header[..8] == *b"\x89PNG\r\n\x1a\n" && header[12..16] == *b"IHDR";
    let width = u32::from_be_bytes([header[16], header[17], header[18], header[19]]);
    let height = u32::from_be_bytes([header[20], header[21], header[22], header[23]]);
    if !signature_ok || width != shot.width() || height != shot.height() {
        return Err(XtaskError::Validation(format!(
            "{} is not a {}x{} PNG",
            png.display(),
            shot.width(),
            shot.height()
        )));
    }
    Ok(())
}

fn expect_port_released(lane: &str, port: u16) -> Result<(), XtaskError> {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    match TcpStream::connect_timeout(&address, Duration::from_secs(2)) {
        Err(_) => Ok(()),
        Ok(_) => Err(XtaskError::Validation(format!(
            "{lane}: 127.0.0.1:{port} still accepts connections after teardown"
        ))),
    }
}

fn fixture_command(run_dir: &Path, qmp_args: &[String]) -> io::Result<Command> {
    let image = write_fixture_image(run_dir)?;
    let mut qemu = Command::new("qemu-system-x86_64");
    qemu.args(["-machine", "q35,vmport=off", "-m", "32M", "-nodefaults"])
        .args(["-vga", "std", "-display", "none", "-serial", "stdio"])
        .arg("-no-reboot")
        .arg("-drive")
        .arg(format!(
            "if=none,id=fixture,format=raw,file={}",
            image.display()
        ))
        .args(["-device", "ide-hd,drive=fixture,bus=ide.0"])
        .args(qmp_args);
    Ok(qemu)
}

fn write_fixture_image(run_dir: &Path) -> io::Result<PathBuf> {
    let mut image = boot_sector().map_err(io::Error::other)?;
    image.resize(DISK_IMAGE_BYTES, 0);
    let path = run_dir.join("fixture.img");
    fs::write(&path, image)?;
    Ok(path)
}

/// Assembles the fixture's boot sector. Real mode, loaded at 0000:7C00.
fn boot_sector() -> Result<Vec<u8>, String> {
    const JZ: u8 = 0x74;
    const JBE: u8 = 0x76;
    const JMP_SHORT: u8 = 0xEB;
    let blue_cells = (BLUE_ROWS * TEXT_COLUMNS) as u16;
    let red_cells = ((TEXT_ROWS - BLUE_ROWS) * TEXT_COLUMNS) as u16;
    let mut asm = Asm::default();

    // cli; ds = ss = 0; sp = 7c00; cld
    asm.bytes(&[
        0xFA, 0x31, 0xC0, 0x8E, 0xD8, 0x8E, 0xD0, 0xBC, 0x00, 0x7C, 0xFC,
    ]);
    // CRTC cursor start register: cursor off.
    asm.bytes(&[0xBA, 0xD4, 0x03, 0xB8, 0x0A, 0x20, 0xEF]);
    // es = b800; di = 0; fill blue cells, then red cells.
    asm.bytes(&[0xB8, 0x00, 0xB8, 0x8E, 0xC0, 0x31, 0xFF]);
    asm.bytes(&[0xB8, 0x20, 0x10, 0xB9]);
    asm.bytes(&blue_cells.to_le_bytes());
    asm.bytes(&[0xF3, 0xAB, 0xB8, 0x20, 0x40, 0xB9]);
    asm.bytes(&red_cells.to_le_bytes());
    asm.bytes(&[0xF3, 0xAB]);
    // IVT: IRQ1 (int 09h) and IRQ12 (int 74h) both go to `isr`.
    asm.abs16(&[0xC7, 0x06, 0x24, 0x00], "isr");
    asm.bytes(&[0xC7, 0x06, 0x26, 0x00, 0x00, 0x00]);
    asm.abs16(&[0xC7, 0x06, 0xD0, 0x01], "isr");
    asm.bytes(&[0xC7, 0x06, 0xD2, 0x01, 0x00, 0x00]);
    // Unmask only IRQ1, the cascade, and IRQ12.
    asm.bytes(&[0xB0, 0xF9, 0xE6, 0x21, 0xB0, 0xEF, 0xE6, 0xA1]);
    asm.label("drain");
    asm.bytes(&[0xE4, 0x64, 0xA8, 0x01]);
    asm.rel8(JZ, "drained");
    asm.bytes(&[0xE4, 0x60]);
    asm.rel8(JMP_SHORT, "drain");
    asm.label("drained");
    // Controller config 47h: both port interrupts, system flag, set-1
    // translation. Then enable the aux port and mouse reporting; the mouse
    // ACK (fa) arrives on IRQ12 once interrupts are on.
    asm.bytes(&[0xB0, 0x60, 0xE6, 0x64, 0xB0, 0x47, 0xE6, 0x60]);
    asm.bytes(&[0xB0, 0xA8, 0xE6, 0x64]);
    asm.bytes(&[0xB0, 0xD4, 0xE6, 0x64, 0xB0, 0xF4, 0xE6, 0x60]);
    asm.abs16(&[0xBE], "ready_msg");
    asm.call("puts");
    asm.bytes(&[0xFB]);
    asm.label("idle");
    asm.bytes(&[0xF4]);
    asm.rel8(JMP_SHORT, "idle");

    // Echo every pending i8042 byte; status bit 5 marks aux data.
    asm.label("isr");
    asm.bytes(&[0x50, 0x53, 0x56]);
    asm.label("isr_next");
    asm.bytes(&[0xE4, 0x64, 0xA8, 0x01]);
    asm.rel8(JZ, "isr_done");
    asm.bytes(&[0x88, 0xC4, 0xE4, 0x60, 0x88, 0xC3]);
    asm.abs16(&[0xBE], "kbd_msg");
    asm.bytes(&[0xF6, 0xC4, 0x20]);
    asm.rel8(JZ, "isr_print");
    asm.abs16(&[0xBE], "aux_msg");
    asm.label("isr_print");
    asm.call("puts");
    asm.call("puthex");
    asm.rel8(JMP_SHORT, "isr_next");
    asm.label("isr_done");
    asm.bytes(&[0xB0, 0x20, 0xE6, 0xA0, 0xE6, 0x20, 0x5E, 0x5B, 0x58, 0xCF]);

    // puts: si -> NUL-terminated string.
    asm.label("puts");
    asm.bytes(&[0xAC, 0x84, 0xC0]);
    asm.rel8(JZ, "puts_done");
    asm.call("putc");
    asm.rel8(JMP_SHORT, "puts");
    asm.label("puts_done");
    asm.bytes(&[0xC3]);

    // puthex: bl as two lowercase hex digits and a newline.
    asm.label("puthex");
    asm.bytes(&[0x88, 0xD8, 0xC0, 0xE8, 0x04]);
    asm.call("nibble");
    asm.bytes(&[0x88, 0xD8, 0x24, 0x0F]);
    asm.call("nibble");
    asm.bytes(&[0xB0, 0x0A]);
    asm.rel8(JMP_SHORT, "putc");
    asm.label("nibble");
    asm.bytes(&[0x04, b'0', 0x3C, b'9']);
    asm.rel8(JBE, "putc");
    asm.bytes(&[0x04, b'a' - b'9' - 1]);

    // putc: al -> COM1 once the transmit holding register is empty.
    asm.label("putc");
    asm.bytes(&[0x52, 0x50, 0xBA, 0xFD, 0x03]);
    asm.label("putc_wait");
    asm.bytes(&[0xEC, 0xA8, 0x20]);
    asm.rel8(JZ, "putc_wait");
    asm.bytes(&[0x58, 0xBA, 0xF8, 0x03, 0xEE, 0x5A, 0xC3]);

    asm.label("ready_msg");
    asm.bytes(READY.as_bytes());
    asm.bytes(b"\n\0");
    asm.label("kbd_msg");
    asm.bytes(b"[QMPFIX] kbd \0");
    asm.label("aux_msg");
    asm.bytes(b"[QMPFIX] aux \0");

    let mut sector = asm.finish(LOAD_ADDRESS)?;
    if sector.len() > 510 {
        return Err(format!("boot sector code is {} bytes", sector.len()));
    }
    sector.resize(510, 0);
    sector.extend_from_slice(&[0x55, 0xAA]);
    Ok(sector)
}

enum FixupKind {
    Rel8,
    Rel16,
    Abs16,
}

struct Fixup {
    at: usize,
    label: &'static str,
    kind: FixupKind,
}

/// Just enough of an assembler to place labels and patch their uses.
#[derive(Default)]
struct Asm {
    code: Vec<u8>,
    labels: Vec<(&'static str, usize)>,
    fixups: Vec<Fixup>,
}

impl Asm {
    fn bytes(&mut self, bytes: &[u8]) {
        self.code.extend_from_slice(bytes);
    }

    fn label(&mut self, name: &'static str) {
        self.labels.push((name, self.code.len()));
    }

    fn fixup(&mut self, label: &'static str, kind: FixupKind, width: usize) {
        self.fixups.push(Fixup {
            at: self.code.len(),
            label,
            kind,
        });
        self.code.resize(self.code.len() + width, 0);
    }

    /// Short jump `opcode rel8`.
    fn rel8(&mut self, opcode: u8, label: &'static str) {
        self.bytes(&[opcode]);
        self.fixup(label, FixupKind::Rel8, 1);
    }

    fn call(&mut self, label: &'static str) {
        self.bytes(&[0xE8]);
        self.fixup(label, FixupKind::Rel16, 2);
    }

    /// `prefix imm16` where the immediate is the label's absolute address.
    fn abs16(&mut self, prefix: &[u8], label: &'static str) {
        self.bytes(prefix);
        self.fixup(label, FixupKind::Abs16, 2);
    }

    fn finish(mut self, origin: u16) -> Result<Vec<u8>, String> {
        for fixup in &self.fixups {
            let mut targets = self.labels.iter().filter(|(name, _)| *name == fixup.label);
            let target = match (targets.next(), targets.next()) {
                (Some((_, offset)), None) => *offset,
                (None, _) => return Err(format!("undefined label `{}`", fixup.label)),
                (Some(_), Some(_)) => return Err(format!("duplicate label `{}`", fixup.label)),
            };
            match fixup.kind {
                FixupKind::Rel8 => {
                    let delta = target as isize - (fixup.at as isize + 1);
                    let delta = i8::try_from(delta)
                        .map_err(|_| format!("`{}` is out of short-jump range", fixup.label))?;
                    self.code[fixup.at] = delta as u8;
                }
                FixupKind::Rel16 => {
                    let delta = target as isize - (fixup.at as isize + 2);
                    let delta = i16::try_from(delta)
                        .map_err(|_| format!("`{}` is out of near-call range", fixup.label))?;
                    self.code[fixup.at..fixup.at + 2].copy_from_slice(&delta.to_le_bytes());
                }
                FixupKind::Abs16 => {
                    let address = u16::try_from(usize::from(origin) + target)
                        .map_err(|_| format!("`{}` is above 64 KiB", fixup.label))?;
                    self.code[fixup.at..fixup.at + 2].copy_from_slice(&address.to_le_bytes());
                }
            }
        }
        Ok(self.code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_sector_fits_and_is_bootable() {
        let sector = boot_sector().expect("assemble");
        assert_eq!(sector.len(), 512);
        assert_eq!(&sector[510..], &[0x55, 0xAA]);
    }

    #[test]
    fn boot_sector_vectors_point_at_the_isr() {
        let sector = boot_sector().expect("assemble");
        let find = |pattern: &[u8]| {
            sector
                .windows(pattern.len())
                .position(|window| window == pattern)
                .expect("pattern present")
        };
        let irq1 = find(&[0xC7, 0x06, 0x24, 0x00]) + 4;
        let irq12 = find(&[0xC7, 0x06, 0xD0, 0x01]) + 4;
        let isr = u16::from_le_bytes([sector[irq1], sector[irq1 + 1]]);
        assert_eq!(isr, u16::from_le_bytes([sector[irq12], sector[irq12 + 1]]));
        // The ISR starts by saving ax, bx and si.
        let isr_offset = usize::from(isr - LOAD_ADDRESS);
        assert_eq!(&sector[isr_offset..isr_offset + 3], &[0x50, 0x53, 0x56]);
    }

    #[test]
    fn assembler_patches_relative_and_absolute_uses() {
        let mut asm = Asm::default();
        asm.label("top");
        asm.rel8(0xEB, "end");
        asm.call("end");
        asm.abs16(&[0xBE], "end");
        asm.rel8(0xEB, "top");
        asm.label("end");
        let code = asm.finish(0x7C00).expect("assemble");
        assert_eq!(
            code,
            [0xEB, 0x08, 0xE8, 0x05, 0x00, 0xBE, 0x0A, 0x7C, 0xEB, 0xF6]
        );
    }

    #[test]
    fn assembler_rejects_bad_labels_and_long_jumps() {
        let mut asm = Asm::default();
        asm.rel8(0xEB, "missing");
        assert!(asm.finish(0).unwrap_err().contains("undefined"));

        let mut asm = Asm::default();
        asm.rel8(0xEB, "far");
        asm.bytes(&[0x90; 200]);
        asm.label("far");
        assert!(asm.finish(0).unwrap_err().contains("range"));

        let mut asm = Asm::default();
        asm.label("twice");
        asm.label("twice");
        asm.rel8(0xEB, "twice");
        assert!(asm.finish(0).unwrap_err().contains("duplicate"));
    }

    #[test]
    fn frame_check_accepts_two_bands_and_rejects_a_stray_pixel() {
        let (width, height) = (720u32, 400u32);
        let split = (BLUE_ROWS * CELL_HEIGHT) as u32;
        let mut rgb = Vec::new();
        for y in 0..height {
            for _ in 0..width {
                rgb.extend_from_slice(if y < split {
                    &[0, 0, 0xA8]
                } else {
                    &[0xA8, 0, 0]
                });
            }
        }
        let shot = Screenshot::new(width, height, rgb.clone()).expect("frame");
        check_frame(&shot).expect("two bands");

        rgb[3 * (width as usize * 300 + 10) + 1] = 0x10;
        let shot = Screenshot::new(width, height, rgb).expect("frame");
        assert!(check_frame(&shot).unwrap_err().contains("(10,300)"));
    }

    #[test]
    fn script_awaits_every_fixture_line_after_ready() {
        let awaited: Vec<&str> = smoke_steps()
            .iter()
            .filter_map(|step| match step {
                ScriptStep::AwaitLine(text) => Some(*text),
                _ => None,
            })
            .collect();
        assert_eq!(awaited, SMOKE_LINES[1..]);
    }
}
