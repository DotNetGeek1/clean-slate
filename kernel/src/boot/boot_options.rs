//! #218 S6a: the desktop boot option from QEMU's fw_cfg, read after `ExitBootServices`.
//!
//! Legacy I/O ports `0x510` (selector, 16-bit) and `0x511` (data, one byte per read). The
//! selector is written only when CPUID leaf 1 ECX bit 31 says a hypervisor is present, because
//! on real hardware that port is not guaranteed to be unused. The
//! signature item is checked first. The file directory and the option payload are read in
//! bounded chunks; a missing device, a missing file or a value other than `q0` or `q1` leaves
//! the desktop off. Whether a display is actually attached is not decided here: VirtIO-GPU is
//! brought up after init, so the no-display line is S6c.

use crate::diagnostics::log::{kernel_log_fmt, kernel_log_line};
use clean_slate_service_fixtures::init_bootstrap::{
    DESKTOP_MODE_FRAMEBUFFER, DESKTOP_MODE_NATIVE_SHELL, DESKTOP_MODE_OFF, DESKTOP_MODE_TERMINAL,
    DESKTOP_MODE_VIRTIO_GPU,
};

#[cfg(not(test))]
const SELECTOR_PORT: u16 = 0x510;
#[cfg(not(test))]
const DATA_PORT: u16 = 0x511;
const SIGNATURE_KEY: u16 = 0x0000;
const FILE_DIR_KEY: u16 = 0x0019;
const SIGNATURE: &[u8; 4] = b"QEMU";
/// One `FWCfgFile`: size, select, reserved, name.
const FILE_ENTRY_BYTES: usize = 64;
const FILE_NAME_BYTES: usize = 56;
/// QEMU's default file-slot count is 32. 64 bounds the walk if a firmware adds more, and refuses
/// a corrupt count instead of reading it.
const MAX_DIRECTORY_FILES: u32 = 64;
/// `q0` and `q1` are two bytes. A longer payload is not a value this stage understands, and it
/// is not read.
const MAX_OPTION_BYTES: usize = 16;
const FILE_NAME: &[u8] = b"opt/clean-slate/desktop";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DesktopBackend {
    /// GOP framebuffer, option value `q0`.
    Framebuffer,
    /// VirtIO-GPU, option value `q1`.
    VirtioGpu,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DesktopMode {
    Off,
    On(DesktopBackend),
}

impl DesktopMode {
    pub(crate) const fn word(self) -> u64 {
        match self {
            Self::Off => DESKTOP_MODE_OFF,
            Self::On(DesktopBackend::Framebuffer) => DESKTOP_MODE_FRAMEBUFFER,
            Self::On(DesktopBackend::VirtioGpu) => DESKTOP_MODE_VIRTIO_GPU,
        }
    }

    const fn profile_line(self) -> &'static str {
        match self {
            Self::Off => "[KERN] boot profile=base",
            Self::On(DesktopBackend::Framebuffer) => {
                "[KERN] boot profile=desktop tier=Q0 source=fw_cfg"
            }
            Self::On(DesktopBackend::VirtioGpu) => {
                "[KERN] boot profile=desktop tier=Q1 source=fw_cfg"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Detail {
    Quiet,
    NotUnderstood {
        bytes: [u8; MAX_OPTION_BYTES],
        len: usize,
    },
    Overlong {
        len: u32,
    },
    DirectoryUnreadable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BootOption {
    pub(crate) mode: DesktopMode,
    /// The desktop also declares the terminal rows (#311): `q0`, `q1` and their `-terminal`
    /// spellings. Only `q0-bare` and `q1-bare` leave them out.
    pub(crate) terminal: bool,
    /// The terminal's shell is the native shell (#388): `q0-native-shell`, `q1-native-shell`.
    /// Only with `terminal`.
    pub(crate) native_shell: bool,
    detail: Detail,
}

impl BootOption {
    const fn off() -> Self {
        Self {
            mode: DesktopMode::Off,
            terminal: false,
            native_shell: false,
            detail: Detail::Quiet,
        }
    }

    /// The `InitBootstrap.desktop_mode` word the option asks for.
    pub(crate) const fn word(&self) -> u64 {
        match self.mode {
            DesktopMode::Off => DESKTOP_MODE_OFF,
            DesktopMode::On(_) if self.terminal && self.native_shell => {
                self.mode.word() | DESKTOP_MODE_TERMINAL | DESKTOP_MODE_NATIVE_SHELL
            }
            DesktopMode::On(_) if self.terminal => self.mode.word() | DESKTOP_MODE_TERMINAL,
            DesktopMode::On(_) => self.mode.word(),
        }
    }
}

/// Selector then data-port bytes. `read` is given a buffer of at most one directory entry.
trait FwCfgIo {
    fn select(&mut self, key: u16);
    fn read(&mut self, buf: &mut [u8]);
}

/// Reads the option through the legacy ports. Host tests never touch the ports.
///
/// The hypervisor bit is decided before `io` is used, so a clear bit never selects a port.
pub(crate) fn read_boot_option() -> BootOption {
    #[cfg(not(test))]
    {
        let feature_ecx =
            unsafe { core::arch::x86_64::__cpuid(crate::arch::x86_64::CPUID_FEATURES_LEAF).ecx };
        read_when_hypervisor(
            crate::arch::x86_64::hypervisor_present_from_cpuid(feature_ecx),
            &mut LegacyPorts,
        )
    }
    #[cfg(test)]
    {
        BootOption::off()
    }
}

fn read_when_hypervisor(hypervisor_present: bool, io: &mut impl FwCfgIo) -> BootOption {
    if !hypervisor_present {
        return BootOption::off();
    }
    read_from_io(io)
}

pub(crate) fn log_boot_option(option: &BootOption) {
    match option.detail {
        Detail::Quiet => {}
        Detail::NotUnderstood { bytes, len } => log_not_understood(&bytes[..len]),
        Detail::Overlong { len } => kernel_log_fmt(format_args!(
            "[KERN] boot option opt/clean-slate/desktop len={len} not understood; desktop off\n"
        )),
        Detail::DirectoryUnreadable => kernel_log_line(
            "[KERN] boot option opt/clean-slate/desktop directory unreadable; desktop off",
        ),
    }
    kernel_log_line(option.mode.profile_line());
    if option.terminal && option.mode != DesktopMode::Off {
        kernel_log_line("[KERN] boot option terminal=on: the desktop declares the terminal rows");
        if option.native_shell {
            kernel_log_line(
                "[KERN] boot option shell=native: the terminal's shell is the native shell",
            );
        }
    }
}

fn log_not_understood(bytes: &[u8]) {
    if bytes.is_empty() {
        kernel_log_line("[KERN] boot option opt/clean-slate/desktop= not understood; desktop off");
        return;
    }
    if bytes.iter().all(|byte| (0x20..0x7f).contains(byte)) {
        let mut text = [0u8; MAX_OPTION_BYTES];
        text[..bytes.len()].copy_from_slice(bytes);
        let text = core::str::from_utf8(&text[..bytes.len()]).unwrap_or("");
        kernel_log_fmt(format_args!(
            "[KERN] boot option opt/clean-slate/desktop={text} not understood; desktop off\n"
        ));
        return;
    }
    let mut hex = [0u8; MAX_OPTION_BYTES * 2];
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in bytes.iter().enumerate() {
        hex[index * 2] = DIGITS[usize::from(byte >> 4)];
        hex[index * 2 + 1] = DIGITS[usize::from(byte & 0xf)];
    }
    let hex = core::str::from_utf8(&hex[..bytes.len() * 2]).unwrap_or("");
    kernel_log_fmt(format_args!(
        "[KERN] boot option opt/clean-slate/desktop=hex:{hex} not understood; desktop off\n"
    ));
}

/// `q0` or `q1`, optionally with `-terminal` or `-bare`, and nothing else: no whitespace, no
/// trailing NUL. The terminal is on the default desktop (#311), so plain `q0`/`q1` include it
/// and `-terminal` is the same profile; `-bare` is the desktop without its rows, which the
/// lanes that count the desktop's own rows boot. `-native-shell` is the default desktop with
/// the native shell in the terminal (#388). Returns the backend, the terminal flag and the
/// native-shell flag.
fn parse_desktop_value(bytes: &[u8]) -> Option<(DesktopBackend, bool, bool)> {
    match bytes {
        b"q0" | b"q0-terminal" => Some((DesktopBackend::Framebuffer, true, false)),
        b"q1" | b"q1-terminal" => Some((DesktopBackend::VirtioGpu, true, false)),
        b"q0-bare" => Some((DesktopBackend::Framebuffer, false, false)),
        b"q1-bare" => Some((DesktopBackend::VirtioGpu, false, false)),
        b"q0-native-shell" => Some((DesktopBackend::Framebuffer, true, true)),
        b"q1-native-shell" => Some((DesktopBackend::VirtioGpu, true, true)),
        _ => None,
    }
}

fn read_from_io(io: &mut impl FwCfgIo) -> BootOption {
    io.select(SIGNATURE_KEY);
    let mut signature = [0u8; 4];
    if read_bounded(io, &mut signature).is_err() || signature != *SIGNATURE {
        return BootOption::off();
    }
    io.select(FILE_DIR_KEY);
    let mut count_bytes = [0u8; 4];
    if read_bounded(io, &mut count_bytes).is_err() {
        return unreadable();
    }
    let count = u32::from_be_bytes(count_bytes);
    if count > MAX_DIRECTORY_FILES {
        return unreadable();
    }
    let mut found = None;
    for _ in 0..count {
        let mut entry = [0u8; FILE_ENTRY_BYTES];
        if read_bounded(io, &mut entry).is_err() {
            return unreadable();
        }
        if found.is_some() {
            continue;
        }
        let size = u32::from_be_bytes([entry[0], entry[1], entry[2], entry[3]]);
        let select = u16::from_be_bytes([entry[4], entry[5]]);
        if file_name_is(&entry[8..8 + FILE_NAME_BYTES], FILE_NAME) {
            found = Some((select, size));
        }
    }
    let Some((select, size)) = found else {
        return BootOption::off();
    };
    if size > MAX_OPTION_BYTES as u32 {
        return BootOption {
            mode: DesktopMode::Off,
            terminal: false,
            native_shell: false,
            detail: Detail::Overlong { len: size },
        };
    }
    io.select(select);
    let mut payload = [0u8; MAX_OPTION_BYTES];
    let len = size as usize;
    if read_bounded(io, &mut payload[..len]).is_err() {
        return unreadable();
    }
    match parse_desktop_value(&payload[..len]) {
        Some((backend, terminal, native_shell)) => BootOption {
            mode: DesktopMode::On(backend),
            terminal,
            native_shell,
            detail: Detail::Quiet,
        },
        None => BootOption {
            mode: DesktopMode::Off,
            terminal: false,
            native_shell: false,
            detail: Detail::NotUnderstood {
                bytes: payload,
                len,
            },
        },
    }
}

fn unreadable() -> BootOption {
    BootOption {
        mode: DesktopMode::Off,
        terminal: false,
        native_shell: false,
        detail: Detail::DirectoryUnreadable,
    }
}

fn read_bounded(io: &mut impl FwCfgIo, buf: &mut [u8]) -> Result<(), ()> {
    if buf.len() > FILE_ENTRY_BYTES {
        return Err(());
    }
    io.read(buf);
    Ok(())
}

/// The 56-byte name field matches `expected` only when a NUL ends that exact name.
fn file_name_is(field: &[u8], expected: &[u8]) -> bool {
    let Some(end) = field.iter().position(|byte| *byte == 0) else {
        return false;
    };
    &field[..end] == expected
}

// ---- #314: the display size option -------------------------------------------------------------

const DISPLAY_FILE_NAME: &[u8] = b"opt/clean-slate/display";
/// `1920x1080` is nine bytes; anything past this is not a size.
const MAX_DISPLAY_OPTION_BYTES: usize = 11;

/// The size `opt/clean-slate/display` asks for, read once before `ExitBootServices` (GOP sets its
/// mode there) and remembered for the VirtIO-GPU bring-up. 0 = not read yet, 1 = no size, else
/// `width << 32 | height`.
static DISPLAY_SIZE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The configured display size, `WIDTHxHEIGHT` in decimal, nothing else. A missing file, an
/// unreadable directory, a malformed value or no hypervisor is no size; the backends then fall
/// back on their own default. Bounds are the backends' business: a size out of bounds is offered
/// by neither.
pub(crate) fn configured_display_size() -> Option<(u32, u32)> {
    use core::sync::atomic::Ordering;

    let cached = DISPLAY_SIZE.load(Ordering::Acquire);
    let raw = if cached != 0 {
        cached
    } else {
        let size = read_display_size_now();
        let raw = size.map_or(1, |(width, height)| {
            (u64::from(width) << 32) | u64::from(height)
        });
        DISPLAY_SIZE.store(raw, Ordering::Release);
        raw
    };
    (raw != 1).then_some(((raw >> 32) as u32, raw as u32))
}

fn read_display_size_now() -> Option<(u32, u32)> {
    #[cfg(not(test))]
    {
        let feature_ecx =
            unsafe { core::arch::x86_64::__cpuid(crate::arch::x86_64::CPUID_FEATURES_LEAF).ecx };
        if !crate::arch::x86_64::hypervisor_present_from_cpuid(feature_ecx) {
            return None;
        }
        read_display_size(&mut LegacyPorts)
    }
    #[cfg(test)]
    {
        None
    }
}

fn read_display_size(io: &mut impl FwCfgIo) -> Option<(u32, u32)> {
    let mut payload = [0u8; MAX_DISPLAY_OPTION_BYTES];
    let len = read_named_file(io, DISPLAY_FILE_NAME, &mut payload)?;
    parse_display_size(&payload[..len])
}

/// Finds `name` in the file directory and reads it whole into `out`; `None` when the device,
/// the directory or the file is missing or unreadable, or the file is longer than `out`.
fn read_named_file(io: &mut impl FwCfgIo, name: &[u8], out: &mut [u8]) -> Option<usize> {
    io.select(SIGNATURE_KEY);
    let mut signature = [0u8; 4];
    read_bounded(io, &mut signature).ok()?;
    if signature != *SIGNATURE {
        return None;
    }
    io.select(FILE_DIR_KEY);
    let mut count_bytes = [0u8; 4];
    read_bounded(io, &mut count_bytes).ok()?;
    let count = u32::from_be_bytes(count_bytes);
    if count > MAX_DIRECTORY_FILES {
        return None;
    }
    let mut found = None;
    for _ in 0..count {
        let mut entry = [0u8; FILE_ENTRY_BYTES];
        read_bounded(io, &mut entry).ok()?;
        if found.is_none() && file_name_is(&entry[8..8 + FILE_NAME_BYTES], name) {
            let size = u32::from_be_bytes([entry[0], entry[1], entry[2], entry[3]]);
            let select = u16::from_be_bytes([entry[4], entry[5]]);
            found = Some((select, size));
        }
    }
    let (select, size) = found?;
    let len = usize::try_from(size).ok().filter(|len| *len <= out.len())?;
    io.select(select);
    read_bounded(io, &mut out[..len]).ok()?;
    Some(len)
}

/// `WIDTHxHEIGHT`: one to four decimal digits each, no sign, space or leading zero.
fn parse_display_size(bytes: &[u8]) -> Option<(u32, u32)> {
    let split = bytes.iter().position(|byte| *byte == b'x')?;
    let number = |digits: &[u8]| -> Option<u32> {
        if digits.is_empty() || digits.len() > 4 || digits[0] == b'0' {
            return None;
        }
        digits.iter().try_fold(0u32, |value, digit| {
            digit
                .is_ascii_digit()
                .then(|| value * 10 + u32::from(digit - b'0'))
        })
    };
    Some((number(&bytes[..split])?, number(&bytes[split + 1..])?))
}

#[cfg(not(test))]
struct LegacyPorts;

#[cfg(not(test))]
impl FwCfgIo for LegacyPorts {
    fn select(&mut self, key: u16) {
        crate::arch::x86_64::port::port_out_u16(SELECTOR_PORT, key);
    }

    fn read(&mut self, buf: &mut [u8]) {
        for byte in buf {
            *byte = crate::arch::x86_64::port::port_in(DATA_PORT);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake {
        items: Vec<(u16, Vec<u8>)>,
        selected: Vec<u8>,
        offset: usize,
        bytes_read: usize,
        selects: usize,
    }

    impl Fake {
        fn new(items: Vec<(u16, Vec<u8>)>) -> Self {
            Self {
                items,
                selected: Vec::new(),
                offset: 0,
                bytes_read: 0,
                selects: 0,
            }
        }
    }

    impl FwCfgIo for Fake {
        fn select(&mut self, key: u16) {
            self.selects += 1;
            self.selected = self
                .items
                .iter()
                .find(|(item, _)| *item == key)
                .map(|(_, data)| data.clone())
                .unwrap_or_default();
            self.offset = 0;
        }

        fn read(&mut self, buf: &mut [u8]) {
            assert!(buf.len() <= FILE_ENTRY_BYTES);
            for byte in buf {
                *byte = self.selected.get(self.offset).copied().unwrap_or(0);
                self.offset += 1;
                self.bytes_read += 1;
            }
        }
    }

    fn entry(size: u32, select: u16, name: &str) -> [u8; FILE_ENTRY_BYTES] {
        let mut entry = [0u8; FILE_ENTRY_BYTES];
        entry[0..4].copy_from_slice(&size.to_be_bytes());
        entry[4..6].copy_from_slice(&select.to_be_bytes());
        let name = name.as_bytes();
        assert!(name.len() < FILE_NAME_BYTES);
        entry[8..8 + name.len()].copy_from_slice(name);
        entry
    }

    fn directory(entries: &[[u8; FILE_ENTRY_BYTES]]) -> Vec<u8> {
        let mut bytes = (entries.len() as u32).to_be_bytes().to_vec();
        for entry in entries {
            bytes.extend_from_slice(entry);
        }
        bytes
    }

    fn device(entries: &[[u8; FILE_ENTRY_BYTES]], files: &[(u16, &[u8])]) -> Fake {
        let mut items = vec![
            (SIGNATURE_KEY, SIGNATURE.to_vec()),
            (FILE_DIR_KEY, directory(entries)),
        ];
        for (select, payload) in files {
            items.push((*select, payload.to_vec()));
        }
        Fake::new(items)
    }

    #[test]
    fn display_size_parses_only_width_x_height() {
        assert_eq!(parse_display_size(b"1024x768"), Some((1024, 768)));
        assert_eq!(parse_display_size(b"1920x1080"), Some((1920, 1080)));
        for bad in [
            &b""[..],
            b"1024",
            b"x768",
            b"1024x",
            b"1024X768",
            b"01024x768",
            b"1024x0768",
            b"1024 x768",
            b"1024x768\n",
            b"1024x768x2",
            b"-1x768",
            b"10240x768",
        ] {
            assert_eq!(parse_display_size(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn display_size_reads_its_own_file_and_ignores_the_desktop_one() {
        let desktop = entry(2, 0x21, "opt/clean-slate/desktop");
        let display = entry(8, 0x22, "opt/clean-slate/display");
        let mut io = device(&[desktop, display], &[(0x21, b"q1"), (0x22, b"1024x768")]);
        assert_eq!(read_display_size(&mut io), Some((1024, 768)));
        let mut io = device(&[desktop], &[(0x21, b"q1")]);
        assert_eq!(read_display_size(&mut io), None, "no file");
        let long = entry(12, 0x22, "opt/clean-slate/display");
        let mut io = device(&[long], &[(0x22, b"1024x768    ")]);
        assert_eq!(read_display_size(&mut io), None, "longer than any size");
        let mut io = Fake::new(vec![(SIGNATURE_KEY, b"NOPE".to_vec())]);
        assert_eq!(read_display_size(&mut io), None, "no fw_cfg device");
    }

    #[test]
    fn a_clear_hypervisor_bit_does_not_touch_the_ports() {
        let file = entry(2, 0x21, "opt/clean-slate/desktop");
        let mut io = device(&[file], &[(0x21, b"q1")]);
        let option = read_when_hypervisor(false, &mut io);
        assert_eq!(option, BootOption::off());
        assert_eq!(io.selects, 0);
        assert_eq!(io.bytes_read, 0);

        let option = read_when_hypervisor(true, &mut io);
        assert_eq!(option.mode, DesktopMode::On(DesktopBackend::VirtioGpu));
        assert!(io.selects > 0);
        assert!(io.bytes_read > 0);
    }

    #[test]
    fn without_ports_the_desktop_is_off() {
        let option = read_boot_option();
        assert_eq!(option.mode, DesktopMode::Off);
        assert_eq!(option.mode.word(), DESKTOP_MODE_OFF);
        log_boot_option(&option);
    }

    #[test]
    fn a_missing_device_or_file_is_off_and_does_not_read_a_payload() {
        let mut absent = Fake::new(vec![(SIGNATURE_KEY, b"XXXX".to_vec())]);
        assert_eq!(read_from_io(&mut absent).mode, DesktopMode::Off);
        assert_eq!(absent.bytes_read, 4);

        let mut empty = device(&[], &[]);
        assert_eq!(read_from_io(&mut empty), BootOption::off());

        let other = entry(2, 0x20, "etc/other");
        let mut no_file = device(&[other], &[(0x20, b"q1")]);
        assert_eq!(read_from_io(&mut no_file).mode, DesktopMode::Off);
        assert_eq!(no_file.bytes_read, 4 + 4 + FILE_ENTRY_BYTES);
    }

    #[test]
    fn bare_values_select_the_backend_and_the_bootstrap_word() {
        let cases = [
            (
                b"q0-bare".as_slice(),
                DesktopBackend::Framebuffer,
                DESKTOP_MODE_FRAMEBUFFER,
                "[KERN] boot profile=desktop tier=Q0 source=fw_cfg",
            ),
            (
                b"q1-bare".as_slice(),
                DesktopBackend::VirtioGpu,
                DESKTOP_MODE_VIRTIO_GPU,
                "[KERN] boot profile=desktop tier=Q1 source=fw_cfg",
            ),
        ];
        for (payload, backend, word, line) in cases {
            let file = entry(payload.len() as u32, 0x21, "opt/clean-slate/desktop");
            let decoy = entry(4, 0x20, "opt/clean-slate/other");
            let mut io = device(&[decoy, file], &[(0x20, b"nope"), (0x21, payload)]);
            let option = read_from_io(&mut io);
            assert_eq!(
                option,
                BootOption {
                    mode: DesktopMode::On(backend),
                    terminal: false,
                    native_shell: false,
                    detail: Detail::Quiet,
                }
            );
            assert_eq!(option.mode.word(), word);
            assert_eq!(option.word(), word);
            assert_eq!(option.mode.profile_line(), line);
            let payload_reads = io.bytes_read;
            assert!(payload_reads < 4 + 4 + 2 * FILE_ENTRY_BYTES + MAX_OPTION_BYTES);
            assert_eq!(payload_reads, 4 + 4 + 2 * FILE_ENTRY_BYTES + payload.len());
        }
    }

    #[test]
    fn the_default_desktop_and_its_terminal_spelling_set_the_terminal_flag() {
        for (payload, backend, word) in [
            (
                b"q0".as_slice(),
                DesktopBackend::Framebuffer,
                DESKTOP_MODE_FRAMEBUFFER,
            ),
            (b"q1", DesktopBackend::VirtioGpu, DESKTOP_MODE_VIRTIO_GPU),
            (
                b"q0-terminal",
                DesktopBackend::Framebuffer,
                DESKTOP_MODE_FRAMEBUFFER,
            ),
            (
                b"q1-terminal",
                DesktopBackend::VirtioGpu,
                DESKTOP_MODE_VIRTIO_GPU,
            ),
        ] {
            let file = entry(payload.len() as u32, 0x21, "opt/clean-slate/desktop");
            let mut io = device(&[file], &[(0x21, payload)]);
            let option = read_from_io(&mut io);
            assert_eq!(option.mode, DesktopMode::On(backend));
            assert!(option.terminal);
            assert_eq!(option.word(), word | DESKTOP_MODE_TERMINAL);
        }
        assert_eq!(BootOption::off().word(), DESKTOP_MODE_OFF);
    }

    #[test]
    fn native_shell_values_set_both_flags() {
        for (payload, backend, word) in [
            (
                b"q0-native-shell".as_slice(),
                DesktopBackend::Framebuffer,
                DESKTOP_MODE_FRAMEBUFFER,
            ),
            (
                b"q1-native-shell",
                DesktopBackend::VirtioGpu,
                DESKTOP_MODE_VIRTIO_GPU,
            ),
        ] {
            assert!(payload.len() <= MAX_OPTION_BYTES);
            let file = entry(payload.len() as u32, 0x21, "opt/clean-slate/desktop");
            let mut io = device(&[file], &[(0x21, payload)]);
            let option = read_from_io(&mut io);
            assert_eq!(option.mode, DesktopMode::On(backend));
            assert!(option.terminal && option.native_shell);
            assert_eq!(
                option.word(),
                word | DESKTOP_MODE_TERMINAL | DESKTOP_MODE_NATIVE_SHELL
            );
        }
    }

    #[test]
    fn unknown_empty_and_padded_values_stay_off() {
        for payload in [
            b"".as_slice(),
            b"q1\n",
            b"Q1",
            b"q2",
            b"q1 ",
            b"desktop",
            b"q1-terminal ",
            b"terminal",
            b"q1-bare\0",
            b"bare",
            b"q1-native",
            b"native-shell",
            b"q1-native-shell\0",
        ] {
            let file = entry(payload.len() as u32, 0x22, "opt/clean-slate/desktop");
            let mut io = device(&[file], &[(0x22, payload)]);
            let option = read_from_io(&mut io);
            assert_eq!(option.mode, DesktopMode::Off, "{payload:?}");
            assert!(matches!(option.detail, Detail::NotUnderstood { .. }));
            assert_eq!(parse_desktop_value(payload), None);
        }
    }

    #[test]
    fn an_overlong_value_is_not_read() {
        let file = entry(1_000, 0x23, "opt/clean-slate/desktop");
        let mut io = device(&[file], &[(0x23, &[0x61; 1_000])]);
        let option = read_from_io(&mut io);
        assert_eq!(
            option,
            BootOption {
                mode: DesktopMode::Off,
                terminal: false,
                native_shell: false,
                detail: Detail::Overlong { len: 1_000 },
            }
        );
        assert_eq!(io.bytes_read, 4 + 4 + FILE_ENTRY_BYTES);
    }

    #[test]
    fn a_directory_past_the_cap_is_not_walked() {
        let mut bytes = (MAX_DIRECTORY_FILES + 1).to_be_bytes().to_vec();
        bytes.extend(std::iter::repeat_n(0, FILE_ENTRY_BYTES));
        let mut io = Fake::new(vec![
            (SIGNATURE_KEY, SIGNATURE.to_vec()),
            (FILE_DIR_KEY, bytes),
        ]);
        assert_eq!(read_from_io(&mut io).detail, Detail::DirectoryUnreadable);
        assert_eq!(io.bytes_read, 8);
    }

    #[test]
    fn a_name_without_a_nul_or_a_longer_name_does_not_match() {
        let mut bare = [0u8; FILE_ENTRY_BYTES];
        bare[0..4].copy_from_slice(&2u32.to_be_bytes());
        bare[4..6].copy_from_slice(&0x24u16.to_be_bytes());
        bare[8..].fill(b'a');
        let longer = entry(2, 0x25, "opt/clean-slate/desktop-extra");
        let mut io = device(&[bare, longer], &[(0x24, b"q1"), (0x25, b"q1")]);
        assert_eq!(read_from_io(&mut io).mode, DesktopMode::Off);
    }
}
