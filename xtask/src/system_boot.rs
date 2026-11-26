//! The default image (#218 S3b): `cargo xtask run` and the `test-system-boot` lane.
//!
//! The default image is the kernel built with no feature: the kernel launches userspace init,
//! which starts storage, the audit service (#219) and the console service (#310), then network and the serial-console shell
//! (#218 S5), and waits. `run` always attaches the persistent data
//! disk `target/system-data.img` (created when missing) and starts the network fixture peer
//! only with `--net`. The lane boots the same image three times on a disk of its own: the first
//! boot formats it, the second mounts it, and the third finds it corrupted and must refuse it
//! without writing to it.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clean_slate_block::{
    BlockDevice, BlockDeviceId, BlockGeometry, BlockIoError, BlockTransportError,
    BlockUnsupportedError,
};
use clean_slate_store::{probe, Probe, Refusal, STORE_VERSION};

use crate::m7_fixture::{FixtureOptions, M7FixturePeer, WhichCert};
use crate::{
    run_driven_vm_acceptance, run_vm_inner_with_config, workspace_root, MarkerSet, MarkerStep,
    NoDriver, VmLaunchConfig, XtaskError, M5_DATA_DISK_SIZE_BYTES, RDRAND_CPU_MODEL,
};

pub(crate) const SYSTEM_DATA_DISK_FILENAME: &str = "system-data.img";
/// Logical block size of every QEMU data disk xtask attaches; one store superblock each.
const DATA_DISK_BLOCK_BYTES: usize = 512;
const STORAGE_SERVICE: u32 = 0x5100;
const NETWORK_SERVICE: u32 = 0x5200;
const SHELL_SERVICE: u32 = 0x5400;
pub(crate) const AUDIT_SERVICE: u32 = 0x5500;
pub(crate) const CONSOLE_SERVICE: u32 = 0x5600;
/// The base rows: storage, network, the shell, the audit service and the console service.
pub(crate) const BASE_SERVICES: u64 = 5;
/// Compositor, desktop shell and app (#218 S6c): declared only with the desktop option.
pub(crate) const DESKTOP_SERVICES: [u32; 3] = [0x5300, 0x5301, 0x5302];
/// One boot to init idle, with the network service's DHCP exchange; the build is not counted.
const LANE_TIMEOUT: Duration = Duration::from_secs(180);

/// The kernel's record of a syscall 3 call whose handle names no console sink.
const CONSOLE_REFUSED_PREFIX: &str = "[IPC ] console write refused pid=";
/// The message init sends through its lifecycle handle. The handle names endpoint generation 0,
/// which no endpoint has, so finding it on serial is a regression guard, not evidence.
const CONSOLE_PROBE: &str = "[INIT] console probe on a non-console handle";

/// In serial order, except that network and the shell start together once storage is ready, so
/// their lines interleave as the two run; [`validate_boot`] checks each service's own order. The
/// audit and console services start with storage and run beside all three, so only
/// [`validate_boot`] and the settle count check them.
/// Kernel lines (`[KERN]`, `[SVC ]`) are printed by the kernel; `[INIT]` lines reach serial
/// only through init's console capability, as `[IPC ] console pid=N: …`.
pub(crate) const MARKERS: [MarkerStep<'static>; 19] = [
    MarkerStep::Ordered("[KERN] serial console input on vector="),
    MarkerStep::Ordered("[KERN] boot profile=base"),
    MarkerStep::Ordered("[KERN] init launched pid="),
    MarkerStep::Ordered("[KERN] init authority pid="),
    MarkerStep::Ordered("[INIT] boot profile=base"),
    MarkerStep::Ordered("[INIT] started pid="),
    MarkerStep::Ordered("[INIT] SERVICE_READY from init refused: not a service"),
    MarkerStep::Ordered(CONSOLE_REFUSED_PREFIX),
    MarkerStep::Ordered("[INIT] console write on the lifecycle handle refused: EBADF"),
    MarkerStep::Ordered("[INIT] starting service=20736"),
    MarkerStep::Ordered("[SVC ] authority service=20736 "),
    MarkerStep::Ordered("[SVC ] launch service=20736 "),
    MarkerStep::Ordered("[SVC ] ready service=20736 "),
    MarkerStep::Ordered("[INIT] service=20736 ready; starting service=20992"),
    MarkerStep::Ordered("[SVC ] authority service=20992 "),
    MarkerStep::Ordered("[SVC ] launch service=20992 "),
    MarkerStep::UnorderedGroup(&[
        "[INIT] service=20736,22016 ready; starting service=21504",
        "[SVC ] authority service=21504 ",
        "[SVC ] launch service=21504 ",
        "[SVC ] ready service=21504 ",
        "[INIT] service=21504 ready gen=1",
        "[SVC ] ready service=20992 ",
        "[INIT] service=20992 ready gen=1",
    ]),
    MarkerStep::Ordered("[INIT] boot settled running=5 down=0; waiting, no deadline"),
    MarkerStep::Ordered("[KERN] idle thread halted 16 times in a row while init pid="),
];

pub(crate) fn system_data_disk_path() -> PathBuf {
    workspace_root()
        .join("target")
        .join(SYSTEM_DATA_DISK_FILENAME)
}

/// Creates a zeroed data disk at `path` when there is none. Returns whether it was created.
/// An existing disk is reused only if it is blank or holds this build's store format.
pub(crate) fn ensure_data_disk(path: &Path) -> Result<bool, XtaskError> {
    if path.is_file() {
        let actual = fs::metadata(path)?.len();
        if actual != M5_DATA_DISK_SIZE_BYTES {
            return Err(XtaskError::InvalidDiskSize {
                path: path.to_path_buf(),
                expected: M5_DATA_DISK_SIZE_BYTES,
                actual,
            });
        }
        check_data_disk_store_format(path)?;
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::File::create(path)?.set_len(M5_DATA_DISK_SIZE_BYTES)?;
    Ok(true)
}

/// Refuses a reused data disk that the storage service would refuse, using the store's own
/// [`probe`]: only a blank disk (the service formats it) or a mountable one is accepted.
pub(crate) fn check_data_disk_store_format(path: &Path) -> Result<(), XtaskError> {
    let mut disk = DiskImage::open(path)?;
    let probed = probe(&mut disk).map_err(|error| {
        XtaskError::Validation(format!(
            "data disk {} could not be probed: {error:?}",
            path.display()
        ))
    })?;
    match probed {
        Probe::Blank | Probe::Mountable => Ok(()),
        Probe::Refused(Refusal::UnsupportedVersion(found)) => Err(XtaskError::StaleDataDisk {
            path: path.to_path_buf(),
            found,
            expected: STORE_VERSION,
        }),
        Probe::Refused(Refusal::InterruptedFormat) => Err(XtaskError::InterruptedFormatDataDisk {
            path: path.to_path_buf(),
        }),
        Probe::Refused(refusal) => Err(XtaskError::UnusableDataDisk {
            path: path.to_path_buf(),
            reason: refusal.to_string(),
        }),
    }
}

/// A data disk image as a read-only block device with the geometry QEMU gives the guest.
struct DiskImage {
    file: fs::File,
    geometry: BlockGeometry,
}

impl DiskImage {
    fn open(path: &Path) -> Result<Self, XtaskError> {
        Self::open_with(path, true)
    }

    fn open_with(path: &Path, read_only: bool) -> Result<Self, XtaskError> {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(!read_only)
            .open(path)?;
        let block_count = file.metadata()?.len() / DATA_DISK_BLOCK_BYTES as u64;
        let geometry = BlockGeometry::new(
            BlockDeviceId::new(1),
            DATA_DISK_BLOCK_BYTES as u32,
            block_count,
            8,
            read_only,
        )
        .map_err(|error| {
            XtaskError::Validation(format!(
                "data disk {} has no usable geometry: {error:?}",
                path.display()
            ))
        })?;
        Ok(Self { file, geometry })
    }
}

impl BlockDevice for DiskImage {
    fn geometry(&self) -> BlockGeometry {
        self.geometry
    }

    fn read_blocks(
        &mut self,
        lba: u64,
        blocks: u32,
        buffer: &mut [u8],
    ) -> Result<(), BlockIoError> {
        let bytes = self.geometry.validate_read(lba, blocks, buffer.len())?;
        self.file
            .seek(SeekFrom::Start(bytes.start as u64))
            .and_then(|_| self.file.read_exact(buffer))
            .map_err(|_| BlockIoError::Transport(BlockTransportError::DeviceFault))
    }

    fn write_blocks(&mut self, lba: u64, blocks: u32, buffer: &[u8]) -> Result<(), BlockIoError> {
        let bytes = self.geometry.validate_write(lba, blocks, buffer.len())?;
        self.file
            .seek(SeekFrom::Start(bytes.start as u64))
            .and_then(|_| self.file.write_all(buffer))
            .map_err(|_| BlockIoError::Transport(BlockTransportError::DeviceFault))
    }

    fn flush(&mut self) -> Result<(), BlockIoError> {
        if self.geometry.is_read_only() {
            return Err(BlockIoError::Unsupported(
                BlockUnsupportedError::WriteProtected,
            ));
        }
        self.file
            .sync_all()
            .map_err(|_| BlockIoError::Transport(BlockTransportError::DeviceFault))
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RunOptions {
    net: bool,
    desktop: bool,
    framebuffer: bool,
    /// `--terminal`: the desktop also declares the terminal window and its shell (#311).
    terminal: bool,
}

/// `opt/clean-slate/desktop` plus, for `q1`, the VirtIO-GPU device `run --desktop` adds.
/// #313: QEMU ids of the virtio keyboard and tablet that `run --desktop` and
/// `test-system-tablet` add (`device_del` and `info qtree` name them).
pub(crate) const VIRTIO_KEYBOARD_ID: &str = "cs-keyboard";
pub(crate) const VIRTIO_TABLET_ID: &str = "cs-tablet";

/// A virtio keyboard and tablet. The kernel prefers them to PS/2 for their slots, so the
/// desktop's pointer follows the host cursor instead of capturing it.
pub(crate) fn virtio_input_qemu_args() -> Vec<String> {
    vec![
        "-device".to_owned(),
        format!("virtio-keyboard-pci,id={VIRTIO_KEYBOARD_ID}"),
        "-device".to_owned(),
        format!("virtio-tablet-pci,id={VIRTIO_TABLET_ID}"),
    ]
}

pub(crate) fn desktop_qemu_args(framebuffer: bool) -> Vec<String> {
    desktop_qemu_args_with(framebuffer, false)
}

/// [`desktop_qemu_args`], with `-terminal` on the value when `terminal` (#311).
pub(crate) fn desktop_qemu_args_with(framebuffer: bool, terminal: bool) -> Vec<String> {
    let value = match (framebuffer, terminal) {
        (true, false) => "q0",
        (false, false) => "q1",
        (true, true) => "q0-terminal",
        (false, true) => "q1-terminal",
    };
    let mut args = vec![
        "-fw_cfg".to_owned(),
        format!("name=opt/clean-slate/desktop,string={value}"),
    ];
    if !framebuffer {
        args.extend(crate::m10_virtio_gpu::qemu_args());
    }
    args
}

fn parse_run_options(args: &[OsString]) -> Result<RunOptions, XtaskError> {
    let mut options = RunOptions::default();
    for arg in args {
        if arg == OsStr::new("--net") {
            options.net = true;
            continue;
        }
        if arg == OsStr::new("--desktop") {
            options.desktop = true;
            continue;
        }
        if arg == OsStr::new("--framebuffer") {
            options.framebuffer = true;
            continue;
        }
        if arg == OsStr::new("--terminal") {
            options.terminal = true;
            continue;
        }
        return Err(XtaskError::InvalidOption(
            arg.to_string_lossy().into_owned(),
        ));
    }
    if (options.framebuffer || options.terminal) && !options.desktop {
        return Err(XtaskError::InvalidCommand(
            "usage: cargo xtask run [--net] [--desktop] [--framebuffer] [--terminal]".to_owned(),
        ));
    }
    Ok(options)
}

fn desktop_display() -> String {
    match std::env::var("QEMU_DISPLAY") {
        Ok(display) if !display.is_empty() => display,
        _ => "gtk".to_owned(),
    }
}

fn launch_config(options: RunOptions, disk: PathBuf, fixture_port: Option<u16>) -> VmLaunchConfig {
    let mut config = system_vm_config(disk, fixture_port);
    if options.desktop {
        config.machine_extra = Some("vmport=off");
        config.display = Some(desktop_display());
        if options.framebuffer {
            config.vga = Some("std");
        }
        config.extra_args = desktop_qemu_args_with(options.framebuffer, options.terminal);
        config.extra_args.extend(virtio_input_qemu_args());
    }
    config
}

pub(crate) fn system_vm_config(data_disk: PathBuf, fixture_port: Option<u16>) -> VmLaunchConfig {
    VmLaunchConfig {
        m5_data_disk: Some(data_disk),
        m7_fixture_port: fixture_port,
        cpu_model: Some(RDRAND_CPU_MODEL),
        ..VmLaunchConfig::default()
    }
}

pub(crate) fn start_fixture_peer() -> Result<M7FixturePeer, XtaskError> {
    start_peer(false)
}

/// The peer the shell's BusyBox applets talk to: the M9 profile answers the A, AAAA and PTR
/// queries `nslookup` sends (`m7.fixture.test` is 10.77.0.50) and serves HTTP on
/// 10.77.0.50:4001.
pub(crate) fn start_shell_fixture_peer() -> Result<M7FixturePeer, XtaskError> {
    start_peer(true)
}

fn start_peer(m9_profile: bool) -> Result<M7FixturePeer, XtaskError> {
    M7FixturePeer::start_with(FixtureOptions {
        tls_cert: WhichCert::Correct,
        dns_reply_delay: Duration::ZERO,
        m9_profile,
        impaired: false,
    })
    .map_err(XtaskError::Io)
}

/// `cargo xtask run [--net] [--desktop] [--framebuffer] [--terminal]`. `run-gdb` and `run-gdb-entry` take
/// `--net` only; `--desktop` is refused there.
pub(crate) fn run(
    args: &[OsString],
    wait_for_gdb: bool,
    debug_entry: bool,
) -> Result<(), XtaskError> {
    let options = parse_run_options(args)?;
    if wait_for_gdb && options.desktop {
        return Err(XtaskError::InvalidCommand(
            "run-gdb does not take --desktop".to_owned(),
        ));
    }
    let disk = system_data_disk_path();
    let created = ensure_data_disk(&disk)?;
    println!(
        "[XTSK] data disk {} ({})",
        disk.display(),
        if created { "created" } else { "persistent" }
    );
    let peer = if options.net {
        let peer = start_shell_fixture_peer()?;
        println!("[XTSK] network fixture peer on 127.0.0.1:{}", peer.port());
        Some(peer)
    } else {
        println!("[XTSK] no network device (pass --net for the fixture peer)");
        None
    };
    if options.desktop {
        println!(
            "[XTSK] desktop boot option opt/clean-slate/desktop={} ({})",
            if options.framebuffer { "q0" } else { "q1" },
            if options.framebuffer {
                "-vga std"
            } else {
                "virtio-gpu-pci"
            }
        );
    }
    let result = run_vm_inner_with_config(
        wait_for_gdb,
        debug_entry,
        &[],
        None,
        launch_config(options, disk, peer.as_ref().map(M7FixturePeer::port)),
    );
    if let Some(peer) = peer {
        peer.shutdown();
    }
    result
}

/// `test-system-boot`: two boots of the default image on a fresh lane-owned disk.
pub(crate) fn run_lane() -> Result<(), XtaskError> {
    let disk = workspace_root()
        .join("target")
        .join("system-boot")
        .join(SYSTEM_DATA_DISK_FILENAME);
    if disk.is_file() {
        fs::remove_file(&disk)?;
    }
    ensure_data_disk(&disk)?;
    let first = boot_once(&disk, Formatted::Yes)?;
    let second = boot_once(&disk, Formatted::No)?;
    let refusals = boot_on_corrupt_disk(&disk)?;
    println!(
        "\n[SYS ] PASS boot 1 formatted the disk (storage pid={} block-writes={}), boot 2 mounted it (storage pid={}); every service held exactly its manifest grants and reported ready from its launched pid; boot 3 on the corrupted disk refused it {refusals} times and left every byte unchanged",
        first.storage_pid, first.storage_block_writes, second.storage_pid
    );
    Ok(())
}

const REFUSAL_LINE: &str = "[STOR] refusing data disk: corrupt (both superblock slots invalid)";

/// Storage is launched once and restarted [`STORAGE_RESTARTS`] times, refusing the disk each
/// time; init then gives up on it and on the two services that depend on it. The audit and
/// console services depend on nothing and keep running.
const REFUSED_DISK_MARKERS: [MarkerStep<'static>; 7] = [
    MarkerStep::Ordered("[KERN] init launched pid="),
    MarkerStep::Ordered("[INIT] starting service=20736"),
    MarkerStep::Ordered("[SVC ] launch service=20736 "),
    MarkerStep::Ordered(REFUSAL_LINE),
    MarkerStep::Ordered("[INIT] gave up service=20736 restarts=3; init carries on"),
    MarkerStep::UnorderedGroup(&[
        "[INIT] not starting service=20992: service=20736 is down",
        "[INIT] not starting service=21504: service=20736 is down",
    ]),
    MarkerStep::Ordered("[INIT] boot settled running=2 down=3; waiting, no deadline"),
];
const STORAGE_RESTARTS: usize = 3;

/// Makes both superblock slots of the store on `path` unusable without zeroing them: slot A
/// loses a magic bit, and slot B a generation bit, so its checksum no longer matches.
pub(crate) fn corrupt_both_superblocks(path: &Path) -> Result<(), XtaskError> {
    let mut file = fs::OpenOptions::new().read(true).write(true).open(path)?;
    for (offset, mask) in [(0, 0x01u8), (DATA_DISK_BLOCK_BYTES as u64 + 12, 0x01)] {
        let mut byte = [0u8];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut byte)?;
        byte[0] ^= mask;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&byte)?;
    }
    file.sync_all()?;
    Ok(())
}

/// Boot 3: the store the first two boots built, corrupted. Storage must refuse it, say why,
/// and write nothing to it. Returns how many instances refused it.
fn boot_on_corrupt_disk(disk: &Path) -> Result<usize, XtaskError> {
    corrupt_both_superblocks(disk)?;
    let before = fs::read(disk)?;
    let peer = start_fixture_peer()?;
    let output = run_driven_vm_acceptance(
        &[],
        system_vm_config(disk.to_path_buf(), Some(peer.port())),
        MarkerSet::Steps(&REFUSED_DISK_MARKERS),
        LANE_TIMEOUT,
        &mut NoDriver,
    );
    peer.shutdown();
    let refusals = validate_refused_boot(&output?).map_err(|reason| {
        XtaskError::Validation(format!("system boot on a corrupt disk: {reason}"))
    })?;
    if fs::read(disk)? != before {
        return Err(XtaskError::Validation(
            "system boot on a corrupt disk: the refused disk's bytes changed".to_owned(),
        ));
    }
    Ok(refusals)
}

/// Every storage instance printed the refusal as it exited, straight after the kernel's exit
/// line for its own pid; none reported ready, and neither dependent was launched.
fn validate_refused_boot(output: &str) -> Result<usize, String> {
    let lines: Vec<&str> = output.lines().map(str::trim_end).collect();
    let launches: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|line| line.starts_with("[SVC ] launch service=20736 "))
        .collect();
    if launches.len() != 1 + STORAGE_RESTARTS {
        return Err(format!(
            "expected {} storage launches, found {}",
            1 + STORAGE_RESTARTS,
            launches.len()
        ));
    }
    for launch in &launches {
        let exit = format!("[PROC] fault pid={} vector=128 ", number(launch, "pid")?);
        let at = lines
            .iter()
            .position(|line| line.starts_with(&exit))
            .ok_or_else(|| format!("no exit line {exit:?}"))?;
        if lines.get(at + 1) != Some(&REFUSAL_LINE) {
            return Err(format!(
                "{exit:?} is not followed by {REFUSAL_LINE:?}: {:?}",
                lines.get(at + 1)
            ));
        }
    }
    let refusals = lines
        .iter()
        .filter(|line| line.contains("[STOR] refusing data disk: "))
        .count();
    if refusals != launches.len() {
        return Err(format!(
            "{refusals} refusal lines for {} storage launches",
            launches.len()
        ));
    }
    for absent in [
        "[SVC ] ready service=20736 ",
        "[SVC ] launch service=20992 ",
        "[SVC ] launch service=21504 ",
    ] {
        if let Some(line) = lines.iter().find(|line| line.starts_with(absent)) {
            return Err(format!("unexpected {line:?} on a refused disk"));
        }
    }
    Ok(refusals)
}

fn boot_once(disk: &Path, formatted: Formatted) -> Result<BootSummary, XtaskError> {
    let peer = start_fixture_peer()?;
    let output = run_driven_vm_acceptance(
        &[],
        system_vm_config(disk.to_path_buf(), Some(peer.port())),
        MarkerSet::Steps(&MARKERS),
        LANE_TIMEOUT,
        &mut NoDriver,
    );
    peer.shutdown();
    validate_boot(&output?, formatted)
        .map_err(|reason| XtaskError::Validation(format!("system boot: {reason}")))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Formatted {
    Yes,
    No,
}

#[derive(Debug, PartialEq, Eq)]
struct BootSummary {
    storage_pid: u64,
    storage_block_writes: u64,
}

/// `key=value` from a whitespace-separated line.
pub(crate) fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|token| token.strip_prefix(key)?.strip_prefix('='))
}

pub(crate) fn number(line: &str, key: &str) -> Result<u64, String> {
    field(line, key)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| format!("no numeric {key}= in {line:?}"))
}

fn only_line<'a>(output: &'a str, prefix: &str) -> Result<&'a str, String> {
    let mut found = output
        .lines()
        .map(str::trim_end)
        .filter(|line| line.starts_with(prefix));
    let line = found
        .next()
        .ok_or_else(|| format!("no line starting {prefix:?}"))?;
    if found.next().is_some() {
        return Err(format!("more than one line starting {prefix:?}"));
    }
    Ok(line)
}

/// What the markers cannot say on their own: init holds lifecycle control and the console only;
/// every `[INIT]` line came from init's pid; each service launched once, held exactly its
/// manifest grants and reported ready from the pid and generation the kernel launched, in that
/// order, before init announced it; storage formatted the disk (with block writes) or mounted it,
/// as `formatted` expects; the shell holds the console, stdin, `/tmp`, the network client
/// entitlement, a client capability for the network instance (launched before it in the same
/// init wake, so live) and the Linux personality only, and became ready by blocking on stdin;
/// the audit service holds `AUDIT_READ` and its console only and became ready where the kernel
/// says its first drain stopped ([`check_audit_service`]); the console service serves its port
/// with the serial device and became ready waiting in its work set ([`check_console_service`]).
fn validate_boot(output: &str, formatted: Formatted) -> Result<BootSummary, String> {
    // `[HOOK]` lines come only from the `system-test-hooks` build; this is the default image.
    if let Some(line) = output.lines().find(|line| line.contains("[HOOK]")) {
        return Err(format!("a test-hooks line in the default image: {line:?}"));
    }
    let profile = only_line(output, "[KERN] boot profile=")?;
    if profile != "[KERN] boot profile=base" {
        return Err(format!("desktop boot option: {profile:?}"));
    }
    let launched = only_line(output, "[KERN] init launched pid=")?;
    let init_pid = number(launched, "pid")?;
    check_no_desktop_rows(output, launched)?;
    let authority = only_line(output, "[KERN] init authority pid=")?;
    let expected_authority = format!(
        "[KERN] init authority pid={init_pid} lifecycle-control=1 console=1 block-device=0 object-service=0 network=0 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 audit-read=0 con-serve=0 con-device=0 con-client=0 other=0 revoked=0 allowance=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0 linux=0 console-input=0 expected-only-lifecycle-and-console=1"
    );
    if authority != expected_authority {
        return Err(format!("init authority line {authority:?}"));
    }
    let console_prefix = format!("[IPC ] console pid={init_pid}: [INIT] ");
    for line in output.lines().filter(|line| line.contains("[INIT] ")) {
        if !line.starts_with(&console_prefix) {
            return Err(format!(
                "[INIT] line not sent by init pid={init_pid}: {line:?}"
            ));
        }
    }
    let init_profile = format!("{console_prefix}boot profile=base");
    only_line(output, &init_profile)
        .map_err(|_| format!("desktop boot option: init did not report {init_profile:?}"))?;
    let started = only_line(output, &format!("{console_prefix}started pid="))?;
    if number(&started[console_prefix.len()..], "pid")? != init_pid {
        return Err(format!("init reports a different pid: {started:?}"));
    }
    check_console_refusal(output, init_pid)?;

    let mut summary = None;
    for service in [
        STORAGE_SERVICE,
        NETWORK_SERVICE,
        SHELL_SERVICE,
        AUDIT_SERVICE,
        CONSOLE_SERVICE,
    ] {
        let launch = only_line(output, &format!("[SVC ] launch service={service} "))?;
        let pid = number(launch, "pid")?;
        let generation = number(launch, "gen")?;
        if pid == init_pid {
            return Err(format!("service {service} launched as init's pid"));
        }
        let audit = only_line(output, &format!("[SVC ] authority service={service} "))?;
        if number(audit, "pid")? != pid || field(audit, "matches-manifest") != Some("1") {
            return Err(format!("service {service} authority {audit:?}"));
        }
        let ready = only_line(output, &format!("[SVC ] ready service={service} "))?;
        if number(ready, "pid")? != pid
            || number(ready, "gen")? != generation
            || field(ready, "source") != Some("live-instance")
        {
            return Err(format!(
                "service {service} launched as pid={pid} gen={generation} but ready says {ready:?}"
            ));
        }
        let announced = format!("{console_prefix}service={service} ready gen={generation}");
        let at = |line: &str| output.find(line);
        let order = [at(audit), at(launch), at(ready), at(&announced)];
        if order.contains(&None) || !order.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(format!(
                "service {service}: expected authority, launch, ready, then {announced:?}"
            ));
        }
        if service == SHELL_SERVICE {
            check_shell(output, pid, generation, audit, ready)?;
        }
        if service == AUDIT_SERVICE {
            check_audit_service(output, pid, audit, ready)?;
        }
        if service == CONSOLE_SERVICE {
            check_console_service(output, pid, audit, ready)?;
        }
        if service == NETWORK_SERVICE && field(ready, "raw-backend") != Some("virtio") {
            return Err(format!(
                "network is not on the fixture's virtio device: {ready:?}"
            ));
        }
        if service == STORAGE_SERVICE {
            let block_writes = number(ready, "block-write-requests")?;
            let want = match formatted {
                Formatted::Yes => "1",
                Formatted::No => "0",
            };
            if field(ready, "formatted") != Some(want) {
                return Err(format!(
                    "storage ready expected formatted={want}: {ready:?}"
                ));
            }
            if formatted == Formatted::Yes && block_writes == 0 {
                return Err(format!(
                    "storage formatted without a block write: {ready:?}"
                ));
            }
            summary = Some(BootSummary {
                storage_pid: pid,
                storage_block_writes: block_writes,
            });
        }
    }
    summary.ok_or_else(|| "storage was not checked".to_owned())
}

/// The lifecycle-control family tag, bits 56..64 of every lifecycle handle (#288).
const LIFECYCLE_HANDLE_TAG: u64 = 0x02;

/// Syscall 3 on init's lifecycle handle: the kernel recorded its refusal for init's pid. Init
/// probes before it starts any service, so its refusal is the boot's first and only one. The
/// handle it records must carry the lifecycle family tag: the IPC decoder refuses any other
/// tag before it reads a field, so the refusal is the family check and not a lucky field.
fn check_console_refusal(output: &str, init_pid: u64) -> Result<(), String> {
    if let Some(line) = output.lines().find(|line| line.contains(CONSOLE_PROBE)) {
        return Err(format!(
            "syscall 3 delivered a message on a non-console handle: {line:?}"
        ));
    }
    let refused = only_line(output, CONSOLE_REFUSED_PREFIX)?;
    if number(refused, "pid")? != init_pid || !refused.ends_with(": not the console sink") {
        return Err(format!("console refusal record {refused:?}"));
    }
    let handle = field(refused, "handle")
        .and_then(|value| value.strip_suffix(':'))
        .and_then(|value| value.strip_prefix("0x"))
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .ok_or_else(|| format!("no hex handle= in {refused:?}"))?;
    if handle >> 56 != LIFECYCLE_HANDLE_TAG {
        return Err(format!(
            "init's console probe used handle {handle:#x}, which does not carry the lifecycle family tag"
        ));
    }
    Ok(())
}

/// The audit service's launch audit: `AUDIT_READ` on the log and its console, nothing else.
pub(crate) fn expected_audit_authority(pid: u64) -> String {
    format!(
        "[SVC ] authority service={AUDIT_SERVICE} pid={pid} lifecycle-control=0 console=1 block-device=0 object-service=0 network=0 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 audit-read=1 con-serve=0 con-device=0 con-client=0 other=0 revoked=0 allowance=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0 linux=0 console-input=0 matches-manifest=1"
    )
}

/// The audit service holds exactly its row and reported ready after its first drain. That
/// drain's summary line must account for every sequence up to where it ended (each is a record
/// or inside a lost run), and the kernel's own read cursor, logged with the ready report, must
/// be exactly there: the service read the log rather than only saying so. Its lost count can be
/// no more than the kernel's count of records dropped.
pub(crate) fn check_audit_service(
    output: &str,
    pid: u64,
    audit: &str,
    ready: &str,
) -> Result<(), String> {
    if audit != expected_audit_authority(pid) {
        return Err(format!("audit service authority {audit:?}"));
    }
    let drained_prefix = format!("[IPC ] console pid={pid}: [ADT ] drained ");
    let drained = output
        .lines()
        .map(str::trim_end)
        .find(|line| line.starts_with(&drained_prefix))
        .ok_or_else(|| format!("the audit service printed no {drained_prefix:?} line"))?;
    let drained_fields = &drained[drained.find("[ADT ]").unwrap_or(0)..];
    let through = number(drained_fields, "through")?;
    let records = number(drained_fields, "records")?;
    let lost = number(drained_fields, "lost")?;
    if through == 0 || records + lost != through {
        return Err(format!(
            "the audit service's first drain does not account for sequences 1..={through}: {drained:?}"
        ));
    }
    if number(ready, "audit-read-through")? != through {
        return Err(format!(
            "the kernel's audit read cursor is not where the service's first drain ended ({drained:?}): {ready:?}"
        ));
    }
    if lost > number(ready, "audit-dropped")? {
        return Err(format!(
            "the audit service reported more sequences lost than the kernel dropped ({drained:?}): {ready:?}"
        ));
    }
    // The service's own report, so a consistency check rather than evidence it read the log.
    if number(ready, "first-drain-records")? != records {
        return Err(format!(
            "the audit service's ready detail is not its first drain's record count: {ready:?}"
        ));
    }
    match (output.find(drained), output.find(ready)) {
        (Some(drained_at), Some(ready_at)) if drained_at < ready_at => Ok(()),
        _ => Err(format!(
            "the audit service reported ready before its first drain: {ready:?}"
        )),
    }
}

/// The console service's launch audit (#310): its IPC console for its own failures, `CONSOLE_SERVE`
/// on the port it registered and `READ` and `WRITE` on the serial console device, nothing else.
pub(crate) fn expected_console_authority(pid: u64) -> String {
    format!(
        "[SVC ] authority service={CONSOLE_SERVICE} pid={pid} lifecycle-control=0 console=1 block-device=0 object-service=0 network=0 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 audit-read=0 con-serve=1 con-device=1 con-client=0 other=0 revoked=0 allowance=0 owned-endpoints=0 ports=1 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0 linux=0 console-input=0 matches-manifest=1"
    )
}

/// The console service holds exactly its row, the kernel registered its port before the launch
/// audit, and it reported ready serving that one port from a work set: it found its capability,
/// bound the port's wake and reached its wait loop before it said ready.
pub(crate) fn check_console_service(
    output: &str,
    pid: u64,
    audit: &str,
    ready: &str,
) -> Result<(), String> {
    if audit != expected_console_authority(pid) {
        return Err(format!("console service authority {audit:?}"));
    }
    let granted_prefix = format!("[CONS] authority granted pid={pid} port={CONSOLE_SERVICE}:");
    let granted = only_line(output, &granted_prefix)?;
    if !granted.ends_with(" rights=serve registered=1 device=read|write") {
        return Err(format!("console service port grant {granted:?}"));
    }
    if !ready.contains(" kernel-observed ports=1 port-connections=")
        || field(ready, "work-sets") != Some("1")
    {
        return Err(format!(
            "console service ready without serving its port from a work set: {ready:?}"
        ));
    }
    match (output.find(granted), output.find(audit)) {
        (Some(granted_at), Some(audit_at)) if granted_at < audit_at => Ok(()),
        _ => Err(format!(
            "console service port granted after its launch audit: {granted:?}"
        )),
    }
}

/// With the desktop option off the kernel declares the base rows and nothing of the desktop's:
/// no desktop row is declared or launched and no graphics, display or input authority is
/// granted.
pub(crate) fn check_no_desktop_rows(output: &str, launched: &str) -> Result<(), String> {
    if number(launched, "declared-services")? != BASE_SERVICES {
        return Err(format!("off-mode boot declared desktop rows: {launched:?}"));
    }
    let desktop_line = output.lines().find(|line| {
        DESKTOP_SERVICES.iter().any(|service| {
            line.contains(&format!("[SVC ] declared service={service}"))
                || line.contains(&format!("[SVC ] launch service={service} "))
        }) || [
            "[GFX ] authority granted",
            "[DISP] authority granted",
            "[SEAT] authority granted",
        ]
        .iter()
        .any(|prefix| line.contains(prefix))
    });
    match desktop_line {
        Some(line) => Err(format!("off-mode boot declared desktop rows: {line:?}")),
        None => Ok(()),
    }
}

fn check_shell(
    output: &str,
    pid: u64,
    generation: u64,
    audit: &str,
    ready: &str,
) -> Result<(), String> {
    let expected_audit = format!(
        "[SVC ] authority service={SHELL_SERVICE} pid={pid} lifecycle-control=0 console=1 block-device=0 object-service=0 network=0 net-client=1 net-client-entitlement=1 tmp-objects=5 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 audit-read=0 con-serve=0 con-device=0 con-client=1 other=0 revoked=0 allowance=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0 linux=1 console-input=1 matches-manifest=1"
    );
    if audit != expected_audit {
        return Err(format!("shell authority {audit:?}"));
    }
    // The console port's client capability routes the shell's console fds through the console
    // service (#310): granted to the shell's pid before its launch audit.
    let connect = only_line(
        output,
        &format!("[CONS] authority granted pid={pid} port={CONSOLE_SERVICE}:"),
    )?;
    if !connect.ends_with(" rights=connect") {
        return Err(format!("shell console client grant {connect:?}"));
    }
    match (output.find(connect), output.find(audit)) {
        (Some(granted_at), Some(audit_at)) if granted_at < audit_at => {}
        _ => {
            return Err(format!(
                "shell console client granted after its launch audit: {connect:?}"
            ))
        }
    }
    let process = only_line(output, "[SVC ] shell process ")?;
    let expected_process = format!(
        "[SVC ] shell process pid={pid} gen={generation} argv=/bin/sh,-i env=PATH=/bin stdin=1 stdout=1 tmp=1 net-client=1"
    );
    if process != expected_process {
        return Err(format!("shell process line {process:?}"));
    }
    if !ready.ends_with(" kernel-observed first-console-input-wait") {
        return Err(format!("shell ready without blocking on stdin: {ready:?}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transcript(formatted: u8, writes: u64) -> String {
        format!(
            "[SVC ] declared service=20736\n\
             [SVC ] declared service=20992\n\
             [SVC ] declared service=22016\n\
             [SVC ] declared service=21504\n\
             [SVC ] declared service=21760\n\
             [KERN] serial console input on vector=49\n\
             [KERN] boot profile=base\n\
             [KERN] init launched pid=3 slot=0 declared-services=5\n\
             [KERN] init authority pid=3 lifecycle-control=1 console=1 block-device=0 object-service=0 network=0 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 audit-read=0 con-serve=0 con-device=0 con-client=0 other=0 revoked=0 allowance=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0 linux=0 console-input=0 expected-only-lifecycle-and-console=1\n\
             [IPC ] console pid=3: [INIT] boot profile=base\n\
             [IPC ] console pid=3: [INIT] started pid=3 services=5\n\
             [IPC ] console pid=3: [INIT] SERVICE_READY from init refused: not a service\n\
             [IPC ] console write refused pid=3 handle=0x200000000010000: not the console sink\n\
             [IPC ] console pid=3: [INIT] console write on the lifecycle handle refused: EBADF\n\
             [IPC ] console pid=3: [INIT] starting service=20736\n\
             [SVC ] authority service=20736 pid=4 lifecycle-control=0 console=0 block-device=1 object-service=1 network=0 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 audit-read=0 con-serve=0 con-device=0 con-client=0 other=0 revoked=0 allowance=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0 linux=0 console-input=0 matches-manifest=1\n\
             [SVC ] launch service=20736 pid=4 gen=1\n\
             [IPC ] console pid=3: [INIT] starting service=22016\n\
             [CONS] authority granted pid=8 port=22016:8 rights=serve registered=1 device=read|write\n\
             {console_authority}\n\
             [SVC ] launch service=22016 pid=8 gen=1\n\
             [SVC ] ready service=22016 pid=8 gen=1 source=live-instance kernel-observed ports=1 port-connections=0 work-sets=1 service-reported detail=0x0\n\
             [IPC ] console pid=3: [INIT] service=22016 ready gen=1\n\
             [IPC ] console pid=3: [INIT] starting service=21760\n\
             {audit_authority}\n\
             [SVC ] launch service=21760 pid=7 gen=1\n\
             [IPC ] console pid=7: [ADT ] lost first=1 missing=40\n\
             [IPC ] console pid=7: [ADT ] drained through=60 records=20 lost=40\n\
             [SVC ] ready service=21760 pid=7 gen=1 source=live-instance kernel-observed audit-read-through=60 audit-next=61 audit-dropped=40 service-reported first-drain-records=20\n\
             [IPC ] console pid=3: [INIT] service=21760 ready gen=1\n\
             [SVC ] ready service=20736 pid=4 gen=1 source=live-instance kernel-observed block-write-requests={writes} service-reported formatted={formatted} store-generation=1\n\
             [IPC ] console pid=3: [INIT] service=20736 ready gen=1\n\
             [IPC ] console pid=3: [INIT] service=20736 ready; starting service=20992\n\
             [SVC ] authority service=20992 pid=5 lifecycle-control=0 console=0 block-device=0 object-service=0 network=1 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 audit-read=0 con-serve=0 con-device=0 con-client=0 other=0 revoked=0 allowance=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=1 linux=0 console-input=0 matches-manifest=1\n\
             [SVC ] launch service=20992 pid=5 gen=1\n\
             [IPC ] console pid=3: [INIT] service=20736,22016 ready; starting service=21504\n\
             [SVC ] shell process pid=6 gen=1 argv=/bin/sh,-i env=PATH=/bin stdin=1 stdout=1 tmp=1 net-client=1\n\
             [CONS] authority granted pid=6 port=22016:8 rights=connect\n\
             [SVC ] authority service=21504 pid=6 lifecycle-control=0 console=1 block-device=0 object-service=0 network=0 net-client=1 net-client-entitlement=1 tmp-objects=5 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 audit-read=0 con-serve=0 con-device=0 con-client=1 other=0 revoked=0 allowance=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0 linux=1 console-input=1 matches-manifest=1\n\
             [SVC ] launch service=21504 pid=6 gen=1\n\
             [SVC ] ready service=20992 pid=5 gen=1 source=live-instance kernel-observed raw-backend=virtio service-reported link-up=1\n\
             [IPC ] console pid=3: [INIT] service=20992 ready gen=1\n\
             [CON ] pid=6: \n\
             [CON ] pid=6: \n\
             [CON ] pid=6: # BusyBox v1.37.0 (2026-09-23 09:18:28 UTC) built-in shell (ash)\n\
             [CON ] pid=6: \n\
             [SVC ] ready service=21504 pid=6 gen=1 source=live-instance kernel-observed first-console-input-wait\n\
             [IPC ] console pid=3: [INIT] service=21504 ready gen=1\n\
             [IPC ] console pid=3: [INIT] boot settled running=5 down=0; waiting, no deadline\n\
             [KERN] idle thread halted 16 times in a row while init pid=3 waited in LIFECYCLE_WAIT with no deadline\n",
            audit_authority = expected_audit_authority(7),
            console_authority = expected_console_authority(8),
        )
    }

    #[test]
    fn a_first_and_a_second_boot_validate() {
        assert_eq!(
            validate_boot(&transcript(1, 9), Formatted::Yes),
            Ok(BootSummary {
                storage_pid: 4,
                storage_block_writes: 9
            })
        );
        assert!(validate_boot(&transcript(0, 0), Formatted::No).is_ok());
    }

    #[test]
    fn the_markers_appear_in_order_in_a_good_transcript() {
        let mut tracker = crate::MarkerTracker::from_steps(&MARKERS);
        assert!(
            tracker.consume(&transcript(1, 9)),
            "{}",
            tracker.pending_label()
        );
        let unsettled = transcript(1, 9).replace("running=5 down=0", "running=4 down=1");
        let mut tracker = crate::MarkerTracker::from_steps(&MARKERS);
        assert!(!tracker.consume(&unsettled));
    }

    #[test]
    fn syscall_3_on_a_non_console_handle_is_refused_by_the_kernel_for_init() {
        let refused =
            "[IPC ] console write refused pid=3 handle=0x200000000010000: not the console sink\n";
        let delivered = transcript(1, 9).replace(
            refused,
            &format!("{refused}[IPC ] console pid=3: {CONSOLE_PROBE}\n"),
        );
        assert!(validate_boot(&delivered, Formatted::Yes)
            .unwrap_err()
            .contains("delivered a message on a non-console handle"));
        let unrecorded = transcript(1, 9).replace(refused, "");
        assert!(validate_boot(&unrecorded, Formatted::Yes).is_err());
        let mut tracker = crate::MarkerTracker::from_steps(&MARKERS);
        assert!(!tracker.consume(&unrecorded));
        for (from, to) in [
            ("refused pid=3 ", "refused pid=4 "),
            (": not the console sink", ": unauthorized"),
            ("handle=0x200000000010000:", "handle=0x10000:"),
            ("handle=0x200000000010000:", "handle=0x100000000010000:"),
            ("handle=0x200000000010000:", "handle=zz:"),
        ] {
            let text = transcript(1, 9).replace(from, to);
            assert!(validate_boot(&text, Formatted::Yes).is_err(), "{to}");
        }
    }

    #[test]
    fn the_shell_holds_exactly_its_row_and_is_ready_on_stdin() {
        for (from, to) in [
            ("tmp-objects=5", "tmp-objects=0"),
            ("linux=1 console-input=1", "linux=1 console-input=0"),
            (
                "pid=6 lifecycle-control=0 console=1 block-device=0 object-service=0 network=0",
                "pid=6 lifecycle-control=0 console=1 block-device=0 object-service=0 network=1",
            ),
            (
                "network=0 net-client=1 net-client-entitlement=1",
                "network=0 net-client=0 net-client-entitlement=1",
            ),
            (
                "net-client=1 net-client-entitlement=1",
                "net-client=1 net-client-entitlement=0",
            ),
            ("tmp=1 net-client=1", "tmp=1 net-client=0"),
            ("stdin=1", "stdin=0"),
            ("env=PATH=/bin", "env=PATH=/bin:/sbin"),
            (" first-console-input-wait", " service-reported"),
        ] {
            let text = transcript(1, 9).replace(from, to);
            assert!(validate_boot(&text, Formatted::Yes).is_err(), "{to}");
        }
    }

    #[test]
    fn the_audit_service_holds_its_row_and_is_ready_where_the_kernel_says_it_read() {
        for (from, to) in [
            ("input=0 audit-read=1", "input=0 audit-read=0"),
            (
                "pid=7 lifecycle-control=0 console=1 block-device=0",
                "pid=7 lifecycle-control=0 console=1 block-device=1",
            ),
            ("audit-read-through=60", "audit-read-through=59"),
            ("audit-read-through=60", "audit-read-through=0"),
            ("audit-dropped=40", "audit-dropped=39"),
            ("records=20 lost=40", "records=20 lost=39"),
            ("first-drain-records=20", "first-drain-records=21"),
            ("[ADT ] drained", "[ADT ] skimmed"),
        ] {
            let text = transcript(1, 9).replace(from, to);
            assert!(validate_boot(&text, Formatted::Yes).is_err(), "{to}");
        }
        let overcounted = transcript(1, 9).replace("audit-dropped=40", "audit-dropped=39");
        assert!(validate_boot(&overcounted, Formatted::Yes)
            .unwrap_err()
            .contains("more sequences lost than the kernel dropped"));
        let dropped_since = transcript(1, 9).replace("audit-dropped=40", "audit-dropped=41");
        assert!(validate_boot(&dropped_since, Formatted::Yes).is_ok());
        let drained = "[IPC ] console pid=7: [ADT ] drained through=60 records=20 lost=40\n";
        let late = format!("{}{drained}", transcript(1, 9).replace(drained, ""));
        assert!(validate_boot(&late, Formatted::Yes)
            .unwrap_err()
            .contains("before its first drain"));
    }

    #[test]
    fn each_service_runs_authority_launch_ready_then_init_announces_it() {
        let text = transcript(1, 9).replace(
            "[IPC ] console pid=3: [INIT] service=21504 ready gen=1\n",
            "",
        );
        assert!(validate_boot(&text, Formatted::Yes).is_err());
        let ready = "[SVC ] ready service=21504 pid=6 gen=1 source=live-instance kernel-observed first-console-input-wait\n";
        let text = transcript(1, 9).replace(ready, "").replace(
            "[SVC ] launch service=21504 pid=6 gen=1\n",
            &format!("{ready}[SVC ] launch service=21504 pid=6 gen=1\n"),
        );
        assert!(validate_boot(&text, Formatted::Yes)
            .unwrap_err()
            .contains("expected authority, launch, ready"));
    }

    #[test]
    fn the_console_service_holds_its_row_and_is_ready_serving_its_port() {
        for (from, to) in [
            ("con-serve=1 con-device=1", "con-serve=1 con-device=0"),
            ("con-serve=1 con-device=1", "con-serve=0 con-device=1"),
            (
                "pid=8 lifecycle-control=0 console=1 block-device=0",
                "pid=8 lifecycle-control=0 console=1 block-device=1",
            ),
            (
                "rights=serve registered=1 device=read|write",
                "rights=serve registered=0 device=read|write",
            ),
            ("pid=8 port=22016:8", "pid=7 port=22016:8"),
            (
                "kernel-observed ports=1 port-connections=0 work-sets=1",
                "kernel-observed ports=1 port-connections=0 work-sets=0",
            ),
            (
                "kernel-observed ports=1 port-connections=0 work-sets=1",
                "kernel-observed ports=0 port-connections=0 work-sets=1",
            ),
        ] {
            let text = transcript(1, 9).replace(from, to);
            assert!(validate_boot(&text, Formatted::Yes).is_err(), "{to}");
        }
        let granted =
            "[CONS] authority granted pid=8 port=22016:8 rights=serve registered=1 device=read|write\n";
        let late = transcript(1, 9).replace(granted, "").replace(
            "[SVC ] launch service=22016 pid=8 gen=1\n",
            &format!("{granted}[SVC ] launch service=22016 pid=8 gen=1\n"),
        );
        assert!(validate_boot(&late, Formatted::Yes)
            .unwrap_err()
            .contains("after its launch audit"));
    }

    #[test]
    fn desktop_rows_in_the_off_mode_boot_fail_by_name() {
        let declared = transcript(1, 9).replace(
            "[SVC ] declared service=21504\n",
            "[SVC ] declared service=21504\n[SVC ] declared service=21248\n",
        );
        let counted = transcript(1, 9).replace("declared-services=5", "declared-services=8");
        let granted = transcript(1, 9).replace(
            "[SVC ] launch service=21504 pid=6 gen=1\n",
            "[SVC ] launch service=21504 pid=6 gen=1\n[SEAT] authority granted pid=7 seat=0 rights=consume,inspect\n",
        );
        for text in [declared, counted, granted] {
            assert!(validate_boot(&text, Formatted::Yes)
                .unwrap_err()
                .contains("off-mode boot declared desktop rows"));
        }
    }

    #[test]
    fn formatting_must_match_the_boot() {
        assert!(validate_boot(&transcript(0, 0), Formatted::Yes).is_err());
        assert!(validate_boot(&transcript(1, 9), Formatted::No).is_err());
        assert!(validate_boot(&transcript(1, 0), Formatted::Yes)
            .unwrap_err()
            .contains("without a block write"));
    }

    #[test]
    fn ready_must_come_from_the_launched_instance() {
        let text = transcript(1, 9).replace(
            "[SVC ] ready service=20992 pid=5",
            "[SVC ] ready service=20992 pid=6",
        );
        assert!(validate_boot(&text, Formatted::Yes)
            .unwrap_err()
            .contains("ready says"));
        let text = transcript(1, 9).replace("pid=4 gen=1 source", "pid=4 gen=2 source");
        assert!(validate_boot(&text, Formatted::Yes).is_err());
    }

    #[test]
    fn network_must_be_on_the_fixture_nic() {
        let text = transcript(1, 9).replace("raw-backend=virtio", "raw-backend=loopback");
        assert!(validate_boot(&text, Formatted::Yes)
            .unwrap_err()
            .contains("virtio"));
    }

    #[test]
    fn extra_authority_or_a_restart_fails() {
        let text = transcript(1, 9).replace(
            "pid=3 lifecycle-control=1 console=1 block-device=0 object-service=0 network=0",
            "pid=3 lifecycle-control=1 console=1 block-device=0 object-service=0 network=1",
        );
        assert!(validate_boot(&text, Formatted::Yes).is_err());
        let text = transcript(1, 9).replace(
            "linux=0 console-input=0 expected",
            "linux=1 console-input=0 expected",
        );
        assert!(validate_boot(&text, Formatted::Yes).is_err());
        let text = transcript(1, 9).replace(
            "raw-net-link=1 linux=0 console-input=0 matches-manifest=1",
            "raw-net-link=1 linux=0 console-input=0 matches-manifest=0",
        );
        assert!(validate_boot(&text, Formatted::Yes).is_err());
        let text = transcript(1, 9).replace(
            "[SVC ] launch service=20992 pid=5 gen=1\n",
            "[SVC ] launch service=20992 pid=5 gen=1\n[SVC ] launch service=20992 pid=7 gen=2\n",
        );
        assert!(validate_boot(&text, Formatted::Yes)
            .unwrap_err()
            .contains("more than one"));
    }

    #[test]
    fn init_lines_from_another_pid_fail() {
        let text = transcript(1, 9).replace(
            "[IPC ] console pid=3: [INIT] starting",
            "[IPC ] console pid=4: [INIT] starting",
        );
        assert!(validate_boot(&text, Formatted::Yes)
            .unwrap_err()
            .contains("not sent by init"));
        let text = format!("{}[INIT] boot settled\n", transcript(1, 9));
        assert!(validate_boot(&text, Formatted::Yes).is_err());
    }

    #[test]
    fn a_test_hooks_line_fails_the_default_image() {
        let text = format!(
            "[HOOK] system-test-hooks build: Ctrl-\\ on COM1 faults the network service\n{}",
            transcript(1, 9)
        );
        assert!(validate_boot(&text, Formatted::Yes)
            .unwrap_err()
            .contains("test-hooks"));
    }

    #[test]
    fn run_takes_net_and_desktop() {
        assert_eq!(parse_run_options(&[]).unwrap(), RunOptions::default());
        assert_eq!(
            parse_run_options(&["--net".into()]).unwrap(),
            RunOptions {
                net: true,
                ..RunOptions::default()
            }
        );
        assert_eq!(
            parse_run_options(&["--desktop".into(), "--framebuffer".into(), "--net".into()])
                .unwrap(),
            RunOptions {
                net: true,
                desktop: true,
                framebuffer: true,
                terminal: false,
            }
        );
        assert!(parse_run_options(&["--disk".into()]).is_err());
        assert!(parse_run_options(&["--framebuffer".into()]).is_err());
        let plain = launch_config(RunOptions::default(), PathBuf::from("DISK.img"), None);
        assert!(plain.extra_args.is_empty());
        assert_eq!(plain.display, None);
        assert_eq!(plain.machine_extra, None);
        let virtio = launch_config(
            RunOptions {
                desktop: true,
                ..RunOptions::default()
            },
            PathBuf::from("DISK.img"),
            None,
        );
        assert_eq!(virtio.machine_extra, Some("vmport=off"));
        assert_eq!(virtio.vga, None);
        let mut expected = desktop_qemu_args(false);
        expected.extend(virtio_input_qemu_args());
        assert_eq!(virtio.extra_args, expected);
        assert!(virtio
            .extra_args
            .windows(2)
            .any(|pair| pair == ["-device", "virtio-tablet-pci,id=cs-tablet"]));
        assert!(virtio
            .extra_args
            .windows(2)
            .any(|pair| pair == ["-vga", "none"]));
        assert!(virtio
            .extra_args
            .iter()
            .any(|arg| arg.starts_with("name=opt/ovmf/X-PciMmio64Mb")));
        let framebuffer = launch_config(
            RunOptions {
                desktop: true,
                framebuffer: true,
                ..RunOptions::default()
            },
            PathBuf::from("DISK.img"),
            None,
        );
        assert_eq!(framebuffer.vga, Some("std"));
        let mut expected = desktop_qemu_args(true);
        expected.extend(virtio_input_qemu_args());
        assert_eq!(framebuffer.extra_args, expected);
        assert!(parse_run_options(&["--terminal".into()]).is_err());
        let terminal = launch_config(
            parse_run_options(&["--desktop".into(), "--terminal".into()]).unwrap(),
            PathBuf::from("DISK.img"),
            None,
        );
        assert!(terminal
            .extra_args
            .iter()
            .any(|arg| arg == "name=opt/clean-slate/desktop,string=q1-terminal"));
    }

    #[test]
    fn the_system_vm_attaches_the_disk_and_rdrand_and_a_nic_only_with_a_port() {
        let disk = PathBuf::from("DISK.img");
        let without = system_vm_config(disk.clone(), None);
        assert_eq!(without.m5_data_disk.as_deref(), Some(disk.as_path()));
        assert_eq!(without.cpu_model, Some("qemu64,+rdrand,+smep,+smap,+umip"));
        assert_eq!(without.m7_fixture_port, None);
        assert!(!without.kernel_release);
        assert_eq!(system_vm_config(disk, Some(9)).m7_fixture_port, Some(9));
    }

    #[test]
    fn a_missing_data_disk_is_created_once_and_a_wrong_size_is_refused() {
        let dir = std::env::temp_dir().join(format!("cs-system-disk-{}", std::process::id()));
        let path = dir.join("d.img");
        let _ = fs::remove_dir_all(&dir);
        assert!(ensure_data_disk(&path).unwrap());
        assert!(!ensure_data_disk(&path).unwrap());
        assert_eq!(fs::metadata(&path).unwrap().len(), M5_DATA_DISK_SIZE_BYTES);
        fs::File::create(&path).unwrap().set_len(1).unwrap();
        assert!(ensure_data_disk(&path).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    /// A full-size disk image whose first two blocks are `header`.
    fn disk_with_header(path: &Path, header: &[u8]) {
        let mut image = vec![0u8; M5_DATA_DISK_SIZE_BYTES as usize];
        image[..header.len()].copy_from_slice(header);
        fs::write(path, image).unwrap();
    }

    /// A full-size disk image holding one committed object in this build's store format.
    fn current_format_disk(path: &Path) {
        disk_with_header(path, &[]);
        let disk = DiskImage::open_with(path, false).unwrap();
        let mut store = clean_slate_store::ObjectStore::format(disk).unwrap();
        store.write_object(1, "alpha", b"kept").unwrap();
        store.commit().unwrap();
    }

    #[test]
    fn a_reused_data_disk_must_be_blank_or_this_builds_store_format() {
        let dir = std::env::temp_dir().join(format!("cs-system-format-{}", std::process::id()));
        let path = dir.join("d.img");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        disk_with_header(&path, &[]);
        assert!(!ensure_data_disk(&path).unwrap(), "blank disk is reused");

        current_format_disk(&path);
        assert!(
            !ensure_data_disk(&path).unwrap(),
            "v{STORE_VERSION} disk is reused"
        );

        let mut header = vec![0u8; 2 * DATA_DISK_BLOCK_BYTES];
        fs::File::open(&path)
            .unwrap()
            .read_exact(&mut header)
            .unwrap();
        for slot in header.chunks_exact_mut(DATA_DISK_BLOCK_BYTES) {
            slot[4..6].copy_from_slice(&1u16.to_le_bytes());
        }
        disk_with_header(&path, &header);
        let error = ensure_data_disk(&path).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(": corrupt (both superblock slots invalid);"),
            "a version field whose checksum fails is corruption, not a stale disk: {error}"
        );

        for slot in header.chunks_exact_mut(DATA_DISK_BLOCK_BYTES) {
            let byte_sum = slot
                .iter()
                .enumerate()
                .filter(|(index, _)| !(8..12).contains(index))
                .fold(0u32, |sum, (_, byte)| sum.wrapping_add(u32::from(*byte)));
            slot[8..12].copy_from_slice(&byte_sum.to_le_bytes());
        }
        disk_with_header(&path, &header);
        let error = ensure_data_disk(&path).unwrap_err();
        assert!(matches!(
            error,
            XtaskError::StaleDataDisk {
                found: 1,
                expected: STORE_VERSION,
                ..
            }
        ));
        assert_eq!(
            error.to_string(),
            format!(
                "data disk {0} holds object-store format v1, but this build's storage service expects v{STORE_VERSION} and would refuse it; delete {0} to start from a blank disk",
                path.display()
            )
        );
        let _ = fs::remove_dir_all(&dir);
    }

    fn refused_transcript(pids: &[u64]) -> String {
        let mut text = String::new();
        for pid in pids {
            text += &format!("[SVC ] launch service=20736 pid={pid} gen=1\n");
            text += &format!("[PROC] fault pid={pid} vector=128 err=0x0\n{REFUSAL_LINE}\n");
        }
        text
    }

    #[test]
    fn a_refused_boot_needs_one_refusal_per_storage_exit_and_nothing_started() {
        assert_eq!(
            validate_refused_boot(&refused_transcript(&[5, 6, 7, 8])),
            Ok(4)
        );
        assert!(validate_refused_boot(&refused_transcript(&[5, 6, 7])).is_err());

        let text = refused_transcript(&[5, 6, 7, 8]);
        let unexplained = text.replacen(&format!("{REFUSAL_LINE}\n"), "", 1);
        assert!(validate_refused_boot(&unexplained).is_err());
        let formatted = format!("{text}[SVC ] ready service=20736 pid=8 gen=1\n");
        assert!(validate_refused_boot(&formatted).is_err());
        let started = format!("{text}[SVC ] launch service=20992 pid=9 gen=1\n");
        assert!(validate_refused_boot(&started).is_err());
    }

    #[test]
    fn a_reused_disk_with_a_torn_first_format_is_refused_as_interrupted_or_corrupt() {
        let dir = std::env::temp_dir().join(format!("cs-system-torn-{}", std::process::id()));
        let path = dir.join("d.img");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        current_format_disk(&path);
        let mut fresh = vec![0u8; DATA_DISK_BLOCK_BYTES];
        fs::File::open(&path)
            .unwrap()
            .read_exact(&mut fresh)
            .unwrap();
        let mut header = vec![0u8; 2 * DATA_DISK_BLOCK_BYTES];
        header[..20].copy_from_slice(&fresh[..20]);
        disk_with_header(&path, &header);
        let before = fs::read(&path).unwrap();

        let error = ensure_data_disk(&path).unwrap_err();
        assert!(matches!(
            error,
            XtaskError::InterruptedFormatDataDisk { .. }
        ));
        assert_eq!(
            error.to_string(),
            format!(
                "data disk {0} holds an interrupted first format, or is corrupt (its superblock slots hold only part of a fresh format); the storage service refuses it rather than reformat it, so delete {0} to start from a blank disk",
                path.display()
            )
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_reused_corrupt_data_disk_is_refused_and_left_unchanged() {
        let dir = std::env::temp_dir().join(format!("cs-system-corrupt-{}", std::process::id()));
        let path = dir.join("d.img");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        current_format_disk(&path);
        corrupt_both_superblocks(&path).unwrap();
        let before = fs::read(&path).unwrap();

        let error = ensure_data_disk(&path).unwrap_err();
        assert!(matches!(error, XtaskError::UnusableDataDisk { .. }));
        assert!(error
            .to_string()
            .contains(": corrupt (both superblock slots invalid);"));
        assert_eq!(fs::read(&path).unwrap(), before);
        let _ = fs::remove_dir_all(&dir);
    }
}
