//! The default image (#218 S3b): `cargo xtask run` and the `test-system-boot` lane.
//!
//! The default image is the kernel built with no feature: the kernel launches userspace init,
//! which starts storage and then network and waits. `run` always attaches the persistent data
//! disk `target/system-data.img` (created when missing) and starts the network fixture peer
//! only with `--net`. The lane boots the same image twice on a disk of its own: the first boot
//! formats it, the second mounts it.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::m7_fixture::{FixtureOptions, M7FixturePeer, WhichCert};
use crate::{
    run_driven_vm_acceptance, run_vm_inner_with_config, workspace_root, MarkerSet, NoDriver,
    VmLaunchConfig, XtaskError, M5_DATA_DISK_SIZE_BYTES,
};

const SYSTEM_DATA_DISK_FILENAME: &str = "system-data.img";
const CPU_MODEL: &str = "qemu64,+rdrand";
const STORAGE_SERVICE: u32 = 0x5100;
const NETWORK_SERVICE: u32 = 0x5200;
/// One boot to init idle, with the network service's DHCP exchange; the build is not counted.
const LANE_TIMEOUT: Duration = Duration::from_secs(180);

/// In serial order. Kernel lines (`[KERN]`, `[SVC ]`) are printed by the kernel; `[INIT]`
/// lines reach serial only through init's console capability, as `[IPC ] console pid=N: …`.
pub(crate) const MARKERS: [&str; 15] = [
    "[KERN] init launched pid=",
    "[KERN] init authority pid=",
    "[INIT] started pid=",
    "[INIT] SERVICE_READY from init refused: not a service",
    "[INIT] starting service=20736",
    "[SVC ] authority service=20736 ",
    "[SVC ] launch service=20736 ",
    "[SVC ] ready service=20736 ",
    "[INIT] service=20736 ready; starting service=20992",
    "[SVC ] authority service=20992 ",
    "[SVC ] launch service=20992 ",
    "[SVC ] ready service=20992 ",
    "[INIT] service=20992 ready gen=1",
    "[INIT] boot settled running=2 down=0; waiting, no deadline",
    "[KERN] idle thread halted 16 times in a row while init pid=",
];

pub(crate) fn system_data_disk_path() -> PathBuf {
    workspace_root()
        .join("target")
        .join(SYSTEM_DATA_DISK_FILENAME)
}

/// Creates a zeroed data disk at `path` when there is none. Returns whether it was created.
fn ensure_data_disk(path: &Path) -> Result<bool, XtaskError> {
    if path.is_file() {
        let actual = fs::metadata(path)?.len();
        if actual != M5_DATA_DISK_SIZE_BYTES {
            return Err(XtaskError::InvalidDiskSize {
                path: path.to_path_buf(),
                expected: M5_DATA_DISK_SIZE_BYTES,
                actual,
            });
        }
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::File::create(path)?.set_len(M5_DATA_DISK_SIZE_BYTES)?;
    Ok(true)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RunOptions {
    net: bool,
}

fn parse_run_options(args: &[OsString]) -> Result<RunOptions, XtaskError> {
    let mut options = RunOptions::default();
    for arg in args {
        if arg == OsStr::new("--net") {
            options.net = true;
            continue;
        }
        return Err(XtaskError::InvalidOption(
            arg.to_string_lossy().into_owned(),
        ));
    }
    Ok(options)
}

fn system_vm_config(data_disk: PathBuf, fixture_port: Option<u16>) -> VmLaunchConfig {
    VmLaunchConfig {
        m5_data_disk: Some(data_disk),
        m7_fixture_port: fixture_port,
        cpu_model: Some(CPU_MODEL),
        ..VmLaunchConfig::default()
    }
}

fn start_fixture_peer() -> Result<M7FixturePeer, XtaskError> {
    M7FixturePeer::start_with(FixtureOptions {
        tls_cert: WhichCert::Correct,
        dns_reply_delay: Duration::ZERO,
        m9_profile: false,
    })
    .map_err(XtaskError::Io)
}

/// `cargo xtask run [--net]` and `cargo xtask run-gdb[-entry]` (which take no options).
pub(crate) fn run(
    args: &[OsString],
    wait_for_gdb: bool,
    debug_entry: bool,
) -> Result<(), XtaskError> {
    let options = parse_run_options(args)?;
    let disk = system_data_disk_path();
    let created = ensure_data_disk(&disk)?;
    println!(
        "[XTSK] data disk {} ({})",
        disk.display(),
        if created { "created" } else { "persistent" }
    );
    let peer = if options.net {
        let peer = start_fixture_peer()?;
        println!("[XTSK] network fixture peer on 127.0.0.1:{}", peer.port());
        Some(peer)
    } else {
        println!("[XTSK] no network device (pass --net for the fixture peer)");
        None
    };
    let result = run_vm_inner_with_config(
        wait_for_gdb,
        debug_entry,
        &[],
        None,
        system_vm_config(disk, peer.as_ref().map(M7FixturePeer::port)),
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
    println!(
        "\n[SYS ] PASS boot 1 formatted the disk (storage pid={} block-writes={}), boot 2 mounted it (storage pid={}); every service held exactly its manifest grants and reported ready from its launched pid",
        first.storage_pid, first.storage_block_writes, second.storage_pid
    );
    Ok(())
}

fn boot_once(disk: &Path, formatted: Formatted) -> Result<BootSummary, XtaskError> {
    let peer = start_fixture_peer()?;
    let output = run_driven_vm_acceptance(
        &[],
        system_vm_config(disk.to_path_buf(), Some(peer.port())),
        MarkerSet::Ordered(&MARKERS),
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
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|token| token.strip_prefix(key)?.strip_prefix('='))
}

fn number(line: &str, key: &str) -> Result<u64, String> {
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
/// manifest grants and reported ready from the pid and generation the kernel launched; storage
/// formatted the disk (with block writes) or mounted it, as `formatted` expects.
fn validate_boot(output: &str, formatted: Formatted) -> Result<BootSummary, String> {
    let launched = only_line(output, "[KERN] init launched pid=")?;
    let init_pid = number(launched, "pid")?;
    let authority = only_line(output, "[KERN] init authority pid=")?;
    let expected_authority = format!(
        "[KERN] init authority pid={init_pid} lifecycle-control=1 console=1 block-device=0 object-service=0 network=0 other=0 expected-only-lifecycle-and-console=1"
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
    let started = only_line(output, &format!("{console_prefix}started pid="))?;
    if number(&started[console_prefix.len()..], "pid")? != init_pid {
        return Err(format!("init reports a different pid: {started:?}"));
    }

    let mut summary = None;
    for service in [STORAGE_SERVICE, NETWORK_SERVICE] {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn transcript(formatted: u8, writes: u64) -> String {
        format!(
            "[SVC ] declared service=20736\n\
             [SVC ] declared service=20992\n\
             [KERN] init launched pid=3 slot=0 declared-services=2\n\
             [KERN] init authority pid=3 lifecycle-control=1 console=1 block-device=0 object-service=0 network=0 other=0 expected-only-lifecycle-and-console=1\n\
             [IPC ] console pid=3: [INIT] started pid=3 services=2\n\
             [IPC ] console pid=3: [INIT] SERVICE_READY from init refused: not a service\n\
             [IPC ] console pid=3: [INIT] starting service=20736\n\
             [SVC ] authority service=20736 pid=4 lifecycle-control=0 console=0 block-device=1 object-service=1 network=0 other=0 matches-manifest=1\n\
             [SVC ] launch service=20736 pid=4 gen=1\n\
             [SVC ] ready service=20736 pid=4 gen=1 source=live-instance kernel-observed block-write-requests={writes} service-reported formatted={formatted} store-generation=1\n\
             [IPC ] console pid=3: [INIT] service=20736 ready; starting service=20992\n\
             [SVC ] authority service=20992 pid=5 lifecycle-control=0 console=0 block-device=0 object-service=0 network=1 other=0 matches-manifest=1\n\
             [SVC ] launch service=20992 pid=5 gen=1\n\
             [SVC ] ready service=20992 pid=5 gen=1 source=live-instance kernel-observed block-write-requests=0 raw-backend=virtio service-reported link-up=1\n\
             [IPC ] console pid=3: [INIT] service=20992 ready gen=1\n\
             [IPC ] console pid=3: [INIT] boot settled running=2 down=0; waiting, no deadline\n\
             [KERN] idle thread halted 16 times in a row while init pid=3 waited in LIFECYCLE_WAIT with no deadline\n"
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
        let text = transcript(1, 9);
        let mut from = 0;
        for marker in MARKERS {
            let at = text[from..]
                .find(marker)
                .unwrap_or_else(|| panic!("{marker:?} missing after byte {from}"));
            from += at + marker.len();
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
        let text =
            transcript(1, 9).replace("network=0 other=0 expected", "network=1 other=0 expected");
        assert!(validate_boot(&text, Formatted::Yes).is_err());
        let text = transcript(1, 9).replace(
            "network=1 other=0 matches-manifest=1",
            "network=1 other=0 matches-manifest=0",
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
    fn run_takes_only_net() {
        assert_eq!(parse_run_options(&[]).unwrap(), RunOptions { net: false });
        assert_eq!(
            parse_run_options(&["--net".into()]).unwrap(),
            RunOptions { net: true }
        );
        assert!(parse_run_options(&["--disk".into()]).is_err());
    }

    #[test]
    fn the_system_vm_attaches_the_disk_and_rdrand_and_a_nic_only_with_a_port() {
        let disk = PathBuf::from("DISK.img");
        let without = system_vm_config(disk.clone(), None);
        assert_eq!(without.m5_data_disk.as_deref(), Some(disk.as_path()));
        assert_eq!(without.cpu_model, Some("qemu64,+rdrand"));
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
}
