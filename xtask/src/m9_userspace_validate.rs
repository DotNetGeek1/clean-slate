//! Host re-validation of the `test-m9-userspace` serial log (#108).
//!
//! The guest already fails closed on every check below; this validator re-derives them
//! from the log so the acceptance verdict does not rest on the guest's own `PASS` line:
//! exact matrix order/status/stdout bytes against `commands.toml`, reuse-cycle stdout
//! equality, conventional low-VA entry, authority-denial evidence, sleep-with-native-
//! progress evidence, resource return-to-baseline, and BusyBox integrity.

use crate::m9_fixture::{load_command_matrix, BUSYBOX_SHA256, ROOTFS_IMAGE_SHA256};
use std::collections::BTreeMap;

const LOW_VA_ENTRY_MIN: u64 = 0x40_0000;
const LOW_VA_ENTRY_END: u64 = 0x80_0000;

struct ProbeSpec {
    name: &'static str,
    net: bool,
    tmp: bool,
    status: u64,
}

/// Mirrors `PROBES` in `kernel/src/selftest/m9_userspace.rs`.
const PROBES: &[ProbeSpec] = &[
    ProbeSpec {
        name: "deny-fs-readonly",
        net: true,
        tmp: true,
        status: 1,
    },
    ProbeSpec {
        name: "deny-tmp-write",
        net: true,
        tmp: false,
        status: 1,
    },
    ProbeSpec {
        name: "deny-tmp-read",
        net: true,
        tmp: false,
        status: 1,
    },
    ProbeSpec {
        name: "deny-net",
        net: false,
        tmp: true,
        status: 1,
    },
    ProbeSpec {
        name: "connect-timeout",
        net: true,
        tmp: true,
        status: 1,
    },
];

/// Resource fields that must equal the baseline after every cycle.
const REUSABLE_RESOURCES: &[&str] = &[
    "linux_procs",
    "threads",
    "processes",
    "fd_tables",
    "open_files",
    "pipes",
    "linux_waiters",
    "sockets",
    "net_requests",
    "object_requests",
    "capabilities",
    "linux_mm",
    "linux_signals",
];
/// Persistent `/tmp` state created by cycle 1 and reused afterwards.
const PERSISTENT_RESOURCES: &[&str] = &["tmp_files", "fs_nodes"];

/// `[M9  ] ...` payload of a serial line (guest stdout may precede it on the same line).
fn m9_payload(line: &str) -> Option<&str> {
    line.find("[M9  ] ").map(|at| &line[at + "[M9  ] ".len()..])
}

fn field<'a>(payload: &'a str, key: &str) -> Option<&'a str> {
    payload
        .split(' ')
        .find_map(|token| token.strip_prefix(key)?.strip_prefix('='))
}

fn field_u64(payload: &str, key: &str) -> Result<u64, String> {
    let raw = field(payload, key).ok_or_else(|| format!("missing {key}= in `{payload}`"))?;
    let parsed = match raw.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => raw.parse(),
    };
    parsed.map_err(|_| format!("bad {key}={raw} in `{payload}`"))
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err(format!("odd-length stdout hex `{hex}`"));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| format!("bad hex `{hex}`")))
        .collect()
}

struct Launch {
    pid: u64,
    name: String,
    cycle: u64,
    /// Serial line index of the `shell started` line.
    line: usize,
}

pub fn validate_m9_userspace_serial(serial: &str) -> Result<(), String> {
    let matrix = load_command_matrix()?;
    let lines: Vec<&str> = serial.lines().collect();
    for line in &lines {
        if line.starts_with("[FAIL]") || line.starts_with("[EXC]") {
            return Err(format!("guest reported `{line}`"));
        }
    }

    let header = lines
        .iter()
        .filter_map(|l| m9_payload(l))
        .find(|p| p.starts_with("matrix "))
        .ok_or("missing `[M9  ] matrix` header")?;
    let cycles = field_u64(header, "cycles")?;
    if field_u64(header, "commands")? != matrix.commands.len() as u64 {
        return Err(format!(
            "guest matrix has {} commands, commands.toml has {}",
            field_u64(header, "commands")?,
            matrix.commands.len()
        ));
    }
    if field_u64(header, "probes")? != PROBES.len() as u64 {
        return Err("guest probe count differs from the validator".into());
    }
    if cycles < 2 {
        return Err(format!(
            "reuse evidence needs at least 2 cycles, guest ran {cycles}"
        ));
    }

    validate_integrity(&lines)?;
    let launches = collect_launches(&lines)?;
    validate_matrix(&lines, &matrix, cycles)?;
    validate_probes(&lines, &launches, cycles)?;
    validate_launch_sequence(&launches, &matrix, cycles)?;
    validate_sleep_evidence(&lines)?;
    validate_resources(&lines, cycles)?;
    Ok(())
}

fn validate_integrity(lines: &[&str]) -> Result<(), String> {
    let find = |prefix: &str| {
        lines
            .iter()
            .filter_map(|l| m9_payload(l))
            .find(|p| p.starts_with(prefix))
            .ok_or_else(|| format!("missing `[M9  ] {prefix}`"))
    };
    let verified = find("busybox verified ")?;
    let intact = find("busybox intact ")?;
    for payload in [verified, intact] {
        if field(payload, "pinned_sha256") != Some(BUSYBOX_SHA256) {
            return Err(format!("guest BusyBox pin differs: `{payload}`"));
        }
        if field(payload, "rootfs_sha256") != Some(ROOTFS_IMAGE_SHA256) {
            return Err(format!("guest rootfs pin differs: `{payload}`"));
        }
    }
    if field(verified, "crc32") != field(intact, "crc32")
        || field(verified, "bytes") != field(intact, "bytes")
    {
        return Err("embedded BusyBox bytes changed during the run".into());
    }
    Ok(())
}

fn collect_launches(lines: &[&str]) -> Result<Vec<Launch>, String> {
    let mut launches = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let Some(payload) = m9_payload(line).filter(|p| p.starts_with("shell started ")) else {
            continue;
        };
        let entry = field_u64(payload, "entry")?;
        if !(LOW_VA_ENTRY_MIN..LOW_VA_ENTRY_END).contains(&entry) {
            return Err(format!(
                "BusyBox entry {entry:#x} outside the low-VA window"
            ));
        }
        let name = field(payload, "cmd").ok_or("shell started without cmd=")?;
        let (net, tmp) = (field_u64(payload, "net")?, field_u64(payload, "tmp")?);
        let expected = PROBES
            .iter()
            .find(|p| p.name == name)
            .map(|p| (u64::from(p.net), u64::from(p.tmp)))
            .unwrap_or((1, 1));
        if (net, tmp) != expected {
            return Err(format!(
                "{name}: launched with net={net} tmp={tmp}, expected {expected:?}"
            ));
        }
        launches.push(Launch {
            pid: field_u64(payload, "pid")?,
            name: name.to_string(),
            cycle: field_u64(payload, "cycle")?,
            line: index,
        });
    }
    Ok(launches)
}

fn validate_launch_sequence(
    launches: &[Launch],
    matrix: &clean_slate_rootfs::commands::CommandMatrix,
    cycles: u64,
) -> Result<(), String> {
    let mut expected = Vec::new();
    for cycle in 1..=cycles {
        for spec in &matrix.commands {
            expected.push((spec.name.as_str(), cycle));
        }
        for probe in PROBES {
            expected.push((probe.name, cycle));
        }
    }
    let actual: Vec<(&str, u64)> = launches
        .iter()
        .map(|l| (l.name.as_str(), l.cycle))
        .collect();
    if actual != expected {
        return Err(format!(
            "launch sequence differs from matrix+probes x {cycles} cycles ({} launches, expected {})",
            actual.len(),
            expected.len()
        ));
    }
    Ok(())
}

fn validate_matrix(
    lines: &[&str],
    matrix: &clean_slate_rootfs::commands::CommandMatrix,
    cycles: u64,
) -> Result<(), String> {
    let mut hex: BTreeMap<String, Vec<(u64, Vec<u8>)>> = BTreeMap::new();
    let mut results: Vec<(String, u64, u64, u64, u64)> = Vec::new();
    for payload in lines.iter().filter_map(|l| m9_payload(l)) {
        if let Some(rest) = payload.strip_prefix("stdout ") {
            let name = field(rest, "cmd").ok_or("stdout line without cmd=")?;
            let off = field_u64(rest, "off")?;
            let bytes = decode_hex(field(rest, "hex").ok_or("stdout line without hex=")?)?;
            hex.entry(name.to_string()).or_default().push((off, bytes));
        } else if payload.starts_with("cmd=") {
            results.push((
                field(payload, "cmd").unwrap_or_default().to_string(),
                field_u64(payload, "cycle")?,
                field_u64(payload, "status")?,
                field_u64(payload, "stdout_len")?,
                field_u64(payload, "fnv")?,
            ));
        }
    }
    let expected_len = matrix.commands.len() * cycles as usize;
    if results.len() != expected_len {
        return Err(format!(
            "{} command results logged, expected {expected_len}",
            results.len()
        ));
    }
    let mut first_cycle: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for (index, (name, cycle, status, len, fnv)) in results.iter().enumerate() {
        let spec = &matrix.commands[index % matrix.commands.len()];
        let expected_cycle = (index / matrix.commands.len()) as u64 + 1;
        if name != &spec.name || *cycle != expected_cycle {
            return Err(format!(
                "result #{index} is {name}@{cycle}, expected {}@{expected_cycle}",
                spec.name
            ));
        }
        if *status != u64::from(spec.exit_status) {
            return Err(format!(
                "{name}@{cycle}: exit status {status}, commands.toml expects {}",
                spec.exit_status
            ));
        }
        if *cycle == 1 {
            let mut chunks = hex.remove(name.as_str()).unwrap_or_default();
            chunks.sort_by_key(|(off, _)| *off);
            let mut stdout = Vec::new();
            for (off, bytes) in chunks {
                if off != stdout.len() as u64 {
                    return Err(format!("{name}: stdout hex gap at offset {off}"));
                }
                stdout.extend_from_slice(&bytes);
            }
            if stdout.len() as u64 != *len || u64::from(fnv1a32(&stdout)) != *fnv {
                return Err(format!(
                    "{name}: stdout hex ({} bytes) does not match logged len={len} fnv={fnv:#x}",
                    stdout.len()
                ));
            }
            spec.check_stdout(&stdout)?;
            first_cycle.insert(spec.name.as_str(), (*len, *fnv));
        } else if first_cycle.get(spec.name.as_str()) != Some(&(*len, *fnv)) {
            return Err(format!("{name}@{cycle}: stdout differs from cycle 1"));
        }
    }
    if let Some(extra) = hex.keys().next() {
        return Err(format!("unexpected stdout hex for {extra}"));
    }
    Ok(())
}

fn validate_probes(lines: &[&str], launches: &[Launch], cycles: u64) -> Result<(), String> {
    let mut seen = 0usize;
    for (index, line) in lines.iter().enumerate() {
        let Some(payload) = m9_payload(line).filter(|p| p.starts_with("probe=")) else {
            continue;
        };
        let name = field(payload, "probe").unwrap_or_default();
        let cycle = field_u64(payload, "cycle")?;
        let spec = PROBES
            .get(seen % PROBES.len())
            .filter(|p| p.name == name)
            .ok_or_else(|| format!("probe #{seen} is {name}, out of order"))?;
        if cycle != (seen / PROBES.len()) as u64 + 1 {
            return Err(format!(
                "probe {name} logged for cycle {cycle} out of order"
            ));
        }
        seen += 1;
        if field_u64(payload, "status")? != spec.status {
            return Err(format!(
                "{name}@{cycle}: unexpected exit status in `{payload}`"
            ));
        }
        let launch = launches
            .iter()
            .rev()
            .find(|l| l.line < index && l.name == name && l.cycle == cycle)
            .ok_or_else(|| format!("{name}@{cycle}: no matching launch"))?;
        let window = &lines[launch.line..index];
        let pid = launch.pid;
        let has = |needle: &str| window.iter().any(|l| l.contains(needle));
        let read_denials = field_u64(payload, "object_read_denials")?;
        let write_denials = field_u64(payload, "object_write_denials")?;
        let net_denials = field_u64(payload, "network_denials")?;
        match name {
            "deny-fs-readonly" => {
                if !has("Read-only file system") || read_denials + write_denials + net_denials != 0
                {
                    return Err(format!(
                        "{name}@{cycle}: expected EROFS without a capability denial"
                    ));
                }
            }
            "deny-tmp-write" | "deny-tmp-read" => {
                let op = if name == "deny-tmp-write" {
                    "write"
                } else {
                    "read"
                };
                let denials = if op == "write" {
                    write_denials
                } else {
                    read_denials
                };
                let cap_line = format!("[CAP ] deny holder={pid} ");
                let denied = window.iter().any(|l| {
                    l.contains(&cap_line) && l.contains(&format!(" op={op} reason=no-authority"))
                });
                if denials == 0 || !denied {
                    return Err(format!(
                        "{name}@{cycle}: missing `[CAP ] deny ... op={op}` for pid {pid}"
                    ));
                }
                if has(&format!("[CAP ] object grant holder={pid} ")) {
                    return Err(format!(
                        "{name}@{cycle}: pid {pid} was granted /tmp authority"
                    ));
                }
                if !has("Permission denied") {
                    return Err(format!("{name}@{cycle}: BusyBox did not report EACCES"));
                }
            }
            "deny-net" => {
                if net_denials == 0 || !has(&format!("[NET ] denied pid={pid} reason=no-authority"))
                {
                    return Err(format!(
                        "{name}@{cycle}: missing network denial for pid {pid}"
                    ));
                }
                if has(&format!("[CAP ] net grant holder={pid} ")) {
                    return Err(format!(
                        "{name}@{cycle}: pid {pid} was granted network authority"
                    ));
                }
            }
            "connect-timeout" => {
                if !has("Operation timed out") {
                    return Err(format!(
                        "{name}@{cycle}: connect did not fail with ETIMEDOUT"
                    ));
                }
            }
            _ => unreachable!("probe names come from PROBES"),
        }
    }
    if seen != PROBES.len() * cycles as usize {
        return Err(format!(
            "{seen} probe results logged, expected {}",
            PROBES.len() * cycles as usize
        ));
    }
    Ok(())
}

fn validate_sleep_evidence(lines: &[&str]) -> Result<(), String> {
    let payloads: Vec<&str> = lines.iter().filter_map(|l| m9_payload(l)).collect();
    let blocking = payloads
        .iter()
        .find(|p| p.starts_with("blocking PASS "))
        .ok_or("missing `[M9  ] blocking PASS`")?;
    let timeout = payloads
        .iter()
        .find(|p| p.starts_with("timeout PASS "))
        .ok_or("missing `[M9  ] timeout PASS`")?;
    for proof in [blocking, timeout] {
        if field_u64(proof, "woken_with_native_progress")? == 0
            || field_u64(proof, "native_steps_while_blocked")? == 0
            || field_u64(proof, "max_blocked_ticks")? == 0
        {
            return Err(format!(
                "sleep proof lacks native progress while blocked: `{proof}`"
            ));
        }
    }
    for sleep in payloads.iter().filter(|p| p.starts_with("sleep ")) {
        let blocks = field_u64(sleep, "blocks")?;
        let resolved = field_u64(sleep, "woken")?
            + field_u64(sleep, "timeouts")?
            + field_u64(sleep, "cancelled")?;
        if resolved > blocks {
            return Err(format!("more wakeups than blocks: `{sleep}`"));
        }
    }
    Ok(())
}

fn validate_resources(lines: &[&str], cycles: u64) -> Result<(), String> {
    let snapshots: Vec<(&str, BTreeMap<&str, u64>)> = lines
        .iter()
        .filter_map(|l| m9_payload(l))
        .filter_map(|p| p.strip_prefix("resources "))
        .map(|p| {
            let label = field(p, "label").unwrap_or_default();
            let values = p
                .split(' ')
                .filter_map(|t| t.split_once('='))
                .filter(|(k, _)| *k != "label")
                .filter_map(|(k, v)| v.parse().ok().map(|v| (k, v)))
                .collect();
            (label, values)
        })
        .collect();
    let (label, baseline) = snapshots.first().ok_or("missing resource baseline")?;
    if *label != "baseline" {
        return Err("first resource snapshot is not the baseline".into());
    }
    let cycle_snapshots = &snapshots[1..];
    if cycle_snapshots.len() as u64 != cycles {
        return Err(format!(
            "{} cycle resource snapshots, expected {cycles}",
            cycle_snapshots.len()
        ));
    }
    let mut native_progress = baseline.get("native_progress").copied().unwrap_or(0);
    let first = &cycle_snapshots[0].1;
    for (index, (_, values)) in cycle_snapshots.iter().enumerate() {
        for key in REUSABLE_RESOURCES {
            if values.get(key) != baseline.get(key) || values.get(key).is_none() {
                return Err(format!(
                    "cycle {}: {key}={:?} differs from baseline {:?}",
                    index + 1,
                    values.get(key),
                    baseline.get(key)
                ));
            }
        }
        for key in PERSISTENT_RESOURCES {
            if values.get(key) != first.get(key) || values.get(key).is_none() {
                return Err(format!(
                    "cycle {}: persistent {key} changed after cycle 1",
                    index + 1
                ));
            }
        }
        let progress = values.get("native_progress").copied().unwrap_or(0);
        if progress <= native_progress {
            return Err(format!(
                "cycle {}: native progress stalled at {progress}",
                index + 1
            ));
        }
        native_progress = progress;
    }
    if first.get("tmp_files").copied().unwrap_or(0) == 0 {
        return Err("matrix left no persistent /tmp files (M5/M6 backing unused)".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_and_fields() {
        let line = "test[M9  ] cmd=pwd cycle=1 status=0 stdout_len=2 fnv=0x85d2393c";
        let payload = m9_payload(line).unwrap();
        assert_eq!(field(payload, "cmd"), Some("pwd"));
        assert_eq!(field_u64(payload, "fnv").unwrap(), 0x85d2_393c);
        assert_eq!(field_u64(payload, "stdout_len").unwrap(), 2);
        assert!(field_u64(payload, "missing").is_err());
    }

    #[test]
    fn fnv_matches_guest() {
        assert_eq!(fnv1a32(b""), 0x811c_9dc5);
        assert_eq!(fnv1a32(b"/\n"), 0x85d2_393c);
        assert_eq!(decode_hex("2f0a").unwrap(), b"/\n");
        assert!(decode_hex("2f0").is_err());
    }

    #[test]
    fn rejects_guest_failure_lines() {
        assert!(validate_m9_userspace_serial("[FAIL] boom\n").is_err());
    }
}
