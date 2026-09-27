//! Host re-validation of the `test-m9-userspace` serial log (#108).
//!
//! The guest already fails closed on every check below; this validator re-derives them
//! from the log so the acceptance verdict does not rest on the guest's own `PASS` line:
//! exact matrix order/status, every cycle's stdout bytes against `commands.toml` and
//! byte-for-byte against cycle 1, conventional low-VA entry, authority-denial evidence,
//! sleep-with-native-progress evidence, kernel and network-service resource
//! return-to-baseline, and BusyBox integrity.

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
    "tcp_prefetches",
    "udp_prefetches",
    "net_requests",
    "net_in_service",
    "net_holder_exits",
    "net_holders",
    "object_requests",
    "capabilities",
    "linux_mm",
    "linux_signals",
];
/// Persistent `/tmp` state created by cycle 1 and reused afterwards.
const PERSISTENT_RESOURCES: &[&str] = &["tmp_files", "fs_nodes"];
/// Network-service table rows (`[M9  ] net-service resources`) that must equal the
/// baseline after every cycle.
const NET_SERVICE_RESOURCES: &[&str] = &[
    "sessions",
    "session_pending",
    "tcp_conns",
    "tcp_maps",
    "udp_endpoints",
    "udp_maps",
    "udp_queued",
    "parked_connects",
    "parked_tcp_recvs",
    "parked_udp_recvs",
    "parked_resolves",
    "tls_jobs",
    "dns_queries",
    "heap_bytes",
];

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

/// Offset of the first byte where `actual` departs from `expected`.
fn first_difference(expected: &[u8], actual: &[u8]) -> Option<usize> {
    expected
        .iter()
        .zip(actual)
        .position(|(e, a)| e != a)
        .or((expected.len() != actual.len()).then(|| expected.len().min(actual.len())))
}

fn validate_matrix(
    lines: &[&str],
    matrix: &clean_slate_rootfs::commands::CommandMatrix,
    cycles: u64,
) -> Result<(), String> {
    // `(cmd, cycle)` -> `(offset, bytes)` hex chunks.
    type StdoutChunks = Vec<(u64, Vec<u8>)>;
    let mut hex: BTreeMap<(String, u64), StdoutChunks> = BTreeMap::new();
    let mut results: Vec<(String, u64, u64, u64)> = Vec::new();
    for payload in lines.iter().filter_map(|l| m9_payload(l)) {
        if let Some(rest) = payload.strip_prefix("stdout ") {
            let name = field(rest, "cmd").ok_or("stdout line without cmd=")?;
            let cycle = field_u64(rest, "cycle")?;
            let off = field_u64(rest, "off")?;
            let bytes = decode_hex(field(rest, "hex").ok_or("stdout line without hex=")?)?;
            hex.entry((name.to_string(), cycle))
                .or_default()
                .push((off, bytes));
        } else if payload.starts_with("cmd=") {
            results.push((
                field(payload, "cmd").unwrap_or_default().to_string(),
                field_u64(payload, "cycle")?,
                field_u64(payload, "status")?,
                field_u64(payload, "stdout_len")?,
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
    let mut first_cycle: BTreeMap<&str, Vec<u8>> = BTreeMap::new();
    for (index, (name, cycle, status, len)) in results.iter().enumerate() {
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
        let mut chunks = hex.remove(&(name.clone(), *cycle)).unwrap_or_default();
        chunks.sort_by_key(|(off, _)| *off);
        let mut stdout = Vec::new();
        for (off, bytes) in chunks {
            if off != stdout.len() as u64 {
                return Err(format!("{name}@{cycle}: stdout hex gap at offset {off}"));
            }
            stdout.extend_from_slice(&bytes);
        }
        if stdout.len() as u64 != *len {
            return Err(format!(
                "{name}@{cycle}: stdout hex ({} bytes) does not match logged stdout_len={len}",
                stdout.len()
            ));
        }
        spec.check_stdout(&stdout)
            .map_err(|err| format!("cycle {cycle}: {err}"))?;
        match first_cycle.get(spec.name.as_str()) {
            None if *cycle == 1 => {
                first_cycle.insert(spec.name.as_str(), stdout);
            }
            None => return Err(format!("{name}@{cycle}: no cycle-1 stdout to compare")),
            Some(first) => {
                if let Some(offset) = first_difference(first, &stdout) {
                    return Err(format!(
                        "{name}@{cycle}: stdout differs from cycle 1 at offset {offset} \
                         (cycle-1 {} bytes, cycle-{cycle} {} bytes)",
                        first.len(),
                        stdout.len()
                    ));
                }
            }
        }
    }
    if let Some((extra, cycle)) = hex.keys().next() {
        return Err(format!("unexpected stdout hex for {extra}@{cycle}"));
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

/// `key=value` counts of one resource snapshot line.
type Counts<'a> = BTreeMap<&'a str, u64>;
type Snapshot<'a> = (&'a str, Counts<'a>);

/// `label=baseline` followed by `label=cycle-1..=cycles` snapshots with `prefix`.
fn resource_snapshots<'a>(
    lines: &[&'a str],
    prefix: &str,
    cycles: u64,
) -> Result<(Counts<'a>, Vec<Counts<'a>>), String> {
    let snapshots: Vec<Snapshot<'a>> = lines
        .iter()
        .filter_map(|l| m9_payload(l))
        .filter_map(|p| p.strip_prefix(prefix))
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
    let mut snapshots = snapshots.into_iter();
    let (label, baseline) = snapshots
        .next()
        .ok_or_else(|| format!("missing `{prefix}` baseline"))?;
    if label != "baseline" {
        return Err(format!("first `{prefix}` snapshot is not the baseline"));
    }
    let mut per_cycle = Vec::new();
    for (index, (label, values)) in snapshots.enumerate() {
        let expected_label = format!("cycle-{}", index + 1);
        if label != expected_label {
            return Err(format!(
                "`{prefix}` snapshot {} labelled {label:?}, expected {expected_label:?}",
                index + 1
            ));
        }
        per_cycle.push(values);
    }
    if per_cycle.len() as u64 != cycles {
        return Err(format!(
            "{} cycle `{prefix}` snapshots, expected {cycles}",
            per_cycle.len()
        ));
    }
    Ok((baseline, per_cycle))
}

fn require_baseline(
    what: &str,
    keys: &[&str],
    baseline: &Counts<'_>,
    per_cycle: &[Counts<'_>],
) -> Result<(), String> {
    for key in keys {
        if !baseline.contains_key(key) {
            return Err(format!("{what} baseline lacks {key}="));
        }
    }
    for (index, values) in per_cycle.iter().enumerate() {
        for key in keys {
            if values.get(key) != baseline.get(key) {
                return Err(format!(
                    "cycle {}: {what} {key}={:?} differs from baseline {:?}",
                    index + 1,
                    values.get(key),
                    baseline.get(key)
                ));
            }
        }
    }
    Ok(())
}

fn validate_resources(lines: &[&str], cycles: u64) -> Result<(), String> {
    let (baseline, cycle_snapshots) = resource_snapshots(lines, "resources ", cycles)?;
    require_baseline("kernel", REUSABLE_RESOURCES, &baseline, &cycle_snapshots)?;
    validate_net_service_resources(lines, cycles)?;
    let mut native_progress = baseline.get("native_progress").copied().unwrap_or(0);
    let first = &cycle_snapshots[0];
    for (index, values) in cycle_snapshots.iter().enumerate() {
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

/// Every snapshot comes from a fresh network-service idle point (`idle_seq` strictly
/// increases), and every table row count is back at its baseline.
fn validate_net_service_resources(lines: &[&str], cycles: u64) -> Result<(), String> {
    let (baseline, per_cycle) = resource_snapshots(lines, "net-service resources ", cycles)?;
    require_baseline("net-service", NET_SERVICE_RESOURCES, &baseline, &per_cycle)?;
    let mut idle_seq = *baseline
        .get("idle_seq")
        .ok_or("net-service baseline lacks idle_seq=")?;
    for (index, values) in per_cycle.iter().enumerate() {
        let seq = values.get("idle_seq").copied().unwrap_or(0);
        if seq <= idle_seq {
            return Err(format!(
                "cycle {}: net-service idle_seq={seq} is not newer than {idle_seq}",
                index + 1
            ));
        }
        idle_seq = seq;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use clean_slate_rootfs::commands::CommandSpec;

    #[test]
    fn payload_and_fields() {
        let line = "test[M9  ] cmd=pwd cycle=1 status=0 stdout_len=2 off=0x10";
        let payload = m9_payload(line).unwrap();
        assert_eq!(field(payload, "cmd"), Some("pwd"));
        assert_eq!(field_u64(payload, "off").unwrap(), 0x10);
        assert_eq!(field_u64(payload, "stdout_len").unwrap(), 2);
        assert!(field_u64(payload, "missing").is_err());
    }

    #[test]
    fn hex_decoding() {
        assert_eq!(decode_hex("2f0a").unwrap(), b"/\n");
        assert!(decode_hex("2f0").is_err());
    }

    /// Stdout that satisfies `spec` and spans more than one 32-byte hex chunk when the
    /// spec leaves room for extra bytes.
    fn sample_stdout(spec: &CommandSpec) -> Vec<u8> {
        if let Some(exact) = &spec.stdout {
            return exact.clone();
        }
        let mut out = spec.stdout_prefix.clone().unwrap_or_default();
        for needle in &spec.stdout_contains {
            out.extend_from_slice(needle);
            out.push(b'\n');
        }
        out.extend_from_slice(b"cat\necho\nenv\ngrep\nls\nmkdir\nnslookup\n");
        out
    }

    /// Matrix result and stdout hex lines as the guest logs them, one entry per
    /// `(cycle, command)`.
    fn matrix_log(
        matrix: &clean_slate_rootfs::commands::CommandMatrix,
        cycles: u64,
        mut stdout_for: impl FnMut(u64, &CommandSpec) -> Vec<u8>,
    ) -> String {
        let mut log = String::new();
        for cycle in 1..=cycles {
            for spec in &matrix.commands {
                let out = stdout_for(cycle, spec);
                log.push_str(&format!(
                    "[M9  ] cmd={} cycle={cycle} status={} stdout_len={}\n",
                    spec.name,
                    spec.exit_status,
                    out.len()
                ));
                for (chunk_index, chunk) in out.chunks(32).enumerate() {
                    let hex: String = chunk.iter().map(|b| format!("{b:02x}")).collect();
                    log.push_str(&format!(
                        "[M9  ] stdout cmd={} cycle={cycle} off={} hex={hex}\n",
                        spec.name,
                        chunk_index * 32
                    ));
                }
            }
        }
        log
    }

    fn run_matrix(
        log: &str,
        matrix: &clean_slate_rootfs::commands::CommandMatrix,
        cycles: u64,
    ) -> Result<(), String> {
        let lines: Vec<&str> = log.lines().collect();
        validate_matrix(&lines, matrix, cycles)
    }

    #[test]
    fn matrix_accepts_identical_cycles() {
        let matrix = load_command_matrix().unwrap();
        let log = matrix_log(&matrix, 3, |_, spec| sample_stdout(spec));
        run_matrix(&log, &matrix, 3).unwrap();
    }

    #[test]
    fn matrix_rejects_one_changed_byte_in_a_later_cycle() {
        let matrix = load_command_matrix().unwrap();
        let target = matrix
            .commands
            .iter()
            .find(|spec| spec.stdout.is_none() && spec.stdout_prefix.is_some())
            .expect("a prefix-only command")
            .name
            .clone();
        for bad_cycle in 2..=3u64 {
            let log = matrix_log(&matrix, 3, |cycle, spec| {
                let mut out = sample_stdout(spec);
                if cycle == bad_cycle && spec.name == target {
                    let last = out.len() - 2;
                    out[last] ^= 0x01;
                }
                out
            });
            let err = run_matrix(&log, &matrix, 3).unwrap_err();
            let expected_offset =
                sample_stdout(matrix.commands.iter().find(|s| s.name == target).unwrap()).len() - 2;
            assert!(
                err.contains(&format!("{target}@{bad_cycle}"))
                    && err.contains(&format!("offset {expected_offset}")),
                "{err}"
            );
        }
    }

    #[test]
    fn matrix_rejects_a_later_cycle_without_stdout_hex() {
        let matrix = load_command_matrix().unwrap();
        let log = matrix_log(&matrix, 2, |_, spec| sample_stdout(spec));
        let dropped: String = log
            .lines()
            .filter(|l| !(l.contains("stdout cmd=pwd cycle=2 ")))
            .map(|l| format!("{l}\n"))
            .collect();
        let err = run_matrix(&dropped, &matrix, 2).unwrap_err();
        assert!(err.contains("pwd@2"), "{err}");
    }

    fn net_service_line(label: &str, idle_seq: u64, overrides: &[(&str, u64)]) -> String {
        let mut line = format!("[M9  ] net-service resources label={label} idle_seq={idle_seq}");
        for key in NET_SERVICE_RESOURCES {
            let baseline = if *key == "heap_bytes" { 8192 } else { 0 };
            let value = overrides
                .iter()
                .find(|(k, _)| k == key)
                .map_or(baseline, |(_, v)| *v);
            line.push_str(&format!(" {key}={value}"));
        }
        line
    }

    fn net_service_log(cycles: u64, leak: Option<(u64, &str)>) -> String {
        let mut log = net_service_line("baseline", 1, &[]);
        log.push('\n');
        for cycle in 1..=cycles {
            let overrides: Vec<(&str, u64)> = leak
                .filter(|(at, _)| *at == cycle)
                .map(|(_, key)| (key, if key == "heap_bytes" { 8200 } else { 1 }))
                .into_iter()
                .collect();
            let label = format!("cycle-{cycle}");
            log.push_str(&net_service_line(&label, 1 + cycle * 7, &overrides));
            log.push('\n');
        }
        log
    }

    fn run_net_service(log: &str, cycles: u64) -> Result<(), String> {
        let lines: Vec<&str> = log.lines().collect();
        validate_net_service_resources(&lines, cycles)
    }

    #[test]
    fn net_service_rows_at_baseline_pass() {
        run_net_service(&net_service_log(3, None), 3).unwrap();
    }

    #[test]
    fn net_service_row_left_live_fails() {
        for key in NET_SERVICE_RESOURCES {
            for cycle in 1..=3 {
                let err = run_net_service(&net_service_log(3, Some((cycle, key))), 3).unwrap_err();
                assert!(
                    err.contains(&format!("cycle {cycle}: net-service {key}=")),
                    "{err}"
                );
            }
        }
    }

    #[test]
    fn net_service_snapshot_must_be_fresh_and_complete() {
        let stale = net_service_log(2, None).replace("idle_seq=15", "idle_seq=8");
        assert!(run_net_service(&stale, 2)
            .unwrap_err()
            .contains("idle_seq=8 is not newer"));
        let missing = net_service_log(2, None).replace(" tls_jobs=0", "");
        assert!(run_net_service(&missing, 2).is_err());
        let short = net_service_log(1, None);
        assert!(run_net_service(&short, 2).is_err());
    }

    #[test]
    fn rejects_guest_failure_lines() {
        assert!(validate_m9_userspace_serial("[FAIL] boom\n").is_err());
    }
}
