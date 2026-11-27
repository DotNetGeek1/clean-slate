//! `test-system` (#218 S7b): the network service faults under a live shell, and init restarts
//! it.
//!
//! This lane tests the **`system-test-hooks` build**: the default image plus the test hooks in
//! `kernel/src/service/system_test_hooks.rs`. Here Ctrl-\ on COM1 faults the live network
//! service with a real user-mode page fault. Everything from the fault on is the default image's
//! own code: the fault report, the Linux socket loss, the client capability revoke, init's
//! restart policy, the new instance's launch audit and the capability re-issue.
//!
//! Before that boot, three short headless boots of the same kernel pass
//! `-fw_cfg name=opt/clean-slate/desktop,string=q1-bare` ([`crate::system_desktop`]): one with a
//! VirtIO-GPU, where init launches the compositor, desktop shell and app rows next to the base
//! rows; one with no display, which boots base; and one with only the `-vga std` framebuffer,
//! which runs the desktop at Q0. The shell boot passes no entry and requires `profile=base` and
//! no desktop row.
//!
//! The shell boot is `test-system-shell`'s: a fresh lane-owned data disk, the network fixture
//! peer and COM1 on a loopback socket. Each [`Step`] is typed once the step before it is complete:
//!
//! 1. The audit flood (#219): [`AUDIT_FLOOD_DENIALS`] Ctrl-A then Ctrl-B, and the audit service
//!    must print what the ring's per-holder budget kept and exactly how much it lost
//!    ([`check_audit_flood`]).
//! 2. `nslookup` and `wget` from the shell reach the fixture through network generation 1.
//! 3. A foreground `wget` to the fixture's hold port, which accepts and never answers, leaves
//!    the shell's child blocked in a TCP read.
//! 4. Ctrl-\ faults the network service. The blocked read must fail with the reset error and
//!    the shell must still prompt; init restarts the service once; generation 2 passes its
//!    launch audit, the shell's client capability is re-issued for it, and init settles again.
//! 5. `nslookup` and `wget` from the same shell work again, through generation 2.
//! 6. Ctrl-X faults the console service (#310); init restarts it, and the shell's console
//!    client capability is re-issued for generation 2's port ([`check_console_fault`]).
//! 7. A typed `echo` reaches the same shell through console generation 2, which says so.
//!
//! Each `wget` step proves a full exchange both ways: the fixture answers port 4001 only after
//! receiving the complete request, and the step requires it to have answered exactly one
//! request while the step ran and to have refused none (#255). The hold port reads the blocked
//! reader's request and reports its arrival, but never answers; the held step requires both
//! the held connection and that request. A connection the fixture refuses for lack of a
//! complete request fails the lane at once.
//!
//! TLS is not exercised here: this BusyBox has no TLS, and TLS stays covered by the M7 lanes.

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::process::Stdio;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::guest_reboot::GuestRebootDetector;
use crate::m7_fixture::{FixtureCounts, M7FixturePeer};
use crate::marker_spec::{first_guest_failure, first_guest_failure_in_bytes};
use crate::serial_input_lane::{accept_serial, find, spawn_serial_reader, tail, SerialEvent};
use crate::system_boot::{
    ensure_data_disk, field, number, start_shell_fixture_peer, system_vm_config, AUDIT_SERVICE,
    SYSTEM_DATA_DISK_FILENAME,
};
use crate::system_shell::{
    check_boot, check_lines, kernel_lines, lines, only_kernel_line, prompt_after, qemu_state,
    whole_lines_at, Shell, SHELL_SERVICE,
};
use crate::{
    announce_qemu_version, prepare_vm, workspace_root, xtask_artifact_root, ReapOnDrop,
    VmLaunchConfig, XtaskError,
};

/// The kernel feature this lane builds; nothing else enables it.
const HOOKS_FEATURE: &str = "system-test-hooks";
const NETWORK_SERVICE: u32 = 0x5200;
const CONSOLE_SERVICE: u32 = 0x5600;
/// The console service's line, once per instance, when typed input first answers a read.
const SERIAL_INPUT_SERVED: &str = "[CONS] serial input answered a read";
/// Boot to the first prompt plus every step, the restart's backoff included; the kernel build
/// before it is not counted.
const LANE_TIMEOUT: Duration = Duration::from_secs(300);
const STEP_TIMEOUT: Duration = Duration::from_secs(60);
/// How long the held connection must stay unanswered, with no prompt, before the fault: the
/// reader is then parked in its read, not still on its way to it.
const HOLD_SETTLE: Duration = Duration::from_secs(1);
/// How long the booted system must stay settled before the flood: several of the audit service's
/// one-second polls of an idle log, which must leave the log holding one record of its reads.
const READER_POLLS_SETTLE: Duration = Duration::from_secs(3);
/// BusyBox `wget` when the response read fails with `ECONNRESET`.
const RESET_ERROR: &str = "wget: error getting response: Connection reset by peer";
const HOOKS_BANNER: &str =
    "[HOOK] system-test-hooks build: Ctrl-\\ on COM1 faults the network service";
const SETTLED: &str = "[INIT] boot settled running=5 down=0; waiting, no deadline";
/// How many denials the flood step asks for: well past the budget, so most are lost.
const AUDIT_FLOOD_DENIALS: u64 = 100;
/// `clean_slate_capability::AUDIT_HOLDER_BUDGET`, the records one holder keeps in the audit
/// ring, stated here rather than taken from the code under test.
const AUDIT_HOLDER_BUDGET: u64 = 16;
const _: () = assert!(AUDIT_FLOOD_DENIALS > AUDIT_HOLDER_BUDGET);
/// One Ctrl-A per denial, then Ctrl-B to commit them.
const AUDIT_FLOOD_SEND: [u8; AUDIT_FLOOD_DENIALS as usize + 1] = {
    let mut bytes = [0x01; AUDIT_FLOOD_DENIALS as usize + 1];
    bytes[AUDIT_FLOOD_DENIALS as usize] = 0x02;
    bytes
};
/// What a step must produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Expect {
    /// These whole lines, in order and adjacent, then a prompt, with the fixture peer having
    /// sent at least `fixture_a_answers` A records meanwhile, and answered exactly
    /// `http_responses` received HTTP requests and refused none.
    Network {
        lines: &'static [&'static str],
        fixture_a_answers: u32,
        http_responses: u32,
    },
    /// The fixture peer holds the reader's connection unanswered, has received its request,
    /// and the shell has printed no prompt.
    Held,
    /// The fault, the woken reader, the restart and generation 2 (see [`check_fault`]).
    Fault,
    /// The flood and the audit service's report of it (see [`check_audit_flood`]).
    AuditFlood,
    /// The console service's fault, its restart, and the shell's client capability moved to
    /// the new instance (see [`check_console_fault`]).
    ConsoleFault,
    /// These whole lines and a prompt, the typed line having reached the shell through the
    /// restarted console service, which says so.
    ConsoleInput(&'static [&'static str]),
}

#[derive(Clone, Copy, Debug)]
struct Step {
    name: &'static str,
    send: &'static [u8],
    expect: Expect,
}

const NSLOOKUP: Step = Step {
    name: "nslookup",
    send: b"nslookup m7.fixture.test\r",
    expect: Expect::Network {
        lines: &["Name:      m7.fixture.test", "Address 1: 10.77.0.50"],
        fixture_a_answers: 1,
        http_responses: 0,
    },
};
const WGET: Step = Step {
    name: "wget",
    send: b"wget -q -O - http://m7.fixture.test:4001/\r",
    expect: Expect::Network {
        lines: &["M9-FIXTURE-HTTP"],
        fixture_a_answers: 1,
        http_responses: 1,
    },
};

const STEPS: [Step; 9] = [
    Step {
        name: "audit flood",
        send: &AUDIT_FLOOD_SEND,
        expect: Expect::AuditFlood,
    },
    NSLOOKUP,
    WGET,
    Step {
        name: "blocked reader",
        send: b"wget -q -O - http://m7.fixture.test:4003/\r",
        expect: Expect::Held,
    },
    Step {
        name: "fault",
        send: b"\x1c",
        expect: Expect::Fault,
    },
    Step {
        name: "nslookup after restart",
        ..NSLOOKUP
    },
    Step {
        name: "wget after restart",
        ..WGET
    },
    Step {
        name: "console fault",
        send: b"\x18",
        expect: Expect::ConsoleFault,
    },
    Step {
        name: "echo after console restart",
        send: b"echo hel''lo-again\r",
        expect: Expect::ConsoleInput(&["hello-again"]),
    },
];

/// The live network service instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Network {
    pid: u64,
    generation: u64,
}

/// What the lane knows between steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct State {
    init_pid: u64,
    shell: Shell,
    network: Network,
    audit_pid: u64,
    /// The console service instance the console fault step restarted, once it has.
    console: Option<Network>,
}

/// The kernel's launch audit for a network instance must be exactly the row's grants.
fn expected_network_authority(pid: u64) -> String {
    format!(
        "[SVC ] authority service={NETWORK_SERVICE} pid={pid} lifecycle-control=0 console=0 block-device=0 object-service=0 network=1 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 audit-read=0 con-serve=0 con-device=0 con-client=0 launch-serve=0 launch-client=0 other=0 revoked=0 allowance=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=1 linux=0 console-input=0 matches-manifest=1"
    )
}

/// One network instance came up in `segment`: launch, launch audit, the kernel's ready report
/// from that pid and generation, and init's announcement. Returns it with the offset just past
/// init's announcement.
fn check_network_instance(
    segment: &str,
    generation: u64,
    init_pid: u64,
) -> Result<(Network, usize), String> {
    let launch_prefix = format!("[SVC ] launch service={NETWORK_SERVICE} ");
    let launch = only_kernel_line(segment, &launch_prefix)
        .map_err(|reason| format!("network generation {generation}: {reason}"))?;
    let pid = number(launch, "pid")?;
    if number(launch, "gen")? != generation {
        return Err(format!("expected network gen={generation}: {launch:?}"));
    }
    let authority = only_kernel_line(
        segment,
        &format!("[SVC ] authority service={NETWORK_SERVICE} "),
    )?;
    if authority != expected_network_authority(pid) {
        return Err(format!(
            "network generation {generation} launch audit {authority:?}"
        ));
    }
    let ready = only_kernel_line(segment, &format!("[SVC ] ready service={NETWORK_SERVICE} "))
        .map_err(|reason| format!("network generation {generation}: {reason}"))?;
    if number(ready, "pid")? != pid
        || number(ready, "gen")? != generation
        || field(ready, "source") != Some("live-instance")
    {
        return Err(format!(
            "network launched as pid={pid} gen={generation} but ready says {ready:?}"
        ));
    }
    let announced = format!(
        "[IPC ] console pid={init_pid}: [INIT] service={NETWORK_SERVICE} ready gen={generation}"
    );
    let announced_at = segment
        .find(&announced)
        .ok_or_else(|| format!("init did not announce {announced:?}"))?;
    Ok((Network { pid, generation }, announced_at + announced.len()))
}

/// The boot: the hooks build's banner, network generation 1, the first shell, the audit service
/// and init settled with all five services running.
fn check_boot_segment(segment: &str) -> Result<State, String> {
    if !lines(segment).any(|line| line.contains(HOOKS_BANNER)) {
        return Err(format!("no {HOOKS_BANNER:?}: this is not the hooks build"));
    }
    let (init_pid, shell) = check_boot(segment)?;
    let (network, _) = check_network_instance(segment, 1, init_pid)?;
    let audit = only_kernel_line(segment, &format!("[SVC ] launch service={AUDIT_SERVICE} "))?;
    if !lines(segment).any(|line| line.contains(SETTLED)) {
        return Err(format!("init has not printed {SETTLED:?}"));
    }
    Ok(State {
        init_pid,
        shell,
        network,
        audit_pid: number(audit, "pid")?,
        console: None,
    })
}

/// The flood, in `segment` (the output since it was typed). The kernel's hook line must show it
/// denied init once (the witness) and then the shell once per Ctrl-A the host typed, in
/// contiguous sequences, with none allowed and the shell's holder keeping only the budget.
/// Then the audit service, from its own reads, must print the witness, one lost run of exactly
/// the denials the budget evicted, and each kept denial, each once and nothing else for those
/// sequences, before a summary that reaches the last of them. The counts it must match come
/// from the host: how many bytes it typed and the budget.
fn check_audit_flood(segment: &str, state: State) -> Result<State, String> {
    let hook = only_kernel_line(segment, "[HOOK] audit flood ")?;
    let witness = number(hook, "witness-seq")?;
    let first = number(hook, "first-seq")?;
    let next = number(hook, "next-seq")?;
    if number(hook, "witness-holder")? != state.init_pid
        || number(hook, "holder")? != state.shell.pid
        || number(hook, "denials")? != AUDIT_FLOOD_DENIALS
        || first != witness + 1
        || next != first + AUDIT_FLOOD_DENIALS
        || number(hook, "allowed")? != 0
        || number(hook, "held")? != AUDIT_HOLDER_BUDGET
    {
        return Err(format!(
            "expected init pid={} denied once, then the shell pid={} denied {AUDIT_FLOOD_DENIALS} times in the next sequences and keeping {AUDIT_HOLDER_BUDGET}: {hook:?}",
            state.init_pid, state.shell.pid
        ));
    }
    // More than one means polls store records; none, that reads went unrecorded, unless a full
    // log aged the record out before the next poll.
    let reader_reads = number(hook, "reader-reads")?;
    let may_be_aged_out = number(hook, "aged-out")? > 0;
    if number(hook, "reader")? != state.audit_pid
        || !(reader_reads == 1 || (reader_reads == 0 && may_be_aged_out))
    {
        return Err(format!(
            "expected the log to hold exactly one record of the audit service pid={}'s reads (or none, once a full log aged records out): {hook:?}",
            state.audit_pid
        ));
    }
    let after = &segment[line_at(segment, hook)?..];
    let prefix = format!("[IPC ] console pid={}: [ADT ] ", state.audit_pid);
    let reported: Vec<&str> = kernel_lines(after, &prefix)
        .map(|line| &line[prefix.len()..])
        .collect();
    let last = next - 1;
    let summary = reported
        .iter()
        .position(|line| {
            line.starts_with("drained ") && number(line, "through").is_ok_and(|seq| seq >= last)
        })
        .ok_or_else(|| {
            format!(
                "waiting for the audit service pid={} to drain through seq={last}",
                state.audit_pid
            )
        })?;
    let reported = &reported[..summary];

    let lost_run = format!(
        "lost first={first} missing={}",
        AUDIT_FLOOD_DENIALS - AUDIT_HOLDER_BUDGET
    );
    let mut want = vec![
        format!("#{witness} {} noright audit", state.init_pid),
        lost_run.clone(),
    ];
    want.extend(
        (next - AUDIT_HOLDER_BUDGET..next)
            .map(|seq| format!("#{seq} {} noright audit", state.shell.pid)),
    );
    for line in &want {
        let count = reported.iter().filter(|got| *got == line).count();
        if count != 1 {
            return Err(format!(
                "the audit service printed \"[ADT ] {line}\" {count} times, expected once"
            ));
        }
    }
    let flood = witness..next;
    for line in reported {
        let about_flood = if let Some(rest) = line.strip_prefix('#') {
            let seq = rest.split(' ').next().and_then(|seq| seq.parse().ok());
            seq.is_some_and(|seq| flood.contains(&seq))
        } else if line.starts_with("lost ") {
            let (start, missing) = (number(line, "first")?, number(line, "missing")?);
            start < flood.end && flood.start < start + missing
        } else {
            false
        };
        if about_flood && !want.iter().any(|wanted| wanted == line) {
            return Err(format!(
                "the audit service printed \"[ADT ] {line}\" for the flood's sequences {}..={last}",
                flood.start
            ));
        }
    }
    Ok(state)
}

/// Offset of the first line containing `needle` in `segment`.
fn line_at(segment: &str, needle: &str) -> Result<usize, String> {
    segment
        .find(needle)
        .ok_or_else(|| format!("no line containing {needle:?}"))
}

/// The `[TAG ] ... count=N reason=instance-gone` report, with `N >= 1`.
fn check_loss_report(segment: &str, prefix: &str) -> Result<usize, String> {
    let line = only_kernel_line(segment, prefix)?;
    if number(line, "count")? == 0 || field(line, "reason") != Some("instance-gone") {
        return Err(format!("unexpected {line:?}"));
    }
    line_at(segment, line)
}

/// Everything Ctrl-\ must cause, in `segment` (the output since it was typed), checked in the
/// order it happens so the first missing piece is what a failure names.
fn check_fault(segment: &str, state: State) -> Result<State, String> {
    let State {
        init_pid,
        shell,
        network,
        ..
    } = state;
    let armed = format!(
        "[HOOK] network fault armed pid={} gen={} user_rip=0x0 parked-in=native",
        network.pid, network.generation
    );
    let line = only_kernel_line(segment, "[HOOK] network fault armed ")?;
    // The trailing ` at-ms=` stamp is for the desktop lane's timing report.
    if line.split(" at-ms=").next() != Some(armed.as_str()) {
        return Err(format!("expected {armed:?}"));
    }
    let fault_prefix = format!("[PROC] fault pid={} vector=14 ", network.pid);
    let faulted_at = line_at(segment, &fault_prefix)
        .map_err(|_| format!("the network service did not fault: no {fault_prefix:?}"))?;
    let lost_at = check_loss_report(segment, "[NET ] linux sockets lost ")?;
    check_loss_report(segment, "[CAP ] net client revoked ")?;
    if lost_at < faulted_at {
        return Err("linux sockets were reported lost before the fault".to_owned());
    }

    let reset_end = whole_lines_at(segment, &[RESET_ERROR]).ok_or_else(|| {
        format!("the blocked reader was not woken with the reset error {RESET_ERROR:?}")
    })?;
    if reset_end < lost_at {
        return Err("the reset error came before the sockets were lost".to_owned());
    }
    prompt_after(segment, reset_end)
        .ok_or_else(|| "the shell printed no prompt after the reset error".to_owned())?;
    if lines(segment).any(|line| line.contains(&format!("[LNX ] exit pid={} ", shell.pid))) {
        return Err(format!("the shell pid={} exited", shell.pid));
    }
    if kernel_lines(segment, &format!("[SVC ] launch service={SHELL_SERVICE} ")).count() != 0 {
        return Err("a new shell was launched".to_owned());
    }

    let after_fault = &segment[faulted_at..];
    let restart = format!(
        "[IPC ] console pid={init_pid}: [SUP ] restart service={NETWORK_SERVICE} attempt=1"
    );
    if !lines(after_fault).any(|line| line.contains(&restart)) {
        return Err(format!(
            "waiting for network generation 2: init has not restarted it ({restart:?})"
        ));
    }
    let reaped = format!(
        "[SVC ] reaped service={NETWORK_SERVICE} pid={} ",
        network.pid
    );
    match crate::system_desktop::whole_line(after_fault, &reaped) {
        Some((_, "residue=0")) => {}
        Some((_, residue)) => {
            return Err(format!("network pid={} reaped with {residue}", network.pid));
        }
        None => {
            return Err(format!(
                "the faulted network service was not reaped: no {reaped:?}"
            ))
        }
    }
    let (next, announced_end) =
        check_network_instance(after_fault, network.generation + 1, init_pid)
            .map_err(|reason| format!("waiting for network generation 2: {reason}"))?;
    if next.pid == network.pid {
        return Err(format!("network generation 2 reuses pid={}", network.pid));
    }
    let reissued = format!(
        "[CAP ] net client reissued holder={} generation={}",
        shell.pid, next.generation
    );
    if !lines(after_fault).any(|line| line.contains(&reissued)) {
        return Err(format!("no {reissued:?}"));
    }
    if !lines(&after_fault[announced_end..]).any(|line| line.contains(SETTLED)) {
        return Err(format!(
            "init has not printed {SETTLED:?} since generation 2 became ready"
        ));
    }
    Ok(State {
        network: next,
        ..state
    })
}

/// Everything Ctrl-X must cause, in `segment` (the output since it was typed): the console
/// service faults and is reaped, init restarts it once, generation 2 is granted its port and
/// the serial device, the shell's console client capability is re-issued for that port, the
/// new instance reports ready and init settles, all under the same shell.
fn check_console_fault(segment: &str, state: State) -> Result<State, String> {
    let State {
        init_pid, shell, ..
    } = state;
    let armed = only_kernel_line(segment, "[HOOK] console fault armed ")?;
    let old = number(armed, "pid")?;
    if number(armed, "gen")? != 1 || field(armed, "user_rip") != Some("0x0") {
        return Err(format!("unexpected {armed:?}"));
    }
    let fault_prefix = format!("[PROC] fault pid={old} vector=14 ");
    let faulted_at = line_at(segment, &fault_prefix)
        .map_err(|_| format!("the console service did not fault: no {fault_prefix:?}"))?;
    let after_fault = &segment[faulted_at..];
    let restart = format!(
        "[IPC ] console pid={init_pid}: [SUP ] restart service={CONSOLE_SERVICE} attempt=1"
    );
    if !lines(after_fault).any(|line| line.contains(&restart)) {
        return Err(format!(
            "init has not restarted the console service ({restart:?})"
        ));
    }
    let reaped = format!("[SVC ] reaped service={CONSOLE_SERVICE} pid={old} ");
    match crate::system_desktop::whole_line(after_fault, &reaped) {
        Some((_, "residue=0")) => {}
        Some((_, residue)) => return Err(format!("console pid={old} reaped with {residue}")),
        None => {
            return Err(format!(
                "the faulted console service was not reaped: no {reaped:?}"
            ))
        }
    }
    let launch = only_kernel_line(
        after_fault,
        &format!("[SVC ] launch service={CONSOLE_SERVICE} "),
    )
    .map_err(|reason| format!("console generation 2: {reason}"))?;
    let pid = number(launch, "pid")?;
    if number(launch, "gen")? != 2 || pid == old {
        return Err(format!("expected a new console pid at gen=2: {launch:?}"));
    }
    // The port is named by the new process's instance generation, which the grant line gives.
    let granted_prefix = format!("[CONS] authority granted pid={pid} port={CONSOLE_SERVICE}:");
    let granted = only_kernel_line(after_fault, &granted_prefix)?;
    let port_generation = granted[granted_prefix.len()..]
        .split(' ')
        .next()
        .unwrap_or_default();
    if granted[granted_prefix.len() + port_generation.len()..]
        != *" rights=serve registered=1 device=read|write"
    {
        return Err(format!("unexpected {granted:?}"));
    }
    let granted_at = line_at(after_fault, granted)?;
    let reissued = format!(
        "[CONS] client reissued holder={} port={CONSOLE_SERVICE}:{port_generation}",
        shell.pid
    );
    let reissued_at = line_at(after_fault, &reissued).map_err(|_| format!("no {reissued:?}"))?;
    if reissued_at < granted_at {
        return Err("the shell's console client was reissued before the new port".to_owned());
    }
    let ready = only_kernel_line(
        after_fault,
        &format!("[SVC ] ready service={CONSOLE_SERVICE} "),
    )
    .map_err(|reason| format!("console generation 2: {reason}"))?;
    if number(ready, "pid")? != pid
        || number(ready, "gen")? != 2
        || field(ready, "source") != Some("live-instance")
    {
        return Err(format!(
            "console launched as pid={pid} gen=2 but ready says {ready:?}"
        ));
    }
    let announced =
        format!("[IPC ] console pid={init_pid}: [INIT] service={CONSOLE_SERVICE} ready gen=2");
    let announced_at = after_fault
        .find(&announced)
        .ok_or_else(|| format!("init did not announce {announced:?}"))?;
    if !lines(&after_fault[announced_at..]).any(|line| line.contains(SETTLED)) {
        return Err(format!(
            "init has not printed {SETTLED:?} since console generation 2 became ready"
        ));
    }
    if lines(segment).any(|line| line.contains(&format!("[LNX ] exit pid={} ", shell.pid))) {
        return Err(format!("the shell pid={} exited", shell.pid));
    }
    if kernel_lines(segment, &format!("[SVC ] launch service={SHELL_SERVICE} ")).count() != 0 {
        return Err("a new shell was launched".to_owned());
    }
    Ok(State {
        console: Some(Network { pid, generation: 2 }),
        ..state
    })
}

/// The typed line's output and a prompt, and the restarted console service's report that typed
/// input answered a read: input reached the shell through the new instance.
fn check_console_input(segment: &str, want: &[&str], state: State) -> Result<State, String> {
    let console = state
        .console
        .ok_or_else(|| "no restarted console service".to_owned())?;
    check_lines(segment, want)?;
    let served = format!("[IPC ] console pid={}: {SERIAL_INPUT_SERVED}", console.pid);
    if !lines(segment).any(|line| line.contains(&served)) {
        return Err(format!("no {served:?}"));
    }
    Ok(state)
}

/// Whether `step` has completed within `segment` (the output since it was typed), the fixture
/// peer having gone from `before` to `now` meanwhile.
fn check_step(
    step: &Step,
    segment: &str,
    before: FixtureCounts,
    now: FixtureCounts,
    state: State,
) -> Result<State, String> {
    match step.expect {
        Expect::Network {
            lines: want,
            fixture_a_answers,
            http_responses,
        } => {
            check_lines(segment, want)?;
            let answers = now
                .fixture_a_answers
                .saturating_sub(before.fixture_a_answers);
            let responses = now.http_responses.saturating_sub(before.http_responses);
            let refused = now.http_refused.saturating_sub(before.http_refused);
            if answers < fixture_a_answers || responses != http_responses || refused != 0 {
                return Err(format!(
                    "the fixture peer sent {answers} A answers, answered {responses} received HTTP requests and refused {refused} while the step ran, not {fixture_a_answers}, {http_responses} and 0"
                ));
            }
            Ok(state)
        }
        Expect::Held => {
            if now.held_connections <= before.held_connections {
                return Err("the fixture peer holds no connection from the reader".to_owned());
            }
            if now.held_requests <= before.held_requests {
                return Err(
                    "the fixture peer has not received the reader's request on the hold port"
                        .to_owned(),
                );
            }
            if prompt_after(segment, 0).is_some() {
                return Err("the shell prompted: the reader is not blocked".to_owned());
            }
            Ok(state)
        }
        Expect::Fault => check_fault(segment, state),
        Expect::AuditFlood => check_audit_flood(segment, state),
        Expect::ConsoleFault => check_console_fault(segment, state),
        Expect::ConsoleInput(want) => check_console_input(segment, want, state),
    }
}

/// Whole-run checks once every step has passed.
fn check_whole(transcript: &str) -> Result<(), String> {
    if let Some(failure) = first_guest_failure(transcript, true) {
        return Err(format!("guest failure {failure:?}"));
    }
    for forbidden in ["[INIT] gave up", "[INIT] not starting"] {
        if let Some(line) = lines(transcript).find(|line| line.contains(forbidden)) {
            return Err(format!("{forbidden:?} in {line:?}"));
        }
    }
    for (prefix, want) in [
        (format!("[SVC ] launch service={SHELL_SERVICE} "), 1),
        (format!("[SVC ] launch service={NETWORK_SERVICE} "), 2),
        (format!("[SVC ] launch service={AUDIT_SERVICE} "), 1),
        (format!("[SVC ] launch service={CONSOLE_SERVICE} "), 2),
        ("[SUP ] restart service=".to_owned(), 2),
        ("[PROC] fault pid=".to_owned(), 2),
        ("[HOOK] network fault armed ".to_owned(), 1),
        ("[HOOK] console fault armed ".to_owned(), 1),
        (SERIAL_INPUT_SERVED.to_owned(), 2),
        ("[HOOK] audit flood ".to_owned(), 1),
        ("[NET ] linux sockets lost ".to_owned(), 1),
    ] {
        let got = kernel_lines(transcript, &prefix).count();
        if got != want {
            return Err(format!("{got} lines {prefix:?}, expected {want}"));
        }
    }
    Ok(())
}

fn save_transcript(transcript: &[u8]) -> Result<(), XtaskError> {
    let dir = xtask_artifact_root().join("system");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("serial.log");
    std::fs::write(&path, transcript)?;
    println!("[STM ] serial transcript: {}", path.display());
    Ok(())
}

/// `test-system`: the three desktop boots, then one boot of the hooks build
/// on a fresh lane-owned disk; the host types [`STEPS`] into the shell over a loopback COM1.
pub(crate) fn run() -> Result<(), XtaskError> {
    println!(
        "[STM ] test-system boots the {HOOKS_FEATURE} build: the default image plus test hooks (COM1 fault bytes for the network service, compositor, desktop shell, app and console service; desktop resource, quiet and stale-generation evidence; per-input trace lines)"
    );
    let disk = workspace_root()
        .join("target")
        .join("system")
        .join(SYSTEM_DATA_DISK_FILENAME);
    if disk.is_file() {
        std::fs::remove_file(&disk)?;
    }
    ensure_data_disk(&disk)?;
    crate::system_desktop::run(&[HOOKS_FEATURE], &disk)?;
    if disk.is_file() {
        std::fs::remove_file(&disk)?;
    }
    ensure_data_disk(&disk)?;
    let peer = start_shell_fixture_peer()?;
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let config = VmLaunchConfig {
        serial_tcp_port: Some(listener.local_addr()?.port()),
        ..system_vm_config(disk, Some(peer.port()))
    };
    let result = drive(&listener, config, &peer);
    let counts = peer.shutdown();
    let (transcript, states) = result?;
    check_whole(&String::from_utf8_lossy(&transcript))
        .and_then(|()| check_fixture_totals(counts))
        .map_err(|reason| XtaskError::Validation(format!("system: {reason}")))?;
    let before = states[0];
    let after = states[states.len() - 1];
    println!(
        "\n[STM ] PASS ({HOOKS_FEATURE} build) after {AUDIT_FLOOD_DENIALS} audit denials of the shell, the audit service pid={} printed the witness, the {AUDIT_HOLDER_BUDGET} denials the budget kept and exactly {} lost; shell pid={} resolved through the fixture and fetched from it through network pid={} gen={}, the fixture answering the request it received; the next wget's request reached the fixture's hold port, which held it unanswered; Ctrl-\\ faulted the network service, the blocked wget read failed with ECONNRESET and the shell prompted again, init restarted the service as pid={} gen={}, its launch audit matched, the shell's client capability was re-issued for it, init settled, and from the same shell nslookup resolved through the fixture again and wget's request reached the fixture and was answered again; Ctrl-X faulted the console service, init restarted it as pid={}, the shell's console client was re-issued for it, and a typed echo reached the same shell through it",
        before.audit_pid, AUDIT_FLOOD_DENIALS - AUDIT_HOLDER_BUDGET, before.shell.pid, before.network.pid, before.network.generation, after.network.pid, after.network.generation, after.console.map_or(0, |console| console.pid)
    );
    Ok(())
}

/// The two `wget` steps' requests, one per network generation.
const SYSTEM_HTTP_REQUESTS: u32 = 2;

/// What the fixture peer served over the whole run: each `wget` step's request answered, no
/// connection refused, and the one held connection's request received and never answered.
fn check_fixture_totals(counts: FixtureCounts) -> Result<(), String> {
    counts.require_http_requests("test-system", SYSTEM_HTTP_REQUESTS)?;
    if counts.held_connections != 1 || counts.held_requests != 1 {
        return Err(format!(
            "the fixture's hold port held {} connection(s) and received {} request(s) on them, expected 1 and 1",
            counts.held_connections, counts.held_requests
        ));
    }
    Ok(())
}

/// Boots QEMU and types the script. Returns the transcript and the [`State`] after the boot
/// and after each step.
fn drive(
    listener: &TcpListener,
    config: VmLaunchConfig,
    peer: &M7FixturePeer,
) -> Result<(Vec<u8>, Vec<State>), XtaskError> {
    let mut vm = prepare_vm(false, false, &[HOOKS_FEATURE], config)?;
    announce_qemu_version(&vm.qemu);
    vm.qemu.stdin(Stdio::null());
    let deadline = Instant::now() + LANE_TIMEOUT;
    let mut child = ReapOnDrop(vm.qemu.spawn()?);
    let stream = accept_serial(listener, &mut child, deadline)?;
    let mut writer = stream.try_clone()?;
    let (tx, rx) = mpsc::channel();
    let _reader = spawn_serial_reader(stream, tx);

    let mut transcript = Vec::new();
    let mut reboot_detector = GuestRebootDetector::default();
    let mut states: Vec<State> = Vec::new();
    // Where the step being waited for was typed, and the fixture counts then.
    let mut typed_at = 0usize;
    let mut counts_then = FixtureCounts::default();
    let mut step_started = Instant::now();
    // When the current step's check first passed, for steps that must stay passing.
    let mut passing_since: Option<Instant> = None;
    let fail = |transcript: &[u8], message: String| {
        let _ = save_transcript(transcript);
        Err(XtaskError::Validation(format!(
            "system: {message}; tail {:?}",
            tail(transcript)
        )))
    };
    loop {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(SerialEvent::Bytes(bytes)) => {
                print!("{}", String::from_utf8_lossy(&bytes));
                let _ = std::io::stdout().flush();
                transcript.extend_from_slice(&bytes);
            }
            Ok(SerialEvent::Closed) => {
                let qemu = qemu_state(&mut child)?;
                return fail(
                    &transcript,
                    format!("QEMU closed the serial port; QEMU {qemu}"),
                );
            }
            Ok(SerialEvent::Failed(error)) => {
                let qemu = qemu_state(&mut child)?;
                return fail(
                    &transcript,
                    format!("reading the serial port failed ({error}); QEMU {qemu}"),
                );
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return fail(&transcript, "serial reader stopped".to_owned())
            }
        }
        if let Some(reboot) = reboot_detector.observe(&transcript) {
            return fail(&transcript, reboot);
        }
        let segment = String::from_utf8_lossy(&transcript[typed_at..]);
        let waiting = match states.len() {
            0 => "boot",
            done => STEPS[done - 1].name,
        };
        let progress = match states.last() {
            None => check_boot_segment(&segment),
            Some(state) => check_step(
                &STEPS[states.len() - 1],
                &segment,
                counts_then,
                peer.counts(),
                *state,
            ),
        };
        let refused = peer.counts().http_refused;
        if refused != 0 {
            return fail(
                &transcript,
                format!(
                    "the fixture refused {refused} HTTP connection(s) without a complete request in {waiting:?}"
                ),
            );
        }
        if let Some(failure) = first_guest_failure_in_bytes(&transcript, false) {
            let reason = progress.as_ref().err().cloned().unwrap_or_default();
            return fail(
                &transcript,
                format!("{failure:?} printed in {waiting:?} ({reason})"),
            );
        }
        for forbidden in [&b"[INIT] gave up"[..]] {
            if let Some(at) = find(&transcript, forbidden) {
                let line = String::from_utf8_lossy(&transcript[at..]);
                let line = line.lines().next().unwrap_or_default();
                let reason = progress.as_ref().err().cloned().unwrap_or_default();
                return fail(
                    &transcript,
                    format!("{line:?} printed in {waiting:?} ({reason})"),
                );
            }
        }
        let now = Instant::now();
        match progress {
            Ok(next) => {
                let settle = match states.len().checked_sub(1) {
                    None => READER_POLLS_SETTLE,
                    Some(index) if STEPS[index].expect == Expect::Held => HOLD_SETTLE,
                    Some(_) => Duration::ZERO,
                };
                let since = *passing_since.get_or_insert(now);
                if now.duration_since(since) < settle {
                    continue;
                }
                passing_since = None;
                states.push(next);
                if states.len() == STEPS.len() + 1 {
                    if let Err(missing) = reboot_detector.require_kernel_banner() {
                        return fail(&transcript, missing);
                    }
                    save_transcript(&transcript)?;
                    return Ok((transcript, states));
                }
                let step = &STEPS[states.len() - 1];
                println!("\n[STM ] step {:?}", step.name);
                typed_at = transcript.len();
                counts_then = peer.counts();
                writer.write_all(step.send)?;
                writer.flush()?;
                step_started = now;
            }
            Err(reason) => {
                passing_since = None;
                if now >= deadline || now.duration_since(step_started) >= STEP_TIMEOUT {
                    return fail(&transcript, format!("timed out in {waiting:?}: {reason}"));
                }
                if let Some(status) = child.try_wait()? {
                    return fail(
                        &transcript,
                        format!("QEMU exited with {status} in {waiting:?}: {reason}"),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_shell::expected_authority;

    const INIT: u64 = 1;
    const SHELL: u64 = 4;
    const NET1: u64 = 3;
    const NET2: u64 = 8;
    const AUDIT: u64 = 2;
    const CONS1: u64 = 5;
    const CONS2: u64 = 10;

    fn console_fault() -> String {
        format!(
            "[HOOK] console fault armed pid={CONS1} gen=1 user_rip=0x0 parked-in=native at-ms=9\n\
             [PROC] fault pid={CONS1} vector=14 err=0x14\n\
             [SVC ] reaped service=22016 pid={CONS1} residue=0\n\
             [IPC ] console pid={INIT}: [SUP ] restart service=22016 attempt=1\n\
             [SVC ] launch service=22016 pid={CONS2} gen=2\n\
             [CONS] authority granted pid={CONS2} port=22016:13 rights=serve registered=1 device=read|write\n\
             [CONS] client reissued holder={SHELL} port=22016:13\n\
             [SVC ] ready service=22016 pid={CONS2} gen=2 source=live-instance kernel-observed ports=1\n\
             [IPC ] console pid={INIT}: [INIT] service=22016 ready gen=2\n\
             [IPC ] console pid={INIT}: {SETTLED}\n"
        )
    }

    fn echo_again() -> String {
        format!(
            "echo hel''lo-again\r\n\
             [IPC ] console pid={CONS2}: {SERIAL_INPUT_SERVED}\n\
             [CON ] pid={SHELL}: hello-again\n\
             [CON ] pid={SHELL}: # "
        )
    }

    #[test]
    fn a_console_fault_moves_the_shell_to_generation_2_and_input_follows() {
        let state = check_console_fault(&console_fault(), booted()).expect("console fault");
        assert_eq!(
            state.console,
            Some(Network {
                pid: CONS2,
                generation: 2
            })
        );
        check_console_input(&echo_again(), &["hello-again"], state).expect("echo");
        let error = check_console_input(
            &echo_again().replace(SERIAL_INPUT_SERVED, "nothing"),
            &["hello-again"],
            state,
        )
        .unwrap_err();
        assert!(error.contains(SERIAL_INPUT_SERVED), "{error}");
        let stale = echo_again().replace(&format!("pid={CONS2}:"), &format!("pid={CONS1}:"));
        assert!(check_console_input(&stale, &["hello-again"], state).is_err());
    }

    #[test]
    fn a_console_fault_needs_the_reissue_the_restart_and_the_same_shell() {
        let booted = booted();
        for (from, to) in [
            (
                format!("[CONS] client reissued holder={SHELL} port=22016:13\n"),
                String::new(),
            ),
            (
                format!("holder={SHELL} port=22016:13"),
                format!("holder={SHELL} port=22016:12"),
            ),
            ("attempt=1".to_owned(), "attempt=2".to_owned()),
            ("residue=0".to_owned(), "residue=1".to_owned()),
            (
                format!("pid={CONS2} gen=2\n"),
                format!("pid={CONS1} gen=2\n"),
            ),
            (
                format!("[IPC ] console pid={INIT}: {SETTLED}\n"),
                String::new(),
            ),
        ] {
            let segment = console_fault().replace(&from, &to);
            assert!(check_console_fault(&segment, booted).is_err(), "{from:?}");
        }
        let exited = format!("{}[LNX ] exit pid={SHELL} status=0\n", console_fault());
        assert!(check_console_fault(&exited, booted).is_err());
    }

    fn network_instance(pid: u64, generation: u64) -> String {
        format!(
            "{}\n\
             [SVC ] launch service=20992 pid={pid} gen={generation}\n\
             [SVC ] ready service=20992 pid={pid} gen={generation} source=live-instance kernel-observed raw-backend=virtio service-reported link-up=1\n\
             [IPC ] console pid={INIT}: [INIT] service=20992 ready gen={generation}\n",
            expected_network_authority(pid)
        )
    }

    fn boot() -> String {
        format!(
            "{HOOKS_BANNER}\n\
             [KERN] serial console input on vector=0x31\n\
             [KERN] boot profile=base\n\
             [KERN] init launched pid={INIT} slot=0 declared-services=5\n\
             [IPC ] console pid={INIT}: [INIT] boot profile=base\n\
             [SVC ] launch service=21760 pid={AUDIT} gen=1\n\
             [SVC ] launch service=22016 pid={CONS1} gen=1\n\
             {}\
             {}\n\
             [SVC ] shell process pid={SHELL} gen=1 argv=/bin/sh,-i env=PATH=/bin stdin=1 stdout=1 tmp=1 net-client=1\n\
             [SVC ] launch service=21504 pid={SHELL} gen=1\n\
             [CON ] pid={SHELL}: \n\
             [CON ] pid={SHELL}: # BusyBox v1.37.0 built-in shell (ash)\n\
             [CON ] pid={SHELL}: \n\
             [SVC ] ready service=21504 pid={SHELL} gen=1 source=live-instance kernel-observed first-console-input-wait\n\
             [IPC ] console pid={INIT}: [INIT] service=21504 ready gen=1\n\
             [IPC ] console pid={INIT}: {SETTLED}\n",
            network_instance(NET1, 1),
            expected_authority(SHELL)
        )
    }

    fn fault() -> String {
        format!(
            "[HOOK] network fault armed pid={NET1} gen=1 user_rip=0x0 parked-in=native\n\
             [PROC] fault pid={NET1} vector=14 err=0x14\n\
             [PROC] fault rip=0x0000000000000000 cr2=0x0000000000000000 instruction_fetch=1\n\
             [NET ] linux sockets lost count=1 reason=instance-gone\n\
             [CAP ] net client revoked count=2 reason=instance-gone\n\
             [CON ] pid=7: {RESET_ERROR}\n\
             [LNX ] exit pid=7 status=1\n\
             [SVC ] reaped service=20992 pid={NET1} residue=0\n\
             [CON ] pid={SHELL}: # \n\
             [IPC ] console pid={INIT}: [SUP ] restart service=20992 attempt=1\n\
             [CAP ] net client reissued holder={SHELL} generation=2\n\
             {}\
             [IPC ] console pid={INIT}: {SETTLED}\n",
            network_instance(NET2, 2)
        )
    }

    /// The shell's prompt, shown open by the console service and ended by the kernel line
    /// that follows it.
    fn prompt_line() -> String {
        format!("[CON ] pid={SHELL}: # \n")
    }

    fn booted() -> State {
        check_boot_segment(&boot()).expect("boot")
    }

    /// Counts with every held connection's request received and nothing refused.
    fn counts(dns: u32, http: u32, held: u32) -> FixtureCounts {
        FixtureCounts {
            fixture_a_answers: dns,
            http_responses: http,
            http_refused: 0,
            held_connections: held,
            held_requests: held,
            ..FixtureCounts::ZERO
        }
    }

    fn fault_error(segment: &str) -> String {
        check_fault(segment, booted()).unwrap_err()
    }

    #[test]
    fn a_correct_boot_and_fault_reach_generation_2_under_the_same_shell() {
        let state = booted();
        assert_eq!(
            state,
            State {
                init_pid: INIT,
                shell: Shell {
                    pid: SHELL,
                    generation: 1
                },
                network: Network {
                    pid: NET1,
                    generation: 1
                },
                audit_pid: AUDIT,
                console: None,
            }
        );
        let after = check_fault(&fault(), state).expect("fault");
        assert_eq!(
            after.network,
            Network {
                pid: NET2,
                generation: 2
            }
        );
        assert_eq!(after.shell, state.shell);
    }

    #[test]
    fn the_boot_must_be_the_hooks_build_and_settled() {
        let error = check_boot_segment(&boot().replace(HOOKS_BANNER, "")).unwrap_err();
        assert!(error.contains("not the hooks build"), "{error}");
        assert!(check_boot_segment(&boot().replace("running=5", "running=4")).is_err());
        assert!(check_boot_segment(&boot().replace("service=21760", "service=21761")).is_err());
        let wrong_audit = boot().replace("raw-net-link=1", "raw-net-link=0");
        assert!(check_boot_segment(&wrong_audit)
            .unwrap_err()
            .contains("launch audit"));
    }

    #[test]
    fn the_blocked_reader_must_wake_with_the_reset_error_and_a_prompt() {
        let error = fault_error(&fault().replace(RESET_ERROR, ""));
        assert!(error.contains("blocked reader was not woken"), "{error}");
        let error = fault_error(&fault().replace(&prompt_line(), ""));
        assert!(error.contains("no prompt"), "{error}");
        let error = fault_error(&format!("{}[LNX ] exit pid={SHELL} status=0\n", fault()));
        assert!(error.contains("shell"), "{error}");
    }

    #[test]
    fn the_fault_must_be_real_and_lose_the_sockets() {
        assert!(fault_error(&fault().replace("vector=14", "vector=13")).contains("did not fault"));
        assert!(
            fault_error(&fault().replace("gen=1 user_rip", "gen=2 user_rip")).contains("armed")
        );
        assert!(
            fault_error(&fault().replace("[NET ] linux sockets lost count=1", ""))
                .contains("sockets lost")
        );
        assert!(
            fault_error(&fault().replace("sockets lost count=1", "sockets lost count=0"))
                .contains("unexpected")
        );
        assert!(fault_error(&fault().replace("[CAP ] net client revoked", "")).contains("revoked"));
    }

    #[test]
    fn the_faulted_instance_is_reaped_with_no_residue() {
        let error = fault_error(&fault().replace("residue=0", "residue=1"));
        assert!(error.contains("reaped with residue=1"), "{error}");
        let error = fault_error(&fault().replace("[SVC ] reaped service=20992", "[SVC ] gone"));
        assert!(error.contains("was not reaped"), "{error}");
    }

    #[test]
    fn generation_2_needs_the_restart_its_audit_the_reissue_and_init_settled() {
        let error = fault_error(&fault().replace("[SUP ] restart service=20992 attempt=1", ""));
        assert!(
            error.contains("waiting for network generation 2"),
            "{error}"
        );
        let error = fault_error(&fault().replace("[SVC ] launch service=20992 pid=8 gen=2", ""));
        assert!(
            error.contains("waiting for network generation 2"),
            "{error}"
        );
        let error = fault_error(&fault().replace(
            &expected_network_authority(NET2),
            &expected_network_authority(NET2).replace("network=1", "network=0"),
        ));
        assert!(error.contains("launch audit"), "{error}");
        let error =
            fault_error(&fault().replace("[CAP ] net client reissued", "[CAP ] net client"));
        assert!(error.contains("reissued"), "{error}");
        let error = fault_error(&fault().replace("holder=4 generation=2", "holder=9 generation=2"));
        assert!(error.contains("reissued"), "{error}");
        let settled_last = format!("[IPC ] console pid={INIT}: {SETTLED}\n");
        let error = fault_error(&fault().replace(&settled_last, ""));
        assert!(error.contains("since generation 2"), "{error}");
    }

    #[test]
    fn steps_need_the_fixture_to_have_served_them() {
        let state = booted();
        let nslookup = &format!(
            "nslookup m7.fixture.test\r\n[CON ] pid=7: Name:      m7.fixture.test\n[CON ] pid=7: Address 1: 10.77.0.50\n{}",
            prompt_line()
        );
        assert!(check_step(&NSLOOKUP, nslookup, counts(0, 0, 0), counts(1, 0, 0), state).is_ok());
        assert!(
            check_step(&NSLOOKUP, nslookup, counts(1, 0, 0), counts(1, 0, 0), state)
                .unwrap_err()
                .contains("fixture peer")
        );
        let wget = &format!(
            "wget -q -O - http://m7.fixture.test:4001/\r\n[CON ] pid=7: M9-FIXTURE-HTTP\n{}",
            prompt_line()
        );
        assert!(check_step(&WGET, wget, counts(1, 0, 0), counts(2, 1, 0), state).is_ok());
        assert!(check_step(&WGET, wget, counts(1, 0, 0), counts(2, 0, 0), state).is_err());
        assert!(check_step(&WGET, wget, counts(1, 0, 0), counts(2, 2, 0), state).is_err());
        let refused = FixtureCounts {
            http_refused: 1,
            ..counts(2, 1, 0)
        };
        let error = check_step(&WGET, wget, counts(1, 0, 0), refused, state).unwrap_err();
        assert!(error.contains("refused 1"), "{error}");
        assert!(check_step(&NSLOOKUP, nslookup, counts(0, 0, 0), counts(1, 1, 0), state).is_err());
    }

    #[test]
    fn the_run_needs_both_requests_answered_and_the_held_request_received() {
        assert_eq!(check_fixture_totals(counts(4, 2, 1)), Ok(()));
        assert!(check_fixture_totals(counts(4, 1, 1)).is_err());
        assert!(check_fixture_totals(counts(4, 2, 0)).is_err());
        let unheard = FixtureCounts {
            held_requests: 0,
            ..counts(4, 2, 1)
        };
        assert!(check_fixture_totals(unheard)
            .unwrap_err()
            .contains("received 0 request"));
        let refused = FixtureCounts {
            http_refused: 1,
            ..counts(4, 2, 1)
        };
        assert!(check_fixture_totals(refused).is_err());
    }

    #[test]
    fn the_reader_must_be_held_and_unprompted() {
        let held = &STEPS[3];
        assert_eq!(held.expect, Expect::Held);
        let state = booted();
        let typed =
            "wget -q -O - http://m7.fixture.test:4003/\r\n[LNX ] personality=x86_64 pid=7\n";
        assert!(check_step(held, typed, counts(2, 1, 0), counts(3, 1, 1), state).is_ok());
        assert!(
            check_step(held, typed, counts(2, 1, 0), counts(3, 1, 0), state)
                .unwrap_err()
                .contains("holds no connection")
        );
        let unheard = FixtureCounts {
            held_requests: 0,
            ..counts(3, 1, 1)
        };
        assert!(check_step(held, typed, counts(2, 1, 0), unheard, state)
            .unwrap_err()
            .contains("has not received"));
        let prompted = format!("{typed}[CON ] pid=7: wget: bad address\n{}", prompt_line());
        assert!(
            check_step(held, &prompted, counts(2, 1, 0), counts(3, 1, 1), state)
                .unwrap_err()
                .contains("not blocked")
        );
    }

    /// Init's denial at seq 200, the shell's 100 at 201..=300, of which it keeps 285..=300; the
    /// service had lost 150..=169 before the flood.
    fn flood() -> String {
        let mut text = format!(
            "[HOOK] audit flood witness-holder={INIT} witness-seq=200 holder={SHELL} denials=100 first-seq=201 next-seq=301 allowed=0 held=16 reader={AUDIT} reader-reads=1 aged-out=0\n\
             [IPC ] console pid={AUDIT}: [ADT ] lost first=150 missing=20\n\
             [IPC ] console pid={AUDIT}: [ADT ] #200 {INIT} noright audit\n\
             [IPC ] console pid={AUDIT}: [ADT ] lost first=201 missing=84\n"
        );
        for seq in 285..301 {
            text += &format!("[IPC ] console pid={AUDIT}: [ADT ] #{seq} {SHELL} noright audit\n");
        }
        text += &format!(
            "{}[IPC ] console pid={AUDIT}: [ADT ] drained through=302 records=40 lost=104\n",
            prompt_line()
        );
        text
    }

    fn flood_error(segment: &str) -> String {
        check_audit_flood(segment, booted()).unwrap_err()
    }

    #[test]
    fn the_audit_service_reports_the_witness_the_kept_denials_and_the_exact_loss() {
        assert_eq!(check_audit_flood(&flood(), booted()), Ok(booted()));
        let unfinished = flood().replace("through=302", "through=299");
        assert!(flood_error(&unfinished).contains("waiting for the audit service"));
        let elsewhere = flood().replace(
            &format!("console pid={AUDIT}: [ADT ] drained"),
            "console pid=9: [ADT ] drained",
        );
        assert!(flood_error(&elsewhere).contains("waiting for the audit service"));
        for (from, to) in [
            ("missing=84", "missing=85"),
            ("missing=84", "missing=83"),
            ("[ADT ] #200 1 noright audit\n", ""),
            ("[ADT ] #290 ", "[ADT ] #29 "),
            ("[ADT ] #300 4 noright audit", "[ADT ] #300 5 noright audit"),
        ] {
            let error = flood_error(&flood().replace(from, to));
            assert!(error.contains("expected once"), "{to}: {error}");
        }
        let doubled = flood().replace(
            "[ADT ] #290 4 noright audit\n",
            "[ADT ] #290 4 noright audit\n[IPC ] console pid=2: [ADT ] #290 4 noright audit\n",
        );
        assert!(flood_error(&doubled).contains("2 times"));
        for extra in [
            "#250 4 noright audit",
            "lost first=190 missing=11",
            "lost first=300 missing=5",
        ] {
            let text = flood().replace(
                &prompt_line(),
                &format!(
                    "[IPC ] console pid={AUDIT}: [ADT ] {extra}\n{}",
                    prompt_line()
                ),
            );
            assert!(flood_error(&text).contains("flood's sequences"), "{extra}");
        }
        let before_flood = flood().replace(
            "[ADT ] lost first=150 missing=20",
            "[ADT ] lost first=150 missing=51",
        );
        assert!(flood_error(&before_flood).contains("flood's sequences"));
    }

    #[test]
    fn the_flood_hook_must_show_the_typed_denials_contiguous_and_budgeted() {
        for (from, to) in [
            ("denials=100", "denials=99"),
            ("first-seq=201", "first-seq=202"),
            ("next-seq=301", "next-seq=300"),
            ("allowed=0", "allowed=1"),
            ("held=16", "held=17"),
            ("witness-holder=1", "witness-holder=3"),
            ("holder=4 denials", "holder=3 denials"),
        ] {
            let error = flood_error(&flood().replace(from, to));
            assert!(error.contains("denied once"), "{to}: {error}");
        }
        assert!(
            flood_error(&flood().replace("[HOOK] audit flood", "[HOOK] flood")).contains("no line")
        );
    }

    #[test]
    fn the_log_holds_exactly_one_record_of_the_audit_services_reads() {
        let aged_out = flood().replace("reader-reads=1 aged-out=0", "reader-reads=0 aged-out=3");
        assert_eq!(check_audit_flood(&aged_out, booted()), Ok(booted()));
        let one_after_aging = flood().replace("aged-out=0", "aged-out=3");
        assert_eq!(check_audit_flood(&one_after_aging, booted()), Ok(booted()));
        for (from, to) in [
            ("reader-reads=1", "reader-reads=0"),
            ("reader-reads=1", "reader-reads=2"),
            ("reader-reads=1 aged-out=0", "reader-reads=2 aged-out=3"),
            (&format!("reader={AUDIT} ") as &str, "reader=9 "),
        ] {
            let error = flood_error(&flood().replace(from, to));
            assert!(error.contains("exactly one record"), "{to}: {error}");
        }
    }

    #[test]
    fn the_flood_is_typed_first_as_one_queue_byte_per_denial_then_one_commit() {
        assert_eq!(STEPS[0].expect, Expect::AuditFlood);
        let (commit, queued) = STEPS[0].send.split_last().unwrap();
        assert_eq!(*commit, 0x02);
        assert_eq!(queued.len() as u64, AUDIT_FLOOD_DENIALS);
        assert!(queued.iter().all(|byte| *byte == 0x01));
        for step in &STEPS[1..] {
            assert!(!step.send.iter().any(|byte| [0x01, 0x02].contains(byte)));
        }
    }

    #[test]
    fn the_whole_run_allows_one_fault_one_restart_and_no_failure() {
        let whole = format!(
            "{}[IPC ] console pid={CONS1}: {SERIAL_INPUT_SERVED}\n{}{}{}{}",
            boot(),
            flood(),
            fault(),
            console_fault(),
            echo_again()
        );
        assert_eq!(check_whole(&whole), Ok(()));
        for extra in [
            "[FAIL] something\n",
            "[NET ] FAIL something\n",
            "[IPC ] console pid=1: [INIT] gave up service=20992 restarts=3; init carries on\n",
            "[PROC] fault pid=4 vector=14 err=0x4\n",
            "[IPC ] console pid=1: [SUP ] restart service=20992 attempt=2\n",
            "[SVC ] launch service=21504 pid=9 gen=2\n",
            "[NET ] linux sockets lost count=1 reason=instance-gone\n",
            "[SVC ] launch service=22016 pid=11 gen=3\n",
            "[IPC ] console pid=10: [CONS] serial input answered a read\n",
        ] {
            assert!(check_whole(&format!("{whole}{extra}")).is_err(), "{extra}");
        }
    }

    #[test]
    fn the_script_faults_only_once_and_after_the_reader_is_held() {
        let faults: Vec<usize> = STEPS
            .iter()
            .enumerate()
            .filter(|(_, step)| step.send.contains(&0x1c))
            .map(|(index, _)| index)
            .collect();
        assert_eq!(faults.len(), 1);
        assert_eq!(STEPS[faults[0]].expect, Expect::Fault);
        assert_eq!(STEPS[faults[0] - 1].expect, Expect::Held);
        assert_eq!(STEPS[faults[0] + 1].send, NSLOOKUP.send);
        assert_eq!(STEPS[faults[0] + 2].send, WGET.send);
    }
}
