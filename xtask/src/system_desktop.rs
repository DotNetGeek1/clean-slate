//! `test-system`'s three desktop boots (#218 S6c, S6f), all headless and on the hooks build.
//!
//! 1. **Desktop.** `opt/clean-slate/desktop=q1` and a modern-only VirtIO-GPU: the kernel declares
//!    the five base rows and the compositor, desktop shell and app rows, and init launches all
//!    eight. Each desktop row must hold exactly its manifest grants (the kernel's `[GFX ]`, `[DISP]`,
//!    `[SEAT]` and, for the app's and the serial shell's console streams, `[CONS]` grant lines, then a launch audit that matches the row), report ready from its
//!    launched pid with the bindings the kernel observes, and the compositor must have submitted a
//!    frame before it reports ready. Init settles with eight rows running and the hooks build
//!    prints its desktop resource baseline. Then, over COM1 (S6d), the host faults the
//!    compositor, the desktop shell and the app in turn ([`check_row_fault`]): each faulted row is reaped
//!    with no residue; on a compositor fault the shell and app see the port go and exit with
//!    `reason=compositor-gone`, nothing kills them; init relaunches every row that went, at a
//!    new pid and generation, each only once the row it depends on is ready again; rows that did
//!    not go keep their pids; a new compositor serves a new port generation, the clients'
//!    grants name it and a record for the old generation is refused as stale; the resource
//!    counts return to the baseline and init settles again. Last, the serial shell must answer
//!    a command. No pointer or keyboard input is scripted.
//! 2. **No display** (D4). The same entry with `-vga none` and no GPU: the kernel says once that
//!    the desktop has no display output, declares the base rows only, and init boots base.
//! 3. **Framebuffer alone** (S6f). The same entry with `-vga std` and no GPU: `q1` names
//!    VirtIO-GPU, so the kernel says once that it runs Q0 on the framebuffer, and init, the
//!    compositor and the desktop shell all run at Q0.

use std::path::Path;
use std::time::{Duration, Instant};

use clean_slate_ui::QualityTier;

use crate::marker_spec::first_guest_failure;
use crate::system_boot::{
    check_audit_service, check_console_service, check_no_desktop_rows, expected_audit_authority,
    expected_console_authority, field, number, start_shell_fixture_peer, system_vm_config,
    AUDIT_SERVICE, CONSOLE_SERVICE,
};
use crate::system_desktop_faults::Step;
use crate::system_shell::{console_text, expected_authority as expected_shell_authority, lines};
use crate::{
    run_driven_vm_acceptance, AcceptanceDriver, MarkerSet, MarkerStep, VmLaunchConfig, XtaskError,
};

pub(crate) const STORAGE: u32 = 0x5100;
pub(crate) const NETWORK: u32 = 0x5200;
pub(crate) const SHELL: u32 = 0x5400;
pub(crate) const COMPOSITOR: u32 = 0x5300;
pub(crate) const DESKTOP_SHELL: u32 = 0x5301;
pub(crate) const APP: u32 = 0x5302;
pub(crate) const AUDIT: u32 = AUDIT_SERVICE;
pub(crate) const CONSOLE: u32 = CONSOLE_SERVICE;
/// In init's start order: storage, the audit service and the console service at boot, then
/// network and the shell with the compositor once storage is ready.
const SERVICES: [u32; 8] = [
    STORAGE,
    AUDIT,
    CONSOLE,
    NETWORK,
    SHELL,
    COMPOSITOR,
    DESKTOP_SHELL,
    APP,
];
pub(crate) const DESKTOP_ROWS: [u32; 3] = [COMPOSITOR, DESKTOP_SHELL, APP];
const BOOT_TIMEOUT: Duration = Duration::from_secs(180);
const DESKTOP_PROFILE: &str = "[KERN] boot profile=desktop tier=Q1 source=fw_cfg";
/// `kernel/src/service/system_init.rs` `FRAMEBUFFER_TIER_LINE`.
const FRAMEBUFFER_TIER: &str =
    "[KERN] desktop tier=Q1 needs VirtIO-GPU; running tier=Q0 on the framebuffer";

/// A machine the desktop lanes boot the hooks build on, and what the boot must pick on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DesktopMachine {
    /// Names the run's artifacts and serial log.
    pub(crate) name: &'static str,
    pub(crate) tier: QualityTier,
    /// `-vga std` and no GPU, with `opt/clean-slate/desktop=q0`; otherwise a modern-only
    /// VirtIO-GPU, `-vga none` and `q1`.
    pub(crate) framebuffer: bool,
    /// The `[DISP] backend=` the kernel must install.
    pub(crate) backend: &'static str,
}

pub(crate) const VIRTIO_GPU_Q1: DesktopMachine = DesktopMachine {
    name: "virtio-gpu",
    tier: QualityTier::Q1,
    framebuffer: false,
    backend: "virtio-gpu",
};

pub(crate) const FRAMEBUFFER_Q0: DesktopMachine = DesktopMachine {
    name: "framebuffer",
    tier: QualityTier::Q0,
    framebuffer: true,
    backend: "gop",
};

impl DesktopMachine {
    pub(crate) fn tier_name(&self) -> &'static str {
        match self.tier {
            QualityTier::Q0 => "Q0",
            QualityTier::Q1 => "Q1",
            QualityTier::Q2 => "Q2",
            QualityTier::Q3 => "Q3",
        }
    }
}
/// `kernel/src/service/system_init.rs` `NO_DISPLAY_LINE`.
const NO_DISPLAY: &str =
    "[KERN] boot profile=desktop has no display output; booting base, desktop rows not declared";
pub(crate) const SETTLED_DESKTOP: &str =
    "[INIT] boot settled running=8 down=0; waiting, no deadline";
const SETTLED_BASE: &str = "[INIT] boot settled running=5 down=0; waiting, no deadline";
/// What the app writes through its console stream once it starts (#310).
const APP_CONSOLE_GREETING: &str = "playground: console stream open";
/// A desktop row that never reports ready is restarted until init gives up on it.
pub(crate) const GIVE_UP_LINES: [&str; 2] = ["[INIT] gave up", "[INIT] not starting"];

/// Each desktop row's authority, launch and ready, in the order init must reach them: a row starts
/// only once every row it depends on is ready. The tier is checked per machine by
/// [`check_desktop_boot`].
const DESKTOP_MARKERS: [MarkerStep<'static>; 13] = [
    MarkerStep::Line {
        prefix: "[KERN] boot profile=",
        fields: &[("profile=", "desktop"), ("source=", "fw_cfg")],
    },
    MarkerStep::Line {
        prefix: "[KERN] init launched pid=",
        fields: &[("declared-services=", "8")],
    },
    MarkerStep::Line {
        prefix: "[INIT] boot profile=",
        fields: &[("profile=", "desktop")],
    },
    MarkerStep::Ordered("[SVC ] authority service=21248 "),
    MarkerStep::Ordered("[SVC ] launch service=21248 "),
    MarkerStep::Ordered("[SVC ] ready service=21248 "),
    MarkerStep::Ordered("[SVC ] authority service=21249 "),
    MarkerStep::Ordered("[SVC ] launch service=21249 "),
    MarkerStep::Ordered("[SVC ] ready service=21249 "),
    MarkerStep::Ordered("[SVC ] authority service=21250 "),
    MarkerStep::Ordered("[SVC ] launch service=21250 "),
    MarkerStep::Ordered("[SVC ] ready service=21250 "),
    MarkerStep::Ordered(SETTLED_DESKTOP),
];

const NO_DISPLAY_MARKERS: [MarkerStep<'static>; 5] = [
    MarkerStep::Line {
        prefix: "[KERN] boot profile=",
        fields: &[
            ("profile=", "desktop"),
            ("tier=", "Q1"),
            ("source=", "fw_cfg"),
        ],
    },
    MarkerStep::Ordered(NO_DISPLAY),
    MarkerStep::Line {
        prefix: "[KERN] init launched pid=",
        fields: &[("declared-services=", "5")],
    },
    MarkerStep::Line {
        prefix: "[INIT] boot profile=",
        fields: &[("profile=", "base")],
    },
    MarkerStep::Ordered(SETTLED_BASE),
];

/// `q1` on a machine with only the framebuffer: the kernel says once that it runs Q0, and init
/// and the desktop rows run at Q0.
const FRAMEBUFFER_TIER_MARKERS: [MarkerStep<'static>; 5] = [
    MarkerStep::Line {
        prefix: "[KERN] boot profile=",
        fields: &[
            ("profile=", "desktop"),
            ("tier=", "Q1"),
            ("source=", "fw_cfg"),
        ],
    },
    MarkerStep::Ordered(FRAMEBUFFER_TIER),
    MarkerStep::Line {
        prefix: "[KERN] init launched pid=",
        fields: &[("declared-services=", "8")],
    },
    MarkerStep::Line {
        prefix: "[INIT] boot profile=",
        fields: &[("profile=", "desktop"), ("tier=", "Q0")],
    },
    MarkerStep::Ordered(SETTLED_DESKTOP),
];

/// Fails the no-display boot as soon as init gives up on a row.
#[derive(Default)]
struct DesktopWatch {
    serial: String,
}

impl AcceptanceDriver for DesktopWatch {
    fn on_serial(&mut self, text: &str, _deadline: Instant) -> Result<(), XtaskError> {
        self.serial.push_str(text);
        match lines(&self.serial).find(|line| GIVE_UP_LINES.iter().any(|gave| line.contains(gave)))
        {
            Some(line) => Err(XtaskError::Validation(format!(
                "desktop boot: a row never became ready: {line:?}"
            ))),
            None => Ok(()),
        }
    }
}

/// Both boots, on `disk`; the shell boot that follows gets a fresh disk.
pub(crate) fn run(features: &[&str], disk: &Path) -> Result<(), XtaskError> {
    println!(
        "[STM ] desktop boot: fw_cfg opt/clean-slate/desktop=q1 with virtio-gpu-pci, COM1 driven"
    );
    let mut check = |done: usize, segment: &str, before: Option<&Desktop>| {
        let result = check_desktop_step(done, segment, before);
        if let (Ok(after), Some(before)) = (&result, before) {
            report_step(done, segment, before, after);
        }
        result
    };
    let (_, states) = crate::system_desktop_faults::drive(
        features,
        disk,
        &DESKTOP_STEPS,
        &FORBIDDEN,
        &mut check,
    )?;
    let (first, last) = (&states[0], &states[states.len() - 1]);
    println!(
        "[STM ] desktop boot: eight rows running, compositor port {}; the compositor, the desktop shell and the app each faulted and came back in dependency order (compositor pid={} gen={} port {} at the end), resources matched the baseline after each, and the serial shell answered",
        first.port, last.rows[0].pid, last.rows[0].generation, last.port
    );

    println!("[STM ] desktop boot with no display: opt/clean-slate/desktop=q1, -vga none, no GPU");
    let args = [
        "-fw_cfg",
        "name=opt/clean-slate/desktop,string=q1",
        "-vga",
        "none",
    ]
    .map(str::to_owned)
    .to_vec();
    let output = boot(
        features,
        disk,
        args,
        &NO_DISPLAY_MARKERS,
        &mut DesktopWatch::default(),
    )
    .map_err(|error| XtaskError::Validation(format!("desktop boot with no display: {error}")))?;
    check_no_display_boot(&output).map_err(|reason| {
        XtaskError::Validation(format!("desktop boot with no display: {reason}"))
    })?;
    println!("[STM ] desktop boot with no display: one {NO_DISPLAY:?}, base rows only");

    println!(
        "[STM ] desktop boot on the framebuffer alone: opt/clean-slate/desktop=q1, -vga std, no GPU"
    );
    let args = [
        "-fw_cfg",
        "name=opt/clean-slate/desktop,string=q1",
        "-vga",
        "std",
    ]
    .map(str::to_owned)
    .to_vec();
    let output = boot(
        features,
        disk,
        args,
        &FRAMEBUFFER_TIER_MARKERS,
        &mut DesktopWatch::default(),
    )
    .map_err(|error| {
        XtaskError::Validation(format!("desktop boot on the framebuffer alone: {error}"))
    })?;
    check_framebuffer_tier_boot(&output).map_err(|reason| {
        XtaskError::Validation(format!("desktop boot on the framebuffer alone: {reason}"))
    })?;
    println!(
        "[STM ] desktop boot on the framebuffer alone: one {FRAMEBUFFER_TIER:?}, eight rows at Q0"
    );
    Ok(())
}

fn boot(
    features: &[&str],
    disk: &Path,
    extra_args: Vec<String>,
    markers: &'static [MarkerStep<'static>],
    watch: &mut DesktopWatch,
) -> Result<String, XtaskError> {
    let peer = start_shell_fixture_peer()?;
    let config = VmLaunchConfig {
        machine_extra: Some("vmport=off"),
        extra_args,
        ..system_vm_config(disk.to_path_buf(), Some(peer.port()))
    };
    let output = run_driven_vm_acceptance(
        features,
        config,
        MarkerSet::Steps(markers),
        BOOT_TIMEOUT,
        watch,
    );
    peer.shutdown();
    output
}

#[derive(Debug, PartialEq, Eq)]
struct DesktopSummary {
    compositor_pid: u64,
    shell_pid: u64,
    app_pid: u64,
    /// `21248:<generation>`, as the grant lines name it.
    port: String,
    presents: u64,
}

/// The one line in `output` that contains `prefix`, from `prefix` on.
pub(crate) fn only<'a>(output: &'a str, prefix: &str) -> Result<&'a str, String> {
    let mut found = lines(output).filter_map(|line| line.find(prefix).map(|at| &line[at..]));
    let line = found
        .next()
        .ok_or_else(|| format!("no line containing {prefix:?}"))?;
    if found.next().is_some() {
        return Err(format!("more than one line containing {prefix:?}"));
    }
    Ok(line)
}

/// `[SVC ] authority` for `service`'s row at `pid`: exactly the authority its grants imply.
fn expected_audit(service: u32, pid: u64) -> String {
    if service == SHELL {
        return expected_shell_authority(pid);
    }
    if service == AUDIT {
        return expected_audit_authority(pid);
    }
    if service == CONSOLE {
        return expected_console_authority(pid);
    }
    let counts = match service {
        STORAGE => "lifecycle-control=0 console=0 block-device=1 object-service=1 network=0 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 audit-read=0 con-serve=0 con-device=0 con-client=0 launch-serve=0 launch-client=0 other=0 revoked=0 allowance=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0",
        NETWORK => "lifecycle-control=0 console=0 block-device=0 object-service=0 network=1 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 audit-read=0 con-serve=0 con-device=0 con-client=0 launch-serve=0 launch-client=0 other=0 revoked=0 allowance=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=1",
        COMPOSITOR => "lifecycle-control=0 console=1 block-device=0 object-service=0 network=0 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=1 gfx-shell=0 gfx-client=0 display=1 input=1 audit-read=0 con-serve=0 con-device=0 con-client=0 launch-serve=0 launch-client=0 other=0 revoked=0 allowance=24 owned-endpoints=0 ports=1 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0",
        DESKTOP_SHELL => "lifecycle-control=0 console=1 block-device=0 object-service=0 network=0 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=1 gfx-client=0 display=0 input=0 audit-read=0 con-serve=0 con-device=0 con-client=0 launch-serve=0 launch-client=1 other=0 revoked=0 allowance=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0",
        _ => "lifecycle-control=0 console=1 block-device=0 object-service=0 network=0 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=0 gfx-client=1 display=0 input=0 audit-read=0 con-serve=0 con-device=0 con-client=1 launch-serve=0 launch-client=0 other=0 revoked=0 allowance=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0",
    };
    format!(
        "[SVC ] authority service={service} pid={pid} {counts} linux=0 console-input=0 matches-manifest=1"
    )
}

/// What a desktop row's ready line must show the kernel observed: the compositor serves one port
/// and holds the presenter and the input consumer; the desktop shell holds its compositor
/// connection, and the app that and its console stream (#310).
fn check_bindings(service: u32, ready: &str) -> Result<(), String> {
    let want: [(&str, u64); 4] = if service == COMPOSITOR {
        [
            ("ports", 1),
            ("port-connections", 0),
            ("presenter", 1),
            ("input-consumer", 1),
        ]
    } else {
        [
            ("ports", 0),
            ("port-connections", if service == APP { 2 } else { 1 }),
            ("presenter", 0),
            ("input-consumer", 0),
        ]
    };
    for (key, value) in want {
        if number(ready, key)? != value {
            return Err(format!(
                "service {service} ready with {key}={} instead of {value}: {ready:?}",
                field(ready, key).unwrap_or_default()
            ));
        }
    }
    Ok(())
}

/// The grant line `prefix…suffix` for `pid`, before `before` in `output`; returns what lies
/// between the prefix and the suffix.
fn grant_line<'a>(
    output: &'a str,
    prefix: &str,
    suffix: &str,
    before: usize,
) -> Result<&'a str, String> {
    let line = only(output, prefix)?;
    let middle = line
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(suffix))
        .ok_or_else(|| format!("expected {prefix:?}…{suffix:?}, got {line:?}"))?;
    if output.find(line).is_none_or(|at| at > before) {
        return Err(format!("{line:?} is not before the row's launch audit"));
    }
    Ok(middle)
}

fn check_desktop_boot(output: &str, machine: &DesktopMachine) -> Result<DesktopSummary, String> {
    let backend = only(output, "[DISP] backend=")?;
    if field(backend, "backend") != Some(machine.backend) {
        return Err(format!(
            "expected the {} display: {backend:?}",
            machine.backend
        ));
    }
    let tier = machine.tier_name();
    let profile = only(output, "[KERN] boot profile=")?;
    if profile != format!("[KERN] boot profile=desktop tier={tier} source=fw_cfg") {
        return Err(format!("kernel boot profile {profile:?}"));
    }
    if let Some(line) = lines(output).find(|line| line.contains(FRAMEBUFFER_TIER)) {
        return Err(format!("the requested tier was not run: {line:?}"));
    }
    let launched = only(output, "[KERN] init launched pid=")?;
    let init_pid = number(launched, "pid")?;
    if number(launched, "declared-services")? != 8 {
        return Err(format!("expected eight declared rows: {launched:?}"));
    }
    let console = format!("[IPC ] console pid={init_pid}: ");
    only(
        output,
        &format!("{console}[INIT] boot profile=desktop tier={tier}"),
    )?;
    if let Some(failure) = first_guest_failure(output, true) {
        return Err(format!("guest failure {failure:?}"));
    }
    for gave in GIVE_UP_LINES.iter().chain(&["[SUP ] restart service="]) {
        if let Some(line) = lines(output).find(|line| line.contains(gave)) {
            return Err(format!("{gave:?} in {line:?}"));
        }
    }

    let mut pids = [0u64; 8];
    for (index, service) in SERVICES.iter().copied().enumerate() {
        let launch = only(output, &format!("[SVC ] launch service={service} "))?;
        let pid = number(launch, "pid")?;
        let generation = number(launch, "gen")?;
        let audit = only(output, &format!("[SVC ] authority service={service} "))?;
        let expected = expected_audit(service, pid);
        if audit != expected {
            return Err(format!(
                "service {service} launch audit {audit:?}, expected {expected:?}"
            ));
        }
        let ready = only(output, &format!("[SVC ] ready service={service} "))?;
        if number(ready, "pid")? != pid
            || number(ready, "gen")? != generation
            || field(ready, "source") != Some("live-instance")
        {
            return Err(format!(
                "service {service} launched as pid={pid} gen={generation} but ready says {ready:?}"
            ));
        }
        let announced = format!("{console}[INIT] service={service} ready gen={generation}");
        let at = |line: &str| output.find(line);
        let order = [at(audit), at(launch), at(ready), at(&announced)];
        if order.contains(&None) || !order.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(format!(
                "service {service}: expected authority, launch, ready, then {announced:?}"
            ));
        }
        if DESKTOP_ROWS.contains(&service) {
            check_bindings(service, ready)?;
        }
        if service == AUDIT {
            check_audit_service(output, pid, audit, ready)?;
        }
        if service == CONSOLE {
            check_console_service(output, pid, audit, ready)?;
        }
        pids[index] = pid;
    }
    let [_, _, console_service, _, serial_shell, compositor, shell, app] = pids;
    let audit_at = |service: u32| {
        output
            .find(&format!("[SVC ] authority service={service} "))
            .unwrap_or(0)
    };

    let port = grant_line(
        output,
        &format!("[GFX ] authority granted pid={compositor} port={COMPOSITOR}:"),
        " rights=serve registered=1",
        audit_at(COMPOSITOR),
    )?;
    let port = format!("{COMPOSITOR}:{port}");
    for (prefix, suffix) in [
        (
            format!("[DISP] authority granted pid={compositor} "),
            "output=0 rights=present,inspect",
        ),
        (
            format!("[SEAT] authority granted pid={compositor} "),
            "seat=0 rights=consume,inspect",
        ),
    ] {
        grant_line(output, &prefix, suffix, audit_at(COMPOSITOR))?;
    }
    for (pid, service, rights) in [
        (shell, DESKTOP_SHELL, "connect,shell"),
        (app, APP, "connect"),
    ] {
        let prefix = format!("[GFX ] authority granted pid={pid} port={port} rights={rights}");
        let rest = grant_line(output, &prefix, "", audit_at(service))?;
        if !rest.is_empty() {
            return Err(format!(
                "expected {prefix:?}, got {:?}",
                only(output, &prefix)?
            ));
        }
    }
    let console_port = grant_line(
        output,
        &format!("[CONS] authority granted pid={console_service} port={CONSOLE}:"),
        " rights=serve registered=1 device=read|write",
        audit_at(CONSOLE),
    )?;
    let console_port = format!("{CONSOLE}:{console_port}");
    // The app's console stream, and the serial shell's, whose console fds go through the
    // console service.
    for (pid, service) in [(app, APP), (serial_shell, SHELL)] {
        let prefix =
            format!("[CONS] authority granted pid={pid} port={console_port} rights=connect");
        if !grant_line(output, &prefix, "", audit_at(service))?.is_empty() {
            return Err(format!(
                "expected {prefix:?}, got {:?}",
                only(output, &prefix)?
            ));
        }
    }
    for prefix in [
        "[GFX ] authority granted",
        "[DISP] authority granted",
        "[SEAT] authority granted",
        "[CONS] authority granted",
    ] {
        let count = lines(output).filter(|line| line.contains(prefix)).count();
        // Three graphics grants (the compositor's port and its two clients) and three console
        // grants (the service's port, the app's stream and the serial shell's).
        let want = if prefix.starts_with("[GFX ]") || prefix.starts_with("[CONS]") {
            3
        } else {
            1
        };
        if count != want {
            return Err(format!("{count} lines {prefix:?}, expected {want}"));
        }
    }

    let compositor_ready = only(output, &format!("[SVC ] ready service={COMPOSITOR} "))?;
    let presents = number(compositor_ready, "presents-submitted")?;
    if presents == 0 {
        return Err(format!(
            "the compositor reported ready before presenting a frame: {compositor_ready:?}"
        ));
    }
    for (pid, line) in [
        (
            compositor,
            format!("[COMP] started output=1280x800 tier={tier}"),
        ),
        (
            shell,
            format!("[SHELL] ready rail=88x800 surfaces=2 dock=none tier={tier}"),
        ),
        // #237: init's launcher port lists the app row.
        (shell, "[SHELL] launcher listed=1".to_owned()),
        (app, "[APP ] ready".to_owned()),
    ] {
        only(output, &format!("[IPC ] console pid={pid}: {line}"))?;
    }
    // The app's line through its console stream: the kernel's tag, then the service's label
    // naming the app's pid, at the start of a line of its own.
    let greeting = format!("[CON ] pid={app}: {APP_CONSOLE_GREETING}");
    if !output.lines().any(|line| line.trim_end() == greeting) {
        return Err(format!(
            "no line {greeting:?} from the app's console stream"
        ));
    }
    Ok(DesktopSummary {
        compositor_pid: compositor,
        shell_pid: shell,
        app_pid: app,
        port,
        presents,
    })
}

/// What the desktop boot types: each desktop row's fault byte (`system-test-hooks`), the row
/// the others depend on first, then a command the serial shell must answer.
const DESKTOP_STEPS: [Step; 4] = [
    Step {
        name: "compositor fault",
        send: b"\x1d",
    },
    Step {
        name: "desktop shell fault",
        send: b"\x1e",
    },
    Step {
        name: "app fault",
        send: b"\x1f",
    },
    Step {
        name: "serial shell",
        send: b"echo hel''lo-desktop\r",
    },
];
/// The desktop row each fault step faults, as an index into [`DESKTOP_ROWS`].
const FAULTED_ROW: [usize; 3] = [0, 1, 2];
pub(crate) const ROW_NAMES: [&str; 3] = ["compositor", "desktop-shell", "app"];
pub(crate) const CLIENT_TAGS: [&str; 3] = ["[COMP]", "[SHELL]", "[APP ]"];
const RESTART_LABELS: [&str; 3] = ["compositor-restart", "desktop-shell-restart", "app-restart"];
pub(crate) const SHELL_ANSWER: &str = "hello-desktop";
const FORBIDDEN: [&str; 2] = [GIVE_UP_LINES[0], GIVE_UP_LINES[1]];

/// One desktop row's live instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Row {
    pub(crate) pid: u64,
    pub(crate) generation: u64,
}

/// The desktop as the lane knows it after the boot or a step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Desktop {
    pub(crate) init_pid: u64,
    /// Compositor, desktop shell, app.
    pub(crate) rows: [Row; 3],
    /// `21248:<generation>`, as the grant lines name the compositor's port.
    port: String,
    /// The `[RSRC] baseline` counts after its pids.
    baseline: String,
}

fn check_desktop_step(
    done: usize,
    segment: &str,
    before: Option<&Desktop>,
) -> Result<Desktop, String> {
    match (done, before) {
        (0, _) => check_baseline_boot(segment, &VIRTIO_GPU_Q1),
        (step, Some(before)) if step <= FAULTED_ROW.len() => {
            check_row_fault(segment, before, FAULTED_ROW[step - 1])
        }
        (_, Some(before)) => {
            if lines(segment)
                .filter_map(console_text)
                .any(|line| line == SHELL_ANSWER)
            {
                Ok(before.clone())
            } else {
                Err(format!("the serial shell has not printed {SHELL_ANSWER:?}"))
            }
        }
        (_, None) => Err("no state before a step".to_owned()),
    }
}

/// The rest of the newline-terminated line in `segment` that starts with `prefix`, and where
/// it starts. A line still arriving does not count.
pub(crate) fn whole_line<'a>(segment: &'a str, prefix: &str) -> Option<(usize, &'a str)> {
    let at = segment.find(prefix)?;
    let rest = &segment[at + prefix.len()..];
    let end = rest.find('\n')?;
    Some((at, rest[..end].trim_end_matches('\r')))
}

fn position(segment: &str, needle: &str) -> Result<usize, String> {
    segment.find(needle).ok_or_else(|| format!("no {needle:?}"))
}

/// The boot: the S6c checks, init settled with eight rows, and the hooks build's resource
/// baseline taken with the three desktop rows' pids.
pub(crate) fn check_baseline_boot(
    segment: &str,
    machine: &DesktopMachine,
) -> Result<Desktop, String> {
    let mut tracker = crate::MarkerTracker::from_steps(&DESKTOP_MARKERS);
    if !tracker.consume(segment) {
        return Err(match tracker.mismatch() {
            Some(mismatch) => format!("boot marker mismatch: {mismatch}"),
            None => format!("boot waiting for {:?}", tracker.pending_label()),
        });
    }
    let summary = check_desktop_boot(segment, machine)?;
    let init_pid = number(only(segment, "[KERN] init launched pid=")?, "pid")?;
    let mut rows = [Row {
        pid: 0,
        generation: 0,
    }; 3];
    for (row, service) in rows.iter_mut().zip(DESKTOP_ROWS) {
        let launch = only(segment, &format!("[SVC ] launch service={service} "))?;
        *row = Row {
            pid: number(launch, "pid")?,
            generation: number(launch, "gen")?,
        };
    }
    let pids = format!(
        "compositor={} desktop-shell={} app={} ",
        summary.compositor_pid, summary.shell_pid, summary.app_pid
    );
    let (_, baseline) = whole_line(segment, &format!("[RSRC] baseline {pids}"))
        .ok_or_else(|| format!("no complete \"[RSRC] baseline {pids}...\" line"))?;
    Ok(Desktop {
        init_pid,
        rows,
        port: summary.port,
        baseline: baseline.to_owned(),
    })
}

/// A restarted row's new instance in `segment`: one launch with a new pid at the next
/// generation, its launch audit, its ready line from that pid, and init's announcement.
/// Returns it with the offsets of its launch and ready lines.
fn check_relaunch(
    segment: &str,
    row: usize,
    before: Row,
    init_pid: u64,
) -> Result<(Row, usize, usize), String> {
    let service = DESKTOP_ROWS[row];
    let name = ROW_NAMES[row];
    let launch = only(segment, &format!("[SVC ] launch service={service} "))
        .map_err(|reason| format!("{name} was not relaunched: {reason}"))?;
    let now = Row {
        pid: number(launch, "pid")?,
        generation: number(launch, "gen")?,
    };
    if now.pid == before.pid || now.generation != before.generation + 1 {
        return Err(format!(
            "{name} relaunched as pid={} gen={}, expected a new pid at gen={}",
            now.pid,
            now.generation,
            before.generation + 1
        ));
    }
    let audit = only(segment, &format!("[SVC ] authority service={service} "))?;
    if audit != expected_audit(service, now.pid) {
        return Err(format!("{name} relaunch audit {audit:?}"));
    }
    let (ready_at, ready) = whole_line(segment, &format!("[SVC ] ready service={service} "))
        .ok_or_else(|| format!("{name} pid={} has not reported ready", now.pid))?;
    if number(ready, "pid")? != now.pid
        || number(ready, "gen")? != now.generation
        || field(ready, "source") != Some("live-instance")
    {
        return Err(format!(
            "{name} relaunched as pid={} but ready says {ready:?}",
            now.pid
        ));
    }
    check_bindings(service, ready)?;
    let announced = format!(
        "[IPC ] console pid={init_pid}: [INIT] service={service} ready gen={}",
        now.generation
    );
    position(segment, &announced)?;
    Ok((now, position(segment, launch)?, ready_at))
}

/// How a desktop row went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Gone {
    /// Its hook byte faulted it.
    Fault,
    /// The app's window was closed and it exited.
    Closed,
}

/// Everything faulting desktop row `row` must cause, in `segment` (the output since its byte
/// was typed), checked in the order it happens so a failure names the first missing piece.
fn check_row_fault(segment: &str, before: &Desktop, row: usize) -> Result<Desktop, String> {
    check_row_gone(segment, before, row, Gone::Fault)
}

/// [`check_row_fault`], or for [`Gone::Closed`] the same restart after the app's own exit.
pub(crate) fn check_row_gone(
    segment: &str,
    before: &Desktop,
    row: usize,
    how: Gone,
) -> Result<Desktop, String> {
    let name = ROW_NAMES[row];
    let victim = before.rows[row];
    let init = before.init_pid;
    let faulted_at = match how {
        Gone::Fault => {
            let armed = format!(
                "[HOOK] {name} fault armed pid={} gen={} user_rip=0x0 parked-in=restart",
                victim.pid, victim.generation
            );
            if whole_line(segment, &armed).is_none() {
                return Err(format!(
                    "hook step: the {name} fault did not arm with its restart wait redirected: no {armed:?}"
                ));
            }
            position(
                segment,
                &format!("[PROC] fault pid={} vector=14 ", victim.pid),
            )?
        }
        Gone::Closed => {
            let exit = format!(
                "[IPC ] console pid={}: {} exit reason=closed",
                victim.pid, CLIENT_TAGS[row]
            );
            let at = position(segment, &exit)
                .map_err(|reason| format!("{name} did not exit closed: {reason}"))?;
            // A native process exits through `int 0x80`, which the kernel logs as vector 128.
            if let Some(line) = lines(segment)
                .find(|line| line.contains("[PROC] fault") && !line.contains(" vector=128 "))
            {
                return Err(format!("a closed {name} faulted: {line:?}"));
            }
            at
        }
    };
    // The faulted row, and on a compositor fault its clients, which must see the port go.
    let gone: &[usize] = if row == 0 { &[0, 1, 2] } else { &[row] };
    // Order first, so a row started early is named even while the rest is still arriving.
    for pair in gone.windows(2) {
        let (dependency, dependent) = (pair[0], pair[1]);
        let restart = format!("[SUP ] restart service={} ", DESKTOP_ROWS[dependent]);
        let ready = format!("[SVC ] ready service={} ", DESKTOP_ROWS[dependency]);
        if let Some(restart_at) = segment.find(&restart) {
            if segment
                .find(&ready)
                .is_none_or(|ready_at| ready_at > restart_at)
            {
                return Err(format!(
                    "order: init restarted {} before the new {} was ready",
                    ROW_NAMES[dependent], ROW_NAMES[dependency]
                ));
            }
        }
    }
    for &index in gone {
        let pid = before.rows[index].pid;
        if index != row {
            let exit = format!(
                "[IPC ] console pid={pid}: {} exit reason=compositor-gone",
                CLIENT_TAGS[index]
            );
            if !segment.contains(&exit) {
                return Err(format!(
                    "{} pid={pid} did not exit with reason=compositor-gone: no {exit:?}",
                    ROW_NAMES[index]
                ));
            }
        }
        let prefix = format!("[SVC ] reaped service={} pid={pid} ", DESKTOP_ROWS[index]);
        let (_, reaped) = whole_line(segment, &prefix).ok_or_else(|| {
            format!(
                "{} pid={pid} was not reaped: no {prefix:?}",
                ROW_NAMES[index]
            )
        })?;
        if reaped != "residue=0" {
            return Err(format!(
                "{} pid={pid} reaped with {reaped:?}",
                ROW_NAMES[index]
            ));
        }
    }
    if let Some(line) = lines(segment).find(|line| line.contains("[SVC ] terminate")) {
        return Err(format!("the kernel terminated a process: {line:?}"));
    }

    // Relaunches, each only once the row before it in dependency order is ready again.
    let mut after = before.clone();
    let mut ready_before = faulted_at;
    let mut previous = "the fault";
    for &index in gone {
        let restart = format!(
            "[IPC ] console pid={init}: [SUP ] restart service={} attempt=1",
            DESKTOP_ROWS[index]
        );
        let restart_at = position(segment, &restart)
            .map_err(|reason| format!("init did not restart {}: {reason}", ROW_NAMES[index]))?;
        let order = || {
            format!(
                "order: init restarted {} before {previous}",
                ROW_NAMES[index]
            )
        };
        if restart_at < ready_before {
            return Err(order());
        }
        let (now, launch_at, ready_at) = check_relaunch(segment, index, before.rows[index], init)?;
        if launch_at < ready_before {
            return Err(order());
        }
        ready_before = ready_at;
        previous = match index {
            0 => "the new compositor was ready",
            _ => "the new desktop shell was ready",
        };
        after.rows[index] = now;
    }
    let restarts = lines(segment)
        .filter(|line| line.contains("[SUP ] restart service="))
        .count();
    if restarts != gone.len() {
        return Err(format!("{restarts} restarts, expected {}", gone.len()));
    }
    for (index, service) in DESKTOP_ROWS.iter().enumerate() {
        if gone.contains(&index) {
            continue;
        }
        let pid = before.rows[index].pid;
        if segment.contains(&format!("[SVC ] launch service={service} "))
            || segment.contains(&format!(
                "[IPC ] console pid={pid}: {} exit",
                CLIENT_TAGS[index]
            ))
        {
            return Err(format!(
                "{} pid={pid} should have kept running through the {name} restart",
                ROW_NAMES[index]
            ));
        }
    }

    // Grants name the live port; after a compositor restart the old generation is refused.
    if row == 0 {
        let prefix = format!(
            "[GFX ] authority granted pid={} port={COMPOSITOR}:",
            after.rows[0].pid
        );
        let (_, rest) = whole_line(segment, &prefix).ok_or_else(|| format!("no {prefix:?}"))?;
        let generation = rest
            .strip_suffix(" rights=serve registered=1")
            .ok_or_else(|| format!("unexpected compositor grant {rest:?}"))?;
        after.port = format!("{COMPOSITOR}:{generation}");
        if after.port == before.port {
            return Err(format!(
                "the new compositor serves the old port {}",
                before.port
            ));
        }
    }
    for (index, rights) in [(1, "connect,shell"), (2, "connect")] {
        if !gone.contains(&index) {
            continue;
        }
        let grant = format!(
            "[GFX ] authority granted pid={} port={} rights={rights}",
            after.rows[index].pid, after.port
        );
        if whole_line(segment, &grant).is_none_or(|(_, rest)| !rest.is_empty()) {
            return Err(format!("{} grant: expected {grant:?}", ROW_NAMES[index]));
        }
        if row == 0 {
            let probe = format!(
                "[HOOK] stale generation probe service={} pid={} port={} live={} result=stale revoked=1",
                DESKTOP_ROWS[index], after.rows[index].pid, before.port, after.port
            );
            if whole_line(segment, &probe).is_none() {
                return Err(format!("stale generation: expected {probe:?}"));
            }
        }
    }
    // A client relaunched later still probes the compositor's retired generation; it must
    // still be refused.
    if let Some(line) = lines(segment).find(|line| {
        line.contains("[HOOK] stale generation") && !line.ends_with(" result=stale revoked=1")
    }) {
        return Err(format!(
            "stale generation: the retired port was not refused: {line:?}"
        ));
    }

    // Back to the baseline once the desktop is quiet, and init settled again.
    let [compositor, shell, app] = after.rows.map(|row| row.pid);
    let prefix =
        format!("[RSRC] snapshot compositor={compositor} desktop-shell={shell} app={app} ");
    let (_, counts) = whole_line(segment, &prefix)
        .ok_or_else(|| format!("residue: no complete {prefix:?} line"))?;
    if counts != before.baseline {
        return Err(format!(
            "residue after the {name} restart: {counts:?}, baseline {:?}",
            before.baseline
        ));
    }
    let compare = format!(
        "[RSRC] compare after={} baseline=match",
        RESTART_LABELS[row]
    );
    if whole_line(segment, &compare).is_none() {
        return Err(format!("residue: no {compare:?}"));
    }
    let settled = format!("[IPC ] console pid={init}: {SETTLED_DESKTOP}");
    if segment.rfind(&settled).is_none_or(|at| at < ready_before) {
        return Err(format!("init has not settled again: no {settled:?}"));
    }
    Ok(after)
}

fn report_step(done: usize, segment: &str, before: &Desktop, after: &Desktop) {
    let Some(&row) = done.checked_sub(1).and_then(|step| FAULTED_ROW.get(step)) else {
        return;
    };
    let _ = report_fault(DESKTOP_STEPS[done - 1].name, row, segment, before, after);
}

/// A fault step's restart timing on the guest's clock, from the hooks build's `at-ms` stamps:
/// each relaunched row's launch and ready, in milliseconds after the fault was armed. Returns
/// the faulted row's relaunch delay when every stamp was there.
pub(crate) fn report_fault(
    step: &str,
    row: usize,
    segment: &str,
    before: &Desktop,
    after: &Desktop,
) -> Option<u64> {
    let stamp = |prefix: String| {
        whole_line(segment, &prefix).and_then(|(_, rest)| number(rest, "at-ms").ok())
    };
    let armed = format!(
        "[HOOK] {} fault armed pid={} ",
        ROW_NAMES[row], before.rows[row].pid
    );
    let armed_at = stamp(armed)?;
    let gone: &[usize] = if row == 0 { &[0, 1, 2] } else { &[row] };
    let since = |at: Option<u64>| at.map_or("?".to_owned(), |at| format!("+{}ms", at - armed_at));
    let timings: Vec<String> = gone
        .iter()
        .map(|&index| {
            let (service, pid) = (DESKTOP_ROWS[index], after.rows[index].pid);
            format!(
                "{} launched {} ready {}",
                ROW_NAMES[index],
                since(stamp(format!(
                    "[HOOK] launched service={service} pid={pid} "
                ))),
                since(stamp(format!("[HOOK] ready service={service} pid={pid} ")))
            )
        })
        .collect();
    println!(
        "\n[STM ] desktop {step:?} guest timing from the fault: {}",
        timings.join(", ")
    );
    let relaunched = stamp(format!(
        "[HOOK] launched service={} pid={} ",
        DESKTOP_ROWS[row], after.rows[row].pid
    ))
    .map(|at| at - armed_at);
    let [compositor, shell, app] = after.rows;
    println!(
        "[STM ] desktop now compositor pid={} gen={} desktop shell pid={} gen={} app pid={} gen={} port {}",
        compositor.pid,
        compositor.generation,
        shell.pid,
        shell.generation,
        app.pid,
        app.generation,
        after.port
    );
    relaunched
}

fn check_framebuffer_tier_boot(output: &str) -> Result<(), String> {
    let backend = only(output, "[DISP] backend=")?;
    if field(backend, "backend") != Some("gop") {
        return Err(format!("expected the framebuffer: {backend:?}"));
    }
    if only(output, "[KERN] boot profile=")? != DESKTOP_PROFILE {
        return Err(format!("no {DESKTOP_PROFILE:?}"));
    }
    let said = lines(output)
        .filter(|line| line.contains(FRAMEBUFFER_TIER))
        .count();
    if said != 1 {
        return Err(format!("expected one {FRAMEBUFFER_TIER:?}, found {said}"));
    }
    for line in [
        "[COMP] started output=1280x800 tier=Q0",
        "[SHELL] ready rail=88x800 surfaces=2 dock=none tier=Q0",
    ] {
        only(output, line)?;
    }
    for service in SERVICES {
        only(output, &format!("[SVC ] ready service={service} "))?;
    }
    Ok(())
}

fn check_no_display_boot(output: &str) -> Result<(), String> {
    if let Some(line) = lines(output).find(|line| line.contains("[DISP] backend=")) {
        return Err(format!("a display was installed: {line:?}"));
    }
    let said = lines(output)
        .filter(|line| line.contains(NO_DISPLAY))
        .count();
    if said != 1 {
        return Err(format!("expected one {NO_DISPLAY:?}, found {said}"));
    }
    if !lines(output).any(|line| line.contains(DESKTOP_PROFILE)) {
        return Err(format!("no {DESKTOP_PROFILE:?}"));
    }
    let launched = only(output, "[KERN] init launched pid=")?;
    check_no_desktop_rows(output, launched)?;
    let init_pid = number(launched, "pid")?;
    only(
        output,
        &format!("[IPC ] console pid={init_pid}: [INIT] boot profile=base"),
    )?;
    for service in [STORAGE, AUDIT, CONSOLE, NETWORK, SHELL] {
        only(output, &format!("[SVC ] ready service={service} "))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const INIT: u64 = 1;

    fn desktop_boot() -> String {
        let mut text = format!(
            "[DISP] backend=virtio-gpu output=0 epoch=1\n\
             {DESKTOP_PROFILE}\n\
             [KERN] init launched pid={INIT} slot=0 declared-services=8\n\
             [IPC ] console pid={INIT}: [INIT] boot profile=desktop tier=Q1\n"
        );
        let rows: [(u32, u64, &str, &str); 8] = [
            (STORAGE, 2, "", "block-write-requests=0 service-reported formatted=1 store-generation=1"),
            (AUDIT, 8, "", "audit-read-through=60 audit-next=61 audit-dropped=40 service-reported first-drain-records=20"),
            (
                CONSOLE,
                9,
                "[CONS] authority granted pid=9 port=22016:9 rights=serve registered=1 device=read|write\n",
                "ports=1 port-connections=0 work-sets=1 service-reported detail=0x0",
            ),
            (NETWORK, 3, "", "raw-backend=virtio service-reported link-up=1"),
            (
                SHELL,
                4,
                "[CONS] authority granted pid=4 port=22016:9 rights=connect\n",
                "first-console-input-wait",
            ),
            (
                COMPOSITOR,
                5,
                "[GFX ] authority granted pid=5 port=21248:7 rights=serve registered=1\n\
                 [DISP] authority granted pid=5 output=0 rights=present,inspect\n\
                 [SEAT] authority granted pid=5 seat=0 rights=consume,inspect\n",
                "ports=1 port-connections=0 presenter=1 presents-submitted=2 input-consumer=1 shared-mappings=2 free-pages=90000 service-reported detail=0x0",
            ),
            (
                DESKTOP_SHELL,
                6,
                "[GFX ] authority granted pid=6 port=21248:7 rights=connect,shell\n",
                "ports=0 port-connections=1 presenter=0 presents-submitted=0 input-consumer=0 shared-mappings=2 free-pages=89000 service-reported detail=0x0",
            ),
            (
                APP,
                7,
                "[GFX ] authority granted pid=7 port=21248:7 rights=connect\n\
                 [CONS] authority granted pid=7 port=22016:9 rights=connect\n",
                "ports=0 port-connections=2 presenter=0 presents-submitted=0 input-consumer=0 shared-mappings=1 free-pages=88000 service-reported detail=0x0",
            ),
        ];
        for (service, pid, grants, observed) in rows {
            text.push_str(&format!(
                "{grants}{}\n\
                 [SVC ] launch service={service} pid={pid} gen=1\n\
                 [SVC ] ready service={service} pid={pid} gen=1 source=live-instance kernel-observed {observed}\n\
                 [IPC ] console pid={INIT}: [INIT] service={service} ready gen=1\n",
                expected_audit(service, pid)
            ));
        }
        let audit_ready = "[SVC ] ready service=21760 ";
        text = text.replace(
            audit_ready,
            &format!(
                "[IPC ] console pid=8: [ADT ] drained through=60 records=20 lost=40\n{audit_ready}"
            ),
        );
        text.push_str(
            "[IPC ] console pid=5: [COMP] started output=1280x800 tier=Q1\n\
             [IPC ] console pid=6: [SHELL] ready rail=88x800 surfaces=2 dock=none tier=Q1\n\
             [IPC ] console pid=6: [SHELL] launcher listed=1\n\
             [IPC ] console pid=7: [APP ] ready\n\
             [CON ] pid=7: playground: console stream open\n",
        );
        text.push_str(&format!("[IPC ] console pid={INIT}: {SETTLED_DESKTOP}\n"));
        text
    }

    #[test]
    fn a_good_desktop_boot_passes_its_markers_and_its_checks() {
        let text = desktop_boot();
        let mut tracker = crate::MarkerTracker::from_steps(&DESKTOP_MARKERS);
        assert!(tracker.consume(&text), "{}", tracker.pending_label());
        assert_eq!(
            check_desktop_boot(&text, &VIRTIO_GPU_Q1),
            Ok(DesktopSummary {
                compositor_pid: 5,
                shell_pid: 6,
                app_pid: 7,
                port: "21248:7".to_owned(),
                presents: 2,
            })
        );
    }

    #[test]
    fn an_extra_right_on_the_app_fails_its_audit_by_name() {
        let audit = expected_audit(APP, 7);
        let text = desktop_boot().replace(&audit, &audit.replace(" input=0", " input=1"));
        let error = check_desktop_boot(&text, &VIRTIO_GPU_Q1).unwrap_err();
        assert!(error.contains("service 21250 launch audit"), "{error}");
        let text = desktop_boot().replace(
            &audit,
            &audit.replace("matches-manifest=1", "matches-manifest=0"),
        );
        assert!(check_desktop_boot(&text, &VIRTIO_GPU_Q1).is_err());
    }

    #[test]
    fn missing_grants_and_bindings_fail_by_name() {
        let text = desktop_boot().replace(
            "[SEAT] authority granted pid=5 seat=0 rights=consume,inspect\n",
            "",
        );
        assert!(check_desktop_boot(&text, &VIRTIO_GPU_Q1)
            .unwrap_err()
            .contains("[SEAT] authority granted"));
        let text = desktop_boot().replace(
            "port=21248:7 rights=connect\n",
            "port=21248:8 rights=connect\n",
        );
        assert!(check_desktop_boot(&text, &VIRTIO_GPU_Q1)
            .unwrap_err()
            .contains("pid=7 port=21248:7"));
        let text = desktop_boot().replace(
            "presenter=1 presents-submitted=2",
            "presenter=0 presents-submitted=2",
        );
        assert!(check_desktop_boot(&text, &VIRTIO_GPU_Q1)
            .unwrap_err()
            .contains("presenter=0 instead of 1"));
        let text = desktop_boot().replace("presents-submitted=2", "presents-submitted=0");
        assert!(check_desktop_boot(&text, &VIRTIO_GPU_Q1)
            .unwrap_err()
            .contains("before presenting a frame"));
        let text = desktop_boot().replace(
            "[IPC ] console pid=5: [COMP] started",
            "[IPC ] console pid=6: [COMP] started",
        );
        assert!(check_desktop_boot(&text, &VIRTIO_GPU_Q1)
            .unwrap_err()
            .contains("[COMP] started"));
    }

    #[test]
    fn the_app_needs_its_console_grant_and_its_own_line_on_the_stream() {
        let text = desktop_boot().replace(
            "[CONS] authority granted pid=7 port=22016:9 rights=connect\n",
            "",
        );
        assert!(check_desktop_boot(&text, &VIRTIO_GPU_Q1)
            .unwrap_err()
            .contains("[CONS] authority granted pid=7"));
        let text = desktop_boot().replace(
            "[CON ] pid=7: playground: console stream open\n",
            "[CON ] pid=6: playground: console stream open\n",
        );
        assert!(check_desktop_boot(&text, &VIRTIO_GPU_Q1)
            .unwrap_err()
            .contains("console stream"));
        let text = desktop_boot().replace(
            "[CON ] pid=7: playground: console stream open\n",
            "[IPC ] console pid=7: [CON ] pid=7: playground: console stream open\n",
        );
        assert!(check_desktop_boot(&text, &VIRTIO_GPU_Q1).is_err());
        let text = desktop_boot().replace(
            "port-connections=2 presenter=0",
            "port-connections=1 presenter=0",
        );
        assert!(check_desktop_boot(&text, &VIRTIO_GPU_Q1)
            .unwrap_err()
            .contains("port-connections=1 instead of 2"));
    }

    #[test]
    fn no_compositor_ready_line_leaves_the_markers_pending_on_it() {
        let text: String = desktop_boot()
            .lines()
            .filter(|line| !line.starts_with("[SVC ] ready service=21248 "))
            .map(|line| format!("{line}\n"))
            .collect();
        let mut tracker = crate::MarkerTracker::from_steps(&DESKTOP_MARKERS);
        assert!(!tracker.consume(&text));
        assert!(
            tracker.pending_label().contains("ready service=21248"),
            "{}",
            tracker.pending_label()
        );
        assert!(check_desktop_boot(&text, &VIRTIO_GPU_Q1)
            .unwrap_err()
            .contains("[SVC ] ready service=21248"));
    }

    #[test]
    fn the_desktop_boot_needs_eight_rows_settled_and_no_restart() {
        let text = desktop_boot().replace("declared-services=8", "declared-services=5");
        let mut tracker = crate::MarkerTracker::from_steps(&DESKTOP_MARKERS);
        tracker.consume(&text);
        assert!(tracker.mismatch().is_some());
        let text = format!(
            "{}[IPC ] console pid=1: [SUP ] restart service=21250 attempt=1\n",
            desktop_boot()
        );
        assert!(check_desktop_boot(&text, &VIRTIO_GPU_Q1)
            .unwrap_err()
            .contains("restart"));
        let text = desktop_boot().replace("running=8", "running=7");
        let mut tracker = crate::MarkerTracker::from_steps(&DESKTOP_MARKERS);
        assert!(!tracker.consume(&text));
    }

    fn no_display_boot() -> String {
        format!(
            "{DESKTOP_PROFILE}\n\
             {NO_DISPLAY}\n\
             [KERN] init launched pid={INIT} slot=0 declared-services=5\n\
             [IPC ] console pid={INIT}: [INIT] boot profile=base\n\
             [SVC ] ready service=20736 pid=2 gen=1 source=live-instance\n\
             [SVC ] ready service=21760 pid=5 gen=1 source=live-instance\n\
             [SVC ] ready service=22016 pid=6 gen=1 source=live-instance\n\
             [SVC ] ready service=20992 pid=3 gen=1 source=live-instance\n\
             [SVC ] ready service=21504 pid=4 gen=1 source=live-instance\n\
             [IPC ] console pid={INIT}: {SETTLED_BASE}\n"
        )
    }

    #[test]
    fn no_display_boots_base_with_one_line() {
        let text = no_display_boot();
        let mut tracker = crate::MarkerTracker::from_steps(&NO_DISPLAY_MARKERS);
        assert!(tracker.consume(&text), "{}", tracker.pending_label());
        assert_eq!(check_no_display_boot(&text), Ok(()));
        let twice = format!("{text}{NO_DISPLAY}\n");
        assert!(check_no_display_boot(&twice)
            .unwrap_err()
            .contains("expected one"));
        let shown = format!("[DISP] backend=gop output=0 epoch=1\n{text}");
        assert!(check_no_display_boot(&shown)
            .unwrap_err()
            .contains("display was installed"));
        let declared = text.replace("declared-services=5", "declared-services=8");
        assert!(check_no_display_boot(&declared)
            .unwrap_err()
            .contains("declared desktop rows"));
    }
}
