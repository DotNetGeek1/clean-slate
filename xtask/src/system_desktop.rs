//! `test-system`'s two desktop boots (#218 S6c), both headless and on the hooks build.
//!
//! 1. **Desktop.** `opt/clean-slate/desktop=q1` and a modern-only VirtIO-GPU: the kernel declares
//!    the three base rows and the compositor, desktop shell and app rows, and init launches all
//!    six. Each desktop row must hold exactly its manifest grants (the kernel's `[GFX ]`, `[DISP]`
//!    and `[SEAT]` grant lines, then a launch audit that matches the row), report ready from its
//!    launched pid with the bindings the kernel observes, and the compositor must have submitted a
//!    frame before it reports ready. Init settles with six rows running. No input is scripted.
//! 2. **No display** (D4). The same entry with `-vga none` and no GPU: the kernel says once that
//!    the desktop has no display output, declares the base rows only, and init boots base.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::system_boot::{
    check_no_desktop_rows, desktop_qemu_args, field, number, start_shell_fixture_peer,
    system_vm_config,
};
use crate::system_shell::{expected_authority as expected_shell_authority, lines};
use crate::{
    run_driven_vm_acceptance, AcceptanceDriver, MarkerSet, MarkerStep, VmLaunchConfig, XtaskError,
};

const STORAGE: u32 = 0x5100;
const NETWORK: u32 = 0x5200;
const SHELL: u32 = 0x5400;
const COMPOSITOR: u32 = 0x5300;
const DESKTOP_SHELL: u32 = 0x5301;
const APP: u32 = 0x5302;
/// In init's start order; network and the shell start with the compositor once storage is ready.
const SERVICES: [u32; 6] = [STORAGE, NETWORK, SHELL, COMPOSITOR, DESKTOP_SHELL, APP];
const DESKTOP_ROWS: [u32; 3] = [COMPOSITOR, DESKTOP_SHELL, APP];
const BOOT_TIMEOUT: Duration = Duration::from_secs(180);
const DESKTOP_PROFILE: &str = "[KERN] boot profile=desktop tier=Q1 source=fw_cfg";
/// `kernel/src/service/system_init.rs` `NO_DISPLAY_LINE`.
const NO_DISPLAY: &str =
    "[KERN] boot profile=desktop has no display output; booting base, desktop rows not declared";
const SETTLED_DESKTOP: &str = "[INIT] boot settled running=6 down=0; waiting, no deadline";
const SETTLED_BASE: &str = "[INIT] boot settled running=3 down=0; waiting, no deadline";
/// A desktop row that never reports ready is restarted until init gives up on it.
const GIVE_UP_LINES: [&str; 2] = ["[INIT] gave up", "[INIT] not starting"];

/// Each desktop row's authority, launch and ready, in the order init must reach them: a row starts
/// only once every row it depends on is ready.
const DESKTOP_MARKERS: [MarkerStep<'static>; 13] = [
    MarkerStep::Line {
        prefix: "[KERN] boot profile=",
        fields: &[
            ("profile=", "desktop"),
            ("tier=", "Q1"),
            ("source=", "fw_cfg"),
        ],
    },
    MarkerStep::Line {
        prefix: "[KERN] init launched pid=",
        fields: &[("declared-services=", "6")],
    },
    MarkerStep::Line {
        prefix: "[INIT] boot profile=",
        fields: &[("profile=", "desktop"), ("tier=", "Q1")],
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
        fields: &[("declared-services=", "3")],
    },
    MarkerStep::Line {
        prefix: "[INIT] boot profile=",
        fields: &[("profile=", "base")],
    },
    MarkerStep::Ordered(SETTLED_BASE),
];

/// Fails the boot as soon as init gives up on a row, and times each desktop row from its launch
/// line to its ready line as the host receives them.
#[derive(Default)]
struct DesktopWatch {
    serial: String,
    launched: [Option<Instant>; 3],
    ready: [Option<Instant>; 3],
}

impl DesktopWatch {
    fn report(&self) {
        for (index, service) in DESKTOP_ROWS.iter().enumerate() {
            if let (Some(launched), Some(ready)) = (self.launched[index], self.ready[index]) {
                println!(
                    "[STM ] desktop row service={service} launch-to-ready={} ms (init's ready timeout is 10000 ms)",
                    ready.duration_since(launched).as_millis()
                );
            }
        }
    }
}

impl AcceptanceDriver for DesktopWatch {
    fn on_serial(&mut self, text: &str, _deadline: Instant) -> Result<(), XtaskError> {
        self.serial.push_str(text);
        let now = Instant::now();
        for (index, service) in DESKTOP_ROWS.iter().enumerate() {
            if self.launched[index].is_none()
                && self
                    .serial
                    .contains(&format!("[SVC ] launch service={service} "))
            {
                self.launched[index] = Some(now);
            }
            if self.ready[index].is_none()
                && self
                    .serial
                    .contains(&format!("[SVC ] ready service={service} "))
            {
                self.ready[index] = Some(now);
            }
        }
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
    println!("[STM ] desktop boot: fw_cfg opt/clean-slate/desktop=q1 with virtio-gpu-pci");
    let mut watch = DesktopWatch::default();
    let output = boot(
        features,
        disk,
        desktop_qemu_args(false),
        &DESKTOP_MARKERS,
        &mut watch,
    )
    .map_err(|error| XtaskError::Validation(format!("desktop boot: {error}")))?;
    watch.report();
    let summary = check_desktop_boot(&output)
        .map_err(|reason| XtaskError::Validation(format!("desktop boot: {reason}")))?;
    println!(
        "[STM ] desktop boot: six rows running; compositor pid={} serves port {} and submitted {} presents before ready, desktop shell pid={} and app pid={} connected to it",
        summary.compositor_pid, summary.port, summary.presents, summary.shell_pid, summary.app_pid
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
fn only<'a>(output: &'a str, prefix: &str) -> Result<&'a str, String> {
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
    let counts = match service {
        STORAGE => "lifecycle-control=0 console=0 block-device=1 object-service=1 network=0 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 other=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0",
        NETWORK => "lifecycle-control=0 console=0 block-device=0 object-service=0 network=1 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 other=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=1",
        COMPOSITOR => "lifecycle-control=0 console=1 block-device=0 object-service=0 network=0 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=1 gfx-shell=0 gfx-client=0 display=1 input=1 other=0 owned-endpoints=0 ports=1 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0",
        DESKTOP_SHELL => "lifecycle-control=0 console=1 block-device=0 object-service=0 network=0 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=1 gfx-client=0 display=0 input=0 other=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0",
        _ => "lifecycle-control=0 console=1 block-device=0 object-service=0 network=0 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=0 gfx-client=1 display=0 input=0 other=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0",
    };
    format!(
        "[SVC ] authority service={service} pid={pid} {counts} linux=0 console-input=0 matches-manifest=1"
    )
}

/// What a desktop row's ready line must show the kernel observed: the compositor serves one port
/// and holds the presenter and the input consumer; each client holds one port connection.
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
            ("port-connections", 1),
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

fn check_desktop_boot(output: &str) -> Result<DesktopSummary, String> {
    let backend = only(output, "[DISP] backend=")?;
    if field(backend, "backend") != Some("virtio-gpu") {
        return Err(format!("expected the VirtIO-GPU display: {backend:?}"));
    }
    let profile = only(output, "[KERN] boot profile=")?;
    if profile != DESKTOP_PROFILE {
        return Err(format!("kernel boot profile {profile:?}"));
    }
    let launched = only(output, "[KERN] init launched pid=")?;
    let init_pid = number(launched, "pid")?;
    if number(launched, "declared-services")? != 6 {
        return Err(format!("expected six declared rows: {launched:?}"));
    }
    let console = format!("[IPC ] console pid={init_pid}: ");
    only(
        output,
        &format!("{console}[INIT] boot profile=desktop tier=Q1"),
    )?;
    for gave in GIVE_UP_LINES
        .iter()
        .chain(&["[FAIL]", "[SUP ] restart service="])
    {
        if let Some(line) = lines(output).find(|line| line.contains(gave)) {
            return Err(format!("{gave:?} in {line:?}"));
        }
    }

    let mut pids = [0u64; 6];
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
        pids[index] = pid;
    }
    let [_, _, _, compositor, shell, app] = pids;
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
    for prefix in [
        "[GFX ] authority granted",
        "[DISP] authority granted",
        "[SEAT] authority granted",
    ] {
        let count = lines(output).filter(|line| line.contains(prefix)).count();
        let want = if prefix.starts_with("[GFX ]") { 3 } else { 1 };
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
        (compositor, "[COMP] started output=1280x800 tier=Q1"),
        (
            shell,
            "[SHELL] ready rail=88x800 surfaces=2 dock=none tier=Q1",
        ),
        (app, "[APP ] ready"),
    ] {
        only(output, &format!("[IPC ] console pid={pid}: {line}"))?;
    }
    Ok(DesktopSummary {
        compositor_pid: compositor,
        shell_pid: shell,
        app_pid: app,
        port,
        presents,
    })
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
    for service in [STORAGE, NETWORK, SHELL] {
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
             [KERN] init launched pid={INIT} slot=0 declared-services=6\n\
             [IPC ] console pid={INIT}: [INIT] boot profile=desktop tier=Q1\n"
        );
        let rows: [(u32, u64, &str, &str); 6] = [
            (STORAGE, 2, "", "block-write-requests=0 service-reported formatted=1 store-generation=1"),
            (NETWORK, 3, "", "raw-backend=virtio service-reported link-up=1"),
            (SHELL, 4, "", "first-console-input-wait"),
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
                "[GFX ] authority granted pid=7 port=21248:7 rights=connect\n",
                "ports=0 port-connections=1 presenter=0 presents-submitted=0 input-consumer=0 shared-mappings=1 free-pages=88000 service-reported detail=0x0",
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
        text.push_str(
            "[IPC ] console pid=5: [COMP] started output=1280x800 tier=Q1\n\
             [IPC ] console pid=6: [SHELL] ready rail=88x800 surfaces=2 dock=none tier=Q1\n\
             [IPC ] console pid=7: [APP ] ready\n",
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
            check_desktop_boot(&text),
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
        let error = check_desktop_boot(&text).unwrap_err();
        assert!(error.contains("service 21250 launch audit"), "{error}");
        let text = desktop_boot().replace(
            &audit,
            &audit.replace("matches-manifest=1", "matches-manifest=0"),
        );
        assert!(check_desktop_boot(&text).is_err());
    }

    #[test]
    fn missing_grants_and_bindings_fail_by_name() {
        let text = desktop_boot().replace(
            "[SEAT] authority granted pid=5 seat=0 rights=consume,inspect\n",
            "",
        );
        assert!(check_desktop_boot(&text)
            .unwrap_err()
            .contains("[SEAT] authority granted"));
        let text = desktop_boot().replace(
            "port=21248:7 rights=connect\n",
            "port=21248:8 rights=connect\n",
        );
        assert!(check_desktop_boot(&text)
            .unwrap_err()
            .contains("pid=7 port=21248:7"));
        let text = desktop_boot().replace(
            "presenter=1 presents-submitted=2",
            "presenter=0 presents-submitted=2",
        );
        assert!(check_desktop_boot(&text)
            .unwrap_err()
            .contains("presenter=0 instead of 1"));
        let text = desktop_boot().replace("presents-submitted=2", "presents-submitted=0");
        assert!(check_desktop_boot(&text)
            .unwrap_err()
            .contains("before presenting a frame"));
        let text = desktop_boot().replace(
            "[IPC ] console pid=5: [COMP] started",
            "[IPC ] console pid=6: [COMP] started",
        );
        assert!(check_desktop_boot(&text)
            .unwrap_err()
            .contains("[COMP] started"));
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
        assert!(check_desktop_boot(&text)
            .unwrap_err()
            .contains("[SVC ] ready service=21248"));
    }

    #[test]
    fn the_desktop_boot_needs_six_rows_settled_and_no_restart() {
        let text = desktop_boot().replace("declared-services=6", "declared-services=3");
        let mut tracker = crate::MarkerTracker::from_steps(&DESKTOP_MARKERS);
        tracker.consume(&text);
        assert!(tracker.mismatch().is_some());
        let text = format!(
            "{}[IPC ] console pid=1: [SUP ] restart service=21250 attempt=1\n",
            desktop_boot()
        );
        assert!(check_desktop_boot(&text).unwrap_err().contains("restart"));
        let text = desktop_boot().replace("running=6", "running=5");
        let mut tracker = crate::MarkerTracker::from_steps(&DESKTOP_MARKERS);
        assert!(!tracker.consume(&text));
    }

    fn no_display_boot() -> String {
        format!(
            "{DESKTOP_PROFILE}\n\
             {NO_DISPLAY}\n\
             [KERN] init launched pid={INIT} slot=0 declared-services=3\n\
             [IPC ] console pid={INIT}: [INIT] boot profile=base\n\
             [SVC ] ready service=20736 pid=2 gen=1 source=live-instance\n\
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
        let declared = text.replace("declared-services=3", "declared-services=6");
        assert!(check_no_display_boot(&declared)
            .unwrap_err()
            .contains("declared desktop rows"));
    }
}
