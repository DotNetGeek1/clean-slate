//! #118 desktop launch policy (P5): the supervised compositor, desktop shell and playground.
//!
//! All three are ordinary native CPL3 services started through the
//! [`ServiceLifecycleController`](super::control::ServiceLifecycleController) from images
//! embedded at build time. This module decides who gets which authority
//! ([`crate::capability::graphics`]), registers the compositor's graphics port, and owns the
//! restart policy:
//!
//! - **Boot.** The compositor, then the shell, start at the end of boot. The app starts at the
//!   first quiescence (every thread blocked, no present in flight), so the shell panel is mapped
//!   first and the app's first window takes focus.
//! - **App exit or crash.** At the next quiescence the desktop resource snapshot is compared with
//!   the baseline (`[RSRC]`), the dead pid's residue is checked, and the app is relaunched with a
//!   fresh pid and generation.
//! - **Compositor exit or crash.** Before the compositor is torn down, its clients are terminated
//!   and a new compositor (next port generation) and shell are started, so the system never runs
//!   out of threads; the app follows at the next quiescence.
//!
//! Every quiescent stretch of [`IDLE_PROOF_NS`] after activity logs `[IDLE ]` with the number of
//! presents submitted during it, which the desktop lane requires to be zero.

use clean_slate_capability::{HolderId, ResourceRef};
use clean_slate_graphics::{
    CLIENT_EVENT_QUEUE_DEPTH, MAX_OUTSTANDING_REQUESTS_PER_CLIENT, SERVER_REQUEST_QUEUE_DEPTH,
};
use clean_slate_native_abi::desktop::{
    DesktopLaunchPage, LAUNCH_FLAG_FAULT_KEY, LAUNCH_TIER_Q1, NO_CONSOLE,
};
use clean_slate_native_abi::PortParams;
use clean_slate_service_lifecycle::{ControlRequest, ControlRequestKind, ServiceId};

use crate::capability::graphics::{grant_desktop_role, GraphicsGrantee};
use crate::diagnostics::log::kernel_log_fmt;
use crate::mm::frame_allocator::PageAllocator;
use crate::process::domain::{
    desktop_resource_snapshot, remaining_owned_resource_count, DesktopResourceSnapshot,
};
use crate::service::control::service_lifecycle_controller_mut;
use crate::sync::global_cell::GlobalCell;

pub(crate) const COMPOSITOR_SERVICE_ID: ServiceId = ServiceId(0x5300);
pub(crate) const SHELL_SERVICE_ID: ServiceId = ServiceId(0x5301);
pub(crate) const PLAYGROUND_SERVICE_ID: ServiceId = ServiceId(0x5302);

/// A quiet stretch this long after activity is reported as the idle proof.
pub(crate) const IDLE_PROOF_NS: u64 = 500_000_000;
/// Automatic relaunches per role before the policy gives up (a crash loop must not spin).
const RELAUNCH_BUDGET: u8 = 8;

/// The compositor's service port: one connection per holder, the shell plus a few apps.
pub(crate) const COMPOSITOR_PORT_PARAMS: PortParams = PortParams {
    event_depth: CLIENT_EVENT_QUEUE_DEPTH as u16,
    request_depth: SERVER_REQUEST_QUEUE_DEPTH as u16,
    max_connections: 4,
    max_outstanding: MAX_OUTSTANDING_REQUESTS_PER_CLIENT as u16,
    max_connections_per_holder: 1,
};

const _: () = assert!(COMPOSITOR_PORT_PARAMS.validate().is_ok());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DesktopRole {
    Compositor,
    Shell,
    App,
}

impl DesktopRole {
    const ALL: [Self; 3] = [Self::Compositor, Self::Shell, Self::App];

    pub(crate) const fn service(self) -> ServiceId {
        match self {
            Self::Compositor => COMPOSITOR_SERVICE_ID,
            Self::Shell => SHELL_SERVICE_ID,
            Self::App => PLAYGROUND_SERVICE_ID,
        }
    }

    /// User stack pages (the compositor composes on its stack; clients only paint).
    pub(crate) const fn stack_pages(self) -> u64 {
        match self {
            Self::Compositor => 64,
            Self::Shell | Self::App => 32,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Compositor => "compositor",
            Self::Shell => "shell",
            Self::App => "app",
        }
    }

    const fn grantee(self) -> GraphicsGrantee {
        match self {
            Self::Compositor => GraphicsGrantee::Compositor,
            Self::Shell => GraphicsGrantee::Shell,
            Self::App => GraphicsGrantee::App,
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Why the next quiescence compares the snapshot with the baseline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reason {
    AppExit,
    CompositorRestart,
}

impl Reason {
    const fn name(self) -> &'static str {
        match self {
            Self::AppExit => "app-exit",
            Self::CompositorRestart => "compositor-restart",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct IdleWindow {
    since_ns: u64,
    submitted_seq: u64,
}

struct DesktopState {
    live: [Option<u64>; 3],
    relaunches: [u8; 3],
    /// Graphics port resource of the live compositor generation.
    graphics: Option<ResourceRef>,
    app_pending: bool,
    shell_pending: bool,
    baseline: Option<DesktopResourceSnapshot>,
    compare: Option<Reason>,
    /// Pids whose residue the next quiescence checks.
    reaped: [Option<(DesktopRole, u64)>; 3],
    idle: Option<IdleWindow>,
    idle_reported: bool,
}

impl DesktopState {
    const fn new() -> Self {
        Self {
            live: [None; 3],
            relaunches: [0; 3],
            graphics: None,
            app_pending: false,
            shell_pending: false,
            baseline: None,
            compare: None,
            reaped: [None; 3],
            idle: None,
            idle_reported: false,
        }
    }

    fn role_of(&self, pid: u64) -> Option<DesktopRole> {
        DesktopRole::ALL
            .into_iter()
            .find(|role| self.live[role.index()] == Some(pid))
    }

    fn note_reaped(&mut self, role: DesktopRole, pid: u64) {
        self.live[role.index()] = None;
        if let Some(slot) = self.reaped.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some((role, pid));
        }
    }
}

static STATE: GlobalCell<DesktopState> = GlobalCell::new(DesktopState::new());

fn state() -> &'static mut DesktopState {
    unsafe { &mut *STATE.get() }
}

/// What `spawn` writes at the launch address for `role`'s new `pid`: the graphics resource id, a
/// console handle and the build's flags. Authority is granted separately, after registration.
pub(crate) fn launch_page_for(pid: u64) -> DesktopLaunchPage {
    let console_handle = unsafe { crate::ipc::endpoint_table_mut() }
        .grant_console_capability_for_pid(pid)
        .unwrap_or(NO_CONSOLE);
    DesktopLaunchPage {
        self_pid: pid,
        graphics_resource_id: u64::from(COMPOSITOR_SERVICE_ID.0),
        console_handle,
        flags: if cfg!(feature = "m10-desktop-self-test") {
            LAUNCH_FLAG_FAULT_KEY
        } else {
            0
        },
        tier: LAUNCH_TIER_Q1,
    }
}

/// Boot tail: declares the three services and starts the compositor and the shell.
pub(crate) fn start_desktop(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    let controller = unsafe { service_lifecycle_controller_mut() };
    for role in DesktopRole::ALL {
        controller.declare_service(role.service())?;
    }
    start_role(allocator, DesktopRole::Compositor)?;
    start_role(allocator, DesktopRole::Shell)?;
    state().app_pending = true;
    Ok(())
}

/// `Start` through the controller, then the role's grants (and, for the compositor, its port).
/// Interrupts are off on every caller, so the Ready process cannot run before it is wired.
fn start_role(allocator: &mut PageAllocator, role: DesktopRole) -> Result<u64, &'static str> {
    let controller = unsafe { service_lifecycle_controller_mut() };
    controller
        .handle_control_request(
            allocator,
            0,
            ControlRequest::new(role.service(), ControlRequestKind::Start),
        )
        .map_err(|_| "desktop: controller Start failed")?;
    let pid = controller
        .live_pid(role.service())
        .ok_or("desktop: Start left no live process")?;
    if let Err(message) = wire_role(role, pid) {
        kernel_log_fmt(format_args!(
            "[DESK] wiring failed role={} pid={pid}: {message}\n",
            role.name()
        ));
        let _ = controller.handle_control_request(
            allocator,
            0,
            ControlRequest::new(role.service(), ControlRequestKind::Terminate),
        );
        return Err(message);
    }
    let desktop = state();
    desktop.live[role.index()] = Some(pid);
    let generation = crate::process::live_instance_generation(pid).map_or(0, |g| g.0);
    kernel_log_fmt(format_args!(
        "[DESK] launch role={} pid={pid} gen={generation}\n",
        role.name()
    ));
    Ok(pid)
}

fn wire_role(role: DesktopRole, pid: u64) -> Result<(), &'static str> {
    let holder = HolderId(pid);
    let desktop = state();
    let graphics = match role {
        DesktopRole::Compositor => {
            let generation = crate::process::live_instance_generation(pid)
                .ok_or("desktop: compositor has no instance generation")?;
            let resource =
                ResourceRef::graphics(u64::from(COMPOSITOR_SERVICE_ID.0), u64::from(generation.0));
            super::port::register_port(resource, holder, generation, COMPOSITOR_PORT_PARAMS)
                .map_err(|_| "desktop: compositor port registration failed")?;
            desktop.graphics = Some(resource);
            resource
        }
        DesktopRole::Shell | DesktopRole::App => desktop
            .graphics
            .ok_or("desktop: no live compositor port to connect to")?,
    };
    grant_desktop_role(holder, role.grantee(), graphics)
        .map_err(|_| "desktop: capability grant failed")
}

fn terminate_role(allocator: &mut PageAllocator, role: DesktopRole) {
    let Some(pid) = state().live[role.index()] else {
        return;
    };
    let controller = unsafe { service_lifecycle_controller_mut() };
    if controller
        .handle_control_request(
            allocator,
            0,
            ControlRequest::new(role.service(), ControlRequestKind::Terminate),
        )
        .is_ok()
    {
        state().note_reaped(role, pid);
    }
}

fn take_relaunch(role: DesktopRole) -> bool {
    let budget = &mut state().relaunches[role.index()];
    if *budget >= RELAUNCH_BUDGET {
        kernel_log_fmt(format_args!(
            "[DESK] relaunch budget exhausted role={}\n",
            role.name()
        ));
        return false;
    }
    *budget += 1;
    true
}

/// The faulting-exception path (exit `int 0x80` and crashes alike), after the lifecycle fault was
/// published and before `pid` is torn down. A compositor death replaces the compositor and shell
/// here, while the dying compositor still occupies its slot, so a thread always remains.
pub(crate) fn on_process_exiting(allocator: &mut PageAllocator, pid: u64, vector: u64) {
    let Some(role) = state().role_of(pid) else {
        return;
    };
    let reason = if vector == 0x80 { "exit" } else { "crash" };
    kernel_log_fmt(format_args!(
        "[DESK] exit role={} pid={pid} reason={reason} vector={vector}\n",
        role.name()
    ));
    state().note_reaped(role, pid);
    match role {
        DesktopRole::App => {
            state().app_pending = take_relaunch(role);
            state().compare = Some(Reason::AppExit);
        }
        DesktopRole::Shell => state().shell_pending = take_relaunch(role),
        DesktopRole::Compositor => {
            terminate_role(allocator, DesktopRole::App);
            terminate_role(allocator, DesktopRole::Shell);
            state().graphics = None;
            if !take_relaunch(role) {
                return;
            }
            if start_role(allocator, DesktopRole::Compositor).is_err() {
                return;
            }
            let _ = start_role(allocator, DesktopRole::Shell);
            state().app_pending = true;
            state().compare = Some(Reason::CompositorRestart);
        }
    }
}

/// The idle thread found nothing runnable (interrupts off, idle stack). Runs pending launches at
/// quiescence and the idle proof. Returns `true` when it made a thread Ready.
pub(crate) fn on_idle(now_ns: u64) -> bool {
    let status = crate::device::display::with_active_display(|display| {
        display.map(|display| display.state().status())
    });
    let presenting = status.is_some_and(|status| status.in_flight_index.is_some());
    let submitted_seq = status.map_or(0, |status| status.submitted_seq);
    if presenting {
        state().idle = None;
        return false;
    }
    let desktop = state();
    if desktop.app_pending || desktop.shell_pending {
        return quiescent_launch();
    }
    match desktop.idle {
        None => {
            desktop.idle = Some(IdleWindow {
                since_ns: now_ns,
                submitted_seq,
            })
        }
        Some(window)
            if !desktop.idle_reported
                && now_ns.saturating_sub(window.since_ns) >= IDLE_PROOF_NS =>
        {
            desktop.idle_reported = true;
            kernel_log_fmt(format_args!(
                "[IDLE ] quiet ms={} presents={} seq={submitted_seq}\n",
                now_ns.saturating_sub(window.since_ns) / 1_000_000,
                submitted_seq.saturating_sub(window.submitted_seq)
            ));
        }
        Some(_) => {}
    }
    false
}

/// The idle thread is about to dispatch a thread: the quiet stretch, if any, ends.
pub(crate) fn on_idle_exit() {
    let desktop = state();
    desktop.idle = None;
    desktop.idle_reported = false;
}

fn quiescent_launch() -> bool {
    let Some(allocator) = crate::syscall::service_lifecycle_syscall_allocator_mut().as_mut() else {
        return false;
    };
    let desktop = state();
    let snapshot = desktop_resource_snapshot();
    log_snapshot(desktop.baseline.is_none().then_some("baseline"), &snapshot);
    match (desktop.baseline, desktop.compare.take()) {
        (None, _) => desktop.baseline = Some(snapshot),
        (Some(baseline), Some(reason)) => {
            kernel_log_fmt(format_args!(
                "[RSRC] compare after={} baseline={}\n",
                reason.name(),
                if baseline == snapshot {
                    "match"
                } else {
                    "mismatch"
                }
            ));
        }
        (Some(_), None) => {}
    }
    for slot in &mut desktop.reaped {
        if let Some((role, pid)) = slot.take() {
            kernel_log_fmt(format_args!(
                "[RSRC] reaped role={} pid={pid} residue={}\n",
                role.name(),
                remaining_owned_resource_count(pid)
            ));
        }
    }
    let mut launched = false;
    if core::mem::take(&mut desktop.shell_pending) {
        launched |= start_role(allocator, DesktopRole::Shell).is_ok();
    }
    if core::mem::take(&mut state().app_pending) {
        launched |= start_role(allocator, DesktopRole::App).is_ok();
    }
    launched
}

fn log_snapshot(label: Option<&str>, s: &DesktopResourceSnapshot) {
    kernel_log_fmt(format_args!(
        "[RSRC] {} procs={} caps={} ws={} ports={} conns={} qreq={} qev={} xfer={} bufs={} pages={} maps={} presenter={} wake={} consumer={} scanout={} gpu={}\n",
        label.unwrap_or("snapshot"),
        s.processes,
        s.capabilities,
        s.work_sets,
        s.ports,
        s.port_connections,
        s.port_queued_requests,
        s.port_queued_events,
        s.port_undelivered_transfers,
        s.shared_buffers,
        s.shared_buffer_pages,
        s.shared_mappings,
        u8::from(s.presenter_bound),
        u8::from(s.presenter_wake_bound),
        u8::from(s.input_consumer_bound),
        s.scanout_buffers,
        s.gpu_resources,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_ids_and_roles_round_trip() {
        assert_eq!(COMPOSITOR_SERVICE_ID.0, 0x5300);
        assert_eq!(SHELL_SERVICE_ID.0, 0x5301);
        assert_eq!(PLAYGROUND_SERVICE_ID.0, 0x5302);
        for (index, role) in DesktopRole::ALL.into_iter().enumerate() {
            assert_eq!(role.index(), index);
        }
        assert_eq!(
            DesktopRole::Compositor.grantee(),
            GraphicsGrantee::Compositor
        );
        assert_eq!(DesktopRole::App.grantee(), GraphicsGrantee::App);
    }

    #[test]
    fn port_admits_the_shell_and_apps_one_connection_each() {
        assert_eq!(COMPOSITOR_PORT_PARAMS.validate(), Ok(()));
        assert_eq!(COMPOSITOR_PORT_PARAMS.max_connections_per_holder, 1);
        assert!(COMPOSITOR_PORT_PARAMS.max_connections >= 2);
    }

    #[test]
    fn live_pids_map_back_to_roles_and_reaping_clears_them() {
        let mut desktop = DesktopState::new();
        desktop.live = [Some(10), Some(11), Some(12)];
        assert_eq!(desktop.role_of(12), Some(DesktopRole::App));
        desktop.note_reaped(DesktopRole::App, 12);
        assert_eq!(desktop.role_of(12), None);
        assert_eq!(desktop.reaped[0], Some((DesktopRole::App, 12)));
        assert_eq!(desktop.role_of(10), Some(DesktopRole::Compositor));
    }
}
