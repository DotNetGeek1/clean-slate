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
//! - **Compositor exit or crash.** Before the compositor is torn down, its clients are terminated.
//!   Its teardown then releases the graphics port, the presenter and the input consumer, and the
//!   idle thread starts a new compositor (next port generation) and shell at the next quiescence;
//!   the app follows at the quiescence after that, as at boot.
//! - **Failed launch.** A launch that fails (spawn or wiring) costs one relaunch and is retried at
//!   the next idle pass. With the budget spent the role stays down, the kernel logs
//!   `[DESK] stopped` once nothing is left to run, and the idle thread keeps running.
//!
//! Every quiescent stretch of [`IDLE_PROOF_NS`] after activity logs `[IDLE ]` with the number of
//! presents submitted during it, which the desktop lane requires to be zero.

use clean_slate_capability::{
    CapabilityHandle, CapabilityState, HolderId, ResourceClass, ResourceRef,
};
use clean_slate_graphics::{
    CLIENT_EVENT_QUEUE_DEPTH, MAX_OUTSTANDING_REQUESTS_PER_CLIENT, SERVER_REQUEST_QUEUE_DEPTH,
};
use clean_slate_native_abi::desktop::{
    DesktopLaunchPage, LAUNCH_FLAG_FAULT_KEY, LAUNCH_TIER_Q0, LAUNCH_TIER_Q1, NO_CONSOLE,
};
use clean_slate_native_abi::port::PORT_ROLE_CONNECT;
use clean_slate_native_abi::PortParams;
use clean_slate_port::{PortError, RegistrationError};
use clean_slate_service_lifecycle::{ControlRequest, ControlRequestKind, ServiceId};

use crate::capability::graphics::{grant_desktop_role, GraphicsGrantee};
use crate::diagnostics::log::{kernel_log_fmt, kernel_log_line};
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

/// What one quiescence launches. The compositor goes first, alone with the shell, so the app
/// connects to a compositor that has already mapped the shell panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Quiescence {
    Nothing,
    /// Start the compositor, then the shell if it is pending; the app waits a quiescence.
    Compositor,
    /// Snapshot and compare, then start whichever clients are pending.
    Clients {
        shell: bool,
        app: bool,
    },
}

struct DesktopState {
    started: bool,
    live: [Option<u64>; 3],
    relaunches: [u8; 3],
    /// Roles the next quiescence starts.
    pending: [bool; 3],
    /// Graphics port resource of the live compositor generation.
    graphics: Option<ResourceRef>,
    baseline: Option<DesktopResourceSnapshot>,
    compare: Option<Reason>,
    /// Pids whose residue the next quiescence checks.
    reaped: [Option<(DesktopRole, u64)>; 3],
    idle: Option<IdleWindow>,
    idle_reported: bool,
    stopped_reported: bool,
    /// The live app's graphics handle, which its successor must fail to use.
    app_handle: Option<CapabilityHandle>,
}

impl DesktopState {
    const fn new() -> Self {
        Self {
            started: false,
            live: [None; 3],
            relaunches: [0; 3],
            pending: [false; 3],
            graphics: None,
            baseline: None,
            compare: None,
            reaped: [None; 3],
            idle: None,
            idle_reported: false,
            stopped_reported: false,
            app_handle: None,
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

    fn note_launched(&mut self, role: DesktopRole, pid: u64) {
        self.live[role.index()] = Some(pid);
        self.stopped_reported = false;
    }

    /// Spends one relaunch of `role` and marks it pending; `false` once the budget is spent.
    fn take_relaunch(&mut self, role: DesktopRole) -> bool {
        let budget = &mut self.relaunches[role.index()];
        let granted = *budget < RELAUNCH_BUDGET;
        if granted {
            *budget += 1;
        }
        self.pending[role.index()] = granted;
        granted
    }

    /// `pid` (in `role`) is exiting and has not been torn down yet. Returns the live clients the
    /// caller terminates: a compositor's clients hold connections and surfaces on a port that its
    /// teardown is about to close, so they are relaunched against the new one.
    fn on_exit(&mut self, role: DesktopRole, pid: u64) -> ([Option<DesktopRole>; 2], bool) {
        self.note_reaped(role, pid);
        match role {
            DesktopRole::App => {
                self.compare = Some(Reason::AppExit);
                ([None; 2], self.take_relaunch(role))
            }
            DesktopRole::Shell => ([None; 2], self.take_relaunch(role)),
            DesktopRole::Compositor => {
                self.graphics = None;
                let clients = [DesktopRole::App, DesktopRole::Shell]
                    .map(|client| self.live[client.index()].map(|_| client));
                let relaunch = self.take_relaunch(role);
                if relaunch {
                    self.pending[DesktopRole::Shell.index()] = true;
                    self.pending[DesktopRole::App.index()] = true;
                    self.compare = Some(Reason::CompositorRestart);
                }
                (clients, relaunch)
            }
        }
    }

    /// Takes what this quiescence launches. Clients need a compositor: with none running or
    /// pending, their launches are dropped.
    fn take_quiescence(&mut self) -> Quiescence {
        let [compositor, shell, app] = self.pending;
        if compositor {
            self.pending[DesktopRole::Compositor.index()] = false;
            return Quiescence::Compositor;
        }
        if !(shell || app) {
            return Quiescence::Nothing;
        }
        self.pending[DesktopRole::Shell.index()] = false;
        self.pending[DesktopRole::App.index()] = false;
        if self.live[DesktopRole::Compositor.index()].is_none() {
            return Quiescence::Nothing;
        }
        Quiescence::Clients { shell, app }
    }

    fn has_pending(&self) -> bool {
        self.pending.iter().any(|pending| *pending)
    }

    /// Nothing runs and nothing will be launched; reported once per stop.
    fn take_stopped(&mut self) -> bool {
        let stopped = self.started
            && !self.stopped_reported
            && !self.has_pending()
            && self.live.iter().all(Option::is_none);
        self.stopped_reported |= stopped;
        stopped
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
        tier: if cfg!(feature = "m10-desktop-q0") {
            LAUNCH_TIER_Q0
        } else {
            LAUNCH_TIER_Q1
        },
    }
}

/// Boot tail: declares the three services and starts the compositor and the shell.
pub(crate) fn start_desktop(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    let controller = unsafe { service_lifecycle_controller_mut() };
    for role in DesktopRole::ALL {
        controller.declare_service(role.service())?;
    }
    state().started = true;
    start_role(allocator, DesktopRole::Compositor)?;
    start_role(allocator, DesktopRole::Shell)?;
    state().pending[DesktopRole::App.index()] = true;
    Ok(())
}

/// [`start_role`] for a relaunch: a failure spends one more relaunch and retries next idle pass.
fn relaunch_role(allocator: &mut PageAllocator, role: DesktopRole) -> bool {
    if start_role(allocator, role).is_ok() {
        return true;
    }
    if !state().take_relaunch(role) {
        log_budget_exhausted(role);
    }
    false
}

fn log_budget_exhausted(role: DesktopRole) {
    kernel_log_fmt(format_args!(
        "[DESK] relaunch budget exhausted role={}\n",
        role.name()
    ));
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
    state().note_launched(role, pid);
    let generation = crate::process::live_instance_generation(pid).map_or(0, |g| g.0);
    kernel_log_fmt(format_args!(
        "[DESK] launch role={} pid={pid} gen={generation}\n",
        role.name()
    ));
    if role == DesktopRole::App {
        probe_stale_app_handle(pid);
    }
    Ok(pid)
}

/// The new app tries its predecessor's graphics handle (revoked at teardown, so its slot
/// generation is gone), then the new handle is remembered for its own successor.
///
/// The probe runs as the new app, so a handle that survived teardown would still be refused for
/// naming another holder. Only a `Stale` refusal of a handle the table no longer holds proves the
/// revocation.
fn probe_stale_app_handle(pid: u64) {
    let holder = HolderId(pid);
    let graphics_class = ResourceClass::Graphics;
    let graphics_id = u64::from(COMPOSITOR_SERVICE_ID.0);
    let desktop = state();
    if let Some(stale) = desktop.app_handle.take() {
        let outcome =
            super::port::kernel_client_connect(holder, stale, graphics_class, graphics_id);
        if let Ok(connection) = outcome {
            let _ = super::port::kernel_client_close(holder, connection, 0);
        }
        let revoked = !is_live_handle(stale);
        kernel_log_fmt(format_args!(
            "[RSRC] stale handle pid={pid} handle={:#x} rejected={} revoked={} result={}\n",
            stale.encode(),
            u8::from(stale_handle_rejected(outcome, revoked)),
            u8::from(revoked),
            connect_outcome_name(outcome)
        ));
    }
    desktop.app_handle = super::port::find_handle(
        holder,
        u64::from(graphics_class.as_u8()),
        graphics_id,
        PORT_ROLE_CONNECT,
    )
    .ok()
    .and_then(|raw| CapabilityHandle::decode(raw).ok());
}

fn is_live_handle(handle: CapabilityHandle) -> bool {
    crate::capability::with_capability_space(|table| {
        table
            .record(handle)
            .is_ok_and(|record| record.state == CapabilityState::Live)
    })
}

fn stale_handle_rejected<T>(outcome: Result<T, PortError>, revoked: bool) -> bool {
    revoked && matches!(outcome, Err(PortError::Stale))
}

fn connect_outcome_name<T>(outcome: Result<T, PortError>) -> &'static str {
    match outcome {
        Ok(_) => "connected",
        Err(PortError::Stale) => "stale",
        Err(PortError::Denied) => "denied",
        Err(PortError::Refused) => "refused",
        Err(PortError::Invalid) => "invalid",
        Err(PortError::NoSpace) => "nospace",
        Err(_) => "other",
    }
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
                .map_err(registration_failure)?;
            resource
        }
        DesktopRole::Shell | DesktopRole::App => desktop
            .graphics
            .ok_or("desktop: no live compositor port to connect to")?,
    };
    grant_desktop_role(holder, role.grantee(), graphics)
        .map_err(|_| "desktop: capability grant failed")?;
    if role == DesktopRole::Compositor {
        desktop.graphics = Some(graphics);
    }
    Ok(())
}

fn registration_failure(error: RegistrationError) -> &'static str {
    match error {
        RegistrationError::AlreadyRegistered => {
            "desktop: compositor port registration failed: a previous instance still serves it"
        }
        RegistrationError::RegistryFull => {
            "desktop: compositor port registration failed: port registry full"
        }
        RegistrationError::ServerNotLive => {
            "desktop: compositor port registration failed: server not live"
        }
        RegistrationError::ClassHasNoPort | RegistrationError::Params(_) => {
            "desktop: compositor port registration failed: invalid port"
        }
    }
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

/// The faulting-exception path (exit `int 0x80` and crashes alike), after the lifecycle fault was
/// published and before `pid` is torn down. Nothing is launched here: the dying process still
/// holds what its teardown releases (a compositor's port registration among them), so
/// replacements start from the idle thread once that teardown has run.
pub(crate) fn on_process_exiting(allocator: &mut PageAllocator, pid: u64, vector: u64) {
    let Some(role) = state().role_of(pid) else {
        return;
    };
    let reason = if vector == 0x80 { "exit" } else { "crash" };
    kernel_log_fmt(format_args!(
        "[DESK] exit role={} pid={pid} reason={reason} vector={vector}\n",
        role.name()
    ));
    let (clients, relaunch) = state().on_exit(role, pid);
    if !relaunch {
        log_budget_exhausted(role);
    }
    for client in clients.into_iter().flatten() {
        terminate_role(allocator, client);
    }
}

/// The idle thread is about to halt (interrupts off, idle stack). Runs pending launches at
/// quiescence and the idle proof. Returns `true` when a thread is Ready, so the idle thread
/// dispatches it instead of halting.
///
/// The idle thread is also entered straight from an exit's teardown, which picks the next thread
/// before its release hooks run; a hook that wakes a server (a client's exit notice) leaves that
/// server Ready here, and the snapshot must wait until it has handled the notice.
pub(crate) fn on_idle(now_ns: u64) -> bool {
    if unsafe { crate::sched::scheduler_mut() }.has_runnable_threads() {
        state().idle = None;
        return true;
    }
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
    if desktop.has_pending() {
        return quiescent_launch();
    }
    if desktop.take_stopped() {
        kernel_log_line(
            "[DESK] stopped: no desktop process is running and none will be relaunched; kernel idle",
        );
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
    let (shell, app) = match state().take_quiescence() {
        Quiescence::Nothing => return false,
        Quiescence::Compositor => {
            if !relaunch_role(allocator, DesktopRole::Compositor) {
                return false;
            }
            let desktop = state();
            if core::mem::take(&mut desktop.pending[DesktopRole::Shell.index()]) {
                relaunch_role(allocator, DesktopRole::Shell);
            }
            return true;
        }
        Quiescence::Clients { shell, app } => (shell, app),
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
    if shell {
        launched |= relaunch_role(allocator, DesktopRole::Shell);
    }
    if app {
        launched |= relaunch_role(allocator, DesktopRole::App);
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
        assert_eq!(COMPOSITOR_PORT_PARAMS.max_connections, 4);
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

    fn running_desktop() -> DesktopState {
        let mut desktop = DesktopState::new();
        desktop.started = true;
        desktop.live = [Some(10), Some(11), Some(12)];
        desktop.graphics = Some(ResourceRef::graphics(0x5300, 1));
        desktop
    }

    #[test]
    fn compositor_exit_with_live_clients_relaunches_after_teardown_in_boot_order() {
        let mut desktop = running_desktop();
        let (clients, relaunch) = desktop.on_exit(DesktopRole::Compositor, 10);
        assert!(relaunch);
        assert_eq!(
            clients,
            [Some(DesktopRole::App), Some(DesktopRole::Shell)],
            "both clients are terminated before the compositor's teardown"
        );
        assert_eq!(desktop.graphics, None);
        assert_eq!(desktop.compare, Some(Reason::CompositorRestart));
        assert_eq!(desktop.live, [None, Some(11), Some(12)]);

        assert_eq!(desktop.take_quiescence(), Quiescence::Compositor);
        desktop.note_launched(DesktopRole::Compositor, 15);
        assert!(core::mem::take(
            &mut desktop.pending[DesktopRole::Shell.index()]
        ));
        assert_eq!(
            desktop.take_quiescence(),
            Quiescence::Clients {
                shell: false,
                app: true
            }
        );
        assert_eq!(desktop.take_quiescence(), Quiescence::Nothing);
        assert_eq!(desktop.relaunches, [1, 0, 0], "clients cost no relaunch");
    }

    #[test]
    fn a_failed_compositor_relaunch_is_retried_then_succeeds() {
        let mut desktop = running_desktop();
        desktop.on_exit(DesktopRole::Compositor, 10);
        assert_eq!(desktop.take_quiescence(), Quiescence::Compositor);
        assert!(
            desktop.take_relaunch(DesktopRole::Compositor),
            "wiring failed once"
        );
        assert_eq!(desktop.take_quiescence(), Quiescence::Compositor);
        desktop.note_launched(DesktopRole::Compositor, 16);
        assert_eq!(desktop.relaunches[DesktopRole::Compositor.index()], 2);
        assert!(desktop.pending[DesktopRole::Shell.index()]);
        assert!(desktop.pending[DesktopRole::App.index()]);
    }

    #[test]
    fn a_spent_budget_stops_the_desktop_once_and_drops_client_launches() {
        let mut desktop = running_desktop();
        desktop.relaunches[DesktopRole::Compositor.index()] = RELAUNCH_BUDGET - 1;
        desktop.on_exit(DesktopRole::Compositor, 10);
        assert_eq!(desktop.take_quiescence(), Quiescence::Compositor);
        assert!(!desktop.take_relaunch(DesktopRole::Compositor));
        assert!(!desktop.pending[DesktopRole::Compositor.index()]);
        assert!(desktop.has_pending(), "clients still pending");
        assert!(!desktop.take_stopped(), "pending launches are not a stop");
        assert_eq!(
            desktop.take_quiescence(),
            Quiescence::Nothing,
            "no compositor to connect to"
        );
        assert!(!desktop.has_pending());
        desktop.note_reaped(DesktopRole::Shell, 11);
        desktop.note_reaped(DesktopRole::App, 12);
        assert!(desktop.take_stopped());
        assert!(!desktop.take_stopped(), "reported once");
    }

    #[test]
    fn app_and_shell_exits_relaunch_only_themselves() {
        let mut desktop = running_desktop();
        assert_eq!(desktop.on_exit(DesktopRole::App, 12), ([None; 2], true));
        assert_eq!(desktop.compare, Some(Reason::AppExit));
        assert_eq!(
            desktop.take_quiescence(),
            Quiescence::Clients {
                shell: false,
                app: true
            }
        );
        assert_eq!(desktop.on_exit(DesktopRole::Shell, 11), ([None; 2], true));
        assert_eq!(
            desktop.take_quiescence(),
            Quiescence::Clients {
                shell: true,
                app: false
            }
        );
        assert_eq!(desktop.live[DesktopRole::Compositor.index()], Some(10));
        assert!(!DesktopState::new().take_stopped(), "not before boot");
    }

    #[test]
    fn the_stale_handle_probe_requires_a_revoked_handle_refused_as_stale() {
        let connected: Result<(), PortError> = Ok(());
        assert!(stale_handle_rejected(Err::<(), _>(PortError::Stale), true));
        assert!(
            !stale_handle_rejected(Err::<(), _>(PortError::Denied), false),
            "a live handle refused only for naming another holder"
        );
        assert!(
            !stale_handle_rejected(Err::<(), _>(PortError::Stale), false),
            "refused for the old generation, but never revoked"
        );
        assert!(!stale_handle_rejected(connected, true));
        assert_eq!(connect_outcome_name(connected), "connected");
        assert_eq!(
            connect_outcome_name(Err::<(), _>(PortError::Stale)),
            "stale"
        );
    }
}
