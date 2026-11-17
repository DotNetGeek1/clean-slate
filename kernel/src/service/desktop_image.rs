//! The three #118 desktop images as services: their identities, the compositor's port
//! parameters and the launch page `spawn` writes for a new instance.
//!
//! The system build's manifest rows (#218 S6c) are the only way they launch: the kernel has no
//! desktop launch policy of its own (S6f). A row's page carries a console only when the row
//! holds `Grant::Console`, and the tier of the desktop mode init runs with.

use core::sync::atomic::{AtomicU64, Ordering};

use clean_slate_graphics::{
    CLIENT_EVENT_QUEUE_DEPTH, MAX_OUTSTANDING_REQUESTS_PER_CLIENT, SERVER_REQUEST_QUEUE_DEPTH,
};
use clean_slate_native_abi::desktop::{
    DesktopLaunchPage, LAUNCH_FLAG_INPUT_TRACE, LAUNCH_TIER_Q0, LAUNCH_TIER_Q1, NO_CONSOLE,
};
use clean_slate_native_abi::PortParams;
use clean_slate_service_fixtures::init_bootstrap::DESKTOP_MODE_FRAMEBUFFER;
use clean_slate_service_fixtures::manifest::{Grant, ServiceSpec};
pub(crate) use clean_slate_service_fixtures::{
    COMPOSITOR_SERVICE_ID, DESKTOP_SHELL_SERVICE_ID as SHELL_SERVICE_ID, PLAYGROUND_SERVICE_ID,
};
use clean_slate_service_lifecycle::ServiceId;

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
    pub(crate) const fn service(self) -> ServiceId {
        match self {
            Self::Compositor => COMPOSITOR_SERVICE_ID,
            Self::Shell => SHELL_SERVICE_ID,
            Self::App => PLAYGROUND_SERVICE_ID,
        }
    }

    pub(crate) const fn for_service(service: ServiceId) -> Option<Self> {
        match service.0 {
            id if id == COMPOSITOR_SERVICE_ID.0 => Some(Self::Compositor),
            id if id == SHELL_SERVICE_ID.0 => Some(Self::Shell),
            id if id == PLAYGROUND_SERVICE_ID.0 => Some(Self::App),
            _ => None,
        }
    }

    /// User stack pages (the compositor composes on its stack; clients only paint).
    pub(crate) const fn stack_pages(self) -> u64 {
        match self {
            Self::Compositor => 64,
            Self::Shell | Self::App => 32,
        }
    }
}

/// Tier written into a row's launch page: Q1 unless the boot option chose the framebuffer.
static ROW_TIER: AtomicU64 = AtomicU64::new(LAUNCH_TIER_Q1);

/// Records the boot option's `InitBootstrap.desktop_mode` word for the desktop rows' pages.
#[cfg_attr(not(clean_slate_system_init), allow(dead_code))]
pub(crate) fn set_row_desktop_mode(desktop_mode: u64) {
    ROW_TIER.store(tier_for_mode(desktop_mode), Ordering::Relaxed);
}

const fn tier_for_mode(desktop_mode: u64) -> u64 {
    if desktop_mode == DESKTOP_MODE_FRAMEBUFFER {
        LAUNCH_TIER_Q0
    } else {
        LAUNCH_TIER_Q1
    }
}

/// Per-input console lines are printed only by the hooks build (D5).
const fn row_flags() -> u64 {
    if cfg!(feature = "system-test-hooks") {
        LAUNCH_FLAG_INPUT_TRACE
    } else {
        0
    }
}

/// What `spawn` writes at the launch address for the new `pid` of `spec`'s row; its authority
/// comes from the row alone. The graphics, display and input grants are applied separately,
/// after registration.
pub(crate) fn launch_page_for(
    pid: u64,
    spec: &ServiceSpec,
) -> Result<DesktopLaunchPage, &'static str> {
    let console_handle = if spec.grants(Grant::Console) {
        unsafe { crate::ipc::endpoint_table_mut() }
            .grant_console_capability_for_pid(pid)
            .map_err(|_| "desktop row console grant failed")?
    } else {
        NO_CONSOLE
    };
    Ok(page(
        pid,
        console_handle,
        ROW_TIER.load(Ordering::Relaxed),
        row_flags(),
    ))
}

const fn page(pid: u64, console_handle: u64, tier: u64, flags: u64) -> DesktopLaunchPage {
    DesktopLaunchPage {
        self_pid: pid,
        graphics_resource_id: COMPOSITOR_SERVICE_ID.0 as u64,
        console_handle,
        flags,
        tier,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_service_fixtures::init_bootstrap::{DESKTOP_MODE_OFF, DESKTOP_MODE_VIRTIO_GPU};

    #[test]
    fn roles_map_to_the_manifest_ids() {
        for role in [
            DesktopRole::Compositor,
            DesktopRole::Shell,
            DesktopRole::App,
        ] {
            assert_eq!(DesktopRole::for_service(role.service()), Some(role));
        }
        assert_eq!(DesktopRole::for_service(ServiceId(0x5400)), None);
        assert_eq!(COMPOSITOR_SERVICE_ID, ServiceId(0x5300));
        assert_eq!(SHELL_SERVICE_ID, ServiceId(0x5301));
        assert_eq!(PLAYGROUND_SERVICE_ID, ServiceId(0x5302));
    }

    #[test]
    fn the_boot_option_picks_the_tier() {
        assert_eq!(tier_for_mode(DESKTOP_MODE_FRAMEBUFFER), LAUNCH_TIER_Q0);
        assert_eq!(tier_for_mode(DESKTOP_MODE_VIRTIO_GPU), LAUNCH_TIER_Q1);
        assert_eq!(tier_for_mode(DESKTOP_MODE_OFF), LAUNCH_TIER_Q1);
    }

    #[test]
    fn only_the_hooks_build_asks_for_per_input_lines() {
        assert_eq!(
            row_flags() & LAUNCH_FLAG_INPUT_TRACE != 0,
            cfg!(feature = "system-test-hooks")
        );
    }
}
