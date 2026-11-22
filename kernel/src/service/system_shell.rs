//! #218 S5: the interactive BusyBox shell on the serial console.
//!
//! The manifest row [`SYSTEM_SHELL_SPEC`](clean_slate_service_fixtures::manifest::SYSTEM_SHELL_SPEC)
//! names the image and its grants; init decides when it runs. This module builds the process:
//! BusyBox from the embedded rootfs, run as `/bin/sh -i` with `PATH=/bin`, with the row's Linux
//! grants applied before the new thread can be dispatched (syscalls run with interrupts masked,
//! and the launch holds `without_interrupts` as well):
//!
//! - `Console`: one console capability, installed as fd 1 and fd 2;
//! - `ConsoleInput`: serial console input at fd 0;
//! - `TmpObjects`: `READ | WRITE` on every `/tmp` backing object;
//! - `NetworkClient`: the network client entitlement, plus a client capability bound to the
//!   network instance when one is live (see [`crate::capability::network`]). A build without
//!   the Linux socket layer cannot honour it, so the launch fails.
//!
//! Any failure tears the process down, so the controller never records a half-built shell.
//!
//! A Linux process cannot call the native `SERVICE_READY`. The kernel reports the shell ready
//! itself, the first time the instance blocks reading fd 0: by then ash has printed its prompt
//! and waits for a command.

use clean_slate_service_fixtures::manifest::Grant;

use super::spawn::{LaunchContext, SpawnedServiceInstance};
use crate::arch::x86_64::cpu::without_interrupts;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::mm::address_space::kernel_root_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::process::domain::teardown_process_by_id;
use crate::process::linux_exec::{
    launch_linux_process_with_authority, LinuxExecSpec, LinuxLaunchAuthority,
};
use crate::process::linux_image::{
    LINUX_CONVENTIONAL_EXEC_STACK_PAGES, LINUX_CONVENTIONAL_LOAD_POLICY,
};
use crate::process::{linux_fd, linux_fs};
use crate::service::service_lifecycle_controller_mut;
use clean_slate_rootfs::EntryKind;

const SHELL_ARGV: [&[u8]; 2] = [b"/bin/sh", b"-i"];
const SHELL_ENVP: [&[u8]; 1] = [b"PATH=/bin"];
const SHELL_EXEC_FILENAME: &[u8] = b"/bin/sh";
/// Exit status recorded when a half-built shell is torn down.
const SHELL_LAUNCH_ROLLBACK_STATUS: u64 = 1;

/// Which Linux grants a row asks for. A native grant on a Linux row is refused: the manifest
/// validator rejects it, and the launcher must not drop it silently either.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct LinuxGrants {
    console: bool,
    console_input: bool,
    tmp_objects: bool,
    network_client: bool,
}

impl LinuxGrants {
    fn from_row(grants: &[Grant]) -> Result<Self, &'static str> {
        let mut wanted = Self::default();
        for grant in grants {
            match grant {
                Grant::Console => wanted.console = true,
                Grant::ConsoleInput => wanted.console_input = true,
                Grant::TmpObjects => wanted.tmp_objects = true,
                Grant::NetworkClient => wanted.network_client = true,
                Grant::BlockDevice
                | Grant::ObjectServiceRole
                | Grant::AuditReader
                | Grant::NetworkService
                | Grant::GraphicsPort
                | Grant::DisplayPresenter
                | Grant::InputSeat
                | Grant::GraphicsShellRole
                | Grant::GraphicsAppRole => {
                    return Err("system shell: native grant on a Linux row");
                }
            }
        }
        if wanted.console_input && !wanted.console {
            return Err("system shell: console input without console");
        }
        Ok(wanted)
    }
}

fn busybox_bytes() -> Result<&'static [u8], &'static str> {
    let image =
        crate::process::linux_rootfs::image().map_err(|_| "system shell: rootfs image invalid")?;
    let busybox = image
        .lookup(b"/bin/busybox")
        .ok_or("system shell: /bin/busybox missing from rootfs")?;
    if busybox.kind != EntryKind::File {
        return Err("system shell: /bin/busybox is not a file");
    }
    Ok(busybox.data)
}

fn apply_linux_grants(
    pid: u64,
    generation: clean_slate_service_lifecycle::InstanceGeneration,
    wanted: LinuxGrants,
) -> Result<(), &'static str> {
    if wanted.console {
        linux_fd::grant_console_stdio_for_process(pid, generation)?;
    }
    if wanted.console_input {
        linux_fd::install_console_input_for_process(pid, generation)?;
    }
    if wanted.tmp_objects {
        linux_fs::grant_linux_tmp_object_capabilities(pid)?;
    }
    if wanted.network_client {
        grant_network_client(pid)?;
    }
    Ok(())
}

#[cfg(clean_slate_linux_socket)]
fn grant_network_client(pid: u64) -> Result<(), &'static str> {
    crate::capability::network::grant_network_client_entitlement(clean_slate_capability::HolderId(
        pid,
    ))
    .map_err(|_| "system shell: network client entitlement grant failed")
}

#[cfg(not(clean_slate_linux_socket))]
fn grant_network_client(_pid: u64) -> Result<(), &'static str> {
    Err("system shell: NetworkClient needs the Linux socket layer, which this build does not compile")
}

/// Builds the shell for `context`'s row on `scheduler_slot`. The process is Ready on return.
#[inline(never)]
pub(crate) fn launch(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
    context: LaunchContext,
) -> Result<SpawnedServiceInstance, &'static str> {
    let wanted = LinuxGrants::from_row(context.grants())?;
    let spec = LinuxExecSpec {
        image: busybox_bytes()?,
        argv: &SHELL_ARGV,
        envp: &SHELL_ENVP,
        exec_filename: SHELL_EXEC_FILENAME,
        stack_pages: LINUX_CONVENTIONAL_EXEC_STACK_PAGES,
        policy: &LINUX_CONVENTIONAL_LOAD_POLICY,
    };
    without_interrupts(|| {
        let launched = launch_linux_process_with_authority(
            allocator,
            kernel_stack_top,
            scheduler_slot,
            &spec,
            LinuxLaunchAuthority {
                network: false,
                tmp_objects: false,
            },
        )
        .map_err(|error| error.description())?;
        if let Err(message) = apply_linux_grants(launched.pid, launched.instance_generation, wanted)
        {
            return Err(
                match teardown_process_by_id(
                    allocator,
                    kernel_root_frame(),
                    launched.pid,
                    SHELL_LAUNCH_ROLLBACK_STATUS,
                    false,
                ) {
                    Ok(_) => message,
                    Err(_) => "system shell: rollback teardown failed after a grant error",
                },
            );
        }
        kernel_log_fmt(format_args!(
            "[SVC ] shell process pid={} gen={} argv=/bin/sh,-i env=PATH=/bin stdin={} stdout={} tmp={} net-client={}\n",
            launched.pid,
            context.generation.0,
            u8::from(wanted.console_input),
            u8::from(wanted.console),
            u8::from(wanted.tmp_objects),
            u8::from(wanted.network_client),
        ));
        kernel_log_fmt(format_args!(
            "[SVC ] console input so far {}\n",
            crate::device::serial_console::stats()
        ));
        Ok(SpawnedServiceInstance {
            pid: launched.pid,
            tid: launched.tid,
            domain_id: launched.pid,
            scheduler_slot: launched.scheduler_slot,
        })
    })
}

/// A Linux process is about to block reading console input. The first time the live shell
/// instance does so it is reported ready; later waits, and waits by its children, change
/// nothing.
pub(crate) fn on_console_input_wait(pid: u64) {
    let controller = unsafe { service_lifecycle_controller_mut() };
    if let Ok(instance) = controller.report_ready_from_pid(pid) {
        kernel_log_fmt(format_args!(
            "[SVC ] ready service={} pid={} gen={} source=live-instance kernel-observed first-console-input-wait\n",
            instance.service.0, instance.pid.0, instance.generation.0
        ));
    }
}

/// Publishes `Exited` for `pid` before its Linux `exit` or `exit_group` tears it down, when
/// `pid` is a live service instance; any other pid is ignored. A refused publication means the
/// controller's state and the process table disagree, so it is fatal rather than logged.
pub(crate) fn publish_linux_service_exit(pid: u64) {
    let controller = unsafe { service_lifecycle_controller_mut() };
    if let Err(error) = controller.notify_exited_live_process(pid) {
        kernel_log_fmt(format_args!(
            "[FAIL] supervised exit publication failed pid={pid} err={error:?}\n"
        ));
        fatal_kernel_error("failed to publish supervised exit event");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_service_fixtures::manifest::{grants_for, SYSTEM_MANIFEST};
    use clean_slate_service_fixtures::SYSTEM_SHELL_SERVICE_ID;

    #[test]
    fn the_system_row_asks_for_console_stdin_tmp_and_network_client() {
        assert_eq!(
            LinuxGrants::from_row(grants_for(SYSTEM_MANIFEST, SYSTEM_SHELL_SERVICE_ID)),
            Ok(LinuxGrants {
                console: true,
                console_input: true,
                tmp_objects: true,
                network_client: true,
            })
        );
    }

    #[test]
    fn a_row_without_console_input_installs_no_stdin() {
        assert_eq!(
            LinuxGrants::from_row(&[Grant::Console, Grant::TmpObjects]),
            Ok(LinuxGrants {
                console: true,
                console_input: false,
                tmp_objects: true,
                network_client: false,
            })
        );
    }

    #[test]
    fn native_grants_and_stdin_without_console_are_refused() {
        for grants in [
            &[Grant::Console, Grant::BlockDevice] as &[Grant],
            &[Grant::NetworkService],
            &[Grant::ObjectServiceRole],
        ] {
            assert_eq!(
                LinuxGrants::from_row(grants),
                Err("system shell: native grant on a Linux row")
            );
        }
        assert_eq!(
            LinuxGrants::from_row(&[Grant::ConsoleInput]),
            Err("system shell: console input without console")
        );
    }

    #[test]
    fn the_shell_is_busybox_sh_interactive_with_bin_on_path() {
        assert_eq!(SHELL_ARGV, [b"/bin/sh" as &[u8], b"-i"]);
        assert_eq!(SHELL_ENVP, [b"PATH=/bin" as &[u8]]);
        let busybox = busybox_bytes().expect("rootfs carries busybox");
        assert_eq!(&busybox[..4], b"\x7fELF");
    }
}
