//! Kernel lanes driven over QMP: builds and boots the kernel headless, attaches a
//! [`QmpScriptDriver`] on a private loopback endpoint, and returns the serial output for the
//! lane's own host-side checks. #113's input lane is the first user; #119's aggregate reuses it.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

pub(crate) use super::script::Capture;
use super::{QmpScriptDriver, ScriptStep};
use crate::marker_spec::MarkerSet;
use crate::{
    prepare_vm, run_driven_acceptance_command, xtask_artifact_root, AcceptanceDriver,
    VmLaunchConfig, XtaskError,
};

pub(crate) struct KernelLane {
    /// Names the QMP log lines and the artifact directory.
    pub(crate) lane: &'static str,
    pub(crate) features: &'static [&'static str],
    pub(crate) markers: MarkerSet<'static>,
    pub(crate) timeout: Duration,
    pub(crate) config: VmLaunchConfig,
    /// QEMU arguments after the lane config's own (devices such as `virtio-gpu-pci`).
    pub(crate) extra_args: Vec<String>,
}

/// What a lane run leaves for its host-side checks.
pub(crate) struct LaneRun {
    pub(crate) output: String,
    pub(crate) captures: Vec<Capture>,
}

/// Launch config for lanes that inject input: `vmport=off` leaves QEMU's PS/2 mouse as the
/// only relative pointer, so `input-send-event` motion reaches the i8042 aux port.
pub(crate) fn input_lane_config() -> VmLaunchConfig {
    VmLaunchConfig {
        machine_extra: Some("vmport=off"),
        ..VmLaunchConfig::default()
    }
}

/// Never `-S` (`input-send-event` fails while paused) and never a display: QEMU keeps
/// `qemu_command`'s `-display none`, and the driver only adds its `-name` and client `-qmp`.
pub(crate) fn run_kernel_lane(
    lane: KernelLane,
    steps: Vec<ScriptStep>,
) -> Result<String, XtaskError> {
    run_kernel_lane_in(lane, steps, &xtask_artifact_root()).map(|run| run.output)
}

/// [`run_kernel_lane`], also returning the screendumps the script captured.
pub(crate) fn run_kernel_lane_capturing(
    lane: KernelLane,
    steps: Vec<ScriptStep>,
) -> Result<LaneRun, XtaskError> {
    run_kernel_lane_in(lane, steps, &xtask_artifact_root())
}

fn run_kernel_lane_in(
    lane: KernelLane,
    steps: Vec<ScriptStep>,
    artifact_root: &Path,
) -> Result<LaneRun, XtaskError> {
    let mut vm = prepare_vm(false, false, lane.features, lane.config)?;
    vm.qemu.args(&lane.extra_args);
    let mut driver = QmpScriptDriver::new(lane.lane, steps, artifact_root)?;
    attach_driver(&mut vm.qemu, &driver);
    let output =
        run_driven_acceptance_command(&mut vm.qemu, lane.markers, lane.timeout, &mut driver)?;
    Ok(LaneRun {
        output,
        captures: driver.into_captures(),
    })
}

fn attach_driver(qemu: &mut Command, driver: &dyn AcceptanceDriver) {
    qemu.args(driver.qemu_args());
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{qemu_command, OvmfPaths};

    fn lane_argv() -> (Vec<String>, u16) {
        let ovmf = OvmfPaths {
            code: PathBuf::from("CODE.fd"),
            vars_template: PathBuf::from("TEMPLATE.fd"),
        };
        let mut qemu = qemu_command(
            &ovmf,
            Path::new("RUN_VARS.fd"),
            Path::new("ESP"),
            &input_lane_config(),
            false,
        );
        let root = std::env::temp_dir().join("clean-slate-xtask-lane-tests");
        let driver =
            QmpScriptDriver::new("lane-argv", Vec::new(), &root).expect("bind QMP endpoint");
        attach_driver(&mut qemu, &driver);
        let argv = qemu
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        (argv, driver.port())
    }

    fn value_after<'a>(argv: &'a [String], flag: &str) -> Vec<&'a str> {
        argv.windows(2)
            .filter(|pair| pair[0] == flag)
            .map(|pair| pair[1].as_str())
            .collect()
    }

    #[test]
    fn input_lane_is_headless_with_one_private_client_qmp_endpoint() {
        let (argv, port) = lane_argv();
        assert_eq!(value_after(&argv, "-display"), ["none"]);
        assert_eq!(value_after(&argv, "-machine"), ["q35,vmport=off"]);
        assert_eq!(
            value_after(&argv, "-qmp"),
            [format!("tcp:127.0.0.1:{port}")],
            "QEMU connects out to xtask's loopback listener; it never serves QMP itself"
        );
        assert_eq!(value_after(&argv, "-name").len(), 1);
        for forbidden in [
            "-S",
            "-s",
            "-monitor",
            "-vnc",
            "-spice",
            "-sdl",
            "-curses",
            "-nographic",
        ] {
            assert!(
                !argv.iter().any(|arg| arg == forbidden),
                "{forbidden} in {argv:?}"
            );
        }
        assert!(
            !argv
                .iter()
                .any(|arg| arg.contains("gtk") || arg.contains("cocoa")),
            "{argv:?}"
        );
    }
}
