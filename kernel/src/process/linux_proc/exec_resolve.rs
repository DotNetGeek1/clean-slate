//! Temporary `resolve_executable` until #101 lands (delete at integration).

use crate::process::linux_image::LINUX_M8_FIXTURE;
use clean_slate_linux_abi::{LinuxErrno, ENOENT};

pub(crate) const LINUX_PATH_MAX: usize = 256;

pub(crate) struct ExecutableRef {
    pub image: &'static [u8],
    pub resolved_path_len: usize,
}

// ORCHESTRATOR: replace with linux_fs::resolve_executable
pub(crate) fn resolve_executable(
    _pid: u64,
    _generation: clean_slate_service_lifecycle::InstanceGeneration,
    path: &[u8],
    resolved_out: &mut [u8; LINUX_PATH_MAX],
) -> Result<ExecutableRef, LinuxErrno> {
    #[cfg(feature = "m9-linux-proc-self-test")]
    const PROC_PROBE: &[u8] =
        include_bytes!("../../../../fixtures/linux-proc-probe/linux-proc-probe-x86_64");
    #[cfg(any(
        feature = "m9-linux-proc-self-test",
        feature = "m9-linux-exec-self-test"
    ))]
    const EXEC_ARGS: &[u8] =
        include_bytes!("../../../../fixtures/linux-exec-args/linux-exec-args-x86_64");

    let image: Option<&[u8]> = match path {
        b"/bin/busybox" | b"/bin/sh" => Some(LINUX_M8_FIXTURE),
        #[cfg(feature = "m9-linux-proc-self-test")]
        b"/fixture/linux-proc-probe" => Some(PROC_PROBE),
        #[cfg(not(feature = "m9-linux-proc-self-test"))]
        b"/fixture/linux-proc-probe" => None,
        #[cfg(any(
            feature = "m9-linux-proc-self-test",
            feature = "m9-linux-exec-self-test"
        ))]
        b"/fixture/linux-exec-args" => Some(EXEC_ARGS),
        #[cfg(not(any(
            feature = "m9-linux-proc-self-test",
            feature = "m9-linux-exec-self-test"
        )))]
        b"/fixture/linux-exec-args" => None,
        _ => None,
    };
    let Some(image) = image else {
        return Err(ENOENT);
    };
    let len = path.len().min(LINUX_PATH_MAX);
    resolved_out[..len].copy_from_slice(&path[..len]);
    Ok(ExecutableRef {
        image,
        resolved_path_len: len,
    })
}
