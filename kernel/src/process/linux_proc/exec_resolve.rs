//! Temporary `resolve_executable` until #101 lands (delete at integration).

use crate::process::linux_image::LINUX_M8_FIXTURE;
use clean_slate_linux_abi::{LinuxErrno, ENOENT};

pub(crate) const LINUX_PATH_MAX: usize = 256;

pub(crate) struct ExecutableRef {
    pub image: &'static [u8],
    pub resolved_path_len: usize,
}

/// Resolves `/bin/busybox` and `/bin/sh` to the M8 hello fixture bytes.
pub(crate) fn resolve_executable(
    _pid: u64,
    _generation: clean_slate_service_lifecycle::InstanceGeneration,
    path: &[u8],
    resolved_out: &mut [u8; LINUX_PATH_MAX],
) -> Result<ExecutableRef, LinuxErrno> {
    if path == b"/bin/busybox" || path == b"/bin/sh" {
        let len = path.len().min(LINUX_PATH_MAX);
        resolved_out[..len].copy_from_slice(&path[..len]);
        let _ = &mut resolved_out[..len];
        return Ok(ExecutableRef {
            image: LINUX_M8_FIXTURE,
            resolved_path_len: len,
        });
    }
    Err(ENOENT)
}
