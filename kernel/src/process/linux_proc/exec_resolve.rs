//! Executable resolution for Linux `execve` (#102 / #101).

use clean_slate_linux_abi::{LinuxErrno, ENOENT};

#[cfg(feature = "m9-rootfs")]
pub(crate) use crate::process::linux_fs::path::LINUX_PATH_MAX;
#[cfg(not(feature = "m9-rootfs"))]
pub(crate) const LINUX_PATH_MAX: usize = 256;

pub(crate) struct ExecutableRef<'a> {
    pub image: &'a [u8],
    pub resolved_path_len: usize,
}

#[cfg(feature = "m9-rootfs")]
pub(crate) fn resolve_executable(
    pid: u64,
    generation: clean_slate_service_lifecycle::InstanceGeneration,
    path: &[u8],
    resolved_out: &mut [u8; LINUX_PATH_MAX],
) -> Result<ExecutableRef<'_>, LinuxErrno> {
    let image = crate::process::linux_rootfs::image().map_err(|_| ENOENT)?;
    let exec =
        crate::process::linux_fs::resolve_executable(pid, generation, path, resolved_out, &image)?;
    Ok(ExecutableRef {
        image: exec.image,
        resolved_path_len: exec.resolved_path_len,
    })
}

#[cfg(not(feature = "m9-rootfs"))]
pub(crate) fn resolve_executable(
    _pid: u64,
    _generation: clean_slate_service_lifecycle::InstanceGeneration,
    path: &[u8],
    resolved_out: &mut [u8; LINUX_PATH_MAX],
) -> Result<ExecutableRef<'static>, LinuxErrno> {
    use crate::process::linux_image::LINUX_M8_FIXTURE;

    // M8 fixture paths only; #107 (BusyBox convergence) removes this stub.
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
