//! Console sink backend for Linux stdio (#144 byte-transparent serial).

use super::open_description::ConsoleSinkRef;
use crate::capability::holder_has_resource_rights;
use crate::diagnostics::log::kernel_log_fmt;
use crate::ipc::IpcEndpointKind;
use crate::ipc::IpcEndpointTable;
use crate::ipc::IpcSendError;
use crate::ipc::IPC_MAX_MESSAGE_BYTES;
use crate::process::personality::ExecutionPersonality;
use clean_slate_capability::{HolderId, ResourceRef, Rights};
use clean_slate_linux_abi::{LinuxErrno, EACCES, EBADF, EINVAL};

/// How a ConsoleSink message from the Linux fd path is rendered on serial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConsoleSinkRenderStyle {
    Verbatim,
    NativeFramed,
}

/// Pure render-style decision from trusted personality (host-testable).
pub(crate) const fn console_sink_render_style(
    personality: ExecutionPersonality,
) -> ConsoleSinkRenderStyle {
    match personality {
        ExecutionPersonality::LinuxX86_64 => ConsoleSinkRenderStyle::Verbatim,
        ExecutionPersonality::Native => ConsoleSinkRenderStyle::NativeFramed,
    }
}

/// Map an IPC send failure onto a Linux errno for the fd projection path.
pub(crate) const fn map_ipc_send_error(error: IpcSendError) -> LinuxErrno {
    match error {
        IpcSendError::InvalidCapability | IpcSendError::StaleCapability => EBADF,
        IpcSendError::Unauthorized => EACCES,
        IpcSendError::InvalidMessageLength => EINVAL,
    }
}

/// Deliver Linux ConsoleSink payload bytes to the host serial device.
pub(crate) fn console_write_bytes(bytes: &[u8]) {
    #[cfg(feature = "m8-linux-dispatch-self-test")]
    crate::selftest::m8_linux_dispatch::observe_linux_console_write_bytes(bytes);

    #[cfg(feature = "m9-fd-core-self-test")]
    crate::selftest::m9_fd_core::observe_linux_console_write_bytes(bytes);

    #[cfg(feature = "m9-linux-runtime-self-test")]
    crate::selftest::m9_linux_runtime::observe_linux_console_write_bytes(bytes);

    #[cfg(feature = "m9-userspace-self-test")]
    crate::selftest::m9_userspace::observe_linux_console_write_bytes(bytes);

    #[cfg(test)]
    {
        linux_console_byte_test_sink::capture(bytes);
    }

    #[cfg(not(test))]
    crate::diagnostics::serial::serial_write_bytes(bytes);
}

fn emit_console_sink_render(style: ConsoleSinkRenderStyle, sender_pid: u64, payload: &[u8]) {
    match style {
        ConsoleSinkRenderStyle::Verbatim => console_write_bytes(payload),
        ConsoleSinkRenderStyle::NativeFramed => {
            let message = core::str::from_utf8(payload).unwrap_or("<non-utf8>");
            kernel_log_fmt(format_args!("[IPC ] console pid={sender_pid}: {message}\n"));
        }
    }
}

/// Write bytes through a console open description (IPC capability path).
pub(crate) fn write_console(
    ipc: &mut IpcEndpointTable,
    pid: u64,
    sink: ConsoleSinkRef,
    bytes: &[u8],
    personality: ExecutionPersonality,
) -> Result<usize, LinuxErrno> {
    if bytes.is_empty() {
        return Ok(0);
    }
    let send_len = core::cmp::min(bytes.len(), IPC_MAX_MESSAGE_BYTES);
    let payload = &bytes[..send_len];
    let resource = ResourceRef::ipc_endpoint(u64::from(sink.endpoint_slot));
    if !holder_has_resource_rights(HolderId(pid), resource, Rights::WRITE) {
        return Err(EACCES);
    }
    match ipc.send_message_to_endpoint(
        usize::from(sink.endpoint_slot),
        sink.endpoint_generation,
        payload,
    ) {
        Ok(result) => {
            if result.endpoint_kind == IpcEndpointKind::ConsoleSink {
                emit_console_sink_render(console_sink_render_style(personality), pid, payload);
            }
            Ok(result.bytes_sent)
        }
        Err(error) => Err(map_ipc_send_error(error)),
    }
}

#[cfg(test)]
pub(crate) mod linux_console_byte_test_sink {
    use std::cell::RefCell;

    thread_local! {
        static CAPTURE: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    }

    pub fn reset() {
        CAPTURE.with(|capture| capture.borrow_mut().clear());
    }

    pub fn capture(bytes: &[u8]) {
        CAPTURE.with(|capture| capture.borrow_mut().extend_from_slice(bytes));
    }

    pub fn take() -> Vec<u8> {
        CAPTURE.with(|capture| capture.borrow().clone())
    }
}
