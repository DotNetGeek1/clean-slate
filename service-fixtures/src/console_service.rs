//! #310 bootstrap page the kernel writes for the console service.
//!
//! The console service owns console streams: native clients connect to its port
//! (`ResourceRef::console_port(CONSOLE_SERVICE_ID, generation)`) and it writes their output,
//! framed per writer, to the serial console device (syscall 25 `CONSOLE_DEVICE`). Its port, its
//! serve capability and its device capability come from `Grant::ConsoleService`; it finds the
//! serve and device handles with their `FIND_HANDLE` calls. Its own diagnostics go through the
//! kernel console (`Grant::Console`), whose handle is in this page.
//!
//! Layout, little-endian, no padding (`repr(C)` of three `u64`s):
//!
//! | Offset | Field | Meaning |
//! | --- | --- | --- |
//! | 0 | `self_pid` | the service's pid |
//! | 8 | `console_capability` | IPC send handle for the service's own console lines |
//! | 16 | `port_resource_id` | the id of the console port it serves (its service id) |

use crate::ServiceId;

/// Stable logical identity for the console service. Its port is `console_port(0x5600, gen)`.
pub const CONSOLE_SERVICE_ID: ServiceId = ServiceId(0x0000_5600);

const _: () = assert!(
    CONSOLE_SERVICE_ID.0 as u64 == clean_slate_native_abi::console::CONSOLE_PORT_RESOURCE_ID
);

/// Where the kernel maps the console service's bootstrap page (the same slot as init's).
pub const CONSOLE_SERVICE_BOOTSTRAP_ADDRESS: u64 = 0x0000_4000_0010_0000;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsoleServiceBootstrap {
    pub self_pid: u64,
    /// IPC send capability for the service's own console lines.
    pub console_capability: u64,
    /// `ResourceRef::console_port` id of the port the service serves.
    pub port_resource_id: u64,
}

const _: () = assert!(core::mem::size_of::<ConsoleServiceBootstrap>() == 24);
const _: () = assert!(core::mem::offset_of!(ConsoleServiceBootstrap, port_resource_id) == 16);
