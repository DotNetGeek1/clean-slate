//! Desktop launch contract (#118): the launch page the kernel's desktop launch policy writes for
//! the compositor, the desktop shell and native apps, and the console line every one of them
//! uses for serial diagnostics.
//!
//! The page is read-only data at [`DESKTOP_LAUNCH_ADDRESS`]; authority never comes from it. The
//! first two words keep the #112 client-fixture layout (`{ self_pid, graphics_resource_id }`).

use core::fmt;

/// Address of the launch page (shared with the #112 compositor and its client fixture).
pub const DESKTOP_LAUNCH_ADDRESS: u64 = 0x0000_4000_0000_1000;

/// Launch page layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DesktopLaunchPage {
    /// The process's own pid, for diagnostics only.
    pub self_pid: u64,
    /// Resource id of the compositor's `Graphics` port (`ResourceRef::graphics`).
    pub graphics_resource_id: u64,
    /// `IPC_SEND` handle on the kernel console sink, or [`NO_CONSOLE`].
    pub console_handle: u64,
    /// `LAUNCH_FLAG_*` bits.
    pub flags: u64,
    /// Visual quality tier: [`LAUNCH_TIER_Q0`] or [`LAUNCH_TIER_Q1`].
    pub tier: u64,
}

/// Bytes the launch policy writes.
pub const DESKTOP_LAUNCH_BYTES: usize = core::mem::size_of::<DesktopLaunchPage>();

const _: () = assert!(DESKTOP_LAUNCH_BYTES == 40);
const _: () = assert!(core::mem::offset_of!(DesktopLaunchPage, graphics_resource_id) == 8);
const _: () = assert!(core::mem::offset_of!(DesktopLaunchPage, console_handle) == 16);

/// `console_handle` when the launch policy granted no console.
pub const NO_CONSOLE: u64 = u64::MAX;
/// Self-test builds only: the process crashes itself on its fault key (acceptance of crash
/// containment); never set by the production launch policy.
pub const LAUNCH_FLAG_FAULT_KEY: u64 = 1 << 0;
/// Opaque Q0: no translucency.
pub const LAUNCH_TIER_Q0: u64 = 0;
/// Q1: translucent shell furniture, no blur or animation.
pub const LAUNCH_TIER_Q1: u64 = 1;

impl DesktopLaunchPage {
    /// `true` when the fault key is armed.
    pub const fn fault_key_armed(&self) -> bool {
        self.flags & LAUNCH_FLAG_FAULT_KEY != 0
    }

    /// `true` for the opaque tier; any unknown value falls back to Q1.
    pub const fn is_opaque_tier(&self) -> bool {
        self.tier == LAUNCH_TIER_Q0
    }

    /// The console handle, if one was granted.
    pub const fn console(&self) -> Option<u64> {
        if self.console_handle == NO_CONSOLE {
            None
        } else {
            Some(self.console_handle)
        }
    }
}

/// Syscall 3 `IPC_SEND(handle, ptr, len)`: on a console-sink handle the kernel prints
/// `[IPC ] console pid=<pid>: <text>` on serial.
pub const SYSCALL_NR_IPC_SEND: u64 = 3;
/// Longest console message the kernel accepts.
pub const CONSOLE_LINE_BYTES: usize = 64;

/// One console message, truncated (on a char boundary) at [`CONSOLE_LINE_BYTES`].
#[derive(Clone, Copy)]
pub struct ConsoleLine {
    bytes: [u8; CONSOLE_LINE_BYTES],
    len: usize,
}

impl ConsoleLine {
    pub const fn new() -> Self {
        Self {
            bytes: [0; CONSOLE_LINE_BYTES],
            len: 0,
        }
    }

    /// Formats `args` into a fresh line.
    pub fn format(args: fmt::Arguments<'_>) -> Self {
        let mut line = Self::new();
        let _ = fmt::write(&mut line, args);
        line
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for ConsoleLine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Write for ConsoleLine {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for ch in s.chars() {
            let mut utf8 = [0u8; 4];
            let encoded = ch.encode_utf8(&mut utf8).as_bytes();
            if self.len + encoded.len() > CONSOLE_LINE_BYTES {
                return Err(fmt::Error);
            }
            self.bytes[self.len..self.len + encoded.len()].copy_from_slice(encoded);
            self.len += encoded.len();
        }
        Ok(())
    }
}

impl fmt::Debug for ConsoleLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ConsoleLine").field(&self.as_str()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_lines_truncate_on_char_boundaries() {
        let line = ConsoleLine::format(format_args!("[APP ] clicks={}", 3));
        assert_eq!(line.as_str(), "[APP ] clicks=3");
        let long = "x".repeat(CONSOLE_LINE_BYTES + 9);
        assert_eq!(
            ConsoleLine::format(format_args!("{long}")).as_bytes().len(),
            CONSOLE_LINE_BYTES
        );
        let wide = "é".repeat(CONSOLE_LINE_BYTES);
        let line = ConsoleLine::format(format_args!("{wide}"));
        assert_eq!(line.as_bytes().len(), CONSOLE_LINE_BYTES);
        assert!(core::str::from_utf8(line.as_bytes()).is_ok());
    }

    #[test]
    fn launch_page_flags_and_tier() {
        let page = DesktopLaunchPage {
            self_pid: 7,
            graphics_resource_id: 0x5300,
            console_handle: NO_CONSOLE,
            flags: LAUNCH_FLAG_FAULT_KEY,
            tier: LAUNCH_TIER_Q0,
        };
        assert!(page.fault_key_armed());
        assert!(page.is_opaque_tier());
        assert_eq!(page.console(), None);
        let page = DesktopLaunchPage {
            console_handle: 4,
            flags: 0,
            tier: 9,
            ..page
        };
        assert!(!page.fault_key_armed());
        assert!(!page.is_opaque_tier());
        assert_eq!(page.console(), Some(4));
    }
}
