//! Serial diagnostics of the shell, formatted here so the lines the acceptance lanes match are
//! host-tested. Each is one console message (at most 64 bytes).

use clean_slate_native_abi::desktop::ConsoleLine;
use clean_slate_ui::shell::rail_entry;
use clean_slate_ui::QualityTier;

use crate::session::ShellSession;

/// Emitted once both shell surfaces are committed.
pub const READY_PREFIX: &str = "[SHELL] ready";

const fn tier_name(tier: QualityTier) -> &'static str {
    match tier.clamp_m10() {
        QualityTier::Q0 => "Q0",
        _ => "Q1",
    }
}

/// `[SHELL] ready rail=88x800 surfaces=2 dock=none tier=Q1`, or `None` before the shell knows
/// its output.
pub fn ready_line(session: &ShellSession) -> Option<ConsoleLine> {
    let shell = session.shell()?;
    let rail = shell.zones().rail;
    Some(ConsoleLine::format(format_args!(
        "{READY_PREFIX} rail={}x{} surfaces={} dock=none tier={}",
        rail.width,
        rail.height,
        shell.surfaces().len(),
        tier_name(shell.tier()),
    )))
}

/// `[SHELL] rail selected=<index> <label>`.
pub fn activation_line(index: usize) -> ConsoleLine {
    let label = rail_entry(index).map_or("?", |entry| entry.label);
    ConsoleLine::format(format_args!("[SHELL] rail selected={index} {label}"))
}

/// `[SHELL] exit reason=<reason>`.
pub fn exit_line(reason: &str) -> ConsoleLine {
    ConsoleLine::format(format_args!("[SHELL] exit reason={reason}"))
}
