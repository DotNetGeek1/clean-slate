//! Serial diagnostics of the shell, formatted here so the lines the acceptance lanes match are
//! host-tested. Each is one console message (at most 64 bytes).

use clean_slate_native_abi::desktop::ConsoleLine;
use clean_slate_native_abi::launcher::StartResult;
use clean_slate_ui::QualityTier;

use crate::apps::Action;
use crate::session::{ExitReason, HostError, Outcome, ShellSession};

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

/// What a rail click did: `[SHELL] rail start=<name>` (asked init to start it) or
/// `[SHELL] rail switch=<name> window=<handle>` (focused its window).
pub fn action_line(action: Action) -> ConsoleLine {
    match action {
        Action::Start(name) => {
            ConsoleLine::format(format_args!("[SHELL] rail start={}", name.as_str()))
        }
        Action::Activate { window, name } => ConsoleLine::format(format_args!(
            "[SHELL] rail switch={} window={}",
            name.as_str(),
            window.raw()
        )),
    }
}

/// `[SHELL] launch result=<result>`: init's answer to the shell's `START`.
pub fn launch_result_line(result: StartResult) -> ConsoleLine {
    ConsoleLine::format(format_args!("[SHELL] launch result={}", result.name()))
}

/// `[SHELL] launcher listed=<count>`, once the shell has its first launcher listing (#237).
pub fn launcher_listed_line(count: usize) -> ConsoleLine {
    ConsoleLine::format(format_args!("[SHELL] launcher listed={count}"))
}

/// `[SHELL] launcher unavailable reason=<reason>`: no listing, the rail carries on without it.
pub fn launcher_unavailable_line(reason: &str) -> ConsoleLine {
    ConsoleLine::format(format_args!("[SHELL] launcher unavailable reason={reason}"))
}

/// `[SHELL] exit reason=<reason>`.
pub fn exit_line(reason: &str) -> ConsoleLine {
    ConsoleLine::format(format_args!("[SHELL] exit reason={reason}"))
}

/// The `reason=` word for how the session ended. A compositor that ended, seen on a receive
/// or on a send, is `compositor-gone`: the desktop lane relaunches on that word.
pub const fn exit_reason(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Continue | Outcome::Exit(ExitReason::HostFailed(HostError::Gone)) => {
            "compositor-gone"
        }
        Outcome::Exit(_) => "setup-failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launcher_lines_fit_one_message() {
        assert_eq!(
            launcher_listed_line(2).as_bytes(),
            b"[SHELL] launcher listed=2"
        );
        assert_eq!(
            launcher_unavailable_line("connect").as_bytes(),
            b"[SHELL] launcher unavailable reason=connect"
        );
    }

    #[test]
    fn lines_match_what_the_desktop_lane_parses() {
        assert!(ready_line(&ShellSession::new(QualityTier::Q1)).is_none());
        assert_eq!(exit_line("closed").as_str(), "[SHELL] exit reason=closed");
        let name = clean_slate_native_abi::launcher::AppName::new(b"terminal").unwrap();
        assert_eq!(
            action_line(Action::Start(name)).as_str(),
            "[SHELL] rail start=terminal"
        );
        assert_eq!(
            action_line(Action::Activate {
                window: clean_slate_graphics::window::WindowHandle(3),
                name,
            })
            .as_str(),
            "[SHELL] rail switch=terminal window=3"
        );
        assert_eq!(
            launch_result_line(StartResult::AlreadyRunning).as_str(),
            "[SHELL] launch result=already-running"
        );
    }

    #[test]
    fn tiers_above_q1_report_as_the_m10_clamp() {
        assert_eq!(tier_name(QualityTier::Q0), "Q0");
        assert_eq!(tier_name(QualityTier::Q1), "Q1");
        assert_eq!(tier_name(QualityTier::Q3), "Q1");
    }

    #[test]
    fn a_compositor_that_ended_mid_send_is_compositor_gone() {
        assert_eq!(exit_reason(Outcome::Continue), "compositor-gone");
        assert_eq!(
            exit_reason(Outcome::Exit(ExitReason::HostFailed(HostError::Gone))),
            "compositor-gone"
        );
        assert_eq!(
            exit_reason(Outcome::Exit(ExitReason::HostFailed(HostError::Failed(1)))),
            "setup-failed"
        );
        assert_eq!(
            exit_reason(Outcome::Exit(ExitReason::BadOutput)),
            "setup-failed"
        );
    }
}
