//! Serial diagnostics of the playground, formatted here so the lines the #118 desktop lane
//! matches are host-tested. Each is one console message (at most 64 bytes).
//!
//! The binary prints a line only when what it reports changed, so diagnostics add no work while
//! the app is idle.

use clean_slate_native_abi::desktop::ConsoleLine;
use clean_slate_ui::QualityTier;

use crate::app::Playground;
use crate::layout::PANEL_SIZE;

/// The app state the lane observes: what clicks and keys change.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub clicks: u32,
    pub magenta: bool,
    pub presses: u32,
    pub text_len: usize,
}

/// Focus as the app last heard it from the compositor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Focus {
    pub window_active: bool,
    pub keyboard: bool,
}

impl Summary {
    pub fn of(app: &Playground) -> Self {
        let view = app.view();
        Self {
            clicks: view.clicks,
            magenta: view.magenta,
            presses: view.presses,
            text_len: app.text().len(),
        }
    }
}

impl Focus {
    pub fn of(app: &Playground) -> Self {
        let view = app.view();
        Self {
            window_active: view.window_active,
            keyboard: view.keyboard_focus,
        }
    }
}

/// `[APP ] ready size=520x360 tier=Q1`.
pub fn ready_line(tier: QualityTier) -> ConsoleLine {
    let tier = match tier.clamp_m10() {
        QualityTier::Q0 => "Q0",
        _ => "Q1",
    };
    ConsoleLine::format(format_args!(
        "[APP ] ready size={}x{} tier={tier}",
        PANEL_SIZE.width, PANEL_SIZE.height
    ))
}

/// `[APP ] input state=changed clicks=1 magenta=0 presses=2 text=ab` (text truncated to fit).
pub fn input_line(app: &Playground) -> ConsoleLine {
    let s = Summary::of(app);
    ConsoleLine::format(format_args!(
        "[APP ] input state=changed clicks={} magenta={} presses={} text={}",
        s.clicks,
        u8::from(s.magenta),
        s.presses,
        app.text()
    ))
}

/// `[APP ] focus active=1 keyboard=1`.
pub fn focus_line(focus: Focus) -> ConsoleLine {
    ConsoleLine::format(format_args!(
        "[APP ] focus active={} keyboard={}",
        u8::from(focus.window_active),
        u8::from(focus.keyboard)
    ))
}

/// `[APP ] exit reason=<reason>`; `closed` after a #115 close.
pub fn exit_line(reason: &str) -> ConsoleLine {
    ConsoleLine::format(format_args!("[APP ] exit reason={reason}"))
}
