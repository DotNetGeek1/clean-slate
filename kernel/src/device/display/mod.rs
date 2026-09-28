//! Kernel display: scanout backends behind one present engine (#111 GOP; #114 VirtIO-GPU next).
//!
//! Backends carry no UI policy (no cursor, layout or background). Clients never see the aperture,
//! its stride, or physical addresses; they get the frozen reference mode through syscall 18.

// `MAP_SCANOUT`/`PRESENT` (gated on #195 S6) are the production callers of bind/present/complete;
// until they land only the framebuffer lane and host tests drive that half.
#![cfg_attr(
    not(any(test, feature = "m10-framebuffer-self-test")),
    allow(dead_code)
)]

pub(crate) mod aperture;
pub(crate) mod engine;
#[cfg(feature = "m10-framebuffer-self-test")]
pub(crate) mod frame;
pub(crate) mod gop;
#[cfg(any(test, feature = "m10-framebuffer-self-test"))]
pub(crate) mod presenter;
pub(crate) mod source;
#[cfg(test)]
pub(crate) mod test_support;

use clean_slate_graphics::display::{DisplayError, PresentRequest, PresentState};
use clean_slate_graphics::{BufferRect, DisplayMode};

use crate::arch::x86_64::cpu::without_interrupts;
use crate::boot::gop::BootFramebuffer;
use crate::sync::global_cell::GlobalCell;

use aperture::ApertureWriter;
use engine::DisplayState;
use gop::GopBackend;
use source::FrameSource;

/// M10 drives exactly one physical output (`MAX_OUTPUTS`); capabilities name it by index (S10).
pub(crate) const PRIMARY_OUTPUT_INDEX: u8 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Submitted {
    Completed,
    Pending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BackendError {
    Timeout,
    Failed,
    SourceRejected,
}

pub(crate) trait ScanoutBackend {
    fn mode(&self) -> DisplayMode;

    fn bind(&mut self, index: u8, source: &dyn FrameSource) -> Result<(), BackendError>;

    /// Copies exactly `damage` (already validated against the mode) from `source` to scanout.
    /// `Pending` completes later through `DisplayState::complete`.
    fn submit(
        &mut self,
        index: u8,
        source: &dyn FrameSource,
        damage: &[BufferRect],
    ) -> Result<Submitted, BackendError>;

    fn reset(&mut self) -> Result<(), BackendError>;
}

pub(crate) enum Backend {
    Gop(GopBackend),
}

impl Backend {
    fn scanout(&mut self) -> &mut dyn ScanoutBackend {
        match self {
            Self::Gop(gop) => gop,
        }
    }
}

pub(crate) struct ActiveDisplay {
    state: DisplayState,
    backend: Backend,
}

impl ActiveDisplay {
    pub(crate) fn new(mut backend: Backend) -> Result<Self, DisplayError> {
        let state = DisplayState::new(backend.scanout().mode())?;
        Ok(Self { state, backend })
    }

    pub(crate) fn state(&self) -> &DisplayState {
        &self.state
    }

    pub(crate) fn bind(&mut self, index: u8, source: &dyn FrameSource) -> Result<(), DisplayError> {
        self.state.bind(self.backend.scanout(), index, source)
    }

    pub(crate) fn present(
        &mut self,
        source: &dyn FrameSource,
        request: &PresentRequest,
        now_ns: u64,
    ) -> Result<u64, DisplayError> {
        self.state
            .present(self.backend.scanout(), source, request, now_ns)
    }

    /// Leaves `ResetRequired` through a backend reset: a new epoch on success, `Poisoned` otherwise.
    pub(crate) fn recover(&mut self) {
        if self.state.status().state == PresentState::ResetRequired {
            let reset = self.backend.scanout().reset();
            self.state.finish_reset(reset.is_ok());
        }
    }

    #[cfg(feature = "m10-framebuffer-self-test")]
    pub(crate) fn gop_aperture(&self) -> Option<&ApertureWriter> {
        match &self.backend {
            Backend::Gop(gop) => Some(gop.aperture()),
        }
    }
}

static ACTIVE_DISPLAY: GlobalCell<Option<ActiveDisplay>> = GlobalCell::new(None);

/// Installs the GOP backend over an aperture already mapped uncached at `aperture_virt`.
pub(crate) fn install_gop_backend(
    framebuffer: &BootFramebuffer,
    aperture_virt: u64,
) -> Result<(), DisplayError> {
    let byte_len =
        usize::try_from(framebuffer.byte_len).map_err(|_| DisplayError::ModeUnavailable)?;
    let aperture = unsafe {
        ApertureWriter::new(
            aperture_virt as *mut u8,
            byte_len,
            framebuffer.stride_bytes,
            framebuffer.width,
            framebuffer.height,
        )
    }
    .map_err(|_| DisplayError::ModeUnavailable)?;
    let backend =
        GopBackend::new(aperture, framebuffer.order).map_err(|_| DisplayError::ModeUnavailable)?;
    let display = ActiveDisplay::new(Backend::Gop(backend))?;
    let output = display.state().output();
    without_interrupts(|| unsafe { *ACTIVE_DISPLAY.get() = Some(display) });
    crate::diagnostics::serial::serial_write_fmt(format_args!(
        "[DISP] backend=gop output={} epoch={}\n",
        output.index(),
        output.backend_epoch()
    ));
    Ok(())
}

/// Runs `f` on the installed output, or `None` when boot found no display backend.
pub(crate) fn with_active_display<R>(f: impl FnOnce(Option<&mut ActiveDisplay>) -> R) -> R {
    without_interrupts(|| f(unsafe { (*ACTIVE_DISPLAY.get()).as_mut() }))
}
