//! Kernel display: scanout backends behind one present engine (#111 GOP; #114 VirtIO-GPU next).
//!
//! Backends carry no UI policy (no cursor, layout or background). Clients never see the aperture,
//! its stride, or physical addresses; they get the frozen reference mode through syscall 18.
//!
//! Kernel builds install output 0 for the syscall 18 query subops. The scanout write path (the
//! uncached aperture mapping, `ScanoutBackend` and the present half of the engine) is compiled only
//! where something presents: host tests and the framebuffer lane now, `MAP_SCANOUT`/`PRESENT`
//! (#195 S6) and the #114 backend later.

#[cfg(any(test, feature = "m10-framebuffer-self-test"))]
pub(crate) mod aperture;
pub(crate) mod engine;
#[cfg(feature = "m10-framebuffer-self-test")]
pub(crate) mod frame;
#[cfg(any(test, feature = "m10-framebuffer-self-test"))]
pub(crate) mod gop;
#[cfg(any(test, feature = "m10-framebuffer-self-test"))]
pub(crate) mod presenter;
#[cfg(any(test, feature = "m10-framebuffer-self-test"))]
pub(crate) mod source;
#[cfg(test)]
pub(crate) mod test_support;

use clean_slate_graphics::display::DisplayError;
#[cfg(test)]
use clean_slate_graphics::display::{PresentRequest, PresentState};
#[cfg(any(test, feature = "m10-framebuffer-self-test"))]
use clean_slate_graphics::{BufferRect, DisplayMode};

use crate::arch::x86_64::cpu::without_interrupts;
#[cfg(feature = "m10-framebuffer-self-test")]
use crate::boot::gop::BootFramebuffer;
use crate::sync::global_cell::GlobalCell;

use engine::DisplayState;
#[cfg(any(test, feature = "m10-framebuffer-self-test"))]
use gop::GopBackend;
#[cfg(any(test, feature = "m10-framebuffer-self-test"))]
use source::FrameSource;

/// M10 drives exactly one physical output (`MAX_OUTPUTS`); capabilities name it by index (S10).
pub(crate) const PRIMARY_OUTPUT_INDEX: u8 = 0;

#[cfg(any(test, feature = "m10-framebuffer-self-test"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Submitted {
    Completed,
    #[cfg(test)]
    Pending,
}

#[cfg(any(test, feature = "m10-framebuffer-self-test"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BackendError {
    #[cfg(test)]
    Timeout,
    Failed,
    SourceRejected,
}

#[cfg(any(test, feature = "m10-framebuffer-self-test"))]
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

    #[cfg(test)]
    fn reset(&mut self) -> Result<(), BackendError>;
}

#[cfg(any(test, feature = "m10-framebuffer-self-test"))]
pub(crate) enum Backend {
    Gop(GopBackend),
}

#[cfg(any(test, feature = "m10-framebuffer-self-test"))]
impl Backend {
    fn scanout(&mut self) -> &mut dyn ScanoutBackend {
        match self {
            Self::Gop(gop) => gop,
        }
    }
}

pub(crate) struct ActiveDisplay {
    state: DisplayState,
    #[cfg(any(test, feature = "m10-framebuffer-self-test"))]
    backend: Backend,
}

impl ActiveDisplay {
    #[cfg(any(test, feature = "m10-framebuffer-self-test"))]
    pub(crate) fn new(mut backend: Backend) -> Result<Self, DisplayError> {
        let state = DisplayState::new(backend.scanout().mode())?;
        Ok(Self { state, backend })
    }

    pub(crate) fn state(&self) -> &DisplayState {
        &self.state
    }

    #[cfg(any(test, feature = "m10-framebuffer-self-test"))]
    pub(crate) fn bind(&mut self, index: u8, source: &dyn FrameSource) -> Result<(), DisplayError> {
        self.state.bind(self.backend.scanout(), index, source)
    }

    #[cfg(test)]
    pub(crate) fn present(
        &mut self,
        source: &dyn FrameSource,
        request: &PresentRequest,
        now_ns: u64,
    ) -> Result<u64, DisplayError> {
        self.state
            .present(self.backend.scanout(), source, request, now_ns)
    }

    #[cfg(any(test, feature = "m10-framebuffer-self-test"))]
    pub(crate) fn add_damage(
        &self,
        presenter: &mut presenter::KernelPresenter,
        rect: clean_slate_graphics::Rect,
    ) -> Result<(), clean_slate_graphics::GeometryError> {
        presenter.add_damage(&self.state, rect)
    }

    #[cfg(any(test, feature = "m10-framebuffer-self-test"))]
    pub(crate) fn present_pending(
        &mut self,
        presenter: &mut presenter::KernelPresenter,
        source: &dyn FrameSource,
        buffer_index: u8,
        now_ns: u64,
    ) -> Result<Option<u64>, DisplayError> {
        presenter.present_pending(
            &mut self.state,
            self.backend.scanout(),
            source,
            buffer_index,
            now_ns,
        )
    }

    /// Leaves `ResetRequired` through a backend reset: a new epoch on success, `Poisoned` otherwise.
    #[cfg(test)]
    pub(crate) fn recover(&mut self) {
        if self.state.status().state == PresentState::ResetRequired {
            let reset = self.backend.scanout().reset();
            self.state.finish_reset(reset.is_ok());
        }
    }

    #[cfg(feature = "m10-framebuffer-self-test")]
    pub(crate) fn gop_aperture(&self) -> Option<&aperture::ApertureWriter> {
        match &self.backend {
            Backend::Gop(gop) => Some(gop.aperture()),
        }
    }
}

static ACTIVE_DISPLAY: GlobalCell<Option<ActiveDisplay>> = GlobalCell::new(None);

/// Installs output 0 for the query subops once boot has captured GOP in the reference mode.
#[cfg(not(any(test, feature = "m10-framebuffer-self-test")))]
pub(crate) fn install_gop_display() -> Result<(), DisplayError> {
    let state = DisplayState::new(clean_slate_graphics::REFERENCE_MODE)?;
    publish(ActiveDisplay { state })
}

/// Installs the GOP backend over the aperture `map_device_aperture_uncached` mapped for
/// `framebuffer`.
#[cfg(feature = "m10-framebuffer-self-test")]
pub(crate) fn install_gop_display(
    framebuffer: &BootFramebuffer,
    aperture: crate::mm::kernel_bootstrap::UncachedAperture,
) -> Result<(), DisplayError> {
    if aperture.phys_base() != framebuffer.phys_base || aperture.len() < framebuffer.byte_len {
        return Err(DisplayError::ModeUnavailable);
    }
    let byte_len =
        usize::try_from(framebuffer.byte_len).map_err(|_| DisplayError::ModeUnavailable)?;
    let writer = unsafe {
        aperture::ApertureWriter::new(
            aperture.as_mut_ptr(),
            byte_len,
            framebuffer.stride_bytes,
            framebuffer.width,
            framebuffer.height,
        )
    }
    .map_err(|_| DisplayError::ModeUnavailable)?;
    let backend =
        GopBackend::new(writer, framebuffer.order).map_err(|_| DisplayError::ModeUnavailable)?;
    publish(ActiveDisplay::new(Backend::Gop(backend))?)
}

#[cfg(not(test))]
fn publish(display: ActiveDisplay) -> Result<(), DisplayError> {
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
