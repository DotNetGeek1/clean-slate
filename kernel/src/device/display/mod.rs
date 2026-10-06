//! Kernel display: scanout backends behind one present engine (#111 GOP; #114 VirtIO-GPU next).
//!
//! Backends carry no UI policy (no cursor, layout or background). Clients never see the aperture,
//! its stride, or physical addresses: they get the frozen reference mode and the presenter's two
//! kernel-owned scanout buffers through syscall 18.

pub(crate) mod aperture;
pub(crate) mod engine;
#[cfg(feature = "m10-framebuffer-self-test")]
pub(crate) mod frame;
pub(crate) mod gop;
#[cfg(any(test, feature = "m10-framebuffer-self-test"))]
pub(crate) mod presenter;
pub(crate) mod scanout;
pub(crate) mod source;
#[cfg(test)]
pub(crate) mod test_support;
#[cfg(any(test, clean_slate_virtio_gpu))]
pub(crate) mod virtio_gpu;

use clean_slate_capability::HolderId;
use clean_slate_graphics::display::PresentState;
use clean_slate_graphics::display::{DisplayError, PresentRequest, ScanoutMapping};
use clean_slate_graphics::{BufferRect, DisplayMode, REFERENCE_FRAME_BYTES, SCANOUT_BUFFER_COUNT};
use clean_slate_native_abi::SharedBufferId;

use crate::arch::x86_64::cpu::without_interrupts;
#[cfg(not(test))]
use crate::boot::gop::BootFramebuffer;
use crate::mm::shared_buffer::{BufferFrames, ShareError};
use crate::sched::work_set::WorkSetBinding;
use crate::sync::global_cell::GlobalCell;

use engine::DisplayState;
use gop::GopBackend;
use scanout::{Presenter, ScanoutBuffer};
use source::FrameSource;

/// M10 drives exactly one physical output (`MAX_OUTPUTS`); capabilities name it by index (S10).
pub(crate) const PRIMARY_OUTPUT_INDEX: u8 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Submitted {
    Completed,
    #[cfg(any(test, clean_slate_virtio_gpu))]
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
    /// `Pending` completes later: [`Self::poll`] reports it.
    fn submit(
        &mut self,
        index: u8,
        source: &dyn FrameSource,
        damage: &[BufferRect],
    ) -> Result<Submitted, BackendError>;

    /// Harvests device completions. `Some` ends whatever was pending (a present, a reset, or the
    /// VirtIO-GPU bring-up) exactly once. Runs with interrupts masked, including from the backend's
    /// interrupt sink.
    fn poll(&mut self) -> Option<Result<(), BackendError>> {
        None
    }

    /// Leaves `ResetRequired`: `Completed` when the backend is usable now, `Pending` when [`Self::poll`]
    /// reports the outcome later. Strands everything submitted before it.
    fn reset(&mut self) -> Result<Submitted, BackendError>;
}

pub(crate) enum Backend {
    Gop(GopBackend),
    /// The boot's one GPU lives in its own static (`virtio_gpu::install`).
    #[cfg(any(test, clean_slate_virtio_gpu))]
    VirtioGpu(&'static mut virtio_gpu::MmioGpuBackend),
    #[cfg(test)]
    Recording(test_support::RecordingScanout),
}

impl Backend {
    fn scanout(&mut self) -> &mut dyn ScanoutBackend {
        match self {
            Self::Gop(gop) => gop,
            #[cfg(any(test, clean_slate_virtio_gpu))]
            Self::VirtioGpu(gpu) => *gpu,
            #[cfg(test)]
            Self::Recording(recording) => recording,
        }
    }
}

pub(crate) struct ActiveDisplay {
    state: DisplayState,
    backend: Backend,
    presenter: Presenter,
    buffers: [Option<ScanoutBuffer>; SCANOUT_BUFFER_COUNT],
    /// A backend reset was submitted and has not been reported by `poll` yet.
    resetting: bool,
}

impl ActiveDisplay {
    pub(crate) fn new(mut backend: Backend) -> Result<Self, DisplayError> {
        let state = DisplayState::new(backend.scanout().mode())?;
        Ok(Self {
            state,
            backend,
            presenter: Presenter::default(),
            buffers: [const { None }; SCANOUT_BUFFER_COUNT],
            resetting: false,
        })
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

    /// `MAP_SCANOUT` after authorisation: presenter → index → buffer (allocated, pinned and bound
    /// on first use) → `map` into the caller. Binds `holder` as presenter only on success.
    pub(crate) fn map_scanout<F: BufferFrames>(
        &mut self,
        holder: HolderId,
        index: u8,
        frames: &mut F,
        map: impl FnOnce(SharedBufferId, &mut F) -> Result<u64, ShareError>,
    ) -> Result<ScanoutMapping, u64> {
        self.presenter
            .check(holder, true)
            .map_err(DisplayError::status)?;
        let slot = self
            .buffers
            .get_mut(usize::from(index))
            .ok_or(DisplayError::InvalidBuffer.status())?;
        if slot.is_none() {
            let buffer = ScanoutBuffer::allocate(frames).map_err(ShareError::status)?;
            if let Err(error) = self.state.bind(self.backend.scanout(), index, &buffer) {
                buffer.release(frames);
                return Err(error.status());
            }
            *slot = Some(buffer);
        }
        let id = slot
            .as_ref()
            .map(ScanoutBuffer::id)
            .expect("buffer bound above");
        let user_va = map(id, frames).map_err(ShareError::status)?;
        self.presenter.bind_mapping(holder, index);
        let mode = self.state.mode_info().mode;
        Ok(ScanoutMapping {
            output: self.state.output(),
            buffer_index: index,
            user_va,
            byte_len: REFERENCE_FRAME_BYTES as u64,
            stride_bytes: mode.stride_bytes,
        })
    }

    /// `PRESENT` after authorisation and decode, in the frozen order: backend state → presenter →
    /// `validate` → index mapped → in-flight gate → accept. Signals the wake bit when the backend
    /// completed (or failed) synchronously.
    pub(crate) fn present_scanout(
        &mut self,
        holder: HolderId,
        request: &PresentRequest,
        now_ns: u64,
    ) -> Result<u64, DisplayError> {
        self.state.check_accepting()?;
        self.presenter.check(holder, false)?;
        request.validate(self.state.output(), &self.state.mode_info().mode)?;
        let buffer = self
            .buffers
            .get(usize::from(request.buffer_index))
            .and_then(Option::as_ref)
            .filter(|_| self.presenter.is_mapped(request.buffer_index))
            .ok_or(DisplayError::InvalidBuffer)?;
        let seq = self
            .state
            .present(self.backend.scanout(), buffer, request, now_ns)?;
        if self.state.status().completed_seq == seq {
            self.presenter.signal();
        }
        Ok(seq)
    }

    /// `BIND_WAKE` after authorisation and bit validation: only the bound presenter may bind.
    pub(crate) fn bind_wake(
        &mut self,
        holder: HolderId,
        bind: impl FnOnce() -> Result<(WorkSetBinding, u32), u64>,
    ) -> Result<(), u64> {
        self.presenter
            .check(holder, false)
            .map_err(DisplayError::status)?;
        let (binding, bit) = bind()?;
        self.presenter.bind_wake(binding, bit);
        Ok(())
    }

    /// Teardown slot 2: drops `holder`'s presenter binding and wake; buffers stay bound.
    pub(crate) fn release_presenter(&mut self, holder: HolderId) -> bool {
        self.presenter.release(holder)
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

    /// Advances the output on a device event or at a syscall-18 entry: harvest the backend, fail an
    /// in-flight present whose deadline passed, and (`may_reset`, never from interrupt context)
    /// start the reset `ResetRequired` asks for. Every visible status change signals the wake bit.
    pub(crate) fn service(&mut self, now_ns: u64, may_reset: bool) {
        let before = self.state.status();
        match self.backend.scanout().poll() {
            Some(result) if self.resetting => {
                self.resetting = false;
                self.state.finish_reset(result.is_ok());
            }
            Some(result) if self.state.in_flight_deadline().is_some() => {
                self.state.complete(result, now_ns);
            }
            Some(Err(error)) => self.state.fault(error),
            Some(Ok(())) => {}
            None if !self.resetting => {
                self.state.expire(now_ns);
            }
            None => {}
        }
        if may_reset && !self.resetting && self.state.status().state == PresentState::ResetRequired
        {
            match self.backend.scanout().reset() {
                Ok(Submitted::Completed) => self.state.finish_reset(true),
                #[cfg(any(test, clean_slate_virtio_gpu))]
                Ok(Submitted::Pending) => self.resetting = true,
                Err(_) => self.state.finish_reset(false),
            }
        }
        if self.state.status() != before {
            self.presenter.signal();
        }
    }

    /// The syscall-18 reset step, run only once the caller's `DISPLAY_PRESENT` authority has been
    /// checked: starts a pending reset for the bound presenter, or for any such caller while no
    /// presenter is bound (it could bind by mapping). Everyone else leaves the reset pending.
    pub(crate) fn service_for_presenter(&mut self, holder: HolderId, now_ns: u64) {
        if self.presenter.check(holder, true).is_ok() {
            self.service(now_ns, true);
        }
    }

    /// Leaves `ResetRequired` through a backend reset: a new epoch on success, `Poisoned` otherwise.
    #[cfg(test)]
    pub(crate) fn recover(&mut self) {
        self.service(0, true);
    }

    #[cfg(feature = "m10-framebuffer-self-test")]
    pub(crate) fn gop_aperture(&self) -> Option<&aperture::ApertureWriter> {
        match &self.backend {
            Backend::Gop(gop) => Some(gop.aperture()),
            #[cfg(any(test, clean_slate_virtio_gpu))]
            Backend::VirtioGpu(_) => None,
            #[cfg(test)]
            Backend::Recording(_) => None,
        }
    }

    #[cfg(feature = "m10-virtio-gpu-self-test")]
    pub(crate) fn virtio_gpu_mut(&mut self) -> Option<&mut virtio_gpu::MmioGpuBackend> {
        match &mut self.backend {
            Backend::VirtioGpu(gpu) => Some(*gpu),
            Backend::Gop(_) => None,
            #[cfg(test)]
            Backend::Recording(_) => None,
        }
    }

    #[cfg(feature = "m10-virtio-gpu-self-test")]
    pub(crate) fn scanout_buffer(&self, index: u8) -> Option<&ScanoutBuffer> {
        self.buffers.get(usize::from(index))?.as_ref()
    }
}

/// Uninstalls the output and hands back its VirtIO-GPU backend, if that is what it was. The
/// scanout buffers stay pinned for the rest of the boot.
#[cfg(all(not(test), feature = "m10-virtio-gpu-self-test"))]
pub(crate) fn take_virtio_gpu() -> Option<virtio_gpu::MmioGpuBackend> {
    let display = without_interrupts(|| unsafe { (*ACTIVE_DISPLAY.get()).take() })?;
    match display.backend {
        Backend::VirtioGpu(_) => virtio_gpu::take_installed(),
        Backend::Gop(_) => None,
    }
}

static ACTIVE_DISPLAY: GlobalCell<Option<ActiveDisplay>> = GlobalCell::new(None);

/// Installs the GOP backend over the aperture `map_device_aperture_uncached` mapped for
/// `framebuffer`.
#[cfg(not(test))]
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
    publish(ActiveDisplay::new(Backend::Gop(backend))?, "gop")
}

/// Claims the modern `virtio-gpu-pci` function when GOP left no display, and installs it with its
/// bring-up batch in flight (#114). Interrupts and the W3 timeout path must already be live; the
/// bring-up completes asynchronously and a failure surfaces as `ResetRequired` and then `Poisoned`.
#[cfg(all(not(test), clean_slate_virtio_gpu))]
pub(crate) fn install_virtio_gpu_display() -> Result<(), virtio_gpu::GpuInitError> {
    if with_active_display(|display| display.is_some()) {
        return Err(virtio_gpu::GpuInitError::DisplayPresent);
    }
    let backend = virtio_gpu::install(virtio_gpu::begin_mmio(on_backend_interrupt)?)?;
    publish(
        ActiveDisplay::new(Backend::VirtioGpu(backend))
            .map_err(|_| virtio_gpu::GpuInitError::Mode)?,
        "virtio-gpu",
    )
    .map_err(|_| virtio_gpu::GpuInitError::Mode)
}

/// Production boot tail: brings up VirtIO-GPU only when GOP left no display installed.
#[cfg(all(not(test), clean_slate_boot_tail))]
pub(crate) fn begin_virtio_gpu_and_log() {
    match install_virtio_gpu_display() {
        Ok(()) | Err(virtio_gpu::GpuInitError::DisplayPresent) => {}
        Err(error) => crate::diagnostics::serial::serial_write_fmt(format_args!(
            "[DISP] virtio-gpu unavailable reason={}\n",
            error.name()
        )),
    }
}

/// The VirtIO-GPU queue and W3 timeout sink (interrupt context, single CPU, interrupts masked):
/// harvest completions into the engine and wake the presenter. Never resets.
#[cfg(all(not(test), clean_slate_virtio_gpu))]
fn on_backend_interrupt() {
    let now_ns = crate::time::monotonic_ns();
    with_active_display(|display| {
        if let Some(display) = display {
            display.service(now_ns, false);
        }
    });
}

#[cfg(not(test))]
fn publish(display: ActiveDisplay, backend: &str) -> Result<(), DisplayError> {
    let output = display.state().output();
    without_interrupts(|| unsafe { *ACTIVE_DISPLAY.get() = Some(display) });
    crate::diagnostics::serial::serial_write_fmt(format_args!(
        "[DISP] backend={backend} output={} epoch={}\n",
        output.index(),
        output.backend_epoch()
    ));
    Ok(())
}

#[cfg(test)]
pub(crate) fn install_for_test(display: Option<ActiveDisplay>) {
    without_interrupts(|| unsafe { *ACTIVE_DISPLAY.get() = display });
}

/// A recording output whose `presenter` mapped buffer 0 and whose last present failed, leaving
/// `ResetRequired` pending.
#[cfg(test)]
pub(crate) fn reset_pending_for_test(
    presenter: HolderId,
    frames: &mut crate::mm::shared_buffer::ArenaFrames,
) -> ActiveDisplay {
    use test_support::{RecordingScanout, Reply};

    let mut display = ActiveDisplay::new(Backend::Recording(RecordingScanout::reference(
        Reply::Completed,
    )))
    .expect("display");
    display
        .map_scanout(presenter, 0, frames, |id, _| {
            Ok(0x4000_0000 + u64::from(id.slot()) * 0x40_0000)
        })
        .expect("map 0");
    let Backend::Recording(recording) = &mut display.backend else {
        unreachable!("recording backend");
    };
    recording.reply = Reply::Fail(BackendError::Failed);
    let damage = BufferRect {
        x: 0,
        y: 0,
        width: 8,
        height: 2,
    };
    let mut request = PresentRequest {
        output: display.state().output(),
        buffer_index: 0,
        damage_count: 1,
        rects: [damage; clean_slate_graphics::MAX_PRESENT_DAMAGE_RECTS],
    };
    request.rects[1..].fill(BufferRect {
        x: 0,
        y: 0,
        width: 0,
        height: 0,
    });
    display
        .present_scanout(presenter, &request, 1)
        .expect("accepted");
    assert_eq!(display.state().status().state, PresentState::ResetRequired);
    let Backend::Recording(recording) = &mut display.backend else {
        unreachable!("recording backend");
    };
    recording.reply = Reply::Completed;
    display
}

/// Runs `f` on the installed output, or `None` when boot found no display backend.
pub(crate) fn with_active_display<R>(f: impl FnOnce(Option<&mut ActiveDisplay>) -> R) -> R {
    without_interrupts(|| f(unsafe { (*ACTIVE_DISPLAY.get()).as_mut() }))
}

/// Teardown slot 2 of the shared hook block (after the port, before the input consumer): releases
/// `holder`'s presenter binding and unmaps its scanout grants. Returns the rows unmapped.
pub(crate) fn release_presenter_for_holder(
    holder: HolderId,
    frames: &mut impl BufferFrames,
) -> usize {
    let released = with_active_display(|display| {
        display.is_some_and(|display| display.release_presenter(holder))
    });
    if !released {
        return 0;
    }
    crate::mm::shared_buffer::kernel_owned::unmap_kernel_grants_for(holder.0, frames)
}

#[cfg(test)]
mod tests {
    use clean_slate_capability::HolderId;
    use clean_slate_graphics::display::{DisplayError, PresentRequest, PresentState};
    use clean_slate_graphics::{BufferRect, REFERENCE_FRAME_BYTES, REFERENCE_MODE};
    use clean_slate_native_abi::SharedBufferId;

    use super::test_support::{RecordingScanout, Reply};
    use super::{ActiveDisplay, Backend};
    use crate::mm::shared_buffer::{ArenaFrames, ShareError};
    use crate::mm::PAGE_SIZE;

    const PRESENTER: HolderId = HolderId(21);
    const STRANGER: HolderId = HolderId(22);
    const BUFFER_PAGES: usize = REFERENCE_FRAME_BYTES / PAGE_SIZE as usize;

    fn display(reply: Reply) -> ActiveDisplay {
        ActiveDisplay::new(Backend::Recording(RecordingScanout::reference(reply))).expect("display")
    }

    fn fake_map(id: SharedBufferId, _: &mut ArenaFrames) -> Result<u64, ShareError> {
        Ok(0x4000_0000 + u64::from(id.slot()) * 0x40_0000)
    }

    fn map(
        display: &mut ActiveDisplay,
        holder: HolderId,
        index: u8,
        frames: &mut ArenaFrames,
    ) -> Result<u64, u64> {
        display
            .map_scanout(holder, index, frames, fake_map)
            .map(|mapping| mapping.user_va)
    }

    fn request(display: &ActiveDisplay, index: u8) -> PresentRequest {
        let damage = BufferRect {
            x: 0,
            y: 0,
            width: 8,
            height: 2,
        };
        let mut request = PresentRequest {
            output: display.state().output(),
            buffer_index: index,
            damage_count: 1,
            rects: [damage; clean_slate_graphics::MAX_PRESENT_DAMAGE_RECTS],
        };
        request.rects[1..].fill(BufferRect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        });
        request
    }

    #[test]
    fn map_scanout_allocates_lazily_binds_the_presenter_and_is_idempotent() {
        let mut frames = ArenaFrames::new(2 * BUFFER_PAGES as u64 + 64);
        let mut display = display(Reply::Completed);
        let base = frames.live_frames();

        assert_eq!(
            map(&mut display, PRESENTER, 2, &mut frames),
            Err(DisplayError::InvalidBuffer.status())
        );
        assert_eq!(frames.live_frames(), base, "a bad index allocates nothing");

        let mapping = display
            .map_scanout(PRESENTER, 0, &mut frames, fake_map)
            .expect("map 0");
        assert_eq!(mapping.output, display.state().output());
        assert_eq!(mapping.buffer_index, 0);
        assert_eq!(mapping.byte_len, REFERENCE_FRAME_BYTES as u64);
        assert_eq!(mapping.stride_bytes, REFERENCE_MODE.stride_bytes);
        assert_eq!(frames.live_frames(), base + BUFFER_PAGES);

        assert_eq!(
            map(&mut display, PRESENTER, 0, &mut frames),
            Ok(mapping.user_va)
        );
        assert_eq!(
            frames.live_frames(),
            base + BUFFER_PAGES,
            "idempotent per index"
        );
        assert_eq!(
            map(&mut display, STRANGER, 1, &mut frames),
            Err(DisplayError::NotPresenter.status())
        );
        assert_eq!(frames.live_frames(), base + BUFFER_PAGES);
    }

    #[test]
    fn failed_map_into_the_caller_binds_no_presenter() {
        let mut frames = ArenaFrames::new(BUFFER_PAGES as u64 + 64);
        let mut display = display(Reply::Completed);
        let refused =
            display.map_scanout(PRESENTER, 0, &mut frames, |_, _| Err(ShareError::NoSpace));
        assert_eq!(refused, Err(ShareError::NoSpace.status()));
        assert_eq!(
            map(&mut display, STRANGER, 0, &mut frames).map(|_| ()),
            Ok(()),
            "the buffer stays bound; the first successful mapper becomes presenter"
        );
    }

    #[test]
    fn present_runs_presenter_then_validate_then_mapped_then_in_flight() {
        let mut frames = ArenaFrames::new(2 * BUFFER_PAGES as u64 + 64);
        let mut display = display(Reply::Pending);
        let req0 = request(&display, 0);
        assert_eq!(
            display.present_scanout(PRESENTER, &req0, 1),
            Err(DisplayError::NotPresenter),
            "no presenter bound yet"
        );
        map(&mut display, PRESENTER, 0, &mut frames).expect("map 0");
        assert_eq!(
            display.present_scanout(STRANGER, &req0, 1),
            Err(DisplayError::NotPresenter)
        );
        let mut stale = req0;
        stale.output = clean_slate_graphics::OutputId::new(0, 2).expect("epoch 2");
        assert_eq!(
            display.present_scanout(PRESENTER, &stale, 1),
            Err(DisplayError::StaleEpoch)
        );
        assert_eq!(
            display.present_scanout(PRESENTER, &request(&display, 1), 1),
            Err(DisplayError::InvalidBuffer),
            "index 1 is not mapped"
        );
        assert_eq!(display.present_scanout(PRESENTER, &req0, 1), Ok(1));
        assert_eq!(display.state().status().state, PresentState::InFlight);
        assert_eq!(
            display.present_scanout(PRESENTER, &req0, 2),
            Err(DisplayError::BufferBusy)
        );
    }

    #[test]
    fn synchronous_present_completes_and_a_failed_backend_requires_reset() {
        let mut frames = ArenaFrames::new(BUFFER_PAGES as u64 + 64);
        let mut display = display(Reply::Completed);
        map(&mut display, PRESENTER, 0, &mut frames).expect("map 0");
        let req0 = request(&display, 0);
        assert_eq!(display.present_scanout(PRESENTER, &req0, 5), Ok(1));
        let status = display.state().status();
        assert_eq!(
            (status.state, status.completed_seq),
            (PresentState::Idle, 1)
        );

        let Backend::Recording(recording) = &mut display.backend else {
            panic!("recording backend");
        };
        recording.reply = Reply::Fail(super::BackendError::Failed);
        assert_eq!(display.present_scanout(PRESENTER, &req0, 6), Ok(2));
        assert_eq!(display.state().status().state, PresentState::ResetRequired);
        assert_eq!(
            display.present_scanout(PRESENTER, &req0, 7),
            Err(DisplayError::ResetRequired),
            "backend state is checked before the presenter"
        );
        assert_eq!(
            display.present_scanout(STRANGER, &req0, 7),
            Err(DisplayError::ResetRequired)
        );
    }

    #[test]
    fn bind_wake_needs_the_bound_presenter() {
        let mut frames = ArenaFrames::new(BUFFER_PAGES as u64 + 64);
        let mut display = display(Reply::Completed);
        assert_eq!(
            display.bind_wake(PRESENTER, || unreachable!(
                "work set resolved before presenter"
            )),
            Err(DisplayError::NotPresenter.status())
        );
        map(&mut display, PRESENTER, 0, &mut frames).expect("map 0");
        assert_eq!(
            display.bind_wake(STRANGER, || unreachable!()),
            Err(DisplayError::NotPresenter.status())
        );
        assert_eq!(display.bind_wake(PRESENTER, || Err(77)), Err(77));
        assert!(display.presenter.wake().is_none());
    }

    #[test]
    fn released_presenter_frees_the_binding_but_not_the_buffers() {
        let mut frames = ArenaFrames::new(2 * BUFFER_PAGES as u64 + 64);
        let mut display = display(Reply::Completed);
        map(&mut display, PRESENTER, 0, &mut frames).expect("map 0");
        let live = frames.live_frames();
        assert!(!display.release_presenter(STRANGER));
        assert!(display.release_presenter(PRESENTER));
        assert!(!display.release_presenter(PRESENTER), "released once");
        assert_eq!(
            display.present_scanout(STRANGER, &request(&display, 0), 1),
            Err(DisplayError::NotPresenter)
        );
        map(&mut display, STRANGER, 0, &mut frames).expect("successor maps the same buffer");
        assert_eq!(frames.live_frames(), live);
        assert_eq!(
            display.present_scanout(STRANGER, &request(&display, 0), 1),
            Ok(1)
        );
    }

    #[test]
    fn teardown_releases_the_installed_presenter_only_for_its_holder() {
        let mut frames = ArenaFrames::new(BUFFER_PAGES as u64 + 64);
        assert_eq!(
            super::release_presenter_for_holder(PRESENTER, &mut frames),
            0
        );
        let mut installed = display(Reply::Completed);
        map(&mut installed, PRESENTER, 0, &mut frames).expect("map 0");
        super::install_for_test(Some(installed));
        let holder =
            || super::with_active_display(|display| display.expect("installed").presenter.holder());
        super::release_presenter_for_holder(STRANGER, &mut frames);
        assert_eq!(holder(), Some(PRESENTER));
        super::release_presenter_for_holder(PRESENTER, &mut frames);
        assert_eq!(holder(), None);
        super::install_for_test(None);
    }
}
