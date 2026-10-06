use std::vec;
use std::vec::Vec;

use clean_slate_graphics::display::{DisplayError, PresentRequest, PresentState};
use clean_slate_graphics::{
    BufferRect, MAX_PRESENT_DAMAGE_RECTS, REFERENCE_FRAME_BYTES, REFERENCE_MODE,
};

use super::fake::FakeGpu;
use super::{wire, Command, VirtioGpuBackend, COMMAND_SLOTS, SLOT_BYTES};
use crate::device::display::engine::DisplayState;
use crate::device::display::scanout::ScanoutBuffer;
use crate::device::display::source::{
    FrameSource, FrameSourceId, FrameSourceKind, PhysExtent, SourceError,
};
use crate::device::display::{ActiveDisplay, Backend, BackendError, ScanoutBackend, Submitted};
use crate::device::virtio::dma::DmaRegion;
use crate::device::virtio::modern::{ResetReason, TransportState};
use crate::device::virtio::virtqueue::Token;
use crate::mm::shared_buffer::ArenaFrames;
use clean_slate_capability::HolderId;
use clean_slate_graphics::DISPLAY_COMMAND_TIMEOUT_NS;

const STRIDE: usize = REFERENCE_MODE.stride_bytes as usize;
const BUFFER_PAGES: u64 = (REFERENCE_FRAME_BYTES / 4096) as u64;
const NOW_NS: u64 = 5_000;

fn clock() -> u64 {
    NOW_NS
}

fn slots() -> [DmaRegion; COMMAND_SLOTS] {
    core::array::from_fn(|_| {
        let buffer = vec![0u8; SLOT_BYTES].leak();
        let phys = buffer.as_ptr() as u64;
        DmaRegion::fake(buffer, phys)
    })
}

fn backend() -> VirtioGpuBackend<FakeGpu> {
    VirtioGpuBackend::new(FakeGpu::new(), slots(), clock)
}

fn brought_up() -> VirtioGpuBackend<FakeGpu> {
    let mut gpu = backend();
    assert!(gpu.is_idle());
    gpu.begin_bring_up().expect("bring-up");
    assert!(!gpu.is_idle());
    assert_eq!(gpu.poll(), Some(Ok(())));
    assert!(gpu.is_idle());
    gpu
}

fn rect(x: u16, y: u16, width: u16, height: u16) -> BufferRect {
    BufferRect {
        x,
        y,
        width,
        height,
    }
}

/// A reference frame in two separately allocated page runs, so attach and transfers cross an
/// extent boundary (mid-row: 400 pages is not a whole number of 5120-byte rows).
struct SplitFrame {
    generation: u64,
    extents: [PhysExtent; 2],
}

impl SplitFrame {
    fn new(generation: u64) -> Self {
        let run = |pages: u32| {
            let layout =
                std::alloc::Layout::from_size_align(pages as usize * 4096, 4096).expect("layout");
            // SAFETY: nonzero size; the run is leaked for the test's lifetime.
            let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
            assert!(!ptr.is_null());
            PhysExtent {
                phys: ptr as u64,
                pages,
            }
        };
        Self {
            generation,
            extents: [run(400), run(BUFFER_PAGES as u32 - 400)],
        }
    }
}

impl FrameSource for SplitFrame {
    fn id(&self) -> FrameSourceId {
        FrameSourceId::new(FrameSourceKind::SharedBuffer, self.generation)
    }

    fn layout(&self) -> clean_slate_graphics::BufferLayout {
        reference_layout()
    }

    fn for_each_span(
        &self,
        _: usize,
        _: usize,
        _: &mut dyn FnMut(&[u8]),
    ) -> Result<(), SourceError> {
        Err(SourceError::OutOfRange)
    }

    fn phys_extents(&self) -> &[PhysExtent] {
        &self.extents
    }
}

fn reference_layout() -> clean_slate_graphics::BufferLayout {
    clean_slate_graphics::BufferLayout::new(
        1280,
        800,
        5120,
        clean_slate_graphics::PixelFormat::Xrgb8888,
    )
    .expect("layout")
}

fn buffers() -> (SplitFrame, SplitFrame) {
    (SplitFrame::new(1), SplitFrame::new(2))
}

fn paint(buffer: &dyn FrameSource, pixel: impl Fn(usize, usize) -> u8) {
    let mut offset = 0usize;
    for extent in buffer.phys_extents() {
        let len = extent.pages as usize * 4096;
        // SAFETY: host-test extents are arena memory owned by `buffer`.
        let bytes = unsafe { std::slice::from_raw_parts_mut(extent.phys as *mut u8, len) };
        for (index, byte) in bytes.iter_mut().enumerate() {
            let at = offset + index;
            *byte = pixel(at % STRIDE / 4, at / STRIDE);
        }
        offset += len;
    }
}

fn request(state: &DisplayState, index: u8, damage: &[BufferRect]) -> PresentRequest {
    let mut rects = [rect(0, 0, 0, 0); MAX_PRESENT_DAMAGE_RECTS];
    rects[..damage.len()].copy_from_slice(damage);
    PresentRequest {
        output: state.output(),
        buffer_index: index,
        damage_count: damage.len() as u8,
        rects,
    }
}

fn pixel_of(scanout: &[u8], x: usize, y: usize) -> u8 {
    scanout[y * STRIDE + x * 4]
}

#[test]
fn bring_up_sends_display_info_create_and_scanout_with_the_reference_geometry() {
    let mut gpu = backend();
    gpu.begin_bring_up().expect("bring-up");
    let device = &gpu.transport;
    assert_eq!(
        device.kinds(),
        [
            wire::CMD_GET_DISPLAY_INFO,
            wire::CMD_RESOURCE_CREATE_2D,
            wire::CMD_SET_SCANOUT
        ]
    );
    assert_eq!(device.notifies, 1, "one notify per batch");
    assert_eq!(
        device.seen[1].words,
        [1, wire::FORMAT_B8G8R8X8_UNORM, 1280, 800]
    );
    assert_eq!(device.seen[2].words, [0, 0, 1280, 800, 0, 1]);
    assert!(device
        .deadlines
        .iter()
        .all(|deadline| *deadline == NOW_NS + DISPLAY_COMMAND_TIMEOUT_NS));
    assert_eq!(gpu.poll(), Some(Ok(())));
    assert_eq!(gpu.poll(), None, "an outcome is reported once");
}

#[test]
fn a_display_that_is_not_the_reference_mode_fails_bring_up() {
    let mut gpu = backend();
    gpu.transport.display_size = (1024, 768);
    gpu.begin_bring_up().expect("bring-up");
    assert_eq!(gpu.poll(), Some(Err(BackendError::Failed)));
    assert_eq!(
        gpu.begin_bring_up(),
        Err(BackendError::Failed),
        "nothing is submitted until a reset"
    );
}

#[test]
fn present_attaches_once_transfers_exact_damage_and_flushes_its_bounds() {
    let (first, _) = buffers();
    let mut gpu = brought_up();
    let mut state = DisplayState::new(REFERENCE_MODE).expect("state");
    state.bind(&mut gpu, 0, &first).expect("bind");
    gpu.transport.seen.clear();

    let damage = [rect(10, 20, 30, 2), rect(100, 5, 4, 40)];
    let seq = state
        .present(&mut gpu, &first, &request(&state, 0, &damage), NOW_NS)
        .expect("present");
    assert_eq!(state.status().state, PresentState::InFlight);
    let device = &gpu.transport;
    assert_eq!(
        device.kinds(),
        [
            wire::CMD_RESOURCE_ATTACH_BACKING,
            wire::CMD_TRANSFER_TO_HOST_2D,
            wire::CMD_TRANSFER_TO_HOST_2D,
            wire::CMD_RESOURCE_FLUSH
        ]
    );
    let attach = &device.seen[0].words;
    let extents = first.phys_extents();
    assert_eq!((attach[0], attach[1] as usize), (1, extents.len()));
    for (entry, extent) in extents.iter().enumerate() {
        let at = 2 + entry * 4;
        let addr = u64::from(attach[at]) | (u64::from(attach[at + 1]) << 32);
        assert_eq!((addr, attach[at + 2]), (extent.phys, extent.pages * 4096));
    }
    let offset = (20 * STRIDE + 10 * 4) as u32;
    assert_eq!(device.seen[1].words, [10, 20, 30, 2, offset, 0, 1, 0]);
    assert_eq!(device.seen[3].words, [10, 5, 94, 40, 1, 0], "bounding box");

    let outcome = gpu.poll().expect("completed");
    assert_eq!(state.complete(outcome, NOW_NS + 1), Some(seq));
    assert_eq!(state.status().completed_seq, seq);

    gpu.transport.seen.clear();
    state
        .present(&mut gpu, &first, &request(&state, 0, &damage[..1]), NOW_NS)
        .expect("present again");
    assert_eq!(
        gpu.transport.kinds(),
        [wire::CMD_TRANSFER_TO_HOST_2D, wire::CMD_RESOURCE_FLUSH],
        "same buffer: no re-attach"
    );
}

#[test]
fn switching_buffers_keeps_undamaged_scanout_pixels() {
    let (first, second) = buffers();
    paint(&first, |_, _| 0xA0);
    paint(&second, |x, y| if x < 64 && y < 64 { 0xB0 } else { 0xDE });
    let mut gpu = brought_up();
    let mut state = DisplayState::new(REFERENCE_MODE).expect("state");
    state.bind(&mut gpu, 0, &first).expect("bind 0");
    state.bind(&mut gpu, 1, &second).expect("bind 1");

    let full = [rect(0, 0, 1280, 800)];
    state
        .present(&mut gpu, &first, &request(&state, 0, &full), NOW_NS)
        .expect("present A");
    state.complete(gpu.poll().expect("A done"), NOW_NS);
    gpu.transport.seen.clear();

    let damage = [rect(0, 0, 64, 64)];
    state
        .present(&mut gpu, &second, &request(&state, 1, &damage), NOW_NS)
        .expect("present B");
    assert_eq!(
        gpu.transport.kinds()[..2],
        [
            wire::CMD_RESOURCE_DETACH_BACKING,
            wire::CMD_RESOURCE_ATTACH_BACKING
        ]
    );
    assert_eq!(gpu.poll(), Some(Ok(())));
    let scanout = &gpu.transport.scanout;
    assert_eq!(pixel_of(scanout, 3, 3), 0xB0);
    assert_eq!(
        pixel_of(scanout, 64, 3),
        0xA0,
        "undamaged pixel keeps A, not the decoy"
    );
    assert_eq!(pixel_of(scanout, 1279, 799), 0xA0);
    assert!(gpu.stats().transferred_bytes == (1280 * 800 * 4 + 64 * 64 * 4) as u64);
}

#[test]
fn an_error_response_fails_the_batch_once_and_needs_a_reset() {
    let mut frames = ArenaFrames::new(BUFFER_PAGES + 8);
    let first = ScanoutBuffer::allocate(&mut frames).expect("buffer");
    let mut gpu = brought_up();
    let mut state = DisplayState::new(REFERENCE_MODE).expect("state");
    state.bind(&mut gpu, 0, &first).expect("bind");
    gpu.transport.fail_kind = Some(wire::CMD_TRANSFER_TO_HOST_2D);
    state
        .present(
            &mut gpu,
            &first,
            &request(&state, 0, &[rect(0, 0, 8, 8)]),
            NOW_NS,
        )
        .expect("accepted");
    let outcome = gpu.poll().expect("ended");
    assert_eq!(outcome, Err(BackendError::Failed));
    state.complete(outcome, NOW_NS);
    assert_eq!(state.status().state, PresentState::ResetRequired);
    assert_eq!(gpu.poll(), None);
    assert_eq!(
        gpu.submit(0, &first, &[rect(0, 0, 1, 1)]),
        Err(BackendError::Failed)
    );

    gpu.transport.fail_kind = None;
    let generation = gpu.generation();
    assert_eq!(gpu.reset(), Ok(Submitted::Pending));
    assert_eq!(gpu.generation(), generation + 1);
    assert_eq!(gpu.poll(), Some(Ok(())), "bring-up after the reset");
    gpu.transport.seen.clear();
    gpu.submit(0, &first, &[rect(0, 0, 1, 1)]).expect("submit");
    assert_eq!(
        gpu.transport.kinds()[0],
        wire::CMD_RESOURCE_ATTACH_BACKING,
        "the reset dropped the attachment"
    );
}

#[test]
fn a_timeout_reports_timeout_and_strands_the_batch() {
    let mut frames = ArenaFrames::new(BUFFER_PAGES + 8);
    let first = ScanoutBuffer::allocate(&mut frames).expect("buffer");
    let mut gpu = brought_up();
    gpu.bind(0, &first).expect("bind");
    gpu.transport.stall = true;
    assert_eq!(
        gpu.submit(0, &first, &[rect(0, 0, 8, 8)]),
        Ok(Submitted::Pending)
    );
    assert_eq!(gpu.poll(), None, "still in flight");
    gpu.transport.time_out();
    assert_eq!(gpu.poll(), Some(Err(BackendError::Timeout)));
    assert_eq!(gpu.poll(), None);
    assert_eq!(
        gpu.transport.state,
        TransportState::ResetRequired(ResetReason::Timeout)
    );
    gpu.transport.stall = false;
    assert_eq!(gpu.reset(), Ok(Submitted::Pending));
    assert_eq!(gpu.poll(), Some(Ok(())));
}

#[test]
fn a_completion_for_an_unknown_token_is_a_failure() {
    let mut gpu = brought_up();
    gpu.transport.stall = true;
    gpu.begin_bring_up().expect("batch");
    gpu.transport.inject_completion(Token::fake(0, 0, 999));
    assert_eq!(gpu.poll(), Some(Err(BackendError::Failed)));
    assert_eq!(gpu.poll(), None);
}

#[test]
fn a_failed_device_reset_is_permanent() {
    let mut gpu = brought_up();
    gpu.transport.fail_reset = true;
    assert_eq!(gpu.reset(), Err(BackendError::Failed));
}

#[test]
fn held_notify_publishes_without_telling_the_device() {
    let mut gpu = brought_up();
    let notifies = gpu.transport.notifies;
    gpu.hold_next_notify();
    gpu.begin_bring_up().expect("published");
    assert_eq!(gpu.transport.notifies, notifies);
    assert_eq!(gpu.poll(), None);
}

struct FakeSource {
    extents: Vec<PhysExtent>,
}

impl FrameSource for FakeSource {
    fn id(&self) -> FrameSourceId {
        FrameSourceId::new(FrameSourceKind::SharedBuffer, 77)
    }

    fn layout(&self) -> clean_slate_graphics::BufferLayout {
        reference_layout()
    }

    fn for_each_span(
        &self,
        _: usize,
        _: usize,
        _: &mut dyn FnMut(&[u8]),
    ) -> Result<(), SourceError> {
        Err(SourceError::OutOfRange)
    }

    fn phys_extents(&self) -> &[PhysExtent] {
        &self.extents
    }
}

#[test]
fn bind_validates_the_backing_extents() {
    let mut gpu = backend();
    let extent = |phys, pages| PhysExtent { phys, pages };
    let pages = BUFFER_PAGES as u32;
    let rejected = [
        vec![],
        vec![extent(0x10_0000, pages - 1)],
        vec![extent(0x10_0000, pages + 1)],
        vec![extent(0x10_0010, pages)],
        vec![extent(0x10_0000, 0), extent(0x20_0000, pages)],
        vec![extent(0x1000, 1); 17],
        vec![extent(u64::MAX & !0xfff, pages)],
    ];
    for extents in rejected {
        let source = FakeSource { extents };
        assert_eq!(gpu.bind(0, &source), Err(BackendError::SourceRejected));
    }
    let split = FakeSource {
        extents: vec![extent(0x10_0000, 400), extent(0x80_0000, pages - 400)],
    };
    assert_eq!(gpu.bind(1, &split), Ok(()));
    assert_eq!(gpu.bind(2, &split), Err(BackendError::SourceRejected));
    let other = FakeSource {
        extents: split.extents.clone(),
    };
    let _ = other;
    assert_eq!(
        gpu.submit(0, &split, &[rect(0, 0, 1, 1)]),
        Err(BackendError::SourceRejected),
        "index 0 has no binding"
    );
}

#[test]
fn present_commands_fit_beside_a_bring_up_batch() {
    let mut frames = ArenaFrames::new(BUFFER_PAGES + 8);
    let first = ScanoutBuffer::allocate(&mut frames).expect("buffer");
    let mut gpu = backend();
    gpu.bind(0, &first).expect("bind");
    gpu.transport.stall = true;
    gpu.begin_bring_up().expect("bring-up");
    let damage: Vec<BufferRect> = (0..MAX_PRESENT_DAMAGE_RECTS as u16)
        .map(|i| rect(i * 8, 0, 4, 4))
        .collect();
    assert_eq!(gpu.submit(0, &first, &damage), Ok(Submitted::Pending));
    assert_eq!(
        gpu.transport.deadlines.len(),
        3 + 1 + MAX_PRESENT_DAMAGE_RECTS + 1
    );
    assert!(matches!(
        super::encode(Command::AttachBacking(1), &gpu.backings, &mut [0; 512]),
        Err(BackendError::SourceRejected)
    ));
}

const PRESENTER: HolderId = HolderId(31);

fn gpu_display(frames: &mut ArenaFrames) -> ActiveDisplay {
    let mut display =
        ActiveDisplay::new(Backend::VirtioGpu(Box::leak(Box::new(brought_up())))).expect("display");
    display
        .map_scanout(PRESENTER, 0, frames, |_, _| Ok(0x4000_0000))
        .expect("map");
    display
}

fn gpu_of(display: &mut ActiveDisplay) -> &mut VirtioGpuBackend<FakeGpu> {
    let Backend::VirtioGpu(gpu) = &mut display.backend else {
        panic!("gpu backend");
    };
    gpu
}

#[test]
fn service_completes_presents_and_recovers_a_timed_out_device_with_a_new_epoch() {
    let mut frames = ArenaFrames::new(BUFFER_PAGES + 8);
    let mut display = gpu_display(&mut frames);
    let req = |display: &ActiveDisplay| request(display.state(), 0, &[rect(0, 0, 16, 16)]);

    let first = req(&display);
    assert_eq!(display.present_scanout(PRESENTER, &first, NOW_NS), Ok(1));
    assert_eq!(display.state().status().state, PresentState::InFlight);
    assert_eq!(
        display.present_scanout(PRESENTER, &first, NOW_NS),
        Err(DisplayError::BufferBusy)
    );
    display.service(NOW_NS + 10, false);
    let status = display.state().status();
    assert_eq!(
        (status.state, status.completed_seq),
        (PresentState::Idle, 1)
    );

    gpu_of(&mut display).transport.stall = true;
    assert_eq!(display.present_scanout(PRESENTER, &first, NOW_NS), Ok(2));
    gpu_of(&mut display).transport.time_out();
    display.service(NOW_NS + 20, false);
    let status = display.state().status();
    assert_eq!(status.state, PresentState::ResetRequired);
    assert_eq!(status.last_error, Some(DisplayError::DeviceTimeout));
    assert_eq!(status.completed_seq, 2);
    assert_eq!(
        display.present_scanout(PRESENTER, &first, NOW_NS),
        Err(DisplayError::ResetRequired)
    );

    gpu_of(&mut display).transport.stall = false;
    display.service(NOW_NS + 30, true);
    assert_eq!(
        display.state().status().state,
        PresentState::ResetRequired,
        "the reset's bring-up is still in flight"
    );
    display.service(NOW_NS + 40, false);
    let status = display.state().status();
    assert_eq!(status.state, PresentState::Idle);
    assert_eq!(status.output.backend_epoch(), 2);
    assert_eq!(
        display.present_scanout(PRESENTER, &first, NOW_NS),
        Err(DisplayError::StaleEpoch)
    );
    assert_eq!(
        display.present_scanout(PRESENTER, &req(&display), NOW_NS),
        Ok(3)
    );
}

#[test]
fn service_expires_a_present_the_device_never_answers() {
    let mut frames = ArenaFrames::new(BUFFER_PAGES + 8);
    let mut display = gpu_display(&mut frames);
    gpu_of(&mut display).transport.stall = true;
    let req = request(display.state(), 0, &[rect(0, 0, 4, 4)]);
    assert_eq!(display.present_scanout(PRESENTER, &req, NOW_NS), Ok(1));
    display.service(NOW_NS + DISPLAY_COMMAND_TIMEOUT_NS - 1, false);
    assert_eq!(display.state().status().state, PresentState::InFlight);
    display.service(NOW_NS + DISPLAY_COMMAND_TIMEOUT_NS, false);
    assert_eq!(
        display.state().status().last_error,
        Some(DisplayError::DeviceTimeout)
    );
}

#[test]
fn a_failed_bring_up_faults_the_idle_output_and_a_second_failure_poisons_it() {
    let mut gpu = backend();
    gpu.transport.display_size = (800, 600);
    gpu.begin_bring_up().expect("bring-up");
    let mut display =
        ActiveDisplay::new(Backend::VirtioGpu(Box::leak(Box::new(gpu)))).expect("display");
    display.service(NOW_NS, false);
    let status = display.state().status();
    assert_eq!(status.state, PresentState::ResetRequired);
    assert_eq!(status.completed_seq, 0, "no present completed");
    display.service(NOW_NS, true);
    display.service(NOW_NS, true);
    assert_eq!(display.state().status().state, PresentState::Poisoned);
}

#[test]
fn transfer_log_records_each_damage_rect_by_buffer() {
    let (first, second) = buffers();
    let mut gpu = brought_up();
    gpu.bind(0, &first).expect("bind 0");
    gpu.bind(1, &second).expect("bind 1");
    gpu.submit(0, &first, &[rect(0, 0, 2, 2)]).expect("0");
    assert_eq!(gpu.poll(), Some(Ok(())));
    gpu.submit(1, &second, &[rect(4, 4, 1, 1), rect(9, 9, 1, 1)])
        .expect("1");
    let log: Vec<(u8, BufferRect)> = gpu
        .transfer_log()
        .map(|entry| (entry.buffer_index, entry.rect))
        .collect();
    assert_eq!(
        log,
        [
            (0, rect(0, 0, 2, 2)),
            (1, rect(4, 4, 1, 1)),
            (1, rect(9, 9, 1, 1))
        ]
    );
    assert_eq!(gpu.poll(), Some(Ok(())));
    gpu.begin_release().expect("release");
    assert_eq!(
        gpu.transport.kinds()[gpu.transport.seen.len() - 2..],
        [wire::CMD_RESOURCE_DETACH_BACKING, wire::CMD_RESOURCE_UNREF]
    );
    assert_eq!(gpu.poll(), Some(Ok(())));
}
