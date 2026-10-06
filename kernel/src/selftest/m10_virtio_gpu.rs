//! Boot-context probe of the VirtIO-GPU scanout backend (#114) over the #196 modern transport,
//! against a modern-only `virtio-gpu-pci` at the reference mode.
//!
//! It drives the same `MAP_SCANOUT`/`PRESENT` path as syscall 18 (a kernel holder stands in for
//! the presenter) and only reads the output status while it waits: every completion is harvested
//! by the backend's interrupt sink or by the W3 timeout path, never by this loop. Each step prints
//! a `[VGPU]` marker that `cargo xtask test-m10-virtio-gpu` checks.
//!
//! Readback is guest-side: the 2D command set cannot read the host resource back, so the probe
//! replays the logged transfers from the scanout buffers into a model of the host resource and
//! checks its CRC against the #111 reference golden. Visual proof is #118/#119 through #197.

use clean_slate_capability::HolderId;
use clean_slate_graphics::display::{DisplayError, PresentRequest, PresentState, PresentStatus};
use clean_slate_graphics::{
    BufferRect, Rect, MAX_PRESENT_DAMAGE_RECTS, REFERENCE_FRAME_BYTES, REFERENCE_MODE,
};
use clean_slate_raster::{
    draw_reference_a, draw_reference_b, draw_reference_decoy, reference_layout, visible_crc32,
    Canvas, REFERENCE_B_DAMAGE,
};

use crate::device::display::source::FrameSource;
use crate::device::display::virtio_gpu::{GpuStats, LoggedTransfer, MmioGpuBackend};
use crate::device::display::{install_virtio_gpu_display, take_virtio_gpu, with_active_display};
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::layout::phys_to_virt;
use crate::mm::PAGE_SIZE;
use crate::sched::timeout;
use crate::selftest::boot_wait;
use crate::serial_write_fmt;
use crate::time::monotonic_ns;

/// Stands in for the compositor's process; no process ever has this id.
const HOLDER: HolderId = HolderId(u64::MAX - 0x114);
/// `draw_reference_a` then `draw_reference_b` (the #111 golden; the decoy is never transferred).
const REFERENCE_CRC: u32 = 0x20F2_EEC9;
/// Longer than `DISPLAY_COMMAND_TIMEOUT_NS`, so W3 always decides first.
const WAIT_BUDGET_MS: u64 = 2_500;
const FULL_FRAME: BufferRect = BufferRect {
    x: 0,
    y: 0,
    width: REFERENCE_MODE.width_px as u16,
    height: REFERENCE_MODE.height_px as u16,
};
const NO_RECT: BufferRect = BufferRect {
    x: 0,
    y: 0,
    width: 0,
    height: 0,
};

type Probe<T> = Result<T, &'static str>;

pub(crate) fn run_m10_virtio_gpu_self_test(allocator: &mut PageAllocator) -> Probe<()> {
    boot_wait::init_clock()?;
    run(allocator).map_err(|reason| {
        serial_write_fmt(format_args!("[FAIL] m10-virtio-gpu: {reason}\n"));
        "m10 virtio-gpu probe failed"
    })
}

fn run(allocator: &mut PageAllocator) -> Probe<()> {
    install_virtio_gpu_display().map_err(|error| error.name())?;
    let status = wait_settled("bring-up budget")?;
    let stats = stats()?;
    if status.state != PresentState::Idle || status.output.backend_epoch() != 1 {
        return Err("bring-up did not leave the output idle at epoch 1");
    }
    if stats.submitted != 3 || stats.completed != 3 {
        return Err("bring-up command count");
    }
    serial_write_fmt(format_args!(
        "[VGPU] bring-up ok display-info={}x{} resource=1 format=b8g8r8x8 scanout=0 completed={}\n",
        REFERENCE_MODE.width_px, REFERENCE_MODE.height_px, stats.completed
    ));

    for index in 0..2u8 {
        with_active_display(|display| {
            display
                .ok_or(u64::MAX)?
                .map_scanout(HOLDER, index, allocator, |_, _| Ok(0))
        })
        .map_err(|_| "map scanout failed")?;
    }
    serial_write_fmt(format_args!(
        "[VGPU] scanout buffers mapped=2 stride={}\n",
        REFERENCE_MODE.stride_bytes
    ));

    let staging = staging_frame(allocator)?;
    draw(staging, draw_reference_a)?;
    write_buffer(0, staging)?;
    let seq = present(0, &[FULL_FRAME])?;
    let stats = wait_present(seq)?;
    if (
        stats.attaches,
        stats.detaches,
        stats.transfers,
        stats.flushes,
    ) != (1, 0, 1, 1)
    {
        return Err("first present command mix");
    }
    serial_write_fmt(format_args!(
        "[VGPU] present seq={seq} buffer=0 attach={} transfers={} flushes={} irq-completed\n",
        stats.attaches, stats.transfers, stats.flushes
    ));

    let mut damage = [NO_RECT; REFERENCE_B_DAMAGE.len()];
    for (slot, rect) in damage.iter_mut().zip(REFERENCE_B_DAMAGE) {
        *slot = to_buffer_rect(rect)?;
    }
    draw(staging, |canvas| {
        draw_reference_b(canvas);
        draw_reference_decoy(canvas);
    })?;
    write_buffer(1, staging)?;
    let before = stats.transferred_bytes;
    let seq = present(1, &damage)?;
    let stats = wait_present(seq)?;
    if (
        stats.attaches,
        stats.detaches,
        stats.transfers,
        stats.flushes,
    ) != (2, 1, 4, 2)
    {
        return Err("buffer switch command mix");
    }
    let damage_bytes = stats.transferred_bytes - before;
    let expected: u64 = damage
        .iter()
        .map(|rect| u64::from(rect.width) * u64::from(rect.height) * 4)
        .sum();
    if damage_bytes != expected {
        return Err("transfer was not limited to the damage");
    }
    serial_write_fmt(format_args!(
        "[VGPU] present seq={seq} buffer=1 detach={} attach={} transfers={} flushes={} \
         damage-bytes={damage_bytes} frame-bytes={REFERENCE_FRAME_BYTES}\n",
        stats.detaches, stats.attaches, stats.transfers, stats.flushes
    ));

    let crc = replay_transfers(staging)?;
    if crc != REFERENCE_CRC {
        serial_write_fmt(format_args!(
            "[VGPU] readback crc32=0x{crc:08x} (mismatch)\n"
        ));
        return Err("readback crc mismatch");
    }
    serial_write_fmt(format_args!("[VGPU] readback crc32=0x{crc:08x}\n"));

    force_timeout(damage[0])?;
    reset_and_present()?;
    release()?;
    serial_write_fmt(format_args!("[VGPU] PASS\n"));
    Ok(())
}

fn to_buffer_rect(rect: Rect) -> Probe<BufferRect> {
    let converted = (|| {
        Some(BufferRect {
            x: u16::try_from(rect.x).ok()?,
            y: u16::try_from(rect.y).ok()?,
            width: u16::try_from(rect.width).ok()?,
            height: u16::try_from(rect.height).ok()?,
        })
    })();
    converted
        .and_then(|buffer| buffer.clip_to_extent(REFERENCE_MODE.width_px, REFERENCE_MODE.height_px))
        .filter(|clipped| clipped.to_rect() == rect)
        .ok_or("reference damage outside the mode")
}

/// One reference frame of physically consecutive pages, zeroed, through the direct map.
fn staging_frame(allocator: &mut PageAllocator) -> Probe<&'static mut [u8]> {
    let pages = REFERENCE_FRAME_BYTES as u64 / PAGE_SIZE;
    let (first, _) = allocator
        .allocate_run(pages, pages)
        .ok_or("staging allocation failed")?;
    // SAFETY: the run was just allocated for this probe and is never freed; the direct map covers it.
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(phys_to_virt(first) as *mut u8, REFERENCE_FRAME_BYTES)
    };
    bytes.fill(0);
    Ok(bytes)
}

fn draw(bytes: &mut [u8], paint: impl FnOnce(&mut Canvas<'_>)) -> Probe<()> {
    let mut canvas = Canvas::new(bytes, reference_layout()).map_err(|_| "staging canvas")?;
    paint(&mut canvas);
    Ok(())
}

fn write_buffer(index: u8, frame: &[u8]) -> Probe<()> {
    with_active_display(|display| {
        display
            .and_then(|display| display.scanout_buffer(index))
            .ok_or("scanout buffer missing")?
            .write_frame(frame)
            .map_err(|_| "scanout buffer write failed")
    })
}

fn present(index: u8, damage: &[BufferRect]) -> Probe<u64> {
    with_active_display(|display| {
        let display = display.ok_or("display missing")?;
        let mut request = PresentRequest {
            output: display.state().output(),
            buffer_index: index,
            damage_count: damage.len() as u8,
            rects: [NO_RECT; MAX_PRESENT_DAMAGE_RECTS],
        };
        request.rects[..damage.len()].copy_from_slice(damage);
        display
            .present_scanout(HOLDER, &request, monotonic_ns())
            .map_err(|_| "present rejected")
    })
}

fn gpu<R>(f: impl FnOnce(&mut MmioGpuBackend) -> R) -> Probe<R> {
    with_active_display(|display| display.and_then(|display| display.virtio_gpu_mut()).map(f))
        .ok_or("virtio-gpu display missing")
}

fn stats() -> Probe<GpuStats> {
    gpu(|gpu| gpu.stats())
}

fn status() -> Probe<PresentStatus> {
    with_active_display(|display| display.map(|display| display.state().status()))
        .ok_or("display missing")
}

/// Waits, without harvesting, until the backend has no batch open and no present is in flight.
fn wait_settled(budget: &'static str) -> Probe<PresentStatus> {
    boot_wait::wait_until(WAIT_BUDGET_MS, budget, |_| {
        let status = status()?;
        let idle = gpu(|gpu| gpu.is_idle())?;
        Ok((idle && status.state != PresentState::InFlight).then_some(status))
    })
}

fn wait_present(seq: u64) -> Probe<GpuStats> {
    let status = wait_settled("present budget")?;
    if status.state != PresentState::Idle
        || status.completed_seq != seq
        || status.last_error.is_some()
    {
        return Err("present did not complete cleanly");
    }
    if timeout::armed_count() != 0 {
        return Err("completed present left its timeout armed");
    }
    stats()
}

/// Rebuilds the host resource from the logged transfers and returns its visible CRC.
fn replay_transfers(model: &mut [u8]) -> Probe<u32> {
    let mut log = [None::<LoggedTransfer>; 2 * MAX_PRESENT_DAMAGE_RECTS];
    gpu(|gpu| {
        for (slot, entry) in log.iter_mut().zip(gpu.transfer_log()) {
            *slot = Some(entry);
        }
    })?;
    model.fill(0);
    let stride = REFERENCE_MODE.stride_bytes as usize;
    for transfer in log.iter().flatten() {
        let rect = transfer.rect;
        let row_bytes = usize::from(rect.width) * 4;
        for y in rect.y..rect.y + rect.height {
            let start = usize::from(y) * stride + usize::from(rect.x) * 4;
            let row = &mut model[start..start + row_bytes];
            with_active_display(|display| {
                let buffer = display
                    .and_then(|display| display.scanout_buffer(transfer.buffer_index))
                    .ok_or("scanout buffer missing")?;
                let mut cursor = 0;
                buffer
                    .for_each_span(start, row_bytes, &mut |span| {
                        row[cursor..cursor + span.len()].copy_from_slice(span);
                        cursor += span.len();
                    })
                    .map_err(|_| "scanout buffer read failed")
            })?;
        }
    }
    visible_crc32(model, reference_layout()).ok_or("model crc")
}

/// Publishes a present without notifying the device: only the W3 deadline, expired from the
/// timer interrupt during the halt, can end it.
fn force_timeout(rect: BufferRect) -> Probe<()> {
    gpu(|gpu| gpu.hold_next_notify())?;
    let seq = present(1, &[rect])?;
    if timeout::armed_count() == 0 {
        return Err("held present has no timeout armed");
    }
    let status = boot_wait::wait_until(WAIT_BUDGET_MS, "forced timeout budget", |_| {
        let status = status()?;
        match status.state {
            PresentState::InFlight => Ok(None),
            PresentState::ResetRequired => Ok(Some(status)),
            _ => Err("forced timeout ended in the wrong state"),
        }
    })?;
    if status.completed_seq != seq || status.last_error != Some(DisplayError::DeviceTimeout) {
        return Err("forced timeout did not fail the present with DeviceTimeout");
    }
    if present(1, &[rect]).is_ok() {
        return Err("present accepted while reset-required");
    }
    serial_write_fmt(format_args!(
        "[VGPU] timeout -> reset-required seq={seq} error=device-timeout present-rejected\n"
    ));
    Ok(())
}

/// The reset a syscall-18 entry would start, then a full present that must re-attach backing.
fn reset_and_present() -> Probe<()> {
    let attaches = stats()?.attaches;
    with_active_display(|display| {
        if let Some(display) = display {
            display.service(monotonic_ns(), true);
        }
    });
    let status = wait_settled("reset budget")?;
    if status.state != PresentState::Idle || status.output.backend_epoch() != 2 {
        return Err("reset did not bring the output back at epoch 2");
    }
    if stats()?.resets != 1 {
        return Err("reset count");
    }
    serial_write_fmt(format_args!(
        "[VGPU] reset ok epoch={} generation={}\n",
        status.output.backend_epoch(),
        gpu(|gpu| gpu.generation())?
    ));

    let seq = present(1, &[FULL_FRAME])?;
    let stats = wait_present(seq)?;
    if stats.attaches != attaches + 1 {
        return Err("present after reset did not re-attach the backing");
    }
    serial_write_fmt(format_args!(
        "[VGPU] present seq={seq} buffer=1 epoch=2 reattached\n"
    ));
    Ok(())
}

fn release() -> Probe<()> {
    let detaches = stats()?.detaches;
    gpu(|gpu| gpu.begin_release())?.map_err(|_| "release submit failed")?;
    let status = wait_settled("release budget")?;
    if status.state != PresentState::Idle || stats()?.detaches != detaches + 1 {
        return Err("detach/unref did not complete");
    }
    let gpu = take_virtio_gpu().ok_or("virtio-gpu display missing")?;
    if !gpu.into_transport().release().device_reset {
        return Err("release did not reset the device");
    }
    serial_write_fmt(format_args!(
        "[VGPU] release ok detach=1 unref=1 device-reset=1\n"
    ));
    Ok(())
}
