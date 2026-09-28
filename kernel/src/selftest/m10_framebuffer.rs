use clean_slate_graphics::display::{DisplayError, PresentState, PresentStatus};
use clean_slate_graphics::{Rect, REFERENCE_MODE};
use clean_slate_raster::{
    draw_reference_a, draw_reference_b, draw_reference_decoy, Canvas, Crc32, REFERENCE_B_DAMAGE,
    REFERENCE_PROBES,
};

use crate::device::display::frame::KernelFrame;
use crate::device::display::presenter::KernelPresenter;
use crate::device::display::with_active_display;
use crate::interrupt::timer::initialize_timer;
use crate::mm::frame_allocator::PageAllocator;
use crate::time::monotonic_ns;
use crate::{serial_write_fmt, serial_write_line};

const ROW_BYTES: usize = 1280 * 4;
const FRAME_HEIGHT: u32 = 800;

fn fail(reason: &'static str) -> Result<(), &'static str> {
    serial_write_fmt(format_args!("[FAIL] m10-framebuffer: {reason}\n"));
    Err(reason)
}

fn map_display_err(_: DisplayError) -> &'static str {
    "display operation failed"
}

pub(crate) fn run_m10_framebuffer_self_test(
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    initialize_timer();

    if !with_active_display(|display| display.is_some()) {
        serial_write_line("[FAIL] m10-framebuffer: display unavailable");
        return Err("display unavailable");
    }

    let mut frame = match KernelFrame::allocate(allocator, 1) {
        Ok(frame) => frame,
        Err(reason) => {
            serial_write_fmt(format_args!("[FAIL] m10-framebuffer: {reason}\n"));
            return Err(reason);
        }
    };

    let layout = frame.layout();
    {
        let mut canvas = match Canvas::new(frame.bytes_mut(), layout) {
            Ok(canvas) => canvas,
            Err(_) => return fail("reference canvas invalid"),
        };
        draw_reference_a(&mut canvas);
    }

    let full_damage = Rect {
        x: 0,
        y: 0,
        width: REFERENCE_MODE.width_px,
        height: REFERENCE_MODE.height_px,
    };

    let mut presenter = KernelPresenter::new();
    let source = match frame.source() {
        Some(source) => source,
        None => return fail("kernel frame source invalid"),
    };
    let seq1 = with_active_display(|display| -> Result<Option<u64>, &'static str> {
        let display = display.ok_or("display unavailable")?;
        display.bind(0, &source).map_err(map_display_err)?;
        display
            .add_damage(&mut presenter, full_damage)
            .map_err(|_| "add full-frame damage failed")?;
        display
            .present_pending(&mut presenter, &source, 0, monotonic_ns())
            .map_err(map_display_err)
    });
    match seq1 {
        Ok(Some(1)) => {}
        _ => return fail("present seq 1 unexpected result"),
    }
    serial_write_line("[FB  ] present seq=1 rects=1");

    {
        let mut canvas = match Canvas::new(frame.bytes_mut(), layout) {
            Ok(canvas) => canvas,
            Err(_) => return fail("reference canvas invalid"),
        };
        draw_reference_b(&mut canvas);
        draw_reference_decoy(&mut canvas);
    }

    let source = match frame.source() {
        Some(source) => source,
        None => return fail("kernel frame source invalid"),
    };
    let seq2 = with_active_display(|display| -> Result<Option<u64>, &'static str> {
        let display = display.ok_or("display unavailable")?;
        for rect in REFERENCE_B_DAMAGE {
            display
                .add_damage(&mut presenter, rect)
                .map_err(|_| "add pattern B damage failed")?;
        }
        display
            .present_pending(&mut presenter, &source, 0, monotonic_ns())
            .map_err(map_display_err)
    });
    match seq2 {
        Ok(Some(2)) => {}
        _ => return fail("present seq 2 unexpected result"),
    }
    serial_write_fmt(format_args!(
        "[FB  ] present seq=2 rects={}\n",
        REFERENCE_B_DAMAGE.len()
    ));

    let source = match frame.source() {
        Some(source) => source,
        None => return fail("kernel frame source invalid"),
    };
    let idle = with_active_display(|display| -> Result<Option<u64>, &'static str> {
        let display = display.ok_or("display unavailable")?;
        display
            .present_pending(&mut presenter, &source, 0, monotonic_ns())
            .map_err(map_display_err)
    });
    match idle {
        Ok(None) => {}
        _ => return fail("idle present was not skipped"),
    }
    if presenter.counters().submits != 2 {
        return fail("presenter submit count mismatch");
    }
    serial_write_fmt(format_args!(
        "[FB  ] idle skipped submits={}\n",
        presenter.counters().submits
    ));

    let crc = match with_active_display(|display| -> Result<u32, &'static str> {
        let display = display.ok_or("display unavailable")?;
        let aperture = display.gop_aperture().ok_or("gop aperture missing")?;
        let mut crc = Crc32::new();
        let mut row = [0u8; ROW_BYTES];
        for y in 0..FRAME_HEIGHT {
            aperture
                .read_row_segment(y, 0, &mut row)
                .map_err(|_| "aperture read failed")?;
            crc.update(&row);
        }
        Ok(crc.finish())
    }) {
        Ok(value) => value,
        Err(reason) => return fail(reason),
    };
    serial_write_fmt(format_args!("[FB  ] readback crc32=0x{:08x}\n", crc));

    match with_active_display(|display| -> Result<(), &'static str> {
        let display = display.ok_or("display unavailable")?;
        let aperture = display.gop_aperture().ok_or("gop aperture missing")?;
        let mut probe = [0u8; 4];
        for (x, y) in REFERENCE_PROBES {
            aperture
                .read_row_segment(y, x, &mut probe)
                .map_err(|_| "probe read failed")?;
            serial_write_fmt(format_args!(
                "[FB  ] probe x={} y={} bgrx={:02x}{:02x}{:02x}{:02x}\n",
                x, y, probe[0], probe[1], probe[2], probe[3]
            ));
        }
        Ok(())
    }) {
        Ok(()) => {}
        Err(reason) => return fail(reason),
    }

    let status = match with_active_display(|display| -> Result<PresentStatus, &'static str> {
        display
            .map(|display| display.state().status())
            .ok_or("display unavailable")
    }) {
        Ok(status) => status,
        Err(reason) => return fail(reason),
    };
    if status.state != PresentState::Idle || status.submitted_seq != 2 || status.completed_seq != 2
    {
        return fail("display status not idle at seq 2");
    }
    serial_write_line("[FB  ] status idle seq=2");

    serial_write_line("[M10.2] PASS");
    Ok(())
}
