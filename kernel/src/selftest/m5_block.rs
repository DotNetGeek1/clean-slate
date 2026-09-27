use clean_slate_block::{BlockIoError, BlockTransportError};

use crate::arch::x86_64::cpu::{disable_interrupts, enable_interrupts_and_halt};
use crate::device::virtio::block::{
    block_interrupt_stats, VirtioBlockDevice, BLOCK_COMPLETION_TIMEOUT_NS,
};
use crate::interrupt::timer::initialize_timer;
use crate::time::monotonic_ns;
use crate::{serial_write_fmt, serial_write_line};

const MAX_TEST_IO_BYTES: usize = 8192;
/// The lane runs in boot context without a scheduler thread; the queue
/// interrupt (or the periodic timer, for the deadline) ends each `hlt`.
fn ignore_completion() {}

pub(crate) fn run_m5_block_self_test() -> Result<(), &'static str> {
    initialize_timer();
    let mut device = VirtioBlockDevice::discover(ignore_completion)?;
    serial_write_line("[VIRT] block device found");

    let geometry = device.geometry();
    serial_write_fmt(format_args!(
        "[BLK ] virtio-block ready blocks={} block-size={}\n",
        geometry.block_count(),
        geometry.logical_block_size()
    ));

    let transfer_blocks = if geometry.max_transfer_blocks() >= 2 && geometry.block_count() >= 3 {
        2
    } else {
        1
    };
    let start_lba = if geometry.block_count() > u64::from(transfer_blocks) {
        1
    } else {
        0
    };

    let transfer_bytes = usize::try_from(geometry.logical_block_size())
        .map_err(|_| "logical block size does not fit into usize")?
        .checked_mul(usize::try_from(transfer_blocks).map_err(|_| "transfer block count overflow")?)
        .ok_or("transfer length overflow")?;
    if transfer_bytes > MAX_TEST_IO_BYTES {
        return Err("self-test transfer exceeds static I/O buffers");
    }

    let mut write_buffer = [0u8; MAX_TEST_IO_BYTES];
    let mut read_buffer = [0u8; MAX_TEST_IO_BYTES];
    for (index, slot) in write_buffer[..transfer_bytes].iter_mut().enumerate() {
        *slot = ((index * 37 + 11) & 0xff) as u8;
    }

    device
        .submit_write(start_lba, transfer_blocks, &write_buffer[..transfer_bytes])
        .map_err(map_block_io_error)?;
    await_completion(&mut device, None).map_err(map_block_io_error)?;
    serial_write_fmt(format_args!(
        "[BLK ] write lba={} blocks={} OK\n",
        start_lba, transfer_blocks
    ));

    device.submit_flush().map_err(map_block_io_error)?;
    await_completion(&mut device, None).map_err(map_block_io_error)?;
    serial_write_line("[BLK ] flush complete");

    device
        .submit_read(start_lba, transfer_blocks, transfer_bytes)
        .map_err(map_block_io_error)?;
    await_completion(&mut device, Some(&mut read_buffer[..transfer_bytes]))
        .map_err(map_block_io_error)?;
    serial_write_fmt(format_args!(
        "[BLK ] read lba={} blocks={} OK\n",
        start_lba, transfer_blocks
    ));

    if read_buffer[..transfer_bytes] != write_buffer[..transfer_bytes] {
        return Err("virtio block readback mismatch");
    }

    let stats = block_interrupt_stats();
    serial_write_fmt(format_args!(
        "[BLK ] completion interrupts={} spurious={}\n",
        stats.queue, stats.spurious
    ));
    // A completion harvested before the first `hlt` leaves its MSI pending, and
    // the next one coalesces with it, so the count is not one per request.
    if stats.queue == 0 {
        return Err("virtio block completions did not raise queue interrupts");
    }

    serial_write_line("[M5.2] PASS");
    Ok(())
}

/// Halt until the in-flight request completes or its TSC deadline passes.
/// The check runs with interrupts masked and `sti; hlt` re-enables them
/// atomically, so a completion interrupt cannot land between check and halt.
fn await_completion(
    device: &mut VirtioBlockDevice,
    mut read_into: Option<&mut [u8]>,
) -> Result<(), BlockIoError> {
    let deadline_ns = monotonic_ns().saturating_add(BLOCK_COMPLETION_TIMEOUT_NS);
    loop {
        disable_interrupts();
        if let Some(result) = device.take_completion(read_into.as_deref_mut()) {
            return result;
        }
        if monotonic_ns() >= deadline_ns {
            device.abandon_in_flight();
            return Err(BlockIoError::Transport(BlockTransportError::Timeout));
        }
        enable_interrupts_and_halt();
    }
}

fn map_block_io_error(error: BlockIoError) -> &'static str {
    match error {
        BlockIoError::InvalidRequest(_) => "virtio block request was invalid",
        BlockIoError::Unsupported(_) => "virtio block operation unsupported",
        BlockIoError::Transport(BlockTransportError::Timeout) => {
            "virtio block completion timed out"
        }
        BlockIoError::Transport(_) => "virtio block transport failed",
    }
}
