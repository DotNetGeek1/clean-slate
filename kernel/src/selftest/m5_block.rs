use clean_slate_block::BlockDevice;

use crate::device::virtio::block::VirtioBlockDevice;
use crate::{serial_write_fmt, serial_write_line};

const MAX_TEST_IO_BYTES: usize = 8192;

pub(crate) fn run_m5_block_self_test() -> Result<(), &'static str> {
    let mut device = VirtioBlockDevice::discover()?;
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
        .write_blocks(start_lba, transfer_blocks, &write_buffer[..transfer_bytes])
        .map_err(map_block_io_error)?;
    serial_write_fmt(format_args!(
        "[BLK ] write lba={} blocks={} OK\n",
        start_lba, transfer_blocks
    ));

    device.flush().map_err(map_block_io_error)?;
    serial_write_line("[BLK ] flush complete");

    device
        .read_blocks(
            start_lba,
            transfer_blocks,
            &mut read_buffer[..transfer_bytes],
        )
        .map_err(map_block_io_error)?;
    serial_write_fmt(format_args!(
        "[BLK ] read lba={} blocks={} OK\n",
        start_lba, transfer_blocks
    ));

    if read_buffer[..transfer_bytes] != write_buffer[..transfer_bytes] {
        return Err("virtio block readback mismatch");
    }

    serial_write_line("[M5.2] PASS");
    Ok(())
}

fn map_block_io_error(error: clean_slate_block::BlockIoError) -> &'static str {
    match error {
        clean_slate_block::BlockIoError::InvalidRequest(_) => "virtio block request was invalid",
        clean_slate_block::BlockIoError::Unsupported(_) => "virtio block operation unsupported",
        clean_slate_block::BlockIoError::Transport(_) => "virtio block transport failed",
    }
}
