//! Boot-context probe of the modern VirtIO transport (#196) against a
//! modern-only `virtio-blk-pci` and, when present, `virtio-gpu-pci`.
//!
//! The block request, the forced W3 timeout, reset, release and rediscovery all
//! complete through interrupts or the timer path; the probe only halts between
//! checks ([`boot_wait::wait_until`]). QEMU runs the block device with
//! `ioeventfd=off`, so a request that is never notified is never processed and
//! the timeout is deterministic.

use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::device::virtio::dma::DmaRegion;
use crate::device::virtio::modern::{
    step_completion, DeviceRequest, InterruptRoute, MmioTransport, QueueRequest, ResetReason,
    TransportError, TransportState, VirtqueueTransport, WaitStep,
};
use crate::device::virtio::virtqueue::Token;
use crate::sched::timeout;
use crate::sched::wait::Deadline;
use crate::selftest::boot_wait;
use crate::serial_write_fmt;

const VIRTIO_ID_BLOCK: u16 = 2;
const VIRTIO_ID_GPU: u16 = 16;
const SECTOR_BYTES: u32 = 512;
const SENTINEL_SECTOR: u64 = 1;
const SENTINEL: &[u8] = b"CLEAN-SLATE-M10-VMOD\0";
/// 1 MiB image.
const EXPECTED_CAPACITY_SECTORS: u64 = 2048;
const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_S_OK: u8 = 0;
const GPU_NUM_SCANOUTS: u32 = 8;

const REQUEST_TIMEOUT_NS: u64 = 1_000_000_000;
const FORCED_TIMEOUT_NS: u64 = 250_000_000;
/// Longer than either deadline, so W3 always decides first.
const WAIT_BUDGET_MS: u64 = 1_500;

const HEADER_OFFSET: u32 = 0;
const STATUS_OFFSET: u32 = 16;
const DATA_OFFSET: u32 = 512;

static BLOCK_QUEUES: [QueueRequest; 1] = [QueueRequest {
    index: 0,
    max_size: 16,
}];
static GPU_QUEUES: [QueueRequest; 2] = [
    QueueRequest {
        index: 0,
        max_size: 16,
    },
    QueueRequest {
        index: 1,
        max_size: 8,
    },
];

const BLOCK_REQUEST: DeviceRequest = DeviceRequest {
    virtio_id: VIRTIO_ID_BLOCK,
    required_features: 0,
    optional_features: 0,
    queues: &BLOCK_QUEUES,
    min_device_cfg_len: 8,
};
const GPU_REQUEST: DeviceRequest = DeviceRequest {
    virtio_id: VIRTIO_ID_GPU,
    required_features: 0,
    optional_features: 0,
    queues: &GPU_QUEUES,
    min_device_cfg_len: 16,
};

static BLOCK_EVENTS: AtomicU32 = AtomicU32::new(0);
static GPU_EVENTS: AtomicU32 = AtomicU32::new(0);

fn block_sink() {
    BLOCK_EVENTS.fetch_add(1, Ordering::Relaxed);
}

fn gpu_sink() {
    GPU_EVENTS.fetch_add(1, Ordering::Relaxed);
}

#[repr(C, align(4096))]
struct RequestPage([u8; 4096]);

static mut REQUEST_PAGE: RequestPage = RequestPage([0; 4096]);

pub(crate) fn run_m10_virtio_modern_self_test() -> Result<(), &'static str> {
    boot_wait::init_clock()?;
    run().map_err(|error| {
        serial_write_fmt(format_args!("[VMOD] FAIL {error:?}\n"));
        "m10 virtio-modern probe failed"
    })
}

#[derive(Debug)]
enum ProbeError {
    Transport(TransportError),
    Dma,
    Unexpected(&'static str),
}

impl From<TransportError> for ProbeError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

fn run() -> Result<(), ProbeError> {
    // SAFETY: the probe runs once, in boot context, and is the page's only user.
    let buffer = unsafe { &mut (*addr_of_mut!(REQUEST_PAGE)).0 };
    let mut page = DmaRegion::from_static(buffer).map_err(|_| ProbeError::Dma)?;

    let mut block = MmioTransport::discover(&BLOCK_REQUEST, block_sink)?;
    let layout = *block.layout();
    serial_write_fmt(format_args!(
        "[VMOD] caps common=bar{} notify=bar{} mult={} isr=bar{} device=bar{} ignored={}\n",
        layout.common.bar,
        layout.notify.bar,
        layout.notify_off_multiplier,
        layout.isr.bar,
        layout.device.map_or(u8::MAX, |device| device.bar),
        layout.ignored,
    ));
    serial_write_fmt(format_args!(
        "[VMOD] features accepted={:#x}\n",
        block.negotiated_features()
    ));
    let (capacity, attempts) = block.read_device_config(|config| config.read_u64(0))?;
    serial_write_fmt(format_args!(
        "[VMOD] config capacity={capacity} gen_attempts={attempts}\n"
    ));
    if capacity != EXPECTED_CAPACITY_SECTORS {
        return Err(ProbeError::Unexpected("capacity"));
    }
    let mode = match block.interrupt_route() {
        Some(InterruptRoute::Msix { .. }) => "msix",
        Some(InterruptRoute::Intx { .. }) => "intx",
        None => return Err(ProbeError::Unexpected("no interrupt route")),
    };
    serial_write_fmt(format_args!(
        "[VMOD] queue0 size={} irq={mode}\n",
        block.queue_size(0).unwrap_or(0)
    ));

    read_sentinel(&mut block, &mut page)?;
    let stats = block.interrupt_stats();
    serial_write_fmt(format_args!(
        "[VMOD] read ok irq_count={} queue_irqs={} spurious={}\n",
        BLOCK_EVENTS.load(Ordering::Relaxed),
        stats.queue,
        stats.spurious
    ));

    let stranded = force_timeout(&mut block, &page)?;
    serial_write_fmt(format_args!("[VMOD] timeout -> reset-required\n"));

    block.reset()?;
    if block.token_in_flight(stranded) != Err(TransportError::StaleToken) {
        return Err(ProbeError::Unexpected("token survived reset"));
    }
    read_sentinel(&mut block, &mut page)?;
    serial_write_fmt(format_args!(
        "[VMOD] reset ok generation={} stale-token-rejected\n",
        block.generation()
    ));

    if !block.release().device_reset {
        return Err(ProbeError::Unexpected("release did not reset the device"));
    }
    let mut block = MmioTransport::discover(&BLOCK_REQUEST, block_sink)?;
    read_sentinel(&mut block, &mut page)?;
    serial_write_fmt(format_args!(
        "[VMOD] release ok rediscover ok generation={}\n",
        block.generation()
    ));

    match MmioTransport::discover(&GPU_REQUEST, gpu_sink) {
        Ok(mut gpu) => {
            let (scanouts, _) =
                gpu.read_device_config(|config| config.read_u32(GPU_NUM_SCANOUTS))?;
            serial_write_fmt(format_args!(
                "[VMOD] gpu controlq ok size={} cursorq size={} scanouts={scanouts}\n",
                gpu.queue_size(0).unwrap_or(0),
                gpu.queue_size(1).unwrap_or(0),
            ));
            if !gpu.release().device_reset {
                return Err(ProbeError::Unexpected("gpu release did not reset"));
            }
        }
        Err(TransportError::NotFound) => serial_write_fmt(format_args!("[VMOD] gpu absent\n")),
        Err(error) => return Err(error.into()),
    }

    block.release();
    serial_write_fmt(format_args!("[VMOD] PASS mode={mode}\n"));
    Ok(())
}

fn now_ns() -> u64 {
    crate::time::monotonic_ns()
}

fn submit_sentinel_read(
    block: &mut MmioTransport,
    page: &mut DmaRegion,
    timeout_ns: u64,
) -> Result<Token, ProbeError> {
    let mut header = [0u8; 16];
    header[..4].copy_from_slice(&VIRTIO_BLK_T_IN.to_le_bytes());
    header[8..].copy_from_slice(&SENTINEL_SECTOR.to_le_bytes());
    page.copy_in(HEADER_OFFSET, &header)
        .and_then(|()| page.copy_in(STATUS_OFFSET, &[0xff]))
        .and_then(|()| page.copy_in(DATA_OFFSET, &[0; SECTOR_BYTES as usize]))
        .map_err(|_| ProbeError::Dma)?;
    let chain = [
        page.readable(HEADER_OFFSET, 16),
        page.writable(DATA_OFFSET, SECTOR_BYTES),
        page.writable(STATUS_OFFSET, 1),
    ];
    let [Ok(header), Ok(data), Ok(status)] = chain else {
        return Err(ProbeError::Dma);
    };
    Ok(block.submit(
        0,
        &[header, data, status],
        Deadline::MonotonicNs(now_ns().saturating_add(timeout_ns)),
    )?)
}

/// Read the sentinel sector and wait for both its used entry and the queue
/// interrupt. QEMU may complete the request inside the notify write, before the
/// interrupt is taken, so a harvested completion alone proves nothing about
/// interrupt delivery.
fn read_sentinel(block: &mut MmioTransport, page: &mut DmaRegion) -> Result<(), ProbeError> {
    let queue_interrupts = block.interrupt_stats().queue;
    let token = submit_sentinel_read(block, page, REQUEST_TIMEOUT_NS)?;
    block.notify(0)?;
    let mut harvested = None;
    let completion = boot_wait::wait_until(WAIT_BUDGET_MS, "block read budget", |_| {
        if harvested.is_none() {
            harvested = match step_completion(block, 0) {
                Ok(WaitStep::Complete(completion)) => Some(completion),
                Ok(WaitStep::Wait(_)) => None,
                Ok(WaitStep::Idle) => return Err("block read vanished"),
                Err(TransportError::ResetRequired) => return Err("block read timed out"),
                Err(_) => return Err("block transport failed"),
            };
        }
        let interrupted = block.interrupt_stats().queue > queue_interrupts;
        Ok(harvested.filter(|_| interrupted))
    })
    .map_err(ProbeError::Unexpected)?;
    if completion.token != token {
        return Err(ProbeError::Unexpected("completion for another token"));
    }
    let mut status = [0xffu8];
    let mut data = [0u8; SENTINEL.len()];
    page.copy_out(STATUS_OFFSET, &mut status)
        .and_then(|()| page.copy_out(DATA_OFFSET, &mut data))
        .map_err(|_| ProbeError::Dma)?;
    if status[0] != VIRTIO_BLK_S_OK {
        return Err(ProbeError::Unexpected("block status"));
    }
    if data != SENTINEL {
        return Err(ProbeError::Unexpected("sentinel mismatch"));
    }
    if timeout::armed_count() != 0 {
        return Err(ProbeError::Unexpected(
            "completed read left its timeout armed",
        ));
    }
    Ok(())
}

/// Publish a read without notifying: only the W3 deadline, expired from the
/// timer interrupt during the halt, can end it.
fn force_timeout(block: &mut MmioTransport, page: &DmaRegion) -> Result<Token, ProbeError> {
    let header = page
        .readable(HEADER_OFFSET, 16)
        .map_err(|_| ProbeError::Dma)?;
    let status = page
        .writable(STATUS_OFFSET, 1)
        .map_err(|_| ProbeError::Dma)?;
    let token = block.submit(
        0,
        &[header, status],
        Deadline::MonotonicNs(now_ns().saturating_add(FORCED_TIMEOUT_NS)),
    )?;
    if timeout::armed_count() != 1 {
        return Err(ProbeError::Unexpected("request timeout not armed"));
    }
    boot_wait::wait_until(WAIT_BUDGET_MS, "forced timeout budget", |_| {
        Ok(match block.state() {
            TransportState::Ready => None,
            TransportState::ResetRequired(ResetReason::Timeout) => Some(()),
            TransportState::ResetRequired(_) | TransportState::Poisoned(_) => {
                return Err("forced timeout ended in the wrong state")
            }
        })
    })
    .map_err(ProbeError::Unexpected)?;
    if timeout::armed_count() != 0 {
        return Err(ProbeError::Unexpected("expired timeout still armed"));
    }
    Ok(token)
}
