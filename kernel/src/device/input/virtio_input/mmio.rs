//! Boot-tail bring-up of the virtio-input devices on bus 0 and their interrupt sinks.

use core::ptr::addr_of_mut;

use super::{
    classify, ClassifyError, DeviceClass, InputConfig, InputDevice, CONFIG_UNION_BYTES,
    EVENT_BUFFERS, EVENT_BYTES, EVENT_QUEUE,
};
use crate::arch::x86_64::cpu::without_interrupts;
use crate::device::input::i8042::InputSink;
use crate::device::input::{input_mut, now_ns};
use crate::device::pci::PciFunction;
use crate::device::virtio::dma::DmaRegion;
use crate::device::virtio::modern::{DeviceRequest, MmioTransport, QueueRequest, TransportError};
use crate::diagnostics::log::kernel_log_fmt;
use crate::sync::global_cell::GlobalCell;
use clean_slate_graphics::raw_input::RawInputKind;

const VIRTIO_ID_INPUT: u16 = 18;
/// `virtio_input_config`: select, subsel, size, 5 reserved bytes, then the union.
const CONFIG_SELECT: u32 = 0;
const CONFIG_SUBSEL: u32 = 1;
const CONFIG_SIZE: u32 = 2;
const CONFIG_UNION: u32 = 8;

/// A keyboard and a pointer: one device per raw-input slot.
const MAX_DEVICES: usize = 2;
/// Functions looked at; extra virtio-input functions beyond the slots are logged and skipped.
const MAX_FUNCTIONS: usize = 4;

static EVENT_QUEUES: [QueueRequest; 1] = [QueueRequest {
    index: EVENT_QUEUE,
    max_size: EVENT_BUFFERS as u16,
}];

/// Only the 8-byte config header is required: QEMU sizes the config to its largest entry.
const INPUT_REQUEST: DeviceRequest = DeviceRequest {
    virtio_id: VIRTIO_ID_INPUT,
    required_features: 0,
    optional_features: 0,
    queues: &EVENT_QUEUES,
    min_device_cfg_len: CONFIG_UNION,
};

type MmioInputDevice = InputDevice<MmioTransport>;

struct Devices {
    slots: [Option<MmioInputDevice>; MAX_DEVICES],
    /// A failed device is reported lost once.
    lost_reported: [bool; MAX_DEVICES],
}

static DEVICES: GlobalCell<Devices> = GlobalCell::new(Devices {
    slots: [None, None],
    lost_reported: [false; MAX_DEVICES],
});

fn devices_mut() -> &'static mut Devices {
    // SAFETY: single CPU; every caller runs in interrupt context or under `without_interrupts`
    // and drops the borrow before interrupts are enabled again.
    unsafe { &mut *DEVICES.get() }
}

const SINKS: [fn(); MAX_DEVICES] = [on_device0_interrupt, on_device1_interrupt];

fn on_device0_interrupt() {
    service(0);
}

fn on_device1_interrupt() {
    service(1);
}

/// The raw-input queue, bypassing the PS/2 ownership filter: these slots are ours.
struct VirtioSink;

impl InputSink for VirtioSink {
    fn record(&mut self, device_index: u8, kind: RawInputKind) {
        input_mut().record(device_index, kind, now_ns());
    }

    fn loss(&mut self, device_index: u8) {
        input_mut().loss(device_index);
    }

    fn device_lost(&mut self, device_index: u8) {
        input_mut().device_lost(device_index);
    }

    fn device_ready(&mut self, device_index: u8) {
        input_mut().device_ready(device_index);
    }
}

/// Interrupt context (or masked): drain one device.
fn service(position: usize) {
    let devices = devices_mut();
    let Some(device) = devices.slots[position].as_mut() else {
        return;
    };
    if device.service(&mut VirtioSink).is_err() && !devices.lost_reported[position] {
        devices.lost_reported[position] = true;
        VirtioSink.device_lost(device.device_index());
    }
}

/// Event buffers for both devices in one page, so each device's range is contiguous.
#[repr(C, align(4096))]
struct EventPage([u8; 4096]);
const DEVICE_BUFFER_BYTES: usize = EVENT_BUFFERS * EVENT_BYTES;
const _: () = assert!(DEVICE_BUFFER_BYTES * MAX_DEVICES <= 4096);

static mut EVENT_PAGE: EventPage = EventPage([0; 4096]);

/// Device `position`'s event buffers; each position is handed out at most once per boot.
fn event_region(position: usize) -> Option<DmaRegion> {
    static TAKEN: GlobalCell<[bool; MAX_DEVICES]> = GlobalCell::new([false; MAX_DEVICES]);
    without_interrupts(|| {
        // SAFETY: masked, single CPU.
        let taken = unsafe { &mut *TAKEN.get() };
        if core::mem::replace(&mut taken[position], true) {
            return None;
        }
        // SAFETY: `TAKEN` hands each disjoint chunk out once; the region owns it for the boot.
        let page = unsafe { &mut (*addr_of_mut!(EVENT_PAGE)).0 };
        let chunk = page.chunks_mut(DEVICE_BUFFER_BYTES).nth(position)?;
        DmaRegion::from_static(chunk).ok()
    })
}

struct MmioConfig<'a>(&'a mut MmioTransport);

impl InputConfig for MmioConfig<'_> {
    fn query(
        &mut self,
        select: u8,
        subsel: u8,
        out: &mut [u8; CONFIG_UNION_BYTES],
    ) -> Result<usize, TransportError> {
        // QEMU bumps the config generation whenever `select` or `subsel` changes, so they are
        // written first and only the reads run inside the generation loop.
        self.0.write_device_config_u8(CONFIG_SELECT, select)?;
        self.0.write_device_config_u8(CONFIG_SUBSEL, subsel)?;
        let (size, _) = self.0.read_device_config(|config| {
            let size = usize::from(config.read_u8(CONFIG_SIZE)?).min(CONFIG_UNION_BYTES);
            for (offset, byte) in (CONFIG_UNION..).zip(out.iter_mut().take(size)) {
                *byte = config.read_u8(offset)?;
            }
            Ok(size)
        })?;
        Ok(size)
    }
}

/// Which raw-input slots now have a virtio device behind them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Claimed {
    pub(crate) keyboard: Option<DeviceClass>,
    pub(crate) pointer: Option<DeviceClass>,
}

fn label(function: PciFunction) -> (u8, u8, u8) {
    (function.bus, function.device, function.function)
}

/// Bring up every virtio-input function on bus 0, one per raw-input slot, before the i8042
/// driver starts. A slot that gets a device here is closed to PS/2. Never fatal.
pub(crate) fn begin() -> Claimed {
    let mut claimed = Claimed::default();
    let mut functions = [PciFunction::new(0, 0, 0); MAX_FUNCTIONS];
    let found = match MmioTransport::find_functions(&INPUT_REQUEST, &mut functions) {
        Ok(found) => found,
        Err(_) => return claimed,
    };
    let mut position = 0;
    for &function in &functions[..found] {
        let (bus, dev, func) = label(function);
        if position == MAX_DEVICES {
            kernel_log_fmt(format_args!(
                "[INPT] virtio-input {bus:02x}:{dev:02x}.{func} skipped reason=slots-full\n"
            ));
            continue;
        }
        match bring_up(function, position) {
            Ok(class) => {
                let slot = match class {
                    DeviceClass::Keyboard => &mut claimed.keyboard,
                    _ => &mut claimed.pointer,
                };
                *slot = Some(class);
                kernel_log_fmt(format_args!(
                    "[INPT] virtio-input {bus:02x}:{dev:02x}.{func} class={} ready\n",
                    class.name()
                ));
                position += 1;
            }
            Err(reason) => kernel_log_fmt(format_args!(
                "[INPT] virtio-input {bus:02x}:{dev:02x}.{func} unavailable reason={reason}\n"
            )),
        }
    }
    claimed
}

fn bring_up(function: PciFunction, position: usize) -> Result<DeviceClass, &'static str> {
    let mut transport = MmioTransport::discover_function(&INPUT_REQUEST, function, SINKS[position])
        .map_err(|_| "transport")?;
    let class = match classify(&mut MmioConfig(&mut transport)) {
        Ok(class) => class,
        Err(error) => {
            if let ClassifyError::Transport(cause) = error {
                kernel_log_fmt(format_args!(
                    "[INPT] virtio-input config query failed: {cause:?}\n"
                ));
            }
            transport.release();
            return Err(error.name());
        }
    };
    let index = class.device_index();
    if without_interrupts(|| input_mut().virtio_owns(index)) {
        transport.release();
        return Err("duplicate");
    }
    let count = usize::from(transport.queue_size(EVENT_QUEUE).unwrap_or(0)).min(EVENT_BUFFERS);
    let Some(buffers) = event_region(position).filter(|_| count > 0) else {
        transport.release();
        return Err("dma");
    };
    let device = InputDevice::new(transport, buffers, count, class);
    let started = without_interrupts(|| {
        let devices = devices_mut();
        let device = devices.slots[position].insert(device);
        if device.start().is_err() {
            return Err(devices.slots[position].take());
        }
        let state = input_mut();
        state.claim_virtio(index);
        state.device_ready(index);
        Ok(())
    });
    match started {
        Ok(()) => {
            // Anything the device wrote before the slot was published.
            without_interrupts(|| service(position));
            Ok(class)
        }
        Err(device) => {
            if let Some(device) = device {
                device.into_transport().release();
            }
            Err("start")
        }
    }
}
