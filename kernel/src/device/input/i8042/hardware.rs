//! The real controller behind [`ControllerIo`]: port I/O, IRQ 1/12 routing and handlers, and
//! [`begin_init`]. Compiled with `clean_slate_isa_irq` (the boot tail or the input self-test).
//! A plain host-test build sets that cfg too, but host tests never call this module: they drive
//! the driver through `FakeController`.

#[cfg(feature = "m10-input-self-test")]
use core::sync::atomic::{AtomicU32, Ordering};

use super::{
    bootstrap, driver_mut, enable_irqs, ControllerError, ControllerIo, DriverState, Port, Ports,
};
#[cfg(feature = "m10-input-self-test")]
use super::{Controller, CMD_WRITE_AUX_OUTPUT, CMD_WRITE_KEYBOARD_OUTPUT};
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::port::{port_in, port_out};
use crate::device::input::QueueSink;
use crate::interrupt::irq::{
    allocate_device_vector, release_device_vector, route_isa_irq, DeviceInterruptHandler,
};

const DATA_PORT: u16 = 0x60;
const STATUS_COMMAND_PORT: u16 = 0x64;

/// Every access to the controller's ports, for the smoke lane's no-polling proof.
#[cfg(feature = "m10-input-self-test")]
static PORT_ACCESSES: AtomicU32 = AtomicU32::new(0);

fn count_port_access() {
    #[cfg(feature = "m10-input-self-test")]
    PORT_ACCESSES.fetch_add(1, Ordering::Relaxed);
}

struct HardwarePorts;

impl ControllerIo for HardwarePorts {
    fn status(&mut self) -> u8 {
        count_port_access();
        port_in(STATUS_COMMAND_PORT)
    }

    fn read_data(&mut self) -> u8 {
        count_port_access();
        port_in(DATA_PORT)
    }

    fn write_command(&mut self, command: u8) {
        count_port_access();
        port_out(STATUS_COMMAND_PORT, command);
    }

    fn write_data(&mut self, byte: u8) {
        count_port_access();
        port_out(DATA_PORT, byte);
    }

    fn now_ns(&mut self) -> u64 {
        crate::time::monotonic_ns()
    }
}

fn route_device(irq: u8, handler: DeviceInterruptHandler) -> Option<u8> {
    let vector = allocate_device_vector(handler).ok()?;
    if route_isa_irq(irq, vector).is_err() {
        release_device_vector(vector);
        return None;
    }
    Some(vector)
}

fn keyboard_interrupt() {
    let DriverState { driver, timers, .. } = driver_mut();
    driver.interrupt(Port::Keyboard, &mut HardwarePorts, &mut QueueSink, timers);
}

fn mouse_interrupt() {
    let DriverState { driver, timers, .. } = driver_mut();
    driver.interrupt(Port::Aux, &mut HardwarePorts, &mut QueueSink, timers);
}

const KEYBOARD_IRQ: u8 = 1;
const MOUSE_IRQ: u8 = 12;

/// Bootstraps the controller, routes IRQ 1 and IRQ 12, and starts both device init programs;
/// returns the ports whose programs were started. The devices become ready later, from the IRQ
/// handlers. Requires the calibrated TSC for the handshake deadlines; call once, after timer
/// initialisation and before interrupts are enabled.
pub(crate) fn begin_init() -> Result<Ports, ControllerError> {
    if crate::time::tsc_hz().is_none() {
        return Err(ControllerError::ClockUnavailable);
    }
    let state = driver_mut();
    let ports = without_interrupts(|| bootstrap(&mut HardwarePorts, &mut state.driver.stats))?;
    state.keyboard_vector = ports
        .keyboard
        .then(|| route_device(KEYBOARD_IRQ, keyboard_interrupt))
        .flatten();
    state.mouse_vector = ports
        .aux
        .then(|| route_device(MOUSE_IRQ, mouse_interrupt))
        .flatten();
    let routed = Ports {
        keyboard: state.keyboard_vector.is_some(),
        aux: state.mouse_vector.is_some(),
    };
    let enabled = without_interrupts(|| {
        enable_irqs(&mut HardwarePorts, ports, routed, &mut state.driver.stats)?;
        state.driver.start(
            &mut HardwarePorts,
            routed,
            &mut QueueSink,
            &mut state.timers,
        );
        Ok(())
    });
    if let Err(error) = enabled {
        release_routes();
        return Err(error);
    }
    Ok(routed)
}

fn release_routes() {
    let driver = driver_mut();
    for vector in [driver.keyboard_vector.take(), driver.mouse_vector.take()]
        .into_iter()
        .flatten()
    {
        release_device_vector(vector);
    }
}

#[cfg(feature = "m10-input-self-test")]
pub(crate) fn port_accesses() -> u32 {
    PORT_ACCESSES.load(Ordering::Relaxed)
}

/// Self-test stimulus: the controller's write-output-buffer commands place `bytes` in the output
/// buffer as if the keyboard (or mouse) had sent them, raising the real IRQ path.
#[cfg(feature = "m10-input-self-test")]
pub(crate) fn inject(aux: bool, byte: u8) -> Result<(), ControllerError> {
    let command = if aux {
        CMD_WRITE_AUX_OUTPUT
    } else {
        CMD_WRITE_KEYBOARD_OUTPUT
    };
    without_interrupts(|| {
        let mut controller = Controller {
            io: &mut HardwarePorts,
        };
        controller.command(command)?;
        controller.wait_input_clear()?;
        controller.io.write_data(byte);
        Ok(())
    })
}
