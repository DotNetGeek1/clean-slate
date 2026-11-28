//! Powering the machine off and resetting it (#372).
//!
//! Boot reads the FADT and the DSDT's `\_S5` package while the firmware identity map is live
//! (`interrupt::acpi`, before `ExitBootServices`) and keeps the result here. Power-off writes
//! `SLP_TYP | SLP_EN` to the PM1 control blocks; reset tries the FADT reset register, the 8042
//! reset line and finally a triple fault. Userspace reaches them through syscall 26 `POWER`
//! ([`syscall`]), which only init's capability authorizes.

pub(crate) mod acpi;
pub(crate) mod syscall;

use core::fmt;

use acpi::{pm1_sleep_value, FadtPower, ResetRegister, SleepType, Q35_S5_SLEEP_TYPE};

use crate::arch::x86_64::port::{port_in, port_in_u16, port_out, port_out_u16};
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::serial::serial_drain;
use crate::sync::global_cell::GlobalCell;

/// Where `SLP_TYP` came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SleepTypeSource {
    Dsdt,
    /// The DSDT had no readable `\_S5` package; [`Q35_S5_SLEEP_TYPE`] is used.
    Q35Fallback,
}

impl SleepTypeSource {
    const fn name(self) -> &'static str {
        match self {
            Self::Dsdt => "dsdt",
            Self::Q35Fallback => "q35-fallback",
        }
    }
}

/// The machine's power registers, as boot found them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PowerControl {
    pub(crate) registers: FadtPower,
    pub(crate) sleep_type: SleepType,
    pub(crate) source: SleepTypeSource,
}

impl PowerControl {
    /// `s5` is the DSDT scan's result; a failed scan falls back to the q35 value.
    pub(crate) fn new(registers: FadtPower, s5: Result<SleepType, &'static str>) -> Self {
        let (sleep_type, source) = match s5 {
            Ok(sleep_type) => (sleep_type, SleepTypeSource::Dsdt),
            Err(_) => (Q35_S5_SLEEP_TYPE, SleepTypeSource::Q35Fallback),
        };
        Self {
            registers,
            sleep_type,
            source,
        }
    }
}

struct Port(Option<u16>);

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(port) => write!(f, "{port:#x}"),
            None => f.write_str("none"),
        }
    }
}

impl fmt::Display for ResetRegister {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => f.write_str("none"),
            Self::Io { port, value } => write!(f, "io:{port:#x}={value:#04x}"),
            Self::Unsupported { space } => write!(f, "unsupported-space={space}"),
        }
    }
}

impl fmt::Display for PowerControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "pm1a={} pm1b={} reset={} s5={}/{} source={}",
            Port(self.registers.pm1a_control),
            Port(self.registers.pm1b_control),
            self.registers.reset,
            self.sleep_type.a,
            self.sleep_type.b,
            self.source.name()
        )
    }
}

static POWER_CONTROL: GlobalCell<Result<PowerControl, &'static str>> =
    GlobalCell::new(Err("ACPI power registers were not captured at boot"));

/// Stores what boot found. Called once, before `ExitBootServices`.
pub(crate) fn set_captured(control: Result<PowerControl, &'static str>) {
    unsafe { *POWER_CONTROL.get() = control };
}

fn captured() -> Result<PowerControl, &'static str> {
    unsafe { *POWER_CONTROL.get() }
}

/// One boot line saying what power-off and reset will use.
pub(crate) fn log_boot_capture() {
    match captured() {
        Ok(control) => kernel_log_fmt(format_args!("[PWR ] acpi {control}\n")),
        Err(reason) => kernel_log_fmt(format_args!("[PWR ] acpi unavailable: {reason}\n")),
    }
}

/// Port reads used as a delay while the hardware acts: about 100 ms on QEMU and real
/// hardware alike, without needing a calibrated clock.
const SETTLE_PORT_READS: u32 = 100_000;
/// The POST diagnostic port; reading it has no effect.
const DELAY_PORT: u16 = 0x80;

fn settle() {
    for _ in 0..SETTLE_PORT_READS {
        let _ = port_in(DELAY_PORT);
    }
}

/// Enters ACPI S5. Logs `[PWR ] off …` first. Returns only if the machine is still running,
/// with the reason.
pub(crate) fn off() -> &'static str {
    let control = match captured() {
        Ok(control) => control,
        Err(reason) => {
            kernel_log_fmt(format_args!("[PWR ] off refused: {reason}\n"));
            return reason;
        }
    };
    let Some(pm1a) = control.registers.pm1a_control else {
        kernel_log_fmt(format_args!(
            "[PWR ] off refused: the FADT has no usable PM1a control block\n"
        ));
        return "the FADT has no usable PM1a control block";
    };
    kernel_log_fmt(format_args!(
        "[PWR ] off slp_typ={}/{} source={} pm1a={pm1a:#x} pm1b={}\n",
        control.sleep_type.a,
        control.sleep_type.b,
        control.source.name(),
        Port(control.registers.pm1b_control),
    ));
    serial_drain();
    crate::arch::x86_64::cpu::disable_interrupts();
    port_out_u16(
        pm1a,
        pm1_sleep_value(port_in_u16(pm1a), control.sleep_type.a),
    );
    if let Some(pm1b) = control.registers.pm1b_control {
        port_out_u16(
            pm1b,
            pm1_sleep_value(port_in_u16(pm1b), control.sleep_type.b),
        );
    }
    settle();
    kernel_log_fmt(format_args!(
        "[PWR ] off failed: still running after the S5 write\n"
    ));
    "the machine did not power off"
}

/// 8042 controller status port and its "input buffer full" bit, and the pulse command that
/// drives the CPU reset line.
const I8042_STATUS: u16 = 0x64;
const I8042_INPUT_FULL: u8 = 1 << 1;
const I8042_PULSE_RESET: u8 = 0xfe;
const I8042_READY_POLLS: u32 = 100_000;

/// Resets the machine: the FADT reset register, then the 8042, then a triple fault. Logs
/// `[PWR ] reset method=…` before each.
pub(crate) fn reset() -> ! {
    crate::arch::x86_64::cpu::disable_interrupts();
    match captured().map(|control| control.registers.reset) {
        Ok(ResetRegister::Io { port, value }) => {
            kernel_log_fmt(format_args!(
                "[PWR ] reset method=fadt port={port:#x} value={value:#04x}\n"
            ));
            serial_drain();
            port_out(port, value);
            settle();
        }
        Ok(register) => kernel_log_fmt(format_args!(
            "[PWR ] reset fadt register unusable ({register})\n"
        )),
        Err(reason) => kernel_log_fmt(format_args!("[PWR ] reset fadt skipped: {reason}\n")),
    }
    kernel_log_fmt(format_args!("[PWR ] reset method=8042\n"));
    serial_drain();
    for _ in 0..I8042_READY_POLLS {
        if port_in(I8042_STATUS) & I8042_INPUT_FULL == 0 {
            break;
        }
    }
    port_out(I8042_STATUS, I8042_PULSE_RESET);
    settle();
    kernel_log_fmt(format_args!("[PWR ] reset method=triple-fault\n"));
    serial_drain();
    triple_fault()
}

/// Loads an empty IDT and raises an exception: with no handler the CPU shuts down, which
/// resets the machine.
fn triple_fault() -> ! {
    #[repr(C, packed)]
    struct EmptyIdt {
        limit: u16,
        base: u64,
    }
    let empty = EmptyIdt { limit: 0, base: 0 };
    unsafe {
        core::arch::asm!(
            "lidt [{0}]",
            "int3",
            "2:",
            "hlt",
            "jmp 2b",
            in(reg) &empty,
            options(noreturn)
        );
    }
}

/// The self-test boots (`power-off-self-test`, `power-reset-self-test`): power the machine
/// off or reset it at the end of boot. Returns only when power-off failed.
#[cfg(any(
    clean_slate_power_selftest = "off",
    clean_slate_power_selftest = "reset"
))]
pub(crate) fn run_self_test() -> Result<(), &'static str> {
    kernel_log_fmt(format_args!("[PWR ] self-test at the end of boot\n"));
    #[cfg(clean_slate_power_selftest = "off")]
    {
        Err(off())
    }
    #[cfg(clean_slate_power_selftest = "reset")]
    {
        reset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const Q35_FACP: &[u8] = include_bytes!("fixtures/q35-facp.bin");
    const Q35_DSDT: &[u8] = include_bytes!("fixtures/q35-dsdt.bin");

    #[test]
    fn the_boot_line_names_every_register_and_the_s5_source() {
        let registers = acpi::parse_fadt(Q35_FACP).unwrap();
        let control = PowerControl::new(registers, acpi::s5_sleep_type(Q35_DSDT));
        let mut line = std::string::String::new();
        fmt::write(&mut line, format_args!("{control}")).unwrap();
        assert_eq!(
            line,
            "pm1a=0x604 pm1b=none reset=io:0xcf9=0x0f s5=0/0 source=dsdt"
        );
    }

    #[test]
    fn a_failed_s5_scan_falls_back_to_q35_and_says_so() {
        let registers = acpi::parse_fadt(Q35_FACP).unwrap();
        let control = PowerControl::new(registers, Err("DSDT has no \\_S5 package"));
        assert_eq!(control.sleep_type, Q35_S5_SLEEP_TYPE);
        assert_eq!(control.source, SleepTypeSource::Q35Fallback);
    }
}
