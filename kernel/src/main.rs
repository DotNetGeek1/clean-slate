#![no_std]
#![no_main]

use clean_slate_kernel::{halt_loop, run, serial_write_line};
use core::panic::PanicInfo;
use uefi::{entry, Status};

#[entry]
fn efi_main() -> Status {
    run()
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    serial_write_line("PANIC: kernel halted");
    clean_slate_kernel::serial_write_fmt(format_args!("PANIC: {info}\n"));
    halt_loop()
}
