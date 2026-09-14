#![no_std]
#![no_main]

use core::arch::asm;
use core::panic::PanicInfo;

const COM1: u16 = 0x3F8;

#[no_mangle]
pub extern "efiapi" fn efi_main(_image_handle: usize, _system_table: usize) -> usize {
    serial_init();
    serial_write_line("CLEAN-SLATE 0.0.1");
    serial_write_line("x86_64");
    serial_write_line("Hello world.");

    loop {
        cpu_halt();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    serial_write_line("PANIC: kernel halted");
    loop {
        cpu_halt();
    }
}

fn serial_init() {
    serial_out(COM1 + 1, 0x00);
    serial_out(COM1 + 3, 0x80);
    serial_out(COM1, 0x03);
    serial_out(COM1 + 1, 0x00);
    serial_out(COM1 + 3, 0x03);
    serial_out(COM1 + 2, 0xC7);
    serial_out(COM1 + 4, 0x0B);
}

fn serial_write_line(message: &str) {
    for byte in message.bytes() {
        serial_write_byte(byte);
    }
    serial_write_byte(b'\n');
}

fn serial_write_byte(byte: u8) {
    while (serial_in(COM1 + 5) & 0x20) == 0 {}
    serial_out(COM1, byte);
}

fn serial_out(port: u16, value: u8) {
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nostack, nomem));
    }
}

fn serial_in(port: u16) -> u8 {
    let mut value: u8;
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") value, options(nostack, nomem));
    }
    value
}

fn cpu_halt() {
    unsafe {
        asm!("hlt", options(nomem, nostack));
    }
}
