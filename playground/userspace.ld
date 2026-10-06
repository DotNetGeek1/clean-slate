OUTPUT_ARCH(x86_64)
ENTRY(_start)

SECTIONS
{
  . = 0x0000400000000000;
  .text : {
    *(.text .text.*)
  }
  /* Keep R-X text off the same page as R-only rodata when the linker splits them. */
  . = ALIGN(4096);
  .rodata : {
    *(.rodata .rodata.*)
  }
  /* RX vs RW must never share a page (W^X). */
  . = ALIGN(4096);
  .data : {
    *(.data .data.*)
  }
  .bss : {
    *(.bss .bss.*)
  }
}
