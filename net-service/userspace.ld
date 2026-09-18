OUTPUT_ARCH(x86_64)
ENTRY(_start)

SECTIONS
{
  . = 0x0000400000000000;
  .text : {
    *(.text .text.*)
  }
  .rodata : {
    *(.rodata .rodata.*)
  }
  .data : {
    *(.data .data.*)
  }
  .bss : {
    *(.bss .bss.*)
  }
}
