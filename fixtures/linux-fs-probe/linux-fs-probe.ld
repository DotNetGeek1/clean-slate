ENTRY(_start)

PHDRS
{
  text PT_LOAD FILEHDR PHDRS FLAGS(5);
  data PT_LOAD FLAGS(6);
}

SECTIONS
{
  . = 0x400000 + SIZEOF_HEADERS;
  .text : { *(.text .text.*) *(.rodata .rodata.*) } :text
  . = ALIGN(0x1000);
  .bss : { *(.bss .bss.*) *(COMMON) } :data
  /DISCARD/ : { *(.note.*) *(.comment) *(.eh_frame*) *(.gnu.*) }
}
