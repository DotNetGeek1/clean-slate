/* Single RX PT_LOAD at conventional Linux ET_EXEC base 0x400000.
 * .text and .rodata share the segment so the fixture needs no writable data.
 */
ENTRY(_start)

PHDRS
{
  text PT_LOAD FLAGS(5); /* PF_R | PF_X */
}

SECTIONS
{
  . = 0x400000 + SIZEOF_HEADERS;

  .text : {
    *(.text .text.*)
    *(.rodata .rodata.*)
  } :text

  /DISCARD/ : {
    *(.note.*)
    *(.comment)
    *(.eh_frame*)
    *(.gnu.*)
  }
}
