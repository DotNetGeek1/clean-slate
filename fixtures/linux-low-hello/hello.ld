/* M9 low ET_EXEC at conventional Linux base 0x400000. */
ENTRY(_start)

PHDRS
{
  text PT_LOAD FILEHDR PHDRS FLAGS(5);
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
