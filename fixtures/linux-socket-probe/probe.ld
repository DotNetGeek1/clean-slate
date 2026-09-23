/* M9 #105: static ET_EXEC at 0x400000 — Linux socket probe (raw syscalls). */
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
