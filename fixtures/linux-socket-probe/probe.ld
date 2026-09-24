/* M9 #105: static ET_EXEC at 0x400000 — Linux socket probe (raw syscalls). */
ENTRY(_start)

PHDRS
{
  text PT_LOAD FILEHDR PHDRS FLAGS(5);
  data PT_LOAD FLAGS(6);
}

SECTIONS
{
  . = 0x400000 + SIZEOF_HEADERS;

  .text : {
    *(.text .text.*)
    *(.rodata .rodata.*)
  } :text

  . = ALIGN(0x1000);
  .data : {
    /* One mapped byte so PT_LOAD p_offset stays within the ELF file. */
    __data_start = .;
    LONG(0)
  } :data

  .bss : {
    *(.bss .bss.*)
    *(COMMON)
  } :data

  /DISCARD/ : {
    *(.note.*)
    *(.comment)
    *(.eh_frame*)
    *(.gnu.*)
  }
}
