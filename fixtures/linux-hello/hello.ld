/* Single RX PT_LOAD inside the Clean-Slate M8 user VA window.
 *
 * Image base 0x0000400000400000 = PML4 slot 128 base (0x4000_0000_0000)
 * plus the classic 4 MiB offset. FILEHDR+PHDRS are part of the load so
 * AT_PHDR can point at a mapped user address. .text/.rodata share RX.
 */
ENTRY(_start)

PHDRS
{
  text PT_LOAD FILEHDR PHDRS FLAGS(5); /* PF_R | PF_X */
}

SECTIONS
{
  . = 0x0000400000400000 + SIZEOF_HEADERS;

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
