/* Compact layout for CKB-VM: sections contiguous, 4 KiB page aligned,
   so no read-only page carries writable data. */
ENTRY(_start)
SECTIONS {
  . = 0x10000;
  .text : ALIGN(0x1000) { *(.text .text.*) }
  .rodata : ALIGN(0x1000) { *(.rodata .rodata.* .srodata .srodata.*) }
  .data : ALIGN(0x1000) { *(.data .data.* .sdata .sdata.*) }
  .bss : ALIGN(0x1000) { *(.bss .bss.* .sbss .sbss.* COMMON) }
  /DISCARD/ : { *(.eh_frame .eh_frame_hdr .note .note.*) }
}
