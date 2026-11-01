# CaelumOS kernel linker script (x86-64, higher half).
#
# The kernel is linked at 0xFFFFFFFF80000000; the UEFI loader maps every
# PT_LOAD at its virtual link address and also identity-maps the physical
# image range. Three segments keep W^X permissions expressible:
#   text   R+X, rodata R (NX), data/bss R+W (NX).
#
# Section boundary symbols (__text_start .. __bss_end) feed the M2 bootstrap
# page tables (mm::vm) for the W^X kernel mapping.

OUTPUT_FORMAT("elf64-x86-64")
ENTRY(_start)

PHDRS {
    text   PT_LOAD FLAGS(5);   /* PF_R | PF_X */
    rodata PT_LOAD FLAGS(4);   /* PF_R       */
    data   PT_LOAD FLAGS(6);   /* PF_R | PF_W */
}

SECTIONS {
    . = 0xFFFFFFFF80000000;

    __text_start = .;
    .text : ALIGN(0x1000) {
        *(.text .text.*)
    } :text
    __text_end = .;

    . = ALIGN(0x1000);
    __rodata_start = .;
    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    } :rodata

    .caelum.bootreq : {
        KEEP(*(.caelum.bootreq))
    } :rodata
    __rodata_end = .;

    . = ALIGN(0x1000);
    __data_start = .;
    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
        *(.data.rel.ro .data.rel.ro.*)
        *(.got)
    } :data

    .bss : {
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
    } :data
    __bss_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame_hdr)
    }
}
