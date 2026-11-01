/*
 * CaelumOS M9d1 custom `PT_INTERP` interpreter link script.
 *
 * The interpreter is a *fixed-address* ET_EXEC image: the kernel loads it at
 * its link address, so `AT_BASE` is 0 (fixed ET_EXEC load bias) and no
 * self-relocation is needed. It is linked at 0x0000000040000000, inside the
 * user low half and far from the main program's fixed ET_DYN base
 * 0x0000000002000000 (see `services/linux-dyn`).
 *
 * Three page-aligned PT_LOAD segments, no W+X mapping:
 *
 *   text   R + X   entry point (`_start`) and code
 *   rodata R       read-only data, relocated read-only data, GOT
 *   data   R + W   writable data and .bss
 *
 * The GOT is fully resolved at link time for ET_EXEC, so it can stay
 * read-only. The interpreter never writes its own image; it only writes the
 * main program's `DT_RELA` targets.
 */

ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5); /* PF_R | PF_X */
    rodata PT_LOAD FLAGS(4); /* PF_R         */
    data   PT_LOAD FLAGS(6); /* PF_R | PF_W  */
}

SECTIONS
{
    . = 0x0000000040000000;

    .text : ALIGN(0x1000)
    {
        *(.text._start)
        *(.text .text.*)
    } :text

    . = ALIGN(0x1000);
    .rodata :
    {
        *(.rodata .rodata.*)
        *(.data.rel.ro .data.rel.ro.*)
        *(.got .got.*)
    } :rodata

    . = ALIGN(0x1000);
    .data :
    {
        *(.data .data.*)
    } :data

    .bss (NOLOAD) :
    {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ :
    {
        *(.eh_frame .eh_frame_hdr)
        *(.comment)
        *(.note .note.*)
        *(.llvm_addrsig)
    }
}
