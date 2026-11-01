/*
 * CaelumOS M4 user program link script.
 *
 * Shared by every native user program built for x86_64-unknown-none. It
 * produces a static ET_EXEC image in the low half of the address space with
 * three PT_LOAD segments and no W+X mapping:
 *
 *   text   R + X   entry point and code
 *   rodata R       read-only data, relocated read-only data, GOT
 *   data   R + W   writable data and .bss
 *
 * The segment bases are page aligned relative to the 0x400000 load address so
 * a loader can map each PT_LOAD with its own permissions without splitting
 * pages. x86-64 is used as the reference layout; other architectures need their
 * own script with the same segment split (see docs/abi/native-syscall.md).
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
    . = 0x0000000000400000;

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
