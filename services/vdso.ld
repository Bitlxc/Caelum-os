/*
 * M9d2 vDSO linker script.
 *
 * Fixed link addresses frozen with the kernel side:
 *   0x0700_0000  ELF headers + `__vdso_clock_gettime` image (text PT_LOAD)
 *   0x0700_1000  `__vdso_clock_gettime` entry (e_entry)
 *   0x0700_2000  vDSO data page (RW PT_LOAD: magic/version/seq/hz/ticks)
 *
 * The image is an ET_EXEC object mapped at its link address; the kernel does not
 * relocate it, and programs call it directly through AT_SYSINFO_EHDR.
 *
 * M10a: a real Linux vDSO is always a dynamically-shaped object, and musl's
 * `__dls3` builds a `struct dso` for the image reported through
 * `AT_SYSINFO_EHDR`: it derives `dso->base` from a `PT_LOAD` and `dso->dynv`
 * from `PT_DYNAMIC`. Without `PT_DYNAMIC` that pointer stays NULL and the
 * dynamic-vector decoder dereferences NULL. The empty `.dynamic` below (a
 * single `DT_NULL` pair) satisfies that contract; it advertises no symbols, so
 * musl falls back to the syscall path when it cannot resolve a vDSO function.
 * The kernel ignores `PT_DYNAMIC` (it only maps non-writable `PT_LOAD`s).
 */
ENTRY(__vdso_clock_gettime)

PHDRS
{
    text PT_LOAD FILEHDR PHDRS FLAGS(5);
    dynamic PT_DYNAMIC FLAGS(5);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = 0x07001000;
    .text : {
        *(.text._vdso)
        *(.text .text.*)
    } :text

    /*
     * M10a: empty dynamic section for musl's vDSO `struct dso` setup. A single
     * Elf64_Dyn { DT_NULL, 0 } pair is the whole content; it lives in the
     * read-only text PT_LOAD so the kernel's existing vDSO loader maps it.
     */
    .dynamic : ALIGN(8) {
        *(.dynamic)
        QUAD(0); /* DT_NULL tag */
        QUAD(0); /* d_val      */
    } :text :dynamic

    . = 0x07002000;
    .data : ALIGN(8) {
        KEEP(*(.data._vdso))
        *(.data .data.*)
    } :data

    .bss : {
        KEEP(*(.bss .bss.*))
        *(COMMON)
    } :data

    /DISCARD/ : {
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.comment)
        *(.note*)
        *(.llvm_addrsig)
    }
}
