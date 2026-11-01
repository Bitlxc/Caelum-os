fn main() {
    // The M9e library is a `bin` crate forced into a real ET_DYN shared object:
    // `x86_64-unknown-none` has no `cdylib` support and rustc always passes
    // `-pie` for binaries, so `-no-pie` must precede `-shared`.
    println!("cargo:rustc-link-arg=-no-pie");
    println!("cargo:rustc-link-arg=-shared");
    // The SONAME becomes the main program's DT_NEEDED string; it must be the
    // exact VFS path the kernel loads (FAT 8.3: `m9e.so`).
    println!("cargo:rustc-link-arg=-soname");
    println!("cargo:rustc-link-arg=/fat/m9e.so");
    // Publish both hash tables: the interpreter only needs DT_HASH, but having
    // the GNU hash keeps the image a normal shared object.
    println!("cargo:rustc-link-arg=--hash-style=both");
    println!("cargo:rustc-link-arg=-z");
    println!("cargo:rustc-link-arg=max-page-size=4096");
    // The interpreter applies RELATIVE relocations itself and never mprotects
    // RELRO (same rule as the main program).
    println!("cargo:rustc-link-arg=-z");
    println!("cargo:rustc-link-arg=norelro");
}
