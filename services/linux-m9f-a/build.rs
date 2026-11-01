use std::env;
use std::path::PathBuf;

fn m9f_b_library() -> PathBuf {
    // M9f: library A carries DT_NEEDED `/fat/m9f-b.so`; the dynamic interpreter
    // loads B from the VFS. For the link step rust-lld needs the actual file.
    // xtask builds B first and may point us at the produced artifact explicitly.
    if let Some(explicit) = env::var_os("CAELUM_M9F_B_LIB") {
        return PathBuf::from(explicit);
    }
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    manifest_dir
        .join("..")
        .join("..")
        .join("target")
        .join("x86_64-unknown-none")
        .join("release")
        .join("caelum-m9f-b")
}

fn main() {
    // Library A: a `bin` crate forced into a real ET_DYN shared object.
    // `-no-pie` must precede `-shared` (rustc always passes `-pie` for bins).
    println!("cargo:rustc-link-arg=-no-pie");
    println!("cargo:rustc-link-arg=-shared");
    // The SONAME becomes the main program's second DT_NEEDED string; it must be
    // the exact VFS path the kernel maps (FAT 8.3: `m9f-a.so`).
    println!("cargo:rustc-link-arg=-soname");
    println!("cargo:rustc-link-arg=/fat/m9f-a.so");
    println!("cargo:rustc-link-arg=--hash-style=both");
    println!("cargo:rustc-link-arg=-z");
    println!("cargo:rustc-link-arg=max-page-size=4096");
    println!("cargo:rustc-link-arg=-z");
    println!("cargo:rustc-link-arg=norelro");

    // M9f: link against library B. Passing the path as a positional input keeps
    // B's SONAME (`/fat/m9f-b.so`) in A's DT_NEEDED entry; the interpreter
    // resolves that fixed name from the VFS.
    let library = m9f_b_library();
    println!("cargo:rerun-if-env-changed=CAELUM_M9F_B_LIB");
    println!("cargo:rerun-if-changed={}", library.display());
    println!("cargo:rustc-link-arg={}", library.display());
}
