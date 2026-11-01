use std::env;
use std::path::PathBuf;

fn m9e_library() -> PathBuf {
    // M9e: the interpreter loads the shared library from `/fat/m9e.so`; the
    // dynamic main program only carries a DT_NEEDED entry with that SONAME.
    // For the link step rust-lld needs the actual file. xtask builds the
    // library first and may point us at the produced artifact explicitly.
    if let Some(explicit) = env::var_os("CAELUM_M9E_LIB") {
        return PathBuf::from(explicit);
    }
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    manifest_dir
        .join("..")
        .join("..")
        .join("target")
        .join("x86_64-unknown-none")
        .join("release")
        .join("caelum-m9e-lib")
}

fn m9f_a_library() -> PathBuf {
    // M9f: the dynamic main program additionally carries DT_NEEDED
    // `/fat/m9f-a.so`; library A itself depends on `/fat/m9f-b.so`. rust-lld
    // needs the actual files for the link step; xtask builds the libraries
    // first and may point us at the produced artifacts explicitly.
    if let Some(explicit) = env::var_os("CAELUM_M9F_A_LIB") {
        return PathBuf::from(explicit);
    }
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    manifest_dir
        .join("..")
        .join("..")
        .join("target")
        .join("x86_64-unknown-none")
        .join("release")
        .join("caelum-m9f-a")
}

fn main() {
    // M9d1 dynamic main program (ET_DYN PIE). These flags are link arguments,
    // so they are applied after every crate in the binary has been compiled;
    // the PIC code model itself is passed by the build driver (-C
    // relocation-model=pic) because a `[profile]` cannot override it per crate.
    println!("cargo:rustc-link-arg=-pie");
    println!("cargo:rustc-link-arg=--dynamic-linker=/fat/ldcaelum.so");
    println!("cargo:rustc-link-arg=-z");
    println!("cargo:rustc-link-arg=max-page-size=4096");
    // Keep .data.rel.ro writable at runtime: our interpreter applies RELATIVE
    // relocations itself and does not mprotect RELRO.
    println!("cargo:rustc-link-arg=-z");
    println!("cargo:rustc-link-arg=norelro");

    // M9e: link against the shared library. Passing the path as a positional
    // input keeps the SONAME (`/fat/m9e.so`) in the resulting DT_NEEDED entry;
    // the interpreter resolves that fixed name from the VFS.
    let library = m9e_library();
    println!("cargo:rerun-if-env-changed=CAELUM_M9E_LIB");
    println!("cargo:rerun-if-changed={}", library.display());
    println!("cargo:rustc-link-arg={}", library.display());

    // M9f: second DT_NEEDED (`/fat/m9f-a.so`), which in turn needs
    // `/fat/m9f-b.so`. The order of the two link args fixes the NEEDED order in
    // the dynamic table (m9e first, m9f-a second).
    let m9f_a = m9f_a_library();
    println!("cargo:rerun-if-env-changed=CAELUM_M9F_A_LIB");
    println!("cargo:rerun-if-changed={}", m9f_a.display());
    println!("cargo:rustc-link-arg={}", m9f_a.display());
}
