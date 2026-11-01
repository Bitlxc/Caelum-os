//! Links the binary with the shared CaelumOS user link script
//! (`services/user.ld`) so the image is a static ET_EXEC with the M4 segment
//! split. The script path is absolute, and every allocatable section is
//! assigned to one of its three PT_LOAD segments.

use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set"),
    );
    // services/<package>/../user.ld
    let script = manifest_dir.join("..").join("user.ld");

    println!("cargo:rerun-if-changed={}", script.display());
    // rust-lld: pass the script and pin the segment alignment to 4 KiB pages.
    println!("cargo:rustc-link-arg=-T{}", script.display());
    println!("cargo:rustc-link-arg=-z");
    println!("cargo:rustc-link-arg=max-page-size=4096");
}
