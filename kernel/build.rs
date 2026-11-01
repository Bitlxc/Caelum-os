fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let script = dir.replace('\\', "/");
    println!("cargo:rustc-link-arg=-T{script}/kernel.ld");
    println!("cargo:rerun-if-changed=kernel.ld");
}
