fn main() {
    // The vDSO image is linked with its own script: fixed ET_EXEC addresses
    // 0x0700_0000 (headers), 0x0700_1000 (entry) and 0x0700_2000 (data page).
    //
    // `-no-pie` is explicit: the dynamic main program needs
    // `RUSTFLAGS=-C relocation-model=pic`, and an ambient PIC flag must not be
    // allowed to turn this fixed-address ET_EXEC image into ET_DYN.
    println!("cargo:rustc-link-arg=-no-pie");
    println!(
        "cargo:rustc-link-arg=-T{}/../vdso.ld",
        env!("CARGO_MANIFEST_DIR")
    );
    println!("cargo:rustc-link-arg=-z");
    println!("cargo:rustc-link-arg=max-page-size=4096");
    println!(
        "cargo:rerun-if-changed={}/../vdso.ld",
        env!("CARGO_MANIFEST_DIR")
    );
}
