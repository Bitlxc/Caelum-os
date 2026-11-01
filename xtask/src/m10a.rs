//! M10a real-sample loading and SHA-256 verification.
//!
//! M10a runs genuine Linux binaries: `busybox` and the two musl shared objects
//! copied verbatim from an Alpine container (see `tools/m10a/README.md`). The
//! harness injects them into the ext2 test volume at `/bin/busybox` and
//! `/lib/ld-musl-x86_64.so.1` + `/lib/libc.musl-x86_64.so.1` before the guest
//! starts, and the host re-checks the image after each boot.
//!
//! Those samples are third-party bytes that nothing in this repository builds,
//! so a locally corrupted checkout must not be able to turn a run green:
//! `cargo xtask build` and `cargo xtask image` verify them against
//! `tools/m10a/SHA256SUMS` every time.
//!
//! `std` only: the SHA-256 implementation lives here because no crypto crate
//! (or `sha2`-like helper) is available to `xtask`.

use std::fs;
use std::path::{Path, PathBuf};

/// Directory (relative to the workspace root) holding the M10a samples.
pub const SAMPLE_DIR: &str = "tools/m10a";
/// The checksum manifest every build verifies the samples against.
pub const SUMS_FILE: &str = "SHA256SUMS";

/// Real `busybox` binary, injected as ext2 `/bin/busybox`.
pub const BUSYBOX: &str = "busybox";
/// musl dynamic loader, injected as ext2 `/lib/ld-musl-x86_64.so.1`.
pub const LD_MUSL: &str = "ld-musl-x86_64.so.1";
/// musl libc (the same bytes as the loader in this sample), injected as
/// `/lib/libc.musl-x86_64.so.1`.
pub const LIBC_MUSL: &str = "libc.musl-x86_64.so.1";

/// The sample names, in the order they are verified and reported.
#[cfg(test)]
pub const ALL_SAMPLES: [&str; 3] = [BUSYBOX, LD_MUSL, LIBC_MUSL];

/// The three M10a payloads, already verified against [`SUMS_FILE`].
pub struct Samples {
    pub busybox: Vec<u8>,
    pub ld_musl: Vec<u8>,
    pub libc_musl: Vec<u8>,
}

impl Samples {
    /// An empty set for unit tests that only exercise the M5 volumes.
    #[cfg(test)]
    pub fn empty() -> Self {
        Samples {
            busybox: Vec::new(),
            ld_musl: Vec::new(),
            libc_musl: Vec::new(),
        }
    }

    /// True when nothing is injected (the M5-only test shape).
    pub fn is_empty(&self) -> bool {
        self.busybox.is_empty() && self.ld_musl.is_empty() && self.libc_musl.is_empty()
    }

    /// Total number of injected bytes, for the build summary.
    pub fn total_len(&self) -> usize {
        self.busybox.len() + self.ld_musl.len() + self.libc_musl.len()
    }
}

/// Absolute path of the sample directory.
pub fn sample_dir() -> PathBuf {
    crate::root().join(SAMPLE_DIR)
}

/// Load and verify the three M10a samples against `SHA256SUMS`.
///
/// Every failure names the file and the expected/actual digest, so a corrupted
/// checkout is diagnosed instead of merely failing the run.
pub fn load_samples() -> Result<Samples, String> {
    let dir = sample_dir();
    let sums_path = dir.join(SUMS_FILE);
    let sums = fs::read(&sums_path).map_err(|e| format!("reading {}: {e}", sums_path.display()))?;
    let entries = parse_sums(&sums)?;
    let busybox = read_verified(&dir, &entries, BUSYBOX)?;
    let ld_musl = read_verified(&dir, &entries, LD_MUSL)?;
    let libc_musl = read_verified(&dir, &entries, LIBC_MUSL)?;
    Ok(Samples {
        busybox,
        ld_musl,
        libc_musl,
    })
}

fn read_verified(
    dir: &Path,
    entries: &[(String, [u8; 32])],
    name: &str,
) -> Result<Vec<u8>, String> {
    let path = dir.join(name);
    let bytes =
        fs::read(&path).map_err(|e| format!("reading the M10a sample {}: {e}", path.display()))?;
    verify_sample(name, &bytes, entries).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(bytes)
}

/// Check one payload against the manifest entry that names it.
fn verify_sample(name: &str, bytes: &[u8], entries: &[(String, [u8; 32])]) -> Result<(), String> {
    let expected = entries
        .iter()
        .find(|(listed, _)| listed == name)
        .map(|(_, hash)| hash)
        .ok_or_else(|| format!("{SUMS_FILE} does not list {name}"))?;
    let actual = sha256(bytes);
    if &actual != expected {
        return Err(format!(
            "SHA-256 mismatch: got {}, expected {} ({SUMS_FILE})",
            hex(&actual),
            hex(expected)
        ));
    }
    Ok(())
}

/// Parse the `sha256sum`-style manifest (`<64 hex digits>  <name>`).
fn parse_sums(bytes: &[u8]) -> Result<Vec<(String, [u8; 32])>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| format!("{SUMS_FILE} is not valid UTF-8"))?;
    let mut entries = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let number = index + 1;
        let mut fields = line.split_whitespace();
        let hash = fields
            .next()
            .ok_or_else(|| format!("{SUMS_FILE}:{number}: missing hash"))?;
        let name = fields
            .next()
            .ok_or_else(|| format!("{SUMS_FILE}:{number}: missing file name"))?;
        if fields.next().is_some() {
            return Err(format!("{SUMS_FILE}:{number}: unexpected extra column"));
        }
        if hash.len() != 64 {
            return Err(format!(
                "{SUMS_FILE}:{number}: hash is {} hex digits, expected 64",
                hash.len()
            ));
        }
        let mut digest = [0u8; 32];
        for (slot, chunk) in digest.iter_mut().zip(hash.as_bytes().chunks(2)) {
            let pair = std::str::from_utf8(chunk)
                .map_err(|_| format!("{SUMS_FILE}:{number}: hash is not ASCII"))?;
            *slot = u8::from_str_radix(pair, 16)
                .map_err(|_| format!("{SUMS_FILE}:{number}: hash has a non-hex digit"))?;
        }
        entries.push((name.to_string(), digest));
    }
    Ok(entries)
}

/// SHA-256 (FIPS 180-4), implemented here to keep `xtask` crate-free.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in message.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut digest = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        digest[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Lowercase hex digest, as `sha256sum` prints it.
pub fn hex(hash: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in hash {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digests every M10a run is pinned to (mirrors `tools/m10a/SHA256SUMS`).
    const BUSYBOX_SHA256: &str = "f3547b3d78d08a028a4833ddb83b77cf012838c078bfd2b76355f53d1d8bba62";
    const MUSL_SHA256: &str = "0ea959387b385d63b7e8730cd4fc7e7f94ee032a61aacabc81e1df3ce4a9344e";

    #[test]
    fn sha256_matches_the_fips_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn repository_samples_match_the_manifest() {
        let samples = load_samples().expect("tools/m10a samples must verify");
        assert_eq!(samples.busybox.len(), 804_616);
        assert_eq!(samples.ld_musl.len(), 666_216);
        assert_eq!(samples.libc_musl.len(), 666_216);
        assert_eq!(hex(&sha256(&samples.busybox)), BUSYBOX_SHA256);
        // musl's loader and libc are the same file in this sample.
        assert_eq!(hex(&sha256(&samples.ld_musl)), MUSL_SHA256);
        assert_eq!(hex(&sha256(&samples.libc_musl)), MUSL_SHA256);
        assert_eq!(samples.total_len(), 2_137_048);
        assert!(!samples.is_empty());
    }

    #[test]
    fn corrupted_sample_bytes_are_rejected() {
        let entries = parse_sums(
            format!("{BUSYBOX_SHA256}  {BUSYBOX}\n{MUSL_SHA256}  {LD_MUSL}\n{MUSL_SHA256}  {LIBC_MUSL}\n")
                .as_bytes(),
        )
        .expect("manifest parses");
        verify_sample(BUSYBOX, b"not busybox", &entries).expect_err("wrong bytes must fail");
        let mut good = vec![0u8; 16];
        good[0] = 1;
        verify_sample(LD_MUSL, &good, &entries).expect_err("unknown digest must fail");
        // A name the manifest does not mention is rejected instead of trusted.
        verify_sample("busybox.bak", &good, &entries).expect_err("unlisted sample");
    }

    #[test]
    fn sums_parser_rejects_malformed_manifests() {
        assert!(parse_sums(b"").expect("empty manifest is legal").is_empty());
        let short = b"abc  busybox\n";
        assert!(parse_sums(short).expect_err("short hash").contains("64"));
        let extra = format!("{BUSYBOX_SHA256}  {BUSYBOX} extra\n");
        assert!(
            parse_sums(extra.as_bytes())
                .expect_err("extra column")
                .contains("extra column")
        );
        let not_hex = format!("{}  {BUSYBOX}\n", "z".repeat(64));
        assert!(parse_sums(not_hex.as_bytes()).is_err(), "non-hex");
    }
}
