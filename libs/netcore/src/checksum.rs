//! Internet checksum (RFC 1071) and the IPv4/IPv6 pseudo-header variants.
//!
//! All functions accumulate big-endian 16-bit words; an odd trailing byte is
//! padded with a zero low byte, exactly as the wire protocols specify. The
//! pseudo-header forms are the only ones UDP, TCP and ICMPv6 may use, so they
//! live next to the plain checksum to keep loopback and the driver consistent.

use crate::{Ipv4Addr, Ipv6Addr};

/// Incremental Internet-checksum accumulator.
///
/// Build one, [`add`](Checksum::add) the pseudo header and payload (including
/// the checksum field itself when verifying), then [`finish`](Checksum::finish)
/// for the field value or [`verify`](Checksum::verify) for a verdict.
#[derive(Debug, Clone, Copy, Default)]
pub struct Checksum {
    sum: u32,
    /// A trailing odd byte carried across [`Checksum::add`] calls.
    pending: u8,
    has_pending: bool,
}

impl Checksum {
    /// An empty accumulator.
    pub const fn new() -> Self {
        Checksum {
            sum: 0,
            pending: 0,
            has_pending: false,
        }
    }

    /// Fold the 32-bit sum into 16 bits (one's complement carry wrap).
    fn folded(&self) -> u16 {
        let mut sum = self.sum;
        if self.has_pending {
            sum += u32::from(self.pending) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        sum as u16
    }

    /// Add bytes as big-endian 16-bit words.
    ///
    /// An odd number of bytes leaves one byte pending; the next [`add`] call
    /// pairs it with its own first byte, so the result is independent of how a
    /// caller splits the data (e.g. pseudo header then segment).
    ///
    /// [`add`]: Checksum::add
    pub fn add(&mut self, data: &[u8]) {
        let mut index = 0;
        if self.has_pending {
            if data.is_empty() {
                return;
            }
            self.sum += u32::from(u16::from_be_bytes([self.pending, data[0]]));
            self.has_pending = false;
            index = 1;
        }
        while index + 1 < data.len() {
            self.sum += u32::from(u16::from_be_bytes([data[index], data[index + 1]]));
            index += 2;
        }
        if index < data.len() {
            self.pending = data[index];
            self.has_pending = true;
        }
    }

    /// Add one 16-bit word (network byte order implied by the caller).
    ///
    /// Words are only meaningful on an even byte boundary; callers add whole
    /// pseudo headers, never half a byte, before using this.
    pub fn add_u16(&mut self, value: u16) {
        self.sum += u32::from(value);
    }

    /// The value to store in a checksum field that was zeroed before the call.
    pub fn finish(&self) -> u16 {
        !self.folded()
    }

    /// Whether the accumulated bytes (including a checksum field) are valid.
    ///
    /// A valid Internet checksum over the whole packet folds to `0xFFFF`.
    pub fn verify(&self) -> bool {
        self.folded() == 0xFFFF
    }
}

/// Internet checksum of `data` (ICMPv4 style, no pseudo header).
pub fn checksum(data: &[u8]) -> u16 {
    let mut accumulator = Checksum::new();
    accumulator.add(data);
    accumulator.finish()
}

/// Whether `data` (which includes its checksum field) verifies.
pub fn verify(data: &[u8]) -> bool {
    let mut accumulator = Checksum::new();
    accumulator.add(data);
    accumulator.verify()
}

fn add_pseudo_v4(
    accumulator: &mut Checksum,
    protocol: u8,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    len: usize,
) {
    accumulator.add(&src.0);
    accumulator.add(&dst.0);
    // Zero byte + protocol.
    accumulator.add_u16(u16::from(protocol));
    // Upper-layer length (always representable: callers reject > 65535).
    accumulator.add_u16(len as u16);
}

/// Checksum field value for an IPv4 UDP/TCP segment (`payload` has a zeroed
/// checksum field when building).
pub fn checksum_v4(protocol: u8, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> u16 {
    let mut accumulator = Checksum::new();
    add_pseudo_v4(&mut accumulator, protocol, src, dst, payload.len());
    accumulator.add(payload);
    accumulator.finish()
}

/// Verify an IPv4 UDP/TCP segment with its checksum field in place.
pub fn verify_v4(protocol: u8, src: Ipv4Addr, dst: Ipv4Addr, segment: &[u8]) -> bool {
    let mut accumulator = Checksum::new();
    add_pseudo_v4(&mut accumulator, protocol, src, dst, segment.len());
    accumulator.add(segment);
    accumulator.verify()
}

fn add_pseudo_v6(
    accumulator: &mut Checksum,
    protocol: u8,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    len: usize,
) {
    accumulator.add(&src.0);
    accumulator.add(&dst.0);
    let len = len as u32;
    accumulator.add_u16((len >> 16) as u16);
    accumulator.add_u16(len as u16);
    // Three zero bytes + next header.
    accumulator.add_u16(0);
    accumulator.add_u16(u16::from(protocol));
}

/// Checksum field value for an IPv6 UDP/TCP/ICMPv6 upper-layer packet.
pub fn checksum_v6(protocol: u8, src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> u16 {
    let mut accumulator = Checksum::new();
    add_pseudo_v6(&mut accumulator, protocol, src, dst, payload.len());
    accumulator.add(payload);
    accumulator.finish()
}

/// Verify an IPv6 upper-layer packet with its checksum field in place.
pub fn verify_v6(protocol: u8, src: Ipv6Addr, dst: Ipv6Addr, segment: &[u8]) -> bool {
    let mut accumulator = Checksum::new();
    add_pseudo_v6(&mut accumulator, protocol, src, dst, segment.len());
    accumulator.add(segment);
    accumulator.verify()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1071_worked_example() {
        // RFC 1071 section 3: bytes 00 01 f2 03 f4 f5 f6 f7 -> checksum 0x220D.
        let data = [0x00u8, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&data), 0x220D);
        let mut with_field = [0u8; 10];
        with_field[..8].copy_from_slice(&data);
        with_field[8..].copy_from_slice(&0x220Du16.to_be_bytes());
        assert!(verify(&with_field));
    }

    #[test]
    fn odd_length_is_padded_with_a_zero_low_byte() {
        assert_eq!(checksum(&[0x12]), !0x1200u16);
        let mut accumulator = Checksum::new();
        accumulator.add(&[0x12]);
        assert_eq!(accumulator.finish(), !0x1200u16);
    }

    #[test]
    fn empty_input_has_an_all_ones_field() {
        assert_eq!(checksum(&[]), 0xFFFF);
        assert!(verify(&[0xFF, 0xFF]));
    }

    #[test]
    fn incremental_accumulation_matches_one_shot() {
        let data = [0x45u8, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00];
        let one_shot = checksum(&data);
        let mut accumulator = Checksum::new();
        accumulator.add(&data[..3]);
        accumulator.add(&data[3..]);
        assert_eq!(accumulator.finish(), one_shot);
    }

    #[test]
    fn ipv4_pseudo_header_is_deterministic() {
        let src = Ipv4Addr::new(192, 0, 2, 1);
        let dst = Ipv4Addr::new(198, 51, 100, 2);
        let payload = [0u8; 8];
        let first = checksum_v4(PROTOCOL_UDP_FOR_TEST, src, dst, &payload);
        let second = checksum_v4(PROTOCOL_UDP_FOR_TEST, src, dst, &payload);
        assert_eq!(first, second);
        // A different pseudo header must change the result (the sum of the
        // address words is order independent, so change the protocol or an
        // address rather than swapping the two).
        assert_ne!(
            first,
            checksum_v4(PROTOCOL_TCP_FOR_TEST, src, dst, &payload)
        );
    }

    const PROTOCOL_UDP_FOR_TEST: u8 = 17;
    const PROTOCOL_TCP_FOR_TEST: u8 = 6;

    #[test]
    fn ipv4_segment_verifies_after_placing_the_field() {
        let src = Ipv4Addr::LOOPBACK;
        let dst = Ipv4Addr::LOOPBACK;
        let mut segment = [0u8; 8];
        segment[..4].copy_from_slice(&[0x04, 0xd2, 0x00, 0x07]); // ports
        let field = checksum_v4(PROTOCOL_UDP_FOR_TEST, src, dst, &segment);
        segment[6..8].copy_from_slice(&field.to_be_bytes());
        assert!(verify_v4(PROTOCOL_UDP_FOR_TEST, src, dst, &segment));
        segment[0] ^= 0x01;
        assert!(!verify_v4(PROTOCOL_UDP_FOR_TEST, src, dst, &segment));
    }

    #[test]
    fn ipv6_pseudo_header_covers_addresses_and_length() {
        let src = Ipv6Addr::LOOPBACK;
        let dst = Ipv6Addr::LOOPBACK;
        let payload = [0u8; 8];
        let field = checksum_v6(58, src, dst, &payload);
        let mut segment = payload;
        segment[2..4].copy_from_slice(&field.to_be_bytes());
        assert!(verify_v6(58, src, dst, &segment));
        assert!(!verify_v6(17, src, dst, &segment));
        assert_ne!(field, checksum_v6(58, src, Ipv6Addr::UNSPECIFIED, &payload));
    }
}
