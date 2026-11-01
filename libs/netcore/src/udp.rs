//! UDP (RFC 768) datagram parsing and construction.
//!
//! UDP's checksum is optional over IPv4 (a zero field means "not computed") and
//! mandatory over IPv6 (a zero field is illegal, RFC 8200 section 8.1). Both
//! pseudo-header variants are exposed so the caller picks the right one from the
//! IP version it just parsed; nothing here inspects IP headers itself.

use crate::addr::{Ipv4Addr, Ipv6Addr};
use crate::checksum;
use crate::{PROTOCOL_UDP, PacketError};

/// UDP header length.
pub const HEADER_LEN: usize = 8;
/// Protocol number used in both pseudo headers.
pub const PROTOCOL: u8 = PROTOCOL_UDP;

/// A parsed UDP datagram with a borrowed payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Value of the length field (header included).
    pub length: u16,
    /// The checksum field as it appeared on the wire.
    pub checksum: u16,
    /// The payload (`length - 8` bytes).
    pub payload: &'a [u8],
}

/// Parse a UDP datagram without verifying its checksum.
///
/// Bytes beyond the length field (Ethernet padding) are ignored; a length field
/// below the header or larger than the slice is rejected.
pub fn parse(packet: &[u8]) -> Result<UdpDatagram<'_>, PacketError> {
    if packet.len() < HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    let length = u16::from_be_bytes([packet[4], packet[5]]);
    let length_usize = usize::from(length);
    if length_usize < HEADER_LEN {
        return Err(PacketError::BadLength);
    }
    if length_usize > packet.len() {
        return Err(PacketError::Truncated);
    }
    Ok(UdpDatagram {
        src_port: u16::from_be_bytes([packet[0], packet[1]]),
        dst_port: u16::from_be_bytes([packet[2], packet[3]]),
        length,
        checksum: u16::from_be_bytes([packet[6], packet[7]]),
        payload: &packet[HEADER_LEN..length_usize],
    })
}

/// Parse a UDP datagram and verify its IPv4 pseudo-header checksum.
///
/// A zero checksum field is accepted: over IPv4 it means the sender did not
/// compute one.
pub fn parse_checked_v4(
    packet: &[u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
) -> Result<UdpDatagram<'_>, PacketError> {
    let datagram = parse(packet)?;
    if datagram.checksum == 0 {
        return Ok(datagram);
    }
    let segment = &packet[..usize::from(datagram.length)];
    if !checksum::verify_v4(PROTOCOL, src, dst, segment) {
        return Err(PacketError::BadChecksum);
    }
    Ok(datagram)
}

/// Parse a UDP datagram and verify its IPv6 pseudo-header checksum.
///
/// A zero checksum is rejected: over IPv6 UDP it is illegal.
pub fn parse_checked_v6(
    packet: &[u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
) -> Result<UdpDatagram<'_>, PacketError> {
    let datagram = parse(packet)?;
    if datagram.checksum == 0 {
        return Err(PacketError::BadChecksum);
    }
    let segment = &packet[..usize::from(datagram.length)];
    if !checksum::verify_v6(PROTOCOL, src, dst, segment) {
        return Err(PacketError::BadChecksum);
    }
    Ok(datagram)
}

/// Write a UDP datagram for IPv4, returning its length.
///
/// `checksum_enabled = false` stores a zero checksum field (legal over IPv4).
/// When the checksum *is* computed and the result happens to be zero, the wire
/// field is written as `0xFFFF`: a zero field means "not computed" over IPv4,
/// so transmitting a literal zero would make a verified datagram look
/// unchecked (RFC 768).
pub fn write_v4(
    out: &mut [u8],
    src_port: u16,
    dst_port: u16,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    payload: &[u8],
    checksum_enabled: bool,
) -> Result<usize, PacketError> {
    let total = HEADER_LEN + payload.len();
    if out.len() < total {
        return Err(PacketError::Truncated);
    }
    if total > 65_535 {
        return Err(PacketError::OutOfRange);
    }
    write_header(out, src_port, dst_port, total)?;
    out[HEADER_LEN..total].copy_from_slice(payload);
    if checksum_enabled {
        let mut field = checksum::checksum_v4(PROTOCOL, src, dst, &out[..total]);
        if field == 0 {
            // See the doc comment: over IPv4 a zero field means "not computed".
            field = 0xFFFF;
        }
        out[6..8].copy_from_slice(&field.to_be_bytes());
    }
    Ok(total)
}

/// Write a UDP datagram for IPv6, returning its length.
///
/// The checksum is mandatory; if the computed field would be zero it is stored
/// as `0xFFFF`, as the protocol requires.
pub fn write_v6(
    out: &mut [u8],
    src_port: u16,
    dst_port: u16,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    payload: &[u8],
) -> Result<usize, PacketError> {
    let total = HEADER_LEN + payload.len();
    if out.len() < total {
        return Err(PacketError::Truncated);
    }
    if total > 65_535 {
        return Err(PacketError::OutOfRange);
    }
    write_header(out, src_port, dst_port, total)?;
    out[HEADER_LEN..total].copy_from_slice(payload);
    let mut field = checksum::checksum_v6(PROTOCOL, src, dst, &out[..total]);
    if field == 0 {
        field = 0xFFFF;
    }
    out[6..8].copy_from_slice(&field.to_be_bytes());
    Ok(total)
}

fn write_header(
    out: &mut [u8],
    src_port: u16,
    dst_port: u16,
    total: usize,
) -> Result<(), PacketError> {
    if out.len() < HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    out[0..2].copy_from_slice(&src_port.to_be_bytes());
    out[2..4].copy_from_slice(&dst_port.to_be_bytes());
    out[4..6].copy_from_slice(&(total as u16).to_be_bytes());
    out[6..8].copy_from_slice(&[0, 0]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_round_trips_over_ipv4() {
        let mut buffer = [0u8; 64];
        let payload = [1u8, 2, 3, 4, 5, 6, 7];
        let written = write_v4(
            &mut buffer,
            0xD431,
            0x0035,
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(10, 0, 2, 2),
            &payload,
            true,
        )
        .unwrap();
        assert_eq!(written, HEADER_LEN + payload.len());
        let datagram = parse_checked_v4(
            &buffer[..written],
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(10, 0, 2, 2),
        )
        .unwrap();
        assert_eq!(datagram.src_port, 0xD431);
        assert_eq!(datagram.dst_port, 0x0035);
        assert_eq!(datagram.length as usize, written);
        assert_eq!(datagram.payload, &payload[..]);
        // The sum of the address words is order independent, so a different
        // address (not a swap) is what must break the checksum.
        assert_eq!(
            parse_checked_v4(
                &buffer[..written],
                Ipv4Addr::new(10, 0, 2, 3),
                Ipv4Addr::new(10, 0, 2, 2)
            ),
            Err(PacketError::BadChecksum)
        );
        // A corrupted payload must be rejected even with the right pseudo
        // header, so the check really covers the checksum field.
        let mut broken = buffer;
        broken[written - 1] ^= 0x01;
        assert_eq!(
            parse_checked_v4(
                &broken[..written],
                Ipv4Addr::new(10, 0, 2, 15),
                Ipv4Addr::new(10, 0, 2, 2)
            ),
            Err(PacketError::BadChecksum)
        );
    }

    #[test]
    fn ipv4_allows_a_zero_checksum_but_ipv6_does_not() {
        let mut buffer = [0u8; 32];
        let written = write_v4(
            &mut buffer,
            1,
            2,
            Ipv4Addr::LOOPBACK,
            Ipv4Addr::LOOPBACK,
            &[0xAA; 4],
            false,
        )
        .unwrap();
        assert_eq!(&buffer[6..8], &[0, 0]);
        assert!(
            parse_checked_v4(&buffer[..written], Ipv4Addr::LOOPBACK, Ipv4Addr::LOOPBACK).is_ok()
        );

        let mut buffer = [0u8; 32];
        let written = write_v6(
            &mut buffer,
            1,
            2,
            Ipv6Addr::LOOPBACK,
            Ipv6Addr::LOOPBACK,
            &[0xAA; 4],
        )
        .unwrap();
        assert_ne!(&buffer[6..8], &[0, 0]);
        assert!(
            parse_checked_v6(&buffer[..written], Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK).is_ok()
        );
        // A zero field over IPv6 is illegal even if the rest is well formed.
        let mut zeroed = buffer;
        zeroed[6..8].copy_from_slice(&[0, 0]);
        assert_eq!(
            parse_checked_v6(&zeroed[..written], Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK),
            Err(PacketError::BadChecksum)
        );
    }

    #[test]
    fn length_field_is_validated_and_padding_ignored() {
        let mut buffer = [0u8; 64];
        let written = write_v4(
            &mut buffer,
            1,
            2,
            Ipv4Addr::LOOPBACK,
            Ipv4Addr::LOOPBACK,
            &[0u8; 4],
            true,
        )
        .unwrap();
        // Trailing Ethernet padding beyond the UDP length is not payload.
        let padded = &buffer[..written + 6];
        let datagram = parse(padded).unwrap();
        assert_eq!(datagram.payload.len(), 4);
        // A length below the header is rejected.
        let mut short = buffer;
        short[4..6].copy_from_slice(&7u16.to_be_bytes());
        assert_eq!(parse(&short[..written]), Err(PacketError::BadLength));
        // A length beyond the slice is rejected.
        short[4..6].copy_from_slice(&(written as u16 + 8).to_be_bytes());
        assert_eq!(parse(&short[..written]), Err(PacketError::Truncated));
        assert_eq!(parse(&[0u8; 7]), Err(PacketError::Truncated));
    }

    #[test]
    fn construction_rejects_short_buffers() {
        let mut short = [0u8; HEADER_LEN + 1];
        assert_eq!(
            write_v4(
                &mut short,
                1,
                2,
                Ipv4Addr::LOOPBACK,
                Ipv4Addr::LOOPBACK,
                &[0u8; 4],
                true
            ),
            Err(PacketError::Truncated)
        );
        assert_eq!(
            write_v6(
                &mut short,
                1,
                2,
                Ipv6Addr::LOOPBACK,
                Ipv6Addr::LOOPBACK,
                &[0u8; 4]
            ),
            Err(PacketError::Truncated)
        );
    }

    #[test]
    fn corrupted_payload_is_detected() {
        let mut buffer = [0u8; 64];
        let written = write_v6(
            &mut buffer,
            7,
            9,
            Ipv6Addr::LOOPBACK,
            Ipv6Addr::LOOPBACK,
            &[0x10, 0x20, 0x30],
        )
        .unwrap();
        buffer[written - 1] ^= 0xFF;
        assert_eq!(
            parse_checked_v6(&buffer[..written], Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK),
            Err(PacketError::BadChecksum)
        );
    }

    #[test]
    fn ipv4_zero_checksum_result_is_transmitted_as_0xffff() {
        let src = Ipv4Addr::new(192, 0, 2, 1);
        let dst = Ipv4Addr::new(192, 0, 2, 2);
        let mut wire = [0u8; 64];

        // Find a two-byte payload whose IPv4 pseudo-header checksum is zero.
        // Adding one 16-bit word shifts the folded sum one-to-one, so a
        // candidate always exists in the 65536 possible values.
        let mut zero_payload = [0u8; 2];
        let mut found = false;
        for value in 0u32..=0xFFFF {
            let candidate = [(value >> 8) as u8, (value & 0xFF) as u8];
            let total = write_v4(&mut wire, 7, 9, src, dst, &candidate, false).unwrap();
            if checksum::checksum_v4(PROTOCOL, src, dst, &wire[..total]) == 0 {
                zero_payload = candidate;
                found = true;
                break;
            }
        }
        assert!(found, "a zero-checksum payload must exist");

        // Unchecked IPv4 UDP stores a literal zero ("not computed").
        write_v4(&mut wire, 7, 9, src, dst, &zero_payload, false).unwrap();
        assert_eq!(u16::from_be_bytes([wire[6], wire[7]]), 0);

        // A computed zero must be stored as 0xFFFF and still verify.
        let total = write_v4(&mut wire, 7, 9, src, dst, &zero_payload, true).unwrap();
        assert_eq!(
            u16::from_be_bytes([wire[6], wire[7]]),
            0xFFFF,
            "a computed zero checksum must never be written as 0"
        );
        assert!(parse_checked_v4(&wire[..total], src, dst).is_ok());

        // IPv6 contrast: the same payload stores a non-zero field (zero is
        // illegal there) and verifies through the v6 pseudo header.
        let mut wire6 = [0u8; 64];
        let total6 = write_v6(
            &mut wire6,
            7,
            9,
            Ipv6Addr::LOOPBACK,
            Ipv6Addr::LOOPBACK,
            &zero_payload,
        )
        .unwrap();
        assert_ne!(u16::from_be_bytes([wire6[6], wire6[7]]), 0);
        assert!(parse_checked_v6(&wire6[..total6], Ipv6Addr::LOOPBACK, Ipv6Addr::LOOPBACK).is_ok());
    }
}
