//! IPv4 header parsing and building (RFC 791).
//!
//! The parser is strictly structural: it validates the version, IHL, total
//! length and slice bounds, and exposes the header options as a borrowed slice.
//! Checksum validation is opt-in via [`parse_checked`] so a caller that only
//! needs to look at the header does not pay for it.
//!
//! Fragment reassembly is out of scope for M7a: a fragment is parsed as a
//! fragment (see [`Ipv4Header::is_fragmented`]) and its payload is the fragment
//! data only.

use crate::PacketError;
use crate::addr::Ipv4Addr;
use crate::checksum;

/// IPv4 version nibble.
pub const VERSION: u8 = 4;
/// Smallest legal header (no options).
pub const MIN_HEADER_LEN: usize = 20;
/// Largest legal header (IHL = 15).
pub const MAX_HEADER_LEN: usize = 60;
/// Protocol 1: ICMP.
pub const PROTOCOL_ICMP: u8 = 1;
/// Protocol 6: TCP.
pub const PROTOCOL_TCP: u8 = 6;
/// Protocol 17: UDP.
pub const PROTOCOL_UDP: u8 = 17;
/// Don't-fragment flag.
pub const FLAG_DF: u16 = 0x4000;
/// More-fragments flag.
pub const FLAG_MF: u16 = 0x2000;
/// Mask of the fragment offset (in 8-byte units).
pub const FRAGMENT_OFFSET_MASK: u16 = 0x1FFF;

/// A parsed IPv4 header plus borrowed options and payload views.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Header<'a> {
    /// Header length in 32-bit words (5..=15).
    pub ihl: u8,
    /// Differentiated services / ECN byte.
    pub dscp: u8,
    /// Value of the total-length field.
    pub total_len: u16,
    /// Datagram identification.
    pub identification: u16,
    /// Raw flags + fragment-offset field.
    pub flags_fragment: u16,
    /// Time to live.
    pub ttl: u8,
    /// Upper-layer protocol (`PROTOCOL_*`).
    pub protocol: u8,
    /// The header checksum field as it appeared on the wire.
    pub header_checksum: u16,
    /// Source address.
    pub src: Ipv4Addr,
    /// Destination address.
    pub dst: Ipv4Addr,
    /// Header options (`IHL * 4 - 20` bytes, possibly empty).
    pub options: &'a [u8],
    /// The datagram payload (`total_len - IHL * 4` bytes).
    pub payload: &'a [u8],
}

impl<'a> Ipv4Header<'a> {
    /// Length of the header in bytes.
    pub const fn header_len(&self) -> usize {
        self.ihl as usize * 4
    }

    /// Whether any flag/offset field marks this as a fragment.
    pub const fn is_fragmented(&self) -> bool {
        self.more_fragments() || self.fragment_offset() != 0
    }

    /// The more-fragments flag.
    pub const fn more_fragments(&self) -> bool {
        self.flags_fragment & FLAG_MF != 0
    }

    /// Whether the don't-fragment flag is set.
    pub const fn dont_fragment(&self) -> bool {
        self.flags_fragment & FLAG_DF != 0
    }

    /// Fragment offset in 8-byte units.
    pub const fn fragment_offset(&self) -> u16 {
        self.flags_fragment & FRAGMENT_OFFSET_MASK
    }
}

/// Parse an IPv4 header without verifying its checksum.
pub fn parse(packet: &[u8]) -> Result<Ipv4Header<'_>, PacketError> {
    if packet.len() < MIN_HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    if packet[0] >> 4 != VERSION {
        return Err(PacketError::BadVersion);
    }
    let ihl = packet[0] & 0x0F;
    if ihl < 5 {
        return Err(PacketError::BadHeaderLength);
    }
    let header_len = ihl as usize * 4;
    if header_len > packet.len() {
        return Err(PacketError::Truncated);
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]);
    if usize::from(total_len) < header_len {
        return Err(PacketError::BadLength);
    }
    if usize::from(total_len) > packet.len() {
        return Err(PacketError::Truncated);
    }
    Ok(Ipv4Header {
        ihl,
        dscp: packet[1],
        total_len,
        identification: u16::from_be_bytes([packet[4], packet[5]]),
        flags_fragment: u16::from_be_bytes([packet[6], packet[7]]),
        ttl: packet[8],
        protocol: packet[9],
        header_checksum: u16::from_be_bytes([packet[10], packet[11]]),
        src: Ipv4Addr([packet[12], packet[13], packet[14], packet[15]]),
        dst: Ipv4Addr([packet[16], packet[17], packet[18], packet[19]]),
        options: &packet[MIN_HEADER_LEN..header_len],
        payload: &packet[header_len..usize::from(total_len)],
    })
}

/// Parse an IPv4 header and verify its header checksum.
pub fn parse_checked(packet: &[u8]) -> Result<Ipv4Header<'_>, PacketError> {
    let header = parse(packet)?;
    if !checksum::verify(&packet[..header.header_len()]) {
        return Err(PacketError::BadChecksum);
    }
    Ok(header)
}

/// The header checksum for a 20-byte IPv4 header (no options).
pub fn header_checksum(header: &[u8; MIN_HEADER_LEN]) -> u16 {
    checksum::checksum(header)
}

/// Write a 20-byte IPv4 header (no options) into `out` and compute its checksum.
///
/// `payload_len` is the number of upper-layer bytes that follow; the caller must
/// write exactly that many bytes after the returned header length.
pub fn write_header(
    out: &mut [u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    ttl: u8,
    dscp: u8,
    identification: u16,
    flags_fragment: u16,
    payload_len: usize,
) -> Result<usize, PacketError> {
    if out.len() < MIN_HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    if payload_len > usize::from(u16::MAX) - MIN_HEADER_LEN {
        return Err(PacketError::OutOfRange);
    }
    let total_len = (MIN_HEADER_LEN + payload_len) as u16;
    out[0] = (VERSION << 4) | 5; // IHL = 5, no options
    out[1] = dscp;
    out[2..4].copy_from_slice(&total_len.to_be_bytes());
    out[4..6].copy_from_slice(&identification.to_be_bytes());
    out[6..8].copy_from_slice(&flags_fragment.to_be_bytes());
    out[8] = ttl;
    out[9] = protocol;
    out[10] = 0;
    out[11] = 0;
    out[12..16].copy_from_slice(&src.0);
    out[16..20].copy_from_slice(&dst.0);
    let field = checksum::checksum(&out[..MIN_HEADER_LEN]);
    out[10..12].copy_from_slice(&field.to_be_bytes());
    Ok(MIN_HEADER_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
    const DST: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);

    fn build(payload: &[u8]) -> [u8; 64] {
        let mut buffer = [0u8; 64];
        let written = write_header(
            &mut buffer,
            SRC,
            DST,
            PROTOCOL_UDP,
            64,
            0,
            0x1234,
            0,
            payload.len(),
        )
        .unwrap();
        buffer[written..written + payload.len()].copy_from_slice(payload);
        buffer
    }

    #[test]
    fn header_round_trips_and_payload_is_borrowed() {
        let payload = [0xABu8; 8];
        let datagram = build(&payload);
        let header = parse_checked(&datagram[..20 + payload.len()]).unwrap();
        assert_eq!(header.ihl, 5);
        assert_eq!(header.header_len(), 20);
        assert_eq!(header.total_len, 28);
        assert_eq!(header.protocol, PROTOCOL_UDP);
        assert_eq!(header.ttl, 64);
        assert_eq!(header.identification, 0x1234);
        assert_eq!(header.src, SRC);
        assert_eq!(header.dst, DST);
        assert!(header.options.is_empty());
        assert_eq!(header.payload, &payload[..]);
        assert!(!header.is_fragmented());
        assert!(!header.dont_fragment());
    }

    #[test]
    fn version_and_ihl_are_validated() {
        let mut datagram = build(&[]);
        datagram[0] = 0x60; // version 6
        assert_eq!(parse(&datagram[..20]), Err(PacketError::BadVersion));
        let mut datagram = build(&[]);
        datagram[0] = 0x44; // IHL 4
        assert_eq!(parse(&datagram[..20]), Err(PacketError::BadHeaderLength));
        let mut datagram = build(&[]);
        datagram[0] = 0x4F; // IHL 15, header 60 > slice
        assert_eq!(parse(&datagram[..20]), Err(PacketError::Truncated));
    }

    #[test]
    fn total_length_must_cover_header_and_slice() {
        let mut datagram = build(&[0u8; 4]);
        datagram[2..4].copy_from_slice(&19u16.to_be_bytes()); // < 20
        assert_eq!(parse(&datagram[..24]), Err(PacketError::BadLength));
        let mut datagram = build(&[0u8; 4]);
        datagram[2..4].copy_from_slice(&25u16.to_be_bytes()); // > slice
        assert_eq!(parse(&datagram[..24]), Err(PacketError::Truncated));
        let mut datagram = build(&[0u8; 4]);
        datagram[2..4].copy_from_slice(&24u16.to_be_bytes());
        // Trailing bytes beyond total_len are padding, not payload.
        let header = parse(&datagram[..24]).unwrap();
        assert_eq!(header.payload.len(), 4);
        let padded = parse(&datagram[..32]).unwrap();
        assert_eq!(padded.payload.len(), 4);
    }

    #[test]
    fn checksum_is_opt_in() {
        let payload = [0u8; 8];
        let mut datagram = build(&payload);
        assert!(parse_checked(&datagram[..28]).is_ok());
        datagram[10] ^= 0xFF;
        assert!(parse(&datagram[..28]).is_ok());
        assert_eq!(
            parse_checked(&datagram[..28]),
            Err(PacketError::BadChecksum)
        );
    }

    #[test]
    fn options_are_borrowed_and_ihl_honoured() {
        // Craft a 24-byte header (IHL = 6) with four bytes of options.
        let mut datagram = build(&[]);
        datagram.copy_within(20..20, 24);
        datagram[0] = 0x46;
        datagram[20..24].copy_from_slice(&[1, 1, 1, 0]); // NOP NOP NOP END
        datagram[2..4].copy_from_slice(&24u16.to_be_bytes());
        datagram[10] = 0;
        datagram[11] = 0;
        let field = checksum::checksum(&datagram[..24]);
        datagram[10..12].copy_from_slice(&field.to_be_bytes());
        let header = parse_checked(&datagram[..24]).unwrap();
        assert_eq!(header.header_len(), 24);
        assert_eq!(header.options, &[1u8, 1, 1, 0]);
        assert!(header.payload.is_empty());
    }

    #[test]
    fn fragment_fields_are_exposed() {
        let mut datagram = build(&[0u8; 4]);
        datagram[6..8].copy_from_slice(&(FLAG_MF | 0x0001).to_be_bytes());
        let header = parse(&datagram[..24]).unwrap();
        assert!(header.is_fragmented());
        assert!(header.more_fragments());
        assert_eq!(header.fragment_offset(), 1);
    }

    #[test]
    fn write_rejects_an_oversized_payload() {
        let mut out = [0u8; 20];
        assert_eq!(
            write_header(&mut out, SRC, DST, PROTOCOL_UDP, 64, 0, 0, 0, 65_515),
            Ok(20)
        );
        assert_eq!(
            write_header(&mut out, SRC, DST, PROTOCOL_UDP, 64, 0, 0, 0, 65_516),
            Err(PacketError::OutOfRange)
        );
        let mut short = [0u8; 19];
        assert_eq!(
            write_header(&mut short, SRC, DST, PROTOCOL_UDP, 64, 0, 0, 0, 0),
            Err(PacketError::Truncated)
        );
    }
}
