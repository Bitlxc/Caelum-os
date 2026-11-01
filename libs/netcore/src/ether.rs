//! Ethernet II frame header (the only link format M7 uses).
//!
//! The frame checksum (FCS) is not part of the slice: devices deliver frames
//! without it, and padding to the 60-byte minimum is the sender's job.

use crate::PacketError;
use crate::addr::MacAddr;

/// Octets in an Ethernet II header (destination, source, ethertype).
pub const HEADER_LEN: usize = 14;

/// Smallest frame a sender must put on the wire (header + payload + padding).
pub const MIN_FRAME_LEN: usize = 60;

/// Ethertype of an IPv4 payload.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// Ethertype of an ARP payload.
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// Ethertype of an IPv6 payload.
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

/// A parsed Ethernet II header plus a borrowed view of its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthernetFrame<'a> {
    /// Destination MAC.
    pub dst: MacAddr,
    /// Source MAC.
    pub src: MacAddr,
    /// Ethertype (0x0800 IPv4, 0x0806 ARP, 0x86DD IPv6, ...).
    pub ethertype: u16,
    /// Everything after the 14-byte header (payload plus any padding).
    pub payload: &'a [u8],
}

/// Parse the 14-byte header of `frame`.
///
/// Only the header is interpreted: the payload is returned whole, because a
/// minimum-size frame carries padding that the upper layer must ignore using
/// its own length field.
pub fn parse(frame: &[u8]) -> Result<EthernetFrame<'_>, PacketError> {
    if frame.len() < HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    let mut dst = [0u8; 6];
    dst.copy_from_slice(&frame[..6]);
    let mut src = [0u8; 6];
    src.copy_from_slice(&frame[6..12]);
    Ok(EthernetFrame {
        dst: MacAddr(dst),
        src: MacAddr(src),
        ethertype: u16::from_be_bytes([frame[12], frame[13]]),
        payload: &frame[HEADER_LEN..],
    })
}

/// Write a 14-byte header into `out`; returns the header length.
pub fn write_header(
    out: &mut [u8],
    dst: &MacAddr,
    src: &MacAddr,
    ethertype: u16,
) -> Result<usize, PacketError> {
    if out.len() < HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    out[..6].copy_from_slice(&dst.0);
    out[6..12].copy_from_slice(&src.0);
    out[12..14].copy_from_slice(&ethertype.to_be_bytes());
    Ok(HEADER_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_frame() -> [u8; 20] {
        let mut frame = [0u8; 20];
        frame[..6].copy_from_slice(&MacAddr::BROADCAST.0);
        frame[6..12].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        frame[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
        for (index, byte) in frame[14..].iter_mut().enumerate() {
            *byte = index as u8;
        }
        frame
    }

    #[test]
    fn header_round_trips_and_payload_is_borrowed() {
        let frame = sample_frame();
        let parsed = parse(&frame).unwrap();
        assert!(parsed.dst.is_broadcast());
        assert_eq!(parsed.src, MacAddr::new([0x52, 0x54, 0, 0x12, 0x34, 0x56]));
        assert_eq!(parsed.ethertype, ETHERTYPE_ARP);
        assert_eq!(parsed.payload, &frame[14..]);

        let mut out = [0u8; HEADER_LEN];
        assert_eq!(
            write_header(&mut out, &parsed.dst, &parsed.src, parsed.ethertype),
            Ok(HEADER_LEN)
        );
        assert_eq!(&out[..], &frame[..HEADER_LEN]);
    }

    #[test]
    fn short_frames_are_rejected() {
        assert_eq!(parse(&[0u8; 13]), Err(PacketError::Truncated));
        assert_eq!(parse(&[]), Err(PacketError::Truncated));
        let mut short = [0u8; 10];
        assert_eq!(
            write_header(&mut short, &MacAddr::BROADCAST, &MacAddr::BROADCAST, 0x0800),
            Err(PacketError::Truncated)
        );
    }

    #[test]
    fn known_ethertypes_decode() {
        for (ethertype, expected) in [
            (0x0800u16, ETHERTYPE_IPV4),
            (0x0806, ETHERTYPE_ARP),
            (0x86DD, ETHERTYPE_IPV6),
        ] {
            assert_eq!(ethertype, expected);
        }
    }

    #[test]
    fn header_only_frame_has_an_empty_payload() {
        let mut frame = [0u8; HEADER_LEN];
        frame[12..].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let parsed = parse(&frame).unwrap();
        assert!(parsed.payload.is_empty());
    }
}
