//! IPv6 header parsing, building and bounded extension-header walking.
//!
//! IPv6 has no header checksum: integrity is the upper layer's job (UDP/TCP
//! pseudo header, ICMPv6 pseudo header). The interesting part here is the
//! extension-header chain, which a peer controls and which must therefore be
//! walked with a hard bound ([`crate::MAX_IPV6_EXT_HEADERS`]) and strict length
//! checks.
//!
//! Fragment reassembly is out of scope for M7a. [`upper_layer`] reports
//! `fragmented = true` for a fragment so the caller can drop it instead of
//! misparsing a partial upper-layer packet as a whole one.

use crate::addr::Ipv6Addr;
use crate::{MAX_IPV6_EXT_HEADERS, PacketError};

/// IPv6 version nibble.
pub const VERSION: u8 = 6;
/// Fixed IPv6 header length.
pub const HEADER_LEN: usize = 40;
/// Largest payload length field value.
pub const MAX_PAYLOAD_LEN: usize = 65_535;

/// Next-header value: hop-by-hop options.
pub const NEXT_HOP_BY_HOP: u8 = 0;
/// Next-header value: TCP.
pub const NEXT_TCP: u8 = 6;
/// Next-header value: UDP.
pub const NEXT_UDP: u8 = 17;
/// Next-header value: IPv6 routing header.
pub const NEXT_ROUTING: u8 = 43;
/// Next-header value: IPv6 fragment header.
pub const NEXT_FRAGMENT: u8 = 44;
/// Next-header value: ICMPv6.
pub const NEXT_ICMPV6: u8 = 58;
/// Next-header value: no next header.
pub const NEXT_NONE: u8 = 59;
/// Next-header value: destination options.
pub const NEXT_DEST_OPTS: u8 = 60;

/// A parsed fixed IPv6 header plus a borrowed payload view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Header<'a> {
    /// Traffic class (former TOS).
    pub traffic_class: u8,
    /// Flow label (20 bits).
    pub flow_label: u32,
    /// Value of the payload-length field.
    pub payload_len: u16,
    /// First next-header value.
    pub next_header: u8,
    /// Hop limit (former TTL).
    pub hop_limit: u8,
    /// Source address.
    pub src: Ipv6Addr,
    /// Destination address.
    pub dst: Ipv6Addr,
    /// The packet payload (`payload_len` bytes, exactly).
    pub payload: &'a [u8],
}

/// An upper-layer packet after walking the extension-header chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UpperLayer<'a> {
    /// Final next-header value (`NEXT_TCP`, `NEXT_UDP`, `NEXT_ICMPV6`, ...).
    pub protocol: u8,
    /// The upper-layer bytes (a fragment's data when `fragmented`).
    pub payload: &'a [u8],
    /// True when a fragmentation header was crossed with a non-zero offset or
    /// the more-fragments flag, i.e. this is not a complete upper-layer packet.
    pub fragmented: bool,
}

/// Parse the fixed 40-byte IPv6 header.
pub fn parse(packet: &[u8]) -> Result<Ipv6Header<'_>, PacketError> {
    if packet.len() < HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    if packet[0] >> 4 != VERSION {
        return Err(PacketError::BadVersion);
    }
    let payload_len = u16::from_be_bytes([packet[4], packet[5]]);
    let end = HEADER_LEN + usize::from(payload_len);
    if end > packet.len() {
        return Err(PacketError::Truncated);
    }
    let traffic_class = ((packet[0] & 0x0F) << 4) | (packet[1] >> 4);
    let flow_label =
        ((u32::from(packet[1]) & 0x0F) << 16) | (u32::from(packet[2]) << 8) | u32::from(packet[3]);
    Ok(Ipv6Header {
        traffic_class,
        flow_label,
        payload_len,
        next_header: packet[6],
        hop_limit: packet[7],
        src: Ipv6Addr::from_slice(&packet[8..24])?,
        dst: Ipv6Addr::from_slice(&packet[24..40])?,
        payload: &packet[HEADER_LEN..end],
    })
}

/// Walk the extension-header chain and return the upper-layer packet.
///
/// Hop-by-hop, routing and destination options headers are skipped by their
/// length field. A fragment header records `fragmented` and stops the walk (the
/// remaining bytes belong to the fragment, not necessarily to a whole
/// upper-layer packet). Anything else is treated as the upper-layer protocol.
pub fn upper_layer<'a>(header: &Ipv6Header<'a>) -> Result<UpperLayer<'a>, PacketError> {
    let mut protocol = header.next_header;
    let mut payload = header.payload;
    let mut walked = 0usize;
    loop {
        match protocol {
            NEXT_HOP_BY_HOP | NEXT_ROUTING | NEXT_DEST_OPTS => {
                walked += 1;
                if walked > MAX_IPV6_EXT_HEADERS {
                    return Err(PacketError::BadOptions);
                }
                if payload.len() < 2 {
                    return Err(PacketError::Truncated);
                }
                let next = payload[0];
                let extension_len = (usize::from(payload[1]) + 1) * 8;
                if payload.len() < extension_len {
                    return Err(PacketError::Truncated);
                }
                protocol = next;
                payload = &payload[extension_len..];
            }
            NEXT_FRAGMENT => {
                walked += 1;
                if walked > MAX_IPV6_EXT_HEADERS {
                    return Err(PacketError::BadOptions);
                }
                if payload.len() < 8 {
                    return Err(PacketError::Truncated);
                }
                let next = payload[0];
                let offset_flags = u16::from_be_bytes([payload[2], payload[3]]);
                let fragment_offset = (offset_flags & 0xFFF8) >> 3;
                let more_fragments = offset_flags & 0x0001 != 0;
                return Ok(UpperLayer {
                    protocol: next,
                    payload: &payload[8..],
                    fragmented: fragment_offset != 0 || more_fragments,
                });
            }
            _ => {
                return Ok(UpperLayer {
                    protocol,
                    payload,
                    fragmented: false,
                });
            }
        }
    }
}

/// Write a 40-byte IPv6 header into `out`; returns the header length.
///
/// `payload_len` must be at most [`MAX_PAYLOAD_LEN`]; the caller writes the
/// payload after the returned offset.
#[allow(clippy::too_many_arguments)]
pub fn write_header(
    out: &mut [u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_header: u8,
    hop_limit: u8,
    traffic_class: u8,
    flow_label: u32,
    payload_len: usize,
) -> Result<usize, PacketError> {
    if out.len() < HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(PacketError::OutOfRange);
    }
    out[0] = (VERSION << 4) | (traffic_class >> 4);
    out[1] = ((traffic_class & 0x0F) << 4) | ((flow_label >> 16) as u8 & 0x0F);
    out[2] = (flow_label >> 8) as u8;
    out[3] = flow_label as u8;
    out[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    out[6] = next_header;
    out[7] = hop_limit;
    out[8..24].copy_from_slice(&src.0);
    out[24..40].copy_from_slice(&dst.0);
    Ok(HEADER_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: Ipv6Addr = Ipv6Addr::LOOPBACK;
    const DST: Ipv6Addr = Ipv6Addr::LOOPBACK;

    fn build(payload: &[u8]) -> [u8; 96] {
        let mut buffer = [0u8; 96];
        let written = write_header(
            &mut buffer,
            SRC,
            DST,
            NEXT_UDP,
            64,
            0x28,
            0x81234,
            payload.len(),
        )
        .unwrap();
        buffer[written..written + payload.len()].copy_from_slice(payload);
        buffer
    }

    #[test]
    fn header_round_trips() {
        let payload = [0xCDu8; 12];
        let packet = build(&payload);
        let header = parse(&packet[..HEADER_LEN + payload.len()]).unwrap();
        assert_eq!(header.payload_len, 12);
        assert_eq!(header.next_header, NEXT_UDP);
        assert_eq!(header.hop_limit, 64);
        assert_eq!(header.traffic_class, 0x28);
        assert_eq!(header.flow_label, 0x81234);
        assert_eq!(header.src, SRC);
        assert_eq!(header.dst, DST);
        assert_eq!(header.payload, &payload[..]);
    }

    #[test]
    fn version_and_length_are_checked() {
        let mut packet = build(&[0u8; 4]);
        packet[0] = 0x40; // version 4
        assert_eq!(parse(&packet[..44]), Err(PacketError::BadVersion));
        let mut packet = build(&[0u8; 4]);
        packet[4..6].copy_from_slice(&8u16.to_be_bytes()); // more than present
        assert_eq!(parse(&packet[..44]), Err(PacketError::Truncated));
        assert_eq!(parse(&[0u8; 39]), Err(PacketError::Truncated));
    }

    #[test]
    fn extension_headers_are_walked() {
        let mut packet = [0u8; 80];
        // IPv6 header: next = hop-by-hop, payload 16.
        write_header(&mut packet, SRC, DST, NEXT_HOP_BY_HOP, 64, 0, 0, 16).unwrap();
        // Hop-by-hop: next = UDP, len = 0 (8 bytes total).
        packet[40] = NEXT_UDP;
        packet[41] = 0;
        let udp_offset = 48;
        packet[udp_offset..udp_offset + 8].copy_from_slice(&[0, 7, 0, 9, 0, 8, 0, 0]);
        let header = parse(&packet[..56]).unwrap();
        let upper = upper_layer(&header).unwrap();
        assert_eq!(upper.protocol, NEXT_UDP);
        assert!(!upper.fragmented);
        assert_eq!(upper.payload.len(), 8);
    }

    #[test]
    fn too_many_extension_headers_are_rejected() {
        // 10 chained 8-byte destination-options headers.
        let mut packet = [0u8; HEADER_LEN + 10 * 8];
        write_header(&mut packet, SRC, DST, NEXT_DEST_OPTS, 64, 0, 0, 10 * 8).unwrap();
        for index in 0..10 {
            let offset = HEADER_LEN + index * 8;
            packet[offset] = if index == 9 { NEXT_UDP } else { NEXT_DEST_OPTS };
            packet[offset + 1] = 0;
        }
        let header = parse(&packet).unwrap();
        assert_eq!(upper_layer(&header), Err(PacketError::BadOptions));
    }

    #[test]
    fn truncated_extension_header_is_rejected() {
        let mut packet = [0u8; HEADER_LEN + 4];
        write_header(&mut packet, SRC, DST, NEXT_DEST_OPTS, 64, 0, 0, 4).unwrap();
        packet[HEADER_LEN + 1] = 1; // claims 16 bytes, only 4 present
        let header = parse(&packet).unwrap();
        assert_eq!(upper_layer(&header), Err(PacketError::Truncated));
    }

    #[test]
    fn fragment_header_is_flagged() {
        let mut packet = [0u8; HEADER_LEN + 8 + 4];
        write_header(&mut packet, SRC, DST, NEXT_FRAGMENT, 64, 0, 0, 12).unwrap();
        packet[HEADER_LEN] = NEXT_UDP;
        // Offset 1 (8-byte units), no more-fragments.
        packet[HEADER_LEN + 2..HEADER_LEN + 4].copy_from_slice(&8u16.to_be_bytes());
        let header = parse(&packet).unwrap();
        let upper = upper_layer(&header).unwrap();
        assert_eq!(upper.protocol, NEXT_UDP);
        assert!(upper.fragmented);
        assert_eq!(upper.payload.len(), 4);

        // First fragment with M=1 also counts as fragmented.
        packet[HEADER_LEN + 2] = 0;
        packet[HEADER_LEN + 3] = 1;
        let header = parse(&packet).unwrap();
        assert!(upper_layer(&header).unwrap().fragmented);
    }

    #[test]
    fn write_rejects_oversized_payload_and_short_buffer() {
        let mut out = [0u8; HEADER_LEN];
        assert_eq!(
            write_header(&mut out, SRC, DST, NEXT_TCP, 64, 0, 0, MAX_PAYLOAD_LEN),
            Ok(HEADER_LEN)
        );
        assert_eq!(
            write_header(&mut out, SRC, DST, NEXT_TCP, 64, 0, 0, MAX_PAYLOAD_LEN + 1),
            Err(PacketError::OutOfRange)
        );
        let mut short = [0u8; HEADER_LEN - 1];
        assert_eq!(
            write_header(&mut short, SRC, DST, NEXT_TCP, 64, 0, 0, 0),
            Err(PacketError::Truncated)
        );
    }
}
