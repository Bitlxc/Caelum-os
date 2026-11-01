//! ICMPv6 (RFC 4443) plus the two neighbour-discovery messages a stack needs
//! to bring a link up: neighbour solicitation and advertisement (RFC 4861).
//!
//! ICMPv6 has no header checksum of its own; the checksum covers the IPv6
//! pseudo header, so the parsing functions that verify it take the IP addresses.

use crate::PacketError;
use crate::addr::Ipv6Addr;
use crate::checksum;
use crate::ipv6::NEXT_ICMPV6;

/// ICMPv6 fixed header length (type, code, checksum, four type-specific bytes).
pub const HEADER_LEN: usize = 8;
/// Neighbour solicitation/advertisement length before options (8 + 16 target).
pub const NEIGHBOUR_HEADER_LEN: usize = 24;

/// Type 1: destination unreachable.
pub const TYPE_DESTINATION_UNREACHABLE: u8 = 1;
/// Type 2: packet too big.
pub const TYPE_PACKET_TOO_BIG: u8 = 2;
/// Type 3: time exceeded.
pub const TYPE_TIME_EXCEEDED: u8 = 3;
/// Type 4: parameter problem.
pub const TYPE_PARAMETER_PROBLEM: u8 = 4;
/// Type 128: echo request.
pub const TYPE_ECHO_REQUEST: u8 = 128;
/// Type 129: echo reply.
pub const TYPE_ECHO_REPLY: u8 = 129;
/// Type 133: neighbour solicitation.
pub const TYPE_NEIGHBOUR_SOLICITATION: u8 = 133;
/// Type 134: neighbour advertisement.
pub const TYPE_NEIGHBOUR_ADVERTISEMENT: u8 = 134;

/// Neighbour advertisement flag: router.
pub const NA_FLAG_ROUTER: u8 = 0x80;
/// Neighbour advertisement flag: solicited.
pub const NA_FLAG_SOLICITED: u8 = 0x40;
/// Neighbour advertisement flag: override.
pub const NA_FLAG_OVERRIDE: u8 = 0x20;

/// Option type: source link-layer address.
pub const OPTION_SOURCE_LINK_LAYER: u8 = 1;
/// Option type: target link-layer address.
pub const OPTION_TARGET_LINK_LAYER: u8 = 2;
/// Option type: prefix information.
pub const OPTION_PREFIX_INFORMATION: u8 = 3;

/// A parsed ICMPv6 message: header plus borrowed type-specific words and body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Icmpv6Message<'a> {
    /// Message type.
    pub kind: u8,
    /// Message code.
    pub code: u8,
    /// The checksum field as it appeared on the wire.
    pub checksum: u16,
    /// The four type-specific bytes after the checksum.
    pub rest: &'a [u8],
    /// Everything after those four bytes.
    pub body: &'a [u8],
}

/// Parse an ICMPv6 message without verifying its checksum.
pub fn parse(packet: &[u8]) -> Result<Icmpv6Message<'_>, PacketError> {
    if packet.len() < HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    Ok(Icmpv6Message {
        kind: packet[0],
        code: packet[1],
        checksum: u16::from_be_bytes([packet[2], packet[3]]),
        rest: &packet[4..8],
        body: &packet[HEADER_LEN..],
    })
}

/// Parse and verify an ICMPv6 message against its IPv6 pseudo header.
pub fn parse_checked(
    packet: &[u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
) -> Result<Icmpv6Message<'_>, PacketError> {
    let message = parse(packet)?;
    if !checksum::verify_v6(NEXT_ICMPV6, src, dst, packet) {
        return Err(PacketError::BadChecksum);
    }
    Ok(message)
}

/// Compare the ICMPv6 `kind` against the types this parser verifies checksums
/// for (Echo only, RFC 4443: the pseudo-header layout is identical for all, but
/// only echo is round-tripped here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Echo<'a> {
    /// Echo identifier.
    pub identifier: u16,
    /// Echo sequence number.
    pub sequence: u16,
    /// Echo data.
    pub data: &'a [u8],
}

/// Interpret an echo request/reply.
pub fn echo<'a>(message: &Icmpv6Message<'a>) -> Result<Echo<'a>, PacketError> {
    match message.kind {
        TYPE_ECHO_REQUEST | TYPE_ECHO_REPLY => Ok(Echo {
            identifier: u16::from_be_bytes([message.rest[0], message.rest[1]]),
            sequence: u16::from_be_bytes([message.rest[2], message.rest[3]]),
            data: message.body,
        }),
        _ => Err(PacketError::Unsupported),
    }
}

/// An ICMPv6 error report (types 1..=4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorReport<'a> {
    /// Message type (1..=4).
    pub kind: u8,
    /// Message code.
    pub code: u8,
    /// The four type-specific bytes (unused, MTU, or pointer).
    pub rest: &'a [u8],
    /// The beginning of the packet that triggered the error.
    pub original: &'a [u8],
}

/// Interpret an ICMPv6 error report.
pub fn error_report<'a>(message: &Icmpv6Message<'a>) -> Result<ErrorReport<'a>, PacketError> {
    match message.kind {
        TYPE_DESTINATION_UNREACHABLE
        | TYPE_PACKET_TOO_BIG
        | TYPE_TIME_EXCEEDED
        | TYPE_PARAMETER_PROBLEM => Ok(ErrorReport {
            kind: message.kind,
            code: message.code,
            rest: message.rest,
            original: message.body,
        }),
        _ => Err(PacketError::Unsupported),
    }
}

/// A neighbour solicitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeighbourSolicitation<'a> {
    /// The address being resolved.
    pub target: Ipv6Addr,
    /// Option bytes following the target address.
    pub options: &'a [u8],
}

/// A neighbour advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeighbourAdvertisement<'a> {
    /// Raw flag byte (`NA_FLAG_*`).
    pub flags: u8,
    /// The address the advertisement is about.
    pub target: Ipv6Addr,
    /// Option bytes following the target address.
    pub options: &'a [u8],
}

/// Interpret a neighbour solicitation.
pub fn neighbour_solicitation<'a>(
    message: &Icmpv6Message<'a>,
) -> Result<NeighbourSolicitation<'a>, PacketError> {
    if message.kind != TYPE_NEIGHBOUR_SOLICITATION {
        return Err(PacketError::Unsupported);
    }
    if message.body.len() < 16 {
        return Err(PacketError::Truncated);
    }
    Ok(NeighbourSolicitation {
        target: Ipv6Addr::from_slice(&message.body[..16])?,
        options: &message.body[16..],
    })
}

/// Interpret a neighbour advertisement.
pub fn neighbour_advertisement<'a>(
    message: &Icmpv6Message<'a>,
) -> Result<NeighbourAdvertisement<'a>, PacketError> {
    if message.kind != TYPE_NEIGHBOUR_ADVERTISEMENT {
        return Err(PacketError::Unsupported);
    }
    if message.body.len() < 16 {
        return Err(PacketError::Truncated);
    }
    Ok(NeighbourAdvertisement {
        flags: message.rest[0],
        target: Ipv6Addr::from_slice(&message.body[..16])?,
        options: &message.body[16..],
    })
}

/// One neighbour-discovery option (`pad1` yields an empty payload).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NdpOption<'a> {
    /// Option type.
    pub kind: u8,
    /// Option payload (without the type/length bytes).
    pub data: &'a [u8],
}

/// Bounded iterator over neighbour-discovery options.
///
/// The chain is walkable only as far as [`crate::MAX_ICMPV6_OPTIONS`]; a chain
/// that is longer, truncated, or carries a non-`pad1` option with a length below
/// two yields an error once instead of looping.
#[derive(Debug, Clone)]
pub struct OptionIter<'a> {
    bytes: &'a [u8],
    offset: usize,
    count: usize,
    failed: bool,
}

/// Start walking an option chain.
pub fn options(bytes: &[u8]) -> OptionIter<'_> {
    OptionIter {
        bytes,
        offset: 0,
        count: 0,
        failed: false,
    }
}

impl<'a> Iterator for OptionIter<'a> {
    type Item = Result<NdpOption<'a>, PacketError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        if self.offset >= self.bytes.len() {
            return None;
        }
        self.count += 1;
        if self.count > crate::MAX_ICMPV6_OPTIONS {
            self.failed = true;
            return Some(Err(PacketError::BadOptions));
        }
        let kind = self.bytes[self.offset];
        if kind == 0 {
            // Pad1: no length field, one byte long.
            self.offset += 1;
            return Some(Ok(NdpOption {
                kind,
                data: &self.bytes[self.offset..self.offset],
            }));
        }
        if self.offset + 2 > self.bytes.len() {
            self.failed = true;
            return Some(Err(PacketError::Truncated));
        }
        let units = usize::from(self.bytes[self.offset + 1]);
        let length = units * 8;
        if length < 2 {
            self.failed = true;
            return Some(Err(PacketError::BadOptions));
        }
        let end = self.offset + length;
        if end > self.bytes.len() {
            self.failed = true;
            return Some(Err(PacketError::Truncated));
        }
        let data = &self.bytes[self.offset + 2..end];
        self.offset = end;
        Some(Ok(NdpOption { kind, data }))
    }
}

/// Write an echo request/reply and return the message length.
pub fn write_echo(
    out: &mut [u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    is_reply: bool,
    identifier: u16,
    sequence: u16,
    data: &[u8],
) -> Result<usize, PacketError> {
    let total = HEADER_LEN + data.len();
    if out.len() < total {
        return Err(PacketError::Truncated);
    }
    if total > 65_535 {
        return Err(PacketError::OutOfRange);
    }
    out[0] = if is_reply {
        TYPE_ECHO_REPLY
    } else {
        TYPE_ECHO_REQUEST
    };
    out[1] = 0;
    out[2..4].copy_from_slice(&[0, 0]);
    out[4..6].copy_from_slice(&identifier.to_be_bytes());
    out[6..8].copy_from_slice(&sequence.to_be_bytes());
    out[HEADER_LEN..total].copy_from_slice(data);
    let field = checksum::checksum_v6(NEXT_ICMPV6, src, dst, &out[..total]);
    out[2..4].copy_from_slice(&field.to_be_bytes());
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: Ipv6Addr = Ipv6Addr::LOOPBACK;
    const DST: Ipv6Addr = Ipv6Addr::LOOPBACK;

    fn solicitation(target: Ipv6Addr, options: &[u8]) -> [u8; 64] {
        let mut buffer = [0u8; 64];
        buffer[0] = TYPE_NEIGHBOUR_SOLICITATION;
        buffer[4..8].copy_from_slice(&[0, 0, 0, 0]);
        buffer[8..24].copy_from_slice(&target.0);
        buffer[24..24 + options.len()].copy_from_slice(options);
        let total = NEIGHBOUR_HEADER_LEN + options.len();
        let field = checksum::checksum_v6(NEXT_ICMPV6, SRC, DST, &buffer[..total]);
        buffer[2..4].copy_from_slice(&field.to_be_bytes());
        buffer
    }

    #[test]
    fn echo_round_trips_with_pseudo_header_checksum() {
        let mut buffer = [0u8; 32];
        let data = [9u8, 8, 7, 6];
        // Two distinct addresses: swapping equal addresses would leave the
        // pseudo-header sum unchanged and the checksum would still verify.
        let src = Ipv6Addr::LOOPBACK;
        let dst =
            Ipv6Addr::from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).unwrap();
        let written = write_echo(&mut buffer, src, dst, false, 0x4321, 5, &data).unwrap();
        let message = parse_checked(&buffer[..written], src, dst).unwrap();
        assert_eq!(message.kind, TYPE_ECHO_REQUEST);
        let echo = echo(&message).unwrap();
        assert_eq!(echo.identifier, 0x4321);
        assert_eq!(echo.sequence, 5);
        assert_eq!(echo.data, &data[..]);
        // A different pseudo header does not verify (the address words are
        // summed, so a swap alone would leave the checksum intact).
        let other =
            Ipv6Addr::from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]).unwrap();
        assert_eq!(
            parse_checked(&buffer[..written], other, dst),
            Err(PacketError::BadChecksum)
        );
        // A corrupted payload must be rejected with the right pseudo header too.
        let mut broken = buffer;
        broken[written - 1] ^= 0x01;
        assert_eq!(
            parse_checked(&broken[..written], src, dst),
            Err(PacketError::BadChecksum)
        );
    }

    #[test]
    fn solicitations_expose_target_and_options() {
        let target: Ipv6Addr =
            Ipv6Addr::from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).unwrap();
        // Source link-layer address option: type 1, len 1 unit, 6 bytes MAC.
        let options = [1u8, 1, 0x52, 0x54, 0, 0x12, 0x34, 0x56];
        let packet = solicitation(target, &options);
        let message = parse_checked(&packet[..24 + options.len()], SRC, DST).unwrap();
        let ns = neighbour_solicitation(&message).unwrap();
        assert_eq!(ns.target, target);
        let mut iter = options_iter(&ns.options);
        let option = iter.next().unwrap().unwrap();
        assert_eq!(option.kind, OPTION_SOURCE_LINK_LAYER);
        assert_eq!(option.data, &options[2..]);

        // Advertisements reuse the layout but carry flags in rest[0].
        let mut advertisement = packet;
        advertisement[0] = TYPE_NEIGHBOUR_ADVERTISEMENT;
        advertisement[4] = NA_FLAG_SOLICITED | NA_FLAG_OVERRIDE;
        let total = 24 + options.len();
        // Zero the field first: `checksum_v6` expects a zeroed checksum field.
        advertisement[2..4].copy_from_slice(&[0, 0]);
        let field = checksum::checksum_v6(NEXT_ICMPV6, SRC, DST, &advertisement[..total]);
        advertisement[2..4].copy_from_slice(&field.to_be_bytes());
        let message = parse_checked(&advertisement[..total], SRC, DST).unwrap();
        let na = neighbour_advertisement(&message).unwrap();
        assert_eq!(na.flags & NA_FLAG_SOLICITED, NA_FLAG_SOLICITED);
        assert_eq!(na.target, target);
    }

    fn options_iter(bytes: &[u8]) -> OptionIter<'_> {
        options(bytes)
    }

    #[test]
    fn option_chain_is_bounded_and_validated() {
        // pad1 + a well-formed option.
        let chain = [0u8, 2, 1, 0x52, 0x54, 0, 0x12, 0x34, 0x56];
        let first = options(&chain).next().unwrap().unwrap();
        assert_eq!(first.kind, 0);
        assert!(first.data.is_empty());
        let mut iter = options(&chain);
        iter.next();
        let second = iter.next().unwrap().unwrap();
        assert_eq!(second.kind, OPTION_TARGET_LINK_LAYER);
        // Zero length for a non-pad1 option is invalid.
        let mut iter = options(&[2u8, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(iter.next(), Some(Err(PacketError::BadOptions)));
        // Truncated option body.
        let mut iter = options(&[2u8, 1, 0x52]);
        assert_eq!(iter.next(), Some(Err(PacketError::Truncated)));
        // Too many options in the chain.
        let chain = [1u8; 9 * 8];
        let mut iter = options(&chain);
        let mut seen = 0;
        let mut error = None;
        for item in &mut iter {
            seen += 1;
            if let Err(err) = item {
                error = Some(err);
            }
        }
        assert_eq!(seen, crate::MAX_ICMPV6_OPTIONS + 1);
        assert_eq!(error, Some(PacketError::BadOptions));
    }

    #[test]
    fn error_reports_and_unsupported_types() {
        let mut packet = [0u8; 12];
        packet[0] = TYPE_DESTINATION_UNREACHABLE;
        packet[1] = 3; // address unreachable
        let field = checksum::checksum_v6(NEXT_ICMPV6, SRC, DST, &packet);
        packet[2..4].copy_from_slice(&field.to_be_bytes());
        let message = parse_checked(&packet, SRC, DST).unwrap();
        let report = error_report(&message).unwrap();
        assert_eq!(report.kind, TYPE_DESTINATION_UNREACHABLE);
        assert_eq!(report.code, 3);
        // Echoing an error is unsupported; a neighbour message is too short.
        assert_eq!(echo(&message), Err(PacketError::Unsupported));
        assert_eq!(
            neighbour_solicitation(&message),
            Err(PacketError::Unsupported)
        );
        let mut short = [0u8; HEADER_LEN];
        short[0] = TYPE_NEIGHBOUR_SOLICITATION;
        let field = checksum::checksum_v6(NEXT_ICMPV6, SRC, DST, &short);
        short[2..4].copy_from_slice(&field.to_be_bytes());
        let message = parse_checked(&short, SRC, DST).unwrap();
        assert_eq!(
            neighbour_solicitation(&message),
            Err(PacketError::Truncated)
        );
    }

    #[test]
    fn short_and_bad_checksum_are_rejected() {
        assert_eq!(parse(&[0u8; 7]), Err(PacketError::Truncated));
        let mut buffer = [0u8; 16];
        let written = write_echo(&mut buffer, SRC, DST, false, 1, 1, &[0x11, 0x22]).unwrap();
        let mut broken = buffer;
        broken[written - 1] ^= 0x80;
        assert_eq!(
            parse_checked(&broken[..written], SRC, DST),
            Err(PacketError::BadChecksum)
        );
        assert!(parse(&broken[..written]).is_ok());
    }

    #[test]
    fn write_rejects_short_buffers() {
        let mut short = [0u8; 9];
        assert_eq!(
            write_echo(&mut short, SRC, DST, false, 1, 1, &[0u8; 2]),
            Err(PacketError::Truncated)
        );
    }
}
