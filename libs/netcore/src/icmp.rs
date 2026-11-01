//! ICMP for IPv4 (RFC 792): echo, destination unreachable, time exceeded.
//!
//! Only the messages a small stack needs are decoded structurally; everything
//! else is exposed as a borrowed `kind/code/checksum/rest/body` view so a caller
//! can inspect it without netcore pretending to understand every ICMP subtype.

use crate::PacketError;
use crate::checksum;

/// ICMP header length before the type-specific words.
pub const HEADER_LEN: usize = 8;
/// ICMP type: echo reply.
pub const TYPE_ECHO_REPLY: u8 = 0;
/// ICMP type: destination unreachable.
pub const TYPE_DESTINATION_UNREACHABLE: u8 = 3;
/// ICMP type: echo request.
pub const TYPE_ECHO_REQUEST: u8 = 8;
/// ICMP type: time exceeded.
pub const TYPE_TIME_EXCEEDED: u8 = 11;

/// Code 3/0: network unreachable.
pub const CODE_NETWORK_UNREACHABLE: u8 = 0;
/// Code 3/1: host unreachable.
pub const CODE_HOST_UNREACHABLE: u8 = 1;
/// Code 3/2: protocol unreachable.
pub const CODE_PROTOCOL_UNREACHABLE: u8 = 2;
/// Code 3/3: port unreachable.
pub const CODE_PORT_UNREACHABLE: u8 = 3;
/// Code 3/4: fragmentation needed, DF set.
pub const CODE_FRAGMENTATION_NEEDED: u8 = 4;

/// A parsed ICMP message: the fixed header plus borrowed type-specific words and
/// body. The four bytes after the checksum are type specific ("rest") and are
/// kept verbatim so echo and error messages share one parse path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpMessage<'a> {
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

/// Parse an ICMP message without verifying its checksum.
pub fn parse(packet: &[u8]) -> Result<IcmpMessage<'_>, PacketError> {
    if packet.len() < HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    Ok(IcmpMessage {
        kind: packet[0],
        code: packet[1],
        checksum: u16::from_be_bytes([packet[2], packet[3]]),
        rest: &packet[4..8],
        body: &packet[HEADER_LEN..],
    })
}

/// Parse an ICMP message and verify its checksum (ICMPv4 checksums the whole
/// message, header included, with no pseudo header).
pub fn parse_checked(packet: &[u8]) -> Result<IcmpMessage<'_>, PacketError> {
    let message = parse(packet)?;
    if !checksum::verify(packet) {
        return Err(PacketError::BadChecksum);
    }
    Ok(message)
}

/// An echo request or reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Echo<'a> {
    /// Echo identifier.
    pub identifier: u16,
    /// Echo sequence number.
    pub sequence: u16,
    /// Echo data.
    pub data: &'a [u8],
}

/// Interpret an echo message (`TYPE_ECHO_REQUEST`/`TYPE_ECHO_REPLY`).
pub fn echo<'a>(message: &IcmpMessage<'a>) -> Result<Echo<'a>, PacketError> {
    match message.kind {
        TYPE_ECHO_REQUEST | TYPE_ECHO_REPLY => Ok(Echo {
            identifier: u16::from_be_bytes([message.rest[0], message.rest[1]]),
            sequence: u16::from_be_bytes([message.rest[2], message.rest[3]]),
            data: message.body,
        }),
        _ => Err(PacketError::Unsupported),
    }
}

/// An ICMP error report (destination unreachable or time exceeded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorReport<'a> {
    /// Message type (3 or 11).
    pub kind: u8,
    /// Message code.
    pub code: u8,
    /// The four type-specific bytes (unused, or MTU for code 4).
    pub rest: &'a [u8],
    /// The beginning of the packet that triggered the error (typically the IP
    /// header plus eight payload bytes).
    pub original: &'a [u8],
}

/// Interpret a destination-unreachable or time-exceeded message.
pub fn error_report<'a>(message: &IcmpMessage<'a>) -> Result<ErrorReport<'a>, PacketError> {
    match message.kind {
        TYPE_DESTINATION_UNREACHABLE | TYPE_TIME_EXCEEDED => Ok(ErrorReport {
            kind: message.kind,
            code: message.code,
            rest: message.rest,
            original: message.body,
        }),
        _ => Err(PacketError::Unsupported),
    }
}

/// Write an echo request or reply with `data`, returning the message length.
///
/// The complete message is `8 + data.len()` bytes and its checksum is computed
/// over exactly that range.
pub fn write_echo(
    out: &mut [u8],
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
    let field = checksum::checksum(&out[..total]);
    out[2..4].copy_from_slice(&field.to_be_bytes());
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_round_trips() {
        let mut buffer = [0u8; 32];
        let data = [1u8, 2, 3, 4, 5];
        let written = write_echo(&mut buffer, false, 0x1234, 7, &data).unwrap();
        assert_eq!(written, 13);
        let message = parse_checked(&buffer[..written]).unwrap();
        assert_eq!(message.kind, TYPE_ECHO_REQUEST);
        let parsed = echo(&message).unwrap();
        assert_eq!(parsed.identifier, 0x1234);
        assert_eq!(parsed.sequence, 7);
        assert_eq!(parsed.data, &data[..]);

        let written = write_echo(&mut buffer, true, 0x1234, 7, &data).unwrap();
        let message = parse_checked(&buffer[..written]).unwrap();
        assert_eq!(message.kind, TYPE_ECHO_REPLY);
        assert_eq!(echo(&message).unwrap().identifier, 0x1234);
    }

    #[test]
    fn truncated_and_bad_checksum_are_rejected() {
        assert_eq!(parse(&[0u8; 7]), Err(PacketError::Truncated));
        let mut buffer = [0u8; 16];
        let written = write_echo(&mut buffer, false, 1, 1, &[0xAA, 0xBB]).unwrap();
        let mut broken = buffer;
        broken[written - 1] ^= 0xFF;
        assert_eq!(
            parse_checked(&broken[..written]),
            Err(PacketError::BadChecksum)
        );
        assert!(parse(&broken[..written]).is_ok());
    }

    #[test]
    fn error_reports_are_borrowed() {
        // Destination unreachable, port unreachable, with an embedded packet.
        let mut packet = [0u8; 28];
        packet[0] = TYPE_DESTINATION_UNREACHABLE;
        packet[1] = CODE_PORT_UNREACHABLE;
        packet[4..8].copy_from_slice(&[0, 0, 0, 0]);
        packet[8..12].copy_from_slice(&[0x45, 0, 0, 20]);
        let field = checksum::checksum(&packet);
        packet[2..4].copy_from_slice(&field.to_be_bytes());
        let message = parse_checked(&packet).unwrap();
        let report = error_report(&message).unwrap();
        assert_eq!(report.kind, TYPE_DESTINATION_UNREACHABLE);
        assert_eq!(report.code, CODE_PORT_UNREACHABLE);
        assert_eq!(report.rest, &[0u8, 0, 0, 0]);
        assert_eq!(report.original.len(), 20);
        assert_eq!(report.original[0], 0x45);

        // Time exceeded, code 0.
        packet[0] = TYPE_TIME_EXCEEDED;
        packet[1] = 0;
        packet[2..4].copy_from_slice(&[0, 0]);
        let field = checksum::checksum(&packet);
        packet[2..4].copy_from_slice(&field.to_be_bytes());
        let message = parse_checked(&packet).unwrap();
        assert_eq!(error_report(&message).unwrap().kind, TYPE_TIME_EXCEEDED);
    }

    #[test]
    fn unsupported_types_keep_a_raw_view() {
        let mut packet = [0u8; 12];
        packet[0] = 13; // timestamp
        packet[1] = 0;
        let field = checksum::checksum(&packet);
        packet[2..4].copy_from_slice(&field.to_be_bytes());
        let message = parse_checked(&packet).unwrap();
        assert_eq!(message.kind, 13);
        assert_eq!(echo(&message), Err(PacketError::Unsupported));
        assert_eq!(error_report(&message), Err(PacketError::Unsupported));
        assert_eq!(message.rest.len(), 4);
        assert_eq!(message.body.len(), 4);
    }

    #[test]
    fn checksum_is_stable_over_large_echo_data() {
        let mut buffer = [0u8; 1_500];
        let written = write_echo(&mut buffer, false, 0xABCD, 0xFFFF, &[0x5Au8; 1_400]).unwrap();
        let message = parse_checked(&buffer[..written]).unwrap();
        assert_eq!(echo(&message).unwrap().data.len(), 1_400);
    }

    #[test]
    fn write_rejects_short_buffers() {
        let mut short = [0u8; 9];
        assert_eq!(
            write_echo(&mut short, false, 1, 1, &[0u8; 2]),
            Err(PacketError::Truncated)
        );
        let mut exact = [0u8; 10];
        assert_eq!(write_echo(&mut exact, false, 1, 1, &[0u8; 2]), Ok(10));
    }
}
