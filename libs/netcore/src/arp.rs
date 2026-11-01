//! ARP for IPv4 over Ethernet (RFC 826).
//!
//! Only the Ethernet/IPv4 shape is accepted: hardware type 1, protocol type
//! 0x0800, hardware length 6, protocol length 4. IPv6 resolves neighbours with
//! NDP (see [`crate::icmpv6`]) and therefore never uses this module.

use crate::PacketError;
use crate::addr::{Ipv4Addr, MacAddr};

/// Size of an Ethernet/IPv4 ARP packet.
pub const PACKET_LEN: usize = 28;

/// Hardware type: Ethernet.
pub const HTYPE_ETHERNET: u16 = 1;
/// Protocol type: IPv4.
pub const PTYPE_IPV4: u16 = 0x0800;
/// Opcode: request.
pub const OP_REQUEST: u16 = 1;
/// Opcode: reply.
pub const OP_REPLY: u16 = 2;

/// A parsed ARP packet for IPv4 over Ethernet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket<'a> {
    /// Opcode (`OP_REQUEST` / `OP_REPLY`).
    pub op: u16,
    /// Sender hardware address.
    pub sender_mac: MacAddr,
    /// Sender protocol (IPv4) address.
    pub sender_ip: Ipv4Addr,
    /// Target hardware address (all zero in a request).
    pub target_mac: MacAddr,
    /// Target protocol (IPv4) address.
    pub target_ip: Ipv4Addr,
    /// Padding the caller added to reach the Ethernet minimum frame size.
    pub trailer: &'a [u8],
}

/// Parse an ARP packet.
///
/// A short packet is [`PacketError::Truncated`]; a well-formed ARP for another
/// hardware/protocol family is [`PacketError::Unsupported`] rather than an
/// error the caller must special-case.
pub fn parse(packet: &[u8]) -> Result<ArpPacket<'_>, PacketError> {
    if packet.len() < PACKET_LEN {
        return Err(PacketError::Truncated);
    }
    let htype = u16::from_be_bytes([packet[0], packet[1]]);
    let ptype = u16::from_be_bytes([packet[2], packet[3]]);
    let hlen = packet[4];
    let plen = packet[5];
    if htype != HTYPE_ETHERNET || ptype != PTYPE_IPV4 || hlen != 6 || plen != 4 {
        return Err(PacketError::Unsupported);
    }
    let op = u16::from_be_bytes([packet[6], packet[7]]);
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&packet[8..14]);
    let mut sender_ip = [0u8; 4];
    sender_ip.copy_from_slice(&packet[14..18]);
    let mut target_mac = [0u8; 6];
    target_mac.copy_from_slice(&packet[18..24]);
    let mut target_ip = [0u8; 4];
    target_ip.copy_from_slice(&packet[24..28]);
    Ok(ArpPacket {
        op,
        sender_mac: MacAddr(sender_mac),
        sender_ip: Ipv4Addr(sender_ip),
        target_mac: MacAddr(target_mac),
        target_ip: Ipv4Addr(target_ip),
        trailer: &packet[PACKET_LEN..],
    })
}

/// Write an ARP packet into `out`; returns the number of bytes written (28).
pub fn write(
    out: &mut [u8],
    op: u16,
    sender_mac: &MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: &MacAddr,
    target_ip: Ipv4Addr,
) -> Result<usize, PacketError> {
    if out.len() < PACKET_LEN {
        return Err(PacketError::Truncated);
    }
    out[0..2].copy_from_slice(&HTYPE_ETHERNET.to_be_bytes());
    out[2..4].copy_from_slice(&PTYPE_IPV4.to_be_bytes());
    out[4] = 6;
    out[5] = 4;
    out[6..8].copy_from_slice(&op.to_be_bytes());
    out[8..14].copy_from_slice(&sender_mac.0);
    out[14..18].copy_from_slice(&sender_ip.0);
    out[18..24].copy_from_slice(&target_mac.0);
    out[24..28].copy_from_slice(&target_ip.0);
    Ok(PACKET_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_packet() -> [u8; PACKET_LEN] {
        let mut packet = [0u8; PACKET_LEN];
        let sender_mac = MacAddr::new([0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        let sender_ip = Ipv4Addr::new(10, 0, 2, 15);
        let target_mac = MacAddr::UNSPECIFIED;
        let target_ip = Ipv4Addr::new(10, 0, 2, 2);
        let written = write(
            &mut packet,
            OP_REQUEST,
            &sender_mac,
            sender_ip,
            &target_mac,
            target_ip,
        )
        .unwrap();
        assert_eq!(written, PACKET_LEN);
        packet
    }

    #[test]
    fn request_round_trips() {
        let packet = request_packet();
        let parsed = parse(&packet).unwrap();
        assert_eq!(parsed.op, OP_REQUEST);
        assert_eq!(
            parsed.sender_mac,
            MacAddr::new([0x52, 0x54, 0, 0x12, 0x34, 0x56])
        );
        assert_eq!(parsed.sender_ip, Ipv4Addr::new(10, 0, 2, 15));
        assert!(parsed.target_mac.is_broadcast() == false);
        assert_eq!(parsed.target_mac, MacAddr::UNSPECIFIED);
        assert_eq!(parsed.target_ip, Ipv4Addr::new(10, 0, 2, 2));
        assert!(parsed.trailer.is_empty());
    }

    #[test]
    fn trailer_is_preserved_for_padded_frames() {
        let mut frame = [0u8; PACKET_LEN + 18];
        frame[..PACKET_LEN].copy_from_slice(&request_packet());
        let parsed = parse(&frame).unwrap();
        assert_eq!(parsed.trailer.len(), 18);
    }

    #[test]
    fn short_packets_are_truncated() {
        let packet = request_packet();
        assert_eq!(
            parse(&packet[..PACKET_LEN - 1]),
            Err(PacketError::Truncated)
        );
    }

    #[test]
    fn foreign_families_are_unsupported() {
        let mut packet = request_packet();
        packet[0..2].copy_from_slice(&6u16.to_be_bytes()); // htype = IEEE 802
        assert_eq!(parse(&packet), Err(PacketError::Unsupported));
        let mut packet = request_packet();
        packet[2..4].copy_from_slice(&0x86DDu16.to_be_bytes()); // ptype = IPv6
        assert_eq!(parse(&packet), Err(PacketError::Unsupported));
        let mut packet = request_packet();
        packet[4] = 8;
        assert_eq!(parse(&packet), Err(PacketError::Unsupported));
        let mut packet = request_packet();
        packet[5] = 16;
        assert_eq!(parse(&packet), Err(PacketError::Unsupported));
    }

    #[test]
    fn write_rejects_a_short_buffer() {
        let mut out = [0u8; PACKET_LEN - 1];
        assert_eq!(
            write(
                &mut out,
                OP_REPLY,
                &MacAddr::BROADCAST,
                Ipv4Addr::LOOPBACK,
                &MacAddr::BROADCAST,
                Ipv4Addr::LOOPBACK,
            ),
            Err(PacketError::Truncated)
        );
    }
}
