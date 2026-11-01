//! Link, IPv4 and IPv6 address types.
//!
//! The types are plain `repr(transparent)`-shaped arrays: layout is part of the
//! crate's contract, so the header codecs can write them without conversion.

use crate::PacketError;

/// A 48-bit Ethernet MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// All-zero address. IPv4 ARP probes and DHCP DISCOVER use it as source.
    pub const UNSPECIFIED: MacAddr = MacAddr([0; 6]);
    /// The broadcast address (`ff:ff:ff:ff:ff:ff`).
    pub const BROADCAST: MacAddr = MacAddr([0xFF; 6]);

    /// Build from raw bytes.
    pub const fn new(bytes: [u8; 6]) -> Self {
        MacAddr(bytes)
    }

    /// The raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// Parse exactly six bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, PacketError> {
        if bytes.len() != 6 {
            return Err(PacketError::Truncated);
        }
        let mut out = [0u8; 6];
        out.copy_from_slice(bytes);
        Ok(MacAddr(out))
    }

    /// The IEEE 802 broadcast address.
    pub const fn is_broadcast(&self) -> bool {
        self.0[0] == 0xFF
            && self.0[1] == 0xFF
            && self.0[2] == 0xFF
            && self.0[3] == 0xFF
            && self.0[4] == 0xFF
            && self.0[5] == 0xFF
    }

    /// Whether the group bit is set (multicast/broadcast).
    pub const fn is_group(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Write the six bytes into `out` (which must have room for six).
    pub fn write(&self, out: &mut [u8]) -> Result<(), PacketError> {
        if out.len() < 6 {
            return Err(PacketError::Truncated);
        }
        out[..6].copy_from_slice(&self.0);
        Ok(())
    }
}

/// An IPv4 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ipv4Addr(pub [u8; 4]);

impl Ipv4Addr {
    /// `0.0.0.0`.
    pub const UNSPECIFIED: Ipv4Addr = Ipv4Addr([0; 4]);
    /// `127.0.0.1`.
    pub const LOOPBACK: Ipv4Addr = Ipv4Addr([127, 0, 0, 1]);
    /// `255.255.255.255`.
    pub const BROADCAST: Ipv4Addr = Ipv4Addr([255; 4]);

    /// Build from octets.
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4Addr([a, b, c, d])
    }

    /// The four octets.
    pub const fn octets(&self) -> [u8; 4] {
        self.0
    }

    /// Parse exactly four bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, PacketError> {
        if bytes.len() != 4 {
            return Err(PacketError::Truncated);
        }
        let mut out = [0u8; 4];
        out.copy_from_slice(bytes);
        Ok(Ipv4Addr(out))
    }

    /// Whole 127/8 block.
    pub const fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }

    /// `0.0.0.0`.
    pub const fn is_unspecified(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    /// 224.0.0.0/4.
    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 0xF0 == 0xE0
    }

    /// The limited broadcast address.
    pub const fn is_broadcast(&self) -> bool {
        self.0[0] == 255 && self.0[1] == 255 && self.0[2] == 255 && self.0[3] == 255
    }

    /// Whether this address is in 10/8, 172.16/12 or 192.168/16.
    pub const fn is_private(&self) -> bool {
        if self.0[0] == 10 {
            return true;
        }
        if self.0[0] == 172 && (self.0[1] & 0xF0) == 16 {
            return true;
        }
        self.0[0] == 192 && self.0[1] == 168
    }

    /// Write the four octets into `out`.
    pub fn write(&self, out: &mut [u8]) -> Result<(), PacketError> {
        if out.len() < 4 {
            return Err(PacketError::Truncated);
        }
        out[..4].copy_from_slice(&self.0);
        Ok(())
    }
}

/// An IPv6 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ipv6Addr(pub [u8; 16]);

impl Ipv6Addr {
    /// `::`.
    pub const UNSPECIFIED: Ipv6Addr = Ipv6Addr([0; 16]);
    /// `::1`.
    pub const LOOPBACK: Ipv6Addr = Ipv6Addr([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    /// Build from raw bytes.
    pub const fn new(bytes: [u8; 16]) -> Self {
        Ipv6Addr(bytes)
    }

    /// The sixteen bytes.
    pub const fn octets(&self) -> [u8; 16] {
        self.0
    }

    /// Parse exactly sixteen bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, PacketError> {
        if bytes.len() != 16 {
            return Err(PacketError::Truncated);
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(bytes);
        Ok(Ipv6Addr(out))
    }

    /// `::1`.
    pub const fn is_loopback(&self) -> bool {
        let mut i = 0;
        while i < 15 {
            if self.0[i] != 0 {
                return false;
            }
            i += 1;
        }
        self.0[15] == 1
    }

    /// `::`.
    pub const fn is_unspecified(&self) -> bool {
        let mut i = 0;
        while i < 16 {
            if self.0[i] != 0 {
                return false;
            }
            i += 1;
        }
        true
    }

    /// `ff00::/8`.
    pub const fn is_multicast(&self) -> bool {
        self.0[0] == 0xFF
    }

    /// `fe80::/10`.
    pub const fn is_link_local(&self) -> bool {
        self.0[0] == 0xFE && (self.0[1] & 0xC0) == 0x80
    }

    /// `fec0::/10` (deprecated site-local range, used by QEMU's user network).
    pub const fn is_site_local(&self) -> bool {
        self.0[0] == 0xFE && (self.0[1] & 0xC0) == 0xC0
    }

    /// Write the sixteen bytes into `out`.
    pub fn write(&self, out: &mut [u8]) -> Result<(), PacketError> {
        if out.len() < 16 {
            return Err(PacketError::Truncated);
        }
        out[..16].copy_from_slice(&self.0);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_round_trips_and_validates_length() {
        let mac = MacAddr::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        let mut out = [0u8; 6];
        mac.write(&mut out).unwrap();
        assert_eq!(out, mac.0);
        assert_eq!(MacAddr::from_slice(&out), Ok(mac));
        assert_eq!(MacAddr::from_slice(&[0u8; 5]), Err(PacketError::Truncated));
        assert_eq!(MacAddr::from_slice(&[0u8; 7]), Err(PacketError::Truncated));
    }

    #[test]
    fn mac_group_and_broadcast_flags() {
        assert!(MacAddr::BROADCAST.is_broadcast());
        assert!(MacAddr::BROADCAST.is_group());
        assert!(!MacAddr::UNSPECIFIED.is_group());
        assert!(MacAddr::new([1, 0, 0, 0, 0, 0]).is_group());
        assert!(!MacAddr::new([2, 0, 0, 0, 0, 0]).is_group());
    }

    #[test]
    fn ipv4_classification() {
        assert!(Ipv4Addr::LOOPBACK.is_loopback());
        assert!(Ipv4Addr::UNSPECIFIED.is_unspecified());
        assert!(Ipv4Addr::BROADCAST.is_broadcast());
        assert!(Ipv4Addr::new(224, 0, 0, 1).is_multicast());
        assert!(!Ipv4Addr::new(223, 255, 255, 255).is_multicast());
        assert!(Ipv4Addr::new(10, 1, 2, 3).is_private());
        assert!(Ipv4Addr::new(172, 16, 0, 1).is_private());
        assert!(!Ipv4Addr::new(172, 32, 0, 1).is_private());
        assert!(Ipv4Addr::new(192, 168, 1, 1).is_private());
        assert!(!Ipv4Addr::new(192, 169, 1, 1).is_private());
    }

    #[test]
    fn ipv4_round_trips() {
        let addr = Ipv4Addr::new(192, 0, 2, 7);
        let mut out = [0u8; 4];
        addr.write(&mut out).unwrap();
        assert_eq!(Ipv4Addr::from_slice(&out), Ok(addr));
        assert_eq!(Ipv4Addr::from_slice(&[0u8; 3]), Err(PacketError::Truncated));
    }

    #[test]
    fn ipv6_classification_and_round_trip() {
        assert!(Ipv6Addr::LOOPBACK.is_loopback());
        assert!(!Ipv6Addr::UNSPECIFIED.is_loopback());
        assert!(Ipv6Addr::UNSPECIFIED.is_unspecified());
        assert!(
            Ipv6Addr::new([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).is_multicast()
        );
        assert!(
            Ipv6Addr::new([0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).is_link_local()
        );
        assert!(
            Ipv6Addr::new([0xFE, 0xC0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).is_site_local()
        );
        let addr = Ipv6Addr::new([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        let mut out = [0u8; 16];
        addr.write(&mut out).unwrap();
        assert_eq!(Ipv6Addr::from_slice(&out), Ok(addr));
        assert_eq!(
            Ipv6Addr::from_slice(&[0u8; 15]),
            Err(PacketError::Truncated)
        );
    }
}
