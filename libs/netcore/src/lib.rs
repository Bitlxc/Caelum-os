//! CaelumOS network core (M7a).
//!
//! This crate is `no_std`, has no dependencies and forbids `unsafe`. It is the
//! single protocol contract shared by the future loopback interface, the
//! `virtio-net` driver and the kernel socket layer, mirroring the role
//! `libs/block` plays for storage.
//!
//! # What lives here (and what does not)
//!
//! * Frame/segment **parsing is zero-copy**: every parser borrows a caller
//!   slice and returns field views into it. No parser allocates, and no parser
//!   copies a packet-sized array onto the stack (the maximum in-crate local is
//!   a `[u8; 64]` scratch block in tests only).
//! * Every length, option chain and extension-header walk is bounded and
//!   overflow-checked. A malformed packet always yields [`PacketError`]; the
//!   crate never panics on peer-controlled input.
//! * Checksums (Internet checksum, plus the IPv4/IPv6 pseudo-header variants
//!   used by UDP, TCP and ICMPv6) are implemented here so loopback and the
//!   driver agree on the exact arithmetic.
//! * The TCP state machine is a **pure logic** object: it consumes parsed
//!   segments and emits outgoing segment headers, sequence bookkeeping,
//!   retransmit deadlines and events. It owns no buffers and never sends
//!   anything itself.
//!
//! Deliberately out of scope for M7a (documented in [`tcp`] and [`ipv4`]):
//! IPv4 fragment reassembly, IPv6 fragment reassembly, TCP congestion control,
//! SACK/WScale/timestamps negotiation effects, socket objects, and any device
//! or DMA code.
//!
//! # Layout
//!
//! ```text
//! Ethernet -> ARP / IPv4 -> ICMP / UDP / TCP
//!                     \-> IPv6 -> ICMPv6 / UDP / TCP (via extension headers)
//! ```

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

use core::fmt;

/// Largest IPv4/IPv6 datagram (including headers) this crate supports.
pub const MAX_PACKET_BYTES: usize = 65_535;

/// Largest Ethernet payload (frame minus the 14-byte header).
pub const MAX_ETHERNET_PAYLOAD: usize = 1_500;

/// Upper bound on the IPv6 extension headers walked by [`ipv6::upper_layer`].
///
/// A malicious peer could otherwise build an extension-header chain that never
/// ends; the walk stops with [`PacketError::BadOptions`] after this many.
pub const MAX_IPV6_EXT_HEADERS: usize = 8;

/// Everything that can go wrong while parsing or building a packet.
///
/// The variants are deliberately coarse: the kernel's error reporting only
/// needs "the peer sent something structurally impossible", and a finer
/// taxonomy would leak implementation details into the ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketError {
    /// The slice is shorter than the header it claims to contain.
    Truncated,
    /// A length field disagrees with the slice or exceeds the protocol limit.
    BadLength,
    /// Wrong protocol version (IPv4 parser on an IPv6 packet, etc.).
    BadVersion,
    /// The header or pseudo-header checksum does not verify.
    BadChecksum,
    /// A header-length field is out of range (IHL, TCP data offset).
    BadHeaderLength,
    /// An option/extension-header chain is malformed or too long.
    BadOptions,
    /// The packet is well-formed but uses a feature this crate does not model.
    Unsupported,
    /// A field value cannot be represented in the requested operation.
    OutOfRange,
}

impl PacketError {
    /// Short static description, used by kernel diagnostics and tests.
    pub const fn as_str(self) -> &'static str {
        match self {
            PacketError::Truncated => "packet truncated",
            PacketError::BadLength => "packet length invalid",
            PacketError::BadVersion => "packet version invalid",
            PacketError::BadChecksum => "packet checksum invalid",
            PacketError::BadHeaderLength => "packet header length invalid",
            PacketError::BadOptions => "packet options invalid",
            PacketError::Unsupported => "packet feature unsupported",
            PacketError::OutOfRange => "packet field out of range",
        }
    }
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub mod addr;
pub mod arp;
pub mod checksum;
pub mod ether;
pub mod icmp;
pub mod icmpv6;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;

/// Upper bound on the neighbour-discovery options walked by
/// [`icmpv6::options`]; a longer chain is rejected with
/// [`PacketError::BadOptions`].
pub const MAX_ICMPV6_OPTIONS: usize = 8;

pub use addr::{Ipv4Addr, Ipv6Addr, MacAddr};
pub use checksum::{Checksum, checksum, checksum_v4, checksum_v6, verify as verify_checksum};
pub use ether::{ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, EthernetFrame};
pub use icmp::{Echo as IcmpEcho, ErrorReport as IcmpErrorReport, IcmpMessage};
pub use icmpv6::{
    ErrorReport as Icmpv6ErrorReport, Icmpv6Message, NdpOption, NeighbourAdvertisement,
    NeighbourSolicitation,
};
pub use ipv4::{Ipv4Header, PROTOCOL_ICMP, PROTOCOL_TCP, PROTOCOL_UDP};
pub use ipv6::{Ipv6Header, UpperLayer};
pub use tcp::{
    OutgoingSegment, TcpConnection, TcpEvent, TcpOptions, TcpResponse, TcpSegment, TcpState,
    TcpTick, seq_between, seq_in_window, seq_le, seq_lt,
};
pub use udp::UdpDatagram;
