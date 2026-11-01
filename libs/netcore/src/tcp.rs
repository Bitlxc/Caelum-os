//! TCP (RFC 793 / 9293) header parsing, option decoding and a pure connection
//! state machine.
//!
//! The state machine has **no I/O and no clock of its own**: the caller passes
//! `now` in abstract ticks and gets back the segments it should transmit, so the
//! same logic can be table-tested on the host, driven by loopback and driven by
//! the virtio-net path later. Retransmission is therefore a deadline comparison
//! rather than a timer callback.

use crate::PacketError;
use crate::addr::{Ipv4Addr, Ipv6Addr};
use crate::checksum;

/// Fixed TCP header length.
pub const HEADER_LEN: usize = 20;
/// Largest header (data offset 15).
pub const MAX_HEADER_LEN: usize = 60;
/// Protocol number for both pseudo headers.
pub const PROTOCOL: u8 = 6;
/// Bound on option TLVs a single header may contain.
pub const MAX_TCP_OPTIONS: usize = 8;
/// Bound on a decoded window scale (RFC 7323).
pub const MAX_WINDOW_SCALE: u8 = 14;
/// Default MSS we advertise when no MSS option is supplied.
pub const DEFAULT_MSS: u16 = 536;
/// Advertised receive window in the bare state machine.
pub const DEFAULT_WINDOW: u16 = 4_096;
/// Deterministic initial sequence number for the listening path.
pub const DEFAULT_ISN: u32 = 0x1234_5678;

/// FIN flag.
pub const FLAG_FIN: u8 = 0x01;
/// SYN flag.
pub const FLAG_SYN: u8 = 0x02;
/// RST flag.
pub const FLAG_RST: u8 = 0x04;
/// PSH flag.
pub const FLAG_PSH: u8 = 0x08;
/// ACK flag.
pub const FLAG_ACK: u8 = 0x10;
/// URG flag.
pub const FLAG_URG: u8 = 0x20;
/// ECE flag.
pub const FLAG_ECE: u8 = 0x40;
/// CWR flag.
pub const FLAG_CWR: u8 = 0x80;

/// Option kind: end of options.
pub const OPTION_END: u8 = 0;
/// Option kind: no-operation padding.
pub const OPTION_NOP: u8 = 1;
/// Option kind: maximum segment size.
pub const OPTION_MSS: u8 = 2;
/// Option kind: window scale.
pub const OPTION_WINDOW_SCALE: u8 = 3;
/// Option kind: SACK permitted.
pub const OPTION_SACK_PERMITTED: u8 = 4;
/// Option kind: SACK blocks (validated, not retained).
pub const OPTION_SACK: u8 = 5;
/// Option kind: timestamps.
pub const OPTION_TIMESTAMP: u8 = 8;

/// Initial retransmission timeout in caller-supplied ticks.
pub const INITIAL_RTO_TICKS: u64 = 200;
/// Upper bound for the doubled retransmission timeout.
pub const MAX_RTO_TICKS: u64 = 3_200;
/// Give up after this many retransmissions of one segment.
pub const MAX_RETRANSMITS: u8 = 5;

/// A parsed TCP segment with borrowed option and payload views.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Sequence number.
    pub seq: u32,
    /// Acknowledgment number.
    pub ack: u32,
    /// Data offset in 32-bit words (5..=15).
    pub data_offset: u8,
    /// Raw flags byte.
    pub flags: u8,
    /// Advertised window.
    pub window: u16,
    /// The checksum field as it appeared on the wire.
    pub checksum: u16,
    /// Urgent pointer.
    pub urgent: u16,
    /// Option bytes (without the fixed header).
    pub options: &'a [u8],
    /// Segment payload.
    pub payload: &'a [u8],
}

impl<'a> TcpSegment<'a> {
    /// Header length in bytes.
    pub const fn header_len(&self) -> usize {
        self.data_offset as usize * 4
    }

    /// Whether `flag` is set.
    pub const fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    /// FIN flag.
    pub const fn fin(&self) -> bool {
        self.has(FLAG_FIN)
    }

    /// SYN flag.
    pub const fn syn(&self) -> bool {
        self.has(FLAG_SYN)
    }

    /// RST flag.
    pub const fn rst(&self) -> bool {
        self.has(FLAG_RST)
    }

    /// ACK flag.
    pub const fn ack(&self) -> bool {
        self.has(FLAG_ACK)
    }

    /// Acknowledgment field if the ACK flag is set.
    pub const fn ack_number(&self) -> Option<u32> {
        if self.ack() { Some(self.ack) } else { None }
    }
}

/// Decoded options that the state machine cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpOptions {
    /// Maximum segment size.
    pub mss: Option<u16>,
    /// Window scale shift count.
    pub window_scale: Option<u8>,
    /// Whether SACK is permitted.
    pub sack_permitted: bool,
    /// Timestamps (TSval, TSecr).
    pub timestamp: Option<(u32, u32)>,
}

/// Parse a TCP segment without verifying its checksum.
pub fn parse(packet: &[u8]) -> Result<TcpSegment<'_>, PacketError> {
    if packet.len() < HEADER_LEN {
        return Err(PacketError::Truncated);
    }
    let data_offset = packet[12] >> 4;
    if data_offset < 5 {
        return Err(PacketError::BadHeaderLength);
    }
    let header_len = usize::from(data_offset) * 4;
    if header_len > packet.len() {
        return Err(PacketError::Truncated);
    }
    Ok(TcpSegment {
        src_port: u16::from_be_bytes([packet[0], packet[1]]),
        dst_port: u16::from_be_bytes([packet[2], packet[3]]),
        seq: u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
        ack: u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]),
        data_offset,
        flags: packet[13],
        window: u16::from_be_bytes([packet[14], packet[15]]),
        checksum: u16::from_be_bytes([packet[16], packet[17]]),
        urgent: u16::from_be_bytes([packet[18], packet[19]]),
        options: &packet[HEADER_LEN..header_len],
        payload: &packet[header_len..],
    })
}

/// Parse and verify a TCP segment against its IPv4 pseudo header.
pub fn parse_checked_v4(
    packet: &[u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
) -> Result<TcpSegment<'_>, PacketError> {
    let segment = parse(packet)?;
    if !checksum::verify_v4(PROTOCOL, src, dst, packet) {
        return Err(PacketError::BadChecksum);
    }
    Ok(segment)
}

/// Parse and verify a TCP segment against its IPv6 pseudo header.
pub fn parse_checked_v6(
    packet: &[u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
) -> Result<TcpSegment<'_>, PacketError> {
    let segment = parse(packet)?;
    if !checksum::verify_v6(PROTOCOL, src, dst, packet) {
        return Err(PacketError::BadChecksum);
    }
    Ok(segment)
}

/// Decode the options of a segment, validating every known TLV's length.
pub fn parse_options(bytes: &[u8]) -> Result<TcpOptions, PacketError> {
    let mut options = TcpOptions::default();
    let mut offset = 0usize;
    let mut seen = 0usize;
    while offset < bytes.len() {
        let kind = bytes[offset];
        if kind == OPTION_END {
            break;
        }
        seen += 1;
        if seen > MAX_TCP_OPTIONS {
            return Err(PacketError::BadOptions);
        }
        if kind == OPTION_NOP {
            offset += 1;
            continue;
        }
        if offset + 2 > bytes.len() {
            return Err(PacketError::Truncated);
        }
        let length = usize::from(bytes[offset + 1]);
        if length < 2 {
            return Err(PacketError::BadOptions);
        }
        let end = offset + length;
        if end > bytes.len() {
            return Err(PacketError::Truncated);
        }
        let data = &bytes[offset + 2..end];
        match kind {
            OPTION_MSS => {
                if data.len() != 2 {
                    return Err(PacketError::BadOptions);
                }
                options.mss = Some(u16::from_be_bytes([data[0], data[1]]));
            }
            OPTION_WINDOW_SCALE => {
                if data.len() != 1 || data[0] > MAX_WINDOW_SCALE {
                    return Err(PacketError::BadOptions);
                }
                options.window_scale = Some(data[0]);
            }
            OPTION_SACK_PERMITTED => {
                if !data.is_empty() {
                    return Err(PacketError::BadOptions);
                }
                options.sack_permitted = true;
            }
            OPTION_SACK => {
                // 2 + n * 8 bytes, at least one block.
                if data.len() < 8 || (data.len() - 8) % 8 != 0 {
                    return Err(PacketError::BadOptions);
                }
            }
            OPTION_TIMESTAMP => {
                if data.len() != 8 {
                    return Err(PacketError::BadOptions);
                }
                options.timestamp = Some((
                    u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
                    u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
                ));
            }
            _ => {}
        }
        offset = end;
    }
    Ok(options)
}

/// Write a TCP header (with optional option bytes) into `out`.
///
/// The checksum field is left zero; call [`fill_checksum_v4`] or
/// [`fill_checksum_v6`] once the payload is in place. `options` must be a
/// multiple of four bytes and at most 40 bytes (use NOP/END padding).
pub fn write_header(
    out: &mut [u8],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: &[u8],
) -> Result<usize, PacketError> {
    if options.len() > MAX_HEADER_LEN - HEADER_LEN || options.len() % 4 != 0 {
        return Err(PacketError::BadOptions);
    }
    let header_len = HEADER_LEN + options.len();
    if out.len() < header_len {
        return Err(PacketError::Truncated);
    }
    let data_offset = (header_len / 4) as u8;
    out[0..2].copy_from_slice(&src_port.to_be_bytes());
    out[2..4].copy_from_slice(&dst_port.to_be_bytes());
    out[4..8].copy_from_slice(&seq.to_be_bytes());
    out[8..12].copy_from_slice(&ack.to_be_bytes());
    out[12] = data_offset << 4;
    out[13] = flags;
    out[14..16].copy_from_slice(&window.to_be_bytes());
    out[16..18].copy_from_slice(&[0, 0]);
    out[18..20].copy_from_slice(&[0, 0]);
    out[HEADER_LEN..header_len].copy_from_slice(options);
    Ok(header_len)
}

/// Write a complete segment (header + payload) and return its length.
#[allow(clippy::too_many_arguments)]
pub fn write_segment(
    out: &mut [u8],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: &[u8],
    payload: &[u8],
) -> Result<usize, PacketError> {
    let header_len = write_header(out, src_port, dst_port, seq, ack, flags, window, options)?;
    let total = header_len + payload.len();
    if out.len() < total {
        return Err(PacketError::Truncated);
    }
    out[header_len..total].copy_from_slice(payload);
    Ok(total)
}

/// Check that a segment length is usable before filling its checksum.
fn check_segment(out: &[u8], total: usize) -> Result<(), PacketError> {
    if total < HEADER_LEN || total > out.len() {
        return Err(PacketError::BadLength);
    }
    Ok(())
}

/// Compute and store the IPv4 pseudo-header checksum of `out[..total]`.
///
/// TCP has no "no checksum" escape: a computed zero is stored as `0xFFFF`.
pub fn fill_checksum_v4(
    out: &mut [u8],
    total: usize,
    src: Ipv4Addr,
    dst: Ipv4Addr,
) -> Result<(), PacketError> {
    check_segment(out, total)?;
    out[16..18].copy_from_slice(&[0, 0]);
    let mut field = checksum::checksum_v4(PROTOCOL, src, dst, &out[..total]);
    if field == 0 {
        field = 0xFFFF;
    }
    out[16..18].copy_from_slice(&field.to_be_bytes());
    Ok(())
}

/// Compute and store the IPv6 pseudo-header checksum of `out[..total]`.
pub fn fill_checksum_v6(
    out: &mut [u8],
    total: usize,
    src: Ipv6Addr,
    dst: Ipv6Addr,
) -> Result<(), PacketError> {
    check_segment(out, total)?;
    out[16..18].copy_from_slice(&[0, 0]);
    let mut field = checksum::checksum_v6(PROTOCOL, src, dst, &out[..total]);
    if field == 0 {
        field = 0xFFFF;
    }
    out[16..18].copy_from_slice(&field.to_be_bytes());
    Ok(())
}

/// Wrapping "a comes before b" over the 32-bit sequence space.
pub const fn seq_lt(a: u32, b: u32) -> bool {
    (b.wrapping_sub(a) as i32) > 0
}

/// Wrapping "a comes before or equals b".
pub const fn seq_le(a: u32, b: u32) -> bool {
    (b.wrapping_sub(a) as i32) >= 0
}

/// Wrapping half-open interval check: `start <= seq < start + len`.
pub const fn seq_between(seq: u32, start: u32, len: u32) -> bool {
    if len == 0 {
        return false;
    }
    seq.wrapping_sub(start) < len
}

/// Whether `seq` falls inside the receive window `[start, start + window)`.
pub const fn seq_in_window(seq: u32, start: u32, window: u32) -> bool {
    seq_between(seq, start, window)
}

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// No connection.
    Closed,
    /// Waiting for a SYN.
    Listen,
    /// SYN sent, waiting for SYN|ACK.
    SynSent,
    /// SYN received, waiting for the handshake ACK.
    SynReceived,
    /// Data transfer.
    Established,
    /// Our FIN sent, waiting for its ACK.
    FinWait1,
    /// Our FIN acknowledged, waiting for the peer's FIN.
    FinWait2,
    /// Peer's FIN received, we can still send.
    CloseWait,
    /// Both sides sent FIN, waiting for the peer's ACK.
    Closing,
    /// Peer's FIN acknowledged after our close, waiting for our ACK of its FIN.
    LastAck,
    /// Both FINs acknowledged; lingers before Closed.
    TimeWait,
}

impl TcpState {
    /// Short static name, for diagnostics and tests.
    pub const fn as_str(self) -> &'static str {
        match self {
            TcpState::Closed => "closed",
            TcpState::Listen => "listen",
            TcpState::SynSent => "syn-sent",
            TcpState::SynReceived => "syn-received",
            TcpState::Established => "established",
            TcpState::FinWait1 => "fin-wait-1",
            TcpState::FinWait2 => "fin-wait-2",
            TcpState::CloseWait => "close-wait",
            TcpState::Closing => "closing",
            TcpState::LastAck => "last-ack",
            TcpState::TimeWait => "time-wait",
        }
    }

    /// Whether the connection is synchronized (RST moves it to `Closed`).
    pub const fn is_synchronized(self) -> bool {
        !matches!(self, TcpState::Closed | TcpState::Listen)
    }
}

/// A segment the state machine wants transmitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutgoingSegment {
    /// Flags to send.
    pub flags: u8,
    /// Sequence number (of the first data byte, or of SYN/FIN).
    pub seq: u32,
    /// Acknowledgment number.
    pub ack: u32,
    /// Our advertised window.
    pub window: u16,
}

/// What happened while processing an incoming segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpEvent {
    /// Nothing notable (e.g. a pure ACK that advanced nothing).
    None,
    /// The handshake completed.
    Connected,
    /// Incoming ACK acknowledged transmitted data.
    DataAcknowledged,
    /// Payload bytes were accepted (count).
    Data(u32),
    /// The peer closed its direction.
    PeerFin,
    /// The connection was reset.
    Reset,
}

/// Result of [`TcpConnection::on_segment`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpResponse {
    /// Segment to transmit, if any.
    pub send: Option<OutgoingSegment>,
    /// Event observed.
    pub event: TcpEvent,
    /// Whether incoming payload was accepted into the receive sequence space.
    pub accepted: bool,
    /// Whether the caller should drop the segment silently.
    pub drop: bool,
}

impl TcpResponse {
    const fn silent() -> Self {
        TcpResponse {
            send: None,
            event: TcpEvent::None,
            accepted: false,
            drop: true,
        }
    }
}

/// Result of [`TcpConnection::on_tick`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpTick {
    /// The outstanding segment must be retransmitted now.
    pub retransmit: bool,
    /// Too many retransmissions; the connection was abandoned.
    pub give_up: bool,
}

#[derive(Debug, Clone, Copy)]
struct Retransmit {
    seq: u32,
    len: u32,
    deadline: u64,
    attempts: u8,
}

/// A pure TCP connection state machine.
#[derive(Debug, Clone)]
pub struct TcpConnection {
    state: TcpState,
    local_port: u16,
    remote_port: u16,
    isn: u32,
    snd_una: u32,
    snd_nxt: u32,
    rcv_nxt: u32,
    window: u16,
    peer_mss: u16,
    retransmit: Option<Retransmit>,
    /// `close` was called while data was still unacknowledged; the FIN is sent
    /// as soon as that data is acknowledged (M7c: never overwrite a pending
    /// data retransmission).
    pending_close: bool,
}

impl Default for TcpConnection {
    fn default() -> Self {
        TcpConnection::new()
    }
}

impl TcpConnection {
    /// A fresh, closed connection.
    pub const fn new() -> Self {
        TcpConnection {
            state: TcpState::Closed,
            local_port: 0,
            remote_port: 0,
            isn: DEFAULT_ISN,
            snd_una: 0,
            snd_nxt: 0,
            rcv_nxt: 0,
            window: DEFAULT_WINDOW,
            peer_mss: DEFAULT_MSS,
            retransmit: None,
            pending_close: false,
        }
    }

    /// Enter `Listen` with the deterministic initial sequence number.
    pub fn listen(&mut self, local_port: u16) {
        self.listen_with_isn(local_port, DEFAULT_ISN);
    }

    /// Enter `Listen` with an explicit initial sequence number.
    pub fn listen_with_isn(&mut self, local_port: u16, isn: u32) {
        *self = TcpConnection::new();
        self.state = TcpState::Listen;
        self.local_port = local_port;
        self.isn = isn;
        self.snd_una = isn;
        self.snd_nxt = isn;
    }

    /// Actively connect: enter `SynSent` and return the SYN to transmit.
    ///
    /// The SYN is registered for retransmission like any other segment: while
    /// the peer has not answered, [`TcpConnection::on_tick`] reports the same
    /// RTO/backoff schedule and eventually gives up. Without that a dropped SYN
    /// would leave the connection in `SynSent` forever on a real link.
    pub fn connect(
        &mut self,
        local_port: u16,
        remote_port: u16,
        isn: u32,
        now: u64,
    ) -> OutgoingSegment {
        *self = TcpConnection::new();
        self.state = TcpState::SynSent;
        self.local_port = local_port;
        self.remote_port = remote_port;
        self.isn = isn;
        self.snd_una = isn;
        self.snd_nxt = isn.wrapping_add(1);
        // A SYN occupies one sequence number, exactly like a FIN.
        self.retransmit = Some(Retransmit {
            seq: isn,
            len: 0,
            deadline: now.saturating_add(INITIAL_RTO_TICKS),
            attempts: 0,
        });
        OutgoingSegment {
            flags: FLAG_SYN,
            seq: isn,
            ack: 0,
            window: self.window,
        }
    }

    /// Current state.
    pub fn state(&self) -> TcpState {
        self.state
    }

    /// Local port.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Remote port.
    pub fn remote_port(&self) -> u16 {
        self.remote_port
    }

    /// Next sequence number we will send.
    pub fn snd_nxt(&self) -> u32 {
        self.snd_nxt
    }

    /// Oldest unacknowledged sequence number.
    pub fn snd_una(&self) -> u32 {
        self.snd_una
    }

    /// Next sequence number we expect to receive.
    pub fn rcv_nxt(&self) -> u32 {
        self.rcv_nxt
    }

    /// Peer's MSS (from its SYN option, else the default).
    pub fn peer_mss(&self) -> u16 {
        self.peer_mss
    }

    /// Whether a segment is awaiting retransmission.
    pub fn retransmit_pending(&self) -> bool {
        self.retransmit.is_some()
    }

    /// Queue `len` bytes of outgoing payload and return the sequence number of
    /// the first byte.
    ///
    /// Only one outstanding segment is tracked (M7a simplification); calling
    /// this again before the previous one is acknowledged returns
    /// [`PacketError::OutOfRange`].
    pub fn send(&mut self, len: u32, now: u64) -> Result<u32, PacketError> {
        if !matches!(self.state, TcpState::Established | TcpState::CloseWait) {
            return Err(PacketError::Unsupported);
        }
        if len == 0 {
            return Err(PacketError::OutOfRange);
        }
        if self.retransmit.is_some() {
            return Err(PacketError::OutOfRange);
        }
        let seq = self.snd_nxt;
        self.snd_nxt = self.snd_nxt.wrapping_add(len);
        self.retransmit = Some(Retransmit {
            seq,
            len,
            deadline: now.saturating_add(INITIAL_RTO_TICKS),
            attempts: 0,
        });
        Ok(seq)
    }

    /// Begin a graceful close; returns the FIN to transmit.
    ///
    /// If data is still unacknowledged, the FIN is **deferred** instead of
    /// overwriting that data's retransmission record: `close` returns `None`
    /// and the FIN is emitted from [`TcpConnection::on_segment`] as soon as the
    /// outstanding data is acknowledged. Use
    /// [`TcpConnection::retransmit_pending`] to tell "deferred" apart from
    /// "not in a closable state" (which also returns `None`).
    pub fn close(&mut self, now: u64) -> Option<OutgoingSegment> {
        if !matches!(self.state, TcpState::Established | TcpState::CloseWait) {
            return None;
        }
        if self.retransmit.is_some() {
            // M7a tracks a single outstanding segment, so a FIN would overwrite
            // the data retransmission. Defer it; silently dropping the data is
            // not acceptable.
            self.pending_close = true;
            return None;
        }
        Some(self.emit_fin(now))
    }

    /// Emit the FIN and enter the matching closing state.
    fn emit_fin(&mut self, now: u64) -> OutgoingSegment {
        let state = match self.state {
            TcpState::CloseWait => TcpState::LastAck,
            _ => TcpState::FinWait1,
        };
        let seq = self.snd_nxt;
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        self.retransmit = Some(Retransmit {
            seq,
            len: 0,
            deadline: now.saturating_add(INITIAL_RTO_TICKS),
            attempts: 0,
        });
        self.state = state;
        OutgoingSegment {
            flags: FLAG_FIN | FLAG_ACK,
            seq,
            ack: self.rcv_nxt,
            window: self.window,
        }
    }

    /// Deadline check for the outstanding segment; call whenever the caller's
    /// clock advances.
    pub fn on_tick(&mut self, now: u64) -> TcpTick {
        let Some(retransmit) = self.retransmit else {
            return TcpTick {
                retransmit: false,
                give_up: false,
            };
        };
        if now < retransmit.deadline {
            return TcpTick {
                retransmit: false,
                give_up: false,
            };
        }
        let attempts = retransmit.attempts + 1;
        if attempts > MAX_RETRANSMITS {
            self.retransmit = None;
            // The peer is considered dead; do not send a deferred FIN to it.
            self.pending_close = false;
            self.state = TcpState::Closed;
            return TcpTick {
                retransmit: false,
                give_up: true,
            };
        }
        let base = INITIAL_RTO_TICKS << (attempts - 1).min(5);
        let timeout = base.min(MAX_RTO_TICKS);
        self.retransmit = Some(Retransmit {
            deadline: now.saturating_add(timeout),
            attempts,
            ..retransmit
        });
        TcpTick {
            retransmit: true,
            give_up: false,
        }
    }

    /// Process one incoming segment and return the segment to transmit, if any.
    pub fn on_segment(&mut self, segment: &TcpSegment<'_>, now: u64) -> TcpResponse {
        if segment.rst() {
            return self.on_reset(segment);
        }
        match self.state {
            TcpState::Closed => TcpResponse::silent(),
            TcpState::Listen => self.on_syn_in_listen(segment),
            TcpState::SynSent => self.on_segment_in_syn_sent(segment),
            _ => self.on_segment_synchronized(segment, now),
        }
    }

    fn on_reset(&mut self, segment: &TcpSegment<'_>) -> TcpResponse {
        // RFC 5961: in Listen a RST is ignored; in SynSent only an acceptable
        // ACK validates it; in a synchronized state the RST must fall inside
        // the receive window, otherwise it is a blind in-window forgery.
        let acceptable = match self.state {
            TcpState::Listen | TcpState::Closed => false,
            TcpState::SynSent => segment.ack() && segment.ack == self.snd_nxt,
            _ => seq_in_window(segment.seq, self.rcv_nxt, u32::from(self.window)),
        };
        if !acceptable {
            return TcpResponse::silent();
        }
        self.state = TcpState::Closed;
        self.retransmit = None;
        self.pending_close = false;
        TcpResponse {
            send: None,
            event: TcpEvent::Reset,
            accepted: false,
            drop: false,
        }
    }

    fn on_syn_in_listen(&mut self, segment: &TcpSegment<'_>) -> TcpResponse {
        if !segment.syn() {
            return TcpResponse::silent();
        }
        if segment.ack() {
            // An ACK for something we never sent; ask the peer to reset.
            return TcpResponse {
                send: Some(OutgoingSegment {
                    flags: FLAG_RST,
                    seq: segment.ack,
                    ack: 0,
                    window: 0,
                }),
                event: TcpEvent::None,
                accepted: false,
                drop: false,
            };
        }
        self.remote_port = segment.src_port;
        if let Ok(options) = parse_options(segment.options) {
            self.peer_mss = options.mss.unwrap_or(DEFAULT_MSS).max(1);
        }
        self.rcv_nxt = segment.seq.wrapping_add(1);
        self.snd_una = self.isn;
        self.snd_nxt = self.isn.wrapping_add(1);
        self.state = TcpState::SynReceived;
        TcpResponse {
            send: Some(OutgoingSegment {
                flags: FLAG_SYN | FLAG_ACK,
                seq: self.isn,
                ack: self.rcv_nxt,
                window: self.window,
            }),
            event: TcpEvent::None,
            accepted: false,
            drop: false,
        }
    }

    fn on_segment_in_syn_sent(&mut self, segment: &TcpSegment<'_>) -> TcpResponse {
        if segment.syn() && segment.ack() {
            if segment.ack != self.snd_nxt {
                return TcpResponse::silent();
            }
            self.remote_port = segment.src_port;
            if let Ok(options) = parse_options(segment.options) {
                self.peer_mss = options.mss.unwrap_or(DEFAULT_MSS).max(1);
            }
            self.snd_una = segment.ack;
            self.rcv_nxt = segment.seq.wrapping_add(1);
            // The ACK covers our SYN; stop retransmitting it.
            self.retransmit = None;
            self.state = TcpState::Established;
            return TcpResponse {
                send: Some(OutgoingSegment {
                    flags: FLAG_ACK,
                    seq: self.snd_nxt,
                    ack: self.rcv_nxt,
                    window: self.window,
                }),
                event: TcpEvent::Connected,
                accepted: false,
                drop: false,
            };
        }
        if segment.syn() {
            // Simultaneous open: acknowledge the SYN and wait for its ACK.
            self.remote_port = segment.src_port;
            self.rcv_nxt = segment.seq.wrapping_add(1);
            self.state = TcpState::SynReceived;
            return TcpResponse {
                send: Some(OutgoingSegment {
                    flags: FLAG_SYN | FLAG_ACK,
                    seq: self.isn,
                    ack: self.rcv_nxt,
                    window: self.window,
                }),
                event: TcpEvent::None,
                accepted: false,
                drop: false,
            };
        }
        TcpResponse::silent()
    }

    fn on_segment_synchronized(&mut self, segment: &TcpSegment<'_>, now: u64) -> TcpResponse {
        if segment.syn() {
            // Unexpected SYN in a synchronized state: reset (RFC 5961).
            return TcpResponse {
                send: Some(OutgoingSegment {
                    flags: FLAG_RST | FLAG_ACK,
                    seq: self.snd_nxt,
                    ack: self.rcv_nxt,
                    window: 0,
                }),
                event: TcpEvent::Reset,
                accepted: false,
                drop: false,
            };
        }

        let mut event = TcpEvent::None;
        // A FIN that `close` deferred because data was still unacknowledged.
        let mut deferred_fin: Option<OutgoingSegment> = None;
        // Acknowledgment processing.
        if segment.ack() {
            if seq_le(self.snd_una, segment.ack) && seq_le(segment.ack, self.snd_nxt) {
                let previous_una = self.snd_una;
                self.snd_una = segment.ack;
                if let Some(retransmit) = self.retransmit {
                    // A FIN occupies exactly one sequence number, while data
                    // occupies `len`. Acknowledging only the first byte of a
                    // FIN (`ack == seq`) must not complete the close.
                    let complete = if retransmit.len == 0 {
                        segment.ack == retransmit.seq.wrapping_add(1)
                    } else {
                        seq_le(retransmit.seq.wrapping_add(retransmit.len), segment.ack)
                    };
                    if complete {
                        self.retransmit = None;
                        if retransmit.len > 0 {
                            event = TcpEvent::DataAcknowledged;
                        }
                        self.advance_after_fin_ack();
                        if self.pending_close {
                            // The outstanding data is acknowledged, so the FIN
                            // that `close` deferred can leave with this response.
                            self.pending_close = false;
                            deferred_fin = Some(self.emit_fin(now));
                        }
                    }
                }
                // The passive-open handshake ACK must acknowledge our SYN
                // (`SND.UNA < ACK <= SND.NXT`, i.e. exactly ISN+1 here). An ACK
                // that only covers `isn` leaves the state in SYN-RECEIVED.
                if self.state == TcpState::SynReceived
                    && segment.ack == self.snd_nxt
                    && seq_lt(previous_una, segment.ack)
                {
                    self.state = TcpState::Established;
                    event = TcpEvent::Connected;
                }
            } else if seq_lt(self.snd_nxt, segment.ack) {
                if self.state == TcpState::SynReceived {
                    // RFC 793: an ACK beyond SND.NXT in SYN-RECEIVED is
                    // unacceptable and must be answered with a reset, not a
                    // plain ACK.
                    return TcpResponse {
                        send: Some(OutgoingSegment {
                            flags: FLAG_RST,
                            seq: segment.ack,
                            ack: 0,
                            window: 0,
                        }),
                        event: TcpEvent::None,
                        accepted: false,
                        drop: false,
                    };
                }
                return TcpResponse {
                    send: Some(OutgoingSegment {
                        flags: FLAG_ACK,
                        seq: self.snd_nxt,
                        ack: self.rcv_nxt,
                        window: self.window,
                    }),
                    event: TcpEvent::None,
                    accepted: false,
                    drop: false,
                };
            }
        }

        // A deferred FIN, if any, replaces the plain ACK in every reply below.
        let reply = move |conn: &TcpConnection| deferred_fin.unwrap_or_else(|| conn.ack_segment());

        // Payload acceptance: in order only (no reassembly in M7a). A single
        // segment may carry data *and* FIN, so acceptance falls through to the
        // FIN handling instead of returning early.
        let mut accepted = false;
        if !segment.payload.is_empty() {
            if segment.seq != self.rcv_nxt {
                // Duplicate or out-of-order: acknowledge what we do have. An
                // out-of-order FIN cannot be accepted either.
                return TcpResponse {
                    send: Some(reply(self)),
                    event: TcpEvent::None,
                    accepted: false,
                    drop: false,
                };
            }
            let len = segment.payload.len() as u32;
            self.rcv_nxt = self.rcv_nxt.wrapping_add(len);
            accepted = true;
            event = TcpEvent::Data(len);
        }

        // Peer FIN, possibly on the same segment as the data just accepted.
        if segment.fin() {
            let fin_seq = segment.seq.wrapping_add(segment.payload.len() as u32);
            if fin_seq == self.rcv_nxt {
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                match self.state {
                    TcpState::Established => self.state = TcpState::CloseWait,
                    TcpState::FinWait1 => self.state = TcpState::Closing,
                    TcpState::FinWait2 => self.state = TcpState::TimeWait,
                    TcpState::CloseWait
                    | TcpState::Closing
                    | TcpState::LastAck
                    | TcpState::TimeWait => {}
                    _ => {}
                }
                return TcpResponse {
                    send: Some(reply(self)),
                    event: TcpEvent::PeerFin,
                    accepted,
                    drop: false,
                };
            }
            return TcpResponse {
                send: Some(reply(self)),
                event,
                accepted,
                drop: false,
            };
        }

        TcpResponse {
            send: Some(reply(self)),
            event,
            accepted,
            drop: false,
        }
    }

    fn advance_after_fin_ack(&mut self) {
        match self.state {
            TcpState::FinWait1 => self.state = TcpState::FinWait2,
            TcpState::Closing => self.state = TcpState::TimeWait,
            TcpState::LastAck => self.state = TcpState::Closed,
            _ => {}
        }
    }

    fn ack_segment(&self) -> OutgoingSegment {
        OutgoingSegment {
            flags: FLAG_ACK,
            seq: self.snd_nxt,
            ack: self.rcv_nxt,
            window: self.window,
        }
    }
}

/// Terse alias so tests and callers can name the four-tuple ack shape.
pub type Ack = TcpResponse;

#[cfg(test)]
mod tests {
    use super::*;

    fn segment<'a>(seq: u32, ack: u32, flags: u8, payload: &'a [u8]) -> TcpSegment<'a> {
        TcpSegment {
            src_port: 4000,
            dst_port: 80,
            seq,
            ack,
            data_offset: 5,
            flags,
            window: 4096,
            checksum: 0,
            urgent: 0,
            options: &[],
            payload,
        }
    }

    #[test]
    fn header_round_trips_with_options() {
        let mut buffer = [0u8; 64];
        let options = [
            OPTION_MSS,
            4,
            0x05,
            0xB4,
            OPTION_NOP,
            OPTION_WINDOW_SCALE,
            3,
            7,
        ];
        let written = write_segment(
            &mut buffer,
            1234,
            80,
            0x0102_0304,
            0x0506_0708,
            FLAG_SYN | FLAG_ACK,
            4096,
            &options,
            &[0xAA, 0xBB],
        )
        .unwrap();
        assert_eq!(written, HEADER_LEN + 8 + 2);
        let segment = parse(&buffer[..written]).unwrap();
        assert_eq!(segment.header_len(), 28);
        assert_eq!(segment.src_port, 1234);
        assert_eq!(segment.dst_port, 80);
        assert_eq!(segment.seq, 0x0102_0304);
        assert_eq!(segment.ack, 0x0506_0708);
        assert!(segment.syn() && segment.ack());
        assert_eq!(segment.window, 4096);
        assert_eq!(segment.options, &options[..]);
        assert_eq!(segment.payload, &[0xAA, 0xBB]);
        let decoded = parse_options(segment.options).unwrap();
        assert_eq!(decoded.mss, Some(1460));
        assert_eq!(decoded.window_scale, Some(7));
    }

    #[test]
    fn header_length_is_validated() {
        assert_eq!(parse(&[0u8; 19]), Err(PacketError::Truncated));
        let mut buffer = [0u8; 20];
        buffer[12] = 4 << 4; // data offset 4
        assert_eq!(parse(&buffer), Err(PacketError::BadHeaderLength));
        buffer[12] = 15 << 4; // 60 > slice
        assert_eq!(parse(&buffer), Err(PacketError::Truncated));
    }

    #[test]
    fn checksum_is_verified_per_ip_version() {
        let mut buffer = [0u8; 32];
        let written = write_segment(
            &mut buffer,
            1,
            2,
            7,
            9,
            FLAG_ACK,
            1024,
            &[],
            &[0x11, 0x22, 0x33],
        )
        .unwrap();
        let src4 = Ipv4Addr::new(10, 0, 2, 15);
        let dst4 = Ipv4Addr::new(10, 0, 2, 2);
        fill_checksum_v4(&mut buffer, written, src4, dst4).unwrap();
        assert!(parse_checked_v4(&buffer[..written], src4, dst4).is_ok());
        // The pseudo-header sum is order independent, so a *different* address
        // (not a swap) is what must break the checksum.
        let other4 = Ipv4Addr::new(10, 0, 2, 3);
        assert_eq!(
            parse_checked_v4(&buffer[..written], other4, dst4),
            Err(PacketError::BadChecksum)
        );
        let src6 = Ipv6Addr::LOOPBACK;
        let dst6 = Ipv6Addr::LOOPBACK;
        fill_checksum_v6(&mut buffer, written, src6, dst6).unwrap();
        assert!(parse_checked_v6(&buffer[..written], src6, dst6).is_ok());
        buffer[written - 1] ^= 0x01;
        assert_eq!(
            parse_checked_v6(&buffer[..written], src6, dst6),
            Err(PacketError::BadChecksum)
        );
    }

    #[test]
    fn options_are_strictly_validated() {
        // MSS with the wrong length.
        assert_eq!(
            parse_options(&[OPTION_MSS, 3, 0x05, 0]),
            Err(PacketError::BadOptions)
        );
        // Window scale above the maximum.
        assert_eq!(
            parse_options(&[OPTION_WINDOW_SCALE, 3, 15, OPTION_END]),
            Err(PacketError::BadOptions)
        );
        // SACK permitted must not carry data.
        assert_eq!(
            parse_options(&[OPTION_SACK_PERMITTED, 3, 0, 0]),
            Err(PacketError::BadOptions)
        );
        // Timestamp must be exactly 10 bytes.
        assert_eq!(
            parse_options(&[OPTION_TIMESTAMP, 9, 0, 0, 0, 0, 0, 0, 0]),
            Err(PacketError::BadOptions)
        );
        // Unknown option with length >= 2 is skipped by its length.
        let decoded = parse_options(&[200, 4, 1, 2, OPTION_END, 0, 0, 0]).unwrap();
        assert_eq!(decoded, TcpOptions::default());
        // Truncated TLV.
        assert_eq!(parse_options(&[OPTION_MSS, 4]), Err(PacketError::Truncated));
        // Too many TLVs.
        let mut many = [OPTION_NOP; 9];
        assert_eq!(parse_options(&many), Err(PacketError::BadOptions));
        many[8] = OPTION_END;
        assert!(parse_options(&many).is_ok());
    }

    #[test]
    fn write_header_rejects_bad_options_and_short_buffers() {
        let mut out = [0u8; 64];
        assert_eq!(
            write_header(&mut out, 1, 2, 0, 0, FLAG_SYN, 1, &[OPTION_MSS, 3, 0]),
            Err(PacketError::BadOptions)
        );
        let mut short = [0u8; 20];
        assert_eq!(
            write_segment(&mut short, 1, 2, 0, 0, FLAG_SYN, 1, &[], &[0u8; 1]),
            Err(PacketError::Truncated)
        );
    }

    #[test]
    fn sequence_comparisons_wrap() {
        assert!(seq_lt(4_294_967_294, 1));
        assert!(!seq_lt(1, 4_294_967_294));
        assert!(seq_lt(0, 1));
        assert!(seq_le(5, 5));
        assert!(!seq_le(6, 5));
        assert!(seq_between(10, 9, 4));
        assert!(seq_between(4_294_967_295, 4_294_967_294, 4));
        assert!(!seq_between(2, 4_294_967_294, 4));
        assert!(!seq_between(1, 1, 0));
        assert!(seq_in_window(4_294_967_295, 4_294_967_294, 16));
    }

    #[test]
    fn passive_open_and_handshake() {
        let mut connection = TcpConnection::new();
        connection.listen(80);
        assert_eq!(connection.state(), TcpState::Listen);

        let syn = segment(1000, 0, FLAG_SYN, &[]);
        let response = connection.on_segment(&syn, 0);
        let out = response.send.unwrap();
        assert_eq!(out.flags, FLAG_SYN | FLAG_ACK);
        assert_eq!(out.seq, DEFAULT_ISN);
        assert_eq!(out.ack, 1001);
        assert_eq!(connection.state(), TcpState::SynReceived);

        let ack = segment(1001, DEFAULT_ISN.wrapping_add(1), FLAG_ACK, &[]);
        let response = connection.on_segment(&ack, 0);
        assert_eq!(response.event, TcpEvent::Connected);
        assert_eq!(connection.state(), TcpState::Established);
        assert_eq!(connection.rcv_nxt(), 1001);
    }

    #[test]
    fn active_open_and_handshake() {
        let mut connection = TcpConnection::new();
        let syn = connection.connect(50000, 80, 4242, 0);
        assert_eq!(syn.flags, FLAG_SYN);
        assert_eq!(syn.seq, 4242);
        assert_eq!(connection.state(), TcpState::SynSent);

        let syn_ack = segment(9000, 4243, FLAG_SYN | FLAG_ACK, &[]);
        let response = connection.on_segment(&syn_ack, 0);
        let out = response.send.unwrap();
        assert_eq!(out.flags, FLAG_ACK);
        assert_eq!(out.ack, 9001);
        assert_eq!(response.event, TcpEvent::Connected);
        assert_eq!(connection.state(), TcpState::Established);
        // A wrong ACK in SynSent is dropped.
        let mut other = TcpConnection::new();
        other.connect(50000, 80, 4242, 0);
        assert!(
            other
                .on_segment(&segment(9000, 1, FLAG_SYN | FLAG_ACK, &[]), 0)
                .drop
        );
    }

    #[test]
    fn established_data_ack_and_duplicates() {
        let mut connection = established();
        let first = connection.on_segment(&segment(1001, DEFAULT_ISN + 1, FLAG_ACK, &[1, 2, 3]), 0);
        assert!(first.accepted);
        assert_eq!(first.event, TcpEvent::Data(3));
        assert_eq!(first.send.unwrap().ack, 1004);
        assert_eq!(connection.rcv_nxt(), 1004);

        // Duplicate bytes are rejected but acknowledged.
        let duplicate =
            connection.on_segment(&segment(1001, DEFAULT_ISN + 1, FLAG_ACK, &[1, 2, 3]), 0);
        assert!(!duplicate.accepted);
        assert_eq!(duplicate.send.unwrap().ack, 1004);
        assert_eq!(connection.rcv_nxt(), 1004);

        // Out-of-order bytes are rejected and acknowledged with the current rcv_nxt.
        let hole = connection.on_segment(&segment(1006, DEFAULT_ISN + 1, FLAG_ACK, &[9]), 0);
        assert!(!hole.accepted);
        assert_eq!(hole.send.unwrap().ack, 1004);
        assert_eq!(connection.rcv_nxt(), 1004);

        // Acknowledgement of our outstanding data clears the retransmit entry.
        let seq = connection.send(10, 0).unwrap();
        let ack = connection.on_segment(&segment(1007, seq.wrapping_add(10), FLAG_ACK, &[]), 0);
        assert_eq!(ack.event, TcpEvent::DataAcknowledged);
        assert!(!connection.retransmit_pending());
        assert_eq!(connection.snd_una(), seq.wrapping_add(10));
    }

    #[test]
    fn fin_paths_through_close_wait_and_last_ack() {
        let mut connection = established();
        let response =
            connection.on_segment(&segment(1001, DEFAULT_ISN + 1, FLAG_FIN | FLAG_ACK, &[]), 0);
        assert_eq!(response.event, TcpEvent::PeerFin);
        assert_eq!(connection.state(), TcpState::CloseWait);
        assert_eq!(connection.rcv_nxt(), 1002);
        let fin = connection.close(0).unwrap();
        assert_eq!(fin.flags, FLAG_FIN | FLAG_ACK);
        assert_eq!(connection.state(), TcpState::LastAck);
        // Acknowledging our FIN completes the connection.
        let response =
            connection.on_segment(&segment(1002, fin.seq.wrapping_add(1), FLAG_ACK, &[]), 0);
        assert_eq!(response.event, TcpEvent::None);
        assert_eq!(connection.state(), TcpState::Closed);
    }

    #[test]
    fn active_close_reaches_time_wait() {
        let mut connection = established();
        let fin = connection.close(0).unwrap();
        assert_eq!(connection.state(), TcpState::FinWait1);
        let acked =
            connection.on_segment(&segment(1001, fin.seq.wrapping_add(1), FLAG_ACK, &[]), 0);
        assert!(acked.send.is_some());
        assert_eq!(connection.state(), TcpState::FinWait2);
        let peer_fin = connection.on_segment(
            &segment(1001, fin.seq.wrapping_add(1), FLAG_FIN | FLAG_ACK, &[]),
            0,
        );
        assert_eq!(peer_fin.event, TcpEvent::PeerFin);
        assert_eq!(connection.state(), TcpState::TimeWait);
    }

    #[test]
    fn reset_handling_depends_on_state() {
        let mut listening = TcpConnection::new();
        listening.listen(80);
        assert!(listening.on_segment(&segment(1, 0, FLAG_RST, &[]), 0).drop);
        assert_eq!(listening.state(), TcpState::Listen);

        let mut connection = established();
        let response = connection.on_segment(&segment(1001, 0, FLAG_RST, &[]), 0);
        assert_eq!(response.event, TcpEvent::Reset);
        assert_eq!(connection.state(), TcpState::Closed);
    }

    #[test]
    fn unexpected_syn_resets_an_established_connection() {
        let mut connection = established();
        let response = connection.on_segment(&segment(5000, 0, FLAG_SYN, &[]), 0);
        let out = response.send.unwrap();
        assert_eq!(out.flags & FLAG_RST, FLAG_RST);
        assert_eq!(response.event, TcpEvent::Reset);
    }

    #[test]
    fn retransmission_backs_off_and_gives_up() {
        let mut connection = established();
        connection.send(100, 1_000).unwrap();
        // Before the deadline: nothing to do.
        let tick = connection.on_tick(1_000 + INITIAL_RTO_TICKS - 1);
        assert!(!tick.retransmit && !tick.give_up);
        // At the deadline: retransmit once; the next deadline is now + 200.
        let tick = connection.on_tick(1_000 + INITIAL_RTO_TICKS);
        assert!(tick.retransmit && !tick.give_up);
        let second_deadline = 1_000 + INITIAL_RTO_TICKS + INITIAL_RTO_TICKS;
        let tick = connection.on_tick(second_deadline - 1);
        assert!(!tick.retransmit);
        let tick = connection.on_tick(second_deadline);
        assert!(tick.retransmit && !tick.give_up);
        // Keep timing out until the state machine gives up.
        let mut now = second_deadline;
        let mut gave_up = false;
        for _ in 0..10 {
            now += MAX_RTO_TICKS;
            let tick = connection.on_tick(now);
            if tick.give_up {
                gave_up = true;
                break;
            }
        }
        assert!(gave_up);
        assert_eq!(connection.state(), TcpState::Closed);
        assert!(!connection.retransmit_pending());
    }

    #[test]
    fn send_requires_an_open_connection_and_a_free_slot() {
        let mut connection = TcpConnection::new();
        assert_eq!(connection.send(1, 0), Err(PacketError::Unsupported));
        let mut connection = established();
        connection.send(5, 0).unwrap();
        assert_eq!(connection.send(5, 0), Err(PacketError::OutOfRange));
        assert_eq!(connection.send(0, 0), Err(PacketError::OutOfRange));
    }

    fn established() -> TcpConnection {
        let mut connection = TcpConnection::new();
        connection.listen(80);
        connection.on_segment(&segment(1000, 0, FLAG_SYN, &[]), 0);
        connection.on_segment(
            &segment(1001, DEFAULT_ISN.wrapping_add(1), FLAG_ACK, &[]),
            0,
        );
        connection
    }

    #[test]
    fn passive_open_requires_an_ack_that_covers_the_syn() {
        let mut connection = TcpConnection::new();
        connection.listen(80);
        connection.on_segment(&segment(1000, 0, FLAG_SYN, &[]), 0);
        assert_eq!(connection.state(), TcpState::SynReceived);

        // An ACK that only repeats `isn` acknowledges nothing new and must
        // leave the connection in SYN-RECEIVED.
        let weak = connection.on_segment(&segment(1001, DEFAULT_ISN, FLAG_ACK, &[]), 0);
        assert_ne!(weak.event, TcpEvent::Connected);
        assert_eq!(connection.state(), TcpState::SynReceived);

        // The ACK that covers our SYN (isn + 1) completes the handshake.
        let strong = connection.on_segment(
            &segment(1001, DEFAULT_ISN.wrapping_add(1), FLAG_ACK, &[]),
            0,
        );
        assert_eq!(strong.event, TcpEvent::Connected);
        assert_eq!(connection.state(), TcpState::Established);
    }

    #[test]
    fn fin_acknowledgment_requires_the_fin_sequence_number() {
        let mut connection = established();
        let fin = connection.close(0).unwrap();
        assert_eq!(connection.state(), TcpState::FinWait1);

        // ACK of the FIN's own sequence number is not enough: the FIN occupies
        // one sequence number, so the state stays in FIN-WAIT-1.
        let partial = connection.on_segment(&segment(1001, fin.seq, FLAG_ACK, &[]), 0);
        assert!(partial.send.is_some());
        assert_eq!(connection.state(), TcpState::FinWait1);

        // ACK of fin.seq + 1 completes the close.
        connection.on_segment(&segment(1001, fin.seq.wrapping_add(1), FLAG_ACK, &[]), 0);
        assert_eq!(connection.state(), TcpState::FinWait2);
    }

    #[test]
    fn data_and_fin_in_one_segment_are_both_consumed() {
        let mut connection = established();
        let response = connection.on_segment(
            &segment(
                1001,
                DEFAULT_ISN.wrapping_add(1),
                FLAG_FIN | FLAG_ACK,
                &[7, 8, 9],
            ),
            0,
        );
        assert!(response.accepted);
        assert_eq!(response.event, TcpEvent::PeerFin);
        assert_eq!(connection.state(), TcpState::CloseWait);
        // Three payload bytes plus the FIN itself.
        assert_eq!(connection.rcv_nxt(), 1005);
        assert_eq!(response.send.unwrap().ack, 1005);
    }

    #[test]
    fn active_open_retransmits_the_syn_and_eventually_gives_up() {
        let mut connection = TcpConnection::new();
        let syn = connection.connect(4000, 80, 1000, 0);
        assert_eq!(syn.flags, FLAG_SYN);
        assert_eq!(syn.seq, 1000);
        assert_eq!(connection.state(), TcpState::SynSent);
        assert!(connection.retransmit_pending());

        // Nothing happens before the first deadline.
        assert!(!connection.on_tick(INITIAL_RTO_TICKS - 1).retransmit);
        // At the deadline the SYN is retransmitted.
        let tick = connection.on_tick(INITIAL_RTO_TICKS);
        assert!(tick.retransmit && !tick.give_up);

        // Backoff: the next deadline sits a further two RTOs out.
        let second = INITIAL_RTO_TICKS * 2;
        assert!(!connection.on_tick(second - 1).retransmit);
        assert!(connection.on_tick(second).retransmit);

        let mut now = second;
        let mut gave_up = false;
        for _ in 0..10 {
            now += MAX_RTO_TICKS;
            if connection.on_tick(now).give_up {
                gave_up = true;
                break;
            }
        }
        assert!(gave_up);
        assert_eq!(connection.state(), TcpState::Closed);
        assert!(!connection.retransmit_pending());
    }

    #[test]
    fn syn_acknowledgement_stops_the_syn_retransmission() {
        let mut connection = TcpConnection::new();
        connection.connect(4000, 80, 1000, 0);
        let response = connection.on_segment(&segment(5000, 1001, FLAG_SYN | FLAG_ACK, &[]), 0);
        assert_eq!(response.event, TcpEvent::Connected);
        assert_eq!(connection.state(), TcpState::Established);
        assert!(!connection.retransmit_pending());
    }

    #[test]
    fn close_defers_fin_until_outstanding_data_is_acknowledged() {
        let mut connection = established();
        let seq = connection.send(4, 0).unwrap();
        assert!(connection.retransmit_pending());

        // `close` must not overwrite the data retransmission record.
        assert!(connection.close(0).is_none());
        assert_eq!(connection.state(), TcpState::Established);
        assert!(connection.retransmit_pending());

        // The data is still retransmitted when the RTO expires.
        let tick = connection.on_tick(INITIAL_RTO_TICKS);
        assert!(tick.retransmit && !tick.give_up);

        // As soon as the data is acknowledged the FIN leaves with that reply.
        let ack_seq = seq.wrapping_add(4);
        let response =
            connection.on_segment(&segment(1001, ack_seq, FLAG_ACK, &[]), INITIAL_RTO_TICKS);
        let fin = response.send.expect("the deferred FIN must be transmitted");
        assert_eq!(fin.flags, FLAG_FIN | FLAG_ACK);
        assert_eq!(fin.seq, ack_seq);
        assert_eq!(connection.state(), TcpState::FinWait1);
        assert!(connection.retransmit_pending());

        // Acknowledging the FIN completes the first half of the close.
        connection.on_segment(
            &segment(1001, ack_seq.wrapping_add(1), FLAG_ACK, &[]),
            INITIAL_RTO_TICKS,
        );
        assert_eq!(connection.state(), TcpState::FinWait2);
        assert!(!connection.retransmit_pending());
    }

    #[test]
    fn abandoned_connection_does_not_send_a_deferred_fin() {
        let mut connection = established();
        connection.send(4, 0).unwrap();
        assert!(connection.close(0).is_none());

        let mut now = 0;
        let mut gave_up = false;
        for _ in 0..16 {
            now += MAX_RTO_TICKS;
            if connection.on_tick(now).give_up {
                gave_up = true;
                break;
            }
        }
        assert!(gave_up);
        assert_eq!(connection.state(), TcpState::Closed);
        assert!(!connection.retransmit_pending());

        // A late ACK for the abandoned data must not resurrect a FIN.
        let response = connection.on_segment(
            &segment(1001, DEFAULT_ISN.wrapping_add(5), FLAG_ACK, &[]),
            now,
        );
        assert!(response.send.is_none());
    }

    #[test]
    fn synchronized_reset_requires_an_in_window_sequence() {
        let mut connection = established();
        let window = u32::from(connection.window);
        let outside = connection.rcv_nxt().wrapping_add(window).wrapping_add(4);
        let response = connection.on_segment(&segment(outside, 0, FLAG_RST, &[]), 0);
        assert!(response.send.is_none());
        assert_eq!(response.event, TcpEvent::None);
        assert_eq!(connection.state(), TcpState::Established);

        let response = connection.on_segment(&segment(connection.rcv_nxt(), 0, FLAG_RST, &[]), 0);
        assert_eq!(response.event, TcpEvent::Reset);
        assert_eq!(connection.state(), TcpState::Closed);
    }

    #[test]
    fn syn_received_answers_an_ack_beyond_snd_nxt_with_a_reset() {
        let mut connection = TcpConnection::new();
        connection.listen(80);
        connection.on_segment(&segment(1000, 0, FLAG_SYN, &[]), 0);
        assert_eq!(connection.state(), TcpState::SynReceived);

        let beyond = connection.snd_nxt().wrapping_add(10);
        let response = connection.on_segment(&segment(1001, beyond, FLAG_ACK, &[]), 0);
        let reset = response.send.expect("an unacceptable ACK must be reset");
        assert_eq!(reset.flags, FLAG_RST);
        assert_eq!(reset.seq, beyond);
        assert_eq!(reset.ack, 0);
        assert_eq!(connection.state(), TcpState::SynReceived);
    }
}
