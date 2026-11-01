//! Socket identity, address and fixed-capacity buffer types for the loopback
//! stack.
//!
//! Everything in this file is plain data with `const fn` constructors: the
//! table logic and the protocol handling live in [`super`]. The types are kept
//! here so the stack, the host tests and the future socket object layer agree
//! on one definition of "endpoint", "socket id" and "error".
//!
//! No allocation is involved and every buffer is a fixed-size array, so the
//! whole socket layer is a set of `static` tables (agents.md §21, §7.3: no
//! unbounded kernel queues).

use netcore::{Ipv4Addr, Ipv6Addr, OutgoingSegment, TcpConnection, TcpState, tcp};

use crate::object::ObjectId;

// ---------------------------------------------------------------------------
// Fixed budgets (agents.md §2.3, §11.2: bounded queues, no heap)
// ---------------------------------------------------------------------------

/// Sockets reachable from the socket API (a socket id names one of these).
pub const MAX_SOCKETS: usize = 16;

/// Concurrent TCP connections, including listeners (M7a budget).
pub const MAX_TCP_CONNECTIONS: usize = MAX_SOCKETS;

/// Queued datagrams per bound UDP socket.
pub const UDP_QUEUE_DEPTH: usize = 4;

/// Largest UDP payload a single datagram may carry.
pub const UDP_DGRAM_MAX: usize = 512;

/// Bytes buffered on the receive side of a TCP connection.
pub const TCP_RX_BYTES: usize = 4_096;

/// Bytes in the one unacknowledged outgoing TCP segment.
pub const TCP_TX_SEG_MAX: usize = 1_024;

/// Largest pending-connection backlog a listener may request (M4).
pub const MAX_BACKLOG: usize = 64;

/// Pending connections a TCP listener holds before refusing the handshake.
pub const TCP_BACKLOG: usize = MAX_BACKLOG;

/// First ephemeral port picked for an active TCP open.
pub const EPHEMERAL_PORT_FIRST: u16 = 49_152;

/// Largest frame the loopback path builds (IPv6 40 + TCP 60 + payload).
pub const MAX_FRAME_BYTES: usize = 1_536;

/// Socket domains understood by the M7b front-end.
pub const DOMAIN_UNIX: u32 = 1;
/// IPv4 socket domain.
pub const DOMAIN_INET: u32 = 2;
/// IPv6 socket domain.
pub const DOMAIN_INET6: u32 = 10;

/// Socket kinds understood by the M7b front-end.
pub const SOCK_STREAM: u32 = 1;
/// Datagram socket kind.
pub const SOCK_DGRAM: u32 = 2;

/// Network namespaces tracked by the path-binding tables.
pub const MAX_NAMESPACES: usize = 2;

/// Path bindings per namespace (fixed budget, agents.md §11.2).
pub const MAX_BINDINGS_PER_NAMESPACE: usize = 8;

/// Capacity of a UNIX path field (matches the Linux `sun_path` size).
pub const SOCKET_PATH_BYTES: usize = 108;

/// Longest `AF_UNIX` path accepted by the M7b engine (the field keeps a byte
/// spare so the accepted length can never fill the whole array).
pub const SOCKET_PATH_MAX: usize = SOCKET_PATH_BYTES - 1;

/// Bytes buffered in each direction of a local stream socket.
pub const LOCAL_STREAM_BYTES: usize = 4_096;

/// Queued datagrams per direction of a local datagram socket.
pub const LOCAL_DGRAM_DEPTH: usize = 4;

/// Largest payload a local datagram socket accepts.
pub const LOCAL_DGRAM_MAX: usize = 512;

/// Static capacity of one local listener's accept queue (M4: bounded, but the
/// per-listener limit the caller asked for decides how much of it is usable).
pub const LOCAL_BACKLOG: usize = MAX_BACKLOG;

/// Maximum file descriptors one UNIX message may carry (`SCM_RIGHTS`).
///
/// Matches the fixed `objects` field of [`StreamAncillary`] and a queued
/// [`LocalDatagramEntry`]; a message with more descriptors is refused with
/// [`NetError::Unsupported`] so the caller can map it to `EMSGSIZE`.
pub const MAX_SCM_FDS: usize = 4;

/// Ancillary records buffered per stream direction.
///
/// One record is queued per send that carries descriptors or credentials, so
/// this bounds how far a sender may run ahead with ancillary data before the
/// stream applies back-pressure.
pub const LOCAL_ANCILLARY_DEPTH: usize = 4;

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

/// IP address of the loopback interface (family only: the M7a loopback
/// interface has both `127.0.0.1` and `::1`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IpAddr {
    /// IPv4 address.
    V4(Ipv4Addr),
    /// IPv6 address.
    V6(Ipv6Addr),
}

/// The IPv4 loopback address `127.0.0.1`.
pub const LOOPBACK_V4: IpAddr = IpAddr::V4(Ipv4Addr::LOOPBACK);
/// The IPv6 loopback address `::1`.
pub const LOOPBACK_V6: IpAddr = IpAddr::V6(Ipv6Addr::LOOPBACK);

impl IpAddr {
    /// The IPv4 loopback address `127.0.0.1`.
    pub const LOOPBACK_V4: IpAddr = IpAddr::V4(Ipv4Addr::LOOPBACK);
    /// The IPv6 loopback address `::1`.
    pub const LOOPBACK_V6: IpAddr = IpAddr::V6(Ipv6Addr::LOOPBACK);

    /// Whether this address belongs to the loopback interface.
    pub const fn is_loopback(self) -> bool {
        match self {
            IpAddr::V4(addr) => addr.is_loopback(),
            IpAddr::V6(addr) => addr.is_loopback(),
        }
    }

    /// Whether two addresses share an IP version.
    pub const fn same_family(self, other: IpAddr) -> bool {
        matches!(
            (self, other),
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
        )
    }
}

/// A transport-layer address: an IP address plus a port.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Endpoint {
    /// Address part.
    pub addr: IpAddr,
    /// Port part (host order, never zero in a bound endpoint).
    pub port: u16,
}

impl Endpoint {
    /// Build an endpoint.
    pub const fn new(addr: IpAddr, port: u16) -> Endpoint {
        Endpoint { addr, port }
    }

    /// IPv4 loopback endpoint.
    pub const fn v4(port: u16) -> Endpoint {
        Endpoint::new(IpAddr::LOOPBACK_V4, port)
    }

    /// IPv6 loopback endpoint.
    pub const fn v6(port: u16) -> Endpoint {
        Endpoint::new(IpAddr::LOOPBACK_V6, port)
    }
}

/// Transport protocol served by the loopback stack.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Protocol {
    /// Connectionless datagrams.
    Udp,
    /// Byte stream with the `netcore` state machine.
    Tcp,
}

/// Description used by `bind`/`listen`/`connect`.
///
/// `local` is optional for an active open (the stack picks an ephemeral port),
/// `remote` is required only by `connect`. The protocol plus the family picked
/// from `local`/`remote` decide which table the socket goes into.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SocketKey {
    /// Requested local endpoint (`None` = let the stack choose for `connect`).
    pub local: Option<Endpoint>,
    /// Requested remote endpoint for an active TCP open.
    pub remote: Option<Endpoint>,
    /// Protocol to create.
    pub protocol: Protocol,
}

impl SocketKey {
    /// A passive socket bound to `local`.
    pub const fn bind(local: Endpoint, protocol: Protocol) -> SocketKey {
        SocketKey {
            local: Some(local),
            remote: None,
            protocol,
        }
    }

    /// An active TCP open to `remote` with an ephemeral local port.
    pub const fn connect(remote: Endpoint) -> SocketKey {
        SocketKey {
            local: None,
            remote: Some(remote),
            protocol: Protocol::Tcp,
        }
    }

    /// An active TCP open from an explicit local endpoint.
    pub const fn connect_from(local: Endpoint, remote: Endpoint) -> SocketKey {
        SocketKey {
            local: Some(local),
            remote: Some(remote),
            protocol: Protocol::Tcp,
        }
    }
}

// ---------------------------------------------------------------------------
// Socket ids and errors
// ---------------------------------------------------------------------------

/// Stable, generation-tagged socket handle.
///
/// A slot is reused only with a new generation, so an id kept by a closed
/// socket never resolves to its successor (ABA protection).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SocketId {
    slot: u8,
    generation: u16,
}

impl SocketId {
    /// A placeholder that never resolves.
    pub const INVALID: SocketId = SocketId {
        slot: u8::MAX,
        generation: 0,
    };

    /// Pack a slot index and its generation.
    pub const fn new(slot: usize, generation: u16) -> SocketId {
        SocketId {
            slot: slot as u8,
            generation,
        }
    }

    /// Slot index, `None` for [`SocketId::INVALID`].
    pub const fn slot(self) -> Option<usize> {
        if self.slot as usize >= MAX_SOCKETS {
            None
        } else {
            Some(self.slot as usize)
        }
    }

    /// Generation stamp of the slot.
    pub const fn generation(self) -> u16 {
        self.generation
    }

    /// Wire representation (used by diagnostics in tests).
    pub const fn raw(self) -> u32 {
        ((self.slot as u32) << 16) | self.generation as u32
    }
}

/// Error type shared by the socket engine and the object front-end.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NetError {
    /// No free socket slot / TCP connection / queue entry.
    Quota,
    /// The operation would block; the caller must retry after a wake.
    WouldBlock,
    /// The id's slot is free or its generation is stale.
    InvalidSocket,
    /// The socket exists but the operation does not fit its state.
    NotConnected,
    /// The peer closed its direction (TCP `recv` returns EOF instead).
    PeerClosed,
    /// The connection was reset.
    Reset,
    /// The remote end refused the connection (no listener / RST in SYN-SENT).
    Refused,
    /// A deadline passed (retransmission gave up).
    Timeout,
    /// A malformed frame, bad checksum or unsupported feature.
    Malformed,
    /// A peer-controlled value cannot be represented.
    Unsupported,
    /// A local endpoint is already bound.
    AddressInUse,
    /// The requested path / namespace binding does not exist.
    NotFound,
    /// A zero port, wrong family or a non-loopback address was supplied.
    BadAddress,
    /// The buffer is too small for the requested payload.
    TooLarge,
}

impl NetError {
    /// Short static description, used by diagnostics and tests.
    pub const fn as_str(self) -> &'static str {
        match self {
            NetError::Quota => "net quota exhausted",
            NetError::WouldBlock => "net operation would block",
            NetError::InvalidSocket => "net socket id invalid",
            NetError::NotConnected => "net socket not connected",
            NetError::PeerClosed => "net peer closed",
            NetError::Reset => "net connection reset",
            NetError::Refused => "net connection refused",
            NetError::Timeout => "net timeout",
            NetError::Malformed => "net frame malformed",
            NetError::Unsupported => "net feature unsupported",
            NetError::AddressInUse => "net address in use",
            NetError::NotFound => "net binding not found",
            NetError::BadAddress => "net address invalid",
            NetError::TooLarge => "net payload too large",
        }
    }
}

// ---------------------------------------------------------------------------
// Readiness
// ---------------------------------------------------------------------------

/// Readiness bits returned by [`super::poll`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PollMask(u8);

impl PollMask {
    /// No readiness.
    pub const EMPTY: PollMask = PollMask(0);
    /// Data is available.
    pub const READ: PollMask = PollMask(0b0001);
    /// The socket accepts more data.
    pub const WRITE: PollMask = PollMask(0b0010);
    /// An error is pending.
    pub const ERROR: PollMask = PollMask(0b0100);

    /// Union of two masks.
    pub const fn union(self, other: PollMask) -> PollMask {
        PollMask(self.0 | other.0)
    }

    /// Whether `other` is fully contained in this mask.
    pub const fn contains(self, other: PollMask) -> bool {
        self.0 & other.0 == other.0
    }

    /// Raw bits.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether no bit is set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Single readiness transition reported to the object layer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ReadyEvent {
    /// Data or a connection can be read/accepted.
    Read,
    /// The socket can accept more data.
    Write,
    /// An error is pending.
    Error,
    /// The peer closed (TCP EOF / UDP peer gone).
    PeerClosed,
}

/// One pending wake notification, collected under the stack lock and delivered
/// only after it is released, so the hook may call [`crate::process`] safely.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WakeEvent {
    /// Socket whose readiness changed.
    pub socket: SocketId,
    /// What changed.
    pub event: ReadyEvent,
    /// `0` when the socket has no object attached yet (M7a-style unit tests);
    /// otherwise the object whose waiter has to be woken (M7b front-end).
    pub object: ObjectId,
}

impl WakeEvent {
    /// A wake for a socket without an attached object.
    pub const fn new(socket: SocketId, event: ReadyEvent) -> WakeEvent {
        WakeEvent {
            socket,
            event,
            object: 0,
        }
    }

    /// Attach the object id that owns the socket.
    pub const fn with_object(socket: SocketId, event: ReadyEvent, object: ObjectId) -> WakeEvent {
        WakeEvent {
            socket,
            event,
            object,
        }
    }
}

/// Wakes are called after the stack lock is released.
pub type WakeHook = fn(WakeEvent);

/// Maximum wake notifications buffered per public call.
pub const MAX_WAKE_EVENTS: usize = 8;

// ---------------------------------------------------------------------------
// Fixed-capacity buffers
// ---------------------------------------------------------------------------

/// One queued UDP datagram and the endpoint it came from.
#[derive(Clone, Copy)]
pub struct Datagram {
    length: u16,
    data: [u8; UDP_DGRAM_MAX],
    source: Endpoint,
}

impl Datagram {
    /// Empty place-holder.
    pub const fn empty() -> Datagram {
        Datagram {
            length: 0,
            data: [0; UDP_DGRAM_MAX],
            source: Endpoint::v4(0),
        }
    }

    /// Store `payload` as a datagram from `source`, or fail if too large.
    pub fn write(&mut self, payload: &[u8], source: Endpoint) -> Result<(), NetError> {
        if payload.len() > UDP_DGRAM_MAX {
            return Err(NetError::TooLarge);
        }
        self.data[..payload.len()].copy_from_slice(payload);
        self.length = payload.len() as u16;
        self.source = source;
        Ok(())
    }

    /// Payload length.
    pub fn len(&self) -> usize {
        usize::from(self.length)
    }

    /// Whether the datagram carries no payload.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Sender endpoint.
    pub fn source(&self) -> Endpoint {
        self.source
    }

    /// Copy the payload into `out`; `TooLarge` without consuming anything when
    /// the caller's buffer is too small.
    pub fn read_into(&self, out: &mut [u8]) -> Result<usize, NetError> {
        let len = self.len();
        if out.len() < len {
            return Err(NetError::TooLarge);
        }
        out[..len].copy_from_slice(&self.data[..len]);
        Ok(len)
    }
}

/// Bounded, FIFO datagram queue with back-pressure: a full queue rejects new
/// datagrams instead of dropping the oldest one (Lead m01303).
pub struct DatagramQueue {
    slots: [Option<Datagram>; UDP_QUEUE_DEPTH],
    head: u8,
    count: u8,
}

impl DatagramQueue {
    /// Empty queue.
    pub const fn new() -> DatagramQueue {
        DatagramQueue {
            slots: [None; UDP_QUEUE_DEPTH],
            head: 0,
            count: 0,
        }
    }

    /// Queued datagrams.
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Enqueue a copy of `payload`; `false` when the queue is full or the
    /// payload exceeds [`UDP_DGRAM_MAX`].
    pub fn push(&mut self, payload: &[u8], source: Endpoint) -> bool {
        if usize::from(self.count) >= UDP_QUEUE_DEPTH || payload.len() > UDP_DGRAM_MAX {
            return false;
        }
        let index = (usize::from(self.head) + usize::from(self.count)) % UDP_QUEUE_DEPTH;
        let mut datagram = Datagram::empty();
        if datagram.write(payload, source).is_err() {
            return false;
        }
        self.slots[index] = Some(datagram);
        self.count += 1;
        true
    }

    /// Copy the oldest datagram into `out` and consume it.
    pub fn pop(&mut self, out: &mut [u8]) -> Result<(usize, Endpoint), NetError> {
        let len = self.peek_len().ok_or(NetError::WouldBlock)?;
        if out.len() < len {
            return Err(NetError::TooLarge);
        }
        let index = usize::from(self.head);
        let datagram = self.slots[index].take().ok_or(NetError::WouldBlock)?;
        let copied = datagram.read_into(out)?;
        self.head = ((usize::from(self.head) + 1) % UDP_QUEUE_DEPTH) as u8;
        self.count -= 1;
        Ok((copied, datagram.source()))
    }

    /// Length of the oldest datagram without consuming it.
    pub fn peek_len(&self) -> Option<usize> {
        self.slots[usize::from(self.head)].map(|datagram| datagram.len())
    }

    /// Drop every queued datagram.
    pub fn clear(&mut self) {
        for slot in self.slots.iter_mut() {
            *slot = None;
        }
        self.head = 0;
        self.count = 0;
    }
}

impl Default for DatagramQueue {
    fn default() -> DatagramQueue {
        DatagramQueue::new()
    }
}

/// Fixed-size receive ring for one TCP connection.
pub struct TcpReceiveBuffer {
    data: [u8; TCP_RX_BYTES],
    head: u16,
    length: u16,
}

impl TcpReceiveBuffer {
    /// Empty buffer.
    pub const fn new() -> TcpReceiveBuffer {
        TcpReceiveBuffer {
            data: [0; TCP_RX_BYTES],
            head: 0,
            length: 0,
        }
    }

    /// Bytes currently buffered.
    pub fn len(&self) -> usize {
        usize::from(self.length)
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Free space in bytes.
    pub fn free(&self) -> usize {
        TCP_RX_BYTES - self.len()
    }

    /// Append bytes; `false` when they do not fit.
    pub fn push(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() > self.free() {
            return false;
        }
        let mut written = 0;
        while written < bytes.len() {
            let index =
                (usize::from(self.head) + usize::from(self.length) + written) % TCP_RX_BYTES;
            self.data[index] = bytes[written];
            written += 1;
        }
        self.length += bytes.len() as u16;
        true
    }

    /// Pop up to `out.len()` bytes and return the count.
    pub fn pop(&mut self, out: &mut [u8]) -> usize {
        let count = out.len().min(self.len());
        for byte in out.iter_mut().take(count) {
            *byte = self.data[usize::from(self.head)];
            self.head = ((usize::from(self.head) + 1) % TCP_RX_BYTES) as u16;
        }
        self.length -= count as u16;
        count
    }

    /// Drop everything buffered.
    pub fn clear(&mut self) {
        self.head = 0;
        self.length = 0;
    }
}

/// The one unacknowledged outgoing TCP segment kept for retransmission.
pub struct TcpSendBuffer {
    flags: u8,
    seq: u32,
    length: u16,
    data: [u8; TCP_TX_SEG_MAX],
}

impl TcpSendBuffer {
    /// Empty buffer.
    pub const fn new() -> TcpSendBuffer {
        TcpSendBuffer {
            flags: 0,
            seq: 0,
            length: 0,
            data: [0; TCP_TX_SEG_MAX],
        }
    }

    /// Remember a control segment (SYN / FIN / pure ACK) for retransmission.
    pub fn set_control(&mut self, flags: u8, seq: u32) {
        self.flags = flags;
        self.seq = seq;
        self.length = 0;
    }

    /// Remember a data segment for retransmission.
    pub fn set_data(&mut self, flags: u8, seq: u32, payload: &[u8]) -> Result<(), NetError> {
        if payload.len() > TCP_TX_SEG_MAX {
            return Err(NetError::TooLarge);
        }
        self.data[..payload.len()].copy_from_slice(payload);
        self.flags = flags;
        self.seq = seq;
        self.length = payload.len() as u16;
        Ok(())
    }

    /// Flags of the outstanding segment (`0` = nothing outstanding).
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Sequence number of the outstanding segment.
    pub fn seq(&self) -> u32 {
        self.seq
    }

    /// Payload of the outstanding segment.
    pub fn payload(&self) -> &[u8] {
        &self.data[..usize::from(self.length)]
    }

    /// Whether nothing is outstanding.
    pub fn is_empty(&self) -> bool {
        self.flags == 0
    }

    /// Forget the outstanding segment.
    pub fn clear(&mut self) {
        self.flags = 0;
        self.length = 0;
    }
}

// ---------------------------------------------------------------------------
// Socket payloads
// ---------------------------------------------------------------------------

/// A bound UDP socket.
pub struct UdpSocket {
    local: Endpoint,
    /// Receive queue, owned by the enclosing static [`NetStack`](super::NetStack)
    /// (indexed by socket slot). Keeping it out of this struct keeps
    /// `Option<UdpSocket>` small, so every constructor and table reset stays
    /// well inside the boot stack budget.
    queue: *mut DatagramQueue,
}

impl UdpSocket {
    /// A socket bound to `local`, using the static queue at `queue`.
    pub fn new(local: Endpoint, queue: *mut DatagramQueue) -> UdpSocket {
        // SAFETY: `queue` points at a `NetStack::udp_queues` element for this
        // slot and is always initialised; clearing it in place creates no stack
        // temporary and stops a rebound socket inheriting stale datagrams.
        unsafe { (*queue).clear() };
        UdpSocket { local, queue }
    }

    /// Local endpoint.
    pub fn local(&self) -> Endpoint {
        self.local
    }

    /// Point this socket at the queue that belongs to its (new) slot.
    pub fn set_queue(&mut self, queue: *mut DatagramQueue) {
        self.queue = queue;
    }

    /// Queue handle.
    pub fn queue(&self) -> &DatagramQueue {
        // SAFETY: `queue` points at a `NetStack::udp_queues` element that lives
        // as long as the socket and is only reached through this socket; the
        // whole stack is serialised by the `net` lock.
        unsafe { &*self.queue }
    }

    /// Mutable queue handle (the stack is the only user).
    pub fn queue_mut(&mut self) -> &mut DatagramQueue {
        // SAFETY: same invariant as [`UdpSocket::queue`]; `&mut self` makes the
        // access exclusive.
        unsafe { &mut *self.queue }
    }
}

/// A connection the listener has not accepted yet.
pub struct BacklogEntry {
    /// Connection state machine, cloned from the listener on its SYN.
    pub connection: TcpConnection,
    /// Peer endpoint of the pending connection.
    pub remote: Endpoint,
    /// Whether the three-way handshake completed.
    pub established: bool,
}

/// A TCP listener or connection.
pub struct TcpSocket {
    local: Endpoint,
    remote: Option<Endpoint>,
    /// `true` for a listening socket (its `connection` stays in `Listen`).
    listen: bool,
    connection: TcpConnection,
    /// Receive ring owned by the enclosing static `NetStack` (indexed by slot).
    /// Keeping the 4 KiB ring out of this struct keeps `Option<TcpSocket>` small,
    /// so constructors, adoptions and resets never build a big stack temporary.
    receive: *mut TcpReceiveBuffer,
    /// Outstanding-segment buffer owned by the static `NetStack` (same reason).
    send: *mut TcpSendBuffer,
    /// Backlog storage owned by the enclosing static `NetStack`, not inline in
    /// this socket. Keeping it out of the struct avoids large stack temporaries.
    backlog: *mut Option<BacklogEntry>,
    backlog_len: u8,
    peer_fin: bool,
    error: bool,
    closing: bool,
    /// Last advertised window was zero (waiting to announce a reopen).
    zero_window: bool,
    /// Local read shutdown (further `recv` reports `NotConnected`).
    read_shut: bool,
    /// Local write shutdown (further `send` reports `NotConnected`).
    write_shut: bool,
    /// The active open was refused (`RST` in SYN-SENT, or no listener at all).
    refused: bool,
    /// Pending connections this listener accepts (clamped to the static queue).
    backlog_limit: u16,
}

impl TcpSocket {
    /// Reset the external storage a fresh socket will use and return the
    /// pointers it keeps.
    ///
    /// The pointers come from the enclosing static `NetStack` pools; they are
    /// always initialised and only reachable through this socket, so no
    /// temporary of the payload type is ever built on the stack.
    fn initialise_storage(
        backlog: *mut Option<BacklogEntry>,
        receive: *mut TcpReceiveBuffer,
        send: *mut TcpSendBuffer,
    ) {
        for index in 0..TCP_BACKLOG {
            // SAFETY: all constructors receive a pointer into the static
            // `NetStack::tcp_backlogs` array, which remains alive for the
            // lifetime of the socket.
            unsafe { backlog.add(index).write(None) };
        }
        // SAFETY: the buffers belong to the slot this socket is being built in
        // and may hold the previous occupant's bytes; clearing them in place
        // creates no stack temporary.
        unsafe {
            (*receive).clear();
            (*send).clear();
        }
    }

    /// Initialise a fresh listener directly in its static table slot.
    ///
    /// Returning a `TcpSocket` by value creates a >10 KiB temporary in debug
    /// builds; writing the `Option` in place keeps the M7a boot-stack budget.
    pub fn listener_into(
        slot: &mut Option<TcpSocket>,
        backlog: *mut Option<BacklogEntry>,
        receive: *mut TcpReceiveBuffer,
        send: *mut TcpSendBuffer,
        local: Endpoint,
    ) {
        debug_assert!(slot.is_none());
        Self::initialise_storage(backlog, receive, send);
        let mut connection = TcpConnection::new();
        connection.listen_with_isn(local.port, tcp::DEFAULT_ISN);
        // SAFETY: the caller reserved this empty static slot; no old value is
        // overwritten and the resulting `Some` is fully initialised.
        unsafe {
            core::ptr::write(
                slot,
                Some(TcpSocket {
                    local,
                    remote: None,
                    listen: true,
                    connection,
                    receive,
                    send,
                    backlog,
                    backlog_len: 0,
                    peer_fin: false,
                    error: false,
                    closing: false,
                    zero_window: false,
                    read_shut: false,
                    write_shut: false,
                    refused: false,
                    backlog_limit: TCP_BACKLOG as u16,
                }),
            );
        }
    }

    /// Initialise an active open in place and return the SYN to transmit.
    pub fn connecting_into(
        slot: &mut Option<TcpSocket>,
        backlog: *mut Option<BacklogEntry>,
        receive: *mut TcpReceiveBuffer,
        send: *mut TcpSendBuffer,
        local: Endpoint,
        remote: Endpoint,
        isn: u32,
    ) -> OutgoingSegment {
        debug_assert!(slot.is_none());
        Self::initialise_storage(backlog, receive, send);
        let mut connection = TcpConnection::new();
        let syn = connection.connect(local.port, remote.port, isn, 0);
        // SAFETY: same empty-slot invariant as `listener_into`.
        unsafe {
            core::ptr::write(
                slot,
                Some(TcpSocket {
                    local,
                    remote: Some(remote),
                    listen: false,
                    connection,
                    receive,
                    send,
                    backlog,
                    backlog_len: 0,
                    peer_fin: false,
                    error: false,
                    closing: false,
                    zero_window: false,
                    read_shut: false,
                    write_shut: false,
                    refused: false,
                    backlog_limit: 0,
                }),
            );
        }
        syn
    }

    /// Initialise a connection handed over by `accept` directly in its slot.
    ///
    /// The backlog may already have consumed the peer's FIN while the handshake
    /// completed: seed `peer_fin` from the state machine so the accepted socket
    /// still reports EOF instead of blocking forever (Lead M7a review fix 2).
    pub fn accepted_into(
        slot: &mut Option<TcpSocket>,
        backlog: *mut Option<BacklogEntry>,
        receive: *mut TcpReceiveBuffer,
        send: *mut TcpSendBuffer,
        local: Endpoint,
        remote: Endpoint,
        connection: TcpConnection,
    ) {
        debug_assert!(slot.is_none());
        Self::initialise_storage(backlog, receive, send);
        let peer_fin = matches!(
            connection.state(),
            TcpState::CloseWait
                | TcpState::LastAck
                | TcpState::Closing
                | TcpState::TimeWait
                | TcpState::Closed
        );
        // SAFETY: same empty-slot invariant as `listener_into`.
        unsafe {
            core::ptr::write(
                slot,
                Some(TcpSocket {
                    local,
                    remote: Some(remote),
                    listen: false,
                    connection,
                    receive,
                    send,
                    backlog,
                    backlog_len: 0,
                    peer_fin,
                    error: false,
                    closing: false,
                    zero_window: false,
                    read_shut: false,
                    write_shut: false,
                    refused: false,
                    backlog_limit: 0,
                }),
            );
        }
    }

    /// Re-point the external storage after the socket moved to another slot.
    pub fn retarget_storage(
        &mut self,
        backlog: *mut Option<BacklogEntry>,
        receive: *mut TcpReceiveBuffer,
        send: *mut TcpSendBuffer,
    ) {
        self.backlog = backlog;
        self.receive = receive;
        self.send = send;
    }

    /// Local endpoint.
    pub fn local(&self) -> Endpoint {
        self.local
    }

    /// Remote endpoint, once connected/listening-target known.
    pub fn remote(&self) -> Option<Endpoint> {
        self.remote
    }

    /// Override the remote endpoint (used when accepting from the backlog).
    pub fn set_remote(&mut self, remote: Endpoint) {
        self.remote = Some(remote);
    }

    /// Whether this socket is a listener.
    pub fn is_listener(&self) -> bool {
        self.listen
    }

    /// State machine handle.
    pub fn connection(&self) -> &TcpConnection {
        &self.connection
    }

    /// Mutable state machine handle.
    pub fn connection_mut(&mut self) -> &mut TcpConnection {
        &mut self.connection
    }

    /// Receive buffer.
    pub fn receive(&self) -> &TcpReceiveBuffer {
        // SAFETY: `receive` points at a `NetStack::tcp_receive` element owned by
        // this socket's slot; the whole stack is serialised by the `net` lock.
        unsafe { &*self.receive }
    }

    /// Mutable receive buffer.
    pub fn receive_mut(&mut self) -> &mut TcpReceiveBuffer {
        // SAFETY: same invariant as [`TcpSocket::receive`]; `&mut self` makes the
        // access exclusive.
        unsafe { &mut *self.receive }
    }

    /// Outstanding outgoing segment.
    pub fn send(&self) -> &TcpSendBuffer {
        // SAFETY: `send` points at a `NetStack::tcp_send` element owned by this
        // socket's slot.
        unsafe { &*self.send }
    }

    /// Mutable outstanding outgoing segment.
    pub fn send_mut(&mut self) -> &mut TcpSendBuffer {
        // SAFETY: same invariant as [`TcpSocket::send`]; `&mut self` makes the
        // access exclusive.
        unsafe { &mut *self.send }
    }

    /// Whether the peer already sent FIN.
    pub fn peer_fin(&self) -> bool {
        self.peer_fin
    }

    /// Record that the peer sent FIN.
    pub fn set_peer_fin(&mut self) {
        self.peer_fin = true;
    }

    /// Whether the connection failed.
    pub fn error(&self) -> bool {
        self.error
    }

    /// Record a connection failure.
    pub fn set_error(&mut self) {
        self.error = true;
    }

    /// Whether a local close is in flight.
    pub fn closing(&self) -> bool {
        self.closing
    }

    /// Record that a local close started.
    pub fn set_closing(&mut self) {
        self.closing = true;
    }

    /// Whether the last segment advertised a zero receive window.
    pub fn zero_window(&self) -> bool {
        self.zero_window
    }

    /// Record that a zero window was advertised.
    pub fn set_zero_window(&mut self) {
        self.zero_window = true;
    }

    /// Clear the zero-window marker after sending a window update.
    pub fn clear_zero_window(&mut self) {
        self.zero_window = false;
    }

    /// Whether this socket's read direction was shut down locally.
    pub fn read_shut(&self) -> bool {
        self.read_shut
    }

    /// Record a local read shutdown (the socket keeps its write direction).
    pub fn set_read_shut(&mut self) {
        self.read_shut = true;
    }

    /// Whether this socket's write direction was shut down locally.
    pub fn write_shut(&self) -> bool {
        self.write_shut
    }

    /// Record a local write shutdown.
    pub fn set_write_shut(&mut self) {
        self.write_shut = true;
    }

    /// Whether the active open was refused by the peer.
    pub fn refused(&self) -> bool {
        self.refused
    }

    /// Record that the active open was refused.
    pub fn set_refused(&mut self) {
        self.refused = true;
    }

    /// How many pending connections this listener accepts.
    pub fn backlog_limit(&self) -> usize {
        usize::from(self.backlog_limit).min(TCP_BACKLOG)
    }

    /// Set the requested backlog limit (`1..=MAX_BACKLOG`, already validated).
    pub fn set_backlog_limit(&mut self, limit: u16) {
        self.backlog_limit = limit.min(TCP_BACKLOG as u16).max(1);
    }

    /// Pending connection at `index`.
    pub fn backlog(&self, index: usize) -> Option<&BacklogEntry> {
        if index >= TCP_BACKLOG {
            return None;
        }
        // SAFETY: `backlog` points into the static per-socket array; index was
        // bounds-checked and the net lock serialises access.
        unsafe { (*self.backlog.add(index)).as_ref() }
    }

    /// Mutable pending connection at `index`.
    pub fn backlog_mut(&mut self, index: usize) -> Option<&mut BacklogEntry> {
        if index >= TCP_BACKLOG {
            return None;
        }
        // SAFETY: same static-storage and locking invariant as `backlog`.
        unsafe { (*self.backlog.add(index)).as_mut() }
    }

    /// Number of pending connections.
    pub fn backlog_len(&self) -> usize {
        usize::from(self.backlog_len)
    }

    /// Append a pending connection; `false` when the backlog is full.
    pub fn push_backlog(&mut self, entry: BacklogEntry) -> bool {
        if usize::from(self.backlog_len) >= self.backlog_limit() {
            return false;
        }
        // SAFETY: backlog_len is below the validated backlog limit.
        unsafe { *self.backlog.add(usize::from(self.backlog_len)) = Some(entry) };
        self.backlog_len += 1;
        true
    }

    /// Remove and return the pending connection at `index`, keeping the rest
    /// contiguous.
    pub fn take_backlog(&mut self, index: usize) -> Option<BacklogEntry> {
        if index >= usize::from(self.backlog_len) {
            return None;
        }
        // SAFETY: all indices below were checked against backlog_len and the
        // caller holds the net lock, so the static array accesses are valid.
        let taken = unsafe { (*self.backlog.add(index)).take()? };
        let mut cursor = index;
        while cursor + 1 < usize::from(self.backlog_len) {
            unsafe {
                *self.backlog.add(cursor) = (*self.backlog.add(cursor + 1)).take();
            }
            cursor += 1;
        }
        self.backlog_len -= 1;
        Some(taken)
    }
}

// ---------------------------------------------------------------------------
// Slot table
// ---------------------------------------------------------------------------

/// What a socket slot currently points at.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlotKind {
    /// Free slot.
    Free,
    /// Created by `create`, not bound yet (M7b front-end).
    Unbound,
    /// Index into the UDP socket table.
    Udp(u8),
    /// Index into the TCP connection table.
    Tcp(u8),
    /// Index into the local stream table (same index as the slot).
    LocalStream,
    /// Index into the local datagram table (same index as the slot).
    LocalDatagram,
}

/// One entry of the socket id table.
pub struct SocketSlot {
    /// Generation stamped into the ids issued for this slot.
    pub generation: u16,
    /// Payload pointer, or [`SlotKind::Free`].
    pub kind: SlotKind,
    /// `DOMAIN_*` of the socket (kept across `Unbound`).
    pub domain: u8,
    /// `SOCK_*` of the socket (kept across `Unbound`).
    pub hint: u8,
    /// Object the socket is attached to (`0` = none).
    pub object: ObjectId,
    /// Local endpoint for a bound-but-not-listening INET socket.
    pub local: Option<Endpoint>,
    /// Credentials of the process owning this socket (M9b; `NONE` if unknown).
    pub cred: Credential,
    /// `SO_PASSCRED` state of this socket (M9b).
    pub passcred: bool,
    /// Credentials of the connected peer, captured at connect/accept (M9b).
    pub peer_cred: Option<Credential>,
}

impl SocketSlot {
    /// A free slot with generation 0.
    pub const fn free() -> SocketSlot {
        SocketSlot {
            generation: 0,
            kind: SlotKind::Free,
            domain: 0,
            hint: 0,
            object: 0,
            local: None,
            cred: Credential::NONE,
            passcred: false,
            peer_cred: None,
        }
    }

    /// Release the socket payload while keeping the generation stamp, so an id
    /// issued before the release stays stale (no ABA).
    pub fn clear(&mut self) {
        let generation = self.generation;
        *self = SocketSlot {
            generation,
            ..SocketSlot::free()
        };
    }

    /// Whether the slot is free.
    pub fn is_free(&self) -> bool {
        matches!(self.kind, SlotKind::Free)
    }
}

// ---------------------------------------------------------------------------
// M7b front-end: portable address, local sockets, namespace path bindings
// ---------------------------------------------------------------------------

/// Address handed to and returned by the M7b socket front-end.
///
/// The layout mirrors the wire `SockAddr` (family / port / flags / 16 address
/// bytes / scope / path length / 108 path bytes) so the object layer can copy it
/// without translation. INET and INET6 use [`SocketAddress::as_endpoint`]; UNIX
/// uses `path[..path_len]`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SocketAddress {
    /// `DOMAIN_*` selector.
    pub family: u32,
    /// Port for INET/INET6, `0` for UNIX.
    pub port: u32,
    /// Reserved for later stages (must be `0`).
    pub flags: u32,
    /// IPv4 in `addr[..4]`, IPv6 in `addr[..16]`.
    pub addr: [u8; 16],
    /// IPv6 scope id.
    pub scope: u32,
    /// Used path bytes in `path`.
    pub path_len: u32,
    /// `AF_UNIX` path bytes (not NUL terminated).
    pub path: [u8; SOCKET_PATH_BYTES],
}

impl SocketAddress {
    /// Place-holder address.
    pub const INVALID: SocketAddress = SocketAddress {
        family: 0,
        port: 0,
        flags: 0,
        addr: [0; 16],
        scope: 0,
        path_len: 0,
        path: [0; SOCKET_PATH_BYTES],
    };

    /// IPv4 address plus port.
    pub const fn inet_v4(addr: Ipv4Addr, port: u16) -> SocketAddress {
        let octets = addr.0;
        let mut bytes = [0u8; 16];
        bytes[0] = octets[0];
        bytes[1] = octets[1];
        bytes[2] = octets[2];
        bytes[3] = octets[3];
        SocketAddress {
            family: DOMAIN_INET,
            port: port as u32,
            flags: 0,
            addr: bytes,
            scope: 0,
            path_len: 0,
            path: [0; SOCKET_PATH_BYTES],
        }
    }

    /// IPv6 address plus port.
    pub const fn inet_v6(addr: Ipv6Addr, port: u16) -> SocketAddress {
        SocketAddress {
            family: DOMAIN_INET6,
            port: port as u32,
            flags: 0,
            addr: addr.0,
            scope: 0,
            path_len: 0,
            path: [0; SOCKET_PATH_BYTES],
        }
    }

    /// UNIX path address; rejects an empty path and one that does not fit.
    pub fn unix_path(path: &[u8]) -> Result<SocketAddress, NetError> {
        if path.is_empty() || path.len() > SOCKET_PATH_MAX {
            return Err(NetError::BadAddress);
        }
        let mut address = SocketAddress {
            family: DOMAIN_UNIX,
            ..SocketAddress::INVALID
        };
        address.path[..path.len()].copy_from_slice(path);
        address.path_len = path.len() as u32;
        Ok(address)
    }

    /// Abstract UNIX socket address (Linux `sun_path[0] == 0`).
    ///
    /// The stored bytes are the **whole** abstract name including the leading
    /// NUL byte, so path bindings compare abstract and pathname addresses with
    /// plain byte equality (`PathBinding::path_bytes`) and need no extra flag.
    /// `name` may contain NUL bytes and must be non-empty; the encoded name is
    /// at most [`SOCKET_PATH_BYTES`] bytes (leading NUL + name).
    pub fn unix_abstract(name: &[u8]) -> Result<SocketAddress, NetError> {
        if name.is_empty() || name.len() + 1 > SOCKET_PATH_BYTES {
            return Err(NetError::BadAddress);
        }
        let mut address = SocketAddress {
            family: DOMAIN_UNIX,
            ..SocketAddress::INVALID
        };
        address.path[0] = 0;
        address.path[1..=name.len()].copy_from_slice(name);
        address.path_len = (name.len() + 1) as u32;
        Ok(address)
    }

    /// Whether this is a Linux abstract UNIX address (first path byte is NUL).
    pub fn is_abstract(&self) -> bool {
        self.is_unix() && self.path_len > 0 && self.path[0] == 0
    }

    /// Whether this is a pathname UNIX address.
    pub fn is_pathname(&self) -> bool {
        self.is_unix() && self.path_len > 0 && self.path[0] != 0
    }

    /// Convert an INET/INET6 address to the internal endpoint form.
    pub fn as_endpoint(&self) -> Option<Endpoint> {
        let port = u16::try_from(self.port).ok()?;
        match self.family {
            DOMAIN_INET => Some(Endpoint::new(
                IpAddr::V4(Ipv4Addr::new(
                    self.addr[0],
                    self.addr[1],
                    self.addr[2],
                    self.addr[3],
                )),
                port,
            )),
            DOMAIN_INET6 => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(&self.addr);
                Some(Endpoint::new(IpAddr::V6(Ipv6Addr::new(bytes)), port))
            }
            _ => None,
        }
    }

    /// Build an INET/INET6 address from an endpoint.
    pub fn from_endpoint(endpoint: Endpoint, family: u32) -> SocketAddress {
        match endpoint.addr {
            IpAddr::V4(addr) => SocketAddress {
                family,
                port: u32::from(endpoint.port),
                ..SocketAddress::inet_v4(addr, endpoint.port)
            },
            IpAddr::V6(addr) => SocketAddress {
                family,
                port: u32::from(endpoint.port),
                ..SocketAddress::inet_v6(addr, endpoint.port)
            },
        }
    }

    /// Bound UNIX path bytes.
    pub fn path_bytes(&self) -> &[u8] {
        let len = (self.path_len as usize).min(SOCKET_PATH_BYTES);
        &self.path[..len]
    }

    /// Whether this is a UNIX address.
    pub const fn is_unix(&self) -> bool {
        self.family == DOMAIN_UNIX
    }

    /// Whether this is an INET or INET6 address.
    pub const fn is_inet(&self) -> bool {
        self.family == DOMAIN_INET || self.family == DOMAIN_INET6
    }
}

/// Result of a successful `recv`: byte count plus the datagram source.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Received {
    /// Bytes written into the caller's buffer.
    pub len: usize,
    /// Source address for datagram sockets (`None` for streams).
    pub source: Option<SocketAddress>,
}

impl Received {
    /// An empty receive result.
    pub const fn empty() -> Received {
        Received {
            len: 0,
            source: None,
        }
    }
}

/// Sender credentials carried by a UNIX message (`struct ucred`, M9b).
///
/// This slice has no credential model of its own: callers fill `uid`/`gid`
/// with the values the personality layer reports (`0` today) and `pid` with
/// the Linux pid (`process::current_linux_pid`). `NONE` (`pid == 0`) means
/// "no credentials attached".
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Credential {
    /// Linux pid of the sending process (`0` when unset).
    pub pid: u32,
    /// User id (compat layer reports `0` in this slice).
    pub uid: u32,
    /// Group id (compat layer reports `0` in this slice).
    pub gid: u32,
}

impl Credential {
    /// No credentials attached.
    pub const NONE: Credential = Credential {
        pid: 0,
        uid: 0,
        gid: 0,
    };

    /// Build a credential triple.
    pub const fn new(pid: u32, uid: u32, gid: u32) -> Credential {
        Credential { pid, uid, gid }
    }

    /// Whether any credential is present.
    pub const fn is_set(self) -> bool {
        self.pid != 0
    }
}

/// Ancillary descriptors and/or credentials attached to one stream send.
///
/// The record is bound to the absolute stream offset `at` of the **first byte**
/// of the send that carried it. `recv_msg` returns the record once that byte
/// has been consumed; a plain `read`/`recv` that consumes the first byte drops
/// the record (and releases its object references), matching Linux.
#[derive(Clone, Copy, Debug)]
pub struct StreamAncillary {
    /// Absolute stream offset of the first byte of the carrying send.
    pub at: u64,
    /// Transferred object ids (`objects[..count]` are valid).
    pub objects: [ObjectId; MAX_SCM_FDS],
    /// Number of valid object ids.
    pub count: u8,
    /// Credentials attached to the same send.
    pub cred: Option<Credential>,
}

impl StreamAncillary {
    /// An empty record.
    pub const fn empty() -> StreamAncillary {
        StreamAncillary {
            at: 0,
            objects: [0; MAX_SCM_FDS],
            count: 0,
            cred: None,
        }
    }

    /// Number of attached object ids.
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }
}

/// Result of a successful `recv_msg` (M9b).
///
/// On success the receiver owns one reference per `objects[..object_count]`
/// entry and must install them (or release them); `source` is the sender
/// address for datagrams and `None` for streams, and `cred` is the credentials
/// the carrying send attached (if any).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ReceivedMessage {
    /// Bytes written into the caller's buffer.
    pub len: usize,
    /// Source address for datagram sockets (`None` for streams).
    pub source: Option<SocketAddress>,
    /// Transferred object ids (`objects[..object_count]` are valid).
    pub objects: [ObjectId; MAX_SCM_FDS],
    /// Number of valid object ids.
    pub object_count: u8,
    /// Credentials carried by the message, when the sender attached any.
    pub cred: Option<Credential>,
}

impl ReceivedMessage {
    /// An empty receive result (stream EOF, or a zero-length datagram).
    pub const fn empty() -> ReceivedMessage {
        ReceivedMessage {
            len: 0,
            source: None,
            objects: [0; MAX_SCM_FDS],
            object_count: 0,
            cred: None,
        }
    }
}

/// Which directions `shutdown` closes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ShutdownHow {
    /// No further receives.
    Read,
    /// No further sends.
    Write,
    /// Both directions.
    Both,
}

impl ShutdownHow {
    /// Decode the wire value (`0` read, `1` write, `2` both).
    pub const fn from_u32(value: u32) -> Option<ShutdownHow> {
        match value {
            0 => Some(ShutdownHow::Read),
            1 => Some(ShutdownHow::Write),
            2 => Some(ShutdownHow::Both),
            _ => None,
        }
    }

    /// Whether the read direction is closed.
    pub const fn closes_read(self) -> bool {
        matches!(self, ShutdownHow::Read | ShutdownHow::Both)
    }

    /// Whether the write direction is closed.
    pub const fn closes_write(self) -> bool {
        matches!(self, ShutdownHow::Write | ShutdownHow::Both)
    }
}

/// Lifecycle of a local (UNIX) stream socket.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LocalState {
    /// Bound to a path but not listening.
    Bound,
    /// Bound and accepting connections.
    Listening,
    /// Connected to a peer.
    Connected,
    /// Released.
    Closed,
}

/// One direction of a connected local stream socket.
pub struct LocalStream {
    /// Namespace the path binding (if any) belongs to.
    pub namespace: ObjectId,
    /// Lifecycle state.
    pub state: LocalState,
    /// Peer socket id (full generation, `SocketId::INVALID` when unconnected).
    /// Storing the generation keeps a recycled slot from being mistaken for
    /// the old peer (Lead M7b review M1).
    pub peer: SocketId,
    /// Configured backlog for a listener.
    pub backlog_limit: u16,
    /// Accepted-but-not-yet-accepted connections, in id order.
    pub accept_queue: [SocketId; LOCAL_BACKLOG],
    /// Entries used in `accept_queue`.
    pub accept_len: u16,
    /// This side stopped reading.
    pub read_shut: bool,
    /// This side stopped writing (peer sees EOF).
    pub write_shut: bool,
    /// The peer stopped writing (local reads see EOF).
    pub peer_write_shut: bool,
    /// Received bytes, owned by the enclosing static `NetStack` (indexed by
    /// slot). Keeping the 4 KiB ring out of this struct keeps the payload and
    /// every reset temporary small.
    rx: *mut TcpReceiveBuffer,
    /// Absolute count of bytes received on this stream (M9b send offsets).
    pub rx_received: u64,
    /// Absolute count of bytes already handed to `recv`/`read` (M9b).
    pub rx_consumed: u64,
    /// Ancillary records queued per carrying send, oldest at `ancil_head`.
    pub ancil: [StreamAncillary; LOCAL_ANCILLARY_DEPTH],
    /// Index of the oldest ancillary record.
    pub ancil_head: u8,
    /// Number of queued ancillary records.
    pub ancil_count: u8,
}

impl LocalStream {
    /// A fresh, unconnected stream state using the static ring at `rx`.
    pub fn new(namespace: ObjectId, rx: *mut TcpReceiveBuffer) -> LocalStream {
        // SAFETY: `rx` points at a `NetStack::local_stream_rx` element for this
        // slot; it is always initialised, and clearing it in place creates no
        // stack temporary.
        unsafe { (*rx).clear() };
        LocalStream {
            namespace,
            state: LocalState::Bound,
            peer: SocketId::INVALID,
            backlog_limit: LOCAL_BACKLOG as u16,
            accept_queue: [SocketId::INVALID; LOCAL_BACKLOG],
            accept_len: 0,
            read_shut: false,
            write_shut: false,
            peer_write_shut: false,
            rx,
            rx_received: 0,
            rx_consumed: 0,
            ancil: [StreamAncillary::empty(); LOCAL_ANCILLARY_DEPTH],
            ancil_head: 0,
            ancil_count: 0,
        }
    }

    /// Received bytes.
    pub fn rx(&self) -> &TcpReceiveBuffer {
        // SAFETY: `rx` points at a `NetStack::local_stream_rx` element owned by
        // this socket's slot; the whole stack is serialised by the `net` lock.
        unsafe { &*self.rx }
    }

    /// Mutable received bytes.
    pub fn rx_mut(&mut self) -> &mut TcpReceiveBuffer {
        // SAFETY: same invariant as [`LocalStream::rx`]; `&mut self` makes the
        // access exclusive.
        unsafe { &mut *self.rx }
    }

    /// Bytes available to read.
    pub fn pending(&self) -> usize {
        self.rx().len()
    }

    /// Connect this stream to `peer`.
    pub fn set_peer(&mut self, peer: SocketId) {
        self.peer = peer;
    }

    /// Whether this stream has a peer.
    pub fn has_peer(&self) -> bool {
        self.peer.slot().is_some()
    }

    /// Pending connections not yet accepted.
    pub fn accept_len(&self) -> usize {
        usize::from(self.accept_len)
    }

    /// Whether the accept queue is at the configured limit.
    pub fn accept_full(&self) -> bool {
        usize::from(self.accept_len) >= usize::from(self.backlog_limit)
    }

    /// Queue a freshly connected peer; `false` when the queue is at its limit.
    pub fn accept_push(&mut self, peer: SocketId) -> bool {
        if self.accept_full() || self.accept_len() >= LOCAL_BACKLOG {
            return false;
        }
        self.accept_queue[usize::from(self.accept_len)] = peer;
        self.accept_len += 1;
        true
    }

    /// Pop the oldest queued peer.
    pub fn accept_take(&mut self) -> Option<SocketId> {
        if self.accept_len == 0 {
            return None;
        }
        let first = self.accept_queue[0];
        let mut cursor = 0;
        while cursor + 1 < usize::from(self.accept_len) {
            self.accept_queue[cursor] = self.accept_queue[cursor + 1];
            cursor += 1;
        }
        self.accept_queue[cursor] = SocketId::INVALID;
        self.accept_len -= 1;
        Some(first)
    }

    /// Drop every queued connection (listener close, Lead M7b review N7/M2).
    pub fn clear_accept_queue(&mut self) {
        self.accept_queue = [SocketId::INVALID; LOCAL_BACKLOG];
        self.accept_len = 0;
    }

    /// Set the requested backlog limit (`1..=MAX_BACKLOG`, already validated).
    pub fn set_backlog_limit(&mut self, limit: u16) {
        self.backlog_limit = limit.clamp(1, LOCAL_BACKLOG as u16);
    }

    /// Queue an ancillary record; `false` when the per-direction buffer is full.
    pub fn push_ancillary(&mut self, record: StreamAncillary) -> bool {
        if self.ancillary_len() >= LOCAL_ANCILLARY_DEPTH {
            return false;
        }
        let index =
            (usize::from(self.ancil_head) + usize::from(self.ancil_count)) % LOCAL_ANCILLARY_DEPTH;
        self.ancil[index] = record;
        self.ancil_count += 1;
        true
    }

    /// Oldest queued ancillary record, if any.
    pub fn peek_ancillary(&self) -> Option<StreamAncillary> {
        if self.ancil_count == 0 {
            return None;
        }
        Some(self.ancil[usize::from(self.ancil_head)])
    }

    /// Remove and return the oldest ancillary record.
    pub fn pop_ancillary(&mut self) -> Option<StreamAncillary> {
        let record = self.peek_ancillary()?;
        self.ancil[usize::from(self.ancil_head)] = StreamAncillary::empty();
        self.ancil_head = (self.ancil_head + 1) % (LOCAL_ANCILLARY_DEPTH as u8);
        self.ancil_count -= 1;
        Some(record)
    }

    /// Number of queued ancillary records.
    pub fn ancillary_len(&self) -> usize {
        usize::from(self.ancil_count)
    }

    /// Drop every queued ancillary record, returning how many were dropped.
    pub fn clear_ancillary(&mut self) -> usize {
        let count = self.ancillary_len();
        self.ancil = [StreamAncillary::empty(); LOCAL_ANCILLARY_DEPTH];
        self.ancil_head = 0;
        self.ancil_count = 0;
        count
    }
}

/// One queued local datagram.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LocalDatagramEntry {
    length: u16,
    data: [u8; LOCAL_DGRAM_MAX],
    source: SocketAddress,
    /// Transferred object ids carried by this message (M9b).
    objects: [ObjectId; MAX_SCM_FDS],
    /// Number of valid object ids in `objects`.
    object_count: u8,
    /// Credentials attached to this message (M9b).
    cred: Option<Credential>,
}

impl LocalDatagramEntry {
    /// Empty place-holder.
    pub const fn empty() -> LocalDatagramEntry {
        LocalDatagramEntry {
            length: 0,
            data: [0; LOCAL_DGRAM_MAX],
            source: SocketAddress::INVALID,
            objects: [0; MAX_SCM_FDS],
            object_count: 0,
            cred: None,
        }
    }

    /// Payload length.
    pub fn len(&self) -> usize {
        usize::from(self.length)
    }

    /// Whether the datagram is empty.
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Sender address.
    pub fn source(&self) -> SocketAddress {
        self.source
    }

    /// Number of transferred object ids.
    pub fn object_count(&self) -> usize {
        usize::from(self.object_count)
    }

    /// Transferred object ids (`objects[..object_count()]`).
    pub fn objects(&self) -> &[ObjectId] {
        &self.objects[..self.object_count()]
    }

    /// Credentials attached to this message.
    pub fn cred(&self) -> Option<Credential> {
        self.cred
    }

    /// Copy the payload into `out`; fails without consuming anything when the
    /// buffer is too small (`recv` keeps message boundaries).
    pub fn read_into(&self, out: &mut [u8]) -> Result<usize, NetError> {
        let len = self.len();
        if out.len() < len {
            return Err(NetError::TooLarge);
        }
        out[..len].copy_from_slice(&self.data[..len]);
        Ok(len)
    }
}

/// Bounded datagram queue for one local socket direction (back-pressure, no
/// drop-oldest: a full queue refuses the sender with [`NetError::WouldBlock`]).
pub struct LocalQueue {
    slots: [Option<LocalDatagramEntry>; LOCAL_DGRAM_DEPTH],
    head: u8,
    count: u8,
}

impl LocalQueue {
    /// Empty queue.
    pub const fn new() -> LocalQueue {
        LocalQueue {
            slots: [None; LOCAL_DGRAM_DEPTH],
            head: 0,
            count: 0,
        }
    }

    /// Queued entries.
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Enqueue a copy of `payload`; `WouldBlock` when the queue is full.
    ///
    /// Convenience for callers without ancillary data; equivalent to
    /// [`LocalQueue::push_msg`] with no objects and no credentials.
    pub fn push(&mut self, payload: &[u8], source: SocketAddress) -> Result<(), NetError> {
        self.push_msg(payload, source, &[], None)
    }

    /// Enqueue one message with transferred object references and credentials.
    ///
    /// On success the queue owns one reference per `objects` entry; on any
    /// error nothing is transferred and the caller keeps them.
    pub fn push_msg(
        &mut self,
        payload: &[u8],
        source: SocketAddress,
        objects: &[ObjectId],
        cred: Option<Credential>,
    ) -> Result<(), NetError> {
        if payload.len() > LOCAL_DGRAM_MAX {
            return Err(NetError::TooLarge);
        }
        if objects.len() > MAX_SCM_FDS {
            return Err(NetError::Unsupported);
        }
        if usize::from(self.count) >= LOCAL_DGRAM_DEPTH {
            return Err(NetError::WouldBlock);
        }
        let index = (usize::from(self.head) + usize::from(self.count)) % LOCAL_DGRAM_DEPTH;
        let mut entry = LocalDatagramEntry::empty();
        entry.data[..payload.len()].copy_from_slice(payload);
        entry.length = payload.len() as u16;
        entry.source = source;
        entry.object_count = objects.len() as u8;
        entry.objects[..objects.len()].copy_from_slice(objects);
        entry.cred = cred;
        self.slots[index] = Some(entry);
        self.count += 1;
        Ok(())
    }

    /// Copy the oldest payload into `out` and consume it.
    ///
    /// Convenience for callers that drop ancillary data; equivalent to
    /// [`LocalQueue::pop_msg`] ignoring the transfer fields.
    pub fn pop(&mut self, out: &mut [u8]) -> Result<(usize, SocketAddress), NetError> {
        let message = self.pop_msg(out)?;
        Ok((
            message.len,
            message.source.unwrap_or(SocketAddress::INVALID),
        ))
    }

    /// Dequeue the oldest message, transferring its object references to the
    /// caller.
    pub fn pop_msg(&mut self, out: &mut [u8]) -> Result<ReceivedMessage, NetError> {
        let len = self.peek_len().ok_or(NetError::WouldBlock)?;
        if out.len() < len {
            return Err(NetError::TooLarge);
        }
        let index = usize::from(self.head);
        let entry = self.slots[index].take().ok_or(NetError::WouldBlock)?;
        let copied = entry.read_into(out)?;
        self.head = ((usize::from(self.head) + 1) % LOCAL_DGRAM_DEPTH) as u8;
        self.count -= 1;
        Ok(ReceivedMessage {
            len: copied,
            source: Some(entry.source()),
            objects: entry.objects,
            object_count: entry.object_count,
            cred: entry.cred,
        })
    }

    /// Remove every queued message's transferred object ids into `out`.
    ///
    /// Used when a socket is closed/destroyed or datagrams are dropped without
    /// a receiver; the caller releases the returned references outside the net
    /// lock. Returns how many ids were written (queue is emptied either way).
    pub fn drain_objects(&mut self, out: &mut [ObjectId]) -> usize {
        let mut written = 0;
        for slot in self.slots.iter_mut() {
            if let Some(entry) = slot.take() {
                for index in 0..entry.object_count() {
                    if written < out.len() {
                        out[written] = entry.objects[index];
                        written += 1;
                    }
                }
            }
        }
        self.head = 0;
        self.count = 0;
        written
    }

    /// Length of the oldest entry without consuming it.
    pub fn peek_len(&self) -> Option<usize> {
        self.slots[usize::from(self.head)].map(|entry| entry.len())
    }

    /// Drop every queued entry.
    pub fn clear(&mut self) {
        for slot in self.slots.iter_mut() {
            *slot = None;
        }
        self.head = 0;
        self.count = 0;
    }
}

impl Default for LocalQueue {
    fn default() -> LocalQueue {
        LocalQueue::new()
    }
}

/// A local (UNIX) datagram socket.
pub struct LocalDatagram {
    /// Namespace the path binding belongs to.
    pub namespace: ObjectId,
    /// Default peer socket id for a connected datagram socket
    /// (`SocketId::INVALID` when unconnected). The full generation is kept so
    /// a recycled slot can never be mistaken for the old peer (review M1).
    pub connected: SocketId,
    /// Received datagrams, owned by the enclosing static `NetStack` (indexed by
    /// slot). Keeping the queue out of this struct keeps the payload small.
    queue: *mut LocalQueue,
    /// This side stopped receiving.
    pub read_shut: bool,
    /// This side stopped sending.
    pub write_shut: bool,
    /// The connected peer has been closed (local reads drain, then EOF).
    ///
    /// Kept separate from [`LocalDatagram::read_shut`]: the latter is an
    /// explicit local `shutdown(read)`, which must keep rejecting receives
    /// even when datagrams are still queued. A closed peer instead lets the
    /// survivor drain what was already queued and then report EOF (M7b
    /// phase 12 faults / phase 7 regression).
    pub peer_write_shut: bool,
}

impl LocalDatagram {
    /// A fresh, unbound datagram state using the static queue at `queue`.
    pub fn new(namespace: ObjectId, queue: *mut LocalQueue) -> LocalDatagram {
        // SAFETY: `queue` points at a `NetStack::local_dgram_queues` element for
        // this slot; it is always initialised, and clearing it in place creates
        // no stack temporary.
        unsafe { (*queue).clear() };
        LocalDatagram {
            namespace,
            connected: SocketId::INVALID,
            queue,
            read_shut: false,
            write_shut: false,
            peer_write_shut: false,
        }
    }

    /// Received datagrams.
    pub fn queue(&self) -> &LocalQueue {
        // SAFETY: `queue` points at a `NetStack::local_dgram_queues` element
        // owned by this socket's slot; the whole stack is serialised by the
        // `net` lock.
        unsafe { &*self.queue }
    }

    /// Mutable received datagrams.
    pub fn queue_mut(&mut self) -> &mut LocalQueue {
        // SAFETY: same invariant as [`LocalDatagram::queue`]; `&mut self` makes
        // the access exclusive.
        unsafe { &mut *self.queue }
    }

    /// Pending datagrams.
    pub fn pending(&self) -> usize {
        self.queue().len()
    }

    /// Whether a default peer is configured.
    pub fn has_peer(&self) -> bool {
        self.connected.slot().is_some()
    }
}

/// One path registered in a namespace.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PathBinding {
    /// Used path bytes.
    pub path_len: u8,
    /// Path bytes.
    pub path: [u8; SOCKET_PATH_BYTES],
    /// Socket slot index bound to the path.
    pub slot: u8,
    /// Whether the binding is a stream (listening) socket.
    pub stream: bool,
}

impl PathBinding {
    /// Empty place-holder.
    pub const fn empty() -> PathBinding {
        PathBinding {
            path_len: 0,
            path: [0; SOCKET_PATH_BYTES],
            slot: 0,
            stream: false,
        }
    }

    /// Path bytes of the binding.
    pub fn path_bytes(&self) -> &[u8] {
        let len = usize::from(self.path_len).min(SOCKET_PATH_BYTES);
        &self.path[..len]
    }
}

/// Bindings that belong to one network namespace object.
pub struct NamespaceEntry {
    /// Object id of the namespace (`0` = free entry).
    pub id: ObjectId,
    /// Fixed binding table, owned by the enclosing static `NetStack` (indexed by
    /// namespace slot). Kept outside this struct so `Option<NamespaceEntry>` —
    /// and therefore every reset temporary — stays small.
    bindings: *mut [Option<PathBinding>; MAX_BINDINGS_PER_NAMESPACE],
}

impl NamespaceEntry {
    /// A namespace entry for `id` using the static binding table at `bindings`.
    pub fn new(
        id: ObjectId,
        bindings: *mut [Option<PathBinding>; MAX_BINDINGS_PER_NAMESPACE],
    ) -> NamespaceEntry {
        // SAFETY: `bindings` points at a `NetStack::namespace_bindings` row
        // (fixed length `MAX_BINDINGS_PER_NAMESPACE`); the row is always
        // initialised.
        unsafe {
            for binding in (*bindings).iter_mut() {
                *binding = None;
            }
        }
        NamespaceEntry { id, bindings }
    }

    /// The fixed binding table.
    pub fn bindings(&self) -> &[Option<PathBinding>; MAX_BINDINGS_PER_NAMESPACE] {
        // SAFETY: `bindings` points at a static `NetStack` row that lives as
        // long as the entry; the stack is serialised by the `net` lock.
        unsafe { &*self.bindings }
    }

    /// Mutable binding table.
    pub fn bindings_mut(&mut self) -> &mut [Option<PathBinding>; MAX_BINDINGS_PER_NAMESPACE] {
        // SAFETY: same invariant as [`NamespaceEntry::bindings`].
        unsafe { &mut *self.bindings }
    }

    /// Registrations currently installed.
    pub fn binding_count(&self) -> usize {
        self.bindings()
            .iter()
            .filter(|binding| binding.is_some())
            .count()
    }
}
