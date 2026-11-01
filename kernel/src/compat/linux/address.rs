//! Linux socket address layouts.
//!
//! The Linux personality sees the three `sockaddr` layouts a socket program
//! uses:
//!
//! | layout | size | family | port | address | extra |
//! |---|---|---|---|---|---|
//! | `sockaddr_in` | 16 | native-endian `sa_family_t` | network order | 4 bytes | zero padding |
//! | `sockaddr_in6` | 28 | native-endian | network order | 16 bytes | flowinfo (network order, must be 0), scope id (native order) |
//! | `sockaddr_un` | 110 | native-endian | - | - | `sun_path` (108 bytes incl. NUL) |
//!
//! Conversion to and from [`net::SocketAddress`] is the only place that knows
//! both layouts; the syscall layer never hand-assembles address bytes.

use crate::net::{self, SocketAddress};
use netcore::{Ipv4Addr, Ipv6Addr};

use super::errno;

/// `AF_UNIX`.
pub const AF_UNIX: u16 = 1;
/// `AF_INET`.
pub const AF_INET: u16 = 2;
/// `AF_INET6`.
pub const AF_INET6: u16 = 10;

/// `sizeof(struct sockaddr_in)`.
pub const SOCKADDR_IN: usize = 16;
/// `sizeof(struct sockaddr_in6)`.
pub const SOCKADDR_IN6: usize = 28;
/// `sizeof(struct sockaddr_un)`.
pub const SOCKADDR_UN: usize = 110;
/// `sizeof(sun_path)` inside `sockaddr_un`.
pub const SOCKADDR_UN_PATH: usize = 108;

/// Largest `sockaddr` any syscall accepts.
pub const SOCKADDR_MAX: usize = SOCKADDR_UN;

/// Whether a `sun_path` starts with the Linux abstract-namespace marker.
///
/// An abstract name begins with a NUL byte and is *not* terminated by one; the
/// bytes after the marker up to `addrlen` are the name itself.
pub fn is_abstract_path(path: &[u8]) -> bool {
    path.first() == Some(&0)
}

/// Linux `AF_*` value that matches a `net` domain selector, if any.
pub fn family_for_domain(domain: u32) -> Option<u16> {
    match domain {
        net::DOMAIN_UNIX => Some(AF_UNIX),
        net::DOMAIN_INET => Some(AF_INET),
        net::DOMAIN_INET6 => Some(AF_INET6),
        _ => None,
    }
}

/// `net` domain selector that matches a Linux `AF_*` value, if any.
pub fn domain_for_family(family: u16) -> Option<u32> {
    match family {
        AF_UNIX => Some(net::DOMAIN_UNIX),
        AF_INET => Some(net::DOMAIN_INET),
        AF_INET6 => Some(net::DOMAIN_INET6),
        _ => None,
    }
}

/// Parse a `sockaddr` image into a `net::SocketAddress`.
///
/// The caller supplies the user buffer exactly as the program wrote it (the
/// value of `addrlen` may be larger than the layout; the layout itself is
/// bounds-checked here). Errors are positive Linux error numbers.
pub fn parse(bytes: &[u8]) -> Result<SocketAddress, i64> {
    if bytes.len() < 2 {
        return Err(errno::EINVAL);
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]);
    match family {
        AF_INET => {
            if bytes.len() < SOCKADDR_IN {
                return Err(errno::EINVAL);
            }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let addr = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
            Ok(SocketAddress::inet_v4(addr, port))
        }
        AF_INET6 => {
            if bytes.len() < SOCKADDR_IN6 {
                return Err(errno::EINVAL);
            }
            let port = u16::from_be_bytes([bytes[2], bytes[3]]);
            let flowinfo = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            if flowinfo != 0 {
                // The engine has no flow labels; accepting a non-zero one would
                // silently drop information, so it is rejected instead.
                return Err(errno::EINVAL);
            }
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&bytes[8..24]);
            let scope = u32::from_ne_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
            let mut address = SocketAddress::inet_v6(Ipv6Addr::new(raw), port);
            address.scope = scope;
            Ok(address)
        }
        AF_UNIX => {
            if bytes.len() < 2 || bytes.len() > SOCKADDR_UN {
                return Err(errno::EINVAL);
            }
            let path = &bytes[2..];
            if is_abstract_path(path) {
                // Linux abstract namespace: `sun_path[0] == 0` and the name runs
                // verbatim to `addrlen`. It is **not** NUL-terminated and may
                // itself contain NUL bytes, so no truncation happens here.
                if path.len() > net::SOCKET_PATH_MAX {
                    return Err(errno::EINVAL);
                }
                return net::SocketAddress::unix_path(path).map_err(|_| errno::EINVAL);
            }
            let end = path
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(path.len());
            let path = &path[..end];
            if path.is_empty() || path.len() > net::SOCKET_PATH_MAX {
                return Err(errno::EINVAL);
            }
            net::SocketAddress::unix_path(path).map_err(|_| errno::EINVAL)
        }
        _ => Err(errno::EAFNOSUPPORT),
    }
}

/// Serialise `address` into a user `sockaddr` buffer.
///
/// `out` is the user buffer with the capacity the program supplied through the
/// `*_addrlen` argument; the returned value is the real address length the
/// kernel must write back. A buffer that is too small fails with `EINVAL`
/// (Linux reports `EINVAL` from `getpeername`/`accept` in that case).
///
/// An anonymous `AF_UNIX` address (no path) serialises to just the family, a
/// length of 2: that is exactly what Linux reports for a socketpair endpoint.
pub fn write(address: &SocketAddress, out: &mut [u8]) -> Result<usize, i64> {
    let family = family_for_domain(address.family).ok_or(errno::EINVAL)?;
    match family {
        AF_INET => {
            if out.len() < SOCKADDR_IN {
                return Err(errno::EINVAL);
            }
            out[..SOCKADDR_IN].fill(0);
            out[..2].copy_from_slice(&AF_INET.to_ne_bytes());
            out[2..4].copy_from_slice(&(address.port as u16).to_be_bytes());
            out[4..8].copy_from_slice(&address.addr[..4]);
            Ok(SOCKADDR_IN)
        }
        AF_INET6 => {
            if out.len() < SOCKADDR_IN6 {
                return Err(errno::EINVAL);
            }
            out[..SOCKADDR_IN6].fill(0);
            out[..2].copy_from_slice(&AF_INET6.to_ne_bytes());
            out[2..4].copy_from_slice(&(address.port as u16).to_be_bytes());
            // bytes 4..8 are sin6_flowinfo and stay zero.
            out[8..24].copy_from_slice(&address.addr[..16]);
            out[24..28].copy_from_slice(&address.scope.to_ne_bytes());
            Ok(SOCKADDR_IN6)
        }
        AF_UNIX => {
            let path = address.path_bytes();
            if path.len() > net::SOCKET_PATH_MAX {
                return Err(errno::EINVAL);
            }
            if path.is_empty() {
                // Anonymous address: the family alone, as Linux reports it.
                if out.len() < 2 {
                    return Err(errno::EINVAL);
                }
                out[..2].copy_from_slice(&AF_UNIX.to_ne_bytes());
                return Ok(2);
            }
            if is_abstract_path(path) {
                // Abstract name: exactly the raw bytes, no trailing NUL, and the
                // reported length is `2 + name length` (name includes the
                // leading NUL byte).
                let total = 2 + path.len();
                if out.len() < total {
                    return Err(errno::EINVAL);
                }
                out[..2].copy_from_slice(&AF_UNIX.to_ne_bytes());
                out[2..total].copy_from_slice(path);
                return Ok(total);
            }
            let total = 2 + path.len() + 1;
            if out.len() < total {
                return Err(errno::EINVAL);
            }
            out[..2].copy_from_slice(&AF_UNIX.to_ne_bytes());
            out[2..2 + path.len()].copy_from_slice(path);
            out[2 + path.len()] = 0;
            Ok(total)
        }
        _ => Err(errno::EAFNOSUPPORT),
    }
}

/// Whether the address family is one the personality supports.
pub fn is_supported_family(family: u16) -> bool {
    domain_for_family(family).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inet(port: u16, a: u8, b: u8, c: u8, d: u8) -> [u8; SOCKADDR_IN] {
        let mut wire = [0u8; SOCKADDR_IN];
        wire[..2].copy_from_slice(&AF_INET.to_ne_bytes());
        wire[2..4].copy_from_slice(&port.to_be_bytes());
        wire[4..8].copy_from_slice(&[a, b, c, d]);
        wire
    }

    #[test]
    fn sockaddr_in_round_trips_with_network_order_port() {
        let wire = inet(8080, 127, 0, 0, 1);
        assert_eq!(&wire[2..4], &[0x1F, 0x90]);
        let address = parse(&wire).expect("parse inet");
        assert_eq!(address.family, net::DOMAIN_INET);
        assert_eq!(address.port, 8080);
        assert_eq!(&address.addr[..4], &[127, 0, 0, 1]);

        let mut out = [0u8; SOCKADDR_IN];
        assert_eq!(write(&address, &mut out), Ok(SOCKADDR_IN));
        assert_eq!(out, wire);
    }

    #[test]
    fn sockaddr_in6_carries_scope_and_rejects_flow_labels() {
        let mut wire = [0u8; SOCKADDR_IN6];
        wire[..2].copy_from_slice(&AF_INET6.to_ne_bytes());
        wire[2..4].copy_from_slice(&1234u16.to_be_bytes());
        let loopback = Ipv6Addr::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        wire[8..24].copy_from_slice(&loopback.0);
        wire[24..28].copy_from_slice(&7u32.to_ne_bytes());
        let address = parse(&wire).expect("parse inet6");
        assert_eq!(address.family, net::DOMAIN_INET6);
        assert_eq!(address.port, 1234);
        assert_eq!(address.scope, 7);

        let mut out = [0u8; SOCKADDR_IN6];
        assert_eq!(write(&address, &mut out), Ok(SOCKADDR_IN6));
        assert_eq!(out, wire);

        wire[4..8].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(parse(&wire), Err(errno::EINVAL));
    }

    #[test]
    fn sockaddr_un_carries_a_nul_terminated_path() {
        let mut wire = [0u8; SOCKADDR_UN];
        wire[..2].copy_from_slice(&AF_UNIX.to_ne_bytes());
        wire[2..11].copy_from_slice(b"/tmp/m7d\0");
        let address = parse(&wire[..SOCKADDR_UN]).expect("parse unix");
        assert_eq!(address.family, net::DOMAIN_UNIX);
        assert_eq!(address.path_bytes(), b"/tmp/m7d");

        let mut out = [0u8; SOCKADDR_UN];
        let len = write(&address, &mut out).expect("serialise unix");
        assert_eq!(len, 2 + 8 + 1);
        assert_eq!(&out[..2], &AF_UNIX.to_ne_bytes());
        assert_eq!(&out[2..len], b"/tmp/m7d\0");
    }

    #[test]
    fn an_anonymous_unix_address_serialises_to_family_only() {
        // A socketpair endpoint has no path: Linux reports `sa_family_t` only.
        let address = SocketAddress {
            family: net::DOMAIN_UNIX,
            ..SocketAddress::INVALID
        };
        let mut out = [0xAAu8; SOCKADDR_UN];
        let len = write(&address, &mut out).expect("serialise anonymous unix");
        assert_eq!(len, 2);
        assert_eq!(&out[..2], &AF_UNIX.to_ne_bytes());

        let mut tiny = [0u8; 1];
        assert_eq!(write(&address, &mut tiny), Err(errno::EINVAL));
    }

    #[test]
    fn malformed_addresses_are_rejected() {
        assert_eq!(parse(&[0]), Err(errno::EINVAL));
        let mut wire = inet(1, 127, 0, 0, 1);
        wire[..2].copy_from_slice(&7u16.to_ne_bytes());
        assert_eq!(parse(&wire), Err(errno::EAFNOSUPPORT));
        assert_eq!(parse(&wire[..10]), Err(errno::EAFNOSUPPORT));
        let short_inet = [0u8, 0];
        // Family 0 is not supported at all.
        assert_eq!(parse(&short_inet), Err(errno::EAFNOSUPPORT));
        // A truncated sockaddr_in whose family *is* supported fails with EINVAL.
        let truncated_inet = [AF_INET as u8, 0, 0, 0];
        assert_eq!(parse(&truncated_inet), Err(errno::EINVAL));

        let mut unix = [0u8; SOCKADDR_UN];
        unix[..2].copy_from_slice(&AF_UNIX.to_ne_bytes());
        assert_eq!(parse(&unix), Err(errno::EINVAL));
        unix[2] = b'/';
        unix[3] = 0;
        assert!(!matches!(parse(&unix), Err(errno::EINVAL)));

        let address = SocketAddress::inet_v4(Ipv4Addr::new(127, 0, 0, 1), 1);
        let mut tiny = [0u8; 4];
        assert_eq!(write(&address, &mut tiny), Err(errno::EINVAL));
    }

    #[test]
    fn an_abstract_unix_name_is_byte_exact_and_has_no_terminator() {
        // Abstract name: `sun_path[0] == 0`, the remaining bytes are the name
        // and may themselves contain NUL; the length comes from `addrlen`, not
        // from a terminator.
        let mut wire = [0u8; SOCKADDR_UN];
        wire[..2].copy_from_slice(&AF_UNIX.to_ne_bytes());
        wire[3] = b'a';
        wire[4] = 0; // an interior NUL is part of the name
        wire[5] = b'b';
        let address = parse(&wire[..6]).expect("parse abstract");
        assert_eq!(address.family, net::DOMAIN_UNIX);
        assert_eq!(address.path_bytes(), &[0, b'a', 0, b'b']);

        let mut out = [0xAAu8; SOCKADDR_UN];
        let len = write(&address, &mut out).expect("serialise abstract");
        assert_eq!(len, 2 + 4);
        assert_eq!(&out[..2], &AF_UNIX.to_ne_bytes());
        assert_eq!(&out[2..len], &[0, b'a', 0, b'b']);
        // No trailing NUL is appended for an abstract name.
        assert_eq!(out[len], 0xAA);

        // The maximal engine-supported path length is accepted...
        let mut limit = [0u8; SOCKADDR_UN];
        limit[..2].copy_from_slice(&AF_UNIX.to_ne_bytes());
        limit[3..3 + 106].fill(b'z'); // path length 107 = marker + 106 bytes
        let limit_address = parse(&limit[..2 + 107]).expect("parse maximal abstract");
        assert_eq!(limit_address.path_bytes().len(), net::SOCKET_PATH_MAX);

        // ...and one byte more is rejected, not clipped.
        assert_eq!(parse(&limit[..2 + 108]), Err(errno::EINVAL));
        let mut too_long = [0u8; SOCKADDR_UN];
        too_long[..2].copy_from_slice(&AF_UNIX.to_ne_bytes());
        assert_eq!(parse(&too_long), Err(errno::EINVAL));
    }

    #[test]
    fn family_and_domain_helpers_agree() {
        for domain in [net::DOMAIN_UNIX, net::DOMAIN_INET, net::DOMAIN_INET6] {
            let family = family_for_domain(domain).expect("family");
            assert_eq!(domain_for_family(family), Some(domain));
            assert!(is_supported_family(family));
        }
        assert_eq!(family_for_domain(99), None);
        assert!(!is_supported_family(99));
    }
}
