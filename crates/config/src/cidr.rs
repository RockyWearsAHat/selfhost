//! Source-address matching in CIDR notation.
//!
//! A [`Cidr`] is the unit of a site's `allowed_cidrs` gate: each entry names a
//! network prefix, and a client may reach the site only when its source address
//! falls inside one of them. Parsing and matching live here, beside the schema,
//! so validation and the proxy's request-time check can never disagree about
//! what an entry means.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A network prefix such as `10.66.0.0/24` or `fd00::/8`.
///
/// A bare address is accepted as the exact-host prefix (`/32` for IPv4, `/128`
/// for IPv6). The network address is stored with its host bits already masked
/// off, so `10.66.0.7/24` and `10.66.0.0/24` describe the same network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    /// The network address, host bits zeroed.
    network: IpAddr,
    /// Number of leading bits that identify the network.
    prefix: u8,
}

impl Cidr {
    /// Parses `a.b.c.d/n`, `v6addr/n`, or a bare address of either family.
    ///
    /// The prefix must fit the family: 0–32 for IPv4, 0–128 for IPv6. Anything
    /// else — an unparseable address, an out-of-range or non-numeric prefix —
    /// is rejected with a message naming what was wrong.
    pub fn parse(text: &str) -> Result<Self, String> {
        let (addr_text, prefix_text) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text, None),
        };

        let addr: IpAddr = addr_text.parse().map_err(|_| {
            format!("\"{text}\" is not an IP address or CIDR block like 10.66.0.0/24")
        })?;
        let widest = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        let prefix = match prefix_text {
            None => widest,
            Some(digits) => {
                let n: u8 = digits.parse().map_err(|_| {
                    format!("\"{text}\" has a non-numeric prefix length \"{digits}\"")
                })?;
                if n > widest {
                    return Err(format!(
                        "\"{text}\" has prefix /{n}, but {} allows only /0 through /{widest}",
                        if widest == 32 { "IPv4" } else { "IPv6" }
                    ));
                }
                n
            }
        };

        Ok(Self { network: mask(addr, prefix), prefix })
    }

    /// Whether `ip` falls inside this network.
    ///
    /// An address of the other family is never contained: `10.0.0.0/8` says
    /// nothing about any IPv6 client, and vice versa.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                mask(ip, self.prefix) == self.network
            }
            _ => false,
        }
    }
}

/// Zeroes the host bits of `addr`, keeping the leading `prefix` bits.
///
/// A prefix of 0 keeps nothing (the all-zero network, matching everything) and
/// a full-width prefix keeps the address intact. The zero case is handled
/// explicitly because shifting an integer by its full width is undefined in
/// Rust rather than yielding zero.
fn mask(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let kept =
                if prefix == 0 { 0 } else { u32::from(v4) & (u32::MAX << (32 - u32::from(prefix))) };
            IpAddr::V4(Ipv4Addr::from(kept))
        }
        IpAddr::V6(v6) => {
            let kept = if prefix == 0 {
                0
            } else {
                u128::from(v6) & (u128::MAX << (128 - u32::from(prefix)))
            };
            IpAddr::V6(Ipv6Addr::from(kept))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn parses_ipv4_blocks_and_matches_by_network_prefix() {
        let vpn = Cidr::parse("10.66.0.0/24").unwrap();
        assert!(vpn.contains(ip("10.66.0.1")));
        assert!(vpn.contains(ip("10.66.0.254")));
        assert!(!vpn.contains(ip("10.66.1.1")));
        assert!(!vpn.contains(ip("192.168.1.1")));
    }

    #[test]
    fn host_bits_in_the_written_network_are_masked_off() {
        // 10.66.0.7/24 means the /24 containing .7, not a literal comparison
        // against .7 — the operator's sloppy spelling still gates correctly.
        let sloppy = Cidr::parse("10.66.0.7/24").unwrap();
        assert_eq!(sloppy, Cidr::parse("10.66.0.0/24").unwrap());
        assert!(sloppy.contains(ip("10.66.0.200")));
    }

    #[test]
    fn a_bare_ipv4_address_is_an_exact_host() {
        let host = Cidr::parse("192.168.1.9").unwrap();
        assert!(host.contains(ip("192.168.1.9")));
        assert!(!host.contains(ip("192.168.1.10")));
        assert_eq!(host, Cidr::parse("192.168.1.9/32").unwrap());
    }

    #[test]
    fn prefix_zero_matches_every_address_of_its_family_only() {
        let all_v4 = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(all_v4.contains(ip("8.8.8.8")));
        assert!(all_v4.contains(ip("255.255.255.255")));
        assert!(!all_v4.contains(ip("::1")));

        let all_v6 = Cidr::parse("::/0").unwrap();
        assert!(all_v6.contains(ip("fd00::1")));
        assert!(!all_v6.contains(ip("127.0.0.1")));
    }

    #[test]
    fn full_width_prefixes_match_exactly_one_address() {
        let v4 = Cidr::parse("172.83.6.109/32").unwrap();
        assert!(v4.contains(ip("172.83.6.109")));
        assert!(!v4.contains(ip("172.83.6.110")));

        let v6 = Cidr::parse("fd00::1/128").unwrap();
        assert!(v6.contains(ip("fd00::1")));
        assert!(!v6.contains(ip("fd00::2")));
    }

    #[test]
    fn parses_ipv6_blocks_and_bare_addresses() {
        let ula = Cidr::parse("fd00::/8").unwrap();
        assert!(ula.contains(ip("fd12:3456::1")));
        assert!(!ula.contains(ip("2001:db8::1")));

        let host = Cidr::parse("::1").unwrap();
        assert!(host.contains(ip("::1")));
        assert!(!host.contains(ip("::2")));
    }

    #[test]
    fn the_families_never_cross_match() {
        // An IPv4-mapped or unrelated v6 client must not slip through a v4
        // gate, and vice versa — mixed families are always outside.
        assert!(!Cidr::parse("10.0.0.0/8").unwrap().contains(ip("::ffff:10.0.0.1")));
        assert!(!Cidr::parse("fd00::/8").unwrap().contains(ip("10.0.0.1")));
    }

    #[test]
    fn rejects_junk_with_a_message_naming_the_input() {
        for junk in ["", "not-an-ip", "10.0.0/8", "10.0.0.0/", "10.0.0.0/8/2", "10.0.0.0/-1"] {
            let err = Cidr::parse(junk).unwrap_err();
            assert!(err.contains(junk), "error for {junk:?} should quote it: {err}");
        }
    }

    #[test]
    fn rejects_prefixes_wider_than_the_family() {
        let v4 = Cidr::parse("10.0.0.0/33").unwrap_err();
        assert!(v4.contains("/0 through /32"), "{v4}");
        // /33 is fine for IPv6 even though it is out of range for IPv4.
        assert!(Cidr::parse("fd00::/33").is_ok());
        let v6 = Cidr::parse("fd00::/129").unwrap_err();
        assert!(v6.contains("/0 through /128"), "{v6}");
    }
}
