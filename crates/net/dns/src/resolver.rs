//! A stub resolver: asks a full resolver a question over UDP.
//!
//! Which resolver is used matters more than it looks, and the reason is
//! specific: **Spamhaus refuses queries that arrive via large public resolvers**
//! such as `8.8.8.8` and `1.1.1.1`. A blocklist lookup through one of those
//! comes back as an error code in the `127.255.255.x` range that a careless
//! reader mistakes for "listed". So the system resolver is preferred, and when
//! a public fallback is used the caller is told, because it changes how the
//! answer should be read.

use crate::wire::{self, RecordType, Response, WireError};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

/// Default timeout for one query.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Where a resolver address came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverSource {
    /// Read from the operating system's configuration.
    System,
    /// Supplied by the caller.
    Explicit,
    /// A public fallback, used because the system's could not be determined.
    ///
    /// Blocklist answers obtained this way are not trustworthy.
    PublicFallback,
}

/// A configured stub resolver.
#[derive(Debug, Clone)]
pub struct Resolver {
    address: SocketAddr,
    source: ResolverSource,
    timeout: Duration,
}

/// Why a query failed.
#[derive(Debug)]
pub enum ResolveError {
    /// The socket could not be used.
    Io(io::Error),
    /// No answer arrived within the timeout.
    Timeout,
    /// The response could not be decoded.
    Wire(WireError),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Timeout => write!(f, "no answer before the timeout"),
            Self::Wire(e) => write!(f, "malformed response: {e}"),
        }
    }
}

impl std::error::Error for ResolveError {}

impl From<io::Error> for ResolveError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl Resolver {
    /// Uses a specific resolver address.
    pub fn at(address: SocketAddr) -> Self {
        Self { address, source: ResolverSource::Explicit, timeout: DEFAULT_TIMEOUT }
    }

    /// Discovers the system resolver, falling back to a public one.
    ///
    /// On Unix this reads `/etc/resolv.conf`. Windows keeps its resolvers in the
    /// registry and adapter configuration rather than a file, so discovery is
    /// not implemented there yet and the fallback is used — which is reported
    /// rather than hidden, because it changes how blocklist answers read.
    pub fn system() -> Self {
        match system_resolver() {
            Some(address) => Self { address, source: ResolverSource::System, timeout: DEFAULT_TIMEOUT },
            None => Self {
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
                source: ResolverSource::PublicFallback,
                timeout: DEFAULT_TIMEOUT,
            },
        }
    }

    /// Where this resolver's address came from.
    pub fn source(&self) -> ResolverSource {
        self.source
    }

    /// The resolver address in use.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Whether blocklist answers from this resolver can be trusted.
    ///
    /// Spamhaus returns an error code rather than a verdict when queried through
    /// a large public resolver, and that code is easily misread as a listing.
    pub fn trustworthy_for_blocklists(&self) -> bool {
        self.source != ResolverSource::PublicFallback
    }

    /// Sets the per-query timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Asks one question.
    pub async fn query(&self, name: &str, record_type: RecordType) -> Result<Response, ResolveError> {
        // A fixed id would let an off-path attacker guess it. This is derived
        // from the socket's ephemeral port and the clock rather than a random
        // number generator, which keeps the crate dependency-free.
        let id = query_id();
        let message = wire::encode_query(id, name, record_type).map_err(ResolveError::Wire)?;

        let bind: SocketAddr = if self.address.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }
            .parse()
            .expect("literal bind address");
        let socket = UdpSocket::bind(bind).await?;
        socket.send_to(&message, self.address).await?;

        let mut buffer = vec![0_u8; 4096];
        let received = match tokio::time::timeout(self.timeout, socket.recv(&mut buffer)).await {
            Ok(result) => result?,
            Err(_) => return Err(ResolveError::Timeout),
        };

        let response = &buffer[..received];
        // A reply whose id does not match belongs to a different question.
        if response.len() >= 2 && u16::from_be_bytes([response[0], response[1]]) != id {
            return Err(ResolveError::Wire(WireError::Truncated));
        }

        wire::decode_response(response).map_err(ResolveError::Wire)
    }

    /// Resolves IPv4 addresses.
    pub async fn lookup_a(&self, name: &str) -> Result<Vec<Ipv4Addr>, ResolveError> {
        let response = self.query(name, RecordType::A).await?;
        Ok(response
            .answers
            .iter()
            .filter_map(|record| match record.data {
                wire::RecordData::A(address) => Some(address),
                _ => None,
            })
            .collect())
    }

    /// Resolves mail exchangers, in the order they should be tried.
    pub async fn lookup_mx(&self, name: &str) -> Result<Vec<(u16, String)>, ResolveError> {
        Ok(self.query(name, RecordType::Mx).await?.mail_exchangers())
    }

    /// Resolves text records.
    pub async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, ResolveError> {
        Ok(self.query(name, RecordType::Txt).await?.texts())
    }

    /// Resolves the reverse name for an address.
    pub async fn lookup_ptr(&self, address: Ipv4Addr) -> Result<Vec<String>, ResolveError> {
        Ok(self.query(&reverse_name(address), RecordType::Ptr).await?.names())
    }

    /// Resolves nameservers.
    pub async fn lookup_ns(&self, name: &str) -> Result<Vec<String>, ResolveError> {
        Ok(self.query(name, RecordType::Ns).await?.names())
    }
}

/// The `in-addr.arpa` name for an IPv4 address.
///
/// The octets are reversed, which is also the form a DNS blocklist is queried
/// with — getting the order wrong asks about a completely different address and
/// reliably returns "not listed".
pub fn reverse_name(address: Ipv4Addr) -> String {
    let [a, b, c, d] = address.octets();
    format!("{d}.{c}.{b}.{a}.in-addr.arpa")
}

/// The query name for checking an address against a DNS blocklist.
pub fn blocklist_name(address: Ipv4Addr, zone: &str) -> String {
    let [a, b, c, d] = address.octets();
    format!("{d}.{c}.{b}.{a}.{zone}")
}

/// Whether a blocklist answer is a real listing rather than an error code.
///
/// Blocklists signal problems — query volume limits, a public resolver being
/// refused — by answering in `127.255.255.0/24`. Counting those as listings is a
/// common and alarming false positive.
pub fn is_real_listing(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    a == 127 && !(b == 255 && c == 255)
}

/// Reads the first nameserver from `/etc/resolv.conf`.
fn system_resolver() -> Option<SocketAddr> {
    #[cfg(unix)]
    {
        let text = std::fs::read_to_string("/etc/resolv.conf").ok()?;
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let mut parts = line.split_whitespace();
            if parts.next() != Some("nameserver") {
                continue;
            }
            if let Some(address) = parts.next().and_then(|a| a.parse::<IpAddr>().ok()) {
                return Some(SocketAddr::new(address, 53));
            }
        }
        None
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// A per-query identifier.
fn query_id() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    // Mixing in the process id keeps two processes starting together apart.
    (nanos as u16) ^ (std::process::id() as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_names_put_the_octets_in_the_right_order() {
        // Reversed order is the whole mechanism; getting it wrong asks about a
        // different address and quietly answers "not listed".
        assert_eq!(reverse_name(Ipv4Addr::new(172, 83, 7, 210)), "210.7.83.172.in-addr.arpa");
        assert_eq!(reverse_name(Ipv4Addr::new(1, 2, 3, 4)), "4.3.2.1.in-addr.arpa");
    }

    #[test]
    fn blocklist_names_are_built_the_same_way() {
        assert_eq!(
            blocklist_name(Ipv4Addr::new(172, 83, 7, 210), "zen.spamhaus.org"),
            "210.7.83.172.zen.spamhaus.org"
        );
    }

    #[test]
    fn error_codes_are_not_treated_as_listings() {
        // 127.255.255.x means the blocklist refused the query — often because it
        // came through a public resolver. Reading it as a listing is a false
        // positive that sends people chasing a problem they do not have.
        assert!(!is_real_listing(Ipv4Addr::new(127, 255, 255, 252)));
        assert!(!is_real_listing(Ipv4Addr::new(127, 255, 255, 254)));

        // Genuine verdicts.
        assert!(is_real_listing(Ipv4Addr::new(127, 0, 0, 2)));
        assert!(is_real_listing(Ipv4Addr::new(127, 0, 0, 3)));
        assert!(is_real_listing(Ipv4Addr::new(127, 0, 0, 4)));
        assert!(is_real_listing(Ipv4Addr::new(127, 0, 0, 10)));
    }

    #[test]
    fn a_public_fallback_is_flagged_as_untrustworthy_for_blocklists() {
        let public = Resolver::at("1.1.1.1:53".parse().unwrap());
        // Explicitly chosen is the caller's decision, so it is trusted.
        assert!(public.trustworthy_for_blocklists());

        let fallback = Resolver {
            address: "1.1.1.1:53".parse().unwrap(),
            source: ResolverSource::PublicFallback,
            timeout: DEFAULT_TIMEOUT,
        };
        assert!(!fallback.trustworthy_for_blocklists());
    }

    #[tokio::test]
    async fn a_dead_resolver_times_out_rather_than_hanging() {
        // 203.0.113.0/24 is reserved for documentation and routes nowhere.
        let resolver = Resolver::at("203.0.113.1:53".parse().unwrap())
            .with_timeout(Duration::from_millis(300));
        assert!(matches!(
            resolver.query("example.com", RecordType::A).await,
            Err(ResolveError::Timeout)
        ));
    }
}
