//! The authoritative DNS server: answers for zones this machine owns.
//!
//! This is the *other* direction from [`crate::resolver`]. The resolver asks a
//! full resolver a question; this answers questions clients ask us, from an
//! in-memory [`Zone`] set, over UDP and TCP on the same bind (usually `:53`).
//!
//! Three rules shape every line here, and each is a deliberate refusal:
//!
//! - **Authoritative only — never a resolver.** A query for a name in no zone we
//!   own is answered `REFUSED`, never forwarded and never `SERVFAIL`. Recursion
//!   is what turns a nameserver into a DNS amplification reflector; we do not
//!   have it, so we cannot be one.
//! - **NXDOMAIN and NODATA carry the SOA.** "The name does not exist" and "the
//!   name exists but has no record of that type" are different answers (RFC 2308),
//!   and both put the zone's SOA in the authority section so a resolver caches
//!   the negative for the right span.
//! - **UDP has a ceiling.** A UDP answer over 512 bytes is re-sent with its
//!   answers dropped and TC set, which tells the client to retry over TCP where
//!   there is no size cap. A forged-large answer cannot become an amplifier.
//!
//! Peer identity is used for exactly one thing: **split horizon.** When the
//! config names a LAN address ([`Dns::lan_ip`](selfhost_config::Dns)), a query
//! arriving from a private address is answered with that address wherever a
//! record points at the machine's public IP — a NAT that does not hairpin makes
//! the public address unreachable from inside — and names outside the served
//! zones are forwarded upstream so the router can hand this box out as the
//! LAN's resolver. A public peer never gets either behaviour: it sees exactly
//! the authoritative answers, and a name in no owned zone stays `REFUSED`, so
//! the public face cannot be used as an open resolver. Peer identity is still
//! **not** treated as authorisation for `AXFR`/`IXFR` — a source address is
//! spoofable where a zone transfer would leak data, so transfers stay refused
//! and a secondary bootstraps out of band via [`Authority::export`].

use crate::wire::{self, Query, Record, RecordData, RecordType, ResponseCode, ResponseFlags};
use crate::zone::Zone;
use selfhost_config::{Config, RecordConfig};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;

/// Largest UDP datagram accepted on receive, matching the EDNS0 size clients
/// advertise and the resolver/forwarder buffers elsewhere in the crate.
const MAX_UDP: usize = 4096;

/// The safe ceiling for a UDP *response* before it must be truncated. 512 is the
/// classic floor every client accepts without EDNS0; honouring a larger
/// advertised size is a later refinement.
const MAX_UDP_RESPONSE: usize = 512;

/// TTL used for a freshly written apex A when the zone had none to inherit from.
const DEFAULT_A_TTL: u32 = 3600;

/// How long a LAN client's forwarded query waits on the upstream resolver.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// The split-horizon view LAN peers are answered from.
///
/// `lan_ip` replaces the public address in answers, and `upstream` receives the
/// queries for names outside every served zone. Held in a `OnceLock` on the
/// authority because it is decided once at startup, from config, before the
/// first query arrives.
#[derive(Debug, Clone, Copy)]
pub struct LanView {
    /// The address LAN peers should reach this machine at.
    pub lan_ip: Ipv4Addr,
    /// The resolver LAN peers' foreign queries are forwarded to.
    pub upstream: SocketAddr,
}

/// The set of zones this machine is authoritative for.
///
/// Clone is cheap (a shared `Arc`), so the daemon that binds the sockets and the
/// updater that rewrites the apex A hold the same zones rather than two that
/// could disagree — the same handle pattern as `firewall::Manager` and
/// `Supervisor`. Zones sit behind a `Mutex` because the updater mutates them in
/// place while the server reads them per query.
#[derive(Clone)]
pub struct Authority(Arc<Inner>);

struct Inner {
    zones: Mutex<Vec<Zone>>,
    /// The public address the zones' derived records point at, kept beside them
    /// so split-horizon substitution and the WAN-change retarget agree on which
    /// address "means this machine". `None` until discovery or the updater's
    /// first tick supplies one.
    public_ip: Mutex<Option<Ipv4Addr>>,
    /// The split-horizon view, set once at startup when `[dns].lan_ip` is
    /// configured. Absent means every peer gets the public answers and nothing
    /// is ever forwarded.
    lan: OnceLock<LanView>,
}

impl Inner {
    fn new(zones: Vec<Zone>, public_ip: Option<Ipv4Addr>) -> Self {
        Self { zones: Mutex::new(zones), public_ip: Mutex::new(public_ip), lan: OnceLock::new() }
    }
}

/// Why the DNS server could not start or serve.
#[derive(Debug)]
pub enum DnsError {
    /// A listener could not be bound — privilege on `:53`, or the address is in use.
    Bind {
        /// The address that could not be bound.
        address: SocketAddr,
        /// The underlying OS error.
        source: io::Error,
    },
    /// A listener failed while serving.
    Io(io::Error),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind { address, source } => write!(f, "cannot bind {address}: {source}"),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for DnsError {}

impl From<io::Error> for DnsError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl Authority {
    /// Builds the authoritative set from config and this machine's public IP.
    ///
    /// Zones come from `[dns]`. A bare zone with no records is expanded from
    /// `public_ip` by `Zone::from_config`. Returns an empty authority — which
    /// serves nothing and refuses everything — when `[dns]` is absent, because
    /// DNS is opt-in.
    pub fn for_config(config: &Config, public_ip: Option<Ipv4Addr>) -> Self {
        Self::for_config_with_mail(config, public_ip, &[])
    }

    /// Builds the authoritative set, also publishing each mail domain's records.
    ///
    /// `mail_records` maps a mail domain to the records `config::Mail::dns_records`
    /// generated for it — the `MX`, SPF, DMARC, DKIM, and CAA a domain must carry
    /// to send and receive. The caller generates them (not this crate) because the
    /// DKIM public key is derived by the `mail` crate, which `dns` does not depend
    /// on; the daemon, which depends on both, is the one place all three meet.
    ///
    /// A domain's records are appended only to a **bare** zone — one that listed
    /// none of its own — honouring the "explicit records replace defaults" rule: a
    /// zone the operator spelled out by hand is served exactly as written, mail
    /// records included only if they wrote them.
    pub fn for_config_with_mail(
        config: &Config,
        public_ip: Option<Ipv4Addr>,
        mail_records: &[(String, Vec<RecordConfig>)],
    ) -> Self {
        let zones = config
            .dns
            .as_ref()
            .map(|dns| {
                dns.zones
                    .iter()
                    .map(|zone_config| {
                        let mut zone =
                            Zone::from_config(zone_config, &dns.secondaries, public_ip);
                        if zone_config.records.is_empty() {
                            if let Some((_, records)) = mail_records
                                .iter()
                                .find(|(domain, _)| domain.eq_ignore_ascii_case(&zone.origin))
                            {
                                zone.push_config_records(records);
                            }
                            populate_claimed_hosts(&mut zone, config, public_ip);
                        }
                        zone
                    })
                    .collect()
            })
            .unwrap_or_default();
        Authority(Arc::new(Inner::new(zones, public_ip)))
    }

    /// Enables the split-horizon LAN view (see the module note).
    ///
    /// Decided once at startup, before the first query; the first call wins and
    /// any later call is a no-op by design — a view that changed mid-flight
    /// would answer half a client's queries from each horizon.
    pub fn set_lan(&self, view: LanView) {
        let _ = self.0.lan.set(view);
    }

    /// Serves UDP + TCP on `bind` until a listener fails.
    ///
    /// The two halves run under one `try_join!`, so a failure in either stops the
    /// whole server; `Ctrl-C`/SIGTERM handling belongs to the caller (the daemon's
    /// `select!`). TCP messages are length-prefixed, one task per connection.
    pub async fn serve(&self, bind: SocketAddr) -> Result<(), DnsError> {
        let datagram = Arc::new(
            UdpSocket::bind(bind)
                .await
                .map_err(|source| DnsError::Bind { address: bind, source })?,
        );
        let stream = TcpListener::bind(bind)
            .await
            .map_err(|source| DnsError::Bind { address: bind, source })?;

        tokio::try_join!(self.serve_udp(datagram), self.serve_tcp(stream))?;
        Ok(())
    }

    /// The UDP half: one datagram in, one datagram out, each query on its own task.
    async fn serve_udp(&self, socket: Arc<UdpSocket>) -> Result<(), DnsError> {
        let mut buffer = vec![0_u8; MAX_UDP];
        loop {
            let (read, from) = socket.recv_from(&mut buffer).await?;
            let raw = buffer[..read].to_vec();
            let authority = self.clone();
            let socket = Arc::clone(&socket);
            tokio::spawn(async move {
                let answer = authority.handle_query(&raw, false, from.ip()).await;
                let _ = socket.send_to(&answer, from).await;
            });
        }
    }

    /// The TCP half: accept, then serve length-prefixed messages per connection.
    async fn serve_tcp(&self, listener: TcpListener) -> Result<(), DnsError> {
        loop {
            let (client, from) = listener.accept().await?;
            let authority = self.clone();
            tokio::spawn(async move {
                let _ = authority.serve_connection(client, from.ip()).await;
            });
        }
    }

    /// Serves one TCP connection, message by message, until the client hangs up.
    async fn serve_connection(&self, mut client: TcpStream, peer: IpAddr) -> io::Result<()> {
        loop {
            let Some(raw) = read_message(&mut client).await? else { return Ok(()) };
            let answer = self.handle_query(&raw, true, peer).await;
            write_message(&mut client, &answer).await?;
        }
    }

    /// Decodes one query, finds the owning zone, and builds the reply bytes.
    ///
    /// Never panics on hostile input: an undecodable message becomes a
    /// `FORMERR` reply rather than an error, because a nameserver that dies on a
    /// bad packet is a nameserver one packet can take down.
    ///
    /// `peer` decides the horizon (see the module note): a private peer with a
    /// configured [`LanView`] is answered with the LAN address wherever a record
    /// points at the public one, and its foreign questions are forwarded
    /// upstream; every other peer gets the pure authoritative behaviour.
    async fn handle_query(&self, raw: &[u8], over_tcp: bool, peer: IpAddr) -> Vec<u8> {
        let query = match wire::decode_query(raw) {
            Ok(query) => query,
            Err(_) => {
                let answer = format_error(raw);
                eprintln!(
                    "{} [dns] {peer} malformed query ({} bytes): FORMERR",
                    crate::time::stamp(),
                    raw.len()
                );
                return answer;
            }
        };
        // Clone the matched zone out from under the lock so the response is built
        // without holding it — the updater must be able to write meanwhile.
        let zone = {
            let zones = self.0.zones.lock().await;
            zones.iter().find(|zone| zone.contains(&query.name)).cloned()
        };
        let lan = self.0.lan.get().copied().filter(|_| is_lan_peer(peer));

        let answer = match (zone, lan) {
            (Some(zone), Some(view)) => {
                let public = *self.0.public_ip.lock().await;
                respond(&query, Some(&lan_horizon(zone, public, view.lan_ip)), over_tcp)
            }
            (Some(zone), None) => respond(&query, Some(&zone), over_tcp),
            // A LAN peer's foreign question is forwarded so the router can hand
            // this box out as the network's one resolver. SERVFAIL when the
            // upstream gives nothing usable — honest, and the client retries.
            (None, Some(view)) => match forward(raw, view.upstream, over_tcp).await {
                Some(answer) => answer,
                None => wire::encode_response(
                    &query,
                    ResponseCode::ServerFailure,
                    plain_flags(),
                    &[],
                    &[],
                    &[],
                ),
            },
            (None, None) => respond(&query, None, over_tcp),
        };
        log_query(peer, &query.name, query.record_type, &answer);
        answer
    }

    /// Replaces the apex A of `origin` and bumps that zone's SOA serial in place.
    ///
    /// Returns the new serial, or `None` if no such zone. The serial only ever
    /// increases (RFC 1982 arithmetic) — a serial that went backwards would make
    /// a secondary ignore the change. Called by the dynamic-IP updater.
    pub async fn set_apex_a(&self, origin: &str, address: Ipv4Addr) -> Option<u32> {
        let mut zones = self.0.zones.lock().await;
        let zone = zones.iter_mut().find(|zone| zone.origin.eq_ignore_ascii_case(origin))?;

        let apex = zone.origin.clone();
        let is_apex_a =
            |record: &Record| record.name.eq_ignore_ascii_case(&apex) && matches!(record.data, RecordData::A(_));
        let ttl = zone.records.iter().find(|record| is_apex_a(record)).map_or(DEFAULT_A_TTL, |record| record.ttl);

        zone.records.retain(|record| !is_apex_a(record));
        zone.records.push(Record { name: apex, ttl, data: RecordData::A(address) });
        // Saturating, never wrapping: a serial that wrapped past u32::MAX to 0
        // would go *backwards*, and a secondary silently ignores a zone whose
        // serial decreased — the exact failure this whole design guards against.
        zone.soa.serial = zone.soa.serial.saturating_add(1);
        let serial = zone.soa.serial;
        drop(zones);

        // The apex A *is* this machine's public address (that is what the
        // dynamic-IP updater tracks), so split-horizon substitution must follow
        // it — a stale public_ip here would stop rewriting answers for LAN peers.
        *self.0.public_ip.lock().await = Some(address);
        Some(serial)
    }

    /// Upserts a record in the zone authoritative for `name`, bumping its serial.
    ///
    /// Every existing record of the same owner name and type is replaced, then
    /// `data` is added; the new record inherits an existing TTL for that
    /// name/type, or [`DEFAULT_A_TTL`] when there was none. The serial only ever
    /// increases (RFC 1982 arithmetic, saturating never wrapping) so a secondary
    /// always sees the change.
    ///
    /// Returns the new serial, or `None` when no served zone is authoritative for
    /// `name`. That `None` is the signal a caller uses to report that this
    /// deployment does not own the name, so no record can be written for it
    /// here. This generalises
    /// [`set_apex_a`](Self::set_apex_a) to any owner name and record type — a
    /// freshly-provisioned subdomain's A record is the motivating case.
    pub async fn upsert_record(&self, name: &str, data: RecordData) -> Option<u32> {
        let owner = normalize_name(name);
        let kind = record_kind(&data);

        let mut zones = self.0.zones.lock().await;
        let zone = zones.iter_mut().find(|zone| zone.contains(&owner))?;

        let matches = |record: &Record| record.name.eq_ignore_ascii_case(&owner) && record_kind(&record.data) == kind;
        let ttl = zone.records.iter().find(|record| matches(record)).map_or(DEFAULT_A_TTL, |record| record.ttl);

        zone.records.retain(|record| !matches(record));
        zone.records.push(Record { name: owner, ttl, data });
        zone.soa.serial = zone.soa.serial.saturating_add(1);
        Some(zone.soa.serial)
    }

    /// Removes every record of `name`/`rtype` from its zone, bumping the serial.
    ///
    /// Returns the new serial when something was actually removed, and `None`
    /// when no served zone owns `name` or the name held no such record — in
    /// either case there is nothing to propagate, so the serial is left alone.
    /// The inverse of [`upsert_record`](Self::upsert_record); used when a site is
    /// taken down.
    pub async fn remove_record(&self, name: &str, rtype: RecordType) -> Option<u32> {
        let owner = normalize_name(name);

        let mut zones = self.0.zones.lock().await;
        let zone = zones.iter_mut().find(|zone| zone.contains(&owner))?;

        let before = zone.records.len();
        zone.records.retain(|record| !(record.name.eq_ignore_ascii_case(&owner) && record_kind(&record.data) == rtype));
        if zone.records.len() == before {
            return None;
        }
        zone.soa.serial = zone.soa.serial.saturating_add(1);
        Some(zone.soa.serial)
    }

    /// The origin of the served zone authoritative for `name`, if any.
    ///
    /// A read-only companion to [`upsert_record`](Self::upsert_record): it tells a
    /// caller whether this machine's DNS owns a name *without* mutating anything,
    /// which is what a diagnostic (`doctor`) needs to say "served here" versus
    /// "no zone here covers this name".
    pub async fn zone_for(&self, name: &str) -> Option<String> {
        let owner = normalize_name(name);
        let zones = self.0.zones.lock().await;
        zones.iter().find(|zone| zone.contains(&owner)).map(|zone| zone.origin.clone())
    }

    /// A snapshot of one zone as wire records — SOA, NS, then the rest — for a
    /// secondary bootstrap and for the doctor. `None` if the zone is not served.
    pub async fn export(&self, origin: &str) -> Option<Vec<Record>> {
        let zones = self.0.zones.lock().await;
        let zone = zones.iter().find(|zone| zone.origin.eq_ignore_ascii_case(origin))?;
        let mut out = Vec::with_capacity(zone.records.len() + zone.nameservers.len() + 1);
        out.push(zone.soa_record());
        out.extend(zone.ns_records());
        out.extend(zone.records.iter().cloned());
        Some(out)
    }

    /// The origins served, for startup logging and the doctor.
    pub async fn origins(&self) -> Vec<String> {
        self.0.zones.lock().await.iter().map(|zone| zone.origin.clone()).collect()
    }
}

/// Gives every hostname the rest of the config claims under `zone` an address,
/// and a mail-covered zone its RFC 6186 service locators.
///
/// Called only for a **bare** zone (one that listed no records of its own), so
/// the "explicit records replace defaults" rule holds. Adds, at `public_ip`:
///
/// - an `A` for each site domain the zone contains — a provisioned site
///   resolves without the operator writing a record for it;
/// - an `A` for the `[mail]` hostname and each client-autoconfig host
///   (`mail.`/`imap.`/`smtp.`/`ua-auto-config.`/`autodiscover.` per mail
///   domain) the zone contains;
/// - when the zone's origin is a mail domain, `_imaps._tcp` → port 993 at
///   `imap.<origin>`, `_submission._tcp` → port 587 at `smtp.<origin>`
///   (RFC 6186 `STARTTLS` discovery), and `_submissions._tcp` → port 465 at
///   `smtp.<origin>` (RFC 8314 implicit-TLS discovery, served alongside 587,
///   never instead of it). This zone is the only place those records exist, so
///   there is no second copy of them to disagree with about client discovery.
///
/// With no `public_ip` yet, only the SRVs are added: their targets are names,
/// not addresses, and the updater fills the missing `A`s on its first tick.
fn populate_claimed_hosts(zone: &mut Zone, config: &Config, public_ip: Option<Ipv4Addr>) {
    if let Some(ip) = public_ip {
        for site in &config.sites {
            for domain in &site.domains {
                if zone.contains(domain) {
                    zone.ensure_address(domain, ip);
                }
            }
        }
    }
    let Some(mail) = &config.mail else { return };
    if let Some(ip) = public_ip {
        if zone.contains(&mail.hostname) {
            zone.ensure_address(&mail.hostname, ip);
        }
        for host in mail.client_hosts() {
            if zone.contains(&host) {
                zone.ensure_address(&host, ip);
            }
        }
    }
    if mail.domains.iter().any(|domain| domain.eq_ignore_ascii_case(&zone.origin)) {
        let origin = zone.origin.clone();
        for (service, port, target) in [
            ("_imaps._tcp", 993, format!("imap.{origin}")),
            ("_submission._tcp", 587, format!("smtp.{origin}")),
            ("_submissions._tcp", 465, format!("smtp.{origin}")),
        ] {
            zone.records.push(Record {
                name: format!("{service}.{origin}"),
                ttl: DEFAULT_A_TTL,
                data: RecordData::Srv { priority: 0, weight: 1, port, target },
            });
        }
    }
}

/// The LAN peer's view of a zone: every address record that points at the
/// public IP is rewritten to the LAN one, because a NAT that does not hairpin
/// makes the public address unreachable from inside. With no known public IP
/// there is nothing to recognise, so the zone passes through unchanged.
fn lan_horizon(mut zone: Zone, public_ip: Option<Ipv4Addr>, lan_ip: Ipv4Addr) -> Zone {
    let Some(public) = public_ip else { return zone };
    for record in &mut zone.records {
        if record.data == RecordData::A(public) {
            record.data = RecordData::A(lan_ip);
        }
    }
    zone
}

/// Whether a peer address belongs to the local network — the split-horizon
/// gate. Private, loopback, and link-local ranges count for IPv4; loopback,
/// unique-local, and link-local for IPv6. Everything else is the public face.
fn is_lan_peer(peer: IpAddr) -> bool {
    match peer {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Relays one raw query to the upstream resolver and returns its raw answer,
/// or `None` on timeout or failure. UDP queries forward over UDP and TCP over
/// TCP, so a truncated upstream answer keeps meaning "retry over TCP" to the
/// client that receives it. A fresh ephemeral socket per query keeps
/// concurrent answers from crossing without tracking message ids ourselves.
async fn forward(raw: &[u8], upstream: SocketAddr, over_tcp: bool) -> Option<Vec<u8>> {
    let exchange = async {
        if over_tcp {
            let mut server = TcpStream::connect(upstream).await.ok()?;
            write_message(&mut server, raw).await.ok()?;
            read_message(&mut server).await.ok().flatten()
        } else {
            let bind = if upstream.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
            let socket = UdpSocket::bind(bind).await.ok()?;
            socket.send_to(raw, upstream).await.ok()?;
            let mut buffer = vec![0_u8; MAX_UDP];
            let read = socket.recv(&mut buffer).await.ok()?;
            buffer.truncate(read);
            Some(buffer)
        }
    };
    tokio::time::timeout(UPSTREAM_TIMEOUT, exchange).await.ok().flatten()
}

/// Builds the reply for one decoded query against its (maybe-absent) zone.
///
/// Pure: no sockets, no lock — every branch of the answer algorithm is decided
/// here so it can be tested with a hand-built `Zone` and `Query`.
fn respond(query: &Query, zone: Option<&Zone>, over_tcp: bool) -> Vec<u8> {
    let Some(zone) = zone else {
        // Not our zone. Authoritative-only: REFUSED, never a forward, never SERVFAIL.
        return wire::encode_response(query, ResponseCode::Refused, plain_flags(), &[], &[], &[]);
    };

    let (code, answers, authority, additional) = resolve(zone, query);
    let flags = ResponseFlags { authoritative: true, truncated: false };
    let message = wire::encode_response(query, code, flags, &answers, &authority, &additional);

    if over_tcp || message.len() <= MAX_UDP_RESPONSE {
        return message;
    }

    // Too large for UDP: drop the answers and set TC so the client retries over
    // TCP. If the remaining sections still overflow, clear them too — a truncated
    // datagram must be guaranteed to fit.
    let truncated = ResponseFlags { authoritative: true, truncated: true };
    let cut = wire::encode_response(query, code, truncated, &[], &authority, &additional);
    if cut.len() <= MAX_UDP_RESPONSE {
        cut
    } else {
        wire::encode_response(query, code, truncated, &[], &[], &[])
    }
}

/// The record sections for a query known to fall inside `zone`.
///
/// Returns `(rcode, answers, authority, additional)` per RFC 1034/2308: a match
/// answers with the apex NS in authority and glue in additional; a name that
/// exists without the asked type is NODATA (empty answer, SOA in authority); a
/// name that does not exist is NXDOMAIN (SOA in authority).
fn resolve(zone: &Zone, query: &Query) -> (ResponseCode, Vec<Record>, Vec<Record>, Vec<Record>) {
    let name = &query.name;
    let qtype = query.record_type;
    let is_apex = name.eq_ignore_ascii_case(&zone.origin);

    // AXFR (252) / IXFR (251): a zone transfer is authorised by the peer's
    // identity, which this layer is not given (see the module note). Refuse
    // rather than hand a zone to an unverified caller.
    if matches!(qtype, RecordType::Other(251) | RecordType::Other(252)) {
        return (ResponseCode::Refused, Vec::new(), Vec::new(), Vec::new());
    }

    // The apex SOA and NS live beside the record set, not in it, so they are
    // answered explicitly rather than through `Zone::answer`.
    if is_apex && qtype == RecordType::Soa {
        let answers = vec![zone.soa_record()];
        let authority = zone.ns_records();
        let additional = glue(zone, &authority);
        return (ResponseCode::NoError, answers, authority, additional);
    }
    if is_apex && qtype == RecordType::Ns {
        let answers = zone.ns_records();
        let additional = glue(zone, &answers);
        return (ResponseCode::NoError, answers, Vec::new(), additional);
    }

    let answers = zone.answer(name, qtype);
    if !answers.is_empty() {
        let authority = zone.ns_records();
        let mut additional = glue(zone, &authority);
        // Glue for hostnames named in the answer itself (delegating NS, MX).
        for record in glue(zone, &answers) {
            if !additional.contains(&record) {
                additional.push(record);
            }
        }
        return (ResponseCode::NoError, answers, authority, additional);
    }

    // Empty answer: name exists → NODATA; name absent → NXDOMAIN. Both carry the
    // SOA so the negative answer caches for the zone's minimum TTL.
    let code = if zone.name_exists(name) { ResponseCode::NoError } else { ResponseCode::NameError };
    (code, Vec::new(), vec![zone.soa_record()], Vec::new())
}

/// Address records within `zone` for the hostnames named by `records`.
///
/// Feeds the additional section: an NS or MX answer is only useful with the
/// target's A/AAAA alongside it. Only in-zone targets are glued — supplying
/// addresses for names in another zone is out-of-bailiwick and ignored by
/// resolvers.
fn glue(zone: &Zone, records: &[Record]) -> Vec<Record> {
    let mut out: Vec<Record> = Vec::new();
    for record in records {
        let target = match &record.data {
            RecordData::Name(name) => name,
            RecordData::Mx { exchange, .. } => exchange,
            _ => continue,
        };
        if !zone.contains(target) {
            continue;
        }
        let addresses =
            zone.answer(target, RecordType::A).into_iter().chain(zone.answer(target, RecordType::Aaaa));
        for address in addresses {
            if !out.contains(&address) {
                out.push(address);
            }
        }
    }
    out
}

/// One `[dns]`-tagged line into the daemon's log stream, per query answered.
///
/// This is the server's only record of what it was asked and what it said
/// back — every other subsystem (mail, IMAP, the HTTP proxy) logs each
/// connection, and DNS was a blind spot: an intermittent bad answer (a
/// resolver hitting this box at the wrong moment) left nothing to inspect
/// after the fact. Decoding `answer` back into a [`wire::Response`] here,
/// rather than threading the response code out through every branch of
/// [`Authority::handle_query`], keeps this the one place that needs to know
/// the wire format of what already went out on the socket.
fn log_query(peer: IpAddr, name: &str, qtype: RecordType, answer: &[u8]) {
    match wire::decode_response(answer) {
        Ok(response) => eprintln!(
            "{} [dns] {peer} {name} {qtype} {} answers={}",
            crate::time::stamp(),
            response.code,
            response.answers.len()
        ),
        Err(_) => eprintln!("{} [dns] {peer} {name} {qtype} ?", crate::time::stamp()),
    }
}

/// Flags for a reply that is not authoritative and not truncated (REFUSED, FORMERR).
fn plain_flags() -> ResponseFlags {
    ResponseFlags { authoritative: false, truncated: false }
}

/// An owner name in the form the zone stores: lowercased, no trailing dot.
///
/// Callers pass names in whatever case and with or without the root dot; the
/// zone's own records are canonicalised this way, so an upsert must match them.
fn normalize_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// The record type a payload carries, for matching an owner+type RRset.
///
/// Local to this module by intent: `wire` and `zone` each keep their own copy
/// rather than share a public one, and an upsert only ever needs it to find the
/// existing records it must replace.
fn record_kind(data: &RecordData) -> RecordType {
    match data {
        RecordData::A(_) => RecordType::A,
        RecordData::Aaaa(_) => RecordType::Aaaa,
        RecordData::Name(_) => RecordType::Cname,
        RecordData::Mx { .. } => RecordType::Mx,
        RecordData::Txt(_) => RecordType::Txt,
        RecordData::Soa { .. } => RecordType::Soa,
        RecordData::Srv { .. } => RecordType::Srv,
        RecordData::Unknown { record_type, .. } => *record_type,
    }
}

/// A `FORMERR` reply for a message that could not be decoded.
///
/// Echoes the id if the first two bytes are readable so the client can match the
/// reply to its query; falls back to id 0 when even that is missing.
fn format_error(raw: &[u8]) -> Vec<u8> {
    let id = if raw.len() >= 2 { u16::from_be_bytes([raw[0], raw[1]]) } else { 0 };
    let query = Query { id, name: String::new(), record_type: RecordType::A, recursion_desired: false };
    wire::encode_response(&query, ResponseCode::FormatError, plain_flags(), &[], &[], &[])
}

/// Reads one length-prefixed DNS message, or `None` at a clean end of stream.
async fn read_message(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0_u8; 2];
    match stream.read_exact(&mut length).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let mut message = vec![0_u8; u16::from_be_bytes(length) as usize];
    stream.read_exact(&mut message).await?;
    Ok(Some(message))
}

/// Writes one length-prefixed DNS message.
async fn write_message(stream: &mut TcpStream, message: &[u8]) -> io::Result<()> {
    let length = u16::try_from(message.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "DNS message exceeds 65535 bytes"))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(message).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{self, Record, RecordData, RecordType, ResponseCode};
    use crate::zone::{Soa, Zone};
    use std::net::Ipv4Addr;

    const PUBLIC: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
    /// A peer on the public internet: sees exactly the authoritative answers.
    const WAN_PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200));
    /// A peer on the home network: gets the split-horizon view when one is set.
    const LAN_PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 23));
    /// The LAN address split-horizon answers substitute for [`PUBLIC`].
    const LAN_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 8);

    /// A small example.com zone: apex A + www A, an MX, and an in-zone ns1.
    fn example_zone() -> Zone {
        Zone {
            origin: "example.com".to_owned(),
            soa: Soa {
                primary: "ns1.example.com".to_owned(),
                responsible: "hostmaster.example.com".to_owned(),
                serial: 2_026_080_700,
                refresh: 7200,
                retry: 3600,
                expire: 1_209_600,
                minimum: 3600,
            },
            nameservers: vec!["ns1.example.com".to_owned()],
            records: vec![
                record("example.com", RecordData::A(PUBLIC)),
                record("www.example.com", RecordData::A(PUBLIC)),
                record("example.com", RecordData::Mx { preference: 10, exchange: "mail.example.com".to_owned() }),
                record("ns1.example.com", RecordData::A(PUBLIC)),
            ],
        }
    }

    fn record(name: &str, data: RecordData) -> Record {
        Record { name: name.to_owned(), ttl: 3600, data }
    }

    fn ask(name: &str, record_type: RecordType) -> Query {
        Query { id: 0x1234, name: name.to_owned(), record_type, recursion_desired: true }
    }

    /// The AA bit out of a raw response's flags byte.
    fn is_authoritative(message: &[u8]) -> bool {
        message[2] & 0x04 != 0
    }

    /// The TC bit out of a raw response's flags byte.
    fn is_truncated(message: &[u8]) -> bool {
        message[2] & 0x02 != 0
    }

    #[test]
    fn an_apex_a_query_is_answered_authoritatively() {
        let zone = example_zone();
        let message = respond(&ask("example.com", RecordType::A), Some(&zone), false);

        assert!(is_authoritative(&message), "an answer from our own zone sets AA");
        assert_eq!(message[..2], [0x12, 0x34], "the id is echoed");
        let response = wire::decode_response(&message).unwrap();
        assert_eq!(response.code, ResponseCode::NoError);
        assert_eq!(response.first_a(), Some(PUBLIC));
        // The apex NS belongs in the authority section.
        assert!(response.authority.iter().any(|record| matches!(&record.data, RecordData::Name(name) if name == "ns1.example.com")));
    }

    #[test]
    fn an_mx_query_returns_the_exchanger() {
        let zone = example_zone();
        let message = respond(&ask("example.com", RecordType::Mx), Some(&zone), false);
        let response = wire::decode_response(&message).unwrap();
        assert_eq!(response.code, ResponseCode::NoError);
        assert_eq!(response.mail_exchangers(), vec![(10, "mail.example.com".to_owned())]);
    }

    #[test]
    fn an_apex_ns_query_lists_the_nameservers() {
        let zone = example_zone();
        let message = respond(&ask("example.com", RecordType::Ns), Some(&zone), false);
        let response = wire::decode_response(&message).unwrap();
        assert_eq!(response.code, ResponseCode::NoError);
        assert!(is_authoritative(&message));
        assert_eq!(response.names(), vec!["ns1.example.com".to_owned()]);
    }

    #[test]
    fn an_apex_soa_query_carries_the_serial() {
        // The serial and timers must be on the wire; the resolver's SOA read
        // dropped them, which is why wire.rs §1c put them back.
        let zone = example_zone();
        let message = respond(&ask("example.com", RecordType::Soa), Some(&zone), false);
        let response = wire::decode_response(&message).unwrap();
        assert_eq!(response.code, ResponseCode::NoError);
        let soa = response
            .answers
            .iter()
            .find_map(|record| match &record.data {
                RecordData::Soa { serial, minimum, .. } => Some((*serial, *minimum)),
                _ => None,
            })
            .expect("an SOA in the answer");
        assert_eq!(soa, (2_026_080_700, 3600));
    }

    #[test]
    fn a_missing_name_is_nxdomain_with_the_soa_in_authority() {
        // "does not exist" must be distinguishable and cacheable: NXDOMAIN plus
        // the SOA so a resolver caches the negative for the zone minimum.
        let zone = example_zone();
        let message = respond(&ask("nope.example.com", RecordType::A), Some(&zone), false);
        let response = wire::decode_response(&message).unwrap();
        assert_eq!(response.code, ResponseCode::NameError);
        assert!(response.answers.is_empty());
        assert!(is_authoritative(&message));
        assert!(response.authority.iter().any(|record| matches!(record.data, RecordData::Soa { .. })));
    }

    #[test]
    fn an_existing_name_without_the_type_is_nodata_not_nxdomain() {
        // www exists as an A; asking it for MX is NODATA (NOERROR, empty answer,
        // SOA in authority), never NXDOMAIN.
        let zone = example_zone();
        let message = respond(&ask("www.example.com", RecordType::Mx), Some(&zone), false);
        let response = wire::decode_response(&message).unwrap();
        assert_eq!(response.code, ResponseCode::NoError);
        assert!(response.answers.is_empty());
        assert!(response.authority.iter().any(|record| matches!(record.data, RecordData::Soa { .. })));
    }

    #[test]
    fn a_name_in_no_owned_zone_is_refused() {
        // Authoritative-only: a foreign name is REFUSED, not resolved, and AA is
        // clear because we assert nothing about a zone we do not own.
        let message = respond(&ask("example.org", RecordType::A), None, false);
        let response = wire::decode_response(&message).unwrap();
        assert_eq!(response.code, ResponseCode::Refused);
        assert!(!is_authoritative(&message));
        assert!(response.answers.is_empty());
    }

    #[test]
    fn a_zone_transfer_is_refused_without_a_verified_peer() {
        // AXFR is authorised by peer identity, which respond() is not given.
        let zone = example_zone();
        let message = respond(&ask("example.com", RecordType::Other(252)), Some(&zone), true);
        assert_eq!(wire::decode_response(&message).unwrap().code, ResponseCode::Refused);
    }

    #[test]
    fn an_oversized_udp_answer_sets_tc_and_drops_answers() {
        // A large answer over UDP must come back truncated so the client retries
        // over TCP, rather than being sent as an oversized (amplifiable) datagram.
        let mut zone = example_zone();
        for octet in 0..40_u8 {
            zone.records.push(record("example.com", RecordData::A(Ipv4Addr::new(203, 0, 113, octet))));
        }

        let over_udp = respond(&ask("example.com", RecordType::A), Some(&zone), false);
        assert!(over_udp.len() <= MAX_UDP_RESPONSE, "a UDP reply must fit the 512-byte floor");
        assert!(is_truncated(&over_udp), "TC tells the client to retry over TCP");
        assert!(wire::decode_response(&over_udp).unwrap().answers.is_empty());

        // The same query over TCP is not truncated and carries the full set.
        let over_tcp = respond(&ask("example.com", RecordType::A), Some(&zone), true);
        assert!(!is_truncated(&over_tcp));
        assert!(over_tcp.len() > MAX_UDP_RESPONSE);
        assert!(wire::decode_response(&over_tcp).unwrap().answers.len() >= 40);
    }

    #[tokio::test]
    async fn a_malformed_packet_is_answered_formerr_not_a_panic() {
        // A nameserver a single bad packet can crash is a nameserver one packet
        // can take offline. Every hostile shape decodes to FORMERR.
        let authority = Authority(Arc::new(Inner::new(vec![example_zone()], None)));
        for raw in [&[][..], &[0x00][..], &[0x12, 0x34, 0x00][..], &[0xff; 5][..]] {
            let message = authority.handle_query(raw, false, WAN_PEER).await;
            let response = wire::decode_response(&message).unwrap();
            assert_eq!(response.code, ResponseCode::FormatError, "raw {raw:?}");
        }
    }

    #[tokio::test]
    async fn handle_query_routes_a_real_query_to_its_zone() {
        // End to end through decode_query + zone lookup: the bytes a client sends
        // arrive as an authoritative answer.
        let authority = Authority(Arc::new(Inner::new(vec![example_zone()], None)));
        let raw = wire::encode_query(0x2222, "example.com", RecordType::A).unwrap();
        let message = authority.handle_query(&raw, false, WAN_PEER).await;
        assert_eq!(message[..2], [0x22, 0x22]);
        assert_eq!(wire::decode_response(&message).unwrap().first_a(), Some(PUBLIC));
    }

    #[tokio::test]
    async fn set_apex_a_rewrites_the_address_and_bumps_the_serial() {
        // The updater's contract: the apex A moves and the serial climbs, so a
        // secondary sees a newer zone and refreshes.
        let authority = Authority(Arc::new(Inner::new(vec![example_zone()], None)));
        let moved = Ipv4Addr::new(198, 51, 100, 7);
        let serial = authority.set_apex_a("example.com", moved).await.expect("the zone is served");
        assert_eq!(serial, 2_026_080_701, "the serial only ever increases");

        let raw = wire::encode_query(1, "example.com", RecordType::A).unwrap();
        let message = authority.handle_query(&raw, false, WAN_PEER).await;
        assert_eq!(wire::decode_response(&message).unwrap().first_a(), Some(moved));
        assert!(authority.set_apex_a("absent.example", moved).await.is_none());
    }

    #[tokio::test]
    async fn a_lan_peer_is_answered_with_the_lan_address() {
        // The split horizon: a record pointing at the public IP answers with
        // the LAN address for a private peer, because the NAT does not hairpin.
        let authority = Authority(Arc::new(Inner::new(vec![example_zone()], Some(PUBLIC))));
        authority.set_lan(LanView { lan_ip: LAN_IP, upstream: "203.0.113.53:53".parse().unwrap() });

        let raw = wire::encode_query(1, "www.example.com", RecordType::A).unwrap();
        let from_lan = authority.handle_query(&raw, false, LAN_PEER).await;
        assert_eq!(wire::decode_response(&from_lan).unwrap().first_a(), Some(LAN_IP));

        // The same question from the internet gets the public address.
        let from_wan = authority.handle_query(&raw, false, WAN_PEER).await;
        assert_eq!(wire::decode_response(&from_wan).unwrap().first_a(), Some(PUBLIC));
    }

    #[tokio::test]
    async fn a_public_peers_foreign_question_stays_refused_with_a_lan_view_set() {
        // The forwarding path must never open to the internet: even with the
        // LAN view configured, a public peer asking a foreign name is REFUSED.
        let authority = Authority(Arc::new(Inner::new(vec![example_zone()], Some(PUBLIC))));
        authority.set_lan(LanView { lan_ip: LAN_IP, upstream: "203.0.113.53:53".parse().unwrap() });

        let raw = wire::encode_query(2, "elsewhere.net", RecordType::A).unwrap();
        let message = authority.handle_query(&raw, false, WAN_PEER).await;
        assert_eq!(wire::decode_response(&message).unwrap().code, ResponseCode::Refused);
    }

    #[tokio::test]
    async fn without_a_lan_view_a_private_peer_is_answered_like_the_public() {
        // Split horizon is opt-in: no configured view, no substitution and no
        // forwarding — a private peer's foreign question is refused too.
        let authority = Authority(Arc::new(Inner::new(vec![example_zone()], Some(PUBLIC))));

        let owned = wire::encode_query(3, "www.example.com", RecordType::A).unwrap();
        let answer = authority.handle_query(&owned, false, LAN_PEER).await;
        assert_eq!(wire::decode_response(&answer).unwrap().first_a(), Some(PUBLIC));

        let foreign = wire::encode_query(4, "elsewhere.net", RecordType::A).unwrap();
        let refused = authority.handle_query(&foreign, false, LAN_PEER).await;
        assert_eq!(wire::decode_response(&refused).unwrap().code, ResponseCode::Refused);
    }

    #[test]
    fn lan_and_public_peers_are_told_apart_by_address_range() {
        assert!(is_lan_peer("192.168.1.23".parse().unwrap()));
        assert!(is_lan_peer("10.0.0.5".parse().unwrap()));
        assert!(is_lan_peer("127.0.0.1".parse().unwrap()));
        assert!(is_lan_peer("169.254.10.10".parse().unwrap()));
        assert!(is_lan_peer("::1".parse().unwrap()));
        assert!(is_lan_peer("fe80::1".parse().unwrap()));
        assert!(is_lan_peer("fd00::1".parse().unwrap()));
        assert!(!is_lan_peer("172.83.6.109".parse().unwrap()));
        assert!(!is_lan_peer("8.8.8.8".parse().unwrap()));
        assert!(!is_lan_peer("2001:db8::1".parse().unwrap()));
    }

    #[tokio::test]
    async fn origins_and_export_report_the_served_zone() {
        let authority = Authority(Arc::new(Inner::new(vec![example_zone()], None)));
        assert_eq!(authority.origins().await, vec!["example.com".to_owned()]);
        let export = authority.export("example.com").await.expect("a served zone");
        assert!(matches!(export.first().map(|record| &record.data), Some(RecordData::Soa { .. })));
        assert!(authority.export("nowhere.test").await.is_none());
    }

    #[tokio::test]
    async fn upsert_record_adds_a_subdomain_a_and_serves_it() {
        // Provisioning a new site adds its A record live; the next query returns
        // it and the serial climbs so a secondary refreshes.
        let authority = Authority(Arc::new(Inner::new(vec![example_zone()], None)));
        let addr = Ipv4Addr::new(198, 51, 100, 9);

        let serial = authority.upsert_record("BLOG.example.com.", RecordData::A(addr)).await.expect("owned");
        assert_eq!(serial, 2_026_080_701, "the serial only ever increases");

        let raw = wire::encode_query(7, "blog.example.com", RecordType::A).unwrap();
        let message = authority.handle_query(&raw, false, WAN_PEER).await;
        assert_eq!(wire::decode_response(&message).unwrap().first_a(), Some(addr));
    }

    #[tokio::test]
    async fn upsert_record_replaces_the_prior_rrset_rather_than_appending() {
        let authority = Authority(Arc::new(Inner::new(vec![example_zone()], None)));
        let first = Ipv4Addr::new(198, 51, 100, 1);
        let second = Ipv4Addr::new(198, 51, 100, 2);

        authority.upsert_record("www.example.com", RecordData::A(first)).await;
        authority.upsert_record("www.example.com", RecordData::A(second)).await;

        let raw = wire::encode_query(1, "www.example.com", RecordType::A).unwrap();
        let answers = wire::decode_response(&authority.handle_query(&raw, false, WAN_PEER).await).unwrap().answers;
        let a_records = answers.iter().filter(|r| matches!(r.data, RecordData::A(_))).count();
        assert_eq!(a_records, 1, "an upsert replaces the RRset, never grows it");
    }

    #[tokio::test]
    async fn a_name_in_no_owned_zone_cannot_be_upserted() {
        let authority = Authority(Arc::new(Inner::new(vec![example_zone()], None)));
        assert!(authority.upsert_record("blog.elsewhere.test", RecordData::A(Ipv4Addr::LOCALHOST)).await.is_none());
        assert!(authority.zone_for("blog.elsewhere.test").await.is_none());
        assert_eq!(authority.zone_for("blog.example.com").await.as_deref(), Some("example.com"));
    }

    #[tokio::test]
    async fn remove_record_drops_the_name_and_bumps_only_on_a_change() {
        let authority = Authority(Arc::new(Inner::new(vec![example_zone()], None)));
        let addr = Ipv4Addr::new(198, 51, 100, 9);
        authority.upsert_record("blog.example.com", RecordData::A(addr)).await;

        assert!(authority.remove_record("blog.example.com", RecordType::A).await.is_some(), "a real removal bumps");
        let raw = wire::encode_query(1, "blog.example.com", RecordType::A).unwrap();
        assert_eq!(wire::decode_response(&authority.handle_query(&raw, false, WAN_PEER).await).unwrap().code, ResponseCode::NameError);

        // A second removal changes nothing, so no serial is spent.
        assert!(authority.remove_record("blog.example.com", RecordType::A).await.is_none());
        assert!(authority.remove_record("blog.elsewhere.test", RecordType::A).await.is_none());
    }

    #[tokio::test]
    async fn mail_records_are_published_on_a_bare_zone_but_not_a_hand_written_one() {
        use selfhost_config::Config;

        // A bare `[[dns.zone]]` gets its derived apex/www/glue plus the mail
        // records; a zone that lists its own records is served exactly as written.
        let config = Config::parse(
            r#"
version = 1

[server]
acme_email = "a@b.com"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "a"
domains = ["example.com"]
static_root = "./public"

[dns]

[[dns.zone]]
domain = "example.com"

[[dns.zone]]
domain = "hand.example"

  [[dns.zone.record]]
  name = "@"
  type = "A"
  value = "203.0.113.99"

[mail]
hostname = "mail.example.com"
domains = ["example.com", "hand.example"]
"#,
        )
        .expect("valid config");

        // The daemon generates these (with the DKIM key when it has one); here no
        // key, so no _domainkey record — the honest posture.
        let mail = config.mail.as_ref().expect("mail present");
        let mail_records: Vec<(String, Vec<RecordConfig>)> = mail
            .domains
            .iter()
            .map(|domain| (domain.clone(), mail.dns_records(domain, None, None)))
            .collect();

        let authority = Authority::for_config_with_mail(&config, Some(PUBLIC), &mail_records);

        // The bare zone now answers MX with the configured mail host.
        let mx = authority.export("example.com").await.expect("bare zone served");
        assert!(
            mx.iter().any(|r| matches!(&r.data, RecordData::Mx { exchange, .. } if exchange == "mail.example.com")),
            "the bare zone publishes the mail MX"
        );
        assert!(
            mx.iter().any(|r| matches!(&r.data, RecordData::Txt(t) if t == "v=spf1 mx -all")),
            "and SPF"
        );

        // The hand-written zone is untouched: only its listed A, no injected MX.
        let hand = authority.export("hand.example").await.expect("hand zone served");
        assert!(
            !hand.iter().any(|r| matches!(&r.data, RecordData::Mx { .. })),
            "an explicit zone is served exactly as written, mail records excluded"
        );

        // The bare zone also resolves the client-autoconfig hosts a mail
        // client's account setup probes, and answers the RFC 6186 SRVs it asks.
        let served = |name: &str, qtype| {
            let authority = authority.clone();
            let raw = wire::encode_query(9, name, qtype).unwrap();
            async move { authority.handle_query(&raw, false, WAN_PEER).await }
        };
        for host in ["mail.example.com", "imap.example.com", "smtp.example.com", "autodiscover.example.com"] {
            let message = served(host, RecordType::A).await;
            assert_eq!(
                wire::decode_response(&message).unwrap().first_a(),
                Some(PUBLIC),
                "{host} must resolve for account autodiscovery"
            );
        }
        let imaps = served("_imaps._tcp.example.com", RecordType::Srv).await;
        let answers = wire::decode_response(&imaps).unwrap().answers;
        assert!(
            answers.iter().any(|r| matches!(&r.data,
                RecordData::Srv { port: 993, target, .. } if target == "imap.example.com")),
            "the IMAPS SRV names imap.example.com:993, got {answers:?}"
        );
        let submission = served("_submission._tcp.example.com", RecordType::Srv).await;
        let answers = wire::decode_response(&submission).unwrap().answers;
        assert!(
            answers.iter().any(|r| matches!(&r.data,
                RecordData::Srv { port: 587, target, .. } if target == "smtp.example.com")),
            "the submission SRV names smtp.example.com:587, got {answers:?}"
        );
        let submissions = served("_submissions._tcp.example.com", RecordType::Srv).await;
        let answers = wire::decode_response(&submissions).unwrap().answers;
        assert!(
            answers.iter().any(|r| matches!(&r.data,
                RecordData::Srv { port: 465, target, .. } if target == "smtp.example.com")),
            "the RFC 8314 implicit-TLS submission SRV names smtp.example.com:465, got {answers:?}"
        );

        // The hand zone is a mail domain but wrote its own records: no SRVs.
        assert!(
            !hand.iter().any(|r| matches!(&r.data, RecordData::Srv { .. })),
            "an explicit zone gets no injected SRVs"
        );
    }
}
