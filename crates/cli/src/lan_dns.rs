//! `selfhost lan-dns` — the split-horizon resolver the LAN depends on.
//!
//! The router hands this machine out as the network's DNS server, so every
//! device on the LAN asks here first. For names this deployment serves —
//! every configured site domain, plus the `[dns]` zone apexes and their `www` —
//! the answer is the box's **LAN** address rather than the public one, because
//! a NAT that does not hairpin makes the public address unreachable from
//! inside the network. Every other question is forwarded upstream unchanged,
//! exactly like [`crate::watch`]'s diagnostic forwarder: nothing else is
//! filtered, rewritten, or blocked, because a resolver that breaks the
//! household's internet gets unplugged before it helps anyone.
//!
//! # Deployment contract — do not rename the flags
//!
//! The box runs a scheduled task, `selfhost-lan-dns`, executing
//! `selfhost lan-dns --lan-ip 192.168.1.8`. The command name and the
//! `--lan-ip <ip>` / `--bind <addr>` flags are therefore a deployment
//! contract: shipping a binary where any of them changed silently kills DNS
//! for the entire LAN, because the router keeps pointing at a resolver that
//! no longer starts.
//!
//! # The IPv6 subtlety
//!
//! An overridden name must answer `AAAA` with an **empty `NOERROR`**, not a
//! forwarded upstream answer. Forwarding would hand back the site's public
//! `AAAA` (if one exists), and a dual-stack client prefers IPv6 — it would
//! connect straight past the override to the public address, defeating the
//! split horizon for exactly the clients modern enough to have v6.

use selfhost_config::Config;
use selfhost_dns::wire::{self, Record, RecordData, RecordType, ResponseCode, ResponseFlags};
use selfhost_dns::Resolver;
use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// TTL on synthesised override answers. Short, so a client notices within a
/// minute when the box's LAN address changes.
const OVERRIDE_TTL: u32 = 60;

/// How long to wait for the upstream resolver before giving up on one query.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest UDP payload accepted, matching the EDNS0 size clients advertise.
const MAX_UDP: usize = 4096;

/// The override table: canonical name → the LAN address to answer with.
type Overrides = BTreeMap<String, Ipv4Addr>;

/// Serves split-horizon DNS for the LAN until interrupted.
///
/// Builds the override table from `config` (see [`overrides`]), discovers the
/// upstream resolver the same way `watch-dns` does, and serves UDP and TCP on
/// `bind`. Runs until a listener fails or Ctrl-C; the scheduled task restarts
/// it on the next trigger. Errors are returned as operator-readable strings in
/// the CLI's usual style.
pub async fn lan_dns_command(
    config: &Config,
    lan_ip: Ipv4Addr,
    bind: SocketAddr,
) -> Result<(), String> {
    let table = overrides(config, lan_ip);
    let upstream = Resolver::system().address();

    // Forwarding to ourselves would answer every question with the question.
    if upstream.port() == bind.port()
        && (upstream.ip() == bind.ip()
            || upstream.ip() == IpAddr::V4(lan_ip)
            || upstream.ip().is_loopback())
    {
        return Err(format!(
            "the system resolver is {upstream}, which is this machine, so every query would \
             be forwarded back here.\n  \
             Point this machine's own network adapter at a public resolver (for example \
             1.1.1.1), then re-run."
        ));
    }

    println!("selfhost split-horizon DNS");
    println!("  bind      {bind}");
    println!("  upstream  {upstream}");
    if table.is_empty() {
        println!("  overrides none — no site domains configured; every query forwards unchanged");
    } else {
        for (name, address) in &table {
            println!("  override  {name} -> {address}");
        }
    }
    println!("\nEverything not listed forwards upstream unchanged. Ctrl-C to stop.\n");

    let serving = serve(bind, upstream, Arc::new(table));
    tokio::select! {
        result = serving => result.map_err(|error| match error.kind() {
            io::ErrorKind::PermissionDenied => format!(
                "cannot bind {bind}: port 53 needs privilege.\n  \
                 Run it with sudo, or on Linux grant the capability once:\n  \
                 sudo setcap 'cap_net_bind_service=+ep' ./target/release/selfhost"
            ),
            io::ErrorKind::AddrInUse => format!(
                "cannot bind {bind}: something already answers DNS on this machine.\n  \
                 On macOS that is usually a VPN client or Internet Sharing."
            ),
            _ => format!("LAN DNS stopped: {error}"),
        }),
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

/// Builds the override table: every name this deployment serves → `lan_ip`.
///
/// Sources, all lowercased and stripped of any trailing dot:
/// - every domain of every configured site;
/// - each `[dns]` zone's apex, plus `www.<apex>`, since a bare zone serves both;
/// - the `[mail]` hostname and its client-autoconfig hosts (`mail.`, `imap.`,
///   `smtp.` per mail domain), so a LAN mail client reaches the listeners
///   directly instead of dying against the non-hairpinning public address.
///
/// Entries that are raw IP literals or `localhost` are skipped: an IP needs no
/// resolving, and hijacking `localhost` would break every device's loopback.
fn overrides(config: &Config, lan_ip: Ipv4Addr) -> Overrides {
    let mut table = Overrides::new();
    let mut claim = |name: &str| {
        let name = canonical(name);
        if name.is_empty() || name == "localhost" || name.parse::<IpAddr>().is_ok() {
            return;
        }
        table.insert(name, lan_ip);
    };

    for site in &config.sites {
        for domain in &site.domains {
            claim(domain);
        }
    }
    if let Some(dns) = &config.dns {
        for zone in &dns.zones {
            claim(&zone.domain);
            claim(&format!("www.{}", zone.domain));
        }
    }
    if let Some(mail) = &config.mail {
        claim(&mail.hostname);
        for host in mail.client_hosts() {
            claim(&host);
        }
    }
    table
}

/// A query name in the form the override table is keyed by: lowercase, no
/// trailing dot. DNS names are case-insensitive and a client may or may not
/// send the root dot, so both differences must be erased before lookup.
fn canonical(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Decides one query: `Some(response)` to answer locally, `None` to forward.
///
/// Local answers, for a name in `table` only:
/// - `A` or `ANY` → an authoritative `A` for the LAN address, TTL
///   [`OVERRIDE_TTL`];
/// - `AAAA` → an authoritative empty `NOERROR`, so a dual-stack client cannot
///   slip past the override on IPv6 (see the module docs).
///
/// Everything else forwards: names not in the table, other record types (an
/// overridden domain's `MX` and `TXT` must still resolve publicly), and
/// messages that do not decode — a resolver in the LAN's critical path passes
/// on what it cannot parse rather than becoming a fault of its own.
fn respond(table: &Overrides, query: &[u8]) -> Option<Vec<u8>> {
    let question = wire::decode_query(query).ok()?;
    let address = *table.get(&canonical(&question.name))?;

    // 255 is QTYPE `ANY` (RFC 1035 §3.2.3); it has no dedicated variant.
    let answers: Vec<Record> = match question.record_type {
        RecordType::A | RecordType::Other(255) => vec![Record {
            name: question.name.clone(),
            ttl: OVERRIDE_TTL,
            data: RecordData::A(address),
        }],
        RecordType::Aaaa => Vec::new(),
        _ => return None,
    };

    Some(wire::encode_response(
        &question,
        ResponseCode::NoError,
        ResponseFlags { authoritative: true, truncated: false },
        &answers,
        &[],
        &[],
    ))
}

/// Serves UDP and TCP on the same port until one listener fails.
///
/// Both transports, because a truncated UDP answer sends the client straight
/// to TCP — a resolver that only speaks UDP breaks large lookups, which is the
/// household's internet rather than just this feature.
async fn serve(bind: SocketAddr, upstream: SocketAddr, table: Arc<Overrides>) -> io::Result<()> {
    let datagram = Arc::new(UdpSocket::bind(bind).await?);
    let stream = TcpListener::bind(bind).await?;

    tokio::try_join!(
        serve_udp(Arc::clone(&datagram), upstream, Arc::clone(&table)),
        serve_tcp(stream, upstream, table),
    )?;
    Ok(())
}

/// The UDP half: one datagram in, one datagram out.
async fn serve_udp(
    socket: Arc<UdpSocket>,
    upstream: SocketAddr,
    table: Arc<Overrides>,
) -> io::Result<()> {
    let mut buffer = vec![0_u8; MAX_UDP];
    loop {
        let (read, from) = socket.recv_from(&mut buffer).await?;
        let query = buffer[..read].to_vec();

        // A synthesised answer needs no network, so it is sent inline; only a
        // forward waits on the upstream and earns its own task.
        if let Some(answer) = respond(&table, &query) {
            let _ = socket.send_to(&answer, from).await;
            continue;
        }
        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            if let Some(answer) = forward_udp(&query, upstream).await {
                let _ = socket.send_to(&answer, from).await;
            }
        });
    }
}

/// Sends one query upstream and waits for its answer.
///
/// A fresh ephemeral socket per query, so answers cannot be confused between
/// concurrent lookups without tracking message ids ourselves.
async fn forward_udp(query: &[u8], upstream: SocketAddr) -> Option<Vec<u8>> {
    let work = async {
        let bind = if upstream.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = UdpSocket::bind(bind).await.ok()?;
        socket.send_to(query, upstream).await.ok()?;

        let mut buffer = vec![0_u8; MAX_UDP];
        let read = socket.recv(&mut buffer).await.ok()?;
        buffer.truncate(read);
        Some(buffer)
    };
    tokio::time::timeout(UPSTREAM_TIMEOUT, work).await.ok().flatten()
}

/// The TCP half: length-prefixed messages, as many as the client sends.
async fn serve_tcp(
    listener: TcpListener,
    upstream: SocketAddr,
    table: Arc<Overrides>,
) -> io::Result<()> {
    loop {
        let (client, _) = listener.accept().await?;
        let table = Arc::clone(&table);
        tokio::spawn(async move {
            let _ = relay_tcp(client, upstream, table).await;
        });
    }
}

/// Relays one client's TCP connection, query by query, answering overridden
/// names locally and forwarding the rest.
async fn relay_tcp(
    mut client: TcpStream,
    upstream: SocketAddr,
    table: Arc<Overrides>,
) -> io::Result<()> {
    loop {
        let Some(query) = read_message(&mut client).await? else { return Ok(()) };

        if let Some(answer) = respond(&table, &query) {
            write_message(&mut client, &answer).await?;
            continue;
        }

        let exchange = async {
            let mut server = TcpStream::connect(upstream).await?;
            write_message(&mut server, &query).await?;
            read_message(&mut server).await
        };
        let answer = match tokio::time::timeout(UPSTREAM_TIMEOUT, exchange).await {
            Ok(Ok(Some(answer))) => answer,
            // Nothing usable came back. Closing is the honest reply: the client
            // then retries, rather than being handed a forged answer.
            _ => return Ok(()),
        };
        write_message(&mut client, &answer).await?;
    }
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
    use selfhost_config::{
        AcmeEnvironment, Dns, Firewall, Health, Node, Role, Server, Site, ZoneConfig,
    };
    use std::path::PathBuf;

    /// The address every override answers with in these tests.
    const LAN_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 8);

    fn site(domains: &[&str]) -> Site {
        Site {
            name: "site".into(),
            domains: domains.iter().map(|d| (*d).to_owned()).collect(),
            static_root: Some(PathBuf::from("./public")),
            spa: false,
            app_paths: vec![],
            instances: vec![],
            health: Health::default(),
            canonical_redirect: true,
            allowed_cidrs: vec![],
            console: false,
        }
    }

    fn config_with(sites: Vec<Site>, dns: Option<Dns>) -> Config {
        Config {
            version: 1,
            server: Server {
                http_bind: "0.0.0.0:80".into(),
                https_bind: "0.0.0.0:443".into(),
                acme_email: "a@b.com".into(),
                acme: AcmeEnvironment::SelfSigned,
                data_dir: PathBuf::from("./data"),
                admin_bind: "127.0.0.1:9191".into(),
                firewall: Firewall::default(),
            },
            nodes: vec![Node { name: "home".into(), role: Role::Owner, mesh_ip: None }],
            sites,
            dns,
            mail: None,
            namecheap_ddns: vec![],
            registrar: None,
        }
    }

    fn query_for(name: &str, record_type: RecordType) -> Vec<u8> {
        wire::encode_query(0xBEEF, name, record_type).expect("a valid query")
    }

    #[test]
    fn overrides_cover_every_site_domain_lowercased() {
        let config =
            config_with(vec![site(&["Example.COM", "www.example.com", "other.net"])], None);
        let table = overrides(&config, LAN_IP);

        assert_eq!(
            table.keys().cloned().collect::<Vec<_>>(),
            vec!["example.com", "other.net", "www.example.com"]
        );
        assert!(table.values().all(|address| *address == LAN_IP));
    }

    #[test]
    fn ip_literals_and_localhost_are_never_overridden() {
        // An IP literal needs no resolving, and answering for `localhost` would
        // hijack every device's loopback — both would be config typos amplified
        // into a LAN-wide fault.
        let config = config_with(vec![site(&["192.168.1.8", "localhost", "real.example"])], None);
        let table = overrides(&config, LAN_IP);
        assert_eq!(table.keys().cloned().collect::<Vec<_>>(), vec!["real.example"]);
    }

    #[test]
    fn dns_zone_apexes_and_their_www_are_included() {
        let dns = Dns {
            bind: "0.0.0.0:53".into(),
            secondaries: vec![],
            dynamic_ip: true,
            lan_ip: None,
            zones: vec![ZoneConfig {
                domain: "rockywearsahat.com".into(),
                soa: None,
                nameservers: vec![],
                records: vec![],
            }],
        };
        let table = overrides(&config_with(vec![], Some(dns)), LAN_IP);
        assert_eq!(
            table.keys().cloned().collect::<Vec<_>>(),
            vec!["rockywearsahat.com", "www.rockywearsahat.com"]
        );
    }

    #[test]
    fn mail_hostname_and_client_autoconfig_hosts_are_included() {
        // A LAN mail client resolves `imap.`/`smtp.`/`mail.` — hand those the
        // LAN address too, or account setup dies against the hairpin NAT.
        let mut config = config_with(vec![], None);
        config.mail = Some(selfhost_config::Mail {
            hostname: "rockywearsahat.com".into(),
            domains: vec!["rockywearsahat.com".into()],
            mailboxes: vec![],
            dkim: None,
            relay: None,
            bind: selfhost_config::MailBind::default(),
            max_message_bytes: 1,
            require_tls_for_auth: true,
        });

        let table = overrides(&config, LAN_IP);
        assert_eq!(
            table.keys().cloned().collect::<Vec<_>>(),
            vec![
                "imap.rockywearsahat.com",
                "mail.rockywearsahat.com",
                "rockywearsahat.com",
                "smtp.rockywearsahat.com",
            ]
        );
        assert!(table.values().all(|address| *address == LAN_IP));
    }

    #[test]
    fn qname_matching_ignores_case_and_the_trailing_dot() {
        assert_eq!(canonical("ExAmPle.COM."), "example.com");
        assert_eq!(canonical("example.com"), "example.com");

        let table = overrides(&config_with(vec![site(&["example.com"])], None), LAN_IP);
        let mixed = query_for("ExAmPle.COM.", RecordType::A);
        assert!(respond(&table, &mixed).is_some(), "case and dot must not defeat the override");
    }

    #[test]
    fn an_overridden_a_query_gets_an_authoritative_lan_answer() {
        // Wire-correctness end to end: the bytes handed back must decode with
        // the same parser real responses go through.
        let table = overrides(&config_with(vec![site(&["example.com"])], None), LAN_IP);
        let answer = respond(&table, &query_for("example.com", RecordType::A))
            .expect("an overridden A query is answered locally");

        assert_eq!(&answer[0..2], &[0xBE, 0xEF], "the query id is echoed");
        assert_ne!(answer[2] & 0x04, 0, "the AA bit marks the answer authoritative");

        let decoded = wire::decode_response(&answer).expect("our own output decodes");
        assert_eq!(decoded.code, ResponseCode::NoError);
        assert_eq!(decoded.first_a(), Some(LAN_IP));
        assert_eq!(decoded.answers[0].ttl, OVERRIDE_TTL);
        assert_eq!(decoded.answers[0].name, "example.com");
    }

    #[test]
    fn an_any_query_for_an_overridden_name_is_answered_like_a() {
        let table = overrides(&config_with(vec![site(&["example.com"])], None), LAN_IP);
        let answer = respond(&table, &query_for("example.com", RecordType::Other(255)))
            .expect("ANY is answered locally");
        assert_eq!(wire::decode_response(&answer).expect("decodes").first_a(), Some(LAN_IP));
    }

    #[test]
    fn aaaa_for_an_overridden_name_is_an_empty_noerror() {
        // Forwarding AAAA would hand back the public v6 address and a
        // dual-stack client would connect straight past the override.
        let table = overrides(&config_with(vec![site(&["example.com"])], None), LAN_IP);
        let answer = respond(&table, &query_for("example.com", RecordType::Aaaa))
            .expect("AAAA is answered locally, not forwarded");

        let decoded = wire::decode_response(&answer).expect("decodes");
        assert_eq!(decoded.code, ResponseCode::NoError);
        assert!(decoded.answers.is_empty(), "no address, and no NXDOMAIN either");
    }

    #[test]
    fn everything_else_is_forwarded() {
        let table = overrides(&config_with(vec![site(&["example.com"])], None), LAN_IP);

        // A name this deployment does not serve.
        assert!(respond(&table, &query_for("elsewhere.net", RecordType::A)).is_none());
        // An overridden name's mail and text records still resolve publicly.
        assert!(respond(&table, &query_for("example.com", RecordType::Mx)).is_none());
        assert!(respond(&table, &query_for("example.com", RecordType::Txt)).is_none());
        // A message that does not decode is passed on rather than dropped.
        assert!(respond(&table, &[0xFF, 0x00, 0x01]).is_none());
    }
}
