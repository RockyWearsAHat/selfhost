//! `selfhost lan-dns` — the nameserver the LAN depends on, now the real one.
//!
//! The router hands this machine out as the network's DNS server, so every
//! device on the LAN asks here first. This command serves the full
//! [`Authority`] with its split-horizon LAN view enabled: names in the zones
//! this deployment owns are answered *authoritatively* — every record type,
//! `A` through `MX`, `TXT`, and the RFC 6186 `SRV`s a mail client's account
//! setup asks for — with the box's **LAN** address substituted wherever a
//! record points at the public one, because a NAT that does not hairpin makes
//! the public address unreachable from inside. Every other question from a LAN
//! peer is forwarded upstream unchanged, because a resolver that breaks the
//! household's internet gets unplugged before it helps anyone. A peer on the
//! public internet sees exactly the authoritative answers and is never
//! forwarded for, so the public face cannot be used as an open resolver — and
//! once the router forwards UDP+TCP 53 here and a domain's `NS` delegation
//! points at this box, the same process answers the world.
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
//! # Zones without `[dns]`
//!
//! A config that never wrote a `[dns]` section still gets a full zone set:
//! one bare zone per registrable domain claimed anywhere in the config (site
//! domains, mail domains, the mail hostname), so the LAN resolves everything
//! this box hosts with zero DNS configuration. A config that *did* write
//! `[dns]` zones is served exactly those.

use selfhost_config::{Config, Dns, RecordConfig, ZoneConfig, psl};
use selfhost_mail::Dkim;
use selfhost_dns::authority::{Authority, LanView};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use tokio::net::{UdpSocket, TcpListener};

/// Builds the authority every DNS-serving path shares.
///
/// One constructor for the daemon, `selfhost dns serve`, and `lan-dns`, so the
/// three can never serve different zone content: zones from `[dns]` (bare ones
/// expanded from `public_ip`), each mail domain's `MX`/SPF/DMARC/DKIM/PACC/CAA
/// records (the DKIM `TXT` only when the key on disk is readable — read-only
/// here, `selfhost run` is what generates it; the `_ua-auto-config` digest is
/// pure, so it is always published for a mail domain), and the addresses and
/// `SRV`s of every host the config claims. The split-horizon LAN view is *not* set here;
/// each caller decides that from its own configuration.
pub fn build_authority(
    config: &Config,
    project_dir: &Path,
    public_ip: Option<Ipv4Addr>,
) -> Authority {
    let mail_records: Vec<(String, Vec<RecordConfig>)> = match &config.mail {
        Some(mail) => {
            let dkim = dkim_public(config, project_dir);
            mail.domains
                .iter()
                .map(|domain| {
                    let pacc = pacc_digest(config, domain);
                    (domain.clone(), mail.dns_records(domain, dkim.as_deref(), pacc.as_deref()))
                })
                .collect()
        }
        None => Vec::new(),
    };
    Authority::for_config_with_mail(config, public_ip, &mail_records)
}

/// The digest of the PACC configuration document `domain` publishes, when
/// `[mail]` covers that domain.
///
/// Pure: the document is derived from the config, not read back from the
/// running proxy — the proxy derives it from the same config with the same
/// function, so hashing it here cannot disagree with what is served unless the
/// config itself changed, which changes both sides together.
fn pacc_digest(config: &Config, domain: &str) -> Option<String> {
    let mail = config.mail.as_ref()?;
    mail.domains
        .iter()
        .any(|covered| covered.eq_ignore_ascii_case(domain))
        .then(|| selfhost_mail::pacc::digest(&selfhost_config::pacc::document(domain)))
}

/// The DKIM public TXT value, when signing is configured and the key exists.
///
/// Read-only on purpose: the mail server generates the key on first start, and
/// building the zone must not mint one as a side effect of describing it. A
/// configured-but-absent key is stated and the record omitted, because a
/// `_domainkey` with no live key behind it invites receivers to distrust our
/// mail. The record appears at the next authority build once the key exists.
fn dkim_public(config: &Config, project_dir: &Path) -> Option<String> {
    let mail = config.mail.as_ref()?;
    let dkim = mail.dkim.as_ref()?;
    let key_path = project_dir.join(&config.server.data_dir).join(&dkim.private_key);
    match Dkim::load(&key_path) {
        Ok(key) => Some(key.public_txt()),
        Err(error) => {
            println!(
                "note: DKIM key {} is not readable ({error}); the DKIM record is omitted \
                 from the zone until the mail server has generated it.",
                key_path.display()
            );
            None
        }
    }
}

/// The config as served by `lan-dns`: `[dns]` zones synthesised when absent.
///
/// Collects every domain the config claims — site domains, mail domains, the
/// mail hostname — groups them by registrable domain (`blog.example.com` and
/// `example.com` are one zone), and writes a bare `[[dns.zone]]` for each.
/// IP literals and single-label names (`localhost`) have no registrable domain
/// and are skipped. A config that already lists zones is returned unchanged:
/// the operator's `[dns]` is authoritative over this convenience.
fn with_synthesised_zones(config: &Config) -> Config {
    if config.dns.as_ref().is_some_and(|dns| !dns.zones.is_empty()) {
        return config.clone();
    }

    let mut origins: Vec<String> = Vec::new();
    let mut claim = |name: &str| {
        // An IP literal needs no resolving, and `registrable` would happily
        // treat its last octet as a public suffix.
        if name.parse::<IpAddr>().is_ok() {
            return;
        }
        if let Some(origin) = psl::registrable(name) {
            if !origins.contains(&origin) {
                origins.push(origin);
            }
        }
    };
    for site in &config.sites {
        for domain in &site.domains {
            claim(domain);
        }
    }
    if let Some(mail) = &config.mail {
        claim(&mail.hostname);
        for domain in &mail.domains {
            claim(domain);
        }
    }

    let mut augmented = config.clone();
    let zones = origins
        .into_iter()
        .map(|domain| ZoneConfig { domain, soa: None, nameservers: Vec::new(), records: Vec::new() })
        .collect();
    match &mut augmented.dns {
        Some(dns) => dns.zones = zones,
        None => {
            augmented.dns = Some(Dns {
                bind: "0.0.0.0:53".into(),
                secondaries: Vec::new(),
                dynamic_ip: false,
                lan_ip: None,
                zones,
                upstreams: vec!["1.1.1.1:53".into(), "9.9.9.9:53".into()],
                serve_in_daemon: true,
            });
        }
    }
    augmented
}

/// The zone origins this deployment actually answers for.
///
/// The same set [`lan_dns_command`] serves, exposed so a health probe can ask
/// the running nameserver a question it is supposed to be able to answer. This
/// has to go through [`with_synthesised_zones`] rather than reading
/// `config.dns.zones` directly: the production box has **no `[dns]` section**
/// and its zones exist only because this function invents them, so a probe built
/// on `[dns]` would report "nothing configured, nothing to check" on the one
/// deployment the probe was written for. See [`crate::health`] for the outage
/// that lesson came from.
pub fn served_origins(config: &Config) -> Vec<String> {
    with_synthesised_zones(config)
        .dns
        .map(|dns| {
            dns.zones
                .into_iter()
                .map(|zone| zone.domain.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|origin| !origin.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Serves split-horizon DNS for the LAN until interrupted.
///
/// Builds the shared [`Authority`] (see [`build_authority`]) over the config's
/// zones — synthesised from the claimed domains when `[dns]` is absent —
/// enables the LAN view at `lan_ip` with the system resolver as upstream, and
/// serves UDP and TCP on `bind`. Runs until a listener fails or Ctrl-C; the
/// scheduled task restarts it on the next trigger.
///
/// Uses SO_REUSEADDR on the sockets to allow zero-drop handoff: a new instance
/// can bind and prove it answers before the old one exits. After binding, writes
/// this process's PID to a handoff file, then monitors it; if a different PID
/// appears, stops accepting new packets and exits cleanly.
pub async fn lan_dns_command(
    config: &Config,
    project_dir: &Path,
    lan_ip: Ipv4Addr,
    bind: SocketAddr,
) -> Result<(), String> {
    let augmented = with_synthesised_zones(config);

    // Parse upstreams from config.
    let upstreams: Vec<SocketAddr> = augmented
        .dns
        .as_ref()
        .map(|dns| dns.upstreams.iter().filter_map(|s| s.parse().ok()).collect())
        .unwrap_or_else(|| vec!["1.1.1.1:53".parse().unwrap(), "9.9.9.9:53".parse().unwrap()]);

    // Validate that we're not forwarding to ourselves.
    for upstream in &upstreams {
        if upstream.port() == bind.port()
            && (upstream.ip() == bind.ip()
                || upstream.ip() == IpAddr::V4(lan_ip)
                || upstream.ip().is_loopback())
        {
            return Err(format!(
                "upstream {upstream} is this machine, so every query would be forwarded back here.\n  \
                 Point this machine's own network adapter at a public resolver (for example \
                 1.1.1.1), then re-run."
            ));
        }
    }

    // The public address the zones' records point at. Discovery can fail on a
    // flaky uplink; an explicit apex A in the config is the fallback, and the
    // LAN address the final one — LAN service (the job that must not die)
    // still works, since the LAN answer is the LAN address either way.
    let public_ip = match crate::doctor::discover_public_ip().await {
        Some(address) => address,
        None => config_apex_a(config).unwrap_or(lan_ip),
    };

    let authority = build_authority(&augmented, project_dir, Some(public_ip));
    authority.set_lan(LanView { lan_ip, upstreams: upstreams.clone() });

    println!("selfhost split-horizon DNS");
    println!("  bind      {bind}");
    for (i, upstream) in upstreams.iter().enumerate() {
        if i == 0 {
            println!("  upstream  {upstream}");
        } else {
            println!("  upstream  {upstream} (failover)");
        }
    }
    println!("  lan ip    {lan_ip} (answers for LAN peers)");
    println!("  public ip {public_ip} (answers for everyone else)");
    let origins = authority.origins().await;
    if origins.is_empty() {
        println!("  zones     none — no site or mail domains configured; every query forwards");
    } else {
        for origin in &origins {
            println!("  zone      {origin}");
        }
    }
    println!("\nLAN peers: zone names answer {lan_ip}; everything else forwards upstream.");
    println!("Public peers: zone names answer authoritatively; everything else is refused.");
    println!("Ctrl-C to stop.\n");

    // Bind UDP and TCP with SO_REUSEADDR set so new instances can bind alongside
    // old ones during zero-drop handoff.
    let udp = bind_udp_with_reuse(bind).map_err(|e| format!(
        "cannot bind {bind} (UDP): {e}\n  \
         This usually means port 53 needs privilege or something is already listening.\n  \
         On macOS that is usually a VPN client or Internet Sharing."
    ))?;
    let tcp = bind_tcp_with_reuse(bind).map_err(|e| format!(
        "cannot bind {bind} (TCP): {e}\n  \
         This usually means port 53 needs privilege or something is already listening.\n  \
         On macOS that is usually a VPN client or Internet Sharing."
    ))?;

    println!("{} [dns] bound with SO_REUSEADDR", selfhost_dns::stamp());

    // Self-test: ask the authority for one of its own zones to verify it's alive.
    let origins_vec = authority.origins().await;
    if !origins_vec.is_empty() {
        let test_zone = &origins_vec[0];
        let resolver = selfhost_dns::Resolver::at(bind).with_timeout(std::time::Duration::from_secs(1));
        if resolver.query(test_zone, selfhost_dns::RecordType::Soa).await.is_ok() {
            eprintln!("{} [dns] self-test passed for {test_zone}", selfhost_dns::stamp());
        } else {
            return Err(format!(
                "self-test failed: could not query {test_zone} from this machine"
            ));
        }
    }

    // Write this process's PID to the handoff file, signaling we're ready to serve.
    let data_dir = project_dir.join(&config.server.data_dir);
    let this_pid = write_handoff(&data_dir).map_err(|e| format!("could not write handoff file: {e}"))?;
    println!("{} [dns] wrote handoff file with PID {this_pid}", selfhost_dns::stamp());

    // Spawn the telemetry writer task.
    selfhost_dns::writer::spawn_stats_writer(authority.clone(), &data_dir, "lan-dns").await;

    // Serve until interrupted, or until a new DNS process takes over (handoff).
    tokio::select! {
        result = authority.serve_with_sockets(udp, tcp) => {
            result.map_err(|error| bind_hint(bind, error))
        }
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = watch_handoff(this_pid, &data_dir) => {
            eprintln!("{} [dns] exiting cleanly to allow new instance", selfhost_dns::stamp());
            Ok(())
        }
    }
}

/// The first explicit apex `A` in any configured `[dns]` zone, if one parses.
fn config_apex_a(config: &Config) -> Option<Ipv4Addr> {
    config
        .dns
        .as_ref()?
        .zones
        .iter()
        .flat_map(|zone| &zone.records)
        .find(|record| record.name == "@" && record.record_type.eq_ignore_ascii_case("A"))
        .and_then(|record| record.value.parse().ok())
}

/// An operator-readable message for a serve failure, with the two classic
/// port-53 causes spelled out.
fn bind_hint(bind: SocketAddr, error: selfhost_dns::authority::DnsError) -> String {
    use selfhost_dns::authority::DnsError;
    match &error {
        DnsError::Bind { source, .. } if source.kind() == std::io::ErrorKind::PermissionDenied => {
            format!(
                "cannot bind {bind}: port 53 needs privilege.\n  \
                 Run it with sudo, or on Linux grant the capability once:\n  \
                 sudo setcap 'cap_net_bind_service=+ep' ./target/release/selfhost"
            )
        }
        DnsError::Bind { source, .. } if source.kind() == std::io::ErrorKind::AddrInUse => {
            format!(
                "cannot bind {bind}: something already answers DNS on this machine.\n  \
                 On macOS that is usually a VPN client or Internet Sharing."
            )
        }
        _ => format!("LAN DNS stopped: {error}"),
    }
}

/// Binds a UDP socket with SO_REUSEADDR set so multiple instances can bind the
/// same address on Windows. Uses socket2 to configure the socket before binding,
/// then converts it to a tokio UdpSocket.
fn bind_udp_with_reuse(bind: SocketAddr) -> std::io::Result<UdpSocket> {
    use socket2::Socket;

    let socket = match bind {
        SocketAddr::V4(_) => Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?,
        SocketAddr::V6(_) => Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?,
    };

    // Enable SO_REUSEADDR so a new instance can bind alongside a running one.
    socket.set_reuse_address(true)?;

    // Bind the socket, then set it to non-blocking so tokio can use it.
    socket.bind(&bind.into())?;
    socket.set_nonblocking(true)?;

    // Convert the socket2::Socket into a std::net::UdpSocket, then into tokio's.
    let std_socket = std::net::UdpSocket::from(socket);
    Ok(UdpSocket::from_std(std_socket)?)
}

/// Binds a TCP listener with SO_REUSEADDR set so multiple instances can bind
/// the same address on Windows. Uses socket2 to configure the socket before
/// binding, then converts it to a tokio TcpListener.
fn bind_tcp_with_reuse(bind: SocketAddr) -> std::io::Result<TcpListener> {
    use socket2::Socket;

    let socket = match bind {
        SocketAddr::V4(_) => Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?,
        SocketAddr::V6(_) => Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None)?,
    };

    // Enable SO_REUSEADDR so a new instance can bind alongside a running one.
    socket.set_reuse_address(true)?;

    // Bind the socket, then set it to non-blocking so tokio can use it.
    socket.bind(&bind.into())?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;

    // Convert the socket2::Socket into a std::net::TcpListener, then into tokio's.
    let std_socket = std::net::TcpListener::from(socket);
    Ok(TcpListener::from_std(std_socket)?)
}

/// Path to the handoff coordination file, where the current DNS process PID is
/// stored for other instances to detect when a new process has taken over.
fn handoff_file(data_dir: &Path) -> PathBuf {
    data_dir.join("dns-handoff")
}

/// Writes this process's PID to the handoff file, signaling that this instance
/// is now serving DNS. Returns the written PID for verification.
fn write_handoff(data_dir: &Path) -> std::io::Result<u32> {
    use std::fs;

    let pid = std::process::id();
    let content = pid.to_string();
    fs::write(handoff_file(data_dir), &content)?;
    Ok(pid)
}

/// Reads the current PID from the handoff file. Returns None if the file doesn't
/// exist or is unreadable, and None if the contents are not a valid PID.
fn read_handoff(data_dir: &Path) -> Option<u32> {
    use std::fs;

    fs::read_to_string(handoff_file(data_dir))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Decides whether this process should keep serving DNS or hand off to a new
/// instance. Pure function: given this process's PID and the PID in the handoff
/// file, returns true if serving should continue, false if this instance should
/// drain and exit.
fn should_keep_serving(this_pid: u32, file_pid: Option<u32>) -> bool {
    match file_pid {
        None => true, // File missing: no handoff yet, keep serving.
        Some(pid) if pid == this_pid => true, // Same PID: keep serving.
        Some(_) => false, // Different PID: hand off.
    }
}

/// Monitors the handoff file every 2 seconds and signals when a new DNS process
/// has taken over. Returns immediately if the handoff is detected, otherwise
/// returns when interrupted.
async fn watch_handoff(this_pid: u32, data_dir: &Path) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
    loop {
        interval.tick().await;
        let file_pid = read_handoff(data_dir);
        if !should_keep_serving(this_pid, file_pid) {
            eprintln!(
                "{} [dns] handoff detected: new DNS process is taking over",
                selfhost_dns::stamp()
            );
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_config::{AcmeEnvironment, Firewall, Health, Node, Role, Server, Site};
    use std::path::PathBuf;

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
            public_api_paths: vec![],
            exposure: None,
            owner: None,
            relay: None,
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
            self_update: None,
            github_app: None,
            shares: vec![],
            desktop: None,
            mesh: None,
            home: None,
            vpn: Vec::new(),
            maintenance: None,
        }
    }

    fn zone_origins(config: &Config) -> Vec<String> {
        with_synthesised_zones(config)
            .dns
            .expect("a dns section exists after synthesis")
            .zones
            .into_iter()
            .map(|zone| zone.domain)
            .collect()
    }

    #[test]
    fn zones_are_synthesised_per_registrable_domain() {
        // Subdomain and apex collapse into one zone; a second domain gets its own.
        let config = config_with(
            vec![site(&["blog.example.com", "Example.COM", "other.net"])],
            None,
        );
        assert_eq!(zone_origins(&config), vec!["example.com", "other.net"]);
    }

    #[test]
    fn mail_domains_and_hostname_are_claimed_too() {
        let mut config = config_with(vec![], None);
        config.mail = Some(selfhost_config::Mail {
            hostname: "mail.example.com".into(),
            domains: vec!["example.com".into()],
            mailboxes: vec![],
            dkim: None,
            relay: None,
            bind: selfhost_config::MailBind::default(),
            max_message_bytes: 1,
            require_tls_for_auth: true,
        });
        assert_eq!(zone_origins(&config), vec!["example.com"]);
    }

    #[test]
    fn ip_literals_and_localhost_synthesise_no_zone() {
        // An IP needs no resolving and `localhost` has no registrable domain;
        // both would be config typos amplified into a LAN-wide fault.
        let config = config_with(vec![site(&["192.168.1.8", "localhost", "real.example.com"])], None);
        assert_eq!(zone_origins(&config), vec!["example.com"]);
    }

    #[test]
    fn an_operator_written_dns_section_is_served_verbatim() {
        let dns = Dns {
            bind: "0.0.0.0:53".into(),
            secondaries: vec![],
            dynamic_ip: true,
            lan_ip: None,
            zones: vec![ZoneConfig {
                domain: "chosen.example".into(),
                soa: None,
                nameservers: vec![],
                records: vec![],
            }],
            upstreams: vec!["1.1.1.1:53".into(), "9.9.9.9:53".into()],
        };
        // The site domain does NOT grow a zone: the operator's [dns] wins.
        let config = config_with(vec![site(&["other.net"])], Some(dns));
        assert_eq!(zone_origins(&config), vec!["chosen.example"]);
    }

    #[test]
    fn handoff_decision_fn_keeps_serving_with_same_pid() {
        let this_pid = 1234;
        assert!(should_keep_serving(this_pid, Some(1234)), "should keep serving with same PID");
    }

    #[test]
    fn handoff_decision_fn_stops_serving_with_different_pid() {
        let this_pid = 1234;
        assert!(!should_keep_serving(this_pid, Some(5678)), "should stop serving with different PID");
    }

    #[test]
    fn handoff_decision_fn_keeps_serving_with_missing_file() {
        let this_pid = 1234;
        assert!(should_keep_serving(this_pid, None), "should keep serving when file is missing");
    }

    #[tokio::test]
    async fn reuse_address_allows_binding_same_port_twice() {
        use std::net::IpAddr;

        let addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 0);

        // First bind: the OS gives us an ephemeral port
        let first_socket = bind_udp_with_reuse(addr).expect("first bind");
        let bound_addr = first_socket.local_addr().expect("get local addr");

        // Second bind: with SO_REUSEADDR, we can bind to the same port immediately
        // (this would fail without SO_REUSEADDR on most systems, or take 60+ seconds)
        let second_socket = bind_udp_with_reuse(bound_addr).expect("second bind to same port");
        let second_bound_addr = second_socket.local_addr().expect("get second local addr");

        // Both sockets bound to the same address
        assert_eq!(bound_addr, second_bound_addr);
    }

    #[tokio::test]
    async fn tcp_reuse_address_allows_binding_same_port_twice() {
        use std::net::IpAddr;

        let addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 0);

        // First bind: the OS gives us an ephemeral port
        let first_listener = bind_tcp_with_reuse(addr).expect("first bind");
        let bound_addr = first_listener.local_addr().expect("get local addr");

        // Second bind: with SO_REUSEADDR, we can bind to the same port immediately
        let second_listener = bind_tcp_with_reuse(bound_addr).expect("second bind to same port");
        let second_bound_addr = second_listener.local_addr().expect("get second local addr");

        // Both listeners bound to the same address
        assert_eq!(bound_addr, second_bound_addr);
    }

    #[tokio::test]
    async fn handoff_file_can_be_written_and_read() {
        use std::fs;

        // Use a temporary directory path without actually creating tempfile crate dependency
        let base_dir = std::path::PathBuf::from(format!("/tmp/selfhost-dns-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&base_dir);

        let this_pid = std::process::id();
        let written_pid = write_handoff(&base_dir).expect("write handoff");
        assert_eq!(written_pid, this_pid);

        let read_pid = read_handoff(&base_dir);
        assert_eq!(read_pid, Some(this_pid));

        // Cleanup
        let _ = fs::remove_dir_all(&base_dir);
    }

    #[tokio::test]
    async fn handoff_file_returns_none_when_missing() {
        use std::fs;

        // Use a non-existent temporary directory path
        let base_dir = std::path::PathBuf::from(format!("/tmp/selfhost-dns-test-missing-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base_dir);  // Ensure it doesn't exist

        let read_pid = read_handoff(&base_dir);
        assert_eq!(read_pid, None, "should return None for missing handoff file");
    }
}
