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
use selfhost_dns::Resolver;
use selfhost_dns::authority::{Authority, LanView};
use selfhost_dns::socket::{bind_tcp_shared, bind_udp_shared};
use selfhost_mail::Dkim;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

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
                    (
                        domain.clone(),
                        mail.dns_records(domain, dkim.as_deref(), pacc.as_deref()),
                    )
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
    let key_path = project_dir
        .join(&config.server.data_dir)
        .join(&dkim.private_key);
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
        .map(|domain| ZoneConfig {
            domain,
            soa: None,
            nameservers: Vec::new(),
            records: Vec::new(),
        })
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
                .map(|zone| {
                    zone.domain
                        .trim()
                        .trim_end_matches('.')
                        .to_ascii_lowercase()
                })
                .filter(|origin| !origin.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// The upstreams a LAN peer's foreign question is forwarded to, in order.
///
/// The system resolver comes first: on this network it is the router, which
/// answers from its own cache in single-digit milliseconds and was measured
/// (2026-10-03, `docs/labs/insight-lab.dx`) not to forward the box's own
/// questions back here. The configured `[dns] upstreams` follow, so a router
/// hiccup fails over instead of becoming a SERVFAIL. Any address that is this
/// machine is left out — forwarding to ourselves would answer every question
/// with the question — and an empty list is refused rather than served.
pub fn forward_upstreams(
    config: &Config,
    lan_ip: Ipv4Addr,
    bind: SocketAddr,
) -> Result<Vec<SocketAddr>, String> {
    let is_this_machine = |upstream: &SocketAddr| {
        upstream.port() == bind.port()
            && (upstream.ip() == bind.ip()
                || upstream.ip() == IpAddr::V4(lan_ip)
                || upstream.ip().is_loopback())
    };
    let configured = config
        .dns
        .as_ref()
        .map(|dns| dns.upstreams.clone())
        .unwrap_or_default();
    let mut upstreams = vec![Resolver::system().address()];
    for text in &configured {
        let upstream: SocketAddr = text
            .parse()
            .map_err(|error| format!("[dns] upstreams: {text:?} is not ip:port ({error})"))?;
        upstreams.push(upstream);
    }
    let mut kept: Vec<SocketAddr> = Vec::new();
    for upstream in upstreams {
        if is_this_machine(&upstream) {
            eprintln!("warning: dns upstream {upstream} is this machine; leaving it out");
        } else if !kept.contains(&upstream) {
            kept.push(upstream);
        }
    }
    if kept.is_empty() {
        return Err(
            "no usable DNS upstream: every candidate is this machine.\n  Point this \
                    machine's own network adapter at the router or a public resolver (for \
                    example 1.1.1.1), or list one in [dns] upstreams, then re-run."
                .to_owned(),
        );
    }
    Ok(kept)
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

    let upstreams = forward_upstreams(&augmented, lan_ip, bind)?;

    // The public address the zones' records point at. Discovery can fail on a
    // flaky uplink; an explicit apex A in the config is the fallback, and the
    // LAN address the final one — LAN service (the job that must not die)
    // still works, since the LAN answer is the LAN address either way.
    let public_ip = match crate::doctor::discover_public_ip().await {
        Some(address) => address,
        None => config_apex_a(config).unwrap_or(lan_ip),
    };

    let authority = build_authority(&augmented, project_dir, Some(public_ip));
    authority.set_lan(LanView {
        lan_ip,
        upstreams: upstreams.clone(),
    });

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
    // old ones during zero-drop handoff; wait while a server that cannot be
    // joined still holds the port.
    let (udp, tcp) = tokio::select! {
        sockets = bind_when_free(bind) => sockets?,
        _ = tokio::signal::ctrl_c() => return Ok(()),
    };

    println!("{} [dns] bound with SO_REUSEADDR", selfhost_dns::stamp());

    // Serve first, then prove. Port 53 is shared with any instance being
    // replaced, and on Windows the first socket on a shared port receives all
    // of it, so live traffic cannot prove a newcomer: it asks its own query
    // path a forwarded question and a zone question instead. The handoff is
    // claimed once that passes, and the old instance drains only then. A
    // failing new instance leaves while the old one, which never stopped,
    // keeps serving: rollback is simply not taking over.
    let data_dir = project_dir.join(&config.server.data_dir);
    let serving = authority.serve_with_sockets(udp, tcp);
    tokio::pin!(serving);
    tokio::select! {
        result = &mut serving => return result.map_err(|error| bind_hint(bind, error)),
        _ = tokio::signal::ctrl_c() => return Ok(()),
        verdict = await_proof(&authority, &data_dir) => {
            if let Proof::Failing { lan, answered } = verdict {
                return Err(format!(
                    "{answered} of {lan} LAN queries answered; leaving DNS to the running instance"
                ));
            }
        }
    }

    let this_pid =
        write_handoff(&data_dir).map_err(|e| format!("could not write handoff file: {e}"))?;
    println!(
        "{} [dns] answered its own forwarded and zone questions; claimed the handoff as PID {this_pid}",
        selfhost_dns::stamp()
    );
    selfhost_dns::writer::spawn_stats_writer(authority.clone(), &data_dir, "lan-dns").await;

    // Serve until interrupted, or until a newer instance proves itself and claims the handoff.
    tokio::select! {
        result = &mut serving => result.map_err(|error| bind_hint(bind, error)),
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = watch_handoff(this_pid, &data_dir) => {
            // Keep serving until idle: closing with a query queued or still
            // being answered would lose it.
            let drained = tokio::select! {
                result = &mut serving => return result.map_err(|error| bind_hint(bind, error)),
                drained = authority.quiesce(DRAIN_FOR) => drained,
            };
            if drained {
                eprintln!("{} [dns] a newer instance took over; drained, exiting", selfhost_dns::stamp());
            } else {
                eprintln!(
                    "{} [dns] a newer instance took over; still busy after {} s, exiting anyway",
                    selfhost_dns::stamp(),
                    DRAIN_FOR.as_secs()
                );
            }
            Ok(())
        }
    }
}

/// How long a replaced instance waits to fall idle before it exits regardless.
const DRAIN_FOR: std::time::Duration = std::time::Duration::from_secs(3);

/// Answers this process must give before it claims the handoff.
const PROOF_ANSWERS: u64 = 3;

/// LAN queries seen before a mostly-failing instance gives up.
const PROOF_SAMPLE: u64 = 20;

/// What this process's own counters say about whether it serves correctly.
#[derive(Debug, PartialEq, Eq)]
enum Proof {
    /// Not enough traffic yet to tell.
    Pending,
    /// Enough real answers: safe to take over.
    Proven,
    /// Most LAN queries failed: do not take over.
    Failing { lan: u64, answered: u64 },
}

fn judge(counters: &selfhost_dns::telemetry::GlobalCounters) -> Proof {
    let answered = counters.zone + counters.cache_hit + counters.forwarded + counters.stale;
    if answered >= PROOF_ANSWERS {
        Proof::Proven
    } else if counters.lan >= PROOF_SAMPLE && answered * 2 < counters.lan {
        Proof::Failing {
            lan: counters.lan,
            answered,
        }
    } else {
        Proof::Pending
    }
}

/// Waits until this process has proven itself, or has shown it is failing
/// while another instance holds the handoff. Each failed self-test counts as
/// unanswered LAN queries, so about ten in a row read as failing. With no
/// other instance (a fresh boot) a failing verdict keeps waiting: leaving
/// would take DNS away entirely.
async fn await_proof(authority: &Authority, data_dir: &Path) -> Proof {
    let this_pid = std::process::id();
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        tick.tick().await;
        if authority.answers_itself().await {
            return Proof::Proven;
        }
        match judge(&authority.telemetry_snapshot("lan-dns").counters) {
            Proof::Pending => {}
            Proof::Failing { .. } if should_keep_serving(this_pid, read_handoff(data_dir)) => {}
            verdict => return verdict,
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

/// How often a held port is retried at first, while a cutover is most likely
/// under way, and for how long before slowing to [`BIND_RETRY_SLOW`].
const BIND_RETRY_FAST: std::time::Duration = std::time::Duration::from_millis(50);
const BIND_FAST_FOR: std::time::Duration = std::time::Duration::from_secs(30);
/// How often a port still held after the first 30 s is retried.
const BIND_RETRY_SLOW: std::time::Duration = std::time::Duration::from_secs(2);

/// Binds UDP and TCP on `bind`, waiting while another server holds the port.
///
/// Windows refuses a shared bind over a socket bound without SO_REUSEADDR
/// (WSAEACCES; measured on the box 2026-10-04 against the daemon's own
/// binary), so a daemon serving :53 itself cannot be joined, only replaced.
/// While the port is held this retries, every 50 ms for the first 30 s and
/// every 2 s after, and takes the port the moment its holder lets go. Any
/// other bind error is fatal.
async fn bind_when_free(
    bind: SocketAddr,
) -> Result<(tokio::net::UdpSocket, tokio::net::TcpListener), String> {
    let started = tokio::time::Instant::now();
    let mut waiting = false;
    loop {
        // A UDP socket bound before the TCP bind fails is dropped here, so a
        // waiting instance never holds half the port.
        match bind_udp_shared(bind).and_then(|udp| Ok((udp, bind_tcp_shared(bind)?))) {
            Ok(sockets) => {
                if waiting {
                    println!(
                        "{} [dns] {bind} is free; bound after {} ms",
                        selfhost_dns::stamp(),
                        started.elapsed().as_millis()
                    );
                }
                return Ok(sockets);
            }
            Err(error) if is_held(&error) => {
                if !waiting {
                    eprintln!(
                        "{} [dns] {bind} is held by another server ({error}); waiting for it",
                        selfhost_dns::stamp()
                    );
                    waiting = true;
                }
                let pause = if started.elapsed() < BIND_FAST_FOR {
                    BIND_RETRY_FAST
                } else {
                    BIND_RETRY_SLOW
                };
                tokio::time::sleep(pause).await;
            }
            Err(error) => {
                return Err(format!(
                    "cannot bind {bind}: {error}\n  \
                     This usually means port 53 needs privilege.\n  \
                     On macOS that is usually a VPN client or Internet Sharing."
                ));
            }
        }
    }
}

/// Whether a bind failed because another socket holds the port. Windows says
/// so with WSAEACCES, which Rust reads as permission denied; elsewhere that
/// means a privileged port, which waiting never fixes.
fn is_held(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::AddrInUse
        || (cfg!(windows) && error.kind() == std::io::ErrorKind::PermissionDenied)
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
        None => true,                         // File missing: no handoff yet, keep serving.
        Some(pid) if pid == this_pid => true, // Same PID: keep serving.
        Some(_) => false,                     // Different PID: hand off.
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
            nodes: vec![Node {
                name: "home".into(),
                role: Role::Owner,
                mesh_ip: None,
            }],
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

    fn counters(
        lan: u64,
        forwarded: u64,
        servfail: u64,
    ) -> selfhost_dns::telemetry::GlobalCounters {
        selfhost_dns::telemetry::GlobalCounters {
            queries: lan,
            lan,
            forwarded,
            servfail,
            ..Default::default()
        }
    }

    #[test]
    fn the_handoff_waits_for_real_answers() {
        assert_eq!(judge(&counters(0, 0, 0)), Proof::Pending);
        assert_eq!(judge(&counters(2, 2, 0)), Proof::Pending);
        assert_eq!(judge(&counters(3, 3, 0)), Proof::Proven);
        // A trickle of failures is not yet a verdict either way.
        assert_eq!(judge(&counters(19, 0, 19)), Proof::Pending);
    }

    #[test]
    fn a_mostly_failing_instance_does_not_take_over() {
        assert_eq!(
            judge(&counters(20, 2, 18)),
            Proof::Failing {
                lan: 20,
                answered: 2
            }
        );
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
        let config = config_with(
            vec![site(&["192.168.1.8", "localhost", "real.example.com"])],
            None,
        );
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
            serve_in_daemon: true,
        };
        // The site domain does NOT grow a zone: the operator's [dns] wins.
        let config = config_with(vec![site(&["other.net"])], Some(dns));
        assert_eq!(zone_origins(&config), vec!["chosen.example"]);
    }

    #[test]
    fn handoff_decision_fn_keeps_serving_with_same_pid() {
        let this_pid = 1234;
        assert!(
            should_keep_serving(this_pid, Some(1234)),
            "should keep serving with same PID"
        );
    }

    #[test]
    fn handoff_decision_fn_stops_serving_with_different_pid() {
        let this_pid = 1234;
        assert!(
            !should_keep_serving(this_pid, Some(5678)),
            "should stop serving with different PID"
        );
    }

    #[test]
    fn handoff_decision_fn_keeps_serving_with_missing_file() {
        let this_pid = 1234;
        assert!(
            should_keep_serving(this_pid, None),
            "should keep serving when file is missing"
        );
    }

    #[tokio::test]
    async fn reuse_address_allows_binding_same_port_twice() {
        use std::net::IpAddr;

        let addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 0);

        // First bind: the OS gives us an ephemeral port
        let first_socket = bind_udp_shared(addr).expect("first bind");
        let bound_addr = first_socket.local_addr().expect("get local addr");

        // Second bind: with SO_REUSEADDR, we can bind to the same port immediately
        // (this would fail without SO_REUSEADDR on most systems, or take 60+ seconds)
        let second_socket = bind_udp_shared(bound_addr).expect("second bind to same port");
        let second_bound_addr = second_socket.local_addr().expect("get second local addr");

        // Both sockets bound to the same address
        assert_eq!(bound_addr, second_bound_addr);
    }

    #[tokio::test]
    async fn tcp_reuse_address_allows_binding_same_port_twice() {
        use std::net::IpAddr;

        let addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 0);

        // First bind: the OS gives us an ephemeral port
        let first_listener = bind_tcp_shared(addr).expect("first bind");
        let bound_addr = first_listener.local_addr().expect("get local addr");

        // Second bind: with SO_REUSEADDR, we can bind to the same port immediately
        let second_listener = bind_tcp_shared(bound_addr).expect("second bind to same port");
        let second_bound_addr = second_listener.local_addr().expect("get second local addr");

        // Both listeners bound to the same address
        assert_eq!(bound_addr, second_bound_addr);
    }

    #[tokio::test]
    async fn handoff_file_can_be_written_and_read() {
        use std::fs;

        // Use a temporary directory path without actually creating tempfile crate dependency
        let base_dir =
            std::path::PathBuf::from(format!("/tmp/selfhost-dns-test-{}", std::process::id()));
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
        let base_dir = std::path::PathBuf::from(format!(
            "/tmp/selfhost-dns-test-missing-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base_dir); // Ensure it doesn't exist

        let read_pid = read_handoff(&base_dir);
        assert_eq!(
            read_pid, None,
            "should return None for missing handoff file"
        );
    }

    #[tokio::test]
    async fn a_held_port_is_taken_the_moment_it_is_freed() {
        use std::time::Duration;

        // A plain socket, like the daemon's own :53, cannot be joined.
        let holder = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let bind = holder.local_addr().unwrap();
        let started = std::time::Instant::now();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            drop(holder);
        });
        let (udp, _tcp) = bind_when_free(bind).await.expect("binds once the holder lets go");
        let waited = started.elapsed();
        assert_eq!(udp.local_addr().unwrap(), bind);
        assert!(waited >= Duration::from_millis(300), "bound while still held: {waited:?}");
        assert!(waited < Duration::from_millis(300) + 4 * BIND_RETRY_FAST, "slow to take the port: {waited:?}");
    }

    /// WP0's swap, on loopback: an old server answers, a new one binds the
    /// same port beside it, the old one exits, and a client asking all along
    /// never goes unanswered. One retry is allowed, as every stub resolver
    /// makes one; a query that needs it is counted and reported.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_swap_on_a_shared_port_leaves_no_query_unanswered() {
        use selfhost_dns::wire::{RecordType, encode_query};
        use std::sync::Arc;
        use std::time::Duration;

        let config = with_synthesised_zones(&config_with(vec![site(&["swap.test"])], None));
        let public = Some(Ipv4Addr::new(203, 0, 113, 7));
        let old = build_authority(&config, &std::env::temp_dir(), public);
        let new = build_authority(&config, &std::env::temp_dir(), public);

        let first = bind_udp_shared("127.0.0.1:0".parse().unwrap()).expect("old binds");
        let port = first.local_addr().unwrap();
        let mut old_server = tokio::spawn(async move { old.serve_udp(Arc::new(first)).await });
        let mut new_server = None;

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(port).await.unwrap();
        let mut retried = Vec::new();
        for id in 0..300_u16 {
            if id == 100 {
                let second = bind_udp_shared(port).expect("new binds beside the old");
                let new = new.clone();
                new_server = Some(tokio::spawn(async move { new.serve_udp(Arc::new(second)).await }));
            }
            if id == 200 {
                // The old instance exits: its socket is closed once the task is gone.
                old_server.abort();
                assert!((&mut old_server).await.unwrap_err().is_cancelled());
            }
            let query = encode_query(id, "swap.test", RecordType::A).unwrap();
            let mut answered = false;
            for attempt in 0..2 {
                client.send(&query).await.unwrap();
                let mut reply = [0_u8; 512];
                if let Ok(Ok(read)) = tokio::time::timeout(Duration::from_millis(500), client.recv(&mut reply)).await {
                    assert!(read >= 12 && reply[..2] == id.to_be_bytes() && reply[2] & 0x80 != 0, "query {id}: not its reply");
                    answered = true;
                    if attempt > 0 {
                        retried.push(id);
                    }
                    break;
                }
            }
            assert!(answered, "query {id} went unanswered across the swap (retried so far: {retried:?})");
        }
        assert!(retried.len() <= 1, "queries needing a retry: {retried:?}");
        let taken_over = new.telemetry_snapshot("new").counters.queries;
        assert!(taken_over >= 100, "the new instance answered only {taken_over} queries after the old one left");
        new_server.unwrap().abort();
    }
}
