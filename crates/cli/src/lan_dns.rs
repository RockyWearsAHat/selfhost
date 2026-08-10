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
//! once the router forwards UDP+TCP 53 here and the registrar delegates a
//! domain's `NS` to this box, the same process answers the world.
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

use crate::dns_sync;
use selfhost_config::{Config, Dns, RecordConfig, ZoneConfig, psl};
use selfhost_dns::Resolver;
use selfhost_dns::authority::{Authority, LanView};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

/// Builds the authority every DNS-serving path shares.
///
/// One constructor for the daemon, `selfhost dns serve`, and `lan-dns`, so the
/// three can never serve different zone content: zones from `[dns]` (bare ones
/// expanded from `public_ip`), each mail domain's `MX`/SPF/DMARC/DKIM/CAA
/// records (the DKIM `TXT` only when the key on disk is readable — read-only
/// here, `selfhost run` is what generates it), and the addresses and `SRV`s of
/// every host the config claims. The split-horizon LAN view is *not* set here;
/// each caller decides that from its own configuration.
pub fn build_authority(
    config: &Config,
    project_dir: &Path,
    public_ip: Option<Ipv4Addr>,
) -> Authority {
    let mail_records: Vec<(String, Vec<RecordConfig>)> = match &config.mail {
        Some(mail) => {
            let dkim = dns_sync::dkim_public(config, project_dir);
            mail.domains
                .iter()
                .map(|domain| (domain.clone(), mail.dns_records(domain, dkim.as_deref())))
                .collect()
        }
        None => Vec::new(),
    };
    Authority::for_config_with_mail(config, public_ip, &mail_records)
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
            });
        }
    }
    augmented
}

/// Serves split-horizon DNS for the LAN until interrupted.
///
/// Builds the shared [`Authority`] (see [`build_authority`]) over the config's
/// zones — synthesised from the claimed domains when `[dns]` is absent —
/// enables the LAN view at `lan_ip` with the system resolver as upstream, and
/// serves UDP and TCP on `bind`. Runs until a listener fails or Ctrl-C; the
/// scheduled task restarts it on the next trigger.
pub async fn lan_dns_command(
    config: &Config,
    project_dir: &Path,
    lan_ip: Ipv4Addr,
    bind: SocketAddr,
) -> Result<(), String> {
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

    // The public address the zones' records point at. Discovery can fail on a
    // flaky uplink; an explicit apex A in the config is the fallback, and the
    // LAN address the final one — LAN service (the job that must not die)
    // still works, since the LAN answer is the LAN address either way.
    let public_ip = match crate::doctor::discover_public_ip().await {
        Some(address) => address,
        None => config_apex_a(config).unwrap_or(lan_ip),
    };

    let augmented = with_synthesised_zones(config);
    let authority = build_authority(&augmented, project_dir, Some(public_ip));
    authority.set_lan(LanView { lan_ip, upstream });

    println!("selfhost split-horizon DNS");
    println!("  bind      {bind}");
    println!("  upstream  {upstream}");
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

    tokio::select! {
        result = authority.serve(bind) => result.map_err(|error| bind_hint(bind, error)),
        _ = tokio::signal::ctrl_c() => Ok(()),
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
            self_update: None,
            shares: vec![],
            desktop: None,
            mesh: None,
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
        };
        // The site domain does NOT grow a zone: the operator's [dns] wins.
        let config = config_with(vec![site(&["other.net"])], Some(dns));
        assert_eq!(zone_origins(&config), vec!["chosen.example"]);
    }
}
