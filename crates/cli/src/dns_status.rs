//! `selfhost dns` — show the zone this machine serves, and whether it is live.
//!
//! Two questions in one place, because they are always asked together: *what
//! would this machine serve?* and *is it serving it right now?*
//!
//! The **preview** is derived from the config exactly the way the server derives
//! it — [`Authority::for_config`] expands a bare `[[dns.zone]]` into the same
//! apex/`www` records the daemon would answer with — so what is printed here is
//! what the wire would carry, not a second description that could drift from it.
//!
//! The **status** is a single query to the configured bind: if the server
//! answers its own apex `SOA`, it is up. That probe goes to loopback, so it
//! measures the local server alone. It says nothing about whether the internet
//! can reach port 53 — that depends on the router/edge forwarding UDP **and** TCP
//! 53 to this machine, which selfhost deliberately never changes. `selfhost
//! doctor` reports the edge; this command only names the requirement.

use selfhost_config::Config;
use selfhost_dns::authority::Authority;
use selfhost_dns::{Record, RecordData, RecordType, Resolver};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Prints the configured zone(s), a preview of their records, and live status.
///
/// Needs no running daemon to describe the zone; it also probes the bind so the
/// reader learns whether the server is answering. Returns an error only when the
/// bind address in the config cannot be parsed — the config validator should
/// have caught that already, so reaching it means the config was hand-edited
/// past validation.
pub async fn show(config: &Config) -> Result<(), String> {
    let Some(dns) = &config.dns else {
        println!("This machine serves no DNS zone of its own.\n");
        println!(
            "Add a [dns] section to selfhost.config.toml to have it answer authoritatively\n\
             for your domain. A bare zone derives its apex and www records from the public IP:\n"
        );
        println!("  [dns]");
        println!("  secondaries = [\"ns2.he.net\"]\n");
        println!("  [[dns.zone]]");
        println!("  domain = \"example.com\"");
        return Ok(());
    };

    let bind: SocketAddr =
        dns.bind.parse().map_err(|error| format!("dns.bind {} does not parse: {error}", dns.bind))?;

    // Derived once, from the same public IP the server would use, so the preview
    // matches what would actually be answered.
    let public_ip = crate::doctor::discover_public_ip().await;
    let authority = Authority::for_config(config, public_ip);
    let origins = authority.origins().await;

    println!("authoritative DNS");
    println!("  bind          {bind}");
    match public_ip {
        Some(address) => println!("  public IP     {address}"),
        None => println!("  public IP     unknown — could not discover it from here"),
    }
    if dns.dynamic_ip {
        println!("  dynamic IP    on — the apex A follows this machine's WAN IP");
    } else {
        println!("  dynamic IP    off — the apex A stays as configured");
    }
    if dns.secondaries.is_empty() {
        println!("  secondaries   none — a single nameserver (see the warning below)");
    } else {
        println!("  secondaries   {}", dns.secondaries.join(", "));
    }

    // Live status: ask the server for its own apex SOA on loopback.
    let live = match origins.first() {
        Some(origin) => is_serving(bind, origin).await,
        None => false,
    };
    if live {
        println!("  status        answering on {bind}");
    } else {
        println!(
            "  status        not answering on {bind} — start it with `selfhost daemon` or \
             `selfhost serve-dns`"
        );
    }

    for origin in &origins {
        println!("\n  zone {origin}");
        match authority.export(origin).await {
            Some(records) if records.is_empty() => {
                println!("    (no records)");
            }
            Some(records) => {
                for record in &records {
                    println!("    {}", render_record(record, origin));
                }
            }
            None => println!("    (could not read this zone's records)"),
        }
    }

    if dns.secondaries.is_empty() {
        println!(
            "\nWarning: with only this machine as a nameserver, the domain and its mail stop\n\
             resolving whenever this box is down. Add a secondary (Hurricane Electric runs free\n\
             secondary DNS) and list it in [dns].secondaries."
        );
    }

    println!(
        "\nReachability: for the internet to reach this server, the router/edge must forward\n\
         UDP and TCP port 53 to this machine. selfhost does not change the router — that is a\n\
         deliberate change you make. `selfhost doctor` reports whether the edge allows it."
    );

    Ok(())
}

/// Whether the server at `bind` answers authoritatively for `origin`.
///
/// A single apex `SOA` query on loopback: an answer means the server is up and
/// owns the zone. A wildcard bind is queried on loopback, since the wildcard
/// address itself cannot be a query target.
async fn is_serving(bind: SocketAddr, origin: &str) -> bool {
    let target = if bind.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bind.port())
    } else {
        bind
    };
    let resolver = Resolver::at(target).with_timeout(Duration::from_secs(2));
    matches!(resolver.query(origin, RecordType::Soa).await, Ok(response) if !response.answers.is_empty())
}

/// Renders one zone record as a single aligned line, in zone-file spirit.
///
/// Owner names are shown relative to the apex (`@` for the apex itself) so the
/// preview reads like the zone rather than a wall of fully-qualified names.
fn render_record(record: &Record, origin: &str) -> String {
    let owner = relative_owner(&record.name, origin);
    let (kind, value) = describe_data(&record.data);
    format!("{owner:<20} {:<7} {kind:<5} {value}", record.ttl)
}

/// The owner name relative to the zone apex: `@` for the apex, the leftmost
/// labels otherwise.
fn relative_owner(name: &str, origin: &str) -> String {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let origin = origin.trim_end_matches('.').to_ascii_lowercase();
    if name == origin {
        "@".to_owned()
    } else if let Some(prefix) = name.strip_suffix(&format!(".{origin}")) {
        prefix.to_owned()
    } else {
        name
    }
}

/// A record's type name and value, without interpreting it.
///
/// The `Soa` arm uses `..` so it stays correct once the wire type gains its
/// numeric serial and timer fields — the preview shows the two names, which is
/// what a reader checks at a glance.
fn describe_data(data: &RecordData) -> (&'static str, String) {
    match data {
        RecordData::A(address) => ("A", address.to_string()),
        RecordData::Aaaa(address) => ("AAAA", address.to_string()),
        RecordData::Name(name) => ("NAME", name.clone()),
        RecordData::Mx { preference, exchange } => ("MX", format!("{preference} {exchange}")),
        RecordData::Txt(text) => ("TXT", format!("\"{text}\"")),
        RecordData::Soa { primary, responsible, .. } => {
            ("SOA", format!("{primary} {responsible}"))
        }
        RecordData::Srv { priority, weight, port, target } => {
            ("SRV", format!("{priority} {weight} {port} {target}"))
        }
        RecordData::Unknown { record_type, data } => {
            ("?", format!("{record_type:?} ({} bytes)", data.len()))
        }
    }
}
