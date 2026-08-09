//! The authoritative-DNS section of a deployment.
//!
//! A deployment that serves its own zone declares it here, in
//! `selfhost.config.toml`, exactly as it declares its sites: one hand-written
//! document that every service reads. This module is only the *schema* and its
//! validation — the runtime zone the server actually serves is built from these
//! types in `selfhost-dns` (`dns::Zone::from_config`), because that crate owns
//! the wire spelling of a record and this one must not depend on it.
//!
//! The one subtlety worth stating plainly: **a bare zone is the common case.**
//! Most deployments write `[[dns.zone]] domain = "example.com"` and nothing
//! else, and the records — apex `A`, `www`, the nameserver glue, a sane SOA —
//! are *derived* from the machine's discovered public IP. Listing records is the
//! escape hatch, not the default. Validation therefore treats an empty record
//! list as valid, not as a zone that serves nothing.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::validate::Problem;

/// Longest a domain name may be, in bytes. Mirrors `dns::wire::MAX_NAME`; kept
/// local so this crate stays free of a dependency on the DNS crate (which
/// depends on *this* one).
const MAX_NAME: usize = 255;
/// Longest a single label may be, in bytes. Mirrors `dns::wire::MAX_LABEL`.
const MAX_LABEL: usize = 63;

/// Authoritative DNS, when this machine serves its own zone.
///
/// Absent from the config means no DNS: the daemon binds no `:53` listener and
/// the doctor's authority section is skipped. DNS is opt-in because a box that
/// answers authoritatively for a zone it does not own is a misconfiguration that
/// is worse than silence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dns {
    /// Address the DNS server binds for UDP and TCP. Defaults to `0.0.0.0:53`.
    #[serde(default = "default_dns_bind")]
    pub bind: String,

    /// Secondary nameservers permitted to `AXFR`, and advertised as `NS`.
    ///
    /// Not optional in spirit: with one nameserver the domain — and its mail —
    /// stops resolving whenever this box is down. Empty is allowed but the doctor
    /// warns, since a free secondary (Hurricane Electric offers one) removes a
    /// single point of failure that takes the whole domain with it.
    #[serde(default)]
    pub secondaries: Vec<String>,

    /// Whether the daemon tracks the WAN IP and rewrites the apex `A` on change.
    ///
    /// On by default because a residential address is dynamic: without this the
    /// apex `A` goes stale the first time the ISP hands out a new address, and
    /// the domain points at a stranger.
    #[serde(default = "default_true")]
    pub dynamic_ip: bool,

    /// This machine's LAN address, enabling split-horizon answers.
    ///
    /// When set, a query arriving from a private address is answered with this
    /// address wherever a record points at the machine's public IP — a NAT that
    /// does not hairpin makes the public address unreachable from inside — and
    /// names outside the served zones are forwarded upstream for LAN clients,
    /// so the router can hand this box out as the network's DNS server. Public
    /// queriers are never forwarded for and never see this address. Unset means
    /// every querier gets the public answers and nothing is ever forwarded,
    /// which supersedes running `selfhost lan-dns` as a separate process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lan_ip: Option<String>,

    /// The zones served. A single-domain deployment writes one, often bare.
    #[serde(default, rename = "zone")]
    pub zones: Vec<ZoneConfig>,
}

impl Dns {
    /// Collects every structural problem with the DNS configuration.
    ///
    /// `at` is the dotted path problems are reported under (`dns`). Every rule is
    /// checked and every violation collected, in the crate's all-at-once style,
    /// so one `selfhost check` names everything that needs fixing rather than the
    /// first thing.
    pub fn check(&self, at: &str, problems: &mut Vec<Problem>) {
        if self.bind.parse::<SocketAddr>().is_err() {
            problems.push(Problem {
                field: format!("{at}.bind"),
                message: "must be a bindable address like 0.0.0.0:53".into(),
            });
        }

        for (i, secondary) in self.secondaries.iter().enumerate() {
            if let Some(message) = name_problem(secondary) {
                problems.push(Problem {
                    field: format!("{at}.secondaries[{i}]"),
                    message,
                });
            }
        }

        if let Some(lan_ip) = &self.lan_ip {
            if lan_ip.parse::<Ipv4Addr>().is_err() {
                problems.push(Problem {
                    field: format!("{at}.lan_ip"),
                    message: format!("\"{lan_ip}\" is not an IPv4 address like 192.168.1.8"),
                });
            }
        }

        for (i, zone) in self.zones.iter().enumerate() {
            zone.check(&format!("{at}.zone[{i}]"), problems);
        }
    }
}

/// One zone in TOML.
///
/// A bare `{ domain }` derives its records from the public IP via
/// `dns::default_zone`; a non-empty `records` list replaces that default
/// entirely, so an explicit zone is exactly what it says and nothing more.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneConfig {
    /// The apex domain, e.g. "example.com". Lowercased where it is served.
    pub domain: String,
    /// SOA overrides; every field defaults (RFC 1912 timers, `ns1.<domain>`
    /// primary, today's serial), so this is only for a deployment that needs to
    /// pin one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soa: Option<SoaConfig>,
    /// Authoritative nameserver hostnames. Empty derives `ns1`/`ns2.<domain>`
    /// plus any configured secondaries.
    #[serde(default)]
    pub nameservers: Vec<String>,
    /// Explicit records. Empty derives apex and `www` `A` from the public IP.
    #[serde(default, rename = "record")]
    pub records: Vec<RecordConfig>,
}

impl ZoneConfig {
    /// Whether `name` is this zone's apex — `"@"` or the domain itself.
    fn is_apex(&self, name: &str) -> bool {
        name == "@" || name.trim_end_matches('.').eq_ignore_ascii_case(&self.domain)
    }

    /// Collects every structural problem with this zone.
    fn check(&self, at: &str, problems: &mut Vec<Problem>) {
        if let Some(message) = name_problem(&self.domain) {
            problems.push(Problem { field: format!("{at}.domain"), message });
        }

        for (i, ns) in self.nameservers.iter().enumerate() {
            if let Some(message) = name_problem(ns) {
                problems.push(Problem { field: format!("{at}.nameservers[{i}]"), message });
            }
        }

        for (i, record) in self.records.iter().enumerate() {
            record.check(&format!("{at}.record[{i}]"), self, problems);
        }
    }
}

/// SOA overrides. An unset field is derived rather than zero.
///
/// Every field is optional because the whole record is derivable from the domain
/// and the date; this exists only for the deployment that must match a serial a
/// secondary already holds, or wants slower timers than the defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SoaConfig {
    /// Primary nameserver. Defaults to `ns1.<domain>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<String>,
    /// Responsible party in DNS form. Defaults to `hostmaster.<domain>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub responsible: Option<String>,
    /// Zone version. Defaults to today's `YYYYMMDD00`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<u32>,
    /// Refresh timer, seconds. Defaults to two hours.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<u32>,
    /// Retry timer, seconds. Defaults to one hour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<u32>,
    /// Expire timer, seconds. Defaults to two weeks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire: Option<u32>,
    /// Minimum / negative-cache TTL, seconds. Defaults to one hour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum: Option<u32>,
}

/// One record in TOML, string-typed on the wire face like `RecordType::Display`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordConfig {
    /// Owner, relative to the zone apex. `"@"` is the apex, `"www"` is
    /// `www.<domain>`.
    pub name: String,
    /// Record type, spelled `A`, `AAAA`, `MX`, `TXT`, `CNAME`, `NS`, `SRV`, or `CAA`.
    #[serde(rename = "type")]
    pub record_type: String,
    /// Time-to-live in seconds. Defaults to one hour.
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    /// The value: an IP for `A`/`AAAA`, a hostname for `CNAME`/`NS`/`MX`, text
    /// for `TXT`, `<priority> <weight> <port> <target>` for `SRV`, and
    /// `<flags> <tag> <value>` for `CAA`.
    pub value: String,
    /// `MX` preference — lower is tried first. Required for `MX`, ignored
    /// elsewhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preference: Option<u16>,
}

impl RecordConfig {
    /// Collects every structural problem with this record.
    ///
    /// `zone` is needed to reject a `CNAME` at the apex, which is illegal because
    /// the apex must also carry `SOA` and `NS` and a `CNAME` forbids any sibling.
    fn check(&self, at: &str, zone: &ZoneConfig, problems: &mut Vec<Problem>) {
        if self.name.is_empty() {
            problems.push(Problem {
                field: format!("{at}.name"),
                message: "must not be empty; use \"@\" for the apex".into(),
            });
        }

        // The value fault for this record's type, if any. Held as a message and
        // pushed once, so no closure borrows `problems` while the type-specific
        // rules below (preference, apex CNAME) also need to push.
        let value_fault: Option<String> = match self.record_type.to_ascii_uppercase().as_str() {
            "A" => (self.value.parse::<Ipv4Addr>().is_err())
                .then(|| format!("\"{}\" is not an IPv4 address", self.value)),
            "AAAA" => (self.value.parse::<Ipv6Addr>().is_err())
                .then(|| format!("\"{}\" is not an IPv6 address", self.value)),
            "MX" => {
                if self.preference.is_none() {
                    problems.push(Problem {
                        field: format!("{at}.preference"),
                        message: "an MX record needs a preference; lower is tried first".into(),
                    });
                }
                self.value
                    .is_empty()
                    .then(|| "an MX record needs a mail-exchanger hostname".to_owned())
            }
            "CNAME" => {
                if zone.is_apex(&self.name) {
                    problems.push(Problem {
                        field: format!("{at}.name"),
                        message: "a CNAME cannot sit at the zone apex; the apex must carry SOA \
                                  and NS, and a CNAME forbids any other record on its name"
                            .into(),
                    });
                }
                self.value.is_empty().then(|| "a CNAME record needs a target hostname".to_owned())
            }
            "NS" => self
                .value
                .is_empty()
                .then(|| "an NS record needs a nameserver hostname".to_owned()),
            "TXT" => self.value.is_empty().then(|| "a TXT record needs a value".to_owned()),
            "SRV" => srv_problem(&self.value),
            "CAA" => caa_problem(&self.value),
            other => {
                problems.push(Problem {
                    field: format!("{at}.type"),
                    message: format!(
                        "\"{other}\" is not a known record type (A, AAAA, MX, TXT, CNAME, NS, SRV, CAA)"
                    ),
                });
                None
            }
        };

        if let Some(message) = value_fault {
            problems.push(Problem { field: format!("{at}.value"), message });
        }
    }
}

/// Why an `SRV` value is unusable, or `None` if it parses.
///
/// An `SRV` value is written in RFC 2782 zone-file order,
/// `<priority> <weight> <port> <target>`, e.g. `0 1 993 imap.example.com`.
fn srv_problem(value: &str) -> Option<String> {
    let fields: Vec<&str> = value.split_whitespace().collect();
    let [priority, weight, port, target] = fields.as_slice() else {
        return Some(
            "SRV needs priority, weight, port, and a target host, e.g. 0 1 993 imap.example.com"
                .into(),
        );
    };
    for (label, field) in [("priority", priority), ("weight", weight), ("port", port)] {
        if field.parse::<u16>().is_err() {
            return Some(format!("SRV {label} \"{field}\" must be a number 0-65535"));
        }
    }
    target.is_empty().then(|| "SRV needs a target hostname".to_owned())
}

/// Why a `CAA` value is unusable, or `None` if it parses.
///
/// A `CAA` value is written in presentation form `<flags> <tag> <value>`, e.g.
/// `0 issue letsencrypt.org`. This checks the shape the runtime later encodes,
/// so a typo is a load error rather than a record the server silently drops.
fn caa_problem(value: &str) -> Option<String> {
    let mut fields = value.split_whitespace();
    let Some(flags) = fields.next() else {
        return Some("CAA needs flags, a tag, and a value, e.g. 0 issue letsencrypt.org".into());
    };
    if flags.parse::<u8>().is_err() {
        return Some(format!("CAA flags \"{flags}\" must be a number 0-255"));
    }
    let Some(tag) = fields.next() else {
        return Some("CAA needs a tag such as \"issue\"".into());
    };
    if tag.is_empty() || tag.len() > MAX_LABEL {
        return Some(format!("CAA tag \"{tag}\" is not a usable length"));
    }
    let rest: Vec<&str> = fields.collect();
    if rest.is_empty() {
        return Some("CAA needs a value, e.g. letsencrypt.org".into());
    }
    None
}

/// Why a name cannot be used as a domain, or `None` if it is fine.
///
/// The same posture as the service-name check: a name that is empty, over-long,
/// or has an empty or dash-led label is refused outright rather than quietly
/// rewritten, because a zone served under a name the operator did not mean is a
/// silent, hard-to-see failure.
fn name_problem(name: &str) -> Option<String> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        return Some("must not be empty".into());
    }
    if trimmed.len() > MAX_NAME {
        return Some(format!("is {} bytes; a domain name may be at most {MAX_NAME}", trimmed.len()));
    }
    for label in trimmed.split('.') {
        if label.is_empty() {
            return Some(format!("\"{name}\" has an empty label"));
        }
        if label.len() > MAX_LABEL {
            return Some(format!("label \"{label}\" is over {MAX_LABEL} bytes"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Some(format!("label \"{label}\" may not start or end with a dash"));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Some(format!(
                "label \"{label}\" may only contain letters, digits, dash, and underscore"
            ));
        }
    }
    None
}

/// Every registered domain the config serves: site domains and mail domains,
/// each grouped to its registered parent, deduplicated, sorted.
///
/// This is the set of *zones* the deployment implies — `www.example.com` and
/// `example.com` are one zone, not two. It feeds both sides of the DNS story
/// from one definition: the authoritative server derives a zone per entry, and
/// `selfhost dns sync` reconciles the same entries at a registrar, so the two
/// can never disagree about which domains the deployment owns. Names without a
/// dot (`localhost`) belong to no registry and are skipped. Grouping is by the
/// vendored Public Suffix List ([`crate::psl::registrable`]), so `example.co.uk`
/// and `waves.surf` both land on their real registered apex.
pub fn registered_domains(config: &crate::Config) -> BTreeSet<String> {
    let mut domains = BTreeSet::new();
    let mut claim = |name: &str| {
        if let Some(registered) = crate::psl::registrable(name) {
            domains.insert(registered);
        }
    };
    for site in &config.sites {
        for domain in &site.domains {
            claim(domain);
        }
    }
    if let Some(mail) = &config.mail {
        for domain in &mail.domains {
            claim(domain);
        }
    }
    domains
}

fn default_dns_bind() -> String {
    "0.0.0.0:53".to_owned()
}

fn default_ttl() -> u32 {
    3600
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    /// Parses a config and returns its validation problems, or an empty vec.
    fn problems_of(text: &str) -> Vec<Problem> {
        match Config::parse(text) {
            Ok(_) => Vec::new(),
            Err(crate::ConfigError::Invalid(problems)) => problems,
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    /// A valid deployment with the given `[dns]` body appended.
    fn config_with_dns(dns_body: &str) -> String {
        format!(
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

{dns_body}
"#
        )
    }

    #[test]
    fn a_bare_zone_parses_and_validates() {
        let text = config_with_dns(
            r#"
[dns]

[[dns.zone]]
domain = "example.com"
"#,
        );
        let config = Config::parse(&text).expect("valid");
        let dns = config.dns.expect("dns present");
        // Bind and dynamic_ip default rather than needing to be written.
        assert_eq!(dns.bind, "0.0.0.0:53");
        assert!(dns.dynamic_ip);
        assert_eq!(dns.zones.len(), 1);
        assert!(dns.zones[0].records.is_empty(), "a bare zone lists no records");
    }

    #[test]
    fn a_config_without_a_dns_section_parses_and_serves_no_dns() {
        let config = Config::parse(&config_with_dns("")).expect("valid");
        assert!(config.dns.is_none(), "DNS is opt-in");
    }

    #[test]
    fn the_full_example_from_the_contract_parses() {
        let text = config_with_dns(
            r#"
[dns]
bind = "0.0.0.0:53"
secondaries = ["ns2.he.net"]
dynamic_ip = true

[[dns.zone]]
domain = "example.com"
nameservers = ["ns1.example.com", "ns2.he.net"]

  [[dns.zone.record]]
  name = "@"
  type = "A"
  value = "203.0.113.10"

  [[dns.zone.record]]
  name = "@"
  type = "MX"
  preference = 10
  value = "mail.example.com"

  [[dns.zone.record]]
  name = "@"
  type = "TXT"
  value = "v=spf1 mx -all"
"#,
        );
        let config = Config::parse(&text).expect("valid");
        let dns = config.dns.expect("dns present");
        assert_eq!(dns.secondaries, vec!["ns2.he.net".to_owned()]);
        assert_eq!(dns.zones[0].records.len(), 3);
        // The record TTL defaults rather than parsing as zero.
        assert_eq!(dns.zones[0].records[0].ttl, 3600);
    }

    #[test]
    fn rejects_a_bind_that_is_not_a_socket_address() {
        let problems = problems_of(&config_with_dns(
            r#"
[dns]
bind = "53"

[[dns.zone]]
domain = "example.com"
"#,
        ));
        assert!(problems.iter().any(|p| p.field == "dns.bind"), "{problems:?}");
    }

    #[test]
    fn rejects_an_mx_record_with_no_preference() {
        let problems = problems_of(&config_with_dns(
            r#"
[dns]

[[dns.zone]]
domain = "example.com"

  [[dns.zone.record]]
  name = "@"
  type = "MX"
  value = "mail.example.com"
"#,
        ));
        assert!(
            problems.iter().any(|p| p.field == "dns.zone[0].record[0].preference"),
            "{problems:?}"
        );
    }

    #[test]
    fn rejects_a_cname_at_the_apex() {
        // The apex must carry SOA and NS; a CNAME forbids any sibling on its
        // name, so a CNAME there would delete the zone's own authority records.
        let problems = problems_of(&config_with_dns(
            r#"
[dns]

[[dns.zone]]
domain = "example.com"

  [[dns.zone.record]]
  name = "@"
  type = "CNAME"
  value = "elsewhere.example.net"
"#,
        ));
        assert!(
            problems.iter().any(|p| p.field == "dns.zone[0].record[0].name"),
            "{problems:?}"
        );
    }

    #[test]
    fn rejects_a_malformed_address_and_an_unknown_type() {
        let problems = problems_of(&config_with_dns(
            r#"
[dns]

[[dns.zone]]
domain = "example.com"

  [[dns.zone.record]]
  name = "@"
  type = "A"
  value = "not-an-ip"

  [[dns.zone.record]]
  name = "weird"
  type = "NAPTR"
  value = "x"
"#,
        ));
        assert!(problems.iter().any(|p| p.field == "dns.zone[0].record[0].value"), "{problems:?}");
        assert!(problems.iter().any(|p| p.field == "dns.zone[0].record[1].type"), "{problems:?}");
    }

    #[test]
    fn accepts_a_well_formed_srv_and_rejects_a_malformed_one() {
        // RFC 2782 zone-file order: priority weight port target.
        let good = config_with_dns(
            r#"
[dns]

[[dns.zone]]
domain = "example.com"

  [[dns.zone.record]]
  name = "_imaps._tcp"
  type = "SRV"
  value = "0 1 993 imap.example.com"
"#,
        );
        assert!(Config::parse(&good).is_ok());

        let problems = problems_of(&config_with_dns(
            r#"
[dns]

[[dns.zone]]
domain = "example.com"

  [[dns.zone.record]]
  name = "_imaps._tcp"
  type = "SRV"
  value = "0 1 imap.example.com"
"#,
        ));
        assert!(problems.iter().any(|p| p.field == "dns.zone[0].record[0].value"), "{problems:?}");
    }

    #[test]
    fn rejects_a_malformed_caa_value() {
        let problems = problems_of(&config_with_dns(
            r#"
[dns]

[[dns.zone]]
domain = "example.com"

  [[dns.zone.record]]
  name = "@"
  type = "CAA"
  value = "issue"
"#,
        ));
        assert!(problems.iter().any(|p| p.field == "dns.zone[0].record[0].value"), "{problems:?}");
    }

    #[test]
    fn accepts_a_well_formed_caa_letsencrypt_record() {
        let text = config_with_dns(
            r#"
[dns]

[[dns.zone]]
domain = "example.com"

  [[dns.zone.record]]
  name = "@"
  type = "CAA"
  value = "0 issue letsencrypt.org"
"#,
        );
        assert!(Config::parse(&text).is_ok());
    }

    #[test]
    fn rejects_a_domain_with_an_empty_or_dash_led_label() {
        let problems = problems_of(&config_with_dns(
            r#"
[dns]

[[dns.zone]]
domain = "-bad..example"
"#,
        ));
        assert!(problems.iter().any(|p| p.field == "dns.zone[0].domain"), "{problems:?}");
    }

    #[test]
    fn reports_every_problem_at_once_not_just_the_first() {
        let problems = problems_of(&config_with_dns(
            r#"
[dns]
bind = "nope"

[[dns.zone]]
domain = "example.com"

  [[dns.zone.record]]
  name = "@"
  type = "A"
  value = "bad"

  [[dns.zone.record]]
  name = "@"
  type = "MX"
  value = "mail.example.com"
"#,
        ));
        assert!(problems.len() >= 3, "expected several problems, got {problems:?}");
    }

    #[test]
    fn round_trips_through_toml() {
        let text = config_with_dns(
            r#"
[dns]
secondaries = ["ns2.he.net"]

[[dns.zone]]
domain = "example.com"

  [[dns.zone.record]]
  name = "www"
  type = "A"
  value = "203.0.113.10"
"#,
        );
        let config = Config::parse(&text).expect("valid");
        let written = toml::to_string(&config).expect("serialise");
        let read = Config::parse(&written).expect("re-parse");
        assert_eq!(read.dns.unwrap().zones[0].records[0].name, "www");
    }
}
