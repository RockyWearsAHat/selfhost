//! `selfhost dns sync` — reconcile each domain's records at the registrar.
//!
//! The other side of `selfhost dns`: that command describes the zone this
//! machine *serves*; this one pushes the records the config implies to the
//! registrar that hosts the domain's DNS instead. The derivation and the
//! reconcile engine live in `selfhost-registrar` — this module only gathers
//! the inputs (the domains, the server address, the DKIM key), picks the
//! provider `[registrar]` names, and presents the plan.
//!
//! Dry-run is the default, always: the command prints what would change and
//! touches nothing until `--apply` is passed. The safety law comes with the
//! engine — a record whose `(host, type)` the config does not claim is never
//! deleted or modified, so the operator's own TXT verifications and
//! elsewhere-pointing CNAMEs survive every sync verbatim.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::path::Path;

use selfhost_acme::AcmeError;
use selfhost_acme::transport::{HttpsClient, Url};
use selfhost_config::{Config, Registrar, RegistrarProvider};
use selfhost_mail::Dkim;
use selfhost_registrar::cloudflare::Cloudflare;
use selfhost_registrar::godaddy::GoDaddy;
use selfhost_registrar::namecheap::{self, Namecheap};
use selfhost_registrar::plan::{self, Plan};
use selfhost_registrar::porkbun::Porkbun;
use selfhost_registrar::{ApiRequest, ApiResponse, DnsProvider, ProviderError, Record, Transport};

use crate::doctor;

/// Runs the sync: derive, list, plan, and — only with `apply` — write.
///
/// One registrar serves every domain: each registered domain the config
/// serves (site domains and mail domains, grouped to their registered
/// parents) is derived, listed, and reconciled in turn, so one command keeps
/// the whole deployment's DNS true rather than one domain at a time.
pub async fn run(config: &Config, project_dir: &Path, apply: bool) -> Result<(), String> {
    let Some(registrar) = config.registrar.as_ref() else {
        return Err("no [registrar] section in the config, so there is nowhere to sync to.\n  \
                    Add one naming the provider (namecheap, cloudflare, godaddy, porkbun, or \
                    manual)\n  and its credentials — `selfhost check` will name anything missing."
            .into());
    };

    let domains = registered_domains(config);
    if domains.is_empty() {
        return Err("the config serves no domains — no sites, no mail — so there is nothing \
                    to publish."
            .into());
    }

    let server_ip = server_address(config).await?;
    let dkim_txt = dkim_public(config, project_dir);

    match registrar.provider {
        RegistrarProvider::Manual => {
            print_manual(config, &domains, server_ip, dkim_txt.as_deref());
            Ok(())
        }
        RegistrarProvider::Namecheap => {
            let credentials = namecheap::Credentials {
                api_user: required(registrar, "api_user")?,
                api_key: required(registrar, "api_key")?,
                // Acting on one's own account: the API's UserName is the
                // ApiUser unless a sub-account is involved, which this
                // config schema does not model.
                user_name: required(registrar, "api_user")?,
                client_ip: required(registrar, "client_ip")?,
            };
            let provider = Namecheap::new(https_transport()?, credentials);
            sync_domains(&provider, config, &domains, server_ip, dkim_txt.as_deref(), apply, true)
                .await
        }
        RegistrarProvider::Cloudflare => {
            let provider = Cloudflare::new(https_transport()?, required(registrar, "api_key")?);
            sync_domains(&provider, config, &domains, server_ip, dkim_txt.as_deref(), apply, false)
                .await
        }
        RegistrarProvider::Godaddy => {
            let provider = GoDaddy::new(
                https_transport()?,
                required(registrar, "api_key")?,
                required(registrar, "api_secret")?,
            );
            sync_domains(&provider, config, &domains, server_ip, dkim_txt.as_deref(), apply, false)
                .await
        }
        RegistrarProvider::Porkbun => {
            let provider = Porkbun::new(
                https_transport()?,
                required(registrar, "api_key")?,
                required(registrar, "api_secret")?,
            );
            sync_domains(&provider, config, &domains, server_ip, dkim_txt.as_deref(), apply, false)
                .await
        }
    }
}

/// Derives, lists, plans, and reports every domain against one provider.
///
/// `srv_unsupported` is Namecheap's concession: its API cannot express SRV
/// records, so for that provider they are pulled out of the desired set and
/// simply go unpublished (mail clients fall back to the autoconfig
/// hostnames) rather than letting the provider refuse the entire apply over
/// records it can never write. The operator is explicitly told **not** to
/// add them by hand: Namecheap's setHosts replaces the whole zone per call
/// and can never restate an SRV, so the provider refuses to write any zone
/// holding one — a hand-added SRV would block every future sync.
async fn sync_domains<P: DnsProvider>(
    provider: &P,
    config: &Config,
    domains: &BTreeSet<String>,
    server_ip: Ipv4Addr,
    dkim_txt: Option<&str>,
    apply: bool,
    srv_unsupported: bool,
) -> Result<(), String> {
    let mut pending = 0_usize;
    for domain in domains {
        println!("\n── {domain}");

        let mut desired = plan::desired_records(config, domain, server_ip, dkim_txt);
        if srv_unsupported {
            let unwritable: Vec<Record> =
                Namecheap::<HttpsTransport>::unwritable(&desired).into_iter().cloned().collect();
            if !unwritable.is_empty() {
                println!("  ! Namecheap's API cannot write SRV records, so these client-discovery");
                println!("    SRVs go unpublished (mail clients fall back to the autoconfig");
                println!("    hostnames, so account setup still works):");
                for record in &unwritable {
                    println!("      {record}");
                }
                println!("    Do NOT add them by hand: Namecheap's API rewrites the whole zone");
                println!("    per push and can never restate an SRV, so a zone holding one");
                println!("    refuses every future `selfhost dns sync --apply`.");
                desired.retain(|record| record.rtype.kind() != "SRV");
            }
        }

        let observed = provider
            .list(domain)
            .await
            .map_err(|error| format!("{domain}: listing the current records failed — {error}"))?;
        let plan = plan::plan(&observed, &desired);
        print_plan(&plan);

        if plan.is_settled() {
            println!("  ✓ already in sync");
            continue;
        }
        if apply {
            provider
                .apply(domain, &plan.final_set())
                .await
                .map_err(|error| format!("{domain}: applying the plan failed — {error}"))?;
            println!("  ✓ applied");
        } else {
            pending += 1;
        }
    }

    if pending > 0 {
        println!("\ndry-run: nothing was written. Pass --apply to make the plan above real.");
    }
    Ok(())
}

/// Prints a plan's diff, indented under its domain heading.
fn print_plan(plan: &Plan) {
    for line in plan.render().lines() {
        println!("  {line}");
    }
}

/// Prints every domain's desired records for the operator to add by hand —
/// the whole of `provider = "manual"`, serving every registrar without an API.
///
/// No listing, no diff: without an API there is nothing to read back, so the
/// full desired set is shown in add-a-record form (type, host, value, TTL —
/// the fields every registrar's DNS panel asks for, in that order).
fn print_manual(
    config: &Config,
    domains: &BTreeSet<String>,
    server_ip: Ipv4Addr,
    dkim_txt: Option<&str>,
) {
    println!("provider = \"manual\": add these records in the registrar's DNS panel.");
    println!("Records already there that this list does not mention can stay as they are.");
    for domain in domains {
        println!("\n── {domain}");
        let records = plan::desired_records(config, domain, server_ip, dkim_txt);
        if records.is_empty() {
            println!("  (nothing — no site or mail claims this domain)");
            continue;
        }
        println!("  {:<6} {:<24} {:<52} TTL", "TYPE", "HOST", "VALUE");
        for record in &records {
            let ttl = record.ttl.map_or_else(|| "default".to_owned(), |ttl| ttl.to_string());
            println!(
                "  {:<6} {:<24} {:<52} {ttl}",
                record.rtype.kind(),
                record.host,
                panel_value(record)
            );
        }
    }
}

/// A record's value as a DNS panel expects it typed: MX preference and SRV
/// numbers lead the target, since panels take them in the value field (or in
/// fields right beside it), and TXT is quoted so trailing spaces survive.
fn panel_value(record: &Record) -> String {
    use selfhost_registrar::RecordType;
    match &record.rtype {
        RecordType::Mx { preference } => format!("{preference} {}", record.value),
        RecordType::Srv { priority, weight, port } => {
            format!("{priority} {weight} {port} {}", record.value)
        }
        RecordType::Txt => format!("\"{}\"", record.value),
        _ => record.value.clone(),
    }
}

/// Every registered domain the config serves: site domains and mail domains,
/// each grouped to its registered parent, deduplicated, sorted.
///
/// A registrar manages zones by *registered* domain, so `www.example.com` and
/// `example.com` are one sync target, not two. Grouping is by the last two
/// labels — right for `.com`/`.net`/`.io` — extended to three under the
/// common two-label public suffixes ([`TWO_LABEL_SUFFIXES`]), so
/// `shop.example.co.uk` syncs the zone `example.co.uk` instead of targeting
/// `co.uk`, a zone no account can own. Names without a dot (`localhost`)
/// have no registrar and are skipped.
fn registered_domains(config: &Config) -> BTreeSet<String> {
    let mut domains = BTreeSet::new();
    let mut claim = |name: &str| {
        if let Some(registered) = registrable(name) {
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

/// The two-label public suffixes a self-host deployment plausibly sits
/// under. Not the full public-suffix list — carrying and updating that is a
/// project of its own — but enough that a domain like `example.co.uk` groups
/// to its real zone instead of to a suffix no registrar account can own,
/// which would otherwise surface only as a confusing per-provider API error.
const TWO_LABEL_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "co.jp", "ne.jp", "or.jp", "com.au", "net.au",
    "org.au", "co.nz", "net.nz", "org.nz", "com.br", "net.br", "co.za", "co.in", "co.kr",
    "com.mx", "com.ar", "com.tr", "com.cn", "com.tw", "com.sg", "com.hk", "com.my", "co.th",
    "co.id", "com.ph", "com.vn", "co.il", "com.pl",
];

/// The registered domain `name` belongs to — its last two labels, lowercased,
/// or its last three when the last two are a known public suffix
/// ([`TWO_LABEL_SUFFIXES`]) — or `None` for a name (like `localhost`, or a
/// bare public suffix) that no registrar account can own.
fn registrable(name: &str) -> Option<String> {
    let trimmed = name.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = trimmed.split('.').filter(|label| !label.is_empty()).collect();
    let last_two = |labels: &[&str]| labels[labels.len() - 2..].join(".");
    match labels.len() {
        0 | 1 => None,
        2 if TWO_LABEL_SUFFIXES.contains(&trimmed.as_str()) => None,
        2 => Some(trimmed),
        len if TWO_LABEL_SUFFIXES.contains(&last_two(&labels).as_str()) => {
            Some(labels[len - 3..].join("."))
        }
        _ => Some(last_two(&labels)),
    }
}

/// The IPv4 address every published record points at.
///
/// Discovered the way the daemon fills its own apex A — from the address a
/// TCP connection appears to come from ([`doctor::discover_public_ip`]) —
/// because that is the address that actually receives visitors. When
/// discovery fails (no internet, an echo service down) the config's own
/// `[dns]` apex A is trusted instead, stated as such; with neither, the sync
/// stops rather than publish records pointing somewhere invented.
async fn server_address(config: &Config) -> Result<Ipv4Addr, String> {
    if let Some(address) = doctor::discover_public_ip().await {
        println!("server address {address} (discovered public IP)");
        return Ok(address);
    }
    if let Some(address) = config_apex_a(config) {
        println!("server address {address} (the config's [dns] apex A; discovery failed)");
        return Ok(address);
    }
    Err("could not discover this machine's public IP, and the config records no apex A \
         under [dns] to fall back on.\n  \
         Check the internet connection, or add the address as an explicit \
         [[dns.zone.record]] A at \"@\"."
        .into())
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

/// The DKIM public TXT value, when signing is configured and the key exists.
///
/// Read-only on purpose: `selfhost run` generates the key; a sync must not
/// mint one as a side effect of a dry-run. A configured-but-absent key is
/// stated and the record omitted — exactly what the engine then publishes,
/// since a `_domainkey` with no live key behind it invites receivers to
/// distrust our mail.
fn dkim_public(config: &Config, project_dir: &Path) -> Option<String> {
    let mail = config.mail.as_ref()?;
    let dkim = mail.dkim.as_ref()?;
    let key_path = project_dir.join(&config.server.data_dir).join(&dkim.private_key);
    match Dkim::load(&key_path) {
        Ok(key) => Some(key.public_txt()),
        Err(error) => {
            println!(
                "note: DKIM key {} is not readable ({error}); the DKIM record is omitted \
                 until `selfhost run` has generated it — re-sync afterwards.",
                key_path.display()
            );
            None
        }
    }
}

/// A credential the provider needs, or an error naming the field.
///
/// Validation already enforces presence, but this path can run against a
/// config edited since load — naming the field beats a panic.
fn required(registrar: &Registrar, field: &str) -> Result<String, String> {
    let value = match field {
        "api_user" => &registrar.api_user,
        "api_key" => &registrar.api_key,
        "api_secret" => &registrar.api_secret,
        _ => &registrar.client_ip,
    };
    value
        .clone()
        .filter(|text| !text.trim().is_empty())
        .ok_or_else(|| format!("registrar.{field} is missing — `selfhost check` explains each field"))
}

/// The real HTTPS transport registrar providers speak through: the ACME
/// crate's verified-roots client, driven by the provider-built [`ApiRequest`].
struct HttpsTransport {
    client: HttpsClient,
}

/// Builds the transport, or says why TLS could not be set up.
fn https_transport() -> Result<HttpsTransport, String> {
    let client = HttpsClient::new()
        .map_err(|error| format!("could not set up the HTTPS client: {error}"))?;
    Ok(HttpsTransport { client })
}

impl Transport for HttpsTransport {
    /// One exchange over the wire. Every failure — bad URL, TCP, TLS, a
    /// response that would not frame — is [`ProviderError::Transport`], per
    /// the trait's contract; an HTTP error status comes back as a successful
    /// [`ApiResponse`] for the provider to interpret.
    async fn send(&self, request: ApiRequest) -> Result<ApiResponse, ProviderError> {
        let url = Url::parse(&request.url).map_err(transport_failure)?;
        let response = self
            .client
            .request(&request.method, &url, &request.headers, &request.body)
            .await
            .map_err(transport_failure)?;
        Ok(ApiResponse { status: response.status.0, body: response.body })
    }
}

/// Maps the HTTPS client's failure into the one error a [`Transport`] may raise.
fn transport_failure(error: AcmeError) -> ProviderError {
    ProviderError::Transport(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_registrar::RecordType;

    /// A config serving sites on two hosts of one domain, plus mail on another.
    fn config() -> Config {
        Config::parse(
            r#"
version = 1

[server]
acme_email = "a@b.com"
acme = "self-signed"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "main"
domains = ["example.com", "www.example.com", "localhost"]
static_root = "./public"

[[sites]]
name = "second"
domains = ["app.other.net"]
static_root = "./app"

[mail]
hostname = "mail.example.com"
domains = ["example.com"]

[registrar]
provider = "manual"
"#,
        )
        .expect("a valid config")
    }

    #[test]
    fn registered_domains_group_hosts_and_skip_the_registrarless() {
        // www.example.com and example.com are one zone at one registrar, and
        // localhost has no registrar at all — a sync that treated them as
        // three targets would fail on two of them.
        let domains = registered_domains(&config());
        assert_eq!(
            domains.into_iter().collect::<Vec<_>>(),
            vec!["example.com".to_owned(), "other.net".to_owned()]
        );
    }

    #[test]
    fn registrable_lowers_case_and_takes_the_last_two_labels() {
        assert_eq!(registrable("WWW.Example.COM").as_deref(), Some("example.com"));
        assert_eq!(registrable("deep.sub.example.com").as_deref(), Some("example.com"));
        assert_eq!(registrable("example.com.").as_deref(), Some("example.com"));
        assert_eq!(registrable("localhost"), None);
        assert_eq!(registrable(""), None);
    }

    #[test]
    fn registrable_keeps_three_labels_under_a_two_label_public_suffix() {
        // "co.uk" is a suffix, not a zone: syncing it would derive nonsense
        // records for an apex the account cannot own and fail with a
        // misleading per-provider error.
        assert_eq!(registrable("shop.example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(registrable("example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(registrable("Example.COM.AU").as_deref(), Some("example.com.au"));
        assert_eq!(registrable("co.uk"), None, "a bare public suffix has no owner");
    }

    #[test]
    fn panel_values_lead_with_the_numbers_a_panel_asks_for() {
        // A panel's MX and SRV forms want the numbers with the value; a bare
        // hostname would have the operator guessing where the preference goes.
        let mx = Record {
            host: "@".into(),
            rtype: RecordType::Mx { preference: 10 },
            value: "mail.example.com".into(),
            ttl: None,
        };
        assert_eq!(panel_value(&mx), "10 mail.example.com");

        let srv = Record {
            host: "_imaps._tcp".into(),
            rtype: RecordType::Srv { priority: 0, weight: 1, port: 993 },
            value: "imap.example.com".into(),
            ttl: None,
        };
        assert_eq!(panel_value(&srv), "0 1 993 imap.example.com");

        let txt = Record {
            host: "@".into(),
            rtype: RecordType::Txt,
            value: "v=spf1 mx -all".into(),
            ttl: None,
        };
        assert_eq!(panel_value(&txt), "\"v=spf1 mx -all\"");
    }

    #[test]
    fn the_fallback_apex_a_is_read_from_the_dns_section() {
        let mut config = config();
        assert_eq!(config_apex_a(&config), None, "no [dns] section, no fallback");

        let with_dns = Config::parse(
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

  [[dns.zone.record]]
  name = "@"
  type = "A"
  value = "172.83.6.109"
"#,
        )
        .expect("valid");
        config.dns = with_dns.dns;
        assert_eq!(config_apex_a(&config), Some(Ipv4Addr::new(172, 83, 6, 109)));
    }
}
