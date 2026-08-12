//! Background certificate issuance and renewal against ACME.
//!
//! This is the daemon-side orchestration of the ACME core (`selfhost_acme`) and
//! the SNI resolver (`selfhost_proxy`). It owns none of the protocol and none of
//! the TLS plumbing: it decides *when* a site needs a certificate, drives one
//! exchange, installs the result, and points the live resolver at it — then
//! sleeps until the next sweep.
//!
//! **Staging is the safe default, on purpose.** Production Let's Encrypt permits
//! only five duplicate certificates per week; a crash-loop or a domain that does
//! not yet resolve here would exhaust that in minutes. Two things keep that from
//! happening: the environment defaults to staging in the config, and a freshly
//! issued certificate is stamped with its issue time and the names it covers
//! (`<host>.issued`) so a real certificate is never re-requested until it is
//! genuinely near expiry — or until the order asks for a name it does not hold.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use selfhost_acme::Acme;
use selfhost_acme::transport::HttpsClient;
use selfhost_config::{AcmeEnvironment, Config};
use selfhost_proxy::{CertificateStore, SniResolver};
use tokio::time::sleep;

/// Let's Encrypt certificate lifetime. Used to turn an issue time into a
/// remaining-days figure without parsing the certificate's own `notAfter`.
pub const CERTIFICATE_LIFETIME_DAYS: u64 = 90;

/// A certificate is renewed once it is older than this — 60 days into a 90-day
/// lifetime, leaving a 30-day margin for retries before anything served expires.
const RENEW_AFTER: Duration = Duration::from_secs(60 * 24 * 60 * 60);

/// Cadence of the renewal sweep when everything is healthy.
const SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Shorter cadence after a failure, so a site is not left without a certificate
/// for a whole day because one exchange did not complete.
const RETRY_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Issues certificates for every eligible site, then renews them on a timer.
///
/// Runs for the life of the daemon. Each sweep issues for any site whose
/// certificate is missing, still the self-signed fallback, or older than the
/// renewal threshold; a site already holding a fresh ACME certificate is left
/// untouched, which is what keeps issuance well inside the CA's rate limits.
///
/// `SelfSigned` never reaches here — the caller does not spawn the task in that
/// mode — but it is handled defensively so a stray call cannot contact a CA.
pub async fn issue_and_renew(
    config: Config,
    project_dir: PathBuf,
    store: CertificateStore,
    resolver: Arc<SniResolver>,
) {
    if matches!(config.server.acme, AcmeEnvironment::SelfSigned) {
        return;
    }

    let data_dir = project_dir.join(&config.server.data_dir);
    let challenge_dir = data_dir.join("acme-challenges");
    let account_dir = data_dir.join("acme");

    loop {
        let interval = run_sweep(&config, &store, &resolver, &account_dir, &challenge_dir).await;
        sleep(interval).await;
    }
}

/// Runs one issuance sweep and reports how long to wait before the next.
///
/// Returns [`RETRY_INTERVAL`] if anything went wrong (so the failure is retried
/// soon) and [`SWEEP_INTERVAL`] otherwise. Connects to the CA only when at least
/// one site needs work, so a fully-provisioned deployment makes no network calls.
async fn run_sweep(
    config: &Config,
    store: &CertificateStore,
    resolver: &Arc<SniResolver>,
    account_dir: &Path,
    challenge_dir: &Path,
) -> Duration {
    let due: Vec<CertOrder> =
        certificate_orders(config).into_iter().filter(|order| needs_certificate(store, order)).collect();
    if due.is_empty() {
        return SWEEP_INTERVAL;
    }

    let environment = describe_environment(config.server.acme);
    log(format!("{} certificate order(s) due — contacting Let's Encrypt {environment}", due.len()));

    let http = match HttpsClient::new() {
        Ok(http) => http,
        Err(error) => {
            log(format!("could not build the HTTPS client: {error} — retrying in an hour"));
            return RETRY_INTERVAL;
        }
    };
    let acme = match Acme::connect(http, config.server.acme, &config.server.acme_email, account_dir).await {
        Ok(acme) => acme,
        Err(error) => {
            log(format!("could not reach the {environment} directory: {error} — retrying in an hour"));
            return RETRY_INTERVAL;
        }
    };

    let mut all_ok = true;
    for order in &due {
        if let Err(error) = issue_order(&acme, store, resolver, challenge_dir, order).await {
            all_ok = false;
            log(format!("{}: certificate not issued — {error}", order.canonical));
        }
    }

    if all_ok { SWEEP_INTERVAL } else { RETRY_INTERVAL }
}

/// One certificate to hold: a canonical host the store's bookkeeping keys on,
/// and every domain the certificate must cover as a SAN.
struct CertOrder {
    canonical: String,
    domains: Vec<String>,
}

/// Every certificate this deployment should hold: one order per site, plus —
/// when `[mail]` is configured — one for the client-autoconfig hosts
/// ([`selfhost_config::Mail::client_hosts`]), so a mail client that guesses
/// `imap.<domain>` meets a certificate that actually names it.
///
/// Only publicly certifiable names go in an order (see [`certifiable`]): a CA
/// rejects IP literals and `localhost` outright, and one such name fails its
/// whole order — a site listing them alongside real domains would never get a
/// certificate at all, and a loopback-only site would fail every sweep forever.
/// A site left with no certifiable name places no order and keeps serving the
/// self-signed fallback, which is all a CA could ever give it anyway.
fn certificate_orders(config: &Config) -> Vec<CertOrder> {
    let mut orders: Vec<CertOrder> = config
        .sites
        .iter()
        .filter_map(|site| {
            let domains: Vec<String> =
                site.domains.iter().filter(|domain| certifiable(domain)).cloned().collect();
            let canonical = domains.first()?.clone();
            Some(CertOrder { canonical, domains })
        })
        .collect();
    if let Some(mail) = &config.mail {
        let domains = mail.client_hosts();
        if let Some(canonical) = domains.first().cloned() {
            orders.push(CertOrder { canonical, domains });
        }
    }
    orders
}

/// Whether a public CA can issue for this name: a real DNS name, not an IP
/// literal and not `localhost`. Mirrors the exclusion `lan_dns::overrides`
/// applies for the same reason — these names are config conveniences for local
/// access, never public identities.
fn certifiable(domain: &str) -> bool {
    domain != "localhost" && domain.parse::<std::net::IpAddr>().is_err()
}

/// Issues one certificate, installs it, and makes it live without a restart.
///
/// On success the certificate is on disk, stamped with its issue time, and the
/// running SNI resolver serves it for the site's hostname immediately.
///
/// One certificate covers every domain in `order.domains` as a SAN — that is
/// the order ACME issued — but the store and the SNI resolver both key by a
/// single hostname, so the same chain and key are installed and registered
/// under *each* of the order's domains, not just the canonical one. Skipping
/// this would leave a client connecting by any non-canonical name (a bare
/// `www.` alongside an apex, or `imap.` alongside `mail.`) served the
/// self-signed fallback instead of the certificate that was just issued to
/// also cover it.
async fn issue_order(
    acme: &Acme,
    store: &CertificateStore,
    resolver: &Arc<SniResolver>,
    challenge_dir: &Path,
    order: &CertOrder,
) -> Result<(), String> {
    let host = &order.canonical;

    let issued = acme.issue(&order.domains, challenge_dir).await.map_err(|e| e.to_string())?;
    for domain in &order.domains {
        store.install(domain, &issued.chain_pem, &issued.key_pem).map_err(|e| e.to_string())?;
        resolver.refresh(store, domain).map_err(|e| format!("installed but resolver not refreshed: {e}"))?;
    }
    stamp_issued(store, host, &order.domains)
        .map_err(|e| format!("installed but could not record issue time: {e}"))?;

    log(format!("{host}: certificate installed and live ({} domain(s))", order.domains.len()));
    Ok(())
}

/// Whether an order should be (re)issued this sweep.
///
/// True when there is no pair at all, when the only pair is the self-signed
/// fallback (no issue-time marker), when the certificate on disk does not cover
/// every name the order now asks for, or when a real certificate has passed the
/// renewal threshold — all judged on the order's canonical host, whose marker
/// dates and names the whole SAN set. A fresh ACME certificate covering the
/// current name set returns false, which is the guard that keeps a restart from
/// re-requesting inside the rate limit.
///
/// The coverage test is what makes a *widened* order take effect. Age alone
/// cannot see it: adding a host to a set that already holds a young certificate
/// (as `ua-auto-config.<domain>` was added to the mail order) would otherwise
/// leave the new name on the self-signed fallback for the certificate's whole
/// 60-day renewal window, and a PACC document served under a certificate no
/// client trusts is a document no client reads.
fn needs_certificate(store: &CertificateStore, order: &CertOrder) -> bool {
    let host = &order.canonical;
    if !store.has_pair(host) {
        return true;
    }
    if !covers(&covered_domains(store, host), &order.domains) {
        return true;
    }
    match certificate_age(store, host) {
        Some(age) => age >= RENEW_AFTER,
        None => true,
    }
}

/// Whether a marker's recorded name set accounts for every name in `wanted`.
///
/// A marker written before the set was recorded (`None`) proves nothing about
/// coverage, so it does not count as covering anything: that order is reissued
/// once, and the marker it writes carries its names from then on.
fn covers(recorded: &Option<Vec<String>>, wanted: &[String]) -> bool {
    let Some(recorded) = recorded else { return false };
    wanted.iter().all(|name| recorded.iter().any(|had| had.eq_ignore_ascii_case(name)))
}

/// Records the current time and the covered names as a host certificate's
/// issue marker: the issue time on the first line, one SAN per line after it.
///
/// The marker distinguishes a real ACME certificate from the self-signed
/// fallback, dates it for renewal, and says which names it speaks for — all
/// without parsing the certificate itself.
fn stamp_issued(store: &CertificateStore, host: &str, domains: &[String]) -> std::io::Result<()> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let mut marker = now.to_string();
    for domain in domains {
        marker.push('\n');
        marker.push_str(domain);
    }
    std::fs::write(issued_marker_path(store, host), marker)
}

/// Age of a host's certificate from its issue-time marker.
///
/// `None` means there is no real ACME certificate on disk — either nothing at
/// all, or only the self-signed fallback, which is stamped with no marker.
pub fn certificate_age(store: &CertificateStore, host: &str) -> Option<Duration> {
    let raw = std::fs::read_to_string(issued_marker_path(store, host)).ok()?;
    let issued_secs: u64 = raw.lines().next()?.trim().parse().ok()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(Duration::from_secs(now.saturating_sub(issued_secs)))
}

/// The names a host's stored certificate was issued for, as recorded by
/// [`stamp_issued`].
///
/// `None` for a certificate with no marker and for a marker that records only
/// an issue time — the format before the names were written down — because
/// neither can answer the question.
fn covered_domains(store: &CertificateStore, host: &str) -> Option<Vec<String>> {
    let raw = std::fs::read_to_string(issued_marker_path(store, host)).ok()?;
    let names: Vec<String> =
        raw.lines().skip(1).map(str::trim).filter(|line| !line.is_empty()).map(str::to_owned).collect();
    (!names.is_empty()).then_some(names)
}

/// Days until a host's certificate expires, or `None` if it is not a real
/// ACME certificate (see [`certificate_age`]).
pub fn certificate_days_remaining(store: &CertificateStore, host: &str) -> Option<i64> {
    let age_days = certificate_age(store, host)?.as_secs() / (24 * 60 * 60);
    Some(CERTIFICATE_LIFETIME_DAYS as i64 - age_days as i64)
}

/// The issue-time marker path that sits beside a host's certificate, e.g.
/// `<data_dir>/tls/example.com.issued` next to `example.com.crt.pem`.
///
/// Derived from the store's own certificate path so it inherits the exact same
/// hostname sanitisation, rather than duplicating that rule here.
fn issued_marker_path(store: &CertificateStore, host: &str) -> PathBuf {
    let certificate = store.certificate_path(host);
    let stem = certificate
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(".crt.pem"))
        .map(str::to_owned)
        .unwrap_or_else(|| host.to_owned());
    certificate.with_file_name(format!("{stem}.issued"))
}

/// Human name for an ACME environment, for log lines.
fn describe_environment(environment: AcmeEnvironment) -> &'static str {
    match environment {
        AcmeEnvironment::Production => "production",
        AcmeEnvironment::Staging => "staging",
        AcmeEnvironment::SelfSigned => "self-signed",
    }
}

/// Writes one clearly-tagged line to stderr.
///
/// The task runs in the background with no console of its own; a consistent
/// `acme:` prefix lets its output be told apart in the daemon's log stream.
fn log(message: impl AsRef<str>) {
    eprintln!("{} acme: {}", selfhost_mail::stamp(), message.as_ref());
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_config::{AcmeEnvironment, Firewall, Health, Mail, MailBind, Node, Role, Server, Site};

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

    fn config_with(sites: Vec<Site>, mail: Option<Mail>) -> Config {
        Config {
            version: 1,
            server: Server {
                http_bind: "0.0.0.0:80".into(),
                https_bind: "0.0.0.0:443".into(),
                acme_email: "a@b.com".into(),
                acme: AcmeEnvironment::Production,
                data_dir: PathBuf::from("./data"),
                admin_bind: "127.0.0.1:9191".into(),
                firewall: Firewall::default(),
            },
            nodes: vec![Node { name: "home".into(), role: Role::Owner, mesh_ip: None }],
            sites,
            dns: None,
            mail,
            namecheap_ddns: vec![],
            registrar: None,
            self_update: None,
            shares: vec![],
            desktop: None,
            mesh: None,
        }
    }

    fn mail(domain: &str) -> Mail {
        Mail {
            hostname: domain.into(),
            domains: vec![domain.into()],
            mailboxes: vec![],
            dkim: None,
            relay: None,
            bind: MailBind::default(),
            max_message_bytes: 1,
            require_tls_for_auth: true,
        }
    }

    #[test]
    fn a_loopback_only_site_places_no_order() {
        // ACME rejects IP identifiers and `localhost`; ordering for them fails
        // every sweep forever and pointlessly contacts the CA each hour.
        let config = config_with(vec![site(&["localhost", "127.0.0.1", "192.168.1.8"])], None);
        assert!(certificate_orders(&config).is_empty());
    }

    #[test]
    fn only_certifiable_names_survive_into_a_mixed_sites_order() {
        // One bad identifier fails the whole ACME order, so the real domains
        // must be ordered without their loopback companions.
        let config = config_with(vec![site(&["127.0.0.1", "example.com", "www.example.com"])], None);
        let orders = certificate_orders(&config);

        assert_eq!(orders.len(), 1);
        assert_eq!(orders[0].canonical, "example.com");
        assert_eq!(orders[0].domains, vec!["example.com", "www.example.com"]);
    }

    /// A store in a fresh temporary directory, with a certificate pair already
    /// on disk for `host` — enough for the marker rules under test, which never
    /// read the certificate's own bytes.
    fn store_holding(label: &str, host: &str) -> CertificateStore {
        let dir = std::env::temp_dir().join(format!("selfhost-acme-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = CertificateStore::open(&dir).expect("a certificate store");
        std::fs::write(store.certificate_path(host), "chain").expect("a chain on disk");
        std::fs::write(store.key_path(host), "key").expect("a key on disk");
        store
    }

    fn order(domains: &[&str]) -> CertOrder {
        let domains: Vec<String> = domains.iter().map(|d| (*d).to_owned()).collect();
        CertOrder { canonical: domains[0].clone(), domains }
    }

    #[test]
    fn a_fresh_certificate_covering_every_name_is_left_alone() {
        // The rate-limit guard: a sweep that re-requests what it already holds
        // burns the CA's five-per-week allowance on nothing.
        let wanted = order(&["mail.example.com", "ua-auto-config.example.com"]);
        let store = store_holding("fresh", &wanted.canonical);
        stamp_issued(&store, &wanted.canonical, &wanted.domains).expect("a marker");

        assert!(!needs_certificate(&store, &wanted));
    }

    #[test]
    fn a_name_added_to_an_order_reissues_a_certificate_that_does_not_name_it() {
        // How `ua-auto-config.<domain>` reaches a real certificate: the mail
        // order widened while its certificate was young, and age alone would
        // have left the new host on the self-signed fallback for 60 days.
        let held = order(&["mail.example.com", "imap.example.com"]);
        let store = store_holding("widened", &held.canonical);
        stamp_issued(&store, &held.canonical, &held.domains).expect("a marker");

        let widened = order(&["mail.example.com", "imap.example.com", "ua-auto-config.example.com"]);
        assert!(needs_certificate(&store, &widened));
    }

    #[test]
    fn a_marker_that_records_no_names_cannot_prove_coverage_and_reissues_once() {
        // The pre-existing marker format was a bare issue time. It says nothing
        // about SANs, so the order is reissued once and stamped with its names.
        let wanted = order(&["mail.example.com", "ua-auto-config.example.com"]);
        let store = store_holding("legacy", &wanted.canonical);
        std::fs::write(issued_marker_path(&store, &wanted.canonical), "1754000000")
            .expect("a legacy marker");

        assert!(certificate_age(&store, &wanted.canonical).is_some(), "the issue time still parses");
        assert!(needs_certificate(&store, &wanted));

        stamp_issued(&store, &wanted.canonical, &wanted.domains).expect("a marker");
        assert!(!needs_certificate(&store, &wanted), "the rewritten marker settles it");
    }

    #[test]
    fn mail_client_hosts_get_one_order_keyed_by_the_first_host() {
        let config = config_with(vec![], Some(mail("example.com")));
        let orders = certificate_orders(&config);

        assert_eq!(orders.len(), 1);
        assert_eq!(orders[0].canonical, "mail.example.com");
        assert_eq!(
            orders[0].domains,
            vec![
                "mail.example.com",
                "imap.example.com",
                "smtp.example.com",
                "ua-auto-config.example.com",
            ]
        );
    }
}
