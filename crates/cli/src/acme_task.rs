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
//! issued certificate is stamped with its issue time (`<host>.issued`) so a real
//! certificate is never re-requested until it is genuinely near expiry.

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
    stamp_issued(store, host).map_err(|e| format!("installed but could not record issue time: {e}"))?;

    log(format!("{host}: certificate installed and live ({} domain(s))", order.domains.len()));
    Ok(())
}

/// Whether an order should be (re)issued this sweep.
///
/// True when there is no pair at all, when the only pair is the self-signed
/// fallback (no issue-time marker), or when a real certificate has passed the
/// renewal threshold — all judged on the order's canonical host, whose stamp
/// dates the whole SAN set. A fresh ACME certificate returns false, which is
/// the guard that keeps a restart from re-requesting inside the rate limit.
fn needs_certificate(store: &CertificateStore, order: &CertOrder) -> bool {
    let host = &order.canonical;
    if !store.has_pair(host) {
        return true;
    }
    match certificate_age(store, host) {
        Some(age) => age >= RENEW_AFTER,
        None => true,
    }
}

/// Records the current time as a host certificate's issue time.
///
/// The marker distinguishes a real ACME certificate from the self-signed
/// fallback and dates it for renewal, without parsing the certificate itself.
fn stamp_issued(store: &CertificateStore, host: &str) -> std::io::Result<()> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    std::fs::write(issued_marker_path(store, host), now.to_string())
}

/// Age of a host's certificate from its issue-time marker.
///
/// `None` means there is no real ACME certificate on disk — either nothing at
/// all, or only the self-signed fallback, which is stamped with no marker.
pub fn certificate_age(store: &CertificateStore, host: &str) -> Option<Duration> {
    let raw = std::fs::read_to_string(issued_marker_path(store, host)).ok()?;
    let issued_secs: u64 = raw.trim().parse().ok()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(Duration::from_secs(now.saturating_sub(issued_secs)))
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

    #[test]
    fn mail_client_hosts_get_one_order_keyed_by_the_first_host() {
        let config = config_with(vec![], Some(mail("example.com")));
        let orders = certificate_orders(&config);

        assert_eq!(orders.len(), 1);
        assert_eq!(orders[0].canonical, "mail.example.com");
        assert_eq!(
            orders[0].domains,
            vec!["mail.example.com", "imap.example.com", "smtp.example.com"]
        );
    }
}
