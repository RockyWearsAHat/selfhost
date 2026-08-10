//! `selfhost doctor` — diagnose a deployment without reading its source.
//!
//! Written for somebody who did not build this. Every check reports three
//! things, and the third is the one that matters:
//!
//! 1. **what was tested**, named concretely enough to repeat by hand,
//! 2. **what came back**, as a measurement rather than a verdict,
//! 3. **what to do about it**, when the answer is not "nothing".
//!
//! A check that cannot run says so instead of passing. "Could not test" and
//! "tested and fine" are different states, and collapsing them is how a
//! diagnostic tells somebody their mail works when it has never been tried.

use crate::{acme_task, assess, investigate};
use selfhost_admin::token::{Privacy, Token, privacy_of};
use selfhost_config::validate::console_gate_refusal;
use selfhost_config::{AcmeEnvironment, Cidr, Config};
use selfhost_proxy::CertificateStore;
use selfhost_dns::{RecordType, Resolver, ResolverSource, blocklist_name, is_real_listing};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// How a check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Working as intended.
    Pass,
    /// Working, but something should be known about it.
    Warn,
    /// Broken, and the deployment will not do its job until it is fixed.
    Fail,
    /// Could not be tested from here. Not the same as passing.
    Unknown,
    /// Deliberately not configured.
    Skipped,
}

impl Verdict {
    fn marker(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
            Self::Unknown => "????",
            Self::Skipped => "SKIP",
        }
    }

    fn colour(self) -> &'static str {
        match self {
            Self::Pass => "\x1b[32m",
            Self::Warn => "\x1b[33m",
            Self::Fail => "\x1b[31m",
            Self::Unknown => "\x1b[36m",
            Self::Skipped => "\x1b[2m",
        }
    }
}

/// One diagnostic result.
#[derive(Debug, Clone)]
pub struct Check {
    /// What was tested.
    pub name: String,
    /// How it came out.
    pub verdict: Verdict,
    /// What was actually observed.
    pub detail: String,
    /// What to do about it, when there is something to do.
    pub fix: Option<String>,
}

impl Check {
    fn new(name: impl Into<String>, verdict: Verdict, detail: impl Into<String>) -> Self {
        Self { name: name.into(), verdict, detail: detail.into(), fix: None }
    }

    fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

/// A named group of checks.
#[derive(Debug, Default)]
pub struct Section {
    /// Section heading.
    pub title: String,
    /// Checks in this section.
    pub checks: Vec<Check>,
}

/// The full report.
#[derive(Debug, Default)]
pub struct Report {
    /// Sections in the order they were run.
    pub sections: Vec<Section>,
}

impl Report {
    fn section(&mut self, title: &str) -> &mut Section {
        self.sections.push(Section { title: title.to_owned(), checks: Vec::new() });
        self.sections.last_mut().expect("just pushed")
    }

    /// Number of checks with a given verdict.
    pub fn count(&self, verdict: Verdict) -> usize {
        self.sections
            .iter()
            .flat_map(|s| &s.checks)
            .filter(|c| c.verdict == verdict)
            .count()
    }

    /// Whether anything failed.
    pub fn has_failures(&self) -> bool {
        self.count(Verdict::Fail) > 0
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let colour = std::env::var_os("NO_COLOR").is_none();
        let paint = |v: Verdict| {
            if colour {
                format!("{}{}\x1b[0m", v.colour(), v.marker())
            } else {
                v.marker().to_owned()
            }
        };

        for section in &self.sections {
            writeln!(f, "\n{}", section.title)?;
            writeln!(f, "{}", "─".repeat(section.title.chars().count()))?;
            for check in &section.checks {
                writeln!(f, "  [{}] {}", paint(check.verdict), check.name)?;
                writeln!(f, "         {}", check.detail)?;
                if let Some(fix) = &check.fix {
                    for (index, line) in fix.lines().enumerate() {
                        let prefix = if index == 0 { "      →  " } else { "         " };
                        writeln!(f, "{prefix}{line}")?;
                    }
                }
            }
        }

        writeln!(
            f,
            "\n{} passed · {} warnings · {} failed · {} untestable",
            self.count(Verdict::Pass),
            self.count(Verdict::Warn),
            self.count(Verdict::Fail),
            self.count(Verdict::Unknown),
        )
    }
}

/// Blocklists worth consulting, and how much a listing on each actually costs.
const BLOCKLISTS: [(&str, &str); 4] = [
    ("zen.spamhaus.org", "widely used by corporate and small-provider filters"),
    ("bl.spamcop.net", "used by some providers"),
    ("b.barracudacentral.org", "used by Barracuda appliances"),
    ("dnsbl-1.uceprotect.net", "aggressive; listings are common and less meaningful"),
];

/// Runs every check and returns the report.
pub async fn run(config: &Config, project_dir: &Path, deep: bool, scan_lan: bool) -> Report {
    let mut report = Report::default();
    let resolver = Resolver::system();

    check_config(&mut report, config, project_dir);
    check_secrets(&mut report, config, project_dir);
    check_binds(&mut report, config).await;
    check_certificates(&mut report, config, project_dir);
    let public_ip = check_network(&mut report, &resolver).await;
    check_dns(&mut report, config, &resolver, public_ip).await;
    check_authority(&mut report, config, &resolver, public_ip).await;
    check_mail(&mut report, config, &resolver, public_ip, deep).await;
    if deep || scan_lan {
        investigate_causes(&mut report, &resolver, public_ip, deep, scan_lan).await;
    }

    report
}

/// Config coherence and whether the paths it names exist.
fn check_config(report: &mut Report, config: &Config, project_dir: &Path) {
    let section = report.section("Configuration");

    section.checks.push(Check::new(
        "config loads and validates",
        Verdict::Pass,
        format!("{config}"),
    ));

    for site in &config.sites {
        if let Some(root) = &site.static_root {
            let resolved = project_dir.join(root);
            if resolved.is_dir() {
                section.checks.push(Check::new(
                    format!("static root for \"{}\"", site.name),
                    Verdict::Pass,
                    resolved.display().to_string(),
                ));
            } else {
                section.checks.push(
                    Check::new(
                        format!("static root for \"{}\"", site.name),
                        Verdict::Fail,
                        format!("{} does not exist", resolved.display()),
                    )
                    .with_fix("Create the directory, or correct static_root in selfhost.config.toml."),
                );
            }
        }
    }

    let data_dir = project_dir.join(&config.server.data_dir);
    // `create_if_absent` rather than `prepare`: doctor reports what to do and
    // never does it, so a directory that already exists is observed here and
    // judged by `check_secrets` below — repairing it would erase the finding.
    // One that does not exist yet is still created, as it always has been, and
    // is created owner-only so the act of diagnosing cannot itself expose it.
    match crate::data_dir::create_if_absent(&data_dir) {
        Ok(()) => section.checks.push(Check::new(
            "data directory is writable",
            Verdict::Pass,
            data_dir.display().to_string(),
        )),
        Err(error) => section.checks.push(
            Check::new("data directory is writable", Verdict::Fail, format!("{error}"))
                .with_fix("Certificates, mail, and databases all live here. Fix the permissions."),
        ),
    }
}

/// The three things that stand between this deployment and whoever else can
/// reach the machine: the data directory, the bearer token in it, and the
/// console's source-address gate.
///
/// These are grouped because they fail together in one specific way. The gate
/// decides who may *ask*; the token is what makes an answer authoritative
/// without any further question; and the directory is what keeps the token from
/// being readable by an account that was never admitted through the gate at all.
/// A deployment can have a perfect gate and still be wide open because the file
/// underneath it inherited a permissive ACL.
fn check_secrets(report: &mut Report, config: &Config, project_dir: &Path) {
    let data_dir = project_dir.join(&config.server.data_dir);
    let token_path = Token::path_in(&data_dir);
    let section = report.section("Secrets and access");

    section.checks.push(permission_check(
        "data directory permissions",
        &data_dir,
        privacy_of(&data_dir),
        "Certificates, private keys, the console password hash and the bearer token all live \
         here. Anything that can read this directory is the deployment.",
        &format!(
            "chmod 700 {dir}\n\
             Windows, from an elevated prompt:\n\
             icacls \"{dir}\" /inheritance:r /grant *S-1-5-18:(OI)(CI)F \
             /grant *S-1-5-32-544:(OI)(CI)F",
            dir = data_dir.display()
        ),
    ));

    section.checks.push(permission_check(
        "admin token permissions",
        &token_path,
        privacy_of(&token_path),
        "This file is the deployment's root credential: a valid bearer token skips the CSRF \
         header, the Origin check, the session cookie's expiry, the login rate limiter and \
         the passkey, all at once.",
        &format!(
            "chmod 600 {file}\n\
             Windows, from an elevated prompt:\n\
             icacls \"{file}\" /inheritance:r /grant *S-1-5-18:F /grant *S-1-5-32-544:F\n\
             Assume a token that was ever readable by anyone else is captured: delete the \
             file, restart the daemon to mint a new one, and re-pair every client.",
            file = token_path.display()
        ),
    ));

    section.checks.push(console_gate_check(config));
}

/// Turns one permission observation into a report line.
///
/// Pure given the observation, so the rule that decides Pass from Unknown is
/// tested without a filesystem. The rule is the one this whole file is written
/// around: an answer that could not be obtained is [`Verdict::Unknown`], never
/// [`Verdict::Pass`]. A "permissions fine" line printed by a check that never
/// managed to look is worse than no line, because it is the line an operator
/// stops worrying about.
fn permission_check(
    name: &str,
    path: &Path,
    outcome: std::io::Result<Privacy>,
    stakes: &str,
    fix: &str,
) -> Check {
    let where_it_is = path.display();
    match outcome {
        Ok(Privacy::Private(detail)) => {
            Check::new(name, Verdict::Pass, format!("{where_it_is} — {detail}"))
        }
        Ok(Privacy::Exposed(detail)) => Check::new(
            name,
            Verdict::Fail,
            format!("{where_it_is} — {detail}. {stakes}"),
        )
        .with_fix(fix),
        Ok(Privacy::Unanswerable(why)) => Check::new(
            name,
            Verdict::Unknown,
            format!("{where_it_is} — could not be judged: {why}. {stakes}"),
        )
        .with_fix(fix),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Check::new(
            name,
            Verdict::Unknown,
            format!(
                "{where_it_is} does not exist yet, so its permissions cannot be checked — \
                 the daemon creates it on first start"
            ),
        ),
        Err(error) => Check::new(
            name,
            Verdict::Unknown,
            format!("{where_it_is} — could not be read: {error}. {stakes}"),
        )
        .with_fix(fix),
    }
}

/// What the console site's source-address gate actually admits.
///
/// The verdict comes from [`console_gate_refusal`] — the loader's own rule,
/// called rather than re-derived, so this report can never disagree with what
/// `selfhost check` would accept.
///
/// The detail says the part an operator is most likely to get wrong, and it is
/// not about breadth. A loopback gate is the *correct* configuration here, and
/// it still admits every process already executing on this box — including the
/// co-hosted web applications the same proxy serves. "Behind the gate" therefore
/// means "not from the internet", not "authenticated", which is why every route
/// behind it demands a credential of its own.
fn console_gate_check(config: &Config) -> Check {
    let Some(site) = config.sites.iter().find(|site| site.console) else {
        return Check::new(
            "console source gate",
            Verdict::Skipped,
            "no site sets console = true, so nothing relays to the admin API",
        );
    };

    let name = format!("console source gate for \"{}\"", site.name);
    if site.allowed_cidrs.is_empty() {
        return Check::new(
            name,
            Verdict::Fail,
            "allowed_cidrs is empty, and an empty list is open to everyone".to_owned(),
        )
        .with_fix(
            "Set allowed_cidrs to the addresses the console is actually reached from — \
             [\"127.0.0.1/32\", \"::1/128\"] when it is reached over the VPN tunnel.",
        );
    }

    let refusals: Vec<String> =
        site.allowed_cidrs.iter().filter_map(|entry| console_gate_refusal(entry)).collect();
    if !refusals.is_empty() {
        return Check::new(name, Verdict::Fail, refusals.join(" ")).with_fix(
            "Narrow allowed_cidrs to the addresses the console is reached from. The console \
             controls this deployment; it is never reachable from a routable address.",
        );
    }

    let listed = site.allowed_cidrs.join(", ");
    Check::new(
        name,
        Verdict::Pass,
        format!(
            "admits {listed} only; every other source gets the same 404 an unknown hostname \
             gets. {}",
            gate_reach(&site.allowed_cidrs).what_it_is_not()
        ),
    )
}

/// How far a console gate's admitted sources actually reach.
///
/// The distinction the operator has to be handed, because the two shapes read
/// identically in the config file and defend against completely different
/// things. A loopback gate stops the internet and the LAN and stops nothing on
/// this box. A gate naming a LAN range stops the internet and admits every
/// device on that network — a printer, a television, a guest's laptop.
#[derive(Debug, PartialEq, Eq)]
enum GateReach {
    /// Every entry is loopback: the deployed shape, where the console is
    /// reached through the Secure-VPN tunnel that exits on `127.0.0.1`.
    LoopbackOnly,
    /// Loopback, and at least one range beyond this machine, named as written.
    LoopbackAndBeyond(Vec<String>),
    /// No loopback entry at all, so the tunnel is not how this console is
    /// reached.
    ElsewhereOnly,
}

impl GateReach {
    /// The sentence naming what this gate is *not* a perimeter against.
    ///
    /// Every arm ends in the same place — the gate is not authentication —
    /// because that is the sentence a reader has to leave with whatever their
    /// configuration looks like. It is spelled out here rather than left to
    /// `docs/VPN.md`, since the operator reading a doctor line is exactly the
    /// operator who has not read the document.
    fn what_it_is_not(&self) -> String {
        match self {
            Self::LoopbackOnly => "The gate is loopback-only, which is the deployed shape: the \
                 Secure-VPN tunnel exits on 127.0.0.1. So does every process already running on \
                 this machine — every local account, and every co-hosted web app this same \
                 proxy serves. A loopback gate is a perimeter against the internet and the LAN; \
                 it is not a perimeter against this box, and nothing behind it may treat it as \
                 authentication"
                .to_owned(),
            Self::LoopbackAndBeyond(beyond) => format!(
                "The gate admits loopback — where the Secure-VPN tunnel exits, and where every \
                 process already running on this machine sits, co-hosted web apps included — \
                 and beyond that every host on {}. It is a perimeter against the internet, not \
                 against this box or those networks, so nothing behind it may treat it as \
                 authentication",
                beyond.join(", ")
            ),
            Self::ElsewhereOnly => "The gate admits no loopback address, so the Secure-VPN \
                 tunnel — which exits on 127.0.0.1 — does not reach this console; it is \
                 reachable only from the listed networks. A gate is a perimeter against the \
                 internet, not authentication: every host on those networks is admitted, so \
                 each route behind it still demands a credential of its own"
                .to_owned(),
        }
    }
}

/// Classifies a console gate's entries by how far they reach.
///
/// # Why a per-entry loopback test is enough to say "loopback-only"
///
/// Containing `127.0.0.1` does not by itself mean an entry contains *nothing
/// else*: `0.0.0.0/0` contains loopback too. What makes the shortcut sound is
/// the precondition — this runs only after [`console_gate_refusal`] has cleared
/// every entry, and that rule admits an IPv4 entry only when its address falls
/// in one of the named private ranges *and* its prefix is `/24` or narrower. An
/// entry that reaches loopback and survives both rules is inside `127.0.0.0/8`
/// and cannot extend past it. The one v6 loopback range, `::1/128`, is a single
/// address by construction.
///
/// Membership is decided with [`Cidr::contains`] — the same matcher the proxy
/// uses at request time — rather than by comparing text, because `127.0.0.0/8`
/// and `127.0.0.1/32` both admit loopback and neither is spelled like the
/// other. An entry that does not parse is counted as reaching beyond this
/// machine and named: it admits nothing at request time, but reporting it as
/// loopback would be the one direction of error that reassures.
fn gate_reach(entries: &[String]) -> GateReach {
    let (loopback, beyond): (Vec<&String>, Vec<&String>) =
        entries.iter().partition(|entry| admits_loopback(entry));
    match (loopback.is_empty(), beyond.is_empty()) {
        (false, true) => GateReach::LoopbackOnly,
        (false, false) => {
            GateReach::LoopbackAndBeyond(beyond.into_iter().cloned().collect())
        }
        (true, _) => GateReach::ElsewhereOnly,
    }
}

/// Whether one gate entry admits either loopback address.
fn admits_loopback(entry: &str) -> bool {
    Cidr::parse(entry).is_ok_and(|cidr| {
        cidr.contains(IpAddr::V4(Ipv4Addr::LOCALHOST))
            || cidr.contains(IpAddr::V6(Ipv6Addr::LOCALHOST))
    })
}

/// Whether the configured ports can actually be bound.
async fn check_binds(report: &mut Report, config: &Config) {
    let section = report.section("Listeners");

    for (label, address) in
        [("http", &config.server.http_bind), ("https", &config.server.https_bind)]
    {
        match TcpListener::bind(address).await {
            Ok(listener) => {
                drop(listener);
                section.checks.push(Check::new(
                    format!("{label} bind {address}"),
                    Verdict::Pass,
                    "available",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                // Almost always selfhost itself already running, which is fine.
                section.checks.push(
                    Check::new(
                        format!("{label} bind {address}"),
                        Verdict::Warn,
                        "already in use",
                    )
                    .with_fix(
                        "Either selfhost is already running (expected), or another program holds \
                         the port. Check with: lsof -i :PORT   (Windows: netstat -ano | findstr :PORT)",
                    ),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                section.checks.push(
                    Check::new(format!("{label} bind {address}"), Verdict::Fail, "permission denied")
                        .with_fix(
                            "Ports below 1024 need privilege on Unix. Either run as root, grant the \
                             capability once with:\n\
                             sudo setcap 'cap_net_bind_service=+ep' ./target/release/selfhost\n\
                             or bind a high port and forward to it in the router.",
                        ),
                );
            }
            Err(error) => section.checks.push(Check::new(
                format!("{label} bind {address}"),
                Verdict::Fail,
                format!("{error}"),
            )),
        }
    }
}

/// Certificate presence and what kind they are.
fn check_certificates(report: &mut Report, config: &Config, project_dir: &Path) {
    let section = report.section("Certificates");
    let data_dir = project_dir.join(&config.server.data_dir);
    let tls_dir = data_dir.join("tls");

    match config.server.acme {
        AcmeEnvironment::SelfSigned => section.checks.push(
            Check::new(
                "certificate source",
                Verdict::Warn,
                "self-signed — browsers will warn, which is expected",
            )
            .with_fix(
                "Fine for local work. For a public site set acme = \"staging\" once DNS points \
                 here, then \"production\" once staging works.",
            ),
        ),
        AcmeEnvironment::Staging => section.checks.push(Check::new(
            "certificate source",
            Verdict::Warn,
            "Let's Encrypt staging — certificates are not browser-trusted (safe default)",
        )),
        AcmeEnvironment::Production => section.checks.push(Check::new(
            "certificate source",
            Verdict::Pass,
            "Let's Encrypt production",
        )),
    }

    // The ACME account key is created on the first successful exchange. Its
    // presence is the difference between "registered with the CA" and "not yet".
    if !matches!(config.server.acme, AcmeEnvironment::SelfSigned) {
        let account_key = data_dir.join("acme").join("account.key");
        if account_key.is_file() {
            section.checks.push(Check::new(
                "ACME account",
                Verdict::Pass,
                "registered — an account key is present",
            ));
        } else {
            section.checks.push(Check::new(
                "ACME account",
                Verdict::Unknown,
                "no account key yet — one is created on the first issuance",
            ));
        }
    }

    report_stored_certificates(section, &data_dir, &tls_dir, config.server.acme);
}

/// Reports each stored certificate: whether it is a real ACME certificate or the
/// self-signed fallback, and — for real ones — how many days until it expires.
///
/// A certificate under 30 days from expiry is a `Warn`: the renewal loop renews
/// at 30 days remaining, so anything below that has either just been noticed or
/// is failing to renew and deserves attention.
fn report_stored_certificates(
    section: &mut Section,
    data_dir: &Path,
    tls_dir: &Path,
    environment: AcmeEnvironment,
) {
    let store = match CertificateStore::open(data_dir) {
        Ok(store) => store,
        Err(error) => {
            section.checks.push(Check::new(
                "stored certificates",
                Verdict::Unknown,
                format!("could not open {}: {error}", tls_dir.display()),
            ));
            return;
        }
    };

    let hosts = store.hosts();
    if hosts.is_empty() {
        section.checks.push(Check::new(
            "stored certificates",
            Verdict::Unknown,
            format!("none in {} yet — they are created on first run", tls_dir.display()),
        ));
        return;
    }

    let kind = match environment {
        AcmeEnvironment::Production => "Let's Encrypt production",
        AcmeEnvironment::Staging => "Let's Encrypt staging",
        AcmeEnvironment::SelfSigned => "self-signed",
    };

    for host in hosts {
        match acme_task::certificate_days_remaining(&store, &host) {
            Some(days) if days < 30 => section.checks.push(
                Check::new(
                    format!("certificate {host}"),
                    Verdict::Warn,
                    format!("{kind}, {days} day(s) until expiry"),
                )
                .with_fix(
                    "The renewal loop renews at 30 days remaining. If this keeps dropping, the \
                     HTTP-01 challenge on port 80 is probably not reachable — run doctor --deep.",
                ),
            ),
            Some(days) => section.checks.push(Check::new(
                format!("certificate {host}"),
                Verdict::Pass,
                format!("{kind}, {days} day(s) until expiry"),
            )),
            None => section.checks.push(Check::new(
                format!("certificate {host}"),
                Verdict::Warn,
                "self-signed fallback — no ACME certificate issued for this host yet",
            )),
        }
    }
}

/// Public address discovery, and what can and cannot be concluded from here.
async fn check_network(report: &mut Report, resolver: &Resolver) -> Option<Ipv4Addr> {
    let section = report.section("Network");

    match resolver.source() {
        ResolverSource::PublicFallback => section.checks.push(
            Check::new(
                "DNS resolver",
                Verdict::Warn,
                format!("{} (system resolver could not be determined)", resolver.address()),
            )
            .with_fix(
                "Blocklist answers through a public resolver are unreliable — Spamhaus refuses \
                 those queries and the refusal looks like a listing. Pass --resolver <ip> to use \
                 your ISP's or router's resolver.",
            ),
        ),
        _ => section.checks.push(Check::new(
            "DNS resolver",
            Verdict::Pass,
            resolver.address().to_string(),
        )),
    }

    // Discovered over DNS rather than an HTTP service, so this needs no HTTP
    // client and no third-party endpoint that could disappear.
    let public_ip = discover_public_ip().await;
    match public_ip {
        Some(address) => section.checks.push(Check::new(
            "public IP address",
            Verdict::Pass,
            format!("{address} (as seen by an outbound TCP connection)"),
        )),
        None => section.checks.push(
            Check::new("public IP address", Verdict::Unknown, "could not be determined")
                .with_fix(
                    "Every blocklist and reverse-DNS check below depends on this, so they are \
                     skipped. Check connectivity and re-run.",
                ),
        ),
    }

    section.checks.push(
        Check::new(
            "inbound 80/443 from the internet",
            Verdict::Unknown,
            "not testable from this machine",
        )
        .with_fix(
            "This is the single most common reason a home server appears not to work, and it \
             cannot be tested from inside your own network — traffic never leaves the building.\n\
             Start selfhost, then from a phone on mobile data (Wi-Fi OFF) open:\n\
             http://<your-public-ip>/\n\
             If that times out: the router is not forwarding 80/443, or the ISP filters them.",
        ),
    );

    public_ip
}

/// Site hostnames, and whether they point where this machine actually is.
async fn check_dns(
    report: &mut Report,
    config: &Config,
    resolver: &Resolver,
    public_ip: Option<Ipv4Addr>,
) {
    let section = report.section("DNS");

    for site in &config.sites {
        for domain in &site.domains {
            if domain == "localhost" || domain.parse::<IpAddr>().is_ok() {
                section.checks.push(Check::new(
                    domain.to_string(),
                    Verdict::Skipped,
                    "local name, nothing to resolve",
                ));
                continue;
            }

            match resolver.lookup_a(domain).await {
                Ok(addresses) if addresses.is_empty() => section.checks.push(
                    Check::new(format!("{domain} → A record"), Verdict::Fail, "no A record")
                        .with_fix(format!(
                            "Add an A record for {domain} pointing at {}.",
                            public_ip
                                .map(|a| a.to_string())
                                .unwrap_or_else(|| "your public IP".into())
                        )),
                ),
                Ok(addresses) => {
                    let listed = addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ");
                    match public_ip {
                        Some(ours) if addresses.contains(&ours) => section.checks.push(Check::new(
                            format!("{domain} → A record"),
                            Verdict::Pass,
                            format!("{listed} (matches this network)"),
                        )),
                        Some(ours) => section.checks.push(
                            Check::new(
                                format!("{domain} → A record"),
                                Verdict::Warn,
                                format!("{listed}, but this network is {ours}"),
                            )
                            .with_fix(
                                "Expected while the site is still hosted elsewhere. Update the A \
                                 record when you cut over — and remember DNS caches, so allow for \
                                 the record's TTL.",
                            ),
                        ),
                        None => section.checks.push(Check::new(
                            format!("{domain} → A record"),
                            Verdict::Unknown,
                            format!("{listed}; cannot compare without our public IP"),
                        )),
                    }
                }
                Err(error) => section.checks.push(Check::new(
                    format!("{domain} → A record"),
                    Verdict::Unknown,
                    format!("lookup failed: {error}"),
                )),
            }
        }
    }

    if config.sites.is_empty() {
        section.checks.push(Check::new("sites", Verdict::Skipped, "none configured"));
    }
}

/// The zone this machine serves itself, and whether it is actually serving it.
///
/// This is the counterpart to [`check_dns`], which asks the *public* resolver
/// whether a site's name points here. This asks *this machine's own* server
/// three questions, each a failure mode that leaves the domain dark:
///
/// 1. **Is :53 bound?** The server is queried on loopback for the apex `SOA`. No
///    answer means nothing is listening — the daemon is not up, or `serve-dns`
///    was never run. It is queried on loopback deliberately: a failure here is
///    the local server, cleanly separated from the router forwarding that this
///    program cannot test and does not touch (see [`crate::serve_daemon`]).
/// 2. **Does the apex A match the WAN IP?** A served address that is not this
///    machine's public IP sends every visitor to the wrong place; with
///    `dynamic_ip` on it usually means the updater has not run yet.
/// 3. **Is the zone delegated here?** The parent zone must list this machine's
///    `ns1` or the world never asks it anything, however correct it is.
///
/// A single nameserver earns a `Warn`: when this box is down the domain and its
/// mail vanish, so a secondary (Hurricane Electric offers free secondary DNS) is
/// strongly wanted even though it is not a hard config error.
async fn check_authority(
    report: &mut Report,
    config: &Config,
    resolver: &Resolver,
    public_ip: Option<Ipv4Addr>,
) {
    let section = report.section("Authoritative DNS");

    let Some(dns) = &config.dns else {
        section.checks.push(Check::new(
            "authoritative DNS",
            Verdict::Skipped,
            "no [dns] section — this machine serves no zone of its own",
        ));
        return;
    };

    let bind: SocketAddr = match dns.bind.parse() {
        Ok(address) => address,
        Err(error) => {
            section.checks.push(Check::new(
                "dns bind address",
                Verdict::Fail,
                format!("dns.bind {} does not parse: {error}", dns.bind),
            ));
            return;
        }
    };
    // A wildcard bind (0.0.0.0 / ::) cannot itself be queried, so ask the server
    // where it is reachable from here — loopback on the same port.
    let query_at = loopback_target(bind);
    let local = Resolver::at(query_at).with_timeout(Duration::from_secs(2));

    if dns.secondaries.is_empty() {
        section.checks.push(
            Check::new(
                "secondary nameservers",
                Verdict::Warn,
                "none configured — this machine is the only nameserver for its zone",
            )
            .with_fix(
                "With one nameserver, the domain and its mail stop resolving whenever this box is \
                 down or its connection drops. Add a secondary — Hurricane Electric runs free \
                 secondary DNS at dns.he.net — and list it in [dns].secondaries.",
            ),
        );
    }

    for zone in &dns.zones {
        let origin = zone.domain.trim().trim_end_matches('.').to_ascii_lowercase();

        // 1. Is anything answering on :53?
        match local.query(&origin, RecordType::Soa).await {
            Err(error) => {
                section.checks.push(
                    Check::new(
                        format!("{origin} served on {bind}"),
                        Verdict::Unknown,
                        format!("this machine's DNS server is not answering ({error})"),
                    )
                    .with_fix(
                        "Start it with `selfhost daemon` or `selfhost serve-dns`. This query went \
                         to loopback, so a failure here is the local server — not the router. For \
                         the internet to reach it, the router/edge must also forward UDP+TCP 53.",
                    ),
                );
                // Nobody answered; the apex-A comparison would only repeat the point.
                continue;
            }
            Ok(response) if response.answers.is_empty() => {
                section.checks.push(
                    Check::new(
                        format!("{origin} SOA"),
                        Verdict::Fail,
                        format!("the server answered on {bind} but returned no SOA for {origin}"),
                    )
                    .with_fix(
                        "The server is running but does not consider itself authoritative for this \
                         zone. Check the domain in [dns] matches the name being queried.",
                    ),
                );
            }
            Ok(_) => {
                section.checks.push(Check::new(
                    format!("{origin} SOA"),
                    Verdict::Pass,
                    format!("served on {bind}"),
                ));

                // 2. Does the served apex A match this machine's public IP?
                match local.lookup_a(&origin).await {
                    Ok(addresses) if addresses.is_empty() => section.checks.push(
                        Check::new(
                            format!("{origin} apex A"),
                            Verdict::Fail,
                            "the zone is served but has no apex A record",
                        )
                        .with_fix(
                            "Add an A record at the apex (name \"@\"), or let a bare [[dns.zone]] \
                             derive one from the discovered public IP.",
                        ),
                    ),
                    Ok(addresses) => {
                        let served =
                            addresses.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ");
                        match public_ip {
                            Some(ip) if addresses.contains(&ip) => section.checks.push(Check::new(
                                format!("{origin} apex A == WAN IP"),
                                Verdict::Pass,
                                format!("{served} matches this machine's public IP"),
                            )),
                            Some(ip) => section.checks.push(
                                Check::new(
                                    format!("{origin} apex A == WAN IP"),
                                    Verdict::Fail,
                                    format!(
                                        "the served apex A is {served}, but this machine's public \
                                         IP is {ip}"
                                    ),
                                )
                                .with_fix(
                                    "Visitors would be sent to the wrong address. If dynamic_ip is \
                                     off, correct the apex A in [dns]. If it is on, the updater has \
                                     not run yet, or the router's GetExternalIPAddress could not be \
                                     read — check `selfhost doctor` for the edge and re-run.",
                                ),
                            ),
                            None => section.checks.push(Check::new(
                                format!("{origin} apex A"),
                                Verdict::Unknown,
                                format!("served as {served}; cannot compare without our public IP"),
                            )),
                        }
                    }
                    Err(error) => section.checks.push(Check::new(
                        format!("{origin} apex A"),
                        Verdict::Unknown,
                        format!("lookup against the local server failed: {error}"),
                    )),
                }
            }
        }

        // 3. Is the zone delegated to this machine at the parent?
        match resolver.lookup_ns(&origin).await {
            Ok(nameservers) if nameservers.is_empty() => section.checks.push(
                Check::new(
                    format!("{origin} delegation"),
                    Verdict::Warn,
                    "the parent zone delegates no nameservers to this domain",
                )
                .with_fix(format!(
                    "Until the registrar publishes NS records for {origin} pointing at this \
                     machine (ns1.{origin}, plus glue), the internet never asks this server \
                     anything, however correctly it is configured.",
                )),
            ),
            Ok(nameservers) => {
                let expected = format!("ns1.{origin}");
                let listed = nameservers
                    .iter()
                    .any(|ns| ns.trim_end_matches('.').eq_ignore_ascii_case(&expected));
                if listed {
                    section.checks.push(Check::new(
                        format!("{origin} delegation"),
                        Verdict::Pass,
                        format!("the parent lists {expected}: {}", nameservers.join(", ")),
                    ));
                } else {
                    section.checks.push(
                        Check::new(
                            format!("{origin} delegation"),
                            Verdict::Warn,
                            format!(
                                "the parent delegates to {}, which does not include {expected}",
                                nameservers.join(", ")
                            ),
                        )
                        .with_fix(
                            "Expected while the domain is still served elsewhere. Point the \
                             registrar's NS records at this machine when you cut over.",
                        ),
                    );
                }
            }
            Err(error) => section.checks.push(Check::new(
                format!("{origin} delegation"),
                Verdict::Unknown,
                format!("could not read the parent's NS records: {error}"),
            )),
        }
    }

    if dns.zones.is_empty() {
        section.checks.push(Check::new(
            "zones",
            Verdict::Skipped,
            "the [dns] section defines no zones",
        ));
    }
}

/// The address to query a server on, given the address it binds.
///
/// A server bound to a wildcard address (`0.0.0.0` or `::`) is listening on every
/// interface but cannot be *queried* at the wildcard, so this machine reaches it
/// on loopback. A specific bind is queried as-is.
fn loopback_target(bind: SocketAddr) -> SocketAddr {
    if bind.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bind.port())
    } else {
        bind
    }
}

/// Everything that decides whether mail works.
async fn check_mail(
    report: &mut Report,
    config: &Config,
    resolver: &Resolver,
    public_ip: Option<Ipv4Addr>,
    deep: bool,
) {
    let section = report.section("Mail");

    let Some(address) = public_ip else {
        section.checks.push(Check::new(
            "mail diagnostics",
            Verdict::Unknown,
            "skipped — public IP unknown",
        ));
        return;
    };

    // --- reputation -------------------------------------------------------
    if !resolver.trustworthy_for_blocklists() {
        section.checks.push(
            Check::new("blocklists", Verdict::Unknown, "not checked through a public resolver")
                .with_fix("Re-run with --resolver <your ISP or router resolver>."),
        );
    } else {
        for (zone, significance) in BLOCKLISTS {
            let name = blocklist_name(address, zone);
            match resolver.lookup_a(&name).await {
                Ok(answers) if answers.is_empty() => section.checks.push(Check::new(
                    zone.to_string(),
                    Verdict::Pass,
                    "not listed",
                )),
                Ok(answers) => {
                    let real: Vec<_> = answers.iter().filter(|a| is_real_listing(**a)).collect();
                    if real.is_empty() {
                        section.checks.push(Check::new(
                            zone.to_string(),
                            Verdict::Unknown,
                            "the blocklist refused the query (not a listing)",
                        ));
                        continue;
                    }
                    // Each code names a different list meaning a different
                    // thing. Reporting them as one lump loses the distinction
                    // between "residential address" and "compromised machine".
                    for code in &real {
                        let listing = investigate::describe(**code);
                        let verdict = if listing.indicates_compromise || listing.list != "PBL" {
                            Verdict::Fail
                        } else {
                            Verdict::Warn
                        };
                        section.checks.push(
                            Check::new(
                                format!("{zone} → {} ({})", listing.list, listing.code),
                                verdict,
                                format!("{} · {significance}", listing.meaning),
                            )
                            .with_fix(listing.action),
                        );
                    }
                }
                Err(error) => section.checks.push(Check::new(
                    zone.to_string(),
                    Verdict::Unknown,
                    format!("lookup failed: {error}"),
                )),
            }
        }
    }

    // --- forward-confirmed reverse DNS ------------------------------------
    match resolver.lookup_ptr(address).await {
        Ok(names) if names.is_empty() => section.checks.push(
            Check::new("reverse DNS (PTR)", Verdict::Fail, "no PTR record")
                .with_fix("Ask your ISP to set a PTR record for your address."),
        ),
        Ok(names) => {
            let ptr = names[0].clone();
            match resolver.lookup_a(&ptr).await {
                Ok(forward) if forward.contains(&address) => section.checks.push(Check::new(
                    "forward-confirmed reverse DNS",
                    Verdict::Pass,
                    format!("{ptr} → {address}"),
                )),
                Ok(forward) if forward.is_empty() => section.checks.push(
                    Check::new(
                        "forward-confirmed reverse DNS",
                        Verdict::Fail,
                        format!("PTR is {ptr}, but that name has no A record"),
                    )
                    .with_fix(
                        "Gmail and Outlook weight this heavily for inbox placement, and only your \
                         ISP can fix it — you cannot set your own PTR.\n\
                         The Investigation section below names the exact address to email.",
                    ),
                ),
                Ok(forward) => section.checks.push(Check::new(
                    "forward-confirmed reverse DNS",
                    Verdict::Fail,
                    format!(
                        "PTR is {ptr}, which resolves to {} — not {address}",
                        forward.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ")
                    ),
                )),
                Err(error) => section.checks.push(Check::new(
                    "forward-confirmed reverse DNS",
                    Verdict::Unknown,
                    format!("lookup failed: {error}"),
                )),
            }
        }
        Err(error) => section.checks.push(Check::new(
            "reverse DNS (PTR)",
            Verdict::Unknown,
            format!("lookup failed: {error}"),
        )),
    }

    // --- outbound path ----------------------------------------------------
    match TcpStream::connect("gmail-smtp-in.l.google.com:25").await {
        Ok(_) => section.checks.push(Check::new(
            "outbound port 25",
            Verdict::Pass,
            "open — direct delivery is possible from this network",
        )),
        Err(_) => section.checks.push(
            Check::new("outbound port 25", Verdict::Fail, "blocked or filtered")
                .with_fix(
                    "Most residential ISPs block outbound 25. Direct delivery is impossible; use \
                     a relay (submission on 587) instead.",
                ),
        ),
    }

    // --- per-domain records -----------------------------------------------
    let domains: Vec<String> = config
        .sites
        .iter()
        .flat_map(|s| s.domains.clone())
        .filter(|d| d != "localhost" && d.contains('.') && !d.starts_with("www."))
        .collect();

    for domain in domains.iter().take(5) {
        match resolver.lookup_mx(domain).await {
            Ok(hosts) if hosts.is_empty() => section.checks.push(
                Check::new(format!("{domain} MX"), Verdict::Warn, "no MX record")
                    .with_fix("Without an MX record this domain receives no mail."),
            ),
            Ok(hosts) => section.checks.push(Check::new(
                format!("{domain} MX"),
                Verdict::Pass,
                hosts.iter().map(|(p, h)| format!("{p} {h}")).collect::<Vec<_>>().join(", "),
            )),
            Err(error) => section.checks.push(Check::new(
                format!("{domain} MX"),
                Verdict::Unknown,
                format!("lookup failed: {error}"),
            )),
        }

        let texts = resolver.lookup_txt(domain).await.unwrap_or_default();
        match texts.iter().find(|t| t.starts_with("v=spf1")) {
            Some(spf) => section.checks.push(Check::new(
                format!("{domain} SPF"),
                Verdict::Pass,
                spf.clone(),
            )),
            None => section.checks.push(
                Check::new(format!("{domain} SPF"), Verdict::Warn, "no SPF record").with_fix(
                    "Receivers use SPF to decide whether you were allowed to send. Without one, \
                     mail is far more likely to be junked.",
                ),
            ),
        }

        let dmarc = resolver.lookup_txt(&format!("_dmarc.{domain}")).await.unwrap_or_default();
        match dmarc.iter().find(|t| t.starts_with("v=DMARC1")) {
            Some(policy) => section.checks.push(Check::new(
                format!("{domain} DMARC"),
                Verdict::Pass,
                policy.clone(),
            )),
            None => section.checks.push(
                Check::new(format!("{domain} DMARC"), Verdict::Warn, "no DMARC record").with_fix(
                    "Add a TXT record at _dmarc.<domain>. Start permissive and tighten:\n\
                     v=DMARC1; p=none; rua=mailto:you@<domain>",
                ),
            ),
        }
    }

    // --- live handshake ---------------------------------------------------
    if deep {
        for host in ["gmail-smtp-in.l.google.com", "outlook-com.olc.protection.outlook.com"] {
            let (check, seen) = smtp_handshake(host).await;
            section.checks.push(check);

            // Cross-check: the receiver tells us which address it saw. If that
            // differs from the one every check above was run against, those
            // checks examined the wrong host — worth knowing loudly, because it
            // is how a diagnostic passes while mail is broken.
            if let Some(seen) = seen {
                if seen != address {
                    section.checks.push(
                        Check::new(
                            "address agreement",
                            Verdict::Fail,
                            format!("{host} sees this machine as {seen}, not {address}"),
                        )
                        .with_fix(
                            "The blocklist and reverse-DNS checks above were run against the wrong \
                             address and cannot be trusted. This usually means more than one \
                             internet connection, or mail leaving through a different route.",
                        ),
                    );
                } else {
                    section.checks.push(Check::new(
                        format!("address agreement with {host}"),
                        Verdict::Pass,
                        format!("confirms {seen}"),
                    ));
                }
            }
        }
    } else {
        section.checks.push(Check::new(
            "live SMTP handshake",
            Verdict::Skipped,
            "run `selfhost doctor --deep` to test whether major providers accept a connection",
        ));
    }
}

/// Opens an SMTP conversation with a real mail exchanger and stops before
/// sending anything.
///
/// This answers a question no DNS lookup can: whether the receiver will talk to
/// this address at all. It is deliberately not a delivery test — no message is
/// sent, and acceptance here does not mean a message would reach an inbox.
async fn smtp_handshake(host: &str) -> (Check, Option<Ipv4Addr>) {
    let name = format!("live SMTP handshake with {host}");

    let attempt = tokio::time::timeout(Duration::from_secs(15), async {
        let mut stream = TcpStream::connect((host, 25)).await.ok()?;
        let mut buffer = [0_u8; 1024];

        let read = stream.read(&mut buffer).await.ok()?;
        let greeting = String::from_utf8_lossy(&buffer[..read]).trim().to_owned();
        if !greeting.starts_with("220") {
            return Some((false, greeting));
        }

        stream.write_all(b"EHLO selfhost.diagnostic\r\n").await.ok()?;
        let read = stream.read(&mut buffer).await.ok()?;
        let reply = String::from_utf8_lossy(&buffer[..read]).trim().to_owned();

        let _ = stream.write_all(b"QUIT\r\n").await;
        Some((reply.starts_with("250"), reply.lines().next().unwrap_or_default().to_owned()))
    })
    .await;

    match attempt {
        Ok(Some((true, reply))) => {
            let seen = address_from_ehlo(&reply);
            (
                Check::new(name, Verdict::Pass, format!("accepted the connection — {reply}")),
                seen,
            )
        }
        Ok(Some((false, reply))) => (
            Check::new(name, Verdict::Fail, format!("refused — {reply}")).with_fix(
                "The receiver is rejecting this address outright. Check the blocklists above.",
            ),
            None,
        ),
        Ok(None) | Err(_) => (
            Check::new(name, Verdict::Unknown, "could not connect or timed out")
                .with_fix("Usually means outbound port 25 is blocked; see the check above."),
            None,
        ),
    }
}

/// Chases the causes behind whatever the checks above reported.
///
/// The checks say *what* is wrong. This says *why*, and *who can fix it* — which
/// for the two problems that actually stop mail is never the person running this
/// program.
async fn investigate_causes(
    report: &mut Report,
    resolver: &Resolver,
    public_ip: Option<Ipv4Addr>,
    deep: bool,
    scan_lan: bool,
) {
    let section = report.section("Investigation");

    // --- who owns the reverse record --------------------------------------
    if let Some(address) = public_ip {
        let authority = investigate::reverse_authority(resolver, address).await;
        match &authority.contact {
            Some(contact) => section.checks.push(
                Check::new(
                    "who controls your reverse DNS",
                    Verdict::Pass,
                    format!("zone {} — contact {contact}", authority.zone),
                )
                .with_fix(format!(
                    "You cannot change your own PTR; only they can. Email {contact} and ask for \
                     EITHER:\n\
                     · a forward A record for your PTR name, so forward-confirmed reverse DNS \
                     resolves, OR\n\
                     · delegation of the PTR so you can point it at your own mail hostname.\n\
                     Worth asking about a static address in the same message — a residential lease \
                     can move, and every record you set would then be wrong.",
                )),
            ),
            None => section.checks.push(Check::new(
                "who controls your reverse DNS",
                Verdict::Unknown,
                format!("no SOA contact found for {}", authority.zone),
            )),
        }

        if !authority.nameservers.is_empty() {
            section.checks.push(Check::new(
                "reverse zone nameservers",
                Verdict::Pass,
                authority.nameservers.join(", "),
            ));
        }
    }

    // --- is it you, or the whole block ------------------------------------
    if let (Some(address), true) = (public_ip, deep) {
        let survey = investigate::survey_block(resolver, address, "zen.spamhaus.org").await;
        if survey.sampled == 0 {
            section.checks.push(Check::new(
                "is the listing yours or your provider's",
                Verdict::Unknown,
                "could not sample neighbouring addresses",
            ));
        } else if survey.is_block_wide() {
            let examples =
                survey.examples.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ");
            section.checks.push(
                Check::new(
                    "is the listing yours or your provider's",
                    Verdict::Warn,
                    format!(
                        "{}/{} sampled neighbours are also listed ({examples}) — this looks \
                         provider-wide",
                        survey.listed, survey.sampled
                    ),
                )
                .with_fix(
                    "Delisting your own address achieves nothing while the range is listed. This \
                     is between your ISP and the blocklist — raise it with them, and plan on \
                     relaying outbound mail meanwhile.",
                ),
            );
        } else {
            section.checks.push(
                Check::new(
                    "is the listing yours or your provider's",
                    Verdict::Pass,
                    format!(
                        "0 of {} sampled neighbours are listed — this is specific to your address",
                        survey.sampled
                    ),
                )
                .with_fix(
                    "Good news, in a sense: it is not a dirty provider range, so delisting should \
                     hold once the cause is fixed. It also means the cause is on your network.",
                ),
            );
        }
    }

    // --- what could be earning an XBL listing ------------------------------
    let local = investigate::local_services().await;
    if local.is_empty() {
        section.checks.push(Check::new(
            "services listening on this machine",
            Verdict::Pass,
            "none of the commonly abused ports are open here",
        ));
    } else {
        for service in &local {
            section.checks.push(
                Check::new(
                    format!("port {} open on this machine", service.port),
                    Verdict::Warn,
                    service.note.to_owned(),
                )
                .with_fix(
                    "Confirm you meant to run this. An open proxy or relay is the most common \
                     way a machine earns a compromised-host listing.",
                ),
            );
        }
    }

    // --- outbound filtering -------------------------------------------------
    if deep {
        for (port, note, reachable) in investigate::outbound_matrix().await {
            if reachable {
                section.checks.push(Check::new(
                    format!("outbound port {port}"),
                    Verdict::Pass,
                    note.to_owned(),
                ));
            } else {
                section.checks.push(
                    Check::new(format!("outbound port {port}"), Verdict::Fail, note.to_owned())
                        .with_fix(
                            "Blocked by the network, not by this software. The distinction matters: \
                             no amount of configuration here will open it.",
                        ),
                );
            }
        }
    }

    // --- what is actually reachable from the internet -----------------------
    // Kept for the device assessment below: whether a device can be reached
    // from outside changes what its open ports mean.
    let gateway = investigate::Gateway::discover().await;
    let edge = match (&gateway, public_ip) {
        (Ok(gateway), Some(public)) => gateway
            .external_address()
            .await
            .ok()
            .map(|router_wan| investigate::NetworkEdge { router_wan, public }),
        _ => None,
    };
    report_edge(section, edge);

    let forwards = match &gateway {
        Ok(gateway) => Ok(gateway.mappings().await),
        Err(reason) => Err(reason.clone()),
    };
    // Without the edge established, treat the router as the edge — the historical
    // assumption — but never state the stronger conclusion as fact.
    let router_is_the_edge = edge.map(|edge| edge.forwards_reach_the_internet());
    match &forwards {
        Ok(mappings) if mappings.is_empty() => section.checks.push(match router_is_the_edge {
            Some(true) => Check::new(
                "ports open to the internet",
                Verdict::Pass,
                "the router forwards nothing, and it holds the public address — so no device on \
                 your network is reachable from outside",
            )
            .with_fix(
                "This matters for a blocklisting: a service listening on your LAN cannot be abused \
                 by anyone outside if nothing reaches it. It also means you must add a forward \
                 before this machine can serve the internet.",
            ),
            Some(false) => Check::new(
                "ports open to the internet",
                Verdict::Unknown,
                "this router forwards nothing — but it is not the edge, so that settles only the \
                 inner hop",
            )
            .with_fix(
                "Do not read this as \"nothing is reachable from outside\". The upstream router \
                 holds the public address and has a forwarding table of its own that this machine \
                 cannot read, and anything else behind it shares your public address. Sort the \
                 edge out first; until then, treat inbound exposure as unmeasured.",
            ),
            None => Check::new(
                "ports open to the internet",
                Verdict::Unknown,
                "the router forwards nothing, but would not say what its own outside address is",
            )
            .with_fix(
                "Nothing is reachable through this router. Whether that means nothing is reachable \
                 at all depends on whether another router sits upstream, which this check could \
                 not establish — compare the router's WAN address in its status page against your \
                 public address by hand.",
            ),
        }),
        Ok(mappings) => {
            for mapping in mappings {
                let abusable = mapping.exposes_abusable_service();
                section.checks.push(
                    Check::new(
                        format!("port {} open to the internet", mapping.external_port),
                        if abusable { Verdict::Fail } else { Verdict::Warn },
                        format!(
                            "{}/{} → {}:{} \"{}\"",
                            mapping.external_port,
                            mapping.protocol,
                            mapping.internal_client,
                            mapping.internal_port,
                            mapping.description
                        ),
                    )
                    .with_fix(if abusable {
                        "This exposes a service commonly abused as a relay. If you did not create \
                         this forward, something on your network opened it via UPnP — remove it and \
                         consider turning UPnP off on the router."
                    } else {
                        "Confirm you meant to open this. UPnP lets any program on the network open \
                         a hole in the firewall without asking, so a forward you do not recognise \
                         is worth removing."
                    }),
                );
            }
        }
        Err(reason) => section.checks.push(Check::new(
            "ports open to the internet",
            Verdict::Unknown,
            format!("could not read the router's forwards: {reason}"),
        )),
    }

    // --- find the compromised device ---------------------------------------
    if scan_lan {
        match investigate::local_address() {
            Some(local_ip) => {
                let survey = investigate::sweep_lan(local_ip).await;
                let mappings = forwards.as_deref().unwrap_or(&[]);
                report_lan(section, &assess::assess(&survey, mappings, local_ip));
                if router_is_the_edge == Some(false) {
                    section.checks.push(
                        Check::new(
                            "how far this scan could see",
                            Verdict::Warn,
                            "the sweep covers this router's network only, and it is not the edge",
                        )
                        .with_fix(
                            "Everything behind the upstream router shares your public address, so \
                             a device on a segment this machine cannot route to would earn the \
                             same listing and never appear above. If the sweep names no culprit, \
                             that is not an all-clear — ask your provider what else sits behind \
                             that box.",
                        ),
                    );
                }
            }
            None => section.checks.push(Check::new(
                "devices on the local network",
                Verdict::Unknown,
                "could not determine this machine's LAN address",
            )),
        }
    } else {
        section.checks.push(Check::new(
            "devices on the local network",
            Verdict::Skipped,
            "run `selfhost doctor --scan-lan` to identify every device and name the one at fault",
        ));
    }
}

/// Reports whether the local router is where the internet actually arrives.
///
/// One comparison — the address the router claims on its outside interface
/// against the address a public echo reports — decides how far every other
/// inbound conclusion in this report can be trusted, so it is stated before
/// them rather than inferred afterwards.
fn report_edge(section: &mut Section, edge: Option<investigate::NetworkEdge>) {
    let Some(edge) = edge else {
        section.checks.push(Check::new(
            "what sits between you and the internet",
            Verdict::Unknown,
            "the router would not say what address it holds on its outside interface",
        ));
        return;
    };

    let check = match edge.shape() {
        investigate::Edge::Direct => Check::new(
            "what sits between you and the internet",
            Verdict::Pass,
            format!("your router holds {} directly — nothing translates in between", edge.public),
        )
        .with_fix(
            "This is the arrangement everything else here assumes: a forward on this router is a \
             forward from the internet, and a certificate challenge can reach this machine.",
        ),
        investigate::Edge::DoubleNat => Check::new(
            "what sits between you and the internet",
            Verdict::Warn,
            format!(
                "your router's outside address is {}, but the internet sees {} — a second router \
                 sits between them",
                edge.router_wan, edge.public
            ),
        )
        .with_fix(
            "Outbound is unaffected: sending mail and fetching certificates keep working. Inbound \
             does not — a forward has to exist on both boxes, and you have no login on the \
             upstream one. Ask your provider, in this order: bridge or passthrough so this router \
             holds the public address itself; failing that a static forward of 80 and 443 to your \
             router's WAN address; failing that a DMZ to it.",
        ),
        investigate::Edge::CarrierGrade => Check::new(
            "what sits between you and the internet",
            Verdict::Fail,
            format!(
                "your router's outside address {} is carrier-grade NAT — the public address {} is \
                 shared with other customers",
                edge.router_wan, edge.public
            ),
        )
        .with_fix(
            "No port forward you can configure will make this machine reachable, because the \
             address is not yours alone. Ask your provider for a static or dedicated public \
             address; without one, hosting anything inbound here needs a tunnel or a relay.",
        ),
    };
    section.checks.push(check);
}

/// Reports what the local network amounts to, strongest finding first.
///
/// Only devices that need attention get a line of their own. The rest are
/// counted, because a diagnostic that prints every device it looked at buries
/// the one finding that matters and leaves the reader to do the diagnosis.
fn report_lan(section: &mut Section, conclusion: &assess::Conclusion) {
    section.checks.push(
        Check::new("what the local network shows", Verdict::Pass, conclusion.summary.clone())
            .with_fix(conclusion.next_step.clone()),
    );

    for assessment in &conclusion.notable {
        let verdict = match assessment.standing {
            assess::Standing::Responsible => Verdict::Fail,
            assess::Standing::PrimeSuspect => Verdict::Fail,
            assess::Standing::Unresolved => Verdict::Warn,
            assess::Standing::Consistent => Verdict::Pass,
        };

        let mut fix = assessment.because.join(" ");
        if let Some(test) = &assessment.decisive_test {
            fix.push(' ');
            fix.push_str(test);
        }

        section.checks.push(
            Check::new(
                format!("{} — {}", assessment.address, assessment.standing.label()),
                verdict,
                assessment.what_it_is.clone(),
            )
            .with_fix(fix),
        );
    }

    if !conclusion.consistent.is_empty() {
        let listed = conclusion
            .consistent
            .iter()
            .map(|assessment| format!("{} ({})", assessment.address, assessment.what_it_is))
            .collect::<Vec<_>>()
            .join(", ");
        section.checks.push(Check::new(
            "other devices",
            Verdict::Pass,
            format!("{} behaving as expected — {listed}", conclusion.consistent.len()),
        ));
    }
}

/// Discovers this machine's public IPv4 address.
///
/// # Why this is not done over DNS
///
/// The obvious trick — querying `whoami.akamai.net` or `whoami.cloudflare` — is
/// wrong here, and wrong in a way that quietly breaks every check downstream.
/// Those services answer with the address of **the resolver that asked**, not
/// the client behind it. Query them through a router forwarding to the ISP's
/// resolver and the answer is the *ISP's* address.
///
/// This was not theoretical: the first version of this function used exactly
/// that trick, reported the ISP resolver's address, and then passed every
/// blocklist and reverse-DNS check — because the ISP's own resolver is clean and
/// correctly configured. It declared mail healthy on a network whose real
/// address was blocklisted with broken forward-confirmed reverse DNS.
///
/// So the address is read from a service that reports the address the *TCP
/// connection* came from, which is the one that actually sends mail and receives
/// visitors.
pub(crate) async fn discover_public_ip() -> Option<Ipv4Addr> {
    // Plain HTTP, and deliberately so: this needs the address a TCP connection
    // appears to come from, and TLS would add a certificate dependency without
    // changing what is learned. Nothing secret is sent.
    for host in ["checkip.amazonaws.com", "ifconfig.me"] {
        if let Some(address) = http_echo(host).await {
            return Some(address);
        }
    }
    None
}

/// Fetches an IP-echo endpoint over plain HTTP and parses the address.
async fn http_echo(host: &str) -> Option<Ipv4Addr> {
    let attempt = tokio::time::timeout(Duration::from_secs(8), async {
        let mut stream = TcpStream::connect((host, 80)).await.ok()?;
        let request =
            format!("GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.ok()?;

        let mut body = Vec::new();
        stream.read_to_end(&mut body).await.ok()?;
        let text = String::from_utf8_lossy(&body);

        // Skip the head; the address is the first thing in the body that parses.
        let payload = text.split("\r\n\r\n").nth(1).unwrap_or(&text);
        payload
            .split(|c: char| c.is_whitespace() || c == ',')
            .find_map(|token| token.trim().parse::<Ipv4Addr>().ok())
    })
    .await;

    attempt.ok().flatten()
}

/// Extracts the address a mail server reports seeing us as.
///
/// Both Gmail and Outlook echo the connecting address in their `EHLO` reply —
/// `250-mx.google.com at your service, [172.83.7.210]`. That is ground truth for
/// the path that actually matters for mail, straight from the receiver.
fn address_from_ehlo(reply: &str) -> Option<Ipv4Addr> {
    let start = reply.find('[')?;
    let end = reply[start..].find(']')? + start;
    reply[start + 1..end].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_counts_each_verdict() {
        let mut report = Report::default();
        let section = report.section("Test");
        section.checks.push(Check::new("a", Verdict::Pass, ""));
        section.checks.push(Check::new("b", Verdict::Fail, ""));
        section.checks.push(Check::new("c", Verdict::Fail, ""));
        section.checks.push(Check::new("d", Verdict::Unknown, ""));

        assert_eq!(report.count(Verdict::Pass), 1);
        assert_eq!(report.count(Verdict::Fail), 2);
        assert_eq!(report.count(Verdict::Unknown), 1);
        assert!(report.has_failures());
    }

    #[test]
    fn untestable_is_not_a_pass() {
        // Collapsing "could not test" into "fine" is how a diagnostic tells
        // somebody their mail works when it has never been tried.
        let mut report = Report::default();
        report.section("Test").checks.push(Check::new("x", Verdict::Unknown, ""));

        assert_eq!(report.count(Verdict::Pass), 0);
        assert!(!report.has_failures());
        assert_eq!(report.count(Verdict::Unknown), 1);
    }

    #[test]
    fn every_failure_carries_a_fix() {
        // A diagnostic that reports a problem without saying what to do about it
        // is only half a diagnostic.
        let check = Check::new("x", Verdict::Fail, "broken").with_fix("do this");
        assert!(check.fix.is_some());
    }

    #[test]
    fn reads_the_address_a_mail_server_reports_seeing() {
        // The receiver's own view is ground truth for the path that sends mail,
        // and it is what caught this tool checking the wrong address entirely.
        assert_eq!(
            address_from_ehlo("250-mx.google.com at your service, [172.83.7.210]"),
            Some(Ipv4Addr::new(172, 83, 7, 210))
        );
        assert_eq!(
            address_from_ehlo("250-SG2PEPF000B66CB.mail.protection.outlook.com Hello [172.83.7.210]"),
            Some(Ipv4Addr::new(172, 83, 7, 210))
        );
    }

    #[test]
    fn an_ehlo_without_an_address_yields_nothing() {
        assert_eq!(address_from_ehlo("250-mail.example.com at your service"), None);
        assert_eq!(address_from_ehlo("250 OK"), None);
        assert_eq!(address_from_ehlo("250-hello [not-an-ip]"), None);
        assert_eq!(address_from_ehlo(""), None);
    }

    #[test]
    fn a_permission_check_that_could_not_look_reports_unknown() {
        // The whole point of this file: "could not test" is not "fine". A
        // platform whose ACLs selfhost does not model, and a file that cannot
        // be read at all, are both untestable — never passes.
        let path = Path::new("/data/admin.token");
        for outcome in [
            Ok(Privacy::Unanswerable("this platform is not modelled".into())),
            Err(std::io::Error::other("permission denied reading the ACL")),
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no such file")),
        ] {
            let check = permission_check("admin token permissions", path, outcome, "stakes", "fix");
            assert_eq!(check.verdict, Verdict::Unknown, "{}", check.detail);
            assert!(check.detail.contains("admin.token"), "{}", check.detail);
        }
    }

    #[test]
    fn a_permission_check_passes_only_on_a_private_file() {
        let path = Path::new("/data/admin.token");
        let passing = permission_check(
            "admin token permissions",
            path,
            Ok(Privacy::Private("mode 0600 — owner only".into())),
            "stakes",
            "fix",
        );
        assert_eq!(passing.verdict, Verdict::Pass);
        assert!(passing.detail.contains("0600"));

        let failing = permission_check(
            "admin token permissions",
            path,
            Ok(Privacy::Exposed("mode 0644 — any account on this machine can reach it".into())),
            "the deployment's root credential",
            "chmod 600 it",
        );
        assert_eq!(failing.verdict, Verdict::Fail);
        assert!(failing.detail.contains("root credential"), "{}", failing.detail);
        assert!(failing.fix.is_some(), "a failure without a fix is half a diagnostic");
    }

    /// A deployment whose console site is gated to `gate`, or ungated when the
    /// list is empty.
    fn console_config(gate: &str) -> Config {
        Config::parse(&format!(
            r#"
version = 1

[server]
acme_email = "a@b.com"
acme = "self-signed"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "console"
domains = ["admin.example.com"]
static_root = "./sites/console"
console = true
allowed_cidrs = [{gate}]
"#
        ))
        .expect("the fixture parses")
    }

    /// The deployed shape: a console gated to the tunnel's loopback exit.
    fn production_config() -> Config {
        console_config("\"127.0.0.1/32\", \"::1/128\"")
    }

    #[test]
    fn the_console_gate_check_reports_what_the_loader_would_accept() {
        // Production: loopback, and the line has to say what loopback means.
        let production = console_gate_check(&console_config("\"127.0.0.1/32\", \"::1/128\""));
        assert_eq!(production.verdict, Verdict::Pass);
        assert!(production.detail.contains("127.0.0.1/32"), "{}", production.detail);
        assert!(
            production.detail.contains("every process already running on this machine"),
            "a loopback gate must say what it does not defend against: {}",
            production.detail
        );

        // A LAN gate is legitimate and carries no such note.
        let lan = console_gate_check(&console_config("\"192.168.1.0/24\""));
        assert_eq!(lan.verdict, Verdict::Pass);
        assert!(!lan.detail.contains("every process"), "{}", lan.detail);

        // The gates the loader refuses have to be built by hand, because
        // `Config::parse` will not produce them any more — which is the point of
        // the validation rule. The check still reports them: doctor runs against
        // whatever a daemon is holding, and a config can reach one by other
        // routes than this loader.
        let mut opened = production_config();
        opened.sites[0].allowed_cidrs = vec!["0.0.0.0/0".into()];
        let open = console_gate_check(&opened);
        assert_eq!(open.verdict, Verdict::Fail);
        assert!(open.detail.contains("0.0.0.0/0"), "{}", open.detail);
        assert!(open.fix.is_some());

        let mut ungated = production_config();
        ungated.sites[0].allowed_cidrs.clear();
        let empty = console_gate_check(&ungated);
        assert_eq!(empty.verdict, Verdict::Fail);
        assert!(empty.fix.is_some());
    }

    #[test]
    fn a_deployment_without_a_console_has_no_gate_to_report() {
        // Skipped, not Pass: there is nothing to be right about.
        let mut config = console_config("\"127.0.0.1/32\"");
        config.sites[0].console = false;
        assert_eq!(console_gate_check(&config).verdict, Verdict::Skipped);
    }

    #[test]
    fn a_loopback_gate_passes_and_says_what_it_does_not_defend_against() {
        // The sentence every subsystem behind the gate depends on being told:
        // loopback admits everything already running on this box.
        assert!(admits_loopback("127.0.0.1/32"));
        assert!(admits_loopback("::1/128"));
        assert!(admits_loopback("127.0.0.0/8"), "a wider loopback block counts too");
        assert!(!admits_loopback("10.66.0.0/24"));
        assert!(!admits_loopback("garbage"), "an unparseable entry admits nothing");
    }

    /// A gate's entries as `gate_reach` takes them.
    fn gate(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|entry| (*entry).to_owned()).collect()
    }

    #[test]
    fn a_gate_is_loopback_only_only_when_every_entry_is_loopback() {
        // The deployed shape.
        assert_eq!(gate_reach(&gate(&["127.0.0.1/32", "::1/128"])), GateReach::LoopbackOnly);
        assert_eq!(gate_reach(&gate(&["127.0.0.0/8"])), GateReach::LoopbackOnly);

        // The one that would otherwise be reported as loopback-only and is not:
        // the LAN entry admits every device on the network as well, and the
        // prose has to name it rather than talk about the tunnel alone.
        assert_eq!(
            gate_reach(&gate(&["127.0.0.1/32", "192.168.1.0/24"])),
            GateReach::LoopbackAndBeyond(vec!["192.168.1.0/24".to_owned()])
        );

        assert_eq!(gate_reach(&gate(&["192.168.1.0/24"])), GateReach::ElsewhereOnly);

        // An entry the matcher cannot read admits nothing at request time, but
        // it is reported as reaching beyond this machine: the direction of
        // error that alarms is the safe one.
        assert_eq!(
            gate_reach(&gate(&["127.0.0.1/32", "garbage"])),
            GateReach::LoopbackAndBeyond(vec!["garbage".to_owned()])
        );
    }

    #[test]
    fn every_reach_says_the_gate_is_not_authentication() {
        // Whatever the shape, the reader has to leave with this. An operator
        // who believes the gate authenticates is an operator who will put an
        // unauthenticated route behind it.
        for reach in [
            GateReach::LoopbackOnly,
            GateReach::LoopbackAndBeyond(vec!["192.168.1.0/24".to_owned()]),
            GateReach::ElsewhereOnly,
        ] {
            let prose = reach.what_it_is_not();
            assert!(prose.contains("perimeter"), "{prose}");
            assert!(prose.contains("credential") || prose.contains("authentication"), "{prose}");
        }

        // And a loopback gate has to name what it does not stop, in the words
        // that make it concrete: the things already running on this box.
        assert!(
            GateReach::LoopbackOnly.what_it_is_not().contains("loopback-only"),
            "the answer to \"is it loopback-only\" has to be in the line"
        );
        let mixed = GateReach::LoopbackAndBeyond(vec!["192.168.1.0/24".to_owned()]).what_it_is_not();
        assert!(mixed.contains("192.168.1.0/24"), "{mixed}");
    }

    #[test]
    fn a_gate_that_admits_loopback_and_a_lan_is_not_reported_as_loopback_only() {
        // The whole check, not just the classifier: a config an operator could
        // plausibly write, whose two entries defend against different things.
        let check = console_gate_check(&console_config("\"127.0.0.1/32\", \"192.168.1.0/24\""));
        assert_eq!(check.verdict, Verdict::Pass);
        assert!(check.detail.contains("192.168.1.0/24"), "{}", check.detail);
        assert!(
            !check.detail.contains("loopback-only"),
            "a gate that also admits a LAN is not loopback-only: {}",
            check.detail
        );
    }

    #[test]
    fn the_rendered_report_shows_detail_and_fix() {
        let mut report = Report::default();
        report
            .section("Mail")
            .checks
            .push(Check::new("blocklist", Verdict::Fail, "LISTED").with_fix("delist it"));

        let rendered = report.to_string();
        assert!(rendered.contains("Mail"));
        assert!(rendered.contains("blocklist"));
        assert!(rendered.contains("LISTED"));
        assert!(rendered.contains("delist it"));
        assert!(rendered.contains("1 failed"));
    }
}
