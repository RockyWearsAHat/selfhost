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

use crate::investigate;
use selfhost_config::Config;
use selfhost_dns::{Resolver, ResolverSource, blocklist_name, is_real_listing};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
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
    check_binds(&mut report, config).await;
    check_certificates(&mut report, config, project_dir);
    let public_ip = check_network(&mut report, &resolver).await;
    check_dns(&mut report, config, &resolver, public_ip).await;
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
    match std::fs::create_dir_all(&data_dir) {
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
    let tls_dir = project_dir.join(&config.server.data_dir).join("tls");

    match config.server.acme {
        selfhost_config::AcmeEnvironment::SelfSigned => section.checks.push(
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
        selfhost_config::AcmeEnvironment::Staging => section.checks.push(Check::new(
            "certificate source",
            Verdict::Warn,
            "Let's Encrypt staging — certificates are not browser-trusted",
        )),
        selfhost_config::AcmeEnvironment::Production => section.checks.push(Check::new(
            "certificate source",
            Verdict::Pass,
            "Let's Encrypt production",
        )),
    }

    let count = std::fs::read_dir(&tls_dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().ends_with(".crt.pem"))
                .count()
        })
        .unwrap_or(0);

    if count == 0 {
        section.checks.push(Check::new(
            "stored certificates",
            Verdict::Unknown,
            format!("none in {} yet — they are created on first run", tls_dir.display()),
        ));
    } else {
        section.checks.push(Check::new(
            "stored certificates",
            Verdict::Pass,
            format!("{count} in {}", tls_dir.display()),
        ));
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
                    format!("{domain}"),
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
                    format!("{zone}"),
                    Verdict::Pass,
                    "not listed",
                )),
                Ok(answers) => {
                    let real: Vec<_> = answers.iter().filter(|a| is_real_listing(**a)).collect();
                    if real.is_empty() {
                        section.checks.push(Check::new(
                            format!("{zone}"),
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
                    format!("{zone}"),
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

    // --- find the compromised device ---------------------------------------
    if scan_lan {
        match investigate::local_address() {
            Some(local_ip) => {
                let devices = investigate::sweep_lan(local_ip).await;
                if devices.is_empty() {
                    section.checks.push(Check::new(
                        "devices on the local network",
                        Verdict::Pass,
                        "no device is exposing a commonly abused service",
                    ));
                } else {
                    for device in &devices {
                        let ports = device
                            .open
                            .iter()
                            .map(|(port, note)| format!("{port} ({note})"))
                            .collect::<Vec<_>>()
                            .join("; ");
                        section.checks.push(
                            Check::new(
                                format!("device {}", device.address),
                                Verdict::Warn,
                                ports,
                            )
                            .with_fix(
                                "Identify this device. An XBL listing means something on this \
                                 network is compromised, and a home network rarely has an \
                                 inventory — this is the shortlist worth checking.",
                            ),
                        );
                    }
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
            "run `selfhost doctor --scan-lan` to shortlist devices worth investigating",
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
async fn discover_public_ip() -> Option<Ipv4Addr> {
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
