//! Whether this deployment is **serving**, asked of the wire rather than of the
//! process table.
//!
//! # The failure this module exists because of
//!
//! On 2026-08-16 the production box's `selfhost-lan-dns` scheduled task carried
//! `ExecutionTimeLimit = PT72H` — the Windows default — and `RestartCount = 0`.
//! Task Scheduler therefore killed it every seventy-two hours and never started
//! it again. `selfhost-daemon` kept running, the proxy kept answering, the task
//! for the daemon was in the correct state, and every signal anybody looked at
//! was green. Public DNS went `SERVFAIL`, and every hosted site broke *seconds*
//! after it loaded: the first page came from a cached answer and every lookup
//! after it failed.
//!
//! Nothing noticed for as long as the question being asked was "is a process
//! alive". A live process proves that something was spawned. It does not prove
//! that a socket is bound, that a zone is loaded, that a certificate resolves,
//! or that a query gets an answer. So every probe here **asks the component the
//! question it exists to answer** and reads the reply off the wire:
//!
//! - **DNS** — a real `SOA` query for a zone this deployment claims, sent to the
//!   port the deployment serves DNS on, over the loopback interface. Asked only
//!   of a deployment that *declares* it serves DNS; see [`dns_duty`].
//! - **HTTP** — a real `GET /` with a `Host:` header, and an `HTTP/1.` status
//!   line read back. Any status counts: a 404 is the proxy answering, and the
//!   thing being tested is whether it answers at all.
//! - **HTTPS** — a real, hand-built TLS `ClientHello`, and a TLS record read
//!   back. A `ServerHello`/`HelloRetryRequest` *or* an alert both prove a TLS
//!   implementation is on that port; a closed connection or a plaintext reply
//!   proves it is not. Nothing here completes a handshake or verifies a
//!   certificate — `doctor`'s certificate section already does that, and a probe
//!   that needed a trusted chain could not run on a box on `acme =
//!   "self-signed"`, which is most of them.
//! - **The control API** — `GET /api/health` on `admin_bind`, which is the one
//!   route that answers without a credential precisely so it can be probed.
//!
//! # "Not running here" is not "broken"
//!
//! [`probe_all`] asks the control API first and uses the answer to grade the
//! rest. A development tree with no daemon running is not a deployment that has
//! failed, and reporting three red lines on a laptop is how a health check
//! teaches its reader to ignore it. So a probe that finds nothing listening is
//! [`Serving::No`] only when the control API *did* answer — a running deployment
//! that is not serving, which is exactly the incident above — and
//! [`Serving::Untestable`] otherwise.
//!
//! # "Not this deployment's job" is not "broken" either
//!
//! The grading above answers *is this deployment running here*. It does not
//! answer *is this component this deployment's responsibility at all*, and on
//! 2026-08-17 the first-run walk (`docs/labs/first-run-lab.dx`) proved the
//! difference is not academic. [`probe_dns`] took its zone set from
//! [`crate::lan_dns::served_origins`], which derives origins from the **site and
//! mail domains** — so any deployment with an ordinary site name was assumed to
//! be an authoritative nameserver. Most are not: they point a registrar's
//! nameservers at this box and serve only HTTP. On every one of those,
//! `selfhost health` read `dns NOT SERVING` and exited non-zero for ever,
//! `selfhost doctor` failed, and — worst — [`crate::converge`] read a fault,
//! spent all three repair attempts restarting a nameserver the deployment never
//! asked for, and escalated. A supervisor that repeatedly restarts a service
//! nobody declared manufactures the outage it exists to prevent.
//!
//! So a probe fires only where the deployment **declares that surface**, and
//! [`Serving::NotDeclared`] is the answer where it does not. The other three
//! components need no such test and the reason is worth writing down rather than
//! leaving to be re-derived: `serve_everything` binds `http_bind`, `https_bind`
//! and `admin_bind` unconditionally and fails to start if any of them will not
//! bind, so a deployment that is running has, by construction, declared all
//! three. DNS is the only component the daemon serves conditionally, and it was
//! therefore the only one that could be over-claimed.
//!
//! # One opinion about health
//!
//! `selfhost doctor` renders these probes ([`crate::doctor`]'s "Serving"
//! section) and [`crate::converge`] repairs from them. There is deliberately no
//! second implementation: two health checks that can disagree are how a box ends
//! up green in one place and dead in another, which is the whole shape of the
//! outage above.

use selfhost_config::Config;
use selfhost_dns::{RecordType, Resolver};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// How long any single probe is given before it is called a failure.
///
/// Every probe here is to a socket on this machine's own loopback interface, so
/// a healthy answer arrives in microseconds and the only thing this bounds is
/// how long a *wedged* component holds up the round. Short enough that a
/// convergence pass never becomes the reason the daemon is unresponsive.
const PROBE_DEADLINE: Duration = Duration::from_secs(3);

/// The most bytes any probe reads back.
///
/// Every reply this module looks at is a status line or a TLS record header.
/// Anything larger is a page body being streamed at a diagnostic, and reading it
/// would only cost memory.
const MAX_REPLY: usize = 4096;

/// One part of the deployment that can be asked whether it is serving.
///
/// A closed set rather than a string, because [`crate::converge`] maps each one
/// to a repair and a component nobody wrote a repair for must fail to compile
/// rather than fail silently at four in the morning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Component {
    /// The nameserver on port 53.
    Dns,
    /// The reverse proxy's plaintext listener.
    Http,
    /// The reverse proxy's TLS listener.
    Https,
    /// The loopback control API.
    ControlApi,
}

impl Component {
    /// Every component, in the order a pass walks them.
    ///
    /// The control API is first because its answer grades the rest — see
    /// [`probe_all`] — so this is an order with meaning rather than a list.
    pub const ALL: [Component; 4] =
        [Component::ControlApi, Component::Dns, Component::Http, Component::Https];

    /// What this component is called in a report and in the repair ledger.
    pub fn label(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Http => "http",
            Self::Https => "https",
            Self::ControlApi => "control-api",
        }
    }

    /// Whether this component runs in the daemon's own process.
    ///
    /// The distinction decides what a repair may be, and it is the whole of the
    /// design decision recorded in [`crate::converge`]: an in-process component
    /// came up with the daemon and cannot be restarted from inside itself, and
    /// an out-of-process one is a separate service registration that can.
    pub fn in_process(self) -> bool {
        match self {
            Self::Dns => false,
            Self::Http | Self::Https | Self::ControlApi => true,
        }
    }
}

/// What a probe found.
///
/// Four states rather than a boolean, for the reason `doctor`'s [`Verdict`] has
/// five: "could not test" and "tested and fine" are different facts, and
/// collapsing them is how a health check tells somebody DNS works when it has
/// never been asked.
///
/// [`Verdict`]: crate::doctor::Verdict
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Serving {
    /// It answered the question it exists to answer.
    Yes,
    /// It did not, and this deployment *is* running here — so this is a fault.
    No,
    /// Nothing about this deployment asks for this component.
    NotDeclared,
    /// It could not be asked from here, and that is not the same as broken.
    Untestable,
}

impl Serving {
    /// Whether this is a fault a repair should act on.
    ///
    /// Only [`Serving::No`]. An untestable probe must never trigger a repair:
    /// restarting a service because a diagnostic could not reach it is how a
    /// health check becomes the outage.
    pub fn is_fault(&self) -> bool {
        matches!(self, Self::No)
    }
}

/// One probe: what was asked, where, and what came back.
#[derive(Debug, Clone)]
pub struct Probe {
    /// Which part of the deployment was asked.
    pub component: Component,
    /// The question, named concretely enough to repeat by hand.
    pub target: String,
    /// The answer.
    pub serving: Serving,
    /// What was actually observed, as a measurement rather than a verdict.
    pub detail: String,
}

impl Probe {
    fn new(
        component: Component,
        target: impl Into<String>,
        serving: Serving,
        detail: impl Into<String>,
    ) -> Self {
        Self { component, target: target.into(), serving, detail: detail.into() }
    }
}

/// Probes every component and grades the result against whether this deployment
/// is running here at all.
///
/// The control API is asked first because its answer is what distinguishes the
/// two readings of silence — see the module documentation. Probes run in
/// sequence rather than concurrently: there are four of them, each is a loopback
/// round trip, and a sequential pass is trivially ordered in a log an operator
/// is reading during an incident.
pub async fn probe_all(config: &Config, project_dir: &Path) -> Vec<Probe> {
    let mut deployment_is_up = false;
    let mut probes = Vec::with_capacity(Component::ALL.len());
    for component in Component::ALL {
        let mut result = probe(component, config, project_dir).await;
        if component == Component::ControlApi {
            deployment_is_up = result.serving == Serving::Yes;
        } else if result.serving == Serving::No && !deployment_is_up {
            result.serving = Serving::Untestable;
            result.detail.push_str(
                "; and the control API is not answering either, so this deployment is not \
                 running on this machine",
            );
        }
        probes.push(result);
    }
    probes
}

/// Probes one component, ungraded.
///
/// Public so [`crate::converge`] can re-probe a single component after repairing
/// it without paying for the other three, and so a repair's verification uses
/// the *same* function that found the fault rather than a cheaper stand-in.
pub async fn probe(component: Component, config: &Config, project_dir: &Path) -> Probe {
    match component {
        Component::Dns => probe_dns(config, project_dir).await,
        Component::Http => probe_http(config).await,
        Component::Https => probe_https(config).await,
        Component::ControlApi => probe_control_api(config).await,
    }
}

/// Whether serving DNS is this deployment's job, and — when it is — what says so.
///
/// # Why this cannot be one signal
///
/// Two shapes both genuinely serve DNS and they declare it in different places,
/// which is precisely why the first version of this probe guessed instead of
/// asking:
///
/// - A deployment with a **`[dns]` section** serves `:53` from the daemon's own
///   arm. `serve_everything` builds that arm only when the section is present,
///   so the section is the declaration.
/// - The **production box has no `[dns]` section** and serves DNS anyway,
///   through the separately-registered `selfhost-lan-dns` task
///   ([`crate::service_install::LAN_DNS_TASK_NAME`], and `docs/labs/checkup.dx`
///   is the evidence). Reading only `[dns]` would have reported "nothing to
///   check" on that box throughout the seventy-two-hour outage this whole
///   module exists because of — which is exactly what `doctor`'s
///   authoritative-DNS section did.
///
/// Neither signal alone is sufficient, so both are asked and either one is
/// enough. **Absence of both is a real answer**, not a gap to be filled by
/// inference: a deployment that claims a site name has not thereby volunteered
/// to be a nameserver, and treating it as one is the over-claim recorded in this
/// module's documentation.
///
/// Pure and total, so the three shapes that matter — ordinary site, `[dns]`
/// section, production registration — are all testable on a machine that has
/// none of them.
pub fn dns_duty(config: &Config, separate_registration: Option<&str>) -> DnsDuty {
    if config.dns.is_some() {
        return DnsDuty::Declared(
            "this deployment has a [dns] section, so the daemon serves :53 itself".to_owned(),
        );
    }
    match separate_registration {
        Some(name) => DnsDuty::Declared(format!(
            "there is no [dns] section, but this machine has a {name} registration, which serves \
             :53 from a separate process"
        )),
        None => DnsDuty::NotDeclared,
    }
}

/// Whether this deployment is the thing that is supposed to answer DNS queries.
///
/// A two-state answer with the *reason* carried in it, rather than a boolean,
/// because the reason is what a health line and a repair ledger have to print:
/// "not serving" and "not this deployment's job" send an operator to two
/// completely different places.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsDuty {
    /// This deployment serves DNS, and this is what says so.
    Declared(String),
    /// Nothing about this deployment says it serves DNS.
    NotDeclared,
}

/// Asks this machine's own nameserver for a zone this deployment claims — but
/// only if this deployment ever said it serves DNS.
///
/// The declaration test is [`dns_duty`] and it is the whole of the fix recorded
/// in this module's documentation: the zone set below comes from
/// [`crate::lan_dns::served_origins`], which derives origins from site and mail
/// domains, so it is a list of names this deployment *claims* and never evidence
/// that it is authoritative for them. Using it to decide whether to probe at all
/// is what made a registrar-hosted deployment permanently red and gave the
/// convergence loop a fault to burn its repair budget on.
///
/// The zone set is still `served_origins` and not `config.dns.zones` once the
/// probe does fire, and that difference is still the point: on the production
/// box the zones exist only because that function invents them.
async fn probe_dns(config: &Config, _project_dir: &Path) -> Probe {
    // Only asked when there is no `[dns]` section, because that section already
    // settles the question — and on Windows this answer costs a `schtasks`
    // process. A convergence pass runs every sixty seconds, so a lookup that
    // cannot change the verdict is one this loop should not pay for.
    let registration =
        config.dns.is_none().then(crate::service_install::separate_dns_registration).flatten();
    probe_dns_declared(config, registration.as_deref()).await
}

/// [`probe_dns`] with the machine's answer about a separate registration passed
/// in.
///
/// Split out so the production shape — no `[dns]` section, a live
/// `selfhost-lan-dns` registration — can be exercised on a Mac, which has no
/// Task Scheduler and would otherwise leave the one deployment this module was
/// written for as the one shape no test covers.
async fn probe_dns_declared(config: &Config, separate_registration: Option<&str>) -> Probe {
    // The reason is carried down to the failure details rather than dropped: a
    // `NOT SERVING` line and an escalation in the repair ledger both raise the
    // question "why does supervision think DNS is this box's job", and the
    // answer is exactly this sentence. Making an operator go and read the config
    // to find out is how a diagnostic sends somebody to the wrong subsystem.
    let declared = match dns_duty(config, separate_registration) {
        DnsDuty::Declared(why) => why,
        DnsDuty::NotDeclared => {
            return Probe::new(
                Component::Dns,
                "dns",
                Serving::NotDeclared,
                format!(
                    "nothing declares that this deployment serves DNS: there is no [dns] section \
                     and no {} registration on this machine. Most deployments point a registrar's \
                     nameservers at this box and serve only HTTP; if this one is meant to be \
                     authoritative, add a [dns] section or install that registration and this \
                     line becomes a real check",
                    crate::service_install::LAN_DNS_TASK_NAME
                ),
            );
        }
    };

    let bind = dns_bind(config);
    let origins = crate::lan_dns::served_origins(config);
    let Some(origin) = origins.first() else {
        // Declared, and there is nothing to ask. Untestable rather than a fault:
        // a deployment that serves DNS for no zone is a configuration to fix,
        // not a nameserver to restart, and restarting it would change nothing.
        return Probe::new(
            Component::Dns,
            "dns",
            Serving::Untestable,
            "this deployment serves DNS but names no zone — no [dns].zones entries and no site or \
             mail domain to synthesise one from — so there is no question to ask it",
        );
    };

    let query_at = loopback_target(bind);
    let target = format!("SOA {origin} @ {query_at}");
    let resolver = Resolver::at(query_at).with_timeout(PROBE_DEADLINE);
    match resolver.query(origin, RecordType::Soa).await {
        Ok(response) if response.answers.is_empty() => Probe::new(
            Component::Dns,
            target,
            Serving::No,
            format!(
                "the nameserver answered but returned no SOA for {origin}, so it is running \
                 without the zone this deployment is supposed to be authoritative for; \
                 {declared}"
            ),
        ),
        Ok(response) => Probe::new(
            Component::Dns,
            target,
            Serving::Yes,
            format!("{} answer(s) for the apex SOA", response.answers.len()),
        ),
        Err(error) => Probe::new(
            Component::Dns,
            target,
            Serving::No,
            format!("nothing answered on {query_at}: {error}; {declared}"),
        ),
    }
}

/// Sends a real request to the proxy's plaintext listener and reads the status
/// line back.
///
/// Any status is a pass. The proxy redirects to HTTPS, serves a site, or answers
/// 404 for a name it does not host — all three are the proxy *answering*, and
/// which one it is depends on configuration this probe deliberately knows
/// nothing about. What is being tested is that a request goes in and an HTTP
/// response comes out.
async fn probe_http(config: &Config) -> Probe {
    let bind = match parse_bind(&config.server.http_bind) {
        Ok(bind) => bind,
        Err(detail) => return Probe::new(Component::Http, "http", Serving::No, detail),
    };
    let address = loopback_target(bind);
    let host = probe_host(config);
    let target = format!("GET / HTTP/1.1 Host: {host} @ {address}");

    let request = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: selfhost-health\r\nConnection: close\r\n\r\n"
    );
    match exchange(address, request.as_bytes(), first_line_complete).await {
        Err(detail) => Probe::new(Component::Http, target, Serving::No, detail),
        Ok(reply) => match http_status(&reply) {
            Some(status) => Probe::new(
                Component::Http,
                target,
                Serving::Yes,
                format!("answered HTTP {status}"),
            ),
            None => Probe::new(
                Component::Http,
                target,
                Serving::No,
                format!(
                    "something accepted the connection on {address} but did not answer with an \
                     HTTP status line ({} byte(s) read)",
                    reply.len()
                ),
            ),
        },
    }
}

/// Sends a real `ClientHello` to the proxy's TLS listener and reads a TLS record
/// back.
///
/// An accepted TCP connection is not evidence: the listener accepts before
/// rustls sees a byte, so a proxy whose certificate resolver is broken accepts
/// every connection and serves none. A TLS record coming back is evidence,
/// because only a TLS implementation produces one.
///
/// An **alert** counts as serving, and that is deliberate rather than sloppy.
/// This probe offers no key share, so a correct TLS 1.3 server answers with a
/// `HelloRetryRequest`; a server that dislikes the hello for any other reason
/// answers with an alert. Both are a TLS implementation reading and replying on
/// that port, which is the fact being established. The alert's *reason* is not
/// interpreted here, because interpreting it would make this probe an opinion
/// about certificates — which `doctor`'s certificate section already holds.
async fn probe_https(config: &Config) -> Probe {
    let bind = match parse_bind(&config.server.https_bind) {
        Ok(bind) => bind,
        Err(detail) => return Probe::new(Component::Https, "https", Serving::No, detail),
    };
    let address = loopback_target(bind);
    let host = probe_host(config);
    let target = format!("TLS ClientHello SNI={host} @ {address}");

    match exchange(address, &client_hello(&host), record_header_complete).await {
        Err(detail) => Probe::new(Component::Https, target, Serving::No, detail),
        Ok(reply) => match classify_tls_reply(&reply) {
            TlsReply::Handshake => Probe::new(
                Component::Https,
                target,
                Serving::Yes,
                "answered with a TLS handshake record",
            ),
            TlsReply::Alert => Probe::new(
                Component::Https,
                target,
                Serving::Yes,
                "answered with a TLS alert record — a TLS server is on this port; \
                 `selfhost doctor` reports on the certificates themselves",
            ),
            TlsReply::NotTls => Probe::new(
                Component::Https,
                target,
                Serving::No,
                format!(
                    "something on {address} answered {} byte(s) that are not a TLS record",
                    reply.len()
                ),
            ),
            TlsReply::Nothing => Probe::new(
                Component::Https,
                target,
                Serving::No,
                format!("{address} accepted the connection and then said nothing"),
            ),
        },
    }
}

/// Asks the control API the one question it answers without a credential.
///
/// `/api/health` exists for exactly this: it is matched ahead of the
/// authorisation wall and says nothing about the deployment, so a probe does not
/// need the bearer token — which matters because a token that cannot be read is
/// a *different* fault from an API that is not listening, and a probe that
/// conflated them would send an operator to rotate a credential during a DNS
/// outage.
async fn probe_control_api(config: &Config) -> Probe {
    let bind = match parse_bind(&config.server.admin_bind) {
        Ok(bind) => bind,
        Err(detail) => return Probe::new(Component::ControlApi, "control-api", Serving::No, detail),
    };
    let address = loopback_target(bind);
    let target = format!("GET /api/health @ {address}");
    let request = format!(
        "GET /api/health HTTP/1.1\r\nHost: {address}\r\nUser-Agent: selfhost-health\r\n\
         Connection: close\r\n\r\n"
    );

    match exchange(address, request.as_bytes(), first_line_complete).await {
        // Untestable rather than No: this is the probe whose answer grades the
        // others, so it must not assert a fault on the strength of its own
        // silence. A refused loopback connection means no daemon here.
        Err(detail) => Probe::new(Component::ControlApi, target, Serving::Untestable, detail),
        Ok(reply) => match http_status(&reply) {
            Some(200) => Probe::new(Component::ControlApi, target, Serving::Yes, "answered 200"),
            Some(status) => Probe::new(
                Component::ControlApi,
                target,
                Serving::No,
                format!(
                    "the control API answered {status}; /api/health answers 200 unconditionally, \
                     so anything else is a daemon that is up and not well"
                ),
            ),
            None => Probe::new(
                Component::ControlApi,
                target,
                Serving::Untestable,
                format!(
                    "something accepted the connection on {address} without answering HTTP \
                     ({} byte(s) read)",
                    reply.len()
                ),
            ),
        },
    }
}

/// One request, and as much of the reply as the caller needs to judge it.
///
/// Deliberately not a client: it writes the bytes it is given and reads until
/// `enough` is satisfied, the peer closes, or [`MAX_REPLY`] is reached. Every
/// probe above needs exactly this and nothing more, and keeping it this shape is
/// what stops a health check growing an HTTP stack nobody maintains.
///
/// `enough` is the parameter that makes this work at all rather than a
/// refinement. A TLS server answers a `ClientHello` and then **waits** — it has
/// no reason to close, because as far as it knows a handshake is in progress —
/// so reading until end of stream would time out against every healthy proxy on
/// 443 and report it dead. The caller says how much of the answer decides the
/// question: a record header, a status line.
///
/// A read error *after* bytes have arrived ends the reply rather than failing
/// it. A server that answers and then resets the connection has answered, and
/// treating that as silence would turn a working component into a fault.
async fn exchange(
    address: SocketAddr,
    request: &[u8],
    enough: impl Fn(&[u8]) -> bool,
) -> Result<Vec<u8>, String> {
    let attempt = async {
        let mut stream = TcpStream::connect(address)
            .await
            .map_err(|error| format!("nothing is listening on {address}: {error}"))?;
        stream
            .write_all(request)
            .await
            .map_err(|error| format!("{address} closed the connection before reading: {error}"))?;
        let mut reply = Vec::new();
        let mut buffer = [0u8; 1024];
        while reply.len() < MAX_REPLY && !enough(&reply) {
            match stream.read(&mut buffer).await {
                Ok(0) => break,
                Ok(read) => reply.extend_from_slice(buffer.get(..read).unwrap_or_default()),
                Err(_) if !reply.is_empty() => break,
                Err(error) => return Err(format!("{address} stopped answering: {error}")),
            }
        }
        Ok(reply)
    };

    tokio::time::timeout(PROBE_DEADLINE, attempt)
        .await
        .map_err(|_| {
            format!("{address} did not answer within {}s", PROBE_DEADLINE.as_secs())
        })?
}

/// Whether a reply carries a complete first line — everything the HTTP probes
/// need to reach a verdict.
fn first_line_complete(reply: &[u8]) -> bool {
    reply.contains(&b'\n')
}

/// Whether a reply carries a complete TLS record header — five bytes, which is
/// everything [`classify_tls_reply`] reads.
fn record_header_complete(reply: &[u8]) -> bool {
    reply.len() >= 5
}

/// The status code from an HTTP reply's first line, if it has one.
///
/// Pure, so the classification a probe turns on is testable without a socket.
/// Only `HTTP/1.` is accepted: this reads a proxy's own answer on loopback, and
/// something replying with a different protocol is exactly the "port is open,
/// wrong program" case the probe is looking for.
fn http_status(reply: &[u8]) -> Option<u16> {
    let line = reply.split(|byte| *byte == b'\n').next()?;
    let line = String::from_utf8_lossy(line);
    let line = line.trim_end_matches('\r');
    let mut fields = line.split(' ');
    let version = fields.next()?;
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    fields.next()?.parse().ok()
}

/// What came back from a TLS listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsReply {
    /// A handshake record: `ServerHello` or `HelloRetryRequest`.
    Handshake,
    /// An alert record. Still a TLS implementation answering.
    Alert,
    /// Bytes that are not a TLS record at all.
    NotTls,
    /// The connection was accepted and closed without a byte.
    Nothing,
}

/// Classifies a TLS listener's reply from its record header alone.
///
/// Pure and deliberately shallow: the record type and the legacy version are
/// enough to prove a TLS implementation answered, and parsing further would mean
/// re-implementing a handshake this project already has rustls for.
fn classify_tls_reply(reply: &[u8]) -> TlsReply {
    if reply.is_empty() {
        return TlsReply::Nothing;
    }
    // A record header is five bytes: type, two version bytes, two length bytes.
    // Anything shorter cannot be one however promising its first byte looks.
    if reply.len() < 5 {
        return TlsReply::NotTls;
    }
    // Every TLS version in use frames records as 0x03 0x0X, including TLS 1.3,
    // which keeps the legacy version on the wire for middlebox compatibility.
    if reply.get(1) != Some(&0x03) {
        return TlsReply::NotTls;
    }
    match reply.first() {
        Some(0x16) => TlsReply::Handshake,
        Some(0x15) => TlsReply::Alert,
        _ => TlsReply::NotTls,
    }
}

/// A minimal but well-formed TLS 1.3 `ClientHello`, framed as a record.
///
/// Hand-built rather than driven through rustls because completing a handshake
/// would mean verifying a certificate, and the boxes this runs on are mostly on
/// `acme = "self-signed"` — a probe that needed a trusted chain would report the
/// proxy dead on every one of them. The alternative, a client that accepts any
/// certificate, is a verifier-bypass living permanently in the binary for the
/// sake of a diagnostic; that trade is not worth making.
///
/// The hello offers an **empty** `key_share`, which is the canonical way to say
/// "none of your groups, tell me which one you want": a correct TLS 1.3 server
/// answers `HelloRetryRequest` — a handshake record — and the exchange stops
/// there with no session, no key agreement and nothing to clean up.
///
/// The client random is fixed rather than drawn from the system source. It is
/// never used for key agreement because the handshake never completes, and a
/// fixed value makes the whole hello a pure function that a test can assert byte
/// for byte.
fn client_hello(server_name: &str) -> Vec<u8> {
    /// A fixed, obviously-synthetic client random. See the note above about why
    /// this is not entropy: nothing is ever derived from it.
    const CLIENT_RANDOM: [u8; 32] = [0x53; 32];

    let mut extensions: Vec<u8> = Vec::new();

    // server_name (0x0000). Skipped for an address literal: RFC 6066 forbids one
    // in SNI, and rustls rejects the hello outright rather than ignoring it.
    if server_name.parse::<IpAddr>().is_err() && !server_name.is_empty() {
        let name = server_name.as_bytes();
        let mut entry = vec![0x00];
        push_u16_prefixed(&mut entry, name);
        let mut list = Vec::new();
        push_u16_prefixed(&mut list, &entry);
        extensions.extend_from_slice(&0x0000u16.to_be_bytes());
        push_u16_prefixed(&mut extensions, &list);
    }

    // supported_versions (0x002b): TLS 1.3 only.
    extensions.extend_from_slice(&0x002bu16.to_be_bytes());
    push_u16_prefixed(&mut extensions, &[0x02, 0x03, 0x04]);

    // supported_groups (0x000a): x25519 and secp256r1.
    extensions.extend_from_slice(&0x000au16.to_be_bytes());
    push_u16_prefixed(&mut extensions, &[0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);

    // signature_algorithms (0x000d): one ECDSA and one RSA-PSS, enough that a
    // server has something acceptable to name in a HelloRetryRequest.
    extensions.extend_from_slice(&0x000du16.to_be_bytes());
    push_u16_prefixed(&mut extensions, &[0x00, 0x04, 0x04, 0x03, 0x08, 0x04]);

    // key_share (0x0033), empty — see the note above.
    extensions.extend_from_slice(&0x0033u16.to_be_bytes());
    push_u16_prefixed(&mut extensions, &[0x00, 0x00]);

    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(&CLIENT_RANDOM);
    body.push(0x00); // legacy_session_id: empty
    body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]); // two TLS 1.3 suites
    body.extend_from_slice(&[0x01, 0x00]); // legacy_compression_methods: null
    push_u16_prefixed(&mut body, &extensions);

    let mut handshake: Vec<u8> = vec![0x01]; // ClientHello
    let length = body.len();
    handshake.extend_from_slice(&[(length >> 16) as u8, (length >> 8) as u8, length as u8]);
    handshake.extend_from_slice(&body);

    let mut record: Vec<u8> = vec![0x16, 0x03, 0x01];
    push_u16_prefixed(&mut record, &handshake);
    record
}

/// Appends `payload` behind its own big-endian sixteen-bit length, which is how
/// nearly every field in a `ClientHello` is framed.
fn push_u16_prefixed(out: &mut Vec<u8>, payload: &[u8]) {
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
}

/// The address to *query* a server on, given the address it binds.
///
/// A server bound to a wildcard address is listening on every interface but
/// cannot be reached at the wildcard itself, so this machine asks it on
/// loopback. A specific bind is used as it stands. Loopback also keeps a probe's
/// failure meaning one thing: the local component, cleanly separated from the
/// router forwarding this program cannot test.
pub fn loopback_target(bind: SocketAddr) -> SocketAddr {
    if bind.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bind.port())
    } else {
        bind
    }
}

/// The address this deployment serves DNS on.
///
/// `[dns].bind` when the operator wrote one, and the same `0.0.0.0:53` the
/// synthesising path in [`crate::lan_dns`] uses otherwise — because the box this
/// was written for has no `[dns]` section and serves DNS anyway.
fn dns_bind(config: &Config) -> SocketAddr {
    config
        .dns
        .as_ref()
        .and_then(|dns| dns.bind.parse().ok())
        .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53))
}

/// A `Host:`/SNI name the proxy is likely to recognise.
///
/// The first configured site's first domain, or `localhost`. An unrecognised
/// name would still prove the proxy answers, but a recognised one exercises
/// routing as well, and a name from the config costs nothing to prefer.
fn probe_host(config: &Config) -> String {
    config
        .sites
        .iter()
        .flat_map(|site| &site.domains)
        .find(|domain| domain.parse::<IpAddr>().is_err())
        .cloned()
        .unwrap_or_else(|| "localhost".to_owned())
}

/// A bind string as an address, or the reason it is not one.
fn parse_bind(bind: &str) -> Result<SocketAddr, String> {
    bind.parse().map_err(|error| format!("the configured bind {bind} is not an address: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wildcard_bind_is_probed_on_loopback_and_a_specific_one_as_it_stands() {
        // Connecting to 0.0.0.0 is not a way to reach a server bound to it, so a
        // probe that tried would report every wildcard-bound component dead.
        assert_eq!(
            loopback_target("0.0.0.0:443".parse().expect("literal")),
            "127.0.0.1:443".parse::<SocketAddr>().expect("literal")
        );
        assert_eq!(
            loopback_target("192.168.1.8:53".parse().expect("literal")),
            "192.168.1.8:53".parse::<SocketAddr>().expect("literal")
        );
    }

    #[test]
    fn any_http_status_line_is_read_as_the_proxy_answering() {
        // A redirect and a 404 are both the proxy answering. The probe asks
        // whether it answers at all, not whether it likes the request.
        assert_eq!(http_status(b"HTTP/1.1 301 Moved Permanently\r\n\r\n"), Some(301));
        assert_eq!(http_status(b"HTTP/1.0 404 Not Found\r\n\r\n"), Some(404));
        assert_eq!(http_status(b"HTTP/1.1 200 OK\r\n"), Some(200));
    }

    #[test]
    fn a_reply_that_is_not_http_is_not_a_status() {
        // The "port is open, wrong program" case — which is a fault, and must
        // not be read as a pass because bytes arrived.
        assert_eq!(http_status(b""), None);
        assert_eq!(http_status(b"SSH-2.0-OpenSSH_9.6\r\n"), None);
        assert_eq!(http_status(b"HTTP/2 200\r\n"), None);
        assert_eq!(http_status(b"HTTP/1.1 not-a-number\r\n"), None);
    }

    #[test]
    fn a_tls_handshake_or_an_alert_both_prove_a_tls_server_is_there() {
        // The probe offers no key share, so a correct TLS 1.3 server replies
        // with a HelloRetryRequest and a fussier one replies with an alert.
        // Reading only the first as "serving" would report a healthy proxy dead.
        assert_eq!(classify_tls_reply(&[0x16, 0x03, 0x03, 0x00, 0x7a]), TlsReply::Handshake);
        assert_eq!(classify_tls_reply(&[0x15, 0x03, 0x03, 0x00, 0x02]), TlsReply::Alert);
    }

    #[test]
    fn silence_and_a_plaintext_reply_are_both_not_serving() {
        assert_eq!(classify_tls_reply(&[]), TlsReply::Nothing);
        assert_eq!(classify_tls_reply(b"HTTP/1.1 400 Bad Request\r\n"), TlsReply::NotTls);
        // A first byte that looks like a handshake but no record behind it.
        assert_eq!(classify_tls_reply(&[0x16, 0x03]), TlsReply::NotTls);
        // Right length, wrong version family.
        assert_eq!(classify_tls_reply(&[0x16, 0x02, 0x00, 0x00, 0x01]), TlsReply::NotTls);
    }

    #[test]
    fn the_client_hello_is_a_well_formed_record_whose_lengths_agree() {
        let hello = client_hello("example.com");
        assert_eq!(hello.first(), Some(&0x16), "a handshake record");
        let record_length =
            u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(record_length, hello.len() - 5, "the record length covers the handshake");
        assert_eq!(hello.get(5), Some(&0x01), "the handshake is a ClientHello");
        let body_length =
            ((hello[6] as usize) << 16) | ((hello[7] as usize) << 8) | hello[8] as usize;
        assert_eq!(body_length, hello.len() - 9, "the handshake length covers the body");
    }

    #[test]
    fn the_client_hello_carries_the_name_it_was_asked_for() {
        let hello = client_hello("rockywearsahat.com");
        assert!(
            hello.windows(18).any(|window| window == b"rockywearsahat.com"),
            "the SNI name is on the wire"
        );
    }

    #[test]
    fn an_address_literal_is_never_put_in_sni() {
        // RFC 6066 forbids a literal in SNI and rustls refuses the hello
        // outright, which would make the probe report a healthy proxy dead on
        // any deployment whose first site domain is an IP.
        let hello = client_hello("192.168.1.8");
        assert!(
            !hello.windows(11).any(|window| window == b"192.168.1.8"),
            "an address literal must be left out rather than sent"
        );
        // Still a valid record: the rest of the hello does not depend on SNI.
        assert_eq!(hello.first(), Some(&0x16));
        assert_eq!(u16::from_be_bytes([hello[3], hello[4]]) as usize, hello.len() - 5);
    }

    #[test]
    fn only_an_outright_no_is_something_a_repair_may_act_on() {
        // Restarting a service because a probe could not reach it is how a
        // health check becomes the outage it was written to prevent.
        assert!(Serving::No.is_fault());
        assert!(!Serving::Yes.is_fault());
        assert!(!Serving::Untestable.is_fault());
        assert!(!Serving::NotDeclared.is_fault());
    }

    #[test]
    fn dns_is_the_one_component_a_repair_can_restart_from_here() {
        // The in-process/out-of-process split is what decides whether a repair
        // is possible at all; see `converge`'s module documentation.
        assert!(!Component::Dns.in_process());
        for component in [Component::Http, Component::Https, Component::ControlApi] {
            assert!(component.in_process(), "{}", component.label());
        }
    }

    /// The smallest config that parses, with every bind pointed at loopback
    /// ports the caller chooses.
    fn config(http: u16, https: u16, admin: u16) -> Config {
        use selfhost_config::{AcmeEnvironment, Firewall, Node, Role, Server};
        Config {
            version: 1,
            server: Server {
                http_bind: format!("127.0.0.1:{http}"),
                https_bind: format!("127.0.0.1:{https}"),
                acme_email: "a@b.com".into(),
                acme: AcmeEnvironment::SelfSigned,
                data_dir: std::path::PathBuf::from("./data"),
                admin_bind: format!("127.0.0.1:{admin}"),
                firewall: Firewall::default(),
            },
            nodes: vec![Node { name: "home".into(), role: Role::Owner, mesh_ip: None }],
            sites: Vec::new(),
            dns: None,
            mail: None,
            self_update: None,
            shares: Vec::new(),
            desktop: None,
            mesh: None,
            vpn: Vec::new(),
        }
    }

    /// A one-shot loopback server that answers every connection with `reply`.
    ///
    /// Returns the port it is on. The task ends with the test, and it accepts
    /// exactly the connections it is asked for, so nothing is left listening.
    async fn answering_with(reply: &'static [u8], connections: usize) -> u16 {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("an ephemeral loopback port");
        let port = listener.local_addr().expect("a bound address").port();
        tokio::spawn(async move {
            for _ in 0..connections {
                let Ok((mut stream, _)) = listener.accept().await else { return };
                // The request is read before the reply is written. A server that
                // closes with unread bytes in its receive buffer sends a reset
                // rather than a clean close, which is a fixture artefact and not
                // a thing being tested.
                let mut discard = [0u8; 1024];
                let _ = stream.read(&mut discard).await;
                let _ = stream.write_all(reply).await;
                let _ = stream.shutdown().await;
            }
        });
        port
    }

    #[tokio::test]
    async fn a_proxy_that_answers_any_http_status_is_serving() {
        // A redirect to HTTPS is what the real proxy answers `GET /` on :80
        // with, and it is a pass: the question is whether it answers.
        let port = answering_with(b"HTTP/1.1 301 Moved Permanently\r\nLocation: /\r\n\r\n", 1).await;
        let probe = probe_http(&config(port, 1, 2)).await;
        assert_eq!(probe.serving, Serving::Yes, "{}", probe.detail);
        assert!(probe.detail.contains("301"), "{}", probe.detail);
    }

    #[tokio::test]
    async fn an_open_port_running_something_else_is_not_serving() {
        // The failure a liveness check cannot see: the port is open, something
        // accepted, and it is not the proxy.
        let port = answering_with(b"SSH-2.0-OpenSSH_9.6\r\n", 1).await;
        let probe = probe_http(&config(port, 1, 2)).await;
        assert_eq!(probe.serving, Serving::No, "{}", probe.detail);
        assert!(probe.detail.contains("did not answer with an HTTP status line"), "{}", probe.detail);
    }

    #[tokio::test]
    async fn a_port_that_accepts_and_says_nothing_is_not_serving() {
        // Precisely the case a TCP connect test passes and a functional probe
        // must not: the listener accepted, and no service is behind it.
        let port = answering_with(b"", 1).await;
        let probe = probe_https(&config(1, port, 2)).await;
        assert_eq!(probe.serving, Serving::No, "{}", probe.detail);
        assert!(probe.detail.contains("said nothing"), "{}", probe.detail);
    }

    #[tokio::test]
    async fn a_real_rustls_listener_answers_the_hand_built_client_hello() {
        // The riskiest thing in this module: a ClientHello assembled by hand
        // here has to be good enough that the actual TLS implementation this
        // project serves 443 with replies to it. If it were not, the probe would
        // report a perfectly healthy proxy dead — and would do it on every box
        // at once. So this runs the probe against a real rustls server built by
        // `selfhost_proxy`, not against a fixture.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let directory = std::env::temp_dir()
            .join(format!("selfhost-health-tls-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("a temporary directory");
        let store = selfhost_proxy::CertificateStore::open(&directory).expect("a certificate store");
        let (chain, key) =
            store.load_or_generate_self_signed("probe.example", &[]).expect("a self-signed pair");
        let server = selfhost_proxy::server_config(chain, key).expect("a server configuration");
        let acceptor = tokio_rustls::TlsAcceptor::from(server);

        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("an ephemeral loopback port");
        let port = listener.local_addr().expect("a bound address").port();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                // The handshake will not complete — the hello offers no key
                // share on purpose — so whatever this returns is fine. What
                // matters is that rustls wrote a record before giving up.
                let _ = acceptor.accept(stream).await;
            }
        });

        let probe = probe_https(&config(1, port, 2)).await;
        let _ = std::fs::remove_dir_all(&directory);
        assert_eq!(
            probe.serving,
            Serving::Yes,
            "rustls must answer this hello with a TLS record: {}",
            probe.detail
        );
    }

    #[tokio::test]
    async fn the_control_api_answering_200_grades_the_rest_of_the_pass() {
        // `/api/health` answers 200 unconditionally and without a credential,
        // which is why it is the probe whose answer decides whether the others'
        // silence is a fault or a laptop.
        let port = answering_with(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"ok\":true}", 1).await;
        let probe = probe_control_api(&config(1, 2, port)).await;
        assert_eq!(probe.serving, Serving::Yes, "{}", probe.detail);
    }

    #[tokio::test]
    async fn nothing_running_anywhere_reports_untestable_rather_than_broken() {
        // A development tree with no daemon is not a deployment that has failed.
        // Three red lines on a laptop is how a health check teaches its reader
        // to ignore it.
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("an ephemeral loopback port");
        let closed = listener.local_addr().expect("a bound address").port();
        drop(listener);

        let probes =
            probe_all(&config(closed, closed, closed), std::path::Path::new(".")).await;
        assert_eq!(probes.len(), Component::ALL.len());
        for probe in &probes {
            assert!(
                !probe.serving.is_fault(),
                "{} must not be a fault when nothing is running: {}",
                probe.component.label(),
                probe.detail
            );
        }
    }

    /// One ordinary website, of the shape `selfhost init` writes and the shape
    /// the overwhelming majority of deployments have: a registrable name, served
    /// over HTTP, with its DNS hosted at a registrar.
    fn ordinary_site() -> selfhost_config::Site {
        selfhost_config::Site {
            name: "hello".into(),
            domains: vec!["example.com".into()],
            static_root: Some(std::path::PathBuf::from("./sites/hello")),
            spa: false,
            app_paths: Vec::new(),
            instances: Vec::new(),
            health: selfhost_config::Health::default(),
            canonical_redirect: true,
            allowed_cidrs: Vec::new(),
            console: false,
        }
    }

    /// A loopback port with nothing behind it, for the probes that have to be
    /// asked a question and get silence.
    async fn closed_port() -> u16 {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("an ephemeral loopback port");
        let port = listener.local_addr().expect("a bound address").port();
        drop(listener);
        port
    }

    #[test]
    fn claiming_a_site_name_is_not_declaring_that_this_box_is_a_nameserver() {
        // The defect this test exists for: `served_origins` derives zones from
        // site and mail domains, so *every* deployment with a name looked like
        // an authoritative nameserver. It is not a declaration — it is a list of
        // names somebody else's registrar probably serves.
        let mut config = config(1, 2, 3);
        config.sites = vec![ordinary_site()];
        assert!(
            !crate::lan_dns::served_origins(&config).is_empty(),
            "the site does claim a registrable name — that is what made the guess look right"
        );
        assert_eq!(dns_duty(&config, None), DnsDuty::NotDeclared);
    }

    #[test]
    fn either_signal_alone_declares_dns_and_neither_is_sufficient_by_itself() {
        // Both shapes genuinely serve DNS and they say so in different places.
        // Reading only one of them is how this was got wrong in both directions:
        // `[dns]` alone would have reported "nothing to check" on the production
        // box during the outage, and the site set alone reports every ordinary
        // deployment as a broken nameserver.
        let mut with_section = config(1, 2, 3);
        with_section.dns = Some(selfhost_config::Dns {
            bind: "0.0.0.0:53".into(),
            secondaries: Vec::new(),
            dynamic_ip: false,
            lan_ip: None,
            zones: Vec::new(),
        });
        assert!(matches!(dns_duty(&with_section, None), DnsDuty::Declared(_)));

        // The production shape: no section at all, and a separate registration.
        let mut production = config(1, 2, 3);
        production.sites = vec![ordinary_site()];
        assert!(matches!(
            dns_duty(&production, Some(crate::service_install::LAN_DNS_TASK_NAME)),
            DnsDuty::Declared(_)
        ));
    }

    #[tokio::test]
    async fn a_deployment_that_never_declared_dns_is_not_asked_about_it() {
        // The whole fix, at the probe. An ordinary site and no declaration must
        // not produce a question, because a "no" to a question nobody asked for
        // is what burned three repair attempts on a healthy deployment.
        let mut config = config(1, 2, 3);
        config.sites = vec![ordinary_site()];

        let probe = probe_dns_declared(&config, None).await;
        assert_eq!(probe.serving, Serving::NotDeclared, "{}", probe.detail);
        assert!(!probe.serving.is_fault(), "and therefore nothing to repair");
        // The silence has to be explainable, or a deployment that *should* be
        // serving DNS learns nothing from a line that says "not declared".
        assert!(probe.detail.contains("[dns] section"), "{}", probe.detail);
        assert!(
            probe.detail.contains(crate::service_install::LAN_DNS_TASK_NAME),
            "{}",
            probe.detail
        );
    }

    #[tokio::test]
    async fn a_deployment_that_does_declare_dns_and_is_silent_is_still_a_fault() {
        // The half the fix must not blind. A `[dns]` section is a promise to
        // serve `:53`; a nameserver that is not answering is the original
        // outage, and it has to stay red.
        let mut config = config(1, 2, 3);
        config.sites = vec![ordinary_site()];
        config.dns = Some(selfhost_config::Dns {
            bind: format!("127.0.0.1:{}", closed_port().await),
            secondaries: Vec::new(),
            dynamic_ip: false,
            lan_ip: None,
            zones: Vec::new(),
        });

        let probe = probe_dns_declared(&config, None).await;
        assert_eq!(probe.serving, Serving::No, "{}", probe.detail);
        assert!(probe.serving.is_fault());
        assert!(probe.target.starts_with("SOA example.com @"), "{}", probe.target);
        // The declaration travels into the detail, which is the text the repair
        // ledger and the escalation carry. "Why does supervision think DNS is
        // this box's job" is the first question a `NOT SERVING` line raises, and
        // an operator should not have to go and read the config to answer it.
        assert!(probe.detail.contains("[dns] section"), "{}", probe.detail);
    }

    #[tokio::test]
    async fn the_production_shape_has_no_dns_section_and_is_probed_anyway() {
        // ALEX-DESKTOP: no `[dns]` section, DNS served by the separately
        // registered `selfhost-lan-dns` task. A narrowing that read only the
        // config would have made this box — the one machine the whole module was
        // written for — the one shape nothing checks.
        let mut config = config(1, 2, 3);
        config.sites = vec![ordinary_site()];

        let probe =
            probe_dns_declared(&config, Some(crate::service_install::LAN_DNS_TASK_NAME)).await;
        assert_ne!(probe.serving, Serving::NotDeclared, "{}", probe.detail);
        assert!(
            probe.target.starts_with("SOA example.com @"),
            "a real SOA query was sent: {}",
            probe.target
        );
    }

    #[tokio::test]
    async fn a_deployment_that_serves_dns_for_no_zone_has_nothing_to_be_asked() {
        // Declared, and no question to put to it. Untestable rather than a
        // fault: restarting a nameserver does not give it a zone.
        let mut config = config(1, 2, 3);
        config.dns = Some(selfhost_config::Dns {
            bind: "0.0.0.0:53".into(),
            secondaries: Vec::new(),
            dynamic_ip: false,
            lan_ip: None,
            zones: Vec::new(),
        });
        let probe = probe_dns_declared(&config, None).await;
        assert_eq!(probe.serving, Serving::Untestable, "{}", probe.detail);
        assert!(!probe.serving.is_fault());
    }

    #[tokio::test]
    async fn an_ordinary_deployment_with_nothing_running_has_no_faults_at_all() {
        // `selfhost health` exits non-zero for a fault, so this is the exit code
        // as well as the report: a laptop with one website and no daemon must
        // read clean. It did not before the fix — `dns` read NOT SERVING here.
        let closed = closed_port().await;
        let mut config = config(closed, closed, closed);
        config.sites = vec![ordinary_site()];

        let probes = probe_all(&config, std::path::Path::new(".")).await;
        for probe in &probes {
            assert!(
                !probe.serving.is_fault(),
                "{} must not be a fault on an ordinary deployment: {}",
                probe.component.label(),
                probe.detail
            );
        }
        // Not asserted as `NotDeclared` here, deliberately: this pass asks the
        // *machine* whether it has a `selfhost-lan-dns` registration, and on the
        // production box it does — where a probe is the right answer. The
        // declaration test itself is asserted exactly, without a machine, in
        // `a_deployment_that_never_declared_dns_is_not_asked_about_it`.
        let dns = probes
            .iter()
            .find(|probe| probe.component == Component::Dns)
            .expect("dns is probed on every pass");
        assert!(!dns.serving.is_fault(), "{}", dns.detail);
    }

    #[test]
    fn every_component_is_in_the_all_list_exactly_once() {
        // `ALL` is what a convergence pass walks; a component missing from it is
        // one nothing ever probes, which is the shape of the original outage.
        let mut all = Component::ALL.to_vec();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), Component::ALL.len());
    }
}
