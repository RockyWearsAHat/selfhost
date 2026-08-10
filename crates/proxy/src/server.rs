//! The accept loop and request dispatch.
//!
//! One connection is one task. A request is read, matched to a site by its
//! `Host`, and then either served from disk or forwarded to a healthy instance.
//!
//! # Known limitation, stated rather than hidden
//!
//! A forwarded response is relayed verbatim and the client connection is closed
//! afterwards. This is correct — the upstream's own framing reaches the client
//! untouched, so there is no way for the two to disagree — but it costs a
//! connection setup per proxied request. Static responses keep keep-alive.
//! Parsing upstream response framing so proxied connections can also be reused
//! is tracked in `docs/roadmap.md`.

use crate::files::{self, Resolution};
use crate::health;
use crate::upgrade;
use crate::upstream::Pool;
use selfhost_config::{Config, Site};
use selfhost_http::{Body, Method, ParseError, Request, Response, Status};
use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// How long a connection may stay idle between requests before it is closed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Path prefix reserved for ACME HTTP-01 challenges.
///
/// Never routed to a site, and never redirected to HTTPS.
pub const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

/// Path prefix reserved for a hosting provider's push notification.
///
/// Reached at a normal site hostname — a webhook needs a real, TLS-terminated
/// URL to call, the same one the site itself answers on — but never routed to
/// that site's own content. The trailing segment names the service whose git
/// watch should be checked now rather than at its next poll; see
/// [`serve_webhook`] for the rest.
pub const WEBHOOK_PREFIX: &str = "/.selfhost/webhook/";

/// The most request-body bytes read for a webhook.
///
/// A push payload is a few kilobytes; this is generous headroom without being
/// the same 25 MiB an app upload is allowed, since nothing here is relayed
/// onward byte for byte the way `forward` does — every byte is held in memory
/// to compute a signature over it.
const WEBHOOK_MAX_BODY: u64 = 1024 * 1024;

/// How long the request head may take to arrive.
///
/// Bounds a slowloris: a client dribbling one byte at a time cannot hold a
/// connection open indefinitely.
const HEAD_TIMEOUT: Duration = Duration::from_secs(15);

/// The largest request body relayed to an app upstream.
///
/// `forward()` streams a declared `Content-Length` straight through with no
/// cap of its own — fine while every site was static and nothing ever called
/// it, but the first app instance makes this reachable, and an unbounded
/// relay is an unbounded memory/bandwidth commitment on the upstream's
/// behalf for whatever a caller claims to be sending. 25 MiB comfortably
/// covers a JSON API body or a modest upload; anything larger is refused
/// before the upstream connection even opens.
const MAX_FORWARD_BODY_BYTES: u64 = 25 * 1024 * 1024;

/// The largest request body relayed to the admin API for a console site.
///
/// The admin API caps its own reads at 64 KiB, so a larger body is refused
/// here — before the loopback connection even opens — rather than relayed
/// only for the admin API to refuse it anyway.
const CONSOLE_API_MAX_BODY: u64 = 64 * 1024;

/// Numbers the upgraded streams this process has carried, so the line logged
/// when a stream opens and the line logged when it closes can be tied together.
///
/// A stream lives for minutes or hours, and the per-request access log prints
/// once, after dispatch returns. Without an identifier the two lines about the
/// same connection are an hour apart with any number of ordinary requests in
/// between, which is the same as having no record at all. Monotonic and process-
/// local; it names a stream in this log and nothing else, so wrapping after
/// 2^64 streams would be harmless even if it were reachable.
static NEXT_STREAM_ID: AtomicU64 = AtomicU64::new(1);

/// Everything the proxy needs to serve one site.
#[derive(Debug)]
pub struct SiteRuntime {
    /// The site's declared configuration.
    pub site: Site,
    /// Instances to balance across. Empty for a purely static site.
    pub pool: Arc<Pool>,
    /// Absolute static root, or `None` when the site has no files.
    pub static_root: Option<PathBuf>,
}

/// The running proxy.
#[derive(Debug)]
pub struct Server {
    /// Hostname to site. Behind a lock so [`Server::reload`] can swap in a
    /// freshly built table without rebinding the listeners that hold this
    /// `Server` — a request mid-flight keeps the `Arc<SiteRuntime>` it already
    /// resolved, and the next lookup simply sees the new table.
    routes: RwLock<BTreeMap<String, Arc<SiteRuntime>>>,
    /// Sites in declaration order, for health tasks and diagnostics.
    sites: RwLock<Vec<Arc<SiteRuntime>>>,
    /// Where ACME HTTP-01 tokens are written, when issuance is configured.
    ///
    /// Derived from `data_dir`, which a reload never changes — recomputing it
    /// on every reload would be pure churn for a value that cannot differ.
    acme_challenge_dir: Option<PathBuf>,
    /// The daemon's data directory — where its service catalogue and admin
    /// token live. Same reasoning as `acme_challenge_dir`: fixed at startup,
    /// not re-derived on a reload.
    data_dir: PathBuf,
    /// Where the loopback admin API listens, if `admin_bind` parses.
    ///
    /// `None` rather than a startup failure when it does not: a malformed
    /// `admin_bind` is the daemon's problem to refuse at its own startup, and
    /// the proxy's only use for this is the webhook relay — better to serve
    /// every site and answer a webhook with 502 than to refuse to start.
    admin_bind: Option<SocketAddr>,
}

impl Server {
    /// Builds the routing table from a validated config.
    ///
    /// `project_dir` is where relative static roots resolve from.
    pub fn build(config: &Config, project_dir: &std::path::Path) -> Self {
        let (routes, sites) = Self::routing(config, project_dir);
        let data_dir = project_dir.join(&config.server.data_dir);
        Self {
            routes: RwLock::new(routes),
            sites: RwLock::new(sites),
            acme_challenge_dir: Some(data_dir.join("acme-challenges")),
            data_dir,
            admin_bind: config.server.admin_bind.parse().ok(),
        }
    }

    /// Rebuilds the routing table from a freshly reloaded config and swaps it
    /// in, live.
    ///
    /// Safe for sites that only serve static content or an already-running
    /// pool of instances — routing takes effect on the next request with no
    /// dropped connection. **Not** a full reconciliation: a site *added* by a
    /// reload with its own instances gets routed immediately but its health
    /// probe only starts on the next full restart, since
    /// [`Server::spawn_health_tasks`] runs once at startup. Every site
    /// deployed today is static-only, so this boundary costs nothing yet; it
    /// is named here rather than silently assumed away.
    pub fn reload(&self, config: &Config, project_dir: &std::path::Path) {
        let (routes, sites) = Self::routing(config, project_dir);
        *self.routes.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = routes;
        *self.sites.write().unwrap_or_else(|poisoned| poisoned.into_inner()) = sites;
    }

    /// The routing table and site list a config builds, shared by
    /// [`Server::build`] and [`Server::reload`] so the two can never diverge.
    fn routing(
        config: &Config,
        project_dir: &std::path::Path,
    ) -> (BTreeMap<String, Arc<SiteRuntime>>, Vec<Arc<SiteRuntime>>) {
        let mut routes = BTreeMap::new();
        let mut sites = Vec::new();

        for site in &config.sites {
            let addresses: Vec<String> = site
                .instances
                .iter()
                .filter_map(|instance| config.instance_address(instance))
                .collect();

            let runtime = Arc::new(SiteRuntime {
                site: site.clone(),
                pool: Arc::new(Pool::new(addresses)),
                static_root: site.static_root.as_ref().map(|root| project_dir.join(root)),
            });

            for domain in &site.domains {
                routes.insert(domain.to_ascii_lowercase(), Arc::clone(&runtime));
            }
            sites.push(runtime);
        }

        (routes, sites)
    }

    /// Looks up the site serving a hostname.
    pub fn route(&self, host: &str) -> Option<Arc<SiteRuntime>> {
        self.routes
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&host.to_ascii_lowercase())
            .cloned()
    }

    /// Every site, in declaration order.
    pub fn sites(&self) -> Vec<Arc<SiteRuntime>> {
        self.sites.read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }

    /// Spawns one health-probe task per site that has instances.
    ///
    /// Called once at startup, not re-run by [`Server::reload`] — see its doc
    /// for what that means for a site added later with its own instances.
    pub fn spawn_health_tasks(&self) {
        for runtime in self.sites.read().unwrap_or_else(|poisoned| poisoned.into_inner()).iter() {
            if runtime.pool.is_empty() {
                continue;
            }
            tokio::spawn(health::run(
                runtime.site.name.clone(),
                Arc::clone(&runtime.pool),
                runtime.site.health.clone(),
            ));
        }
    }
}

/// Accepts cleartext connections and serves them.
///
/// Cleartext exists to redirect to HTTPS and, later, to answer ACME challenges.
pub async fn serve_http(listener: TcpListener, server: Arc<Server>) -> io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, server, peer, false).await {
                if error.kind() != io::ErrorKind::UnexpectedEof {
                    eprintln!("[proxy] {peer}: {error}");
                }
            }
        });
    }
}

/// Accepts TLS connections and serves them.
pub async fn serve_https(
    listener: TcpListener,
    server: Arc<Server>,
    tls: Arc<rustls::ServerConfig>,
) -> io::Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    loop {
        let (stream, peer) = listener.accept().await?;
        let server = Arc::clone(&server);
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            // A failed handshake is routine — port scanners, plain HTTP sent to
            // 443, clients that reject a self-signed certificate — so it is not
            // worth a log line each time.
            let Ok(stream) = acceptor.accept(stream).await else {
                return;
            };
            if let Err(error) = handle_connection(stream, server, peer, true).await {
                if error.kind() != io::ErrorKind::UnexpectedEof {
                    eprintln!("[proxy] {peer}: {error}");
                }
            }
        });
    }
}

/// Serves requests on one connection until it closes.
async fn handle_connection<S>(
    mut stream: S,
    server: Arc<Server>,
    peer: SocketAddr,
    is_tls: bool,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffer = Vec::with_capacity(8 * 1024);

    loop {
        let parsed = match read_head(&mut stream, &mut buffer).await {
            Ok(Some(parsed)) => parsed,
            // The peer closed cleanly between requests.
            Ok(None) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                // A malformed or ambiguously framed request. Answer 400 and
                // close rather than dropping the connection silently: the
                // sender deserves to know it was refused, and a bare close is
                // indistinguishable from a network fault while debugging.
                //
                // The connection is never reused after this. Once the framing
                // is untrustworthy there is no way to know where the next
                // request begins, and guessing is the smuggling bug itself.
                eprintln!("[proxy] {peer}: refused — {error}");
                let _ = write_response(&mut stream, Response::error_page(Status::BAD_REQUEST), false).await;
                return Ok(());
            }
            Err(error) => return Err(error),
        };

        let request = parsed.request;
        let consumed = parsed.consumed;
        buffer.drain(..consumed);

        let keep_alive = request.wants_keep_alive();
        let started = std::time::Instant::now();
        let host = request.host().unwrap_or_default();
        let method = request.method.as_str().to_owned();
        let target = request.target.clone();

        let outcome =
            dispatch(&server, &request, peer, is_tls, &mut buffer, &mut stream, keep_alive).await?;

        // One line per request. Without this there is no way to answer "is
        // anyone actually reaching the site" except by guessing.
        //
        // The target is logged through `upgrade::loggable_target`, which
        // withholds the remainder of a share path or a stream path. On a NAS the
        // file name is more sensitive than the fact of the transfer, and an
        // operator reading a log should not incidentally learn the name of every
        // document in the household.
        let ms = started.elapsed().as_millis();
        let scheme = if is_tls { "https" } else { "http" };
        let logged = upgrade::loggable_target(&target);
        match outcome {
            // A stream already announced itself when it opened; this line closes
            // the record and the elapsed time is the stream's whole life, not a
            // request's latency, so it is not written as one.
            Outcome::Upgraded(id) => {
                eprintln!("[stream] {id} {peer} {host} closed after {ms}ms");
            }
            _ => eprintln!("[access] {peer} {scheme} {host} {method} {logged} {ms}ms"),
        }

        if !keep_alive || outcome != Outcome::Reusable {
            return Ok(());
        }
    }
}

/// Whether the connection may be reused after a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The connection may serve another request.
    Reusable,
    /// The connection must be closed.
    MustClose,
    /// The connection stopped speaking HTTP and carried an upgraded stream,
    /// which has now ended. Its identifier ties the closing log line to the one
    /// written when it opened.
    ///
    /// Distinct from [`Outcome::MustClose`] rather than folded into it because
    /// the two mean different things to a reader of the log: a `MustClose` is a
    /// request that was answered and whose connection cannot be reused, and this
    /// is a connection that stopped being HTTP altogether. Both end the loop.
    Upgraded(u64),
}

/// Reads one request head, returning `None` on a clean close.
async fn read_head<S>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
) -> io::Result<Option<selfhost_http::Parsed>>
where
    S: AsyncRead + Unpin,
{
    // A buffer that already holds a pipelined request needs no read at all.
    if !buffer.is_empty() {
        match Request::parse(buffer) {
            Ok(parsed) => return Ok(Some(parsed)),
            Err(ParseError::Incomplete) => {}
            Err(error) => return Err(io::Error::new(io::ErrorKind::InvalidData, error.to_string())),
        }
    }

    let deadline = if buffer.is_empty() { IDLE_TIMEOUT } else { HEAD_TIMEOUT };
    let mut chunk = [0_u8; 8 * 1024];

    loop {
        let read = match tokio::time::timeout(deadline, stream.read(&mut chunk)).await {
            Ok(result) => result?,
            Err(_) => return Ok(None),
        };

        if read == 0 {
            return Ok(None);
        }
        buffer.extend_from_slice(&chunk[..read]);

        match Request::parse(buffer) {
            Ok(parsed) => return Ok(Some(parsed)),
            Err(ParseError::Incomplete) => continue,
            Err(error) => return Err(io::Error::new(io::ErrorKind::InvalidData, error.to_string())),
        }
    }
}

/// Routes a request and writes its response.
///
/// `leftover` is whatever `read_head` already pulled off the socket beyond the
/// request's header block — a small body arrives in the same TCP read as its
/// headers far more often than not. It must be consulted before either
/// [`serve_webhook`] or [`forward`] reads a body, or those bytes are stranded
/// in this function's caller forever: the socket itself has nothing left to
/// give until the peer sends more, which a client that already sent its whole
/// request and is waiting on a response never does.
async fn dispatch<S>(
    server: &Server,
    request: &Request,
    peer: SocketAddr,
    is_tls: bool,
    leftover: &mut Vec<u8>,
    stream: &mut S,
    keep_alive: bool,
) -> io::Result<Outcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(host) = request.host() else {
        write_response(stream, Response::error_page(Status::BAD_REQUEST), false).await?;
        return Ok(Outcome::MustClose);
    };

    // The ACME HTTP-01 exemption, ahead of even the Host lookup. The
    // certificate authority fetches over plain HTTP, does not follow redirects
    // to a host whose certificate it has not issued yet, and — decisively —
    // asks for hostnames that are certificates without being sites at all (the
    // mail client-autoconfig hosts), which the routing table has never heard
    // of. Possession of the token is the entire proof; which Host header rode
    // along proves nothing, and a random token 404s byte-identically to an
    // unknown Host, so this discloses nothing the uniform 404 was hiding.
    if !is_tls && request.path().starts_with(ACME_CHALLENGE_PREFIX) {
        return serve_acme_challenge(server, request, stream, keep_alive).await;
    }

    let Some(runtime) = server.route(&host) else {
        // An unknown Host is answered with 404 rather than a default site, so a
        // stray DNS record cannot quietly expose one site under another's name.
        write_response(stream, Response::error_page(Status::NOT_FOUND), keep_alive).await?;
        return Ok(Outcome::Reusable);
    };

    // Checked ahead of everything below, over both schemes, for the same
    // reason the ACME exemption is: a platform concern that happens to be
    // reached at a site's own hostname, not that site's content.
    if request.path().starts_with(WEBHOOK_PREFIX) {
        return serve_webhook(server, request, leftover, stream).await;
    }

    // Cleartext exists to send callers to HTTPS: everything below the ACME
    // exemption above upgrades the scheme rather than serving content.
    if !is_tls {
        // A gated site refuses non-permitted peers on cleartext too, with the
        // same 404 as an unknown Host — otherwise the 308-upgrade answered here
        // would distinguish "gated site exists" from "not hosted", an existence
        // oracle on the plain-HTTP port. The ACME exemption above still runs
        // first, so certificate issuance is unaffected.
        if !runtime.site.permits(peer.ip()) {
            write_response(stream, Response::error_page(Status::NOT_FOUND), keep_alive).await?;
            return Ok(Outcome::Reusable);
        }
        // Upgrade the scheme on the host the caller actually used, not the site's
        // canonical name: redirecting http://<addr> to https://<canonical> would
        // send every visitor to the first configured domain (e.g. "localhost") and
        // present a certificate for the wrong name. Canonicalisation, if enabled,
        // happens on the HTTPS side below where the certificate already matches.
        let target = format!("https://{host}{}", request.target);
        let response = Response::redirect(Status::PERMANENT_REDIRECT, &target)
            .unwrap_or_else(|_| Response::error_page(Status::BAD_REQUEST));
        write_response(stream, response, keep_alive).await?;
        return Ok(Outcome::Reusable);
    }

    // The per-site source-address gate. Everything above stays reachable from
    // anywhere on purpose — a deploy webhook must be callable by its hosting
    // provider, an ACME challenge by the certificate authority, and the
    // cleartext 308 upgrade discloses nothing — but everything below serves a
    // site's real content, and a gated site refuses peers outside its
    // `allowed_cidrs` before any of it runs. The refusal is byte-identical to
    // the unknown-`Host` 404 above, so a probe cannot tell "gated" apart from
    // "not hosted here".
    if !runtime.site.permits(peer.ip()) {
        eprintln!("[proxy] {peer}: denied — source address not permitted for {host}");
        write_response(stream, Response::error_page(Status::NOT_FOUND), keep_alive).await?;
        return Ok(Outcome::Reusable);
    }

    let canonical = runtime.site.canonical();
    if runtime.site.canonical_redirect && host != canonical {
        let target = format!("https://{canonical}{}", request.target);
        let response = Response::redirect(Status::MOVED_PERMANENTLY, &target)
            .unwrap_or_else(|_| Response::error_page(Status::BAD_REQUEST));
        write_response(stream, response, keep_alive).await?;
        return Ok(Outcome::Reusable);
    }

    // The built-in console: `/api/*` goes to the loopback admin API, and
    // everything else falls through to the SPA in `static_root`. Validation
    // guarantees a console site has no instances, so `routes_to_app` below
    // can never claim these paths first.
    if runtime.site.console && is_console_api(request.path()) {
        return relay_console_api(server, request, peer, leftover, stream).await;
    }

    if runtime.site.routes_to_app(request.path()) {
        return forward(&runtime, request, peer, leftover, stream).await;
    }

    serve_static(&runtime, request, stream, keep_alive).await
}

/// Serves an ACME HTTP-01 challenge token.
///
/// Tokens are written to `<data_dir>/acme-challenges/<token>` by the ACME client
/// and removed once the order completes. Serving them here rather than through
/// the normal static path keeps them off every site's document root — a token
/// is proof of domain control and has no business being reachable as ordinary
/// site content.
async fn serve_acme_challenge<S>(
    server: &Server,
    request: &Request,
    stream: &mut S,
    keep_alive: bool,
) -> io::Result<Outcome>
where
    S: AsyncWrite + Unpin,
{
    let token = &request.path()[ACME_CHALLENGE_PREFIX.len()..];

    // The token is attacker-supplied, so it must be a single plain filename.
    // Without this a challenge fetch would be a directory traversal.
    let safe = !token.is_empty()
        && token.len() <= 128
        && token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');

    let response = match (safe, &server.acme_challenge_dir) {
        (true, Some(directory)) => match tokio::fs::read(directory.join(token)).await {
            Ok(bytes) => Response::bytes(Status::OK, "text/plain", bytes)
                .unwrap_or_else(|_| Response::error_page(Status::INTERNAL_SERVER_ERROR)),
            Err(_) => Response::error_page(Status::NOT_FOUND),
        },
        _ => Response::error_page(Status::NOT_FOUND),
    };

    write_response(stream, response, keep_alive).await?;
    Ok(Outcome::Reusable)
}

/// Reads exactly `length` body bytes, taking whatever `read_head` already
/// buffered before falling through to the socket for the rest.
///
/// A body that arrives in the same TCP segment as its headers — true of most
/// small requests — is sitting in `leftover` by the time a handler gets here;
/// `stream` alone no longer has it. Skipping `leftover` and reading `stream`
/// directly hangs on exactly that common case, waiting for bytes the peer
/// already sent and will not send again.
async fn take_body<S>(leftover: &mut Vec<u8>, stream: &mut S, length: u64) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut body = Vec::with_capacity(length as usize);
    let from_leftover = leftover.len().min(length as usize);
    body.extend(leftover.drain(..from_leftover));
    let remaining = length - from_leftover as u64;
    if remaining > 0 {
        let mut limited = stream.take(remaining);
        limited.read_to_end(&mut body).await?;
    }
    Ok(body)
}

/// Relays exactly `length` body bytes to `upstream`, same rule as [`take_body`]:
/// whatever `read_head` already buffered goes first, the socket makes up the
/// rest.
async fn relay_body<S>(
    leftover: &mut Vec<u8>,
    stream: &mut S,
    upstream: &mut TcpStream,
    length: u64,
) -> io::Result<()>
where
    S: AsyncRead + Unpin,
{
    let from_leftover = leftover.len().min(length as usize);
    if from_leftover > 0 {
        let chunk: Vec<u8> = leftover.drain(..from_leftover).collect();
        upstream.write_all(&chunk).await?;
    }
    let remaining = length - from_leftover as u64;
    if remaining > 0 {
        let mut limited = stream.take(remaining);
        tokio::io::copy(&mut limited, upstream).await?;
    }
    Ok(())
}

/// Verifies a push notification and, on a match, relays it into an immediate
/// deployment.
///
/// The proxy holds no webhook secrets of its own. [`selfhost_admin::Store`]
/// reads the daemon's service catalogue fresh from disk on every call rather
/// than caching it, so a secret set or rotated through the console or a
/// config edit takes effect on the very next push, with nothing to restart —
/// the same "no dropped connection, no restart" property [`Server::reload`]
/// already gives the routing table. A verified push is relayed to the
/// loopback admin API exactly as an operator's own `POST
/// /api/services/<name>/deploy` would be: this route changes nothing about
/// that API's own authorisation, it is simply a caller of it, using the same
/// bearer token every other caller needs.
async fn serve_webhook<S>(
    server: &Server,
    request: &Request,
    leftover: &mut Vec<u8>,
    stream: &mut S,
) -> io::Result<Outcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if request.method != Method::Post {
        write_response(stream, Response::error_page(Status::NOT_FOUND), false).await?;
        return Ok(Outcome::MustClose);
    }

    let name = &request.path()[WEBHOOK_PREFIX.len()..];
    if !valid_service_name(name) {
        write_response(stream, Response::error_page(Status::NOT_FOUND), false).await?;
        return Ok(Outcome::MustClose);
    }

    let length = match request.body_length() {
        Ok(selfhost_http::BodyLength::Fixed(length)) if length > 0 && length <= WEBHOOK_MAX_BODY => {
            length
        }
        _ => {
            write_response(stream, Response::error_page(Status::BAD_REQUEST), false).await?;
            return Ok(Outcome::MustClose);
        }
    };

    let body = take_body(leftover, stream, length).await?;

    // No such service, no active watch, or no secret configured for one all
    // answer the same way: a probe against this path learns nothing about
    // which services are real.
    let Some(secret) = lookup_webhook_secret(server, name) else {
        write_response(stream, Response::error_page(Status::NOT_FOUND), false).await?;
        return Ok(Outcome::MustClose);
    };

    let presented = request.headers.get_str("x-hub-signature-256").and_then(|value| value.strip_prefix("sha256="));
    let verified = presented.is_some_and(|hex| signature_matches(&secret, &body, hex));
    if !verified {
        // Byte-identical to the no-secret 404 above: a bad signature must not be
        // distinguishable from an absent service, or the difference enumerates
        // which service names are real and secret-protected.
        write_response(stream, Response::error_page(Status::NOT_FOUND), false).await?;
        return Ok(Outcome::MustClose);
    }

    let response = match relay_deploy(server, name).await {
        Ok(status) => Response::bytes(status, "application/json", b"{\"accepted\":true}".to_vec())
            .unwrap_or_else(|_| Response::error_page(Status::INTERNAL_SERVER_ERROR)),
        Err(error) => {
            eprintln!("[proxy] webhook for {name}: could not reach the admin API: {error}");
            Response::error_page(Status::BAD_GATEWAY)
        }
    };
    write_response(stream, response, false).await?;
    Ok(Outcome::MustClose)
}

/// Whether a webhook's trailing path segment is safe to use as a service name.
///
/// This is attacker-supplied input on the public listener, reaching a raw HTTP
/// request line ([`relay_deploy`]) as well as a catalogue lookup — the same
/// character allow-list [`serve_acme_challenge`] applies to its token, and for
/// the same reason: anything outside it could inject a header or a second
/// request line rather than naming a service.
fn valid_service_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The webhook secret configured for a service's active git watch, if any.
///
/// Reads `services.toml` directly rather than going through the admin API: the
/// daemon is the only *writer* of that file, but nothing stops another local
/// reader, and asking the admin API to hand back a secret over HTTP would be a
/// second, worse way to learn it. `known_nodes: &[]` matches how the admin API
/// itself reads the catalogue for an update — this is a lookup, not the
/// validation a fresh install runs.
fn lookup_webhook_secret(server: &Server, name: &str) -> Option<String> {
    let store = selfhost_admin::Store::new(&server.data_dir);
    let catalog = store.load(&[]).ok()?;
    let spec = catalog.services.iter().find(|spec| spec.name == name)?;
    let watch = spec.active_watch()?;
    watch.webhook_secret.clone()
}

/// Whether `presented` (lowercase hex) is the HMAC-SHA256 of `body` under
/// `secret`.
///
/// `ring::hmac::verify` both computes the tag and compares it in constant
/// time — the same property [`Token::matches`](selfhost_admin::Token::matches)
/// gives the admin API's own bearer token, reused here via `ring` rather than
/// hand-rolled, for the reason every other constant-time comparison in this
/// project is not hand-rolled either.
fn signature_matches(secret: &str, body: &[u8], presented: &str) -> bool {
    let Some(tag) = hex_decode(presented) else { return false };
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    ring::hmac::verify(&key, body, &tag).is_ok()
}

/// Decodes a lowercase hex string into bytes, refusing anything malformed
/// rather than skipping the bytes that do not parse.
fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok()).collect()
}

/// Calls the loopback admin API's deploy route for one service, returning the
/// status it answered.
///
/// One connection, `Connection: close`, mirroring [`forward`] and the ACME
/// transport: this fires rarely enough that keep-alive would only add state.
async fn relay_deploy(server: &Server, name: &str) -> io::Result<Status> {
    let admin_bind = server
        .admin_bind
        .ok_or_else(|| io::Error::other("admin_bind is not configured or does not parse"))?;
    let token = selfhost_admin::Token::load_or_create(&server.data_dir)?;

    let mut upstream = TcpStream::connect(admin_bind).await?;
    let head = format!(
        "POST /api/services/{name}/deploy HTTP/1.1\r\n\
         Host: 127.0.0.1\r\n\
         Authorization: Bearer {}\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n",
        token.as_str(),
    );
    upstream.write_all(head.as_bytes()).await?;
    upstream.flush().await?;
    read_status(&mut upstream).await
}

/// Reads only as much of a response as its head, to learn its status.
///
/// Mirrors the shape of `crates/acme/src/transport.rs`'s response reader —
/// same [`IncomingResponse`](selfhost_http::IncomingResponse) parser, applied
/// to a plaintext loopback stream rather than a TLS one — but this caller has
/// no use for the body, only the status the admin API answered with.
async fn read_status<R>(stream: &mut R) -> io::Result<Status>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        match selfhost_http::IncomingResponse::parse(&buffer) {
            Ok(parsed) => return Ok(parsed.response.status),
            Err(selfhost_http::ParseError::Incomplete) => {}
            Err(error) => return Err(io::Error::new(io::ErrorKind::InvalidData, error.to_string())),
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the admin API closed the connection before a response head arrived",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

/// Whether a console site's path belongs to the admin API rather than the SPA.
///
/// `/api` itself and anything under `/api/` — but never `/apidocs`, which is
/// an ordinary SPA path.
fn is_console_api(path: &str) -> bool {
    path == "/api" || path.starts_with("/api/")
}

/// Relays a console site's `/api/*` request to the loopback admin API and
/// returns that API's response verbatim.
///
/// Unlike [`relay_deploy`], which mints its own bearer-token request, this
/// relay carries the *caller's* credentials — `Cookie`, `Authorization`, and
/// `X-Selfhost-Console` pass through untouched, so the admin API applies its
/// own authorisation exactly as if the browser had reached it directly. The
/// response — status, headers including any `Set-Cookie`, and body — is
/// copied back byte for byte, the same verbatim-relay rule [`forward`]
/// follows, and the connection closes afterwards for the same reason.
///
/// # The upgrade path
///
/// A request that [`upgrade::looks_like_upgrade`] recognises takes a second
/// route through the same function: no body is read, four extra fields are
/// relayed for that one request, and the answer's head is *parsed* rather than
/// copied blind, because the proxy has to know whether the daemon agreed to
/// leave HTTP. If it did not — a `401` for a missing ticket, a `404` for a path
/// that is not a stream — the fallback is byte-for-byte what this function did
/// before upgrades existed, including the bytes already read while looking for
/// the head. If it did, the proxy stops framing anything and moves opaque bytes
/// in both directions until one side finishes.
///
/// Everything about this path is *below* `Site::permits(peer.ip())` in
/// [`dispatch`], which is where it must stay: the source-address gate runs on
/// the TCP peer before the console branch is reached at all, and no upgrade
/// widens it, exempts anything from it, or is reachable without passing it.
async fn relay_console_api<S>(
    server: &Server,
    request: &Request,
    peer: SocketAddr,
    leftover: &mut Vec<u8>,
    stream: &mut S,
) -> io::Result<Outcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let is_upgrade = upgrade::looks_like_upgrade(request);

    // Framing is settled before anything else. The admin API rejects chunked
    // bodies, and buffering an unbounded chunked stream here just to measure
    // it would defeat the cap — so only a fixed length (or no body) proceeds,
    // and an oversized one is refused before the loopback connection opens.
    //
    // A handshake carries no body, and one that declares a non-empty body is
    // refused outright rather than relayed with its length forced to zero. The
    // bytes of such a body would otherwise sit unread until after the `101` and
    // then be handed to the daemon's frame parser as if the peer had sent them
    // as frames — a message whose meaning depends on which layer counted it,
    // which is the family of ambiguity this codebase refuses on principle.
    let length = match request.body_length() {
        Ok(selfhost_http::BodyLength::None) => 0,
        Ok(selfhost_http::BodyLength::Fixed(0)) => 0,
        Ok(selfhost_http::BodyLength::Fixed(_)) if is_upgrade => {
            write_response(stream, Response::error_page(Status::BAD_REQUEST), false).await?;
            return Ok(Outcome::MustClose);
        }
        Ok(selfhost_http::BodyLength::Fixed(length)) if length <= CONSOLE_API_MAX_BODY => length,
        Ok(selfhost_http::BodyLength::Fixed(_)) => {
            write_response(stream, Response::error_page(Status::CONTENT_TOO_LARGE), false).await?;
            return Ok(Outcome::MustClose);
        }
        Ok(selfhost_http::BodyLength::Chunked) | Err(_) => {
            write_response(stream, Response::error_page(Status::BAD_REQUEST), false).await?;
            return Ok(Outcome::MustClose);
        }
    };

    // On the upgrade path nothing is taken out of `leftover`: whatever the
    // client sent after its head is the first bytes of the new protocol, and it
    // belongs to the upstream once the switch is agreed.
    let body = if is_upgrade { Vec::new() } else { take_body(leftover, stream, length).await? };

    let Some(admin_bind) = server.admin_bind else {
        eprintln!("[proxy] console relay: admin_bind is not configured or does not parse");
        write_response(stream, Response::error_page(Status::BAD_GATEWAY), false).await?;
        return Ok(Outcome::MustClose);
    };
    let mut upstream = match TcpStream::connect(admin_bind).await {
        Ok(connection) => connection,
        Err(error) => {
            eprintln!("[proxy] console relay: could not reach the admin API: {error}");
            write_response(stream, Response::error_page(Status::BAD_GATEWAY), false).await?;
            return Ok(Outcome::MustClose);
        }
    };

    let mut head = Vec::new();
    head.extend_from_slice(request.method.as_str().as_bytes());
    head.push(b' ');
    head.extend_from_slice(request.target.as_bytes());
    head.extend_from_slice(b" HTTP/1.1\r\nHost: 127.0.0.1\r\n");

    // Only what the admin API acts on is passed along: the body's type and the
    // caller's credentials, widened for this one request by the handshake's own
    // fields when it is a handshake. Everything else — including any framing or
    // hop-by-hop field the client sent — is dropped and re-derived below. See
    // `upgrade::RELAYED_FOR_UPGRADE` for what the widening does and does not
    // include, and why.
    for field in request.headers.iter() {
        let name = field.name();
        if upgrade::is_relayed(name, is_upgrade) {
            head.extend_from_slice(name.as_bytes());
            head.extend_from_slice(b": ");
            head.extend_from_slice(field.value());
            head.extend_from_slice(b"\r\n");
        }
    }

    head.extend_from_slice(format!("X-Forwarded-For: {}\r\n", peer.ip()).as_bytes());
    if is_upgrade {
        // No `Content-Length`: there is no body, and the two hop-by-hop lines
        // are the proxy's own statement about this hop rather than an echo of
        // the client's.
        head.extend_from_slice(upgrade::UPGRADE_REQUEST_LINES);
        head.extend_from_slice(b"\r\n");
    } else {
        head.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        head.extend_from_slice(b"Connection: close\r\n\r\n");
    }

    upstream.write_all(&head).await?;
    upstream.write_all(&body).await?;
    upstream.flush().await?;

    if is_upgrade {
        return splice_upgrade(&mut upstream, leftover, stream, peer, request).await;
    }

    // The admin API's response is relayed byte for byte, so its own framing
    // reaches the client untouched and the two cannot disagree.
    tokio::io::copy(&mut upstream, stream).await?;
    stream.flush().await?;
    Ok(Outcome::MustClose)
}

/// Reads the admin API's answer to a handshake and either hands the connection
/// over or falls back to relaying an ordinary response.
///
/// # The stranding trap, in the other direction
///
/// [`dispatch`]'s doc explains why a handler must consult `leftover` before
/// reading a body: bytes that arrived in the same TCP segment as the head are
/// already in this process, and the socket has nothing more to give until the
/// peer sends again — which a peer waiting for an answer never does. An upgrade
/// puts the same trap on both sides of the splice at once, and both are fatal
/// rather than slow, because after this point nobody is waiting on a timeout.
///
/// - Whatever the *client* already sent past its head is the first bytes of the
///   new protocol. It is pushed to the upstream before the copy begins;
///   otherwise the daemon waits forever for a message the browser has already
///   delivered.
/// - Whatever the *upstream* sent past its own head — the daemon writes its
///   first frame immediately, and it very often lands in the same read as the
///   `101` — is written to the client with the head. It is inside `buffered`,
///   so writing that buffer whole is what handles it; slicing it to `consumed`
///   would drop the daemon's first message on the floor.
///
/// Neither hazard is hypothetical and neither shows up under a hand test on an
/// idle link, which is exactly why both are written down here.
async fn splice_upgrade<S>(
    upstream: &mut TcpStream,
    leftover: &mut Vec<u8>,
    stream: &mut S,
    peer: SocketAddr,
    request: &Request,
) -> io::Result<Outcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffered = Vec::with_capacity(1024);
    let parsed = match read_response_head(upstream, &mut buffered).await {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("[proxy] console relay: the admin API's answer was unreadable: {error}");
            write_response(stream, Response::error_page(Status::BAD_GATEWAY), false).await?;
            return Ok(Outcome::MustClose);
        }
    };

    if !upgrade::is_switching_protocols(&parsed.response) {
        // The daemon refused, or the path is not a stream at all. From here on
        // this is an ordinary relayed response: the bytes already read go out
        // first, then the rest of the connection, which together are exactly the
        // byte sequence the unmodified `tokio::io::copy` would have produced.
        stream.write_all(&buffered).await?;
        tokio::io::copy(upstream, stream).await?;
        stream.flush().await?;
        return Ok(Outcome::MustClose);
    }

    // The head goes out exactly as the daemon wrote it. Not through
    // `write_response`: that path derives framing from a body this response does
    // not have, and `apply_security_headers` would splice `X-Frame-Options` and
    // friends into a `101` — fields that mean nothing to a protocol that is no
    // longer HTTP, in a message a browser checks strictly before it hands the
    // socket to the page.
    stream.write_all(&buffered).await?;
    stream.flush().await?;

    if !leftover.is_empty() {
        upstream.write_all(leftover).await?;
        upstream.flush().await?;
        leftover.clear();
    }

    let id = NEXT_STREAM_ID.fetch_add(1, Ordering::Relaxed);
    // Logged here rather than only at close: the access line for this request is
    // printed once, after this function returns, which for a stream is hours
    // later. Without this line an open stream is invisible in the log.
    eprintln!("[stream] {id} {peer} open {target}", target = upgrade::loggable_target(&request.target));

    // From here the proxy interprets nothing. Every ceiling and every deadline
    // that applies to these bytes belongs to `crates/ws` in the daemon; this
    // process is a pipe, which is the whole point of putting the frame parser
    // anywhere but here. `crates/ws` is linked — the upgrade predicate comes
    // from it — so its frame codec is one `use` away, and reaching for it to
    // count messages or enforce a cap on this line would move a parser over
    // stranger-chosen bytes into the process that owns 80, 443, mail and the
    // certificate store, under `panic = "abort"`. See `crate::upgrade`.
    let moved = tokio::io::copy_bidirectional(stream, upstream).await;
    if let Err(error) = moved {
        // Ordinary at the end of a stream — a browser tab closing produces a
        // reset as often as a clean shutdown — so it is reported at the same
        // weight as the close itself rather than as a fault.
        eprintln!("[stream] {id} ended: {error}");
    }
    Ok(Outcome::Upgraded(id))
}

/// Reads exactly as much of the upstream's answer as its head, keeping every
/// byte read in `buffered` so the caller can forward them.
///
/// Bounded by [`HEAD_TIMEOUT`] for the same reason the request head is: until
/// the head has been read the proxy is holding a client connection open on the
/// promise of an answer, and a daemon that has stopped answering must not be
/// able to accumulate those. Once the head is read the deadline stops, exactly
/// as it does for a request — after that, liveness is the stream layer's job and
/// is enforced by pings the proxy never sees.
async fn read_response_head(
    upstream: &mut TcpStream,
    buffered: &mut Vec<u8>,
) -> io::Result<selfhost_http::ParsedResponse> {
    let mut chunk = [0u8; 1024];
    loop {
        match selfhost_http::IncomingResponse::parse(buffered) {
            Ok(parsed) => return Ok(parsed),
            Err(ParseError::Incomplete) => {}
            Err(error) => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, error.to_string()));
            }
        }
        let read = match tokio::time::timeout(HEAD_TIMEOUT, upstream.read(&mut chunk)).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the admin API did not answer the handshake in time",
                ));
            }
        };
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the admin API closed the connection before a response head arrived",
            ));
        }
        buffered.extend_from_slice(&chunk[..read]);
    }
}

/// The same request target with a slash appended to its path.
///
/// Rebuilt from the raw target rather than from the decoded path, so percent
/// escapes and the query string reach the browser exactly as they arrived.
fn with_trailing_slash(target: &str) -> String {
    match target.split_once('?') {
        Some((path, query)) => format!("{path}/?{query}"),
        None => format!("{target}/"),
    }
}

/// Serves a request from the site's static root.
async fn serve_static<S>(
    runtime: &SiteRuntime,
    request: &Request,
    stream: &mut S,
    keep_alive: bool,
) -> io::Result<Outcome>
where
    S: AsyncWrite + Unpin,
{
    let Some(root) = runtime.static_root.as_ref() else {
        write_response(stream, Response::error_page(Status::NOT_FOUND), keep_alive).await?;
        return Ok(Outcome::Reusable);
    };

    if !files::method_allowed(&request.method) {
        let mut response = Response::error_page(Status::METHOD_NOT_ALLOWED);
        let _ = response.headers.set("Allow", "GET, HEAD");
        write_response(stream, response, keep_alive).await?;
        return Ok(Outcome::Reusable);
    }

    let resolution = files::resolve(root, request.path(), runtime.site.spa);
    let path = match resolution {
        Resolution::File(path) => path,
        // A directory asked for without its trailing slash is answered where it
        // actually lives, so the browser's base URL — and every relative link on
        // the page — resolves inside the directory rather than beside it.
        Resolution::TrailingSlash => {
            let response = Response::redirect(Status::MOVED_PERMANENTLY, &with_trailing_slash(&request.target))
                .unwrap_or_else(|_| Response::error_page(Status::BAD_REQUEST));
            write_response(stream, response, keep_alive).await?;
            return Ok(Outcome::Reusable);
        }
        // A traversal attempt is answered 404, not 403: confirming that
        // something exists outside the root is information the caller has not
        // earned.
        Resolution::Rejected | Resolution::NotFound => {
            write_response(stream, Response::error_page(Status::NOT_FOUND), keep_alive).await?;
            return Ok(Outcome::Reusable);
        }
    };

    let mut file = tokio::fs::File::open(&path).await?;
    let metadata = file.metadata().await?;
    let built = files::build_response(request, &path, metadata.len(), metadata.modified().ok());

    let mut head = Vec::new();
    built
        .response
        .write_head(&mut head, keep_alive)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    apply_security_headers(&mut head);
    stream.write_all(&head).await?;

    if built.length > 0 {
        use tokio::io::AsyncSeekExt;
        file.seek(io::SeekFrom::Start(built.offset)).await?;
        let mut limited = file.take(built.length);
        tokio::io::copy(&mut limited, stream).await?;
    }

    stream.flush().await?;
    Ok(Outcome::Reusable)
}

/// Forwards a request to a healthy instance and relays the answer.
async fn forward<S>(
    runtime: &SiteRuntime,
    request: &Request,
    peer: SocketAddr,
    leftover: &mut Vec<u8>,
    stream: &mut S,
) -> io::Result<Outcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if let Ok(selfhost_http::BodyLength::Fixed(length)) = request.body_length()
        && length > MAX_FORWARD_BODY_BYTES
    {
        // Refused before the upstream connection opens: relaying first and
        // discovering the size only once the transfer is under way would have
        // already spent the upstream's time and bandwidth on a request this
        // proxy was always going to reject.
        write_response(stream, Response::error_page(Status::CONTENT_TOO_LARGE), false).await?;
        return Ok(Outcome::MustClose);
    }

    let Some(lease) = runtime.pool.acquire() else {
        // Every instance is out of rotation. Answering 502 is the point of
        // health checking — forwarding to a node known to be dead is worse.
        write_response(stream, Response::error_page(Status::BAD_GATEWAY), false).await?;
        return Ok(Outcome::MustClose);
    };

    let mut upstream = match TcpStream::connect(lease.address()).await {
        Ok(connection) => connection,
        Err(_) => {
            write_response(stream, Response::error_page(Status::BAD_GATEWAY), false).await?;
            return Ok(Outcome::MustClose);
        }
    };

    let mut head = Vec::new();
    head.extend_from_slice(request.method.as_str().as_bytes());
    head.push(b' ');
    head.extend_from_slice(request.target.as_bytes());
    head.extend_from_slice(b" HTTP/1.1\r\n");

    for field in request.headers.iter() {
        let name = field.name();
        // Hop-by-hop fields describe this connection, not the message, and must
        // not be passed along. Framing fields are re-derived below.
        if is_hop_by_hop(name) || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        head.extend_from_slice(name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(field.value());
        head.extend_from_slice(b"\r\n");
    }

    head.extend_from_slice(format!("X-Forwarded-For: {}\r\n", peer.ip()).as_bytes());
    head.extend_from_slice(b"X-Forwarded-Proto: https\r\n");
    head.extend_from_slice(b"Connection: close\r\n");
    if let Some(length) = request.headers.get_str("content-length") {
        head.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
    }
    head.extend_from_slice(b"\r\n");

    upstream.write_all(&head).await?;

    // Relay a request body, if the framing said there is one.
    if let Ok(selfhost_http::BodyLength::Fixed(length)) = request.body_length() {
        if length > 0 {
            relay_body(leftover, stream, &mut upstream, length).await?;
        }
    }
    upstream.flush().await?;

    // The upstream's response is relayed byte for byte, so its own framing
    // reaches the client untouched and the two cannot disagree.
    tokio::io::copy(&mut upstream, stream).await?;
    stream.flush().await?;

    Ok(Outcome::MustClose)
}

/// Whether a header describes the connection rather than the message.
fn is_hop_by_hop(name: &str) -> bool {
    const HOP_BY_HOP: [&str; 8] = [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ];
    HOP_BY_HOP.iter().any(|candidate| name.eq_ignore_ascii_case(candidate))
}

/// Appends the headers every response carries, just before the blank line.
///
/// `nosniff` is what makes the `application/octet-stream` fallback in [`crate::mime`]
/// a real defence rather than a label.
fn apply_security_headers(head: &mut Vec<u8>) {
    const EXTRA: &[u8] = b"X-Content-Type-Options: nosniff\r\n\
X-Frame-Options: DENY\r\n\
Referrer-Policy: strict-origin-when-cross-origin\r\n";

    // The head ends with the blank line; the extra fields go before it.
    if head.ends_with(b"\r\n\r\n") {
        let insert_at = head.len() - 2;
        head.splice(insert_at..insert_at, EXTRA.iter().copied());
    }
}

/// Writes a complete in-memory response.
async fn write_response<S>(stream: &mut S, response: Response, keep_alive: bool) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut out = Vec::new();
    response
        .write_head(&mut out, keep_alive)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    apply_security_headers(&mut out);

    if let Body::Bytes(bytes) = &response.body {
        out.extend_from_slice(bytes);
    }

    stream.write_all(&out).await?;
    stream.flush().await
}

/// Whether a method may carry a request body that must be relayed.
pub fn method_may_have_body(method: &Method) -> bool {
    matches!(method, Method::Post | Method::Put | Method::Patch | Method::Delete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_config::{AcmeEnvironment, Health, Instance, Node, Role, Server as ServerConfig, Site};

    fn config_with(sites: Vec<Site>) -> Config {
        Config {
            version: 1,
            server: ServerConfig {
                http_bind: "0.0.0.0:0".into(),
                https_bind: "0.0.0.0:0".into(),
                acme_email: "a@b.com".into(),
                acme: AcmeEnvironment::SelfSigned,
                data_dir: PathBuf::from("./data"),
                admin_bind: "127.0.0.1:9191".into(),
                firewall: selfhost_config::Firewall::default(),
            },
            nodes: vec![Node { name: "home".into(), role: Role::Owner, mesh_ip: None }],
            sites,
            dns: None,
            mail: None,
            namecheap_ddns: vec![],
            registrar: None,
            self_update: None,
            shares: vec![],
            desktop: None,
            mesh: None,
        }
    }

    fn site(name: &str, domains: &[&str]) -> Site {
        Site {
            name: name.into(),
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

    #[test]
    fn routes_every_alias_to_the_same_site() {
        let config = config_with(vec![site("levelup", &["example.com", "www.example.com"])]);
        let server = Server::build(&config, std::path::Path::new("/tmp"));

        assert!(server.route("example.com").is_some());
        assert!(server.route("www.example.com").is_some());
        // Host matching is case-insensitive.
        assert!(server.route("EXAMPLE.com").is_some());
        assert!(server.route("other.com").is_none());
    }

    #[test]
    fn reload_takes_effect_immediately_and_drops_what_the_new_config_removed() {
        let config = config_with(vec![site("levelup", &["example.com"])]);
        let server = Server::build(&config, std::path::Path::new("/tmp"));
        assert!(server.route("example.com").is_some());
        assert!(server.route("added.example.com").is_none());

        let reconfigured =
            config_with(vec![site("added", &["added.example.com"])]);
        server.reload(&reconfigured, std::path::Path::new("/tmp"));

        assert!(server.route("added.example.com").is_some(), "the new site is routed");
        assert!(server.route("example.com").is_none(), "the removed site is gone");
    }

    #[test]
    fn reload_leaves_a_route_resolved_before_it_unaffected() {
        // A request that already resolved its site holds an owned `Arc`, not a
        // borrow of the table — a reload racing a request in flight must not
        // invalidate what that request is already holding.
        let config = config_with(vec![site("levelup", &["example.com"])]);
        let server = Server::build(&config, std::path::Path::new("/tmp"));
        let held = server.route("example.com").expect("routed before reload");

        server.reload(&config_with(vec![]), std::path::Path::new("/tmp"));

        assert_eq!(held.site.name, "levelup");
    }

    #[test]
    fn instances_become_pool_upstreams() {
        let mut with_app = site("api", &["api.example.com"]);
        with_app.instances =
            vec![Instance { node: "home".into(), port: 5050 }, Instance { node: "home".into(), port: 5051 }];

        let config = config_with(vec![with_app]);
        let server = Server::build(&config, std::path::Path::new("/tmp"));
        let runtime = server.route("api.example.com").unwrap();

        assert_eq!(runtime.pool.upstreams().len(), 2);
        assert_eq!(runtime.pool.healthy_count(), 2);
        assert_eq!(runtime.pool.upstreams()[0].address(), "127.0.0.1:5050");
    }

    #[test]
    fn a_static_site_has_an_empty_pool() {
        let config = config_with(vec![site("static", &["example.com"])]);
        let server = Server::build(&config, std::path::Path::new("/tmp"));
        assert!(server.route("example.com").unwrap().pool.is_empty());
    }

    #[test]
    fn hop_by_hop_headers_are_not_forwarded() {
        // Passing these along would let a client's connection semantics leak
        // into the proxy-to-upstream connection.
        for name in ["Connection", "keep-alive", "Transfer-Encoding", "Upgrade", "TE"] {
            assert!(is_hop_by_hop(name), "{name} should be hop-by-hop");
        }
        for name in ["Host", "Content-Type", "Authorization", "Cookie", "Range"] {
            assert!(!is_hop_by_hop(name), "{name} should be forwarded");
        }
    }

    #[test]
    fn security_headers_land_before_the_blank_line() {
        let mut head = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec();
        apply_security_headers(&mut head);
        let text = String::from_utf8(head).unwrap();

        assert!(text.contains("X-Content-Type-Options: nosniff\r\n"));
        assert!(text.contains("X-Frame-Options: DENY\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
        // Exactly one blank line, or the body would start in the wrong place.
        assert_eq!(text.matches("\r\n\r\n").count(), 1);
    }

    #[test]
    fn the_acme_challenge_prefix_is_the_well_known_path() {
        // The CA fetches this over plain HTTP and does not follow a redirect to
        // a host whose certificate it has not issued yet.
        assert_eq!(ACME_CHALLENGE_PREFIX, "/.well-known/acme-challenge/");
        assert!("/.well-known/acme-challenge/tok3n".starts_with(ACME_CHALLENGE_PREFIX));
        assert!(!"/.well-known/other".starts_with(ACME_CHALLENGE_PREFIX));
    }

    #[test]
    fn challenge_tokens_are_confined_to_plain_filenames() {
        // The token comes off the wire, so without this a challenge fetch would
        // be a directory traversal into the data directory.
        let acceptable = |token: &str| {
            !token.is_empty()
                && token.len() <= 128
                && token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        };

        assert!(acceptable("LoqXcYV8q1ONbJls-hint7"));
        assert!(!acceptable("../../../etc/passwd"));
        assert!(!acceptable("a/b"));
        assert!(!acceptable("a.b"));
        assert!(!acceptable(""));
        assert!(!acceptable(&"a".repeat(129)));
    }

    #[test]
    fn the_challenge_directory_sits_under_the_data_directory() {
        // Tokens are proof of domain control and must not be reachable as
        // ordinary site content.
        let config = config_with(vec![site("levelup", &["example.com"])]);
        let server = Server::build(&config, std::path::Path::new("/srv/project"));
        assert_eq!(
            server.acme_challenge_dir.as_deref(),
            Some(std::path::Path::new("/srv/project/./data/acme-challenges"))
        );
    }

    #[test]
    fn static_roots_resolve_against_the_project_directory() {
        let config = config_with(vec![site("levelup", &["example.com"])]);
        let server = Server::build(&config, std::path::Path::new("/srv/project"));
        let root = server.route("example.com").unwrap().static_root.clone().unwrap();
        assert_eq!(root, PathBuf::from("/srv/project/public"));
    }

    #[tokio::test]
    async fn a_request_body_over_the_cap_is_refused_before_any_upstream_connection() {
        // The pool address is deliberately one nothing listens on: if `forward`
        // tried to connect before checking the size, this test would hang or
        // report the wrong status instead of the 413 the cap is for.
        let runtime = SiteRuntime {
            site: site("api", &["api.example.com"]),
            pool: Arc::new(Pool::new(vec!["127.0.0.1:1".into()])),
            static_root: None,
        };

        let oversized = MAX_FORWARD_BODY_BYTES + 1;
        let head = format!(
            "POST /upload HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: {oversized}\r\n\r\n"
        );
        let request = Request::parse(head.as_bytes()).expect("a well-formed head parses").request;

        let (mut client, mut upstream_side) = tokio::io::duplex(4096);
        let outcome = forward(
            &runtime,
            &request,
            "127.0.0.1:1".parse().unwrap(),
            &mut Vec::new(),
            &mut upstream_side,
        )
        .await
        .expect("a refusal is not an I/O error");
        assert_eq!(outcome, Outcome::MustClose);
        drop(upstream_side);

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.expect("the refusal to read back");
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 413"), "{text}");
    }

    /// A site root holding the shape a static-site generator emits: a page as a
    /// sibling `.html` file, and a section as a directory with an index.
    fn static_site(label: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("selfhost-serve-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("docs")).unwrap();
        std::fs::write(root.join("index.html"), b"<h1>home</h1>").unwrap();
        std::fs::write(root.join("about.html"), b"<h1>about</h1>").unwrap();
        std::fs::write(root.join("docs/index.html"), b"<h1>docs</h1>").unwrap();
        root
    }

    /// Runs one GET through `serve_static` and returns the raw response.
    async fn get_static(root: PathBuf, target: &str) -> String {
        let runtime = SiteRuntime {
            site: site("pages", &["example.com"]),
            pool: Arc::new(Pool::new(vec![])),
            static_root: Some(root),
        };
        let raw = format!("GET {target} HTTP/1.1\r\nHost: example.com\r\n\r\n");
        let request = Request::parse(raw.as_bytes()).expect("a well-formed head parses").request;

        let (mut client, mut server_side) = tokio::io::duplex(8192);
        serve_static(&runtime, &request, &mut server_side, false)
            .await
            .expect("serving is not an I/O error");
        drop(server_side);

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.expect("the response to read back");
        String::from_utf8_lossy(&response).into_owned()
    }

    #[tokio::test]
    async fn a_clean_url_serves_the_page_instead_of_404ing() {
        // The bug this guards: `/about` is the link the site's own navigation
        // writes, and answering it 404 while `about.html` sits in the root
        // makes every internal link on the site dead.
        let response = get_static(static_site("clean"), "/about").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("<h1>about</h1>"), "{response}");
    }

    #[tokio::test]
    async fn a_section_without_its_slash_is_redirected_to_where_it_lives() {
        let response = get_static(static_site("slash"), "/docs?page=2").await;
        assert!(response.starts_with("HTTP/1.1 301"), "{response}");
        // The query survives, so the redirect does not silently drop state.
        assert!(response.contains("Location: /docs/?page=2"), "{response}");

        let followed = get_static(static_site("slash"), "/docs/").await;
        assert!(followed.contains("<h1>docs</h1>"), "{followed}");
    }

    #[tokio::test]
    async fn a_path_matching_nothing_is_still_404() {
        let response = get_static(static_site("miss"), "/nowhere").await;
        assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    }

    #[test]
    fn appending_a_slash_keeps_the_target_otherwise_byte_identical() {
        assert_eq!(with_trailing_slash("/docs"), "/docs/");
        assert_eq!(with_trailing_slash("/docs?page=2"), "/docs/?page=2");
        // Escapes are carried through untouched: re-encoding a decoded path
        // would be a second chance to get the encoding wrong.
        assert_eq!(with_trailing_slash("/a%20b"), "/a%20b/");
    }

    #[test]
    fn a_service_name_is_valid_only_within_the_same_shape_service_specs_already_require() {
        assert!(valid_service_name("levelup"));
        assert!(valid_service_name("level-up_2"));
        assert!(!valid_service_name(""));
        assert!(!valid_service_name(&"x".repeat(129)));
        // Characters that would reach the relayed request line as something
        // other than a path segment — a header injection, a second request.
        assert!(!valid_service_name("x\r\nHost: evil"));
        assert!(!valid_service_name("x/y"));
        assert!(!valid_service_name("x y"));
    }

    #[test]
    fn hex_decode_round_trips_and_refuses_malformed_input() {
        assert_eq!(hex_decode("00ff"), Some(vec![0x00, 0xff]));
        assert_eq!(hex_decode(""), Some(vec![]));
        assert_eq!(hex_decode("0"), None, "odd length");
        assert_eq!(hex_decode("zz"), None, "not hex");
    }

    #[test]
    fn a_signature_matches_only_the_exact_secret_and_body_it_was_made_for() {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"s3cret");
        let tag = ring::hmac::sign(&key, b"push payload");
        let presented = hex_encode(tag.as_ref());

        assert!(signature_matches("s3cret", b"push payload", &presented));
        assert!(!signature_matches("wrong-secret", b"push payload", &presented));
        assert!(!signature_matches("s3cret", b"tampered payload", &presented));
        assert!(!signature_matches("s3cret", b"push payload", "not-hex-at-all"));
    }

    /// Renders bytes as lowercase hex, for building test signatures.
    fn hex_encode(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    /// A scratch data directory this test owns, removed when dropped.
    struct ScratchDataDir(PathBuf);

    impl ScratchDataDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("selfhost-proxy-webhook-test-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("scratch data dir");
            Self(path)
        }
    }

    impl Drop for ScratchDataDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A `Server` whose `data_dir` is a scratch directory and whose one site
    /// answers `api.example.com`, so `server.route` (and the webhook check
    /// that runs after it in `dispatch`) both succeed.
    fn server_over(data_dir: &std::path::Path, admin_bind: &str) -> Server {
        let mut config = config_with(vec![site("api", &["api.example.com"])]);
        config.server.data_dir = PathBuf::from(".");
        config.server.admin_bind = admin_bind.to_owned();
        Server::build(&config, data_dir)
    }

    /// Writes a service whose git watch carries `secret`, into `dir`'s
    /// catalogue — the same file [`lookup_webhook_secret`] reads.
    async fn install_watched_service(dir: &std::path::Path, name: &str, secret: &str) {
        let mut spec = selfhost_config::ServiceSpec::new(name, "/bin/true");
        let mut watch =
            selfhost_config::GitWatch::new("https://example.com/repo.git", "checkouts/site");
        watch.webhook_secret = Some(secret.to_owned());
        spec.git = Some(watch);
        selfhost_admin::Store::new(dir).upsert(spec).await.expect("write the catalogue");
    }

    /// Sends `request` (whose declared body is `body`) through `serve_webhook`
    /// over an in-memory duplex and returns the response text.
    ///
    /// `body` is handed in as `leftover` rather than written onto the duplex:
    /// that is what `read_head` actually produces for a real connection — a
    /// small body arrives in the same read as its headers far more often than
    /// not — and it is the case that let a body-reading hang go undetected
    /// here before `serve_webhook` learned to consult `leftover` at all.
    async fn webhook_response(server: &Server, request: &Request, body: &[u8]) -> String {
        let (mut client, mut server_side) = tokio::io::duplex(8192);
        let mut leftover = body.to_vec();
        serve_webhook(server, request, &mut leftover, &mut server_side).await.expect("no I/O error");
        drop(server_side);
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.expect("read the response back");
        String::from_utf8_lossy(&response).into_owned()
    }

    /// A webhook request head plus the body it declares, parsed the way the
    /// connection loop would parse the head off a real socket.
    fn webhook_request(name: &str, body: &str, signature: Option<&str>) -> (Request, Vec<u8>) {
        let mut head = format!(
            "POST /.selfhost/webhook/{name} HTTP/1.1\r\nHost: api.example.com\r\n\
             Content-Length: {}\r\n",
            body.len()
        );
        if let Some(signature) = signature {
            head.push_str(&format!("X-Hub-Signature-256: sha256={signature}\r\n"));
        }
        head.push_str("\r\n");
        let request = Request::parse(head.as_bytes()).expect("a well-formed head parses").request;
        (request, body.as_bytes().to_vec())
    }

    #[tokio::test]
    async fn a_webhook_for_a_service_with_no_configured_secret_is_a_404() {
        let dir = ScratchDataDir::new("unconfigured");
        let server = server_over(&dir.0, "127.0.0.1:1");
        let (request, body) = webhook_request("levelup", "{}", Some("00"));

        let response = webhook_response(&server, &request, &body).await;
        assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    }

    #[tokio::test]
    async fn a_webhook_with_a_bad_signature_is_refused() {
        let dir = ScratchDataDir::new("bad-sig");
        install_watched_service(&dir.0, "levelup", "s3cret").await;
        let server = server_over(&dir.0, "127.0.0.1:1");

        let (request, body) = webhook_request("levelup", "{}", Some("00"));
        let response = webhook_response(&server, &request, &body).await;
        // 404, not 401: a bad signature is byte-identical to an absent service,
        // so the response cannot be used to enumerate real, secret-protected
        // service names.
        assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    }

    #[tokio::test]
    async fn a_webhook_with_no_signature_header_is_refused() {
        let dir = ScratchDataDir::new("no-sig");
        install_watched_service(&dir.0, "levelup", "s3cret").await;
        let server = server_over(&dir.0, "127.0.0.1:1");

        let (request, body) = webhook_request("levelup", "{}", None);
        let response = webhook_response(&server, &request, &body).await;
        // 404 for the same non-enumeration reason as the bad-signature case.
        assert!(response.starts_with("HTTP/1.1 404"), "{response}");
    }

    #[tokio::test]
    async fn a_correctly_signed_webhook_is_relayed_to_the_admin_api_and_echoes_its_status() {
        let dir = ScratchDataDir::new("relayed");
        install_watched_service(&dir.0, "levelup", "s3cret").await;
        selfhost_admin::Token::load_or_create(&dir.0).expect("plant a token to read back");

        // A stand-in admin API: accepts one connection, reads the request, and
        // answers 202 — enough to prove the relay carries the right method,
        // path, and bearer token, and that this route echoes back whatever
        // status the admin API gave.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind a fake admin port");
        let admin_bind = listener.local_addr().expect("a bound address");
        let accepted = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("one connection");
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 512];
            loop {
                let read = stream.read(&mut chunk).await.expect("read the relayed request");
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\n\r\n{}")
                .await
                .expect("answer the relay");
            stream.flush().await.expect("flush the answer");
            String::from_utf8_lossy(&buffer).into_owned()
        });

        let server = server_over(&dir.0, &admin_bind.to_string());
        let body = "{}";
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"s3cret");
        let signature = hex_encode(ring::hmac::sign(&key, body.as_bytes()).as_ref());
        let (request, body) = webhook_request("levelup", body, Some(&signature));

        let response = webhook_response(&server, &request, &body).await;
        assert!(response.starts_with("HTTP/1.1 202"), "{response}");

        let relayed = accepted.await.expect("the fake admin task did not panic");
        assert!(relayed.starts_with("POST /api/services/levelup/deploy HTTP/1.1"), "{relayed}");
        assert!(relayed.contains("Authorization: Bearer "), "{relayed}");
    }

    /// `site()` with the VPN network gate applied.
    fn gated_site(name: &str, domains: &[&str]) -> Site {
        let mut site = site(name, domains);
        site.allowed_cidrs = vec!["10.66.0.0/24".into()];
        site
    }

    /// Writes `public/index.html` under `dir`, so a site whose `static_root`
    /// is `./public` has a real file to serve.
    fn write_spa(dir: &std::path::Path) {
        let public = dir.join("public");
        std::fs::create_dir_all(&public).expect("public dir");
        std::fs::write(public.join("index.html"), b"<h1>console spa</h1>").expect("index.html");
    }

    /// Runs `dispatch` over an in-memory duplex and returns the raw response
    /// bytes.
    ///
    /// `body` is injected as `leftover`, exactly what `read_head` produces
    /// for a real connection — see [`webhook_response`] for why that shape,
    /// and not bytes written onto the duplex, is the one that catches
    /// body-reading hangs. The client's write half is shut before dispatch
    /// runs, so a handler that wrongly reads the socket for a body it was
    /// already handed sees EOF instead of hanging the test.
    async fn dispatch_bytes(
        server: &Server,
        head: &str,
        peer: &str,
        is_tls: bool,
        body: &[u8],
    ) -> Vec<u8> {
        let request = Request::parse(head.as_bytes()).expect("a well-formed head parses").request;
        let mut leftover = body.to_vec();
        let (mut client, mut server_side) = tokio::io::duplex(64 * 1024);
        client.shutdown().await.expect("close the client's write half");
        dispatch(
            server,
            &request,
            peer.parse().expect("a socket address"),
            is_tls,
            &mut leftover,
            &mut server_side,
            request.wants_keep_alive(),
        )
        .await
        .expect("no I/O error");
        drop(server_side);
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.expect("read the response back");
        response
    }

    #[test]
    fn console_api_paths_cover_api_and_below_but_not_lookalikes() {
        assert!(is_console_api("/api"));
        assert!(is_console_api("/api/session"));
        assert!(!is_console_api("/apidocs"), "an ordinary SPA path, not the admin API");
        assert!(!is_console_api("/"));
    }

    #[tokio::test]
    async fn a_gated_denial_is_byte_identical_to_the_unknown_host_404() {
        let dir = ScratchDataDir::new("gate-denial");
        write_spa(&dir.0);
        let config = config_with(vec![gated_site("console", &["console.example.com"])]);
        let server = Server::build(&config, &dir.0);

        let denied = dispatch_bytes(
            &server,
            "GET / HTTP/1.1\r\nHost: console.example.com\r\n\r\n",
            "203.0.113.9:5000",
            true,
            b"",
        )
        .await;
        let unknown = dispatch_bytes(
            &server,
            "GET / HTTP/1.1\r\nHost: not-hosted.example.com\r\n\r\n",
            "203.0.113.9:5000",
            true,
            b"",
        )
        .await;

        assert!(denied.starts_with(b"HTTP/1.1 404"), "{}", String::from_utf8_lossy(&denied));
        assert_eq!(
            denied, unknown,
            "a probe must not be able to tell a gated site from one not hosted here"
        );
    }

    #[tokio::test]
    async fn a_gated_site_serves_a_peer_inside_its_network() {
        let dir = ScratchDataDir::new("gate-allowed");
        write_spa(&dir.0);
        let config = config_with(vec![gated_site("console", &["console.example.com"])]);
        let server = Server::build(&config, &dir.0);

        let response = dispatch_bytes(
            &server,
            "GET / HTTP/1.1\r\nHost: console.example.com\r\n\r\n",
            "10.66.0.2:5000",
            true,
            b"",
        )
        .await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(text.contains("console spa"), "{text}");
    }

    #[tokio::test]
    async fn a_webhook_on_a_gated_site_stays_reachable_from_a_public_peer() {
        let dir = ScratchDataDir::new("gate-webhook");
        install_watched_service(&dir.0, "levelup", "s3cret").await;
        let mut config = config_with(vec![gated_site("api", &["api.example.com"])]);
        config.server.data_dir = PathBuf::from(".");
        config.server.admin_bind = "127.0.0.1:1".into();
        let server = Server::build(&config, &dir.0);

        // A *correctly* signed webhook from a public peer outside the gate. The
        // gate now answers a bad signature with the same 404 as a denied peer,
        // so reachability can no longer be proven by a 401. Instead: a valid
        // signature drives the handler to relay to the (dead) admin bind, which
        // yields 502 — reached only if the gate let the webhook path through.
        // A gate-denied request would have returned 404 before any relay.
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"s3cret");
        let signature = hex_encode(ring::hmac::sign(&key, b"{}").as_ref());
        let head = format!(
            "POST /.selfhost/webhook/levelup HTTP/1.1\r\nHost: api.example.com\r\n\
             Content-Length: 2\r\nX-Hub-Signature-256: sha256={signature}\r\n\r\n"
        );
        let response = dispatch_bytes(&server, &head, "203.0.113.9:5000", true, b"{}").await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 502"), "{text}");
    }

    #[tokio::test]
    async fn a_cleartext_acme_challenge_on_a_gated_host_stays_reachable() {
        let dir = ScratchDataDir::new("gate-acme");
        let mut config = config_with(vec![gated_site("console", &["console.example.com"])]);
        config.server.data_dir = PathBuf::from(".");
        let server = Server::build(&config, &dir.0);

        let challenges = dir.0.join("acme-challenges");
        std::fs::create_dir_all(&challenges).expect("challenge dir");
        std::fs::write(challenges.join("tok3n"), b"proof-bytes").expect("token file");

        // The certificate authority fetches from wherever it likes; the gate
        // must not apply, or a gated site could never obtain a certificate.
        let response = dispatch_bytes(
            &server,
            "GET /.well-known/acme-challenge/tok3n HTTP/1.1\r\nHost: console.example.com\r\n\r\n",
            "203.0.113.9:5000",
            false,
            b"",
        )
        .await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(text.contains("proof-bytes"), "{text}");
    }

    #[tokio::test]
    async fn a_cleartext_acme_challenge_for_an_unrouted_hostname_is_served() {
        // Mail client-autoconfig hosts (imap.<domain> and friends) hold
        // certificates without being sites: the CA fetches their challenges
        // under a Host the routing table has never heard of, and the unknown-
        // Host 404 must not fire first or those names can never be issued for.
        let dir = ScratchDataDir::new("unrouted-acme");
        let mut config = config_with(vec![site("web", &["example.com"])]);
        config.server.data_dir = PathBuf::from(".");
        let server = Server::build(&config, &dir.0);

        let challenges = dir.0.join("acme-challenges");
        std::fs::create_dir_all(&challenges).expect("challenge dir");
        std::fs::write(challenges.join("tok3n"), b"proof-bytes").expect("token file");

        let served = dispatch_bytes(
            &server,
            "GET /.well-known/acme-challenge/tok3n HTTP/1.1\r\nHost: imap.example.com\r\n\r\n",
            "203.0.113.9:5000",
            false,
            b"",
        )
        .await;
        let text = String::from_utf8_lossy(&served);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(text.contains("proof-bytes"), "{text}");

        // A missing token under the same unknown Host stays the uniform 404,
        // so the exemption discloses nothing about which names are hosted.
        let missing = dispatch_bytes(
            &server,
            "GET /.well-known/acme-challenge/absent HTTP/1.1\r\nHost: imap.example.com\r\n\r\n",
            "203.0.113.9:5000",
            false,
            b"",
        )
        .await;
        assert!(missing.starts_with(b"HTTP/1.1 404"));
    }

    #[tokio::test]
    async fn reload_applies_a_changed_gate_to_the_next_request() {
        let dir = ScratchDataDir::new("gate-reload");
        write_spa(&dir.0);
        let server =
            Server::build(&config_with(vec![site("console", &["console.example.com"])]), &dir.0);

        let head = "GET / HTTP/1.1\r\nHost: console.example.com\r\n\r\n";
        let open = dispatch_bytes(&server, head, "203.0.113.9:5000", true, b"").await;
        assert!(open.starts_with(b"HTTP/1.1 200"), "open before the reload");

        server.reload(&config_with(vec![gated_site("console", &["console.example.com"])]), &dir.0);

        let denied = dispatch_bytes(&server, head, "203.0.113.9:5000", true, b"").await;
        assert!(denied.starts_with(b"HTTP/1.1 404"), "gated after the reload");
        let allowed = dispatch_bytes(&server, head, "10.66.0.2:5000", true, b"").await;
        assert!(allowed.starts_with(b"HTTP/1.1 200"), "the network itself still passes");
    }

    /// A console site gated to the VPN network, serving `./public`.
    fn console_site() -> Site {
        let mut site = gated_site("console", &["console.example.com"]);
        site.console = true;
        site
    }

    #[tokio::test]
    async fn a_console_api_request_is_relayed_and_the_admin_response_returns_verbatim() {
        let dir = ScratchDataDir::new("console-relay");
        write_spa(&dir.0);

        // A stand-in admin API: accepts one connection, reads the relayed
        // request through the end of its body, answers with a `Set-Cookie`,
        // and closes — the response must come back byte for byte.
        const ADMIN_REPLY: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Set-Cookie: selfhost_session=abc; HttpOnly\r\nContent-Length: 2\r\n\r\nok";
        let body = "{\"password\":\"pw\"}";
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind a fake admin port");
        let admin_bind = listener.local_addr().expect("a bound address");
        let accepted = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("one connection");
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 512];
            loop {
                let read = stream.read(&mut chunk).await.expect("read the relayed request");
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.ends_with(b"\"pw\"}") {
                    break;
                }
            }
            stream.write_all(ADMIN_REPLY).await.expect("answer the relay");
            stream.flush().await.expect("flush the answer");
            String::from_utf8_lossy(&buffer).into_owned()
        });

        let mut config = config_with(vec![console_site()]);
        config.server.admin_bind = admin_bind.to_string();
        let server = Server::build(&config, &dir.0);

        let head = format!(
            "POST /api/session?from=spa HTTP/1.1\r\nHost: console.example.com\r\n\
             Content-Type: application/json\r\nCookie: selfhost_session=old\r\n\
             X-Selfhost-Console: 1\r\nAuthorization: Bearer tok\r\n\
             Content-Length: {}\r\n\r\n",
            body.len()
        );
        // The whole body travels as leftover — the shape that catches a relay
        // reading the socket for bytes `read_head` already took.
        let response = dispatch_bytes(&server, &head, "10.66.0.2:40000", true, body.as_bytes()).await;
        assert_eq!(response, ADMIN_REPLY, "{}", String::from_utf8_lossy(&response));

        let relayed = accepted.await.expect("the fake admin task did not panic");
        assert!(relayed.starts_with("POST /api/session?from=spa HTTP/1.1"), "{relayed}");
        assert!(relayed.contains("Content-Type: application/json\r\n"), "{relayed}");
        assert!(relayed.contains("Cookie: selfhost_session=old\r\n"), "{relayed}");
        assert!(relayed.contains("Authorization: Bearer tok\r\n"), "{relayed}");
        assert!(relayed.contains("X-Selfhost-Console: 1\r\n"), "{relayed}");
        assert!(relayed.contains("X-Forwarded-For: 10.66.0.2\r\n"), "{relayed}");
        assert!(relayed.contains("Connection: close\r\n"), "{relayed}");
        assert!(relayed.contains(&format!("Content-Length: {}\r\n", body.len())), "{relayed}");
        assert!(relayed.ends_with(body), "the body reached the admin API: {relayed}");
    }

    #[tokio::test]
    async fn a_console_path_outside_the_api_serves_the_spa() {
        let dir = ScratchDataDir::new("console-static");
        write_spa(&dir.0);
        let mut config = config_with(vec![console_site()]);
        // Nothing listens here; a static path must never touch the admin API.
        config.server.admin_bind = "127.0.0.1:1".into();
        let server = Server::build(&config, &dir.0);

        let response = dispatch_bytes(
            &server,
            "GET / HTTP/1.1\r\nHost: console.example.com\r\n\r\n",
            "10.66.0.2:5000",
            true,
            b"",
        )
        .await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(text.contains("console spa"), "{text}");
    }

    #[tokio::test]
    async fn an_oversized_console_api_body_is_refused_before_any_upstream_connection() {
        let dir = ScratchDataDir::new("console-413");
        write_spa(&dir.0);
        let mut config = config_with(vec![console_site()]);
        // Nothing listens here: if the relay connected before checking the
        // size, this would answer 502 — the 413 proves the cap fires first.
        config.server.admin_bind = "127.0.0.1:1".into();
        let server = Server::build(&config, &dir.0);

        let head = format!(
            "POST /api/upload HTTP/1.1\r\nHost: console.example.com\r\nContent-Length: {}\r\n\r\n",
            CONSOLE_API_MAX_BODY + 1
        );
        let response = dispatch_bytes(&server, &head, "10.66.0.2:5000", true, b"").await;
        let text = String::from_utf8_lossy(&response);
        assert!(text.starts_with("HTTP/1.1 413"), "{text}");
    }

    // The upgrade relay, and the four ways it is known to be got wrong. Each of
    // these traps is silent under a hand test on an idle link — the connection
    // simply sits there, or the browser simply refuses without saying why — so
    // each one has a test that fails loudly instead.

    /// The head a browser sends to open a desktop stream: RFC 6455's four
    /// fields, the ticket the console carries in `Sec-WebSocket-Protocol`
    /// because it is the only header a page may set on a handshake, the `Origin`
    /// a browser always volunteers, and a couple of fields the admin API has no
    /// business seeing.
    fn handshake_head(target: &str) -> String {
        format!(
            "GET {target} HTTP/1.1\r\nHost: console.example.com\r\n\
             Upgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Protocol: selfhost.desktop.1, tkt.abc123\r\n\
             Origin: https://console.example.com\r\nCookie: selfhost_session=abc\r\n\
             User-Agent: probe\r\nAccept-Language: en\r\n\r\n"
        )
    }

    /// What the stand-in admin API saw on a relayed handshake.
    struct RelayedHandshake {
        /// The request head, through its terminating blank line.
        head: String,
        /// Every byte that arrived after that head. On an agreed upgrade these
        /// are the client's own first bytes of the new protocol, which is the
        /// whole point of [`the_bytes_the_client_already_sent_are_pushed_to_the_daemon`].
        after_head: Vec<u8>,
    }

    /// The offset just past a head's terminating blank line, if it has arrived.
    fn head_end(bytes: &[u8]) -> Option<usize> {
        bytes.windows(4).position(|window| window == b"\r\n\r\n").map(|at| at + 4)
    }

    /// Runs a stand-in admin API that answers one relayed request with `answer`
    /// and then reads until the proxy hangs up.
    ///
    /// `answer` is written in a single `write_all`, so on loopback the proxy's
    /// head reader sees the response head *and* whatever the daemon wrote after
    /// it in one read — the arrangement that makes the "forward `buffered`
    /// whole" rule observable. The write half is closed straight afterwards
    /// because the fallback path relays until the upstream's EOF: a daemon that
    /// held the connection open while waiting for the proxy to close would
    /// deadlock against a proxy waiting for the daemon to.
    async fn fake_daemon(
        answer: &'static [u8],
    ) -> (SocketAddr, tokio::task::JoinHandle<RelayedHandshake>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind a fake admin port");
        let admin_bind = listener.local_addr().expect("a bound address");
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("one connection");
            let mut head = Vec::new();
            let mut chunk = [0u8; 512];
            while head_end(&head).is_none() {
                let read = stream.read(&mut chunk).await.expect("read the relayed head");
                assert!(read > 0, "the relay closed before it finished its head");
                head.extend_from_slice(&chunk[..read]);
            }
            let end = head_end(&head).expect("the loop only exits with a complete head");
            let mut after_head = head.split_off(end);
            stream.write_all(answer).await.expect("answer the relayed request");
            stream.flush().await.expect("flush the answer");
            stream.shutdown().await.expect("close the answering half");
            stream.read_to_end(&mut after_head).await.expect("read to the proxy's close");
            RelayedHandshake { head: String::from_utf8_lossy(&head).into_owned(), after_head }
        });
        (admin_bind, task)
    }

    /// A `101` exactly as the daemon's handshake writer emits it.
    ///
    /// It ends at the blank line, which is the shape that makes the
    /// security-header trap observable: `apply_security_headers` splices its
    /// fields in front of a trailing `\r\n\r\n` and does nothing to a buffer
    /// that has bytes after it. A test whose fixture carried a frame would pass
    /// even against a relay that called it.
    const DAEMON_101: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\n\
        Upgrade: websocket\r\nConnection: Upgrade\r\n\
        Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
        Sec-WebSocket-Protocol: selfhost.desktop.1\r\n\r\n";

    /// The same `101` with the daemon's first frame in the same write — the
    /// ordinary case, since a stream that has something to say says it at once.
    const DAEMON_101_AND_FRAME: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\n\
        Upgrade: websocket\r\nConnection: Upgrade\r\n\
        Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
        Sec-WebSocket-Protocol: selfhost.desktop.1\r\n\r\n\x81\x04helo";

    #[tokio::test]
    async fn a_101_reaches_the_browser_exactly_as_the_daemon_wrote_it() {
        let dir = ScratchDataDir::new("upgrade-101");
        write_spa(&dir.0);
        let (admin_bind, daemon) = fake_daemon(DAEMON_101).await;
        let mut config = config_with(vec![console_site()]);
        config.server.admin_bind = admin_bind.to_string();
        let server = Server::build(&config, &dir.0);

        let head = handshake_head("/api/desktop/stream");
        let response = dispatch_bytes(&server, &head, "10.66.0.2:40000", true, b"").await;

        // Byte-for-byte. The head must not go out through `write_response`,
        // which would derive a `Content-Length` and a `Connection` from a body
        // this response does not have, and whose `apply_security_headers` would
        // splice `X-Frame-Options` and friends into a message that is no longer
        // HTTP — and that a browser checks strictly before it hands the socket
        // to the page.
        assert_eq!(response, DAEMON_101, "{}", String::from_utf8_lossy(&response));
        let text = String::from_utf8_lossy(&response);
        for spliced in ["X-Frame-Options", "Content-Security-Policy", "Content-Length"] {
            assert!(!text.contains(spliced), "{spliced} was spliced into a 101: {text}");
        }

        // And the head the daemon received: the handshake's own fields relayed,
        // the hop-by-hop pair written by the proxy exactly once, no body framing
        // at all, and nothing a browser volunteers that the API does not act on.
        let relayed = daemon.await.expect("the fake daemon did not panic");
        assert!(relayed.head.starts_with("GET /api/desktop/stream HTTP/1.1"), "{}", relayed.head);
        for expected in [
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "Sec-WebSocket-Protocol: selfhost.desktop.1, tkt.abc123\r\n",
            "Origin: https://console.example.com\r\n",
            "Cookie: selfhost_session=abc\r\n",
            "X-Forwarded-For: 10.66.0.2\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
        ] {
            assert!(relayed.head.contains(expected), "{expected:?} was not relayed: {}", relayed.head);
        }
        for refused in ["User-Agent", "Accept-Language", "Content-Length", "keep-alive"] {
            assert!(!relayed.head.contains(refused), "{refused} reached the daemon: {}", relayed.head);
        }
        assert_eq!(relayed.head.matches("Connection:").count(), 1, "{}", relayed.head);
        assert!(relayed.after_head.is_empty(), "this client sent nothing past its head");
    }

    #[tokio::test]
    async fn the_daemons_first_frame_is_not_left_behind_in_the_head_buffer() {
        let dir = ScratchDataDir::new("upgrade-first-frame");
        write_spa(&dir.0);
        let (admin_bind, daemon) = fake_daemon(DAEMON_101_AND_FRAME).await;
        let mut config = config_with(vec![console_site()]);
        config.server.admin_bind = admin_bind.to_string();
        let server = Server::build(&config, &dir.0);

        // The stranding trap seen from the upstream's side. `read_response_head`
        // stops parsing at the blank line but has already read whatever came
        // with it into `buffered`; forwarding only as far as the head parser
        // consumed would drop the daemon's first message on the floor, and no
        // retransmission would ever bring it back — those bytes are in this
        // process, not on the wire.
        let head = handshake_head("/api/desktop/stream");
        let response = dispatch_bytes(&server, &head, "10.66.0.2:40000", true, b"").await;
        assert_eq!(response, DAEMON_101_AND_FRAME, "{}", String::from_utf8_lossy(&response));
        daemon.await.expect("the fake daemon did not panic");
    }

    #[tokio::test]
    async fn the_bytes_the_client_already_sent_are_pushed_to_the_daemon() {
        let dir = ScratchDataDir::new("upgrade-leftover");
        write_spa(&dir.0);
        let (admin_bind, daemon) = fake_daemon(DAEMON_101).await;
        let mut config = config_with(vec![console_site()]);
        config.server.admin_bind = admin_bind.to_string();
        let server = Server::build(&config, &dir.0);

        // A masked client frame that arrived in the same TCP segment as the
        // handshake — which is what a page opening a socket and writing to it
        // immediately produces. `read_head` has already taken these bytes off
        // the socket, so nothing but the relay can deliver them: forget the push
        // and the daemon waits forever for a message that is sitting in this
        // process, with no timeout left anywhere to break the wait.
        const FIRST_FRAME: &[u8] = b"\x81\x83\x01\x02\x03\x04abc";
        let head = handshake_head("/api/desktop/stream");
        let response = dispatch_bytes(&server, &head, "10.66.0.2:40000", true, FIRST_FRAME).await;
        assert_eq!(response, DAEMON_101, "{}", String::from_utf8_lossy(&response));

        let relayed = daemon.await.expect("the fake daemon did not panic");
        assert_eq!(
            relayed.after_head, FIRST_FRAME,
            "the bytes read past the head were stranded in the proxy"
        );
    }

    #[tokio::test]
    async fn a_refused_handshake_falls_back_to_an_ordinary_verbatim_relay() {
        let dir = ScratchDataDir::new("upgrade-refused");
        write_spa(&dir.0);
        // The uniform 401 the admin API answers a handshake with no valid
        // ticket. Nothing about it is special to the proxy: it must come back
        // exactly as the daemon wrote it, which is what this relay did for every
        // response before upgrades existed.
        const REFUSAL: &[u8] =
            b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\
              Content-Length: 16\r\n\r\n{\"error\":\"auth\"}";
        let (admin_bind, daemon) = fake_daemon(REFUSAL).await;
        let mut config = config_with(vec![console_site()]);
        config.server.admin_bind = admin_bind.to_string();
        let server = Server::build(&config, &dir.0);

        let head = handshake_head("/api/desktop/stream");
        let response = dispatch_bytes(&server, &head, "10.66.0.2:40000", true, b"\x81\x03abc").await;
        assert_eq!(response, REFUSAL, "{}", String::from_utf8_lossy(&response));

        // And the client's would-be first frame is not pushed to an upstream
        // that refused the switch: those bytes are only the new protocol's if
        // there is a new protocol.
        let relayed = daemon.await.expect("the fake daemon did not panic");
        assert!(
            relayed.after_head.is_empty(),
            "bytes were pushed to a daemon that never agreed to upgrade"
        );
    }

    #[tokio::test]
    async fn the_source_address_gate_runs_above_the_upgrade_path() {
        let dir = ScratchDataDir::new("upgrade-gate");
        write_spa(&dir.0);
        let mut config = config_with(vec![console_site()]);
        // Nothing listens here. A handshake that reached the relay at all would
        // answer 502; the 404 is the proof that the gate refused it first.
        config.server.admin_bind = "127.0.0.1:1".into();
        let server = Server::build(&config, &dir.0);

        let head = handshake_head("/api/desktop/stream");
        let denied = dispatch_bytes(&server, &head, "203.0.113.9:5000", true, b"").await;
        let unknown = dispatch_bytes(
            &server,
            "GET / HTTP/1.1\r\nHost: not-hosted.example.com\r\n\r\n",
            "203.0.113.9:5000",
            true,
            b"",
        )
        .await;
        assert!(denied.starts_with(b"HTTP/1.1 404"), "{}", String::from_utf8_lossy(&denied));
        assert_eq!(
            denied, unknown,
            "a refused handshake must be indistinguishable from a hostname that is not hosted"
        );

        // The peer inside the gate reaches the relay, and fails only because
        // nothing is listening on the admin port — which is what makes the 404
        // above a statement about the gate rather than about the route.
        let permitted = dispatch_bytes(&server, &head, "10.66.0.2:40000", true, b"").await;
        assert!(permitted.starts_with(b"HTTP/1.1 502"), "{}", String::from_utf8_lossy(&permitted));
    }

    #[tokio::test]
    async fn an_upgrade_cannot_borrow_the_exemptions_that_sit_above_the_gate() {
        let dir = ScratchDataDir::new("upgrade-exemptions");
        write_spa(&dir.0);
        let mut config = config_with(vec![console_site()]);
        // Again a dead admin port: every answer below must be a refusal written
        // by the proxy itself, never a 502 from a relay that was attempted.
        config.server.admin_bind = "127.0.0.1:1".into();
        let server = Server::build(&config, &dir.0);
        let denied = "203.0.113.9:5000";

        // Exactly two things are answered above `Site::permits`: an ACME
        // challenge on cleartext, and a deploy webhook. Both must stay reachable
        // — a certificate authority and a hosting provider have no VPN — and
        // neither may become a way in for a stream. A handshake shaped at each
        // of them is answered by that route's own handler, which for a `GET`
        // webhook and an unknown challenge token is a 404, and never spliced.
        for exempt in [
            format!("{WEBHOOK_PREFIX}levelup"),
            format!("{ACME_CHALLENGE_PREFIX}t0ken"),
        ] {
            let response = dispatch_bytes(&server, &handshake_head(&exempt), denied, true, b"").await;
            assert!(
                response.starts_with(b"HTTP/1.1 404"),
                "{exempt} answered a handshake with {}",
                String::from_utf8_lossy(&response)
            );
        }

        // And nothing on the cleartext listener upgrades anything but the
        // scheme, even for a peer the gate permits: the console API — and
        // therefore the whole upgrade path — is below the HTTPS branch.
        let cleartext = handshake_head("/api/desktop/stream");
        let response = dispatch_bytes(&server, &cleartext, "10.66.0.2:40000", false, b"").await;
        assert!(response.starts_with(b"HTTP/1.1 308"), "{}", String::from_utf8_lossy(&response));
    }
}
