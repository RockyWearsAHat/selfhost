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
use crate::upstream::Pool;
use selfhost_config::{Config, Site};
use selfhost_http::{Body, Method, ParseError, Request, Response, Status};
use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// How long a connection may stay idle between requests before it is closed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Path prefix reserved for ACME HTTP-01 challenges.
///
/// Never routed to a site, and never redirected to HTTPS.
pub const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

/// How long the request head may take to arrive.
///
/// Bounds a slowloris: a client dribbling one byte at a time cannot hold a
/// connection open indefinitely.
const HEAD_TIMEOUT: Duration = Duration::from_secs(15);

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
    /// Hostname to site, built once so routing is a lookup rather than a scan.
    routes: BTreeMap<String, Arc<SiteRuntime>>,
    /// Sites in declaration order, for health tasks and diagnostics.
    sites: Vec<Arc<SiteRuntime>>,
    /// Where ACME HTTP-01 tokens are written, when issuance is configured.
    acme_challenge_dir: Option<PathBuf>,
}

impl Server {
    /// Builds the routing table from a validated config.
    ///
    /// `project_dir` is where relative static roots resolve from.
    pub fn build(config: &Config, project_dir: &std::path::Path) -> Self {
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

        Self {
            routes,
            sites,
            acme_challenge_dir: Some(project_dir.join(&config.server.data_dir).join("acme-challenges")),
        }
    }

    /// Looks up the site serving a hostname.
    pub fn route(&self, host: &str) -> Option<&Arc<SiteRuntime>> {
        self.routes.get(&host.to_ascii_lowercase())
    }

    /// Every site, in declaration order.
    pub fn sites(&self) -> &[Arc<SiteRuntime>] {
        &self.sites
    }

    /// Spawns one health-probe task per site that has instances.
    pub fn spawn_health_tasks(&self) {
        for runtime in &self.sites {
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

        let outcome = dispatch(&server, &request, peer, is_tls, &mut stream, keep_alive).await?;

        // One line per request. Without this there is no way to answer "is
        // anyone actually reaching the site" except by guessing.
        eprintln!(
            "[access] {peer} {scheme} {host} {method} {target} {ms}ms",
            scheme = if is_tls { "https" } else { "http" },
            ms = started.elapsed().as_millis(),
        );

        if !keep_alive || outcome == Outcome::MustClose {
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
async fn dispatch<S>(
    server: &Server,
    request: &Request,
    peer: SocketAddr,
    is_tls: bool,
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

    let Some(runtime) = server.route(&host) else {
        // An unknown Host is answered with 404 rather than a default site, so a
        // stray DNS record cannot quietly expose one site under another's name.
        write_response(stream, Response::error_page(Status::NOT_FOUND), keep_alive).await?;
        return Ok(Outcome::Reusable);
    };

    // Cleartext exists to send callers to HTTPS — with exactly one exception.
    //
    // An ACME HTTP-01 challenge is fetched over plain HTTP by the certificate
    // authority, which does not follow redirects to a host whose certificate it
    // has not issued yet. Redirecting this path would make issuance impossible,
    // and the failure is confusing because everything else works. The exemption
    // lives here so it cannot be forgotten when the ACME client lands.
    if !is_tls {
        if request.path().starts_with(ACME_CHALLENGE_PREFIX) {
            return serve_acme_challenge(server, request, stream, keep_alive).await;
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

    let canonical = runtime.site.canonical();
    if runtime.site.canonical_redirect && host != canonical {
        let target = format!("https://{canonical}{}", request.target);
        let response = Response::redirect(Status::MOVED_PERMANENTLY, &target)
            .unwrap_or_else(|_| Response::error_page(Status::BAD_REQUEST));
        write_response(stream, response, keep_alive).await?;
        return Ok(Outcome::Reusable);
    }

    if runtime.site.routes_to_app(request.path()) {
        return forward(runtime, request, peer, stream).await;
    }

    serve_static(runtime, request, stream, keep_alive).await
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
    stream: &mut S,
) -> io::Result<Outcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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
            let mut limited = (&mut *stream).take(length);
            tokio::io::copy(&mut limited, &mut upstream).await?;
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
}
