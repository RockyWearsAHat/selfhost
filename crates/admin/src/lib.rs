//! The loopback control API the console drives.
//!
//! # Why this binds loopback and nothing else
//!
//! The API binds loopback only, on its own listener rather than as a path on an
//! ordinary site. A bug in a hosted website must not become a way to read or
//! control the deployment, and a reserved path prefix on a shared listener is
//! one routing mistake away from being reachable from the internet.
//!
//! There is exactly **one sanctioned path** through a shared listener: the
//! proxy's console site (`console = true` in the config) relays `/api/*` here.
//! That site is only ever admitted after the proxy's source-IP gate
//! (`allowed_cidrs`, in practice the WireGuard subnet `10.66.0.0/24`) has
//! passed the client, and every relayed request still authenticates — a session
//! cookie issued by `POST /api/session` against the `console.passwd` PBKDF2
//! hash, or the same bearer token as always. The direct bind stays
//! loopback-only regardless; the relay adds a gated, authenticated front door
//! without ever exposing this socket itself.
//!
//! Beyond that relay, remote access is deliberately *not* a feature here. The
//! console reaches a remote daemon by tunnelling this port over SSH, which
//! means the authentication and the encryption are OpenSSH's rather than
//! something invented for this.
//!
//! # Shape
//!
//! [`Api::handle`] turns a request into a response and touches no sockets, so
//! every route — including every way of getting the authorisation wrong — is
//! tested directly. [`serve`] is the thin part that owns the listener.

#![warn(missing_docs)]

pub mod passwd;
pub mod session;
pub mod store;
pub mod token;

use selfhost_firewall::Manager;
use selfhost_git::Watches;
use selfhost_http::{Body, Method, Request, Response, Status};
use selfhost_json::Json;
use selfhost_supervisor::Supervisor;
use selfhost_supervisor::state::{spec_from_json, spec_to_json};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub use passwd::ConsolePassword;
pub use session::{FailureGate, Sessions};
pub use store::Store;
pub use token::Token;

/// The largest request body accepted.
///
/// A service definition is a few hundred bytes; anything approaching this is a
/// mistake or an attempt to exhaust memory, and either way it is refused before
/// being read rather than after.
const MAX_BODY: usize = 64 * 1024;

/// Default number of log lines returned when the caller does not say.
const DEFAULT_LOG_LIMIT: usize = 500;

/// The control API.
#[derive(Clone)]
pub struct Api {
    supervisor: Supervisor,
    store: Arc<Store>,
    token: Token,
    watches: Watches,
    firewall: Manager,
    console: Option<ConsoleAuth>,
}

/// Cookie-session authentication, present once [`Api::with_console_auth`] has
/// been called.
///
/// Absent by default so a daemon built without the console feature behaves
/// byte-for-byte as before: bearer tokens only, and every session route
/// answers the same uninformative 401 as any other unauthorised request.
#[derive(Clone)]
struct ConsoleAuth {
    /// The stored password hash logins are verified against.
    password: Arc<ConsolePassword>,
    /// The shared session store; one store across every clone of the `Api`.
    sessions: Sessions,
    /// The shared login rate limiter.
    gate: FailureGate,
}

/// The name of the session cookie the console browser holds.
const SESSION_COOKIE: &str = "selfhost_session";

/// The header a cookie-authenticated non-GET request must carry.
///
/// The CSRF defence: a cross-site form or fetch can make the browser attach
/// the cookie, but it cannot attach a custom header without a CORS preflight
/// this API never approves. Bearer-token callers never need it — a token is
/// not something a browser attaches on its own, so bearer requests cannot be
/// forged this way.
const CONSOLE_HEADER: &str = "x-selfhost-console";

impl Api {
    /// Builds the API over a supervisor, the catalogue it persists to, and the
    /// set of Git watches that follow the services in it.
    ///
    /// The watches are held here because installing a service is what decides
    /// whether it is watched: a definition that gains a branch has to start being
    /// polled at that moment, and one that is uninstalled has to stop. Leaving
    /// that to the daemon's startup would mean a service installed from the
    /// console is only deployed after the next daemon restart, which is exactly
    /// the silent half-working state this feature exists to avoid.
    ///
    /// The firewall `Manager` is the same cheap-clone handle the daemon holds and
    /// reconciles on a timer, so `GET /api/firewall` reports the very state the
    /// daemon is driving — not a second view that could disagree with it.
    pub fn new(
        supervisor: Supervisor,
        store: Store,
        token: Token,
        watches: Watches,
        firewall: Manager,
    ) -> Self {
        Self { supervisor, store: Arc::new(store), token, watches, firewall, console: None }
    }

    /// Enables cookie-session login, loading the password hash from `dir`.
    ///
    /// The wiring seam for the daemon: called once, right after [`Api::new`],
    /// with the daemon's data directory. A missing password file still enables
    /// the session routes — they just refuse every login until
    /// `selfhost console-password` writes one.
    pub fn with_console_auth(self, dir: &Path) -> Self {
        self.with_console_auth_parts(ConsolePassword::load(dir), Sessions::new())
    }

    /// Enables cookie-session login from already-built parts.
    ///
    /// The seam behind [`Api::with_console_auth`] that makes expiry testable:
    /// a test passes a [`Sessions`] built with `Sessions::with_expiry` to get
    /// sessions that expire without waiting hours.
    pub fn with_console_auth_parts(mut self, password: ConsolePassword, sessions: Sessions) -> Self {
        self.console =
            Some(ConsoleAuth { password: Arc::new(password), sessions, gate: FailureGate::new() });
        self
    }

    /// The supervisor this API drives.
    pub fn supervisor(&self) -> &Supervisor {
        &self.supervisor
    }

    /// Turns a request into a response.
    ///
    /// Takes no sockets so every route is directly testable, including the ways
    /// authorisation can be got wrong.
    pub async fn handle(&self, request: &Request, body: &[u8]) -> Response {
        let (path, query) = split_target(&request.target);

        // Unauthenticated, and deliberately says nothing about the deployment:
        // it exists so the console can tell a daemon is listening before it has
        // a token, and so a tunnel can be health-checked.
        if path == "/api/health" {
            return json(Status(200), Json::object([("ok", Json::Bool(true))]));
        }

        // Matched ahead of the authorisation wall, like /api/health: logging in
        // is how a browser *gets* authorised, and the GET probe must be able to
        // answer "not logged in" rather than merely refusing.
        if path == "/api/session" {
            return match &request.method {
                // The login POST counts failures into a global rate-limit gate,
                // so it must carry the CSRF header too — otherwise a cross-site
                // simple request (no preflight) could drive failures and lock
                // the door for everyone. The SPA sends the header on this POST;
                // a forged cross-site fetch cannot without a preflight the API
                // never grants. A missing header answers the same uninformative
                // 401 as every other refusal.
                Method::Post if has_console_header(request) => self.login(body),
                Method::Post => problem(Status(401), "authorisation required"),
                Method::Delete => self.logout(request),
                Method::Get => self.session_probe(request),
                _ => problem(Status(404), "no such endpoint"),
            };
        }

        if !self.authorised(request) {
            // No detail about why. "Wrong token" and "no token" are the same
            // answer to anyone who should not be here.
            return problem(Status(401), "authorisation required");
        }

        let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
        match (&request.method, segments.as_slice()) {
            (Method::Get, ["api", "services"]) => self.list_services().await,
            (Method::Get, ["api", "services", name]) => self.describe(name).await,
            (Method::Put, ["api", "services", name]) => self.install(name, body).await,
            (Method::Delete, ["api", "services", name]) => self.uninstall(name).await,
            (Method::Get, ["api", "services", name, "logs"]) => self.logs(name, query).await,
            // Matched ahead of the generic action route below: "deploy" is not a
            // supervisor action like start/stop/restart, it drives a git watch.
            (Method::Post, ["api", "services", name, "deploy"]) => self.deploy_now(name).await,
            (Method::Post, ["api", "services", name, action]) => self.act(name, action).await,
            // Authenticated, not on `/api/health`: the open ports it reveals are
            // as sensitive as the service list, so it sits inside the token wall.
            (Method::Get, ["api", "firewall"]) => self.firewall_state().await,
            (Method::Post, ["api", "firewall", "reconcile"]) => self.firewall_reconcile().await,
            _ => problem(Status(404), "no such endpoint"),
        }
    }

    /// Whether the request carries the right bearer token or a live session.
    ///
    /// Either credential opens every route; the console client and the webhook
    /// relay keep presenting the token exactly as before, the browser presents
    /// its cookie.
    fn authorised(&self, request: &Request) -> bool {
        self.bearer_authorised(request) || self.cookie_authorised(request)
    }

    /// Whether the request carries the right bearer token.
    fn bearer_authorised(&self, request: &Request) -> bool {
        request
            .headers
            .get_str("authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|presented| self.token.matches(presented.trim()))
    }

    /// Whether the request carries a live session cookie — and, for a non-GET,
    /// the CSRF header (see [`CONSOLE_HEADER`]).
    ///
    /// A cookie-authenticated write missing the header answers the same 401 as
    /// every other refusal: an uninformative body tells a forger nothing about
    /// whether the stolen ride would otherwise have worked. The header is
    /// checked *before* the store so a forged request cannot even refresh the
    /// session's idle timer.
    fn cookie_authorised(&self, request: &Request) -> bool {
        let Some(console) = &self.console else {
            return false;
        };
        if request.method != Method::Get && !has_console_header(request) {
            return false;
        }
        session_cookie(request).is_some_and(|id| console.sessions.validate(&id))
    }

    /// Answers `POST /api/session`: verifies the password and mints a session.
    ///
    /// Every authentication failure — no password configured, wrong password —
    /// is the identical 401 the rest of the API sends, so probing this route
    /// reveals nothing about the deployment's configuration. A malformed body
    /// is a 400, which reveals only that the caller cannot form JSON.
    fn login(&self, body: &[u8]) -> Response {
        let Some(console) = &self.console else {
            return problem(Status(401), "authorisation required");
        };
        if console.gate.locked() {
            return problem(Status(429), "too many attempts");
        }
        let Some(password) = login_password(body) else {
            return problem(Status(400), "body must be JSON with a \"password\" string");
        };
        if !console.password.verify(&password) {
            console.gate.record_failure();
            return problem(Status(401), "authorisation required");
        }
        console.gate.reset();
        match console.sessions.create() {
            Ok(id) => with_session_cookie(
                json(Status(200), Json::object([("ok", Json::Bool(true))])),
                &id,
                session::SESSION_LIFETIME_SECS,
            ),
            Err(error) => problem(Status(500), &format!("could not create a session: {error}")),
        }
    }

    /// Answers `DELETE /api/session`: revokes the cookie's session.
    ///
    /// Deliberately outside the authorisation wall and always a 200: logging
    /// out an expired or unknown cookie must still clear it from the browser,
    /// and the worst a forged logout can do is inconvenience the operator into
    /// logging in again.
    fn logout(&self, request: &Request) -> Response {
        if let (Some(console), Some(id)) = (&self.console, session_cookie(request)) {
            console.sessions.revoke(&id);
        }
        // Max-Age=0 makes the browser discard the cookie immediately.
        with_session_cookie(json(Status(200), Json::object([("ok", Json::Bool(true))])), "", 0)
    }

    /// Answers `GET /api/session`: the SPA's session probe.
    ///
    /// A 200 for any authenticated caller — cookie or bearer — and the usual
    /// uninformative 401 otherwise, so the SPA can decide between its login
    /// form and its dashboard with one request.
    fn session_probe(&self, request: &Request) -> Response {
        if self.authorised(request) {
            json(Status(200), Json::object([("ok", Json::Bool(true))]))
        } else {
            problem(Status(401), "authorisation required")
        }
    }

    async fn list_services(&self) -> Response {
        let statuses = self.supervisor.statuses().await;
        json(
            Status(200),
            Json::object([("services", Json::array(statuses.iter().map(|s| s.to_json())))]),
        )
    }

    async fn describe(&self, name: &str) -> Response {
        match (self.supervisor.status(name).await, self.supervisor.spec(name).await) {
            (Some(status), Some(spec)) => json(
                Status(200),
                Json::object([("status", status.to_json()), ("spec", spec_to_json(&spec))]),
            ),
            _ => problem(Status(404), "no such service"),
        }
    }

    /// Creates or replaces a service, persisting it before running it.
    ///
    /// Written to disk first on purpose: a service that is running but absent
    /// from the catalogue vanishes at the next daemon restart, which is a far
    /// more confusing failure than one that was refused outright.
    async fn install(&self, name: &str, body: &[u8]) -> Response {
        let text = match std::str::from_utf8(body) {
            Ok(text) => text,
            Err(_) => return problem(Status(400), "body is not valid UTF-8"),
        };
        let value = match selfhost_json::parse(text) {
            Ok(value) => value,
            Err(error) => return problem(Status(400), &error.to_string()),
        };

        let mut spec = match spec_from_json(&value) {
            Some(spec) => spec,
            None => return problem(Status(400), "a service needs at least a name and a program"),
        };

        // The path names the service; a body disagreeing with it is ambiguous
        // rather than a preference, so the path wins and the mismatch is visible.
        spec.name = name.to_owned();

        let mut problems = Vec::new();
        spec.check("service", &[], &mut problems);
        if !problems.is_empty() {
            return json(
                Status(422),
                Json::object([(
                    "problems",
                    Json::array(problems.iter().map(|p| {
                        Json::object([
                            ("field", Json::string(&p.field)),
                            ("message", Json::string(&p.message)),
                        ])
                    })),
                )]),
            );
        }

        if let Err(error) = self.store.upsert(spec.clone()).await {
            return problem(Status(500), &format!("could not save the catalogue: {error}"));
        }

        self.supervisor.install(spec.clone()).await;
        // After the install, not before: a watch polling a service the supervisor
        // has not been given yet would find nothing to stop or start.
        self.watches.follow(&self.supervisor, &spec).await;

        match self.supervisor.status(name).await {
            Some(status) => json(Status(200), status.to_json()),
            None => problem(Status(500), "the service was saved but did not install"),
        }
    }

    async fn uninstall(&self, name: &str) -> Response {
        if !self.supervisor.remove(name).await {
            return problem(Status(404), "no such service");
        }
        // A watch outliving its service would keep pulling into a working copy
        // nothing runs from, and would report deployments of a service that is
        // no longer installed.
        self.watches.forget(name).await;
        if let Err(error) = self.store.remove(name).await {
            return problem(Status(500), &format!("could not save the catalogue: {error}"));
        }
        json(Status(200), Json::object([("removed", Json::string(name))]))
    }

    async fn logs(&self, name: &str, query: &str) -> Response {
        let from = query_value(query, "from").and_then(|v| v.parse().ok()).unwrap_or(0);
        let limit = query_value(query, "limit")
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_LOG_LIMIT)
            .min(5_000);

        match self.supervisor.logs(name, from, limit).await {
            Some(slice) => json(Status(200), slice.to_json()),
            None => problem(Status(404), "no such service"),
        }
    }

    async fn act(&self, name: &str, action: &str) -> Response {
        let known = match action {
            "start" => self.supervisor.start(name).await,
            "stop" => self.supervisor.stop(name).await,
            "restart" => self.supervisor.restart(name).await,
            _ => return problem(Status(404), "no such action"),
        };
        if !known {
            return problem(Status(404), "no such service");
        }

        // Supervision is asynchronous: this reports the command was accepted, not
        // that it finished. The console polls for the outcome, which is also what
        // it must do for a state change nobody asked for.
        json(
            Status(202),
            Json::object([("accepted", Json::string(action)), ("service", Json::string(name))]),
        )
    }

    /// Drives this service's git watch right now, instead of waiting out its
    /// poll interval.
    ///
    /// This is the trusted side of the webhook feature: the proxy's public
    /// webhook path, after verifying a push's signature against the watch's
    /// own secret, calls this loopback route with the same bearer token every
    /// other request here needs. Nothing about the deployment itself is
    /// special-cased — it runs [`selfhost_git::check_once`], the identical
    /// stop/pull/build/start sequence the background poller runs, which is
    /// why an earlier check can never deploy anything other than what is
    /// really at the tip of the watched branch.
    ///
    /// Spawned rather than awaited, for the same reason [`Api::act`] reports
    /// acceptance rather than completion: a build step can run long enough
    /// that blocking the response on it would tie up the caller — the proxy's
    /// webhook handler, in turn tying up the pusher's HTTP client — for as
    /// long as the build takes. The outcome lands where every other
    /// deployment's does: the service's own `[git]`-tagged output.
    async fn deploy_now(&self, name: &str) -> Response {
        let Some(spec) = self.supervisor.spec(name).await else {
            return problem(Status(404), "no such service");
        };
        let Some(watch) = spec.active_watch().cloned() else {
            return problem(Status(404), "this service has no active git watch to deploy from");
        };

        let supervisor = self.supervisor.clone();
        tokio::spawn(async move {
            let _ = selfhost_git::check_once(&supervisor, &spec, &watch).await;
        });

        json(
            Status(202),
            Json::object([("accepted", Json::Bool(true)), ("service", Json::string(name))]),
        )
    }

    /// The host firewall as the daemon last observed it.
    ///
    /// Reads the manager's cached state rather than re-snapshotting on every
    /// poll: the console asks for this on its normal cadence, and the daemon's
    /// own drift timer is what keeps the cache honest.
    async fn firewall_state(&self) -> Response {
        json(Status(200), self.firewall.state().await.to_json())
    }

    /// Re-asserts the firewall on demand and returns the resulting state.
    ///
    /// The same reconcile the daemon runs at startup and on its drift timer,
    /// exposed so the console can force it after changing the policy rather than
    /// waiting for the next tick. A firewall that refused the change is a 500
    /// carrying the tool's own reason — never a silent success.
    async fn firewall_reconcile(&self) -> Response {
        match self.firewall.reconcile().await {
            Ok(state) => json(Status(200), state.to_json()),
            Err(error) => {
                problem(Status(500), &format!("could not reconcile the firewall: {error}"))
            }
        }
    }
}

/// Reads the `password` string out of a login request body.
///
/// `None` for anything that is not JSON carrying a `password` string — the
/// caller answers 400 rather than treating a malformed body as a failed guess.
fn login_password(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let value = selfhost_json::parse(text).ok()?;
    value.get("password").and_then(Json::as_str).map(str::to_owned)
}

/// Extracts the session id from a request's `Cookie` header, if present.
///
/// A browser sends every cookie for the site in one header, `name=value` pairs
/// separated by semicolons; only [`SESSION_COOKIE`] is ours.
fn session_cookie(request: &Request) -> Option<String> {
    let header = request.headers.get_str("cookie")?;
    header.split(';').find_map(|pair| {
        let (name, value) = pair.trim().split_once('=')?;
        (name.trim() == SESSION_COOKIE).then(|| value.trim().to_owned())
    })
}

/// Whether the request carries the CSRF header (see [`CONSOLE_HEADER`]).
fn has_console_header(request: &Request) -> bool {
    request.headers.get_str(CONSOLE_HEADER).is_some_and(|value| value.trim() == "1")
}

/// Attaches the session cookie to a response.
///
/// `HttpOnly` keeps the id away from scripts, `Secure` keeps it off plaintext
/// hops (the browser talks to the proxy over HTTPS; this API itself only ever
/// sees loopback), `SameSite=Strict` keeps it out of cross-site requests, and
/// `Max-Age` matches the session's absolute lifetime — or is zero, to expire
/// the cookie on logout. The value is hex or empty, so setting the header
/// cannot fail; the fallback mirrors [`json`]'s.
fn with_session_cookie(mut response: Response, id: &str, max_age: u64) -> Response {
    let cookie = format!(
        "{SESSION_COOKIE}={id}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age}"
    );
    match response.headers.set("Set-Cookie", cookie) {
        Ok(()) => response,
        Err(_) => Response::empty(Status(500)),
    }
}

/// Splits a request target into its path and query string.
fn split_target(target: &str) -> (&str, &str) {
    match target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (target, ""),
    }
}

/// Reads one parameter out of a query string.
fn query_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key).then_some(value)
    })
}

/// A JSON response.
fn json(status: Status, value: Json) -> Response {
    Response::bytes(status, "application/json; charset=utf-8", value.to_text().into_bytes())
        .unwrap_or_else(|_| Response::empty(Status(500)))
}

/// An error response carrying a human-readable explanation.
fn problem(status: Status, message: &str) -> Response {
    json(status, Json::object([("error", Json::string(message))]))
}

/// Serves the API until the listener fails.
///
/// The listener must be bound to loopback; [`bind`] is the way to get one.
pub async fn serve(listener: TcpListener, api: Api) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let api = api.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, peer, api).await {
                // A client that hangs up mid-request is ordinary, not notable.
                if error.kind() != std::io::ErrorKind::UnexpectedEof {
                    eprintln!("admin: connection from {peer} ended: {error}");
                }
            }
        });
    }
}

/// Binds the admin listener, refusing any address that is not loopback.
///
/// Checked here rather than trusted from config: this port is unauthenticated
/// apart from a bearer token in a file, and exposing it to the network would hand
/// control of every service to anyone who can reach the machine. Remote access is
/// meant to go through an SSH tunnel, which terminates on loopback anyway.
pub async fn bind(address: SocketAddr) -> std::io::Result<TcpListener> {
    if !address.ip().is_loopback() {
        return Err(std::io::Error::other(format!(
            "refusing to bind the admin API to {address}: it must be loopback. \
             Reach it from another machine by tunnelling over SSH, for example \
             `ssh -L {0}:127.0.0.1:{0} <host>`, so the authentication and encryption \
             are OpenSSH's rather than this port's.",
            address.port()
        )));
    }
    TcpListener::bind(address).await
}

/// Reads one request, answers it, and closes.
///
/// One request per connection: this API sees a handful of requests a second from
/// a single console, so keep-alive buys nothing and every connection reused is a
/// chance for two responses to disagree about framing.
async fn handle_connection(
    mut stream: TcpStream,
    _peer: SocketAddr,
    api: Api,
) -> std::io::Result<()> {
    let mut buffer = Vec::with_capacity(1024);
    let mut scratch = [0u8; 4096];

    let (request, consumed) = loop {
        match Request::parse(&buffer) {
            Ok(parsed) => break (parsed.request, parsed.consumed),
            Err(selfhost_http::ParseError::Incomplete) => {
                let read = stream.read(&mut scratch).await?;
                if read == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "client closed before sending a complete request",
                    ));
                }
                buffer.extend_from_slice(&scratch[..read]);
                if buffer.len() > MAX_BODY {
                    return write_response(&mut stream, &problem(Status(413), "request too large"))
                        .await;
                }
            }
            Err(error) => {
                let response = problem(Status(400), &error.to_string());
                return write_response(&mut stream, &response).await;
            }
        }
    };

    let body = match read_body(&mut stream, &request, &mut buffer, consumed).await {
        Ok(body) => body,
        Err(response) => return write_response(&mut stream, &response).await,
    };

    let response = api.handle(&request, &body).await;
    write_response(&mut stream, &response).await
}

/// Reads exactly the declared body, refusing anything oversized or unframed.
async fn read_body(
    stream: &mut TcpStream,
    request: &Request,
    buffer: &mut Vec<u8>,
    consumed: usize,
) -> Result<Vec<u8>, Response> {
    let length = match request.body_length() {
        Ok(selfhost_http::BodyLength::None) => 0,
        Ok(selfhost_http::BodyLength::Fixed(length)) => length,
        // Chunked would mean writing a dechunker for a client we wrote ourselves
        // and which has no reason to use it.
        Ok(selfhost_http::BodyLength::Chunked) => {
            return Err(problem(Status(411), "send a Content-Length rather than chunked framing"));
        }
        Err(error) => return Err(problem(Status(400), &error.to_string())),
    };

    if length as usize > MAX_BODY {
        return Err(problem(Status(413), "request too large"));
    }

    let mut body = buffer.split_off(consumed);
    let mut scratch = [0u8; 4096];
    while (body.len() as u64) < length {
        match stream.read(&mut scratch).await {
            Ok(0) => return Err(problem(Status(400), "body ended early")),
            Ok(read) => body.extend_from_slice(&scratch[..read]),
            Err(error) => return Err(problem(Status(400), &error.to_string())),
        }
    }
    body.truncate(length as usize);
    Ok(body)
}

/// Writes a response and flushes it.
async fn write_response(stream: &mut TcpStream, response: &Response) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(256);
    response
        .write_head(&mut out, false)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    if let Body::Bytes(bytes) = &response.body {
        out.extend_from_slice(bytes);
    }
    stream.write_all(&out).await?;
    stream.flush().await
}
