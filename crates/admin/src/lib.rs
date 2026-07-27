//! The loopback control API the console drives.
//!
//! # Why this is not on a site's hostname
//!
//! The API binds loopback and nothing else, and it is served on its own listener
//! rather than as a path on a site. A bug in a hosted website must not become a
//! way to read or control the deployment, and a reserved path prefix on a shared
//! listener is one routing mistake away from being reachable from the internet.
//! A separate socket cannot be reached by a request that arrived on the public one.
//!
//! Remote access is deliberately *not* a feature here. The console reaches a
//! remote daemon by tunnelling this port over SSH, which means the authentication
//! and the encryption are OpenSSH's rather than something invented for this.
//!
//! # Shape
//!
//! [`Api::handle`] turns a request into a response and touches no sockets, so
//! every route — including every way of getting the authorisation wrong — is
//! tested directly. [`serve`] is the thin part that owns the listener.

#![warn(missing_docs)]

pub mod store;
pub mod token;

use selfhost_http::{Body, Method, Request, Response, Status};
use selfhost_json::Json;
use selfhost_supervisor::Supervisor;
use selfhost_supervisor::state::{spec_from_json, spec_to_json};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
}

impl Api {
    /// Builds the API over a supervisor and the catalogue it persists to.
    pub fn new(supervisor: Supervisor, store: Store, token: Token) -> Self {
        Self { supervisor, store: Arc::new(store), token }
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
            (Method::Post, ["api", "services", name, action]) => self.act(name, action).await,
            _ => problem(Status(404), "no such endpoint"),
        }
    }

    /// Whether the request carries the right bearer token.
    fn authorised(&self, request: &Request) -> bool {
        request
            .headers
            .get_str("authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|presented| self.token.matches(presented.trim()))
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

        self.supervisor.install(spec).await;
        match self.supervisor.status(name).await {
            Some(status) => json(Status(200), status.to_json()),
            None => problem(Status(500), "the service was saved but did not install"),
        }
    }

    async fn uninstall(&self, name: &str) -> Response {
        if !self.supervisor.remove(name).await {
            return problem(Status(404), "no such service");
        }
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
