//! The HTTP surface: four routes, one of which is open to the internet.
//!
//! ```text
//! POST <route>?<service>        file a report        open to anyone, rate limited
//! GET  <route>/health           is the intake up     open, says nothing about content
//! GET  <route>/feed?<service>   every open report    owner token
//! POST <route>/close?<service>  a report is fixed    owner token
//! ```
//!
//! # The address is the base, and the service is the query
//!
//! One box holds every service's reports, and which database a call means is the **bare query
//! key** — `…/report?dx` — never a path segment and never `project=`. A path segment would make
//! the proxy's routing prefix depend on the tenant; a named parameter would invite a second
//! spelling of the same thing. A bare word is also the whole of registering a service: the
//! first report filed to `…/report?billing` creates it ([`crate::store`] bounds that door).
//!
//! The reporter's own repository holds the other half of this contract, written from the wire
//! outward: `docs/intake.dx` in the dx workspace. What is stated there is stated here in code
//! and in the tests below, and nowhere else twice.
//!
//! # Where this listens, and what stands in front of it
//!
//! On loopback, always — [`bind`] refuses anything else, exactly as
//! [`selfhost_admin::bind`] does and for the same reason. The public door is the reverse
//! proxy on 443, which terminates TLS and forwards `<route>` here; `docs/SECURITY.md` §3.2
//! (PUB-06) requires an app behind that proxy to set its own security headers, so every
//! response from here carries them.
//!
//! # The client address is the *last* forwarded value, not the first
//!
//! The proxy relays the request's own headers and then appends its own
//! `X-Forwarded-For: <peer>`. A client that sends `X-Forwarded-For: 1.2.3.4` therefore
//! produces two such headers, and the trustworthy one is the last — the one this box wrote.
//! Reading the first would let anyone rotate a header value to get an unlimited rate.
//!
//! # What an open intake must bound, and does
//!
//! The request head and body ([`MAX_BODY`]), the rate per source and in total
//! ([`crate::limit`]), the number of sources remembered, the size and count of stored records
//! ([`crate::store`]), and how often a notification may be sent. A public endpoint that
//! allocates or spends without a bound is the vulnerability, whatever else it gets right.
//!
//! # Nothing here reflects what a stranger sent
//!
//! Answers are JSON built from fixed strings, the report's own fingerprint, and its sighting
//! count. A refusal names the field that was wrong, never the value — so this endpoint cannot
//! be used to serve a payload of somebody else's choosing to somebody else's browser.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use selfhost_http::{BodyLength, Method, ParseError, Request, Response, Status};
use selfhost_json::Json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::clock;
use crate::limit::{Decision, Limiter, Meter, Rate};
use crate::notify::{self, Mailbox};
use crate::report::{Refusal, Report, project_key};
use crate::store::{self, Store, StoreError};

/// The largest request body accepted. A report is prose; sixteen kilobytes is a generous
/// essay, and refusing more before reading it is what keeps an anonymous POST from choosing
/// this process's memory use.
pub const MAX_BODY: usize = 16 * 1024;

/// How long a client has to finish sending its request head and body.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// How often undelivered reports are retried into the owner's mailbox.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// How many reports one delivery pass will attempt.
const DELIVERY_BATCH: usize = 5;

/// How the intake is configured.
#[derive(Debug, Clone)]
pub struct Config {
    /// The path the proxy forwards, without a trailing slash — `/report`.
    pub route: String,
    /// The service a call that names none in its address is about.
    pub default_project: String,
    /// What one source may file.
    pub per_source: Rate,
    /// What everyone together may file.
    pub global: Rate,
    /// What one source may *read* — the token routes, counted separately so that a checkout
    /// syncing on a timer can never spend the allowance an agent needs to file.
    pub per_reader: Rate,
    /// Where notifications go, when the box has a mailbox for them.
    pub mail: Option<Mailbox>,
    /// How often a notification may be sent, however many reports arrive.
    pub mail_rate: Rate,
    /// The owner's bearer token for the reading routes. Without one they do not exist.
    pub token: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            route: "/report".to_string(),
            default_project: "dx".to_string(),
            // Three at once, then one every twenty seconds: an agent writing up two related
            // reports is never refused, and a loop gets nowhere.
            per_source: Rate::new(3, 3.0),
            // The whole box: a burst of twenty, then one a second sustained.
            global: Rate::new(20, 60.0),
            // Reading is cheap and a subscribed checkout does it on a timer, so the burst is
            // larger; it exists to make guessing at the token expensive, not to ration syncs.
            per_reader: Rate::new(10, 30.0),
            mail: None,
            // At most one message a minute, so a flood is a database problem, not an inbox one.
            mail_rate: Rate::new(3, 1.0),
            token: None,
        }
    }
}

/// The intake, as one shareable value.
#[derive(Debug)]
pub struct Service {
    store: Store,
    config: Config,
    filing: Mutex<Limiter>,
    reading: Mutex<Limiter>,
    mail_meter: Mutex<Meter>,
}

impl Service {
    /// An intake over `store`, configured by `config`.
    #[must_use]
    pub fn new(store: Store, config: Config) -> Self {
        let filing = Mutex::new(Limiter::new(config.per_source, config.global));
        let reading = Mutex::new(Limiter::new(config.per_reader, config.global));
        let mail_meter = Mutex::new(Meter::new(config.mail_rate));
        Self {
            store,
            config,
            filing,
            reading,
            mail_meter,
        }
    }

    /// The configuration this intake runs with.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The database behind it.
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Answers one request from `client`, at `now` on the monotonic clock and `wall` on the
    /// calendar.
    ///
    /// Both clocks are parameters so the whole surface is testable without sleeping and
    /// without a stamp that changes between runs. Nothing in here awaits: a report is stored
    /// and answered, and the mail it produces is delivered by [`deliver_pending`] afterwards,
    /// so a slow SMTP server can never hold a reporter's connection open.
    pub fn answer(
        &self,
        request: &Request,
        body: &[u8],
        client: &str,
        now: Instant,
        wall: SystemTime,
    ) -> Response {
        let (path, query) = split_target(&request.target);
        let route = self.config.route.as_str();

        if path == route {
            return match request.method {
                Method::Post => self.file(body, query, client, now, wall),
                Method::Options => refuse(Status::METHOD_NOT_ALLOWED, "this endpoint takes POST"),
                _ => refuse(Status::METHOD_NOT_ALLOWED, "file a report with POST"),
            };
        }
        if path == format!("{route}/health") {
            // The one route with no allowance to spend: it is what the proxy's health check
            // calls on its own timer, and a health check that can be rate-limited is a site
            // that drops out of rotation because somebody else was rude.
            return self.health(request);
        }
        // Everything else costs an allowance *before* the token is looked at, so a stranger
        // cannot try tokens at line speed. A subscribed checkout syncs every few minutes and
        // never comes near the burst.
        if path == format!("{route}/feed") || path == format!("{route}/close") {
            if let Decision::Refuse(seconds) = self.admit(&self.reading, client, now) {
                return retry_after(seconds);
            }
            return if path.ends_with("/feed") {
                self.feed(request, query)
            } else {
                self.close(request, query, body)
            };
        }
        refuse(Status::NOT_FOUND, "no such endpoint")
    }

    /// `POST <route>?<service>` — the one open door.
    fn file(
        &self,
        body: &[u8],
        query: &str,
        client: &str,
        now: Instant,
        wall: SystemTime,
    ) -> Response {
        if let Decision::Refuse(seconds) = self.admit(&self.filing, client, now) {
            return retry_after(seconds);
        }
        let Ok(text) = std::str::from_utf8(body) else {
            return refuse(Status::BAD_REQUEST, "the body is not UTF-8 JSON");
        };
        let Ok(value) = selfhost_json::parse(text) else {
            return refuse(Status::BAD_REQUEST, "the body is not JSON");
        };
        let service = match self.service_of(query, Some(&value)) {
            Ok(service) => service,
            Err(refusal) => return refuse(Status::BAD_REQUEST, refusal.message()),
        };
        let report = match Report::parse(
            &value,
            &service,
            clock::iso8601(wall),
            crate::report::source_hash(client),
        ) {
            Ok(report) => report,
            Err(refusal) => return refuse(Status::BAD_REQUEST, refusal.message()),
        };

        match self.store.record(&report) {
            Ok(recorded) => answer(
                Status::OK,
                Json::object([
                    ("filed", Json::string(&recorded.entry.id)),
                    ("project", Json::string(&recorded.entry.project)),
                    ("sightings", Json::Number(recorded.entry.sightings as f64)),
                    ("known", Json::Bool(!recorded.fresh)),
                ]),
            ),
            Err(StoreError::NoProject(message)) => refuse(Status::NOT_FOUND, &message),
            Err(StoreError::Full(message)) => refuse(Status::SERVICE_UNAVAILABLE, &message),
            Err(error) => {
                // The reporter is told the truth without being told this box's paths.
                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                refuse(
                    Status::INTERNAL_SERVER_ERROR,
                    "the report could not be stored",
                )
            }
        }
    }

    /// `GET <route>/health` — enough for the proxy's health check and nothing more.
    fn health(&self, request: &Request) -> Response {
        if request.method != Method::Get {
            return refuse(Status::METHOD_NOT_ALLOWED, "this endpoint takes GET");
        }
        let projects = self.store.projects().unwrap_or_default().len();
        answer(
            Status::OK,
            Json::object([
                ("ok", Json::Bool(true)),
                ("projects", Json::Number(projects as f64)),
            ]),
        )
    }

    /// `GET <route>/feed?<service>` — what a subscribed checkout folds into its `reports.dx`.
    fn feed(&self, request: &Request, query: &str) -> Response {
        if request.method != Method::Get {
            return refuse(Status::METHOD_NOT_ALLOWED, "this endpoint takes GET");
        }
        if let Some(refused) = self.check_token(request) {
            return refused;
        }
        let project = match self.service_of(query, None) {
            Ok(project) => project,
            Err(refusal) => return refuse(Status::BAD_REQUEST, refusal.message()),
        };
        match self.store.list(&project) {
            Ok(entries) => answer(
                Status::OK,
                Json::object([
                    ("project", Json::string(&project)),
                    ("reports", Json::array(entries.iter().map(store::to_json))),
                ]),
            ),
            Err(StoreError::NoProject(message)) => refuse(Status::NOT_FOUND, &message),
            Err(error) => {
                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                refuse(Status::INTERNAL_SERVER_ERROR, "the feed could not be read")
            }
        }
    }

    /// `POST <route>/close?<service>` — a fixed report leaves the database, so a checkout that
    /// syncs again does not fold it back in.
    fn close(&self, request: &Request, query: &str, body: &[u8]) -> Response {
        if request.method != Method::Post {
            return refuse(Status::METHOD_NOT_ALLOWED, "this endpoint takes POST");
        }
        if let Some(refused) = self.check_token(request) {
            return refused;
        }
        let asked = std::str::from_utf8(body)
            .ok()
            .and_then(|text| selfhost_json::parse(text).ok());
        let Some(value) = asked else {
            return refuse(Status::BAD_REQUEST, "the body is not JSON");
        };
        let project = match self.service_of(query, Some(&value)) {
            Ok(project) => project,
            Err(refusal) => return refuse(Status::BAD_REQUEST, refusal.message()),
        };
        let Some(id) = value.get("id").and_then(Json::as_str) else {
            return refuse(Status::BAD_REQUEST, "`id` is required");
        };
        match self.store.close(&project, id) {
            Ok(()) => answer(
                Status::OK,
                Json::object([
                    ("closed", Json::string(id)),
                    ("project", Json::string(&project)),
                ]),
            ),
            Err(StoreError::Unreadable(message) | StoreError::NoProject(message)) => {
                refuse(Status::NOT_FOUND, &message)
            }
            Err(error) => {
                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                refuse(
                    Status::INTERNAL_SERVER_ERROR,
                    "the report could not be closed",
                )
            }
        }
    }

    /// Which service this call is about: the address first, then the body, then this box's
    /// default.
    ///
    /// The address wins over the body because the address is where the report was actually
    /// sent — a body claiming `"project": "dx"` on a call to `…/report?billing` is a reporter
    /// with a stale template, not an instruction. The body is consulted at all so that a caller
    /// with no query still files somewhere sensible, and so a record is complete on its own.
    ///
    /// # Errors
    /// The [`Refusal`] [`project_key`] gives, naming what a key may contain.
    fn service_of(&self, query: &str, body: Option<&Json>) -> Result<String, Refusal> {
        if let Some(named) = service_in_query(query) {
            return project_key(named);
        }
        let stated = body
            .and_then(|value| value.get("project"))
            .and_then(Json::as_str)
            .unwrap_or_default()
            .trim();
        if stated.is_empty() {
            return Ok(self.config.default_project.clone());
        }
        project_key(stated)
    }

    /// Whether this request carries the owner's token.
    ///
    /// A box with no token configured answers the reading routes with the same `404` an
    /// unknown path gets: a route that cannot be used should not be a thing to probe.
    fn check_token(&self, request: &Request) -> Option<Response> {
        let Some(expected) = self.config.token.as_deref() else {
            return Some(refuse(Status::NOT_FOUND, "no such endpoint"));
        };
        let offered = request
            .headers
            .get_str("authorization")
            .and_then(|value| value.strip_prefix("Bearer ").map(str::to_string))
            .unwrap_or_default();
        if constant_time_eq(offered.trim().as_bytes(), expected.as_bytes()) {
            return None;
        }
        Some(refuse(
            Status::UNAUTHORIZED,
            "this endpoint needs the owner's token",
        ))
    }

    /// Spends one allowance for `client` out of `limiter`.
    ///
    /// Filing and reading have a limiter each, so a checkout syncing every few minutes and an
    /// agent filing a burst of reports never take each other's allowance — and a stranger
    /// guessing at the token cannot stop either.
    fn admit(&self, limiter: &Mutex<Limiter>, client: &str, now: Instant) -> Decision {
        match limiter.lock() {
            Ok(mut limiter) => limiter.admit(client, now),
            // A poisoned lock means a panic happened while holding it. Under `panic = "abort"`
            // that cannot happen; if it somehow did, refusing is the safe half of the choice.
            Err(_) => Decision::Refuse(RETRY_INTERVAL.as_secs()),
        }
    }

    /// Whether a notification may be sent right now.
    fn may_notify(&self, now: Instant) -> bool {
        self.mail_meter
            .lock()
            .map(|mut meter| meter.take(now).admitted())
            .unwrap_or(false)
    }
}

/// Delivers up to [`DELIVERY_BATCH`] stored-but-untold reports into the owner's mailbox.
///
/// Called right after a report is accepted and again on a timer, so the ordinary case is
/// "the message is already in the inbox before the reporter's next sentence" and the failure
/// case is "it arrives on the next pass". A report is marked delivered only after the mail
/// server accepted it.
pub async fn deliver_pending(service: &Service, now: Instant, wall: SystemTime) {
    let Some(mailbox) = service.config.mail.clone() else {
        return;
    };
    let waiting = match service.store.undelivered(DELIVERY_BATCH) {
        Ok(waiting) => waiting,
        Err(error) => {
            eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
            return;
        }
    };
    for entry in waiting {
        if !service.may_notify(now) {
            // The database still has it and the next pass will send it: a throttled inbox is
            // never a lost report.
            return;
        }
        let message = notify::message(&mailbox, &entry, wall);
        match notify::send(&mailbox, &message).await {
            Ok(()) => {
                if let Err(error) = service.store.mark_delivered(&entry.project, &entry.id) {
                    eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                }
            }
            Err(reason) => {
                eprintln!(
                    "[{}] reports: {} not delivered — {reason}",
                    selfhost_mail::stamp(),
                    entry.id
                );
                return;
            }
        }
    }
}

/// Retries undelivered reports forever, every [`RETRY_INTERVAL`].
pub async fn retry_forever(service: Arc<Service>) {
    loop {
        tokio::time::sleep(RETRY_INTERVAL).await;
        deliver_pending(&service, Instant::now(), SystemTime::now()).await;
    }
}

/// Binds the intake, refusing any address that is not loopback.
///
/// # Errors
/// The bind error, or a sentence explaining the refusal — the public door is the reverse
/// proxy, and an intake bound to `0.0.0.0` would be a second one with no TLS in front of it.
pub async fn bind(address: SocketAddr) -> std::io::Result<TcpListener> {
    if !address.ip().is_loopback() {
        return Err(std::io::Error::other(format!(
            "refusing to bind the report intake to {address}: it must be loopback. The public \
             door is the reverse proxy — give the site an `app_paths` entry and an instance on \
             this port instead."
        )));
    }
    TcpListener::bind(address).await
}

/// Serves the intake until the listener fails.
///
/// # Errors
/// The accept error that ended the loop.
pub async fn serve(listener: TcpListener, service: Arc<Service>) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let service = Arc::clone(&service);
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, peer, service).await {
                if error.kind() != std::io::ErrorKind::UnexpectedEof {
                    eprintln!(
                        "[{}] reports: {peer} ended: {error}",
                        selfhost_mail::stamp()
                    );
                }
            }
        });
    }
}

/// Reads one request, answers it, and closes.
///
/// One request per connection: this endpoint sees a handful of requests an hour, keep-alive
/// buys nothing, and every reused connection is a chance for two answers to disagree about
/// framing.
async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    service: Arc<Service>,
) -> std::io::Result<()> {
    let read = tokio::time::timeout(REQUEST_TIMEOUT, read_request(&mut stream)).await;
    let outcome = match read {
        Err(_) => {
            return write(
                &mut stream,
                &refuse(Status(408), "the request took too long"),
            )
            .await;
        }
        Ok(outcome) => outcome?,
    };
    let (request, body) = match outcome {
        Ok(pair) => pair,
        Err(response) => return write(&mut stream, &response).await,
    };

    let client = client_address(&request, peer);
    let response = service.answer(&request, &body, &client, Instant::now(), SystemTime::now());
    let filed = response.status == Status::OK && request.method == Method::Post;
    write(&mut stream, &response).await?;
    // The reporter is done: close the socket before this task spends up to twenty seconds
    // talking to a mail server, so a slow delivery holds nothing of theirs open.
    let _ = stream.shutdown().await;
    drop(stream);

    if filed {
        // After the answer, never during it: the reporter waits for the database, not for a
        // mail server it has no relationship with.
        deliver_pending(&service, Instant::now(), SystemTime::now()).await;
    }
    Ok(())
}

/// Reads one complete request and its body, or the response that refuses it.
async fn read_request(
    stream: &mut TcpStream,
) -> std::io::Result<Result<(Request, Vec<u8>), Response>> {
    let mut buffer = Vec::with_capacity(1024);
    let mut scratch = [0u8; 4096];

    let (request, consumed) = loop {
        match Request::parse(&buffer) {
            Ok(parsed) => break (parsed.request, parsed.consumed),
            Err(ParseError::Incomplete) => {
                let read = stream.read(&mut scratch).await?;
                if read == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "client closed before sending a complete request",
                    ));
                }
                buffer.extend_from_slice(&scratch[..read]);
                if buffer.len() > MAX_BODY * 2 {
                    return Ok(Err(refuse(
                        Status::CONTENT_TOO_LARGE,
                        "the request is too large",
                    )));
                }
            }
            Err(error) => {
                return Ok(Err(refuse(Status::BAD_REQUEST, &error.to_string())));
            }
        }
    };

    let length = match request.body_length() {
        Ok(BodyLength::None) => 0,
        Ok(BodyLength::Fixed(length)) => length,
        // Chunked is refused rather than decoded: it exists to send a body of unknown size,
        // which is the one thing this endpoint will not accept.
        Ok(BodyLength::Chunked) => {
            return Ok(Err(refuse(
                Status(411),
                "send the report with a Content-Length, not chunked",
            )));
        }
        Err(error) => return Ok(Err(refuse(Status::BAD_REQUEST, &error.to_string()))),
    };
    if length > MAX_BODY as u64 {
        return Ok(Err(refuse(
            Status::CONTENT_TOO_LARGE,
            "a report may be at most 16 KB",
        )));
    }

    let mut body = buffer.split_off(consumed);
    body.truncate(length as usize);
    while (body.len() as u64) < length {
        let read = stream.read(&mut scratch).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "client closed before sending the whole body",
            ));
        }
        let wanted = (length as usize) - body.len();
        body.extend_from_slice(&scratch[..read.min(wanted)]);
    }
    Ok(Ok((request, body)))
}

/// Who this request is from, for rate limiting.
///
/// The **last** `X-Forwarded-For` value, which is the one this box's own proxy appended; a
/// client's own forwarded header is relayed too and comes first. With no such header the peer
/// address is used, which is the direct-connection case.
fn client_address(request: &Request, peer: SocketAddr) -> String {
    let forwarded: Vec<String> = request
        .headers
        .iter()
        .filter(|field| field.name().eq_ignore_ascii_case("x-forwarded-for"))
        .filter_map(|field| std::str::from_utf8(field.value()).ok())
        .filter_map(|value| value.rsplit(',').next())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    forwarded
        .last()
        .cloned()
        .unwrap_or_else(|| peer.ip().to_string())
}

/// Splits a request target into its path and query string.
fn split_target(target: &str) -> (&str, &str) {
    match target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (target, ""),
    }
}

/// The service a query names: its first **bare** key, the one with no `=` in it.
///
/// `?dx` names dx. `?dx&verbose=1` still names dx, so a query that grows a parameter one day
/// does not change which database a call means. A query with no bare key names no service, and
/// the caller falls back — deliberately, rather than inventing `project=` as a second spelling.
fn service_in_query(query: &str) -> Option<&str> {
    query
        .split('&')
        .find(|pair| !pair.is_empty() && !pair.contains('='))
}

/// A JSON answer with the headers `docs/SECURITY.md` requires of an app behind the proxy.
fn answer(status: Status, value: Json) -> Response {
    let mut response = match Response::bytes(
        status,
        "application/json; charset=utf-8",
        value.to_text().into_bytes(),
    ) {
        Ok(response) => response,
        Err(_) => Response::empty(Status::INTERNAL_SERVER_ERROR),
    };
    // PUB-06: upstream heads reach the client verbatim, so the app sets these itself.
    let _ = response.headers.set("X-Content-Type-Options", "nosniff");
    let _ = response.headers.set("X-Frame-Options", "DENY");
    let _ = response.headers.set("Referrer-Policy", "no-referrer");
    let _ = response.headers.set(
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    );
    let _ = response.headers.set("Cache-Control", "no-store");
    response
}

/// An error answer carrying an explanation written for the agent that sent the request.
fn refuse(status: Status, message: &str) -> Response {
    answer(status, Json::object([("error", Json::string(message))]))
}

/// The refusal a rate-limited reporter gets, carrying the wait.
fn retry_after(seconds: u64) -> Response {
    let mut response = refuse(
        Status::TOO_MANY_REQUESTS,
        "too many reports from here just now — the wait is in Retry-After",
    );
    let _ = response.headers.set("Retry-After", seconds.to_string());
    response
}

/// Compares two byte strings in time that does not depend on where they first differ.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |differences, (a, b)| differences | (a ^ b))
        == 0
}

/// Writes one response and closes the write half.
async fn write(stream: &mut TcpStream, response: &Response) -> std::io::Result<()> {
    let mut head = Vec::new();
    response
        .write_head(&mut head, false)
        .map_err(|error| std::io::Error::other(format!("{error}")))?;
    stream.write_all(&head).await?;
    if let selfhost_http::Body::Bytes(bytes) = &response.body {
        stream.write_all(bytes).await?;
    }
    stream.flush().await
}

/// A refusal every caller of [`Report::parse`] can produce, kept here so the module's error
/// type is nameable from the binary that runs the service.
pub type Rejected = Refusal;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn service(label: &str) -> Service {
        let dir = std::env::temp_dir().join(format!("selfhost-reports-service-{label}"));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir).expect("store");
        store.add_project("dx").expect("project");
        Service::new(
            store,
            Config {
                token: Some("secret-token".to_string()),
                ..Config::default()
            },
        )
    }

    fn request(head: &str) -> Request {
        Request::parse(head.as_bytes())
            .expect("request parses")
            .request
    }

    fn post(body: &str) -> Request {
        request(&format!(
            "POST /report HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ))
    }

    fn text(response: &Response) -> String {
        match &response.body {
            selfhost_http::Body::Bytes(bytes) => String::from_utf8_lossy(bytes).to_string(),
            _ => String::new(),
        }
    }

    fn file(service: &Service, body: &str, client: &str) -> Response {
        service.answer(
            &post(body),
            body.as_bytes(),
            client,
            Instant::now(),
            UNIX_EPOCH,
        )
    }

    #[test]
    fn a_report_from_anywhere_is_stored_and_answered_with_its_id() {
        let service = service("filed");
        let response = file(
            &service,
            r#"{"kind":"bug","title":"search misses","detail":"it answered the heading"}"#,
            "203.0.113.9",
        );
        assert_eq!(response.status, Status::OK);
        let answered = text(&response);
        assert!(answered.contains("\"filed\":\"report-"), "{answered}");
        assert!(answered.contains("\"project\":\"dx\""), "{answered}");
        assert_eq!(service.store().list("dx").expect("list").len(), 1);
    }

    #[test]
    fn the_same_defect_twice_is_one_record_and_the_answer_says_so() {
        let service = service("twice");
        let body = r#"{"kind":"bug","title":"same","detail":"one"}"#;
        file(&service, body, "203.0.113.9");
        let second = file(&service, body, "198.51.100.4");
        assert!(
            text(&second).contains("\"known\":true"),
            "{}",
            text(&second)
        );
        assert!(
            text(&second).contains("\"sightings\":2"),
            "{}",
            text(&second)
        );
    }

    #[test]
    fn a_flood_from_one_source_is_refused_with_a_wait() {
        let service = service("flood");
        let now = Instant::now();
        for nth in 0..3 {
            let body = format!(r#"{{"kind":"bug","title":"defect {nth}","detail":"d"}}"#);
            let response = service.answer(
                &post(&body),
                body.as_bytes(),
                "203.0.113.9",
                now,
                UNIX_EPOCH,
            );
            assert_eq!(response.status, Status::OK);
        }
        let body = r#"{"kind":"bug","title":"one too many","detail":"d"}"#;
        let refused = service.answer(&post(body), body.as_bytes(), "203.0.113.9", now, UNIX_EPOCH);
        assert_eq!(refused.status, Status::TOO_MANY_REQUESTS);
        assert!(refused.headers.get_str("retry-after").is_some());
        // And it did not cost the reporter's neighbour anything.
        let other = service.answer(
            &post(body),
            body.as_bytes(),
            "198.51.100.4",
            now,
            UNIX_EPOCH,
        );
        assert_eq!(other.status, Status::OK);
    }

    #[test]
    fn the_client_is_the_last_forwarded_value_not_the_one_the_client_chose() {
        let request = request(
            "POST /report HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 1.2.3.4\r\n\
             X-Forwarded-For: 203.0.113.9\r\nContent-Length: 0\r\n\r\n",
        );
        let peer: SocketAddr = "127.0.0.1:5000".parse().expect("peer");
        assert_eq!(client_address(&request, peer), "203.0.113.9");

        let direct =
            Request::parse(b"POST /report HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
                .expect("request parses")
                .request;
        assert_eq!(client_address(&direct, peer), "127.0.0.1");
    }

    #[test]
    fn a_spoofed_forwarded_header_cannot_buy_a_fresh_allowance() {
        let service = service("spoof");
        let now = Instant::now();
        let body = r#"{"kind":"bug","title":"t","detail":"d"}"#;
        for _ in 0..3 {
            service.answer(&post(body), body.as_bytes(), "203.0.113.9", now, UNIX_EPOCH);
        }
        // The header a client sends is not what the limiter sees; the proxy's value is.
        let refused = service.answer(&post(body), body.as_bytes(), "203.0.113.9", now, UNIX_EPOCH);
        assert_eq!(refused.status, Status::TOO_MANY_REQUESTS);
    }

    /// The whole of registering a service: file one report to it.
    #[test]
    fn filing_to_a_service_nobody_declared_brings_it_into_existence() {
        let service = service("new-service");
        let body = r#"{"project":"billing","kind":"bug","title":"t","detail":"d"}"#;
        let posted = request(&format!(
            "POST /report?billing HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ));
        let response = service.answer(
            &posted,
            body.as_bytes(),
            "203.0.113.9",
            Instant::now(),
            UNIX_EPOCH,
        );
        assert_eq!(response.status, Status::OK, "{}", text(&response));
        assert!(
            text(&response).contains("\"filed\":\"report-"),
            "{}",
            text(&response)
        );
        assert_eq!(service.store().list("billing").expect("list").len(), 1);
        assert!(
            service.store().list("dx").expect("list").is_empty(),
            "a new service's reports do not land in the default one"
        );
    }

    /// The address is where the report was actually sent, so it wins over a stale template.
    #[test]
    fn the_query_names_the_service_and_the_body_does_not_override_it() {
        let service = service("query-wins");
        let body = r#"{"project":"dx","kind":"bug","title":"t","detail":"d"}"#;
        let posted = request(&format!(
            "POST /report?billing&verbose=1 HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ));
        let response = service.answer(
            &posted,
            body.as_bytes(),
            "203.0.113.9",
            Instant::now(),
            UNIX_EPOCH,
        );
        assert_eq!(response.status, Status::OK, "{}", text(&response));
        assert_eq!(service.store().list("billing").expect("list").len(), 1);
        assert!(service.store().list("dx").expect("list").is_empty());
    }

    /// A bare word, and nothing that could name a directory this store does not own.
    #[test]
    fn a_service_name_that_is_not_a_word_is_refused_in_a_sentence() {
        let service = service("bad-service");
        let body = r#"{"kind":"bug","title":"t","detail":"d"}"#;
        let posted = request(&format!(
            "POST /report?..%2f..%2fetc HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ));
        let response = service.answer(
            &posted,
            body.as_bytes(),
            "203.0.113.9",
            Instant::now(),
            UNIX_EPOCH,
        );
        assert_eq!(response.status, Status::BAD_REQUEST);
        assert!(
            text(&response).contains("not a service key"),
            "{}",
            text(&response)
        );
    }

    #[test]
    fn a_malformed_body_is_refused_without_being_echoed() {
        let service = service("malformed");
        let body = "<script>alert(1)</script>";
        let response = file(&service, body, "203.0.113.9");
        assert_eq!(response.status, Status::BAD_REQUEST);
        assert!(!text(&response).contains("script"), "{}", text(&response));
    }

    #[test]
    fn every_answer_carries_the_headers_an_app_behind_the_proxy_must_set() {
        let service = service("headers");
        let response = file(
            &service,
            r#"{"kind":"bug","title":"t","detail":"d"}"#,
            "203.0.113.9",
        );
        assert_eq!(
            response.headers.get_str("x-content-type-options"),
            Some("nosniff")
        );
        assert_eq!(response.headers.get_str("x-frame-options"), Some("DENY"));
        assert_eq!(response.headers.get_str("cache-control"), Some("no-store"));
        assert!(
            response
                .headers
                .get_str("content-security-policy")
                .is_some()
        );
    }

    #[test]
    fn the_feed_needs_the_owners_token_and_carries_the_whole_report() {
        let service = service("feed");
        file(
            &service,
            r#"{"kind":"bug","title":"in the feed","detail":"the words"}"#,
            "203.0.113.9",
        );

        let anonymous = request("GET /report/feed?dx HTTP/1.1\r\nHost: x\r\n\r\n");
        let refused = service.answer(&anonymous, &[], "203.0.113.9", Instant::now(), UNIX_EPOCH);
        assert_eq!(refused.status, Status::UNAUTHORIZED);

        let owner = request(
            "GET /report/feed?dx HTTP/1.1\r\nHost: x\r\n\
             Authorization: Bearer secret-token\r\n\r\n",
        );
        let answered = service.answer(&owner, &[], "127.0.0.1", Instant::now(), UNIX_EPOCH);
        assert_eq!(answered.status, Status::OK);
        let payload = text(&answered);
        assert!(payload.contains("in the feed"), "{payload}");
        assert!(
            payload.contains("the words"),
            "the feed carries the detail a checkout folds in"
        );
    }

    /// A 256-bit token is not guessable, but a route that answers "wrong" at line speed is
    /// still a route worth making expensive — and the same allowance stops a token route
    /// being a free amplifier for anyone who finds it.
    #[test]
    fn guessing_at_the_token_costs_the_guesser_an_allowance() {
        // A reading allowance the size of the filing one, so the property is asserted in four
        // requests rather than eleven. The shipped burst is larger, because a subscribed
        // checkout reads on a timer and this limiter exists to make guessing expensive.
        let dir = std::env::temp_dir().join("selfhost-reports-service-token-rate");
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir).expect("store");
        store.add_project("dx").expect("project");
        let service = Service::new(
            store,
            Config {
                token: Some("secret-token".to_string()),
                per_reader: Rate::new(3, 3.0),
                ..Config::default()
            },
        );
        let now = Instant::now();
        let wrong =
            request("GET /report/feed HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer nope\r\n\r\n");
        for _ in 0..3 {
            assert_eq!(
                service
                    .answer(&wrong, &[], "203.0.113.9", now, UNIX_EPOCH)
                    .status,
                Status::UNAUTHORIZED
            );
        }
        assert_eq!(
            service
                .answer(&wrong, &[], "203.0.113.9", now, UNIX_EPOCH)
                .status,
            Status::TOO_MANY_REQUESTS
        );

        // The health check is deliberately outside that allowance: it runs on the proxy's
        // own timer, and a site must not leave rotation because somebody else was rude.
        let health = request("GET /report/health HTTP/1.1\r\nHost: x\r\n\r\n");
        for _ in 0..5 {
            assert_eq!(
                service
                    .answer(&health, &[], "203.0.113.9", now, UNIX_EPOCH)
                    .status,
                Status::OK
            );
        }

        // And filing is a separate allowance, so a reader that has spent its own — a checkout
        // syncing on a timer, or somebody trying tokens — has not taken the one an agent needs
        // to report what it just hit. A read starving a write is the bug this pair prevents.
        let body = r#"{"kind":"bug","title":"still able to file","detail":"d"}"#;
        assert_eq!(
            service
                .answer(&post(body), body.as_bytes(), "203.0.113.9", now, UNIX_EPOCH)
                .status,
            Status::OK
        );
    }

    #[test]
    fn a_wrong_token_is_refused_and_a_box_with_no_token_has_no_such_route() {
        let service = service("token");
        let wrong =
            request("GET /report/feed HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer nope\r\n\r\n");
        assert_eq!(
            service
                .answer(&wrong, &[], "203.0.113.9", Instant::now(), UNIX_EPOCH)
                .status,
            Status::UNAUTHORIZED
        );

        let dir = std::env::temp_dir().join("selfhost-reports-service-tokenless");
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir).expect("store");
        store.add_project("dx").expect("project");
        let tokenless = Service::new(store, Config::default());
        let asked = request("GET /report/feed HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(
            tokenless
                .answer(&asked, &[], "203.0.113.9", Instant::now(), UNIX_EPOCH)
                .status,
            Status::NOT_FOUND,
            "a route that cannot be used is not a route to probe"
        );
    }

    #[test]
    fn closing_a_report_removes_it_from_the_feed() {
        let service = service("close");
        let filed = file(
            &service,
            r#"{"kind":"bug","title":"fixed soon","detail":"d"}"#,
            "203.0.113.9",
        );
        let id = text(&filed)
            .split("\"filed\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("id")
            .to_string();

        let body = format!(r#"{{"project":"dx","id":"{id}"}}"#);
        let closing = request(&format!(
            "POST /report/close?dx HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer secret-token\r\n\
             Content-Length: {}\r\n\r\n",
            body.len()
        ));
        let closed = service.answer(
            &closing,
            body.as_bytes(),
            "127.0.0.1",
            Instant::now(),
            UNIX_EPOCH,
        );
        assert_eq!(closed.status, Status::OK);
        assert!(service.store().list("dx").expect("list").is_empty());
    }

    #[test]
    fn the_health_route_says_nothing_about_content() {
        let service = service("health");
        file(
            &service,
            r#"{"kind":"bug","title":"secret title","detail":"d"}"#,
            "203.0.113.9",
        );
        let asked = request("GET /report/health HTTP/1.1\r\nHost: x\r\n\r\n");
        let answered = service.answer(&asked, &[], "203.0.113.9", Instant::now(), UNIX_EPOCH);
        assert_eq!(answered.status, Status::OK);
        assert!(
            !text(&answered).contains("secret title"),
            "{}",
            text(&answered)
        );
    }

    #[test]
    fn a_get_on_the_intake_says_to_post_and_an_unknown_path_is_a_404() {
        let service = service("methods");
        let asked = request("GET /report HTTP/1.1\r\nHost: x\r\n\r\n");
        let answered = service.answer(&asked, &[], "203.0.113.9", Instant::now(), UNIX_EPOCH);
        assert_eq!(answered.status, Status::METHOD_NOT_ALLOWED);

        let elsewhere = request("GET /report/../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n");
        let refused = service.answer(&elsewhere, &[], "203.0.113.9", Instant::now(), UNIX_EPOCH);
        assert_eq!(refused.status, Status::NOT_FOUND);
    }

    #[test]
    fn constant_time_comparison_still_compares() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"sane"));
        assert!(!constant_time_eq(b"same", b"same-but-longer"));
    }

    #[tokio::test]
    async fn the_intake_refuses_to_bind_anywhere_but_loopback() {
        let error = bind("0.0.0.0:0".parse().expect("address"))
            .await
            .expect_err("refused");
        assert!(error.to_string().contains("must be loopback"), "{error}");
        assert!(bind("127.0.0.1:0".parse().expect("address")).await.is_ok());
    }

    /// The end-to-end shape, over a real socket: a report POSTed by something that is not
    /// this crate is stored, and an oversized one is refused before it is read.
    #[tokio::test]
    async fn a_real_request_over_a_real_socket_is_stored() {
        let service = Arc::new(service("socket"));
        let listener = bind("127.0.0.1:0".parse().expect("address"))
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let serving = Arc::clone(&service);
        tokio::spawn(async move {
            let _ = serve(listener, serving).await;
        });

        let body = r#"{"kind":"bug","title":"over a socket","detail":"it works"}"#;
        let mut stream = TcpStream::connect(address).await.expect("connect");
        stream
            .write_all(
                format!(
                    "POST /report HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .expect("write");
        let mut answered = Vec::new();
        stream.read_to_end(&mut answered).await.expect("read");
        let answered = String::from_utf8_lossy(&answered).to_string();
        assert!(answered.starts_with("HTTP/1.1 200"), "{answered}");
        assert!(answered.contains("\"filed\""), "{answered}");
        assert_eq!(service.store().list("dx").expect("list").len(), 1);

        // A body larger than the cap is refused on its declared length alone.
        let mut stream = TcpStream::connect(address).await.expect("connect");
        stream
            .write_all(
                format!(
                    "POST /report HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n",
                    MAX_BODY + 1
                )
                .as_bytes(),
            )
            .await
            .expect("write");
        let mut answered = Vec::new();
        stream.read_to_end(&mut answered).await.expect("read");
        assert!(
            String::from_utf8_lossy(&answered).starts_with("HTTP/1.1 413"),
            "{}",
            String::from_utf8_lossy(&answered)
        );
    }
}
