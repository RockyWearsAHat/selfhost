//! An ACME (RFC 8555) client for issuing this deployment's TLS certificates.
//!
//! The crate owns everything above the socket, in keeping with the project's
//! dependency policy: the JSON on the wire, the JWS signing, the order state
//! machine, and the HTTP/1.1 request/response exchange. `rustls`/`ring` provide
//! only the transport cryptography and the P-256 primitives — the same line the
//! rest of the codebase draws.
//!
//! It touches nothing of the proxy directly. Issued material leaves as PEM
//! ([`IssuedCertificate`]); the CLI installs it into the certificate store. The
//! HTTP-01 challenge directory is reached through a plain `&Path`.
//!
//! # The flow
//!
//! [`Acme::connect`] fetches the [`directory`](protocol::Directory), loads or
//! creates the account key, and registers the account. [`Acme::issue`] then runs
//! the order: place each identifier, answer its HTTP-01 challenge via the
//! [`solver`], poll to `valid`, finalize with a [`csr`], and download the chain.
//!
//! # Module map
//!
//! - [`transport`] — the outbound HTTPS client (this is the wire, so we own it).
//! - [`protocol`] — the wire objects and their statuses (the reading half).
//! - [`solver`] — the HTTP-01 write side, coordinating with the proxy's serving.
//! - `jose` / `csr` — ES256 account key + JWS, and the finalize CSR.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod protocol;
pub mod solver;
pub mod transport;

mod csr;
mod jose;

use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;

use selfhost_config::AcmeEnvironment;
use selfhost_http::Headers;
use selfhost_json::Json;

use crate::csr::build_csr;
use crate::jose::{base64url, sign_jws, AccountKey};
use crate::protocol::{Authorization, AuthzStatus, Directory, Order, OrderStatus};
use crate::transport::{HttpResponse, Url};

/// Let's Encrypt's staging directory — untrusted certs, generous rate limits.
///
/// The default. Production permits only five duplicate certificates per week, so
/// a misconfigured retry against a name that does not yet resolve here would
/// exhaust it in minutes; staging is where that mistake is cheap.
pub const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// Let's Encrypt's production directory — browser-trusted, strict rate limits.
pub const LETSENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// The most times an order or authorization is polled before giving up.
const MAX_POLLS: usize = 10;

/// How long to wait between polls when the CA does not send a `Retry-After`.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// The directory URL for an environment; staging unless [`AcmeEnvironment::Production`].
///
/// [`AcmeEnvironment::SelfSigned`] never issues over ACME, so it maps to staging
/// defensively rather than panicking — a self-signed deployment simply never
/// calls into this crate.
pub fn directory_url(environment: AcmeEnvironment) -> &'static str {
    match environment {
        AcmeEnvironment::Production => LETSENCRYPT_PRODUCTION,
        AcmeEnvironment::Staging | AcmeEnvironment::SelfSigned => LETSENCRYPT_STAGING,
    }
}

/// A future returned by the [`Http`] transport: boxed so the trait is
/// dyn-compatible, and `Send` so issuance may run on a multi-threaded runtime.
pub type HttpFuture<'a> =
    Pin<Box<dyn Future<Output = Result<HttpResponse, AcmeError>> + Send + 'a>>;

/// The outbound HTTP surface the ACME driver needs: one `GET`, one `POST`.
///
/// [`transport::HttpsClient`] is the production implementation; a test supplies a
/// mock. The driver depends only on this trait, which is what lets the whole
/// state machine be exercised with scripted responses and no socket.
pub trait Http: Send + Sync {
    /// Fetches `url` — used for the directory and for `newNonce`.
    fn get<'a>(&'a self, url: &'a Url) -> HttpFuture<'a>;
    /// Posts `body` to `url` with `content_type` (ACME uses `application/jose+json`).
    fn post<'a>(&'a self, url: &'a Url, content_type: &'a str, body: &'a [u8]) -> HttpFuture<'a>;
}

impl Http for transport::HttpsClient {
    fn get<'a>(&'a self, url: &'a Url) -> HttpFuture<'a> {
        Box::pin(transport::HttpsClient::get(self, url))
    }
    fn post<'a>(&'a self, url: &'a Url, content_type: &'a str, body: &'a [u8]) -> HttpFuture<'a> {
        Box::pin(transport::HttpsClient::post(self, url, content_type, body))
    }
}

/// A certificate issued by the CA: the chain and its matching private key, as PEM.
///
/// The only thing that crosses the boundary back to the CLI. The key is the leaf
/// key generated for the CSR, never the account key.
pub struct IssuedCertificate {
    /// The certificate chain in PEM order (leaf first).
    pub chain_pem: String,
    /// The leaf private key in PEM form.
    pub key_pem: String,
}

/// A connected, registered ACME account ready to issue certificates.
///
/// Construct with [`Acme::connect`], then call [`Acme::issue`] per certificate.
/// One `Acme` corresponds to one account key; it is `Send + Sync` so a renewal
/// task can own it across `await`s.
pub struct Acme {
    http: Box<dyn Http>,
    key: AccountKey,
    directory: Directory,
    /// The account URL, used as the JWS `kid` on every request after newAccount.
    kid: Mutex<Option<String>>,
    /// The next anti-replay nonce, refreshed from every response's `Replay-Nonce`.
    nonce: Mutex<Option<String>>,
}

impl Acme {
    /// Connects to the CA, loads or creates the account key, and registers.
    ///
    /// The transport is injected rather than built here, so the flow can be
    /// driven by a mock in tests; production passes a [`transport::HttpsClient`].
    /// The account key is read from `acme_dir/account.key` if present, otherwise
    /// generated and written there mode 0600. `acme_email`, when non-empty,
    /// becomes the account's `mailto:` contact.
    pub async fn connect(
        http: impl Http + 'static,
        environment: AcmeEnvironment,
        acme_email: &str,
        acme_dir: &Path,
    ) -> Result<Self, AcmeError> {
        let key = load_or_create_account_key(acme_dir)?;

        let http: Box<dyn Http> = Box::new(http);
        let directory_document = {
            let url = Url::parse(directory_url(environment))?;
            let response = http.get(&url).await?;
            body_json(&response)?
        };
        let directory = Directory::parse(&directory_document)?;

        let acme = Self {
            http,
            key,
            directory,
            kid: Mutex::new(None),
            nonce: Mutex::new(None),
        };

        let mut fields = vec![("termsOfServiceAgreed", Json::Bool(true))];
        if !acme_email.is_empty() {
            fields.push((
                "contact",
                Json::array([Json::string(format!("mailto:{acme_email}"))]),
            ));
        }
        let payload = Json::object(fields).to_text();
        let new_account_url = acme.directory.new_account.clone();
        let response = acme.post(&new_account_url, payload.as_bytes(), Jws::Jwk).await?;
        let account_url = response.headers.get_str("location").ok_or_else(|| AcmeError::Protocol {
            kind: "newAccount".to_owned(),
            detail: "account registration returned no Location header".to_owned(),
        })?;
        *acme.kid.lock().expect("kid mutex is never poisoned") = Some(account_url.to_owned());

        Ok(acme)
    }

    /// Issues a certificate for `domains` (SANs; `domains[0]` is the CN).
    ///
    /// Runs the full order and, whatever the outcome, removes every challenge
    /// token it placed under `challenge_dir` before returning — a token left
    /// behind is a stale proof of control.
    pub async fn issue(
        &self,
        domains: &[String],
        challenge_dir: &Path,
    ) -> Result<IssuedCertificate, AcmeError> {
        if domains.is_empty() {
            return Err(AcmeError::Crypto("cannot issue a certificate for zero domains".to_owned()));
        }

        let mut placed_tokens = Vec::new();
        let outcome = self.run_order(domains, challenge_dir, &mut placed_tokens).await;
        for token in &placed_tokens {
            // Cleanup is best-effort: the order's result is what matters, and a
            // failed delete must not mask a successful issuance.
            let _ = solver::remove(challenge_dir, token).await;
        }
        outcome
    }

    /// The order itself, factored out so [`issue`](Self::issue) can clean up around it.
    async fn run_order(
        &self,
        domains: &[String],
        challenge_dir: &Path,
        placed_tokens: &mut Vec<String>,
    ) -> Result<IssuedCertificate, AcmeError> {
        let order_url;
        let order = {
            let identifiers = Json::array(domains.iter().map(|domain| {
                Json::object([("type", Json::string("dns")), ("value", Json::string(domain.as_str()))])
            }));
            let payload = Json::object([("identifiers", identifiers)]).to_text();
            let response = self.post(&self.directory.new_order, payload.as_bytes(), Jws::Kid).await?;
            order_url = response
                .headers
                .get_str("location")
                .ok_or_else(|| AcmeError::Protocol {
                    kind: "newOrder".to_owned(),
                    detail: "order creation returned no Location header".to_owned(),
                })?
                .to_owned();
            Order::parse(&body_json(&response)?, order_url.clone())?
        };

        let thumbprint = self.key.thumbprint();
        for authorization_url in &order.authorizations {
            self.authorize(authorization_url, &thumbprint, challenge_dir, placed_tokens).await?;
        }

        let material = build_csr(domains)?;
        let finalize_payload =
            Json::object([("csr", Json::string(base64url(&material.csr_der)))]).to_text();
        self.post(&order.finalize, finalize_payload.as_bytes(), Jws::Kid).await?;

        let certificate_url = self.poll_order(&order_url).await?;
        let response = self.post_as_get(&certificate_url).await?;
        let chain_pem = String::from_utf8(response.body).map_err(|_| AcmeError::Protocol {
            kind: "certificate".to_owned(),
            detail: "certificate chain was not UTF-8 PEM".to_owned(),
        })?;

        Ok(IssuedCertificate { chain_pem, key_pem: material.key_pem })
    }

    /// Proves control of one identifier via its HTTP-01 challenge.
    ///
    /// Fetches the authorization; if already `valid` (a reused authorization),
    /// returns at once. Otherwise places the key-authorization file, triggers the
    /// challenge, and polls the authorization to `valid`.
    async fn authorize(
        &self,
        authorization_url: &str,
        thumbprint: &str,
        challenge_dir: &Path,
        placed_tokens: &mut Vec<String>,
    ) -> Result<(), AcmeError> {
        let authorization = Authorization::parse(&body_json(&self.post_as_get(authorization_url).await?)?)?;
        if authorization.status == AuthzStatus::Valid {
            return Ok(());
        }

        let challenge = protocol::http01_challenge(&authorization).ok_or_else(|| AcmeError::Protocol {
            kind: "authorization".to_owned(),
            detail: "the CA offered no http-01 challenge".to_owned(),
        })?;
        let key_authorization = solver::key_authorization(&challenge.token, thumbprint);
        solver::place(challenge_dir, &challenge.token, &key_authorization).await?;
        placed_tokens.push(challenge.token.clone());

        // An empty JSON object tells the CA the challenge is ready (RFC 8555 §7.5.1).
        self.post(&challenge.url, b"{}", Jws::Kid).await?;
        self.poll_authorization(authorization_url).await
    }

    /// Polls an authorization until it is `valid`, or fails/times out.
    async fn poll_authorization(&self, authorization_url: &str) -> Result<(), AcmeError> {
        for _ in 0..MAX_POLLS {
            let response = self.post_as_get(authorization_url).await?;
            let authorization = Authorization::parse(&body_json(&response)?)?;
            match authorization.status {
                AuthzStatus::Valid => return Ok(()),
                AuthzStatus::Pending => {}
                terminal => {
                    // Name the identifier and quote the CA's own reason: an
                    // order covers several names, and "Invalid" alone says
                    // neither which one failed nor why.
                    let detail = match protocol::http01_challenge(&authorization)
                        .and_then(|challenge| challenge.error.as_deref())
                    {
                        Some(reason) => format!(
                            "{}: authorization ended in {terminal:?} — {reason}",
                            authorization.identifier
                        ),
                        None => format!(
                            "{}: authorization ended in {terminal:?}",
                            authorization.identifier
                        ),
                    };
                    return Err(AcmeError::Protocol { kind: "authorization".to_owned(), detail });
                }
            }
            tokio::time::sleep(retry_after(&response.headers).unwrap_or(POLL_INTERVAL)).await;
        }
        Err(AcmeError::Timeout)
    }

    /// Polls an order until it is `valid`, returning its certificate URL.
    async fn poll_order(&self, order_url: &str) -> Result<String, AcmeError> {
        for _ in 0..MAX_POLLS {
            let response = self.post_as_get(order_url).await?;
            let order = Order::parse(&body_json(&response)?, order_url.to_owned())?;
            match order.status {
                OrderStatus::Valid => {
                    return order.certificate.ok_or_else(|| AcmeError::Protocol {
                        kind: "order".to_owned(),
                        detail: "a valid order carried no certificate URL".to_owned(),
                    });
                }
                OrderStatus::Pending | OrderStatus::Ready | OrderStatus::Processing => {}
                OrderStatus::Invalid => {
                    return Err(AcmeError::Protocol {
                        kind: "order".to_owned(),
                        detail: "the order became invalid".to_owned(),
                    });
                }
            }
            tokio::time::sleep(retry_after(&response.headers).unwrap_or(POLL_INTERVAL)).await;
        }
        Err(AcmeError::Timeout)
    }

    /// A signed POST-as-GET: an empty payload, so a resource can be read
    /// authenticated (RFC 8555 §6.3). Always uses the `kid`.
    async fn post_as_get(&self, url: &str) -> Result<HttpResponse, AcmeError> {
        self.post(url, b"", Jws::Kid).await
    }

    /// Signs and sends one ACME POST, refreshing the nonce and retrying once on
    /// a `badNonce`.
    ///
    /// Every response's `Replay-Nonce` becomes the next request's nonce. A CA
    /// that rejects the nonce (clock skew, a nonce used twice) is retried a single
    /// time with the fresh nonce it just supplied; a second rejection surfaces.
    async fn post(&self, url: &str, payload: &[u8], key_ref: Jws) -> Result<HttpResponse, AcmeError> {
        let mut last = AcmeError::BadNonce;
        for attempt in 0..2 {
            let nonce = self.nonce().await?;
            let protected = self.protected_header(&nonce, url, key_ref)?;
            let signed = sign_jws(&self.key, &protected, payload)?;
            let parsed = Url::parse(url)?;
            let response = self.http.post(&parsed, "application/jose+json", &signed).await?;
            self.store_nonce(&response.headers);

            if response.status.code() >= 400 {
                let error = problem(&response);
                if matches!(error, AcmeError::BadNonce) && attempt == 0 {
                    last = error;
                    continue;
                }
                return Err(error);
            }
            return Ok(response);
        }
        Err(last)
    }

    /// Builds the JWS protected header for a request: `alg`, `nonce`, `url`, and
    /// exactly one of `jwk` (newAccount) or `kid` (everything after).
    fn protected_header(&self, nonce: &str, url: &str, key_ref: Jws) -> Result<Json, AcmeError> {
        let mut fields = vec![
            ("alg".to_owned(), Json::string("ES256")),
            ("nonce".to_owned(), Json::string(nonce)),
            ("url".to_owned(), Json::string(url)),
        ];
        match key_ref {
            Jws::Jwk => fields.push(("jwk".to_owned(), self.key.jwk().to_json())),
            Jws::Kid => {
                let kid = self
                    .kid
                    .lock()
                    .expect("kid mutex is never poisoned")
                    .clone()
                    .ok_or_else(|| AcmeError::Crypto("account URL (kid) not set".to_owned()))?;
                fields.push(("kid".to_owned(), Json::string(kid)));
            }
        }
        Ok(Json::object(fields))
    }

    /// Takes the cached nonce, or fetches a fresh one from `newNonce`.
    async fn nonce(&self) -> Result<String, AcmeError> {
        if let Some(nonce) = self.nonce.lock().expect("nonce mutex is never poisoned").take() {
            return Ok(nonce);
        }
        let url = Url::parse(&self.directory.new_nonce)?;
        let response = self.http.get(&url).await?;
        response.headers.get_str("replay-nonce").map(str::to_owned).ok_or_else(|| {
            AcmeError::Protocol {
                kind: "newNonce".to_owned(),
                detail: "the newNonce response carried no Replay-Nonce header".to_owned(),
            }
        })
    }

    /// Records a response's `Replay-Nonce` as the nonce for the next request.
    fn store_nonce(&self, headers: &Headers) {
        if let Some(nonce) = headers.get_str("replay-nonce") {
            *self.nonce.lock().expect("nonce mutex is never poisoned") = Some(nonce.to_owned());
        }
    }
}

/// Which key reference a JWS protected header carries.
#[derive(Debug, Clone, Copy)]
enum Jws {
    /// The full public key — only the first request (newAccount) uses this.
    Jwk,
    /// The account URL — every request after registration uses this.
    Kid,
}

/// Loads the account key from `acme_dir/account.key`, or creates and persists one.
fn load_or_create_account_key(acme_dir: &Path) -> Result<AccountKey, AcmeError> {
    let key_path = acme_dir.join("account.key");
    match std::fs::read(&key_path) {
        Ok(der) => AccountKey::from_pkcs8(&der),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let key = AccountKey::generate()?;
            std::fs::create_dir_all(acme_dir)?;
            write_private(&key_path, key.to_pkcs8())?;
            Ok(key)
        }
        Err(error) => Err(AcmeError::Io(error)),
    }
}

/// Writes secret bytes mode 0600 on Unix; elsewhere inherits the directory ACL.
///
/// Mirrors `proxy::tls::write_private`: the account key is secret material and
/// must never be briefly world-readable.
fn write_private(path: &Path, contents: &[u8]) -> Result<(), AcmeError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)?;
    }
    Ok(())
}

/// Parses a response body as JSON, or reports why it could not be.
fn body_json(response: &HttpResponse) -> Result<Json, AcmeError> {
    let text = std::str::from_utf8(&response.body)
        .map_err(|_| AcmeError::Json("response body was not UTF-8".to_owned()))?;
    selfhost_json::parse(text).map_err(|error| AcmeError::Json(error.to_string()))
}

/// Turns an error response into an [`AcmeError`], recognising `badNonce`.
///
/// ACME errors are `application/problem+json` (RFC 8555 §6.7) with a `type` URN
/// and human `detail`. A `badNonce` maps to [`AcmeError::BadNonce`] so the caller
/// can retry; everything else becomes [`AcmeError::Protocol`].
fn problem(response: &HttpResponse) -> AcmeError {
    let fallback = || AcmeError::Protocol {
        kind: "unknown".to_owned(),
        detail: format!("HTTP {}", response.status.code()),
    };
    let Ok(text) = std::str::from_utf8(&response.body) else { return fallback() };
    let Ok(document) = selfhost_json::parse(text) else { return fallback() };

    let kind = document.get("type").and_then(Json::as_str).unwrap_or("unknown").to_owned();
    let detail = document.get("detail").and_then(Json::as_str).unwrap_or_default().to_owned();
    if kind == "urn:ietf:params:acme:error:badNonce" || kind.ends_with(":badNonce") {
        return AcmeError::BadNonce;
    }
    AcmeError::Protocol { kind, detail }
}

/// The delay a `Retry-After` header asks for, when it is a plain integer of seconds.
///
/// ACME's `Retry-After` may also be an HTTP date; that form is ignored (the
/// default interval applies), since parsing it buys nothing for a poll loop that
/// is already bounded by [`MAX_POLLS`].
fn retry_after(headers: &Headers) -> Option<Duration> {
    headers.get_str("retry-after")?.trim().parse::<u64>().ok().map(Duration::from_secs)
}

/// Why an ACME operation failed.
///
/// One error for the whole flow: the transport, the CA's own JSON problem
/// documents, and the local crypto and filesystem steps all funnel here so a
/// caller has a single thing to match on. RFC 8555 §6.7 problem types surface as
/// [`AcmeError::Protocol`], carrying the `type` and human-readable `detail`.
#[derive(Debug)]
pub enum AcmeError {
    /// A socket read or write failed, or a response could not be framed.
    Transport(String),
    /// The TLS handshake with the ACME endpoint failed or the name was invalid.
    Tls(String),
    /// A response body was not the JSON the protocol required.
    Json(String),
    /// The CA reported a problem: `kind` is the RFC 8555 `type`, `detail` its text.
    Protocol {
        /// The problem type URN, e.g. `urn:ietf:params:acme:error:unauthorized`.
        kind: String,
        /// The human-readable detail the CA supplied.
        detail: String,
    },
    /// The CA rejected the request nonce; the caller should refetch and retry once.
    BadNonce,
    /// An order or authorization did not reach a terminal state within the bound.
    Timeout,
    /// A local cryptographic step (key generation, signing, CSR) failed.
    Crypto(String),
    /// A local filesystem step (account key, challenge token) failed.
    Io(io::Error),
}

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(detail) => write!(f, "ACME transport failed: {detail}"),
            Self::Tls(detail) => write!(f, "ACME TLS handshake failed: {detail}"),
            Self::Json(detail) => write!(f, "ACME response was not valid JSON: {detail}"),
            Self::Protocol { kind, detail } => write!(f, "ACME server reported {kind}: {detail}"),
            Self::BadNonce => write!(f, "ACME server rejected the request nonce"),
            Self::Timeout => write!(f, "ACME order did not complete in time"),
            Self::Crypto(detail) => write!(f, "ACME cryptographic step failed: {detail}"),
            Self::Io(error) => write!(f, "ACME local I/O failed: {error}"),
        }
    }
}

impl std::error::Error for AcmeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for AcmeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(test)]
mod driver_tests {
    use super::*;
    use selfhost_http::Status;
    use std::collections::HashMap;
    use std::collections::VecDeque;

    /// A scripted transport: responses are queued per request path and returned
    /// in order, so the whole order flow runs with no socket.
    struct MockHttp {
        by_path: Mutex<HashMap<String, VecDeque<HttpResponse>>>,
        seen: Mutex<Vec<(String, String)>>,
    }

    impl MockHttp {
        fn new() -> Self {
            Self { by_path: Mutex::new(HashMap::new()), seen: Mutex::new(Vec::new()) }
        }

        fn queue(&self, path: &str, response: HttpResponse) {
            self.by_path
                .lock()
                .unwrap()
                .entry(path.to_owned())
                .or_default()
                .push_back(response);
        }

        fn queue_front(&self, path: &str, response: HttpResponse) {
            self.by_path
                .lock()
                .unwrap()
                .entry(path.to_owned())
                .or_default()
                .push_front(response);
        }

        fn respond(&self, method: &str, url: &Url) -> Result<HttpResponse, AcmeError> {
            self.seen.lock().unwrap().push((method.to_owned(), url.path.clone()));
            self.by_path
                .lock()
                .unwrap()
                .get_mut(&url.path)
                .and_then(VecDeque::pop_front)
                .ok_or_else(|| AcmeError::Transport(format!("no scripted response for {}", url.path)))
        }
    }

    impl Http for MockHttp {
        fn get<'a>(&'a self, url: &'a Url) -> HttpFuture<'a> {
            let result = self.respond("GET", url);
            Box::pin(async move { result })
        }
        fn post<'a>(&'a self, url: &'a Url, _content_type: &'a str, _body: &'a [u8]) -> HttpFuture<'a> {
            let result = self.respond("POST", url);
            Box::pin(async move { result })
        }
    }

    fn response(code: u16, headers: &[(&str, &str)], body: &str) -> HttpResponse {
        let mut fields = Headers::new();
        for (name, value) in headers {
            fields.push(*name, *value).expect("valid header");
        }
        HttpResponse { status: Status(code), headers: fields, body: body.as_bytes().to_vec() }
    }

    /// The directory body, keyed on paths the mock also answers.
    fn directory_body() -> String {
        Json::object([
            ("newNonce", Json::string("https://ca.test/new-nonce")),
            ("newAccount", Json::string("https://ca.test/new-acct")),
            ("newOrder", Json::string("https://ca.test/new-order")),
            ("revokeCert", Json::string("https://ca.test/revoke")),
        ])
        .to_text()
    }

    /// A mock scripted for one successful single-domain issuance.
    fn happy_mock() -> MockHttp {
        let mock = MockHttp::new();
        // connect: directory, then a nonce, then newAccount.
        mock.queue("/directory", response(200, &[], &directory_body()));
        mock.queue("/new-nonce", response(204, &[("Replay-Nonce", "nonce-1")], ""));
        mock.queue(
            "/new-acct",
            response(201, &[("Location", "https://ca.test/acct/1"), ("Replay-Nonce", "nonce-2")], "{}"),
        );

        // issue: newOrder -> authz (pending, then valid) -> challenge -> finalize
        // -> order (valid) -> certificate.
        let order_pending = Json::object([
            ("status", Json::string("pending")),
            ("authorizations", Json::array([Json::string("https://ca.test/authz/1")])),
            ("finalize", Json::string("https://ca.test/finalize/1")),
        ])
        .to_text();
        mock.queue(
            "/new-order",
            response(
                201,
                &[("Location", "https://ca.test/order/1"), ("Replay-Nonce", "nonce-3")],
                &order_pending,
            ),
        );

        let authz_pending = Json::object([
            ("identifier", Json::object([("type", Json::string("dns")), ("value", Json::string("example.test"))])),
            ("status", Json::string("pending")),
            (
                "challenges",
                Json::array([Json::object([
                    ("type", Json::string("http-01")),
                    ("url", Json::string("https://ca.test/chall/1")),
                    ("token", Json::string("tok3n-value")),
                    ("status", Json::string("pending")),
                ])]),
            ),
        ])
        .to_text();
        let authz_valid = Json::object([
            ("identifier", Json::object([("type", Json::string("dns")), ("value", Json::string("example.test"))])),
            ("status", Json::string("valid")),
            ("challenges", Json::array([])),
        ])
        .to_text();
        mock.queue("/authz/1", response(200, &[("Replay-Nonce", "nonce-4")], &authz_pending));
        mock.queue("/authz/1", response(200, &[("Replay-Nonce", "nonce-6")], &authz_valid));

        mock.queue(
            "/chall/1",
            response(200, &[("Replay-Nonce", "nonce-5")], r#"{"status":"processing"}"#),
        );
        mock.queue(
            "/finalize/1",
            response(200, &[("Replay-Nonce", "nonce-7")], r#"{"status":"processing","authorizations":[],"finalize":"https://ca.test/finalize/1"}"#),
        );

        let order_valid = Json::object([
            ("status", Json::string("valid")),
            ("authorizations", Json::array([])),
            ("finalize", Json::string("https://ca.test/finalize/1")),
            ("certificate", Json::string("https://ca.test/cert/1")),
        ])
        .to_text();
        mock.queue("/order/1", response(200, &[("Replay-Nonce", "nonce-8")], &order_valid));
        mock.queue(
            "/cert/1",
            response(200, &[("Replay-Nonce", "nonce-9")], "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"),
        );
        mock
    }

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "selfhost-acme-{label}-{}-{}",
            std::process::id(),
            label.len()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[tokio::test]
    async fn a_full_issuance_walks_the_state_machine_to_a_certificate() {
        let acme_dir = temp_dir("driver-acme");
        let challenge_dir = temp_dir("driver-chall");

        let acme = Acme::connect(happy_mock(), AcmeEnvironment::Staging, "ops@example.test", &acme_dir)
            .await
            .expect("connect registers the account");

        let issued = acme
            .issue(&["example.test".to_owned()], &challenge_dir)
            .await
            .expect("issuance yields a certificate");

        assert!(issued.chain_pem.contains("BEGIN CERTIFICATE"));
        assert!(issued.key_pem.contains("BEGIN PRIVATE KEY"));

        // The account key was persisted for reuse.
        assert!(acme_dir.join("account.key").exists());
        // The challenge token file was cleaned up after the order settled.
        assert!(!challenge_dir.join("tok3n-value").exists());

        std::fs::remove_dir_all(&acme_dir).ok();
        std::fs::remove_dir_all(&challenge_dir).ok();
    }

    #[tokio::test]
    async fn a_bad_nonce_is_retried_once_with_the_fresh_nonce() {
        let acme_dir = temp_dir("nonce-acme");
        let challenge_dir = temp_dir("nonce-chall");

        let mock = happy_mock();
        // newOrder first answers a badNonce (carrying a fresh nonce); the driver
        // must retry and then see the real order.
        mock.queue_front(
            "/new-order",
            response(
                400,
                &[("Replay-Nonce", "nonce-retry")],
                r#"{"type":"urn:ietf:params:acme:error:badNonce","detail":"stale"}"#,
            ),
        );

        let acme = Acme::connect(mock, AcmeEnvironment::Staging, "", &acme_dir)
            .await
            .expect("connect");
        let issued = acme
            .issue(&["example.test".to_owned()], &challenge_dir)
            .await
            .expect("issuance recovers from one badNonce");
        assert!(issued.chain_pem.contains("BEGIN CERTIFICATE"));

        std::fs::remove_dir_all(&acme_dir).ok();
        std::fs::remove_dir_all(&challenge_dir).ok();
    }

    #[test]
    fn directory_url_defaults_to_staging() {
        assert_eq!(directory_url(AcmeEnvironment::Staging), LETSENCRYPT_STAGING);
        assert_eq!(directory_url(AcmeEnvironment::SelfSigned), LETSENCRYPT_STAGING);
        assert_eq!(directory_url(AcmeEnvironment::Production), LETSENCRYPT_PRODUCTION);
    }

    #[test]
    fn a_problem_document_recognises_bad_nonce() {
        let bad = response(400, &[], r#"{"type":"urn:ietf:params:acme:error:badNonce"}"#);
        assert!(matches!(problem(&bad), AcmeError::BadNonce));

        let other = response(403, &[], r#"{"type":"urn:ietf:params:acme:error:unauthorized","detail":"nope"}"#);
        match problem(&other) {
            AcmeError::Protocol { kind, detail } => {
                assert!(kind.ends_with("unauthorized"));
                assert_eq!(detail, "nope");
            }
            other => panic!("expected a protocol error, got {other:?}"),
        }
    }
}
