//! Sign in with a third-party identity provider — Google, GitHub, or anything else that speaks
//! OAuth 2.0 authorization-code-with-PKCE.
//!
//! # A provider is configuration, not code
//!
//! Nothing here names Google or GitHub. [`Provider`] is five URLs, a client id and secret, a
//! scope, and the three field names its userinfo response answers a subject, an email, and
//! (optionally) an email-verified claim under — an operator adds a provider with
//! `selfhost reports oauth add`, naming those fields from whatever provider they are pointing
//! at, and this module never grows a per-provider branch. This is the same shape
//! `crates/config::service` takes for "a program and its arguments, never a hand-coded case."
//!
//! # The outbound HTTPS client is mirrored, not shared
//!
//! `crates/acme/src/transport.rs` already owns exactly this problem — dial a host, speak TLS
//! against the bundled Mozilla roots, write an HTTP/1.1 request by hand because `crates/http` is
//! pure and holds no socket, read a response bounded by size. [`HttpsClient`] below is that
//! module's `Url`/`HttpsClient`/`build_request`/`read_response` copied and trimmed to what an
//! OAuth exchange needs (`GET` and `POST` only; no ACME-specific headers), for the reason
//! `crates/admin/src/passwd.rs` gives for its own mirrored code: `selfhost-reports` must not
//! gain a dependency on `selfhost-acme` — which itself pulls in `selfhost-config` — just to make
//! two HTTPS calls.
//!
//! # PKCE, and why it is not optional here
//!
//! Every authorization request carries a `code_challenge` derived from a `code_verifier` this
//! box generates and never sends until the token exchange. Without it, an authorization code
//! intercepted between the provider's redirect and this box's callback (a malicious app on the
//! same device registering the same custom scheme, a proxy in the path) could be redeemed by
//! whoever intercepted it; PKCE binds the code to the party that started the request. The
//! verifier lives in [`Pending`], server-side, keyed by the `state` value — never in a cookie.
//!
//! # `state` says the attempt is live; the nonce cookie says it is *this browser's*
//!
//! PKCE binds the authorization code to this box. It does not bind the attempt to the browser
//! that started it, and `state` on its own does not either: it is a value that travels through a
//! redirect chain, so it can be lifted out of a `Referer`, a proxy log, or a shoulder — or simply
//! *planted*, by an attacker who starts a sign-in as themselves and then walks a victim into the
//! resulting callback URL. Either way the victim's browser redeems an attempt somebody else
//! owns, and this box mints them a session on the attacker's account: login CSRF, and every
//! report the victim files afterwards lands somewhere the attacker can read it.
//!
//! So [`authorize_url`] also mints a **nonce**, hands it back for the caller to set as a
//! short-lived `HttpOnly` cookie on the redirect, and stores only its SHA-256 in the [`Attempt`].
//! [`complete`] refuses — with the same [`OAuthError::ExpiredState`] an unknown `state` gets, so
//! the two are indistinguishable — unless the callback presents a cookie hashing to what the
//! attempt recorded. A stolen or planted `state` is now worth nothing without the browser that
//! started the flow, and the digest means the pool of outstanding attempts is not itself a list
//! of live credentials.
//!
//! # What this box requires before it trusts an email
//!
//! [`Provider::email_verified_field`] names the claim a provider marks a verified email with.
//! When the provider's userinfo answer does not carry that claim as `true`, a returned identity
//! is linked to an account only when the email is *new* — never silently merged into an
//! existing account by an unverified claim, which would let anyone type somebody else's address
//! into a provider that never checked it and walk into their account.

use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use selfhost_http::{IncomingResponse, ParseError, ResponseFraming};
use selfhost_json::Json;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// The most response bytes accepted from one exchange — a token or userinfo answer is a handful
/// of fields; a reply that keeps growing past this is not one.
const MAX_RESPONSE_BYTES: usize = 512 * 1024;

/// One read from the socket.
const READ_CHUNK: usize = 8 * 1024;

/// The default port for `https`.
const HTTPS_PORT: u16 = 443;

/// Bytes of entropy in a PKCE code verifier, in the `state` parameter, and in the browser nonce.
const VERIFIER_BYTES: usize = 32;

/// The cookie that ties an outstanding sign-in attempt to the browser that started it.
///
/// Named alongside `crate::sessions::COOKIE_NAME` and set with the identical attribute string —
/// see [`nonce_cookie_header`].
pub const NONCE_COOKIE_NAME: &str = "report_oauth_nonce";

/// How long a start/callback round trip has before its state expires. Five minutes: generous
/// for a person to authenticate at the provider, short enough that an abandoned attempt does not
/// sit in memory.
const PENDING_LIFETIME: Duration = Duration::from_secs(5 * 60);

/// The most concurrent sign-in attempts tracked at once.
const MAX_PENDING: usize = 4_096;

/// Why an OAuth exchange could not be carried out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OAuthError {
    /// The URL, request, or response was not the shape expected.
    Transport(String),
    /// TLS could not be established or verified.
    Tls(String),
    /// The provider is not one this box has configured.
    UnknownProvider,
    /// The `state` parameter is unknown, expired, or already used.
    ExpiredState,
    /// The provider's token or userinfo answer did not carry what was needed.
    Incomplete(String),
    /// The address already belongs to a different, distinct account and the two sides of it were
    /// not both proven — either this provider did not vouch for the address, or the account
    /// standing there never proved it was theirs. Refused rather than silently merged, in one
    /// sentence for both cases so the refusal cannot be used to tell them apart. See the module
    /// documentation here and `crate::service::Service::oauth_account`'s.
    UnverifiedEmailConflict,
}

impl std::fmt::Display for OAuthError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(message) | Self::Tls(message) | Self::Incomplete(message) => {
                out.write_str(message)
            }
            Self::UnknownProvider => out.write_str("no such sign-in provider is configured"),
            Self::ExpiredState => out.write_str("this sign-in attempt has expired — start again"),
            Self::UnverifiedEmailConflict => out.write_str(
                "that email already belongs to an account, and this provider did not confirm it",
            ),
        }
    }
}

impl std::error::Error for OAuthError {}

/// One configured identity provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    /// The name it is reached at: `…/report/oauth/<name>/start`.
    pub name: String,
    /// Where a browser is sent to authenticate.
    pub authorize_url: String,
    /// Where an authorization code is exchanged for a token.
    pub token_url: String,
    /// Where the token is presented to read the signed-in person's profile.
    pub userinfo_url: String,
    /// The client id this box registered with the provider.
    pub client_id: String,
    /// The client secret this box registered with the provider.
    pub client_secret: String,
    /// Requested scope, space-separated, exactly as the provider expects it.
    pub scope: String,
    /// The userinfo field holding this provider's own subject identifier.
    pub subject_field: String,
    /// The userinfo field holding the person's email.
    pub email_field: String,
    /// The userinfo field claiming the email is verified, when the provider has one.
    pub email_verified_field: Option<String>,
}

/// One outstanding sign-in attempt, keyed by its `state`.
struct Attempt {
    state: String,
    provider: String,
    code_verifier: String,
    redirect_uri: String,
    /// The SHA-256 of the nonce handed to the browser that started this attempt, base64url —
    /// the digest rather than the nonce itself, so this pool is not a list of values that would
    /// redeem an attempt if it were ever read out of a core dump or a debug print.
    nonce_digest: String,
    issued: Instant,
}

/// The pool of outstanding sign-in attempts. In-memory only, like `crate::webauthn::Challenges`
/// — losing one on a restart costs an abandoned attempt a retry, never a stored secret.
#[derive(Clone)]
pub struct Pending {
    entries: Arc<Mutex<Vec<Attempt>>>,
}

impl Pending {
    /// An empty pool.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Starts one attempt for `provider`, returning `(state, code_verifier, nonce)`.
    ///
    /// The `nonce` is the browser's half of the binding: the caller sets it as a cookie (see
    /// [`nonce_cookie_header`]) and only its digest is kept here.
    ///
    /// # Errors
    /// An [`io::Error`] naming what the system's random source refused.
    fn start(&self, provider: &str, redirect_uri: &str) -> io::Result<(String, String, String)> {
        let state = b64url_encode(&random_bytes(VERIFIER_BYTES)?);
        let code_verifier = b64url_encode(&random_bytes(VERIFIER_BYTES)?);
        let nonce = b64url_encode(&random_bytes(VERIFIER_BYTES)?);
        let now = Instant::now();
        let mut entries = self.lock();
        entries.retain(|entry| now.duration_since(entry.issued) < PENDING_LIFETIME);
        while entries.len() >= MAX_PENDING {
            entries.remove(0);
        }
        entries.push(Attempt {
            state: state.clone(),
            provider: provider.to_string(),
            code_verifier: code_verifier.clone(),
            redirect_uri: redirect_uri.to_string(),
            nonce_digest: nonce_digest(&nonce),
            issued: now,
        });
        Ok((state, code_verifier, nonce))
    }

    /// Redeems `state`, returning `(code_verifier, redirect_uri)` when it names a live attempt
    /// for `provider` **and** `nonce` is the one handed to the browser that started it. Single-
    /// use: a callback replayed with the same `state` finds nothing the second time.
    ///
    /// A missing or wrong `nonce` answers `None`, exactly as an unknown `state` does — the
    /// caller turns both into the one "this sign-in attempt has expired" sentence, so a client
    /// holding a `state` it did not start learns nothing about whether that `state` was real.
    /// The attempt is *not* consumed in that case: refusing a stranger's guess must not cancel
    /// the sign-in the real browser is still in the middle of.
    fn take(&self, provider: &str, state: &str, nonce: Option<&str>) -> Option<(String, String)> {
        let now = Instant::now();
        let mut entries = self.lock();
        entries.retain(|entry| now.duration_since(entry.issued) < PENDING_LIFETIME);
        let presented = nonce.map(nonce_digest);
        let position = entries.iter().position(|entry| {
            entry.provider == provider && constant_time_eq(entry.state.as_bytes(), state.as_bytes())
        })?;
        let matches_browser = presented.is_some_and(|digest| {
            constant_time_eq(entries[position].nonce_digest.as_bytes(), digest.as_bytes())
        });
        if !matches_browser {
            return None;
        }
        let attempt = entries.remove(position);
        Some((attempt.code_verifier, attempt.redirect_uri))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Attempt>> {
        self.entries
            .lock()
            .expect("the oauth pending-attempt lock was poisoned")
    }
}

impl Default for Pending {
    fn default() -> Self {
        Self::new()
    }
}

/// What a completed exchange answered: the provider's subject, the person's email, and whether
/// the provider itself claims that email is verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The provider's own subject identifier for this person.
    pub subject: String,
    /// The email the provider's profile carries.
    pub email: String,
    /// Whether the provider itself claims that email is verified.
    pub email_verified: bool,
}

/// Builds the URL a browser is sent to, and records the attempt so the callback can be verified.
///
/// `redirect_uri` is the exact `…/report/oauth/<provider>/callback` address this box answers on
/// — carried through to the token exchange because providers require the two to match exactly.
///
/// Answers `(location, nonce)`. The caller **must** put `nonce` on the redirect as
/// [`nonce_cookie_header`] builds it, or its own callback will refuse every attempt this call
/// started — see the module documentation on what that cookie is for.
///
/// # Errors
/// An [`io::Error`] naming what the system's random source refused.
pub fn authorize_url(
    provider: &Provider,
    pending: &Pending,
    redirect_uri: &str,
) -> io::Result<(String, String)> {
    let (state, verifier, nonce) = pending.start(&provider.name, redirect_uri)?;
    let challenge = b64url_encode(digest(&SHA256, verifier.as_bytes()).as_ref());
    let separator = if provider.authorize_url.contains('?') {
        '&'
    } else {
        '?'
    };
    let location = format!(
        "{}{separator}response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        provider.authorize_url,
        percent_encode(&provider.client_id),
        percent_encode(redirect_uri),
        percent_encode(&provider.scope),
        percent_encode(&state),
        percent_encode(&challenge),
    );
    Ok((location, nonce))
}

/// The `Set-Cookie` line binding an outstanding attempt to the browser that started it.
///
/// Byte-for-byte the shape `selfhost_login::session::set_cookie_header` writes — it *is* that
/// function, applied to this cookie's own name and lifetime — so this box has exactly one
/// spelling of "HttpOnly, Secure when the deployment is https, SameSite=Lax, scoped to the
/// route". `SameSite=Lax` is load-bearing rather than incidental: the callback arrives as a
/// top-level `GET` navigation from the provider, which `Lax` allows and `Strict` would drop,
/// taking every OAuth sign-in with it. `secure` comes from the caller's configured public base
/// URL, exactly as the session cookie's does, because this service binds loopback and can never
/// tell from the connection itself whether the browser reached the proxy over TLS.
///
/// Not cleared on the callback: the attempt it names is consumed server-side the moment it is
/// redeemed, so what is left in the browser for the remaining few minutes names nothing.
#[must_use]
pub fn nonce_cookie_header(nonce: &str, route: &str, secure: bool) -> String {
    selfhost_login::session::set_cookie_header(&NONCE_COOKIE_CONFIG, nonce, route, secure)
}

/// Reads the nonce cookie's value out of a request's `Cookie` header, if present.
#[must_use]
pub fn nonce_cookie_value(header: Option<&str>) -> Option<String> {
    selfhost_login::session::cookie_value(&NONCE_COOKIE_CONFIG, header)
}

/// The cookie shape [`nonce_cookie_header`] and [`nonce_cookie_value`] share.
///
/// A [`selfhost_login::session::SessionConfig`] for something that is not a session: only its
/// `cookie_name` and `lifetime_secs` are read by the two cookie functions above, and borrowing
/// the type is what guarantees this cookie's attribute string can never drift from the session
/// cookie's. The store fields are named so an accidental future call that *did* read them would
/// be obviously wrong rather than quietly wrong.
const NONCE_COOKIE_CONFIG: selfhost_login::session::SessionConfig =
    selfhost_login::session::SessionConfig {
        cookie_name: NONCE_COOKIE_NAME,
        filename: "there-is-no-store-for-this-cookie.json",
        // The cookie outlives nothing: `PENDING_LIFETIME` is when the attempt it names expires.
        lifetime_secs: PENDING_LIFETIME.as_secs(),
        idle_secs: 0,
        max_sessions: 0,
    };

/// The base64url SHA-256 of a nonce — what [`Attempt`] stores instead of the nonce itself.
fn nonce_digest(nonce: &str) -> String {
    b64url_encode(digest(&SHA256, nonce.as_bytes()).as_ref())
}

/// Completes the exchange: verifies `state` *and* the browser nonce, trades `code` for a token,
/// and reads the person's profile from the userinfo endpoint.
///
/// `nonce` is whatever the callback request's own [`NONCE_COOKIE_NAME`] cookie carried, or
/// `None` when it carried none — both a missing and a wrong one refuse.
///
/// # Errors
/// [`OAuthError::ExpiredState`] when `state` names no live attempt for this provider *or* the
/// browser does not hold that attempt's nonce, [`OAuthError::Transport`]/[`OAuthError::Tls`] for
/// a network or TLS failure, [`OAuthError::Incomplete`] when the provider's answer is missing
/// what was asked for.
pub async fn complete(
    provider: &Provider,
    pending: &Pending,
    client: &HttpsClient,
    code: &str,
    state: &str,
    nonce: Option<&str>,
) -> Result<Identity, OAuthError> {
    let (verifier, redirect_uri) = pending
        .take(&provider.name, state, nonce)
        .ok_or(OAuthError::ExpiredState)?;

    let body = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={}",
        percent_encode(code),
        percent_encode(&redirect_uri),
        percent_encode(&provider.client_id),
        percent_encode(&provider.client_secret),
        percent_encode(&verifier),
    );
    let token_url = Url::parse(&provider.token_url).map_err(OAuthError::Transport)?;
    let token_response = client
        .request(
            "POST",
            &token_url,
            &[
                (
                    "Content-Type".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                ),
                ("Accept".to_string(), "application/json".to_string()),
            ],
            body.as_bytes(),
        )
        .await?;
    let token_body = std::str::from_utf8(&token_response.body)
        .map_err(|_| OAuthError::Incomplete("the token response was not UTF-8".to_string()))?;
    let token_json = selfhost_json::parse(token_body)
        .map_err(|_| OAuthError::Incomplete("the token response was not JSON".to_string()))?;
    let access_token = token_json
        .get("access_token")
        .and_then(Json::as_str)
        .ok_or_else(|| {
            OAuthError::Incomplete("the token response carried no access_token".to_string())
        })?;

    let userinfo_url = Url::parse(&provider.userinfo_url).map_err(OAuthError::Transport)?;
    let userinfo_response = client
        .request(
            "GET",
            &userinfo_url,
            &[(
                "Authorization".to_string(),
                format!("Bearer {access_token}"),
            )],
            b"",
        )
        .await?;
    let userinfo_body = std::str::from_utf8(&userinfo_response.body)
        .map_err(|_| OAuthError::Incomplete("the profile response was not UTF-8".to_string()))?;
    let userinfo = selfhost_json::parse(userinfo_body)
        .map_err(|_| OAuthError::Incomplete("the profile response was not JSON".to_string()))?;

    let subject = string_field(&userinfo, &provider.subject_field)
        .ok_or_else(|| OAuthError::Incomplete("the profile carried no subject".to_string()))?;
    let email = string_field(&userinfo, &provider.email_field)
        .ok_or_else(|| OAuthError::Incomplete("the profile carried no email".to_string()))?;
    let email_verified = provider
        .email_verified_field
        .as_deref()
        .and_then(|field| userinfo.get(field))
        .and_then(Json::as_bool)
        .unwrap_or(false);

    Ok(Identity {
        subject,
        email,
        email_verified,
    })
}

/// Reads a userinfo field as a string, accepting a bare number for a provider (GitHub) whose
/// subject is numeric — read as text either way, since this box only ever compares it.
fn string_field(value: &Json, field: &str) -> Option<String> {
    match value.get(field)? {
        Json::String(text) => Some(text.clone()),
        Json::Number(number) if number.fract() == 0.0 => Some(format!("{}", *number as i64)),
        _ => None,
    }
}

/// Percent-encodes for a query-string value (RFC 3986 unreserved characters pass through
/// unescaped; everything else becomes `%XX`). Written here rather than pulled from a dependency
/// for the same reason `crates/acme/src/transport.rs::Url` is hand-rolled — this workspace's
/// dependency policy has no room for a URL crate, and the encoding a query value needs is a
/// handful of lines.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |differences, (a, b)| differences | (a ^ b))
        == 0
}

fn random_bytes(count: usize) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; count];
    SystemRandom::new()
        .fill(&mut buffer)
        .map_err(|_| io::Error::other("the system random source was unavailable"))?;
    Ok(buffer)
}

/// Encodes bytes as unpadded base64url — the same alphabet WebAuthn speaks, shared with
/// `crate::webauthn` so the two modules carry one copy between them.
#[must_use]
pub fn b64url_encode(data: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let bits = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[(bits >> 18 & 0x3f) as usize] as char);
        out.push(B64[(bits >> 12 & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64[(bits >> 6 & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64[(bits & 0x3f) as usize] as char);
        }
    }
    out
}

/// Decodes unpadded base64url; padding is tolerated, anything else is `None`.
#[must_use]
pub fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    fn value(byte: u8) -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some((byte - b'A') as u32),
            b'a'..=b'z' => Some((byte - b'a' + 26) as u32),
            b'0'..=b'9' => Some((byte - b'0' + 52) as u32),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let mut symbols = Vec::new();
    for byte in text.bytes() {
        match byte {
            b'=' => {}
            other => symbols.push(value(other)?),
        }
    }
    let mut out = Vec::with_capacity(symbols.len() / 4 * 3);
    for group in symbols.chunks(4) {
        if group.len() == 1 {
            return None;
        }
        let bits = group
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, s)| acc | (s << (18 - 6 * i)));
        out.push((bits >> 16) as u8);
        if group.len() > 2 {
            out.push((bits >> 8) as u8);
        }
        if group.len() > 3 {
            out.push(bits as u8);
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------------------------
// The outbound HTTPS client — mirrored from `crates/acme/src/transport.rs`; see the module
// documentation for why it is a copy rather than a dependency.
// ---------------------------------------------------------------------------------------------

/// An absolute `https` URL, split into the parts a request needs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Url {
    host: String,
    port: u16,
    path: String,
}

impl Url {
    fn parse(absolute_https: &str) -> Result<Self, String> {
        let rest = absolute_https
            .strip_prefix("https://")
            .ok_or_else(|| format!("not an https URL: {absolute_https}"))?;
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(authority_end);
        if authority.is_empty() {
            return Err(format!("no host in URL: {absolute_https}"));
        }
        if authority.contains('@') {
            return Err(format!("userinfo is not supported: {absolute_https}"));
        }
        if authority.contains('[') {
            return Err(format!("IPv6 literals are not supported: {absolute_https}"));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port_text)) => {
                let port = port_text
                    .parse()
                    .map_err(|_| format!("invalid port in URL: {absolute_https}"))?;
                (host, port)
            }
            None => (authority, HTTPS_PORT),
        };
        if host.is_empty() {
            return Err(format!("no host in URL: {absolute_https}"));
        }
        let target = match tail.split_once('#') {
            Some((before, _)) => before,
            None => tail,
        };
        let path = if target.is_empty() {
            "/".to_owned()
        } else if target.starts_with('/') {
            target.to_owned()
        } else {
            format!("/{target}")
        };
        Ok(Self {
            host: host.to_owned(),
            port,
            path,
        })
    }

    fn host_header(&self) -> String {
        if self.port == HTTPS_PORT {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// A response, read whole into memory.
struct HttpResponse {
    body: Vec<u8>,
}

/// A reusable outbound HTTPS client.
#[derive(Clone)]
pub struct HttpsClient {
    config: Arc<rustls::ClientConfig>,
}

impl HttpsClient {
    /// Builds a client that verifies servers against the bundled Mozilla roots.
    ///
    /// # Errors
    /// A sentence naming why the `rustls` configuration could not be built.
    pub fn new() -> Result<Self, OAuthError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| OAuthError::Tls(error.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            config: Arc::new(config),
        })
    }

    async fn request(
        &self,
        method: &str,
        url: &Url,
        extra_headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, OAuthError> {
        let head = build_request(url, method, extra_headers, body);

        let tcp = TcpStream::connect((url.host.as_str(), url.port))
            .await
            .map_err(|error| OAuthError::Transport(error.to_string()))?;
        let server_name = rustls::pki_types::ServerName::try_from(url.host.clone())
            .map_err(|error| OAuthError::Tls(error.to_string()))?;
        let connector = TlsConnector::from(self.config.clone());
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|error| OAuthError::Tls(error.to_string()))?;

        tls.write_all(&head)
            .await
            .map_err(|error| OAuthError::Transport(error.to_string()))?;
        if !body.is_empty() {
            tls.write_all(body)
                .await
                .map_err(|error| OAuthError::Transport(error.to_string()))?;
        }
        tls.flush()
            .await
            .map_err(|error| OAuthError::Transport(error.to_string()))?;

        read_response(&mut tls).await
    }
}

fn build_request(
    url: &Url,
    method: &str,
    extra_headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut head = Vec::new();
    head.extend_from_slice(method.as_bytes());
    head.push(b' ');
    head.extend_from_slice(url.path.as_bytes());
    head.extend_from_slice(b" HTTP/1.1\r\n");
    head.extend_from_slice(b"Host: ");
    head.extend_from_slice(url.host_header().as_bytes());
    head.extend_from_slice(b"\r\n");
    head.extend_from_slice(b"User-Agent: selfhost-reports-oauth/1\r\n");
    head.extend_from_slice(b"Accept-Encoding: identity\r\n");
    head.extend_from_slice(b"Connection: close\r\n");
    for (name, value) in extra_headers {
        head.extend_from_slice(name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    if !body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH") {
        head.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    head.extend_from_slice(b"\r\n");
    head
}

async fn read_response<R>(stream: &mut R) -> Result<HttpResponse, OAuthError>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    let parsed = loop {
        if !read_more(stream, &mut buffer).await? {
            return Err(OAuthError::Transport(
                "connection closed before a response head arrived".to_string(),
            ));
        }
        match IncomingResponse::parse(&buffer) {
            Ok(parsed) => break parsed,
            Err(ParseError::Incomplete) => continue,
            Err(error) => {
                return Err(OAuthError::Transport(format!(
                    "malformed response: {error}"
                )));
            }
        }
    };

    let head = parsed.response;
    let mut body = buffer.split_off(parsed.consumed);

    let body = match head.framing {
        ResponseFraming::None => Vec::new(),
        ResponseFraming::Fixed(length) => {
            let length = length as usize;
            while body.len() < length {
                if !read_more(stream, &mut body).await? {
                    return Err(OAuthError::Transport(
                        "connection closed before the declared body length arrived".to_string(),
                    ));
                }
            }
            body.truncate(length);
            body
        }
        ResponseFraming::UntilClose => {
            while read_more(stream, &mut body).await? {}
            body
        }
        ResponseFraming::Chunked => loop {
            match selfhost_http::dechunk(&body) {
                Ok(decoded) => break decoded,
                Err(ParseError::Incomplete) => {
                    if !read_more(stream, &mut body).await? {
                        return Err(OAuthError::Transport(
                            "connection closed in the middle of a chunked body".to_string(),
                        ));
                    }
                }
                Err(error) => {
                    return Err(OAuthError::Transport(format!(
                        "malformed chunked body: {error}"
                    )));
                }
            }
        },
    };
    Ok(HttpResponse { body })
}

async fn read_more<R>(stream: &mut R, buffer: &mut Vec<u8>) -> Result<bool, OAuthError>
where
    R: AsyncRead + Unpin,
{
    let mut chunk = [0_u8; READ_CHUNK];
    let read = stream
        .read(&mut chunk)
        .await
        .map_err(|error| OAuthError::Transport(error.to_string()))?;
    if read == 0 {
        return Ok(false);
    }
    if buffer.len() + read > MAX_RESPONSE_BYTES {
        return Err(OAuthError::Transport(
            "response exceeded the maximum accepted size".to_string(),
        ));
    }
    buffer.extend_from_slice(&chunk[..read]);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> Provider {
        Provider {
            name: "example".to_string(),
            authorize_url: "https://provider.example/authorize".to_string(),
            token_url: "https://provider.example/token".to_string(),
            userinfo_url: "https://provider.example/userinfo".to_string(),
            client_id: "client-123".to_string(),
            client_secret: "secret-456".to_string(),
            scope: "openid email".to_string(),
            subject_field: "sub".to_string(),
            email_field: "email".to_string(),
            email_verified_field: Some("email_verified".to_string()),
        }
    }

    #[test]
    fn base64url_round_trips() {
        for data in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            &[0xff, 0xee, 0x00, 0x41],
        ] {
            assert_eq!(b64url_decode(&b64url_encode(data)).as_deref(), Some(data));
        }
        assert!(
            b64url_decode("a+b/").is_none(),
            "the standard alphabet is not this one"
        );
    }

    #[test]
    fn percent_encoding_leaves_unreserved_characters_alone() {
        assert_eq!(percent_encode("abcXYZ019-_.~"), "abcXYZ019-_.~");
        assert_eq!(percent_encode("a b"), "a%20b");
        assert_eq!(
            percent_encode("https://x/y?z=1"),
            "https%3A%2F%2Fx%2Fy%3Fz%3D1"
        );
    }

    #[test]
    fn the_authorize_url_carries_pkce_and_records_the_attempt() {
        let provider = provider();
        let pending = Pending::new();
        let (url, nonce) = authorize_url(
            &provider,
            &pending,
            "https://box.example/report/oauth/example/callback",
        )
        .expect("built");
        assert!(
            !nonce.is_empty(),
            "a nonce comes back for the caller to set"
        );
        assert!(url.starts_with("https://provider.example/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=client-123"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("state="));
        assert!(url.contains("code_challenge="));
        // Two calls never reuse a state, a verifier, or a nonce.
        let (second, second_nonce) = authorize_url(
            &provider,
            &pending,
            "https://box.example/report/oauth/example/callback",
        )
        .expect("built");
        assert_ne!(url, second);
        assert_ne!(nonce, second_nonce);
    }

    #[test]
    fn a_state_redeems_exactly_once_and_only_for_its_provider() {
        let pending = Pending::new();
        let (state, verifier, nonce) = pending.start("google", "https://cb").expect("started");
        assert!(
            pending.take("github", &state, Some(&nonce)).is_none(),
            "the provider must match"
        );
        let (found_verifier, redirect) = pending
            .take("google", &state, Some(&nonce))
            .expect("redeems");
        assert_eq!(found_verifier, verifier);
        assert_eq!(redirect, "https://cb");
        assert!(
            pending.take("google", &state, Some(&nonce)).is_none(),
            "single-use"
        );
    }

    /// The login-CSRF fix, at the layer that decides it: `state` alone is not enough, and a
    /// stranger's guess at one must not cancel the attempt the real browser is still running.
    #[test]
    fn a_state_without_the_browser_that_started_it_redeems_nothing() {
        let pending = Pending::new();
        let (state, _, nonce) = pending.start("google", "https://cb").expect("started");
        let (_, _, other_nonce) = pending
            .start("google", "https://cb")
            .expect("a second, unrelated attempt");

        assert!(
            pending.take("google", &state, None).is_none(),
            "a callback carrying no cookie at all"
        );
        assert!(
            pending.take("google", &state, Some(&other_nonce)).is_none(),
            "a callback carrying somebody else's cookie"
        );
        assert!(
            pending.take("google", &state, Some("")).is_none(),
            "a callback carrying an empty cookie"
        );
        assert!(
            pending.take("google", &state, Some(&nonce)).is_some(),
            "the real browser is still able to finish"
        );
    }

    #[test]
    fn the_nonce_cookie_is_written_and_read_in_the_session_cookies_own_shape() {
        let header = nonce_cookie_header("the-nonce", "/report", true);
        assert!(header.starts_with(&format!("{NONCE_COOKIE_NAME}=the-nonce;")));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("Secure"));
        assert!(header.contains("SameSite=Lax"));
        assert!(header.contains("Path=/report"));
        assert!(header.contains(&format!("Max-Age={}", PENDING_LIFETIME.as_secs())));
        assert!(
            !nonce_cookie_header("the-nonce", "/report", false).contains("Secure"),
            "Secure follows the deployment, exactly as the session cookie's does"
        );

        let presented = format!("report_session=abc; {NONCE_COOKIE_NAME}=the-nonce; other=1");
        assert_eq!(
            nonce_cookie_value(Some(&presented)),
            Some("the-nonce".to_string())
        );
        assert_eq!(nonce_cookie_value(Some("report_session=abc")), None);
        assert_eq!(nonce_cookie_value(None), None);
    }

    #[test]
    fn only_the_nonces_digest_is_kept_where_the_attempt_lives() {
        let pending = Pending::new();
        let (_, _, nonce) = pending.start("google", "https://cb").expect("started");
        let stored = pending.lock()[0].nonce_digest.clone();
        assert_ne!(stored, nonce, "the pool holds no redeemable value");
        assert_eq!(stored, nonce_digest(&nonce));
    }

    #[test]
    fn a_numeric_subject_field_is_read_as_text() {
        let value = selfhost_json::parse(r#"{"id": 123456, "email": "a@example.com"}"#).unwrap();
        assert_eq!(string_field(&value, "id"), Some("123456".to_string()));
        assert_eq!(
            string_field(&value, "email"),
            Some("a@example.com".to_string())
        );
        assert_eq!(string_field(&value, "missing"), None);
    }

    #[test]
    fn url_parsing_matches_the_acme_transports_own_shape() {
        let url = Url::parse("https://provider.example/token").unwrap();
        assert_eq!(url.host, "provider.example");
        assert_eq!(url.port, 443);
        assert_eq!(url.path, "/token");
        assert!(
            Url::parse("http://provider.example/token").is_err(),
            "https only"
        );
    }

    #[test]
    fn a_get_carries_no_body_framing() {
        let url = Url::parse("https://provider.example/userinfo").unwrap();
        let head = String::from_utf8(build_request(&url, "GET", &[], b"")).unwrap();
        assert!(head.starts_with("GET /userinfo HTTP/1.1\r\n"));
        assert!(!head.contains("Content-Length"));
    }

    #[test]
    fn a_post_declares_its_length_and_carries_extra_headers() {
        let url = Url::parse("https://provider.example/token").unwrap();
        let headers = vec![(
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        )];
        let head = String::from_utf8(build_request(&url, "POST", &headers, b"a=1")).unwrap();
        assert!(head.contains("Content-Type: application/x-www-form-urlencoded\r\n"));
        assert!(head.contains("Content-Length: 3\r\n"));
    }

    #[tokio::test]
    async fn reads_a_fixed_length_json_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{\"a\":\"token\"}";
        let mut source: &[u8] = raw;
        let response = read_response(&mut source).await.unwrap();
        assert_eq!(response.body, b"{\"a\":\"token\"}");
    }

    #[tokio::test]
    async fn a_response_past_the_size_cap_is_refused() {
        let mut head = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        head.extend(std::iter::repeat_n(b'x', MAX_RESPONSE_BYTES + 10));
        let mut source: &[u8] = &head;
        let result = read_response(&mut source).await;
        assert!(matches!(result, Err(OAuthError::Transport(_))));
    }

    #[tokio::test]
    async fn the_client_configuration_builds() {
        assert!(HttpsClient::new().is_ok());
    }
}
