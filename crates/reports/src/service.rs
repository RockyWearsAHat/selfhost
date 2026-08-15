//! The HTTP surface: four routes, one of which is open to the internet — plus, when
//! [`Config::accounts`] is set, the account subsystem's own doors.
//!
//! ```text
//! POST <route>?<service>        file a report        open to anyone, rate limited
//! GET  <route>/health           is the intake up     open, says nothing about content
//! GET  <route>/feed?<service>   every open report    owner token
//! POST <route>/close?<service>  a report is fixed    owner token
//! GET  <route>/projects         which services take reports    open, rate limited
//! ```
//!
//! # The account routes, off unless configured
//!
//! `Config::accounts: Option<AccountsConfig>` is `None` by default, and every route below
//! answers the same `404` an unknown path gets until it is set — the identical shape
//! [`check_token`](Service::check_token) already gives the feed/close routes on a box with no
//! token, so shipping this subsystem changes nothing about a deployment that has not opted in.
//! `crate::accounts`, `crate::sessions`, `crate::webauthn` and `crate::oauth` are each the
//! authority on their own piece; this module only wires their JSON in and out of HTTP and never
//! re-implements a rule any of them already state.
//!
//! ```text
//! POST <route>/register                     email + password           rate limited
//! POST <route>/login                        email + password           rate limited
//! POST <route>/logout                       ends the session
//! GET  <route>/verify?token=…                confirms an email          rate limited
//! POST <route>/verify/resend                 session required           rate limited
//! GET  <route>/me                            whoami                     session required
//! POST <route>/me/password                   sets/replaces a password   session required
//! GET  <route>/mine                          this account's reports     session required
//! POST <route>/mine/withdraw                 close one's own report     session required
//! POST <route>/passkey/register/start        issues a challenge         session optional
//! POST <route>/passkey/register/finish       completes registration
//! POST <route>/passkey/login/start           issues a challenge
//! POST <route>/passkey/login/finish          completes sign-in
//! GET  <route>/oauth/<provider>/start        redirects to the provider  rate limited
//! GET  <route>/oauth/<provider>/callback     completes sign-in
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
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use selfhost_http::{BodyLength, Method, ParseError, Request, Response, Status};
use selfhost_json::Json;
use selfhost_mail::OutboundQueue;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::accounts::{Account, AccountError, Accounts};
use crate::clock;
use crate::limit::{Decision, Limiter, Meter, Rate};
use crate::notify::{self, Mailbox};
use crate::oauth::{self, OAuthError};
use crate::report::{Refusal, Report, project_key};
use crate::sessions::{self, Sessions};
use crate::store::{self, Store, StoreError};
use crate::verify::Verifications;
use crate::webauthn::{self, Webauthn};

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
    /// The account subsystem — registration, sessions, passkeys, OAuth sign-in. `None` (the
    /// default) means every route under it answers `404`, exactly like a box with no
    /// [`Self::token`]: shipping this code changes nothing about a deployment that has not
    /// opted in.
    pub accounts: Option<AccountsConfig>,
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
            accounts: None,
        }
    }
}

/// How the account subsystem is configured. Constructing one and setting it on [`Config`] is
/// the whole of turning the door on.
#[derive(Debug, Clone)]
pub struct AccountsConfig {
    /// Where `accounts.json`, `sessions.json`, `passkeys.json` and `verify.json` live.
    ///
    /// Deliberately **not** [`crate::store::Store`]'s own directory: a project key may contain
    /// dots and this box lets a stranger bring a project into existence by naming it, so a
    /// fixed filename inside that directory is a name a project key could someday collide with.
    /// A sibling directory makes the collision structurally impossible rather than merely
    /// unlikely.
    pub data_dir: PathBuf,
    /// The name shown in a verification email and nowhere else load-bearing.
    pub site_name: String,
    /// This box's own public address with no trailing slash — `https://rockywearsahat.com` —
    /// used to build the verification link and the OAuth `redirect_uri`. Both must be absolute:
    /// a provider is configured with an exact redirect address and refuses anything else.
    pub public_base_url: String,
    /// The WebAuthn relying party id — this box's own hostname. `None` disables the passkey
    /// routes (they answer the same `404` as an unconfigured token route) while leaving
    /// password and OAuth sign-in unaffected.
    pub rp_id: Option<String>,
    /// Every configured "sign in with…" provider, keyed by [`oauth::Provider::name`] in the
    /// route. Empty means no OAuth route exists.
    pub oauth_providers: Vec<oauth::Provider>,
    /// The `From` address on a verification email — must be a domain this box can send as.
    pub verify_from: String,
    /// The HELO name this box announces when spooling a verification email.
    pub verify_helo: String,
    /// The daemon's own data directory, so a verification email can be spooled into
    /// `<mail_data_dir>/mail/queue` for the daemon's outbound sweep to actually send. `None`
    /// means accounts still work but no verification email is ever sent — the same degraded-but-
    /// working shape [`Config::mail`] being `None` gives report notifications.
    pub mail_data_dir: Option<PathBuf>,
    /// What one source may attempt of register/login/passkey/OAuth-start in total — counted
    /// separately from [`Config::per_source`] and [`Config::per_reader`] so a credential-
    /// stuffing attempt against this door can never spend a filer's or a reader's allowance,
    /// and cannot itself be starved by one either.
    pub per_action: Rate,
}

/// The account subsystem's live state — every store [`AccountsConfig`] describes, opened once
/// and shared for the life of the [`Service`].
struct AccountsRuntime {
    config: AccountsConfig,
    accounts: Accounts,
    sessions: Sessions,
    webauthn: Option<Webauthn>,
    oauth_providers: std::collections::HashMap<String, oauth::Provider>,
    oauth_pending: oauth::Pending,
    // Built once at startup; a `rustls` configuration failure is exceedingly unlikely (it does
    // not touch the network) but is not a reason to make `Service::new` fallible when every
    // other store here already fails closed on its own — the OAuth routes report it themselves
    // instead, once, the first time they are reached.
    oauth_client: Result<oauth::HttpsClient, String>,
    verify: Verifications,
    mail_queue: Option<OutboundQueue>,
    limiter: Mutex<Limiter>,
}

impl AccountsRuntime {
    fn open(config: AccountsConfig) -> Self {
        let accounts = Accounts::load(&config.data_dir);
        let sessions = Sessions::load(&config.data_dir);
        let webauthn = config
            .rp_id
            .as_deref()
            .map(|rp_id| Webauthn::load(rp_id, &config.data_dir));
        let oauth_providers = config
            .oauth_providers
            .iter()
            .cloned()
            .map(|provider| (provider.name.clone(), provider))
            .collect();
        let verify = Verifications::load(&config.data_dir);
        let mail_queue = config
            .mail_data_dir
            .as_deref()
            .and_then(|dir| match OutboundQueue::open(dir) {
                Ok(queue) => Some(queue),
                Err(error) => {
                    eprintln!(
                        "[{}] reports: could not open the outbound mail queue at {}: {error} — \
                         verification email is disabled",
                        selfhost_mail::stamp(),
                        dir.display()
                    );
                    None
                }
            });
        let limiter = Mutex::new(Limiter::new(config.per_action, config.per_action));
        Self {
            oauth_client: oauth::HttpsClient::new().map_err(|error| error.to_string()),
            config,
            accounts,
            sessions,
            webauthn,
            oauth_providers,
            oauth_pending: oauth::Pending::new(),
            verify,
            mail_queue,
            limiter,
        }
    }
}

// Deliberately not a derived `Debug`: `oauth_client` and `mail_queue` do not implement it, and
// even if they did, an account list or a session table in a log line is a target list — the
// same reasoning every credential store in this crate and `crates/admin` gives its own `Debug`.
impl std::fmt::Debug for AccountsRuntime {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            out,
            "AccountsRuntime {{ accounts: {:?}, sessions: {:?}, webauthn: {}, oauth_providers: {}, verify: {:?} }}",
            self.accounts,
            self.sessions,
            if self.webauthn.is_some() {
                "configured"
            } else {
                "disabled"
            },
            self.oauth_providers.len(),
            self.verify,
        )
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
    accounts: Option<AccountsRuntime>,
}

impl Service {
    /// An intake over `store`, configured by `config`.
    #[must_use]
    pub fn new(store: Store, config: Config) -> Self {
        let filing = Mutex::new(Limiter::new(config.per_source, config.global));
        let reading = Mutex::new(Limiter::new(config.per_reader, config.global));
        let mail_meter = Mutex::new(Meter::new(config.mail_rate));
        let accounts = config.accounts.clone().map(AccountsRuntime::open);
        Self {
            store,
            config,
            filing,
            reading,
            mail_meter,
            accounts,
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
    /// The surface [`serve`] actually calls. Every route but one is synchronous — see
    /// [`Self::answer`] — and this is a thin wrapper that awaits only that one:
    /// `<route>/oauth/<provider>/callback`, which cannot answer without trading the
    /// provider's authorization code for a token over the network. Every other path, including
    /// a callback for an unconfigured or unknown provider, is handled by [`Self::answer`]
    /// unchanged — so a box with accounts turned off pays nothing extra reaching this function
    /// on every request, and every already-proven synchronous route stays exactly as tested.
    pub async fn answer_async(
        &self,
        request: &Request,
        body: &[u8],
        client: &str,
        now: Instant,
        wall: SystemTime,
    ) -> Response {
        if let Some(runtime) = &self.accounts {
            let (path, query) = split_target(&request.target);
            let route = self.config.route.as_str();
            if let Some(provider_name) = path
                .strip_prefix(&format!("{route}/oauth/"))
                .and_then(|rest| rest.strip_suffix("/callback"))
            {
                if request.method != Method::Get {
                    return refuse(Status::METHOD_NOT_ALLOWED, "this endpoint takes GET");
                }
                if let Decision::Refuse(seconds) = self.admit(&runtime.limiter, client, now) {
                    return retry_after(seconds);
                }
                return self.oauth_callback(runtime, provider_name, query).await;
            }
        }
        self.answer(request, body, client, now, wall)
    }

    /// Answers one request from `client`, at `now` on the monotonic clock and `wall` on the
    /// calendar.
    ///
    /// Both clocks are parameters so the whole surface is testable without sleeping and
    /// without a stamp that changes between runs. Nothing in here awaits: a report is stored
    /// and answered, and the mail it produces is delivered by [`deliver_pending`] afterwards,
    /// so a slow SMTP server can never hold a reporter's connection open. The one route that
    /// must await network I/O — the OAuth callback — is therefore not reachable through this
    /// function at all; see [`Self::answer_async`].
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
                Method::Post => self.file(request, body, query, client, now, wall),
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
        if path == format!("{route}/projects") {
            if let Decision::Refuse(seconds) = self.admit(&self.reading, client, now) {
                return retry_after(seconds);
            }
            return self.projects(request);
        }
        if let Some(suffix) = path.strip_prefix(&format!("{route}/")) {
            if let Some(runtime) = &self.accounts {
                return self
                    .accounts_answer(runtime, suffix, query, request, body, client, now, wall);
            }
        }
        refuse(Status::NOT_FOUND, "no such endpoint")
    }

    /// `POST <route>?<service>` — the one open door.
    ///
    /// Attributed to a signed-in account when the request carries a live session — additive
    /// only: a request with no cookie, an expired one, or accounts turned off entirely files
    /// exactly as it always has.
    fn file(
        &self,
        request: &Request,
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
        let mut report = match Report::parse(
            &value,
            &service,
            clock::iso8601(wall),
            crate::report::source_hash(client),
        ) {
            Ok(report) => report,
            Err(refusal) => return refuse(Status::BAD_REQUEST, refusal.message()),
        };
        let account = self
            .accounts
            .as_ref()
            .and_then(|runtime| self.caller(runtime, request));
        report.account_id = account.as_ref().map(|account| account.id.clone());

        match self.store.record(&report) {
            Ok(recorded) => {
                if recorded.fresh {
                    if let Some(account) = &account {
                        if let Some(runtime) = &self.accounts {
                            if let Err(error) = runtime.accounts.record_filed(
                                &account.id,
                                &recorded.entry.project,
                                &recorded.entry.id,
                            ) {
                                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                            }
                        }
                    }
                }
                answer(
                    Status::OK,
                    Json::object([
                        ("filed", Json::string(&recorded.entry.id)),
                        ("project", Json::string(&recorded.entry.project)),
                        ("sightings", Json::Number(recorded.entry.sightings as f64)),
                        ("known", Json::Bool(!recorded.fresh)),
                    ]),
                )
            }
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

    /// `GET <route>/projects` — the services this box currently accepts reports about, so a
    /// dashboard can offer a filer a choice rather than a blank field. Names only: no count, no
    /// content — [`Self::health`] already exposes a total count and nothing has ever exposed
    /// which services exist by name, so this is a deliberate, narrow widening of that, not an
    /// accident of implementation.
    fn projects(&self, request: &Request) -> Response {
        if request.method != Method::Get {
            return refuse(Status::METHOD_NOT_ALLOWED, "this endpoint takes GET");
        }
        match self.store.projects() {
            Ok(keys) => answer(
                Status::OK,
                Json::object([("projects", Json::array(keys.into_iter().map(Json::string)))]),
            ),
            Err(error) => {
                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                refuse(
                    Status::INTERNAL_SERVER_ERROR,
                    "the project list could not be read",
                )
            }
        }
    }

    /// The account a request's session cookie names, if any — live, not expired, found. Used
    /// only to *attribute* a filing; its absence is never a refusal.
    fn caller(&self, runtime: &AccountsRuntime, request: &Request) -> Option<Account> {
        let presented = sessions::cookie_value(request.headers.get_str("cookie"));
        let account_id = runtime.sessions.account_of(presented.as_deref()?)?;
        runtime.accounts.find_by_id(&account_id)
    }

    /// Dispatches every route under `<route>/` once accounts are configured — everything
    /// [`Self::answer`] itself does not already own (`health`, `feed`, `close`, `projects`).
    ///
    /// `suffix` is the path with `<route>/` already stripped, so `"register"` here is
    /// `<route>/register` to a caller. The one route this never answers is
    /// `oauth/<provider>/callback` — it needs to await a network exchange, and `answer` is
    /// synchronous; [`Self::answer_async`] intercepts that one path before ever reaching here.
    #[allow(clippy::too_many_arguments)]
    fn accounts_answer(
        &self,
        runtime: &AccountsRuntime,
        suffix: &str,
        query: &str,
        request: &Request,
        body: &[u8],
        client: &str,
        now: Instant,
        wall: SystemTime,
    ) -> Response {
        // Every account-door attempt spends this allowance before anything else runs, so a
        // credential-stuffing run against `login` can never spend the allowance an ordinary
        // filer or a subscribed checkout needs — the same separation `filing`/`reading` already
        // give each other.
        if matches!(
            suffix,
            "register"
                | "login"
                | "verify/resend"
                | "passkey/register/start"
                | "passkey/login/start"
        ) || suffix.starts_with("oauth/")
        {
            if let Decision::Refuse(seconds) = self.admit(&runtime.limiter, client, now) {
                return retry_after(seconds);
            }
        }

        match suffix {
            "register" if request.method == Method::Post => {
                self.register_password(runtime, body, wall)
            }
            "login" if request.method == Method::Post => self.login_password(runtime, body),
            "logout" if request.method == Method::Post => self.logout(runtime, request),
            "verify" if request.method == Method::Get => self.verify_email(runtime, query),
            "verify/resend" if request.method == Method::Post => {
                self.resend_verification(runtime, request, wall)
            }
            "me" if request.method == Method::Get => self.whoami(runtime, request),
            "me/password" if request.method == Method::Post => {
                self.set_account_password(runtime, request, body)
            }
            "mine" if request.method == Method::Get => self.mine(runtime, request),
            "mine/withdraw" if request.method == Method::Post => {
                self.withdraw(runtime, request, body)
            }
            "passkey/register/start" if request.method == Method::Post => {
                self.passkey_register_start(runtime, request, body)
            }
            "passkey/register/finish" if request.method == Method::Post => {
                self.passkey_register_finish(runtime, body)
            }
            "passkey/login/start" if request.method == Method::Post => {
                self.passkey_login_start(runtime)
            }
            "passkey/login/finish" if request.method == Method::Post => {
                self.passkey_login_finish(runtime, body)
            }
            "register"
            | "login"
            | "logout"
            | "verify/resend"
            | "me/password"
            | "mine/withdraw"
            | "passkey/register/start"
            | "passkey/register/finish"
            | "passkey/login/start"
            | "passkey/login/finish" => {
                refuse(Status::METHOD_NOT_ALLOWED, "this endpoint takes POST")
            }
            "verify" | "me" | "mine" => {
                refuse(Status::METHOD_NOT_ALLOWED, "this endpoint takes GET")
            }
            _ if suffix.starts_with("oauth/") => self.oauth_route(runtime, suffix, request),
            _ => refuse(Status::NOT_FOUND, "no such endpoint"),
        }
    }

    /// `POST <route>/register` — email and password, the baseline account door.
    fn register_password(
        &self,
        runtime: &AccountsRuntime,
        body: &[u8],
        wall: SystemTime,
    ) -> Response {
        let Some(value) = parse_json_body(body) else {
            return refuse(Status::BAD_REQUEST, "the body is not JSON");
        };
        let email = text_field(&value, "email");
        let password = text_field(&value, "password");
        if email.is_empty() || password.is_empty() {
            return refuse(Status::BAD_REQUEST, "`email` and `password` are required");
        }
        match runtime.accounts.create_with_password(email, password) {
            Ok(account) => {
                self.send_verification(runtime, &account, wall);
                self.session_response(runtime, &account.id)
            }
            Err(error) => account_error_response(&error),
        }
    }

    /// `POST <route>/login` — email and password. Every way of failing answers the same
    /// sentence: an agent guessing at an email cannot tell a wrong password from no such
    /// account, exactly as `Webauthn::verify_login` refuses every bent assertion identically.
    fn login_password(&self, runtime: &AccountsRuntime, body: &[u8]) -> Response {
        let Some(value) = parse_json_body(body) else {
            return refuse(Status::BAD_REQUEST, "the body is not JSON");
        };
        let email = text_field(&value, "email");
        let password = text_field(&value, "password");
        let wrong = || refuse(Status::UNAUTHORIZED, "wrong email or password");
        let Ok(address) = selfhost_mail::Address::parse(email) else {
            return wrong();
        };
        let Some(account) = runtime.accounts.find_by_email(&address) else {
            return wrong();
        };
        if !runtime.accounts.verify_password(&account, password) {
            return wrong();
        }
        self.session_response(runtime, &account.id)
    }

    /// `POST <route>/logout` — ends the presented session, if any. Never an error: a caller
    /// with no cookie, or one that names nothing live, reaches the same signed-out state either
    /// way.
    fn logout(&self, runtime: &AccountsRuntime, request: &Request) -> Response {
        if let Some(cookie) = sessions::cookie_value(request.headers.get_str("cookie")) {
            runtime.sessions.end(&cookie);
        }
        let mut response = answer(Status::OK, Json::object([("signedOut", Json::Bool(true))]));
        let _ = response.headers.set(
            "Set-Cookie",
            sessions::clear_cookie_header(&self.config.route, self.cookies_secure(runtime)),
        );
        response
    }

    /// `GET <route>/verify?token=…` — confirms an email from a clicked link.
    fn verify_email(&self, runtime: &AccountsRuntime, query: &str) -> Response {
        let Some(token) = query_param(query, "token") else {
            return refuse(Status::BAD_REQUEST, "`token` is required");
        };
        let Some(account_id) = runtime.verify.redeem(&token) else {
            return refuse(
                Status::BAD_REQUEST,
                "this verification link is invalid or has expired — ask for a new one",
            );
        };
        if let Err(error) = runtime.accounts.mark_verified(&account_id) {
            eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
            return refuse(Status::INTERNAL_SERVER_ERROR, "could not confirm the email");
        }
        answer(Status::OK, Json::object([("verified", Json::Bool(true))]))
    }

    /// `POST <route>/verify/resend` — a fresh link, for an account that lost the first one.
    fn resend_verification(
        &self,
        runtime: &AccountsRuntime,
        request: &Request,
        wall: SystemTime,
    ) -> Response {
        let Some(account) = self.caller(runtime, request) else {
            return refuse(Status::UNAUTHORIZED, "sign in first");
        };
        if account.email_verified {
            return answer(
                Status::OK,
                Json::object([("alreadyVerified", Json::Bool(true))]),
            );
        }
        self.send_verification(runtime, &account, wall);
        answer(Status::OK, Json::object([("sent", Json::Bool(true))]))
    }

    /// Mints a verification token and spools the email, when this box has somewhere to spool
    /// it. Silent when it does not — the same degraded-but-working shape an unconfigured
    /// [`Config::mail`] gives report notifications: the account still works, it is simply
    /// unverified until an operator wires up mail or the account sets a password it can prove
    /// some other way.
    fn send_verification(&self, runtime: &AccountsRuntime, account: &Account, wall: SystemTime) {
        let Some(queue) = &runtime.mail_queue else {
            return;
        };
        let Ok(token) = runtime.verify.mint(&account.id) else {
            return;
        };
        let verify_url = format!(
            "{}{}/verify?token={token}",
            runtime.config.public_base_url, self.config.route
        );
        let _ = wall; // reserved: a future retry policy may want the moment this was requested
        if let Err(error) = crate::verify::send_verification(
            queue,
            &runtime.config.verify_from,
            &account.email,
            &runtime.config.verify_helo,
            &runtime.config.site_name,
            &verify_url,
        ) {
            eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
        }
    }

    /// `GET <route>/me` — the account's own view of itself.
    fn whoami(&self, runtime: &AccountsRuntime, request: &Request) -> Response {
        let Some(account) = self.caller(runtime, request) else {
            return refuse(Status::UNAUTHORIZED, "sign in first");
        };
        let passkeys = runtime
            .webauthn
            .as_ref()
            .map(|webauthn| webauthn.passkeys().list_for(&account.id))
            .unwrap_or_default();
        answer(
            Status::OK,
            Json::object([
                ("id", Json::string(&account.id)),
                ("email", Json::string(&account.email)),
                ("emailVerified", Json::Bool(account.email_verified)),
                ("plan", Json::string(&account.plan)),
                ("hasPassword", Json::Bool(account.password.is_some())),
                (
                    "oauthProviders",
                    Json::array(
                        account
                            .oauth_links
                            .iter()
                            .map(|link| Json::string(&link.provider)),
                    ),
                ),
                (
                    "passkeys",
                    Json::array(passkeys.iter().map(|passkey| {
                        Json::object([
                            ("id", Json::string(&passkey.id)),
                            ("label", Json::string(&passkey.label)),
                            ("createdUnix", Json::Number(passkey.created_unix as f64)),
                        ])
                    })),
                ),
                ("createdUnix", Json::Number(account.created_unix as f64)),
            ]),
        )
    }

    /// `POST <route>/me/password` — sets or replaces the account's password.
    ///
    /// Ends every other session on this account: a credential rotation that leaves an older
    /// session alive on a device this was rotated *away from* is not a rotation.
    fn set_account_password(
        &self,
        runtime: &AccountsRuntime,
        request: &Request,
        body: &[u8],
    ) -> Response {
        let Some(account) = self.caller(runtime, request) else {
            return refuse(Status::UNAUTHORIZED, "sign in first");
        };
        let Some(value) = parse_json_body(body) else {
            return refuse(Status::BAD_REQUEST, "the body is not JSON");
        };
        let password = text_field(&value, "password");
        match runtime.accounts.set_password(&account.id, password) {
            Ok(()) => {
                runtime.sessions.end_all_for(&account.id);
                self.session_response(runtime, &account.id)
            }
            Err(error) => account_error_response(&error),
        }
    }

    /// `GET <route>/mine` — the reports this account filed, newest first.
    fn mine(&self, runtime: &AccountsRuntime, request: &Request) -> Response {
        let Some(account) = self.caller(runtime, request) else {
            return refuse(Status::UNAUTHORIZED, "sign in first");
        };
        let reports: Vec<Json> = account
            .filed
            .iter()
            .rev()
            .filter_map(|reference| self.store.get(&reference.project, &reference.id).ok())
            .map(|entry| store::to_json(&entry))
            .collect();
        answer(
            Status::OK,
            Json::object([("reports", Json::array(reports))]),
        )
    }

    /// `POST <route>/mine/withdraw` — closes a report this account filed. A report that does
    /// not exist and one that exists but belongs to somebody else answer the identical `404`,
    /// so this route cannot be used to learn whether a given id belongs to another account.
    fn withdraw(&self, runtime: &AccountsRuntime, request: &Request, body: &[u8]) -> Response {
        let Some(account) = self.caller(runtime, request) else {
            return refuse(Status::UNAUTHORIZED, "sign in first");
        };
        let Some(value) = parse_json_body(body) else {
            return refuse(Status::BAD_REQUEST, "the body is not JSON");
        };
        let project = text_field(&value, "project");
        let id = text_field(&value, "id");
        if project.is_empty() || id.is_empty() {
            return refuse(Status::BAD_REQUEST, "`project` and `id` are required");
        }
        let not_found = || refuse(Status::NOT_FOUND, "no such report");
        let Ok(entry) = self.store.get(project, id) else {
            return not_found();
        };
        if entry.account_id.as_deref() != Some(account.id.as_str()) {
            return not_found();
        }
        match self.store.close(project, id) {
            Ok(()) => {
                if let Err(error) = runtime.accounts.remove_filed(&account.id, project, id) {
                    eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                }
                answer(Status::OK, Json::object([("withdrawn", Json::string(id))]))
            }
            Err(error) => {
                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                refuse(
                    Status::INTERNAL_SERVER_ERROR,
                    "the report could not be withdrawn",
                )
            }
        }
    }

    /// `POST <route>/passkey/register/start` — with a live session, adds a device to the
    /// signed-in account; with none, `email` in the body registers a brand-new account (refused
    /// when that email is already taken — see the module documentation on the tradeoff this
    /// unauthenticated existence check accepts).
    fn passkey_register_start(
        &self,
        runtime: &AccountsRuntime,
        request: &Request,
        body: &[u8],
    ) -> Response {
        let Some(webauthn) = &runtime.webauthn else {
            return refuse(Status::NOT_FOUND, "no such endpoint");
        };
        let account_id = match self.caller(runtime, request) {
            Some(account) => account.id,
            None => {
                let Some(value) = parse_json_body(body) else {
                    return refuse(Status::BAD_REQUEST, "the body is not JSON");
                };
                let email = text_field(&value, "email");
                if email.is_empty() {
                    return refuse(
                        Status::BAD_REQUEST,
                        "`email` is required to register a new account with a passkey",
                    );
                }
                match runtime.accounts.create_pending(email) {
                    Ok(account) => account.id,
                    Err(error) => return account_error_response(&error),
                }
            }
        };
        match webauthn.start_registration(&account_id) {
            Ok(challenge) => answer(Status::OK, challenge),
            Err(error) => {
                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                refuse(
                    Status::INTERNAL_SERVER_ERROR,
                    "could not start registration",
                )
            }
        }
    }

    /// `POST <route>/passkey/register/finish` — completes the ceremony, always under the
    /// account [`webauthn::Webauthn::start_registration`] bound at issuance.
    fn passkey_register_finish(&self, runtime: &AccountsRuntime, body: &[u8]) -> Response {
        let Some(webauthn) = &runtime.webauthn else {
            return refuse(Status::NOT_FOUND, "no such endpoint");
        };
        let Some(value) = parse_json_body(body) else {
            return refuse(Status::BAD_REQUEST, "the body is not JSON");
        };
        match webauthn.finish_registration(&value) {
            Ok(passkey) => self.session_response(runtime, &passkey.account_id),
            Err(_) => refuse(
                Status::UNAUTHORIZED,
                "the passkey ceremony could not be verified",
            ),
        }
    }

    /// `POST <route>/passkey/login/start` — a discoverable-credential challenge; the browser's
    /// own account picker chooses which registered passkey answers it.
    fn passkey_login_start(&self, runtime: &AccountsRuntime) -> Response {
        let Some(webauthn) = &runtime.webauthn else {
            return refuse(Status::NOT_FOUND, "no such endpoint");
        };
        if webauthn.is_empty() {
            // Uniform with a failed assertion below: a door with nothing registered on it must
            // not answer any differently than one that has something a guess merely missed.
            return refuse(Status::UNAUTHORIZED, "no passkey is registered");
        }
        match webauthn.challenge(webauthn::Purpose::Login) {
            Ok(challenge) => answer(Status::OK, challenge),
            Err(error) => {
                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                refuse(Status::INTERNAL_SERVER_ERROR, "could not start sign-in")
            }
        }
    }

    /// `POST <route>/passkey/login/finish` — verifies the assertion and signs in as whichever
    /// account the matched credential belongs to.
    fn passkey_login_finish(&self, runtime: &AccountsRuntime, body: &[u8]) -> Response {
        let Some(webauthn) = &runtime.webauthn else {
            return refuse(Status::NOT_FOUND, "no such endpoint");
        };
        let Some(value) = parse_json_body(body) else {
            return refuse(Status::BAD_REQUEST, "the body is not JSON");
        };
        match webauthn.verify_login(&value) {
            Ok(passkey) => self.session_response(runtime, &passkey.account_id),
            Err(_) => refuse(
                Status::UNAUTHORIZED,
                "the passkey ceremony could not be verified",
            ),
        }
    }

    /// `GET <route>/oauth/<provider>/start` — the only synchronous half of OAuth sign-in;
    /// [`Self::answer_async`] intercepts `.../callback` before this is ever reached for it.
    fn oauth_route(&self, runtime: &AccountsRuntime, suffix: &str, request: &Request) -> Response {
        let Some(rest) = suffix.strip_prefix("oauth/") else {
            return refuse(Status::NOT_FOUND, "no such endpoint");
        };
        let Some(provider_name) = rest.strip_suffix("/start") else {
            // `/callback` (and anything else under `oauth/`) has no synchronous answer.
            return refuse(Status::NOT_FOUND, "no such endpoint");
        };
        if request.method != Method::Get {
            return refuse(Status::METHOD_NOT_ALLOWED, "this endpoint takes GET");
        }
        let Some(provider) = runtime.oauth_providers.get(provider_name) else {
            return refuse(Status::NOT_FOUND, "no such sign-in provider is configured");
        };
        let redirect_uri = format!(
            "{}{}/oauth/{provider_name}/callback",
            runtime.config.public_base_url, self.config.route
        );
        match oauth::authorize_url(provider, &runtime.oauth_pending, &redirect_uri) {
            Ok(location) => redirect(&location),
            Err(error) => {
                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                refuse(Status::INTERNAL_SERVER_ERROR, "could not start sign-in")
            }
        }
    }

    /// `GET <route>/oauth/<provider>/callback?code=…&state=…` — completes the exchange. The
    /// one route in this crate that awaits network I/O, so it is reached only through
    /// [`Self::answer_async`], never through the synchronous [`Self::answer`].
    async fn oauth_callback(
        &self,
        runtime: &AccountsRuntime,
        provider_name: &str,
        query: &str,
    ) -> Response {
        let Some(provider) = runtime.oauth_providers.get(provider_name) else {
            return refuse(Status::NOT_FOUND, "no such sign-in provider is configured");
        };
        let client = match &runtime.oauth_client {
            Ok(client) => client,
            Err(error) => {
                eprintln!(
                    "[{}] reports: oauth client unavailable: {error}",
                    selfhost_mail::stamp()
                );
                return refuse(
                    Status::SERVICE_UNAVAILABLE,
                    "sign-in is unavailable right now",
                );
            }
        };
        let (Some(code), Some(state)) = (query_param(query, "code"), query_param(query, "state"))
        else {
            return refuse(
                Status::BAD_REQUEST,
                "the provider did not return `code` and `state`",
            );
        };
        let identity =
            match oauth::complete(provider, &runtime.oauth_pending, client, &code, &state).await {
                Ok(identity) => identity,
                Err(OAuthError::ExpiredState) => {
                    return refuse(
                        Status::BAD_REQUEST,
                        "this sign-in attempt has expired — start again",
                    );
                }
                Err(error) => {
                    eprintln!(
                        "[{}] reports: oauth exchange failed: {error}",
                        selfhost_mail::stamp()
                    );
                    return refuse(
                        Status::BAD_GATEWAY,
                        "the sign-in provider could not be reached",
                    );
                }
            };

        let account = self.oauth_account(runtime, provider_name, &identity);
        match account {
            Ok(account) => self.session_response(runtime, &account.id),
            Err(response) => response,
        }
    }

    /// Finds or creates the account an OAuth identity signs in as.
    ///
    /// Looked up by the provider link first — a returning sign-in never re-decides anything.
    /// For a first sign-in: a *verified* email (the provider's own claim) merges into an
    /// existing account by address, exactly the "trust a provider that checked" shape
    /// `crate::oauth`'s module documentation states; an *unverified* email is refused when it
    /// already belongs to a different account rather than silently merged, and otherwise mints
    /// a fresh one.
    fn oauth_account(
        &self,
        runtime: &AccountsRuntime,
        provider_name: &str,
        identity: &oauth::Identity,
    ) -> Result<Account, Response> {
        if let Some(account) = runtime
            .accounts
            .find_by_oauth(provider_name, &identity.subject)
        {
            return Ok(account);
        }
        let Ok(address) = selfhost_mail::Address::parse(&identity.email) else {
            return Err(refuse(
                Status::BAD_GATEWAY,
                "the sign-in provider returned an email this box could not parse",
            ));
        };
        if let Some(existing) = runtime.accounts.find_by_email(&address) {
            if !identity.email_verified {
                // 409: this box already has an opinion about who that address belongs to, and
                // an unverified claim does not get to overrule it.
                return Err(refuse(
                    Status(409),
                    &OAuthError::UnverifiedEmailConflict.to_string(),
                ));
            }
            if let Err(error) =
                runtime
                    .accounts
                    .link_oauth(&existing.id, provider_name, &identity.subject)
            {
                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                return Err(refuse(
                    Status::INTERNAL_SERVER_ERROR,
                    "could not link this sign-in",
                ));
            }
            return Ok(existing);
        }
        runtime
            .accounts
            .create_with_oauth(
                &identity.email,
                identity.email_verified,
                provider_name,
                &identity.subject,
            )
            .map_err(|error| account_error_response(&error))
    }

    /// Mints a session for `account_id` and returns it as the answer's `Set-Cookie`.
    fn session_response(&self, runtime: &AccountsRuntime, account_id: &str) -> Response {
        match runtime.sessions.create(account_id) {
            Ok(cookie) => {
                let mut response =
                    answer(Status::OK, Json::object([("signedIn", Json::Bool(true))]));
                let _ = response.headers.set(
                    "Set-Cookie",
                    sessions::set_cookie_header(
                        &cookie,
                        &self.config.route,
                        self.cookies_secure(runtime),
                    ),
                );
                response
            }
            Err(error) => {
                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                refuse(Status::INTERNAL_SERVER_ERROR, "could not start a session")
            }
        }
    }

    /// Whether the session cookie should carry `Secure`. Derived from the configured public
    /// base URL rather than anything on the request: this service always binds loopback (see
    /// [`bind`]) and never itself terminates TLS, so nothing about a live connection here says
    /// whether the browser reached the proxy over `https://` — but [`AccountsConfig::
    /// public_base_url`] already states, once, whether this deployment is one.
    fn cookies_secure(&self, runtime: &AccountsRuntime) -> bool {
        runtime.config.public_base_url.starts_with("https://")
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
    let response = service
        .answer_async(&request, &body, &client, Instant::now(), SystemTime::now())
        .await;
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

/// Sets the headers `docs/SECURITY.md` (PUB-06) requires of every response this app sends —
/// upstream heads reach the client verbatim, so the app sets these itself, on every answer
/// including a redirect.
fn set_security_headers(response: &mut Response) {
    let _ = response.headers.set("X-Content-Type-Options", "nosniff");
    let _ = response.headers.set("X-Frame-Options", "DENY");
    let _ = response.headers.set("Referrer-Policy", "no-referrer");
    let _ = response.headers.set(
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    );
    let _ = response.headers.set("Cache-Control", "no-store");
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
    set_security_headers(&mut response);
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

/// A `302` to `location` — the OAuth authorization dance's only non-JSON answer. Still carries
/// the PUB-06 headers, same as every other answer this app sends.
fn redirect(location: &str) -> Response {
    let mut response = Response::redirect(Status::FOUND, location)
        .unwrap_or_else(|_| Response::empty(Status::INTERNAL_SERVER_ERROR));
    set_security_headers(&mut response);
    response
}

/// Decodes a request body as JSON, or `None` for anything that is not valid UTF-8 JSON — every
/// account route's first check, so a caller always gets the same "the body is not JSON" refusal
/// [`crate::report::Report::parse`]'s own caller already gives.
fn parse_json_body(body: &[u8]) -> Option<Json> {
    std::str::from_utf8(body)
        .ok()
        .and_then(|text| selfhost_json::parse(text).ok())
}

/// A string field from a decoded body, trimmed, or `""` when absent — the same "missing means
/// empty" shape [`Report::parse`] reads optional fields with.
fn text_field<'a>(value: &'a Json, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or_default()
        .trim()
}

/// The value of `name=…` in a query string, if present. No percent-decoding: every value this
/// module reads from a query (a verification token, an OAuth `code`/`state`) is itself
/// generated from a URL-safe alphabet with nothing to encode, so a caller that percent-encoded
/// one anyway would simply fail to match — the same trade [`service_in_query`] already makes by
/// staying a plain split rather than a full query-string parser this workspace's dependency
/// policy has no crate for.
fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name && !value.is_empty()).then(|| value.to_string())
    })
}

/// Maps an [`AccountError`] to the response its caller gives back.
fn account_error_response(error: &AccountError) -> Response {
    match error {
        AccountError::Full => refuse(Status::SERVICE_UNAVAILABLE, &error.to_string()),
        AccountError::NotFound => refuse(Status::NOT_FOUND, &error.to_string()),
        AccountError::Io(_) => {
            eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
            refuse(
                Status::INTERNAL_SERVER_ERROR,
                "the account could not be updated",
            )
        }
        AccountError::EmailTaken | AccountError::WeakPassword | AccountError::BadEmail(_) => {
            refuse(Status::BAD_REQUEST, &error.to_string())
        }
    }
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

    fn file_with_cookie(service: &Service, body: &str, client: &str, cookie: &str) -> Response {
        let posted = request(&format!(
            "POST /report HTTP/1.1\r\nHost: x\r\nCookie: {cookie}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ));
        service.answer(&posted, body.as_bytes(), client, Instant::now(), UNIX_EPOCH)
    }

    /// A scratch service with the account subsystem turned on: password, passkey (relying
    /// party `RP`) and outbound verification mail spooled into a scratch data directory, all
    /// under one generous rate allowance so a test exercising several calls in a row is never
    /// the thing that trips the limiter it is not testing.
    fn service_with_accounts(label: &str) -> Service {
        let dir = std::env::temp_dir().join(format!("selfhost-reports-service-accounts-{label}"));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir.join("store")).expect("store");
        store.add_project("dx").expect("project");
        Service::new(
            store,
            Config {
                accounts: Some(AccountsConfig {
                    data_dir: dir.join("accounts"),
                    site_name: "Test Reports".to_string(),
                    public_base_url: "https://reports.example.com".to_string(),
                    rp_id: Some(RP.to_string()),
                    oauth_providers: vec![oauth::Provider {
                        name: "example".to_string(),
                        authorize_url: "https://provider.example/authorize".to_string(),
                        token_url: "https://provider.example/token".to_string(),
                        userinfo_url: "https://provider.example/userinfo".to_string(),
                        client_id: "client-id".to_string(),
                        client_secret: "client-secret".to_string(),
                        scope: "email".to_string(),
                        subject_field: "sub".to_string(),
                        email_field: "email".to_string(),
                        email_verified_field: Some("email_verified".to_string()),
                    }],
                    verify_from: "reports@example.com".to_string(),
                    verify_helo: "example.com".to_string(),
                    mail_data_dir: Some(dir.join("mail")),
                    per_action: Rate::new(50, 3000.0),
                }),
                ..Config::default()
            },
        )
    }

    fn json_post(target: &str, body: &str) -> Request {
        request(&format!(
            "POST {target} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ))
    }

    fn json_post_with_cookie(target: &str, body: &str, cookie: &str) -> Request {
        request(&format!(
            "POST {target} HTTP/1.1\r\nHost: x\r\nCookie: {cookie}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ))
    }

    fn get(target: &str) -> Request {
        request(&format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n"))
    }

    fn get_with_cookie(target: &str, cookie: &str) -> Request {
        request(&format!(
            "GET {target} HTTP/1.1\r\nHost: x\r\nCookie: {cookie}\r\n\r\n"
        ))
    }

    fn call(service: &Service, request: &Request, body: &str) -> Response {
        service.answer(
            request,
            body.as_bytes(),
            "203.0.113.9",
            Instant::now(),
            UNIX_EPOCH,
        )
    }

    /// The `Set-Cookie` value a response carries, as the bare `name=value` a follow-up request's
    /// own `Cookie` header wants — trimming everything after the first `;`.
    fn set_cookie(response: &Response) -> String {
        response
            .headers
            .get_str("set-cookie")
            .expect("a Set-Cookie header")
            .split(';')
            .next()
            .expect("at least the name=value")
            .to_string()
    }

    fn register(service: &Service, email: &str, password: &str) -> Response {
        let body = format!(r#"{{"email":"{email}","password":"{password}"}}"#);
        call(service, &json_post("/report/register", &body), &body)
    }

    fn login(service: &Service, email: &str, password: &str) -> Response {
        let body = format!(r#"{{"email":"{email}","password":"{password}"}}"#);
        call(service, &json_post("/report/login", &body), &body)
    }

    #[test]
    fn every_account_route_answers_404_when_accounts_are_not_configured() {
        let service = service("accounts-off");
        for (method_target, body) in [
            (
                "POST /report/register",
                r#"{"email":"a@example.com","password":"hunter2fish"}"#,
            ),
            (
                "POST /report/login",
                r#"{"email":"a@example.com","password":"hunter2fish"}"#,
            ),
            ("GET /report/me", ""),
            ("GET /report/mine", ""),
            ("POST /report/passkey/login/start", ""),
            ("GET /report/oauth/example/start", ""),
        ] {
            let (method, target) = method_target.split_once(' ').unwrap();
            let head = if method == "GET" {
                get(target)
            } else {
                json_post(target, body)
            };
            let response = call(&service, &head, body);
            assert_eq!(
                response.status,
                Status::NOT_FOUND,
                "{method_target}: {}",
                text(&response)
            );
        }
    }

    #[test]
    fn registering_signs_in_and_a_second_registration_with_the_same_email_is_refused() {
        let service = service_with_accounts("register");
        let response = register(&service, "alex@example.com", "hunter2fish");
        assert_eq!(response.status, Status::OK, "{}", text(&response));
        let cookie = set_cookie(&response);
        assert!(cookie.starts_with("report_session="), "{cookie}");

        let again = register(&service, "Alex@Example.com", "differentpassword");
        assert_eq!(again.status, Status::BAD_REQUEST);
        assert!(text(&again).contains("already exists"), "{}", text(&again));
    }

    #[test]
    fn a_password_below_the_minimum_is_refused_before_an_account_is_created() {
        let service = service_with_accounts("weak-password");
        let response = register(&service, "alex@example.com", "short");
        assert_eq!(response.status, Status::BAD_REQUEST);
        assert_eq!(
            login(&service, "alex@example.com", "short").status,
            Status::UNAUTHORIZED
        );
    }

    #[test]
    fn logging_in_verifies_the_password_and_a_wrong_one_is_refused_uniformly() {
        let service = service_with_accounts("login");
        register(&service, "alex@example.com", "hunter2fish");

        let wrong_password = login(&service, "alex@example.com", "wrongpassword");
        assert_eq!(wrong_password.status, Status::UNAUTHORIZED);
        let no_such_account = login(&service, "nobody@example.com", "hunter2fish");
        assert_eq!(no_such_account.status, Status::UNAUTHORIZED);
        assert_eq!(
            text(&wrong_password),
            text(&no_such_account),
            "a wrong password and no such account must not be distinguishable"
        );

        let right = login(&service, "alex@example.com", "hunter2fish");
        assert_eq!(right.status, Status::OK);
        assert!(set_cookie(&right).starts_with("report_session="));
    }

    #[test]
    fn logging_out_ends_the_session_the_cookie_named() {
        let service = service_with_accounts("logout");
        let cookie = set_cookie(&register(&service, "alex@example.com", "hunter2fish"));

        let logged_out = call(
            &service,
            &json_post_with_cookie("/report/logout", "", &cookie),
            "",
        );
        assert_eq!(logged_out.status, Status::OK);
        let full_header = logged_out
            .headers
            .get_str("set-cookie")
            .expect("a Set-Cookie header");
        assert!(full_header.contains("Max-Age=0"), "{full_header}");

        let whoami = call(&service, &get_with_cookie("/report/me", &cookie), "");
        assert_eq!(
            whoami.status,
            Status::UNAUTHORIZED,
            "the ended session no longer authenticates"
        );
    }

    #[test]
    fn whoami_answers_the_signed_in_account_and_refuses_anyone_else() {
        let service = service_with_accounts("whoami");
        let cookie = set_cookie(&register(&service, "alex@example.com", "hunter2fish"));

        let anonymous = call(&service, &get("/report/me"), "");
        assert_eq!(anonymous.status, Status::UNAUTHORIZED);

        let mine = call(&service, &get_with_cookie("/report/me", &cookie), "");
        assert_eq!(mine.status, Status::OK);
        assert!(
            text(&mine).contains("\"email\":\"alex@example.com\""),
            "{}",
            text(&mine)
        );
        assert!(
            text(&mine).contains("\"emailVerified\":false"),
            "{}",
            text(&mine)
        );
    }

    #[test]
    fn changing_the_password_signs_out_every_other_session() {
        let service = service_with_accounts("rotate");
        let first = set_cookie(&register(&service, "alex@example.com", "hunter2fish"));
        let second = set_cookie(&login(&service, "alex@example.com", "hunter2fish"));
        assert_ne!(first, second, "two logins mint two distinct sessions");

        let changed = call(
            &service,
            &json_post_with_cookie(
                "/report/me/password",
                r#"{"password":"brandnewpassword"}"#,
                &first,
            ),
            r#"{"password":"brandnewpassword"}"#,
        );
        assert_eq!(changed.status, Status::OK, "{}", text(&changed));

        assert_eq!(
            call(&service, &get_with_cookie("/report/me", &second), "").status,
            Status::UNAUTHORIZED,
            "the other session was ended by the rotation"
        );
        assert_eq!(
            login(&service, "alex@example.com", "hunter2fish").status,
            Status::UNAUTHORIZED
        );
        assert_eq!(
            login(&service, "alex@example.com", "brandnewpassword").status,
            Status::OK
        );
    }

    #[test]
    fn filing_with_a_session_attributes_the_report_and_lists_it_under_mine() {
        let service = service_with_accounts("attribution");
        let cookie = set_cookie(&register(&service, "alex@example.com", "hunter2fish"));

        let filed = file_with_cookie(
            &service,
            r#"{"kind":"bug","title":"attributed","detail":"d"}"#,
            "203.0.113.9",
            &cookie,
        );
        assert_eq!(filed.status, Status::OK, "{}", text(&filed));

        let mine = call(&service, &get_with_cookie("/report/mine", &cookie), "");
        assert_eq!(mine.status, Status::OK);
        assert!(text(&mine).contains("attributed"), "{}", text(&mine));

        // Filed with no session at all: unaffected, as it always was.
        let anonymous = file(
            &service,
            r#"{"kind":"bug","title":"anonymous","detail":"d"}"#,
            "203.0.113.9",
        );
        assert_eq!(anonymous.status, Status::OK);
        let entries = service.store().list("dx").expect("list");
        let anon_entry = entries
            .iter()
            .find(|entry| entry.title == "anonymous")
            .expect("found");
        assert!(anon_entry.account_id.is_none());
    }

    #[test]
    fn an_account_can_withdraw_its_own_report_but_not_anyone_elses() {
        let service = service_with_accounts("withdraw");
        let owner_cookie = set_cookie(&register(&service, "owner@example.com", "hunter2fish"));
        let stranger_cookie =
            set_cookie(&register(&service, "stranger@example.com", "hunter2fish"));

        file_with_cookie(
            &service,
            r#"{"kind":"bug","title":"mine to withdraw","detail":"d"}"#,
            "203.0.113.9",
            &owner_cookie,
        );
        let id = service.store().list("dx").expect("list")[0].id.clone();
        let withdraw_body = format!(r#"{{"project":"dx","id":"{id}"}}"#);

        let by_stranger = call(
            &service,
            &json_post_with_cookie("/report/mine/withdraw", &withdraw_body, &stranger_cookie),
            &withdraw_body,
        );
        assert_eq!(
            by_stranger.status,
            Status::NOT_FOUND,
            "not this account's report"
        );
        assert_eq!(
            service.store().list("dx").expect("list").len(),
            1,
            "still there"
        );

        let by_owner = call(
            &service,
            &json_post_with_cookie("/report/mine/withdraw", &withdraw_body, &owner_cookie),
            &withdraw_body,
        );
        assert_eq!(by_owner.status, Status::OK, "{}", text(&by_owner));
        assert!(service.store().list("dx").expect("list").is_empty());
    }

    #[test]
    fn a_verification_link_confirms_the_email_exactly_once() {
        let service = service_with_accounts("verify");
        register(&service, "alex@example.com", "hunter2fish");

        let token = spooled_verification_token("verify");
        let verified = call(&service, &get(&format!("/report/verify?token={token}")), "");
        assert_eq!(verified.status, Status::OK, "{}", text(&verified));

        let replayed = call(&service, &get(&format!("/report/verify?token={token}")), "");
        assert_eq!(
            replayed.status,
            Status::BAD_REQUEST,
            "a verification link is single-use"
        );

        let cookie = set_cookie(&login(&service, "alex@example.com", "hunter2fish"));
        let whoami = call(&service, &get_with_cookie("/report/me", &cookie), "");
        assert!(
            text(&whoami).contains("\"emailVerified\":true"),
            "{}",
            text(&whoami)
        );
    }

    /// Reads the verification token out of the one message the intake just spooled — the
    /// email a real inbox would receive, without a real mail server in this test.
    fn spooled_verification_token(label: &str) -> String {
        let queue_dir = std::env::temp_dir()
            .join(format!("selfhost-reports-service-accounts-{label}"))
            .join("mail")
            .join("mail")
            .join("queue");
        let entry = std::fs::read_dir(&queue_dir)
            .unwrap_or_else(|error| panic!("{}: {error}", queue_dir.display()))
            .filter_map(Result::ok)
            .next()
            .expect("one spooled message");
        let raw = std::fs::read_to_string(entry.path()).expect("read");
        raw.split("token=")
            .nth(1)
            .expect("a token in the message")
            .split_whitespace()
            .next()
            .expect("the token's own characters")
            .trim()
            .to_string()
    }

    #[test]
    fn passkey_registration_and_login_round_trip_through_the_http_routes() {
        let service = service_with_accounts("passkey");
        let device = Authenticator::new("credential-1");

        let started = call(
            &service,
            &json_post(
                "/report/passkey/register/start",
                r#"{"email":"alex@example.com"}"#,
            ),
            r#"{"email":"alex@example.com"}"#,
        );
        assert_eq!(started.status, Status::OK, "{}", text(&started));
        let challenge = challenge_value(&started);

        let finish_body = device.register_body_json(&challenge, "phone");
        let finished = call(
            &service,
            &json_post("/report/passkey/register/finish", &finish_body),
            &finish_body,
        );
        assert_eq!(finished.status, Status::OK, "{}", text(&finished));
        let registered_cookie = set_cookie(&finished);

        let login_started = call(&service, &json_post("/report/passkey/login/start", ""), "");
        assert_eq!(login_started.status, Status::OK);
        let login_challenge = challenge_value(&login_started);
        let login_body = device.login_body_json(&login_challenge);
        let login_finished = call(
            &service,
            &json_post("/report/passkey/login/finish", &login_body),
            &login_body,
        );
        assert_eq!(
            login_finished.status,
            Status::OK,
            "{}",
            text(&login_finished)
        );

        // Both sessions authenticate the same account.
        let via_registration = call(
            &service,
            &get_with_cookie("/report/me", &registered_cookie),
            "",
        );
        let via_login_cookie = set_cookie(&login_finished);
        let via_login = call(
            &service,
            &get_with_cookie("/report/me", &via_login_cookie),
            "",
        );
        assert_eq!(
            json_field(&text(&via_registration), "id"),
            json_field(&text(&via_login), "id"),
            "one passkey, one account, however it signed in"
        );
    }

    #[test]
    fn oauth_start_redirects_with_pkce_and_an_unknown_provider_is_404() {
        let service = service_with_accounts("oauth-start");
        let started = call(&service, &get("/report/oauth/example/start"), "");
        assert_eq!(started.status, Status::FOUND, "{}", text(&started));
        let location = started
            .headers
            .get_str("location")
            .expect("a Location header");
        assert!(
            location.starts_with("https://provider.example/authorize?"),
            "{location}"
        );
        assert!(
            location.contains("code_challenge_method=S256"),
            "{location}"
        );
        assert!(location.contains("redirect_uri=https%3A%2F%2Freports.example.com%2Freport%2Foauth%2Fexample%2Fcallback"), "{location}");

        let unknown = call(&service, &get("/report/oauth/nope/start"), "");
        assert_eq!(unknown.status, Status::NOT_FOUND);
    }

    #[test]
    fn a_flood_at_the_login_door_does_not_touch_the_filing_or_reading_allowance() {
        let dir = std::env::temp_dir().join("selfhost-reports-service-accounts-flood");
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir.join("store")).expect("store");
        store.add_project("dx").expect("project");
        let service = Service::new(
            store,
            Config {
                token: Some("secret-token".to_string()),
                accounts: Some(AccountsConfig {
                    data_dir: dir.join("accounts"),
                    site_name: "Test Reports".to_string(),
                    public_base_url: "https://reports.example.com".to_string(),
                    rp_id: None,
                    oauth_providers: Vec::new(),
                    verify_from: "reports@example.com".to_string(),
                    verify_helo: "example.com".to_string(),
                    mail_data_dir: None,
                    per_action: Rate::new(2, 3.0),
                }),
                ..Config::default()
            },
        );
        let now = Instant::now();
        for _ in 0..2 {
            login(&service, "nobody@example.com", "whatever1");
        }
        let flooded = login(&service, "nobody@example.com", "whatever1");
        assert_eq!(flooded.status, Status::TOO_MANY_REQUESTS);

        // Filing is a wholly separate allowance.
        let body = r#"{"kind":"bug","title":"still able to file","detail":"d"}"#;
        assert_eq!(
            service
                .answer(&post(body), body.as_bytes(), "203.0.113.9", now, UNIX_EPOCH)
                .status,
            Status::OK
        );
    }

    /// The `challenge` field out of a JSON challenge answer.
    fn challenge_value(response: &Response) -> String {
        let value = selfhost_json::parse(&text(response)).expect("json");
        value
            .get("challenge")
            .and_then(Json::as_str)
            .expect("a challenge")
            .to_string()
    }

    /// A named field out of a flat JSON object's text, for assertions that only need one value.
    fn json_field(text: &str, field: &str) -> String {
        selfhost_json::parse(text)
            .ok()
            .and_then(|value| value.get(field).and_then(Json::as_str).map(str::to_string))
            .unwrap_or_default()
    }

    /// The relying party these tests' passkey ceremonies speak for.
    const RP: &str = "reports.example.com";

    /// A minimal WebAuthn test authenticator — the same shape `webauthn::tests::Authenticator`
    /// uses, duplicated here rather than exported from that module's `#[cfg(test)]` block, so
    /// this file can drive the actual HTTP routes end to end without a browser.
    struct Authenticator {
        keys: ring::signature::EcdsaKeyPair,
        id: String,
    }

    impl Authenticator {
        fn new(id: &str) -> Self {
            use ring::rand::SystemRandom;
            use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                .expect("keypair");
            let keys =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                    .expect("keypair parses back");
            Self {
                keys,
                id: oauth::b64url_encode(id.as_bytes()),
            }
        }

        fn spki(&self) -> Vec<u8> {
            use ring::signature::KeyPair;
            // The exact prefix `crates/reports/src/webauthn.rs::P256_SPKI_PREFIX` cuts back out.
            const P256_SPKI_PREFIX: [u8; 26] = [
                0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
                0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
            ];
            let mut out = P256_SPKI_PREFIX.to_vec();
            out.extend_from_slice(self.keys.public_key().as_ref());
            out
        }

        fn auth_data(flags: u8) -> Vec<u8> {
            let mut out = ring::digest::digest(&ring::digest::SHA256, RP.as_bytes())
                .as_ref()
                .to_vec();
            out.push(flags);
            out.extend_from_slice(&[0, 0, 0, 1]);
            out
        }

        fn client_data(ceremony: &str, challenge: &str) -> Vec<u8> {
            Json::object([
                ("type", Json::string(ceremony)),
                ("challenge", Json::string(challenge)),
                ("origin", Json::string(format!("https://{RP}"))),
            ])
            .to_text()
            .into_bytes()
        }

        fn register_body_json(&self, challenge: &str, label: &str) -> String {
            let client = Self::client_data("webauthn.create", challenge);
            let flags = 0x01 | 0x04 | 0x40; // present, verified, attested credential
            Json::object([
                ("id", Json::string(&self.id)),
                ("algorithm", Json::Number(-7.0)),
                (
                    "publicKey",
                    Json::string(oauth::b64url_encode(&self.spki())),
                ),
                (
                    "clientDataJSON",
                    Json::string(oauth::b64url_encode(&client)),
                ),
                (
                    "authenticatorData",
                    Json::string(oauth::b64url_encode(&Self::auth_data(flags))),
                ),
                ("label", Json::string(label)),
            ])
            .to_text()
        }

        fn login_body_json(&self, challenge: &str) -> String {
            use ring::rand::SystemRandom;
            let client = Self::client_data("webauthn.get", challenge);
            let auth = Self::auth_data(0x01 | 0x04);
            let mut message = auth.clone();
            message
                .extend_from_slice(ring::digest::digest(&ring::digest::SHA256, &client).as_ref());
            let signature = self
                .keys
                .sign(&SystemRandom::new(), &message)
                .expect("signs");
            Json::object([
                ("id", Json::string(&self.id)),
                (
                    "clientDataJSON",
                    Json::string(oauth::b64url_encode(&client)),
                ),
                (
                    "authenticatorData",
                    Json::string(oauth::b64url_encode(&auth)),
                ),
                (
                    "signature",
                    Json::string(oauth::b64url_encode(signature.as_ref())),
                ),
            ])
            .to_text()
        }
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
