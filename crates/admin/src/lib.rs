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
pub mod stream;
pub mod token;
pub mod upgrade;
pub mod webauthn;

use selfhost_firewall::Manager;
use selfhost_git::Watches;
use selfhost_http::{Body, Method, Request, Response, Status};
use selfhost_identity::{Caller, Capability, Credential, Identity, Opening, People, Policy};
use selfhost_json::Json;
use selfhost_supervisor::Supervisor;
use selfhost_supervisor::state::{spec_from_json, spec_to_json};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub use passwd::ConsolePassword;
pub use session::{Authenticated, FailureGate, Sessions};
pub use store::Store;
pub use token::Token;
pub use upgrade::{Ability, Admission, Denial, Doorway, Holder, MintError, Streams, Tickets};
pub use webauthn::Webauthn;

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
    /// Single-use tickets that authorise an upgrade.
    ///
    /// Held on the `Api` rather than inside [`ConsoleAuth`] because the bearer
    /// token opens a stream too — the native console over its SSH tunnel — and a
    /// deployment with no console password would otherwise have a credential
    /// that can reach every route except the streaming ones.
    tickets: Tickets,
    /// How many streams are open, and for whom. Held here for the same reason
    /// the tickets are: a bearer stream counts against the same ceiling a
    /// browser's does.
    streams: Streams,
    /// The authorisation model every route is decided by.
    ///
    /// Locked down by default, so a deployment that has not wired
    /// `[desktop].bearer_may_control` refuses an unattended credential the
    /// capabilities that drive a machine — the safe direction for a switch
    /// nobody has set yet.
    policy: Policy,
    /// The people this deployment knows and what each of them holds.
    ///
    /// `None` until a data directory has been named ([`Api::with_console_auth`]
    /// wires it), and `None` grants nothing: an owner's authority never comes
    /// from this registry, and a person with no registry to be found in holds
    /// exactly what a person with an empty entry holds, which is nothing.
    people: Option<People>,
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
    /// The shared login rate limiter — one gate over both login doors, so a
    /// guesser cannot double the budget by alternating password and passkey.
    gate: FailureGate,
    /// Passkey (biometric) login, present once [`Api::with_console_webauthn`]
    /// has been called. Absent when no console site is configured: without a
    /// hostname there is no relying-party identity to verify against.
    webauthn: Option<Webauthn>,
    /// The console site's canonical origin — `https://<hostname>` — computed
    /// from configuration and never from a request.
    ///
    /// The value an upgrade's `Origin` must equal. It is the same string, from
    /// the same source and for the same reason, as the WebAuthn relying-party
    /// origin: the proxy's relay forwards no `Host`, and an identity the client
    /// could choose would defeat the comparison entirely. Absent means no
    /// console site is configured, and a browser is then refused a stream rather
    /// than admitted unchecked — see [`upgrade::origin_permitted`].
    origin: Option<String>,
}

/// What a route demands of the caller who reached it.
///
/// Two shapes, because the capability vocabulary is closed and deliberately
/// small, and one part of this API is not in it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Demand {
    /// A capability from [`selfhost_identity`]'s closed vocabulary, decided by
    /// [`Policy::decide`].
    Held(Capability),
    /// The owner's own identity, and nothing less.
    ///
    /// The passkey routes. Registering a credential is not *using* a power, it
    /// is *minting* one: a passkey registered under a name is a way to
    /// authenticate as that name for ever after, and the capability vocabulary
    /// has no word for "may create authority" because no grant should ever
    /// confer it. Until there is a capability that honestly describes it, these
    /// routes ask for the identity that cannot be granted to anybody.
    OwnerOnly,
}

/// One matched route behind the authorisation wall, and the whole of this API's
/// surface there.
///
/// Split out of [`Api::handle`] so that "which route is this" and "what does it
/// demand" are separate, pure, and testable without a supervisor. The dispatch
/// below matches this enum exhaustively, so a route added here and forgotten in
/// [`Route::demand`] is a build error rather than a route with no permission.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Route<'a> {
    /// `GET /api/services`
    ListServices,
    /// `GET /api/services/<name>`
    Describe(&'a str),
    /// `PUT /api/services/<name>`
    Install(&'a str),
    /// `DELETE /api/services/<name>`
    Uninstall(&'a str),
    /// `GET /api/services/<name>/logs`
    Logs(&'a str),
    /// `POST /api/services/<name>/deploy`
    DeployNow(&'a str),
    /// `POST /api/services/<name>/<action>`
    Act(&'a str, &'a str),
    /// `POST /api/desktop/ticket`
    MintTicket,
    /// `GET /api/firewall`
    FirewallState,
    /// `POST /api/firewall/reconcile`
    FirewallReconcile,
    /// `POST /api/webauthn/register/challenge`
    RegisterChallenge,
    /// `POST /api/webauthn/register`
    Register,
    /// `GET /api/webauthn/credentials`
    ListPasskeys,
    /// `DELETE /api/webauthn/credentials/<id>`
    RemovePasskey(&'a str),
}

impl<'a> Route<'a> {
    /// The route named by a method and a split path, or `None` for anything
    /// this API does not serve.
    fn of(method: &Method, segments: &[&'a str]) -> Option<Self> {
        match (method, segments) {
            (Method::Get, ["api", "services"]) => Some(Self::ListServices),
            (Method::Get, ["api", "services", name]) => Some(Self::Describe(name)),
            (Method::Put, ["api", "services", name]) => Some(Self::Install(name)),
            (Method::Delete, ["api", "services", name]) => Some(Self::Uninstall(name)),
            (Method::Get, ["api", "services", name, "logs"]) => Some(Self::Logs(name)),
            // Matched ahead of the generic action route below: "deploy" is not a
            // supervisor action like start/stop/restart, it drives a git watch.
            (Method::Post, ["api", "services", name, "deploy"]) => Some(Self::DeployNow(name)),
            (Method::Post, ["api", "services", name, action]) => Some(Self::Act(name, action)),
            // The stream mint. A non-`GET`, so the CSRF header was already
            // demanded of a cookie caller by `authorised()` — by code that
            // predates streams and is not changed by them. That is the whole
            // trick: a handshake is a `GET` and cannot carry a custom header, so
            // the moment that *can* be protected is moved here and the handshake
            // is made to carry proof that it happened. See [`crate::upgrade`].
            (Method::Post, ["api", "desktop", "ticket"]) => Some(Self::MintTicket),
            // Authenticated, not on `/api/health`: the open ports it reveals are
            // as sensitive as the service list, so it sits inside the wall.
            (Method::Get, ["api", "firewall"]) => Some(Self::FirewallState),
            (Method::Post, ["api", "firewall", "reconcile"]) => Some(Self::FirewallReconcile),
            (Method::Post, ["api", "webauthn", "register", "challenge"]) => {
                Some(Self::RegisterChallenge)
            }
            (Method::Post, ["api", "webauthn", "register"]) => Some(Self::Register),
            (Method::Get, ["api", "webauthn", "credentials"]) => Some(Self::ListPasskeys),
            (Method::Delete, ["api", "webauthn", "credentials", id]) => {
                Some(Self::RemovePasskey(id))
            }
            _ => None,
        }
    }

    /// What this route demands of its caller.
    ///
    /// The whole of the mapping from this API's surface onto the capability
    /// model, in one match a reviewer can read in a sitting. Two capabilities
    /// cover everything that existed before this model did, which is what makes
    /// the change byte-for-byte equivalent for an owner: the boolean these
    /// replace answered yes to all of it, and [`Policy::decide`] answers
    /// [`Decision::Allow`](selfhost_identity::Decision::Allow) to all of it for
    /// [`Identity::Owner`].
    ///
    /// The split between the two is *shows* against *does*.
    /// [`Capability::ConsoleRead`] is everything the console renders — the
    /// service list, one service's state, its logs, the firewall's state, and
    /// the events stream that pushes exactly those. [`Capability::ServiceControl`]
    /// is everything that changes the machine: installing, uninstalling,
    /// starting, stopping, restarting, deploying, and re-asserting the firewall.
    /// Reconciling the firewall is deliberately on the second side even though
    /// reading it is on the first, because it rewrites the host's rules.
    ///
    /// [`Route::MintTicket`] is the exception that proves the mapping is real:
    /// its demand is not fixed here, because a ticket carries whatever abilities
    /// were asked for, and each of those is decided separately against its own
    /// capability in [`Api::mint_ticket`]. What is checked here is only that the
    /// caller may read the console at all — a floor, not the decision.
    fn demand(&self) -> Demand {
        match self {
            Self::ListServices
            | Self::Describe(_)
            | Self::Logs(_)
            | Self::FirewallState
            | Self::MintTicket => Demand::Held(Capability::ConsoleRead),
            Self::Install(_)
            | Self::Uninstall(_)
            | Self::DeployNow(_)
            | Self::Act(_, _)
            | Self::FirewallReconcile => Demand::Held(Capability::ServiceControl),
            Self::RegisterChallenge
            | Self::Register
            | Self::ListPasskeys
            | Self::RemovePasskey(_) => Demand::OwnerOnly,
        }
    }
}

/// The name of the session cookie the console browser holds.
const SESSION_COOKIE: &str = "selfhost_session";

/// The identity behind the root credentials: the console password and the
/// bearer token. Passkey sessions carry the holder's own name instead.
const OWNER: &str = "owner";

/// The body of every "you are in" reply — login, passkey login, and the
/// session probe — naming who the session belongs to, in one shape so the
/// SPA reads them with one hand.
fn session_granted(user: &str) -> Json {
    Json::object([("ok", Json::Bool(true)), ("user", Json::string(user))])
}

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
        Self {
            supervisor,
            store: Arc::new(store),
            token,
            watches,
            firewall,
            console: None,
            tickets: Tickets::new(),
            streams: Streams::new(),
            policy: Policy::locked_down(),
            people: None,
        }
    }

    /// Enables cookie-session login, loading the password hash and the people
    /// registry from `dir`.
    ///
    /// The wiring seam for the daemon: called once, right after [`Api::new`],
    /// with the daemon's data directory. A missing password file still enables
    /// the session routes — they just refuse every login until
    /// `selfhost console-password` writes one.
    ///
    /// The registry is persisted through this crate's own
    /// [`token::write_private`], which is the one implementation in this
    /// workspace that builds an explicit owner-only DACL on Windows rather than
    /// inheriting the parent directory's. `selfhost-identity` cannot do that for
    /// itself — it forbids `unsafe` and sits below this crate — so the writer is
    /// injected here, at the one place that already owns it.
    pub fn with_console_auth(self, dir: &Path) -> Self {
        self.with_console_auth_parts(ConsolePassword::load(dir), Sessions::new())
            .with_people(People::with_writer(dir, token::write_private))
    }

    /// Records the people registry the policy reads grants from.
    ///
    /// Separate from [`Api::with_console_auth`] so a test can hand in a registry
    /// it built, and so a deployment without a console password can still have
    /// one. Absent, every person holds nothing; the owner is unaffected either
    /// way, because [`Policy::decide`] never consults an owner's grants.
    pub fn with_people(mut self, people: People) -> Self {
        self.people = Some(people);
        self
    }

    /// Records the authorisation policy, which is one switch today:
    /// `[desktop].bearer_may_control`.
    ///
    /// Not read from configuration here, because this crate must keep working
    /// for a daemon that has not been taught the key yet — and the default it
    /// keeps in that case is the locked-down one, which refuses rather than
    /// permits.
    pub fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    /// Enables cookie-session login from already-built parts.
    ///
    /// The seam behind [`Api::with_console_auth`] that makes expiry testable:
    /// a test passes a [`Sessions`] built with `Sessions::with_expiry` to get
    /// sessions that expire without waiting hours.
    pub fn with_console_auth_parts(mut self, password: ConsolePassword, sessions: Sessions) -> Self {
        self.console = Some(ConsoleAuth {
            password: Arc::new(password),
            sessions,
            gate: FailureGate::new(),
            webauthn: None,
            origin: None,
        });
        self
    }

    /// Records the console site's canonical hostname, which fixes the origin an
    /// upgrade's `Origin` header must equal.
    ///
    /// Separate from [`Api::with_console_webauthn`] so a deployment can have a
    /// console site without passkeys and still get the origin check — but
    /// `with_console_webauthn` calls this itself, because it already receives
    /// the same hostname for the same reason and a second wiring point is a
    /// second thing to forget. Forgetting it fails closed: with no origin
    /// recorded, a browser cannot open a stream at all.
    pub fn with_console_origin(mut self, host: &str) -> Self {
        if let Some(console) = &mut self.console {
            console.origin = Some(format!("https://{host}"));
        }
        self
    }

    /// Enables passkey (biometric) login for the console site at `rp_id`.
    ///
    /// Called after [`Api::with_console_auth`] with the console site's
    /// canonical hostname — the WebAuthn relying-party id every credential is
    /// scoped to. The hostname must come from configuration, never a request:
    /// the proxy relay forwards no `Host`, and an attacker-chosen identity
    /// would defeat the origin binding that makes passkeys unphishable.
    /// Without console auth there is no session to mint, so this is a no-op.
    ///
    /// Also records the stream origin ([`Api::with_console_origin`]): the two
    /// are the same hostname, wanted for the same reason, and the daemon
    /// already calls this with it.
    pub fn with_console_webauthn(mut self, rp_id: &str, dir: &Path) -> Self {
        if let Some(console) = &mut self.console {
            console.webauthn = Some(Webauthn::load(rp_id, dir));
        }
        self.with_console_origin(rp_id)
    }

    /// The same, from an already-built verifier — the tests' seam.
    ///
    /// Deliberately does **not** set the stream origin: a built verifier does not
    /// hand back the hostname it was built for, and inferring one would mean
    /// guessing at the value a security check compares against. A test that wants
    /// both calls [`Api::with_console_origin`] as well, which is one line and is
    /// honest about what it is asserting.
    pub fn with_console_webauthn_parts(mut self, webauthn: Webauthn) -> Self {
        if let Some(console) = &mut self.console {
            console.webauthn = Some(webauthn);
        }
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
                Method::Post if has_console_header(request) => self.login(body).await,
                Method::Post => problem(Status(401), "authorisation required"),
                Method::Delete => self.logout(request),
                Method::Get => self.session_probe(request),
                _ => problem(Status(404), "no such endpoint"),
            };
        }

        // The passkey login pair sits ahead of the wall for the same reason
        // `POST /api/session` does: it is how a browser *gets* authorised.
        // Both are POSTs that carry the CSRF header — the challenge route
        // feeds the failure gate's door and must not be drivable cross-site.
        if path == "/api/webauthn/login/challenge" || path == "/api/webauthn/login" {
            if request.method != Method::Post {
                return problem(Status(404), "no such endpoint");
            }
            if !has_console_header(request) {
                return problem(Status(401), "authorisation required");
            }
            return if path == "/api/webauthn/login" {
                self.webauthn_login(body).await
            } else {
                self.webauthn_login_challenge()
            };
        }

        if !self.authorised(request) {
            // No detail about why. "Wrong token" and "no token" are the same
            // answer to anyone who should not be here.
            return problem(Status(401), "authorisation required");
        }

        let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
        let Some(route) = Route::of(&request.method, &segments) else {
            return problem(Status(404), "no such endpoint");
        };

        // The wall above answers *whether* this request is authenticated; this
        // answers *who*, and what they may do with it. Both are needed and
        // neither replaces the other: the wall is what refreshes an idle timer
        // and what enforces the CSRF header, and this is what decides the route.
        let Some(caller) = self.caller(request) else {
            return problem(Status(401), "authorisation required");
        };
        if !self.permits(&caller, &route.demand()) {
            // The same uninformative 401 an anonymous caller gets. A person who
            // is known to the deployment and holds nothing must not be able to
            // tell that apart from being unknown, or the console becomes a way
            // to enumerate what exists behind it.
            return problem(Status(401), "authorisation required");
        }

        match route {
            Route::ListServices => self.list_services().await,
            Route::Describe(name) => self.describe(name).await,
            Route::Install(name) => self.install(name, body).await,
            Route::Uninstall(name) => self.uninstall(name).await,
            Route::Logs(name) => self.logs(name, query).await,
            Route::DeployNow(name) => self.deploy_now(name).await,
            Route::Act(name, action) => self.act(name, action).await,
            Route::MintTicket => self.mint_ticket(request, &caller, body),
            Route::FirewallState => self.firewall_state().await,
            Route::FirewallReconcile => self.firewall_reconcile().await,
            Route::RegisterChallenge => self.webauthn_register_challenge(),
            Route::Register => self.webauthn_register(body),
            Route::ListPasskeys => self.webauthn_list(),
            Route::RemovePasskey(id) => self.webauthn_remove(id),
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
    ///
    /// Every candidate cookie is tried, not the first (see [`session_cookies`]).
    /// `validate` refreshes the idle timer of whatever it matches, and a planted
    /// value matches nothing, so at most the caller's own real session is
    /// refreshed.
    fn cookie_authorised(&self, request: &Request) -> bool {
        let Some(console) = &self.console else {
            return false;
        };
        if request.method != Method::Get && !has_console_header(request) {
            return false;
        }
        session_cookies(request).iter().any(|id| console.sessions.validate(id))
    }

    /// Who is behind this request, and what they hold.
    ///
    /// The seam `selfhost-identity` was written to end at, and the counterpart
    /// to [`Api::authorised`]: the same two doors, in the same order, answering
    /// *who* rather than *whether*.
    ///
    /// Two properties matter and both are load-bearing:
    ///
    /// - **It preserves the CSRF-header-before-store ordering.** A non-`GET`
    ///   without [`CONSOLE_HEADER`] is refused here before the session store is
    ///   consulted, exactly as in [`Api::cookie_authorised`], so building a
    ///   `Caller` never becomes a second path into the store that skips the
    ///   check.
    /// - **It does not refresh the idle timer.** It reads with
    ///   [`Sessions::authenticated`] rather than `Sessions::validate`, because
    ///   the callers here are a capability check, a ticket mint and a handshake,
    ///   and none of those should be able to keep a session alive on its own.
    ///   For an ordinary request the timer was already refreshed by
    ///   `authorised()`, for a caller who deserved it.
    ///
    /// `None` means no credential this deployment recognises — which is also
    /// what a session naming something [`Identity::parse`] refuses produces. A
    /// stored name that is not a valid identity is a corrupted or hand-edited
    /// store, and the safe reading of an identity nobody can name is nobody.
    pub fn caller(&self, request: &Request) -> Option<Caller> {
        if self.bearer_authorised(request) {
            // The bearer token is the deployment's root credential; whatever
            // holds it is the owner, exactly as it is everywhere else here.
            return Some(Caller::bearer());
        }
        let console = self.console.as_ref()?;
        if request.method != Method::Get && !has_console_header(request) {
            return None;
        }
        let (_, held) = self.live_session(console, request)?;
        let identity = Identity::parse(&held.user).ok()?;
        let credential = Credential::Session(selfhost_identity::Session::new(
            held.opened_by,
            held.opened_at,
        ));
        Some(match &self.people {
            Some(people) => people.caller(identity, credential),
            // No registry wired: the owner's authority does not come from one,
            // and a person's comes from nowhere else, so a person holds nothing.
            None => Caller::new(identity, credential, selfhost_identity::Grants::none()),
        })
    }

    /// The first candidate cookie that names a live session, and who holds it.
    ///
    /// Reads without refreshing; see [`Api::caller`].
    fn live_session(
        &self,
        console: &ConsoleAuth,
        request: &Request,
    ) -> Option<(String, Authenticated)> {
        session_cookies(request)
            .into_iter()
            .find_map(|id| console.sessions.authenticated(&id).map(|held| (id, held)))
    }

    /// Whether `caller` satisfies what a route demands.
    ///
    /// The one place this crate asks the authorisation model a question about an
    /// ordinary route. Every refusal becomes the same uninformative 401 at the
    /// caller; the distinction between the two demands lives here and nowhere
    /// on the wire.
    fn permits(&self, caller: &Caller, demand: &Demand) -> bool {
        match demand {
            Demand::Held(capability) => self.policy.decide(caller, capability).is_allowed(),
            Demand::OwnerOnly => caller.identity().is_owner(),
        }
    }

    /// Answers `POST /api/session`: verifies the password and mints a session.
    ///
    /// Every authentication failure — no password configured, wrong password —
    /// is the identical 401 the rest of the API sends, so probing this route
    /// reveals nothing about the deployment's configuration. A malformed body
    /// is a 400, which reveals only that the caller cannot form JSON.
    ///
    /// The password is checked **before** the rate limiter is consulted, and the
    /// limiter only ever refuses a credential that turned out to be wrong. See
    /// [`FailureGate`] for the reasoning; the short version is that this API is
    /// reachable by anything already running on this box, a lockout would
    /// otherwise be a remotely-triggered denial of the operator's own console,
    /// and the desktop's re-authentication rule routes them back through this
    /// exact door.
    async fn login(&self, body: &[u8]) -> Response {
        let Some(console) = &self.console else {
            return problem(Status(401), "authorisation required");
        };
        let Some(password) = login_password(body) else {
            return problem(Status(400), "body must be JSON with a \"password\" string");
        };
        if !console.password.verify(&password) {
            return self.refuse_login(console).await;
        }
        console.gate.reset();
        // The password is the root credential; the session it mints is the
        // deployment's owner, whatever device typed it.
        match console.sessions.create(OWNER, Opening::Password) {
            Ok(id) => with_session_cookie(
                json(Status(200), session_granted(OWNER)),
                &id,
                session::SESSION_LIFETIME_SECS,
            ),
            Err(error) => problem(Status(500), &format!("could not create a session: {error}")),
        }
    }

    /// Counts one failed login and answers it.
    ///
    /// One place for both login doors, so the password and the passkey cannot
    /// drift into charging different prices for the same mistake.
    ///
    /// The gate is read *before* this failure is counted, which keeps the
    /// thresholds exactly where they were when the gate stood in front of
    /// verification: the attempt that reaches [`FailureGate`]'s limit is still
    /// an ordinary 401, and only the ones after it are refused as a lockout.
    ///
    /// A locked gate waits out [`FailureGate::penalise`] before answering. That
    /// delay is the whole of what a lockout costs a guesser now that it costs a
    /// correct credential nothing, and the 429 rather than a 401 is so an
    /// operator who really did mistype is told the difference between "wrong"
    /// and "the door is busy".
    async fn refuse_login(&self, console: &ConsoleAuth) -> Response {
        let locked = console.gate.locked();
        console.gate.record_failure();
        if locked {
            console.gate.penalise().await;
            return problem(Status(429), "too many attempts");
        }
        problem(Status(401), "authorisation required")
    }

    /// The passkey verifier, when the whole chain to it is enabled.
    fn webauthn(&self) -> Option<(&ConsoleAuth, &Webauthn)> {
        let console = self.console.as_ref()?;
        Some((console, console.webauthn.as_ref()?))
    }

    /// Answers `POST /api/webauthn/login/challenge`: a challenge the login
    /// page can hand to `navigator.credentials.get()`.
    ///
    /// The uniform 401 covers "feature off" and "no passkey registered"
    /// alike, so this unauthenticated route reveals nothing about the
    /// deployment; it names no credential ids for the same reason.
    ///
    /// Issued **even while the gate is locked**, which reverses an earlier rule.
    /// A challenge is a random number that grants nothing: it cannot be turned
    /// into a session without a signature from hardware the guesser does not
    /// have, and the challenge store is bounded and single-use. Refusing it
    /// while locked was therefore not a defence against guessing — it was the
    /// second half of the lockout this deployment cannot afford, shutting the
    /// operator's biometric door because somebody else got a password wrong five
    /// times. See [`FailureGate`].
    fn webauthn_login_challenge(&self) -> Response {
        let Some((_, webauthn)) = self.webauthn() else {
            return problem(Status(401), "authorisation required");
        };
        if webauthn.is_empty() {
            return problem(Status(401), "authorisation required");
        }
        match webauthn.challenge(webauthn::Purpose::Login) {
            Ok(challenge) => json(Status(200), challenge),
            Err(error) => problem(Status(500), &format!("could not issue a challenge: {error}")),
        }
    }

    /// Answers `POST /api/webauthn/login`: verifies an assertion and mints
    /// the same session cookie a password login would.
    ///
    /// Failures count into the shared [`FailureGate`], and every one of them
    /// is the API's uniform 401 — the reasons live in the verifier.
    ///
    /// The assertion is verified before the gate is consulted, for the reason
    /// [`Api::login`] gives: a lockout may refuse a wrong credential and may
    /// never refuse a right one. A passkey assertion is the credential this rule
    /// matters most for, because it is the one that proves a person is at the
    /// machine right now.
    async fn webauthn_login(&self, body: &[u8]) -> Response {
        let Some((console, webauthn)) = self.webauthn() else {
            return problem(Status(401), "authorisation required");
        };
        let Some(assertion) = parse_json_body(body) else {
            return problem(Status(400), "body must be a JSON assertion");
        };
        let Ok(passkey) = webauthn.verify_login(&assertion) else {
            return self.refuse_login(console).await;
        };
        console.gate.reset();
        // The assertion proved which person's credential signed it; the
        // session belongs to that person by cryptographic fact, not claim.
        match console.sessions.create(&passkey.user, Opening::Passkey) {
            Ok(id) => with_session_cookie(
                json(Status(200), session_granted(&passkey.user)),
                &id,
                session::SESSION_LIFETIME_SECS,
            ),
            Err(error) => problem(Status(500), &format!("could not create a session: {error}")),
        }
    }

    /// Answers `POST /api/webauthn/register/challenge` for an authenticated
    /// caller about to run `navigator.credentials.create()`.
    fn webauthn_register_challenge(&self) -> Response {
        let Some((_, webauthn)) = self.webauthn() else {
            return problem(Status(404), "passkey login is not configured on this deployment");
        };
        match webauthn.challenge(webauthn::Purpose::Register) {
            Ok(challenge) => json(Status(200), challenge),
            Err(error) => problem(Status(500), &format!("could not issue a challenge: {error}")),
        }
    }

    /// Answers `POST /api/webauthn/register`: verifies and stores a new
    /// passkey. Behind the wall, but a 401-shaped refusal would mislead an
    /// authenticated caller — a rejected ceremony is this route's 400.
    fn webauthn_register(&self, body: &[u8]) -> Response {
        let Some((_, webauthn)) = self.webauthn() else {
            return problem(Status(404), "passkey login is not configured on this deployment");
        };
        let Some(registration) = parse_json_body(body) else {
            return problem(Status(400), "body must be a JSON registration");
        };
        match webauthn.register(&registration) {
            Ok(passkey) => json(
                Status(200),
                Json::object([
                    ("registered", Json::string(passkey.label)),
                    ("user", Json::string(passkey.user)),
                ]),
            ),
            Err(_) => problem(Status(400), "the registration could not be verified"),
        }
    }

    /// Answers `GET /api/webauthn/credentials`: the registered passkeys.
    fn webauthn_list(&self) -> Response {
        match self.webauthn() {
            Some((_, webauthn)) => json(Status(200), webauthn.list()),
            None => problem(Status(404), "passkey login is not configured on this deployment"),
        }
    }

    /// Answers `DELETE /api/webauthn/credentials/<id>`: revokes one passkey.
    fn webauthn_remove(&self, id: &str) -> Response {
        let Some((_, webauthn)) = self.webauthn() else {
            return problem(Status(404), "passkey login is not configured on this deployment");
        };
        match webauthn.remove(id) {
            Ok(true) => json(Status(200), Json::object([("removed", Json::string(id))])),
            Ok(false) => problem(Status(404), "no such passkey"),
            Err(error) => problem(Status(500), &format!("could not save the passkeys: {error}")),
        }
    }

    /// Answers `DELETE /api/session`: revokes the cookie's session.
    ///
    /// Deliberately outside the authorisation wall and always a 200: logging
    /// out an expired or unknown cookie must still clear it from the browser,
    /// and the worst a forged logout can do is inconvenience the operator into
    /// logging in again.
    /// Every candidate cookie is revoked, not the first: a browser carrying a
    /// planted `selfhost_session` alongside the real one must still be able to
    /// log out of the real one.
    fn logout(&self, request: &Request) -> Response {
        if let Some(console) = &self.console {
            for id in session_cookies(request) {
                console.sessions.revoke(&id);
            }
        }
        // Max-Age=0 makes the browser discard the cookie immediately.
        with_session_cookie(json(Status(200), Json::object([("ok", Json::Bool(true))])), "", 0)
    }

    /// Answers `GET /api/session`: the SPA's session probe.
    ///
    /// A 200 for any authenticated caller — cookie or bearer — and the usual
    /// uninformative 401 otherwise, so the SPA can decide between its login
    /// form and its dashboard with one request. The 200 names the session's
    /// holder; a bearer token is the owner's own credential.
    fn session_probe(&self, request: &Request) -> Response {
        if !self.authorised(request) {
            return problem(Status(401), "authorisation required");
        }
        let user = self
            .console
            .as_ref()
            .and_then(|console| self.live_session(console, request))
            .map(|(_, held)| held.user)
            .unwrap_or_else(|| OWNER.to_owned());
        json(Status(200), session_granted(&user))
    }

    /// The console site's canonical origin, when one is configured.
    fn console_origin(&self) -> Option<&str> {
        self.console.as_ref()?.origin.as_deref()
    }

    /// Which credential this request presents, and who and what it is.
    ///
    /// The same two doors [`Api::authorised`] opens, in the same order, but
    /// answering *which one* rather than merely *whether*: a ticket is bound to
    /// the credential that minted it, so the streaming paths need the credential
    /// instance as well as the authority behind it.
    ///
    /// Reads the session store without refreshing the idle timer, for the reason
    /// [`Api::caller`] gives.
    fn holder_of(&self, request: &Request) -> Option<(Holder, Caller)> {
        Some((self.holder(request)?, self.caller(request)?))
    }

    /// Which credential *instance* this request presents.
    ///
    /// Separate from [`Api::caller`] because the two answer different questions
    /// and only one of them is a secret: a [`Caller`] is an identity and a grant
    /// set, while a [`Holder`] is the session id itself, which is what a ticket
    /// is bound to so that one browser's ticket cannot be redeemed by another.
    fn holder(&self, request: &Request) -> Option<Holder> {
        if self.bearer_authorised(request) {
            return Some(Holder::Bearer);
        }
        let console = self.console.as_ref()?;
        let (id, _) = self.live_session(console, request)?;
        Some(Holder::Session(id))
    }

    /// Answers `POST /api/desktop/ticket`: mints the single-use credential a
    /// handshake must present.
    ///
    /// Behind the authorisation wall, so this route is reachable only by a
    /// caller who could already drive the console — a ticket grants nothing new,
    /// it moves an existing authorisation across a boundary a custom header
    /// cannot cross. The body is optional; `{"want": ["events"]}` names the
    /// abilities, and an unrecognised word is a `400` rather than a ticket that
    /// silently authorises less than was asked for.
    ///
    /// **Every requested ability is decided separately**, against the capability
    /// [`Ability::capability`] names for it, through [`Policy::decide`]. That is
    /// the whole difference between this route and the one the review found:
    /// reading the ability words out of the body and handing them back is not a
    /// mint, it is a caller granting themselves whatever they asked for. A
    /// refusal is the same uninformative 401 as everywhere else, because the
    /// alternative tells a caller which powers exist and which of them they
    /// nearly had.
    fn mint_ticket(&self, request: &Request, caller: &Caller, body: &[u8]) -> Response {
        let Some(holder) = self.holder(request) else {
            return problem(Status(401), "authorisation required");
        };
        let Some(abilities) = requested_abilities(body) else {
            return problem(Status(400), "body must be JSON with a \"want\" array of known abilities");
        };
        for ability in &abilities {
            if !self.policy.decide(caller, &ability.capability()).is_allowed() {
                return problem(Status(401), "authorisation required");
            }
        }
        match self.tickets.mint(holder, abilities) {
            Ok(ticket) => json(
                Status(200),
                Json::object([
                    ("ticket", Json::string(ticket)),
                    ("expiresIn", Json::Number(upgrade::TICKET_LIFETIME.as_secs() as f64)),
                ]),
            ),
            // A client that has asked for more unredeemed tickets than it can
            // hold is looping; that is its own doing and its own to slow down,
            // so it is a 429 rather than a fault reported as a 500.
            Err(error @ MintError::TooManyOutstanding) => problem(Status(429), &error.to_string()),
            Err(error) => problem(Status(500), &format!("could not mint a ticket: {error}")),
        }
    }

    /// Whether this handshake may become a stream on `route`, and everything the
    /// stream needs if it may.
    ///
    /// Pure: it reads a request head and the in-memory ticket store, and touches
    /// no socket. That is what lets every refusal be tested by building a
    /// `Request`, and it is the same property [`Api::handle`] has and must keep.
    /// The socket hand-over is [`crate::stream`]'s.
    ///
    /// The decision itself is [`upgrade::decide`], which owns the ordering of
    /// the checks and the reasoning for it; this supplies the things only an
    /// `Api` can know — which credential was presented and what it may do, what
    /// the console site's origin is, and where the tickets and the concurrency
    /// ceiling live. Every [`Denial`] becomes one uniform 401 at the caller; the
    /// variants exist so the daemon's own log can say which check failed, where
    /// an operator can read it and a stranger cannot.
    pub fn upgrade_for(&self, request: &Request, route: Ability) -> Result<Admission, Denial> {
        upgrade::decide(
            request,
            self.holder_of(request),
            &Doorway {
                policy: &self.policy,
                expected_origin: self.console_origin(),
                tickets: &self.tickets,
                streams: &self.streams,
            },
            route,
        )
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
    parse_json_body(body)?.get("password").and_then(Json::as_str).map(str::to_owned)
}

/// Reads the abilities a ticket is being minted for.
///
/// An empty body means the one ability this deployment has a route for, so the
/// console can ask for a stream without composing a document. Anything else must
/// be `{"want": [...]}` carrying known words: an unknown word is refused rather
/// than skipped, because a ticket that quietly authorises less than was asked
/// for turns into a stream that closes for no stated reason, minutes later and
/// somewhere else.
fn requested_abilities(body: &[u8]) -> Option<Vec<Ability>> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Some(vec![Ability::Events]);
    }
    let value = parse_json_body(body)?;
    let Some(want) = value.get("want") else {
        return Some(vec![Ability::Events]);
    };
    let words = want.as_array()?;
    if words.is_empty() {
        return None;
    }
    words.iter().map(|word| Ability::parse(word.as_str()?)).collect()
}

/// Parses a request body as JSON, or `None` for anything that is not.
fn parse_json_body(body: &[u8]) -> Option<Json> {
    selfhost_json::parse(std::str::from_utf8(body).ok()?).ok()
}

/// The most `selfhost_session` pairs read out of one `Cookie` header.
///
/// A browser sends one cookie per (name, domain, path), so a console request
/// legitimately carries one — two at the very most, while a `Domain`-scoped
/// cookie is being replaced. Beyond a handful, the header is somebody's
/// experiment rather than a browser's, and each extra candidate is another walk
/// of the session store. Candidates past this many are ignored rather than the
/// request refused, so a neighbour cannot lock the console out by planting nine
/// of them.
const MAX_SESSION_COOKIES: usize = 8;

/// Extracts every session-id candidate from a request's `Cookie` header.
///
/// # Why every pair, and not the first
///
/// A browser sends every cookie for the host in one header, `name=value` pairs
/// separated by semicolons, and **cookie scope is not origin scope**. This box's
/// whole purpose is hosting several sites through one proxy, so any site under
/// the same registrable domain can set `selfhost_session=…; Domain=<parent>`,
/// which the browser will then also send to the console host — in whatever order
/// it likes. Taking the first pair meant a neighbouring site could plant a value
/// that sorted first and silently hide the operator's real session: not an
/// authentication bypass, because the planted value names nothing, but a
/// persistent, remotely-triggered lockout of the console.
///
/// The alternative considered was refusing a request that carries more than one
/// such pair outright. That is simpler and it is the wrong choice here, because
/// it leaves the neighbour holding exactly the same lockout: the planted cookie
/// is sent on every request, so every request would be refused. Trying each
/// candidate costs a walk of a store that holds at most 32 entries, compares in
/// constant time either way, and turns the attack into nothing at all — a value
/// that names no session simply names no session.
///
/// The list is bounded by [`MAX_SESSION_COOKIES`] so that the cost stays a
/// handful of walks rather than one per cookie an attacker can fit in a header.
fn session_cookies(request: &Request) -> Vec<String> {
    let Some(header) = request.headers.get_str("cookie") else {
        return Vec::new();
    };
    header
        .split(';')
        .filter_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            (name.trim() == SESSION_COOKIE).then(|| value.trim().to_owned())
        })
        .take(MAX_SESSION_COOKIES)
        .collect()
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

    // The one branch that does not end in a response. Taken only when the path
    // names a stream *and* the head is shaped like a handshake: a plain `GET
    // /api/events` falls through and gets the same "no such endpoint" 404 as any
    // other unmatched route, which is what it should look like to anyone who is
    // not opening a stream.
    let stream_route = Ability::for_path(request.path())
        .filter(|_| selfhost_ws::handshake::looks_like_upgrade(&request));
    if let Some(route) = stream_route {
        // Everything past the head belongs to the new protocol, not to a body.
        // See `stream::Prefixed` for what happens if it is dropped here.
        let leftover = buffer.split_off(consumed);
        return serve_stream(stream, leftover, api, request, route).await;
    }

    let body = match read_body(&mut stream, &request, &mut buffer, consumed).await {
        Ok(body) => body,
        Err(response) => return write_response(&mut stream, &response).await,
    };

    let response = api.handle(&request, &body).await;
    write_response(&mut stream, &response).await
}

/// Decides an upgrade, answers it, and hands the connection to the stream that
/// asked for it.
///
/// The whole of the socket layer's part in a stream. The decision is
/// [`Api::upgrade_for`], which is pure and tested without a port; the hand-over
/// is [`stream::Prefixed`], which carries the bytes that arrived alongside the
/// head so the first message is not eaten; and the loop is [`stream::events`].
///
/// A refusal is the same uninformative 401 every other unauthorised request
/// gets, byte for byte. The reason is written to the daemon's log, where an
/// operator debugging a console that will not connect can read it and a stranger
/// cannot — and it is written for a refusal only, never for a success, so the
/// log does not fill with a line per reconnect.
async fn serve_stream(
    mut stream: TcpStream,
    leftover: Vec<u8>,
    api: Api,
    request: Request,
    route: Ability,
) -> std::io::Result<()> {
    let admission = match api.upgrade_for(&request, route) {
        Ok(admission) => admission,
        Err(denial) => {
            eprintln!("admin: refused a stream on {}: {denial}", request.path());
            return write_response(&mut stream, &problem(Status(401), "authorisation required"))
                .await;
        }
    };

    stream::answer(&mut stream, &admission).await?;
    println!(
        "admin: stream open on {path} for {who}",
        path = request.path(),
        who = Api::stream_identity(&admission),
    );

    let outcome = match route {
        Ability::Events => {
            stream::events(
                stream::Prefixed::new(leftover, stream),
                api,
                admission,
                stream::Watch::default(),
            )
            .await
        }
    };
    match outcome {
        Ok(reason) => println!("admin: stream on {} ended: {reason}", request.path()),
        // A transport that simply went away is a fact about a console on a
        // laptop, not a fault: a closing tab drops its socket often enough that
        // the answering close frame finds nothing to write to. Reporting that at
        // the same weight as a protocol violation is how a log stops being read,
        // so only the genuine failures reach stderr.
        Err(error) if is_departure(&error) => {
            println!("admin: stream on {} ended: {error}", request.path());
        }
        Err(error) => eprintln!("admin: stream on {} failed: {error}", request.path()),
    }
    Ok(())
}

/// Whether a stream's error is simply the peer having gone.
fn is_departure(error: &selfhost_ws::StreamError) -> bool {
    match error {
        selfhost_ws::StreamError::Io(io) => matches!(
            io.kind(),
            std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::UnexpectedEof
        ),
        selfhost_ws::StreamError::Protocol(_) => false,
    }
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
