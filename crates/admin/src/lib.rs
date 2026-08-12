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
//! tested directly. [`serve`] is the thin part that owns the listener, and the
//! handful of routes that stop being HTTP go through [`stream::Upgraded`], which
//! is the only thing in this crate that writes a `101`.
//!
//! One of those routes is unlike every other in this file and is worth knowing
//! about before reading it. `GET /api/mesh/link` is answered **before** its
//! caller has proved anything: a worker dialling its owner presents no cookie
//! and no ticket, because what it can prove is an HMAC over the very handshake
//! being answered, and that does not exist until the handshake does. The `101`
//! there is the start of the conversation in which the caller proves who they
//! are, the next frame decides it, and what an unproved caller can cost this
//! daemon is bounded by [`mesh_api::MAX_PENDING_LINKS`] and a greeting timeout.
//! See [`mesh_api`].

#![warn(missing_docs)]

pub mod audit_api;
pub mod dav_api;
pub mod desk_api;
pub mod invite;
pub mod mesh_api;
pub mod passwd;
pub mod people_api;
pub mod session;
pub mod storage_api;
pub mod store;
pub mod stream;
pub mod token;
pub mod upgrade;
pub mod webauthn;

use selfhost_firewall::Manager;
use selfhost_git::{Nudge, Watches};
use selfhost_http::{Body, Method, Request, Response, Status};
use selfhost_identity::{Caller, Capability, Opening, People, PersonName, Policy};

/// What a deployment with no permission registry answers on every people route.
///
/// One sentence in one place, because four routes give it and a caller
/// distinguishing them by wording would be reading a difference that is not
/// there.
const NO_REGISTRY: &str =
    "this daemon holds no permission registry, so it can neither name people nor grant them \
     anything; it was built without one";
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
pub use dav_api::Webdav;
pub use desk_api::{AgentReport, Fleet, Handover, NodeReport, Standings};
pub use mesh_api::Peerage;
pub use storage_api::Volumes;
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
    /// The signal that asks the self-update watcher to check its branch now.
    ///
    /// `None` on a deployment with no `[self_update]` section, and `None` makes
    /// `POST /api/self-update/deploy` answer exactly as a route this build does
    /// not serve — a caller learns whether self-update is configured only if
    /// they were already authorised to control services.
    self_update: Option<Nudge>,
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
    /// The outstanding invitations: one-time codes that let somebody who is not
    /// the owner register a passkey under a name the owner chose.
    ///
    /// `None` until a data directory has been named, and `None` closes the
    /// invite door completely rather than opening it unguarded — the redemption
    /// routes answer as though the path were not served, which is the honest
    /// report for a deployment that has invited nobody. See [`invite`].
    invites: Option<invite::Invites>,
    /// The shares this daemon serves, opened once at startup.
    ///
    /// `None` when no `[[shares]]` block was declared, and `None` is not a
    /// special case anywhere below: with no shares every storage route answers
    /// the same uninformative 401 an unauthenticated caller gets, which is
    /// exactly what a deployment that serves no files should look like from the
    /// outside.
    storage: Option<Volumes>,
    /// The remote-desktop subsystem, if the daemon wired one.
    ///
    /// `None`, or present with `[desktop].enabled = false`, both mean the same
    /// thing on the wire: there is no desktop here. The dangerous half of this
    /// repository is off unless somebody turned it on in a file and restarted
    /// the daemon, which is the only place it can be turned on.
    desktop: Option<desk_api::Wiring>,
    /// The WebDAV credential cache and lock table, shared by every clone.
    ///
    /// `None` only if the system random source refused to seed the cache key at
    /// start-up, and `None` closes `/dav` entirely rather than opening it
    /// without a cache. That is the safe direction twice over: a cache keyed on
    /// a constant would be a fingerprint table an attacker could build offline,
    /// and a `/dav` endpoint with no cache at all would spend 70 ms of PBKDF2 on
    /// every one of Finder's five hundred requests — thirty-five seconds of a
    /// core, on the first mount, before anybody has copied anything.
    ///
    /// Wired in [`Api::new`] rather than by a builder call, because WebDAV is
    /// not a subsystem an operator switches on: it is a second protocol onto the
    /// shares that are already declared, and a deployment with no `[[shares]]`
    /// and no console password serves nothing over it either way.
    webdav: Option<Arc<Webdav>>,
    /// The append-only record of every control action, for reading back.
    ///
    /// `None` until a data directory has been named, and `None` answers the
    /// audit route with an empty trail rather than an error: a deployment with
    /// no data directory has never written a line, and the honest report of
    /// nothing recorded is nothing, not a fault.
    ///
    /// This crate only ever **reads** it. The writers are the subsystems that
    /// perform the actions — `crates/cli`'s input sink writes one line per
    /// message, and it is the daemon rather than the CLI that records the kill
    /// switch, so that a switch created by `touch`, by Finder or over SMB is
    /// recorded identically and never twice.
    audit: Option<selfhost_identity::AuditLog>,
    /// The machines this owner has invited, and the links they are holding.
    ///
    /// `None` when the daemon wired no peerage, and `None` makes
    /// `GET /api/mesh/link` answer exactly what a path this deployment does not
    /// serve answers — which is what a box with no workers should look like from
    /// outside. A worker's dial is otherwise the one upgrade on this API whose
    /// credential arrives *after* the `101`; see [`mesh_api`].
    peers: Option<Peerage>,
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
    /// The console site's canonical origin — `https://<first declared domain>`
    /// — computed from configuration and never from a request.
    ///
    /// The same string, from the same source and for the same reason, as the
    /// WebAuthn relying-party origin: the proxy's relay forwards no `Host`, and
    /// an identity the client could choose would defeat the comparison
    /// entirely. Used where exactly one hostname is meaningful — the WebAuthn
    /// relying-party id, the WebDAV `Destination` host check, and the one link
    /// an invitation hands out. **Not** what an upgrade's `Origin` is checked
    /// against; see `stream_origins` below.
    origin: Option<String>,
    /// Every origin a browser's `Origin` header may equal on a stream upgrade —
    /// `https://<domain>[:<port>]` for each of the console site's declared
    /// `domains`, at the daemon's real `https_bind` port (omitted when it is
    /// the browser-default 443). Computed from configuration and never from a
    /// request, same as `origin`.
    ///
    /// A site legitimately answers to more than one hostname — a LAN IP beside
    /// a public domain, `localhost` beside both — and a dev or LAN deployment
    /// legitimately runs `https_bind` on something other than 443. Collapsing
    /// the check to `origin` alone (one hostname, port always assumed 443)
    /// refused every stream — the live-events feed and the desktop screen
    /// share alike — on any deployment shaped that way; only the VPN-tunnelled
    /// production path (one domain, always :443) ever happened to satisfy it.
    /// Empty means no console site is configured, and a browser is then
    /// refused a stream rather than admitted unchecked — see
    /// [`upgrade::origin_permitted`].
    stream_origins: Vec<String>,
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
    /// Anyone the wall already admitted, holding anything or nothing.
    ///
    /// Exactly one route asks this: `GET /api/whoami`. A permission-shaped
    /// interface cannot exist until a client can ask what the person in front of
    /// it may do, and a person who holds nothing must get an honest empty answer
    /// rather than the uniform `401` — otherwise "you were refused" and "you
    /// hold nothing yet" are the same event to the only program that could
    /// explain the difference. It discloses nothing the caller does not already
    /// have: their own name, their own credential kind, their own capabilities.
    Authenticated,
    /// Nobody, ever.
    ///
    /// The demand of a route whose target could not name anything this
    /// deployment serves — a share id that is not a legal share id, a node name
    /// that is not a legal node name. It refuses with the API's ordinary 401
    /// rather than a `404`, which is the point: a refusal that distinguished
    /// *no such share* from *not yours* would be a way to enumerate what sits
    /// behind the wall, one guess at a time.
    Unsatisfiable,
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
    /// `POST /api/self-update/deploy`
    SelfUpdateNow,
    /// `POST /api/services/<name>/<action>`
    Act(&'a str, &'a str),
    /// `POST /api/desktop/ticket`
    MintTicket,
    /// `GET /api/desktop`
    DesktopSettings,
    /// `GET /api/desktop/nodes`
    DesktopNodes,
    /// `GET /api/desktop/agent?peer=<node>`
    DesktopAgent,
    /// `GET /api/audit?limit=<n>`
    AuditTrail,
    /// `GET /api/storage/shares`
    Shares,
    /// `GET /api/storage/shares/<id>/list?path=…`
    ShareList(&'a str),
    /// `GET /api/storage/shares/<id>/stat?path=…`
    ShareStat(&'a str),
    /// `POST /api/storage/shares/<id>/mkdir`
    ShareMkdir(&'a str),
    /// `POST /api/storage/shares/<id>/rename`
    ShareRename(&'a str),
    /// `DELETE /api/storage/shares/<id>/entry?path=…`
    ShareDelete(&'a str),
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
    /// `GET /api/whoami`
    WhoAmI,
    /// `GET /api/people`
    ListPeople,
    /// `GET /api/people/capabilities`
    Vocabulary,
    /// `PUT /api/people/<name>`
    SetGrants(&'a str),
    /// `DELETE /api/people/<name>`
    ForgetPerson(&'a str),
    /// `POST /api/people/<name>/invite`
    MintInvite(&'a str),
    /// `GET /api/people/invites`
    ListInvites,
    /// `DELETE /api/people/invites/<name>`
    RevokeInvite(&'a str),
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
            // The same "a push landed" signal as `DeployNow`, aimed at this
            // deployment's own repository rather than a service's. Not under
            // `/api/services/` because selfhost is not in the service
            // catalogue: it is the thing running the catalogue.
            (Method::Post, ["api", "self-update", "deploy"]) => Some(Self::SelfUpdateNow),
            // The stream mint. A non-`GET`, so the CSRF header was already
            // demanded of a cookie caller by `authorised()` — by code that
            // predates streams and is not changed by them. That is the whole
            // trick: a handshake is a `GET` and cannot carry a custom header, so
            // the moment that *can* be protected is moved here and the handshake
            // is made to carry proof that it happened. See [`crate::upgrade`].
            (Method::Post, ["api", "desktop", "ticket"]) => Some(Self::MintTicket),
            (Method::Get, ["api", "desktop"]) => Some(Self::DesktopSettings),
            (Method::Get, ["api", "desktop", "nodes"]) => Some(Self::DesktopNodes),
            (Method::Get, ["api", "desktop", "agent"]) => Some(Self::DesktopAgent),
            // The trail of what the dangerous capabilities did. A `GET`, and
            // owner-only: see `Route::demand`.
            (Method::Get, ["api", "audit"]) => Some(Self::AuditTrail),
            (Method::Get, ["api", "storage", "shares"]) => Some(Self::Shares),
            (Method::Get, ["api", "storage", "shares", id, "list"]) => Some(Self::ShareList(id)),
            (Method::Get, ["api", "storage", "shares", id, "stat"]) => Some(Self::ShareStat(id)),
            (Method::Post, ["api", "storage", "shares", id, "mkdir"]) => Some(Self::ShareMkdir(id)),
            (Method::Post, ["api", "storage", "shares", id, "rename"]) => {
                Some(Self::ShareRename(id))
            }
            (Method::Delete, ["api", "storage", "shares", id, "entry"]) => {
                Some(Self::ShareDelete(id))
            }
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
            // What the caller is, answered to the caller themselves. See
            // `Demand::Authenticated` for why this one is not owner-only.
            (Method::Get, ["api", "whoami"]) => Some(Self::WhoAmI),
            // Matched ahead of the per-person routes below: "capabilities" is
            // the vocabulary, not somebody called `capabilities`. It cannot
            // collide in practice either way — a person's name is validated by
            // `PersonName` and the owner's name is refused — but the order is
            // the guarantee rather than the argument.
            (Method::Get, ["api", "people", "capabilities"]) => Some(Self::Vocabulary),
            // Matched ahead of the per-person routes for the same reason
            // "capabilities" is: "invites" is the pending list, never somebody
            // called `invites`. The four-segment forms below cannot collide with
            // the three-segment ones either way.
            (Method::Get, ["api", "people", "invites"]) => Some(Self::ListInvites),
            (Method::Delete, ["api", "people", "invites", name]) => Some(Self::RevokeInvite(name)),
            (Method::Post, ["api", "people", name, "invite"]) => Some(Self::MintInvite(name)),
            (Method::Get, ["api", "people"]) => Some(Self::ListPeople),
            (Method::Put, ["api", "people", name]) => Some(Self::SetGrants(name)),
            (Method::Delete, ["api", "people", name]) => Some(Self::ForgetPerson(name)),
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
            | Self::MintTicket
            | Self::DesktopSettings
            | Self::DesktopNodes
            | Self::Shares => Demand::Held(Capability::ConsoleRead),
            // Per-node and per-share, so the target has to be a name the
            // vocabulary can hold. One that is not names nothing this
            // deployment serves, and refusing it as though it were somebody
            // else's is what keeps the two indistinguishable.
            Self::DesktopAgent => Demand::Held(Capability::ConsoleRead),
            Self::ShareList(id) | Self::ShareStat(id) => {
                storage_api::demand(id, storage_api::Wants::Read)
            }
            Self::ShareMkdir(id) | Self::ShareRename(id) | Self::ShareDelete(id) => {
                storage_api::demand(id, storage_api::Wants::Write)
            }
            Self::Install(_)
            | Self::Uninstall(_)
            | Self::DeployNow(_)
            | Self::SelfUpdateNow
            | Self::Act(_, _)
            | Self::FirewallReconcile => Demand::Held(Capability::ServiceControl),
            // Owner-only, with the passkey routes and for a related reason.
            // The trail names every person who has driven a machine and what
            // they did with it; reading it is not one of the powers a grant
            // confers, and there is no capability that honestly describes
            // "may read the record of everyone else". A person who could be
            // granted it could watch the record of their own supervision.
            Self::AuditTrail
            | Self::RegisterChallenge
            | Self::Register
            | Self::ListPasskeys
            | Self::RemovePasskey(_) => Demand::OwnerOnly,
            // Writing the permission registry is minting authority, exactly as
            // registering a passkey is: a grant is a power somebody will hold
            // until it is taken away, and the vocabulary has no word for "may
            // grant" because no grant should ever confer it. So these ask for
            // the identity that cannot be delegated. Reading the roster joins
            // them because it is a list of who can reach what — a target list,
            // as `crates/identity`'s registry says in its own header.
            Self::ListPeople | Self::SetGrants(_) | Self::ForgetPerson(_) => Demand::OwnerOnly,
            // Minting an invitation is the most concentrated form of the same
            // act: it does not merely write down a power, it creates the means
            // by which somebody will prove they are the person who holds it. If
            // writing the registry is owner-only then handing out the way in
            // must be, and by the same argument — the vocabulary has no word for
            // "may create authority", because no grant should ever confer it.
            // Reading and withdrawing the pending list join them because that
            // list, like the roster, is a list of who is about to be able to
            // reach this machine.
            Self::MintInvite(_) | Self::ListInvites | Self::RevokeInvite(_) => Demand::OwnerOnly,
            // The vocabulary is a constant of the build, not a fact about this
            // deployment: it names the words that exist, never who holds one.
            // A client needs it to render a grant editor at all.
            Self::Vocabulary | Self::WhoAmI => Demand::Authenticated,
        }
    }
}

/// The paths that stop being HTTP, and what each of them becomes.
///
/// [`Route`] covers everything [`Api::handle`] answers with a response;
/// this covers the handful that answer with a `101` and then a connection. One
/// vocabulary rather than a check per route, so that "which paths are streams"
/// is asked once, in one place, and a path that is not in this list cannot
/// accidentally be upgraded by a route that forgot to ask.
///
/// The split inside it is the one that matters. A console stream is authorised
/// **before** the handshake is answered, by a single-use ticket minted at a
/// CSRF-protected `POST` — that is [`Ability`], and it is a closed vocabulary
/// precisely so a ticket cannot authorise a string a later version invents. A
/// peer link cannot be: a worker is a daemon with no session and no ticket, and
/// what it can prove is an HMAC **over this very handshake**, which does not
/// exist until the handshake does. Modelling the second as an `Ability` would
/// have meant either a ticket nobody can mint or an ability nobody checks; it is
/// its own variant instead, and [`mesh_api`] owns the credential that follows.
#[derive(Debug, Clone, PartialEq, Eq)]
enum StreamRoute {
    /// A console stream, carrying the minimum ability its URL asks for.
    Console(Ability),
    /// `GET /api/mesh/link` — a worker dialling its owner.
    PeerLink,
}

impl StreamRoute {
    /// The stream route reached at `target`, if any.
    ///
    /// The peer link is matched first and on the path alone. It takes no query
    /// string, carries no ticket, and names no node in its URL — the node is
    /// named in the greeting and *proved* there, which is the only place a name
    /// on this route means anything.
    fn for_target(target: &str) -> Option<Self> {
        if split_target(target).0 == mesh_api::LINK_PATH {
            return Some(Self::PeerLink);
        }
        Ability::for_target(target).map(Self::Console)
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
            self_update: None,
            console: None,
            tickets: Tickets::new(),
            streams: Streams::new(),
            policy: Policy::locked_down(),
            people: None,
            invites: None,
            storage: None,
            desktop: None,
            webdav: Webdav::new().ok().map(Arc::new),
            audit: None,
            peers: None,
        }
    }

    /// Records the machines this owner has invited, and opens the link route.
    ///
    /// Built by the caller ([`Peerage::for_owner`]) rather than here, for the
    /// reason [`Api::with_storage`] is: the registry it carries is the *same*
    /// value the daemon's node picker and `doctor` read, and an `Api` that built
    /// its own would be a second belief about which machines are up.
    ///
    /// Without this call `GET /api/mesh/link` is indistinguishable from a path
    /// this deployment does not serve, which is the honest report for a box that
    /// has no workers.
    pub fn with_peers(mut self, peers: Peerage) -> Self {
        self.peers = Some(peers);
        self
    }

    /// Opens `POST /api/self-update/deploy` onto the daemon's own update watcher.
    ///
    /// Takes the *same* [`Nudge`] the watcher is waiting on, for the reason
    /// [`Api::with_peers`] takes an already-built `Peerage`: an `Api` that made
    /// its own would be poking a signal nothing listens to, which fails by
    /// answering `202` and doing nothing — the silent failure this whole path
    /// exists to avoid.
    ///
    /// Without this call the route is indistinguishable from one this build
    /// does not serve, which is the honest report for a deployment with no
    /// `[self_update]` section.
    pub fn with_self_update(mut self, nudge: Nudge) -> Self {
        self.self_update = Some(nudge);
        self
    }

    /// The machines this owner has invited, if the daemon wired any.
    ///
    /// The daemon reaches through this to splice a desktop session onto a peer's
    /// link ([`Peerage::link`]) and to draw the node picker
    /// ([`Peerage::registry`]), so the route that admits a link and the panel
    /// that reports it cannot disagree.
    pub fn peers(&self) -> Option<&Peerage> {
        self.peers.as_ref()
    }

    /// Records the shares this daemon serves.
    ///
    /// Opened by the caller ([`Volumes::open`]) rather than here, because a
    /// share whose root is missing or is rooted somewhere the deployment
    /// protects must stop the daemon with a message at startup rather than
    /// produce an `Api` that answers 500 to one route.
    pub fn with_storage(mut self, volumes: Volumes) -> Self {
        self.storage = Some(volumes);
        self
    }

    /// Records the remote-desktop subsystem and the hardware behind it.
    ///
    /// `config` is `[desktop]` verbatim and `fleet` is the daemon's own screens,
    /// pointers and peer links. The two arrive together because neither is any
    /// use alone: settings with nothing to drive answer questions about a
    /// machine that cannot be reached, and hardware with no settings would be
    /// hardware nobody armed.
    pub fn with_desktop(mut self, config: selfhost_config::Desktop, fleet: Arc<dyn Fleet>) -> Self {
        self.desktop = Some(desk_api::Wiring::new(config, fleet));
        self
    }

    /// Enables cookie-session login, loading the password hash, the people
    /// registry and the audit log from `dir`.
    ///
    /// The wiring seam for the daemon: called once, right after [`Api::new`],
    /// with the daemon's data directory. A missing password file still enables
    /// the session routes — they just refuse every login until
    /// `selfhost console-password` writes one.
    ///
    /// The audit log is wired here rather than through its own call because it
    /// is the third thing that lives in the data directory and there is nothing
    /// to decide about it: `<data_dir>/audit.log` is where
    /// [`AuditLog::in_dir`](selfhost_identity::AuditLog::in_dir) puts it, the
    /// daemon writes it there, and a console that could not read it back would
    /// leave the operator grepping the box for the record of a keyboard.
    ///
    /// The registry is persisted through this crate's own
    /// [`token::write_private`], which is the one implementation in this
    /// workspace that builds an explicit owner-only DACL on Windows rather than
    /// inheriting the parent directory's. `selfhost-identity` cannot do that for
    /// itself — it forbids `unsafe` and sits below this crate — so the writer is
    /// injected here, at the one place that already owns it.
    pub fn with_console_auth(self, dir: &Path) -> Self {
        self.with_console_auth_parts(ConsolePassword::load(dir), Sessions::new())
            .with_people(people_registry(dir))
            .with_invites(invite::Invites::load(dir))
            .with_audit(selfhost_identity::AuditLog::in_dir(dir))
    }

    /// Records the invitation store the invite door reads and the owner's mint
    /// route writes.
    ///
    /// Wired from the data directory alongside the people registry, because an
    /// invitation and the grant set it will eventually be paired with are two
    /// halves of one act and there is nothing to decide about where either
    /// lives. Separate from [`Api::with_console_auth`] on the same grounds as
    /// [`Api::with_people`]: so a test can hand in a scratch store.
    ///
    /// Absent, every invite route answers `404` — a deployment that has invited
    /// nobody should not advertise a door.
    pub fn with_invites(mut self, invites: invite::Invites) -> Self {
        self.invites = Some(invites);
        self
    }

    /// Records the audit log this API reads the trail back out of.
    ///
    /// Separate from [`Api::with_console_auth`] so a test can point the route at
    /// a log it wrote itself, and so a deployment with no console password can
    /// still have its actions readable.
    pub fn with_audit(mut self, log: selfhost_identity::AuditLog) -> Self {
        self.audit = Some(log);
        self
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
            stream_origins: Vec::new(),
        });
        self
    }

    /// Records the console site's canonical hostname, which fixes the origin
    /// the WebAuthn ceremony, the WebDAV host check and invitation links use,
    /// and — until/unless [`Api::with_console_stream_origins`] broadens it —
    /// the only `Origin` a stream upgrade may present.
    ///
    /// Separate from [`Api::with_console_webauthn`] so a deployment can have a
    /// console site without passkeys and still get the origin check — but
    /// `with_console_webauthn` calls this itself, because it already receives
    /// the same hostname for the same reason and a second wiring point is a
    /// second thing to forget. Forgetting it fails closed: with no origin
    /// recorded, a browser cannot open a stream at all.
    pub fn with_console_origin(mut self, host: &str) -> Self {
        if let Some(console) = &mut self.console {
            let origin = format!("https://{host}");
            console.stream_origins = vec![origin.clone()];
            console.origin = Some(origin);
        }
        self
    }

    /// Broadens the set of `Origin`s a stream upgrade (`/api/events`,
    /// `/api/desktop/session`) may present, to every hostname the console site
    /// declares, at the daemon's real `https_bind` port.
    ///
    /// Layered on top of [`Api::with_console_origin`] rather than replacing
    /// it: the WebAuthn relying-party id, the WebDAV `Destination` host check
    /// and the one link an invitation hands out each want exactly one
    /// hostname, so they keep using `console.origin` — the site's first
    /// declared domain — unchanged. This call only ever grows the set an
    /// upgrade's `Origin` may equal; a caller that skips it keeps today's
    /// single-domain, port-443 behaviour.
    ///
    /// A site legitimately answers to more than one hostname — a LAN IP
    /// beside a public domain, `localhost` beside both — and a dev or LAN
    /// deployment legitimately runs `https_bind` on something other than 443.
    /// Before this existed, every stream — the live-events feed and the
    /// desktop screen share alike — was refused on any deployment shaped that
    /// way; only the VPN-tunnelled production path (one domain, always :443)
    /// ever happened to satisfy the single-origin check.
    pub fn with_console_stream_origins(mut self, domains: &[String], port: u16) -> Self {
        if let Some(console) = &mut self.console {
            console.stream_origins = domains
                .iter()
                .map(|domain| match port {
                    443 => format!("https://{domain}"),
                    _ => format!("https://{domain}:{port}"),
                })
                .collect();
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

        // The invite door sits ahead of the wall by necessity rather than by
        // analogy: everything else out here is how an *owner* gets authorised,
        // and this is how somebody who has never had a credential gets their
        // first one. What stands in for a session is the one-time code — checked
        // against the store on both halves, feeding the same failure gate the
        // login doors share, and carrying the same CSRF header for the same
        // reason `POST /api/session` does. See [`invite`].
        if path == "/api/invite/challenge" || path == "/api/invite/register" {
            if request.method != Method::Post {
                return problem(Status(404), "no such endpoint");
            }
            if !has_console_header(request) {
                return problem(Status(401), "authorisation required");
            }
            return if path == "/api/invite/register" {
                self.invite_register(body)
            } else {
                self.invite_challenge(body)
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

        // WebDAV sits ahead of the wall because it has a door of its own, and it
        // has to: a Finder or a Windows mount speaks HTTP authentication or
        // nothing — no login form, no cookie, no bearer header it could be
        // taught. So `/dav` authenticates with Basic over TLS against the same
        // console password, through the verified-credential cache that is the
        // difference between a mount and thirty-five seconds of PBKDF2. See
        // [`dav_api`] for why the cookie and the token are deliberately refused
        // there, and for why a refusal *after* authentication is never a 401.
        if dav_api::is_dav_path(path) {
            return self.dav(request, body).await;
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
            Route::SelfUpdateNow => self.self_update_now(),
            Route::Act(name, action) => self.act(name, action).await,
            Route::MintTicket => self.mint_ticket(request, &caller, body),
            Route::DesktopSettings => self.desktop_settings(),
            Route::DesktopNodes => self.desktop_nodes(&caller),
            Route::DesktopAgent => self.desktop_agent(&caller, query),
            Route::AuditTrail => self.audit_trail(query),
            Route::Shares => self.shares(&caller).await,
            Route::ShareList(id) => self.share_list(id, &caller, query).await,
            Route::ShareStat(id) => self.share_stat(id, &caller, query).await,
            Route::ShareMkdir(id) => self.share_mkdir(id, &caller, body).await,
            Route::ShareRename(id) => self.share_rename(id, &caller, body).await,
            Route::ShareDelete(id) => self.share_delete(id, &caller, query).await,
            Route::FirewallState => self.firewall_state().await,
            Route::FirewallReconcile => self.firewall_reconcile().await,
            Route::RegisterChallenge => self.webauthn_register_challenge(),
            Route::Register => self.webauthn_register(body),
            Route::ListPasskeys => self.webauthn_list(),
            Route::RemovePasskey(id) => self.webauthn_remove(id),
            Route::WhoAmI => json(Status(200), people_api::whoami_json(&caller)),
            Route::Vocabulary => json(Status(200), people_api::vocabulary_json()),
            Route::ListPeople => self.list_people(),
            Route::SetGrants(name) => self.set_grants(name, body),
            Route::ForgetPerson(name) => self.forget_person(name),
            Route::MintInvite(name) => self.mint_invite(name, body),
            Route::ListInvites => self.list_invites(),
            Route::RevokeInvite(name) => self.revoke_invite(name),
        }
    }

    /// The permission registry, or the sentence explaining that there is none.
    ///
    /// A deployment whose daemon was built without [`Api::with_people`] has no
    /// registry to read, and that is a `404` naming the cause rather than an
    /// empty roster: "nobody is registered" and "this daemon cannot register
    /// anybody" are different facts and only one of them is a configuration a
    /// person can act on.
    fn list_people(&self) -> Response {
        match &self.people {
            Some(people) => json(Status(200), people_api::roster_json(people)),
            None => problem(Status(404), NO_REGISTRY),
        }
    }

    /// Replaces everything one person holds.
    ///
    /// Creates the entry if this is the first grant they have been given, which
    /// is what makes this route the way a second person comes to exist at all.
    /// Their name still has to be a name — [`PersonName`] refuses the owner's
    /// spelling in every casing, so no grant written here can touch the
    /// operator's own authority.
    fn set_grants(&self, name: &str, body: &[u8]) -> Response {
        let Some(people) = &self.people else {
            return problem(Status(404), NO_REGISTRY);
        };
        let Ok(person) = PersonName::parse(name) else {
            return problem(
                Status(400),
                "not a usable person name: lower-case letters, digits and dashes, and never \
                 the owner's own name",
            );
        };
        let grants = match people_api::grants_from_body(body) {
            Ok(grants) => grants,
            Err(refusal) => return problem(Status(400), &refusal.message()),
        };
        match people.set_grants(&person, grants) {
            Ok(()) => match people.find(&person) {
                Some(entry) => json(Status(200), people_api::person_json(&entry)),
                // The registry accepted the write and then could not find the
                // entry it had just made. Nothing sane produces this; saying so
                // is better than a 200 over a roster that disagrees with itself.
                None => problem(Status(500), "the registry accepted the change and lost it"),
            },
            Err(error) => problem(Status(500), &format!("could not save the registry: {error}")),
        }
    }

    /// Forgets a person entirely.
    fn forget_person(&self, name: &str) -> Response {
        let Some(people) = &self.people else {
            return problem(Status(404), NO_REGISTRY);
        };
        let Ok(person) = PersonName::parse(name) else {
            return problem(Status(400), "not a usable person name");
        };
        match people.remove(&person) {
            Ok(true) => json(Status(200), Json::object([("forgot", Json::string(name))])),
            Ok(false) => problem(Status(404), "nobody by that name holds anything here"),
            Err(error) => problem(Status(500), &format!("could not save the registry: {error}")),
        }
    }

    /// Mints a one-time invitation for `name` and returns the code once.
    ///
    /// The body may carry `{"hours": n}`; anything else, including no body at
    /// all, means [`invite::DEFAULT_TTL_HOURS`]. A malformed body is not an
    /// error here — the only field is an optional number with a safe default,
    /// and refusing an invitation over a stray byte would be a worse failure
    /// than quietly using the default the operator would have chosen anyway.
    ///
    /// The reply carries the code exactly once: it is not stored in a form this
    /// daemon can reproduce (see [`invite`]), so an owner who loses it mints
    /// another rather than looking the first one up.
    ///
    /// `holdsNothing` is reported alongside, because minting an invitation for
    /// somebody with no entry in the registry is legal, occasionally deliberate,
    /// and almost always a mistake — they would register a passkey, log in, and
    /// find a console with nothing on it. Saying so is cheaper than the support
    /// conversation.
    fn mint_invite(&self, name: &str, body: &[u8]) -> Response {
        let Some(invites) = &self.invites else {
            return problem(Status(404), NO_REGISTRY);
        };
        let Ok(person) = PersonName::parse(name) else {
            return problem(
                Status(400),
                "not a usable person name: lower-case letters, digits and dashes, and never \
                 the owner's own name",
            );
        };
        let hours = std::str::from_utf8(body)
            .ok()
            .and_then(|text| selfhost_json::parse(text).ok())
            .and_then(|document| document.get("hours").and_then(Json::as_u64))
            .unwrap_or(invite::DEFAULT_TTL_HOURS);

        let code = match invites.mint(&person, hours) {
            Ok(code) => code,
            Err(error) => {
                return problem(Status(500), &format!("could not save the invitation: {error}"));
            }
        };
        let expires = invites
            .outstanding()
            .into_iter()
            .find(|entry| entry.name == person)
            .map(|entry| entry.expires_unix)
            .unwrap_or(0);
        let holds_nothing = self
            .people
            .as_ref()
            .map(|people| people.find(&person).is_none_or(|entry| entry.grants.is_empty()))
            .unwrap_or(true);

        let mut fields = vec![
            ("name", Json::string(person.as_str())),
            ("code", Json::string(code.as_str())),
            ("expiresUnix", Json::Number(expires as f64)),
            ("holdsNothing", Json::Bool(holds_nothing)),
        ];
        // The one link an owner can send. Built from the console's own
        // configured origin, never from a request header, for the same reason
        // the WebAuthn relying party is: a hostname the caller could choose
        // would be a hostname the caller could point the invitation at.
        if let Some(origin) = self.console.as_ref().and_then(|console| console.origin.as_deref()) {
            fields.push(("url", Json::string(format!("{origin}/#invite={code}"))));
        }
        json(Status(200), Json::object(fields))
    }

    /// Who has an invitation pending, and until when. Never a code.
    fn list_invites(&self) -> Response {
        let Some(invites) = &self.invites else {
            return problem(Status(404), NO_REGISTRY);
        };
        let outstanding = invites.outstanding();
        json(
            Status(200),
            Json::object([
                (
                    "invites",
                    Json::array(outstanding.iter().map(|entry| {
                        Json::object([
                            ("name", Json::string(entry.name.as_str())),
                            ("issuedUnix", Json::Number(entry.issued_unix as f64)),
                            ("expiresUnix", Json::Number(entry.expires_unix as f64)),
                        ])
                    })),
                ),
                ("count", Json::Number(outstanding.len() as f64)),
            ]),
        )
    }

    /// Withdraws a pending invitation before anybody has used it.
    fn revoke_invite(&self, name: &str) -> Response {
        let Some(invites) = &self.invites else {
            return problem(Status(404), NO_REGISTRY);
        };
        let Ok(person) = PersonName::parse(name) else {
            return problem(Status(400), "not a usable person name");
        };
        match invites.revoke(&person) {
            Ok(true) => json(Status(200), Json::object([("withdrew", Json::string(name))])),
            Ok(false) => problem(Status(404), "nobody by that name has an invitation pending"),
            Err(error) => {
                problem(Status(500), &format!("could not save the invitations: {error}"))
            }
        }
    }

    /// The invite door's first half: a ceremony challenge, and the name the
    /// credential must be made under.
    ///
    /// Answers only to a code this deployment really minted. That is not
    /// avoidable secrecy — the browser has to be told which name to put in the
    /// passkey it is about to create, and that name must come from the
    /// invitation rather than from the person holding it — so the check is made
    /// safe by rate limiting instead: every refusal feeds the same
    /// [`FailureGate`] both login doors share, so guessing codes exhausts the
    /// same small budget as guessing passwords.
    fn invite_challenge(&self, body: &[u8]) -> Response {
        let (Some(console), Some(invites)) = (&self.console, &self.invites) else {
            return problem(Status(404), "no such endpoint");
        };
        let Some(webauthn) = &console.webauthn else {
            return problem(Status(404), "no such endpoint");
        };
        if console.gate.locked() {
            return problem(Status(429), "too many failed attempts; try again shortly");
        }
        let Some(name) = code_from_body(body).and_then(|code| invites.name_for(&code)) else {
            console.gate.record_failure();
            return problem(Status(401), "authorisation required");
        };
        match webauthn.invite_challenge(name.as_str()) {
            Ok(challenge) => json(Status(200), challenge),
            Err(error) => problem(Status(500), &format!("could not issue a challenge: {error}")),
        }
    }

    /// The invite door's second half: the credential itself.
    ///
    /// The name is taken from the invitation and handed to
    /// [`Webauthn::register_as`], so the body's own `user` field is discarded
    /// rather than trusted — the one thing that keeps a code minted for one
    /// person from producing a passkey for another. The invitation is spent only
    /// once the authenticator has really produced a credential; see
    /// [`invite::Invites::name_for`] for why that order and not the other.
    ///
    /// Success does not mint a session. The person has a credential now and logs
    /// in with it through the door that already exists, which keeps exactly one
    /// path in this crate that turns a passkey into a session.
    fn invite_register(&self, body: &[u8]) -> Response {
        let (Some(console), Some(invites)) = (&self.console, &self.invites) else {
            return problem(Status(404), "no such endpoint");
        };
        let Some(webauthn) = &console.webauthn else {
            return problem(Status(404), "no such endpoint");
        };
        if console.gate.locked() {
            return problem(Status(429), "too many failed attempts; try again shortly");
        }
        let Ok(text) = std::str::from_utf8(body) else {
            console.gate.record_failure();
            return problem(Status(401), "authorisation required");
        };
        let Ok(document) = selfhost_json::parse(text) else {
            console.gate.record_failure();
            return problem(Status(401), "authorisation required");
        };
        let Some(code) = document.get("code").and_then(Json::as_str) else {
            console.gate.record_failure();
            return problem(Status(401), "authorisation required");
        };
        let Some(name) = invites.name_for(code) else {
            console.gate.record_failure();
            return problem(Status(401), "authorisation required");
        };
        match webauthn.register_as(&document, webauthn::Purpose::Invite, Some(name.as_str())) {
            Ok(passkey) => {
                // Spent only now, with a credential really in existence.
                let _ = invites.redeem(code);
                console.gate.reset();
                json(
                    Status(200),
                    Json::object([
                        ("registered", Json::Bool(true)),
                        ("name", Json::string(name.as_str())),
                        ("label", Json::string(passkey.label)),
                    ]),
                )
            }
            Err(_) => {
                console.gate.record_failure();
                problem(Status(401), "authorisation required")
            }
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
        // Shared with `Standings`, deliberately: a request and a running
        // desktop stream must never form different opinions about the same
        // stored session.
        held.caller(self.people.as_ref())
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
            // The wall above already decided this, and reaching here proves it.
            Demand::Authenticated => true,
            Demand::Unsatisfiable => false,
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

    /// Every origin a stream upgrade's `Origin` header may equal.
    ///
    /// Empty when no console site is configured — the same fail-closed
    /// reading `console_origin` returning `None` gets. See
    /// [`Api::with_console_stream_origins`] for why this can hold more than
    /// one entry.
    fn console_stream_origins(&self) -> &[String] {
        self.console.as_ref().map_or(&[], |console| console.stream_origins.as_slice())
    }

    /// The console site's configured hostname, without the scheme.
    ///
    /// The value a WebDAV `Destination` header's authority is compared against.
    /// It comes from configuration and never from a request, for the same reason
    /// the passkey relying-party id does: the proxy's relay forwards no `Host`,
    /// so a host taken from the request would be the client's own claim, and a
    /// check against a value the attacker chose is not a check.
    fn console_host(&self) -> Option<&str> {
        self.console_origin()?.strip_prefix("https://")
    }

    /// Everything a WebDAV request is decided against, or `None` when nothing
    /// could ever open one.
    ///
    /// Three things must all be present: a console password to verify against, a
    /// credential cache to verify through, and shares to serve. Any one missing
    /// makes every `/dav` request the same `401` with a challenge — not a `404`
    /// — because a mount point that answered `404` on a box with no password and
    /// `401` on a box with one would be a way to read the deployment's
    /// configuration from outside it.
    pub fn dav_wiring(&self) -> Option<dav_api::Wiring<'_>> {
        Some(dav_api::Wiring {
            password: Arc::clone(&self.console.as_ref()?.password),
            webdav: Arc::clone(self.webdav.as_ref()?),
            volumes: self.storage.as_ref()?,
            policy: &self.policy,
            host: self.console_host(),
        })
    }

    /// Answers a WebDAV request on the document plane.
    ///
    /// The byte plane — `GET`, `HEAD` and `PUT` — is [`serve_dav`], which owns a
    /// connection; its *decision* still runs here, so every refusal it can make
    /// is reachable from this function and therefore from a test with no socket.
    async fn dav(&self, request: &Request, body: &[u8]) -> Response {
        match self.dav_wiring() {
            Some(wiring) => dav_api::answer(&wiring, request, body).await,
            None => dav_api::unauthenticated(),
        }
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
            return problem(
                Status(400),
                "body must be JSON with a \"want\" array of known abilities and, for a desktop, a \"peer\"",
            );
        };
        // A desktop ability on a deployment with no desktop is not a 404 here:
        // the mint is the one route that would otherwise answer *whether this
        // box has a screen* to anybody who can reach the console gate, which on
        // this deployment is every process on the machine.
        if abilities.iter().any(|ability| ability.node().is_some()) && self.desktop().is_none() {
            return problem(Status(401), "authorisation required");
        }
        for ability in &abilities {
            if !self.policy.decide(caller, &ability.capability()).is_allowed() {
                return problem(Status(401), "authorisation required");
            }
        }
        if let Some(refusal) = self.switched_off(&abilities) {
            return refusal;
        }
        if let Some(refusal) = self.stale_for_control(caller, &abilities) {
            return refusal;
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

    /// Refuses an ability the operator has switched off in `[desktop]`, or
    /// `None` when nothing asked for one.
    ///
    /// Two switches, and they are the outermost of the three gates on the
    /// dangerous half of this subsystem: `allow_input` and `allow_clipboard`
    /// both default to false, and neither is reachable from the console — only
    /// from a file on the box and a restart. A caller who passes
    /// [`Policy::decide`] for [`Capability::DesktopControl`] and is refused here
    /// is being told about the *deployment's* configuration, not about their own
    /// permissions.
    ///
    /// Legible for the reason [`Api::stale_for_control`] is: every value it
    /// discloses is one `GET /api/desktop` already returns to the same caller,
    /// and a console that could not distinguish "you may not" from "this box
    /// does not" would offer a keyboard that silently refuses every key.
    fn switched_off(&self, abilities: &[Ability]) -> Option<Response> {
        let wiring = self.desktop()?;
        let config = wiring.config();
        let refused = abilities.iter().find_map(|ability| match ability {
            Ability::DesktopControl(_) if !config.allow_input => {
                Some(("[desktop].allow_input", "this deployment does not allow input"))
            }
            Ability::ClipboardRead(_) if !config.allow_clipboard => Some((
                "[desktop].allow_clipboard",
                "this deployment does not share the clipboard",
            )),
            _ => None,
        })?;
        Some(json(
            Status(403),
            Json::object([
                ("error", Json::string(refused.1)),
                ("setting", Json::string(refused.0)),
            ]),
        ))
    }

    /// Refuses a control or clipboard ticket to a caller whose login is too old,
    /// or `None` when there is nothing to refuse.
    ///
    /// Both abilities are held to one standard because the thing they can take
    /// is the same thing: a keyboard types a password out of the operator, and a
    /// clipboard reads one the operator already copied. See
    /// [`Ability::needs_a_fresh_credential`].
    ///
    /// # Why this refusal is allowed to be legible
    ///
    /// Every other refusal in this file is the same uninformative 401, because
    /// telling a stranger *which* check they failed helps them pass it. This one
    /// is a `403` naming re-authentication, and that is deliberate: it is
    /// reachable only by a caller who has **already** satisfied
    /// [`Policy::decide`] for [`Capability::DesktopControl`] on that machine, so
    /// the only thing it discloses is a fact that caller already holds. The
    /// console needs it — the whole design is that clicking CONNECT prompts for
    /// the passkey — and a uniform 401 there would send the operator to a login
    /// page they are already past.
    fn stale_for_control(&self, caller: &Caller, abilities: &[Ability]) -> Option<Response> {
        if !abilities.iter().any(Ability::needs_a_fresh_credential) {
            return None;
        }
        let wiring = self.desktop()?;
        let fresh = desk_api::fresh_enough(
            caller,
            wiring.config().reauth_window(),
            std::time::Instant::now(),
        );
        (!fresh).then(|| {
            json(
                Status(403),
                Json::object([
                    ("error", Json::string("this login is too old to drive a machine")),
                    ("reauthenticate", Json::Bool(true)),
                    (
                        "withinSecs",
                        Json::Number(wiring.config().reauth_window_secs as f64),
                    ),
                ]),
            )
        })
    }

    /// Whether this request may move bytes to or from a share, and everything
    /// the transfer needs if it may.
    ///
    /// Pure, and for exactly the reason [`Api::upgrade_for`] is: it reads a
    /// request head, asks the capability model, and resolves the path with
    /// `selfhost_storage`'s own pure resolver. No descriptor is opened and no
    /// socket is touched, so every way of getting a bulk transfer's
    /// authorisation wrong is a unit test over a `Request`.
    ///
    /// The `PUT` path inherits the CSRF-header-before-store ordering for free,
    /// because it builds its caller with [`Api::caller`], which refuses a
    /// non-`GET` without [`CONSOLE_HEADER`] before the session store is
    /// consulted. A cross-site upload therefore cannot even refresh the
    /// operator's idle timer, let alone write a file.
    pub fn bulk_for(&self, request: &Request) -> Result<storage_api::Bulk, storage_api::Denied> {
        use storage_api::{Denied, Transfer};

        let (path, query) = split_target(&request.target);
        let (id, remainder) = storage_api::split_blob(path).ok_or(Denied::NoPath)?;

        let transfer = match request.method {
            Method::Get | Method::Head => {
                Transfer::Download(storage_api::requested_disposition(query))
            }
            Method::Put => Transfer::Upload {
                declared: storage_api::declared_length(request)?,
                existing: storage_api::requested_existing(query),
            },
            _ => return Err(Denied::WrongMethod),
        };

        let share = selfhost_identity::ShareId::parse(id).map_err(|_| Denied::Unauthorised)?;
        let want = match transfer {
            Transfer::Download(_) => Capability::FilesRead(share),
            Transfer::Upload { .. } => Capability::FilesWrite(share),
        };
        let caller = self.caller(request).ok_or(Denied::Unauthorised)?;
        if !self.policy.decide(&caller, &want).is_allowed() {
            return Err(Denied::Unauthorised);
        }

        let volume = self.volume(id).ok_or(Denied::NoShare)?;
        let at = volume.resolve(remainder).map_err(Denied::Refused)?;
        Ok(storage_api::Bulk {
            volume: Arc::clone(volume),
            at,
            who: caller.identity().clone(),
            transfer,
        })
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
                expected_origin: self.console_stream_origins(),
                tickets: &self.tickets,
                streams: &self.streams,
            },
            route,
        )
    }

    /// A closure asking the authorisation model one question about this caller.
    ///
    /// The routes that report a *set* — the shares a caller may open, the nodes
    /// they may watch — need to decide each item separately rather than refuse
    /// the whole route, in exactly the way [`Api::mint_ticket`] decides each
    /// requested ability. Handing them a closure rather than the `Policy` and
    /// the `Caller` keeps the decision in one place and keeps the storage and
    /// desktop modules from having to know what a `Policy` is.
    fn may<'a>(&'a self, caller: &'a Caller) -> impl Fn(&Capability) -> bool + Sync + 'a {
        move |capability| self.policy.decide(caller, capability).is_allowed()
    }

    /// The shares this daemon serves, if any were declared.
    pub fn storage(&self) -> Option<&Volumes> {
        self.storage.as_ref()
    }

    /// The desktop subsystem, but only while it is switched on.
    ///
    /// One accessor for both halves of "is there a desktop here", so a route
    /// cannot check the wiring and forget the switch. `[desktop].enabled =
    /// false` and no wiring at all are the same answer, which is what makes the
    /// two indistinguishable from outside.
    fn desktop(&self) -> Option<&desk_api::Wiring> {
        self.desktop.as_ref().filter(|wiring| wiring.enabled())
    }

    /// The volume named by a URL segment, for a caller who has already been
    /// decided against its capability.
    ///
    /// `None` here is a genuine 404 rather than a 401, and that is safe
    /// precisely because [`Route::demand`] ran first: a caller who does not hold
    /// `FilesRead` on this id never reaches this function, so the only people
    /// who can tell an unknown share from a known one are the ones who could
    /// list them anyway.
    fn volume(&self, id: &str) -> Option<&Arc<selfhost_storage::api::Volume>> {
        self.storage.as_ref()?.find(id)
    }

    /// Answers `GET /api/storage/shares`.
    ///
    /// A deployment with no `[[shares]]` block at all holds no `Volumes`, but
    /// `Route::Shares`'s own demand already proved this caller holds
    /// `ConsoleRead` before this method runs — the same floor every other
    /// panel needs. Answering that caller `401` here claimed their session
    /// had died, which sent an authenticated console straight back to the
    /// login screen (and, mid-desktop-session, closed the stream with it).
    /// [`storage_api::shares`]'s own contract is the honest one: the answer
    /// to "what may this caller open" is an empty list, not a refusal.
    async fn shares(&self, caller: &Caller) -> Response {
        let Some(volumes) = &self.storage else {
            return json(Status(200), Json::object([("shares", Json::array(std::iter::empty()))]));
        };
        storage_api::shares(volumes, caller.identity(), &self.may(caller)).await
    }

    /// Answers `GET /api/storage/shares/<id>/list?path=…`.
    async fn share_list(&self, id: &str, caller: &Caller, query: &str) -> Response {
        let Some(volume) = self.volume(id) else {
            return problem(Status(404), "no such share");
        };
        storage_api::list(volume, caller.identity(), query_value(query, "path").unwrap_or("")).await
    }

    /// Answers `GET /api/storage/shares/<id>/stat?path=…`.
    async fn share_stat(&self, id: &str, caller: &Caller, query: &str) -> Response {
        let Some(volume) = self.volume(id) else {
            return problem(Status(404), "no such share");
        };
        storage_api::stat(volume, caller.identity(), query_value(query, "path").unwrap_or("")).await
    }

    /// Answers `POST /api/storage/shares/<id>/mkdir`.
    async fn share_mkdir(&self, id: &str, caller: &Caller, body: &[u8]) -> Response {
        let Some(volume) = self.volume(id) else {
            return problem(Status(404), "no such share");
        };
        storage_api::mkdir(volume, caller.identity(), body).await
    }

    /// Answers `POST /api/storage/shares/<id>/rename`.
    ///
    /// The destination may name a different share, which is why the whole
    /// [`Volumes`] set and a capability closure both travel in: the destination
    /// share's read-only flag, its grants and the caller's capability *for it*
    /// are all the destination's to enforce, and a function given only a path
    /// would have checked the source's.
    async fn share_rename(&self, id: &str, caller: &Caller, body: &[u8]) -> Response {
        let (Some(volumes), Some(volume)) = (self.storage.as_ref(), self.volume(id)) else {
            return problem(Status(404), "no such share");
        };
        storage_api::rename(volumes, volume, caller.identity(), body, &self.may(caller)).await
    }

    /// Answers `DELETE /api/storage/shares/<id>/entry?path=…`.
    async fn share_delete(&self, id: &str, caller: &Caller, query: &str) -> Response {
        let Some(volume) = self.volume(id) else {
            return problem(Status(404), "no such share");
        };
        storage_api::delete(volume, caller.identity(), query_value(query, "path").unwrap_or(""))
            .await
    }

    /// Answers `GET /api/desktop`: the operator's own switches.
    fn desktop_settings(&self) -> Response {
        match self.desktop() {
            Some(wiring) => json(Status(200), desk_api::settings(wiring)),
            None => problem(Status(404), "this deployment serves no desktop"),
        }
    }

    /// Answers `GET /api/desktop/nodes`: the machines this caller may watch.
    ///
    /// Filtered per node against [`Capability::DesktopView`], the same way the
    /// share list is filtered: the route's own demand is a floor, and a caller
    /// who may watch nothing gets an empty list rather than a refusal. Absence
    /// is never the answer for a node that is *down* — that one is reported with
    /// its reason — but a node the caller may not watch is absent, because
    /// listing it would be an enumeration of the fleet.
    fn desktop_nodes(&self, caller: &Caller) -> Response {
        let Some(wiring) = self.desktop() else {
            return problem(Status(404), "this deployment serves no desktop");
        };
        let may = self.may(caller);
        let visible: Vec<Json> = wiring
            .nodes()
            .into_iter()
            .filter(|report| match selfhost_identity::NodeName::parse(&report.node) {
                Ok(node) => may(&Capability::DesktopView(node)),
                // A node whose declared name is not a legal node name cannot be
                // the target of a capability, so nobody can hold one for it.
                Err(_) => false,
            })
            .map(|report| report.to_json())
            .collect();
        json(Status(200), Json::object([("nodes", Json::array(visible))]))
    }

    /// Answers `GET /api/desktop/agent?peer=<node>`: what the capture agent on
    /// one machine is doing.
    ///
    /// Decided against [`Capability::DesktopView`] for *that* machine, and a
    /// caller without it gets the ordinary 401 — the same one an unparseable
    /// node name gets, so the route cannot be used to discover which machines
    /// exist.
    fn desktop_agent(&self, caller: &Caller, query: &str) -> Response {
        let Some(wiring) = self.desktop() else {
            return problem(Status(404), "this deployment serves no desktop");
        };
        let asked = query_value(query, "peer").unwrap_or(desk_api::LOCAL_NODE);
        let Ok(node) = selfhost_identity::NodeName::parse(asked) else {
            return problem(Status(401), "authorisation required");
        };
        if !self.may(caller)(&Capability::DesktopView(node.clone())) {
            return problem(Status(401), "authorisation required");
        }
        json(Status(200), wiring.agent(node.as_str()).to_json())
    }

    /// Answers `GET /api/audit?limit=<n>`: the tail of the control-action
    /// record, newest first.
    ///
    /// The reason this route exists is that an audit trail an operator cannot
    /// read is an audit trail nobody checks. `data/audit.log` is written for the
    /// capability that can type on the machine, and the person who needs it most
    /// is the one who has just seen their own pointer move — in a browser, not
    /// in a shell on the box.
    ///
    /// The read is bounded twice, at [`audit_api::MAX_TAIL_BYTES`] and
    /// [`audit_api::MAX_LIMIT`], because nothing in this repository rotates that
    /// file and a route that loaded it would be a way for a legitimate caller to
    /// make the daemon allocate however large it has grown. An unreadable file
    /// is a `500` naming nothing but the failure: the trail's *contents* are
    /// exactly what this route is for, and its path is not a secret to somebody
    /// who has already proved they are the owner, but an `io::Error`'s text can
    /// carry a path from a locale-dependent message and there is nothing to gain
    /// by relaying it.
    fn audit_trail(&self, query: &str) -> Response {
        let Some(log) = &self.audit else {
            // Never wired: no data directory was named, so nothing was ever
            // written. Reported as an empty trail rather than a 404, because the
            // console asks this question on every refresh and "there is no
            // audit here" is a different — and wrong — thing to display.
            return json(Status(200), audit_api::Tail::default().to_json());
        };
        let limit = query_value(query, "limit")
            .and_then(|asked| asked.parse::<usize>().ok())
            .unwrap_or(audit_api::DEFAULT_LIMIT);
        match audit_api::tail(log, limit) {
            Ok(found) => json(Status(200), found.to_json()),
            Err(error) => {
                eprintln!("admin: the audit log could not be read: {error}");
                problem(Status(500), "the audit log could not be read")
            }
        }
    }

    /// The live session store, as a running desktop stream must read it.
    ///
    /// # Why this is a public accessor and not something the API does itself
    ///
    /// A desktop stream's per-message authorisation is performed by
    /// `selfhost_desk`'s session driver, which runs in the **daemon** — this
    /// crate hands over the socket at the `101` and speaks none of the protocol
    /// that follows. The driver asks a
    /// [`SessionDirectory`](selfhost_desk::viewer::SessionDirectory) on every
    /// input message; this is the real one, over the store the login route
    /// writes and the registry the people route edits, so revoking a grant or
    /// signing out stops the keyboard on the next keystroke rather than at the
    /// next reconnect.
    ///
    /// `None` when there is no console password wired — there is then no session
    /// store to read, and the only credential that can open a stream is the
    /// bearer token, whose standing needs no store.
    ///
    /// See [`Standings`] for the three rules it is written around.
    pub fn standings(&self) -> Option<Standings> {
        let console = self.console.as_ref()?;
        let switches = self
            .desktop
            .as_ref()
            .map_or(desk_api::Switches { allow_input: false, allow_clipboard: false }, |wiring| {
                desk_api::Switches::of(wiring.config())
            });
        Some(Standings::new(console.sessions.clone(), self.people.clone(), self.policy, switches))
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

    /// Asks the self-update watcher to check its branch immediately.
    ///
    /// Returns `202` without waiting for the answer, exactly as
    /// [`deploy_now`](Self::deploy_now) does, because the check involves a
    /// network round trip and may be followed by a build lasting minutes — a
    /// webhook sender that is made to wait for that will time out and record
    /// the delivery as failed.
    ///
    /// `202` promises only that the check was *asked for*. It cannot promise a
    /// deployment: the branch may not have moved, the tree may be dirty, or the
    /// build may fail. Those outcomes are the watcher's to report in the
    /// daemon's own output, and none of them is something to tell an
    /// unauthenticated pusher about.
    fn self_update_now(&self) -> Response {
        let Some(nudge) = self.self_update.as_ref() else {
            return problem(Status(404), "this deployment does not self-update");
        };
        nudge.poke();
        json(Status(202), Json::object([("accepted", Json::Bool(true))]))
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

/// Reads the abilities a ticket is being minted for, and the machine they name.
///
/// An empty body means the one ability every deployment has a route for, so the
/// console can ask for the events stream without composing a document. Anything
/// else must be `{"want": [...], "peer": "..."}` carrying known words: an
/// unknown word is refused rather than skipped, because a ticket that quietly
/// authorises less than was asked for turns into a stream that closes for no
/// stated reason, minutes later and somewhere else.
///
/// `peer` names the machine and defaults to [`desk_api::LOCAL_NODE`] — this box
/// — so that controlling the machine you are logged into and controlling
/// another one are one request shape, one authorisation check and one set of
/// tests. A `peer` that is not a legal node name is refused rather than
/// defaulted, because a target this API chose is not the target the caller
/// asked for.
///
/// **Control and the clipboard both imply view, and it is added here rather
/// than trusted from the body.** A ticket carrying control without view would
/// authorise a session that may type but not see, which is a session typing
/// blind into whatever window happens to have focus; one carrying the clipboard
/// without view would authorise a stream whose only purpose is to take what was
/// last copied. `Capabilities::from_bits` refuses both on the wire, so a mint
/// that produced either would be a ticket the handshake then turned into an
/// empty capability set with no stated reason.
fn requested_abilities(body: &[u8]) -> Option<Vec<Ability>> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Some(vec![Ability::Events]);
    }
    let value = parse_json_body(body)?;
    let node = match value.get("peer").and_then(Json::as_str) {
        Some(named) => Some(selfhost_identity::NodeName::parse(named).ok()?),
        None => selfhost_identity::NodeName::parse(desk_api::LOCAL_NODE).ok(),
    };
    let Some(want) = value.get("want") else {
        return Some(vec![Ability::Events]);
    };
    let words = want.as_array()?;
    if words.is_empty() {
        return None;
    }
    let mut abilities: Vec<Ability> = words
        .iter()
        .map(|word| Ability::parse(word.as_str()?, node.as_ref()))
        .collect::<Option<_>>()?;
    let implied: Vec<Ability> = abilities.iter().filter_map(Ability::implies).collect();
    for view in implied {
        if !abilities.contains(&view) {
            abilities.push(view);
        }
    }
    Some(abilities)
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

/// The invitation code out of a `{"code": "…"}` body.
///
/// One helper rather than the same three fallible steps written twice, and
/// deliberately total: every way the body can fail to carry a code — not UTF-8,
/// not JSON, no `code`, not a string — comes back as the same `None`, which the
/// invite door turns into the same refusal an outright wrong code gets. A door
/// that distinguished "malformed" from "wrong" would answer a question the
/// caller has no business asking.
fn code_from_body(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let document = selfhost_json::parse(text).ok()?;
    Some(document.get("code")?.as_str()?.to_owned())
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

/// The permission registry in `data_dir`, persisted the one correct way.
///
/// The single constructor for [`People`] outside this crate's tests, so the
/// owner-only writer is chosen in one place rather than at each call site. The
/// CLI needs it because `selfhost people` writes the registry directly — the
/// command an operator reaches for is precisely the one that must not require a
/// working console — and a second copy of "which writer" is how the Windows
/// no-op survived four times in the security review.
pub fn people_registry(data_dir: &Path) -> People {
    People::with_writer(data_dir, token::write_private)
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
    let stream_route = StreamRoute::for_target(&request.target)
        .filter(|_| selfhost_ws::handshake::looks_like_upgrade(&request));
    if let Some(route) = stream_route {
        // Everything past the head belongs to the new protocol, not to a body.
        // See `stream::Prefixed` for what happens if it is dropped here.
        let leftover = buffer.split_off(consumed);
        return match route {
            StreamRoute::Console(ability) => {
                serve_stream(stream, leftover, api, request, ability).await
            }
            StreamRoute::PeerLink => serve_link(stream, leftover, api, &request).await,
        };
    }

    // The other branch that does not go through `Api::handle`: a bulk transfer
    // is gigabytes in one direction or the other, and the whole point of
    // `read_body` below is that it refuses to be. Matched on the path alone, so
    // an unauthorised caller reaches the same refusal here that they would
    // anywhere else rather than a 404 that says the prefix is not served.
    if storage_api::is_bulk(request.path()) {
        let leftover = buffer.split_off(consumed);
        return serve_bulk(stream, leftover, api, request).await;
    }

    // And the third, for the same reason: a WebDAV `GET`, `HEAD` or `PUT` is a
    // whole file in one direction or the other. Every other WebDAV verb carries
    // a small document and goes through `Api::handle` with the rest of the API.
    // Matched on the path and the method alone, so a caller with no credential
    // meets the same challenge here as on any other `/dav` request rather than a
    // 404 that says which prefixes are served.
    if dav_api::is_dav_path(request.path()) && dav_api::is_byte_verb(&request.method) {
        let leftover = buffer.split_off(consumed);
        return serve_dav(stream, leftover, api, request).await;
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
/// The whole of the socket layer's part in a console stream. The decision is
/// [`Api::upgrade_for`], which is pure and tested without a port; the hand-over
/// is [`stream::Upgraded`], which writes the `101` — the **only** place in this
/// crate that does — and carries the bytes that arrived alongside the head so
/// the first message is not eaten; and the loop is [`stream::events`].
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
    let admission = match api.upgrade_for(&request, route.clone()) {
        Ok(admission) => admission,
        Err(denial) => {
            eprintln!("admin: refused a stream on {}: {denial}", request.path());
            return write_response(&mut stream, &problem(Status(401), "authorisation required"))
                .await;
        }
    };

    let upgraded = stream::Upgraded::answer(stream, leftover, admission).await?;
    println!(
        "admin: stream open on {path} for {who}",
        path = request.path(),
        who = Api::stream_identity(upgraded.whom()),
    );

    let outcome = match &route {
        Ability::Events => stream::events(upgraded, api, stream::Watch::default()).await,
        // A desktop stream is not this crate's protocol to speak. Everything
        // past the `101` is `selfhost-desk`, driven over screens and peer links
        // that live in the daemon, so the socket, the redeemed grant and the
        // seat go there and this function's job is finished. What it keeps is
        // the part that is its own: deciding who was allowed in.
        Ability::DesktopView(node)
        | Ability::DesktopControl(node)
        | Ability::ClipboardRead(node) => {
            return serve_desktop(upgraded, api, node.clone()).await;
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

/// Hands an admitted desktop handshake to the daemon's own hardware.
///
/// Everything authorisation-shaped has already happened: the ticket was
/// redeemed, the node it names matched the one in the URL, the capability was
/// decided twice, the freshness rule was applied at the mint, and a place in the
/// deployment-wide stream ceiling is held by the [`Admission`]. What is decided
/// *here* is the one ceiling that is per machine rather than per credential —
/// `[desktop].max_viewers` — because it belongs to the thing being watched, and
/// three browsers pointed at one screen is a different question from one browser
/// holding three streams.
///
/// The seat is taken **after** the `101` is written, which is deliberate: a
/// refusal at capacity should close a stream the client has already established
/// rather than answer the handshake with the uniform 401, because "the machine
/// already has two viewers" is not an authorisation failure and telling a
/// legitimate operator it is would send them to a login page.
///
/// It takes an [`Upgraded`](stream::Upgraded) rather than a socket and an
/// [`Admission`], and that is load-bearing rather than cosmetic: this function
/// used to answer the handshake *again*, so the desktop route put two complete
/// `101` heads on the wire and every client read the second as a malformed
/// frame. It can no longer do so, because the connection it is handed has
/// already been answered and it never holds the raw stream a second answer would
/// be written to.
async fn serve_desktop(
    upgraded: stream::Upgraded<TcpStream, Admission>,
    api: Api,
    node: selfhost_identity::NodeName,
) -> std::io::Result<()> {
    let Some(wiring) = api.desktop() else {
        // Reached only if the subsystem was switched off between the handshake's
        // capability check and this line. Nothing is owed to the caller beyond
        // the connection closing.
        eprintln!("admin: a desktop stream was admitted with no desktop wired");
        return Ok(());
    };

    let Some(seat) = wiring.admit(node.as_str()) else {
        println!(
            "admin: refused a desktop stream on {node}: already at {limit} viewers",
            limit = wiring.config().max_viewers
        );
        return Ok(());
    };

    let (io, admission) = upgraded.into_parts();

    // The abilities the admission carries have already been narrowed twice: at
    // the mint, by `Policy::decide` per ability, and at the handshake, by
    // `upgrade::still_permitted`. They are narrowed a third time on every input
    // message, by the driver in the daemon, against `Api::standings`. This line
    // only translates what survived into the wire's vocabulary.
    let capabilities = desk_api::capabilities_for(
        admission.abilities.iter().any(|a| matches!(a, Ability::DesktopView(_))),
        admission.abilities.iter().any(|a| matches!(a, Ability::DesktopControl(_))),
        admission.abilities.iter().any(|a| matches!(a, Ability::ClipboardRead(_))),
    );
    let session = match &admission.holder {
        Holder::Session(id) => Some(id.clone()),
        Holder::Bearer => None,
    };
    println!(
        "admin: desktop stream open on {node} for {who} ({bits:#05b})",
        who = admission.identity(),
        bits = capabilities.bits(),
    );

    let redemption = desk_api::redemption(session.as_deref(), &node, capabilities);
    let ended = wiring
        .serve(desk_api::Handover {
            io: Box::new(io),
            redemption: redemption.clone(),
            ceilings: wiring.ceilings(),
            seat,
            identity: admission.identity().clone(),
            // The real directory, bound to the machine this stream watches.
            // Built here because this is the one place that holds both the
            // session store and the node the ticket named.
            directory: api.standings().map(|standings| standings.for_redemption(&redemption)),
        })
        .await;
    println!("admin: desktop stream on {node} ended: {ended}");
    Ok(())
}

/// Admits a worker's dial, or refuses it before anything is upgraded.
///
/// The owner's half of the peer link, and the reason `crates/mesh` is reachable
/// at all. Three refusals happen **before** the `101`, in this order, and each
/// is answered as an ordinary HTTP response because there is no stream yet to
/// close:
///
/// 1. **No peerage wired.** The same `404` a path this deployment does not serve
///    answers with, because that is exactly what a box with no invited workers
///    is. It is not a `401`: there is no credential to have got wrong yet, and a
///    dialler that is told *authorisation required* would report a stale token
///    to its operator when the truth is that the far end has no mesh at all.
/// 2. **Not a valid handshake.** A `400` with a fixed sentence; the syntax
///    verdict goes to this daemon's log rather than to the caller.
/// 3. **At the admission ceiling** ([`mesh_api::MAX_PENDING_LINKS`]). A `503`,
///    which is honest and says nothing about which nodes exist. Refusing here
///    rather than after the upgrade is the point of the ceiling: a caller who
///    will not be admitted should never be handed an upgraded connection.
///
/// Everything after the `101` — the greeting, the proof, the replay ledger, the
/// registry and the link itself — is [`mesh_api::serve`], and every refusal
/// there is one bare close code with no prose, so the operator's list of their
/// own machines cannot be enumerated one guess at a time.
async fn serve_link(
    mut stream: TcpStream,
    leftover: Vec<u8>,
    api: Api,
    request: &Request,
) -> std::io::Result<()> {
    let Some(peers) = api.peers().cloned() else {
        return write_response(&mut stream, &problem(Status(404), "no such endpoint")).await;
    };
    let key = match selfhost_ws::handshake::validate(request) {
        Ok(handshake) => handshake.key,
        Err(refusal) => {
            eprintln!("admin: refused a peer link: not a handshake: {refusal}");
            return write_response(&mut stream, &problem(Status(400), "not a websocket handshake"))
                .await;
        }
    };
    let Some(pending) = mesh_api::admission_slot(&peers) else {
        eprintln!(
            "admin: refused a peer link: {} admissions are already in flight",
            mesh_api::MAX_PENDING_LINKS
        );
        return write_response(&mut stream, &problem(Status(503), "try again shortly")).await;
    };

    let upgraded = stream::Upgraded::answer(stream, leftover, stream::PeerKey::new(&key)).await?;
    println!("admin: {}", mesh_api::serve(upgraded, peers, pending).await);
    Ok(())
}

/// Answers a bulk storage transfer, or refuses it.
///
/// The refusal is logged **without the path**, and so is the success: on a NAS
/// the file names are the sensitive thing, and a log with no stated ACL is a
/// directory listing waiting to be reconstructed. The share id is fine — it is a
/// configured name, and the caller had to hold a capability naming it to get
/// this far.
async fn serve_bulk(
    mut stream: TcpStream,
    prefix: Vec<u8>,
    api: Api,
    request: Request,
) -> std::io::Result<()> {
    let plan = match api.bulk_for(&request) {
        Ok(plan) => plan,
        Err(denied) => {
            eprintln!("admin: refused a storage transfer: {denied}");
            return write_response(&mut stream, &denied.response()).await;
        }
    };
    match storage_api::serve(&mut stream, prefix, &request, plan).await {
        Ok(report) => println!("admin: {report}"),
        Err(error) => eprintln!("admin: a storage transfer ended badly: {error}"),
    }
    Ok(())
}

/// Serves a WebDAV file transfer, or refuses it.
///
/// The refusal is logged **without the path**, and so is the success: on a NAS
/// the file names are the sensitive thing, and a log with no stated ACL is a
/// directory listing waiting to be reconstructed. The share id is fine — it is a
/// configured name, and the caller had to prove they hold the deployment's own
/// password to get this far.
async fn serve_dav(
    mut stream: TcpStream,
    prefix: Vec<u8>,
    api: Api,
    request: Request,
) -> std::io::Result<()> {
    let Some(wiring) = api.dav_wiring() else {
        return write_response(&mut stream, &dav_api::unauthenticated()).await;
    };
    let passage = match dav_api::admit(&wiring, &request).await {
        Ok(passage) => passage,
        Err(refused) => {
            eprintln!("admin: refused a WebDAV transfer: {refused}");
            return write_response(&mut stream, &refused.response()).await;
        }
    };
    match dav_api::serve(&mut stream, prefix, &request, passage).await {
        Ok(report) => println!("admin: {report}"),
        Err(error) => eprintln!("admin: a WebDAV transfer ended badly: {error}"),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole upgrade routing table, which is the thing that was wrong.
    ///
    /// `/api/mesh/link` had no variant anywhere, so a worker's dial fell through
    /// to the ordinary router and met a `404` — and `crates/mesh`, every line of
    /// it, was unreachable. A table test here is what makes that a build-time
    /// question rather than something discovered on a second machine.
    #[test]
    fn the_upgrade_routing_table_in_full() {
        let node = |name: &str| selfhost_identity::NodeName::parse(name).expect("a legal name");

        assert_eq!(StreamRoute::for_target("/api/mesh/link"), Some(StreamRoute::PeerLink));
        assert_eq!(
            StreamRoute::for_target("/api/events"),
            Some(StreamRoute::Console(Ability::Events))
        );
        // A desktop URL yields the *minimum* ability: whether the stream may also
        // drive the machine is decided by the redeemed ticket, never by a URL a
        // page can compose with no header at all.
        assert_eq!(
            StreamRoute::for_target("/api/desktop/session?peer=alex-desktop"),
            Some(StreamRoute::Console(Ability::DesktopView(node("alex-desktop"))))
        );
        assert_eq!(
            StreamRoute::for_target("/api/desktop/session"),
            Some(StreamRoute::Console(Ability::DesktopView(node(desk_api::LOCAL_NODE)))),
            "an unnamed peer is this machine, which is the same code path as any other"
        );

        // The link route names no machine and takes no parameters, so nothing in
        // a query string may change what it is.
        assert_eq!(
            StreamRoute::for_target("/api/mesh/link?peer=alex-desktop"),
            Some(StreamRoute::PeerLink)
        );

        // Every near miss. None of these is a stream, and each one would be a
        // route reachable without a ticket if the match were a prefix or a
        // contains.
        for target in [
            "/api/mesh",
            "/api/mesh/link/",
            "/api/mesh/links",
            "/api/mesh/link/extra",
            "/API/MESH/LINK",
            "/api/services",
            "/api/desktop/ticket",
            "/",
            "",
        ] {
            assert_eq!(StreamRoute::for_target(target), None, "{target} was routed as a stream");
        }

        // A peer that is not a legal node name names nothing this deployment
        // serves, and is refused rather than defaulted to this machine.
        assert_eq!(StreamRoute::for_target("/api/desktop/session?peer=Not%20A%20Node"), None);
    }
}
