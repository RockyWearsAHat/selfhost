//! Who may open a stream, decided without touching a socket.
//!
//! Everything in this module is the *authorisation* half of an upgrade. The
//! syntax half — is this request shaped like RFC 6455 §4.1, and what accept key
//! answers it — belongs to `selfhost_ws::handshake` and is called from here; the
//! I/O half belongs to [`crate::stream`]. Splitting it this way is not
//! tidiness: it is what lets every refusal below be exercised by a unit test
//! that constructs a `Request` and reads a `Result`, in a codebase whose
//! authorisation is otherwise tested exactly this way and is correct partly
//! because of it.
//!
//! # The problem this module exists to solve
//!
//! A WebSocket handshake is a `GET`. The repository's CSRF defence
//! (`has_console_header`) is demanded only for non-`GET` requests,
//! because a browser will not attach a custom header to a cross-site *simple*
//! request without a preflight the API never grants. A handshake is worse than a
//! simple request: a page **cannot** set a custom header on one at all, there is
//! no preflight on one at all, and the browser attaches the session cookie
//! anyway. So on an upgrade route the cookie alone would authorise, and the
//! entire defence would be `SameSite=Strict` plus an `Origin` allow-list — one
//! browser behaviour and one header, and a hostile page in a logged-in browser
//! is the exact threat.
//!
//! The answer is to move the CSRF-protected moment somewhere a header *can* be
//! demanded, and make the handshake carry proof that the moment happened:
//!
//! > **An upgrade is authorised by a single-use ticket, minted by an ordinary
//! > CSRF-protected `POST`.**
//!
//! `POST /api/desktop/ticket` is a non-`GET`, so `x-selfhost-console` is already
//! required on it by code that predates this module. It mints 32 bytes from the
//! same generator as the bearer token, bound to the credential that asked and to
//! the abilities it asked for, single use, 30-second lifetime, held in memory
//! only, compared in constant time, and consumed at the handshake. A hostile page
//! cannot mint one. A hostile page that opens a `WebSocket` without one gets the
//! same uniform 401 as any other unauthorised caller.
//!
//! `Sec-WebSocket-Protocol` is the one header a browser *will* let a page set on
//! a handshake, which is why the ticket travels in it as a `tkt.<hex>` token.
//!
//! # Five further checks, none of them the whole story
//!
//! 1. **Origin.** Compared against the console site's canonical origin, computed
//!    server-side from configuration exactly as `Webauthn::origin` already is,
//!    and never from anything the client sent. An absent `Origin` is accepted
//!    only with a bearer credential, because the native console is not a browser
//!    and has none to send.
//! 2. **The existing credential check.** A live session cookie or the bearer
//!    token, unchanged.
//! 3. **The capability.** [`Policy::decide`] over the [`Caller`] the credential
//!    names, for the capability this route serves. A ticket is checked the same
//!    way when it is minted, so this is the second of two — but the two are not
//!    redundant, because a person's grants can be revoked in the seconds between
//!    the mint and the handshake, and a standing authorisation that outlives the
//!    grant it came from is the whole failure mode the desktop design is written
//!    against.
//! 4. **The concurrency ceiling.** A place among [`MAX_STREAMS`] deployment-wide
//!    and [`MAX_STREAMS_PER_HOLDER`] for this credential, held by an RAII
//!    [`StreamSlot`] that lives inside the [`Admission`] and releases itself when
//!    the stream ends.
//! 5. **The ability the ticket carries** must include the one this route needs.
//!
//! Each is defence in depth behind the ticket rather than a replacement for it,
//! and every failure among them produces one uninformative 401. The [`Denial`]
//! variants below name the specific failure **for the log**; returning that
//! detail to the caller would tell a stranger which of our checks they failed,
//! which is helping them pass it.

use crate::token::{constant_time_eq, hex, random_bytes};
use selfhost_identity::{Caller, Capability, Identity, NodeName, Policy};
use selfhost_ws::handshake::{self, Refusal, Upgrade};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Bytes of entropy in a ticket: 256 bits, rendered as 64 hex characters.
///
/// The same strength as a session id and the bearer token, from the same
/// generator, because for the thirty seconds it lives it grants the same access
/// the session it was minted from does.
const TICKET_BYTES: usize = 32;

/// How long a ticket may be redeemed for.
///
/// Thirty seconds is the time between a console clicking CONNECT and its browser
/// completing a handshake, with room for a slow tunnel — not a window anyone can
/// wait in. A ticket is a bearer credential in a URL-adjacent position: it rides
/// in a header a page can set, which means it can also be read back by a page
/// that has already achieved script execution. Its whole defence against being
/// stolen and reused is that it is single-use and stale almost immediately.
pub const TICKET_LIFETIME: Duration = Duration::from_secs(30);

/// The most unredeemed tickets **one credential** may hold at once.
///
/// # Why the ceiling is per holder, and why there is no global one
///
/// This used to be a deployment-wide ceiling that evicted the oldest entry when
/// it was reached. That is a ceiling one principal can spend on another's
/// behalf: any authenticated caller — the console mints one ticket per CONNECT,
/// and a ticket lives thirty seconds — could mint in a loop and destroy the
/// credential the owner's browser was about to redeem, denying them the
/// streaming console for as long as the loop ran. The console's `allowed_cidrs`
/// gate is loopback, so "another principal" includes anything already executing
/// on this box.
///
/// Counting per holder removes the interference entirely: minting is bounded by
/// the credential that mints, and one holder filling their own eight slots costs
/// every other holder nothing. There is deliberately **no** second, global cap,
/// because a global cap that refuses is the same denial-of-service wearing a
/// politer error. The deployment-wide bound falls out of the stores instead: at
/// most `MAX_SESSIONS` cookies plus the one bearer token can be a holder, so the
/// store cannot exceed `(MAX_SESSIONS + 1) * MAX_TICKETS_PER_HOLDER` entries of
/// about a hundred bytes each — a few hundred kilobytes at the absolute
/// worst — and expired entries are swept on every mint.
///
/// Eight is generous for the thing it bounds: a console that has more than eight
/// unredeemed thirty-second tickets outstanding is a console reconnecting in a
/// loop, which is a bug worth a refusal rather than a number worth raising.
pub const MAX_TICKETS_PER_HOLDER: usize = 8;

/// The most concurrent upgraded streams this deployment serves at once.
///
/// Each admitted stream is a live socket, a reader task, and a producer task
/// sweeping the supervisor and the firewall ten times a second — and once the
/// desktop lands, a capture pipeline. Nothing else bounds them: the ticket
/// ceiling does not, because a ticket is consumed the instant it is redeemed, so
/// mint-then-connect in a loop never holds more than one outstanding ticket
/// while opening as many streams as it likes.
pub const MAX_STREAMS: usize = 8;

/// The most concurrent streams **one credential** may hold.
///
/// Two, which is the console open in one tab and being reloaded in another, and
/// is the number the design names. The per-holder limit is what stops one
/// principal from spending the whole deployment-wide ceiling; the deployment-wide
/// one is what stops four principals from doing it together.
pub const MAX_STREAMS_PER_HOLDER: usize = 2;

/// The prefix marking a subprotocol token as a ticket.
const TICKET_PREFIX: &str = "tkt.";

/// What a stream is being opened to do.
///
/// A closed vocabulary, deliberately. Tickets are bound to the abilities that
/// were asked for at the CSRF-protected moment, and a ticket bound to a *set of
/// strings* would authorise whatever a later version of this file decided those
/// strings meant. Adding a variant is therefore a decision somebody makes on
/// purpose, in the phase that builds the route it names.
///
/// Four variants, and the three desktop ones **carry the machine they name**.
/// That is not decoration: [`Capability::DesktopView`],
/// [`Capability::DesktopControl`] and [`Capability::ClipboardRead`] are per-node
/// capabilities, so an ability that
/// did not carry its target could only be checked against *some* node, and a
/// ticket minted for the machine in the study would open a stream to the one in
/// the office. Carrying the name makes `abilities.contains(&route)` in
/// [`decide`] simultaneously the ticket check and the target check, which is one
/// comparison that cannot be half-written.
///
/// Two of them bring a rule the others do not — see
/// [`Ability::needs_a_fresh_credential`]: a ticket carrying them is
/// minted only when the caller's session was opened by password or passkey
/// within `[desktop].reauth_window`, so that a twelve-hour cookie in a browser
/// left open on an unlocked laptop is not a keyboard. That check lives in
/// [`Api::mint_ticket`](crate::Api) beside the policy decision, because it needs
/// a clock and a configuration and this type needs neither.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ability {
    /// Receive the console's live snapshot: `GET /api/events`.
    Events,
    /// Watch one machine's screen: `GET /api/desktop/session?peer=<node>`.
    DesktopView(NodeName),
    /// Drive one machine's pointer and keyboard, on the same stream.
    ///
    /// Never granted alone: a mint that is asked for control also grants view,
    /// because a session that may type but not see is a session typing blind
    /// into whatever window happens to have focus.
    DesktopControl(NodeName),
    /// Read what the person at that machine last copied, on the same stream.
    ///
    /// A separate ability rather than a bit of control, because it is a
    /// separate power with a separate blast radius: a clipboard channel
    /// exfiltrates whatever was last copied on the far machine — routinely a
    /// password, a recovery code or a token — and it does so leaving none of the
    /// visible evidence that moving a pointer leaves. It is off unless
    /// `[desktop].allow_clipboard` is true, and it is held to the same freshness
    /// standard as control, because the thing it can take is the same thing a
    /// keyboard can take.
    ///
    /// Never granted alone, for the reason
    /// [`Capabilities::from_bits`](selfhost_desk::grant::Capabilities::from_bits)
    /// also refuses it: the clipboard travels on the desktop stream, and a
    /// stream that may read a clipboard but not see a screen is a stream nobody
    /// asked for.
    ///
    /// **No clipboard message exists on the wire yet**, so a ticket carrying
    /// this authorises a channel that currently transfers nothing. That is
    /// deliberate and it is the same argument the capability model makes
    /// everywhere else: the authorisation path is built, exercised and covered
    /// from the first release, so that switching the feature on later is a
    /// configuration change rather than a new way into the machine that nobody
    /// has tested.
    ClipboardRead(NodeName),
}

impl Ability {
    /// The word this ability is named by on the wire.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Events => "events",
            Self::DesktopView(_) => "desktop.view",
            Self::DesktopControl(_) => "desktop.control",
            Self::ClipboardRead(_) => "desktop.clipboard",
        }
    }

    /// The machine this ability names, for the ones that name a machine.
    pub fn node(&self) -> Option<&NodeName> {
        match self {
            Self::Events => None,
            Self::DesktopView(node) | Self::DesktopControl(node) | Self::ClipboardRead(node) => {
                Some(node)
            }
        }
    }

    /// The ability this one cannot be granted without, if there is one.
    ///
    /// Control and the clipboard both ride on a desktop stream and both are
    /// refused by `Capabilities::from_bits` without
    /// [`VIEW`](selfhost_desk::grant::Capabilities::VIEW), so a mint that
    /// produced either alone would hand back a ticket the handshake turns into
    /// an empty capability set for no stated reason. Written as a `match` on the
    /// vocabulary rather than as a rule at the mint, so a variant added later
    /// has to answer the question.
    pub fn implies(&self) -> Option<Self> {
        match self {
            Self::Events | Self::DesktopView(_) => None,
            Self::DesktopControl(node) | Self::ClipboardRead(node) => {
                Some(Self::DesktopView(node.clone()))
            }
        }
    }

    /// Whether a ticket carrying this ability may be minted only for a login
    /// that happened within `[desktop].reauth_window`.
    ///
    /// True for exactly the two abilities that reach past the screen: driving
    /// the machine, and reading what was last copied on it. The rule is written
    /// here, on the vocabulary, rather than at the one call site that applies
    /// it, because *which powers need a fresh person behind them* is a property
    /// of the power and not of the route — and because a variant added later
    /// must be answered for in a `match` the compiler checks rather than
    /// silently inherit the lenient side of an `if`.
    pub fn needs_a_fresh_credential(&self) -> bool {
        match self {
            Self::Events | Self::DesktopView(_) => false,
            Self::DesktopControl(_) | Self::ClipboardRead(_) => true,
        }
    }

    /// The subprotocol token a client offers for this stream, and the only token
    /// this server will echo back on it.
    ///
    /// Versioned in the name rather than negotiated in a field: a client that
    /// speaks a different revision of the message shape offers a different token
    /// and is answered with no subprotocol at all, which it can notice, rather
    /// than being connected to a peer that means something else by the same
    /// bytes.
    ///
    /// All three desktop abilities share one token, because they are one
    /// protocol on one stream: what a viewer may *do* on it is the capability
    /// set in the `Hello`, re-decided per input message, not a different message
    /// grammar.
    pub fn protocol(&self) -> &'static str {
        match self {
            Self::Events => "selfhost.events.1",
            Self::DesktopView(_) | Self::DesktopControl(_) | Self::ClipboardRead(_) => {
                "selfhost.desktop.1"
            }
        }
    }

    /// The ability named by `word` against `node`, or `None` for anything else.
    ///
    /// Unknown words are refused rather than ignored. A mint that quietly
    /// dropped a word it did not recognise would hand back a ticket that
    /// authorises less than the caller asked for, and the failure would appear
    /// later as a stream that closes for no stated reason.
    ///
    /// A desktop word without a node is refused for the same reason: a target
    /// this API guessed at is a target the caller did not choose, and the guess
    /// would be authorised as though they had.
    pub fn parse(word: &str, node: Option<&NodeName>) -> Option<Self> {
        match word {
            "events" => Some(Self::Events),
            "desktop.view" => Some(Self::DesktopView(node?.clone())),
            "desktop.control" => Some(Self::DesktopControl(node?.clone())),
            "desktop.clipboard" => Some(Self::ClipboardRead(node?.clone())),
            _ => None,
        }
    }

    /// The stream route reached at `target`, if any.
    ///
    /// The one place a URL becomes an ability, so the socket layer never has to
    /// hold a second opinion about which paths are streams.
    ///
    /// Takes the whole request target rather than the path because the desktop
    /// route names its machine in the query string, and the **minimum** ability
    /// is what it yields: a handshake asks for `DesktopView`, and whether the
    /// stream may also drive the machine is decided by what the redeemed ticket
    /// carries, never by the URL. A URL that could ask for a keyboard would be a
    /// keyboard request a page can make with no header at all.
    pub fn for_target(target: &str) -> Option<Self> {
        let (path, query) = crate::split_target(target);
        match path {
            "/api/events" => Some(Self::Events),
            "/api/desktop/session" => {
                let asked = crate::query_value(query, "peer").unwrap_or(crate::desk_api::LOCAL_NODE);
                Some(Self::DesktopView(NodeName::parse(asked).ok()?))
            }
            _ => None,
        }
    }

    /// The capability a caller must hold to be given this ability.
    ///
    /// The bridge between the stream vocabulary and the authorisation model, and
    /// the reason a ticket cannot authorise more than its holder may have: a
    /// mint decides each requested ability through [`Policy::decide`] on this
    /// capability, and the handshake decides it again on the route's own.
    ///
    /// `Events` maps to [`Capability::ConsoleRead`] because that is exactly what
    /// the stream sends — the service list and the firewall state, the very
    /// bodies `GET /api/services` and `GET /api/firewall` answer with. A push
    /// and a poll of the same data must not be two different permissions, or the
    /// console would have a way to read what the REST routes refuse it.
    pub fn capability(&self) -> Capability {
        match self {
            Self::Events => Capability::ConsoleRead,
            Self::DesktopView(node) => Capability::DesktopView(node.clone()),
            Self::DesktopControl(node) => Capability::DesktopControl(node.clone()),
            Self::ClipboardRead(node) => Capability::ClipboardRead(node.clone()),
        }
    }
}

/// Which credential a ticket belongs to, and which credential must present it.
///
/// A ticket is bound to this so that a ticket minted by one browser cannot be
/// redeemed by another, and so a stolen ticket is worthless without also holding
/// the session it names. The bearer token has no id of its own: it *is* the
/// credential, it is a file on the box readable only by the owner, and a caller
/// that holds it needs no ticket to prove anything about a session it does not
/// have. It still takes a ticket, so there is one path through this module
/// rather than two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Holder {
    /// A browser, named by the session id in its cookie.
    Session(String),
    /// The bearer token — the native console over its SSH tunnel, which is not
    /// a browser and has no cookie, no `Origin`, and no cross-site exposure.
    Bearer,
}

impl Holder {
    /// Whether this credential belongs to a browser.
    ///
    /// The `Origin` rule turns on exactly this: a browser always sends one, so
    /// an absent `Origin` from a session-cookie caller is not an old client, it
    /// is something pretending to be a browser without being one.
    pub fn is_browser(&self) -> bool {
        matches!(self, Self::Session(_))
    }

    /// Whether two holders are the same credential, compared in constant time.
    ///
    /// Not `==`: the session id is a secret of the same weight as the cookie it
    /// came from, and a comparison that returns early on the first differing
    /// byte is a comparison that can be measured.
    pub fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bearer, Self::Bearer) => true,
            (Self::Session(mine), Self::Session(theirs)) => {
                constant_time_eq(mine.as_bytes(), theirs.as_bytes())
            }
            _ => false,
        }
    }
}

/// Why a ticket could not be minted.
///
/// Its own type rather than an [`io::Error`], because the two failures want
/// different answers on the wire and different words in a log: one is the
/// operating system refusing entropy, which is a 500 and a genuine fault, and
/// the other is a client asking for more tickets than it can hold, which is a
/// 429 and is that client's own doing.
#[derive(Debug)]
pub enum MintError {
    /// The operating system would not supply entropy. Never a weaker ticket —
    /// the same rule the bearer token and session ids follow.
    Entropy(io::Error),
    /// This holder already has [`MAX_TICKETS_PER_HOLDER`] unredeemed tickets.
    ///
    /// Refused rather than made room for. Evicting to make room is what let one
    /// principal destroy another's ticket; evicting this holder's *own* oldest
    /// would be no better, because the console mints a ticket and then connects
    /// with it, so the entry evicted would be the one about to be redeemed.
    TooManyOutstanding,
    /// `now + lifetime` is not a representable [`Instant`].
    ///
    /// Only reachable on a platform whose monotonic clock is already near the
    /// end of its range, and included because `Instant + Duration` **panics** on
    /// overflow and this workspace builds with `panic = "abort"` in release: a
    /// panic here is not a failed mint, it is the whole daemon going down on a
    /// box that self-updates unattended. The sibling implementation in
    /// `crates/desk/src/grant.rs` uses `checked_add` for exactly this reason.
    ExpiryUnrepresentable,
}

impl std::fmt::Display for MintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Entropy(error) => write!(f, "the system would not supply entropy: {error}"),
            Self::TooManyOutstanding => write!(
                f,
                "this credential already holds {MAX_TICKETS_PER_HOLDER} unredeemed tickets"
            ),
            Self::ExpiryUnrepresentable => {
                write!(f, "a ticket's expiry is not representable on this clock")
            }
        }
    }
}

impl std::error::Error for MintError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Entropy(error) => Some(error),
            Self::TooManyOutstanding | Self::ExpiryUnrepresentable => None,
        }
    }
}

/// A minted, unredeemed ticket.
struct Issued {
    /// The 64-hex-character value the client presents.
    value: String,
    /// The credential it was minted for and must be presented by.
    holder: Holder,
    /// What it authorises.
    abilities: Vec<Ability>,
    /// When it stops being redeemable.
    expires: Instant,
}

/// The in-memory ticket store, shared by every clone of the [`crate::Api`].
///
/// In memory only and never written down: a ticket that survived a restart would
/// be a credential on disk with none of the protection the bearer token's file
/// has, in exchange for a convenience nobody asked for — a daemon restart drops
/// every stream anyway, and the console reconnects by minting a new one.
#[derive(Clone)]
pub struct Tickets {
    issued: Arc<Mutex<Vec<Issued>>>,
    lifetime: Duration,
}

impl Default for Tickets {
    fn default() -> Self {
        Self::new()
    }
}

impl Tickets {
    /// A store with the production lifetime ([`TICKET_LIFETIME`]).
    pub fn new() -> Self {
        Self::with_lifetime(TICKET_LIFETIME)
    }

    /// A store with an explicit lifetime — the seam that makes expiry testable
    /// without a test that sleeps.
    pub fn with_lifetime(lifetime: Duration) -> Self {
        Self { issued: Arc::new(Mutex::new(Vec::new())), lifetime }
    }

    /// Mints a ticket for `holder` carrying `abilities`, and returns its value.
    ///
    /// Entropy comes from the operating system, and a failure to get it is an
    /// error rather than a weaker ticket — the same rule the bearer token and
    /// session ids follow.
    ///
    /// The ceiling is counted over this holder's own live tickets and nothing
    /// else, and it **refuses** rather than evicting; see
    /// [`MAX_TICKETS_PER_HOLDER`] for why both halves of that matter.
    pub fn mint(&self, holder: Holder, abilities: Vec<Ability>) -> Result<String, MintError> {
        let value = hex(&random_bytes(TICKET_BYTES).map_err(MintError::Entropy)?);
        let now = Instant::now();
        // `checked_add` because `Instant + Duration` panics on overflow and this
        // workspace aborts on panic: a ticket mint must not be able to end the
        // daemon.
        let expires = now.checked_add(self.lifetime).ok_or(MintError::ExpiryUnrepresentable)?;

        let mut issued = self.lock();
        issued.retain(|ticket| ticket.expires > now);
        let held = issued.iter().filter(|ticket| ticket.holder.same(&holder)).count();
        if held >= MAX_TICKETS_PER_HOLDER {
            return Err(MintError::TooManyOutstanding);
        }
        issued.push(Issued { value: value.clone(), holder, abilities, expires });
        Ok(value)
    }

    /// Consumes the ticket named by `presented` and answers what it authorised.
    ///
    /// `None` covers every failure — unknown, expired, or minted for a different
    /// credential — because the caller answers all of them identically anyway.
    ///
    /// **A ticket that is found is consumed even when the holder does not
    /// match.** Leaving it live would mean that presenting a stolen ticket from
    /// the wrong session costs the thief nothing and leaves the ticket there for
    /// their next attempt; consuming it costs the legitimate holder one `POST`
    /// and costs the thief the ticket. The walk visits every live entry rather
    /// than returning at the first match, so a hit and a miss cost the same.
    pub fn redeem(&self, presented: &str, holder: &Holder) -> Option<Vec<Ability>> {
        let now = Instant::now();
        let mut issued = self.lock();
        issued.retain(|ticket| ticket.expires > now);

        let mut found: Option<usize> = None;
        for (at, ticket) in issued.iter().enumerate() {
            if constant_time_eq(ticket.value.as_bytes(), presented.as_bytes()) {
                found = Some(at);
            }
        }
        let ticket = issued.remove(found?);
        ticket.holder.same(holder).then_some(ticket.abilities)
    }

    /// How many tickets are outstanding, expired ones excluded. Diagnostics
    /// only; the console shows it on the DIAGNOSTICS plate.
    pub fn outstanding(&self) -> usize {
        let now = Instant::now();
        let mut issued = self.lock();
        issued.retain(|ticket| ticket.expires > now);
        issued.len()
    }

    /// The store, with lock poisoning treated as fatal.
    ///
    /// A poisoned lock means a panic happened while credentials were held;
    /// limping on with them in an unknown state is worse than stopping.
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Issued>> {
        self.issued.lock().expect("the ticket store lock was poisoned")
    }
}

/// How many streams are open, and for whom.
///
/// # Why a counter, and why it is held by the admission rather than the socket
///
/// A ticket bounds nothing here: it is consumed the instant it is redeemed, so a
/// caller that mints and connects in a loop never holds more than one
/// outstanding ticket while opening as many streams as it pleases. Each of those
/// streams is a socket, two tasks, and a sweep of the supervisor and the
/// firewall ten times a second — so this is the resource ceiling, and without it
/// there is none.
///
/// The place is reserved by [`decide`], as part of deciding, and released by
/// dropping the [`StreamSlot`] the [`Admission`] carries. That is deliberate: a
/// counter incremented by the socket layer and decremented in some later cleanup
/// path is a counter that leaks on every early return anybody adds afterwards,
/// and a leaked slot here means a console that can never reconnect. Drop cannot
/// be forgotten.
#[derive(Clone, Default)]
pub struct Streams {
    /// One entry per open stream, naming its holder. A list rather than a map
    /// because it is at most [`MAX_STREAMS`] long, and a linear walk over eight
    /// entries is not worth a second data structure.
    open: Arc<Mutex<Vec<Holder>>>,
}

impl Streams {
    /// A counter with nothing open.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserves a place for `holder`, or `None` if either ceiling is reached.
    ///
    /// The reservation lives in the returned guard; dropping it gives the place
    /// back.
    pub fn reserve(&self, holder: &Holder) -> Option<StreamSlot> {
        let mut open = self.lock();
        if open.len() >= MAX_STREAMS {
            return None;
        }
        if open.iter().filter(|held| held.same(holder)).count() >= MAX_STREAMS_PER_HOLDER {
            return None;
        }
        open.push(holder.clone());
        Some(StreamSlot { streams: self.clone(), holder: holder.clone() })
    }

    /// How many streams are open. Diagnostics, and the tests' way of proving a
    /// slot really was given back.
    pub fn open(&self) -> usize {
        self.lock().len()
    }

    /// Gives back one place held by `holder`.
    ///
    /// Removes a single entry, not every entry naming this holder: two streams
    /// from one browser are two places, and collapsing them would let the first
    /// one to close release the second one's reservation.
    fn release(&self, holder: &Holder) {
        let mut open = self.lock();
        if let Some(at) = open.iter().position(|held| held.same(holder)) {
            open.remove(at);
        }
    }

    /// The open list, with lock poisoning treated as fatal, as in
    /// [`Tickets::lock`].
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Holder>> {
        self.open.lock().expect("the stream counter lock was poisoned")
    }
}

impl std::fmt::Debug for Streams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Streams({} open)", self.open())
    }
}

/// A reserved place in the concurrent-stream ceiling, released on drop.
///
/// Deliberately holds no data anybody reads. It exists to be *owned* — by the
/// [`Admission`], which the socket layer keeps for as long as the stream lives —
/// so that every way a stream can end, including a panic unwinding through it
/// and every early return a future edit adds, gives the place back.
pub struct StreamSlot {
    streams: Streams,
    holder: Holder,
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        self.streams.release(&self.holder);
    }
}

impl std::fmt::Debug for StreamSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StreamSlot")
    }
}

/// A handshake that may proceed, and everything the stream needs from it.
///
/// Deliberately **not** `Clone`, `PartialEq` or `Eq`: it owns a [`StreamSlot`],
/// and a value that could be cloned or compared would be a reservation that
/// could be duplicated or mistaken for another. Tests that want to assert a
/// refusal compare `result.err()` rather than the whole `Result`.
#[derive(Debug)]
pub struct Admission {
    /// The credential that opened it, re-checked on a timer for as long as the
    /// stream lives.
    pub holder: Holder,
    /// Who opened it and what they hold, as the policy decided it at the
    /// handshake.
    pub caller: Caller,
    /// Everything the redeemed ticket authorised, which is a superset of the one
    /// ability this route needed.
    pub abilities: Vec<Ability>,
    /// The `Sec-WebSocket-Accept` value that answers the client's key.
    pub accept: String,
    /// The subprotocol to echo, or `None` when the client offered no token this
    /// server speaks.
    pub subprotocol: Option<String>,
    /// This stream's place in the concurrency ceiling. Never read; dropped with
    /// the admission, which is what gives the place back.
    pub slot: StreamSlot,
}

impl Admission {
    /// Whose stream this is: `"owner"` for a console password login,
    /// `"machine"` for the bearer token, or the passkey holder's own name.
    pub fn identity(&self) -> &Identity {
        self.caller.identity()
    }
}

/// Why an upgrade was refused.
///
/// Every variant becomes the same uninformative 401 on the wire. The detail is
/// for the daemon's own log, where an operator debugging a console that will not
/// connect needs to know whether the ticket was missing or the origin was wrong,
/// and where a stranger cannot read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    /// The request was not a valid RFC 6455 handshake. Carries the syntax
    /// verdict from `selfhost_ws`.
    Handshake(Refusal),
    /// Neither a live session cookie nor the bearer token was presented.
    NoCredential,
    /// A browser sent an `Origin` that is not the console site's own.
    ForeignOrigin,
    /// A browser sent no `Origin` at all, or the deployment has no console site
    /// to compare one against.
    UnverifiableOrigin,
    /// No `tkt.` token was offered, or more than one was.
    NoTicket,
    /// The ticket was unknown, expired, or minted for a different credential.
    StaleTicket,
    /// A valid ticket that does not authorise this route.
    AbilityNotGranted(Ability),
    /// The caller is authenticated and does not hold the capability this route
    /// serves. Carries the policy's own reason, for the log.
    NotPermitted(Capability, selfhost_identity::Refusal),
    /// Either the deployment-wide or this credential's concurrent-stream
    /// ceiling is already reached.
    TooManyStreams,
}

impl std::fmt::Display for Denial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Handshake(refusal) => write!(f, "not a handshake: {refusal}"),
            Self::NoCredential => write!(f, "no live session and no bearer token"),
            Self::ForeignOrigin => write!(f, "Origin is not the console site's own"),
            Self::UnverifiableOrigin => {
                write!(f, "no Origin from a browser, or no console site configured to compare it to")
            }
            Self::NoTicket => write!(f, "no single tkt. token in Sec-WebSocket-Protocol"),
            Self::StaleTicket => write!(f, "the ticket was unknown, expired, or another caller's"),
            Self::AbilityNotGranted(ability) => {
                write!(f, "the ticket does not carry {}", ability.as_str())
            }
            Self::NotPermitted(capability, refusal) => {
                write!(f, "the caller does not hold {capability} ({refusal})")
            }
            Self::TooManyStreams => write!(
                f,
                "at the stream ceiling: {MAX_STREAMS} for the deployment, \
                 {MAX_STREAMS_PER_HOLDER} for one credential"
            ),
        }
    }
}

impl std::error::Error for Denial {}

/// Validates the handshake's syntax, or names what was wrong with it.
///
/// A thin wrapper so that this module owns one error type: a caller matching on
/// [`Denial`] should not also have to know `selfhost_ws`'s.
pub fn validate(request: &selfhost_http::Request) -> Result<Upgrade, Denial> {
    handshake::validate(request).map_err(Denial::Handshake)
}

/// Everything the *deployment* brings to an upgrade decision, as distinct from
/// what the request brings.
///
/// Grouped into one borrow rather than passed as four arguments because they
/// travel together, they all come from the same [`Api`](crate::Api), and a
/// six-argument security function is one whose call sites are read by counting
/// commas.
pub struct Doorway<'a> {
    /// The authorisation model, and the one place `[desktop].bearer_may_control`
    /// is honoured.
    pub policy: &'a Policy,
    /// Every origin a stream upgrade's `Origin` header may equal, computed
    /// from configuration. Empty means no console site is configured.
    pub expected_origin: &'a [String],
    /// The single-use tickets minted by the CSRF-protected `POST`.
    pub tickets: &'a Tickets,
    /// The concurrency ceiling this stream must find a place in.
    pub streams: &'a Streams,
}

/// The whole upgrade decision, over the pieces rather than over an
/// [`Api`](crate::Api).
///
/// [`Api::upgrade_for`](crate::Api::upgrade_for) is a short adapter that
/// supplies `credential` from the request's cookie or bearer token and a
/// [`Doorway`] from its own configuration and stores. Written this way because
/// the alternative — the decision living on `Api` — would mean every test of it
/// first has to build a supervisor, a catalogue, a token file and a firewall
/// manager, and a check that expensive to exercise is a check that ends up
/// exercised once.
///
/// `credential` is `None` when the caller presented neither a live session nor
/// the bearer token; it carries the [`Caller`] alongside the holder because the
/// capability check, the stream's log line, and the per-person input checks the
/// desktop will add all need to know *who and what they hold*, not merely
/// *whether*.
///
/// # The order of the checks, which is the security-relevant part
///
/// Syntax first, because a request that is not a handshake at all should not
/// reach anything stateful. Then the credential, **before** the ticket is
/// redeemed, so a caller who has somehow learned a ticket value but holds no
/// session cannot burn it — denial of service against the legitimate holder is
/// cheaper than it looks when the ticket lives thirty seconds. Then the origin,
/// which is free and catches the cross-site case before any state changes.
///
/// Then the capability, which is also free and also changes nothing: a caller
/// who may not have this route at all is refused before the deployment spends a
/// place in its ceiling or the caller spends their ticket. It is checked here as
/// well as at the mint on purpose. The two are seconds apart, and a grant
/// revoked in those seconds must not still open a stream that then lives for
/// hours — a standing authorisation outliving the grant it came from is exactly
/// the failure this whole module is arranged against.
///
/// Then the concurrency ceiling, reserved before the ticket is spent so that a
/// full deployment refuses without costing anybody a ticket, and released
/// automatically by dropping the [`StreamSlot`] on any refusal below it.
///
/// Then the ticket, which is consumed. Then the ability, checked **after** the
/// ticket is consumed, so presenting a ticket for the wrong route costs it
/// rather than leaving it available for a second attempt against the right one.
///
/// # The ticket's other abilities are re-decided, and losing one is a downgrade
///
/// A desktop ticket carries more than the route: `desktop.control` and
/// `desktop.clipboard` ride on the same stream as `desktop.view`. Each of them
/// is decided again here, against the caller as they stand *now*, and one that
/// no longer passes is **dropped from the admission** rather than refusing the
/// handshake. That asymmetry is deliberate. Refusing would answer a revoked
/// keyboard with the uniform 401, sending an operator who can still legitimately
/// watch the machine to a login page; dropping opens the stream they may have,
/// with the capability set they actually hold, which the `Hello` then states.
/// The route's own capability is not in this filter because it was decided
/// above, where failing it is a refusal and not a downgrade.
pub fn decide(
    request: &selfhost_http::Request,
    credential: Option<(Holder, Caller)>,
    doorway: &Doorway<'_>,
    route: Ability,
) -> Result<Admission, Denial> {
    let handshake = validate(request)?;
    let (holder, caller) = credential.ok_or(Denial::NoCredential)?;
    origin_permitted(handshake.origin.as_deref(), doorway.expected_origin, holder.is_browser())?;

    let capability = route.capability();
    if let Some(refusal) = doorway.policy.decide(&caller, &capability).refusal() {
        return Err(Denial::NotPermitted(capability, refusal));
    }

    // Held in a local from here down, so every `return Err` below gives the
    // place back without anybody remembering to.
    let slot = doorway.streams.reserve(&holder).ok_or(Denial::TooManyStreams)?;

    let presented = ticket_offered(&handshake.subprotocols)?;
    let abilities = doorway.tickets.redeem(presented, &holder).ok_or(Denial::StaleTicket)?;
    if !abilities.contains(&route) {
        return Err(Denial::AbilityNotGranted(route));
    }
    let abilities = still_permitted(doorway.policy, &caller, &route, abilities);

    Ok(Admission {
        subprotocol: echoed_subprotocol(&handshake.subprotocols, &route),
        accept: handshake.accept,
        holder,
        caller,
        abilities,
        slot,
    })
}

/// The abilities on a ticket that the caller may still exercise.
///
/// Pure, so the downgrade rule is a table test rather than a socket. `route` is
/// kept unconditionally: it was decided by [`decide`] before the ticket was
/// spent, and a second decision here could only disagree with the first by being
/// asked a different question.
///
/// The order of the surviving abilities is the order they were minted in, so a
/// stream's log line and the `Hello` it sends read the same way whether or not
/// anything was dropped.
pub fn still_permitted(
    policy: &Policy,
    caller: &Caller,
    route: &Ability,
    abilities: Vec<Ability>,
) -> Vec<Ability> {
    abilities
        .into_iter()
        .filter(|ability| {
            ability == route || policy.decide(caller, &ability.capability()).is_allowed()
        })
        .collect()
}

/// Whether an `Origin` is acceptable.
///
/// The rule, in full:
///
/// - A present `Origin` must equal one entry of `expected` exactly. Not a
///   suffix match, not a host comparison: `https://admin.example.com.attacker.net`
///   ends with the right characters and is a different site, and every family
///   of origin bug ever written began by comparing something less than the
///   whole string. `expected` holds more than one entry only when the
///   deployment itself declares more than one hostname (or a non-default
///   port) for the console site — it is never widened by anything a request
///   carries.
/// - An absent `Origin` is accepted only from a non-browser credential. A
///   browser always sends one on a handshake, so its absence from a cookie
///   caller is not an old client but something wearing a cookie without being
///   the browser that holds it.
/// - When `expected` is empty — no console site is configured, so there is no
///   origin to compare against — a browser is refused outright. Failing closed
///   here costs a deployment that has no console site a feature it cannot reach
///   through a browser anyway.
///
/// `expected` is derived from configuration by the caller and never from a
/// header: the proxy's relay forwards no `Host`, and an identity the client
/// could choose would defeat the whole comparison. This is the same rule, for
/// the same reason, that `Webauthn::origin` already follows.
pub fn origin_permitted(
    presented: Option<&str>,
    expected: &[String],
    is_browser: bool,
) -> Result<(), Denial> {
    match presented {
        Some(sent) if expected.iter().any(|origin| origin == sent.trim()) => Ok(()),
        Some(_) => Err(Denial::ForeignOrigin),
        None if !is_browser => Ok(()),
        None => Err(Denial::UnverifiableOrigin),
    }
}

/// The ticket offered in a subprotocol list, if exactly one was.
///
/// Exactly one, not the first: two `tkt.` tokens is a client asking us to choose
/// which credential it meant, and a server that chooses is a server whose
/// behaviour depends on ordering nobody specified. The tokens themselves were
/// already length-checked and character-checked by the handshake parser, so what
/// arrives here cannot contain a space, a comma or a control byte.
pub fn ticket_offered(subprotocols: &[String]) -> Result<&str, Denial> {
    let mut found = None;
    for token in subprotocols {
        if let Some(value) = token.strip_prefix(TICKET_PREFIX) {
            if found.is_some() {
                return Err(Denial::NoTicket);
            }
            found = Some(value);
        }
    }
    found.filter(|value| !value.is_empty()).ok_or(Denial::NoTicket)
}

/// The subprotocol to echo back: the route's own token when the client offered
/// it, and nothing otherwise.
///
/// The ticket token is **never** echoed. It is a credential, and a response
/// header is written into a log, shown in a browser's network panel, and read by
/// anything sitting between the two — none of which should learn it. Echoing
/// only a fixed, server-known string also means the value written into the `101`
/// is never client-derived, which is one fewer way to attempt a response split
/// even with the header layer's injection check standing behind it.
pub fn echoed_subprotocol(subprotocols: &[String], ability: &Ability) -> Option<String> {
    subprotocols
        .iter()
        .any(|token| token == ability.protocol())
        .then(|| ability.protocol().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_identity::{Grants, Opening, PersonName, Session};

    fn holder(id: &str) -> Holder {
        Holder::Session(id.to_owned())
    }

    /// A login instant offset forward so a test may subtract from it: `Instant`
    /// is monotonic from an arbitrary epoch, and subtracting from `now` in a
    /// freshly-started process can panic.
    fn login_moment() -> Instant {
        Instant::now() + Duration::from_secs(1_000_000)
    }

    /// The owner behind a session cookie, which is what every console request
    /// carries and what the tests below mean by "the operator".
    fn owner_caller() -> Caller {
        Caller::session(
            Identity::Owner,
            Session::new(Opening::Password, login_moment()),
            Grants::none(),
        )
    }

    /// A named person holding exactly `grants`.
    fn person_caller(grants: Grants) -> Caller {
        let name = PersonName::parse("Mom").expect("a valid name");
        Caller::session(
            Identity::Person(name),
            Session::new(Opening::Passkey, login_moment()),
            grants,
        )
    }

    /// The deployment side of a decision, over a fresh ceiling.
    fn doorway<'a>(
        policy: &'a Policy,
        tickets: &'a Tickets,
        streams: &'a Streams,
        expected_origin: &'a [String],
    ) -> Doorway<'a> {
        Doorway { policy, expected_origin, tickets, streams }
    }

    #[test]
    fn a_ticket_is_redeemable_once_and_only_by_its_holder() {
        let tickets = Tickets::new();
        let value = tickets.mint(holder("aaaa"), vec![Ability::Events]).expect("entropy");
        assert_eq!(tickets.redeem(&value, &holder("aaaa")), Some(vec![Ability::Events]));
        assert_eq!(tickets.redeem(&value, &holder("aaaa")), None, "a ticket was reusable");
    }

    #[test]
    fn a_ticket_presented_from_another_session_is_refused_and_burnt() {
        // Burnt on purpose: a replayed ticket that survives its first wrong
        // presentation is a ticket the thief may keep trying.
        let tickets = Tickets::new();
        let value = tickets.mint(holder("aaaa"), vec![Ability::Events]).expect("entropy");
        assert_eq!(tickets.redeem(&value, &holder("bbbb")), None);
        assert_eq!(tickets.redeem(&value, &holder("aaaa")), None, "the ticket survived a theft");
    }

    #[test]
    fn a_bearer_ticket_is_not_a_session_ticket() {
        let tickets = Tickets::new();
        let value = tickets.mint(Holder::Bearer, vec![Ability::Events]).expect("entropy");
        assert_eq!(tickets.redeem(&value, &holder("aaaa")), None);

        let value = tickets.mint(holder("aaaa"), vec![Ability::Events]).expect("entropy");
        assert_eq!(tickets.redeem(&value, &Holder::Bearer), None);
    }

    #[test]
    fn an_expired_ticket_is_gone() {
        let tickets = Tickets::with_lifetime(Duration::ZERO);
        let value = tickets.mint(holder("aaaa"), vec![Ability::Events]).expect("entropy");
        assert_eq!(tickets.redeem(&value, &holder("aaaa")), None);
        assert_eq!(tickets.outstanding(), 0);
    }

    #[test]
    fn an_unknown_ticket_is_refused_without_touching_the_store() {
        let tickets = Tickets::new();
        let mine = tickets.mint(holder("aaaa"), vec![Ability::Events]).expect("entropy");
        assert_eq!(tickets.redeem("not a ticket", &holder("aaaa")), None);
        assert_eq!(tickets.outstanding(), 1, "a miss consumed something");
        assert!(tickets.redeem(&mine, &holder("aaaa")).is_some());
    }

    #[test]
    fn the_ticket_ceiling_is_per_holder_and_refuses_rather_than_evicting() {
        // The finding this replaces: the ceiling was deployment-wide and evicted
        // the oldest entry across every holder, so any authenticated principal
        // could destroy the credential the owner's browser was about to redeem
        // simply by minting in a loop.
        let tickets = Tickets::new();
        let owner = holder("owner-session");
        let intruder = holder("intruder-session");

        let owners = tickets.mint(owner.clone(), vec![Ability::Events]).expect("entropy");

        // Well past the ceiling, all from a different credential. The intruder
        // fills their own eight places and is then refused; nothing of the
        // owner's is touched.
        for round in 0..64 {
            let minted = tickets.mint(intruder.clone(), vec![Ability::Events]);
            if round >= MAX_TICKETS_PER_HOLDER {
                assert!(
                    matches!(minted, Err(MintError::TooManyOutstanding)),
                    "mint {round} past the per-holder ceiling was allowed"
                );
            } else {
                assert!(minted.is_ok(), "mint {round} inside the per-holder ceiling was refused");
            }
        }

        assert_eq!(
            tickets.redeem(&owners, &owner),
            Some(vec![Ability::Events]),
            "another principal's minting destroyed this one's ticket"
        );

        // And the ceiling is a wall for the holder that hit it, not an eviction:
        // their own oldest ticket is still redeemable.
        assert_eq!(tickets.outstanding(), MAX_TICKETS_PER_HOLDER);
    }

    #[test]
    fn a_holder_that_redeems_may_mint_again() {
        // The ceiling counts what is outstanding, so ordinary use — mint,
        // connect, mint again — never meets it.
        let tickets = Tickets::new();
        let who = holder("aaaa");
        for _ in 0..MAX_TICKETS_PER_HOLDER * 4 {
            let value = tickets.mint(who.clone(), vec![Ability::Events]).expect("entropy");
            assert!(tickets.redeem(&value, &who).is_some());
        }
        assert_eq!(tickets.outstanding(), 0);
    }

    #[test]
    fn a_ticket_is_sixty_four_hex_characters() {
        let tickets = Tickets::new();
        let value = tickets.mint(Holder::Bearer, vec![Ability::Events]).expect("entropy");
        assert_eq!(value.len(), TICKET_BYTES * 2);
        assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn two_tickets_are_never_the_same() {
        let tickets = Tickets::new();
        let a = tickets.mint(Holder::Bearer, vec![Ability::Events]).expect("entropy");
        let b = tickets.mint(Holder::Bearer, vec![Ability::Events]).expect("entropy");
        assert_ne!(a, b);
    }

    #[test]
    fn an_expiry_that_cannot_be_represented_is_an_error_rather_than_a_panic() {
        // `Instant + Duration` panics on overflow and this workspace aborts on
        // panic, so a mint must never reach for the operator with `+`.
        let tickets = Tickets::with_lifetime(Duration::MAX);
        assert!(
            matches!(
                tickets.mint(Holder::Bearer, vec![Ability::Events]),
                Err(MintError::ExpiryUnrepresentable)
            ),
            "an unrepresentable expiry must be refused, not abort the daemon"
        );
        assert_eq!(tickets.outstanding(), 0);
    }

    #[test]
    fn the_stream_ceiling_binds_per_holder_and_deployment_wide_and_releases_on_drop() {
        let streams = Streams::new();
        let first = holder("aaaa");

        let held: Vec<StreamSlot> = (0..MAX_STREAMS_PER_HOLDER)
            .map(|round| {
                streams.reserve(&first).unwrap_or_else(|| panic!("slot {round} inside the limit"))
            })
            .collect();
        assert!(streams.reserve(&first).is_none(), "one credential passed its own ceiling");
        assert_eq!(streams.open(), MAX_STREAMS_PER_HOLDER);

        // A different credential still gets in: the per-holder limit is not a
        // way for one principal to shut out the others.
        let second = streams.reserve(&holder("bbbb")).expect("a different credential");

        // The deployment-wide ceiling is the sum of everyone's.
        let mut rest = Vec::new();
        for index in 0..MAX_STREAMS {
            if let Some(slot) = streams.reserve(&holder(&format!("h{index}"))) {
                rest.push(slot);
            }
        }
        assert_eq!(streams.open(), MAX_STREAMS, "the deployment-wide ceiling did not bind");
        assert!(streams.reserve(&holder("late")).is_none());

        // Dropping one slot gives back exactly one place, not every place that
        // credential held.
        drop(second);
        assert_eq!(streams.open(), MAX_STREAMS - 1);
        drop(held);
        drop(rest);
        assert_eq!(streams.open(), 0, "slots leaked");
    }

    #[test]
    fn the_origin_rule_in_full() {
        const CANONICAL: &str = "https://admin.example.com";
        let expected = [CANONICAL.to_string()];

        // A browser with the right origin, which is the ordinary case.
        assert!(origin_permitted(Some(CANONICAL), &expected, true).is_ok());
        // Whitespace a header may carry does not decide.
        assert!(origin_permitted(Some(" https://admin.example.com "), &expected, true).is_ok());

        // Every near miss. Each one of these is a real family of origin bug:
        // a suffix match, a prefix match, a scheme downgrade, a port added, a
        // case change in the scheme, and the null origin a sandboxed frame sends.
        for foreign in [
            "https://admin.example.com.attacker.net",
            "https://evil.com/https://admin.example.com",
            "http://admin.example.com",
            "https://admin.example.com:8443",
            "HTTPS://admin.example.com",
            "https://ADMIN.example.com",
            "null",
            "",
        ] {
            assert_eq!(
                origin_permitted(Some(foreign), &expected, true),
                Err(Denial::ForeignOrigin),
                "{foreign} was accepted as the console's origin"
            );
        }

        // A browser must send one; a bearer caller need not.
        assert_eq!(origin_permitted(None, &expected, true), Err(Denial::UnverifiableOrigin));
        assert!(origin_permitted(None, &expected, false).is_ok());

        // With no console site configured there is nothing to compare against,
        // and a browser is refused rather than admitted unchecked.
        assert_eq!(origin_permitted(Some(CANONICAL), &[], true), Err(Denial::ForeignOrigin));
        assert_eq!(origin_permitted(None, &[], true), Err(Denial::UnverifiableOrigin));
        assert!(origin_permitted(None, &[], false).is_ok());
    }

    /// A site answering to more than one hostname — a LAN IP beside a public
    /// domain, `localhost` beside both, or the same domain at a non-default
    /// port — accepts an `Origin` matching any one of them, and still refuses
    /// everything else. This is the behaviour `with_console_stream_origins`
    /// exists for: the single-canonical-origin check above refused every
    /// stream on a deployment shaped this way even though its `Origin` was
    /// one the deployment itself declares.
    #[test]
    fn a_site_with_several_declared_origins_accepts_any_one_of_them() {
        let expected = [
            "https://admin.example.com".to_string(),
            "https://192.168.1.31".to_string(),
            "https://localhost:18453".to_string(),
        ];

        for accepted in &expected {
            assert!(
                origin_permitted(Some(accepted), &expected, true).is_ok(),
                "{accepted} is one of the deployment's own declared origins"
            );
        }

        for foreign in ["https://admin.example.com:443", "https://192.168.1.32", "https://localhost"] {
            assert_eq!(
                origin_permitted(Some(foreign), &expected, true),
                Err(Denial::ForeignOrigin),
                "{foreign} is not any of the declared origins, port included"
            );
        }
    }

    /// Turns a list of `&str` into the shape the handshake parser produces.
    fn offer(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|token| (*token).to_owned()).collect()
    }

    #[test]
    fn the_ticket_is_read_out_of_the_subprotocol_offer() {
        let offered = offer(&["selfhost.events.1", "tkt.abc123"]);
        assert_eq!(ticket_offered(&offered), Ok("abc123"));
    }

    #[test]
    fn an_offer_with_no_ticket_or_two_tickets_is_refused() {
        for tokens in [
            vec!["selfhost.events.1"],
            vec![],
            vec!["tkt."],
            vec!["tkt.a", "tkt.b"],
            vec!["selfhost.events.1", "tkt.a", "tkt.a"],
            vec!["ticket.a"],
            vec!["TKT.a"],
        ] {
            assert_eq!(
                ticket_offered(&offer(&tokens)),
                Err(Denial::NoTicket),
                "{tokens:?} was read as one ticket"
            );
        }
    }

    #[test]
    fn only_the_routes_own_protocol_is_echoed_and_never_the_ticket() {
        let offered = offer(&["selfhost.events.1", "tkt.secret"]);
        assert_eq!(
            echoed_subprotocol(&offered, &Ability::Events),
            Some("selfhost.events.1".to_owned())
        );
        // A ticket alone is not a protocol offer, and the credential must never
        // appear in the answer.
        let ticket_only = offer(&["tkt.secret"]);
        assert_eq!(echoed_subprotocol(&ticket_only, &Ability::Events), None);
        // A neighbouring version is not this one.
        let other = offer(&["selfhost.events.2"]);
        assert_eq!(echoed_subprotocol(&other, &Ability::Events), None);
    }

    /// The node every desktop test below names.
    fn node() -> NodeName {
        NodeName::parse("alex-desktop").expect("a legal node name")
    }

    #[test]
    fn the_ability_vocabulary_round_trips_and_refuses_everything_else() {
        let target = node();
        for ability in [
            Ability::Events,
            Ability::DesktopView(target.clone()),
            Ability::DesktopControl(target.clone()),
            Ability::ClipboardRead(target.clone()),
        ] {
            assert_eq!(Ability::parse(ability.as_str(), Some(&target)), Some(ability.clone()));
            assert_eq!(
                Ability::parse(ability.protocol(), Some(&target)),
                None,
                "a protocol is not an ability"
            );
        }
        for word in ["", "Events", "events ", "desktop", "*", "admin"] {
            assert_eq!(
                Ability::parse(word, Some(&target)),
                None,
                "{word} was accepted as an ability"
            );
        }
    }

    #[test]
    fn a_desktop_ability_without_a_machine_is_refused_rather_than_guessed_at() {
        // A target this API invented is a target the caller did not choose, and
        // it would be authorised as though they had.
        assert_eq!(Ability::parse("desktop.view", None), None);
        assert_eq!(Ability::parse("desktop.control", None), None);
        assert_eq!(Ability::parse("desktop.clipboard", None), None);
        assert_eq!(Ability::parse("events", None), Some(Ability::Events));
    }

    #[test]
    fn every_ability_names_the_capability_it_needs() {
        // The mapping is what stops a stream from being a way around the REST
        // routes' permissions: the events stream sends exactly what
        // `GET /api/services` and `GET /api/firewall` answer with, so it needs
        // exactly what they need.
        assert_eq!(Ability::Events.capability(), Capability::ConsoleRead);
        assert_eq!(
            Ability::DesktopView(node()).capability(),
            Capability::DesktopView(node())
        );
        assert_eq!(
            Ability::DesktopControl(node()).capability(),
            Capability::DesktopControl(node())
        );
        assert_eq!(
            Ability::ClipboardRead(node()).capability(),
            Capability::ClipboardRead(node())
        );
    }

    #[test]
    fn exactly_the_abilities_that_reach_past_the_screen_need_a_fresh_person() {
        assert!(!Ability::Events.needs_a_fresh_credential());
        assert!(!Ability::DesktopView(node()).needs_a_fresh_credential());
        assert!(Ability::DesktopControl(node()).needs_a_fresh_credential());
        assert!(Ability::ClipboardRead(node()).needs_a_fresh_credential());
    }

    #[test]
    fn exactly_the_abilities_that_ride_a_desktop_stream_imply_watching_it() {
        assert_eq!(Ability::Events.implies(), None);
        assert_eq!(Ability::DesktopView(node()).implies(), None);
        assert_eq!(
            Ability::DesktopControl(node()).implies(),
            Some(Ability::DesktopView(node()))
        );
        assert_eq!(
            Ability::ClipboardRead(node()).implies(),
            Some(Ability::DesktopView(node()))
        );
    }

    #[test]
    fn a_grant_revoked_between_the_mint_and_the_handshake_downgrades_the_stream() {
        // The person may still watch the machine and may no longer drive it.
        // The stream opens, without the keyboard — refusing it outright would
        // answer a revoked keyboard with a login page.
        let name = selfhost_identity::PersonName::parse("Mary-Anne").expect("a valid name");
        let caller = Caller::session(
            selfhost_identity::Identity::Person(name),
            selfhost_identity::Session::new(
                selfhost_identity::Opening::Passkey,
                std::time::Instant::now(),
            ),
            selfhost_identity::Grants::new([Capability::DesktopView(node())]).expect("few grants"),
        );
        let minted = vec![
            Ability::DesktopControl(node()),
            Ability::DesktopView(node()),
            Ability::ClipboardRead(node()),
        ];
        let route = Ability::DesktopView(node());
        assert_eq!(
            still_permitted(&Policy::locked_down(), &caller, &route, minted),
            vec![Ability::DesktopView(node())]
        );
    }

    #[test]
    fn the_route_itself_survives_the_filter_because_it_was_already_decided() {
        // `decide` refuses a caller who may not have the route at all, before
        // the ticket is spent. Re-deciding it here could only disagree with that
        // by asking a different question, so the route is kept unconditionally.
        let caller = Caller::bearer();
        let route = Ability::DesktopControl(node());
        assert_eq!(
            still_permitted(&Policy::locked_down(), &caller, &route, vec![route.clone()]),
            vec![route]
        );
    }

    #[test]
    fn only_the_stream_paths_are_streams() {
        assert_eq!(Ability::for_target("/api/events"), Some(Ability::Events));
        for path in ["/api/events/", "/api/eventsource", "/api", "/api/services", "/", "/events"] {
            assert_eq!(Ability::for_target(path), None, "{path} was taken for a stream");
        }
    }

    #[test]
    fn a_desktop_handshake_asks_for_a_view_of_the_machine_it_names() {
        assert_eq!(
            Ability::for_target("/api/desktop/session?peer=alex-desktop"),
            Some(Ability::DesktopView(node()))
        );
        // No `peer` means this machine, which is the same code path as any
        // other and not a special case.
        assert_eq!(
            Ability::for_target("/api/desktop/session"),
            Some(Ability::DesktopView(NodeName::parse("self").expect("a legal name")))
        );
        // A URL can never ask for a keyboard: whether the stream may drive the
        // machine is what the redeemed ticket carries, and a page can set a
        // query string with no header at all.
        assert!(matches!(
            Ability::for_target("/api/desktop/session?peer=alex-desktop&control=1"),
            Some(Ability::DesktopView(_))
        ));
        assert_eq!(Ability::for_target("/api/desktop/session?peer=Not A Node"), None);
    }

    /// The origin every test below treats as the console's own.
    const CONSOLE: &str = "https://admin.example.com";

    /// A handshake head, with the subprotocol offer and the `Origin` chosen by
    /// the caller. Written out as bytes so a test reads as what a browser sends.
    fn handshake(offer: Option<&str>, origin: Option<&str>) -> selfhost_http::Request {
        let mut raw = String::from(
            "GET /api/events HTTP/1.1\r\n\
             Host: admin.example.com\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        );
        if let Some(offer) = offer {
            raw.push_str(&format!("Sec-WebSocket-Protocol: {offer}\r\n"));
        }
        if let Some(origin) = origin {
            raw.push_str(&format!("Origin: {origin}\r\n"));
        }
        raw.push_str("\r\n");
        selfhost_http::Request::parse(raw.as_bytes()).expect("a well-formed head").request
    }

    /// The credential a browser presents, as `decide` receives it.
    fn browser(id: &str) -> Option<(Holder, Caller)> {
        Some((holder(id), owner_caller()))
    }

    #[test]
    fn the_ordinary_console_handshake_is_admitted() {
        let tickets = Tickets::new();
        let streams = Streams::new();
        let policy = Policy::locked_down();
        let value = tickets.mint(holder("aaaa"), vec![Ability::Events]).expect("entropy");
        let offer = format!("selfhost.events.1, tkt.{value}");
        let request = handshake(Some(&offer), Some(CONSOLE));

        let admitted = decide(
            &request,
            browser("aaaa"),
            &doorway(&policy, &tickets, &streams, &[CONSOLE.to_string()]),
            Ability::Events,
        )
        .expect("an ordinary handshake");

        assert!(admitted.identity().is_owner());
        assert_eq!(admitted.abilities, vec![Ability::Events]);
        assert_eq!(admitted.subprotocol.as_deref(), Some("selfhost.events.1"));
        // The accept key is RFC 6455 §1.3's own worked example, so this asserts
        // the handshake really was computed rather than copied from the request.
        assert_eq!(admitted.accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        // And the credential must never be echoed back.
        assert!(!admitted.subprotocol.as_deref().unwrap_or_default().contains("tkt."));

        // The admission holds the stream's place for as long as it lives.
        assert_eq!(streams.open(), 1);
        drop(admitted);
        assert_eq!(streams.open(), 0);
    }

    #[test]
    fn the_native_console_needs_no_origin_and_gets_no_subprotocol() {
        let tickets = Tickets::new();
        let streams = Streams::new();
        let policy = Policy::locked_down();
        let value = tickets.mint(Holder::Bearer, vec![Ability::Events]).expect("entropy");
        let request = handshake(Some(&format!("tkt.{value}")), None);

        let admitted = decide(
            &request,
            Some((Holder::Bearer, Caller::bearer())),
            &doorway(&policy, &tickets, &streams, &[CONSOLE.to_string()]),
            Ability::Events,
        )
        .expect("the native console");
        assert_eq!(admitted.subprotocol, None);
        // The stream it opens is the machine's, not the operator's. The native
        // console is admitted exactly as before — `Ability::Events` is inside the
        // machine's list — and the difference is that the handover, and every
        // audit line drawn from it, now says which of the two was at the far end.
        assert!(admitted.identity().is_machine());
        assert!(!admitted.identity().is_owner(), "a token in a file is not the operator");
    }

    #[test]
    fn a_person_without_the_capability_is_refused_before_anything_is_spent() {
        // The headline finding: the authorisation model existed and nothing
        // consulted it, so any live session opened a stream. A person's session
        // now meets `Policy::decide`, and meets it before the deployment spends
        // a place in its ceiling or the caller spends their ticket.
        let tickets = Tickets::new();
        let streams = Streams::new();
        let policy = Policy::locked_down();
        let value = tickets.mint(holder("mom"), vec![Ability::Events]).expect("entropy");
        let request = handshake(Some(&format!("selfhost.events.1, tkt.{value}")), Some(CONSOLE));
        let ungranted = Some((holder("mom"), person_caller(Grants::none())));

        assert_eq!(
            decide(
                &request,
                ungranted,
                &doorway(&policy, &tickets, &streams, &[CONSOLE.to_string()]),
                Ability::Events
            )
            .err(),
            Some(Denial::NotPermitted(
                Capability::ConsoleRead,
                selfhost_identity::Refusal::NotGranted
            ))
        );
        assert_eq!(tickets.outstanding(), 1, "a refused caller spent a ticket");
        assert_eq!(streams.open(), 0, "a refused caller held a place in the ceiling");

        // Granted the capability, the same person and the same ticket are let in.
        let granted = Grants::new([Capability::ConsoleRead]).expect("one grant");
        let admitted = decide(
            &request,
            Some((holder("mom"), person_caller(granted))),
            &doorway(&policy, &tickets, &streams, &[CONSOLE.to_string()]),
            Ability::Events,
        )
        .expect("a granted person");
        assert_eq!(admitted.identity().as_str(), "Mom");
    }

    #[test]
    fn a_grant_revoked_between_the_mint_and_the_handshake_does_not_open_the_stream() {
        // Why the capability is checked twice. The mint and the handshake are
        // seconds apart, and a stream lives for hours: an authorisation that
        // outlived the grant it came from would be a standing one.
        let tickets = Tickets::new();
        let streams = Streams::new();
        let policy = Policy::locked_down();
        let value = tickets.mint(holder("mom"), vec![Ability::Events]).expect("entropy");
        let request = handshake(Some(&format!("tkt.{value}")), Some(CONSOLE));

        assert!(
            decide(
                &request,
                Some((holder("mom"), person_caller(Grants::none()))),
                &doorway(&policy, &tickets, &streams, &[CONSOLE.to_string()]),
                Ability::Events
            )
            .is_err(),
            "a ticket minted while granted opened a stream after the grant was gone"
        );
    }

    #[test]
    fn the_stream_ceiling_refuses_the_handshake_without_costing_a_ticket() {
        let tickets = Tickets::new();
        let streams = Streams::new();
        let policy = Policy::locked_down();

        // Fill the deployment-wide ceiling with other credentials' streams.
        let _held: Vec<StreamSlot> = (0..MAX_STREAMS)
            .map(|index| streams.reserve(&holder(&format!("h{index}"))).expect("a place"))
            .collect();

        let value = tickets.mint(holder("aaaa"), vec![Ability::Events]).expect("entropy");
        let request = handshake(Some(&format!("tkt.{value}")), Some(CONSOLE));
        assert_eq!(
            decide(
                &request,
                browser("aaaa"),
                &doorway(&policy, &tickets, &streams, &[CONSOLE.to_string()]),
                Ability::Events
            )
            .err(),
            Some(Denial::TooManyStreams)
        );
        assert_eq!(tickets.outstanding(), 1, "a full deployment burnt a ticket");
    }

    #[test]
    fn a_hostile_page_with_the_victims_cookie_is_refused() {
        // The threat this whole module exists for: a page on another site, in a
        // logged-in browser, opening a `WebSocket`. The cookie rides along
        // because a handshake is a `GET` and `SameSite` is the only thing
        // standing in the way; the ticket does not, because minting one is a
        // `POST` the page cannot forge. Two independent checks refuse it, and
        // the test asserts the *first* one it meets.
        let tickets = Tickets::new();
        let streams = Streams::new();
        let policy = Policy::locked_down();
        let request = handshake(Some("selfhost.events.1"), Some("https://evil.example"));
        assert_eq!(
            decide(
                &request,
                browser("aaaa"),
                &doorway(&policy, &tickets, &streams, &[CONSOLE.to_string()]),
                Ability::Events
            )
            .err(),
            Some(Denial::ForeignOrigin)
        );

        // And with the origin somehow satisfied, the missing ticket still is not.
        let honest_origin = handshake(Some("selfhost.events.1"), Some(CONSOLE));
        assert_eq!(
            decide(
                &honest_origin,
                browser("aaaa"),
                &doorway(&policy, &tickets, &streams, &[CONSOLE.to_string()]),
                Ability::Events
            )
            .err(),
            Some(Denial::NoTicket)
        );
        assert_eq!(streams.open(), 0, "a refused handshake kept its place");
    }

    #[test]
    fn an_anonymous_caller_cannot_burn_a_ticket_it_learned() {
        // The reason the credential is established before the ticket is
        // redeemed. A ticket is a thirty-second credential; letting anyone who
        // can name one destroy it would be a cheap way to keep a console from
        // ever connecting.
        let tickets = Tickets::new();
        let streams = Streams::new();
        let policy = Policy::locked_down();
        let value = tickets.mint(holder("aaaa"), vec![Ability::Events]).expect("entropy");
        let request = handshake(Some(&format!("tkt.{value}")), Some(CONSOLE));

        assert_eq!(
            decide(
                &request,
                None,
                &doorway(&policy, &tickets, &streams, &[CONSOLE.to_string()]),
                Ability::Events
            )
            .err(),
            Some(Denial::NoCredential)
        );
        assert_eq!(tickets.outstanding(), 1, "an unauthenticated caller burnt a ticket");
        assert!(
            decide(
                &request,
                browser("aaaa"),
                &doorway(&policy, &tickets, &streams, &[CONSOLE.to_string()]),
                Ability::Events
            )
            .is_ok()
        );
    }

    #[test]
    fn a_ticket_presented_for_the_wrong_route_is_spent() {
        // The mirror of the rule above, and it points the other way on purpose:
        // once the caller has proved who they are, a ticket they present is
        // theirs to waste. Leaving it live would let a redeemed-but-refused
        // ticket be retried against every route in turn.
        let tickets = Tickets::new();
        let streams = Streams::new();
        let policy = Policy::locked_down();
        let value = tickets.mint(holder("aaaa"), Vec::new()).expect("entropy");
        let request = handshake(Some(&format!("tkt.{value}")), Some(CONSOLE));

        assert_eq!(
            decide(
                &request,
                browser("aaaa"),
                &doorway(&policy, &tickets, &streams, &[CONSOLE.to_string()]),
                Ability::Events
            )
            .err(),
            Some(Denial::AbilityNotGranted(Ability::Events))
        );
        assert_eq!(tickets.outstanding(), 0, "a refused ticket stayed redeemable");
        assert_eq!(streams.open(), 0, "the reserved place was not given back");
    }

    #[test]
    fn a_request_that_is_not_a_handshake_never_reaches_the_ticket_store() {
        let tickets = Tickets::new();
        let streams = Streams::new();
        let policy = Policy::locked_down();
        let value = tickets.mint(holder("aaaa"), vec![Ability::Events]).expect("entropy");
        let raw = format!(
            "GET /api/events HTTP/1.1\r\n\
             Host: admin.example.com\r\n\
             Sec-WebSocket-Protocol: tkt.{value}\r\n\r\n"
        );
        let request = selfhost_http::Request::parse(raw.as_bytes()).expect("a head").request;

        assert!(matches!(
            decide(
                &request,
                browser("aaaa"),
                &doorway(&policy, &tickets, &streams, &[CONSOLE.to_string()]),
                Ability::Events
            ),
            Err(Denial::Handshake(_))
        ));
        assert_eq!(tickets.outstanding(), 1);
    }

    #[test]
    fn a_stolen_ticket_replayed_from_another_browser_is_refused() {
        let tickets = Tickets::new();
        let streams = Streams::new();
        let policy = Policy::locked_down();
        let value = tickets.mint(holder("aaaa"), vec![Ability::Events]).expect("entropy");
        let request = handshake(Some(&format!("tkt.{value}")), Some(CONSOLE));
        assert_eq!(
            decide(
                &request,
                browser("bbbb"),
                &doorway(&policy, &tickets, &streams, &[CONSOLE.to_string()]),
                Ability::Events
            )
            .err(),
            Some(Denial::StaleTicket)
        );
        assert_eq!(streams.open(), 0);
    }

    #[test]
    fn a_handshake_cannot_be_replayed_even_by_its_own_session() {
        let tickets = Tickets::new();
        let streams = Streams::new();
        let policy = Policy::locked_down();
        let value = tickets.mint(holder("aaaa"), vec![Ability::Events]).expect("entropy");
        let request = handshake(Some(&format!("tkt.{value}")), Some(CONSOLE));
        let first = decide(
            &request,
            browser("aaaa"),
            &doorway(&policy, &tickets, &streams, &[CONSOLE.to_string()]),
            Ability::Events,
        )
        .expect("the first handshake");
        assert_eq!(
            decide(
                &request,
                browser("aaaa"),
                &doorway(&policy, &tickets, &streams, &[CONSOLE.to_string()]),
                Ability::Events
            )
            .err(),
            Some(Denial::StaleTicket),
            "the identical handshake opened a second stream"
        );
        drop(first);
    }

    #[test]
    fn a_deployment_with_no_console_site_admits_no_browser() {
        let tickets = Tickets::new();
        let streams = Streams::new();
        let policy = Policy::locked_down();
        let value = tickets.mint(holder("aaaa"), vec![Ability::Events]).expect("entropy");
        let request = handshake(Some(&format!("tkt.{value}")), Some(CONSOLE));
        assert_eq!(
            decide(&request, browser("aaaa"), &doorway(&policy, &tickets, &streams, &[]), Ability::Events)
                .err(),
            Some(Denial::ForeignOrigin)
        );
    }

    #[test]
    fn a_holder_compares_itself_without_leaking_where_it_differs() {
        // The property under test is behavioural equality; the constant-time
        // part is a property of `constant_time_eq`, which has its own tests.
        assert!(Holder::Bearer.same(&Holder::Bearer));
        assert!(holder("abcd").same(&holder("abcd")));
        assert!(!holder("abcd").same(&holder("abce")));
        assert!(!holder("abcd").same(&holder("abcdef")));
        assert!(!holder("abcd").same(&Holder::Bearer));
        assert!(!Holder::Bearer.same(&holder("abcd")));
        assert!(holder("x").is_browser());
        assert!(!Holder::Bearer.is_browser());
    }
}
