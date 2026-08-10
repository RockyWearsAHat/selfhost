//! Single-use tickets, and the freshness rule that decides who may hold a
//! keyboard.
//!
//! # The problem this solves
//!
//! A browser cannot be made to send a custom header on a WebSocket handshake.
//! There is no CORS preflight on one, and this deployment's existing CSRF
//! defence — the `x-selfhost-console` header — is demanded only for non-`GET`
//! requests. A handshake *is* a `GET`. So on an upgrade route the session cookie
//! alone would authorise, and the entire defence against a hostile page opening
//! a desktop session in the operator's browser would be `SameSite=Strict` plus an
//! `Origin` check: one browser behaviour and one header that a non-browser client
//! forges trivially.
//!
//! The answer is to move the authorisation off the handshake entirely:
//!
//! > **An upgrade is authorised by a single-use ticket, minted by an ordinary
//! > CSRF-protected `POST`.**
//!
//! `POST /api/desktop/ticket` is a non-`GET` request, so the header rule that
//! already exists covers it, unchanged, written by code that already ships. It
//! returns thirty-two bytes with a thirty-second life. The handshake then carries
//! the ticket in `Sec-WebSocket-Protocol` — the one header a browser *will* let a
//! page set — and the ticket is consumed there. A hostile page cannot mint one,
//! and a hostile page that opens a socket without one gets the same uninformative
//! 401 as an anonymous caller.
//!
//! # Freshness, which is a separate question from authorisation
//!
//! A console session lasts twelve hours. That is a reasonable lifetime for a
//! surface that shows service states, and an unreasonable one for a surface that
//! is a keyboard on the machine: a laptop left open and unlocked with the console
//! in a tab would be a keyboard for the rest of the day. So a ticket that carries
//! [`Capabilities::CONTROL`] is minted only when the session was authenticated by
//! **password or passkey** within a window the operator configures — two minutes
//! by default. The SPA asks for the passkey at the moment CONNECT is clicked,
//! which turns the rule from an obstacle into the thing that makes the button
//! feel deliberate.
//!
//! [`control_freshness`] is that rule, and it is decided here, as pure logic over
//! an explicit `now`, precisely because it is the kind of rule that gets quietly
//! weakened when it lives inside a request handler that is hard to test.
//!
//! # The bearer asymmetry
//!
//! A bearer token is the deployment's *root* credential and it is also the
//! credential most likely to sit in a script, a scheduled task, or a CI secret.
//! It authorises everything the admin API does — and it is deliberately refused
//! [`Capabilities::CONTROL`] and [`Capabilities::CLIPBOARD`] unless the operator
//! explicitly arms it in config. An unattended automation token should be able to
//! read the box's state; it should not be able to type on it. That asymmetry is
//! not a defence against the token holder, who can edit the config; it is a
//! defence against the token leaking into a place where nobody thought of it as a
//! keyboard.

use std::fmt;
use std::time::{Duration, Instant};

/// Bytes of entropy in a ticket. 256 bits, rendered as 64 hexadecimal
/// characters — the same strength as the bearer token and the session id,
/// because for the thirty seconds it lives it grants comparable power.
pub const TICKET_BYTES: usize = 32;

/// How long a ticket is valid for.
///
/// Thirty seconds is chosen to be longer than any plausible round trip between
/// minting and the handshake, and short enough that a ticket captured from a log
/// or a proxy is worthless by the time anybody reads it. It is not configurable:
/// the value only trades one window against another, and an operator lengthening
/// it would be weakening the rule without gaining anything they wanted.
pub const TICKET_TTL: Duration = Duration::from_secs(30);

/// The most unredeemed tickets held at once.
///
/// Tickets are minted by an authenticated caller, so this is not a defence
/// against a stranger; it is a ceiling that stops a looping console — or a
/// script that mints and never connects — from growing the store without bound
/// inside a process that also serves the proxy. Expired entries are purged on
/// every mint and every redemption, so the ceiling is only ever reached by a
/// caller minting faster than thirty tickets per thirty seconds.
pub const MAX_OUTSTANDING: usize = 32;

/// What a desktop session is allowed to do.
///
/// Three independent decisions, deliberately not one boolean. Viewing a screen
/// and driving it are different powers with different blast radii, and the
/// clipboard is a third: a clipboard channel exfiltrates whatever the person at
/// the machine last copied, which is very often a password.
///
/// Represented as a bitset because it travels on the wire in one byte and
/// because the console needs to display it. Unknown bits are refused rather than
/// ignored, so a newer client cannot ask an older server for a capability it
/// would silently drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Capabilities(u8);

impl Capabilities {
    /// See the screen.
    pub const VIEW: Self = Self(0b0000_0001);
    /// Move the pointer and press keys.
    pub const CONTROL: Self = Self(0b0000_0010);
    /// Read and write the far machine's clipboard.
    pub const CLIPBOARD: Self = Self(0b0000_0100);

    /// Every bit this build understands; anything else is refused.
    const KNOWN: u8 = 0b0000_0111;

    /// The empty set.
    pub const fn none() -> Self {
        Self(0)
    }

    /// Reads a capability set from its wire byte.
    ///
    /// Returns `None` for an unknown bit, and for control or clipboard without
    /// view. That second rule is not tidiness: a session that may type but not
    /// see is a session typing blind into whatever window happens to have focus,
    /// which is a worse outcome than the refusal.
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::KNOWN != 0 {
            return None;
        }
        let set = Self(bits);
        if bits != 0 && !set.contains(Self::VIEW) {
            return None;
        }
        Some(set)
    }

    /// The wire byte.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether every capability in `other` is present in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The union of two sets.
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// `self` with everything in `other` removed.
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Whether nothing is granted.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// How a caller proved who they were.
///
/// The distinction that matters is between a credential a person supplied *just
/// now* and one that was supplied hours ago and has been riding in a cookie
/// since. See [`control_freshness`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// The console password, typed into the login form.
    Password,
    /// A passkey assertion — a biometric or a security key, on hardware present
    /// at the time.
    Passkey,
    /// The deployment's bearer token, presented in an `Authorization` header.
    Bearer,
    /// A session cookie alone: whoever logged in did so at some point, and this
    /// request carries no fresh proof of anything.
    Cookie,
}

/// When, and by what means, the caller last proved who they were.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authentication {
    /// What was presented.
    pub method: Method,
    /// The moment it was presented — the login, not this request.
    pub at: Instant,
}

/// The verdict on whether a caller may be granted control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// A password or passkey was presented recently enough.
    Fresh,
    /// A password or passkey was presented, but too long ago. Carries how long
    /// ago, so the console can say *"re-authenticate — last verified 14 minutes
    /// ago"* rather than the useless *"please log in again"* for a session the
    /// person is plainly still using.
    Stale {
        /// How long since the credential was presented.
        age: Duration,
    },
    /// The caller holds only a session cookie. Logging in once is not a standing
    /// permission to type on the machine.
    NoRecentCredential,
    /// A bearer token was presented and `bearer_may_control` is not set.
    BearerNotArmed,
}

impl Freshness {
    /// Whether control may be granted.
    pub const fn permits_control(self) -> bool {
        matches!(self, Self::Fresh)
    }
}

/// Decides whether a caller's authentication is recent enough to be handed a
/// keyboard.
///
/// `bearer_may_control` is the operator's explicit arming of an automation
/// token; it defaults to false in config and enabling it is a config edit and a
/// restart, never a toggle in the surface an attacker would already hold.
///
/// A bearer token has no meaningful age — it is a long-lived secret in a file,
/// not an act of authentication — so `reauth_window` does not apply to it and
/// arming it is the whole decision. That is stated here rather than left to the
/// reader because "the bearer is always fresh" and "the bearer is never fresh"
/// are both plausible readings of a rule written in terms of time.
pub fn control_freshness(
    auth: Authentication,
    now: Instant,
    reauth_window: Duration,
    bearer_may_control: bool,
) -> Freshness {
    match auth.method {
        Method::Bearer => {
            if bearer_may_control {
                Freshness::Fresh
            } else {
                Freshness::BearerNotArmed
            }
        }
        Method::Cookie => Freshness::NoRecentCredential,
        Method::Password | Method::Passkey => {
            // `saturating_duration_since` rather than subtraction: a clock that
            // appears to run backwards must produce a zero age, not a panic.
            let age = now.saturating_duration_since(auth.at);
            if age <= reauth_window { Freshness::Fresh } else { Freshness::Stale { age } }
        }
    }
}

/// Everything the operator's configuration says about what may be granted.
///
/// Passed in rather than read, because `selfhost-desk` does not depend on
/// `selfhost-config` — the crate both consoles link must not need the box's
/// config to compile — and because a rule with its inputs as arguments is a rule
/// that can be tested at every combination of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// `[desktop].allow_input`. False means no ticket ever carries
    /// [`Capabilities::CONTROL`], whatever the caller asks for or proves.
    pub allow_input: bool,
    /// `[desktop].allow_clipboard`.
    pub allow_clipboard: bool,
    /// `[desktop].bearer_may_control`.
    pub bearer_may_control: bool,
    /// `[desktop].reauth_window`.
    pub reauth_window: Duration,
}

impl Default for Policy {
    /// The safe posture, matching the documented config defaults: viewing only,
    /// no clipboard, no automation control, two minutes of freshness.
    fn default() -> Self {
        Self {
            allow_input: false,
            allow_clipboard: false,
            bearer_may_control: false,
            reauth_window: Duration::from_secs(120),
        }
    }
}

/// The console session a ticket is minted for and bound to.
///
/// A newtype over the id string rather than a bare `String`, so that the one
/// place a session id is compared to another cannot accidentally be handed a
/// node name or a ticket. Comparison goes through [`Grants::redeem`], which is
/// constant-time; `PartialEq` here is derived and is used only in tests and in
/// non-secret bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionId(String);

impl SessionId {
    /// Names a session.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The id as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What a caller asked for when minting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketRequest {
    /// The session doing the asking, captured from the cookie by the caller.
    pub session: SessionId,
    /// The node whose desktop is wanted. `self` is the pseudo-peer naming this
    /// machine, so controlling the box you are logged into and controlling
    /// another one are one code path.
    pub peer: String,
    /// What the caller wants to be able to do.
    pub wanted: Capabilities,
    /// How the caller authenticated, and when.
    pub auth: Authentication,
}

/// Why a ticket could not be minted or redeemed.
///
/// Every variant here is deliberately *specific*, because it is for the
/// operator's log and the console's own message. What crosses the network is a
/// uniform 401: the caller learns that it failed, never which check failed,
/// which is the same discipline the login door already follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantError {
    /// The request asked for nothing.
    NothingRequested,
    /// Control was asked for and `[desktop].allow_input` is false.
    InputDisabled,
    /// The clipboard was asked for and `[desktop].allow_clipboard` is false.
    ClipboardDisabled,
    /// Control was asked for and the caller's credential is not fresh enough.
    NotFresh(Freshness),
    /// The store is full of unredeemed tickets.
    TooManyOutstanding,
    /// The presented text is not a ticket: wrong length, or not hexadecimal.
    Malformed,
    /// No live ticket matches. Covers "never existed", "already used" and
    /// "expired" as one answer on purpose — telling a caller which of the three
    /// it was tells them whether they guessed a real ticket.
    NoSuchTicket,
    /// A real ticket, presented by a session other than the one that minted it.
    /// The ticket is consumed anyway; see [`Grants::redeem`].
    WrongSession,
}

impl fmt::Display for GrantError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NothingRequested => out.write_str("the request asked for no capabilities"),
            Self::InputDisabled => out.write_str("control refused: [desktop].allow_input is false"),
            Self::ClipboardDisabled => {
                out.write_str("clipboard refused: [desktop].allow_clipboard is false")
            }
            Self::NotFresh(Freshness::Stale { age }) => {
                write!(out, "control refused: last verified {} seconds ago", age.as_secs())
            }
            Self::NotFresh(Freshness::NoRecentCredential) => {
                out.write_str("control refused: a session cookie is not a fresh credential")
            }
            Self::NotFresh(Freshness::BearerNotArmed) => {
                out.write_str("control refused: [desktop].bearer_may_control is false")
            }
            Self::NotFresh(Freshness::Fresh) => out.write_str("control refused"),
            Self::TooManyOutstanding => out.write_str("too many unredeemed tickets"),
            Self::Malformed => out.write_str("the presented ticket is not 64 hexadecimal digits"),
            Self::NoSuchTicket => out.write_str("no such ticket"),
            Self::WrongSession => {
                out.write_str("the ticket was minted by a different console session")
            }
        }
    }
}

impl std::error::Error for GrantError {}

/// The thirty-two secret bytes themselves.
///
/// The bytes are supplied by the caller, from the same operating-system entropy
/// source that generates the bearer token and session ids. This crate does not
/// link a random number generator and should not: a pure crate that reaches for
/// entropy is a pure crate whose tests are no longer deterministic, and the one
/// place this deployment gets randomness from is worth keeping to one place.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ticket([u8; TICKET_BYTES]);

impl Ticket {
    /// Wraps freshly generated entropy as a ticket.
    pub const fn from_bytes(bytes: [u8; TICKET_BYTES]) -> Self {
        Self(bytes)
    }

    /// The 64-character lowercase hexadecimal form, which is what travels in
    /// `Sec-WebSocket-Protocol`.
    pub fn to_hex(self) -> String {
        self.0.iter().fold(String::with_capacity(TICKET_BYTES * 2), |mut out, byte| {
            out.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
            out.push(char::from_digit((byte & 0x0F) as u32, 16).unwrap_or('0'));
            out
        })
    }

    /// Parses the hexadecimal form.
    ///
    /// Length and alphabet are public facts about our own tickets, so failing
    /// fast on either leaks nothing. Uppercase is accepted because a client that
    /// upper-cases a hex string is common and the value is not case-sensitive;
    /// anything else is [`GrantError::Malformed`].
    pub fn parse_hex(text: &str) -> Result<Self, GrantError> {
        let bytes = text.as_bytes();
        if bytes.len() != TICKET_BYTES * 2 {
            return Err(GrantError::Malformed);
        }
        let mut out = [0u8; TICKET_BYTES];
        for (index, pair) in bytes.chunks_exact(2).enumerate() {
            let high = hex_digit(pair[0]).ok_or(GrantError::Malformed)?;
            let low = hex_digit(pair[1]).ok_or(GrantError::Malformed)?;
            out[index] = (high << 4) | low;
        }
        Ok(Self(out))
    }
}

/// One hexadecimal digit's value, or `None` if it is not one.
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

// Deliberately not `Display`, and `Debug` reveals nothing: a secret that formats
// itself reaches a log line eventually, and a ticket in a log is a ticket
// anybody with the log can redeem for the next thirty seconds. Same reasoning,
// and same shape, as `selfhost_admin::token::Token`.
impl fmt::Debug for Ticket {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("Ticket(<redacted>)")
    }
}

/// A minted ticket and everything it is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The secret. The caller sends [`Ticket::to_hex`] to the console and keeps
    /// nothing else.
    pub ticket: Ticket,
    /// The console session that minted it. The upgrade route compares this to
    /// the session the handshake's own cookie names, so a ticket stolen from one
    /// browser cannot be redeemed from another.
    pub session: SessionId,
    /// The node this ticket is for.
    pub peer: String,
    /// Exactly what it authorises — never more than was asked for, and never
    /// more than policy allows.
    pub capabilities: Capabilities,
    /// When it stops being valid.
    pub expires: Instant,
}

/// The result of a successful redemption: everything the stream needs, and the
/// ticket already gone from the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redemption {
    /// The session the ticket was minted by.
    pub session: SessionId,
    /// The node it names.
    pub peer: String,
    /// What it authorises.
    pub capabilities: Capabilities,
}

/// The outstanding tickets.
///
/// Memory only, by design: a ticket that outlives a daemon restart is a ticket
/// whose thirty-second life became indefinite, and there is nothing here worth
/// persisting.
///
/// Not internally synchronised. The admin API holds one behind the same lock
/// pattern the session store uses; keeping the mutex out of this type is what
/// lets the whole policy be tested without one.
#[derive(Debug, Default)]
pub struct Grants {
    outstanding: Vec<Grant>,
}

impl Grants {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many unredeemed, unexpired tickets are held. For the diagnostics
    /// plate; a number that stays high means clients are minting and not
    /// connecting.
    pub fn len(&self) -> usize {
        self.outstanding.len()
    }

    /// Whether nothing is outstanding.
    pub fn is_empty(&self) -> bool {
        self.outstanding.is_empty()
    }

    /// Drops every expired ticket.
    ///
    /// Called at the top of both public operations, so no background task is
    /// needed to keep the store bounded — the same lazy-purge shape the session
    /// store uses.
    pub fn purge_expired(&mut self, now: Instant) {
        self.outstanding.retain(|grant| grant.expires > now);
    }

    /// Decides what a request may be granted, without minting anything.
    ///
    /// Separated from [`mint`] so the decision can be asserted at every
    /// combination of policy, credential and request without a single byte of
    /// entropy being involved. [`mint`] is this function plus a store insertion.
    ///
    /// The granted set is the intersection of what was asked for with what
    /// policy allows — never a superset, and never silently more than the caller
    /// requested. A caller that asks for view alone gets view alone even if it
    /// could have had control, because a session that quietly carries more power
    /// than the page thought it asked for is a session whose audit trail lies.
    ///
    /// [`mint`]: Grants::mint
    pub fn decide(request: &TicketRequest, policy: &Policy, now: Instant) -> Result<Capabilities, GrantError> {
        if request.wanted.is_empty() {
            return Err(GrantError::NothingRequested);
        }

        let mut granted = Capabilities::VIEW;

        if request.wanted.contains(Capabilities::CONTROL) {
            if !policy.allow_input {
                return Err(GrantError::InputDisabled);
            }
            let freshness = control_freshness(
                request.auth,
                now,
                policy.reauth_window,
                policy.bearer_may_control,
            );
            if !freshness.permits_control() {
                return Err(GrantError::NotFresh(freshness));
            }
            granted = granted.with(Capabilities::CONTROL);
        }

        if request.wanted.contains(Capabilities::CLIPBOARD) {
            if !policy.allow_clipboard {
                return Err(GrantError::ClipboardDisabled);
            }
            // The clipboard is read-out as well as paste-in, so it is held to
            // the control credential's standard rather than the viewer's: a
            // twelve-hour cookie must not be able to drain whatever the person
            // at the machine last copied.
            let freshness = control_freshness(
                request.auth,
                now,
                policy.reauth_window,
                policy.bearer_may_control,
            );
            if !freshness.permits_control() {
                return Err(GrantError::NotFresh(freshness));
            }
            granted = granted.with(Capabilities::CLIPBOARD);
        }

        Ok(granted)
    }

    /// Mints a ticket for a request, or explains why not.
    ///
    /// `entropy` is thirty-two fresh random bytes from the caller. Ownership of
    /// randomness stays with the caller for the reason given on [`Ticket`].
    pub fn mint(
        &mut self,
        request: &TicketRequest,
        policy: &Policy,
        entropy: [u8; TICKET_BYTES],
        now: Instant,
    ) -> Result<Grant, GrantError> {
        self.purge_expired(now);
        if self.outstanding.len() >= MAX_OUTSTANDING {
            return Err(GrantError::TooManyOutstanding);
        }

        let capabilities = Self::decide(request, policy, now)?;
        let grant = Grant {
            ticket: Ticket::from_bytes(entropy),
            session: request.session.clone(),
            peer: request.peer.clone(),
            capabilities,
            // `checked_add` because `Instant + Duration` panics on overflow and
            // this workspace aborts on panic. A clock near the end of its
            // representable range must cost a refused ticket, never the process
            // that also serves 80/443.
            expires: now.checked_add(TICKET_TTL).ok_or(GrantError::TooManyOutstanding)?,
        };
        self.outstanding.push(grant.clone());
        Ok(grant)
    }

    /// Consumes a presented ticket, returning what it authorises.
    ///
    /// `session` is the console session the *handshake* authenticated, and it is
    /// a required argument rather than something the caller is trusted to check
    /// afterwards. That is the whole point of the parameter: a ticket is bound to
    /// the session that minted it, and a binding a caller has to remember to
    /// verify is a binding that one caller eventually will not. There is exactly
    /// one way to turn a ticket into a [`Redemption`], and it checks.
    ///
    /// # Why the loop looks wasteful
    ///
    /// It compares against **every** outstanding ticket, without a `break`, and
    /// each comparison is constant-time. Short-circuiting on the first match
    /// would make the response time a function of *where* in the store the match
    /// was, and a byte-by-byte comparison would make it a function of how many
    /// leading bytes a guess got right. Both are the classic way a secret leaks
    /// through something that is not the secret. The store holds at most
    /// [`MAX_OUTSTANDING`] entries, so the cost of doing it properly is thirty-two
    /// 32-byte comparisons, which is nothing.
    ///
    /// # Single use, including when it fails
    ///
    /// The entry is removed before the session is compared, so a ticket
    /// presented from the wrong session is **spent**. That is deliberate: a
    /// ticket arriving on a session other than its own is either a stolen ticket
    /// being replayed or a client confused about which session it holds, and in
    /// the first case leaving it live for the thief's next attempt is the worse
    /// of the two outcomes. The legitimate holder loses a ticket that costs one
    /// `POST` to replace.
    ///
    /// A ticket redeemed twice — by a retry, or by an attacker who read it out of
    /// a log — fails the second time with [`GrantError::NoSuchTicket`], the same
    /// answer a guess gets.
    pub fn redeem(
        &mut self,
        presented: &str,
        session: &SessionId,
        now: Instant,
    ) -> Result<Redemption, GrantError> {
        self.purge_expired(now);
        let ticket = Ticket::parse_hex(presented)?;

        let mut found: Option<usize> = None;
        for (index, grant) in self.outstanding.iter().enumerate() {
            if constant_time_eq(&grant.ticket.0, &ticket.0) {
                found = Some(index);
            }
        }

        let index = found.ok_or(GrantError::NoSuchTicket)?;
        let grant = self.outstanding.remove(index);
        if !constant_time_eq(grant.session.as_str().as_bytes(), session.as_str().as_bytes()) {
            return Err(GrantError::WrongSession);
        }
        Ok(Redemption {
            session: grant.session,
            peer: grant.peer,
            capabilities: grant.capabilities,
        })
    }
}

/// Whether two byte strings are equal, without short-circuiting.
///
/// The same shape as `selfhost_admin::token::constant_time_eq`, duplicated
/// rather than imported because this crate deliberately does not depend on
/// `selfhost-admin` — the dependency runs the other way, and both consoles link
/// this crate while neither links the admin API. Ten lines of well-understood
/// arithmetic is a better trade than an edge that would invert the crate graph.
fn constant_time_eq(expected: &[u8], actual: &[u8]) -> bool {
    if expected.len() != actual.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in expected.iter().zip(actual) {
        difference |= a ^ b;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Entropy stand-in: deterministic, distinct per call, never a real ticket.
    fn entropy(seed: u8) -> [u8; TICKET_BYTES] {
        let mut bytes = [0u8; TICKET_BYTES];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = seed.wrapping_mul(31).wrapping_add(index as u8);
        }
        bytes
    }

    /// A base instant far enough above the process start that the tests can
    /// subtract hours from it. `Instant` is monotonic from an arbitrary epoch —
    /// boot, on the machines this runs on — so `Instant::now() - one_day` is an
    /// overflow panic on a box that booted this morning, and a test that only
    /// fails on freshly rebooted machines is worse than no test.
    fn moment() -> Instant {
        Instant::now() + Duration::from_secs(1_000_000)
    }

    fn permissive() -> Policy {
        Policy {
            allow_input: true,
            allow_clipboard: true,
            bearer_may_control: false,
            reauth_window: Duration::from_secs(120),
        }
    }

    fn request(now: Instant, wanted: Capabilities, method: Method) -> TicketRequest {
        TicketRequest {
            session: SessionId::new("s".repeat(64)),
            peer: "self".to_owned(),
            wanted,
            auth: Authentication { method, at: now },
        }
    }

    #[test]
    fn a_capability_set_round_trips_through_its_wire_byte() {
        let sets = [
            Capabilities::none(),
            Capabilities::VIEW,
            Capabilities::VIEW.with(Capabilities::CONTROL),
            Capabilities::VIEW.with(Capabilities::CLIPBOARD),
            Capabilities::VIEW.with(Capabilities::CONTROL).with(Capabilities::CLIPBOARD),
        ];
        for set in sets {
            assert_eq!(Capabilities::from_bits(set.bits()), Some(set), "{set:?}");
        }
    }

    #[test]
    fn an_unknown_capability_bit_is_refused_rather_than_ignored() {
        for bits in [0b0000_1001, 0b1000_0001, 0xFF] {
            assert_eq!(Capabilities::from_bits(bits), None, "{bits:#010b}");
        }
    }

    #[test]
    fn control_or_clipboard_without_view_is_refused() {
        // Typing into a screen you cannot see is worse than being refused.
        assert_eq!(Capabilities::from_bits(Capabilities::CONTROL.bits()), None);
        assert_eq!(Capabilities::from_bits(Capabilities::CLIPBOARD.bits()), None);
    }

    #[test]
    fn a_recent_password_or_passkey_is_fresh_and_an_old_one_is_not() {
        let window = Duration::from_secs(120);
        let now = moment();
        for method in [Method::Password, Method::Passkey] {
            let recent = Authentication { method, at: now - Duration::from_secs(119) };
            assert_eq!(control_freshness(recent, now, window, false), Freshness::Fresh);

            // Exactly at the window is inside it: the boundary is an inclusive
            // "within", so a request that races the deadline by a microsecond
            // does not fail confusingly.
            let boundary = Authentication { method, at: now - window };
            assert_eq!(control_freshness(boundary, now, window, false), Freshness::Fresh);

            let old = Authentication { method, at: now - Duration::from_secs(900) };
            assert_eq!(
                control_freshness(old, now, window, false),
                Freshness::Stale { age: Duration::from_secs(900) }
            );
        }
    }

    #[test]
    fn a_cookie_alone_is_never_fresh_however_recent() {
        let now = moment();
        let auth = Authentication { method: Method::Cookie, at: now };
        assert_eq!(
            control_freshness(auth, now, Duration::from_secs(120), true),
            Freshness::NoRecentCredential
        );
    }

    #[test]
    fn a_bearer_token_controls_only_when_explicitly_armed() {
        let now = moment();
        // Age is irrelevant to a bearer token in both directions: a token
        // presented an hour ago and one presented this instant are the same
        // secret out of the same file.
        for at in [now, now - Duration::from_secs(86_400)] {
            let auth = Authentication { method: Method::Bearer, at };
            assert_eq!(
                control_freshness(auth, now, Duration::from_secs(120), false),
                Freshness::BearerNotArmed
            );
            assert_eq!(
                control_freshness(auth, now, Duration::from_secs(120), true),
                Freshness::Fresh
            );
        }
    }

    #[test]
    fn a_clock_that_appears_to_run_backwards_yields_a_zero_age_not_a_panic() {
        let now = moment();
        let auth = Authentication { method: Method::Password, at: now + Duration::from_secs(60) };
        assert_eq!(control_freshness(auth, now, Duration::from_secs(1), false), Freshness::Fresh);
    }

    #[test]
    fn viewing_needs_no_freshness_at_all() {
        let now = moment();
        let stale = Authentication { method: Method::Cookie, at: now - Duration::from_secs(40_000) };
        let ask = TicketRequest { auth: stale, ..request(now, Capabilities::VIEW, Method::Cookie) };
        assert_eq!(Grants::decide(&ask, &permissive(), now), Ok(Capabilities::VIEW));
    }

    #[test]
    fn control_is_refused_when_input_is_disabled_whatever_the_credential() {
        let now = moment();
        let policy = Policy { allow_input: false, ..permissive() };
        let ask = request(now, Capabilities::VIEW.with(Capabilities::CONTROL), Method::Passkey);
        assert_eq!(Grants::decide(&ask, &policy, now), Err(GrantError::InputDisabled));
    }

    #[test]
    fn control_is_refused_on_a_stale_credential_and_says_how_stale() {
        let now = moment();
        let mut ask = request(now, Capabilities::VIEW.with(Capabilities::CONTROL), Method::Password);
        ask.auth.at = now - Duration::from_secs(600);
        assert_eq!(
            Grants::decide(&ask, &permissive(), now),
            Err(GrantError::NotFresh(Freshness::Stale { age: Duration::from_secs(600) }))
        );
    }

    #[test]
    fn the_clipboard_is_held_to_the_control_standard() {
        let now = moment();
        let mut ask = request(now, Capabilities::VIEW.with(Capabilities::CLIPBOARD), Method::Cookie);
        ask.auth.at = now;
        assert_eq!(
            Grants::decide(&ask, &permissive(), now),
            Err(GrantError::NotFresh(Freshness::NoRecentCredential))
        );

        let policy = Policy { allow_clipboard: false, ..permissive() };
        let fresh = request(now, Capabilities::VIEW.with(Capabilities::CLIPBOARD), Method::Passkey);
        assert_eq!(Grants::decide(&fresh, &policy, now), Err(GrantError::ClipboardDisabled));
    }

    #[test]
    fn an_empty_request_is_refused_rather_than_granted_view_by_accident() {
        let now = moment();
        let ask = request(now, Capabilities::none(), Method::Passkey);
        assert_eq!(Grants::decide(&ask, &permissive(), now), Err(GrantError::NothingRequested));
    }

    #[test]
    fn a_ticket_is_single_use() {
        let now = moment();
        let mut grants = Grants::new();
        let ask = request(now, Capabilities::VIEW, Method::Passkey);
        let grant = grants.mint(&ask, &permissive(), entropy(1), now).expect("mint");
        let hex = grant.ticket.to_hex();

        let redeemed = grants.redeem(&hex, &ask.session, now).expect("first redemption");
        assert_eq!(redeemed.capabilities, Capabilities::VIEW);
        assert_eq!(redeemed.session, ask.session);
        assert_eq!(redeemed.peer, "self");

        // The second attempt gets exactly the answer a guess gets.
        assert_eq!(grants.redeem(&hex, &ask.session, now), Err(GrantError::NoSuchTicket));
        assert!(grants.is_empty());
    }

    #[test]
    fn a_ticket_is_bound_to_the_session_that_minted_it_and_is_spent_either_way() {
        let now = moment();
        let mut grants = Grants::new();
        let ask = request(now, Capabilities::VIEW, Method::Passkey);
        let hex = grants.mint(&ask, &permissive(), entropy(12), now).expect("mint").ticket.to_hex();

        let stolen = SessionId::new("t".repeat(64));
        assert_eq!(grants.redeem(&hex, &stolen, now), Err(GrantError::WrongSession));
        // Spent: the thief does not get to try again, and neither does anybody
        // else. A ticket costs one POST to replace.
        assert!(grants.is_empty());
        assert_eq!(grants.redeem(&hex, &ask.session, now), Err(GrantError::NoSuchTicket));
    }

    #[test]
    fn a_ticket_expires_after_thirty_seconds() {
        let now = moment();
        let mut grants = Grants::new();
        let ask = request(now, Capabilities::VIEW, Method::Passkey);
        let hex = grants.mint(&ask, &permissive(), entropy(2), now).expect("mint").ticket.to_hex();

        // One tick before the deadline it still works; at the deadline it does
        // not. The store purges it rather than leaving it to be swept later.
        assert!(grants.redeem(&hex, &ask.session, now + TICKET_TTL - Duration::from_millis(1)).is_ok());

        let hex = grants.mint(&ask, &permissive(), entropy(3), now).expect("mint").ticket.to_hex();
        assert_eq!(
            grants.redeem(&hex, &ask.session, now + TICKET_TTL),
            Err(GrantError::NoSuchTicket)
        );
        assert!(grants.is_empty(), "an expired ticket must not linger in the store");
    }

    #[test]
    fn redeeming_one_ticket_leaves_the_others_alone() {
        let now = moment();
        let mut grants = Grants::new();
        let ask = request(now, Capabilities::VIEW, Method::Passkey);
        let first = grants.mint(&ask, &permissive(), entropy(4), now).expect("mint");
        let second = grants.mint(&ask, &permissive(), entropy(5), now).expect("mint");
        let third = grants.mint(&ask, &permissive(), entropy(6), now).expect("mint");

        assert!(grants.redeem(&second.ticket.to_hex(), &ask.session, now).is_ok());
        assert_eq!(grants.len(), 2);
        assert!(grants.redeem(&first.ticket.to_hex(), &ask.session, now).is_ok());
        assert!(grants.redeem(&third.ticket.to_hex(), &ask.session, now).is_ok());
        assert!(grants.is_empty());
    }

    #[test]
    fn the_store_refuses_to_grow_without_bound() {
        let now = moment();
        let mut grants = Grants::new();
        let ask = request(now, Capabilities::VIEW, Method::Passkey);
        for seed in 0..MAX_OUTSTANDING {
            grants.mint(&ask, &permissive(), entropy(seed as u8), now).expect("within the ceiling");
        }
        assert_eq!(grants.mint(&ask, &permissive(), entropy(200), now), Err(GrantError::TooManyOutstanding));

        // ...but a full store recovers by itself once the tickets time out,
        // rather than needing a restart.
        let later = now + TICKET_TTL + Duration::from_secs(1);
        assert!(grants.mint(&ask, &permissive(), entropy(201), later).is_ok());
        assert_eq!(grants.len(), 1);
    }

    #[test]
    fn malformed_presentations_are_refused_without_touching_the_store() {
        let now = moment();
        let mut grants = Grants::new();
        let ask = request(now, Capabilities::VIEW, Method::Passkey);
        grants.mint(&ask, &permissive(), entropy(7), now).expect("mint");

        let malformed =
            ["".to_owned(), "abc".to_owned(), "z".repeat(64), "a".repeat(63), "a".repeat(65), "  ".to_owned()];
        for presented in &malformed {
            assert_eq!(
                grants.redeem(presented, &ask.session, now),
                Err(GrantError::Malformed),
                "{presented:?}"
            );
        }
        assert_eq!(grants.len(), 1, "a malformed presentation must not consume anything");
    }

    #[test]
    fn a_well_formed_but_unknown_ticket_is_refused() {
        let now = moment();
        let mut grants = Grants::new();
        let session = SessionId::new("s".repeat(64));
        assert_eq!(
            grants.redeem(&"0".repeat(64), &session, now),
            Err(GrantError::NoSuchTicket)
        );
    }

    #[test]
    fn hexadecimal_round_trips_and_accepts_either_case() {
        let ticket = Ticket::from_bytes(entropy(9));
        let hex = ticket.to_hex();
        assert_eq!(hex.len(), TICKET_BYTES * 2);
        assert!(hex.chars().all(|character| character.is_ascii_hexdigit() && !character.is_uppercase()));
        assert_eq!(Ticket::parse_hex(&hex), Ok(ticket));
        assert_eq!(Ticket::parse_hex(&hex.to_uppercase()), Ok(ticket));
    }

    #[test]
    fn a_ticket_never_prints_itself() {
        // The one property that has to survive every future edit to this type.
        let ticket = Ticket::from_bytes(entropy(11));
        let printed = format!("{ticket:?}");
        assert_eq!(printed, "Ticket(<redacted>)");
        assert!(!printed.contains(&ticket.to_hex()[..8]));
    }

    #[test]
    fn every_error_prints_something_useful() {
        // `Display` here is what reaches the daemon log; the network gets a
        // uniform 401 either way, so these strings are the only diagnosis an
        // operator will ever have.
        let errors = [
            GrantError::NothingRequested,
            GrantError::InputDisabled,
            GrantError::ClipboardDisabled,
            GrantError::NotFresh(Freshness::Stale { age: Duration::from_secs(600) }),
            GrantError::NotFresh(Freshness::NoRecentCredential),
            GrantError::NotFresh(Freshness::BearerNotArmed),
            GrantError::NotFresh(Freshness::Fresh),
            GrantError::TooManyOutstanding,
            GrantError::Malformed,
            GrantError::NoSuchTicket,
            GrantError::WrongSession,
        ];
        for error in errors {
            let printed = error.to_string();
            assert!(!printed.is_empty(), "{error:?}");
            // And none of them may name a secret.
            assert!(!printed.contains("Ticket"), "{printed}");
        }
    }

    // -----------------------------------------------------------------------
    // Adversarial review. Present behaviour, recorded so the gap between the
    // documentation and the code is reproducible.
    // -----------------------------------------------------------------------

    #[test]
    fn review_decide_grants_view_that_was_never_asked_for() {
        // `decide`'s own doc: "The granted set is the intersection of what was
        // asked for with what policy allows — never a superset, and never
        // silently more than the caller requested."
        //
        // It is not an intersection. `granted` is seeded with VIEW
        // unconditionally, so any non-empty request comes back carrying VIEW
        // whether or not it was asked for. `Capabilities::from_bits` refuses
        // control-or-clipboard-without-view on the wire, which means this path
        // can *produce* a set the wire vocabulary would have refused as input.
        //
        // Harmless in isolation — the extra bit is the weakest of the three —
        // but the sentence is the one a reader would rely on when wiring the
        // audit record, and it is false.
        let now = moment();
        let control_only = TicketRequest {
            wanted: Capabilities::CONTROL,
            ..request(now, Capabilities::CONTROL, Method::Passkey)
        };
        assert_eq!(
            Grants::decide(&control_only, &permissive(), now),
            Ok(Capabilities::VIEW.with(Capabilities::CONTROL)),
            "a request for control alone was answered with view as well"
        );

        let clipboard_only = TicketRequest {
            wanted: Capabilities::CLIPBOARD,
            ..request(now, Capabilities::CLIPBOARD, Method::Passkey)
        };
        assert_eq!(
            Grants::decide(&clipboard_only, &permissive(), now),
            Ok(Capabilities::VIEW.with(Capabilities::CLIPBOARD))
        );

        // And the set it produced is one the wire parser would have refused.
        assert_eq!(Capabilities::from_bits(Capabilities::CONTROL.bits()), None);
    }

    #[test]
    fn review_a_redemption_reports_a_peer_it_does_not_bind() {
        // `redeem` checks the ticket and the session. It does not take the peer
        // the *handshake* named, so nothing in this module can stop a route from
        // redeeming a ticket minted for one machine and then splicing the
        // channel to another: the peer travels back in the `Redemption` as
        // advice, and honouring it is left to a caller who must remember to.
        //
        // Contrast the session, which is a required argument precisely so that
        // "a binding a caller has to remember to verify is a binding that one
        // caller eventually will not". The peer is exactly that binding, and it
        // was left out.
        let now = moment();
        let mut grants = Grants::new();
        let mut ask = request(now, Capabilities::VIEW, Method::Passkey);
        ask.peer = "alex-desktop".to_owned();
        let hex = grants.mint(&ask, &permissive(), entropy(21), now).expect("mint").ticket.to_hex();

        // The only thing `redeem` compares is the session. A caller asking about
        // a different machine gets a successful redemption and a string.
        let redeemed = grants.redeem(&hex, &ask.session, now).expect("redeemed");
        assert_eq!(redeemed.peer, "alex-desktop");
        // Nothing in the signature obliged the caller to say which peer it was
        // opening, so nothing here could have refused a mismatch.
    }

    #[test]
    fn constant_time_equality_agrees_with_ordinary_equality() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
    }
}
