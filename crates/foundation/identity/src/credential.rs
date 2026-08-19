//! How a caller proved who they are.
//!
//! # Why this is not part of [`Identity`](crate::Identity)
//!
//! It is tempting to fold the two together — a bearer token is "the owner", a
//! passkey is "a person" — and the temptation is exactly why they are apart.
//! The bearer token is the *deployment's* root credential, not a person's: it
//! lives in a file on disk, it is presented by the CLI, by the native console
//! over an SSH tunnel, and by an unattended webhook relay, and it bypasses every
//! browser-side defence this repository has by design — no CSRF header, no
//! `Origin` check, no `SameSite`, no session expiry, no login rate limiter, no
//! biometric. That is correct for automation and wrong for a keyboard.
//!
//! So the policy needs to be able to say something that an identity alone
//! cannot express: *this is the owner, and the owner may do everything, and
//! nevertheless this particular request may not drive a mouse, because of how
//! it authenticated.* Keeping the credential as a separate axis is what makes
//! that sentence representable. See [`crate::Policy::decide`], where it is the
//! first of the two deliberate asymmetries in the model.
//!
//! # The two axes a credential is judged on
//!
//! A credential answers two different questions, and conflating them is how the
//! first asymmetry was got wrong once already:
//!
//! - **Does it name a person?** [`Credential::is_deployment_wide`]. The bearer
//!   token, the console password, and a session opened by that password all
//!   belong to the deployment rather than to anybody; only a passkey — and a
//!   session a passkey opened — answers *which person*.
//! - **Was a person present when it was used?** [`Credential::is_unattended`].
//!   This is a question about the moment of the request, not about who owns the
//!   secret, and the two answers come apart: the console password is not a
//!   person's, and it is also the credential a WebDAV mount replays out of an
//!   operating system's keychain on every request for the life of that mount.
//!
//! # The pairs that cannot happen
//!
//! Three of the credentials here belong to the deployment rather than to any
//! person, so only certain (identity, credential) pairs are reachable in the
//! wiring, and [`Credential::belongs_to`] is that table written down. The two
//! deployment-wide credentials belong to *different* parts of the deployment and
//! that distinction is the point: the bearer token is
//! [`Identity::Machine`](crate::Identity::Machine) — this box's own automation,
//! never a person and never the operator — while the console password and the
//! session it opens are [`Identity::Owner`](crate::Identity::Owner). Only a
//! passkey, or a session that passkey opened, can name a person. The policy
//! still refuses the unreachable pairs explicitly rather than assuming them
//! away, because "unreachable" is a property of code in another crate and this
//! crate cannot check it. If per-person tokens or per-person passwords are ever
//! added, they get their own variants here — they must not quietly reuse these,
//! whose whole meaning is "the deployment's own".

use crate::identity::Identity;
use std::fmt;
use std::time::Instant;

/// A credential that can open a session, and did.
///
/// A closed pair rather than a re-use of [`Credential`], because exactly two of
/// the credentials can be presented at a login: the bearer token mints no
/// session (it needs none — it *is* the credential on every request it makes),
/// and a session cannot open a session. Keeping the pair separate means
/// [`Session`] cannot be built naming a login that never happens, and it is what
/// lets the freshness rule in `crates/desk` be handed a value it can act on
/// rather than one it must first re-validate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Opening {
    /// The console password, typed into the login form.
    Password,
    /// A passkey assertion — a biometric or a security key, on hardware present
    /// at the moment the session was opened.
    Passkey,
}

impl Opening {
    /// The word the audit log and the wire use for this login.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Passkey => "passkey",
        }
    }

    /// The credential as it was at the login itself, before the cookie existed.
    ///
    /// The bridge between "what opened this session" and the credential axis:
    /// the login request really did carry one of these, and this is the value it
    /// carried.
    pub fn presented(&self) -> Credential {
        match self {
            Self::Password => Credential::Password,
            Self::Passkey => Credential::Passkey,
        }
    }

    /// Both openings, in a fixed order, for exhaustive tables.
    pub const EVERY: [Opening; 2] = [Self::Password, Self::Passkey];
}

impl fmt::Display for Opening {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A live session cookie, and the login it stands for.
///
/// # Why the cookie carries the login rather than merely existing
///
/// Every request after a login carries a session cookie and nothing else, so
/// this is the credential almost every authenticated request in this deployment
/// actually presents. A variant that said only *"a cookie"* would throw away the
/// two facts the desktop's freshness rule is written in terms of — **when** the
/// person last proved themselves and **by what** — and the seam that builds a
/// [`Caller`](crate::Caller) from a request would have no honest value to put in
/// its place. It would have to claim a passkey signed a request that a cookie
/// carried, which is a lie told to an authorisation function.
///
/// `opened_at` is an [`Instant`] rather than an age, so it does not go stale in
/// the value: a `Caller` built at the top of a request and consulted three
/// checks later still describes the same login, and the caller that owns the
/// clock subtracts once, where the subtraction can be seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Session {
    /// What was actually presented at the login.
    pub opened_by: Opening,
    /// The moment it was presented — the login, not this request.
    pub opened_at: Instant,
}

impl Session {
    /// A session opened by `opened_by` at `opened_at`.
    pub fn new(opened_by: Opening, opened_at: Instant) -> Self {
        Self { opened_by, opened_at }
    }

    /// How long ago the login happened, as of `now`.
    ///
    /// `saturating_duration_since` rather than subtraction: [`Instant`] is
    /// monotonic, but this crate is compiled with `panic = "abort"` in release
    /// and a clock that appears to run backwards must produce a zero age rather
    /// than end the daemon.
    pub fn age(&self, now: Instant) -> std::time::Duration {
        now.saturating_duration_since(self.opened_at)
    }
}

/// Which credential opened the door for this request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Credential {
    /// The bearer token from `<data_dir>/admin.token`.
    ///
    /// The box's own credential and the only one that is not a person sitting at
    /// a browser: the CLI, the native console and the webhook relay all present
    /// it. It names [`Identity::Machine`](crate::Identity::Machine), and its
    /// authority is the explicit list in [`crate::Policy::decide`] rather than
    /// the owner's blanket allow. It is unattended by construction, which is why
    /// the policy also refuses it the capabilities that drive the machine unless
    /// the operator arms it in config.
    Bearer,
    /// The console password, verified against the PBKDF2 hash in
    /// `<data_dir>/console.passwd`, and presented on *this* request.
    ///
    /// Also a deployment-wide credential rather than a person's: there is one
    /// of it, and a session it mints belongs to
    /// [`Identity::Owner`](crate::Identity::Owner).
    ///
    /// It is also **unattended**, which reads as a contradiction until you ask
    /// where a bare password arrives on a request rather than at a login form.
    /// There are two such places and neither has a person in it: the login form
    /// itself does not use this variant (it mints a [`Credential::Session`] and
    /// the request that carries the password asks for nothing but the session),
    /// and the storage subsystem's WebDAV endpoint authenticates with HTTP
    /// Basic — a credential Finder and Explorer store in an operating system's
    /// keychain and replay on every single request for the life of a mount.
    Password,
    /// A WebAuthn assertion from a registered passkey, presented on *this*
    /// request.
    ///
    /// The only credential that answers *which person* presented it, because
    /// the signature is made by a key held in one person's own secure element.
    /// This is the credential per-person identity is built on, and the only one
    /// whose presence proves a person was at the machine when the request was
    /// made — the assertion is signed on hardware, after user verification, at
    /// that instant.
    Passkey,
    /// The session cookie a browser holds after a login, carrying the login it
    /// stands for.
    ///
    /// The credential nearly every authenticated request actually presents. See
    /// [`Session`] for why it carries when and by what rather than merely
    /// existing.
    Session(Session),
    /// A scoped agent token, verified against `console.agents`, presented on
    /// *this* request.
    ///
    /// Deliberately shaped like [`Credential::Passkey`] rather than like
    /// [`Credential::Bearer`]: it does not carry *which* agent, because that
    /// answer lives in [`Identity::Agent`](crate::Identity::Agent), built by
    /// whoever looked the presented token up in the store — the same division
    /// [`Credential::Passkey`] already keeps between "how it was proved" and
    /// "who it was proved for". It is **unattended** (a secret in an
    /// environment variable or a file, replayed by an unattended process — see
    /// [`Credential::is_unattended`]) and **not deployment-wide** (it names one
    /// specific trusted machine, the way [`Credential::Passkey`] names one
    /// specific person).
    Agent,
}

impl Credential {
    /// The word the audit log and the wire use for this credential.
    ///
    /// A session is spelled with the login that opened it, because *whose
    /// session* and *how they logged in* are both facts an operator reading the
    /// log needs, and a bare `"session"` would hide the second one behind a
    /// second lookup that the log cannot do.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bearer => "bearer",
            Self::Password => "password",
            Self::Passkey => "passkey",
            Self::Agent => "agent",
            Self::Session(session) => match session.opened_by {
                Opening::Password => "session.password",
                Opening::Passkey => "session.passkey",
            },
        }
    }

    /// Whether this credential belongs to the deployment rather than to a
    /// person.
    ///
    /// True for [`Credential::Bearer`], [`Credential::Password`], and a
    /// [`Credential::Session`] that the password opened — there is one console
    /// password, so a session it minted names nobody in particular. This is the
    /// property that makes a person authenticating with one of them an
    /// incoherent pair rather than merely an unusual one.
    pub fn is_deployment_wide(&self) -> bool {
        match self {
            Self::Bearer | Self::Password => true,
            Self::Passkey | Self::Agent => false,
            Self::Session(session) => session.opened_by == Opening::Password,
        }
    }

    /// Whether this credential can honestly stand for `identity`.
    ///
    /// The reachable pairs, written down rather than left to the wiring. Three
    /// credentials belong to the deployment and one belongs to a person, and the
    /// two deployment-wide ones belong to *different* parts of it: the bearer
    /// token is this box's automation and nothing else, the console password is
    /// the owner and nothing else. The policy asks this first and fails closed on
    /// a `false`, because "the wiring cannot produce that pair" is a claim about
    /// code in another crate and this crate cannot check it — but it can refuse
    /// to guess.
    ///
    /// A passkey may stand for the owner as well as for a person, because the
    /// operator registers passkeys too, and a session inherits whatever opened
    /// it.
    pub fn belongs_to(&self, identity: &Identity) -> bool {
        match self {
            Self::Bearer => identity.is_machine(),
            Self::Password => identity.is_owner(),
            // Neither the machine (a WebAuthn ceremony needs hardware and a
            // person, and `Identity::Machine` is a token in a file) nor an
            // agent (the whole reason `Identity::Agent` exists is that a
            // headless process cannot perform that ceremony per request — see
            // `AgentName`'s documentation) can wear a passkey's identity.
            Self::Passkey => !identity.is_machine() && !identity.is_agent(),
            // Narrower than the passkey's row, and deliberately: an agent
            // credential is minted for one entry in `console.agents`, and that
            // store cannot spell the owner or the machine (see
            // `AgentName::parse`). There is therefore no such thing as "the
            // owner's" or "the machine's" agent credential, and admitting one
            // here would be a second way to wear either identity with a stored
            // secret rather than the credential each already has.
            Self::Agent => identity.is_agent(),
            // A session is minted by a login, and neither the bearer token nor
            // an agent token opens one — the machine and an agent both present
            // their credential directly on every request. Same exclusion as
            // `Self::Passkey` just above, for the same reason.
            Self::Session(session) => match session.opened_by {
                Opening::Password => identity.is_owner(),
                Opening::Passkey => !identity.is_machine() && !identity.is_agent(),
            },
        }
    }

    /// Whether this is the cookie a console *password* login minted.
    ///
    /// The credential the demotion in [`crate::Policy::decide`] keys on, and it
    /// is deliberately narrower than [`Credential::is_deployment_wide`]. The
    /// other nameless credential presented on a request is
    /// [`Credential::Password`] itself, which is the WebDAV mount's HTTP Basic
    /// auth rather than a console login: demoting that would unmount every
    /// Finder and Explorer share on the deployment at the instant somebody
    /// enrolled a passkey, which is a feature being deleted rather than a
    /// credential being narrowed. That door is left open knowingly; closing it
    /// means per-person WebDAV credentials, which is its own piece of work.
    pub fn is_a_password_login(&self) -> bool {
        matches!(self, Self::Session(session) if session.opened_by == Opening::Password)
    }

    /// Whether this credential was replayed by software rather than presented by
    /// a person.
    ///
    /// The predicate the policy's first asymmetry keys on, and it is a question
    /// about the *moment of the request*, not about who owns the secret:
    ///
    /// - [`Credential::Bearer`] — a secret in a file, sent by automation. True.
    /// - [`Credential::Password`] — a secret in an operating system's keychain,
    ///   replayed on every WebDAV request for the life of a mount. True. This
    ///   variant is *not* what the login form presents to the policy; a login
    ///   asks for a session and nothing else.
    /// - [`Credential::Passkey`] — signed on hardware, after user verification,
    ///   at this instant. False, and it is the only credential for which that
    ///   is provable rather than assumed.
    /// - [`Credential::Agent`] — a secret in an environment variable or a file
    ///   on a trusted machine, replayed by an unattended process on every
    ///   request. True, for the same reason [`Credential::Bearer`] is: nothing
    ///   about presenting it proves a person is there, which is exactly why an
    ///   agent must never be handed [`Capability::DesktopControl`](crate::Capability::DesktopControl)
    ///   or [`Capability::ClipboardRead`](crate::Capability::ClipboardRead)
    ///   without the same `[desktop].bearer_may_control` arming the bearer
    ///   token itself needs.
    /// - [`Credential::Session`] — false, and deliberately so. A cookie is
    ///   certainly replayed by the browser, but it carries [`Session::opened_at`]
    ///   and [`Session::opened_by`], and *how recently* a person was present is a
    ///   question about time. [`crate::Policy::decide`] holds no clock on
    ///   purpose, so it answers only *who may ever*; the freshness rule that
    ///   owns a clock answers *how recently*, at the ticket, where it can also
    ///   say how stale the login is. Answering it here with no clock would mean
    ///   refusing every browser a keyboard for ever, which is not a stricter
    ///   rule, it is a broken feature.
    pub fn is_unattended(&self) -> bool {
        matches!(self, Self::Bearer | Self::Password | Self::Agent)
    }

    /// One credential of every shape, for exhaustive tables.
    ///
    /// Takes the login instant rather than inventing one, exactly as
    /// [`Capability::every_shape`](crate::Capability::every_shape) takes its
    /// targets, so a test can sweep the same session it built. The policy's
    /// sweep is only exhaustive if this list is complete; adding a variant
    /// without adding it here would silently shrink the sweep, so
    /// [`Credential::as_str`]'s match is the compile-time guard that a new
    /// variant cannot be forgotten entirely.
    pub fn every_shape(opened_at: Instant) -> Vec<Credential> {
        vec![
            Self::Bearer,
            Self::Password,
            Self::Passkey,
            Self::Agent,
            Self::Session(Session::new(Opening::Password, opened_at)),
            Self::Session(Session::new(Opening::Passkey, opened_at)),
        ]
    }
}

impl fmt::Display for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A reference instant far enough from the process's start that a test may
    /// subtract from it.
    ///
    /// `Instant` is monotonic from an arbitrary epoch — boot, on the machines
    /// this runs on — so `Instant::now() - five_seconds` can panic in a
    /// freshly-started container. Offsetting forward first makes the subtraction
    /// representable everywhere, which is the same trick `crates/desk`'s grant
    /// tests use for the same reason.
    fn moment() -> Instant {
        Instant::now() + Duration::from_secs(1_000_000)
    }

    #[test]
    fn every_credential_has_a_distinct_word_and_appears_in_the_sweep() {
        let shapes = Credential::every_shape(moment());
        let mut words: Vec<&str> = shapes.iter().map(Credential::as_str).collect();
        words.sort_unstable();
        words.dedup();
        assert_eq!(words.len(), shapes.len(), "one word each, all distinct");
        assert_eq!(shapes.len(), 6, "extend every_shape when a variant is added");
    }

    #[test]
    fn only_a_passkey_and_the_session_it_opened_belong_to_a_person() {
        let now = moment();
        assert!(Credential::Bearer.is_deployment_wide());
        assert!(Credential::Password.is_deployment_wide());
        assert!(!Credential::Passkey.is_deployment_wide());
        assert!(!Credential::Agent.is_deployment_wide(), "an agent token names one machine");
        assert!(
            Credential::Session(Session::new(Opening::Password, now)).is_deployment_wide(),
            "there is one console password, so the session it minted names nobody"
        );
        assert!(
            !Credential::Session(Session::new(Opening::Passkey, now)).is_deployment_wide(),
            "a passkey signed for one person, and its session inherits that"
        );
    }

    #[test]
    fn unattended_is_exactly_the_two_credentials_software_replays() {
        let now = moment();
        assert!(Credential::Bearer.is_unattended(), "a token in a file");
        assert!(Credential::Password.is_unattended(), "a password in a keychain, on every WebDAV request");
        assert!(!Credential::Passkey.is_unattended(), "signed on hardware, this instant");
        assert!(Credential::Agent.is_unattended(), "a secret in a file, replayed by an unattended process");
        for opening in Opening::EVERY {
            assert!(
                !Credential::Session(Session::new(opening, now)).is_unattended(),
                "a session's recency is the freshness rule's question, not this one's"
            );
        }
    }

    #[test]
    fn every_credential_belongs_to_exactly_the_identities_it_can_stand_for() {
        use crate::identity::{AgentName, PersonName};
        let now = moment();
        let person = Identity::Person(PersonName::parse("Mom").expect("a valid name"));
        let agent = Identity::Agent(AgentName::parse("claude-mac").expect("a valid name"));
        // The table, written the other way round from the implementation so the
        // two have to agree rather than restate each other. The load-bearing row
        // is the first: the token is the machine's and nobody else's, which is
        // what stops it from being the operator in the audit trail.
        let expected: [(Credential, [bool; 4]); 6] = [
            //                                    owner, machine, person, agent
            (Credential::Bearer, [false, true, false, false]),
            (Credential::Password, [true, false, false, false]),
            (Credential::Passkey, [true, false, true, false]),
            (Credential::Agent, [false, false, false, true]),
            (Credential::Session(Session::new(Opening::Password, now)), [true, false, false, false]),
            (Credential::Session(Session::new(Opening::Passkey, now)), [true, false, true, false]),
        ];
        for (credential, [owner, machine, named, agent_owns]) in expected {
            assert_eq!(credential.belongs_to(&Identity::Owner), owner, "{credential} / owner");
            assert_eq!(credential.belongs_to(&Identity::Machine), machine, "{credential} / machine");
            assert_eq!(credential.belongs_to(&person), named, "{credential} / person");
            assert_eq!(credential.belongs_to(&agent), agent_owns, "{credential} / agent");
        }
    }

    #[test]
    fn only_a_console_login_is_a_password_login() {
        // Narrower than `is_deployment_wide` on purpose: the bare password is a
        // WebDAV mount's HTTP Basic auth, and the demotion must not reach it.
        let now = moment();
        assert!(Credential::Session(Session::new(Opening::Password, now)).is_a_password_login());
        assert!(!Credential::Password.is_a_password_login(), "that is the WebDAV mount");
        assert!(!Credential::Bearer.is_a_password_login());
        assert!(!Credential::Passkey.is_a_password_login());
        assert!(!Credential::Agent.is_a_password_login());
        assert!(!Credential::Session(Session::new(Opening::Passkey, now)).is_a_password_login());
    }

    #[test]
    fn a_session_reports_the_login_it_stands_for() {
        let opened = moment();
        let session = Session::new(Opening::Passkey, opened);
        assert_eq!(session.opened_by.presented(), Credential::Passkey);
        assert_eq!(session.age(opened), Duration::ZERO);
        assert_eq!(session.age(opened + Duration::from_secs(90)), Duration::from_secs(90));
        // A clock that appears to run backwards is a zero age, never a panic:
        // this crate is built with `panic = "abort"` in release.
        assert_eq!(session.age(opened - Duration::from_secs(5)), Duration::ZERO);
    }

    #[test]
    fn an_opening_names_itself_and_the_credential_it_was() {
        assert_eq!(Opening::Password.to_string(), "password");
        assert_eq!(Opening::Passkey.to_string(), "passkey");
        assert_eq!(Opening::Password.presented(), Credential::Password);
        assert_eq!(Credential::Session(Session::new(Opening::Password, moment())).to_string(), "session.password");
    }
}
