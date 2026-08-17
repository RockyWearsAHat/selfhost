//! The authorisation model: one pure function that decides everything.
//!
//! # Why this file is the most important one in the crate
//!
//! Every route in this deployment currently asks a boolean — *is this request
//! authorised?* — and gets one answer for every power the box has. This module
//! replaces that boolean, and it does so with a function that touches no
//! sockets, reads no files, consults no clock and holds no state:
//! [`Policy::decide`] takes a [`Caller`] and a [`Capability`] and returns a
//! [`Decision`]. That shape is not an aesthetic preference. An authorisation
//! rule that can only be exercised by making a request is a rule that is tested
//! by accident, in the combinations somebody happened to think of; a pure
//! function is tested by sweeping every combination that exists, which is what
//! the table at the foot of this file does.
//!
//! It is also what makes the model safe to introduce *before* it has anything
//! to decide. Today every real caller is the owner and every grant is
//! satisfied, so switching the existing routes onto capability checks changes
//! no behaviour at all. That is the point: a permission model retrofitted onto
//! a shipped route is a model nobody has tested against the route, and the
//! first person to find out is whoever it wrongly lets in.
//!
//! # The equivalence this file preserved, and where it deliberately stopped
//!
//! This model was introduced under a rule: for an [`Identity::Owner`] caller and
//! any capability that existed in the deployment at the time, [`Policy::decide`]
//! returned [`Decision::Allow`] for every credential — byte-for-byte the outcome
//! of the boolean it replaced. That rule was scaffolding for the introduction,
//! and it has now been deliberately broken in two places, because it was also
//! the defect: it is the sentence "whatever holds a shared secret is the owner",
//! written as a compatibility guarantee. The two breaks are the next section, and
//! the test `an_owner_is_allowed_everything_that_exists_today` now says which
//! credentials still satisfy it and which no longer do.
//!
//! # The nameless credentials, and how each one is narrowed
//!
//! Two of the three doors into this deployment are opened by a secret that names
//! nobody: the console password, and the bearer token in
//! `<data_dir>/admin.token`. Both used to resolve to [`Identity::Owner`] and
//! therefore to every power the box has, which meant one shared secret was full
//! ownership with no name attached, and the audit trail could not answer the
//! question it exists for. `docs/labs/vpn-identity-lab.dx` is the audit; this
//! section is the answer to it.
//!
//! **The bearer token is not the owner — it is the machine.** It carries
//! [`Identity::Machine`] and an explicit list of capabilities rather than a
//! blanket allow. The list is not a guess: it is what the two programs that hold
//! the token actually call — the CLI on this box, and the native console over
//! its SSH tunnel, whose whole API surface is in `crates/ui/console`'s poller and
//! channel. What it withholds is [`Capability::FilesAdmin`],
//! [`Capability::NodeAdmin`], [`Capability::SiteAdmin`], [`Capability::DnsAdmin`]
//! and [`Capability::MailAdmin`] — the five that change *who and what this
//! deployment is* rather than operating it, and the five that nothing holding
//! the token has ever asked for. A leaked token is now bounded by what it was
//! for.
//!
//! **The console password stops being root the moment a real credential
//! exists.** This is the one rule here driven by the deployment's *state* rather
//! than by a setting, and that is deliberate: a switch defaulting to the
//! permissive side is a documented insecure mode nobody ever turns off. So:
//!
//! - While **no passkey is enrolled**, a password login is the owner outright.
//!   It has to be — it is the only way into a box that has just been installed,
//!   and a permission model that cannot admit its own installer is a model that
//!   bricks the machine.
//! - The moment **one passkey is enrolled**, a password login holds
//!   [`Capability::ConsoleRead`] and nothing else. It may still read the console
//!   and — through `crates/admin`'s own demand check, which is where enrolment
//!   lives because it is not a capability — enrol another passkey. That is the
//!   recovery path, and it is why this cannot lock anybody out: a lost device
//!   still leaves the operator able to log in with the password and enrol a
//!   replacement. They simply cannot restart a service while doing it.
//!
//! The fact travels in [`Policy::with_passkey_enrolled`], read fresh from the
//! passkey store per request by the seam that builds the policy, because this
//! function holds no state and a policy built once at start-up would still be
//! calling the password root an hour after the first passkey was registered.
//!
//! The one nameless credential deliberately **not** narrowed is
//! [`Credential::Password`] presented on a request, which is the storage
//! subsystem's WebDAV HTTP Basic auth rather than a console login. See
//! [`Credential::is_a_password_login`] for why, and read it as a door knowingly
//! left open rather than one nobody noticed.
//!
//! # The two deliberate asymmetries
//!
//! **One — an unattended credential may not drive a keyboard.** A caller holding
//! a credential that software replays rather than a person presents — see
//! [`Credential::is_unattended`] — is refused [`Capability::DesktopControl`] and
//! [`Capability::ClipboardRead`] unless the operator sets
//! `[desktop].bearer_may_control` in config. That is two credentials, not one,
//! and the pair is the whole point of writing the rule as a predicate:
//!
//! - [`Credential::Bearer`] lives in a file, is presented by automation, and
//!   bypasses every browser-side defence this repository has — no CSRF header,
//!   no `Origin`, no `SameSite`, no session expiry, no rate limiter, no
//!   biometric.
//! - [`Credential::Password`] as a *request* credential is the storage
//!   subsystem's WebDAV HTTP Basic auth, which Finder and Explorer store in an
//!   operating system's keychain and replay on every request for the life of a
//!   mount. It is the more unattended of the two, not the less, and an earlier
//!   revision of this rule armed it for the keyboard by keying on one enum
//!   variant instead of on the property the prose named.
//!
//! Those properties are right for a webhook and for a mounted drive, and wrong
//! for a keyboard at the console user's integrity level, so the two are
//! separated by a switch that defaults to off. This is the one place where "the
//! owner may do everything" is deliberately not true, and it is not true because
//! of *how* the request authenticated rather than *who* it is.
//!
//! A [`Credential::Session`] is **not** unattended here, and the reason is a
//! division of labour rather than an exemption: a cookie carries the moment and
//! the means of its login, and "was a person present recently enough" is a
//! question about time. This function holds no clock, so it answers only *who
//! may ever*; the freshness rule that owns a clock answers *how recently*, at
//! the ticket, where it can also say how stale the login is. See
//! [`Credential::is_unattended`], where the same division is written from the
//! credential's side.
//!
//! **Two — the owner's own authority cannot be revoked.** The owner's grants are
//! never consulted: [`Policy::decide`] does not look at [`Caller::grants`] for
//! an owner at all. The registry reinforces this from the other side, since a
//! [`PersonName`](crate::PersonName) can never spell `"owner"`, so no entry
//! naming the owner can exist to be edited. Both halves are needed. Without the
//! registry rule, a grant list could be written that names the owner; without
//! the policy rule, an empty or corrupted grant list would lock the operator out
//! of their own box — and the console is the surface they would have to use to
//! fix it. A permission system that can brick itself is a worse failure than one
//! that is slightly too permissive to its own installer.
//!
//! # The pairs the policy refuses because they should not exist
//!
//! Three of the four credentials belong to the deployment rather than a person
//! (see [`crate::credential`]), and the two that belong to it belong to
//! *different* parts of it, so most (identity, credential) pairs are not requests
//! the wiring can produce. [`Credential::belongs_to`] is that table, and the
//! policy asks it first and refuses with
//! [`Refusal::CredentialIsNotThisIdentitys`] rather than falling through to a
//! grant check. Refusing costs one match arm and fails closed if the wiring is
//! ever wrong; assuming costs nothing today and is an authorisation bypass the
//! day somebody adds a login path that mints a person from a shared secret.

use crate::capability::Capability;
use crate::credential::{Credential, Session};
use crate::identity::Identity;
use std::fmt;

/// The most capabilities one person may be granted.
///
/// Bounded like every stored collection in this workspace: a grant list arrives
/// from a console request and is written to a file, and an unbounded one is a
/// way to grow that file without limit. Generous enough that a person with
/// access to every share on a machine with several nodes never approaches it.
pub const MAX_GRANTS: usize = 64;

/// A person already holds [`MAX_GRANTS`] capabilities.
///
/// Its own error type rather than a boolean, because "the grant was not added"
/// and "the grant was already held" are different outcomes and a caller writing
/// a registry file must be able to tell them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooManyGrants;

impl fmt::Display for TooManyGrants {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a person may hold at most {MAX_GRANTS} capabilities")
    }
}

impl std::error::Error for TooManyGrants {}

/// The capabilities one identity has been granted.
///
/// A set, kept as an ordered list because it is small, it is written to a file
/// that should be diffable, and the console renders it. Holding a capability is
/// not the same as being granted it: [`Grants::holds`] applies the three
/// implications documented there.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Grants(Vec<Capability>);

impl Grants {
    /// The empty grant set: an identity that may do nothing at all.
    ///
    /// This is what a person not in the registry gets, and what a person in the
    /// registry with no toggles turned on gets. Both then receive the same
    /// uninformative 401 as an anonymous caller, which is the point — being
    /// known to the deployment must not be observable from outside it.
    pub fn none() -> Self {
        Self(Vec::new())
    }

    /// Builds a grant set, dropping duplicates and refusing beyond
    /// [`MAX_GRANTS`].
    ///
    /// A repeated capability is not an error here — this is the constructor a
    /// registry file and a console request go through, and "granted twice"
    /// describes the same authority as "granted once". Overflowing the cap *is*
    /// an error, because silently dropping the tail would store a grant set
    /// that differs from the one that was asked for.
    pub fn new(capabilities: impl IntoIterator<Item = Capability>) -> Result<Self, TooManyGrants> {
        let mut grants = Self::none();
        for capability in capabilities {
            grants.grant(capability)?;
        }
        Ok(grants)
    }

    /// Adds one capability, saying whether it was already held.
    ///
    /// The distinction matters to the console: a toggle that was already on and
    /// a toggle that has just been turned on are different things to report, and
    /// only one of them is worth an audit line. At capacity the set is left
    /// exactly as it was — a grant list that dropped its oldest entry to make
    /// room would revoke a capability nobody asked to revoke.
    pub fn grant(&mut self, capability: Capability) -> Result<Granted, TooManyGrants> {
        if self.0.contains(&capability) {
            return Ok(Granted::AlreadyHeld);
        }
        if self.0.len() >= MAX_GRANTS {
            return Err(TooManyGrants);
        }
        self.0.push(capability);
        Ok(Granted::Added)
    }

    /// Removes one capability; `true` if it was there.
    pub fn revoke(&mut self, capability: &Capability) -> bool {
        let before = self.0.len();
        self.0.retain(|held| held != capability);
        self.0.len() != before
    }

    /// Whether this set satisfies a request for `want`.
    ///
    /// An exact grant always satisfies. Beyond that there are exactly three
    /// implications, and each one exists because the broader capability
    /// genuinely contains the narrower one's effect:
    ///
    /// - [`Capability::FilesAdmin`] satisfies any file capability on any share.
    ///   Administering storage means administering the shares in it; a storage
    ///   administrator who had to be granted each share individually would be
    ///   one forgotten share away from a permission bug.
    /// - [`Capability::FilesWrite`] satisfies [`Capability::FilesRead`] on the
    ///   *same* share, mirroring the `mode = "read" | "write" | "admin"` ladder
    ///   the share configuration already exposes to operators. A write-only
    ///   drop box is therefore not expressible, which is a deliberate trade: the
    ///   config already promised a ladder, and two vocabularies for one idea is
    ///   worse than a missing corner case.
    /// - [`Capability::DesktopControl`] satisfies [`Capability::DesktopView`] on
    ///   the *same* node. You cannot aim a pointer at a screen you cannot see.
    ///
    /// Everything else is independent, and the omissions are as deliberate as
    /// the inclusions. [`Capability::ServiceControl`] does not imply
    /// [`Capability::ConsoleRead`], because being able to restart a service is
    /// not a reason to be shown every service's logs.
    /// [`Capability::ClipboardRead`] is implied by nothing at all, including
    /// desktop control, because exfiltrating the last thing copied on a machine
    /// is a separate decision from driving it. And [`Capability::NodeAdmin`]
    /// implies no power over the nodes it administers: managing a list of
    /// machines and sitting at one of them are different jobs.
    ///
    /// The three configuration capabilities — [`Capability::SiteAdmin`],
    /// [`Capability::DnsAdmin`] and [`Capability::MailAdmin`] — imply nothing and
    /// are implied by nothing, including each other, and that is the whole reason
    /// there are three of them rather than one `ConfigAdmin`. They are adjacent
    /// in an obvious way and independent in the way that matters: adding a
    /// mailbox creates an identity that can receive password resets, adding a DNS
    /// record can move a domain and can satisfy an ACME challenge for it, and
    /// adding a site changes what this box answers for. Somebody who should be
    /// able to do one of those is very often somebody who should not be able to
    /// do the other two.
    pub fn holds(&self, want: &Capability) -> bool {
        self.0.iter().any(|held| satisfies(held, want))
    }

    /// The granted capabilities, in the order they were granted.
    pub fn iter(&self) -> impl Iterator<Item = &Capability> {
        self.0.iter()
    }

    /// How many capabilities are granted.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether nothing is granted.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// What adding a capability to a grant set actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granted {
    /// The capability was not held and now is.
    Added,
    /// The capability was already held; the set is unchanged.
    AlreadyHeld,
}

/// Whether one held capability satisfies a request for another.
///
/// Split out from [`Grants::holds`] so the implication table is one small
/// function that can be read in a sitting and asserted directly.
fn satisfies(held: &Capability, want: &Capability) -> bool {
    if held == want {
        return true;
    }
    match (held, want) {
        (
            Capability::FilesAdmin,
            Capability::FilesRead(_) | Capability::FilesWrite(_) | Capability::FilesAdmin,
        ) => true,
        (Capability::FilesWrite(held), Capability::FilesRead(want)) => held == want,
        (Capability::DesktopControl(held), Capability::DesktopView(want)) => held == want,
        _ => false,
    }
}

/// Everything the policy knows about one request's authority.
///
/// Built once per request by `crates/admin`'s `caller()` seam, from the
/// credential the request presented and the grants the [`People`](crate::People)
/// registry holds for whoever that credential names. It carries no request, no
/// socket and no clock: the freshness rules that a desktop control ticket
/// depends on live with the ticket, not here, because "was this password typed
/// in the last two minutes" is a fact about time and this function must not
/// have one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    identity: Identity,
    credential: Credential,
    grants: Grants,
}

impl Caller {
    /// The caller behind a valid bearer token.
    ///
    /// Always [`Identity::Machine`], with no grant set — the machine's authority
    /// is the fixed list in [`Policy::decide`] rather than anything a registry
    /// could hold, so there is no entry to look up and none to be edited. One of
    /// the named constructors that make the reachable pairs the easy thing to
    /// write.
    pub fn bearer() -> Self {
        Self::new(Identity::Machine, Credential::Bearer, Grants::none())
    }

    /// The caller behind the console password, presented on this request.
    ///
    /// Not what a login through the console form produces — that mints a
    /// session and this credential never reaches a capability check. This is
    /// the storage subsystem's WebDAV HTTP Basic caller, which is why the
    /// policy treats it as unattended.
    pub fn password() -> Self {
        Self::new(Identity::Owner, Credential::Password, Grants::none())
    }

    /// The caller behind a verified passkey assertion presented on this request.
    ///
    /// The identity is whoever the passkey was registered to — which may be the
    /// owner, since the owner registers passkeys too — and the grants are that
    /// identity's, looked up before this call so the decision stays pure.
    pub fn passkey(identity: Identity, grants: Grants) -> Self {
        Self::new(identity, Credential::Passkey, grants)
    }

    /// The caller behind a live session cookie.
    ///
    /// The constructor nearly every authenticated request in this deployment
    /// goes through, and the reason [`Credential::Session`] exists: without it
    /// the seam that builds a `Caller` from a cookie-borne request would have to
    /// claim a passkey signed something a cookie carried.
    pub fn session(identity: Identity, session: Session, grants: Grants) -> Self {
        Self::new(identity, Credential::Session(session), grants)
    }

    /// Any combination at all, including the ones the wiring cannot produce.
    ///
    /// Exists so the policy's test table can sweep every
    /// (identity, credential, capability) triple rather than only the reachable
    /// ones. Production code should reach for the four named constructors
    /// above; this one is what proves the unreachable pairs still fail closed.
    pub fn new(identity: Identity, credential: Credential, grants: Grants) -> Self {
        Self { identity, credential, grants }
    }

    /// Who the caller is.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// How they proved it.
    pub fn credential(&self) -> Credential {
        self.credential
    }

    /// What they have been granted. Not consulted for the owner.
    pub fn grants(&self) -> &Grants {
        &self.grants
    }
}

/// Why a capability was refused.
///
/// Never sent to a caller: the API answers one uninformative 401 to every
/// refusal, so that probing a route teaches nothing about what exists behind
/// it. This enum exists for the audit log and for tests, which are the two
/// readers entitled to know the difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The identity holds no grant covering the capability.
    NotGranted,
    /// The credential is one software replays rather than a person presents
    /// (the bearer token, or the console password on a WebDAV mount), the
    /// capability drives the machine, and `[desktop].bearer_may_control` is not
    /// set.
    CredentialNotArmed,
    /// The credential presented cannot stand for the identity presenting it —
    /// a person holding the console password, the owner holding the box's own
    /// token — a pair the wiring should never produce. See
    /// [`Credential::belongs_to`].
    CredentialIsNotThisIdentitys,
    /// The bearer token asked for something outside the machine's list: the
    /// storage subsystem's administration, the peer registry, or one of the
    /// three powers that rewrite the deployment's own description.
    OutsideTheMachinesScope,
    /// A console password login asked for something above reading, on a
    /// deployment that already has a credential naming a person.
    ///
    /// Not a lockout: the same session may still read the console and enrol a
    /// passkey, which is the recovery path when the naming credential is the one
    /// that was lost.
    CredentialNamesNobody,
}

impl Refusal {
    /// The word the audit log uses for this refusal.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotGranted => "not-granted",
            Self::CredentialNotArmed => "credential-not-armed",
            Self::CredentialIsNotThisIdentitys => "credential-is-not-this-identitys",
            Self::OutsideTheMachinesScope => "outside-the-machines-scope",
            Self::CredentialNamesNobody => "credential-names-nobody",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The answer to one authorisation question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The capability is granted.
    Allow,
    /// The capability is refused, for the stated reason.
    Refuse(Refusal),
}

impl Decision {
    /// Whether the capability was granted.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// The word the audit log uses for the outcome, without the reason.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Refuse(_) => "refuse",
        }
    }

    /// Why it was refused, if it was.
    pub fn refusal(&self) -> Option<Refusal> {
        match self {
            Self::Allow => None,
            Self::Refuse(reason) => Some(*reason),
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Refuse(reason) => write!(f, "refuse ({reason})"),
        }
    }
}

/// The deployment-wide facts the decision depends on.
///
/// Two, and they are different kinds of thing. `unattended_may_control` is a
/// *setting*: the operator wrote `[desktop].bearer_may_control` in a file.
/// `a_passkey_is_enrolled` is a *fact about the deployment right now*, read from
/// the passkey store by the seam that builds this value, and it is a fact rather
/// than a setting on purpose — a switch whose permissive side is the default is
/// a documented insecure mode that nobody ever turns off, while a fact resolves
/// itself the moment the deployment has a credential worth the name.
///
/// The other switches the desktop subsystem has — `[desktop].enabled`,
/// `allow_input`, `allow_clipboard` — decide whether the subsystem exists at
/// all: whether an agent is spawned and whether a route is served. Those are
/// facts about the deployment's shape, enforced where the route is mounted, and
/// folding them in here would mean a capability check that answers "refused"
/// for a route that is not there, which is a second, quieter place for the two
/// answers to disagree. This struct holds only what changes *who may do a thing
/// that is being served*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    unattended_may_control: bool,
    a_passkey_is_enrolled: bool,
}

impl Policy {
    /// A freshly installed deployment: nothing armed, and no passkey enrolled
    /// yet, so the console password is still the only way in and is still the
    /// owner.
    ///
    /// The name says locked down and the passkey fact says "the password is
    /// root", which reads like a contradiction until you notice which of the two
    /// is a permission. Arming is a permission and it defaults off. Whether a
    /// passkey exists is not a permission at all; it is something this
    /// deployment either has or has not got, and the honest default for a value
    /// nobody has read out of the store is what a box with no store looks like.
    /// Defaulting it the other way would refuse the installer their own console
    /// on every deployment that never wired passkeys at all.
    pub fn locked_down() -> Self {
        Self { unattended_may_control: false, a_passkey_is_enrolled: false }
    }

    /// The same policy, told whether this deployment has a passkey enrolled.
    ///
    /// Composed per request rather than once at start-up, because the answer
    /// changes the moment somebody finishes a registration ceremony and a policy
    /// built at boot would still be calling the console password root an hour
    /// later. Cheap to do: this type is `Copy` and the store answers from
    /// memory.
    pub fn with_passkey_enrolled(mut self, enrolled: bool) -> Self {
        self.a_passkey_is_enrolled = enrolled;
        self
    }

    /// Whether this deployment has at least one credential that names a person.
    pub fn a_passkey_is_enrolled(&self) -> bool {
        self.a_passkey_is_enrolled
    }

    /// A policy with `[desktop].bearer_may_control` set as the operator asked.
    ///
    /// The config key names the credential operators think of; the field names
    /// the rule, which covers every credential software replays rather than a
    /// person presents — see [`Credential::is_unattended`]. Taking the flag as a
    /// constructor argument rather than reading config here is what keeps this
    /// crate below `selfhost-config` in the dependency graph and keeps
    /// [`Policy::decide`] free of anything that could fail.
    pub fn new(unattended_may_control: bool) -> Self {
        Self::locked_down().armed(unattended_may_control)
    }

    /// The same policy, with the arming switch set as the operator asked.
    ///
    /// Kept beside [`Policy::with_passkey_enrolled`] so the two facts are set the
    /// same way, and so [`Policy::new`] is one line that cannot disagree with
    /// [`Policy::locked_down`] about what the other field starts at.
    fn armed(mut self, unattended_may_control: bool) -> Self {
        self.unattended_may_control = unattended_may_control;
        self
    }

    /// Whether unattended credentials have been armed to drive a machine.
    pub fn unattended_may_control(&self) -> bool {
        self.unattended_may_control
    }

    /// Decides whether `caller` may exercise `want`.
    ///
    /// Pure, total, and the whole authorisation model. The order of the checks
    /// is the order of the argument:
    ///
    /// 1. A credential that cannot stand for the identity presenting it is
    ///    incoherent and is refused before anything else is considered.
    /// 2. An unattended credential is refused the capabilities that drive a
    ///    machine unless the operator armed it. This is checked before every
    ///    allow below, because it is precisely a limit *on* the owner.
    /// 3. The bearer token holds the machine's fixed list and nothing else.
    /// 4. A console password login holds [`Capability::ConsoleRead`] and nothing
    ///    else, once this deployment has a credential that names somebody.
    /// 5. The owner may do everything else, with their grant set never
    ///    consulted, so no grant list can lock the operator out of their box.
    /// 6. Everyone else is decided by their grants, through the three
    ///    implications in [`Grants::holds`].
    ///
    /// Checks 3 and 4 are the two doors the identity audit found standing open,
    /// and they sit *above* the owner's blanket allow for the same reason check
    /// 2 does: each is a limit on what a nameless secret may do, and a limit
    /// written below a blanket allow is a comment.
    ///
    /// Takes `want` by reference: a [`Capability`] owns its target's string,
    /// and a check that ran on every request should not allocate to ask a
    /// question.
    pub fn decide(&self, caller: &Caller, want: &Capability) -> Decision {
        // 1. A name is not a credential. Only a passkey signs for a person, only
        //    the bearer token is this box's automation, and only the console
        //    password is the owner; a `Caller` pairing them any other way means
        //    the code that built it is wrong. Fail closed.
        if !caller.credential.belongs_to(&caller.identity) {
            return Decision::Refuse(Refusal::CredentialIsNotThisIdentitys);
        }

        // 2. Asymmetry one. A credential software replays — the token in a
        //    file, the password in a WebDAV client's keychain — opens every
        //    existing route and will not open a keyboard: no person is proven
        //    to be there, and both skip every browser-side defence at once.
        //    Armed only by an explicit `[desktop].bearer_may_control` in config.
        //    Keyed on the property, not on a variant: the last time this was a
        //    variant check, the credential most replayed by software was the one
        //    it did not name.
        if caller.credential.is_unattended()
            && want.drives_a_machine()
            && !self.unattended_may_control
        {
            return Decision::Refuse(Refusal::CredentialNotArmed);
        }

        // 3. The machine's list. Fixed rather than granted: there is no registry
        //    entry for a token, so there is nothing to look up and nothing an
        //    edited file could widen. See `the_machine_may_operate_the_box`.
        if caller.identity.is_machine() {
            return if the_machine_may(want) {
                Decision::Allow
            } else {
                Decision::Refuse(Refusal::OutsideTheMachinesScope)
            };
        }

        // 4. The console password, demoted the moment this deployment has a
        //    credential that names a person. Reading stays open so the operator
        //    can still see the box; everything that changes it needs a name.
        //    Enrolling a passkey is not a capability and is not decided here —
        //    `crates/admin`'s demand check owns it — which is what keeps this
        //    from being a lockout when the enrolled device is the lost one.
        if self.a_passkey_is_enrolled && caller.credential.is_a_password_login() {
            return if matches!(want, Capability::ConsoleRead) {
                Decision::Allow
            } else {
                Decision::Refuse(Refusal::CredentialNamesNobody)
            };
        }

        // 5. Asymmetry two. The owner's grants are not read, so there is no
        //    grant list — corrupt, empty, or maliciously edited — that can
        //    revoke the operator's authority over their own deployment.
        if caller.identity.is_owner() {
            return Decision::Allow;
        }

        // 6. Everyone else is exactly what they were granted.
        if caller.grants.holds(want) {
            Decision::Allow
        } else {
            Decision::Refuse(Refusal::NotGranted)
        }
    }
}

/// Whether the bearer token holds `want`.
///
/// The machine's whole authority, as a list rather than a blanket allow. It was
/// derived from the two programs that actually present the token — the CLI in
/// `crates/cli`, and the native console in `crates/ui/console`, whose entire API
/// surface is the paths named in its poller and channel — and it is written as an
/// exhaustive match so that a capability added later cannot join it by
/// forgetting to mention it.
///
/// The five that are withheld are the ones that change *who and what this
/// deployment is* rather than operating it: administering the storage subsystem
/// and its SMB export, administering the peer mesh, and the three that rewrite
/// `selfhost.config.toml` — a site's hostnames and the networks allowed to reach
/// it, a zone's records, a mailbox that can receive somebody's password reset.
/// Nothing holding the token has ever asked for one of them, and a secret that
/// sits in a file readable by one account should not be able to repoint a domain.
///
/// What it keeps is honest about its blast radius rather than flattering:
/// [`Capability::ServiceControl`] installs and starts an arbitrary program on
/// this box, which is more than enough to read the files this list withholds.
/// That is the same trade `refusing_an_unattended_credential_a_keyboard_does_not_
/// refuse_it_the_machine` already records — a narrowing, not a boundary — and it
/// is kept because the alternative is refusing the CLI and the webhook relay the
/// one job they exist for.
fn the_machine_may(want: &Capability) -> bool {
    match want {
        // What the native console reads and drives over its SSH tunnel.
        Capability::ConsoleRead
        | Capability::ServiceControl
        | Capability::FilesRead(_)
        | Capability::FilesWrite(_)
        | Capability::DesktopView(_)
        // Still behind `[desktop].bearer_may_control`, refused above when it is
        // not set. Listed here so that arming the switch means what it says
        // rather than meeting a second, silent refusal underneath it.
        | Capability::DesktopControl(_)
        | Capability::ClipboardRead(_) => true,
        Capability::FilesAdmin
        | Capability::NodeAdmin
        | Capability::SiteAdmin
        | Capability::DnsAdmin
        | Capability::MailAdmin => false,
    }
}

impl Default for Policy {
    /// The locked-down policy. A default that armed anything would be a
    /// permission granted by forgetting to say otherwise.
    fn default() -> Self {
        Self::locked_down()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{NodeName, ShareId};
    use crate::credential::Opening;
    use crate::identity::PersonName;
    use std::time::{Duration, Instant};

    /// The login instant every session in these tests stands for.
    ///
    /// Offset forward so a test may subtract from it: `Instant` is monotonic
    /// from an arbitrary epoch, and `Instant::now() - an_hour` can panic in a
    /// freshly-started container.
    fn login_moment() -> Instant {
        Instant::now() + Duration::from_secs(1_000_000)
    }

    /// A session credential opened by `opening`.
    fn session_of(opening: Opening) -> Credential {
        Credential::Session(Session::new(opening, login_moment()))
    }

    fn share() -> ShareId {
        ShareId::parse("vault").expect("a valid share id")
    }

    fn other_share() -> ShareId {
        ShareId::parse("photos").expect("a valid share id")
    }

    fn node() -> NodeName {
        NodeName::parse("alex-desktop").expect("a valid node name")
    }

    fn other_node() -> NodeName {
        NodeName::parse("home").expect("a valid node name")
    }

    fn person() -> Identity {
        Identity::Person(PersonName::parse("Mom").expect("a valid name"))
    }

    /// Every identity the model has, for the sweep.
    fn every_identity() -> Vec<Identity> {
        vec![Identity::Owner, Identity::Machine, person()]
    }

    /// The five capabilities the bearer token does not hold, written out here
    /// rather than read off [`the_machine_may`] so the sweep is checking the
    /// model against a second statement of the rule and not against itself.
    fn withheld_from_the_machine(want: &Capability) -> bool {
        matches!(
            want,
            Capability::FilesAdmin
                | Capability::NodeAdmin
                | Capability::SiteAdmin
                | Capability::DnsAdmin
                | Capability::MailAdmin
        )
    }

    #[test]
    fn a_configuration_capability_implies_nothing_and_is_implied_by_nothing() {
        // Three grants that are adjacent in an obvious way and independent in the
        // way that matters. The sweep is both directions across all three, plus
        // every other capability, because the failure this prevents is the one
        // nobody sees: a person granted mail administration quietly able to point
        // a hostname somewhere, because one implication was written for tidiness.
        let configuring =
            [Capability::SiteAdmin, Capability::DnsAdmin, Capability::MailAdmin];
        for held in &configuring {
            let grants = Grants::new([held.clone()]).expect("one grant");
            for want in Capability::every_shape(&share(), &node()) {
                assert_eq!(
                    grants.holds(&want),
                    *held == want,
                    "holding {held} must open {want} only if they are the same capability"
                );
            }
        }
        // And nothing else reaches them, including the two existing administrative
        // grants, which are the ones most likely to be assumed to.
        for held in [
            Capability::FilesAdmin,
            Capability::NodeAdmin,
            Capability::ServiceControl,
            Capability::ConsoleRead,
        ] {
            let grants = Grants::new([held.clone()]).expect("one grant");
            for want in &configuring {
                assert!(!grants.holds(want), "{held} must not reach {want}");
            }
        }
    }

    #[test]
    fn an_owner_is_allowed_everything_that_exists_today() {
        // `crates/admin`'s routes as they stand — services, logs, install,
        // uninstall, deploy, firewall state and reconcile — are exactly these
        // two capabilities. Every credential the *owner* can hold still opens
        // both of them on a deployment that has not yet enrolled a passkey,
        // which is the equivalence this model was introduced under and the one
        // that must survive for a box nobody has finished setting up.
        let today = [Capability::ConsoleRead, Capability::ServiceControl];
        let owners = Credential::every_shape(login_moment())
            .into_iter()
            .filter(|credential| credential.belongs_to(&Identity::Owner));
        for credential in owners {
            let caller = Caller::new(Identity::Owner, credential, Grants::none());
            for want in &today {
                assert_eq!(
                    Policy::locked_down().decide(&caller, want),
                    Decision::Allow,
                    "{credential} must open {want} while no passkey is enrolled"
                );
            }
        }
        // And the two places the equivalence is deliberately broken, which are
        // the defect it was preserving. The token is not the operator, and a
        // shared password stops being one the moment a real credential exists.
        assert_eq!(
            Policy::locked_down()
                .decide(&Caller::new(Identity::Owner, Credential::Bearer, Grants::none()), &Capability::ConsoleRead),
            Decision::Refuse(Refusal::CredentialIsNotThisIdentitys),
            "the bearer token names the machine; it can no longer wear the owner"
        );
        let enrolled = Policy::locked_down().with_passkey_enrolled(true);
        let logged_in = Caller::new(Identity::Owner, session_of(Opening::Password), Grants::none());
        assert_eq!(enrolled.decide(&logged_in, &Capability::ConsoleRead), Decision::Allow);
        assert_eq!(
            enrolled.decide(&logged_in, &Capability::ServiceControl),
            Decision::Refuse(Refusal::CredentialNamesNobody)
        );
    }

    #[test]
    fn the_machine_may_operate_the_box_and_may_not_decide_what_it_is() {
        // The bearer token's whole authority, from both sides. What it keeps is
        // what the CLI and the native console actually call over the SSH tunnel;
        // what it loses is the five that change who and what this deployment is.
        // Swept under both policies, because neither the arming switch nor the
        // passkey fact has anything to say about this credential.
        for policy in [Policy::locked_down(), Policy::new(true).with_passkey_enrolled(true)] {
            for want in Capability::every_shape(&share(), &node()) {
                let expected = if withheld_from_the_machine(&want) {
                    Decision::Refuse(Refusal::OutsideTheMachinesScope)
                } else if want.drives_a_machine() && !policy.unattended_may_control() {
                    // Arming still comes first: it is a limit on the same
                    // credential for a different reason.
                    Decision::Refuse(Refusal::CredentialNotArmed)
                } else {
                    Decision::Allow
                };
                assert_eq!(policy.decide(&Caller::bearer(), &want), expected, "{want}");
            }
        }
        // A grant set cannot widen it: there is no registry entry for a token,
        // and a hand-edited one naming the machine must buy nothing.
        let everything = Grants::new(Capability::every_shape(&share(), &node())).unwrap();
        let forged = Caller::new(Identity::Machine, Credential::Bearer, everything);
        assert_eq!(
            Policy::new(true).decide(&forged, &Capability::SiteAdmin),
            Decision::Refuse(Refusal::OutsideTheMachinesScope),
            "the machine's list is fixed, not granted"
        );
    }

    #[test]
    fn the_console_password_stops_being_root_when_a_real_credential_exists() {
        // The rule that resolves itself. A fresh box has no passkey and the
        // password is the only way in, so it is the owner; the moment one
        // passkey exists the same login holds `ConsoleRead` and nothing else.
        let logged_in = Caller::new(Identity::Owner, session_of(Opening::Password), Grants::none());
        let fresh = Policy::locked_down();
        let enrolled = fresh.with_passkey_enrolled(true);
        for want in Capability::every_shape(&share(), &node()) {
            // Everything, including the keyboard: a cookie is not unattended,
            // so how recently a person proved themselves is the freshness rule's
            // question and is answered at the ticket rather than here.
            assert_eq!(
                fresh.decide(&logged_in, &want),
                Decision::Allow,
                "no passkey yet, so the password is still the only way in: {want}"
            );

            let after = if matches!(want, Capability::ConsoleRead) {
                Decision::Allow
            } else {
                Decision::Refuse(Refusal::CredentialNamesNobody)
            };
            assert_eq!(enrolled.decide(&logged_in, &want), after, "a passkey exists: {want}");
        }
    }

    #[test]
    fn the_credential_that_names_a_person_is_untouched_by_the_demotion() {
        // The other half of the recovery argument: enrolling a passkey is what
        // gets the operator their box back, so the passkey and the session it
        // opens must be exactly as authoritative as before. The owner's own
        // passkey answers for everything; a person's answers for their grants.
        let enrolled = Policy::locked_down().with_passkey_enrolled(true);
        let by_passkey =
            Caller::new(Identity::Owner, session_of(Opening::Passkey), Grants::none());
        for want in Capability::every_shape(&share(), &node()) {
            assert_eq!(enrolled.decide(&by_passkey, &want), Decision::Allow, "{want}");
            assert_eq!(
                enrolled.decide(&Caller::passkey(Identity::Owner, Grants::none()), &want),
                Decision::Allow,
                "{want}"
            );
        }
        // And the WebDAV mount's credential is deliberately not the one that was
        // demoted: `is_a_password_login` is narrower than "names nobody", so a
        // Finder mount does not go dark the instant a passkey is registered.
        assert_eq!(
            enrolled.decide(&Caller::password(), &Capability::FilesWrite(share())),
            Decision::Allow,
            "the mount credential is a knowingly separate door; see Credential::is_a_password_login"
        );
    }

    #[test]
    fn the_owners_authority_survives_an_empty_or_hostile_grant_set() {
        // Asymmetry two: the grant set is not consulted for the owner, so no
        // registry state can lock the operator out of their own console.
        let stripped = Caller::new(Identity::Owner, Credential::Passkey, Grants::none());
        for want in Capability::every_shape(&share(), &node()) {
            assert_eq!(
                Policy::locked_down().decide(&stripped, &want),
                Decision::Allow,
                "{want} must stay open to the owner"
            );
        }
    }

    #[test]
    fn an_unattended_credential_may_not_drive_a_machine_until_it_is_armed() {
        // Asymmetry one, stated from both sides, and over *both* unattended
        // credentials rather than the one enum variant an earlier revision
        // named. `Caller::password()` is the WebDAV HTTP Basic caller — a
        // secret an operating system's keychain replays on every request for
        // the life of a mount, and therefore the most unattended credential
        // this deployment has.
        let locked = Policy::locked_down();
        let armed = Policy::new(true);
        for unattended in [Caller::bearer(), Caller::password()] {
            // The bearer token also has the machine's list under it, and the
            // five capabilities that list withholds are refused for that reason
            // whether or not the keyboard is armed. This rule is about the other
            // seven, and the two credentials answer identically across them.
            let machine = unattended.identity().is_machine();
            for want in Capability::every_shape(&share(), &node()) {
                if machine && withheld_from_the_machine(&want) {
                    continue;
                }
                let expected = if want.drives_a_machine() {
                    Decision::Refuse(Refusal::CredentialNotArmed)
                } else {
                    Decision::Allow
                };
                assert_eq!(
                    locked.decide(&unattended, &want),
                    expected,
                    "locked down: {} wanting {want}",
                    unattended.credential()
                );
                assert_eq!(
                    armed.decide(&unattended, &want),
                    Decision::Allow,
                    "armed: {} wanting {want}",
                    unattended.credential()
                );
            }
        }
        // The arming is about the credential, not the identity: the owner at a
        // browser, holding a passkey, drives the machine either way — and so
        // does the owner's browser holding the cookie that passkey opened,
        // because how recently they proved themselves is the freshness rule's
        // question and it is answered at the ticket, with a clock.
        let at_the_keyboard = Caller::passkey(Identity::Owner, Grants::none());
        assert_eq!(locked.decide(&at_the_keyboard, &Capability::DesktopControl(node())), Decision::Allow);
        for opening in Opening::EVERY {
            let cookie = Caller::new(Identity::Owner, session_of(opening), Grants::none());
            assert_eq!(
                locked.decide(&cookie, &Capability::ClipboardRead(node())),
                Decision::Allow,
                "a session opened by {opening} is decided on recency, not here"
            );
        }
    }

    #[test]
    fn a_person_holding_a_deployment_credential_is_refused_before_anything_else() {
        for credential in
            [Credential::Bearer, Credential::Password, session_of(Opening::Password)]
        {
            // Even fully granted, and even with the bearer armed: the pair is
            // incoherent and the refusal comes first.
            let grants = Grants::new(Capability::every_shape(&share(), &node())).unwrap();
            let caller = Caller::new(person(), credential, grants);
            for want in Capability::every_shape(&share(), &node()) {
                assert_eq!(
                    Policy::new(true).decide(&caller, &want),
                    Decision::Refuse(Refusal::CredentialIsNotThisIdentitys),
                    "{credential} may not name a person, wanting {want}"
                );
            }
        }
    }

    #[test]
    fn the_two_deployment_credentials_may_not_wear_each_others_identity() {
        // The pair that used to be legal and was the defect: the bearer token
        // presenting as the owner. It is now as incoherent as a person holding
        // the console password, and it is refused first — before the machine's
        // list, before the demotion, before any grant.
        let wrong = [
            (Identity::Owner, Credential::Bearer),
            (Identity::Machine, Credential::Password),
            (Identity::Machine, session_of(Opening::Password)),
            (Identity::Machine, session_of(Opening::Passkey)),
            (Identity::Machine, Credential::Passkey),
        ];
        for (identity, credential) in wrong {
            let caller = Caller::new(identity.clone(), credential, Grants::none());
            assert_eq!(
                Policy::new(true).decide(&caller, &Capability::ConsoleRead),
                Decision::Refuse(Refusal::CredentialIsNotThisIdentitys),
                "{identity} may not present {credential}"
            );
        }
    }

    #[test]
    fn a_person_with_no_grants_is_refused_everything() {
        let caller = Caller::passkey(person(), Grants::none());
        for want in Capability::every_shape(&share(), &node()) {
            assert_eq!(
                Policy::new(true).decide(&caller, &want),
                Decision::Refuse(Refusal::NotGranted),
                "{want}"
            );
        }
    }

    #[test]
    fn a_person_holds_exactly_what_they_were_granted_and_what_it_implies() {
        let shapes = Capability::every_shape(&share(), &node());
        for granted in &shapes {
            let caller =
                Caller::passkey(person(), Grants::new([granted.clone()]).expect("one grant"));
            for want in &shapes {
                let expected = if satisfies(granted, want) {
                    Decision::Allow
                } else {
                    Decision::Refuse(Refusal::NotGranted)
                };
                assert_eq!(
                    Policy::new(true).decide(&caller, want),
                    expected,
                    "holding {granted}, wanting {want}"
                );
            }
        }
    }

    #[test]
    fn the_three_implications_are_exactly_these_and_no_others() {
        let admin = Grants::new([Capability::FilesAdmin]).unwrap();
        assert!(admin.holds(&Capability::FilesRead(other_share())), "admin covers every share");
        assert!(admin.holds(&Capability::FilesWrite(other_share())));
        assert!(!admin.holds(&Capability::DesktopView(node())), "storage is not the desktop");

        let write = Grants::new([Capability::FilesWrite(share())]).unwrap();
        assert!(write.holds(&Capability::FilesRead(share())), "the read|write|admin ladder");
        assert!(!write.holds(&Capability::FilesRead(other_share())), "one share only");
        assert!(!write.holds(&Capability::FilesAdmin), "writing is not administering");

        let control = Grants::new([Capability::DesktopControl(node())]).unwrap();
        assert!(control.holds(&Capability::DesktopView(node())), "you must see what you drive");
        assert!(!control.holds(&Capability::DesktopView(other_node())), "one node only");
        assert!(!control.holds(&Capability::ClipboardRead(node())), "the clipboard is separate");

        let view = Grants::new([Capability::DesktopView(node())]).unwrap();
        assert!(!view.holds(&Capability::DesktopControl(node())), "watching is never driving");

        let services = Grants::new([Capability::ServiceControl]).unwrap();
        assert!(!services.holds(&Capability::ConsoleRead), "no implication was invented");

        let nodes = Grants::new([Capability::NodeAdmin]).unwrap();
        assert!(!nodes.holds(&Capability::DesktopView(node())), "listing nodes is not sitting at one");
    }

    #[test]
    fn every_identity_credential_capability_triple_has_a_stated_outcome() {
        // The exhaustive sweep. It asserts the model against an independently
        // written expectation rather than against itself: if `decide` grows a
        // rule that this table does not describe, the sweep fails.
        let shapes = Capability::every_shape(&share(), &node());
        let full = Grants::new(shapes.clone()).expect("every shape fits under the cap");
        let policies = [
            Policy::locked_down(),
            Policy::new(true),
            Policy::locked_down().with_passkey_enrolled(true),
            Policy::new(true).with_passkey_enrolled(true),
        ];
        for policy in policies {
            for identity in every_identity() {
                for credential in Credential::every_shape(login_moment()) {
                    for grants in [Grants::none(), full.clone()] {
                        let caller = Caller::new(identity.clone(), credential, grants.clone());
                        for want in &shapes {
                            let expected = if !credential.belongs_to(&identity) {
                                Decision::Refuse(Refusal::CredentialIsNotThisIdentitys)
                            } else if credential.is_unattended()
                                && want.drives_a_machine()
                                && !policy.unattended_may_control()
                            {
                                Decision::Refuse(Refusal::CredentialNotArmed)
                            // The box's own token: a fixed list, which no grant
                            // set widens and no switch here touches.
                            } else if identity.is_machine() {
                                if withheld_from_the_machine(want) {
                                    Decision::Refuse(Refusal::OutsideTheMachinesScope)
                                } else {
                                    Decision::Allow
                                }
                            // The console password, once this deployment has a
                            // credential that names somebody: reading, and
                            // nothing that changes the box.
                            } else if policy.a_passkey_is_enrolled()
                                && credential.is_a_password_login()
                            {
                                if matches!(want, Capability::ConsoleRead) {
                                    Decision::Allow
                                } else {
                                    Decision::Refuse(Refusal::CredentialNamesNobody)
                                }
                            // Two distinct reasons for the same answer: the
                            // owner's authority is unconditional, and everyone
                            // else's is exactly their grants.
                            } else if identity.is_owner() || grants.holds(want) {
                                Decision::Allow
                            } else {
                                Decision::Refuse(Refusal::NotGranted)
                            };
                            assert_eq!(
                                policy.decide(&caller, want),
                                expected,
                                "identity {identity}, credential {credential}, \
                                 grants {}, want {want}, armed {}, passkey enrolled {}",
                                grants.len(),
                                policy.unattended_may_control(),
                                policy.a_passkey_is_enrolled()
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn a_grant_set_is_a_set_and_is_bounded() {
        let mut grants = Grants::none();
        assert!(grants.is_empty());
        assert_eq!(grants.grant(Capability::ConsoleRead), Ok(Granted::Added));
        assert_eq!(
            grants.grant(Capability::ConsoleRead),
            Ok(Granted::AlreadyHeld),
            "a set, not a list"
        );
        assert_eq!(grants.len(), 1);
        assert!(grants.revoke(&Capability::ConsoleRead));
        assert!(!grants.revoke(&Capability::ConsoleRead), "revoking twice changes nothing");
        assert!(grants.is_empty());

        // The cap holds, and hitting it never silently drops what was already
        // granted.
        let mut full = Grants::none();
        for index in 0..MAX_GRANTS {
            let share = ShareId::parse(&format!("s{index}")).expect("a valid share id");
            full.grant(Capability::FilesRead(share)).expect("under the cap");
        }
        assert_eq!(full.len(), MAX_GRANTS);
        let overflow = ShareId::parse("one-too-many").unwrap();
        assert_eq!(full.grant(Capability::FilesRead(overflow)), Err(TooManyGrants));
        assert_eq!(full.len(), MAX_GRANTS, "nothing was evicted to make room");
        assert!(full.holds(&Capability::FilesRead(ShareId::parse("s0").unwrap())));
        // The same cap through the bulk constructor, which must refuse rather
        // than truncate.
        let too_many: Vec<Capability> = (0..=MAX_GRANTS)
            .map(|index| {
                Capability::FilesRead(ShareId::parse(&format!("s{index}")).expect("valid"))
            })
            .collect();
        assert_eq!(Grants::new(too_many), Err(TooManyGrants));
    }

    #[test]
    fn a_caller_reports_what_it_was_built_from() {
        let caller = Caller::passkey(person(), Grants::new([Capability::ConsoleRead]).unwrap());
        assert_eq!(caller.identity(), &person());
        assert_eq!(caller.credential(), Credential::Passkey);
        assert_eq!(caller.grants().len(), 1);
        assert_eq!(Caller::bearer().credential(), Credential::Bearer);
        assert_eq!(Caller::bearer().identity(), &Identity::Machine, "a token is not a person");
        assert_eq!(Caller::password().identity(), &Identity::Owner);
    }

    #[test]
    fn a_decision_reports_its_outcome_and_reason() {
        assert!(Decision::Allow.is_allowed());
        assert_eq!(Decision::Allow.refusal(), None);
        assert_eq!(Decision::Allow.as_str(), "allow");
        let refused = Decision::Refuse(Refusal::NotGranted);
        assert!(!refused.is_allowed());
        assert_eq!(refused.refusal(), Some(Refusal::NotGranted));
        assert_eq!(refused.as_str(), "refuse");
        assert_eq!(refused.to_string(), "refuse (not-granted)");
    }

    #[test]
    fn the_default_policy_is_the_locked_down_one() {
        assert_eq!(Policy::default(), Policy::locked_down());
        assert!(!Policy::default().unattended_may_control());
        // Not a permission and so not defaulted for safety: this is what a box
        // with no passkey store looks like, and reading it the other way would
        // refuse the installer their own console on every deployment that never
        // wired passkeys at all.
        assert!(!Policy::default().a_passkey_is_enrolled());
        assert!(!Policy::new(true).a_passkey_is_enrolled(), "one constructor, one default");
    }

    // -----------------------------------------------------------------------
    // The adversarial review's findings against this file, each one now stated
    // as the property that holds rather than the gap that did.
    // -----------------------------------------------------------------------

    #[test]
    fn the_password_a_webdav_mount_replays_is_refused_the_keyboard_exactly_as_the_token_is() {
        // The finding: asymmetry one was written as a rule about *unattended*
        // credentials and implemented as a rule about one enum variant, so the
        // console password — the credential the storage design puts on WebDAV
        // HTTP Basic, which Finder and Explorer keep in a keychain and replay on
        // every request for the life of a mount — was armed for the keyboard
        // while the token in a root-owned file was not.
        let locked = Policy::locked_down();
        for want in [Capability::DesktopControl(node()), Capability::ClipboardRead(node())] {
            for unattended in [Caller::bearer(), Caller::password()] {
                assert_eq!(
                    locked.decide(&unattended, &want),
                    Decision::Refuse(Refusal::CredentialNotArmed),
                    "{} must be refused {want}",
                    unattended.credential()
                );
            }
        }
    }

    #[test]
    fn refusing_an_unattended_credential_a_keyboard_does_not_refuse_it_the_machine() {
        // Recorded rather than fixed, and deliberately so. The prose separates
        // the bearer token from "a keyboard at the console user's integrity
        // level" by a switch that defaults to off. The same token, under the
        // same locked-down policy, holds `ServiceControl` — which in
        // `crates/admin` is `PUT /api/services/<name>`: install an arbitrary
        // program and start it, unattended, on this box.
        //
        // The asymmetry is worth keeping — it is a real narrowing of one blast
        // radius — but it is a speed bump on a path that is already open, not a
        // boundary. Closing it would mean refusing the webhook relay and the
        // CLI the routes they exist to drive, which is a different decision from
        // the one this rule makes, and it belongs to whoever decides that
        // automation should not be able to install services.
        let bearer = Caller::bearer();
        let locked = Policy::locked_down();
        assert_eq!(
            locked.decide(&bearer, &Capability::DesktopControl(node())),
            Decision::Refuse(Refusal::CredentialNotArmed)
        );
        assert_eq!(locked.decide(&bearer, &Capability::ServiceControl), Decision::Allow);
        assert_eq!(locked.decide(&bearer, &Capability::FilesWrite(share())), Decision::Allow);
    }

    #[test]
    fn a_request_that_carried_only_a_cookie_is_expressible_and_carries_its_login() {
        // The finding: every request after a login carries a session cookie and
        // nothing else, `Credential` had no variant for that, and check 1 refuses
        // a person holding any deployment-wide variant — so the only
        // representable credential for a person was `Passkey`, and the seam that
        // builds a `Caller` from a cookie-borne request had no honest choice but
        // to claim a passkey signed a request it did not sign.
        let opened = login_moment();
        let session = Session::new(Opening::Passkey, opened);
        let grants = Grants::new([Capability::DesktopControl(node())]).expect("one grant");
        let caller = Caller::session(person(), session, grants);

        // The pair is now reachable, and it is decided by grants rather than
        // refused as incoherent.
        assert_eq!(caller.credential(), Credential::Session(session));
        assert_eq!(
            Policy::locked_down().decide(&caller, &Capability::DesktopControl(node())),
            Decision::Allow
        );
        assert_eq!(
            Policy::locked_down().decide(&caller, &Capability::FilesAdmin),
            Decision::Refuse(Refusal::NotGranted)
        );

        // And the credential carries what the freshness rule needs: when the
        // person last proved themselves, and by what. This function has no clock
        // and does not weigh it; the value is here so the rule that does can be
        // written without inventing one.
        let Credential::Session(carried) = caller.credential() else {
            panic!("a session caller must carry its session");
        };
        assert_eq!(carried.opened_by, Opening::Passkey);
        assert_eq!(carried.age(opened + Duration::from_secs(43_200)), Duration::from_secs(43_200));

        // The password's session still names nobody, so a person cannot wear it.
        assert_eq!(
            Policy::new(true).decide(
                &Caller::new(person(), session_of(Opening::Password), Grants::none()),
                &Capability::ConsoleRead
            ),
            Decision::Refuse(Refusal::CredentialIsNotThisIdentitys),
            "there is one console password; a session it opened cannot name a person"
        );
    }
}
