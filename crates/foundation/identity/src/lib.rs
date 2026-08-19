//! Who the caller is, and what they may do.
//!
//! # Why this is a crate of its own, sitting underneath everything
//!
//! This deployment has always had exactly one answer to "may you?", and the
//! answer was a boolean: `Api::authorised(&request)` in `crates/admin` returns
//! true for a valid bearer token or a live session cookie, and true opens every
//! route there is. That was honest while every route *served data* — a service
//! list, a log tail, a firewall's state. It stops being honest the moment a
//! route can drive the machine: watching a screen, typing on a keyboard, and
//! writing files into a share are not the same power as reading a log, and a
//! boolean cannot say so.
//!
//! The model that replaces the boolean lives here rather than in `crates/admin`
//! for one structural reason. `crates/admin` is the crate that *routes* to the
//! subsystems; the storage subsystem and the desktop subsystem need to ask "may
//! this caller do this?" without depending on the thing that dispatches to them,
//! or the dependency graph acquires a cycle and the answer to an authorisation
//! question ends up living in whichever crate happened to ask it first. So
//! `selfhost-identity` sits below all of them, links nothing but
//! `selfhost-json` and `ring`, and is the single place the question is answered.
//!
//! # The shape
//!
//! Four ideas, deliberately kept apart, and one function that joins them:
//!
//! - [`identity`] — **who**. [`Identity`] is `Owner`, `Machine` or
//!   `Person(PersonName)`, and `PersonName` is a validated newtype. This is
//!   where the magic string `"owner"` stops being a `const` duplicated across
//!   crates and starts being a variant that a name cannot be spelled into.
//!   `Machine` is the box's own bearer token, which used to answer `Owner` and
//!   so made an unattended webhook indistinguishable from the operator.
//! - [`credential`] — **how they proved it**. [`Credential`] is `Bearer`,
//!   `Password`, `Passkey` or `Session`, and it is *not* folded into the
//!   identity, because three of the four are the deployment's own root
//!   credentials rather than any person's, and the policy needs to be able to
//!   say "this is the owner, and nevertheless this request may not drive a
//!   mouse". `Session` is the one nearly every authenticated request actually
//!   presents, and it carries the login it stands for — when, and by what — so
//!   the desktop's freshness rule can be handed a fact rather than a guess.
//! - [`capability`] — **what**. [`Capability`] is a closed enum whose variants
//!   carry validated targets, so a power is checkable by the compiler and a
//!   forgotten one is a build error rather than a silent allow.
//! - [`policy`] — **the decision**. [`Policy::decide`] is pure, total, and
//!   exhaustively table-tested over every (identity, credential, capability)
//!   triple. It is the whole authorisation model and it is the most important
//!   function in this crate.
//!
//! Around them sit the two pieces of state and record-keeping the model needs:
//! [`registry`] holds [`People`], the owner-only `console.people` file shaped on
//! `crates/admin`'s passkey store, and [`audit`] holds the append-only record of
//! what was decided, in a format nothing written into it can forge.
//!
//! # What it decides, and the two doors it closed
//!
//! This crate shipped under a rule that it changed no observable behaviour: every
//! real caller was the owner and [`Policy::decide`] allowed the owner everything,
//! bar an unattended token at a keyboard. That was the right way to introduce a
//! model onto routes that had already shipped — and it was also the defect,
//! because "every real caller is the owner" is what two nameless shared secrets
//! resolving to one identity looks like written down. Both are now narrowed, in
//! proportion to what each one is and without a setting to remember:
//!
//! - The **bearer token** is [`Identity::Machine`] with a fixed list of
//!   capabilities — what the CLI and the native console actually call — rather
//!   than the owner's blanket allow.
//! - The **console password** is the owner while no passkey is enrolled, because
//!   it is the only way into a box that has just been installed, and holds
//!   [`Capability::ConsoleRead`] alone from the moment this deployment has a
//!   credential that names a person.
//!
//! Both rules are on [`Policy`], and the second is driven by the deployment's own
//! state rather than by configuration: it resolves itself the moment the box has
//! a real credential, and there is nothing for an operator to remember to turn
//! on. The enrolment that clears it stays open to the password for ever, so the
//! rule cannot lock anybody out of a deployment whose passkey was lost.
//!
//! # Where biometric identity lands
//!
//! `crates/admin`'s passkeys are already *named*: each is registered to a
//! person, and a verified assertion answers whose credential signed it, so the
//! session it mints carries that identity as cryptographic fact rather than
//! claim. That name is the key into [`People`]. One thing must be true before
//! the key means anything, and it is not this crate's to enforce: today the
//! registering caller supplies the name, so anyone holding the console password
//! could mint a passkey under any name. A policy keyed on a name the attacker
//! chose is not a policy. `docs/SECURITY.md`'s SEC-08 is the fix — registering
//! under a name other than the caller's own requires the owner credential
//! explicitly, and nobody can register a credential granting a capability they
//! do not already hold — and it belongs in `crates/admin/src/webauthn.rs`,
//! beside the registration it constrains.
//!
//! # The seam `crates/admin` uses
//!
//! Three calls, in this order, and nothing else:
//!
//! ```no_run
//! use selfhost_identity::{Capability, Credential, Identity, Opening, People, Policy, Session};
//! # use std::time::Instant;
//! # fn example(people: &People, policy: &Policy, session_user: &str, opened_at: Instant) -> Option<()> {
//! // 1. Who, and how — from the credential the request presented. A valid
//! //    bearer token is `Identity::Machine` with `Credential::Bearer`; a cookie
//! //    is the session store's holder name parsed into an `Identity`, with the
//! //    login that opened the session.
//! let identity = Identity::parse(session_user).ok()?;
//! let credential = Credential::Session(Session::new(Opening::Passkey, opened_at));
//!
//! // 2. What they hold — looked up once, so the decision stays pure.
//! let caller = people.caller(identity, credential);
//!
//! // 3. May they? One uninformative 401 for every refusal.
//! if !policy.decide(&caller, &Capability::ServiceControl).is_allowed() {
//!     return None;
//! }
//! # Some(())
//! # }
//! ```
//!
//! That seam is `Api::caller()` in `crates/admin/src/lib.rs`, and it preserves
//! the CSRF-header-before-store ordering `Api::cookie_authorised` has: the
//! header is checked *before* the session store is consulted, so a forged
//! cross-site non-GET cannot even refresh a session's idle timer. Building a
//! [`Caller`] must not become a second path to the store that skips it.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod audit;
pub mod capability;
pub mod credential;
pub mod identity;
pub mod policy;
pub mod registry;

pub use audit::{AuditId, AuditLog, AuditRecord, TRUNCATED, escape_field, unescape_field};
pub use capability::{Capability, InvalidToken, NodeName, ShareId};
pub use credential::{Credential, Opening, Session};
pub use identity::{AgentName, Identity, InvalidAgentName, InvalidPersonName, OWNER_NAME, PersonName};
pub use policy::{Caller, Decision, Grants, Granted, Policy, Refusal, TooManyGrants};
pub use registry::{People, Person, PrivateWrite, write_owner_only};
