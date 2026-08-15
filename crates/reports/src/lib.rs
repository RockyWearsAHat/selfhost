//! A public intake for reports about a project, so the next person — or the next agent —
//! working on that project inherits what everyone else ran into.
//!
//! # The problem this exists for
//!
//! An agent working in some repository hits a defect in a *tool*: a search that answered with
//! the wrong block, a message that did not say what to do next, a call it had to make twice.
//! The place that defect has to reach is the tool's own checkout, which is almost never the
//! repository the agent is standing in — so the report either goes into a human's memory, or
//! nowhere. Meanwhile the tool's own repository is where the fixer works, and where the next
//! agent looks.
//!
//! So: one endpoint anybody can POST a report to, one database on this box that holds it, and
//! one feed a subscribed checkout folds into its own `reports.dx`. Nobody has to remember
//! anything, and no report waits on a person to relay it.
//!
//! ```text
//!  agent, anywhere            this box                     the project's checkout
//!  ───────────────           ──────────                    ──────────────────────
//!  dx report bug …  ──POST──▶ intake ──▶ database ──feed──▶ reports.dx, folded in
//!                                │                          (the next agent reads it)
//!                                └──SMTP──▶ the owner's inbox
//! ```
//!
//! # The modules, and what each one is the authority on
//!
//! - [`report`] — what a report *is*, and what is admitted as one. Every hostile-input rule
//!   lives there: the cleaning that makes a mail header injection impossible, the caps, and
//!   the fingerprint that makes one defect one record however many times it is filed.
//! - [`store`] — the database. One directory per subscribable project, one file per defect,
//!   replaced by rename, bounded in every dimension.
//! - [`limit`] — token buckets, per source and global, with a bounded table of sources.
//! - [`notify`] — the message that puts a report in the owner's mailbox, submitted to this
//!   box's own SMTP server on loopback.
//! - [`service`] — the HTTP routes and what stands in front of them.
//! - [`clock`] — the two time formats the others write.
//! - [`accounts`] — who filed a report and how they prove it later: email/password, an optional
//!   passkey, an optional linked OAuth identity, all additive to the anonymous door above.
//! - [`sessions`] — the cookie that keeps an account signed in across visits.
//! - [`webauthn`] — passkey registration and login for an account, mirrored from
//!   `crates/admin/src/webauthn.rs`.
//! - [`oauth`] — "sign in with…" against a configured provider, PKCE-protected, with its own
//!   hand-rolled outbound HTTPS client mirrored from `crates/acme/src/transport.rs`.
//! - [`verify`] — confirming an account's email is reachable, and spooling that message into
//!   this box's own outbound mail queue.
//! - [`invite`] — the one-time code that links a reports account to a `PersonName`
//!   `crates/identity` already knows, so `People::grants_for` decides what it may do elsewhere
//!   on this box.
//!
//! # What this crate never does
//!
//! It does not execute anything, render anything, or resolve a name for itself over DNS. It
//! reads a JSON body, writes a file, and hands messages to a mail server on loopback or spools
//! them for the daemon's own outbound sweep — and, now, dials exactly the identity provider an
//! operator configured, over TLS it verifies itself. A report is text about a defect and an
//! account is a credential to see one's own; nothing in this crate gives either any power over
//! the box itself.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod accounts;
pub mod clock;
pub mod invite;
pub mod limit;
pub mod notify;
pub mod oauth;
pub mod report;
pub mod service;
pub mod sessions;
pub mod store;
pub mod verify;
pub mod webauthn;

pub use accounts::{Account, Accounts};
pub use limit::{Limiter, Rate};
pub use notify::Mailbox;
pub use report::{Kind, Refusal, Report};
pub use service::{Config, Service, bind, serve};
pub use sessions::Sessions;
pub use store::{Entry, Recorded, Store, StoreError};
