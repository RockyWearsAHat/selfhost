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
//! - [`service`] — the four HTTP routes and what stands in front of them.
//! - [`clock`] — the two time formats the others write.
//!
//! # What this crate never does
//!
//! It does not execute anything, render anything, or fetch anything. It reads a JSON body,
//! writes a file, and hands one message to a mail server on loopback. A report is text about
//! a defect; nothing in this crate gives that text any power.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod clock;
pub mod limit;
pub mod notify;
pub mod report;
pub mod service;
pub mod store;

pub use limit::{Limiter, Rate};
pub use notify::Mailbox;
pub use report::{Kind, Refusal, Report};
pub use service::{Config, Service, bind, serve};
pub use store::{Entry, Recorded, Store, StoreError};
