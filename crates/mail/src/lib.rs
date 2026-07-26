//! Mail: SMTP and IMAP, written from the specifications.
//!
//! The goal is custom-domain email without a per-mailbox subscription. What
//! makes that realistic is that receiving mail and reading mail are separate
//! problems:
//!
//! - **SMTP** is how mail reaches you. Nothing else affects deliverability.
//! - **IMAP** is only how a client reads the mailbox afterwards.
//!
//! # The two hard parts, named up front
//!
//! **Not becoming an open relay.** See [`smtp`]. A server that accepts mail for
//! domains it does not own is found by spammers within hours and lands on every
//! blocklist there is. The rule is enforced in exactly one place.
//!
//! **Outbound deliverability is an environment problem, not a code problem.**
//! Sending directly requires clean IP reputation and forward-confirmed reverse
//! DNS. Where those are absent the same message must go through a relay instead.
//! Both modes are first-class here; neither is hardcoded as impossible, and
//! which one is usable is *measured* rather than assumed.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod address;
pub mod smtp;

pub use address::{Address, AddressError, Path};
pub use smtp::{Action, Envelope, Policy, Reply, Session, State};
