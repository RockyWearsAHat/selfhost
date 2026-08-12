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
pub mod autodiscover;
pub mod client;
pub mod context;
pub mod dkim;
pub mod eas;
pub mod ews;
pub mod imap;
pub mod imap_net;
pub mod message;
pub mod mime;
pub mod outbound;
pub mod pacc;
pub mod receive;
pub mod smtp;
pub mod store;
pub mod submission;
mod time;
pub mod wbxml;
mod xml;
pub use time::stamp;

pub use address::{Address, AddressError, Path};
pub use client::{
    deliver_to_host, mx_delivery_order, Delivery, ClientError, OutboundQueue, QueuedMessage,
    SmtpClient,
};
pub use dkim::{Dkim, DkimError};
pub use imap::{
    FetchItem, FetchPlan, Flag, IAction, IConfig, IResponse, ISession, IState, MessageData,
    MessageRef, SelectData, Section, StatusItem, StoreOp, StorePlan,
};
pub use imap_net::{serve_imap, ImapServer};
pub use message::{Message, MessageError};
pub use outbound::{deliver, SendContext, SendReport, SigningIdentity};
pub use receive::{serve_smtp, Greylist, Receiver};
pub use smtp::{Action, Envelope, Policy, Reply, Session, State};
pub use store::{Flags, Folder, Maildir, StoreError, StoredId, Uid};
pub use submission::{
    hash_password, serve_submission, serve_submission_implicit_tls, Authenticator,
    ConfigAuthenticator, Submission, SubmissionError,
};
