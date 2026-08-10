//! Network-attached storage: shares, and the rules that keep one a share rather
//! than a hole in the box.
//!
//! This crate serves declared directories to their owner over HTTP, over WebDAV,
//! and — where the operating system will do it for us — over SMB. It is the
//! first subsystem in this project whose callers can *write*, and that single
//! fact shapes everything below.
//!
//! # The one paragraph to read before changing anything here
//!
//! A static file server and a NAS look like the same problem and are not. A
//! static root is read-only, published on purpose, and never written by a
//! caller; every name in it was chosen by the operator. A share is written by
//! callers, its names are chosen by whoever uploaded them, and it sits behind
//! the console's own origin — the origin that holds the session cookie for the
//! thing that can restart services and read the filesystem. So a NAS needs every
//! rule a static root needs (`crates/proxy/src/files.rs` has them, and they are
//! inherited verbatim), **plus** the rules that only matter once names are
//! attacker-chosen: Windows path normalisation, NTFS alternate data streams,
//! reserved device names, 8.3 aliases, case collisions, and symlinks that did
//! not exist when the path was validated.
//!
//! # The shape of the crate
//!
//! The pure/impure split this project uses everywhere — `crates/firewall`'s
//! `rule` versus `backend`, `crates/supervisor`'s `policy` versus the process
//! code — is sharper here than anywhere else, because the pure half is the
//! security core and it has to be testable without a disk:
//!
//! | Module | Pure? | What it decides |
//! |---|---|---|
//! | [`path`] | **pure** | which name inside a share a request refers to, or why it refers to nothing |
//! | [`share`] | **pure** | what a share is once checked, and whether a caller may do a thing to it |
//! | [`listing`] | **pure** | what one directory contains, in the order and shape the console reads |
//! | [`respond`] | **pure** | the response head for one file: range, validators, and what a browser is allowed to do with the bytes |
//! | [`quota`] | mostly pure | whether one more upload may start, and whether a running one may continue; plus the one live ledger those answers are measured against |
//! | [`fs`] | impure | the descriptor walk that makes a symlink escape impossible, the create that cannot clobber, and the rest of the write path's floor |
//! | [`auth`] | impure | Basic-over-TLS and the verified-credential cache |
//! | [`dav`] | mixed | the WebDAV verb table, the `207` body, and locks that actually exclude |
//! | [`api`] | impure | what a share lets a caller do, as functions a route calls — the engine both the JSON API and WebDAV run on |
//! | [`smb`] | impure | driving the platform's own SMB server *(Phase 10)* |
//! | [`discover`] | mixed | DNS-SD records, published by somebody else's responder *(Phase 10)* |
//!
//! # The division that must not be forgotten
//!
//! [`path`] proves that a request *names* something inside a share. [`fs`]
//! proves that the *bytes* it reaches are inside the share. **Neither is
//! sufficient alone**, and the second cannot be skipped on the grounds that the
//! first passed: a pure function cannot `stat`, so it cannot know that `photos`
//! is a symlink to `/`, and on a share the caller is the one who gets to create
//! that symlink. [`path::Resolved::textual_path`] is named the way it is so a
//! call site cannot forget which half it is holding, and [`fs::Dir`] is the
//! other half made unavoidable: it opens one validated component at a time
//! against an open directory descriptor, so the second proof is not a check a
//! caller could omit but the only route to a byte.
//!
//! The same division decides two questions that look like they belong to the
//! pure half and do not:
//!
//! - **"Do these two names collide?"** [`path::collides`] folds case, which is
//!   enough to explain a `409` and not enough to prevent one. Only the volume
//!   knows whether it folds Unicode normalisation, or case, or neither — so the
//!   thing that actually stops an upload destroying a file is
//!   [`fs::Upload::begin`]'s exclusive create at the destination name.
//! - **"Where may a share be rooted?"** Textually, in [`share::Share::new`],
//!   against the [`share::Reserved`] directories this deployment declares —
//!   because a resolver that confines perfectly to `/` confines perfectly to
//!   nothing. What text cannot see is a symlinked root, which
//!   [`fs::Dir::open_root`] canonicalises before opening — deliberately, since
//!   an operator who points a share through a symlink meant to; every component
//!   *below* the root is walked with links refused.
//!
//! # What the deployment already guarantees, and what it does not
//!
//! A share is reachable only through the console site, which validation forces
//! to carry a non-empty `allowed_cidrs` — in the current deployment, loopback,
//! which is where the Secure-VPN tunnel exits. Nothing in this crate treats that
//! gate as authentication. It is a perimeter against the internet and against
//! the LAN; it is **not** a perimeter against this box, and the same machine
//! hosts co-located applications whose bugs would issue requests from inside it.
//! Every route still authenticates, and every operation still asks
//! [`share::Share::permits`] — [`api::Volume`] does that at the top of each
//! operation rather than leaving it to a route, because a route is a place a
//! check can be forgotten.
//!
//! # Where the bytes go, and where they never do
//!
//! Nothing in this crate buffers a file. A download hands back an open handle
//! and a byte window ([`api::Download`]); an upload is fed in chunks
//! ([`api::Receiver`]); a server-side copy moves through one fixed buffer. That
//! is what makes a 5 GB upload cost the daemon a scratch buffer and a 2 GB
//! download cost it nothing, on a box whose one process also serves ports 80
//! and 443.

pub mod api;
pub mod auth;
pub mod dav;
pub mod discover;
pub mod fs;
pub mod listing;
pub mod path;
pub mod quota;
pub mod respond;
pub mod share;
pub mod smb;

pub use api::{Download, Failure, Landing, Progress, Receiver, Sessions, Ticket, Volume};
pub use auth::{Cached, Credentials, Presented};
pub use fs::{Attributes, Dir, Existing, OpenError, Upload, WriteError};
pub use listing::{Entry, Kind, Listing};
pub use path::{RelativePath, Refusal, Resolved};
pub use quota::{Admission, Ledger, Limits, Reservation, Usage};
pub use respond::{BlobResponse, Disposition};
pub use share::{
    Grant, GrantOutcome, Grantee, Mode, Reserved, Share, ShareError, ShareId, Shares, SmbExport,
    SmbName, SmbNameProblem, Want,
};
