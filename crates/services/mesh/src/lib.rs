//! One link, many channels: the transport this box's machines talk to each other
//! over, and the machine-shaped names they answer to.
//!
//! A remote desktop session, a file transfer and a status feed have to share one
//! connection, because there is exactly one connection available: the worker dials
//! the owner's console site over the tunnel, and nothing anywhere binds a new
//! socket. That constraint is not a limitation this crate works around — it is the
//! security property the whole design is built to preserve, and the multiplexing
//! here is what makes living inside it comfortable.
//!
//! # The shape of the crate
//!
//! The pure/impure split the rest of this project uses, with the line drawn
//! unusually far to the pure side on purpose. Every decision — what a frame means,
//! how much a sender may send, which channel ids belong to which end, whether a
//! proof is genuine, whether a peer is reachable — is a function over explicit
//! inputs, tested directly:
//!
//! - [`mux`] — the fixed eight-byte header. Nothing else, deliberately; read its
//!   documentation before changing anything about the wire format, because its
//!   fixed width is load-bearing for a reason that is not visible from the bytes.
//! - [`credit`] — send-window accounting, and the drop-and-merge policy that keeps
//!   a stalled desktop showing the present instead of a backlog.
//! - [`channel`] — channel ids, the odd/even split that makes simultaneous opens
//!   impossible, the lifecycle table, and the control frames that drive it.
//! - [`enroll`] — the HMAC proof that binds a node's token to one handshake, and
//!   the ledger that refuses a replay of it.
//! - [`registry`] — who is declared, who is live, why the last one dropped.
//! - [`local`] — this machine as a pseudo-peer, so that controlling the box you
//!   are logged into and controlling one across the world are **one** code path,
//!   one router, one authorisation check and one set of tests.
//!
//! And the I/O halves, which are the only files here that touch a socket:
//!
//! - [`link`] — a live link: one WebSocket, many channels, and the
//!   demultiplexer between them. It interprets nothing beyond the eight-byte
//!   header, deliberately.
//! - [`dial`] — the worker dialling out, proving its enrolment, and keeping the
//!   link up without anybody being asked.
//! - [`accept`] — the owner admitting it, or refusing it in a way that tells the
//!   caller nothing at all.
//! - [`splice`] — joining two channels so a browser reaches a machine it has no
//!   link to, with credit forwarded end to end.
//!
//! # The two facts worth knowing before reading any of it
//!
//! **The worker dials the owner; nothing listens.** The worker binds no socket, so
//! it has no new attack surface and NAT is irrelevant. The owner binds nothing new
//! either: the dial lands on the console site's existing 443 and therefore passes
//! the *same* source-address gate as every other console request. The mesh works
//! only over the tunnel, and no exemption is widened to make it work.
//!
//! **The daemon forwards payloads it never interprets.** Under `panic = "abort"` a
//! parser that runs in the owner's daemon is a way to take down the reverse proxy,
//! the authoritative DNS server, the mail server and the self-updater
//! simultaneously, at a time of the attacker's choosing. So the framing is
//! decidable from a fixed prefix, the splice rewrites two bytes and copies the
//! rest, and everything that actually *interprets* attacker-influenced bytes
//! happens in an agent process the daemon spawns, supervises and can watch die.
//!
//! # Example
//!
//! Framing a data frame and reading it back, which is the whole of the codec's
//! surface:
//!
//! ```
//! use selfhost_mesh::channel::ChannelId;
//! use selfhost_mesh::mux::{Kind, encode_frame, parse_frame};
//!
//! let bytes = encode_frame(Kind::Data, ChannelId::new(3), b"pixels")?;
//! let (frame, rest) = parse_frame(&bytes)?;
//! assert_eq!(frame.header.kind, Kind::Data);
//! assert_eq!(frame.payload, b"pixels");
//! assert!(rest.is_empty());
//! # Ok::<(), selfhost_mesh::mux::FrameError>(())
//! ```

pub mod accept;
pub mod channel;
pub mod credit;
pub mod dial;
pub mod enroll;
pub mod link;
pub mod local;
pub mod mux;
pub mod registry;
pub mod splice;

pub use accept::{Admitted, MemoryTokens, Refused, TokenStore};
pub use channel::{ChannelId, ChannelState, ChannelTable, Role};
pub use credit::{CreditStats, LatestOnly, Merge, ReceiveWindow, Reservation, SendWindow};
pub use dial::{Attempts, Connector, DialConfig, DialError, Session, Target};
pub use enroll::{Admission, Binding, NodeToken, NonceLedger, Proof};
pub use link::{ChannelInbox, Hello, Link, LinkControl, LinkError, LinkHandle, OwnedFrame};
pub use local::{LOCAL_NAME, Route, RouteError, Router};
pub use mux::{Frame, FrameError, Header, Kind};
pub use registry::{DropReason, Liveness, NodeName, PeerRecord, Registry, SharedRegistry};
pub use splice::{SpliceEnd, SpliceOutcome, SpliceSide};
