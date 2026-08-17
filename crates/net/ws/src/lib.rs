//! RFC 6455 WebSocket, written here rather than pulled from a dependency.
//!
//! This crate exists because the box needs one thing HTTP cannot give it: a
//! connection that stays open and carries messages in both directions, so the
//! admin console can be *told* that a service restarted instead of asking four
//! hundred times a minute whether it has. Everything else this repository puts on
//! a wire it writes itself — HTTP, the reverse proxy, ACME, the DNS wire format,
//! SMTP, IMAP — and the reason is always the same: a lenient parser is a security
//! bug, and the only way to know a parser is strict is to have written it and to
//! be able to read it in one sitting. A frame codec is nine hundred lines with
//! its tests. There is nothing here that a dependency would save us.
//!
//! # Where this runs, and where it must never run
//!
//! **Only inside the daemon.** The reverse proxy — the one process on this box
//! with a public socket — never parses a WebSocket frame. It recognises an
//! upgrade *request head* with the HTTP parser it already has, forwards it to the
//! loopback admin API, reads the response head with the response parser it
//! already has, and on a 101 moves opaque bytes with `copy_bidirectional`. That
//! containment is not tidiness. The release profile sets `panic = "abort"`: a
//! parser that runs in the proxy is a parser whose worst day takes down 80, 443,
//! mail, the certificate store and the authoritative DNS server together. So the
//! code that interprets attacker-influenced framing runs in the process that can
//! afford to be restarted, and the process that cannot afford it stays a pipe.
//!
//! # The subset, and what is refused
//!
//! Binary frames only. Text is never sent and is refused on receipt, which is why
//! no UTF-8 validator exists anywhere in this stack. No extension is negotiated,
//! so any reserved bit is a protocol error and `permessage-deflate` is refused by
//! omission rather than by a special case. Client frames must be masked and
//! server frames must not be. All three length forms are accepted in their
//! minimal encoding only, with checked arithmetic on every value the peer chose.
//! Control frames must be final and at most 125 bytes. Fragmented messages are
//! bounded in both bytes and fragment count. The reasoning for each refusal is in
//! [`frame`]; the numbers are in [`limits`].
//!
//! # The shape of the crate
//!
//! Five of the six modules are pure functions over bytes and can be tested
//! exhaustively without a socket, which is the whole reason the split exists:
//!
//! - [`handshake`] — is this request head a handshake, and what did it ask for?
//! - [`accept`] — the `Sec-WebSocket-Accept` digest, and the one base64 alphabet
//!   the rest of this workspace does not already speak.
//! - [`frame`] — the total frame parser and the fragment reassembler.
//! - [`close`] — close codes, close bodies, and the map from a refusal to a code.
//! - [`limits`] — every ceiling and every deadline, with its reasoning attached.
//! - [`duplex`] — the only I/O. Generic over `AsyncRead + AsyncWrite`, so the
//!   tests drive a real stream over `tokio::io::duplex` and can assert on a
//!   *timeout* without waiting forty-five seconds for one.
//!
//! # What this crate does not decide
//!
//! It does not decide who may open a stream. A handshake is a `GET`, browsers
//! will not let a page set a custom header on one, and there is no CORS preflight
//! to refuse it — so a hostile page in a logged-in browser can produce a
//! syntactically perfect handshake with the session cookie attached. The
//! authorisation therefore lives above: a single-use ticket minted by an ordinary
//! CSRF-protected `POST`, an `Origin` compared against a value derived from
//! configuration rather than from any header, the session check, and a capability
//! check that is re-run per message rather than inferred from the handshake.
//! [`handshake::validate`] hands that layer the raw material and judges none of
//! it.
//!
//! # The one thing outside the daemon that may call into this crate
//!
//! [`looks_like_upgrade`] is re-exported at the crate root because it is the
//! **single definition** of "this request head is shaped like an upgrade", and
//! the reverse proxy calls it rather than keeping a copy of its own. That is not
//! a hole in the containment rule above: the rule is about which code *runs* in
//! the process that owns 80 and 443, and this predicate reads four header fields,
//! allocates nothing, parses nothing and cannot fail. What it prevents is worth
//! far more — two routers that can come to disagree about whether the same bytes
//! are a handshake is the shape of a request-smuggling bug, and the only way two
//! predicates stay equal is by being one predicate.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod accept;
pub mod close;
pub mod duplex;
pub mod frame;
pub mod handshake;
pub mod limits;

pub use accept::accept_key;
pub use close::{CloseCode, CloseFrame};
pub use duplex::{Closed, Duplex, Event, Gone, Sender, StreamError};
pub use frame::{Assembler, Frame, Opcode, ParsedFrame, ProtocolError, Role};
pub use handshake::{Refusal, Upgrade, looks_like_upgrade};
pub use limits::Limits;
