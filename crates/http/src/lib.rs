//! HTTP/1.1 messages, written from the specification rather than pulled from a
//! dependency.
//!
//! This crate is deliberately pure: it turns bytes into requests and responses
//! into bytes, and does no I/O. That is what lets the security-critical parts —
//! header injection, request smuggling, and range handling — be exhaustively
//! unit-tested without a socket, a certificate, or a running server.
//!
//! # What is enforced here
//!
//! - **Header injection.** A field value containing CR, LF, or NUL is refused at
//!   construction, so a response cannot be split into two.
//! - **Request smuggling.** Ambiguous framing is rejected rather than resolved
//!   by a heuristic: `Transfer-Encoding` alongside `Content-Length`, conflicting
//!   repeated `Content-Length`, a transfer coding that does not end in
//!   `chunked`, obsolete line folding, and whitespace before a header colon.
//! - **Response framing.** Length is derived from the body when the head is
//!   written, so a declared length can never disagree with the bytes sent.
//! - **Byte ranges.** Required for the adaptive video ladder this platform
//!   serves; see [`range`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod headers;
pub mod range;
pub mod request;
pub mod response;

pub use headers::{Header, HeaderError, Headers};
pub use range::{ByteRange, RangeOutcome};
pub use request::{BodyLength, Method, ParseError, Parsed, Request};
pub use response::{Body, Response, Status};
