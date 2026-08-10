//! Response construction and serialisation.
//!
//! A response owns its framing decision. Callers choose a [`Body`] and this
//! module derives the matching `Content-Length` or `Transfer-Encoding`, so it is
//! not possible to declare one length and write another — the mismatch that
//! desynchronises a connection and enables response smuggling.

use crate::headers::{HeaderError, Headers, MAX_HEAD_BYTES, MAX_HEADER_COUNT};
use crate::request::ParseError;
use std::fmt;

/// A response status code and its reason phrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status(pub u16);

impl Status {
    /// The connection is leaving HTTP for the protocol named in `Upgrade`.
    ///
    /// The only status in this codebase whose head is not followed by a body
    /// this crate knows how to frame: after the blank line the bytes belong to
    /// whatever protocol was negotiated, and HTTP has stopped. [`Response::write_head`]
    /// therefore gives it `Connection: Upgrade` and no `Content-Length` — see
    /// the note there for why either of the ordinary answers would be wrong.
    pub const SWITCHING_PROTOCOLS: Self = Self(101);
    /// Success.
    pub const OK: Self = Self(200);
    /// Partial content, sent in answer to a satisfiable `Range`.
    pub const PARTIAL_CONTENT: Self = Self(206);
    /// Permanent redirect preserving the method.
    pub const MOVED_PERMANENTLY: Self = Self(301);
    /// The client's cached representation is still fresh.
    pub const NOT_MODIFIED: Self = Self(304);
    /// Permanent redirect that must not change the method.
    pub const PERMANENT_REDIRECT: Self = Self(308);
    /// Malformed request.
    pub const BAD_REQUEST: Self = Self(400);
    /// Authentication required.
    pub const UNAUTHORIZED: Self = Self(401);
    /// Refused.
    pub const FORBIDDEN: Self = Self(403);
    /// No such resource.
    pub const NOT_FOUND: Self = Self(404);
    /// Method not allowed for this resource.
    pub const METHOD_NOT_ALLOWED: Self = Self(405);
    /// The request head was too large.
    pub const CONTENT_TOO_LARGE: Self = Self(413);
    /// The URI was too long.
    pub const URI_TOO_LONG: Self = Self(414);
    /// The `Range` could not be satisfied.
    pub const RANGE_NOT_SATISFIABLE: Self = Self(416);
    /// Too many requests.
    pub const TOO_MANY_REQUESTS: Self = Self(429);
    /// Request header fields too large.
    pub const HEADERS_TOO_LARGE: Self = Self(431);
    /// Unhandled server fault.
    pub const INTERNAL_SERVER_ERROR: Self = Self(500);
    /// No healthy upstream was available.
    pub const BAD_GATEWAY: Self = Self(502);
    /// The service is starting up or shutting down.
    pub const SERVICE_UNAVAILABLE: Self = Self(503);
    /// The upstream did not answer in time.
    pub const GATEWAY_TIMEOUT: Self = Self(504);

    /// The numeric code.
    pub fn code(self) -> u16 {
        self.0
    }

    /// Whether this status is forbidden from carrying a body (RFC 9110 §6.4.1).
    pub fn forbids_body(self) -> bool {
        matches!(self.0, 100..=199 | 204 | 304)
    }

    /// The canonical reason phrase.
    pub fn reason(self) -> &'static str {
        match self.0 {
            101 => "Switching Protocols",
            200 => "OK",
            206 => "Partial Content",
            301 => "Moved Permanently",
            304 => "Not Modified",
            308 => "Permanent Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            413 => "Content Too Large",
            414 => "URI Too Long",
            416 => "Range Not Satisfiable",
            429 => "Too Many Requests",
            431 => "Request Header Fields Too Large",
            500 => "Internal Server Error",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.0, self.reason())
    }
}

/// How a response body is produced.
#[derive(Debug, Clone)]
pub enum Body {
    /// No body.
    Empty,
    /// A complete in-memory body.
    Bytes(Vec<u8>),
    /// A body of known length written by the caller after the head.
    ///
    /// Used for files and for proxied responses, where the bytes are streamed
    /// rather than buffered.
    Streamed(u64),
}

impl Body {
    /// The byte length of this body, when known ahead of time.
    pub fn len(&self) -> u64 {
        match self {
            Self::Empty => 0,
            Self::Bytes(bytes) => bytes.len() as u64,
            Self::Streamed(len) => *len,
        }
    }

    /// Whether the body carries no bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A response head plus its body.
#[derive(Debug, Clone)]
pub struct Response {
    /// The status.
    pub status: Status,
    /// The header fields, excluding framing fields which are derived on write.
    pub headers: Headers,
    /// The body.
    pub body: Body,
}

impl Response {
    /// A response with no body.
    pub fn empty(status: Status) -> Self {
        Self { status, headers: Headers::new(), body: Body::Empty }
    }

    /// A response carrying an in-memory body of the given content type.
    pub fn bytes(status: Status, content_type: &str, bytes: Vec<u8>) -> Result<Self, HeaderError> {
        let mut headers = Headers::new();
        headers.set("Content-Type", content_type)?;
        Ok(Self { status, headers, body: Body::Bytes(bytes) })
    }

    /// A `text/html` response.
    pub fn html(status: Status, markup: impl Into<String>) -> Result<Self, HeaderError> {
        Self::bytes(status, "text/html; charset=utf-8", markup.into().into_bytes())
    }

    /// A minimal styled error page.
    pub fn error_page(status: Status) -> Self {
        let markup = format!(
            "<!doctype html><meta charset=\"utf-8\"><title>{code} {reason}</title>\
             <style>body{{font:16px/1.6 system-ui,sans-serif;margin:4rem auto;max-width:32rem;padding:0 1.5rem}}\
             h1{{font-size:1.5rem;margin:0 0 .5rem}}p{{color:#666}}</style>\
             <h1>{code} {reason}</h1><p>Nothing further to report.</p>",
            code = status.code(),
            reason = status.reason(),
        );
        // Constructing this cannot fail: the content type and markup are fixed
        // and contain no CR, LF, or NUL.
        Self::html(status, markup).unwrap_or_else(|_| Self::empty(status))
    }

    /// A redirect to `location`.
    pub fn redirect(status: Status, location: &str) -> Result<Self, HeaderError> {
        let mut response = Self::empty(status);
        response.headers.set("Location", location)?;
        Ok(response)
    }

    /// Serialises the status line and headers, deriving the framing fields.
    ///
    /// `head_only` reflects a `HEAD` request: the `Content-Length` still
    /// describes what a `GET` would return, but no bytes follow.
    ///
    /// # The one exception, and why it lives here rather than in the caller
    ///
    /// A `101 Switching Protocols` is the single response this crate writes
    /// whose framing is not a statement about a body: after the blank line the
    /// connection stops speaking HTTP altogether, and the bytes that follow
    /// belong to whatever protocol the `Upgrade` field named. Both of the
    /// ordinary answers are therefore wrong on it. `Content-Length: 0` claims a
    /// zero-length body where in truth there is no body at all and the peer must
    /// keep reading; `Connection: close` and `Connection: keep-alive` both
    /// describe an HTTP connection's reuse, and a browser that reads either one
    /// on a handshake abandons the upgrade — RFC 6455 §4.2.2 requires
    /// `Connection: Upgrade` exactly.
    ///
    /// It is enforced here rather than left to each caller for the same reason
    /// every other framing decision is made in this function: a rule that lives
    /// in one place cannot be got right in one caller and wrong in the next. The
    /// `Content-Length` half already falls out of [`Status::forbids_body`],
    /// which covers the whole `1xx` range; only the `Connection` field needs
    /// saying.
    pub fn write_head(&self, out: &mut Vec<u8>, keep_alive: bool) -> Result<(), HeaderError> {
        out.extend_from_slice(b"HTTP/1.1 ");
        out.extend_from_slice(self.status.code().to_string().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.status.reason().as_bytes());
        out.extend_from_slice(b"\r\n");

        let mut headers = self.headers.clone();

        // Framing is derived here and nowhere else, so the declared length and
        // the bytes actually written can never disagree.
        headers.remove("content-length");
        headers.remove("transfer-encoding");
        if !self.status.forbids_body() {
            headers.set("Content-Length", self.body.len().to_string())?;
        }

        if self.status == Status::SWITCHING_PROTOCOLS {
            headers.set("Connection", "Upgrade")?;
        } else {
            headers.set("Connection", if keep_alive { "keep-alive" } else { "close" })?;
        }
        headers.write_to(out);
        out.extend_from_slice(b"\r\n");
        Ok(())
    }
}

/// How an incoming response's body is delimited.
///
/// A response has one framing a request does not: it may simply run until the
/// connection closes. That is legal, and it is why this is a separate decision
/// from [`crate::BodyLength`] rather than the same one reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseFraming {
    /// There is no body, and none is permitted.
    None,
    /// Exactly this many bytes follow.
    Fixed(u64),
    /// Chunked transfer coding.
    Chunked,
    /// Everything until the peer closes the connection.
    UntilClose,
}

/// A response head read off the wire.
///
/// Distinct from [`Response`], which is a response being *built*: that one owns
/// a [`Body`] and derives its framing when written, and this one has a body it
/// has not read yet and a framing it was told.
#[derive(Debug, Clone)]
pub struct IncomingResponse {
    /// The status.
    pub status: Status,
    /// The minor version: 0 for `HTTP/1.0`, 1 for `HTTP/1.1`.
    pub minor_version: u8,
    /// The header fields, in the order they arrived.
    pub headers: Headers,
    /// How to find the end of the body.
    pub framing: ResponseFraming,
}

/// A parsed response head, and how many bytes of input it took.
#[derive(Debug, Clone)]
pub struct ParsedResponse {
    /// The head.
    pub response: IncomingResponse,
    /// Where the body begins in the input.
    pub consumed: usize,
}

impl IncomingResponse {
    /// Parses a response head from the front of `input`.
    ///
    /// Answers [`ParseError::Incomplete`] until the blank line has arrived, so a
    /// caller reads more and retries.
    ///
    /// The framing rules are the request parser's, kept deliberately strict for
    /// the same reason: a client that resolves an ambiguous length by guessing
    /// can be made to read the *next* response as part of this one.
    pub fn parse(input: &[u8]) -> Result<ParsedResponse, ParseError> {
        let head_end = crate::request::find_head_end(input).ok_or({
            if input.len() > MAX_HEAD_BYTES { ParseError::HeadTooLarge } else { ParseError::Incomplete }
        })?;
        if head_end > MAX_HEAD_BYTES {
            return Err(ParseError::HeadTooLarge);
        }

        let mut lines = crate::request::split_crlf(&input[..head_end]);
        let (status, minor_version) =
            parse_status_line(lines.next().ok_or(ParseError::BadRequestLine)?)?;

        let mut headers = Headers::new();
        for line in lines {
            if line[0] == b' ' || line[0] == b'\t' {
                return Err(ParseError::AmbiguousFraming("obsolete header line folding"));
            }
            if headers.len() >= MAX_HEADER_COUNT {
                return Err(ParseError::BadHeader(HeaderError::TooMany));
            }
            headers
                .append(crate::request::parse_header_line(line)?)
                .map_err(ParseError::BadHeader)?;
        }

        let framing = framing_of(status, &headers)?;
        Ok(ParsedResponse {
            response: IncomingResponse { status, minor_version, headers, framing },
            consumed: head_end,
        })
    }
}

/// Parses `HTTP/1.x SP code SP reason`.
///
/// The reason phrase is discarded. It is free text that no two servers agree on
/// and that nothing should ever branch on; the code is the answer.
fn parse_status_line(line: &[u8]) -> Result<(Status, u8), ParseError> {
    let text = std::str::from_utf8(line).map_err(|_| ParseError::BadRequestLine)?;
    let (version, rest) = text.split_once(' ').ok_or(ParseError::BadRequestLine)?;

    let minor_version = match version {
        "HTTP/1.1" => 1,
        "HTTP/1.0" => 0,
        other if other.starts_with("HTTP/") => return Err(ParseError::UnsupportedVersion),
        _ => return Err(ParseError::BadRequestLine),
    };

    let code = rest.split(' ').next().unwrap_or_default();
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ParseError::BadRequestLine);
    }
    let code: u16 = code.parse().map_err(|_| ParseError::BadRequestLine)?;
    Ok((Status(code), minor_version))
}

/// Decides how a response body ends.
fn framing_of(status: Status, headers: &Headers) -> Result<ResponseFraming, ParseError> {
    // Some statuses cannot carry a body whatever the headers claim. Believing a
    // `Content-Length` on a 204 is how a client ends up waiting forever for
    // bytes that were never going to come.
    if status.forbids_body() {
        return Ok(ResponseFraming::None);
    }

    let chunked = headers.contains("transfer-encoding");
    let lengths = headers.count("content-length");
    if chunked && lengths > 0 {
        return Err(ParseError::AmbiguousFraming(
            "both Transfer-Encoding and Content-Length present",
        ));
    }

    if chunked {
        if headers.count("transfer-encoding") > 1 {
            return Err(ParseError::AmbiguousFraming("repeated Transfer-Encoding"));
        }
        let value = headers
            .get_str("transfer-encoding")
            .ok_or(ParseError::AmbiguousFraming("non-UTF-8 Transfer-Encoding"))?;
        let final_coding =
            value.rsplit(',').next().map(str::trim).unwrap_or_default().to_ascii_lowercase();
        if final_coding != "chunked" {
            return Err(ParseError::AmbiguousFraming("Transfer-Encoding does not end with chunked"));
        }
        return Ok(ResponseFraming::Chunked);
    }

    if lengths == 0 {
        return Ok(ResponseFraming::UntilClose);
    }

    let mut agreed: Option<u64> = None;
    for field in headers.iter() {
        if !field.name().eq_ignore_ascii_case("content-length") {
            continue;
        }
        let text = field
            .value_str()
            .ok_or(ParseError::AmbiguousFraming("non-UTF-8 Content-Length"))?
            .trim();
        if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ParseError::AmbiguousFraming("Content-Length is not a bare integer"));
        }
        let parsed: u64 = text
            .parse()
            .map_err(|_| ParseError::AmbiguousFraming("Content-Length out of range"))?;
        match agreed {
            None => agreed = Some(parsed),
            Some(existing) if existing == parsed => {}
            Some(_) => {
                return Err(ParseError::AmbiguousFraming("conflicting Content-Length values"));
            }
        }
    }
    Ok(ResponseFraming::Fixed(agreed.unwrap_or(0)))
}

#[cfg(test)]
mod incoming_tests {
    use super::*;

    fn parse(raw: &str) -> Result<ParsedResponse, ParseError> {
        IncomingResponse::parse(raw.as_bytes())
    }

    #[test]
    fn parses_a_status_line_and_headers() {
        let parsed = parse("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc").expect("parse");
        assert_eq!(parsed.response.status, Status(200));
        assert_eq!(parsed.response.minor_version, 1);
        assert_eq!(parsed.response.framing, ResponseFraming::Fixed(3));
        assert_eq!(&"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"[parsed.consumed..], "abc");
    }

    #[test]
    fn an_unfinished_head_asks_for_more() {
        assert!(matches!(parse("HTTP/1.1 200 OK\r\n"), Err(ParseError::Incomplete)));
    }

    #[test]
    fn a_missing_reason_phrase_is_still_a_valid_status_line() {
        let parsed = parse("HTTP/1.1 204 \r\n\r\n").expect("parse");
        assert_eq!(parsed.response.status, Status(204));
    }

    #[test]
    fn a_status_that_forbids_a_body_has_none_whatever_it_claims() {
        // A 204 with a Content-Length is a server bug; believing it would leave
        // the client waiting for bytes that are never sent.
        let parsed = parse("HTTP/1.1 204 No Content\r\nContent-Length: 10\r\n\r\n").expect("parse");
        assert_eq!(parsed.response.framing, ResponseFraming::None);
    }

    #[test]
    fn no_length_and_no_coding_means_until_the_connection_closes() {
        let parsed = parse("HTTP/1.1 200 OK\r\n\r\n").expect("parse");
        assert_eq!(parsed.response.framing, ResponseFraming::UntilClose);
    }

    #[test]
    fn chunked_is_recognised() {
        let parsed =
            parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n").expect("parse");
        assert_eq!(parsed.response.framing, ResponseFraming::Chunked);
    }

    #[test]
    fn a_coding_that_does_not_end_in_chunked_is_refused() {
        assert!(matches!(
            parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"),
            Err(ParseError::AmbiguousFraming(_))
        ));
    }

    #[test]
    fn a_length_alongside_a_coding_is_refused() {
        assert!(matches!(
            parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n"),
            Err(ParseError::AmbiguousFraming(_))
        ));
    }

    #[test]
    fn conflicting_lengths_are_refused_and_identical_ones_are_not() {
        assert!(matches!(
            parse("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\n"),
            Err(ParseError::AmbiguousFraming(_))
        ));
        let parsed =
            parse("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\n").expect("parse");
        assert_eq!(parsed.response.framing, ResponseFraming::Fixed(4));
    }

    #[test]
    fn a_padded_or_signed_length_is_refused() {
        for length in ["+4", "4 4", "0x4", ""] {
            let raw = format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n");
            assert!(
                matches!(parse(&raw), Err(ParseError::AmbiguousFraming(_))),
                "accepted Content-Length {length:?}"
            );
        }
    }

    #[test]
    fn obsolete_line_folding_is_refused() {
        assert!(matches!(
            parse("HTTP/1.1 200 OK\r\nX-Thing: a\r\n  b\r\n\r\n"),
            Err(ParseError::AmbiguousFraming(_))
        ));
    }

    #[test]
    fn a_malformed_status_line_is_refused() {
        for line in ["HTTP/1.1 20 OK", "HTTP/1.1 abc OK", "HTTP/2 200 OK", "200 OK", "HTTP/1.1"] {
            let raw = format!("{line}\r\n\r\n");
            assert!(parse(&raw).is_err(), "accepted status line {line:?}");
        }
    }

    #[test]
    fn a_head_that_is_too_large_is_refused_rather_than_buffered() {
        let raw =
            format!("HTTP/1.1 200 OK\r\nX-Pad: {}\r\n\r\n", "a".repeat(MAX_HEAD_BYTES));
        assert!(matches!(parse(&raw), Err(ParseError::HeadTooLarge)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head_of(response: &Response, keep_alive: bool) -> String {
        let mut out = Vec::new();
        response.write_head(&mut out, keep_alive).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn derives_content_length_from_the_body() {
        let response = Response::bytes(Status::OK, "text/plain", b"hello".to_vec()).unwrap();
        assert!(head_of(&response, true).contains("Content-Length: 5\r\n"));
    }

    #[test]
    fn caller_supplied_framing_headers_are_overridden() {
        // A caller must not be able to declare a length that disagrees with the
        // bytes written — that desynchronises the connection.
        let mut response = Response::bytes(Status::OK, "text/plain", b"hello".to_vec()).unwrap();
        response.headers.push("Content-Length", "999").unwrap();
        response.headers.push("Transfer-Encoding", "chunked").unwrap();

        let head = head_of(&response, true);
        assert!(head.contains("Content-Length: 5\r\n"));
        assert!(!head.contains("999"));
        assert!(!head.to_ascii_lowercase().contains("transfer-encoding"));
    }

    #[test]
    fn bodiless_statuses_carry_no_content_length() {
        for status in [Status::NOT_MODIFIED, Status(204)] {
            let head = head_of(&Response::empty(status), true);
            assert!(!head.contains("Content-Length"), "status {status} emitted a length");
        }
    }

    #[test]
    fn connection_header_tracks_keep_alive() {
        let response = Response::empty(Status::OK);
        assert!(head_of(&response, true).contains("Connection: keep-alive\r\n"));
        assert!(head_of(&response, false).contains("Connection: close\r\n"));
    }

    #[test]
    fn a_switching_protocols_head_says_upgrade_and_frames_nothing() {
        // Both halves of the rule at once, and both matter: a browser drops the
        // handshake on the wrong Connection value, and a peer that believes a
        // Content-Length of 0 stops reading exactly where the new protocol
        // begins.
        for keep_alive in [true, false] {
            let head = head_of(&Response::empty(Status::SWITCHING_PROTOCOLS), keep_alive);
            assert!(head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"), "{head}");
            assert!(head.contains("Connection: Upgrade\r\n"), "{head}");
            assert!(!head.contains("Content-Length"), "{head}");
            assert!(!head.to_ascii_lowercase().contains("keep-alive"), "{head}");
            assert!(!head.to_ascii_lowercase().contains("connection: close"), "{head}");
        }
    }

    #[test]
    fn only_a_101_gets_the_upgrade_connection_value() {
        // The rule is keyed on the status and nothing else, so a 200 that
        // happens to carry an Upgrade field is still an ordinary response.
        let mut response = Response::empty(Status::OK);
        response.headers.push("Upgrade", "websocket").unwrap();
        let head = head_of(&response, true);
        assert!(head.contains("Connection: keep-alive\r\n"), "{head}");
        assert!(head.contains("Content-Length: 0\r\n"), "{head}");
    }

    #[test]
    fn a_101_names_itself_in_the_status_line() {
        assert_eq!(Status::SWITCHING_PROTOCOLS.code(), 101);
        assert_eq!(Status::SWITCHING_PROTOCOLS.reason(), "Switching Protocols");
        // Inherited from the 1xx range rather than added for this status: the
        // Content-Length half of the rule is already true for every informational
        // response, and stating it twice is how the two drift apart.
        assert!(Status::SWITCHING_PROTOCOLS.forbids_body());
    }

    #[test]
    fn status_line_is_well_formed() {
        assert!(head_of(&Response::empty(Status::NOT_FOUND), true).starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    #[test]
    fn streamed_body_declares_its_length() {
        let response = Response { status: Status::OK, headers: Headers::new(), body: Body::Streamed(1_048_576) };
        assert!(head_of(&response, true).contains("Content-Length: 1048576\r\n"));
    }

    #[test]
    fn head_ends_with_a_blank_line() {
        assert!(head_of(&Response::empty(Status::OK), true).ends_with("\r\n\r\n"));
    }

    #[test]
    fn error_page_is_self_describing() {
        let page = Response::error_page(Status::BAD_GATEWAY);
        assert_eq!(page.status, Status::BAD_GATEWAY);
        let Body::Bytes(bytes) = &page.body else { panic!("expected an in-memory body") };
        assert!(String::from_utf8_lossy(bytes).contains("502 Bad Gateway"));
    }
}
