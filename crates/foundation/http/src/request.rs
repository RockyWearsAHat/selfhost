//! Request-line and header parsing, and the body-framing decision.
//!
//! The framing rules here are the security-critical part of this crate. A proxy
//! that disagrees with its upstream about where one request ends and the next
//! begins is vulnerable to request smuggling: an attacker sends bytes that this
//! server reads as one request and the origin reads as two, letting them prepend
//! arbitrary content to the *next* client's request.
//!
//! The defence is to be strict rather than lenient. Every ambiguous framing is
//! rejected outright instead of resolved by a heuristic, because any heuristic
//! is a guess about what some other implementation would have guessed.

use crate::headers::{Header, HeaderError, Headers, MAX_HEAD_BYTES, MAX_HEADER_COUNT};
use std::fmt;

/// The request method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    /// Retrieve a representation.
    Get,
    /// Retrieve only the headers a `GET` would return.
    Head,
    /// Submit data.
    Post,
    /// Replace a resource.
    Put,
    /// Remove a resource.
    Delete,
    /// Apply a partial modification.
    Patch,
    /// Describe the communication options.
    Options,
    /// Loop back the request.
    Trace,
    /// Establish a tunnel.
    Connect,
    /// Any other token.
    Other(String),
}

impl Method {
    /// Parses a method token.
    pub fn parse(token: &str) -> Self {
        match token {
            "GET" => Self::Get,
            "HEAD" => Self::Head,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "PATCH" => Self::Patch,
            "OPTIONS" => Self::Options,
            "TRACE" => Self::Trace,
            "CONNECT" => Self::Connect,
            other => Self::Other(other.to_owned()),
        }
    }

    /// The token as it appears on the wire.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Options => "OPTIONS",
            Self::Trace => "TRACE",
            Self::Connect => "CONNECT",
            Self::Other(token) => token,
        }
    }

    /// Whether a response to this method may carry a body.
    ///
    /// `HEAD` responses carry the headers a `GET` would produce — including
    /// `Content-Length` — but never the bytes.
    pub fn allows_response_body(&self) -> bool {
        !matches!(self, Self::Head)
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How the body of a message is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyLength {
    /// No body at all.
    None,
    /// Exactly this many bytes follow.
    Fixed(u64),
    /// Chunked transfer coding.
    Chunked,
}

/// A parsed request head.
#[derive(Debug, Clone)]
pub struct Request {
    /// The method.
    pub method: Method,
    /// The request target, exactly as it arrived — not yet decoded.
    pub target: String,
    /// Minor version of HTTP/1; `1` for `HTTP/1.1`, `0` for `HTTP/1.0`.
    pub minor_version: u8,
    /// The header fields.
    pub headers: Headers,
}

/// Why a request could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// More bytes are needed before a decision can be made.
    Incomplete,
    /// The request line was malformed.
    BadRequestLine,
    /// A header field was malformed.
    BadHeader(HeaderError),
    /// The head exceeded [`MAX_HEAD_BYTES`].
    HeadTooLarge,
    /// Only HTTP/1.0 and HTTP/1.1 are spoken.
    UnsupportedVersion,
    /// `Host` was absent from an HTTP/1.1 request, or present more than once.
    BadHost,
    /// The message framing was ambiguous. This is a smuggling attempt or a
    /// broken client; either way it is refused rather than guessed at.
    AmbiguousFraming(&'static str),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete => write!(f, "incomplete message head"),
            Self::BadRequestLine => write!(f, "malformed request line"),
            Self::BadHeader(e) => write!(f, "malformed header: {e}"),
            Self::HeadTooLarge => write!(f, "message head exceeds {MAX_HEAD_BYTES} bytes"),
            Self::UnsupportedVersion => write!(f, "unsupported HTTP version"),
            Self::BadHost => write!(f, "missing or duplicated Host header"),
            Self::AmbiguousFraming(why) => write!(f, "ambiguous message framing: {why}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// A successfully parsed head, and how many bytes it consumed.
#[derive(Debug)]
pub struct Parsed {
    /// The request.
    pub request: Request,
    /// Number of bytes of `input` that made up the head, including the blank line.
    pub consumed: usize,
}

impl Request {
    /// Parses a request head from the front of `input`.
    ///
    /// Returns [`ParseError::Incomplete`] when the terminating blank line has not
    /// arrived yet, so a caller can read more and retry with a longer buffer.
    pub fn parse(input: &[u8]) -> Result<Parsed, ParseError> {
        let head_end = find_head_end(input).ok_or({
            if input.len() > MAX_HEAD_BYTES {
                ParseError::HeadTooLarge
            } else {
                ParseError::Incomplete
            }
        })?;

        if head_end > MAX_HEAD_BYTES {
            return Err(ParseError::HeadTooLarge);
        }

        let head = &input[..head_end];
        let mut lines = split_crlf(head);

        let request_line = lines.next().ok_or(ParseError::BadRequestLine)?;
        let (method, target, minor_version) = parse_request_line(request_line)?;

        let mut headers = Headers::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            // Obsolete line folding (a continuation line starting with SP/HTAB)
            // is a classic smuggling vector and was removed from the standard.
            if line[0] == b' ' || line[0] == b'\t' {
                return Err(ParseError::AmbiguousFraming("obsolete header line folding"));
            }
            if headers.len() >= MAX_HEADER_COUNT {
                return Err(ParseError::BadHeader(HeaderError::TooMany));
            }
            headers.append(parse_header_line(line)?).map_err(ParseError::BadHeader)?;
        }

        if minor_version >= 1 && headers.count("host") != 1 {
            return Err(ParseError::BadHost);
        }

        let request = Request { method, target, minor_version, headers };
        // Validate framing now so an ambiguous message never reaches routing.
        request.body_length()?;

        Ok(Parsed { request, consumed: head_end })
    }

    /// Determines how this request's body is delimited.
    ///
    /// Rejects every ambiguous combination:
    ///
    /// - `Transfer-Encoding` together with `Content-Length` — the pair that
    ///   makes classic CL.TE / TE.CL smuggling possible.
    /// - repeated `Content-Length` with differing values.
    /// - a `Transfer-Encoding` whose final coding is not `chunked`, which leaves
    ///   the end of the body undefined.
    pub fn body_length(&self) -> Result<BodyLength, ParseError> {
        let has_te = self.headers.contains("transfer-encoding");
        let content_lengths = self.headers.count("content-length");

        if has_te && content_lengths > 0 {
            return Err(ParseError::AmbiguousFraming(
                "both Transfer-Encoding and Content-Length present",
            ));
        }

        if has_te {
            if self.headers.count("transfer-encoding") > 1 {
                return Err(ParseError::AmbiguousFraming("repeated Transfer-Encoding"));
            }
            let value = self
                .headers
                .get_str("transfer-encoding")
                .ok_or(ParseError::AmbiguousFraming("non-UTF-8 Transfer-Encoding"))?;
            let final_coding = value
                .rsplit(',')
                .next()
                .map(str::trim)
                .unwrap_or_default()
                .to_ascii_lowercase();
            if final_coding != "chunked" {
                return Err(ParseError::AmbiguousFraming(
                    "Transfer-Encoding does not end with chunked",
                ));
            }
            return Ok(BodyLength::Chunked);
        }

        if content_lengths == 0 {
            return Ok(BodyLength::None);
        }

        let mut agreed: Option<u64> = None;
        for field in self.headers.iter() {
            if !field.name().eq_ignore_ascii_case("content-length") {
                continue;
            }
            let text = field
                .value_str()
                .ok_or(ParseError::AmbiguousFraming("non-UTF-8 Content-Length"))?
                .trim();
            // A leading sign or whitespace inside the digits is how parsers are
            // made to disagree, so only bare digits are accepted.
            if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
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

        Ok(BodyLength::Fixed(agreed.unwrap_or(0)))
    }

    /// The `Host` field, lowercased and stripped of any port.
    ///
    /// An IPv6 literal arrives bracketed (`[::1]`, `[::1]:8443`), so the closing
    /// bracket — not the last colon — marks the end of the host. Splitting on the
    /// last colon would truncate the address itself.
    pub fn host(&self) -> Option<String> {
        let raw = self.headers.get_str("host")?.trim();

        let without_port = if raw.starts_with('[') {
            match raw.find(']') {
                Some(close) => &raw[..=close],
                None => raw,
            }
        } else if let Some(index) = raw.rfind(':') {
            &raw[..index]
        } else {
            raw
        };

        Some(without_port.trim_end_matches('.').to_ascii_lowercase())
    }

    /// The path portion of the target, without the query string.
    pub fn path(&self) -> &str {
        match self.target.split_once('?') {
            Some((path, _)) => path,
            None => &self.target,
        }
    }

    /// Whether the connection should stay open after this exchange.
    pub fn wants_keep_alive(&self) -> bool {
        match self.headers.get_str("connection") {
            Some(value) if value.eq_ignore_ascii_case("close") => false,
            Some(value) if value.eq_ignore_ascii_case("keep-alive") => true,
            _ => self.minor_version >= 1,
        }
    }
}

/// Locates the end of the head, returning the offset just past the blank line.
pub(crate) fn find_head_end(input: &[u8]) -> Option<usize> {
    let limit = input.len().min(MAX_HEAD_BYTES + 4);
    let window = &input[..limit];
    window.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Splits a head into lines on CRLF, dropping the trailing blank line.
pub(crate) fn split_crlf(head: &[u8]) -> impl Iterator<Item = &[u8]> {
    head.split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.is_empty())
}

/// Parses `METHOD SP target SP HTTP/1.x`.
fn parse_request_line(line: &[u8]) -> Result<(Method, String, u8), ParseError> {
    let text = std::str::from_utf8(line).map_err(|_| ParseError::BadRequestLine)?;
    let mut parts = text.split(' ');

    let method = parts.next().filter(|s| !s.is_empty()).ok_or(ParseError::BadRequestLine)?;
    let target = parts.next().filter(|s| !s.is_empty()).ok_or(ParseError::BadRequestLine)?;
    let version = parts.next().ok_or(ParseError::BadRequestLine)?;

    if parts.next().is_some() {
        return Err(ParseError::BadRequestLine);
    }
    if !method.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(ParseError::BadRequestLine);
    }

    let minor_version = match version {
        "HTTP/1.1" => 1,
        "HTTP/1.0" => 0,
        v if v.starts_with("HTTP/") => return Err(ParseError::UnsupportedVersion),
        _ => return Err(ParseError::BadRequestLine),
    };

    Ok((Method::parse(method), target.to_owned(), minor_version))
}

/// Parses `Name: value`, trimming optional whitespace around the value.
pub(crate) fn parse_header_line(line: &[u8]) -> Result<Header, ParseError> {
    let colon = line.iter().position(|&b| b == b':').ok_or(ParseError::BadHeader(HeaderError::InvalidName))?;
    let name = std::str::from_utf8(&line[..colon]).map_err(|_| ParseError::BadHeader(HeaderError::InvalidName))?;

    // No space is permitted between the field name and the colon. Accepting one
    // is how a proxy and an origin end up parsing different header sets.
    if name.ends_with(' ') || name.ends_with('\t') {
        return Err(ParseError::AmbiguousFraming("whitespace before header colon"));
    }

    let value = trim_ows(&line[colon + 1..]);
    Header::new(name, value.to_vec()).map_err(ParseError::BadHeader)
}

/// Trims leading and trailing spaces and horizontal tabs.
pub(crate) fn trim_ows(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|&b| b != b' ' && b != b'\t').unwrap_or(bytes.len());
    let end = bytes.iter().rposition(|&b| b != b' ' && b != b'\t').map_or(start, |i| i + 1);
    &bytes[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> Result<Parsed, ParseError> {
        Request::parse(raw.as_bytes())
    }

    #[test]
    fn parses_a_simple_get() {
        let raw = "GET /videos?page=2 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let parsed = parse(raw).unwrap();
        assert_eq!(parsed.request.method, Method::Get);
        assert_eq!(parsed.request.target, "/videos?page=2");
        assert_eq!(parsed.request.path(), "/videos");
        assert_eq!(parsed.request.host().as_deref(), Some("example.com"));
        // The whole head is consumed, blank line included, so the caller knows
        // exactly where a pipelined next request begins.
        assert_eq!(parsed.consumed, raw.len());
    }

    #[test]
    fn consumed_marks_the_start_of_a_pipelined_request() {
        let raw = "GET /a HTTP/1.1\r\nHost: a.com\r\n\r\nGET /b HTTP/1.1\r\nHost: a.com\r\n\r\n";
        let first = Request::parse(raw.as_bytes()).unwrap();
        assert_eq!(first.request.path(), "/a");

        let second = Request::parse(&raw.as_bytes()[first.consumed..]).unwrap();
        assert_eq!(second.request.path(), "/b");
    }

    #[test]
    fn ipv6_host_keeps_its_colons_and_drops_its_port() {
        for (raw_host, expected) in [("[::1]", "[::1]"), ("[::1]:8443", "[::1]"), ("[2001:db8::1]:443", "[2001:db8::1]")] {
            let raw = format!("GET / HTTP/1.1\r\nHost: {raw_host}\r\n\r\n");
            assert_eq!(parse(&raw).unwrap().request.host().as_deref(), Some(expected));
        }
    }

    #[test]
    fn incomplete_head_asks_for_more() {
        assert_eq!(parse("GET / HTTP/1.1\r\nHost: a.com\r\n").unwrap_err(), ParseError::Incomplete);
    }

    #[test]
    fn rejects_transfer_encoding_with_content_length() {
        // CL.TE / TE.CL smuggling: this exact pair is what lets a proxy and an
        // origin disagree about where the request ends.
        let err = parse(
            "POST / HTTP/1.1\r\nHost: a.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .unwrap_err();
        assert!(matches!(err, ParseError::AmbiguousFraming(_)));
    }

    #[test]
    fn rejects_conflicting_content_lengths() {
        let err = parse("POST / HTTP/1.1\r\nHost: a.com\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n")
            .unwrap_err();
        assert!(matches!(err, ParseError::AmbiguousFraming(_)));
    }

    #[test]
    fn accepts_repeated_but_identical_content_length() {
        let parsed =
            parse("POST / HTTP/1.1\r\nHost: a.com\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n").unwrap();
        assert_eq!(parsed.request.body_length().unwrap(), BodyLength::Fixed(5));
    }

    #[test]
    fn rejects_non_chunked_final_coding() {
        let err = parse("POST / HTTP/1.1\r\nHost: a.com\r\nTransfer-Encoding: chunked, gzip\r\n\r\n")
            .unwrap_err();
        assert!(matches!(err, ParseError::AmbiguousFraming(_)));
    }

    #[test]
    fn accepts_chunked_as_final_coding() {
        let parsed =
            parse("POST / HTTP/1.1\r\nHost: a.com\r\nTransfer-Encoding: gzip, chunked\r\n\r\n").unwrap();
        assert_eq!(parsed.request.body_length().unwrap(), BodyLength::Chunked);
    }

    #[test]
    fn rejects_signed_or_padded_content_length() {
        for value in ["+5", "-5", "5 5", "0x5", ""] {
            let raw = format!("POST / HTTP/1.1\r\nHost: a.com\r\nContent-Length: {value}\r\n\r\n");
            assert!(parse(&raw).is_err(), "accepted Content-Length {value:?}");
        }
    }

    #[test]
    fn rejects_obsolete_line_folding() {
        let err = parse("GET / HTTP/1.1\r\nHost: a.com\r\nX-Long: one\r\n  two\r\n\r\n").unwrap_err();
        assert!(matches!(err, ParseError::AmbiguousFraming(_)));
    }

    #[test]
    fn rejects_space_before_colon() {
        let err = parse("GET / HTTP/1.1\r\nHost: a.com\r\nX-Bad : v\r\n\r\n").unwrap_err();
        assert!(matches!(err, ParseError::AmbiguousFraming(_)));
    }

    #[test]
    fn http_1_1_requires_exactly_one_host() {
        assert_eq!(parse("GET / HTTP/1.1\r\n\r\n").unwrap_err(), ParseError::BadHost);
        assert_eq!(
            parse("GET / HTTP/1.1\r\nHost: a.com\r\nHost: b.com\r\n\r\n").unwrap_err(),
            ParseError::BadHost
        );
    }

    #[test]
    fn http_1_0_may_omit_host() {
        let parsed = parse("GET / HTTP/1.0\r\n\r\n").unwrap();
        assert_eq!(parsed.request.minor_version, 0);
        assert!(!parsed.request.wants_keep_alive());
    }

    #[test]
    fn rejects_unsupported_versions() {
        assert_eq!(parse("GET / HTTP/2.0\r\n\r\n").unwrap_err(), ParseError::UnsupportedVersion);
    }

    #[test]
    fn host_strips_port_but_not_ipv6_colons() {
        let parsed = parse("GET / HTTP/1.1\r\nHost: Example.COM:8443\r\n\r\n").unwrap();
        assert_eq!(parsed.request.host().as_deref(), Some("example.com"));

        let v6 = parse("GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n").unwrap();
        assert_eq!(v6.request.host().as_deref(), Some("[::1]"));
    }

    #[test]
    fn oversized_head_is_rejected() {
        let filler = "X-Pad: ".to_owned() + &"a".repeat(MAX_HEAD_BYTES);
        let raw = format!("GET / HTTP/1.1\r\nHost: a.com\r\n{filler}\r\n\r\n");
        assert_eq!(parse(&raw).unwrap_err(), ParseError::HeadTooLarge);
    }

    #[test]
    fn keep_alive_defaults_by_version() {
        assert!(parse("GET / HTTP/1.1\r\nHost: a.com\r\n\r\n").unwrap().request.wants_keep_alive());
        assert!(
            !parse("GET / HTTP/1.1\r\nHost: a.com\r\nConnection: close\r\n\r\n")
                .unwrap()
                .request
                .wants_keep_alive()
        );
    }
}
