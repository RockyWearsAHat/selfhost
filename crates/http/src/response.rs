//! Response construction and serialisation.
//!
//! A response owns its framing decision. Callers choose a [`Body`] and this
//! module derives the matching `Content-Length` or `Transfer-Encoding`, so it is
//! not possible to declare one length and write another — the mismatch that
//! desynchronises a connection and enables response smuggling.

use crate::headers::{HeaderError, Headers};
use std::fmt;

/// A response status code and its reason phrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status(pub u16);

impl Status {
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

        headers.set("Connection", if keep_alive { "keep-alive" } else { "close" })?;
        headers.write_to(out);
        out.extend_from_slice(b"\r\n");
        Ok(())
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
