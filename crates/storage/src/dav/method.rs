//! The verb table: which WebDAV methods exist, which this build answers, and
//! what `OPTIONS` is therefore allowed to claim.
//!
//! Pure. Every function here is a value in and a value out.
//!
//! # The table is a closed allow-list, matched first
//!
//! `http/src/request.rs:349` accepts any token as a method, so `PROPFIND`
//! already parses and arrives as [`Method::Other`]. That is convenient and it is
//! also the trap: an unrecognised token must be `405`, decided **before**
//! anything else looks at the request, never a fallthrough into a handler that
//! happened to be reachable. [`Verb::classify`] is that decision and it returns
//! `None` for everything it does not name.
//!
//! # What this build claims is what this build does
//!
//! [`IMPLEMENTED`] is the single list, and the `Allow` and `DAV` headers are
//! **derived** from it rather than written out beside it. That is the whole
//! design of this module, and it exists because the alternative has a specific
//! failure: a server that advertises `DAV: 1, 2` without a working `LOCK` is
//! one the Windows Mini-Redirector will mount and then fail against on the
//! first `PUT`, because it locks before every write. So [`dav_header`] answers
//! `1, 2` exactly when `LOCK` is in the list and `1` otherwise, and the claim
//! cannot outrun the code.
//!
//! Today the list is the read half. Phase 5 adds `PROPPATCH`, `MKCOL`, `PUT`,
//! `DELETE`, `COPY`, `MOVE`, `LOCK` and `UNLOCK` to it, and both headers follow
//! on their own.
//!
//! A verb that exists in the protocol but not in this build is `405` with an
//! `Allow` header, not `501`: `405` is what RFC 9110 §15.5.6 defines for a
//! method a resource does not support, and the `Allow` it carries tells the
//! client what to do instead. `501` would say the *server* does not understand
//! the method, which is not true and which some clients treat as fatal for the
//! whole mount rather than for the request.

use crate::respond::{self, BlobResponse, Disposition};
use selfhost_http::{HeaderError, Method, Request, Response, Status};
use std::time::SystemTime;

/// A WebDAV method this module has an opinion about.
///
/// Every verb in RFC 4918 is here, including the ones this build does not
/// answer, because the point of the type is to be the closed set: a token that
/// does not map to one of these is refused without ever reaching a handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// Describe what this resource supports.
    Options,
    /// Read properties.
    PropFind,
    /// Write properties.
    PropPatch,
    /// Create a collection.
    MkCol,
    /// Read a file.
    Get,
    /// Read a file's headers.
    Head,
    /// Write a file.
    Put,
    /// Remove a resource.
    Delete,
    /// Copy a resource to a `Destination`.
    Copy,
    /// Move a resource to a `Destination`.
    Move,
    /// Take a lock.
    Lock,
    /// Release a lock.
    Unlock,
}

impl Verb {
    /// Recognises a method token, or refuses it.
    ///
    /// `None` is the `405` answer, and it is the answer for `POST`, `PATCH`,
    /// `TRACE`, `CONNECT` and every unknown token alike — a share has no use
    /// for any of them, and a verb table with a default arm is a verb table
    /// with a hole in it.
    pub fn classify(method: &Method) -> Option<Self> {
        match method {
            Method::Options => Some(Self::Options),
            Method::Get => Some(Self::Get),
            Method::Head => Some(Self::Head),
            Method::Put => Some(Self::Put),
            Method::Delete => Some(Self::Delete),
            Method::Post | Method::Patch | Method::Trace | Method::Connect => None,
            Method::Other(token) => match token.as_str() {
                "PROPFIND" => Some(Self::PropFind),
                "PROPPATCH" => Some(Self::PropPatch),
                "MKCOL" => Some(Self::MkCol),
                "COPY" => Some(Self::Copy),
                "MOVE" => Some(Self::Move),
                "LOCK" => Some(Self::Lock),
                "UNLOCK" => Some(Self::Unlock),
                _ => None,
            },
        }
    }

    /// The token as it appears on the wire and in an `Allow` header.
    pub fn token(self) -> &'static str {
        match self {
            Self::Options => "OPTIONS",
            Self::PropFind => "PROPFIND",
            Self::PropPatch => "PROPPATCH",
            Self::MkCol => "MKCOL",
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Copy => "COPY",
            Self::Move => "MOVE",
            Self::Lock => "LOCK",
            Self::Unlock => "UNLOCK",
        }
    }

    /// Whether this verb changes anything.
    ///
    /// The route layer needs this before it needs a handler: a writing verb on a
    /// read-only share is refused on the share's own flag, and the caller's
    /// grants are checked with [`crate::share::Want::Write`] rather than
    /// [`crate::share::Want::Read`].
    pub fn writes(self) -> bool {
        !matches!(self, Self::Options | Self::PropFind | Self::Get | Self::Head)
    }
}

/// The verbs this build actually answers.
///
/// One list, from which both advertised headers are derived. Adding a verb here
/// without implementing it is the one way to make this module lie, which is why
/// the list sits next to the sentence saying so rather than in a header string
/// somewhere else.
pub const IMPLEMENTED: [Verb; 4] = [Verb::Options, Verb::PropFind, Verb::Get, Verb::Head];

/// Whether this build answers a verb.
pub fn implemented(verb: Verb) -> bool {
    IMPLEMENTED.contains(&verb)
}

/// The `Allow` header value, derived from [`IMPLEMENTED`].
pub fn allow_header() -> String {
    IMPLEMENTED.iter().map(|verb| verb.token()).collect::<Vec<_>>().join(", ")
}

/// The `DAV` compliance classes this build may honestly claim.
///
/// Class 1 is the property machinery, which is here. Class 2 is locking, which
/// is not — and claiming it without `LOCK` is worse than not claiming it, as
/// this module's documentation explains. So the claim is computed from
/// [`IMPLEMENTED`] and becomes `1, 2` on the day `LOCK` joins it, in the same
/// edit, with no second place to remember.
pub fn dav_header() -> &'static str {
    if implemented(Verb::Lock) {
        "1, 2"
    } else {
        "1"
    }
}

/// The answer to `OPTIONS`, on a share root and on `/` alike.
///
/// Every header here earns its place:
///
/// - **`DAV`** is what makes a client treat the URL as a WebDAV resource at all.
///   Finder issues `OPTIONS` first and gives up without it.
/// - **`MS-Author-Via: DAV`** is what stops the Windows Mini-Redirector trying
///   FrontPage Server Extensions before WebDAV. Without it a Windows mount takes
///   an extra failed round trip and, on some builds, gives up entirely.
/// - **`Allow`** is derived from [`IMPLEMENTED`], so a client is never invited
///   to use a verb that will answer `405`.
/// - **`Accept-Ranges: bytes`** tells a client it may resume a download, which
///   is what makes a large file over a tunnel survivable.
///
/// `Content-Length: 0` is not set here: `Response::write_head` derives framing
/// from the body and would remove and re-add it. An empty body is a zero length,
/// in one place, which is the arrangement that cannot disagree with itself.
pub fn options() -> Response {
    build_options().unwrap_or_else(|_| Response::error_page(Status::INTERNAL_SERVER_ERROR))
}

/// The body of [`options`], with header failures surfaced rather than ignored.
///
/// Every value set below is a compile-time constant or derived from one, so none
/// can hold the CR, LF or NUL that `Headers::set` refuses. Returning the error
/// anyway keeps that reasoning from becoming a panic if it is ever wrong — under
/// `panic = "abort"` a panic in this process is the whole box.
fn build_options() -> Result<Response, HeaderError> {
    let mut response = Response::empty(Status::OK);
    response.headers.set("DAV", dav_header())?;
    response.headers.set("MS-Author-Via", "DAV")?;
    response.headers.set("Allow", allow_header())?;
    response.headers.set("Accept-Ranges", "bytes")?;
    Ok(response)
}

/// The answer to a verb this build does not implement, and to a token it does
/// not recognise.
///
/// The `Allow` header is the part that matters: `405` without it tells a client
/// only that it was wrong, and a WebDAV client that cannot discover the verb
/// list retries the same request.
pub fn not_allowed() -> Response {
    let mut response = Response::error_page(Status::METHOD_NOT_ALLOWED);
    if response.headers.set("Allow", allow_header()).is_err() {
        // Unreachable: the value is derived from compile-time tokens. A `405`
        // without the header is still a correct refusal, so the honest fallback
        // is to send it rather than to fail the request over a header.
        response.headers.remove("Allow");
    }
    response
}

/// The `GET`/`HEAD` answer for a file in a share.
///
/// This is [`crate::respond::blob`] with the disposition pinned, and the pinning
/// is the point. A WebDAV client never renders a file in a page — it saves it,
/// or it hands the bytes to an application — so the inline path buys nothing
/// here, and what it would cost is real: `/dav` is served from the console's own
/// origin, the origin that holds the session cookie for the thing that can
/// restart services. A file a caller uploaded and then persuaded a browser to
/// render inline on that origin is a stored cross-site scripting hole with the
/// console as its target. So there is no parameter to get wrong.
///
/// `total` and `modified` come from the caller's already-open handle rather than
/// from a fresh `stat`, for the reason [`crate::respond::blob`] gives: metadata
/// read separately from the bytes describes a different file than the one the
/// body will carry.
pub fn blob(
    request: &Request,
    name: &str,
    total: u64,
    modified: Option<SystemTime>,
) -> BlobResponse {
    respond::blob(request, name, total, modified, Disposition::Attachment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_http::{Body, Headers};

    fn request(method: &str, target: &str) -> Request {
        Request {
            method: Method::parse(method),
            target: target.to_string(),
            minor_version: 1,
            headers: Headers::new(),
        }
    }

    #[test]
    fn every_webdav_verb_is_recognised_and_nothing_else_is() {
        for (token, verb) in [
            ("OPTIONS", Verb::Options),
            ("PROPFIND", Verb::PropFind),
            ("PROPPATCH", Verb::PropPatch),
            ("MKCOL", Verb::MkCol),
            ("GET", Verb::Get),
            ("HEAD", Verb::Head),
            ("PUT", Verb::Put),
            ("DELETE", Verb::Delete),
            ("COPY", Verb::Copy),
            ("MOVE", Verb::Move),
            ("LOCK", Verb::Lock),
            ("UNLOCK", Verb::Unlock),
        ] {
            assert_eq!(Verb::classify(&Method::parse(token)), Some(verb), "{token}");
        }

        // Everything else is a 405, including the ordinary HTTP verbs a share
        // has no use for and anything a prober invents.
        for token in ["POST", "PATCH", "TRACE", "CONNECT", "BREW", "propfind", "GETS", ""] {
            assert_eq!(Verb::classify(&Method::parse(token)), None, "{token}");
        }
    }

    #[test]
    fn a_verb_knows_whether_it_writes() {
        for verb in [Verb::Options, Verb::PropFind, Verb::Get, Verb::Head] {
            assert!(!verb.writes(), "{}", verb.token());
        }
        for verb in [
            Verb::PropPatch,
            Verb::MkCol,
            Verb::Put,
            Verb::Delete,
            Verb::Copy,
            Verb::Move,
            Verb::Lock,
            Verb::Unlock,
        ] {
            assert!(verb.writes(), "{}", verb.token());
        }
    }

    /// The claim and the code are one list, and this is the assertion that says
    /// so: a `DAV: 1, 2` may appear only when `LOCK` is answered.
    #[test]
    fn the_compliance_class_cannot_outrun_the_implementation() {
        assert!(!implemented(Verb::Lock));
        assert_eq!(dav_header(), "1");

        for verb in IMPLEMENTED {
            assert!(allow_header().contains(verb.token()), "{}", verb.token());
        }
        for verb in [Verb::Put, Verb::Lock, Verb::MkCol, Verb::Delete] {
            assert!(!implemented(verb), "{}", verb.token());
            assert!(!allow_header().contains(verb.token()), "{}", verb.token());
        }
    }

    #[test]
    fn options_carries_everything_a_client_needs_to_mount() {
        let response = options();
        assert_eq!(response.status, Status::OK);
        assert_eq!(response.headers.get_str("dav"), Some("1"));
        assert_eq!(response.headers.get_str("ms-author-via"), Some("DAV"));
        assert_eq!(response.headers.get_str("allow"), Some("OPTIONS, PROPFIND, GET, HEAD"));
        assert_eq!(response.headers.get_str("accept-ranges"), Some("bytes"));
        assert!(response.body.is_empty());

        // The framing layer writes the zero length, so a `Content-Length` set
        // here would be removed and re-derived — one place, no disagreement.
        let mut head = Vec::new();
        response.write_head(&mut head, true).expect("a writable head");
        assert!(String::from_utf8_lossy(&head).contains("Content-Length: 0"));
    }

    #[test]
    fn a_verb_this_build_does_not_answer_is_405_with_the_list_that_would_work() {
        let response = not_allowed();
        assert_eq!(response.status, Status::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers.get_str("allow"), Some(allow_header().as_str()));
    }

    /// A WebDAV `GET` is always a download, and the type is always opaque.
    #[test]
    fn a_dav_get_never_offers_a_browser_something_to_render() {
        // A name that the inline path would happily serve as an image if the
        // disposition were the caller's to choose.
        let built = blob(&request("GET", "/dav/vault/photo.png"), "photo.png", 9, None);
        assert_eq!(built.response.status, Status::OK);
        assert_eq!(
            built.response.headers.get_str("content-type"),
            Some(crate::respond::OPAQUE_TYPE)
        );
        assert!(
            built
                .response
                .headers
                .get_str("content-disposition")
                .is_some_and(|value| value.starts_with("attachment;")),
            "a WebDAV GET is a download"
        );
        assert!(matches!(built.response.body, Body::Streamed(9)));
        assert_eq!(built.length, 9);

        // And a HEAD gets the same head with none of the bytes.
        let head = blob(&request("HEAD", "/dav/vault/photo.png"), "photo.png", 9, None);
        assert_eq!(head.length, 0);
        assert!(matches!(head.response.body, Body::Streamed(9)));
    }
}
